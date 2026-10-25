#!/usr/bin/env python3
"""leakscan: find leaked AI API keys, Claude Code session links and committed
.env files in a repo's working tree and its entire git history, then tell you
exactly what to rotate.

Zero dependencies. Python 3.9+. Needs git on PATH.

    leakscan .                      # this repo: working tree + full history
    leakscan /path/to/repo
    leakscan github OWNER           # every public repo of a user or org
    leakscan github OWNER/REPO
    leakscan --json .               # machine-readable
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
import urllib.request
from dataclasses import dataclass, asdict, field
from typing import Iterable, Iterator, Optional

__version__ = "0.1.0"

# --------------------------------------------------------------------------
# Detectors
# --------------------------------------------------------------------------

@dataclass(frozen=True)
class Detector:
    id: str
    provider: str
    pattern: str
    rotate: str          # where to revoke and reissue
    severity: str = "high"
    group: int = 0       # regex group holding the secret (0 = whole match)
    note: str = ""


# Order matters: more specific patterns first so a key is attributed once.
DETECTORS: list[Detector] = [
    # ---- AI providers -------------------------------------------------
    Detector("anthropic", "Anthropic", r"sk-ant-(?:api|admin)\d{2}-[A-Za-z0-9_\-]{80,}",
             "https://console.anthropic.com/settings/keys"),
    Detector("openrouter", "OpenRouter", r"sk-or-v1-[a-f0-9]{64}",
             "https://openrouter.ai/settings/keys"),
    Detector("openai_project", "OpenAI", r"sk-proj-[A-Za-z0-9_\-]{40,}T3BlbkFJ[A-Za-z0-9_\-]{20,}",
             "https://platform.openai.com/api-keys"),
    Detector("openai_svc", "OpenAI (service account)", r"sk-svcacct-[A-Za-z0-9_\-]{40,}",
             "https://platform.openai.com/api-keys"),
    Detector("openai_admin", "OpenAI (admin)", r"sk-admin-[A-Za-z0-9_\-]{40,}",
             "https://platform.openai.com/settings/organization/admin-keys",
             severity="critical"),
    Detector("openai_legacy", "OpenAI (legacy)", r"\bsk-[A-Za-z0-9]{20}T3BlbkFJ[A-Za-z0-9]{20}\b",
             "https://platform.openai.com/api-keys"),
    Detector("groq", "Groq", r"\bgsk_[A-Za-z0-9]{52}\b",
             "https://console.groq.com/keys"),
    Detector("replicate", "Replicate", r"\br8_[A-Za-z0-9]{37}\b",
             "https://replicate.com/account/api-tokens"),
    Detector("huggingface", "Hugging Face", r"\bhf_[A-Za-z0-9]{34,40}\b",
             "https://huggingface.co/settings/tokens"),
    Detector("perplexity", "Perplexity", r"\bpplx-[A-Za-z0-9]{40,60}\b",
             "https://www.perplexity.ai/settings/api"),
    Detector("xai", "xAI", r"\bxai-[A-Za-z0-9]{60,100}\b",
             "https://console.x.ai"),
    Detector("fireworks", "Fireworks", r"\bfw_[A-Za-z0-9]{20,32}\b",
             "https://fireworks.ai/account/api-keys", severity="medium"),
    Detector("google_api", "Google (AI Studio / Cloud API key)", r"\bAIza[0-9A-Za-z_\-]{35}\b",
             "https://aistudio.google.com/apikey",
             note="Also check Google Cloud > APIs & Services > Credentials"),
    Detector("elevenlabs", "ElevenLabs", r"\bsk_[a-f0-9]{48}\b",
             "https://elevenlabs.io/app/settings/api-keys", severity="medium"),
    Detector("deepseek_ctx", "DeepSeek", r"(?i)deepseek[A-Za-z0-9_]*(?:key|token)\W{0,5}(sk-[a-f0-9]{32})",
             "https://platform.deepseek.com/api_keys", group=1),
    Detector("ai_env_ctx", "AI provider key (named variable)",
             r"(?i)\b(?:TOGETHER|MISTRAL|COHERE|VOYAGE|CEREBRAS|SAMBANOVA|DEEPINFRA|NOVITA|"
             r"LANGSMITH|LANGCHAIN|HELICONE|PORTKEY|WANDB|PINECONE|WEAVIATE|TAVILY|SERPER|EXA|"
             r"ASSEMBLYAI|DEEPGRAM|STABILITY|RUNWAY|LUMA|OPENAI|ANTHROPIC|GEMINI|GOOGLE_AI|"
             r"GOOGLE_GENAI|GROQ|REPLICATE|HF|HUGGING_?FACE|AZURE_OPENAI)[A-Z0-9_]*"
             r"(?:API_?KEY|SECRET|TOKEN)\s*[:=]\s*[\"']?([A-Za-z0-9_\-\.]{24,})[\"']?",
             "Rotate at the provider named in the variable", group=1, severity="medium",
             note="Matched by variable name and a real-looking value"),

    # ---- Agent session links ----------------------------------------
    Detector("claude_code_session", "Claude Code session link",
             r"https?://claude\.ai/code/(?:sessions?[/_]|s/)?(?=[A-Za-z0-9_\-]*\d)[A-Za-z0-9_\-]{8,}",
             "https://claude.ai/code  (open the session, make it private or delete it)",
             severity="high",
             note="If the session is or becomes public, everything shown in it (env vars, keys, "
                  "file contents) is readable by anyone with the link"),

    # ---- Platform and infra keys that AI builders commit most ---------
    Detector("aws_access_key", "AWS access key", r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b",
             "https://console.aws.amazon.com/iam/home#/security_credentials", severity="critical"),
    Detector("github_token", "GitHub token", r"\b(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{36,}\b|\bgithub_pat_[A-Za-z0-9_]{80,}\b",
             "https://github.com/settings/tokens", severity="critical"),
    Detector("stripe_live", "Stripe live key", r"\b(?:sk|rk)_live_[A-Za-z0-9]{24,}\b",
             "https://dashboard.stripe.com/apikeys", severity="critical"),
    Detector("slack_token", "Slack token", r"\bxox[abprs]-[A-Za-z0-9\-]{10,}\b",
             "https://api.slack.com/apps  (regenerate under OAuth & Permissions)"),
    Detector("supabase_service", "Supabase service_role JWT",
             r"\beyJ[A-Za-z0-9_\-]{10,}\.eyJ[A-Za-z0-9_\-]*(?:c2VydmljZV9yb2xl|InNlcnZpY2Vfcm9sZSI|zZXJ2aWNlX3JvbGU)[A-Za-z0-9_\-]*\.[A-Za-z0-9_\-]{10,}\b",
             "https://supabase.com/dashboard/project/_/settings/api", severity="critical",
             note="service_role bypasses row level security"),
    Detector("resend", "Resend", r"\bre_[A-Za-z0-9]{8}_[A-Za-z0-9]{20,}\b",
             "https://resend.com/api-keys", severity="medium"),
    Detector("railway_ctx", "Railway token",
             r"(?i)RAILWAY[A-Z_]*TOKEN\s*[:=]\s*[\"']?([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})",
             "https://railway.com/account/tokens", group=1),
    Detector("url_credentials", "Credentials embedded in a URL",
             r"https?://(?:[A-Za-z0-9_\-\.]+):([A-Za-z0-9_\-\.~%]{8,})@(?:github\.com|gitlab\.com|bitbucket\.org|huggingface\.co|[A-Za-z0-9\.\-]+)",
             "Rotate the token, then run: git remote set-url origin <url without the token> and use a credential helper",
             group=1, severity="critical",
             note="Often left behind by deploy scripts or CI; .git/config is checked too"),
    Detector("private_key", "Private key block",
             r"-----BEGIN (?:RSA |EC |OPENSSH |DSA |PGP |ENCRYPTED )?PRIVATE KEY(?: BLOCK)?-----",
             "Generate a new key pair and remove the old public key everywhere it is trusted",
             severity="critical"),
]

_COMPILED = [(d, re.compile(d.pattern)) for d in DETECTORS]

# Values that are clearly placeholders, not secrets.
_PLACEHOLDER = re.compile(
    r"(?i)(xxxx|your[_\-]?|example|placeholder|changeme|insert|redacted|dummy|sample|"
    r"<[a-z_ ]+>|\$\{|\{\{|\.\.\.|\*{4,}|0{8,}|1234567890|abcdefghij)"
)

ENV_FILE = re.compile(r"(^|/)\.env(\.[A-Za-z0-9_\-]+)?$")
ENV_SAFE = re.compile(r"\.env\.(example|sample|template|dist|defaults?|schema|test\.example)$", re.I)

SKIP_DIRS = {".git", "node_modules", ".venv", "venv", "__pycache__", ".tox", "dist", "build",
             ".next", ".nuxt", "target", "vendor", ".mypy_cache", ".pytest_cache", ".idea"}
MAX_FILE_BYTES = 2 * 1024 * 1024


def _is_placeholder(value: str) -> bool:
    if _PLACEHOLDER.search(value):
        return True
    core = re.sub(r"^(?:[A-Za-z0-9]{1,8}[-_])+", "", value)  # drop "sk-ant-api03-" style prefixes
    return len(set(core)) <= 4  # "aaaaaaa", "xxxxxxx", etc.


def mask(secret: str) -> str:
    if len(secret) <= 12:
        return secret[:3] + "…"
    return f"{secret[:8]}…{secret[-4:]}"


def fingerprint(secret: str) -> str:
    return hashlib.sha256(secret.encode()).hexdigest()[:12]


# --------------------------------------------------------------------------
# Findings
# --------------------------------------------------------------------------

@dataclass
class Finding:
    kind: str            # "secret" | "session_link" | "env_file"
    detector: str
    provider: str
    severity: str
    masked: str
    fingerprint: str
    rotate: str
    where: str           # "working tree" | "history" | "commit message"
    path: str = ""
    line: int = 0
    commit: str = ""
    commit_date: str = ""
    repo: str = ""
    note: str = ""


def scan_text(text: str, *, where: str, path: str = "", commit: str = "",
              commit_date: str = "", repo: str = "", only_added=False) -> Iterator[Finding]:
    """Yield findings in a blob of text. If only_added, only consider lines
    starting with '+' (a unified diff) and strip the marker."""
    for lineno, raw in enumerate(text.splitlines(), 1):
        if only_added:
            if not raw.startswith("+") or raw.startswith("+++"):
                continue
            line = raw[1:]
        else:
            line = raw
        if len(line) > 20000:
            line = line[:20000]
        if "leakscan:ignore" in line:
            continue
        seen_spans: list[tuple[int, int]] = []
        for det, rx in _COMPILED:
            for m in rx.finditer(line):
                span = m.span(det.group)
                if any(a <= span[0] < b for a, b in seen_spans):
                    continue  # already attributed to a more specific detector
                secret = m.group(det.group)
                if det.id != "private_key" and det.id != "claude_code_session" and _is_placeholder(secret):
                    continue
                seen_spans.append(span)
                kind = "session_link" if det.id == "claude_code_session" else "secret"
                yield Finding(kind=kind, detector=det.id, provider=det.provider,
                              severity=det.severity, masked=mask(secret),
                              fingerprint=fingerprint(secret), rotate=det.rotate,
                              where=where, path=path, line=lineno if not commit or where != "commit message" else 0,
                              commit=commit, commit_date=commit_date, repo=repo, note=det.note)


# --------------------------------------------------------------------------
# Git plumbing
# --------------------------------------------------------------------------

def _git(repo: str, *args: str, check=True) -> str:
    r = subprocess.run(["git", "-C", repo, *args], capture_output=True, text=True,
                       errors="replace")
    if check and r.returncode != 0:
        raise RuntimeError(f"git {' '.join(args)} failed: {r.stderr.strip()}")
    return r.stdout


def is_git_repo(path: str) -> bool:
    r = subprocess.run(["git", "-C", path, "rev-parse", "--git-dir"], capture_output=True)
    return r.returncode == 0


def scan_history(repo: str, repo_label: str = "") -> Iterator[Finding]:
    """Stream `git log -p --all` and scan added lines, plus commit messages."""
    fmt = "%x1e%H%x1f%aI%x1f%B%x1d"
    proc = subprocess.Popen(
        ["git", "-C", repo, "log", "--all", "-p", "--no-color", "--no-renames",
         "--diff-filter=AM", f"--format={fmt}"],
        stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True, errors="replace",
        bufsize=1 << 16,
    )
    assert proc.stdout is not None
    commit = date = ""
    path = ""
    in_header = False
    header_buf: list[str] = []
    for raw in proc.stdout:
        line = raw.rstrip("\n")
        if line.startswith("\x1e"):
            in_header = True
            header_buf = [line[1:]]
            if "\x1d" in line:
                in_header = False
            else:
                continue
        elif in_header:
            header_buf.append(line)
            if "\x1d" in line:
                in_header = False
            else:
                continue
        if header_buf:
            header = "\n".join(header_buf).split("\x1d", 1)[0]
            header_buf = []
            parts = header.split("\x1f", 2)
            if len(parts) == 3:
                commit, date, message = parts
                for f in scan_text(message, where="commit message", commit=commit[:10],
                                   commit_date=date[:10], repo=repo_label):
                    yield f
            path = ""
            continue
        if line.startswith("diff --git "):
            path = ""
            continue
        if line.startswith("+++ b/"):
            path = line[6:]
            continue
        if line.startswith("+++ "):
            path = ""
            continue
        if not path or not line.startswith("+") or line.startswith("+++"):
            continue
        for f in scan_text(line, where="history", path=path, commit=commit[:10],
                           commit_date=date[:10], repo=repo_label, only_added=True):
            f.line = 0
            yield f
    proc.wait()


def scan_env_files_in_history(repo: str, repo_label: str = "") -> Iterator[Finding]:
    out = _git(repo, "log", "--all", "--diff-filter=A", "--name-only", "--no-renames",
               "--format=%x1e%H %aI", check=False)
    commit = date = ""
    seen: set[str] = set()
    for line in out.split("\n"):  # not splitlines(): it treats \x1e as a line break
        if line.startswith("\x1e"):
            commit, _, date = line[1:].partition(" ")
            continue
        p = line.strip()
        if not p or p in seen:
            continue
        if ENV_FILE.search(p) and not ENV_SAFE.search(p):
            seen.add(p)
            yield Finding(kind="env_file", detector="env_file", provider="Committed .env file",
                          severity="high", masked=p, fingerprint=fingerprint(p),
                          rotate="Rotate every value inside it, then purge it from history "
                                 "(git filter-repo) and add it to .gitignore",
                          where="history", path=p, commit=commit[:10], commit_date=date[:10],
                          repo=repo_label)


def _is_venv(path: str) -> bool:
    return os.path.exists(os.path.join(path, "pyvenv.cfg")) or os.path.basename(path) == "site-packages"


def scan_working_tree(root: str, repo_label: str = "") -> Iterator[Finding]:
    # .git/config is skipped by the walk but is where remote URLs with embedded tokens live.
    gitconfig = os.path.join(root, ".git", "config")
    if os.path.isfile(gitconfig):
        try:
            with open(gitconfig, encoding="utf-8", errors="replace") as fh:
                for f in scan_text(fh.read(), where="working tree", path=".git/config", repo=repo_label):
                    yield f
        except OSError:
            pass
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames
                       if d not in SKIP_DIRS and not _is_venv(os.path.join(dirpath, d))]
        for name in filenames:
            full = os.path.join(dirpath, name)
            rel = os.path.relpath(full, root)
            if ENV_FILE.search(rel) and not ENV_SAFE.search(rel):
                # Only a problem if tracked by git (otherwise it is just a local file).
                if is_git_repo(root):
                    tracked = subprocess.run(["git", "-C", root, "ls-files", "--error-unmatch", rel],
                                             capture_output=True).returncode == 0
                    if tracked:
                        yield Finding(kind="env_file", detector="env_file",
                                      provider="Tracked .env file", severity="high", masked=rel,
                                      fingerprint=fingerprint(rel),
                                      rotate="Rotate every value inside it, git rm --cached it, "
                                             "add to .gitignore",
                                      where="working tree", path=rel, repo=repo_label)
            try:
                if os.path.getsize(full) > MAX_FILE_BYTES or os.path.islink(full):
                    continue
                with open(full, "rb") as fh:
                    head = fh.read(8192)
                    if b"\x00" in head:
                        continue
                    data = head + fh.read()
            except OSError:
                continue
            text = data.decode("utf-8", errors="replace")
            for f in scan_text(text, where="working tree", path=rel, repo=repo_label):
                yield f


def scan_repo(path: str, repo_label: str = "", history=True, tree=True) -> list[Finding]:
    findings: list[Finding] = []
    if tree:
        findings.extend(scan_working_tree(path, repo_label))
    if history and is_git_repo(path):
        findings.extend(scan_history(path, repo_label))
        findings.extend(scan_env_files_in_history(path, repo_label))
    return dedupe(findings)


def dedupe(findings: list[Finding]) -> list[Finding]:
    """Same secret in the same place many times across history: keep the earliest."""
    best: dict[tuple, Finding] = {}
    for f in findings:
        key = (f.repo, f.fingerprint, f.path, f.where)
        cur = best.get(key)
        if cur is None or (f.commit_date and (not cur.commit_date or f.commit_date < cur.commit_date)):
            best[key] = f
    sev_rank = {"critical": 0, "high": 1, "medium": 2, "low": 3}
    return sorted(best.values(), key=lambda f: (sev_rank.get(f.severity, 9), f.repo, f.provider, f.path))


# --------------------------------------------------------------------------
# GitHub mode
# --------------------------------------------------------------------------

def _gh_json(url: str):
    req = urllib.request.Request(url, headers={"Accept": "application/vnd.github+json",
                                               "User-Agent": f"leakscan/{__version__}"})
    tok = os.environ.get("GITHUB_TOKEN") or os.environ.get("GH_TOKEN")
    if tok:
        req.add_header("Authorization", f"Bearer {tok}")
    with urllib.request.urlopen(req, timeout=30) as r:
        return json.load(r)


def list_public_repos(owner: str, include_forks=False) -> list[dict]:
    repos: list[dict] = []
    page = 1
    while True:
        batch = _gh_json(f"https://api.github.com/users/{owner}/repos?per_page=100&type=owner&page={page}")
        if not batch:
            break
        repos.extend(batch)
        if len(batch) < 100:
            break
        page += 1
    return [r for r in repos if not r.get("private") and (include_forks or not r.get("fork"))]


def scan_github(target: str, include_forks=False, max_mb=500, log=print) -> list[Finding]:
    if "/" in target:
        owner, name = target.split("/", 1)
        repos = [_gh_json(f"https://api.github.com/repos/{owner}/{name}")]
    else:
        repos = list_public_repos(target, include_forks)
        log(f"{len(repos)} public repos under {target}")
    findings: list[Finding] = []
    for r in repos:
        full = r["full_name"]
        size_mb = (r.get("size") or 0) / 1024
        if size_mb > max_mb:
            log(f"  skip {full}: {size_mb:.0f} MB > {max_mb} MB (raise with --max-mb)")
            continue
        tmp = tempfile.mkdtemp(prefix="leakscan-")
        try:
            log(f"  {full} …", end="", flush=True)
            res = subprocess.run(["git", "clone", "--quiet", "--bare", r["clone_url"], tmp],
                                 capture_output=True, text=True, timeout=600)
            if res.returncode != 0:
                log(f" clone failed: {res.stderr.strip()[:120]}")
                continue
            found = scan_repo(tmp, repo_label=full, tree=False)
            findings.extend(found)
            log(f" {len(found)} finding(s)")
        finally:
            shutil.rmtree(tmp, ignore_errors=True)
    return dedupe(findings)


# --------------------------------------------------------------------------
# Reporting
# --------------------------------------------------------------------------

def _loc(f: Finding) -> str:
    bits = []
    if f.repo:
        bits.append(f.repo)
    if f.where == "commit message":
        bits.append(f"commit {f.commit} message")
    elif f.where == "history":
        bits.append(f"{f.path} @ {f.commit} ({f.commit_date})")
    else:
        bits.append(f"{f.path}:{f.line}" if f.line else f.path)
    return "  ".join(bits)


def render(findings: list[Finding], target: str) -> str:
    if not findings:
        return f"✔ leakscan: nothing found in {target}. Working tree and full history are clean for the patterns checked.\n"
    out = [f"✖ leakscan: {len(findings)} finding(s) in {target}\n"]
    by_provider: dict[str, list[Finding]] = {}
    for f in findings:
        by_provider.setdefault(f.provider, []).append(f)
    for provider, fs in by_provider.items():
        out.append(f"── {provider}  [{fs[0].severity}]  ({len(fs)})")
        for f in fs:
            out.append(f"   {f.masked:<24} {_loc(f)}")
        out.append(f"   → {fs[0].rotate}")
        if fs[0].note:
            out.append(f"     {fs[0].note}")
        out.append("")
    hist = sum(1 for f in findings if f.where != "working tree")
    steps = ["Rotate every key above at the link given. Assume it is already harvested; bots index GitHub pushes within minutes."]
    if hist:
        steps.append(f"{hist} finding(s) live only in history. Deleting the file in a new commit does not help. "
                     "Purge with git filter-repo, force-push, and ask GitHub support to clear cached views.")
    steps.append("Add .env to .gitignore and move keys to your host's secret store.")
    steps.append("Re-run leakscan; it should print a clean result.")
    out.append("What to do, in order:")
    out.extend(f"  {i}. {s}" for i, s in enumerate(steps, 1))
    return "\n".join(out) + "\n"


def dump_patterns_js() -> str:
    """Emit the detector table as JS for the browser scanner so it stays in sync."""
    rows = []
    for d in DETECTORS:
        pat = d.pattern
        flags = ""
        if pat.startswith("(?i)"):
            pat = pat[4:]
            flags = "i"
        rows.append({"id": d.id, "provider": d.provider, "pattern": pat, "flags": flags,
                     "group": d.group, "rotate": d.rotate, "severity": d.severity, "note": d.note})
    return ("// generated by `leakscan --dump-patterns-js`; do not edit by hand\n"
            "window.LEAKSCAN_PATTERNS = " + json.dumps(rows, indent=1) + ";\n"
            "window.LEAKSCAN_PLACEHOLDER = " + json.dumps(_PLACEHOLDER.pattern.replace("(?i)", "")) + ";\n"
            f"window.LEAKSCAN_VERSION = {json.dumps(__version__)};\n")


# --------------------------------------------------------------------------
# CLI
# --------------------------------------------------------------------------

def main(argv: Optional[list[str]] = None) -> int:
    ap = argparse.ArgumentParser(prog="leakscan", description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("target", nargs="*", help="a path, or: github OWNER | github OWNER/REPO")
    ap.add_argument("--json", action="store_true", help="print findings as JSON")
    ap.add_argument("--no-history", action="store_true", help="scan the working tree only")
    ap.add_argument("--include-forks", action="store_true", help="github mode: include forks")
    ap.add_argument("--max-mb", type=int, default=500, help="github mode: skip repos larger than this")
    ap.add_argument("--dump-patterns-js", action="store_true", help=argparse.SUPPRESS)
    ap.add_argument("--version", action="version", version=f"leakscan {__version__}")
    args = ap.parse_args(argv)

    if args.dump_patterns_js:
        sys.stdout.write(dump_patterns_js())
        return 0

    log = (lambda *a, **k: print(*a, file=sys.stderr, **k))
    if not args.target:
        args.target = ["."]

    if args.target[0] == "github":
        if len(args.target) < 2:
            ap.error("github mode needs OWNER or OWNER/REPO")
        label = args.target[1]
        findings = scan_github(label, include_forks=args.include_forks, max_mb=args.max_mb, log=log)
    else:
        path = os.path.abspath(args.target[0])
        if not os.path.isdir(path):
            ap.error(f"{path} is not a directory")
        label = path
        findings = scan_repo(path, history=not args.no_history)

    if args.json:
        print(json.dumps([asdict(f) for f in findings], indent=1))
    else:
        sys.stdout.write(render(findings, label))
    return 1 if findings else 0


if __name__ == "__main__":
    sys.exit(main())
