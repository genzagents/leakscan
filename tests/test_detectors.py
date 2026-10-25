"""Run: python3 -m pytest -q   (or python3 tests/test_detectors.py)"""
import os
import subprocess
import sys
import tempfile

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
from leakscan import scan_text, scan_repo, DETECTORS  # noqa: E402

import random
_r = random.Random(42)
def rnd(n, alphabet="ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"):
    return "".join(_r.choice(alphabet) for _ in range(n))
HEX = "0123456789abcdef"

# Synthetic values with the right shape. None of these are real credentials.
SAMPLES = {
    "anthropic": "sk-ant-api03-" + rnd(98),
    "openrouter": "sk-or-v1-" + rnd(64, HEX),
    "openai_project": "sk-proj-" + rnd(60) + "T3BlbkFJ" + rnd(30),
    "openai_legacy": "sk-" + rnd(20) + "T3BlbkFJ" + rnd(20),
    "groq": "gsk_" + rnd(52),
    "replicate": "r8_" + rnd(37),
    "huggingface": "hf_" + rnd(34),
    "google_api": "AIza" + rnd(35),
    "aws_access_key": "AKIA" + rnd(16, "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567"),
    "github_token": "ghp_" + rnd(36),
    "stripe_live": "sk_live_" + rnd(28),
    "slack_token": "xoxb-" + rnd(10, "0123456789") + "-" + rnd(24),
    "claude_code_session": "https://claude.ai/code/" + "session_01HZX7Y3K9QW2E4R5T6Y7U8I9O",  # leakscan:ignore
    "private_key": "-----BEGIN RSA " + "PRIVATE KEY-----",  # leakscan:ignore
    "railway_ctx": "RAILWAY_TOKEN=" + rnd(8, HEX) + "-" + rnd(4, HEX) + "-4" + rnd(3, HEX) + "-8" + rnd(3, HEX) + "-" + rnd(12, HEX),
    "ai_env_ctx": "TOGETHER_API_KEY=" + rnd(64, HEX),
    "url_credentials": "url = https://deploy:" + rnd(32) + "@gitlab.com/org/repo.git",
}

PLACEHOLDERS = [
    "OPENAI_API_KEY=sk-proj-xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
    "ANTHROPIC_API_KEY=your-anthropic-key-here-your-anthropic-key-here",
    "TOGETHER_API_KEY=${TOGETHER_API_KEY}",
    "GROQ_API_KEY=<your groq key>",
    "sk-ant-api03-" + "a" * 90,
]


def ids(text):
    return sorted({f.detector for f in scan_text(text, where="working tree", path="x")})


def test_each_sample_hits_its_detector():
    for det_id, sample in SAMPLES.items():
        hit = ids(f"KEY = \"{sample}\"")
        assert det_id in hit, (det_id, hit)


def test_placeholders_are_ignored():
    for text in PLACEHOLDERS:
        assert ids(text) == [], (text, ids(text))


def test_github_token_in_url_attributed_once():
    # A GitHub token inside a remote URL is reported once, as a GitHub token (the more specific rotate link).
    hits = list(scan_text("url = https://x-access-token:ghp_" + rnd(36) + "@github.com/o/r.git", where="working tree"))
    assert [h.detector for h in hits] == ["github_token"], [h.detector for h in hits]


def test_venv_is_skipped():
    with tempfile.TemporaryDirectory() as d:
        os.makedirs(os.path.join(d, "myenv", "lib"))
        open(os.path.join(d, "myenv", "pyvenv.cfg"), "w").close()
        with open(os.path.join(d, "myenv", "lib", "k.py"), "w") as fh:
            fh.write("KEY='" + SAMPLES["groq"] + "'\n")
        assert scan_repo(d) == []


def test_one_attribution_per_secret():
    # An OpenAI project key must not also be reported as the generic named-variable detector.
    hits = list(scan_text("OPENAI_API_KEY=" + SAMPLES["openai_project"], where="working tree"))
    assert len(hits) == 1 and hits[0].detector == "openai_project"


def test_inline_ignore_marker():
    assert ids("KEY=" + SAMPLES["groq"] + "  # leakscan:ignore") == []


def test_session_link_placeholder_ignored():
    assert ids("see https://claude.ai/code/session_... for details") == []
    assert ids("https://claude.ai/code/session_01HZX7Y3K9QW2E4R5T6Y7U8I9O") == ["claude_code_session"]  # leakscan:ignore


def test_detector_ids_unique():
    seen = [d.id for d in DETECTORS]
    assert len(seen) == len(set(seen))


def test_history_scan_finds_deleted_secret_and_env_file():
    with tempfile.TemporaryDirectory() as d:
        def git(*a):
            subprocess.run(["git", "-C", d, *a], check=True, capture_output=True)
        git("init", "-q", "-b", "main")
        git("config", "user.email", "t@example.com")
        git("config", "user.name", "t")
        with open(os.path.join(d, ".env"), "w") as fh:
            fh.write("GROQ_API_KEY=" + SAMPLES["groq"] + "\n")
        with open(os.path.join(d, "app.py"), "w") as fh:
            fh.write("print('hi')\n")
        git("add", ".")
        git("commit", "-q", "-m", "init\n\n" + SAMPLES["claude_code_session"])
        git("rm", "-q", ".env")
        git("commit", "-q", "-m", "remove env")
        findings = scan_repo(d)
        kinds = {(f.detector, f.where) for f in findings}
        assert ("groq", "history") in kinds, kinds
        assert ("env_file", "history") in kinds, kinds
        env = [f for f in findings if f.detector == "env_file"][0]
        assert len(env.commit) == 10 and env.commit_date.startswith("20"), (env.commit, env.commit_date)
        assert ("claude_code_session", "commit message") in kinds, kinds
        # Nothing in the working tree now.
        assert not any(f.where == "working tree" for f in findings)


if __name__ == "__main__":
    for name, fn in list(globals().items()):
        if name.startswith("test_"):
            fn()
            print("ok", name)
