# leakscan

Find leaked AI API keys, Claude Code session links and committed `.env` files in a repo
**and its entire git history**, then get told exactly what to rotate.

Zero dependencies. One file. Python 3.9+ and git.

```bash
pipx install git+https://github.com/genzagents/leakscan     # or: uvx --from git+https://github.com/genzagents/leakscan leakscan
leakscan .                      # this repo: working tree + every commit on every branch
leakscan github YOUR_USERNAME   # every public repo you own, straight from GitHub
```

No install at all:

```bash
curl -sL https://raw.githubusercontent.com/genzagents/leakscan/main/leakscan/__init__.py | python3 - .
```

Browser version (paste a diff, a log, or a file; nothing leaves your machine): **https://genzagents.github.io/leakscan/**

## Why this exists

Two things happened in the same week of October 2026:

1. The Railway breach. Attackers went straight for customers' stored AI API keys. Keys in a
   host's env panel are only as safe as the host.
2. Claude Code started embedding `https://claude.ai/code/...` session links in commit messages.
   If that session is made public, everything it showed, including env vars and file contents,
   is readable by anyone with the link. The links are now in thousands of public repos.

Generic secret scanners know about AWS and Stripe. Most do not know about OpenRouter, Groq,
Replicate, Perplexity, xAI, Hugging Face or agent session links, and almost none tell you
*where to go to rotate*. This one does, and it reads the whole history, because deleting a key in a
new commit does not remove it from GitHub.

## What it finds

| Provider / thing | Rotate at |
|---|---|
| Anthropic, OpenAI (project, service account, admin, legacy), OpenRouter, Groq, Replicate, Hugging Face, Perplexity, xAI, Fireworks, Google AI Studio, ElevenLabs, DeepSeek | the provider's key page, linked in the output |
| Together, Mistral, Cohere, Voyage, Cerebras, LangSmith, Pinecone, Tavily, Exa, Deepgram, Stability and 20 more | matched by variable name plus a real-looking value |
| Claude Code session links in commit messages and files | open the session, make it private or delete it |
| `.env` files ever committed, even if since deleted | rotate everything inside, purge from history |
| AWS access keys, GitHub tokens, Stripe live keys, Slack tokens, Supabase service_role JWTs, Resend, Railway tokens, private key blocks | linked in the output |

Placeholders (`sk-xxxx`, `${KEY}`, `<your key>`, `aaaa…`) are ignored. Add `# leakscan:ignore`
to a line to silence it on purpose. Secrets are never printed in full; you get the first 8 and
last 4 characters plus a fingerprint.

## Output

```
✖ leakscan: 3 finding(s) in /Users/you/project

── Groq  [high]  (1)
   gsk_Wq8K…92Zm            .env @ 3f1c2a9b0e (2026-09-14)
   → https://console.groq.com/keys

── Committed .env file  [high]  (1)
   .env                     .env @ 3f1c2a9b0e (2026-09-14)
   → Rotate every value inside it, then purge it from history (git filter-repo) and add it to .gitignore

── Claude Code session link  [high]  (1)
   https://…Q7Rb            commit 9ad0e1f2c3 message
   → https://claude.ai/code  (open the session, make it private or delete it)

What to do, in order:
  1. Rotate every key above at the link given. Assume it is already harvested; bots index GitHub pushes within minutes.
  2. 3 finding(s) live only in history. Deleting the file in a new commit does not help. Purge with git filter-repo, force-push, and ask GitHub support to clear cached views.
  3. Add .env to .gitignore and move keys to your host's secret store.
  4. Re-run leakscan; it should print a clean result.
```

Exit code is 1 when anything is found, so it drops straight into CI.

## Watch your repos continuously (free, self-hosted)

Copy [`workflows/leakscan.yml`](workflows/leakscan.yml) into `.github/workflows/` in any repo. It runs
on every push and every Monday, and fails the build if a key appears. For a whole org, set
`OWNER` in the workflow and it scans every public repo you own on the schedule.

A hosted version that watches your public repos and emails you when something new leaks,
with no workflow to copy, is on the way. If you want it, say so here:
[I want the hosted watch](https://github.com/genzagents/leakscan/issues/new?title=Hosted+watch%3A+I+want+this&body=Repos+or+org+to+watch%3A+%0APrice+I+would+pay+per+month%3A+)

## Flags

```
leakscan [PATH]                 scan a local repo (default: .)
leakscan github OWNER           scan every public, non-fork repo of a user or org
leakscan github OWNER/REPO      scan one repo
  --json                        machine-readable output
  --no-history                  working tree only
  --include-forks               github mode: include forks
  --max-mb N                    github mode: skip repos larger than N MB (default 500)
```

Set `GITHUB_TOKEN` to raise the GitHub API rate limit in github mode. The token is only used to
list repos; cloning is anonymous and read-only.

## How it works

`git log --all -p --diff-filter=AM` is streamed and only added lines are matched, so each secret is
reported at the commit that introduced it. Commit messages are scanned separately for session
links. `git log --all --diff-filter=A --name-only` finds every `.env` that was ever added.
Working-tree files are read directly, skipping binaries and build directories. Nothing is sent
anywhere.

## Development

```bash
python3 tests/test_detectors.py
python3 -m leakscan --dump-patterns-js > docs/patterns.js   # keep the browser scanner in sync
```

MIT. Built by [genzagents](https://github.com/genzagents).
