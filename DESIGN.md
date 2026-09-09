# Design notes

Why this is built the way it is, and what was learned tuning it. Useful if you're changing the
rules, or deciding whether to trust it.

## The problem with the obvious alternatives

| Approach | Why not |
|---|---|
| `permissions.defaultMode: "bypassPermissions"` | Approves everything with no guardrails and no audit log. Often disabled by enterprise policy via `disableBypassPermissionsMode`. |
| `permissions.allow: ["Bash", "Edit", …]` | Same lack of guardrails, and you must enumerate every tool including each `mcp__*`. |
| Screenshot-and-click bot | Can't clear the sandbox gate (no button exists), only sees the focused window so it handles N agents *worse* than a per-call hook, and costs a continuous OCR loop instead of ~50 ms per call. |

A `PreToolUse` hook is the only option that is per-call, auditable, and can say "not this one."

## Three tiers, deliberately different in character

1. **`commands`** — a blocklist of named dangerous operations. Honest about its limit: it can
   only ever catch what someone thought to enumerate.
2. **`suspicious`** and **`code`** — match the *shape* of something hostile rather than a name.
   Obfuscated execution, an interpreter doing what a guarded command would have done, erasing
   traces, unusual network destinations, secrets flowing outward. These exist precisely because
   tier 1 can't be complete.
3. **`paths`** / **`writePaths`** / **`roots`** — scope, not danger. "This is not what you were
   asked to work on."

### `code` closes the biggest hole in a command-only blocklist

Without it, an agent writes a hostile script and then runs it with a perfectly ordinary
`python script.py`. So `Write.content`, `Edit.new_string`, `MultiEdit`, `NotebookEdit.new_source`
and any MCP editing tool's `body` are all inspected. MCP tools that expose
`execute_shell_command` are matched too — otherwise the dangerous string never appears in a
Bash input at all.

## The rule that makes content inspection survivable

Every content pattern pairs a dangerous **capability** with broad **reach** or a sensitive
**source**, because the capability alone is ordinary:

- `os.remove(tmp)` is fine. `shutil.rmtree(expanduser("~"))` is not.
- `requests.post(api, json=payload)` is fine. `requests.post(url, data=os.environ)` is not.
- `subprocess.run([...])` is fine. `os.system(f"rm -rf {target}")` is not.

A pattern that flags code you already ship is too broad, not vigilant. That's what `--scan` is
for: it applies the content rules to real source on disk, where every hit is a false positive by
construction.

## Tier choice matters more than it looks

The tool's own files started in `paths` (all tools). That made every *read* of them prompt, and
produced 14 of the first 19 prompts the tool ever raised. Moving them to `writePaths` fixed it.

> Put a rule in `paths` only when *reading* is the risk (secrets, token-bearing settings).
> Use `writePaths` when only modification is.

## Over-broad patterns are the main failure mode

Three real over-matches, all found by measurement rather than review:

- **Bare filename self-protection** flagged `--stats` and `--selftest` runs — 11 prompts for
  reading and running the tool. Fixed by requiring a mutating verb near the filename. The same
  bug would have fired on every README edit that merely *names* these files.
- **`curl … | python`** treated `curl localhost/api | python -c "<inline script>"` as remote
  code execution — 6 prompts on plain API pokes. What makes `curl x.sh | sh` dangerous is that
  the *program itself* is downloaded; piping a download into a script visible in the command is
  `jq` with extra steps. Fixed with a lookahead, plus a new rule for the one hole that opens
  (an inline script that `exec`s stdin). Bare `curl x | python` still fires, because bare python
  reads its program from stdin.
- **A long-base64 content rule** was dropped before shipping: in a document/OCR codebase, image
  fixtures are indistinguishable from an obfuscated payload. It survives only via the
  exec/decode pairing.

## The gap that was left on purpose

There is no "unrecognized binary" tier. It sounds like the obvious completion of tier 2, and it
was measured rather than dismissed: across 247 real Bash calls a leading-token extractor found
137 distinct "programs", 65% seen exactly once — and many weren't programs at all but `def`,
`interface`, `payload`, `1040`, pulled out of heredocs and multi-line scripts. Shell commands
aren't reliably parseable into "the binary being run" without a real shell parser, and the
legitimate long tail is genuinely long. Such a tier would cry wolf constantly.

## Validation methodology

Three passes, because reasoning about regexes is not the same as testing them:

- **`--selftest`** — 89 cases asserting *both* directions. Allow-cases are the important half:
  they're what fails when a rule gets too broad. Benign fixtures deliberately look a bit like
  the dangerous ones.
- **`--replay`** — re-decides every logged call under current rules and reports only
  `allow → ask` transitions. A new rule appearing here dozens of times is a rule that will
  annoy you dozens of times.
- **`--scan <dir>`** — applies the content rules to trusted source on disk.

## Implementation notes

- Regexes are tested against the **whole** command string, so a dangerous segment can't hide
  behind a harmless first one (`git status && rm -rf /`).
- Git worktrees have a `.git` **file**, not a directory, so repo-root discovery uses
  `existsSync` on both.
- Paths are normalized to forward slashes, trailing slash stripped, lowercased before any glob
  or root comparison.
- Everything is fail-open: malformed rules, unreadable config or bad stdin all exit 0 with no
  output. Exit code 2 would block a call, so the script never uses it.
- Config is re-read on every call. There's no daemon and no cache to invalidate.
