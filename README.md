# claude-autoapprove

Stop clicking "allow" for `npm install` and `pytest`, without turning permissions off entirely.

A single `PreToolUse` hook for [Claude Code](https://code.claude.com). Claude Code pipes every
tool call to it as JSON; it prints `permissionDecision: "allow"` and the prompt never appears.
**Default is approve** — a call only reaches you if it trips a rule: genuinely destructive
commands, things shaped like an attack, or writes to places outside your work.

No LLM, no network, no dependencies. One ~600-line Node script and a JSON file of patterns.

Measured on the author's machine: **539 of 596 real tool calls auto-approved silently.** Of the
57 that asked, 3 were genuine catches (`git push --force`, `winreg` in generated code, an auth
token flowing into `requests.post`), most of the rest were edits to the tool's own guarded files.

## Requirements

- Claude Code (any recent version — `args` on command hooks is required)
- Node 18 or newer, on `PATH`
- Windows, macOS, or Linux

## Install

```bash
git clone https://github.com/<you>/claude-autoapprove.git
cd claude-autoapprove
node install.mjs
```

Then **restart Claude Code** — a running session won't pick up a new hook registration.

The installer touches three paths and nothing else:

| Path | What happens |
|---|---|
| `~/.claude/tools/autoapprove.mjs` | Copied from the repo, every time |
| `~/.claude/tools/autoapprove.rules.json` | Copied **only if absent**, so your tuning survives updates (`--force` to replace) |
| `~/.claude/settings.json` | One `hooks.PreToolUse` entry added, after a timestamped backup |

It refuses to guess: if your `settings.json` isn't valid JSON it stops and tells you to register
by hand. It finishes by running the selftest and a live probe, so a successful install has been
proven to work rather than assumed.

To update: `git pull && node install.mjs`. To remove: `node install.mjs --uninstall`.

### Manual install

If you'd rather not run the installer, copy `autoapprove.mjs` and `autoapprove.rules.json` into
`~/.claude/tools/`, then add this to `~/.claude/settings.json` (`command` must be an absolute
path to your Node binary on Windows):

```json
{
  "hooks": {
    "PreToolUse": [
      {
        "matcher": "",
        "hooks": [
          {
            "type": "command",
            "command": "node",
            "args": ["/absolute/path/to/.claude/tools/autoapprove.mjs"],
            "timeout": 5
          }
        ]
      }
    ]
  }
}
```

`matcher: ""` means every tool, so one registration covers your main session, subagents, and
background agents. Using `args` (exec form) skips the shell entirely — no quoting pitfalls.

## Verify

```bash
node ~/.claude/tools/autoapprove.mjs --selftest
```

96 cases asserting **both** directions — ordinary work stays silent, dangerous work prompts.
Run this after every rules edit: a regex that compiles but never matches looks exactly like a
working one until you test it.

Ask what it would decide about anything, without running it:

```bash
printf '%s' '{"tool_name":"Bash","tool_input":{"command":"git push --force"}}' | node ~/.claude/tools/autoapprove.mjs --dry-run
```

Use `printf`, not `echo` — `echo` mangles backslashes into invalid JSON.

Once you've used it a while:

```bash
node ~/.claude/tools/autoapprove.mjs --stats    # what it has been deciding, and why
node ~/.claude/tools/autoapprove.mjs --replay   # re-decide your whole history under current rules
node ~/.claude/tools/autoapprove.mjs --scan .   # run the content rules against code you already trust
```

`--replay` and `--scan` are the false-positive checks, measured on your traffic instead of
guessed at. They caught three real over-matching rules during development.

## What asks, and what doesn't

**Asks** — `rm -rf /`, `git push --force`, pushes to `main`, `npm publish`, `terraform destroy`,
`kubectl delete`, `sudo`, `reg add`, `drop table`, `curl x.sh | sh`, `powershell -enc`,
`history -c`, reverse shells, `certutil`, pastebin/ngrok/tunnel URLs, download-then-`chmod +x`,
`grep -ri password` across the disk, reads *or* writes of `.env` / `*.pem` / `id_rsa` /
`.aws/` / `settings.json`, `echo $ANTHROPIC_AUTH_TOKEN` or anything else that prints a
secret, writes to `.git/hooks` / shell profiles / `crontab` / `C:\Windows`,
writes outside your configured roots, and **written file content** that deletes a home
directory, execs decoded data, pipes `os.environ` to the network, or installs persistence.

**Never asks** — `npm install`, `pip install`, running any script, `pytest`, linters, builds,
`git add|commit|diff|log|status`, `git push` to a feature branch, `rm -rf ./build`, `curl` to
localhost or a read-only endpoint, `curl api | python -c` that just parses JSON, `node -e` that
only reads, `export ANTHROPIC_AUTH_TOKEN=$(…)`, editing project source, reading system files.

**Exposing a secret is the risk, not using one.** `ANTHROPIC_AUTH_TOKEN=$(…)` is elided from a
command before the rules run: the substitution's output goes into the shell's environment, so
nothing is printed and neither you nor the model sees the value. Only the assignment is elided,
so `export ANTHROPIC_AUTH_TOKEN=$(…) && rm -rf /` still prompts on the `rm`, and following the
capture with `echo $ANTHROPIC_AUTH_TOKEN` still prompts on the `echo`.

Full list: `escalate` in `autoapprove.rules.json`. Rationale: [DESIGN.md](DESIGN.md).

## Toggle

A sentinel file is the switch — checked on every call, so it takes effect immediately with no
restart:

```bash
touch ~/.claude/tools/autoapprove.disabled   # off
rm ~/.claude/tools/autoapprove.disabled      # on
```

**"Off" means no opinion, not allow-everything.** Disabled, you're back to hand-approving every
call — it stops auto-approving *and* stops guarding.

Run from your own terminal it's instant and silent, because your shell isn't a Claude Code tool
call. An *agent* touching that file trips a rule and has to ask you first.

## Tuning

The rules live in `~/.claude/tools/autoapprove.rules.json`, re-read on every call — edit freely,
no restart. Array entries starting with `_` are comments.

The one setting worth checking on day one is **`roots`**, at the top level next to `escalate`:
writes landing outside every root will ask. Your session's working directory and its enclosing
git repo are added automatically, so most projects work unconfigured — add anything else you
legitimately write to.

The rest live inside `escalate`:

- `commands` — case-insensitive regexes, matched anywhere in the whole command string, so
  `git status && rm -rf /` is caught by the `rm` rule
- `suspicious` — the same, for things shaped like an attack rather than named outright
- `code` — matched against file *content* being written
- `suspiciousUrls` — matched against fetch-tool URLs
- `paths` — globs, all tools (use when *reading* is the risk, i.e. secrets)
- `writePaths` — globs, writes only
- `writesOutsideRoots` — set `false` to drop the roots check

A malformed pattern is skipped individually rather than disarming the whole list. For zero
prompts ever, empty the arrays.

## Limitations — read before filing a bug

**It clears one of three independent gates.** Auto-approving is not the only check between a
tool call and execution:

| Gate | How it looks | Cleared here? |
|---|---|---|
| Permission prompt | "Do you want to allow…?" | **Yes** |
| Managed `permissions.deny` | Refused, no buttons | **No** — deny beats a hook allow |
| Sandbox / execution policy | `Enterprise policy requires sandboxing…` | **No** — runs *after* approval |

If your org enforces sandboxing, this hook cannot help with it — that error isn't a permission
decision and nothing renders a button to click.

**The self-protection is a speed bump, not a boundary.** Writes to the tool's own files prompt,
but any agent could rewrite them through `node -e "fs.writeFileSync(...)"`, which no path rule
inspects. The value is that a deliberate change to the guardrails leaves a prompt and a log
line. Treat the audit log, not the globs, as the security property.

**A blocklist can only catch what someone enumerated.** The `suspicious` and `code` tiers exist
to match the *shape* of hostile actions rather than named commands, which helps but does not
close the gap. If you need a hard boundary, use `permissions.deny` — it beats any hook.

**Fail-open by design.** Any internal error exits 0 with no output, which Claude Code reads as
"no opinion" and shows the normal prompt. A bug degrades you to hand-approving; it can never
block a call or approve something by accident.

## License

MIT
