#!/usr/bin/env node
/**
 * Installer for claude-autoapprove.
 *
 *   node install.mjs              install or update
 *   node install.mjs --force      also overwrite an existing rules file
 *   node install.mjs --uninstall  remove the hook registration (leaves files in place)
 *
 * What it touches, and nothing else:
 *   ~/.claude/tools/autoapprove.mjs         copied from this repo, always
 *   ~/.claude/tools/autoapprove.rules.json  copied only if absent, so your tuning survives
 *   ~/.claude/settings.json                 one hooks.PreToolUse entry, backed up first
 */
import { copyFileSync, existsSync, mkdirSync, readFileSync, writeFileSync } from 'node:fs'
import { spawnSync } from 'node:child_process'
import { homedir } from 'node:os'
import { dirname, join } from 'node:path'
import { fileURLToPath } from 'node:url'

const HOOK = 'autoapprove.mjs'
const RULES = 'autoapprove.rules.json'

const HERE = dirname(fileURLToPath(import.meta.url))
const CLAUDE = join(homedir(), '.claude')
const TOOLS = join(CLAUDE, 'tools')
const SETTINGS = join(CLAUDE, 'settings.json')

const FORCE = process.argv.includes('--force')
const UNINSTALL = process.argv.includes('--uninstall')

const ok = (m) => console.log(`  ✓ ${m}`)
const info = (m) => console.log(`    ${m}`)
const die = (m) => {
  console.error(`\n  ✗ ${m}\n`)
  process.exit(1)
}

/** Parse settings.json, or bail with something actionable. Never guess at its contents. */
function readSettings() {
  if (!existsSync(SETTINGS)) return {}
  const raw = readFileSync(SETTINGS, 'utf8').trim()
  if (!raw) return {}
  try {
    return JSON.parse(raw)
  } catch (e) {
    die(
      `${SETTINGS} is not valid JSON (${e.message}).\n` +
        `    Fix it, or register the hook by hand - see the README's "Manual install".`
    )
  }
}

/** Back up before touching a file that may hold an auth token. */
function backup() {
  if (!existsSync(SETTINGS)) return null
  const stamp = new Date().toISOString().replace(/[:.]/g, '-')
  const dest = `${SETTINGS}.bak-${stamp}`
  copyFileSync(SETTINGS, dest)
  return dest
}

function writeSettings(s) {
  writeFileSync(SETTINGS, `${JSON.stringify(s, null, 2)}\n`)
}

/** Any matcher group that mentions this tool, from any past install. */
const isOurs = (group) => JSON.stringify(group ?? {}).includes('autoapprove')

console.log(`\nclaude-autoapprove\n`)

if (UNINSTALL) {
  const s = readSettings()
  const groups = s?.hooks?.PreToolUse
  if (!Array.isArray(groups) || !groups.some(isOurs)) die('Not registered - nothing to remove.')
  const b = backup()
  s.hooks.PreToolUse = groups.filter((g) => !isOurs(g))
  if (s.hooks.PreToolUse.length === 0) delete s.hooks.PreToolUse
  if (Object.keys(s.hooks).length === 0) delete s.hooks
  writeSettings(s)
  ok(`Hook removed from ${SETTINGS}`)
  if (b) info(`backup: ${b}`)
  info(`Files left in ${TOOLS} - delete them by hand if you want them gone.`)
  console.log(`\n  Restart Claude Code for this to take effect.\n`)
  process.exit(0)
}

// 1. Copy the script, and the rules only if there is nothing to lose.
mkdirSync(TOOLS, { recursive: true })
copyFileSync(join(HERE, HOOK), join(TOOLS, HOOK))
ok(`${HOOK} -> ${TOOLS}`)

const rulesDest = join(TOOLS, RULES)
if (!existsSync(rulesDest) || FORCE) {
  copyFileSync(join(HERE, RULES), rulesDest)
  ok(`${RULES} -> ${TOOLS}`)
} else {
  ok(`${RULES} kept - your existing tuning was not overwritten`)
  info(`Use --force to replace it, or diff it against this repo's copy for new patterns.`)
}

// 2. Register the hook. Exec form (command + args) so no shell quoting is involved,
//    and process.execPath so the node binary is the exact one running this installer.
const settings = readSettings()
settings.hooks ??= {}
const groups = Array.isArray(settings.hooks.PreToolUse) ? settings.hooks.PreToolUse : []
const stale = groups.filter(isOurs).length

settings.hooks.PreToolUse = [
  ...groups.filter((g) => !isOurs(g)),
  {
    matcher: '', // every tool: main session, subagents, background agents
    hooks: [{ type: 'command', command: process.execPath, args: [join(TOOLS, HOOK)], timeout: 5 }],
  },
]

const b = backup()
writeSettings(settings)
ok(`${stale ? 'Updated' : 'Registered'} hooks.PreToolUse in ${SETTINGS}`)
if (b) info(`backup: ${b}`)

// 3. Prove it runs before claiming success.
const selftest = spawnSync(process.execPath, [join(TOOLS, HOOK), '--selftest'], { encoding: 'utf8' })
if (selftest.status !== 0 || !/passed/.test(selftest.stdout ?? '')) {
  die(`Selftest failed - the hook is registered but may misbehave.\n${selftest.stdout}${selftest.stderr}`)
}
ok(`Selftest: ${(selftest.stdout.match(/\d+\/\d+ passed/) ?? ['ok'])[0]}`)

const probe = spawnSync(process.execPath, [join(TOOLS, HOOK)], {
  input: JSON.stringify({ tool_name: 'Read', tool_input: { file_path: join(HERE, 'README.md') } }),
  encoding: 'utf8',
})
let decision
try {
  decision = JSON.parse(probe.stdout).hookSpecificOutput?.permissionDecision
} catch {
  /* fall through to the check below */
}
if (decision !== 'allow') {
  die(`The hook did not approve a plain file read. Output was:\n${probe.stdout}${probe.stderr}`)
}
ok(`Smoke test: an ordinary Read was auto-approved`)

console.log(`
  Restart Claude Code so it picks up the new hook.

  Then:
    node ${join(TOOLS, HOOK)} --stats     what it has been deciding
    node ${join(TOOLS, HOOK)} --replay    re-decide your history, find false positives

  Add your code directory to "roots" in ${rulesDest}
  if you work outside your git repos - writes landing outside every root will ask.
`)
