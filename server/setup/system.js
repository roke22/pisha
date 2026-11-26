// What "pisha-server setup" does to the machine: users, folders, files and
// systemd. Linux only.

import { execFile, spawnSync } from 'node:child_process'
import { promisify } from 'node:util'
import { accessSync, constants as FS, chownSync, cpSync, existsSync, lstatSync, mkdirSync, readdirSync, readFileSync, readlinkSync, realpathSync, renameSync, statSync, writeFileSync } from 'node:fs'
import { connect } from 'node:net'
import { dirname, join } from 'node:path'
import { SERVICE } from './plan.js'

const run = promisify(execFile)

// System tools only from the system's own folders.
export const systemTool = name => ['/usr/bin', '/bin', '/usr/sbin', '/sbin'].map(d => join(d, name)).find(f => { try { accessSync(f, FS.X_OK); return true } catch { return false } }) ?? null

const firstLine = err => String(err?.stderr || err?.message || err).trim().split('\n')[0]

// { name, uid, gid, home } or null.
export function lookupUser(name) {
  let line = null
  const getent = systemTool('getent')
  if (getent) {
    const r = spawnSync(getent, ['passwd', name], { encoding: 'utf8', timeout: 10_000 })
    if (r.status === 0) line = r.stdout.trim().split('\n')[0]
  } else {
    try { line = readFileSync('/etc/passwd', 'utf8').split('\n').find(l => l.startsWith(`${name}:`)) ?? null } catch {}
  }
  const f = line?.split(':')
  return f && f.length >= 7 ? { name: f[0], uid: Number(f[2]), gid: Number(f[3]), home: f[5] } : null
}

export async function createSystemUser(name, home) {
  const useradd = systemTool('useradd')
  if (!useradd) throw new Error('useradd was not found: create the user by hand, then run this again')
  const shell = ['/usr/sbin/nologin', '/sbin/nologin', '/bin/false'].find(f => existsSync(f)) ?? '/bin/false'
  try { await run(useradd, ['--system', '--user-group', '--home-dir', home, '--no-create-home', '--shell', shell, name], { timeout: 30_000 }) } catch (err) {
    throw new Error(`could not create the user "${name}": ${firstLine(err)}`)
  }
  const u = lookupUser(name)
  if (!u) throw new Error(`the user "${name}" was created but cannot be found`)
  return u
}

// The folder and everything in it, for that user. (Links are changed, not followed.)
export function chownTree(dir, uid, gid) {
  chownSync(dir, uid, gid)
  for (const e of readdirSync(dir, { withFileTypes: true, recursive: true })) {
    const p = join(e.parentPath, e.name)
    try { if (lstatSync(p).isSymbolicLink()) continue } catch { continue }
    chownSync(p, uid, gid)
  }
}

export function copyData(from, to) {
  mkdirSync(to, { recursive: true, mode: 0o700 })
  cpSync(from, to, { recursive: true, errorOnExist: true, force: false, preserveTimestamps: true, verbatimSymlinks: true })
}

// Whole, or not at all: written beside it and moved into place.
export function writeFileAtomic(path, text, mode) {
  mkdirSync(dirname(path), { recursive: true, mode: 0o755 })
  const tmp = `${path}.${process.pid}.tmp`
  writeFileSync(tmp, text, { mode, flag: 'wx' })
  renameSync(tmp, path)
}

// The processes that have that file open (a server started by hand on that
// data). Only those this user may look into: all of them, for root.
export function processesUsing(file) {
  const pids = []
  let entries = []
  try { entries = readdirSync('/proc') } catch { return pids }
  for (const pid of entries) {
    if (!/^\d+$/.test(pid) || Number(pid) === process.pid) continue
    let fds = []
    try { fds = readdirSync(`/proc/${pid}/fd`) } catch { continue }
    for (const fd of fds) {
      try { if (readlinkSync(`/proc/${pid}/fd/${fd}`) === file) { pids.push(Number(pid)); break } } catch {}
    }
  }
  return pids
}

// Something answers on that port of this machine.
export const portInUse = port => new Promise(resolve => {
  const s = connect({ port, host: '127.0.0.1' })
  const done = v => { s.destroy(); resolve(v) }
  s.setTimeout(1500, () => done(false))
  s.once('connect', () => done(true))
  s.once('error', () => done(false))
})

// The lowest port a user may listen on without a privilege.
export function unprivilegedPortStart() {
  try { return Number(readFileSync('/proc/sys/net/ipv4/ip_unprivileged_port_start', 'utf8').trim()) } catch { return 1024 }
}

// Whether that user can run node and read the server (a node installed in
// root's home, with nvm, can't be run by anyone else). '' when it can, else why not.
export function canRunAs(user, nodePath, scriptPath) {
  const runuser = systemTool('runuser')
  if (!runuser) return ''
  const r = spawnSync(runuser, ['-u', user, '--', nodePath, '-e', 'require("node:fs").accessSync(process.argv[1], 4)', scriptPath], { encoding: 'utf8', timeout: 30_000, cwd: '/' })
  if (r.status === 0) return ''
  return firstLine({ stderr: r.stderr || r.error?.message || `exit ${r.status}` })
}

// The same for a user that doesn't exist yet: every folder on the way open to
// anyone, node runnable and the server readable by anyone. '' or what isn't.
export function othersCanRun(nodePath, scriptPath) {
  const open = (p, bit) => { try { return (statSync(p).mode & bit) !== 0 } catch { return false } }
  for (const [file, bit] of [[realpathSync(nodePath), 0o001], [realpathSync(scriptPath), 0o004]]) {
    for (let d = dirname(file); ; d = dirname(d)) {
      if (!open(d, 0o001)) return `${d} is closed to other users`
      if (d === '/') break
    }
    if (!open(file, bit)) return `${file} is closed to other users`
  }
  return ''
}

// --- systemd ---------------------------------------------------------------------

const scopeFlag = scope => scope === 'user' ? ['--user'] : []

export const hasSystemd = () => !!systemTool('systemctl') && existsSync('/run/systemd/system')

export async function systemctl(scope, args) {
  try { return (await run(systemTool('systemctl'), [...scopeFlag(scope), ...args], { timeout: 60_000 })).stdout.trim() } catch (err) {
    throw new Error(`systemctl ${args.join(' ')} failed: ${firstLine(err)}`)
  }
}

// What systemd says of the service: active, activating, failed, inactive…
export function serviceState(scope) {
  const r = spawnSync(systemTool('systemctl'), [...scopeFlag(scope), 'is-active', SERVICE], { encoding: 'utf8', timeout: 15_000 })
  return (r.stdout ?? '').trim() || 'unknown'
}

// A command shown to the user, with its output on their terminal. Its exit code.
export function inherit(tool, args) {
  const r = spawnSync(systemTool(tool), args, { stdio: 'inherit' })
  return r.status ?? 1
}

// The process the service runs now (0: none).
export function mainPid(scope) {
  const r = spawnSync(systemTool('systemctl'), [...scopeFlag(scope), 'show', '-p', 'MainPID', '--value', SERVICE], { encoding: 'utf8', timeout: 15_000 })
  return Number((r.stdout ?? '').trim()) || 0
}

export function recentLog(scope, lines = 20) {
  const journalctl = systemTool('journalctl')
  if (!journalctl) return ''
  const r = spawnSync(journalctl, [...scopeFlag(scope), '-u', SERVICE, '-n', String(lines), '--no-pager', '-o', 'cat'], { encoding: 'utf8', timeout: 15_000 })
  return (r.stdout ?? '').trim()
}

// A user service needs a systemd session of that user.
export async function userSessionOk() {
  try { await run(systemTool('systemctl'), ['--user', 'show-environment'], { timeout: 15_000 }); return true } catch { return false }
}

// Whether the user's services keep running while nobody is logged in; turned
// on if it can be (it may need an administrator).
export async function ensureLinger(user) {
  const loginctl = systemTool('loginctl')
  if (!loginctl) return false
  try { if (/Linger=yes/.test((await run(loginctl, ['show-user', user, '-p', 'Linger'], { timeout: 15_000 })).stdout)) return true } catch {}
  try { await run(loginctl, ['--no-ask-password', 'enable-linger', user], { timeout: 15_000 }); return true } catch { return false }
}
