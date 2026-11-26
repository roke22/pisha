// "pisha-server setup": the settings file and the systemd unit it writes, what
// it accepts, what it shows with --dry-run, and the server reading its settings
// from a file with --config. (Installing the service itself needs root and
// systemd: that was tried by hand in a container, see the pull request.)
//
// Run: node --test test/setup.test.mjs

import { test } from 'node:test'
import assert from 'node:assert/strict'
import { spawn, spawnSync } from 'node:child_process'
import { existsSync, mkdirSync, writeFileSync } from 'node:fs'
import { join, dirname } from 'node:path'
import { platform } from 'node:os'
import { fileURLToPath } from 'node:url'
import { parseEnv } from 'node:util'
import * as plan from '../server/setup/plan.js'
import { tempDir } from './tempdirs.mjs'
import { freePort } from './ports.mjs'

const ROOT = join(dirname(fileURLToPath(import.meta.url)), '..')
const SERVER = join(ROOT, 'server', 'server.js')
const sleep = ms => new Promise(r => setTimeout(r, ms))

test('setup: the settings for each way of reaching it', () => {
  const domain = plan.settingsFor({ mode: 'domain', domain: 'pisha.example.com', acmeEmail: 'me@example.com', dataDir: '/var/lib/pisha' })
  assert.deepEqual(domain, [['PISHA_DOMAIN', 'pisha.example.com'], ['ACME_EMAIL', 'me@example.com'], ['DATA_DIR', '/var/lib/pisha']])
  const proxy = plan.settingsFor({ mode: 'proxy', publicUrl: 'https://pisha.example.com/', port: 7787, dataDir: '/srv/pisha' })
  assert.deepEqual(Object.fromEntries(proxy), { PUBLIC_URL: 'https://pisha.example.com', HOST: '127.0.0.1', PORT: '7787', TRUST_PROXY: '1', DATA_DIR: '/srv/pisha' })
  const local = plan.settingsFor({ mode: 'local', port: 8000, dataDir: '/srv/pisha' })
  assert.deepEqual(Object.fromEntries(local), { HOST: '127.0.0.1', PORT: '8000', DATA_DIR: '/srv/pisha' })
  assert.equal(plan.needsLowPorts({ mode: 'domain' }), true)
  assert.equal(plan.needsLowPorts({ mode: 'local', port: 7787 }), false)
  assert.equal(plan.needsLowPorts({ mode: 'proxy', port: 443 }), true)
})

test('setup: the settings file reads back the same, keeps the settings it does not manage, and drops the ones of another mode', () => {
  const before = plan.settingsText(plan.settingsFor({ mode: 'domain', domain: 'a.example.com', dataDir: '/data with space' }), [])
  const read = plan.readSettings(`${before}PISHA_MAX_EVENTS=5000\nexport PISHA_GITHUB_API="https://ghe.example.com/api"\n`)
  assert.equal(read.mode, 'domain')
  assert.equal(read.values.DATA_DIR, '/data with space')
  assert.deepEqual(read.others, ['PISHA_MAX_EVENTS=5000', 'export PISHA_GITHUB_API="https://ghe.example.com/api"'])
  const after = plan.settingsText(plan.settingsFor({ mode: 'proxy', publicUrl: 'https://b.example.com', port: 7787, dataDir: '/srv/pisha' }), read.others)
  const values = parseEnv(after)
  assert.equal(values.PISHA_DOMAIN, undefined)
  assert.equal(values.PUBLIC_URL, 'https://b.example.com')
  assert.equal(values.PISHA_MAX_EVENTS, '5000')
  assert.equal(values.PISHA_GITHUB_API, 'https://ghe.example.com/api')
  assert.equal(plan.readSettings(null).mode, null)
  assert.equal(plan.readSettings('HOST=127.0.0.1\n').mode, 'local')
  // (Nothing systemd or Node would read differently.)
  assert.throws(() => plan.settingsText([['DATA_DIR', '/a"b']]), /cannot write/)
  assert.throws(() => plan.settingsText([['DATA_DIR', '/a$HOME']]), /cannot write/)
})

test('setup: what it accepts', () => {
  assert.equal(plan.checkDomain('pisha.example.com'), '')
  for (const bad of ['localhost', 'pisha..com', '-x.com', 'a b.com', 'x.com;rm']) assert.notEqual(plan.checkDomain(bad), '', bad)
  assert.equal(plan.checkPublicUrl('https://pisha.example.com'), '')
  assert.equal(plan.checkPublicUrl('https://pisha.example.com:8443/'), '')
  for (const bad of ['pisha.example.com', 'https://x.com/sub/path', 'https://x.com$(id)', 'ftp://x.com']) assert.notEqual(plan.checkPublicUrl(bad), '', bad)
  assert.equal(plan.checkEmail(''), '')
  assert.equal(plan.checkEmail('me@example.com'), '')
  assert.notEqual(plan.checkEmail('me@example'), '')
  assert.notEqual(plan.checkEmail('me$x@example.com'), '')
  assert.equal(plan.checkPort('7787'), '')
  for (const bad of ['0', '65536', 'x', '-1', '80.5']) assert.notEqual(plan.checkPort(bad), '', bad)
  assert.equal(plan.checkUserName('pisha'), '')
  assert.notEqual(plan.checkUserName('root'), '')
  assert.notEqual(plan.checkUserName('a;b'), '')
  assert.equal(plan.checkDataDir('/var/lib/pisha'), '')
  for (const bad of ['relative/dir', '/', '//', '/a$b', '/a%b', '/a"b', '/a\nb']) assert.notEqual(plan.checkDataDir(bad), '', JSON.stringify(bad))
})

test('setup: the unit, as a system service and as a user one', () => {
  const where = plan.locations({ root: true })
  assert.deepEqual(where, { envFile: '/etc/pisha/pisha.env', unitFile: '/etc/systemd/system/pisha.service' })
  const system = plan.unitText({ root: true, runAs: 'pisha', envFile: where.envFile, nodePath: '/usr/bin/node', scriptPath: '/usr/lib/node_modules/pisha-server/server.js', lowPorts: true })
  assert.match(system, /^User=pisha$/m)
  assert.match(system, /^EnvironmentFile=\/etc\/pisha\/pisha\.env$/m)
  assert.match(system, /^ExecStart="\/usr\/bin\/node" "\/usr\/lib\/node_modules\/pisha-server\/server\.js"$/m)
  assert.match(system, /^AmbientCapabilities=CAP_NET_BIND_SERVICE$/m)
  assert.match(system, /^RestartPreventExitStatus=2$/m)
  assert.match(system, /^WantedBy=multi-user\.target$/m)
  assert.equal(plan.unitUser(system), 'pisha')
  const plain = plan.unitText({ root: true, runAs: 'ana', envFile: where.envFile, nodePath: '/usr/bin/node', scriptPath: '/s.js', lowPorts: false })
  assert.doesNotMatch(plain, /AmbientCapabilities/)
  assert.match(plain, /^CapabilityBoundingSet=$/m)

  const mine = plan.locations({ root: false, configHome: '/home/ana/.config' })
  assert.deepEqual(mine, { envFile: '/home/ana/.config/pisha/pisha.env', unitFile: '/home/ana/.config/systemd/user/pisha.service' })
  const user = plan.unitText({ root: false, runAs: 'ana', envFile: mine.envFile, nodePath: '/home/ana/.nvm/v22/bin/node', scriptPath: '/home/ana/%h $x/server.js', lowPorts: false })
  assert.doesNotMatch(user, /^User=/m)
  assert.match(user, /^WantedBy=default\.target$/m)
  // (% and $ in a path are not systemd's specifiers or variables.)
  assert.match(user, /^ExecStart="\/home\/ana\/\.nvm\/v22\/bin\/node" "\/home\/ana\/%%h \$\$x\/server\.js"$/m)
  assert.throws(() => plan.unitText({ root: false, runAs: 'ana', envFile: '/home/a b/pisha.env', nodePath: '/n', scriptPath: '/s' }), /cannot use the settings file/)
})

const setupCli = (args, home) => spawnSync(process.execPath, [SERVER, 'setup', ...args], {
  encoding: 'utf8',
  env: { ...process.env, HOME: home, XDG_CONFIG_HOME: join(home, '.config') },
  stdio: ['ignore', 'pipe', 'pipe'],
})

test('setup --dry-run: says what it would write and changes nothing', { skip: platform() !== 'linux' || process.getuid?.() === 0 ? 'Linux, as a user that is not root' : false }, () => {
  const home = tempDir('pisha-setup-home-')
  const r = setupCli(['--dry-run', '--yes', '--public-url', 'https://pisha.example.com', '--port', '7799'], home)
  assert.equal(r.status, 0, r.stderr)
  assert.match(r.stdout, /PUBLIC_URL=https:\/\/pisha\.example\.com\nHOST=127\.0\.0\.1\nPORT=7799\nTRUST_PROXY=1\n/)
  assert.ok(r.stdout.includes(`DATA_DIR=${join(home, '.pisha')}`))
  assert.ok(r.stdout.includes(`ExecStart="${process.execPath}" "${SERVER}"`))
  assert.match(r.stdout, /nothing was changed/)
  assert.ok(!existsSync(join(home, '.config')), 'nothing written')
  assert.ok(!existsSync(join(home, '.pisha')), 'no data folder')

  // The data of a server that ran before (in ~/.pisha) is offered; with --yes, taken.
  mkdirSync(join(home, '.pisha'), { recursive: true })
  writeFileSync(join(home, '.pisha', 'pisha.db'), '')
  const moved = setupCli(['--dry-run', '--yes', '--local', '--data-dir', join(home, 'srv', 'pisha')], home)
  assert.equal(moved.status, 0, moved.stderr)
  assert.ok(moved.stdout.includes(`copy ${join(home, '.pisha')} to ${join(home, 'srv', 'pisha')}`), moved.stdout)
  assert.ok(!setupCli(['--dry-run', '--yes', '--fresh', '--local', '--data-dir', join(home, 'srv', 'pisha')], home).stdout.includes('copy '), '--fresh: not copied')
  // (Nor a folder with other things in it.)
  const wrong = setupCli(['--dry-run', '--yes', '--local', '--data-dir', home], home)
  assert.equal(wrong.status, 2)
  assert.match(wrong.stderr, /has other things in it/)

  // Without a way of being reached, or with two, or a user server on port 443.
  assert.match(setupCli(['--dry-run', '--yes'], home).stderr, /pass --domain, --public-url or --local/)
  assert.match(setupCli(['--dry-run', '--yes', '--local', '--domain', 'a.example.com'], home).stderr, /only one of them/)
  assert.match(setupCli(['--dry-run', '--yes', '--public-url', 'https://x.example.com/a/b'], home).stderr, /expected https:\/\/host/)
  assert.equal(setupCli(['--bogus'], home).status, 2)
  // (Asking needs a terminal.)
  assert.match(setupCli(['--dry-run', '--local'], home).stderr, /not a terminal/)
})

test('service: without one installed, says how to install it', { skip: platform() !== 'linux' || process.getuid?.() === 0 ? 'Linux, as a user that is not root' : false }, t => {
  const home = tempDir('pisha-service-home-')
  if (existsSync('/etc/systemd/system/pisha.service')) return t.skip('this machine has a pisha service')
  const r = spawnSync(process.execPath, [SERVER, 'service', 'status'], { encoding: 'utf8', env: { ...process.env, HOME: home, XDG_CONFIG_HOME: join(home, '.config') } })
  assert.equal(r.status, 1)
  assert.match(r.stderr, /there is no service: install it with "pisha-server setup"/)
  assert.equal(spawnSync(process.execPath, [SERVER, 'service', 'explode'], { encoding: 'utf8' }).status, 2)
})

test('--config: the server reads its settings from a file, and the environment wins over it', async () => {
  const dir = tempDir('pisha-config-')
  const port = await freePort()
  const file = join(dir, 'pisha.env')
  writeFileSync(file, `# comment\nPORT=1\nDATA_DIR="${join(dir, 'data')}"\n`)
  const env = { ...process.env, PORT: String(port) }
  delete env.DATA_DIR
  const proc = spawn(process.execPath, [SERVER, '--config', file], { env, stdio: ['ignore', 'pipe', 'pipe'] })
  let said = ''
  proc.stderr.on('data', d => { said += d })
  try {
    let up = false
    for (let i = 0; i < 200 && !up; i++) { try { up = (await fetch(`http://127.0.0.1:${port}/health`)).ok } catch {} if (!up) await sleep(50) }
    assert.ok(up, `it answers on the port of the environment: ${said.slice(-800)}`)
    assert.ok(existsSync(join(dir, 'data', 'pisha.db')), 'its data where the file says')
  } finally {
    proc.kill('SIGTERM')
    await new Promise(r => proc.on('exit', r))
  }
  const missing = spawnSync(process.execPath, [SERVER, `--config=${join(dir, 'nope.env')}`], { encoding: 'utf8' })
  assert.equal(missing.status, 2)
  assert.match(missing.stderr, /cannot read the settings in .*no such file/)
})
