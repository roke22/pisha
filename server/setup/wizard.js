// "pisha-server setup": asks how the server is reached, who runs it and where
// its data goes, then installs it as a systemd service and starts it.
//
// As root: a system service (/etc/systemd/system/pisha.service) that runs as
// another user, "pisha" by default. As anyone else: a service of that user.

import { createInterface } from 'node:readline/promises'
import { parseArgs } from 'node:util'
import { existsSync, mkdirSync, readdirSync, readFileSync, realpathSync, statSync } from 'node:fs'
import { homedir, networkInterfaces, platform, userInfo } from 'node:os'
import { isAbsolute, join, resolve } from 'node:path'
import { lookup } from 'node:dns/promises'
import { fileURLToPath } from 'node:url'
import * as plan from './plan.js'
import * as sys from './system.js'

const USAGE = `Usage: pisha-server setup [options]

Sets pisha-server up as a service that starts by itself, asking what it needs:
how people reach it (a domain with HTTPS built in, behind your reverse proxy, or
only this machine), which user runs it and where its data goes. Run it again to
change any of that. Linux, with systemd.

As root (or with sudo) it installs a system service that runs as another user:
one of its own, "pisha", by default. As any other user, a service of that user.

To answer without being asked (with --yes, nothing is asked):
  --domain <name>        HTTPS on this domain, its certificate from Let's Encrypt
  --acme-email <addr>    Contact address for Let's Encrypt (optional)
  --public-url <url>     Behind your reverse proxy, which people reach at this address
  --local                Only from this machine
  --port <n>             The port it listens on, behind a proxy or local (default ${plan.DEFAULT_PORT})
  --user <name>          The user that runs it (as root; "pisha" is created if missing)
  --data-dir <path>      Where its data goes
  --fresh                Don't copy the data of a server that ran before
  -y, --yes              Ask nothing: the options above, and the defaults for the rest
  --dry-run              Show what it would do, and change nothing
`

// What stops it, said to the user. (2: wrong use; 1: it didn't work.)
class Fail extends Error {
  constructor(message, code = 1) { super(message); this.code = code }
}

const SUDO = 'sudo env "PATH=$PATH" pisha-server'
const readOr = f => { try { return readFileSync(f, 'utf8') } catch { return null } }
const sleep = ms => new Promise(r => setTimeout(r, ms))

export async function setup(argv) {
  let opts
  try {
    opts = parseArgs({
      args: argv,
      options: {
        domain: { type: 'string' }, 'acme-email': { type: 'string' }, 'public-url': { type: 'string' },
        local: { type: 'boolean' }, port: { type: 'string' }, user: { type: 'string' }, 'data-dir': { type: 'string' },
        fresh: { type: 'boolean' }, yes: { type: 'boolean', short: 'y' }, 'dry-run': { type: 'boolean' }, help: { type: 'boolean', short: 'h' },
      },
    }).values
  } catch (err) {
    process.stderr.write(`pisha-server setup: ${err.message}\n\n${USAGE}`)
    return 2
  }
  if (opts.help) { process.stdout.write(USAGE); return 0 }
  const io = prompter(opts)
  try { return await wizard(opts, io) } catch (err) {
    if (!(err instanceof Fail)) throw err
    process.stderr.write(`\npisha-server setup: ${err.message}\n`)
    return err.code
  } finally { io.close() }
}

// --- asking ------------------------------------------------------------------------

function prompter(opts) {
  let rl = null
  const interactive = !opts.yes
  const say = (t = '') => process.stdout.write(t + '\n')
  // (Lines are queued: answers pasted at once are each kept for their question.)
  const lines = []
  let waiting = null
  let closed = false
  const cancel = () => { say('\nCancelled: nothing was changed.'); process.exit(130) }
  const open = () => {
    if (rl) return rl
    if (!process.stdin.isTTY) throw new Fail('this is not a terminal: pass --yes and the options (see pisha-server setup --help)', 2)
    rl = createInterface({ input: process.stdin, output: process.stdout })
    rl.on('line', l => { if (waiting) { const w = waiting; waiting = null; w(l) } else lines.push(l) })
    // (Every question comes before anything is changed.)
    rl.on('SIGINT', cancel)
    rl.on('close', () => { closed = true; if (waiting) cancel() })
    return rl
  }
  const question = prompt => {
    const r = open()
    r.setPrompt(prompt)
    r.prompt()
    if (lines.length) { const l = lines.shift(); process.stdout.write(l + '\n'); return Promise.resolve(l) }
    if (closed) cancel()
    return new Promise(resolve => { waiting = resolve })
  }
  return {
    say,
    // A value: the option given, else the default (with --yes), else asked until it is right.
    async ask(label, { def = '', check = () => '', given, flag }) {
      if (given !== undefined) {
        const why = check(given)
        if (why) throw new Fail(`--${flag} ${given}: ${why}`, 2)
        return given
      }
      if (!interactive) {
        const why = check(def)
        if (why) throw new Fail(def === '' ? `pass --${flag}` : `--${flag}: ${why}`, 2)
        return def
      }
      for (;;) {
        const v = (await question(`${label}${def ? ` [${def}]` : ''}: `)).trim() || def
        const why = check(v)
        if (!why) return v
        say(`  ${why}`)
      }
    },
    // One of the options' keys. options: [{ key, text, unavailable? }]
    async choose(label, options, def) {
      if (!interactive) return def
      say(label)
      options.forEach((o, i) => say(`  ${i + 1}) ${o.text}${o.unavailable ? `\n     (not here: ${o.unavailable})` : ''}`))
      const at = Math.max(0, options.findIndex(o => o.key === def))
      for (;;) {
        const v = (await question(`Choose [${at + 1}]: `)).trim() || String(at + 1)
        const o = /^\d+$/.test(v) ? options[Number(v) - 1] : null
        if (o && !o.unavailable) return o.key
        say(o ? `  not here: ${o.unavailable}` : `  a number from 1 to ${options.length}`)
      }
    },
    async confirm(label) {
      if (!interactive) return true
      for (;;) {
        const v = (await question(`${label} [Y/n]: `)).trim().toLowerCase()
        if (!v || v === 'y' || v === 'yes') return true
        if (v === 'n' || v === 'no') return false
      }
    },
    // Wait for the user to do something. (With --yes there is nobody to wait for.)
    async pause(label, why) {
      if (!interactive) throw new Fail(why)
      await question(`${label} `)
    },
    close() { rl?.close() },
  }
}

// --- where it runs ----------------------------------------------------------------

function context() {
  const root = process.getuid?.() === 0
  const me = userInfo()
  const sudoName = root ? process.env.SUDO_USER : null
  const xdg = process.env.XDG_CONFIG_HOME
  return {
    root,
    user: me.username,
    // (sudo may keep the caller's HOME: root's own, from the system.)
    home: root ? me.homedir : homedir(),
    sudoUser: sudoName && sudoName !== 'root' ? sys.lookupUser(sudoName) : null,
    configHome: xdg && isAbsolute(xdg) ? xdg : join(homedir(), '.config'),
    nodePath: process.execPath,
    scriptPath: realpathSync(fileURLToPath(new URL('../server.js', import.meta.url))),
  }
}

async function checkDns(domain, io) {
  let found = []
  try { found = (await lookup(domain, { all: true })).map(r => r.address) } catch {}
  const mine = Object.values(networkInterfaces()).flat().filter(i => i && !i.internal).map(i => i.address)
  if (!found.length) io.say(`  ⚠️  ${domain} doesn't resolve yet. Point it to this server (an A or AAAA record): the certificate needs it.`)
  else if (found.some(a => mine.includes(a))) io.say(`  ${domain} points to this machine (${found.join(', ')}).`)
  else io.say(`  ${domain} points to ${found.join(', ')}, and this machine has ${mine.join(', ') || 'no other address'}.\n  Behind NAT (most cloud servers) that is fine; if not, fix the DNS record.`)
}

// --- the questions ----------------------------------------------------------------

async function wizard(opts, io) {
  const dry = !!opts['dry-run']
  if (platform() !== 'linux') throw new Fail('it installs a systemd service, so Linux only. Elsewhere, run pisha-server in a terminal or with Docker.', 2)
  if (!sys.hasSystemd() && !dry) throw new Fail('systemd is not running here (in a container, or WSL without systemd?): run pisha-server by hand, or with Docker.', 2)
  if ([opts.domain, opts['public-url'], opts.local].filter(Boolean).length > 1) throw new Fail('--domain, --public-url and --local: only one of them', 2)
  const ctx = context()
  if (/[\\/]_npx[\\/]/.test(ctx.scriptPath) && !dry) {
    throw new Fail(`this pisha-server runs from npx's cache, which npm may empty: a service can't start it from there.\nInstall it, then run setup from it:\n\n  npm install -g pisha-server\n  pisha-server setup${ctx.root ? '' : `            (or, for a system service: ${SUDO} setup)`}\n`, 2)
  }
  const scope = ctx.root ? 'system' : 'user'
  const where = plan.locations(ctx)
  const before = plan.readSettings(readOr(where.envFile))
  const beforeUser = plan.unitUser(readOr(where.unitFile))
  const installed = existsSync(where.unitFile)

  io.say('Pisha server setup')
  io.say(ctx.root
    ? `  As root: a system service (${where.unitFile}) that starts with the machine.`
    : `  As ${ctx.user}: a service of your user (${where.unitFile}).\n  For a system service that starts with the machine, run it as root: ${SUDO} setup`)
  if (installed) io.say('  It is set up already: what you choose now replaces it (Enter keeps each value).')
  io.say()

  if (!ctx.root && !dry && !await sys.userSessionOk()) {
    throw new Fail(`there is no systemd session of ${ctx.user} here. Log in as ${ctx.user} directly (ssh, not su), or run setup as root for a system service: ${SUDO} setup`)
  }

  // How it is reached.
  const lowPorts = ctx.root || sys.unprivilegedPortStart() <= 80
  const a = {}
  a.mode = opts.domain ? 'domain' : opts['public-url'] ? 'proxy' : opts.local ? 'local' : await io.choose('How will people reach the dashboard?', [
    { key: 'domain', text: 'With a domain: HTTPS built in, its certificate from Let\'s Encrypt (needs ports 80 and 443)', unavailable: lowPorts ? '' : `ports 80 and 443 need root: run ${SUDO} setup, or use a reverse proxy` },
    { key: 'proxy', text: 'Behind a reverse proxy you already have (nginx, Caddy, Traefik…), which does the HTTPS' },
    { key: 'local', text: 'Only from this machine (http://127.0.0.1), or through an SSH tunnel' },
  ], before.mode ?? (lowPorts ? 'domain' : 'proxy'))
  if (!a.mode || (opts.yes && !before.mode && !opts.domain && !opts['public-url'] && !opts.local)) throw new Fail('pass --domain, --public-url or --local', 2)
  if (a.mode === 'domain' && !lowPorts) throw new Fail(`ports 80 and 443 need root: run ${SUDO} setup, or use a reverse proxy (--public-url)`, 2)

  if (a.mode === 'domain') {
    a.domain = (await io.ask('Domain', { def: before.values.PISHA_DOMAIN ?? '', check: v => plan.checkDomain(v.toLowerCase()), given: opts.domain, flag: 'domain' })).toLowerCase()
    await checkDns(a.domain, io)
    a.acmeEmail = await io.ask('Email for Let\'s Encrypt (optional, for notices about the certificate)', { def: before.values.ACME_EMAIL ?? '', check: plan.checkEmail, given: opts['acme-email'], flag: 'acme-email' })
  }
  if (a.mode === 'proxy') {
    a.publicUrl = (await io.ask('Address people will open (your proxy\'s, like https://pisha.example.com)', { def: before.values.PUBLIC_URL ?? '', check: plan.checkPublicUrl, given: opts['public-url'], flag: 'public-url' })).replace(/\/+$/, '')
  }
  if (a.mode !== 'domain') {
    const def = before.mode === 'proxy' || before.mode === 'local' ? before.values.PORT ?? String(plan.DEFAULT_PORT) : String(plan.DEFAULT_PORT)
    a.port = Number(await io.ask('Port it listens on, on 127.0.0.1', { def, check: v => plan.checkPort(v) || (Number(v) < 1024 && !lowPorts ? 'below 1024 needs root' : ''), given: opts.port, flag: 'port' }))
  }

  // Who runs it.
  let runAs
  if (ctx.root) {
    const dedicated = sys.lookupUser(plan.DEDICATED_USER)
    const options = [{ key: plan.DEDICATED_USER, text: `A user of its own, "${plan.DEDICATED_USER}"${dedicated ? '' : ' (created now)'}: it only reaches its own data (recommended)` }]
    if (ctx.sudoUser) options.push({ key: ctx.sudoUser.name, text: `You, "${ctx.sudoUser.name}": it can use what is installed in your home (Node with nvm) and your ~/.pisha` })
    if (beforeUser && !options.some(o => o.key === beforeUser)) options.push({ key: beforeUser, text: `"${beforeUser}", as now` })
    options.push({ key: '', text: 'Another user (you type its name)' })
    let name = opts.user ?? await io.choose('Which user runs it?', options, beforeUser ?? plan.DEDICATED_USER)
    if (name === '') name = await io.ask('User name', { check: v => plan.checkUserName(v) || (sys.lookupUser(v) ? '' : 'there is no such user'), flag: 'user' })
    const why = plan.checkUserName(name)
    if (why) throw new Fail(`--user ${name}: ${why}`, 2)
    const found = sys.lookupUser(name)
    if (!found && name !== plan.DEDICATED_USER) throw new Fail(`there is no user "${name}"`, 2)
    if (found?.uid === 0) throw new Fail('the server should not run as root', 2)
    runAs = found ? { ...found, create: false } : { name, create: true }
  } else {
    runAs = { ...(sys.lookupUser(ctx.user) ?? { name: ctx.user, uid: process.getuid(), gid: process.getgid() }), home: ctx.home, create: false }
  }

  // It must be able to run node and the server: a node installed in someone's home (nvm) can't be run by another user.
  const cannot = !ctx.root || runAs.name === ctx.user ? '' : runAs.create ? sys.othersCanRun(ctx.nodePath, ctx.scriptPath) : sys.canRunAs(runAs.name, ctx.nodePath, ctx.scriptPath)
  if (cannot) {
    throw new Fail(`"${runAs.name}" can't run ${ctx.nodePath} with ${ctx.scriptPath} (${cannot}).\nNode is probably installed in a home folder (nvm). Either install Node.js for the whole system (your distribution's package, or NodeSource) and pisha-server with its npm, or choose a user that can run this one${ctx.sudoUser ? ` (you, "${ctx.sudoUser.name}")` : ''}.`)
  }

  // Where its data goes.
  const sameUser = ctx.root ? runAs.name === beforeUser : true
  const defData = (sameUser && before.values.DATA_DIR) || (ctx.root && runAs.name === plan.DEDICATED_USER ? plan.DEDICATED_DATA_DIR : join(runAs.home ?? plan.DEDICATED_DATA_DIR, '.pisha'))
  a.dataDir = resolve(await io.ask('Folder for its data', { def: defData, check: plan.checkDataDir, given: opts['data-dir'], flag: 'data-dir' }))
  const hasData = d => existsSync(join(d, 'pisha.db'))
  if (existsSync(a.dataDir) && !hasData(a.dataDir)) {
    let empty = false
    try { empty = statSync(a.dataDir).isDirectory() && readdirSync(a.dataDir).length === 0 } catch {}
    if (!empty) throw new Fail(`${a.dataDir} has other things in it, and no server data: choose an empty or new folder`, 2)
  }

  // The data of a server that ran before (started by hand, as root or as you).
  let copyFrom = null
  if (!hasData(a.dataDir) && !opts.fresh) {
    const seen = [join(ctx.home, '.pisha'), ctx.sudoUser && join(ctx.sudoUser.home, '.pisha'), runAs.home && join(runAs.home, '.pisha'), before.values.DATA_DIR]
    const found = [...new Set(seen.filter(Boolean).map(d => resolve(d)))].filter(d => d !== a.dataDir && hasData(d))
    if (found.length === 1) {
      if (await io.confirm(`Found the data of a server that ran before, in ${found[0]}.\nCopy it to ${a.dataDir}? (Its owners, machines and teams come along; the old folder is left as it is.\nIf not, it starts empty, with a new server token.)`)) copyFrom = found[0]
    } else if (found.length > 1) {
      copyFrom = await io.choose('Found the data of servers that ran before. Copy one of them?', [...found.map(d => ({ key: d, text: d })), { key: null, text: 'None: start empty, with a new server token' }], found[0])
    }
  }

  const settings = plan.settingsFor(a)
  const envText = plan.settingsText(settings, before.others)
  const unit = plan.unitText({ root: ctx.root, runAs: runAs.name, envFile: where.envFile, nodePath: ctx.nodePath, scriptPath: ctx.scriptPath, lowPorts: plan.needsLowPorts(a) })

  // Nothing else may be using its data or its ports: a server started by hand, most likely.
  const blockers = async () => {
    const own = installed ? sys.mainPid(scope) : 0
    const pids = [...new Set([copyFrom, a.dataDir].filter(Boolean).flatMap(d => sys.processesUsing(join(d, 'pisha.db'))))].filter(p => p !== own)
    const out = pids.length ? [`a pisha-server is running on that data (process ${pids.join(', ')}): stop it (Ctrl+C in its terminal, or kill ${pids.join(' ')}), and the service takes over`] : []
    if (!own) {
      for (const p of a.mode === 'domain' ? [443, 80] : [a.port]) {
        if (await sys.portInUse(p)) out.push(`port ${p} is in use${a.mode === 'domain' ? ' (a web server already there? then choose "behind a reverse proxy")' : ' (a pisha-server started by hand?)'}`)
      }
    }
    return out
  }
  for (let left = await blockers(); left.length; left = await blockers()) {
    io.say()
    for (const b of left) io.say(`  ⚠️  ${b}`)
    if (dry) break
    await io.pause('Press Enter once it is free (Ctrl+C to stop here).', left.join('; '))
  }

  const steps = [
    ...(runAs.create ? [`create the user "${runAs.name}" (a system user, without login)`] : []),
    ...(copyFrom ? [`copy ${copyFrom} to ${a.dataDir}`] : hasData(a.dataDir) ? [] : [`create ${a.dataDir}`]),
    ...(ctx.root ? [`give ${a.dataDir} to "${runAs.name}"`] : []),
    `write ${where.envFile}`,
    `write ${where.unitFile}${ctx.root ? ` (it runs as "${runAs.name}")` : ''}`,
    `enable the service "${plan.SERVICE}" and ${installed ? 'restart' : 'start'} it`,
  ]
  io.say(opts.yes ? 'It will:' : '\nIt will:')
  for (const s of steps) io.say(`  • ${s}`)
  if (dry) {
    io.say(`\n--- ${where.envFile}\n${envText}\n--- ${where.unitFile}\n${unit}\n(--dry-run: nothing was changed)`)
    return 0
  }
  io.say()
  if (!await io.confirm('Go ahead?')) { io.say('Nothing was changed.'); return 1 }

  // --- doing it ---
  if (runAs.create) {
    runAs = { ...sys.lookupUser(runAs.name) ?? await sys.createSystemUser(runAs.name, a.dataDir), create: false }
    const why = sys.canRunAs(runAs.name, ctx.nodePath, ctx.scriptPath)
    if (why) throw new Fail(`"${runAs.name}" was created but can't run ${ctx.nodePath} (${why})`)
  }
  mkdirSync(a.dataDir, { recursive: true, mode: 0o700 })
  if (copyFrom) sys.copyData(copyFrom, a.dataDir)
  if (ctx.root) sys.chownTree(a.dataDir, runAs.uid, runAs.gid)
  const tokenFile = join(a.dataDir, 'server-token')
  const hadToken = existsSync(tokenFile)
  sys.writeFileAtomic(where.envFile, envText, 0o600)
  sys.writeFileAtomic(where.unitFile, unit, 0o644)
  await sys.systemctl(scope, ['daemon-reload'])
  await sys.systemctl(scope, ['enable', plan.SERVICE])
  await sys.systemctl(scope, ['restart', plan.SERVICE])

  // Running? It answers on its port. (With a domain, port 80 first: HTTPS
  // only opens once it has its certificate, which may take a while.)
  io.say('\nStarting…')
  const httpPort = Number(before.values.HTTP_PORT ?? 80)
  let ok = false
  for (let i = 0; i < 40 && !ok; i++) {
    await sleep(500)
    if (sys.serviceState(scope) === 'failed') break
    if (a.mode === 'domain') ok = await sys.portInUse(httpPort)
    else { try { ok = (await fetch(`http://127.0.0.1:${a.port}/health`, { signal: AbortSignal.timeout(1000) })).ok } catch {} }
  }
  let certificate = false
  if (ok && a.mode === 'domain') {
    io.say(`Getting its certificate for ${a.domain}…`)
    for (let i = 0; i < 60 && !certificate; i++) { certificate = await sys.portInUse(443); if (!certificate) await sleep(1000) }
  }
  const logs = `journalctl${ctx.root ? '' : ' --user'} -u ${plan.SERVICE} -f`
  if (!ok) {
    io.say(`\nThe service didn't start well. Its last lines:\n\n${sys.recentLog(scope) || '(nothing)'}\n\nMore with: ${logs}`)
    return 1
  }

  const linger = ctx.root || await sys.ensureLinger(ctx.user)
  const url = plan.dashboardUrl(a)
  let token = ''
  if (!hadToken) { try { token = readFileSync(tokenFile, 'utf8').trim() } catch {} }
  io.say(`\nPisha is running as the service "${plan.SERVICE}"${ctx.root ? `, as the user "${runAs.name}"` : ''}.\n`)
  io.say(`  Dashboard:  ${url}`)
  if (a.mode === 'domain' && !certificate) {
    const why = sys.recentLog(scope, 50).split('\n').reverse().find(l => l.includes('could not get a certificate'))
    io.say(`  ⚠️  It has no certificate yet, and keeps trying. Check that ${a.domain} points here and that\n      ports 80 and 443 are open to the internet.${why ? `\n      Last try: ${why.replace(/^pisha-server: /, '')}` : ''}`)
  }
  if (token) io.say(`  Server token, to create the first owner (shown only now): ${token}`)
  else io.say(`  Server token: in ${tokenFile}${ctx.root ? ` (sudo cat ${tokenFile})` : ''}`)
  io.say(`  Settings:   ${where.envFile} (run "pisha-server setup" again to change them)`)
  io.say(`  Data:       ${a.dataDir} (back it up: it holds the server key)`)
  io.say(`  Log:        ${logs}`)
  io.say(`  Service:    pisha-server service status | restart | stop | logs | remove${ctx.root ? ' (with sudo)' : ''}`)
  if (a.mode === 'domain') io.say('\n  Ports 80 and 443 must be open to the internet (in the firewall, and your cloud\'s, if any).')
  if (a.mode === 'proxy') io.say(`\n  Point your proxy at http://127.0.0.1:${a.port}, passing WebSockets through (the web terminal uses them).`)
  if (a.mode === 'local') io.say(`\n  From another computer: ssh -L ${a.port}:127.0.0.1:${a.port} this-server, then open ${url}`)
  if (!linger) io.say(`\n  It runs while you are logged in. To keep it running always: sudo loginctl enable-linger ${ctx.user}`)
  if (copyFrom) io.say(`\n  Your data was copied from ${copyFrom}, which is left as it was: delete it once you have checked all is well.`)
  io.say('\n  To update: npm install -g pisha-server@latest, then pisha-server service restart.')
  return 0
}
