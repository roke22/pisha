// "pisha-server setup" and "pisha-server service": the server as a systemd
// service. They never load the server itself (nor read its options).

import { existsSync, readFileSync, rmSync } from 'node:fs'
import { homedir, platform } from 'node:os'
import { isAbsolute, join } from 'node:path'
import { parseEnv } from 'node:util'
import { setup } from './wizard.js'
import { locations, SERVICE } from './plan.js'
import * as sys from './system.js'

export async function runCommand(command, args) {
  return command === 'setup' ? setup(args) : service(args)
}

const SERVICE_USAGE = `Usage: pisha-server service [status | start | stop | restart | logs | remove]

The service "pisha-server setup" installed: a system one (run these with sudo)
or one of your user's.

  status    Whether it runs (the default)
  start, stop, restart
  logs      Follow its log (Ctrl+C to stop following)
  remove    Stop it and remove it: it no longer starts by itself. Its settings
            and its data are kept.
`
const ACTIONS = ['status', 'start', 'stop', 'restart', 'logs', 'remove']

function service(args) {
  const [action = 'status', ...rest] = args
  if (['help', '--help', '-h'].includes(action)) { process.stdout.write(SERVICE_USAGE); return 0 }
  if (rest.length || !ACTIONS.includes(action)) { process.stderr.write(SERVICE_USAGE); return 2 }
  const fail = (m, code = 1) => { process.stderr.write(`pisha-server service: ${m}\n`); return code }
  if (platform() !== 'linux' || !sys.systemTool('systemctl')) return fail('systemd is not here: the service is for Linux with systemd')

  const root = process.getuid?.() === 0
  const xdg = process.env.XDG_CONFIG_HOME
  const mine = locations({ root: false, configHome: xdg && isAbsolute(xdg) ? xdg : join(homedir(), '.config') })
  const system = locations({ root: true })
  // (Not root: its own service if it has one, else the system's, to look at.)
  const scope = root ? 'system' : existsSync(mine.unitFile) ? 'user' : 'system'
  const where = scope === 'user' ? mine : system
  if (!existsSync(where.unitFile)) return fail(`there is no service: install it with "pisha-server setup"${root ? '' : ' (or as root, for a system service)'}`)
  if (scope === 'system' && !root && action !== 'status' && action !== 'logs') return fail(`it is a system service: sudo env "PATH=$PATH" pisha-server service ${action}`)
  const f = scope === 'user' ? ['--user'] : []

  if (action === 'status') return sys.inherit('systemctl', [...f, 'status', SERVICE, '--no-pager'])
  if (action === 'logs') return sys.inherit('journalctl', [...f, '-u', SERVICE, '-n', '100', '-f'])
  if (action !== 'remove') return sys.inherit('systemctl', [...f, action, SERVICE])

  sys.inherit('systemctl', [...f, 'disable', '--now', SERVICE])
  rmSync(where.unitFile, { force: true })
  sys.inherit('systemctl', [...f, 'daemon-reload'])
  let dataDir = ''
  try { dataDir = parseEnv(readFileSync(where.envFile, 'utf8')).DATA_DIR ?? '' } catch {}
  process.stdout.write(`The service is removed: pisha-server no longer starts by itself.\nKept: its settings (${where.envFile})${dataDir ? ` and its data (${dataDir})` : ''}. "pisha-server setup" installs it again.\n`)
  return 0
}
