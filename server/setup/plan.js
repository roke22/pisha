// What "pisha-server setup" writes: the settings file and the systemd unit,
// as text. Nothing here touches the machine (see system.js), so the tests can
// check it whole.

import { parseEnv } from 'node:util'
import { join, isAbsolute } from 'node:path'
import { isDomain, isPublicUrl } from '../addresses/index.js'

export const SERVICE = 'pisha'
export const DEFAULT_PORT = 7787
export const DEDICATED_USER = 'pisha'
export const DEDICATED_DATA_DIR = '/var/lib/pisha'

// Where its files go: a system service when run as root, else one of the user's.
export function locations(ctx) {
  if (ctx.root) return { envFile: '/etc/pisha/pisha.env', unitFile: `/etc/systemd/system/${SERVICE}.service` }
  return { envFile: join(ctx.configHome, 'pisha', 'pisha.env'), unitFile: join(ctx.configHome, 'systemd', 'user', `${SERVICE}.service`) }
}

// --- checking what is typed ---------------------------------------------------

// (Each returns what is wrong, or '' when it is fine.)
export const checkDomain = v => isDomain(v) ? '' : 'not a domain name (like pisha.example.com)'
export const checkPublicUrl = v => isPublicUrl(v) && !/\/./.test(v.replace(/^https?:\/\//, '')) ? '' : 'expected https://host or https://host:port'
export const checkEmail = v => !v || /^[^\s@"'`$\\#]+@[^\s@"'`$\\#]+\.[^\s@"'`$\\#]+$/.test(v) ? '' : 'not an email address'
export const checkPort = v => /^\d+$/.test(String(v)) && Number(v) >= 1 && Number(v) <= 65535 ? '' : 'a port goes from 1 to 65535'
export const checkUserName = v => /^[a-z_][a-z0-9_-]{0,31}$/.test(v) ? (v === 'root' ? 'the server should not run as root' : '') : 'not a user name'
// (It goes into the settings file and the unit: nothing either would read as special.)
export const checkDataDir = v => !isAbsolute(v) ? 'it must be a full path (starting with /)'
  : /["'`$\\#%\x00-\x1f\x7f]/.test(v) ? 'it cannot have quotes, $, \\, # or %'
  : v.replace(/\/+$/, '') === '' ? 'not the root folder' : ''

// --- the settings file --------------------------------------------------------

// The settings setup decides. Others found in the file are kept as they were.
const MANAGED = ['PISHA_DOMAIN', 'ACME_EMAIL', 'PUBLIC_URL', 'HOST', 'PORT', 'TRUST_PROXY', 'DATA_DIR']

// What a settings file says: its values, which way it was set up, and the
// lines of the settings setup doesn't manage.
export function readSettings(text) {
  const values = parseEnv(text ?? '')
  const others = []
  for (const line of String(text ?? '').split('\n')) {
    const key = /^\s*(?:export\s+)?([A-Za-z_][A-Za-z0-9_]*)\s*=/.exec(line)?.[1]
    if (key && !MANAGED.includes(key)) others.push(line.trim())
  }
  const mode = values.PISHA_DOMAIN ? 'domain' : values.PUBLIC_URL ? 'proxy' : text ? 'local' : null
  return { values, others, mode }
}

// answers: { mode: 'domain' | 'proxy' | 'local', domain, acmeEmail, publicUrl, port, dataDir }
export function settingsFor(a) {
  const s = []
  if (a.mode === 'domain') {
    s.push(['PISHA_DOMAIN', a.domain])
    if (a.acmeEmail) s.push(['ACME_EMAIL', a.acmeEmail])
  } else {
    if (a.mode === 'proxy') s.push(['PUBLIC_URL', a.publicUrl.replace(/\/+$/, '')])
    s.push(['HOST', '127.0.0.1'], ['PORT', String(a.port)])
    if (a.mode === 'proxy') s.push(['TRUST_PROXY', '1'])
  }
  s.push(['DATA_DIR', a.dataDir])
  return s
}

// (Both systemd and Node read it: only values both read the same way.)
function envValue(v) {
  if (/^[A-Za-z0-9_@+=:,./-]+$/.test(v)) return v
  if (/["'`$\\#%\x00-\x1f\x7f]/.test(v)) throw new Error(`cannot write the value "${v}"`)
  return `"${v}"`
}

export function settingsText(settings, others = []) {
  return [
    '# pisha-server settings, written by "pisha-server setup".',
    '# Run it again to change them, or edit this file and then "pisha-server service restart".',
    '# "pisha-server --help" lists every setting (the Env names).',
    '',
    ...settings.map(([k, v]) => `${k}=${envValue(v)}`),
    ...(others.length ? ['', '# Other settings (kept from before)', ...others] : []),
    '',
  ].join('\n')
}

// --- the systemd unit -------------------------------------------------------------

// systemd: a quoted word, with % (specifiers) and $ (variables) escaped.
const sd = v => `"${String(v).replace(/\\/g, '\\\\').replace(/"/g, '\\"').replace(/%/g, '%%').replace(/\$/g, '$$$$')}"`

// Ports below 1024 need a privilege: with a domain, 80 and 443.
export const needsLowPorts = a => a.mode === 'domain' || Number(a.port) < 1024

// { root, runAs, envFile, nodePath, scriptPath, lowPorts }
export function unitText(u) {
  if (/[\s%"\\]/.test(u.envFile)) throw new Error(`cannot use the settings file ${u.envFile} (spaces, % or quotes in its path)`)
  return [
    '# Written by "pisha-server setup". Its settings are in the file below:',
    '# change them there (or run "pisha-server setup" again), not here.',
    '[Unit]',
    'Description=Pisha server',
    'Documentation=https://github.com/roke22/pisha',
    'After=network-online.target',
    'Wants=network-online.target',
    '',
    '[Service]',
    ...(u.root ? [`User=${u.runAs}`] : []),
    `EnvironmentFile=${u.envFile}`,
    `ExecStart=${sd(u.nodePath)} ${sd(u.scriptPath)}`,
    'Restart=on-failure',
    'RestartSec=5',
    '# (2: its settings are wrong; starting it again would not help.)',
    'RestartPreventExitStatus=2',
    ...(u.root ? [
      'NoNewPrivileges=true',
      'PrivateTmp=true',
      'ProtectSystem=full',
      ...(u.lowPorts ? ['# (Ports 80 and 443 without running as root.)', 'AmbientCapabilities=CAP_NET_BIND_SERVICE', 'CapabilityBoundingSet=CAP_NET_BIND_SERVICE'] : ['CapabilityBoundingSet=']),
    ] : []),
    '',
    '[Install]',
    `WantedBy=${u.root ? 'multi-user.target' : 'default.target'}`,
    '',
  ].join('\n')
}

// The user a unit written before runs as.
export const unitUser = text => /^User=(.+)$/m.exec(text ?? '')?.[1]?.trim() ?? null

// The address people open, from the settings.
export function dashboardUrl(a) {
  if (a.mode === 'domain') return `https://${a.domain}`
  if (a.mode === 'proxy') return a.publicUrl.replace(/\/+$/, '')
  return `http://127.0.0.1:${a.port}`
}
