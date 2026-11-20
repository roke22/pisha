// A port nobody is using right now, chosen by the system. Test files run at
// once: ranges picked at random could meet, and then one file's checks would
// talk to another file's server.

import { createServer } from 'node:net'

export function freePort() {
  return new Promise((resolve, reject) => {
    const s = createServer()
    s.on('error', reject)
    s.listen(0, '127.0.0.1', () => { const { port } = s.address(); s.close(() => resolve(port)) })
  })
}
