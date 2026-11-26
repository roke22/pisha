// What a domain and a public address may be. Shared by the server's options
// (config.js) and by "pisha-server setup", which must not load those options.

export const isDomain = v => /^[a-z0-9]([a-z0-9-]*[a-z0-9])?(\.[a-z0-9]([a-z0-9-]*[a-z0-9])?)+$/.test(v)

// (It goes into the commands the dashboard gives: nothing a shell would read.)
export const isPublicUrl = v => /^https?:\/\/[^\s/'"`$\\&|;<>()^%!]+(\/[^\s'"`$\\&|;<>()^%!]*)?$/.test(v)
