import { $ } from './dom.js'
import { T, LOCALE, COLLATOR } from './i18n.js'
import { state, can } from './state.js'
import { api } from './api.js'
import { esc, ago } from './format.js'
import { setHtml } from './nav.js'
import { currentRoute } from './router.js'
import { dialog, confirmDialog, closeMenu } from './dialogs.js'
import { alertBox } from './mosaic.js'
import { postJson } from './machines.js'

// Webhooks: a team's door for other services (GitHub, GitLab…). Each team's
// page lists its own, and managers make and change them there; #/webhooks is
// the log of what came in through all of them (or one team's), and each
// entry opens with what came, as it came. See server/webhooks.

const STATUS_TAG = {
  queued: 'info', delivered: 'info', processing: 'info', unreported: 'warn', done: 'ok', ignored: '', failed: 'err', filtered: '', ping: '', duplicate: '', undelivered: 'err', no_coordinator: 'err',
  bad_signature: 'err', bad_json: 'warn', too_large: 'warn', disabled: 'warn', rate_limited: 'warn',
}
const STATUSES = Object.keys(STATUS_TAG)
const PRESETS = ['github', 'gitlab', 'stripe', 'standard', 'custom']
const VERIFY = ['hmac-sha256', 'token', 'stripe', 'standard']
// (Stripe and Standard Webhooks make the secret themselves: it is pasted.)
const FROM_SERVICE = ['stripe', 'standard']
const verifyOf = (preset, custom) => ({ github: 'hmac-sha256', gitlab: 'token', stripe: 'stripe', standard: 'standard' })[preset] ?? custom
const WHEN = new Intl.DateTimeFormat(LOCALE, { day: 'numeric', month: 'short', hour: '2-digit', minute: '2-digit', second: '2-digit', hour12: false })

let hooks = null // the company's webhooks, or null before they arrive
let loadingHooks = null
const log = { rows: [], next: null, key: '', seq: 0, loading: false, error: null }
const filter = { webhook: '', status: '' }
let filterTeam = null // (the team the filters were chosen for: another one starts without them)

const teamTitle = c => state.squadMeta.get(c)?.title || c
const urlOf = h => `${location.origin}${h.path}`
const statusTag = s => `<span class="tag ${STATUS_TAG[s] ?? ''}" data-whstatus="${esc(s)}">${esc(T.whStatus[s] ?? s)}</span>`
const eventOf = d => (d.event ? `${d.event}${d.action ? `.${d.action}` : ''}` : '—')

export function loadHooks(force = false) {
  if (loadingHooks && !force) return loadingHooks
  loadingHooks = api('/api/webhooks').then(list => { hooks = list; redraw() }).catch(() => { hooks ??= [] }).finally(() => { loadingHooks = null })
  return loadingHooks
}
function redraw() {
  const r = currentRoute()
  if (r.view === 'team' && !$('team').hidden) void import('./team.js').then(m => m.refreshTeam())
  if (r.view === 'webhooks' && !$('webhooks').hidden) drawScreen()
}

// --- the live stream -----------------------------------------------------------
export function webhooksArrived(list) {
  hooks = Array.isArray(list) ? list : []
  redraw()
}
export function deliveryArrived(d) {
  if (!d?.id) return
  const i = log.rows.findIndex(x => x.id === d.id)
  if (i >= 0) log.rows[i] = d
  else if (matches(d) && (!log.rows.length || d.id > log.rows[0].id)) log.rows.unshift(d)
  else return
  if (hooks) { const h = hooks.find(x => x.id === d.webhook_id); if (h && (!h.last_delivery || h.last_delivery.id <= d.id)) h.last_delivery = { id: d.id, received_at: d.received_at, status: d.status, event: d.event } }
  redraw()
}
function matches(d) {
  const team = currentRoute().team
  if (team && d.coordinator !== team && hooks?.find(h => h.id === d.webhook_id)?.coordinator !== team) return false
  if (filter.webhook && String(d.webhook_id) !== filter.webhook) return false
  if (filter.status && d.status !== filter.status) return false
  return true
}

// --- a team's page: its webhooks -----------------------------------------------
export function webhooksSection(coord) {
  if (!hooks) { void loadHooks(); return card(coord, `<p class="tq-quiet">${esc(T.loading)}</p>`) }
  const mine = hooks.filter(h => h.coordinator === coord).sort((a, b) => COLLATOR.compare(a.name, b.name))
  const body = mine.length ? `<ul class="wh-list">${mine.map(row).join('')}</ul>` : `<p class="tq-quiet">${esc(T.whNone)}</p>`
  return card(coord, body)
}
function card(coord, body) {
  return `<section class="card tq-card" id="whSection">
      <header class="tq-h"><h2>${esc(T.whTitle)}</h2><span class="wh-h-acts"><a class="btn quiet" href="#/webhooks/q/${encodeURIComponent(coord)}">${esc(T.whSeeLog)}</a>${can('manager') ? `<button type="button" class="btn" data-wh-new="${esc(coord)}">${esc(T.whNew)}</button>` : ''}</span></header>
      ${body}
    </section>`
}
function row(h) {
  const last = h.last_delivery
  const state_ = h.enabled ? `<span class="dot ok" aria-hidden="true"></span>${esc(T.whOn)}` : `<span class="dot warn" aria-hidden="true"></span>${esc(h.disabled_reason === 'no_coordinator' ? T.whOffNoCoord : T.whOff)}`
  return `<li class="wh-row" data-wh="${h.id}">
      <div class="wh-main"><b class="wh-name">${esc(h.name)}</b><span class="tag">${esc(T.whPreset[h.preset] ?? h.preset)}</span><span class="wh-state">${state_}</span></div>
      <div class="wh-meta">${h.batch_seconds ? `<span class="tag">${esc(T.whBatchTag(h.batch_seconds))}</span>` : ''}${last ? `${statusTag(last.status)}<span>${esc(eventOf(last))}</span><span class="wh-when">${esc(ago(last.received_at))}</span>` : `<span>${esc(T.whNothingYet)}</span>`}${h.events ? `<span class="wh-events" title="${esc(h.events.join(', '))}">${esc(T.whOnlyEvents(h.events.length))}</span>` : ''}</div>
      ${can('manager') ? `<button type="button" class="icon-btn wh-more" data-wh-menu="${h.id}" aria-label="${esc(T.whActions(h.name))}" title="${esc(T.whActions(h.name))}">⋯</button>` : ''}
    </li>`
}

function openMenu(anchor, id) {
  closeMenu()
  const h = hooks?.find(x => x.id === id)
  if (!h) return
  const m = document.createElement('div')
  m.className = 'menu'
  m.innerHTML = `<button data-a="edit">${esc(T.whEdit)}</button>
      <button data-a="test" ${h.enabled ? '' : 'disabled'}>${esc(T.whTest)}</button>
      <button data-a="url">${esc(T.whShowUrl)}</button>
      <button data-a="secret">${esc(T.whNewSecret)}</button>
      <button data-a="toggle">${esc(h.enabled ? T.whTurnOff : T.whTurnOn)}</button>
      <button data-a="delete" class="danger">${esc(T.delete)}</button>`
  document.body.appendChild(m)
  state.menuEl = m
  const r = anchor.getBoundingClientRect()
  m.style.top = `${Math.min(r.bottom + 4, innerHeight - m.offsetHeight - 8)}px`
  m.style.left = `${Math.max(8, Math.min(r.right - m.offsetWidth, innerWidth - m.offsetWidth - 8))}px`
  m.addEventListener('click', e => {
    const b = e.target.closest('button')
    if (!b || b.disabled) return
    closeMenu()
    hookAction(b.dataset.a, h)
  })
}

async function hookAction(a, h) {
  if (a === 'edit') return hookDialog({ hook: h })
  if (a === 'url') return secretDialog({ ...h, url: urlOf(h) }, { secret: null })
  if (a === 'test') {
    try {
      const d = await postJson('/api/webhooks/test', { id: h.id })
      alertBox(T.whTestSent(d.id, T.whStatus[d.status] ?? d.status), T.whTest)
    } catch (err) { alertBox(err.message) }
    return
  }
  if (a === 'toggle') return postJson('/api/webhooks/update', { id: h.id, enabled: !h.enabled }).then(() => loadHooks(true)).catch(err => alertBox(err.message))
  if (a === 'secret' && h.secret_from_service) return pasteSecretDialog(h)
  if (a === 'secret') {
    return confirmDialog({
      title: T.whNewSecretTitle(h.name), text: esc(T.whNewSecretText), confirm: T.whNewSecret, danger: true,
      run: async () => { const r = await postJson('/api/webhooks/secret', { id: h.id }); secretDialog({ ...h, url: urlOf(h) }, { secret: r.secret, renewed: true }) },
    })
  }
  if (a === 'delete') {
    return confirmDialog({
      title: T.whDeleteTitle(h.name), text: esc(T.whDeleteText), confirm: T.delete, danger: true,
      run: async () => { await postJson('/api/webhooks/delete', { id: h.id }); await loadHooks(true) },
    })
  }
}

// --- making and changing one ---------------------------------------------------
function hookDialog({ hook = null, coordinator = hook?.coordinator } = {}) {
  const editing = !!hook
  let preset = hook?.preset ?? 'github'
  const v = k => esc(hook?.[k] ?? '')
  const { el, close } = dialog(`<h3>${esc(editing ? T.whEditTitle(hook.name) : T.whNewTitle(teamTitle(coordinator)))}</h3>
      <form class="wh-form" novalidate>
        <label class="field"><span>${esc(T.whName)}</span><input name="name" maxlength="80" required value="${v('name')}" placeholder="${esc(T.whNamePh)}"></label>
        ${editing ? '' : `<div class="field"><span>${esc(T.whService)}</span><span class="seg" role="group" aria-label="${esc(T.whService)}">${PRESETS.map(p => `<button type="button" data-preset="${p}" aria-pressed="${p === preset}" class="${p === preset ? 'on' : ''}">${esc(T.whPreset[p])}</button>`).join('')}</span></div>`}
        <div class="wh-custom" ${preset === 'custom' ? '' : 'hidden'}>
          <label class="field"><span>${esc(T.whVerify)}</span><select name="verify" ${editing ? 'disabled' : ''}>${VERIFY.map(x => `<option value="${x}"${(hook?.verify ?? 'hmac-sha256') === x ? ' selected' : ''}>${esc(T.whVerifyName[x])}</option>`).join('')}</select></label>
          <div class="row2">
            <label class="field"><span>${esc(T.whSigHeader)}</span><input name="signature_header" value="${v('signature_header')}" placeholder="X-Signature"></label>
            <label class="field"><span>${esc(T.whEventHeader)}</span><input name="event_header" value="${v('event_header')}" placeholder="X-Event"></label>
          </div>
          <label class="field"><span>${esc(T.whDeliveryHeader)}</span><input name="delivery_header" value="${v('delivery_header')}" placeholder="X-Delivery-Id"></label>
        </div>
        <label class="field"><span>${esc(T.whEvents)}</span><input name="events" value="${esc(hook?.events?.join(', ') ?? '')}" placeholder="push, pull_request.opened, issues"><small class="dim-note">${esc(T.whEventsHint)}</small></label>
        <label class="field"><span>${esc(T.whPrompt)}</span><textarea name="prompt" rows="4" maxlength="4000" placeholder="${esc(T.whPromptPh)}">${v('prompt')}</textarea><small class="dim-note">${esc(T.whPromptHint)}</small></label>
        <div class="field wh-by-event"><span>${esc(T.whByEvent)}</span><small class="dim-note">${esc(T.whByEventHint)}</small>
          <div class="wh-pe-list" data-pe-list>${Object.entries(hook?.prompts ?? {}).map(([e, t]) => peRow(e, t)).join('')}</div>
          <button type="button" class="btn quiet wh-pe-add" data-pe-add>${esc(T.whByEventAdd)}</button></div>
        <label class="field wh-batch"><span>${esc(T.whBatch)}</span><input type="number" name="batch_seconds" min="0" max="300" step="1" inputmode="numeric" value="${esc(hook?.batch_seconds ?? 0)}"><small class="dim-note">${esc(T.whBatchHint)}</small></label>
        ${editing ? '' : `<label class="field"><span data-secret-label>${esc(T.whOwnSecret)}</span><input name="secret" autocomplete="off" spellcheck="false" placeholder="${esc(T.whOwnSecretPh)}"><small class="dim-note" data-secret-hint hidden>${esc(T.whServiceSecretHint)}</small></label>`}
        <div class="err"></div>
        <div class="actions wh-actions"><button type="button" class="btn" data-cancel>${esc(T.cancel)}</button><button type="submit" class="btn primary">${esc(editing ? T.save : T.whCreate)}</button></div>
      </form>`, { wide: true })
  const form = el.querySelector('form')
  form.querySelector('[name=name]').focus()
  // (The secret: one's own or made here, or the one the service made.)
  const secretKind = () => {
    if (editing) return
    const fromService = FROM_SERVICE.includes(verifyOf(preset, form.querySelector('[name=verify]').value))
    el.querySelector('[data-secret-label]').textContent = fromService ? T.whServiceSecret : T.whOwnSecret
    form.querySelector('[name=secret]').placeholder = fromService ? 'whsec_…' : T.whOwnSecretPh
    el.querySelector('[data-secret-hint]').hidden = !fromService
  }
  el.querySelectorAll('[data-preset]').forEach(b => b.addEventListener('click', () => {
    preset = b.dataset.preset
    el.querySelectorAll('[data-preset]').forEach(x => { x.classList.toggle('on', x === b); x.setAttribute('aria-pressed', String(x === b)) })
    el.querySelector('.wh-custom').hidden = preset !== 'custom'
    secretKind()
  }))
  form.querySelector('[name=verify]').addEventListener('change', secretKind)
  el.querySelector('[data-pe-add]').addEventListener('click', () => {
    el.querySelector('[data-pe-list]').insertAdjacentHTML('beforeend', peRow('', ''))
    el.querySelector('[data-pe-list] .wh-pe-row:last-child [name=pe-event]').focus()
  })
  el.querySelector('[data-pe-list]').addEventListener('click', e => { e.target.closest('[data-pe-del]')?.closest('.wh-pe-row')?.remove() })
  form.addEventListener('submit', async e => {
    e.preventDefault()
    const f = Object.fromEntries(new FormData(form))
    const events = String(f.events ?? '').split(/[\s,]+/).filter(Boolean)
    const prompts = {}
    for (const r of el.querySelectorAll('.wh-pe-row')) {
      const ev = r.querySelector('[name=pe-event]').value.trim(), text = r.querySelector('[name=pe-text]').value.trim()
      if (ev || text) prompts[ev] = text
    }
    const body = { name: f.name, events: events.length ? events : null, prompt: f.prompt ?? '', prompts: Object.keys(prompts).length ? prompts : null, batch_seconds: Number(f.batch_seconds || 0) }
    if (preset === 'custom') Object.assign(body, { ...(editing ? {} : { verify: f.verify }), signature_header: f.signature_header, event_header: f.event_header, delivery_header: f.delivery_header })
    const btn = form.querySelector('[type=submit]')
    btn.disabled = true
    try {
      if (editing) {
        await postJson('/api/webhooks/update', { id: hook.id, ...body })
        close()
      } else {
        const made = await postJson('/api/webhooks/create', { ...body, coordinator, preset, ...(f.secret ? { secret: f.secret } : {}) })
        close()
        secretDialog(made, { secret: made.secret, made: true })
      }
      await loadHooks(true)
    } catch (err) {
      el.querySelector('.err').textContent = err.message
      btn.disabled = false
    }
  })
}

// What to do with one event: its name and the words for it.
const peRow = (event, text) => `<div class="wh-pe-row">
    <input name="pe-event" value="${esc(event)}" placeholder="pull_request.opened" aria-label="${esc(T.whEvent)}" spellcheck="false">
    <textarea name="pe-text" rows="2" maxlength="4000" aria-label="${esc(T.whPrompt)}" placeholder="${esc(T.whPromptPh)}">${esc(text)}</textarea>
    <button type="button" class="btn quiet" data-pe-del aria-label="${esc(T.whRemove)}" title="${esc(T.whRemove)}">✕</button>
  </div>`

// A new secret the service made: pasted here (one generated here would never match).
function pasteSecretDialog(h) {
  const { el, close } = dialog(`<h3>${esc(T.whNewSecretTitle(h.name))}</h3>
      <form class="wh-form" novalidate>
        <p class="dim-note">${esc(T.whPasteSecretText)}</p>
        <label class="field"><span>${esc(T.whServiceSecret)}</span><input name="secret" autocomplete="off" spellcheck="false" placeholder="whsec_…" required></label>
        <div class="err"></div>
        <div class="actions wh-actions"><button type="button" class="btn" data-cancel>${esc(T.cancel)}</button><button type="submit" class="btn primary">${esc(T.save)}</button></div>
      </form>`)
  const form = el.querySelector('form')
  form.querySelector('[name=secret]').focus()
  form.addEventListener('submit', async e => {
    e.preventDefault()
    try { await postJson('/api/webhooks/secret', { id: h.id, secret: form.querySelector('[name=secret]').value.trim() }); close() } catch (err) { el.querySelector('.err').textContent = err.message }
  })
}

// Where to send it and with what secret: shown once, when made or renewed.
function secretDialog(h, { secret, made = false, renewed = false }) {
  const copyRow = (text, id) => `<div class="cmdrow"><pre class="cmd" id="${id}">${esc(text)}</pre><button type="button" class="btn" data-copy-from="${id}">${esc(T.copy)}</button></div>`
  const steps = T.whSteps[h.preset] ?? T.whSteps.custom
  const { el } = dialog(`<h3>${esc(made ? T.whMadeTitle(h.name) : renewed ? T.whRenewedTitle(h.name) : T.whUrlTitle(h.name))}</h3>
      <div class="wh-secret">
        <p class="wh-label">${esc(T.whUrl)}</p>${copyRow(h.url ?? urlOf(h), 'whUrl')}
        ${h.secret_from_service ? `<p class="dim-note">${esc(T.whSecretFromService)}</p>` : secret ? `<p class="wh-label">${esc(h.verify === 'token' ? T.whToken : T.whSecret)}</p>${copyRow(secret, 'whSecretVal')}<p class="wh-note">${esc(T.whSecretOnce)}</p>` : `<p class="wh-note">${esc(T.whSecretHidden)}</p>`}
        <ol class="wh-steps">${steps.map(s => `<li>${esc(s)}</li>`).join('')}</ol>
        <p class="dim-note">${esc(T.whPublicNote)}</p>
      </div>
      <div class="actions wh-actions"><button type="button" class="btn primary" data-cancel>${esc(T.close)}</button></div>`, { wide: true })
  el.addEventListener('click', async e => {
    const b = e.target.closest('[data-copy-from]')
    if (!b) return
    try { await navigator.clipboard.writeText(el.querySelector(`#${b.dataset.copyFrom}`).textContent); b.textContent = T.copied } catch {}
  })
}

// --- the log -------------------------------------------------------------------
export function webhooksHead() {
  const team = currentRoute().team
  return { title: esc(team ? T.whLogOf(teamTitle(team)) : T.whTitle) }
}

export function renderWebhooks() {
  if (!hooks) void loadHooks()
  const team = currentRoute().team ?? ''
  if (team !== filterTeam) { filterTeam = team; filter.webhook = '' }
  const key = `${currentRoute().team ?? ''}|${filter.webhook}|${filter.status}`
  if (key !== log.key) { log.key = key; log.rows = []; log.next = null; log.error = null; void loadLog() }
  drawScreen()
}

async function loadLog(more = false) {
  const seq = ++log.seq
  log.loading = true
  const q = new URLSearchParams({ limit: '100' })
  const team = currentRoute().team
  if (team) q.set('coordinator', team)
  if (filter.webhook) q.set('webhook', filter.webhook)
  if (filter.status) q.set('status', filter.status)
  if (more && log.next) q.set('before', String(log.next))
  try {
    const r = await api(`/api/webhooks/deliveries?${q}`)
    if (seq !== log.seq) return
    log.rows = more ? [...log.rows, ...r.deliveries] : r.deliveries
    log.next = r.next_before
    log.error = null
  } catch (err) { if (seq === log.seq) log.error = err.message }
  if (seq === log.seq) log.loading = false
  if (currentRoute().view === 'webhooks') drawScreen()
}

function drawScreen() {
  const team = currentRoute().team
  const list = (hooks ?? []).filter(h => !team || h.coordinator === team)
  const sel = (k, opts, all) => `<label class="u-filter"><span class="sr-only">${esc(all)}</span><select data-whfilter="${k}"><option value="">${esc(all)}</option>${opts.map(([v, l]) => `<option value="${esc(v)}"${filter[k] === v ? ' selected' : ''}>${esc(l)}</option>`).join('')}</select></label>`
  const filters = `<div class="u-filters">
      ${sel('webhook', list.map(h => [String(h.id), team ? h.name : `${h.name} · ${teamTitle(h.coordinator)}`]), T.whAllWebhooks)}
      ${sel('status', STATUSES.map(s => [s, T.whStatus[s]]), T.whAllStatuses)}
      ${team ? `<a class="btn quiet" href="#/q/${encodeURIComponent(team)}">${esc(T.whBackToTeam)}</a>` : ''}
    </div>`
  let body
  if (log.error) body = `<p class="err">${esc(log.error)}</p>`
  else if (!log.rows.length) body = log.loading ? `<p class="dim-note">${esc(T.loading)}</p>` : `<div class="empty"><b>${esc(T.whLogEmpty)}</b><span>${esc(hooks && !list.length ? T.whLogNoHooks : T.whLogEmptyHint)}</span></div>`
  else {
    body = `<div class="card wh-table-card"><div class="mc-scroll"><table class="wh-table">
        <thead><tr><th scope="col">${esc(T.whWhen)}</th><th scope="col">${esc(T.whWebhook)}</th><th scope="col">${esc(T.whEvent)}</th><th scope="col">${esc(T.whState)}</th><th scope="col">${esc(T.whResult)}</th></tr></thead>
        <tbody>${log.rows.map(d => `<tr data-whd="${d.id}" tabindex="0">
          <td class="wh-when-c"><span title="${esc(new Date(d.received_at).toISOString())}">${esc(WHEN.format(d.received_at))}</span><small>#${d.id}</small></td>
          <td>${esc(d.webhook_name ?? '')}${team ? '' : `<small>${esc(teamTitle(d.coordinator ?? hooks?.find(h => h.id === d.webhook_id)?.coordinator ?? ''))}</small>`}</td>
          <td class="wh-ev">${esc(eventOf(d))}</td>
          <td>${statusTag(d.status)}</td>
          <td class="wh-res">${esc(resultLine(d))}</td>
        </tr>`).join('')}</tbody></table></div></div>
      ${log.next ? `<div class="wh-more-row"><button type="button" class="btn" data-whmore ${log.loading ? 'disabled' : ''}>${esc(T.whMore)}</button></div>` : ''}`
  }
  setHtml($('webhooks'), `<div class="u-wrap">${filters}${body}</div>`)
  $('topSub').textContent = log.rows.length ? T.whShown(log.rows.length) : ''
}
// Why it ended as it did, in the dashboard's language. (The server's own words
// only where they are an error it met: the dashboard has none for it.)
function reasonText(d) {
  if (Object.hasOwn(T.whWhy, d.status)) return T.whWhy[d.status]
  const again = /^delivered again from #(\d+)$/.exec(d.reason ?? '')
  if (again) return T.whWhyAgain(again[1])
  if (d.event === 'pisha_test') return T.whWhyTest
  return d.reason ?? ''
}
const waiting = d => d.waiting_for?.length ? T.whWaitingFor(d.waiting_for.join(', ')) : ''
const resultLine = d => d.summary || waiting(d) || (['processing', 'unreported'].includes(d.status) ? T.whWhy[d.status] : d.status === 'delivered' ? [T.whDeliveredTo(d.coordinator ?? ''), d.reason ? reasonText(d) : ''].filter(Boolean).join(' · ') : reasonText(d))

// One entry, whole: what came, as it came.
async function deliveryDialog(id) {
  let d
  try { d = await api(`/api/webhooks/delivery?id=${id}`) } catch (err) { return alertBox(err.message) }
  let pretty = d.body
  try { if (d.body != null) pretty = JSON.stringify(JSON.parse(d.body), null, 2) } catch {}
  const fact = (k, v) => (v == null || v === '' ? '' : `<dt>${esc(k)}</dt><dd>${v}</dd>`)
  const coord = d.coordinator
  const headers = Object.entries(d.headers ?? {})
  const { el, close } = dialog(`<h3 class="wh-d-h">${esc(T.whDeliveryTitle(d.id))} ${statusTag(d.status)}</h3>
      <div class="wh-detail">
        <dl class="wh-facts">
          ${fact(T.whWebhook, esc(d.webhook_name ?? ''))}
          ${fact(T.whWhen, esc(WHEN.format(d.received_at)))}
          ${fact(T.whEvent, `<code>${esc(eventOf(d))}</code>`)}
          ${fact(T.whDeliveryKey, d.delivery_key ? `<code>${esc(d.delivery_key)}</code>` : '')}
          ${fact(T.whFrom, d.ip ? `<code>${esc(d.ip)}</code>` : '')}
          ${fact(T.whSize, esc(T.whBytes(d.size)))}
          ${fact(T.whReason, reasonText(d) ? esc(reasonText(d)) : '')}
          ${fact(T.whTo, coord ? `<a href="#/s/${encodeURIComponent(coord)}/chat" data-cancel>${esc(coord)}</a>${d.message_id ? ` <small>(${esc(T.whMessage(d.message_id))})</small>` : ''}` : '')}
        </dl>
        ${turnHtml(d)}
        ${headers.length ? `<details class="wh-headers"><summary>${esc(T.whHeaders(headers.length))}</summary><table class="wh-kv">${headers.map(([k, v]) => `<tr><th scope="row">${esc(k)}</th><td><code>${esc(v)}</code></td></tr>`).join('')}</table></details>` : ''}
        <p class="wh-label">${esc(T.whBody)}</p>
        ${d.body == null ? `<p class="dim-note">${esc(T.whNoBody)}</p>` : `<pre class="cmd wh-body">${esc(pretty)}</pre>`}
      </div>
      <div class="err"></div>
      <div class="actions wh-actions">${d.body != null && can('manager') ? `<button type="button" class="btn" data-redeliver>${esc(T.whRedeliver)}</button>` : ''}<button type="button" class="btn primary" data-cancel>${esc(T.close)}</button></div>`, { wide: true })
  el.querySelector('[data-redeliver]')?.addEventListener('click', async e => {
    e.currentTarget.disabled = true
    try { const r = await postJson('/api/webhooks/redeliver', { id: d.id }); close(); alertBox(T.whRedelivered(r.id), T.whRedeliver) } catch (err) { el.querySelector('.err').textContent = err.message; e.currentTarget.disabled = false }
  })
}

// What its coordinator did with it: what it said came of it, its turn on it
// (how long, the tools it used, the messages it sent, its last words) and
// what that cost.
const FULL = new Intl.NumberFormat(LOCALE)
function turnHtml(d) {
  if (!d.message_id) return ''
  const t = d.trace, k = d.tokens
  const took = d.turn_started_at && d.turn_ended_at ? T.whTook(Math.max(1, Math.round((d.turn_ended_at - d.turn_started_at) / 1000))) : d.turn_started_at ? T.whStillOn : ''
  const report = d.outcome
    ? `<p class="wh-report"><span class="tag ${STATUS_TAG[d.outcome]}">${esc(T.whStatus[d.outcome])}</span>${d.summary ? ` ${esc(d.summary)}` : ''}<small>${esc(ago(d.reported_at))}</small></p>`
    : `<p class="dim-note">${esc(waiting(d) || (d.turn_started_at ? T.whNoReport : T.whNotYet))}</p>`
  const tools = t?.tools?.length ? `<details class="wh-trace-part"><summary>${esc(T.whTools(t.tools_total ?? t.tools.length))}</summary><ol class="wh-tools">${t.tools.map(x => `<li class="${x.ok ? '' : 'bad'}"><code>${esc(x.tool)}</code> <span>${esc(x.summary)}</span></li>`).join('')}</ol></details>` : ''
  const REPORT_TAG = { done: 'ok', blocked: 'err', failed: 'err', question: 'warn' }
  const reportOf = m => (m.report
    ? `<div class="wh-wreport"><span class="tag ${REPORT_TAG[m.report.state] ?? ''}">${esc(T.reportWord?.[m.report.state] ?? m.report.state)}</span> ${esc(m.report.text)}</div>`
    : m.task ? `<div class="wh-wreport dim-note">${esc(T.whNoWorkerReport)}</div>` : '')
  const tasks = (t?.messages ?? []).filter(m => m.task).length
  const msgs = t?.messages?.length ? `<details class="wh-trace-part"${tasks ? ' open' : ''}><summary>${esc(T.whSent(t.messages.length))}</summary><ul class="wh-msgs">${t.messages.map(m => `<li><b>${esc(T.whSentTo(m.to))}</b> ${esc(m.text)}${reportOf(m)}</li>`).join('')}</ul></details>` : ''
  const said = t?.text ? `<details class="wh-trace-part"><summary>${esc(T.whLastWords)}</summary><p class="wh-said">${esc(t.text)}</p></details>` : ''
  const all = x => x.input + x.cache_read + x.cache_write + x.output
  const w = d.worker_tokens
  const cost = [k ? `<span>${esc(T.whTokens(FULL.format(all(k)), k.calls))}</span>` : '', w ? `<span>${esc(T.whWorkerTokens(FULL.format(all(w)), w.calls))}</span>` : ''].join('')
  const together = d.together?.length ? `<p class="dim-note">${esc(T.whTogether(d.together.map(n => `#${n}`).join(', ')))}</p>` : ''
  return `<section class="wh-turn"><p class="wh-label">${esc(T.whWhatItDid)}</p>${report}${together}
      ${took || cost ? `<p class="wh-turn-meta">${took ? `<span>${esc(took)}</span>` : ''}${cost}</p>` : ''}
      ${tools}${msgs}${said}
      ${d.turn_ended_at && !t?.tools?.length && !t?.text ? `<p class="dim-note">${esc(T.whNoTrace)}</p>` : ''}</section>`
}

// --- clicks ----------------------------------------------------------------------
document.addEventListener('click', e => {
  const n = e.target.closest('[data-wh-new]')
  if (n) return hookDialog({ coordinator: n.dataset.whNew })
  const m = e.target.closest('[data-wh-menu]')
  if (m) return openMenu(m, Number(m.dataset.whMenu))
  if (currentRoute().view !== 'webhooks') return
  if (e.target.closest('[data-whmore]')) return void loadLog(true)
  const r = e.target.closest('[data-whd]')
  if (r && $('webhooks').contains(r)) return void deliveryDialog(Number(r.dataset.whd))
})
document.addEventListener('keydown', e => {
  if (e.key !== 'Enter' || currentRoute().view !== 'webhooks') return
  const r = e.target.closest?.('[data-whd]')
  if (r) void deliveryDialog(Number(r.dataset.whd))
})
document.addEventListener('change', e => {
  const f = e.target.closest?.('[data-whfilter]')
  if (!f || currentRoute().view !== 'webhooks') return
  filter[f.dataset.whfilter] = f.value
  renderWebhooks()
})
