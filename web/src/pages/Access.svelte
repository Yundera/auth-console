<script lang="ts">
  import Card from '../lib/Card.svelte'
  import Pill from '../lib/Pill.svelte'
  import Dialog from '../lib/Dialog.svelte'
  import {
    api,
    errorText,
    type AccessInfo,
    type AuthorizedKey,
    type Capabilities,
    type FetchedKey,
    type HostAccount,
    type Me,
    type SupportStatus,
  } from '../lib/api'
  import { generateEd25519Key, isEd25519GenerationSupported, type GeneratedKey } from '../lib/sshKeygen'

  // App passes `me` to every page; Access only renders for admins, so it has no use for it.
  let {}: { me: Me } = $props()

  let info = $state<AccessInfo | null>(null)
  let infoError = $state('')
  let caps = $state<Capabilities | null>(null)
  let support = $state<SupportStatus | null>(null)
  let supportError = $state('')
  let notice = $state<{ tone: 'ok' | 'warn' | 'bad' | 'info'; text: string } | null>(null)

  async function load() {
    infoError = ''
    try {
      info = await api.get<AccessInfo>('/api/access')
    } catch (e) {
      infoError = errorText(e)
    }
  }

  async function loadSupport() {
    supportError = ''
    try {
      support = await api.get<SupportStatus>('/api/access/support')
    } catch (e) {
      supportError = errorText(e)
    }
  }

  $effect(() => {
    load()
    api
      .get<Capabilities>('/api/capabilities')
      .then((c) => {
        caps = c
        if (c.support) loadSupport()
      })
      .catch(() => {})
  })

  const shown = $derived(
    (info?.accounts ?? []).filter((a) => !a.isSystem || a.authorizedKeys.length > 0 || a.lastLoginTime),
  )
  const hidden = $derived((info?.accounts ?? []).filter((a) => !shown.includes(a)))
  const userKeyCount = $derived(
    (info?.accounts ?? []).reduce((n, a) => n + a.authorizedKeys.filter((k) => k.isUserKey).length, 0),
  )

  function tag(k: AuthorizedKey): { label: string; tone: 'info' | 'warn' | 'ok' | 'neutral' } {
    if (k.isAdminKey) return { label: 'ADMIN APP', tone: 'info' }
    if (k.isSupportKey) return { label: 'SUPPORT', tone: 'warn' }
    if (k.isUserKey) return { label: 'USER', tone: 'ok' }
    return { label: 'UNKNOWN', tone: 'neutral' }
  }

  function lockedReason(a: HostAccount, k: AuthorizedKey): string {
    if (!k.fingerprint) return 'Cannot remove: fingerprint unavailable'
    if (k.isAdminKey && info?.dashboardAccount && a.username === info.dashboardAccount)
      return "The admin app's own key — managed automatically"
    return ''
  }

  // ---- support toggle --------------------------------------------------------

  let supportBusy = $state(false)
  let confirmSupportOff = $state(false)

  async function setSupport(ensure: boolean) {
    supportBusy = true
    supportError = ''
    try {
      support = await api.put<SupportStatus>('/api/access/support', { ensure })
      await load()
    } catch (e) {
      supportError = errorText(e)
    } finally {
      supportBusy = false
      confirmSupportOff = false
    }
  }

  function toggleSupport() {
    if (!support) return
    if (support.ensure && userKeyCount === 0) {
      confirmSupportOff = true
      return
    }
    setSupport(!support.ensure)
  }

  // ---- add / remove ------------------------------------------------------------

  let busy = $state(false)
  let dialogError = $state('')

  let addFor = $state<HostAccount | null>(null)
  let addMode = $state<'paste' | 'generate'>('paste')
  let pasted = $state('')
  let generated = $state<GeneratedKey | null>(null)
  const canGenerate = isEd25519GenerationSupported()

  function openAdd(a: HostAccount) {
    addFor = a
    addMode = 'paste'
    pasted = ''
    generated = null
    dialogError = ''
  }

  async function generate() {
    dialogError = ''
    try {
      generated = await generateEd25519Key(`user-${addFor!.username}`)
      pasted = generated.publicKey
    } catch (e) {
      dialogError = 'This browser cannot generate Ed25519 keys: ' + errorText(e)
    }
  }

  function downloadPrivate() {
    if (!generated || !addFor) return
    const blob = new Blob([generated.privateKey], { type: 'application/octet-stream' })
    const a = document.createElement('a')
    a.href = URL.createObjectURL(blob)
    a.download = `id_ed25519_${addFor.username}`
    a.click()
    URL.revokeObjectURL(a.href)
  }

  async function submitAdd() {
    busy = true
    dialogError = ''
    try {
      const res = await api.post<{ status: string }>('/api/access/keys', {
        username: addFor!.username,
        publicKey: pasted.trim(),
      })
      notice =
        res.status === 'already-present'
          ? { tone: 'info', text: 'Key was already authorized — nothing changed.' }
          : { tone: 'ok', text: `SSH key added to ${addFor!.username}.` }
      addFor = null
      await load()
    } catch (e) {
      dialogError = errorText(e)
    } finally {
      busy = false
    }
  }

  let removeFor = $state<{ account: HostAccount; key: AuthorizedKey } | null>(null)
  const leavesNoUserKey = $derived(!!removeFor && userKeyCount - (removeFor.key.isUserKey ? 1 : 0) === 0)

  async function submitRemove() {
    busy = true
    dialogError = ''
    try {
      const r = removeFor!
      const res = await api.del<{ status: string }>('/api/access/keys', {
        username: r.account.username,
        fingerprint: r.key.fingerprint,
      })
      notice =
        res.status === 'removed'
          ? { tone: 'ok', text: `Key removed from ${r.account.username}.` }
          : { tone: 'info', text: 'The key was already gone.' }
      removeFor = null
      await load()
    } catch (e) {
      dialogError = errorText(e)
    } finally {
      busy = false
    }
  }

  // ---- deep link: ?account=&pubkey= | ?account=&pubkeyUrl= ------------------------

  const params = new URLSearchParams(location.search)
  let link = $state({
    account: params.get('account') ?? '',
    pubkey: params.get('pubkey') ?? '',
    pubkeyUrl: params.get('pubkeyUrl') ?? '',
  })
  const linkActive = $derived(!!(link.account || link.pubkey || link.pubkeyUrl))

  let fetched = $state<FetchedKey | null>(null)
  let fetchError = $state('')
  let fetchLoading = $state(false)
  let rawKey = $state<{ type: string; full: string; comment: string; fingerprint: string } | null>(null)
  let rawInvalid = $state(false)
  let consentBusy = $state(false)
  let consentError = $state('')

  const KEY_TYPE =
    /^(ssh-(rsa|dss|ed25519)|ecdsa-sha2-nistp(256|384|521)|sk-(ssh-ed25519|ecdsa-sha2-nistp256)@openssh\.com)$/

  async function fingerprintOf(b64: string): Promise<string> {
    const bin = Uint8Array.from(atob(b64), (c) => c.charCodeAt(0))
    const sum = new Uint8Array(await crypto.subtle.digest('SHA-256', bin))
    return 'SHA256:' + btoa(String.fromCharCode(...sum)).replace(/=+$/, '')
  }

  $effect(() => {
    if (link.pubkeyUrl) {
      fetchLoading = true
      api
        .get<FetchedKey>('/api/access/fetch-pubkey?url=' + encodeURIComponent(link.pubkeyUrl))
        .then((k) => (fetched = k))
        .catch((e) => (fetchError = errorText(e)))
        .finally(() => (fetchLoading = false))
    } else if (link.pubkey) {
      const parts = link.pubkey.trim().split(/\s+/)
      if (parts.length >= 2 && KEY_TYPE.test(parts[0]) && /^[A-Za-z0-9+/=]+$/.test(parts[1])) {
        fingerprintOf(parts[1])
          .then((fp) => {
            rawKey = { type: parts[0], full: parts.join(' '), comment: parts.slice(2).join(' '), fingerprint: fp }
          })
          .catch(() => (rawInvalid = true))
      } else {
        rawInvalid = true
      }
    }
  })

  const trust = $derived<'trusted' | 'tls-verified' | 'unknown'>(
    link.pubkeyUrl ? (fetched?.trusted ? 'trusted' : 'tls-verified') : 'unknown',
  )
  const tone = $derived(trust === 'trusted' ? 'info' : trust === 'tls-verified' ? 'warn' : 'bad')
  const who = $derived(fetched?.hostname ?? '')
  const resolved = $derived(
    fetched
      ? { type: fetched.type, full: fetched.publicKey, comment: fetched.comment, fingerprint: fetched.fingerprint }
      : rawKey,
  )
  const problem = $derived.by(() => {
    if (!link.account) return 'This authorization link is missing the target account name.'
    if (!link.pubkey && !link.pubkeyUrl) return 'This authorization link is missing the public key.'
    if (link.pubkeyUrl && !fetched && !fetchLoading && fetchError) return fetchError
    if (!link.pubkeyUrl && rawInvalid) return 'The public key in this link is malformed or uses an unsupported type.'
    if (info && !info.accounts.some((a) => a.username === link.account))
      return `Account '${link.account}' does not exist on this box.`
    return ''
  })
  const ready = $derived(!problem && !!resolved && !!info && !fetchLoading)

  function dismissLink() {
    link = { account: '', pubkey: '', pubkeyUrl: '' }
    history.replaceState(null, '', location.pathname)
  }

  async function consent() {
    consentBusy = true
    consentError = ''
    try {
      const res = await api.post<{ status: string }>('/api/access/keys', {
        username: link.account,
        publicKey: resolved!.full,
      })
      notice =
        res.status === 'already-present'
          ? { tone: 'info', text: 'Key was already authorized — nothing changed.' }
          : { tone: 'ok', text: 'SSH key added.' }
      dismissLink()
      await load()
    } catch (e) {
      consentError = errorText(e)
    } finally {
      consentBusy = false
    }
  }
</script>

<div class="stack">
  {#if linkActive}
    <section class="consent {tone}">
      <h2>Authorize SSH access?</h2>

      {#if link.pubkeyUrl}
        <div class="alert {tone}">
          {#if fetchLoading}
            Fetching identity from <span class="break">{link.pubkeyUrl}</span>…
          {:else if fetched}
            <p><strong>{trust === 'trusted' ? 'Trusted source — verified via TLS' : 'Verified to come from this domain via TLS'}</strong></p>
            <p class="host">{fetched.hostname}</p>
            <p class="break">{fetched.url}</p>
            {#if trust === 'tls-verified'}
              <p>
                TLS confirms the key was served by <strong>{fetched.hostname}</strong>. You still need to know that this
                domain belongs to who you think it does.
              </p>
            {/if}
          {:else}
            {fetchError || 'Could not fetch from URL.'}
          {/if}
        </div>
      {/if}

      <div class="alert {tone}">
        <p>
          <strong>
            {trust === 'unknown'
              ? 'An external link is asking to add an SSH key to this box.'
              : `${who} is asking to add an SSH key to this box.`}
          </strong>
        </p>
        <p>
          If you grant this, the holder of the matching private key will be able to log in over SSH and gain full
          control of this box. They can:
        </p>
        <ul>
          <li>Read every file on this box — documents, photos, app data, secrets.</li>
          <li>Modify or <strong>permanently delete</strong> any file. Deleted files cannot be recovered.</li>
          <li>Install, remove, or replace any application or service.</li>
        </ul>
        <p>
          <strong>
            {trust === 'trusted'
              ? `Only proceed if you actually requested support from ${who}.`
              : trust === 'tls-verified'
                ? `Only proceed if you trust ${who} AND asked them for access.`
                : 'Only proceed if you personally trust the person who sent you this link AND you asked them for access. If you did not ask for this, or the link came from an unexpected source, cancel.'}
          </strong>
        </p>
      </div>

      {#if problem}
        <div class="alert bad">{problem} Request rejected — nothing was changed.</div>
      {:else if !info}
        <p class="muted">Verifying target account…</p>
      {:else if resolved}
        <dl class="kv">
          <dt>Account</dt>
          <dd class="mono">{link.account}</dd>
          <dt>Key type</dt>
          <dd class="mono">{resolved.type}</dd>
          <dt>Fingerprint</dt>
          <dd class="mono break">{resolved.fingerprint}</dd>
          {#if resolved.comment}<dt>Comment</dt><dd>{resolved.comment}</dd>{/if}
        </dl>
      {/if}
      {#if consentError}<p class="error">{consentError}</p>{/if}
      <div class="row end">
        <button class="primary" onclick={dismissLink} disabled={consentBusy}>I don't understand — cancel</button>
        <button class="danger" onclick={consent} disabled={consentBusy || !ready}>
          {trust === 'unknown' ? 'I consent to give access to the person who gave me the link' : `I consent to give access to ${who}`}
        </button>
      </div>
    </section>
  {/if}

  {#if notice}
    <div class="alert {notice.tone}">{notice.text}</div>
  {/if}

  {#if caps?.support}
    <Card title="Support access">
      {#if supportError}
        <p class="error">{supportError}</p>
      {/if}
      {#if support}
        <div class="row">
          <label class="row"
            ><input type="checkbox" checked={support.ensure} disabled={supportBusy} onchange={toggleSupport} /> Keep the support
            key installed</label
          >
          <Pill tone={support.accessEnabled ? 'warn' : 'neutral'}>{support.accessEnabled ? 'Key present' : 'Key absent'}</Pill>
        </div>
        <p class="muted">
          Lets the operator's support team reach this box over SSH, as <code>{support.username}</code>. Key
          <span class="mono break">{support.fingerprint}</span> ({support.comment}).
        </p>
        {#if support.ensure !== support.accessEnabled}
          <div class="alert warn">
            {support.ensure
              ? "Support access is enabled but the key is not currently in admin's authorized_keys. The next self-check will re-add it."
              : "The support key is currently in admin's authorized_keys but the safety net is opted out. It will not be re-added if removed."}
          </div>
        {/if}
      {:else if !supportError}
        <p class="muted">Loading…</p>
      {/if}
    </Card>
  {/if}

  <Card title="Host accounts & SSH keys">
    {#snippet actions()}
      <button onclick={load}>Refresh</button>
    {/snippet}
    <p class="muted">The Linux accounts of this box, and the SSH keys that can log in to each.</p>
    {#if infoError}
      <p class="error">{infoError}</p>
    {:else if !info}
      <p class="muted">Loading…</p>
    {:else}
      <div class="stack">
        {#each shown as a (a.username)}
          <div class="account">
            <div class="row">
              <strong class="mono">{a.username}</strong>
              <Pill>UID {a.uid}</Pill>
              {#if a.uid === 0}<Pill tone="warn">ROOT</Pill>{/if}
              {#if a.isSystem}<Pill>SYSTEM</Pill>{/if}
              <span class="spacer"></span>
              <button class="small" onclick={() => openAdd(a)}>Add key</button>
            </div>
            <p class="muted small">
              Home <code>{a.home}</code> · shell <code>{a.shell}</code> · last login
              {a.lastLoginTime ? `${a.lastLoginTime}${a.lastLoginFrom ? ` from ${a.lastLoginFrom}` : ''}` : 'never (within recorded history)'}
            </p>
            {#if a.authorizedKeysError}<p class="error">{a.authorizedKeysError}</p>{/if}
            {#if a.authorizedKeys.length}
              <div class="table-wrap">
                <table>
                  <thead><tr><th>Type</th><th>Fingerprint</th><th>Comment</th><th>Tag</th><th></th></tr></thead>
                  <tbody>
                    {#each a.authorizedKeys as k, i (i)}
                      {@const t = tag(k)}
                      {@const locked = lockedReason(a, k)}
                      <tr>
                        <td class="mono">{k.type}{k.bits ? ` ${k.bits}` : ''}</td>
                        <td class="mono break">{k.fingerprint || '—'}</td>
                        <td class="break">{k.comment || '—'}</td>
                        <td><Pill tone={t.tone}>{t.label}</Pill></td>
                        <td>
                          <button
                            class="small"
                            disabled={!!locked}
                            title={locked || 'Remove this key'}
                            onclick={() => {
                              removeFor = { account: a, key: k }
                              dialogError = ''
                            }}>Remove</button
                          >
                        </td>
                      </tr>
                    {/each}
                  </tbody>
                </table>
              </div>
            {:else}
              <p class="subtle small">No authorized keys.</p>
            {/if}
          </div>
        {/each}
        {#if hidden.length}
          <p class="muted small">
            Other system accounts ({hidden.length}):
            {hidden.map((a) => `${a.username} (${a.uid})`).join(', ')}
          </p>
        {/if}
      </div>
    {/if}
  </Card>

  <Card title="Recent login history">
    {#if info && info.recentLogins.length}
      <div class="table-wrap">
        <table>
          <thead><tr><th>User</th><th>Terminal</th><th>From</th><th>Time</th><th>Duration</th></tr></thead>
          <tbody>
            {#each info.recentLogins as l, i (i)}
              <tr>
                <td class="mono">{l.username}</td>
                <td>{l.terminal || '—'}</td>
                <td class="mono">{l.from || '—'}</td>
                <td>{l.time || '—'}</td>
                <td>{l.duration || '—'}</td>
              </tr>
            {/each}
          </tbody>
        </table>
      </div>
    {:else if info}
      <p class="muted">No recorded logins.</p>
    {/if}
  </Card>
</div>

<Dialog open={!!addFor} title={`Add an SSH key to ${addFor?.username ?? ''}`} onclose={() => (addFor = null)}>
  <div class="row">
    <button class:primary={addMode === 'paste'} onclick={() => { addMode = 'paste'; generated = null; pasted = '' }}>Paste a key</button>
    <button
      class:primary={addMode === 'generate'}
      disabled={!canGenerate}
      title={canGenerate ? '' : 'This browser cannot generate keys'}
      onclick={() => { addMode = 'generate'; generate() }}>Generate a new key</button
    >
  </div>
  {#if addMode === 'paste'}
    <label class="field"
      >Public key <textarea rows="4" bind:value={pasted} placeholder="ssh-ed25519 AAAA… user-name" spellcheck="false"></textarea></label
    >
    <p class="muted small">Start the comment with <code>user-</code> so the key counts as a personal key.</p>
  {:else if generated}
    <div class="alert warn">
      Save the private key now — it is shown only once and never leaves this browser.
    </div>
    <div class="row">
      <button onclick={downloadPrivate}>Download private key</button>
      <button onclick={() => navigator.clipboard?.writeText(generated!.publicKey)}>Copy public key</button>
      <button onclick={generate}>Regenerate</button>
    </div>
    <label class="field">Public key <textarea rows="3" readonly value={generated.publicKey}></textarea></label>
    <p class="mono small break">{generated.fingerprint}</p>
  {/if}
  {#if dialogError}<p class="error">{dialogError}</p>{/if}
  {#snippet actions()}
    <button onclick={() => (addFor = null)} disabled={busy}>Cancel</button>
    <button class="primary" onclick={submitAdd} disabled={busy || !pasted.trim()}>{busy ? 'Adding…' : 'Add key'}</button>
  {/snippet}
</Dialog>

<Dialog open={!!removeFor} title="Remove SSH key" onclose={() => (removeFor = null)}>
  {#if removeFor}
    <p>Remove this key from <strong>{removeFor.account.username}</strong>?</p>
    <dl class="kv">
      <dt>Fingerprint</dt>
      <dd class="mono break">{removeFor.key.fingerprint}</dd>
      <dt>Comment</dt>
      <dd>{removeFor.key.comment || '—'}</dd>
    </dl>
    {#if leavesNoUserKey}
      <div class="alert warn">
        Removing this key would leave <strong>no USER key</strong> on this box. Add a <code>user-</code> key first unless
        you are sure another route in (e.g. support access) is available.
      </div>
    {/if}
  {/if}
  {#if dialogError}<p class="error">{dialogError}</p>{/if}
  {#snippet actions()}
    <button onclick={() => (removeFor = null)} disabled={busy}>Cancel</button>
    <button class="danger" onclick={submitRemove} disabled={busy}>{busy ? 'Removing…' : 'Remove'}</button>
  {/snippet}
</Dialog>

<Dialog open={confirmSupportOff} title="Disable support access?" onclose={() => (confirmSupportOff = false)}>
  <div class="alert warn">
    There is no USER key on this box. Without support access and without a personal key, you could lock yourself out
    of SSH.
  </div>
  {#snippet actions()}
    <button onclick={() => (confirmSupportOff = false)} disabled={supportBusy}>Cancel</button>
    <button class="danger" onclick={() => setSupport(false)} disabled={supportBusy}>Disable anyway</button>
  {/snippet}
</Dialog>

<style>
  .consent {
    background: var(--surface);
    border: 2px solid var(--border-strong);
    border-radius: var(--radius-card);
    padding: 1rem 1.1rem;
    display: grid;
    gap: 0.75rem;
  }
  .consent.bad {
    border-color: var(--bad-fg);
  }
  .consent.warn {
    border-color: var(--warn-fg);
  }
  .consent.info {
    border-color: var(--info-fg);
  }
  .consent h2 {
    margin: 0;
    font-size: 1rem;
  }
  .host {
    font-size: 1.1rem;
    font-weight: 700;
  }
  .end {
    justify-content: flex-end;
  }
  .account {
    border: 1px solid var(--border);
    border-radius: 8px;
    padding: 0.75rem;
  }
  .spacer {
    flex: 1;
  }
  .small {
    font-size: 0.8rem;
  }
  ul {
    margin: 0.4rem 0;
    padding-left: 1.25rem;
  }
</style>
