<script lang="ts">
  import Card from '../lib/Card.svelte'
  import Pill from '../lib/Pill.svelte'
  import Dialog from '../lib/Dialog.svelte'
  import {
    api,
    errorText,
    type Capabilities,
    type Credentials,
    type LocalUser,
    type Me,
    type Onboarding,
    type UsersResponse,
  } from '../lib/api'

  let { me }: { me: Me } = $props()

  const ADMIN_GROUP = 'admins'
  const isAdminUser = (u: LocalUser) => u.groups.includes(ADMIN_GROUP) || u.groups.includes('admin')

  let users = $state<UsersResponse | null>(null)
  let usersError = $state('')
  let onboarding = $state<Onboarding | null>(null)
  let notice = $state<{ tone: 'ok' | 'warn' | 'bad'; text: string } | null>(null)

  async function loadUsers() {
    usersError = ''
    try {
      users = await api.get<UsersResponse>('/api/users')
    } catch (e) {
      usersError = errorText(e)
    }
  }

  $effect(() => {
    if (!me.isAdmin) return
    loadUsers()
    api
      .get<Capabilities>('/api/capabilities')
      .then((c) => {
        if (c.onboarding) {
          api
            .get<Onboarding>('/api/onboarding')
            .then((o) => (onboarding = o))
            .catch(() => (onboarding = null))
        }
      })
      .catch(() => {})
  })

  // ---- dialogs ---------------------------------------------------------------

  let busy = $state(false)
  let dialogError = $state('')

  // Add
  let addOpen = $state(false)
  let add = $state({ username: '', displayname: '', email: '', isAdmin: false })
  const addReady = $derived(!!(add.username.trim() && add.displayname.trim() && add.email.trim()))

  // One-time credentials (add / reset)
  let creds = $state<Credentials | null>(null)

  // Email
  let emailFor = $state<LocalUser | null>(null)
  let emailValue = $state('')

  // Reset / delete confirmations
  let resetFor = $state<LocalUser | null>(null)
  let deleteFor = $state<LocalUser | null>(null)

  function openAdd() {
    add = { username: '', displayname: '', email: '', isAdmin: false }
    dialogError = ''
    addOpen = true
  }

  async function run(fn: () => Promise<void>) {
    busy = true
    dialogError = ''
    try {
      await fn()
    } catch (e) {
      dialogError = errorText(e)
    } finally {
      busy = false
    }
  }

  const submitAdd = () =>
    run(async () => {
      creds = await api.post<Credentials>('/api/users', {
        username: add.username.trim(),
        displayname: add.displayname.trim(),
        email: add.email.trim(),
        isAdmin: add.isAdmin,
      })
      addOpen = false
      await loadUsers()
    })

  const submitEmail = () =>
    run(async () => {
      const u = emailFor!
      await api.put(`/api/users/${encodeURIComponent(u.username)}/email`, { email: emailValue.trim() })
      notice = { tone: 'ok', text: `Email of ${u.username} updated.` }
      emailFor = null
      await loadUsers()
    })

  const submitReset = () =>
    run(async () => {
      const u = resetFor!
      creds = await api.post<Credentials>(`/api/users/${encodeURIComponent(u.username)}/reset-password`)
      resetFor = null
    })

  const submitDelete = () =>
    run(async () => {
      const u = deleteFor!
      const res = await api.del<{ warning?: string }>(`/api/users/${encodeURIComponent(u.username)}`)
      notice = res.warning ? { tone: 'warn', text: res.warning } : { tone: 'ok', text: `Revoked ${u.username}.` }
      deleteFor = null
      await loadUsers()
    })

  async function copy(text: string) {
    try {
      await navigator.clipboard.writeText(text)
    } catch {
      /* clipboard unavailable (plain http, permissions) — the value is on screen */
    }
  }
</script>

<div class="stack">
  <Card title="Your account">
    <div class="row">
      <strong>{me.identity.name || me.identity.user}</strong>
      <Pill tone={me.isAdmin ? 'info' : 'neutral'}>{me.isAdmin ? 'Administrator' : 'User'}</Pill>
    </div>
    <p class="muted">
      Signed in as <strong>{me.identity.user}</strong>{#if me.identity.email}&nbsp;· {me.identity.email}{/if}
    </p>
    {#if me.identity.method === 'oidc' && me.localAuthUrl}
      <p class="muted">
        Your password, password reset by email and two-factor authentication are managed on the sign-in portal.
        This console never sees your password.
      </p>
      <div class="row">
        <button onclick={() => window.open(me.localAuthUrl, '_blank', 'noopener')}>Manage sign-in</button>
      </div>
    {/if}
  </Card>

  {#if me.isAdmin}
    {#if notice}
      <div class="alert {notice.tone}">{notice.text}</div>
    {/if}

    <Card title="Local accounts">
      {#snippet actions()}
        <button onclick={loadUsers}>Refresh</button>
        <button class="primary" onclick={openAdd}>Add user</button>
      {/snippet}
      <p class="muted">
        The accounts behind the "Local Account" sign-in button. An administrator can manage users and SSH access
        — treat it as root.
      </p>
      {#if usersError}
        <p class="error">{usersError}</p>
      {:else if !users}
        <p class="muted">Loading…</p>
      {:else if users.users.length === 0}
        <p class="muted">No local accounts.</p>
      {:else}
        <div class="table-wrap">
          <table>
            <thead>
              <tr><th>Username</th><th>Display name</th><th>Email</th><th>Role</th><th></th></tr>
            </thead>
            <tbody>
              {#each users.users as u (u.username)}
                {@const self = u.username === users.currentUser}
                <tr>
                  <td class="mono">
                    {u.username}{#if self}&nbsp;<span class="muted">(you)</span>{/if}
                    {#if u.protected}&nbsp;<Pill>owner</Pill>{/if}
                    {#if u.disabled}&nbsp;<Pill tone="warn">disabled</Pill>{/if}
                  </td>
                  <td>{u.displayname}</td>
                  <td class="break">{u.email}</td>
                  <td>{isAdminUser(u) ? 'Administrator' : 'User'}</td>
                  <td>
                    <div class="row">
                      <button
                        class="small"
                        disabled={u.protected}
                        title={u.protected ? "The owner's email follows the platform EMAIL setting" : 'Change email'}
                        onclick={() => {
                          emailFor = u
                          emailValue = u.email
                          dialogError = ''
                        }}>Email</button
                      >
                      <button
                        class="small"
                        onclick={() => {
                          resetFor = u
                          dialogError = ''
                        }}>Reset password</button
                      >
                      <button
                        class="small"
                        disabled={u.protected || self}
                        title={u.protected
                          ? 'The owner account cannot be revoked'
                          : self
                            ? 'You cannot revoke the account you are signed in as'
                            : 'Revoke access'}
                        onclick={() => {
                          deleteFor = u
                          dialogError = ''
                        }}>Revoke</button
                      >
                    </div>
                  </td>
                </tr>
              {/each}
            </tbody>
          </table>
        </div>
      {/if}
    </Card>

    {#if onboarding}
      <Card title="Onboarding">
        <p>
          This box is currently <strong>{onboarding.claimed ? 'claimed' : 'unclaimed'}</strong>{#if onboarding.claimed && onboarding.username}&nbsp;by
            <strong>{onboarding.username}</strong>{/if}.
        </p>
        <p class="muted">
          Re-running onboarding deletes every local account. It is done from a terminal on the box:
          <code>onboarding.sh reset --confirm</code>.
        </p>
      </Card>
    {/if}
  {/if}
</div>

<Dialog open={addOpen} title="Add a local account" onclose={() => (addOpen = false)}>
  <label class="field">Username <input bind:value={add.username} autocomplete="off" spellcheck="false" /></label>
  <label class="field">Display name <input bind:value={add.displayname} autocomplete="off" /></label>
  <label class="field">Email <input type="email" bind:value={add.email} autocomplete="off" /></label>
  <label class="row"><input type="checkbox" bind:checked={add.isAdmin} /> Administrator</label>
  {#if add.isAdmin}
    <div class="alert warn">
      An administrator can manage every account and SSH access on this box — effectively root.
    </div>
  {/if}
  {#if dialogError}<p class="error">{dialogError}</p>{/if}
  {#snippet actions()}
    <button onclick={() => (addOpen = false)} disabled={busy}>Cancel</button>
    <button class="primary" onclick={submitAdd} disabled={busy || !addReady}>{busy ? 'Creating…' : 'Create'}</button>
  {/snippet}
</Dialog>

<Dialog open={!!creds} title="One-time password" onclose={() => (creds = null)}>
  {#if creds}
    <div class="alert warn">Copy this password now — it is shown only once. The user can change it on the sign-in portal.</div>
    <dl class="kv">
      <dt>Username</dt>
      <dd class="mono">{creds.username} <button class="small" onclick={() => copy(creds!.username)}>Copy</button></dd>
      <dt>Password</dt>
      <dd class="mono">{creds.password} <button class="small" onclick={() => copy(creds!.password)}>Copy</button></dd>
    </dl>
  {/if}
  {#snippet actions()}
    <button class="primary" onclick={() => (creds = null)}>Done</button>
  {/snippet}
</Dialog>

<Dialog open={!!emailFor} title="Change email" onclose={() => (emailFor = null)}>
  <p class="muted">Password-reset mails for <strong>{emailFor?.username}</strong> go to this address.</p>
  <label class="field">Email <input type="email" bind:value={emailValue} /></label>
  {#if dialogError}<p class="error">{dialogError}</p>{/if}
  {#snippet actions()}
    <button onclick={() => (emailFor = null)} disabled={busy}>Cancel</button>
    <button class="primary" onclick={submitEmail} disabled={busy || !emailValue.trim()}>Save</button>
  {/snippet}
</Dialog>

<Dialog open={!!resetFor} title="Reset password" onclose={() => (resetFor = null)}>
  <p>
    Generate a new password for <strong>{resetFor?.username}</strong>? Their current password stops working and
    their sessions on this console are ended.
  </p>
  <p class="muted">Sessions on other apps end when they expire or sign out.</p>
  {#if dialogError}<p class="error">{dialogError}</p>{/if}
  {#snippet actions()}
    <button onclick={() => (resetFor = null)} disabled={busy}>Cancel</button>
    <button class="primary" onclick={submitReset} disabled={busy}>{busy ? 'Resetting…' : 'Reset password'}</button>
  {/snippet}
</Dialog>

<Dialog open={!!deleteFor} title="Revoke access" onclose={() => (deleteFor = null)}>
  <p>
    Delete the account <strong>{deleteFor?.username}</strong>? They can no longer sign in, and their sessions on this
    console are ended.
  </p>
  <p class="muted">Sessions on other apps end when they expire or sign out.</p>
  {#if dialogError}<p class="error">{dialogError}</p>{/if}
  {#snippet actions()}
    <button onclick={() => (deleteFor = null)} disabled={busy}>Cancel</button>
    <button class="danger" onclick={submitDelete} disabled={busy}>{busy ? 'Revoking…' : 'Revoke'}</button>
  {/snippet}
</Dialog>
