<script lang="ts">
  import Account from './pages/Account.svelte'
  import Access from './pages/Access.svelte'
  import { api, errorText, type Me } from './lib/api'

  let me = $state<Me | null>(null)
  let error = $state('')

  $effect(() => {
    api
      .get<Me>('/api/me')
      .then((m) => (me = m))
      .catch((e) => (error = errorText(e)))
  })

  // Access is admin-only. Hiding it is cosmetic — the API answers 403 anyway.
  const pages = $derived([
    { path: '/', label: 'Account', component: Account },
    ...(me?.isAdmin ? [{ path: '/access', label: 'Access', component: Access }] : []),
  ])

  let path = $state(location.pathname)
  const current = $derived(pages.find((p) => p.path === path) ?? pages[0])

  function go(e: MouseEvent, to: string) {
    if (e.metaKey || e.ctrlKey || e.shiftKey || e.button !== 0) return
    e.preventDefault()
    // Keep the query string only on the page it was meant for (deep links).
    if (to !== path) history.pushState(null, '', to)
    path = to
  }

  $effect(() => {
    const onPop = () => (path = location.pathname)
    addEventListener('popstate', onPop)
    return () => removeEventListener('popstate', onPop)
  })

  $effect(() => {
    document.title = current.path === '/' ? 'Auth Console' : `${current.label} · Auth Console`
  })
</script>

<header class="top">
  <div class="inner">
    <a class="brand" href="/" onclick={(e) => go(e, '/')}>
      <img src="/icon.svg" alt="" width="24" height="24" />
      <span>Auth Console</span>
    </a>
    <nav>
      {#each pages as p (p.path)}
        <a href={p.path} class:active={p.path === current.path} onclick={(e) => go(e, p.path)}>{p.label}</a>
      {/each}
    </nav>
    {#if me}
      <div class="who">
        <span class="muted">{me.identity.name || me.identity.user}</span>
        <a href={me.logoutUrl}>Sign out</a>
      </div>
    {/if}
  </div>
</header>

<main>
  {#if error}
    <p class="error">{error}</p>
  {:else if !me}
    <p class="muted">Loading…</p>
  {:else}
    {#key current.path}
      <current.component {me} />
    {/key}
  {/if}
</main>

<style>
  .top {
    background: var(--surface);
    border-bottom: 1px solid var(--border);
    position: sticky;
    top: 0;
    z-index: 10;
  }
  .inner {
    max-width: 1100px;
    margin: 0 auto;
    padding: 0 16px;
    display: flex;
    align-items: center;
    gap: 1.5rem;
    height: 52px;
  }
  .brand {
    display: flex;
    align-items: center;
    gap: 0.5rem;
    font-weight: 600;
    color: var(--text);
    white-space: nowrap;
  }
  .brand:hover {
    text-decoration: none;
  }
  nav {
    display: flex;
    gap: 0.25rem;
    overflow-x: auto;
    flex: 1;
  }
  nav a {
    padding: 0.4rem 0.7rem;
    border-radius: 8px;
    color: var(--text-muted);
    white-space: nowrap;
  }
  nav a:hover {
    background: var(--surface-2);
    text-decoration: none;
  }
  nav a.active {
    background: var(--surface-3);
    color: var(--text);
    font-weight: 600;
  }
  .who {
    display: flex;
    gap: 0.75rem;
    white-space: nowrap;
  }
  main {
    max-width: 1100px;
    margin: 0 auto;
    padding: 1.25rem 16px 3rem;
  }
  @media (max-width: 620px) {
    .brand span,
    .who .muted {
      display: none;
    }
  }
</style>
