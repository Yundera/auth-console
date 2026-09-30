<script lang="ts">
  import type { Snippet } from 'svelte'

  let { title, actions, children }: { title?: string; actions?: Snippet; children: Snippet } = $props()
</script>

<section class="card">
  {#if title || actions}
    <header>
      {#if title}<h2>{title}</h2>{/if}
      {#if actions}<div class="actions">{@render actions()}</div>{/if}
    </header>
  {/if}
  {@render children()}
</section>

<style>
  .card {
    background: var(--surface);
    border: 1px solid var(--border);
    border-radius: var(--radius-card);
    padding: 1rem 1.1rem;
    min-width: 0;
  }
  header {
    display: flex;
    align-items: center;
    justify-content: space-between;
    gap: 0.75rem;
    margin-bottom: 0.75rem;
  }
  h2 {
    margin: 0;
    font-size: 0.95rem;
    font-weight: 600;
  }
  .actions {
    display: flex;
    gap: 0.5rem;
  }
</style>
