<script lang="ts">
  import type { Snippet } from 'svelte'

  let { tone = 'neutral', children }: { tone?: 'ok' | 'warn' | 'bad' | 'info' | 'neutral'; children: Snippet } =
    $props()
</script>

<span class="pill {tone}">{@render children()}</span>

<style>
  .pill {
    display: inline-flex;
    align-items: center;
    gap: 0.3rem;
    padding: 0.12rem 0.55rem;
    border-radius: var(--radius-pill);
    font-size: 0.75rem;
    font-weight: 600;
    white-space: nowrap;
    background: var(--surface-3);
    color: var(--text-muted);
  }
  .ok {
    background: var(--ok-bg);
    color: var(--ok-fg);
  }
  .warn {
    background: var(--warn-bg);
    color: var(--warn-fg);
  }
  .bad {
    background: var(--bad-bg);
    color: var(--bad-fg);
  }
  .info {
    background: var(--info-bg);
    color: var(--info-fg);
  }
</style>
