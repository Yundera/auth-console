<script lang="ts">
  import type { Snippet } from 'svelte'

  // A native modal <dialog>: focus trap, Escape and the backdrop come from the
  // browser. `open` drives showModal()/close(); closing by Escape reports back
  // through onclose so the parent's state stays the source of truth.
  let {
    open,
    title,
    onclose,
    children,
    actions,
  }: { open: boolean; title: string; onclose: () => void; children: Snippet; actions?: Snippet } = $props()

  let el: HTMLDialogElement | undefined = $state()

  $effect(() => {
    if (!el) return
    if (open && !el.open) el.showModal()
    if (!open && el.open) el.close()
  })
</script>

<dialog bind:this={el} onclose={() => open && onclose()}>
  <h2>{title}</h2>
  <div class="body">{@render children()}</div>
  {#if actions}<div class="actions">{@render actions()}</div>{/if}
</dialog>

<style>
  dialog {
    border: 1px solid var(--border);
    border-radius: var(--radius-card);
    padding: 1.1rem 1.25rem;
    width: min(520px, calc(100vw - 32px));
    background: var(--surface);
    color: var(--text);
  }
  dialog::backdrop {
    background: rgb(0 0 0 / 0.35);
  }
  h2 {
    margin: 0 0 0.75rem;
    font-size: 1rem;
  }
  .body {
    display: grid;
    gap: 0.75rem;
  }
  .actions {
    display: flex;
    justify-content: flex-end;
    gap: 0.5rem;
    margin-top: 1rem;
    flex-wrap: wrap;
  }
</style>
