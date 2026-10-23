<script lang="ts" module>
  // Eigener Bestätigungsdialog statt Browser-Dialog; Abbrechen ist die Vorauswahl
  interface Request {
    title: string
    text: string
    confirm: string
    danger?: boolean
    resolve: (ok: boolean) => void
  }

  let current = $state<Request | null>(null)

  export function ask(title: string, text: string, confirm: string, danger = false): Promise<boolean> {
    return new Promise((resolve) => {
      current = { title, text, confirm, danger, resolve }
    })
  }
</script>

<script lang="ts">
  import { fade, scale } from 'svelte/transition'
  import { t } from '../lib/i18n.svelte'

  let cancelBtn = $state<HTMLButtonElement | null>(null)

  function close(ok: boolean) {
    current?.resolve(ok)
    current = null
  }

  $effect(() => {
    if (current && cancelBtn) cancelBtn.focus()
  })

  function onKey(e: KeyboardEvent) {
    if (current && e.key === 'Escape') close(false)
  }
</script>

<svelte:window onkeydown={onKey} />

{#if current}
  <div class="scrim" transition:fade={{ duration: 180 }} onclick={() => close(false)} role="presentation"></div>
  <div class="dialog" role="alertdialog" aria-modal="true" aria-labelledby="dlg-title" transition:scale={{ start: 0.96, duration: 220 }}>
    <h2 id="dlg-title">{current.title}</h2>
    <p>{current.text}</p>
    <div class="actions">
      <button class="btn" bind:this={cancelBtn} onclick={() => close(false)}>{t('common.cancel')}</button>
      <button class="btn {current.danger ? 'danger' : 'primary'}" onclick={() => close(true)}>{current.confirm}</button>
    </div>
  </div>
{/if}

<style>
  .scrim {
    position: fixed;
    inset: 0;
    background: rgba(8, 12, 11, 0.55);
    z-index: 60;
  }
  .dialog {
    position: fixed;
    left: 50%;
    top: 50%;
    translate: -50% -50%;
    width: min(460px, calc(100vw - 40px));
    background: var(--bg-raised);
    border: 1px solid var(--line-strong);
    border-radius: var(--radius);
    box-shadow: var(--shadow);
    padding: 24px;
    z-index: 61;
  }
  h2 {
    margin: 0 0 8px;
    font-family: var(--font-display);
    font-variation-settings: 'wdth' 82;
    font-weight: 620;
    font-size: 22px;
    letter-spacing: -0.01em;
  }
  p {
    margin: 0;
    color: var(--text-dim);
    word-break: break-word;
  }
  .actions {
    display: flex;
    justify-content: flex-end;
    gap: 10px;
    margin-top: 22px;
  }
</style>
