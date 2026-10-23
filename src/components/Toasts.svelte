<script lang="ts">
  // Rückmeldungen unten rechts, gleiten ein und aus
  import { fly } from 'svelte/transition'
  import { flip } from 'svelte/animate'
  import { toasts } from '../lib/toast.svelte'
  import Icon from './Icon.svelte'
  import { t } from '../lib/i18n.svelte'

  const icons = { success: 'check', info: 'shield', warn: 'alert', error: 'alert' }
</script>

<div class="stack" role="status" aria-live="polite">
  {#each toasts.items as x (x.id)}
    <div class="toast {x.kind}" in:fly={{ x: 24, duration: 320 }} out:fly={{ x: 24, duration: 220 }} animate:flip={{ duration: 260 }}>
      <span class="ic"><Icon name={icons[x.kind]} size={15} /></span>
      <div class="body">
        <div class="text">{x.text}</div>
        {#if x.detail}<div class="detail">{x.detail}</div>{/if}
      </div>
      <button class="close" onclick={() => toasts.dismiss(x.id)} aria-label={t('common.closeMessage')}><Icon name="x" size={13} /></button>
    </div>
  {/each}
</div>

<style>
  .stack {
    position: fixed;
    right: 20px;
    bottom: 20px;
    display: flex;
    flex-direction: column;
    gap: 8px;
    z-index: 50;
    max-width: min(420px, calc(100vw - 40px));
  }
  .toast {
    display: flex;
    align-items: flex-start;
    gap: 11px;
    padding: 12px 12px 12px 14px;
    background: var(--bg-raised);
    border: 1px solid var(--line-strong);
    border-left: 2px solid var(--text-dim);
    border-radius: var(--radius);
    box-shadow: var(--shadow);
  }
  .toast.success {
    border-left-color: var(--safe);
  }
  .toast.warn {
    border-left-color: var(--warn);
  }
  .toast.error {
    border-left-color: var(--threat);
  }
  .ic {
    margin-top: 2px;
    color: var(--text-dim);
  }
  .success .ic {
    color: var(--safe);
  }
  .error .ic {
    color: var(--threat);
  }
  .warn .ic {
    color: var(--warn);
  }
  .body {
    flex: 1;
    min-width: 0;
  }
  .text {
    font-weight: 560;
  }
  .detail {
    margin-top: 3px;
    color: var(--text-dim);
    font-size: 13px;
    word-break: break-word;
    user-select: text;
  }
  .close {
    border: 0;
    background: none;
    color: var(--text-faint);
    padding: 2px;
    border-radius: 3px;
  }
  .close:hover {
    color: var(--text);
  }
</style>
