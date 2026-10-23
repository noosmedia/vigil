<script lang="ts">
  // Fortschritt eines laufenden Updates: Balken und ein Satz, der sagt, was gerade passiert
  import { fade } from 'svelte/transition'
  import { app } from '../lib/store.svelte'
  import { bytes } from '../lib/format'
  import { t } from '../lib/i18n.svelte'

  const p = $derived(app.updateProgress)
  const name = $derived(p?.part === 'pro' ? 'Vigil Pro' : 'Vigil')
  // Anteil 0..1 nur beim Herunterladen mit bekannter Größe, sonst wandernder Balken
  const share = $derived(p && p.phase === 'download' && p.total > 0 ? Math.min(1, p.done / p.total) : null)
  const text = $derived.by(() => {
    if (!p) return ''
    switch (p.phase) {
      case 'download':
        return p.total > 0
          ? t('updateRun.progress.download', { name, done: bytes(p.done), total: bytes(p.total) })
          : t('updateRun.progress.downloadNoSize', { name, done: bytes(p.done) })
      case 'verify':
        return t('updateRun.progress.verify', { name })
      case 'install':
        return t('updateRun.progress.install', { name })
      case 'prepare':
        return t('updateRun.progress.prepare')
      default:
        return t('updateRun.progress.done', { name })
    }
  })
</script>

{#if p}
  <div class="up" in:fade={{ duration: 200 }}>
    <div class="track" class:moving={share === null}>
      <span class="fill" style={share !== null ? `width: ${Math.round(share * 100)}%` : ''}></span>
    </div>
    <div class="txt">{text}</div>
  </div>
{/if}

<style>
  .up {
    margin-top: 10px;
  }
  .track {
    position: relative;
    height: 4px;
    border-radius: 2px;
    overflow: hidden;
    background: var(--line);
  }
  .fill {
    position: absolute;
    inset: 0 auto 0 0;
    border-radius: 2px;
    background: var(--safe);
    transition: width var(--t-fast) linear;
  }
  /* Ohne bekannte Größe: ein Stück Balken wandert hin und her */
  .track.moving .fill {
    width: 30%;
    animation: wander 1.3s var(--ease-inout) infinite;
  }
  @keyframes wander {
    0% {
      transform: translateX(-100%);
    }
    100% {
      transform: translateX(340%);
    }
  }
  .txt {
    margin-top: 6px;
    font-size: 12.5px;
    color: var(--text-dim);
  }
</style>
