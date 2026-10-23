<script lang="ts">
  // Prüfarten zur Auswahl, mit Dauer der letzten gleichen Prüfung
  import { fade } from 'svelte/transition'
  import { invoke } from '@tauri-apps/api/core'
  import Icon from '../components/Icon.svelte'
  import { app } from '../lib/store.svelte'
  import { duration, relative } from '../lib/format'
  import { i18n, t } from '../lib/i18n.svelte'
  import { toasts } from '../lib/toast.svelte'

  const kinds = $derived([
    { id: 'quick' as const, title: t('kind.quick'), text: t('scan.quickText') },
    { id: 'full' as const, title: t('kind.full'), text: t('scan.fullText') },
    { id: 'custom' as const, title: t('kind.custom'), text: t('scan.customText') },
  ])

  function last(kind: string) {
    return app.reports.find((r) => r.kind === kind && r.phase === 'finished') ?? null
  }

  async function start(kind: 'quick' | 'full' | 'custom') {
    if (kind !== 'custom') return app.startScan(kind)
    try {
      const picked = await invoke<string[] | null>('pick_folders')
      if (picked && picked.length) {
        app.page = 'overview'
        app.startJob('custom', picked)
      }
    } catch (e) {
      toasts.show('error', t('overview.folderFailed'), String(e))
    }
  }
  const nf = $derived(new Intl.NumberFormat(i18n.locale))
</script>

<div class="page" in:fade={{ duration: 220 }}>
  <header class="page-head">
    <div>
      <h1 class="page-title">{t('scan.title')}</h1>
      <p class="page-sub">{t('scan.sub')}</p>
    </div>
  </header>

  <ul class="rows stagger">
    {#each kinds as k, i (k.id)}
      {@const r = last(k.id)}
      <li class="kind" style="--i: {i}">
        <div class="main">
          <h2 class="display">{k.title}</h2>
          <p>{k.text}</p>
        </div>
        <div class="meta">
          {#if r}
            <span class="mono">{duration(r.durationSecs)}</span>
            <span>{t('scan.lastRun', { when: relative(r.finishedAt), n: nf.format(r.scanned) })}</span>
          {:else}
            <span class="faint">{t('scan.never')}</span>
          {/if}
        </div>
        <button class="btn {i === 0 ? 'primary' : ''}" class:busy={app.pending[`job:${k.id}`] || app.scanActive} onclick={() => start(k.id)}>
          <Icon name={k.id === 'custom' ? 'folder' : 'play'} size={14} /><span>{k.id === 'custom' ? t('scan.choose') : t('scan.start')}</span>
        </button>
      </li>
    {/each}
  </ul>

  <p class="label section-label">{t('scan.signatures')}</p>
  <div class="sig-row">
    <div>
      <div class="big">{app.snap?.signatures ? t('scan.sigVersion', { v: app.snap.signatures.version }) : t('scan.noSig')}</div>
      <div class="faint">
        {#if app.snap?.signatures}{t('scan.sigText', { when: relative(app.snap.signatures.date), checked: relative(app.snap.signatures.checkedAt ?? app.snap.signatures.date) })}{:else}{t('scan.noClam')}{/if}
      </div>
    </div>
    <button class="btn" class:busy={app.pending['job:update'] || (app.jobActive && app.job?.kind === 'update')} onclick={() => app.startJob('update')}>
      <Icon name="refresh" size={14} /><span>{t('scan.updateNow')}</span>
    </button>
  </div>
</div>

<style>
  .kind {
    display: grid;
    grid-template-columns: minmax(0, 1fr) 230px auto;
    align-items: center;
    gap: 28px;
    padding: 24px 0;
    transition: background-color var(--t-normal) ease;
  }
  h2 {
    margin: 0 0 4px;
    font-size: calc(22px * var(--display-scale));
    letter-spacing: calc(var(--display-tracking) * 0.4);
  }
  .main p {
    margin: 0;
    color: var(--text-dim);
    max-width: 600px;
  }
  .meta {
    display: flex;
    flex-direction: column;
    gap: 2px;
    font-size: 13px;
    color: var(--text-dim);
  }
  .meta .mono {
    font-size: 15px;
    color: var(--text);
  }
  .faint {
    color: var(--text-faint);
  }
  .sig-row {
    display: flex;
    align-items: center;
    justify-content: space-between;
    gap: 24px;
    padding: 16px 0;
    border-top: 1px solid var(--line);
    border-bottom: 1px solid var(--line);
  }
  .big {
    font-size: 16px;
    font-weight: 600;
  }
  @media (max-width: 900px) {
    .kind {
      grid-template-columns: 1fr auto;
    }
    .meta {
      display: none;
    }
  }
</style>
