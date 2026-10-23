<script lang="ts">
  // Kopfleiste: Wortmarke, Navigation mit gleitender Markierung, Update-Hinweis, Thema
  import { tick } from 'svelte'
  import { fly } from 'svelte/transition'
  import { app, type Page } from '../lib/store.svelte'
  import { dateTime, relative } from '../lib/format'
  import { t } from '../lib/i18n.svelte'
  import Icon from './Icon.svelte'

  const items = $derived<{ id: Page; label: string }[]>([
    { id: 'overview', label: t('nav.overview') },
    { id: 'scan', label: t('nav.scan') },
    { id: 'findings', label: t('nav.findings') },
    { id: 'system', label: t('nav.system') },
    { id: 'history', label: t('nav.history') },
    { id: 'pro', label: t('nav.pro') },
    { id: 'settings', label: t('nav.settings') },
  ])

  let nav = $state<HTMLElement | null>(null)
  let marker = $state({ x: 0, w: 0, ready: false })

  // Markierung unter den aktiven Punkt schieben
  async function place() {
    await tick()
    const el = nav?.querySelector<HTMLElement>(`[data-id="${app.page}"]`)
    if (!el) return
    marker = { x: el.offsetLeft + 12, w: el.offsetWidth - 24, ready: true }
  }

  $effect(() => {
    void app.page
    void items
    place()
  })

  const theme = $derived(app.snap?.settings.theme ?? 'system')
  function cycleTheme() {
    if (!app.snap) return
    const next = theme === 'system' ? 'dark' : theme === 'dark' ? 'light' : 'system'
    app.saveSettings({ ...app.snap.settings, theme: next })
  }
  const themeLabel = $derived(t(`nav.theme.${theme}`))
  const status = $derived(app.status)
  // Welche Teile neu sind, steht im Tooltip
  const updateTitle = $derived(
    [app.update?.available ? `Vigil ${app.update.latest ?? ''}` : '', app.proUpdateVersion ? `Vigil Pro ${app.proUpdateVersion}` : '']
      .filter(Boolean)
      .join(', ') + ` · ${t('nav.updateTitle')}`,
  )
</script>

<svelte:window onresize={place} />

<header class="bar">
  <div class="brand" class:scanning={status === 'scanning' || status === 'counting'} class:threat={status === 'threat'} class:warn={status === 'warn' || status === 'paused'}>
    <svg class="mark" viewBox="0 0 28 28" aria-hidden="true">
      <circle class="ring" cx="14" cy="14" r="10.5" fill="none" stroke="currentColor" stroke-width="1.6" stroke-dasharray="52 14" stroke-linecap="round" />
      <circle class="iris" cx="14" cy="14" r="3.2" />
    </svg>
    <span class="word display">vigil</span>
    {#if app.license?.active}<span class="pro-tag" in:fly={{ y: -4, duration: 360 }} title="Vigil Pro">Pro</span>{/if}
  </div>

  <nav bind:this={nav} aria-label={t('nav.areas')}>
    {#each items as it (it.id)}
      <button data-id={it.id} class:active={app.page === it.id} onclick={() => (app.page = it.id)} aria-current={app.page === it.id ? 'page' : undefined}>
        {it.label}
        {#if it.id === 'findings' && app.threatCount > 0}<span class="badge">{app.threatCount}</span>{/if}
      </button>
    {/each}
    <span class="marker" class:ready={marker.ready} style="transform: translateX({marker.x}px); width: {marker.w}px"></span>
  </nav>

  <div class="right">
    {#if app.anyUpdate}
      <button class="update" in:fly={{ y: -8, duration: 400 }} onclick={() => (app.page = 'settings')} title={updateTitle}>
        <Icon name="arrowUp" size={13} />{app.update?.available ? t('nav.update') : t('nav.updatePro')}
      </button>
    {/if}
    {#if app.snap?.signatures}
      <span class="sig mono" title={t('nav.sigTitle', { v: app.snap.signatures.version, date: app.snap.signatures.date ? dateTime(app.snap.signatures.date) : '' })}>{t('nav.sig', { age: relative(app.snap.signatures.checkedAt ?? app.snap.signatures.date) })}</span>
    {/if}
    <button class="icon-btn" onclick={cycleTheme} title={themeLabel} aria-label={themeLabel}>
      <Icon name={theme === 'system' ? 'auto' : theme === 'dark' ? 'moon' : 'sun'} size={16} />
    </button>
  </div>
</header>

<style>
  .bar {
    position: relative;
    z-index: 5;
    display: flex;
    align-items: center;
    gap: 26px;
    height: 54px;
    padding: 0 var(--pad);
    border-bottom: 1px solid var(--line);
    background: var(--bg);
  }
  :global(:root[data-look='terminal']) .bar {
    border-bottom-style: dashed;
  }
  .brand {
    display: flex;
    align-items: center;
    gap: 9px;
    color: var(--text);
  }
  .mark {
    width: 22px;
    height: 22px;
    animation: turn 24s linear infinite;
  }
  /* Während einer Prüfung dreht der Ring schneller */
  .brand.scanning .mark {
    animation-duration: 2.4s;
  }
  .iris {
    fill: var(--safe);
    transform-origin: 14px 14px;
    animation: blink 7s var(--ease-inout) infinite;
    transition: fill var(--t-normal) ease;
  }
  .brand.threat .iris {
    fill: var(--threat);
    animation: beat 1.4s var(--ease-inout) infinite;
  }
  .brand.warn .iris {
    fill: var(--warn);
  }
  @keyframes turn {
    to {
      transform: rotate(360deg);
    }
  }
  @keyframes blink {
    0%,
    92%,
    100% {
      transform: scale(1);
    }
    95% {
      transform: scale(0.25);
    }
  }
  @keyframes beat {
    50% {
      transform: scale(1.35);
    }
  }
  /* Kleines „Pro“ oben rechts an der Wortmarke, nur bei freigeschalteter Lizenz */
  .pro-tag {
    align-self: flex-start;
    margin: -3px 0 0 -5px;
    font-family: var(--font-body);
    font-size: 9.5px;
    font-weight: 700;
    letter-spacing: 0.06em;
    text-transform: uppercase;
    color: var(--safe);
  }
  .word {
    font-size: calc(21px * var(--display-scale));
    line-height: 1;
    margin-top: -2px;
    text-transform: none;
  }
  nav {
    position: relative;
    display: flex;
    align-items: stretch;
    height: 100%;
    flex: 1;
    min-width: 0;
    overflow-x: auto;
    scrollbar-width: none;
  }
  nav::-webkit-scrollbar {
    display: none;
  }
  nav button {
    position: relative;
    display: inline-flex;
    align-items: center;
    gap: 7px;
    padding: 0 12px;
    border: 0;
    background: none;
    color: var(--text-dim);
    font-weight: 520;
    white-space: nowrap;
    transition: color var(--t-fast) ease;
  }
  nav button:hover,
  nav button.active {
    color: var(--text);
  }
  .badge {
    min-width: 18px;
    height: 18px;
    padding: 0 5px;
    border-radius: 9px;
    background: var(--threat);
    color: #fff;
    font-size: 11px;
    font-weight: 700;
    display: inline-grid;
    place-items: center;
    animation: pop 420ms var(--ease-spring);
  }
  @keyframes pop {
    from {
      transform: scale(0.4);
      opacity: 0;
    }
  }
  .marker {
    position: absolute;
    left: 0;
    bottom: -1px;
    height: 2px;
    background: var(--text);
    opacity: 0;
    transition:
      transform var(--t-normal) var(--ease-out),
      width var(--t-normal) var(--ease-out),
      opacity var(--t-fast) ease;
  }
  .marker.ready {
    opacity: 1;
  }
  .right {
    display: flex;
    align-items: center;
    gap: 14px;
  }
  .update {
    display: inline-flex;
    align-items: center;
    gap: 6px;
    height: 26px;
    padding: 0 10px;
    border: 1px solid rgba(var(--safe-rgb), 0.5);
    border-radius: 13px;
    background: rgba(var(--safe-rgb), 0.1);
    color: var(--safe);
    font-size: 12px;
    font-weight: 600;
    white-space: nowrap;
    transition: background-color var(--t-fast) ease;
  }
  .update:hover {
    background: rgba(var(--safe-rgb), 0.2);
  }
  .sig {
    font-size: 11.5px;
    color: var(--text-faint);
    white-space: nowrap;
  }
  .icon-btn {
    width: 32px;
    height: 32px;
    display: grid;
    place-items: center;
    border: 1px solid transparent;
    border-radius: var(--radius);
    background: none;
    color: var(--text-dim);
    transition: all var(--t-fast) ease;
  }
  .icon-btn:hover {
    color: var(--text);
    border-color: var(--line);
  }
  @media (max-width: 1100px) {
    .sig {
      display: none;
    }
  }
</style>
