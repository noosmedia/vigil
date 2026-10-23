<script lang="ts">
  // Vigil Pro: Kauf und Freischaltung, danach die Pro-Bereiche aus dem signierten Paket
  import { onMount, tick } from 'svelte'
  import { fade, fly } from 'svelte/transition'
  import { invoke } from '@tauri-apps/api/core'
  import { listen } from '@tauri-apps/api/event'
  import Icon from '../components/Icon.svelte'
  import UpdateProgress from '../components/UpdateProgress.svelte'
  import { ask } from '../components/Confirm.svelte'
  import { app } from '../lib/store.svelte'
  import { dateOnly, money } from '../lib/format'
  import { i18n, t } from '../lib/i18n.svelte'
  import { toasts } from '../lib/toast.svelte'
  import type { HelperResult, Plan, RawResult } from '../lib/types'

  interface ProPage {
    id: string
    element: string
    titleDe: string
    titleEn: string
  }
  interface ProModule {
    mount: (host: unknown) => void | ProPage[]
    pages?: ProPage[]
  }

  const lic = $derived(app.license)
  let key = $state('')
  let plan = $state<Plan | null>(null)
  let busy = $state<string | null>(null)
  let pages = $state<ProPage[]>([])
  let loadError = $state<string | null>(null)
  let loaded = $state(false)
  let pageHost = $state<HTMLElement | null>(null)

  const features = ['software', 'drivers', 'protection', 'mail', 'hardening', 'cleanup', 'reports', 'machines']

  // Host-Objekt für die Pro-Oberfläche: Sprache, Aussehen, Aufrufe an den Helfer und Ereignisse
  function makeHost() {
    return {
      locale: () => i18n.locale,
      look: () => app.snap?.settings.look ?? 'feld',
      palette: () => app.snap?.settings.palette ?? 'graphit',
      roRun: (args: string[]) => invoke<RawResult>('pro_ro', { args }),
      rwRun: (args: string[]) => invoke<RawResult>('pro_rw', { args }),
      agentRun: (args: string[]) => invoke<RawResult>('pro_agent_run', { args }),
      agentSend: (line: string) => invoke('pro_agent_send', { line }),
      toast: (kind: 'success' | 'info' | 'warn' | 'error', text: string, detail?: string) => toasts.show(kind, text, detail),
      confirm: (title: string, text: string, label: string, danger = false) => ask(title, text, label, danger),
      onEvent: (cb: (ev: unknown) => void) => {
        let off: (() => void) | null = null
        listen('pro-event', (e) => cb(e.payload)).then((u) => (off = u))
        return () => off?.()
      },
      navigate: (page: string) => {
        app.proPage = page
      },
    }
  }

  // Pro-Oberfläche aus dem geprüften Paket laden (Blob-URL, keine Netzquelle)
  async function loadUi() {
    if (loaded || !app.proActive) return
    try {
      const source = await invoke<string>('pro_ui_source')
      const url = URL.createObjectURL(new Blob([source], { type: 'text/javascript' }))
      await import(/* @vite-ignore */ url)
      URL.revokeObjectURL(url)
      const mod = (window as unknown as { vigilPro?: ProModule }).vigilPro
      if (!mod) throw new Error('vigilPro fehlt')
      const fromMount = mod.mount(makeHost())
      pages = (Array.isArray(fromMount) ? fromMount : mod.pages) ?? []
      if (!app.proPage && pages.length) app.proPage = pages[0].id
      loaded = true
    } catch (e) {
      loadError = String(e)
    }
  }

  $effect(() => {
    if (app.proActive) loadUi()
  })

  // Gewählte Pro-Seite als Custom Element einsetzen
  $effect(() => {
    const id = app.proPage
    const host = pageHost
    const p = pages.find((x) => x.id === id)
    if (!host || !p) return
    tick().then(() => {
      host.replaceChildren(document.createElement(p.element))
    })
  })

  onMount(async () => {
    try {
      const plans = await invoke<{ monthly: Plan | null }>('license_plans')
      plan = plans.monthly
    } catch {
      plan = null
    }
  })

  async function buy() {
    busy = 'buy'
    try {
      await invoke('license_checkout', { plan: 'monthly' })
      toasts.show('info', t('pro.checkoutOpened'))
    } catch (e) {
      toasts.show('error', t('common.notDone'), String(e))
    } finally {
      busy = null
    }
  }

  async function activate(k = key) {
    busy = 'activate'
    try {
      const res = await invoke<HelperResult>('license_activate', { key: k })
      if (res.ok) {
        toasts.show('success', res.message || t('pro.activated'))
        key = ''
      } else if (res.message) toasts.show('error', t('common.notDone'), res.message)
      await app.refreshMeta()
    } catch (e) {
      toasts.show('error', t('common.notDone'), String(e))
    } finally {
      busy = null
    }
  }

  // Liegt auf dem Lizenzserver eine neuere Pro-Version als die installierte?
  const proUpdate = $derived(!!app.proUpdateVersion)

  // Pro-Update einspielen: laden, prüfen, installieren (fragt einmal nach dem Administrator-Passwort), danach Ansicht neu laden,
  // damit die neue Pro-Oberfläche geladen wird
  async function updatePro() {
    if (busy === 'update') {
      toasts.show('info', t('pro.update.running'))
      return
    }
    busy = 'update'
    try {
      app.updateProgress = { part: 'pro', phase: 'prepare', done: 0, total: 0, step: 0, steps: 0 }
      const res = await invoke<HelperResult>('install_all')
      if (res.ok) {
        toasts.show('success', res.message || t('pro.update.done'))
        setTimeout(() => window.location.reload(), 1600)
        return
      }
      toasts.show('error', t('common.notDone'), res.message || undefined)
      busy = null
    } catch (e) {
      toasts.show('error', t('common.notDone'), String(e))
      busy = null
    }
  }

  async function portal() {
    busy = 'portal'
    try {
      await invoke('license_portal')
    } catch (e) {
      toasts.show('error', t('common.notDone'), String(e))
    } finally {
      busy = null
    }
  }

  async function deactivate() {
    if (!(await ask(t('pro.deactivateConfirm.title'), t('pro.deactivateConfirm.text'), t('pro.deactivateConfirm.ok'), true))) return
    busy = 'deactivate'
    try {
      const res = await invoke<HelperResult>('license_deactivate')
      if (res.ok) toasts.show('success', res.message)
      else if (res.message) toasts.show('error', t('common.notDone'), res.message)
      pages = []
      loaded = false
      await app.refreshMeta()
    } finally {
      busy = null
    }
  }

  const planName = $derived(lic?.plan === 'granted' ? t('pro.planGranted') : lic?.plan === 'yearly' ? t('pro.planYearly') : t('pro.planMonthly'))
</script>

<div class="page" in:fade={{ duration: 220 }}>
  <header class="page-head">
    <div>
      <h1 class="page-title">{t('pro.title')}</h1>
      <p class="page-sub">{t('pro.teaser')}</p>
    </div>
    {#if lic?.active}
      <div class="status-box" in:fly={{ y: -6, duration: 300 }}>
        <span class="dot ok"></span>
        <div>
          <div class="sname">{planName}</div>
          <div class="hint">
            {#if lic.plan !== 'granted' && lic.periodEnd}{lic.cancelAtPeriodEnd ? t('pro.endsAt', { date: dateOnly(lic.periodEnd) }) : t('pro.until', { date: dateOnly(lic.periodEnd) })}{/if}
            {#if lic.key}<span class="mono"> {t('pro.key', { k: lic.key })}</span>{/if}
          </div>
        </div>
        {#if lic.plan !== 'granted'}<button class="btn small" class:busy={busy === 'portal'} onclick={portal}><Icon name="external" size={13} /><span>{t('pro.portal')}</span></button>{/if}
        <button class="btn small ghost" class:busy={busy === 'deactivate'} onclick={deactivate}>{t('pro.deactivate')}</button>
      </div>
    {/if}
  </header>

  {#if proUpdate}
    <!-- Neue Pro-Version auf dem Lizenzserver -->
    <div class="pro-update" in:fly={{ y: -6, duration: 320 }}>
      <span class="pu-icon"><Icon name="arrowUp" size={16} /></span>
      <div class="pu-text">
        <div class="pu-title">{t('pro.update.title')}</div>
        <div class="hint">{busy === 'update' ? t('pro.update.running') : t('pro.update.text', { v: lic?.availableVersion ?? '' })}</div>
        {#if busy === 'update'}<UpdateProgress />{/if}
      </div>
      <button class="btn primary up-btn" class:busy={busy === 'update'} onclick={updatePro}><span class="rise"><Icon name="arrowUp" size={14} /></span><span>{t('pro.update.button')}</span></button>
    </div>
  {/if}

  {#if app.proActive && pages.length}
    <!-- Unterbereiche der Pro-Oberfläche -->
    <nav class="subnav" aria-label={t('pro.pages')}>
      {#each pages as p (p.id)}
        <button class:active={app.proPage === p.id} onclick={() => (app.proPage = p.id)}>{i18n.locale === 'en' ? p.titleEn : p.titleDe}</button>
      {/each}
    </nav>
    {#key app.proPage}
      <div class="pro-host" bind:this={pageHost} in:fly={{ y: 10, duration: 320 }}></div>
    {/key}
  {:else if app.proActive && loadError}
    <p class="empty">{t('pro.loadFailed')}: {loadError}</p>
  {:else if lic?.active && !lic.proInstalled}
    <div class="install" in:fade>
      <p>{t('pro.installHint')}</p>
      <button class="btn primary" class:busy={busy === 'activate'} onclick={() => activate('')}><Icon name="arrowUp" size={14} /><span>{t('pro.installPkg')}</span></button>
    </div>
  {:else if !lic?.active}
    <!-- Angebot: Funktionen, Preis, Kauf, Schlüssel -->
    <ul class="features rows stagger">
      {#each features as f, i}
        <li style="--i: {i}">
          <span class="fi"><Icon name={f === 'software' ? 'layers' : f === 'drivers' ? 'refresh' : f === 'protection' ? 'shield' : f === 'mail' ? 'mail' : f === 'hardening' ? 'lock' : f === 'cleanup' ? 'trash' : f === 'reports' ? 'copy' : 'spark'} size={16} /></span>
          <div>
            <div class="fname">{t(`pro.features.${f}.name`)}</div>
            <div class="hint">{t(`pro.features.${f}.text`)}</div>
          </div>
        </li>
      {/each}
    </ul>

    <div class="offer" in:fly={{ y: 14, duration: 500, delay: 200 }}>
      <div class="price">
        {#if plan}<span class="amount display">{t('pro.price', { amount: money(plan.amount, plan.currency) })}</span><span class="hint">{t('pro.priceTax')}</span>{/if}
      </div>
      <button class="btn primary" class:busy={busy === 'buy'} onclick={buy}><Icon name="spark" size={14} /><span>{t('pro.buy')}</span></button>
    </div>

    <p class="label section-label">{t('pro.haveKey')}</p>
    <form class="keyrow" onsubmit={(e) => (e.preventDefault(), activate())}>
      <input class="mono" bind:value={key} placeholder={t('pro.keyPlaceholder')} spellcheck="false" autocomplete="off" />
      <button class="btn" type="submit" class:busy={busy === 'activate'}><Icon name="key" size={14} /><span>{busy === 'activate' ? t('pro.activating') : t('pro.activate')}</span></button>
    </form>
    {#if lic?.error}<p class="err">{lic.error}</p>{/if}
  {/if}
</div>

<style>
  .status-box {
    display: flex;
    align-items: center;
    gap: 14px;
    padding: 10px 12px;
    border: 1px solid var(--line);
    border-radius: var(--radius);
  }
  .sname {
    font-weight: 600;
  }
  .hint {
    font-size: 13px;
    color: var(--text-dim);
  }
  .subnav {
    display: flex;
    gap: 4px;
    margin: 18px 0 6px;
    flex-wrap: wrap;
  }
  .subnav button {
    height: 32px;
    padding: 0 12px;
    border: 1px solid transparent;
    border-radius: var(--radius);
    background: none;
    color: var(--text-dim);
    font-weight: 540;
    transition: all var(--t-fast) ease;
  }
  .subnav button:hover {
    color: var(--text);
  }
  .subnav button.active {
    color: var(--text);
    border-color: var(--line-strong);
    background: var(--bg-raised);
  }
  .pro-host {
    min-height: 200px;
  }
  .features li {
    display: grid;
    grid-template-columns: 28px minmax(0, 1fr);
    gap: 14px;
    align-items: center;
    padding: 14px 0;
  }
  .fi {
    display: grid;
    place-items: center;
    width: 28px;
    height: 28px;
    color: var(--safe);
  }
  .fname {
    font-weight: 600;
  }
  .offer {
    display: flex;
    align-items: center;
    justify-content: space-between;
    gap: 20px;
    margin-top: 26px;
    padding: 20px 0;
    border-top: 1px solid var(--line);
    border-bottom: 1px solid var(--line);
  }
  .price {
    display: flex;
    flex-direction: column;
    gap: 4px;
  }
  .amount {
    font-size: calc(30px * var(--display-scale));
    line-height: 1;
  }
  .keyrow {
    display: flex;
    gap: 10px;
    max-width: 560px;
  }
  .keyrow input {
    flex: 1;
    height: 38px;
    padding: 0 12px;
    border: 1px solid var(--line-strong);
    border-radius: var(--radius);
    background: var(--bg-sunk);
    color: var(--text);
    font-size: 13px;
    letter-spacing: 0.04em;
    user-select: text;
  }
  .keyrow input:focus {
    outline: none;
    border-color: var(--text-dim);
  }
  .pro-update {
    display: grid;
    grid-template-columns: 28px minmax(0, 1fr) auto;
    align-items: center;
    gap: 14px;
    margin: 0 0 18px;
    padding: 14px 16px;
    border: 1px solid rgba(var(--safe-rgb), 0.45);
    border-radius: var(--radius);
    background: rgba(var(--safe-rgb), 0.08);
  }
  .pu-icon {
    display: grid;
    place-items: center;
    color: var(--safe);
  }
  .up-btn .rise {
    display: inline-grid;
  }
  .up-btn.busy .rise {
    animation: rise 1s var(--ease-inout) infinite;
  }
  @keyframes rise {
    0% {
      transform: translateY(3px);
      opacity: 0.3;
    }
    50% {
      opacity: 1;
    }
    100% {
      transform: translateY(-4px);
      opacity: 0;
    }
  }
  .pu-title {
    font-weight: 600;
  }
  .install {
    margin-top: 24px;
    display: flex;
    align-items: center;
    gap: 18px;
  }
  .err {
    color: var(--threat);
    font-size: 13px;
  }
</style>
