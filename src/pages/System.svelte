<script lang="ts">
  // Systemcheck: Härtungswert, Prüfpunkte nach Bereichen, Reparaturen
  import { fade, fly, slide } from 'svelte/transition'
  import { Tween } from 'svelte/motion'
  import { cubicOut } from 'svelte/easing'
  import { invoke } from '@tauri-apps/api/core'
  import Icon from '../components/Icon.svelte'
  import { ask } from '../components/Confirm.svelte'
  import { app } from '../lib/store.svelte'
  import { relative } from '../lib/format'
  import { i18n, loc, t, tn } from '../lib/i18n.svelte'
  import { toasts } from '../lib/toast.svelte'
  import type { CheckItem } from '../lib/types'

  const sys = $derived(app.snap?.system ?? null)
  const running = $derived(app.jobActive && app.job?.kind === 'systemcheck')

  const groups: CheckItem['category'][] = ['schutz', 'updates', 'netz', 'rootkit', 'haertung']

  // Härtungswert zählt beim Erscheinen hoch, der Bogen zieht mit
  const index = new Tween(0, { duration: 1400, easing: cubicOut })
  $effect(() => {
    index.target = sys?.hardeningIndex ?? 0
  })
  const R = 54
  const C = 2 * Math.PI * R * 0.75

  let openId = $state<string | null>(null)

  const counts = $derived({
    critical: sys?.items.filter((i) => i.status === 'critical').length ?? 0,
    warn: sys?.items.filter((i) => i.status === 'warn').length ?? 0,
    ok: sys?.items.filter((i) => i.status === 'ok').length ?? 0,
  })

  async function fix(item: CheckItem) {
    if (!item.fix) return
    const a = item.fix.action
    // Öffnet ein Programm des Systems (Aktualisierungsverwaltung, unter Windows auch die Windows-Sicherheit)
    if (a === 'open-update-manager' || a === 'open-windows-security') {
      try {
        await invoke(a === 'open-update-manager' ? 'open_update_manager' : 'open_windows_security')
      } catch (e) {
        toasts.show('error', t('system.managerFailed'), String(e))
      }
      return
    }
    if (a === 'update-signatures') return app.startJob('update')
    const label = loc(item.fix, 'label')
    const known = ['firewall-enable', 'services-enable', 'rkhunter-baseline'].includes(a)
    const ok = await ask(label, known ? t(`system.fixTexts.${a}`) : loc(item, 'detail'), label)
    if (ok) {
      const done = await app.helper(`fix:${a}`, ['fix', '--action', a], t('system.done'))
      if (done) app.startJob('systemcheck')
    }
  }
</script>

<div class="page" in:fade={{ duration: 220 }}>
  <header class="page-head">
    <div>
      <h1 class="page-title">{t('system.title')}</h1>
      <p class="page-sub">{t('system.sub')}</p>
    </div>
    <button class="btn primary" class:busy={running || app.pending['job:systemcheck']} onclick={() => app.startJob('systemcheck')}>
      <Icon name="refresh" size={14} /><span>{running ? t('system.running') : t('system.start')}</span>
    </button>
  </header>

  {#if !sys}
    <p class="empty">{running ? t('system.runningLong') : t('system.none')}</p>
  {:else}
    <div class="summary" in:fly={{ y: 12, duration: 500 }}>
      <div class="gauge" class:low={(sys.hardeningIndex ?? 100) < 55}>
        <svg viewBox="0 0 128 128" aria-hidden="true">
          <circle class="track" cx="64" cy="64" r={R} stroke-dasharray="{C} 999" transform="rotate(135 64 64)" />
          {#if sys.hardeningIndex !== null}<circle class="arc" cx="64" cy="64" r={R} stroke-dasharray="{(C * index.current) / 100} 999" transform="rotate(135 64 64)" />{/if}
        </svg>
        <div class="num">
          <span class="mono">{sys.hardeningIndex === null ? '' : Math.round(index.current)}</span>
          <small>{sys.hardeningIndex === null ? t('system.notMeasured') : t('system.hardening')}</small>
        </div>
      </div>
      <div class="facts">
        <div><span class="dot critical"></span>{t('system.critical', { n: counts.critical })}</div>
        <div><span class="dot warn"></span>{tn('system.warn', counts.warn)}</div>
        <div><span class="dot ok"></span>{t('system.ok', { n: counts.ok })}</div>
        <p>{running ? t('system.checkedRunning', { when: relative(sys.checkedAt) }) : t('system.checked', { when: relative(sys.checkedAt) }).replace('..', '.')} {t('system.lynisNote')}</p>
      </div>
    </div>

    {#each groups as g}
      {@const items = sys.items.filter((i) => i.category === g)}
      {#if items.length}
        <p class="label section-label">{t(`system.groups.${g}`)}</p>
        <ul class="rows stagger">
          {#each items as it, i (it.id)}
            <li style="--i: {i}">
              <div class="item">
                <span class="dot {it.status}"></span>
                <button class="head" onclick={() => (openId = openId === it.id ? null : it.id)} aria-expanded={openId === it.id}>
                  <span class="title">{loc(it, 'title')}</span>
                  <span class="detail">{loc(it, 'detail')}</span>
                </button>
                <div class="acts">
                  {#if it.fix}
                    <button class="btn small {it.status === 'critical' ? 'primary' : ''}" class:busy={app.pending[`fix:${it.fix.action}`]} onclick={() => fix(it)}>
                      {#if it.fix.action === 'open-update-manager' || it.fix.action === 'open-windows-security'}<Icon name="external" size={13} />{/if}<span>{loc(it.fix, 'label')}</span>
                    </button>
                  {/if}
                  {#if it.list.length}
                    <button class="more" onclick={() => (openId = openId === it.id ? null : it.id)} aria-label={t('system.details')}>
                      <span class="chev" class:open={openId === it.id}><Icon name="chevron" size={14} /></span>
                    </button>
                  {/if}
                </div>
              </div>
              {#if openId === it.id && it.list.length}
                <ul class="list mono" transition:slide={{ duration: 260 }}>
                  {#each i18n.locale === 'en' && it.listEn?.length ? it.listEn : it.list as l}<li>{l}</li>{/each}
                </ul>
              {/if}
            </li>
          {/each}
        </ul>
      {/if}
    {/each}
  {/if}
</div>

<style>
  .summary {
    display: flex;
    align-items: center;
    gap: 36px;
    padding: 28px 0;
    border-bottom: 1px solid var(--line);
  }
  :global(:root[data-look='orbit']) .summary {
    justify-content: center;
  }
  .gauge {
    position: relative;
    width: 150px;
    height: 150px;
    flex: none;
  }
  .gauge svg {
    width: 100%;
    height: 100%;
  }
  circle {
    fill: none;
    stroke-width: 5;
    stroke-linecap: round;
  }
  :global(:root[data-look='terminal']) circle {
    stroke-linecap: butt;
    stroke-dasharray: 2 3;
  }
  .track {
    stroke: var(--line);
  }
  .arc {
    stroke: var(--safe);
  }
  .gauge.low .arc {
    stroke: var(--warn);
  }
  .num {
    position: absolute;
    inset: 0;
    display: flex;
    flex-direction: column;
    align-items: center;
    justify-content: center;
  }
  .num .mono {
    font-size: 44px;
    font-weight: 300;
    letter-spacing: -0.05em;
    line-height: 1;
  }
  .num small {
    color: var(--text-faint);
    font-size: 11px;
    letter-spacing: 0.08em;
    text-transform: uppercase;
    margin-top: 4px;
  }
  .facts {
    display: flex;
    flex-direction: column;
    gap: 6px;
  }
  .facts div {
    display: flex;
    align-items: center;
    gap: 10px;
    font-weight: 560;
  }
  .facts p {
    margin: 8px 0 0;
    color: var(--text-dim);
    max-width: 540px;
    font-size: 13px;
  }
  .item {
    display: grid;
    grid-template-columns: 20px minmax(0, 1fr) auto;
    align-items: center;
    gap: 14px;
    padding: 14px 0;
  }
  .item > .dot {
    justify-self: center;
  }
  .head {
    display: flex;
    flex-direction: column;
    align-items: flex-start;
    text-align: left;
    border: 0;
    background: none;
    padding: 0;
    min-width: 0;
  }
  .title {
    font-weight: 600;
  }
  .detail {
    color: var(--text-dim);
    font-size: 13px;
  }
  .acts {
    display: flex;
    align-items: center;
    gap: 6px;
  }
  .more {
    width: 30px;
    height: 30px;
    display: grid;
    place-items: center;
    border: 0;
    background: none;
    color: var(--text-dim);
    border-radius: var(--radius);
  }
  .more:hover {
    background: var(--bg-raised);
    color: var(--text);
  }
  .chev {
    display: grid;
    transition: transform var(--t-normal) var(--ease-out);
  }
  .chev.open {
    transform: rotate(90deg);
  }
  .list {
    list-style: none;
    margin: 0 0 14px 34px;
    padding: 10px 14px;
    background: var(--bg-sunk);
    border-left: 1px solid var(--line-strong);
    font-size: 12px;
    color: var(--text-dim);
    max-height: 260px;
    overflow-y: auto;
    user-select: text;
  }
  .list li {
    padding: 2px 0;
    word-break: break-word;
  }
</style>
