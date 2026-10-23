<script lang="ts">
  // Verlauf: Zeitstreifen der letzten 30 Tage und alle Berichte als Zeilen
  import { fade, slide } from 'svelte/transition'
  import Icon from '../components/Icon.svelte'
  import { app } from '../lib/store.svelte'
  import { bytes, dateTime, duration, kindLabel } from '../lib/format'
  import { i18n, loc, t, tn } from '../lib/i18n.svelte'
  import { isHint } from '../lib/types'

  // Echte Funde und Hinweise eines Berichts getrennt zählen
  const real = (r: { threats: { signature: string; severity?: string }[] }) => r.threats.filter((x) => !isHint(x)).length

  const reports = $derived(app.reports)
  let openId = $state<string | null>(null)
  const nf = $derived(new Intl.NumberFormat(i18n.locale))

  // Ein Tag je Spalte, Höhe nach Zahl der geprüften Dateien
  const days = $derived.by(() => {
    const out: { date: Date; runs: number; files: number; threats: number }[] = []
    const today = new Date()
    today.setHours(0, 0, 0, 0)
    for (let i = 29; i >= 0; i--) {
      const d = new Date(today)
      d.setDate(today.getDate() - i)
      out.push({ date: d, runs: 0, files: 0, threats: 0 })
    }
    for (const r of reports) {
      if (!['quick', 'full', 'custom'].includes(r.kind)) continue
      const d = new Date(r.startedAt)
      d.setHours(0, 0, 0, 0)
      const slot = out.find((o) => o.date.getTime() === d.getTime())
      if (slot) {
        slot.runs++
        slot.files += r.scanned
        slot.threats += real(r)
      }
    }
    return out
  })
  const maxFiles = $derived(Math.max(1, ...days.map((d) => d.files)))

  function phaseText(p: string) {
    return t(`history.phase.${['finished', 'cancelled', 'failed'].includes(p) ? p : 'running'}`)
  }
</script>

<div class="page" in:fade={{ duration: 220 }}>
  <header class="page-head">
    <div>
      <h1 class="page-title">{t('history.title')}</h1>
      <p class="page-sub">{t('history.sub')}</p>
    </div>
  </header>

  <div class="strip" aria-label="30">
    {#each days as d, i}
      <div
        class="day"
        title={t('history.dayTitle', { date: d.date.toLocaleDateString(i18n.locale), runs: d.runs, files: nf.format(d.files) }) + (d.threats ? t('history.dayThreats', { n: d.threats }) : '')}
      >
        <span class="bar" class:none={d.runs === 0} class:hot={d.threats > 0} style="--h: {d.runs ? Math.max(8, (d.files / maxFiles) * 100) : 4}%; --d: {i * 18}ms"></span>
      </div>
    {/each}
  </div>
  <div class="axis"><span>{t('history.ago30')}</span><span>{t('history.today')}</span></div>

  {#if reports.length === 0}
    <p class="empty">{t('history.empty')}</p>
  {:else}
    <ul class="rows stagger">
      {#each reports as r, i (r.id)}
        <li style="--i: {Math.min(i, 14)}">
          <button class="row" onclick={() => (openId = openId === r.id ? null : r.id)} aria-expanded={openId === r.id}>
            <span class="dot {r.phase === 'failed' || real(r) ? 'critical' : r.phase === 'cancelled' || r.threats.length ? 'warn' : 'ok'}"></span>
            <span class="when mono">{dateTime(r.startedAt)}</span>
            <span class="kind">{kindLabel(r.kind)}{r.trigger === 'schedule' ? ` · ${t('history.scheduled')}` : ''}</span>
            <span class="res">
              {#if ['quick', 'full', 'custom'].includes(r.kind)}
                {t('history.filesResult', {
                  files: nf.format(r.scanned),
                  result: [real(r) ? tn('history.findings', real(r)) : t('history.noFindings'), r.threats.length - real(r) ? tn('history.hints', r.threats.length - real(r)) : ''].filter(Boolean).join(', '),
                })}
              {:else}
                {phaseText(r.phase)}
              {/if}
            </span>
            <span class="dur mono">{duration(r.durationSecs)}</span>
            <span class="chev" class:open={openId === r.id}><Icon name="chevron" size={14} /></span>
          </button>
          {#if openId === r.id}
            <div class="details" transition:slide={{ duration: 260 }}>
              <dl>
                <dt>{t('history.status')}</dt><dd>{phaseText(r.phase)}</dd>
                <dt>{t('history.areas')}</dt><dd class="mono">{r.paths.join(', ') || t('history.none')}</dd>
                <dt>{t('history.scanned')}</dt><dd>{t('history.scannedValue', { n: nf.format(r.scanned), size: bytes(r.bytes) })}</dd>
                <dt>{t('history.skipped')}</dt><dd>{t('history.skippedValue', { n: nf.format(r.skipped) })}</dd>
                <dt>{t('history.errors')}</dt><dd>{nf.format(r.errors)}</dd>
                <dt>{t('history.engine')}</dt><dd>{r.engine}</dd>
                {#if r.filesPerSecond}<dt>{t('history.speed')}</dt><dd>{t('history.speedValue', { n: nf.format(Math.round(r.filesPerSecond)) })}</dd>{/if}
                {#if loc(r, 'message')}<dt>{t('history.message')}</dt><dd>{loc(r, 'message')}</dd>{/if}
              </dl>
              {#if r.threats.length}
                <ul class="threats mono">
                  {#each r.threats as th}
                    <li class:hint={isHint(th)}><span class="sig">{th.signature}</span> {th.path} <span class="act">{t(`history.action.${th.action}`)}</span></li>
                  {/each}
                </ul>
              {/if}
            </div>
          {/if}
        </li>
      {/each}
    </ul>
  {/if}
</div>

<style>
  .strip {
    display: grid;
    grid-template-columns: repeat(30, 1fr);
    gap: 4px;
    height: 84px;
    align-items: end;
    margin-top: 28px;
  }
  .day {
    height: 100%;
    display: flex;
    align-items: flex-end;
  }
  .bar {
    width: 100%;
    height: var(--h);
    background: var(--safe);
    opacity: 0.75;
    border-radius: 2px 2px 0 0;
    transform-origin: bottom;
    animation: grow 700ms var(--ease-out) both;
    animation-delay: var(--d);
    transition: opacity var(--t-fast) ease;
  }
  .day:hover .bar {
    opacity: 1;
  }
  .bar.none {
    background: var(--line);
    opacity: 1;
  }
  .bar.hot {
    background: var(--threat);
    opacity: 1;
  }
  :global(:root[data-look='blaupause']) .bar:not(.none) {
    background: repeating-linear-gradient(45deg, var(--safe) 0 1px, transparent 1px 5px);
    border: 1px solid var(--safe);
    opacity: 1;
  }
  @keyframes grow {
    from {
      transform: scaleY(0);
    }
  }
  .axis {
    display: flex;
    justify-content: space-between;
    font-size: 11.5px;
    color: var(--text-faint);
    padding: 6px 0 22px;
    border-bottom: 1px solid var(--line);
  }
  .row {
    width: 100%;
    display: grid;
    grid-template-columns: 20px 150px 240px minmax(0, 1fr) 90px 20px;
    align-items: center;
    gap: 12px;
    padding: 13px 0;
    border: 0;
    background: none;
    text-align: left;
  }
  .row > .dot {
    justify-self: center;
  }
  .row:hover .kind {
    color: var(--text);
  }
  .when {
    font-size: 12.5px;
    color: var(--text-dim);
  }
  .kind {
    font-weight: 560;
  }
  .res {
    color: var(--text-dim);
    white-space: nowrap;
    overflow: hidden;
    text-overflow: ellipsis;
  }
  .dur {
    font-size: 12.5px;
    color: var(--text-faint);
    text-align: right;
  }
  .chev {
    display: grid;
    color: var(--text-faint);
    transition: transform var(--t-normal) var(--ease-out);
  }
  .chev.open {
    transform: rotate(90deg);
  }
  .details {
    padding: 0 0 16px 32px;
  }
  dl {
    display: grid;
    grid-template-columns: 130px 1fr;
    gap: 5px 16px;
    margin: 0;
    font-size: 13px;
  }
  dt {
    color: var(--text-faint);
  }
  dd {
    margin: 0;
    color: var(--text-dim);
    word-break: break-word;
    user-select: text;
  }
  .threats {
    list-style: none;
    margin: 12px 0 0;
    padding: 10px 14px;
    background: var(--bg-sunk);
    border-left: 1px solid var(--threat);
    font-size: 12px;
    user-select: text;
  }
  .threats .sig {
    color: var(--threat);
  }
  .threats .hint .sig {
    color: var(--text-dim);
  }
  .threats .act {
    color: var(--text-faint);
  }
  @media (max-width: 900px) {
    .row {
      grid-template-columns: 20px 130px minmax(0, 1fr) 20px;
    }
    .res,
    .dur {
      display: none;
    }
  }
</style>
