<script lang="ts">
  // Einstellungen: Darstellung, Sprache und Wächter gelten sofort;
  // Zeitplan, Prüfbereich und automatische Updates speichert der Helfer (Administrator-Passwort)
  import { fade, fly, slide } from 'svelte/transition'
  import { invoke } from '@tauri-apps/api/core'
  import Icon from '../components/Icon.svelte'
  import UpdateProgress from '../components/UpdateProgress.svelte'
  import { ask } from '../components/Confirm.svelte'
  import { app } from '../lib/store.svelte'
  import { DAY_IDS, dateTime, relative } from '../lib/format'
  import { i18n, isWindows, t } from '../lib/i18n.svelte'
  import { toasts } from '../lib/toast.svelte'
  import type { Config, Day, FontId, HelperResult, Look, Palette, Settings } from '../lib/types'

  // Arbeitskopie der Systemkonfiguration, erst beim Speichern übernommen
  let draft = $state<Config | null>(null)
  let baseline = $state('')

  function normalize(c: Config): Config {
    return { ...c, updates: c.updates ?? { auto: false, time: '11:00' } }
  }

  $effect(() => {
    const c = app.snap?.config
    if (c) {
      const n = JSON.stringify(normalize(c))
      if (n !== baseline) {
        baseline = n
        draft = JSON.parse(n)
      }
    }
  })

  const dirty = $derived(draft !== null && JSON.stringify(draft) !== baseline)
  const settings = $derived(app.snap?.settings ?? null)

  const looks: Look[] = ['feld', 'orbit', 'terminal', 'blaupause']
  const palettes: { id: Palette; dark: [string, string, string]; light: [string, string, string] }[] = [
    { id: 'graphit', dark: ['#151a19', '#dde4e0', '#8fe3b8'], light: ['#e4e7e5', '#1b2120', '#1d8a5a'] },
    { id: 'tinte', dark: ['#18191b', '#e6e5e1', '#f0efea'], light: ['#eceae5', '#18191b', '#18191b'] },
    { id: 'glut', dark: ['#19181a', '#ebe5df', '#f4a95a'], light: ['#e7e5e4', '#1f1c1b', '#b35b05'] },
    { id: 'fjord', dark: ['#11191c', '#dae6e8', '#7fe1d1'], light: ['#e1e8ea', '#13212a', '#0d7c70'] },
    { id: 'moos', dark: ['#161914', '#e1e6d9', '#bad979'], light: ['#e4e7de', '#1c2117', '#4e781d'] },
  ]
  const fonts: { id: FontId; name: string; family: string; fvs: string; weight: number; upper?: boolean }[] = [
    { id: 'bricolage', name: 'Bricolage Grotesque', family: "'Bricolage Grotesque Variable'", fvs: "'wdth' 75", weight: 700 },
    { id: 'archivo', name: 'Archivo Condensed', family: "'Archivo Variable'", fvs: "'wdth' 64", weight: 800 },
    { id: 'instrument', name: 'Instrument Sans', family: "'Instrument Sans Variable'", fvs: "'wdth' 75", weight: 660 },
    { id: 'syne', name: 'Syne', family: "'Syne Variable'", fvs: 'normal', weight: 760 },
    { id: 'unbounded', name: 'Unbounded', family: "'Unbounded Variable'", fvs: 'normal', weight: 620 },
    { id: 'bigshoulders', name: 'Big Shoulders', family: "'Big Shoulders Display Variable'", fvs: 'normal', weight: 820, upper: true },
  ]
  const plans = ['quick', 'full', 'systemcheck'] as const

  function setUser(patch: Partial<Settings>) {
    if (settings) app.saveSettings({ ...settings, ...patch })
  }

  function toggleDay(id: (typeof plans)[number], d: Day) {
    if (!draft) return
    const days = draft.schedule[id].days
    draft.schedule[id].days = days.includes(d) ? days.filter((x) => x !== d) : [...days, d]
  }

  async function addExclude() {
    const picked = await invoke<string[] | null>('pick_folders').catch(() => null)
    if (picked && draft) draft.scan.excludePaths = [...new Set([...draft.scan.excludePaths, ...picked])]
  }

  async function save() {
    if (!draft) return
    for (const p of plans) {
      if (draft.schedule[p].enabled && draft.schedule[p].days.length === 0) {
        toasts.show('warn', t('settings.needDay', { label: t(`settings.plans.${p}.label`) }))
        return
      }
    }
    const ok = await app.helper('config', ['set-config', '--json', JSON.stringify(draft)], t('settings.saved'))
    if (ok) baseline = JSON.stringify(draft)
  }

  function unallow(sha: string) {
    app.helper(`ua:${sha}`, ['unallow', '--sha256', sha], t('settings.unallowed'))
  }

  async function addWatchPath() {
    const picked = await invoke<string[] | null>('pick_folders').catch(() => null)
    if (picked && settings) setUser({ watcherPaths: [...new Set([...settings.watcherPaths, ...picked])] })
  }

  async function setAutostart(on: boolean) {
    try {
      await invoke('set_autostart', { enabled: on })
      app.autostart = on
    } catch (e) {
      toasts.show('error', t('settings.notSaved'), String(e))
    }
  }

  // Updates für Vigil
  let checking = $state(false)
  let installing = $state(false)

  // Eine Nummer für das ganze Programm: Pro wird nur genannt, ohne eigene Nummer, solange beide gleich sind
  const proSuffix = $derived.by(() => {
    const pv = app.license?.active && app.license.proInstalled ? app.license.proVersion : null
    if (!pv) return ''
    return pv === app.info?.version ? t('settings.about.withPro') : t('settings.about.withProOther', { p: pv })
  })

  // Ein Klick prüft Vigil und Vigil Pro
  async function checkNow() {
    if (checking) return
    checking = true
    if (app.license?.active) await invoke('license_refresh').catch(() => {})
    await app.refreshMeta(true)
    checking = false
    if (app.anyUpdate) toasts.show('info', t('settings.update.found'))
    else if (app.update?.error) toasts.show('warn', t('settings.update.error', { e: app.update.error }))
    else toasts.show('success', t('settings.update.allCurrent'))
  }


  // Was neu ist, in einem Satz: „Vigil 0.3.3 und Vigil Pro 0.3.3“
  const updateList = $derived(
    [app.update?.available ? `Vigil ${app.update.latest ?? ''}` : '', app.proUpdateVersion ? `Vigil Pro ${app.proUpdateVersion}` : '']
      .filter(Boolean)
      .join(t('settings.update.and')),
  )

  // Ein Knopf für alles: zuerst Pro, dann Vigil; das Passwort fragt das System nur einmal ab
  async function installNow() {
    if (installing) {
      toasts.show('info', t('settings.update.installing'))
      return
    }
    if (!(await ask(t('settings.update.confirm.title'), t('settings.update.confirm.text', { v: updateList }), t('settings.update.confirm.ok')))) return
    installing = true
    app.updateProgress = { part: app.proUpdateVersion ? 'pro' : 'vigil', phase: 'prepare', done: 0, total: 0, step: 0, steps: 0 }
    try {
      const res = await invoke<HelperResult>('install_all')
      if (res.ok) {
        toasts.show('success', res.message)
        // Nur Pro neu: Ansicht neu laden, damit die neue Pro-Oberfläche greift; bei Vigil startet das Programm ohnehin neu
        setTimeout(() => window.location.reload(), 1800)
        return
      }
      if (res.message) toasts.show('error', t('common.notDone'), res.message)
    } catch (e) {
      toasts.show('error', t('common.notDone'), String(e))
    }
    installing = false
    app.updateProgress = null
  }
  const notes = $derived(i18n.locale === 'en' ? app.update?.notesEn : app.update?.notes)
</script>

<div class="page" in:fade={{ duration: 220 }}>
  <header class="page-head">
    <div>
      <h1 class="page-title">{t('settings.title')}</h1>
      <p class="page-sub">{t('settings.sub')}</p>
    </div>
  </header>

  {#if settings}
    <!-- Aussehen: vier Looks mit kleiner Vorschau -->
    <p class="label section-label">{t('settings.sections.look')}</p>
    <div class="tiles looks">
      {#each looks as l}
        <button class="tile" class:on={settings.look === l} onclick={() => setUser({ look: l })} aria-pressed={settings.look === l}>
          <div class="preview p-{l}" aria-hidden="true">
            {#if l === 'feld'}
              <svg viewBox="0 0 160 70">{#each Array(10) as _, r}{#each Array(22) as _, c}<rect x={4 + c * 7} y={4 + r * 6.5} width="1.6" height="1.6" class:lit={Math.sin(c * 0.5 - r * 0.4) > 0.6} />{/each}{/each}<text x="6" y="64" class="pw">Ab</text></svg>
            {:else if l === 'orbit'}
              <svg viewBox="0 0 160 70">{#each [12, 19, 26, 33] as r, i}<circle cx="80" cy="35" r={r} class="orb" style="--s: {8 + i * 4}s" />{/each}<circle cx="80" cy="35" r="3" class="core" /></svg>
            {:else if l === 'terminal'}
              <svg viewBox="0 0 160 70"><text x="6" y="16" class="tm">&gt; vigil scan --quick</text><text x="6" y="30" class="tm dim">[~/Downloads] ······██a7f</text><text x="6" y="44" class="tm dim">[~/.config]   ·········</text><text x="6" y="60" class="tm big">GESCHÜTZT_</text></svg>
            {:else}
              <svg viewBox="0 0 160 70"><defs><pattern id="ph" width="5" height="5" patternUnits="userSpaceOnUse" patternTransform="rotate(45)"><line x1="0" y1="0" x2="0" y2="5" class="hl" /></pattern></defs><rect x="6" y="8" width="70" height="56" class="bf" fill="url(#ph)" /><rect x="80" y="8" width="74" height="26" class="bf" /><rect x="80" y="38" width="36" height="26" class="bf" fill="url(#ph)" /><rect x="120" y="38" width="34" height="26" class="bf" /><line x1="6" y1="4" x2="154" y2="4" class="dimline" /></svg>
            {/if}
          </div>
          <div class="tile-text">
            <span class="name">{t(`settings.looks.${l}.name`)}{#if settings.look === l}<Icon name="check" size={14} />{/if}</span>
            <span class="desc">{t(`settings.looks.${l}.text`)}</span>
          </div>
        </button>
      {/each}
    </div>

    <!-- Farbschema: je eine Fläche dunkel und hell -->
    <p class="label section-label">{t('settings.sections.palette')}</p>
    <div class="tiles palettes">
      {#each palettes as p}
        <button class="swatch" class:on={settings.palette === p.id} onclick={() => setUser({ palette: p.id })} aria-pressed={settings.palette === p.id}>
          <span class="halves">
            <span style="background: {p.dark[0]}"><i style="background: {p.dark[2]}"></i><b style="background: {p.dark[1]}"></b></span>
            <span style="background: {p.light[0]}"><i style="background: {p.light[2]}"></i><b style="background: {p.light[1]}"></b></span>
          </span>
          <span class="name">{t(`settings.palettes.${p.id}`)}</span>
        </button>
      {/each}
    </div>

    <!-- Schrift des Statusworts und der Überschriften -->
    <p class="label section-label">{t('settings.sections.font')}</p>
    <div class="tiles fonts">
      {#each fonts as f}
        <button class="font" class:on={settings.font === f.id} onclick={() => setUser({ font: f.id })} aria-pressed={settings.font === f.id} disabled={settings.look === 'terminal'}>
          <span class="sample" style="font-family: {f.family}; font-variation-settings: {f.fvs}; font-weight: {f.weight}; text-transform: {f.upper ? 'uppercase' : 'none'}">{t('settings.fontSample')}</span>
          <span class="name">{f.name}</span>
        </button>
      {/each}
    </div>

    <div class="pairs">
      <div>
        <p class="label section-label">{t('settings.sections.theme')}</p>
        <div class="seg">
          {#each ['system', 'dark', 'light'] as th}
            <button class:on={settings.theme === th} onclick={() => setUser({ theme: th as Settings['theme'] })}><Icon name={th === 'system' ? 'auto' : th === 'dark' ? 'moon' : 'sun'} size={14} /><span>{t(`settings.themes.${th}`)}</span></button>
          {/each}
        </div>
      </div>
      <div>
        <p class="label section-label">{t('settings.sections.language')}</p>
        <div class="seg">
          {#each ['system', 'de', 'en'] as lg}
            <button class:on={settings.language === lg} onclick={() => setUser({ language: lg as Settings['language'] })}><span>{t(`settings.languages.${lg}`)}</span></button>
          {/each}
        </div>
      </div>
      <div>
        <p class="label section-label">{t('settings.sections.motion')}</p>
        <div class="seg">
          {#each ['voll', 'ruhig'] as m}
            <button class:on={settings.motion === m} onclick={() => setUser({ motion: m as Settings['motion'] })}><span>{t(`settings.motions.${m}`)}</span></button>
          {/each}
        </div>
        <p class="note">{t('settings.motionHint')}</p>
      </div>
    </div>

    <p class="label section-label">{t('settings.sections.start')}</p>
    <ul class="rows">
      <li class="opt">
        <label class="switch">
          <input type="checkbox" checked={app.autostart ?? true} onchange={(e) => setAutostart(e.currentTarget.checked)} />
          <span class="track"><span class="knob"></span></span>
        </label>
        <div>
          <div class="name">{t('settings.autostart')}</div>
          <div class="hint">{t('settings.autostartHint')}</div>
        </div>
      </li>
    </ul>
  {/if}

  {#if draft}
    <p class="label section-label">{t('settings.sections.schedule')}</p>
    <ul class="rows">
      {#each plans as p}
        {@const e = draft.schedule[p]}
        <li class="plan" class:off={!e.enabled}>
          <label class="switch">
            <input type="checkbox" bind:checked={draft.schedule[p].enabled} />
            <span class="track"><span class="knob"></span></span>
          </label>
          <div class="pl">
            <div class="name">{t(`settings.plans.${p}.label`)}</div>
            <div class="hint">{t(`settings.plans.${p}.hint`)}</div>
          </div>
          <div class="days" role="group" aria-label={t('settings.weekdays')}>
            {#each DAY_IDS as d}
              <button class="day" class:on={e.days.includes(d)} onclick={() => toggleDay(p, d)} disabled={!e.enabled}>{t(`days.${d}`)}</button>
            {/each}
          </div>
          <input class="time mono" type="time" bind:value={draft.schedule[p].time} disabled={!e.enabled} aria-label={t('settings.time')} />
        </li>
      {/each}
    </ul>
    <p class="note">{t('settings.catchUp')}</p>

    <!-- Virendaten: jetzt suchen, Takt, Zusatzquellen -->
    <p class="label section-label">{t('settings.sections.virusData')}</p>
    <ul class="rows">
      <li class="opt update">
        <div class="grow">
          <div class="name">{app.snap?.signatures ? t('settings.virus.state', { checked: relative(app.snap.signatures.checkedAt ?? app.snap.signatures.date), date: relative(app.snap.signatures.date) }) : t('scan.noSig')}</div>
          <div class="hint">{t('settings.virus.stateHint')}</div>
        </div>
        <button class="btn" class:busy={app.pending['job:update'] || (app.jobActive && app.job?.kind === 'update')} onclick={() => app.startJob('update')}><Icon name="refresh" size={14} /><span>{t('settings.virus.now')}</span></button>
      </li>
      <li class="opt col">
        <div class="name">{t('settings.virus.interval')}</div>
        <div class="seg">
          {#each [1, 2, 4, 8] as h}
            <button class:on={(draft.signatureIntervalHours ?? 1) === h} onclick={() => (draft!.signatureIntervalHours = h)}>{h === 1 ? t('settings.virus.everyHour') : t('settings.virus.everyHours', { n: h })}</button>
          {/each}
        </div>
        <div class="hint">{t('settings.virus.intervalHint')}</div>
      </li>
      <!-- Zusätzliche Virendaten (Sanesecurity) gibt es unter Windows noch nicht -->
      {#if !isWindows}
      <li class="opt">
        <label class="switch">
          <input type="checkbox" checked={draft.extraSignatures ?? true} onchange={(e) => (draft!.extraSignatures = e.currentTarget.checked)} />
          <span class="track"><span class="knob"></span></span>
        </label>
        <div>
          <div class="name">{t('settings.virus.extra')}</div>
          <div class="hint">{t('settings.virus.extraHint')}</div>
        </div>
      </li>
      {/if}
    </ul>

    <p class="label section-label">{t('settings.sections.onThreat')}</p>
    <div class="seg">
      <button class:on={draft.scan.onThreat === 'report'} onclick={() => (draft!.scan.onThreat = 'report')}>{t('settings.report')}</button>
      <button class:on={draft.scan.onThreat === 'quarantine'} onclick={() => (draft!.scan.onThreat = 'quarantine')}>{t('settings.quarantineNow')}</button>
    </div>

    <p class="label section-label">{t('settings.sections.scope')}</p>
    <ul class="rows">
      <li class="opt">
        <label class="switch">
          <input type="checkbox" bind:checked={draft.scan.includeMounts} />
          <span class="track"><span class="knob"></span></span>
        </label>
        <div>
          <div class="name">{t('settings.mounts')}</div>
          <div class="hint">{t('settings.mountsHint')}</div>
        </div>
      </li>
      <li class="opt col">
        <div class="name">{t('settings.excluded')}</div>
        {#each draft.scan.excludePaths as p (p)}
          <div class="pathrow" transition:slide={{ duration: 220 }}>
            <span class="mono">{p}</span>
            <button class="btn small ghost" onclick={() => (draft!.scan.excludePaths = draft!.scan.excludePaths.filter((x) => x !== p))}><Icon name="x" size={13} /><span>{t('settings.remove')}</span></button>
          </div>
        {:else}
          <div class="hint">{t('settings.noExcluded')}</div>
        {/each}
        <button class="btn small add" onclick={addExclude}><Icon name="plus" size={13} /><span>{t('settings.exclude')}</span></button>
      </li>
    </ul>

    {#if draft.allowlist.length}
      <p class="label section-label">{t('settings.sections.allowlist')}</p>
      <ul class="rows">
        {#each draft.allowlist as a (a.sha256)}
          <li class="opt">
            <div class="grow">
              <div class="mono small">{a.path}</div>
              <div class="hint">{t('settings.allowMeta', { sig: a.signature, when: dateTime(a.addedAt) })}</div>
            </div>
            <button class="btn small" class:busy={app.pending[`ua:${a.sha256}`]} onclick={() => unallow(a.sha256)}>{t('settings.unallow')}</button>
          </li>
        {/each}
      </ul>
    {/if}
  {/if}

  {#if settings}
    <p class="label section-label">{t('settings.sections.watcher')}</p>
    <ul class="rows">
      <li class="opt">
        <label class="switch">
          <input type="checkbox" checked={settings.watcherEnabled} onchange={(e) => setUser({ watcherEnabled: e.currentTarget.checked })} />
          <span class="track"><span class="knob"></span></span>
        </label>
        <div>
          <div class="name">{t('settings.watcherOn')}</div>
          <div class="hint">{t('settings.watcherHint')}</div>
        </div>
      </li>
      <li class="opt col">
        {#each settings.watcherPaths as p (p)}
          <div class="pathrow" transition:slide={{ duration: 220 }}>
            <span class="mono">{p}</span>
            <button class="btn small ghost" onclick={() => setUser({ watcherPaths: settings.watcherPaths.filter((x) => x !== p) })}><Icon name="x" size={13} /><span>{t('settings.remove')}</span></button>
          </div>
        {/each}
        <button class="btn small add" onclick={addWatchPath}><Icon name="plus" size={13} /><span>{t('settings.watchFolder')}</span></button>
      </li>
      <li class="opt">
        <label class="switch">
          <input type="checkbox" checked={settings.notifications} onchange={(e) => setUser({ notifications: e.currentTarget.checked })} />
          <span class="track"><span class="knob"></span></span>
        </label>
        <div>
          <div class="name">{t('settings.notifications')}</div>
          <div class="hint">{t('settings.notificationsHint')}</div>
        </div>
      </li>
    </ul>

    <!-- Updates für Vigil selbst -->
    <p class="label section-label">{t('settings.sections.updates')}</p>
    <ul class="rows">
      <li class="opt update">
        <div class="grow">
          <div class="name">
            {#if app.anyUpdate}{t('settings.update.availableList', { list: updateList })}{:else if app.proActive}{t('settings.update.allCurrent')}{:else}{t('settings.update.upToDate')}{/if}
          </div>
          <div class="hint">
            {t('settings.update.current', { v: app.info?.version ?? '' }) + (proSuffix ? ` ${proSuffix}` : '')}{#if app.update?.checkedAt}, {t('settings.update.checkedAt', { when: relative(app.update.checkedAt) })}{/if}
          </div>
          {#if installing}<UpdateProgress />{/if}
          {#if app.update?.available && notes && !installing}
            <details class="notes" transition:slide>
              <summary>{t('settings.update.notes')}</summary>
              <pre>{notes}</pre>
            </details>
          {/if}
        </div>
        {#if app.anyUpdate || installing}
          <button class="btn primary up-btn" class:busy={installing} onclick={installNow}><span class="rise"><Icon name="arrowUp" size={14} /></span><span>{installing ? t('settings.update.installing') : t('settings.update.install')}</span></button>
        {:else}
          <button class="btn" class:busy={checking} onclick={checkNow}><Icon name="refresh" size={14} /><span>{checking ? t('settings.update.checking') : t('settings.update.check')}</span></button>
        {/if}
      </li>
      {#if draft?.updates}
        <li class="opt">
          <label class="switch">
            <input type="checkbox" bind:checked={draft.updates.auto} />
            <span class="track"><span class="knob"></span></span>
          </label>
          <div class="grow">
            <div class="name">{t('settings.update.auto')}</div>
            <div class="hint">{t('settings.update.autoHint')}</div>
          </div>
          <input class="time mono" type="time" bind:value={draft.updates.time} disabled={!draft.updates.auto} aria-label={t('settings.time')} />
        </li>
      {/if}
      <li class="opt">
        <label class="switch">
          <input type="checkbox" checked={settings.updateNotify} onchange={(e) => setUser({ updateNotify: e.currentTarget.checked })} />
          <span class="track"><span class="knob"></span></span>
        </label>
        <div class="name">{t('settings.update.notify')}</div>
      </li>
    </ul>

    <!-- Vigil Pro in Kürze, Einzelheiten auf der Pro-Seite -->
    <p class="label section-label">{t('settings.sections.pro')}</p>
    <ul class="rows">
      <li class="opt">
        <span class="dot {app.license?.active ? 'ok' : 'info'}"></span>
        <div class="grow">
          <div class="name">{app.license?.active ? t('pro.active') : t('pro.inactive')}{#if app.license?.key}<span class="mono faint"> · {app.license.key}</span>{/if}</div>
          <div class="hint">{t('pro.teaser')}</div>
        </div>
        <button class="btn" onclick={() => (app.page = 'pro')}><Icon name="spark" size={14} /><span>{t('pro.title')}</span></button>
      </li>
    </ul>

    <p class="label section-label">{t('settings.sections.about')}</p>
    <div class="about">
      <span class="display brandword">vigil</span>
      <div>
        <div>{t('settings.about.version', { v: app.info?.version ?? '' }) + (proSuffix ? ` ${proSuffix}` : '')} · {t('settings.about.license', { l: app.info?.license ?? 'GPL-3.0-or-later' })}</div>
        <div class="hint">{t('settings.about.engine')}</div>
        {#if app.info?.repo}<button class="link" onclick={() => invoke('open_url', { url: app.info!.repo })}>{t('settings.about.source')} <Icon name="external" size={12} /></button>{/if}
      </div>
    </div>
  {/if}

  <div class="spacer"></div>
</div>

{#if dirty}
  <div class="savebar" transition:fly={{ y: 40, duration: 300 }}>
    <span>{t('settings.dirty')}</span>
    <button class="btn ghost" onclick={() => (draft = JSON.parse(baseline))}>{t('settings.discard')}</button>
    <button class="btn primary" class:busy={app.pending['config']} onclick={save}><Icon name="lock" size={14} /><span>{t('settings.save')}</span></button>
  </div>
{/if}

<style>
  /* Pfeil im Update-Knopf steigt während des Updates immer wieder auf */
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
  .tiles {
    display: grid;
    gap: 10px;
    margin-top: 8px;
  }
  .looks {
    grid-template-columns: repeat(4, minmax(0, 1fr));
  }
  .palettes {
    grid-template-columns: repeat(5, minmax(0, 1fr));
  }
  .fonts {
    grid-template-columns: repeat(3, minmax(0, 1fr));
  }
  .tile,
  .swatch,
  .font {
    display: flex;
    flex-direction: column;
    gap: 10px;
    padding: 10px;
    border: 1px solid var(--line);
    border-radius: var(--radius);
    background: transparent;
    text-align: left;
    transition:
      border-color var(--t-fast) ease,
      background-color var(--t-fast) ease,
      transform var(--t-fast) var(--ease-out);
  }
  .tile:hover,
  .swatch:hover,
  .font:hover:not(:disabled) {
    border-color: var(--line-strong);
    background: var(--bg-raised);
    transform: translateY(-2px);
  }
  .tile.on,
  .swatch.on,
  .font.on {
    border-color: var(--text);
    box-shadow: inset 0 0 0 1px var(--text);
  }
  .font:disabled {
    opacity: 0.4;
    cursor: default;
  }
  .preview {
    height: 76px;
    background: var(--bg-sunk);
    border-radius: calc(var(--radius) - 1px);
    overflow: hidden;
  }
  .preview svg {
    width: 100%;
    height: 100%;
  }
  .p-feld rect {
    fill: var(--text-faint);
  }
  .p-feld rect.lit {
    fill: var(--safe);
  }
  .p-feld .pw {
    font: 800 22px var(--font-display);
    fill: var(--text);
    font-variation-settings: var(--display-fvs);
  }
  .orb {
    fill: none;
    stroke: var(--text-faint);
    stroke-width: 1.4;
    stroke-dasharray: 1 3.5;
    transform-origin: 80px 35px;
    animation: spin var(--s) linear infinite;
  }
  .core {
    fill: var(--safe);
  }
  @keyframes spin {
    to {
      transform: rotate(360deg);
    }
  }
  .tm {
    font: 600 8.5px var(--font-mono);
    fill: var(--safe);
  }
  .tm.dim {
    fill: var(--text-faint);
  }
  .tm.big {
    font-size: 12px;
    fill: var(--text);
  }
  .bf {
    stroke: var(--text-dim);
    stroke-width: 0.8;
    fill-opacity: 1;
  }
  .bf:not([fill]) {
    fill: none;
  }
  .hl {
    stroke: var(--safe);
    stroke-width: 0.8;
  }
  .dimline {
    stroke: var(--text-faint);
    stroke-width: 0.6;
  }
  .tile-text {
    display: flex;
    flex-direction: column;
    gap: 2px;
  }
  .name {
    display: flex;
    align-items: center;
    gap: 6px;
    font-weight: 600;
  }
  .desc {
    font-size: 12.5px;
    color: var(--text-dim);
  }
  .halves {
    display: grid;
    grid-template-columns: 1fr 1fr;
    height: 46px;
    border-radius: calc(var(--radius) - 1px);
    overflow: hidden;
    border: 1px solid var(--line);
  }
  .halves > span {
    position: relative;
  }
  .halves i {
    position: absolute;
    left: 10px;
    top: 10px;
    width: 9px;
    height: 9px;
    border-radius: 50%;
  }
  .halves b {
    position: absolute;
    left: 10px;
    right: 10px;
    bottom: 11px;
    height: 3px;
    border-radius: 2px;
    opacity: 0.8;
  }
  .sample {
    font-size: 30px;
    line-height: 1.15;
    padding-bottom: 0.05em;
    letter-spacing: -0.03em;
    white-space: nowrap;
    overflow: hidden;
  }
  .font .name {
    font-size: 12px;
    color: var(--text-dim);
    font-weight: 500;
  }
  .pairs {
    display: grid;
    grid-template-columns: repeat(3, auto);
    justify-content: start;
    gap: 0 40px;
  }
  .plan,
  .opt {
    display: flex;
    align-items: center;
    gap: 18px;
    padding: 15px 0;
    transition: opacity var(--t-normal) ease;
  }
  .opt.col {
    flex-direction: column;
    align-items: stretch;
    gap: 8px;
  }
  .plan.off .pl,
  .plan.off .days,
  .plan.off .time {
    opacity: 0.45;
  }
  .pl {
    width: 260px;
  }
  .hint,
  .note {
    font-size: 13px;
    color: var(--text-dim);
  }
  .note {
    margin: 10px 0 0;
    color: var(--text-faint);
    max-width: 520px;
  }
  .grow {
    flex: 1;
    min-width: 0;
  }
  .small {
    font-size: 12.5px;
    word-break: break-all;
  }
  .faint {
    color: var(--text-faint);
    font-weight: 400;
  }
  .days {
    display: flex;
    gap: 4px;
    flex: 1;
  }
  .day {
    width: 34px;
    height: 30px;
    border: 1px solid var(--line);
    border-radius: var(--radius);
    background: none;
    color: var(--text-dim);
    font-size: 12.5px;
    font-weight: 560;
    transition: all var(--t-fast) ease;
  }
  .day.on {
    background: var(--text);
    border-color: var(--text);
    color: var(--bg);
  }
  .day:disabled {
    cursor: default;
  }
  .time {
    height: 32px;
    padding: 0 10px;
    border: 1px solid var(--line-strong);
    border-radius: var(--radius);
    background: var(--bg-sunk);
    color: var(--text);
    font-size: 13px;
  }
  .switch {
    position: relative;
    flex: none;
    cursor: pointer;
  }
  .switch input {
    position: absolute;
    opacity: 0;
    inset: 0;
    cursor: pointer;
  }
  .track {
    display: block;
    width: 38px;
    height: 22px;
    border-radius: 11px;
    background: var(--line-strong);
    position: relative;
    transition: background var(--t-normal) ease;
  }
  .knob {
    position: absolute;
    top: 3px;
    left: 3px;
    width: 16px;
    height: 16px;
    border-radius: 50%;
    background: var(--bg);
    transition: transform var(--t-normal) var(--ease-spring);
  }
  .switch input:checked + .track {
    background: var(--safe);
  }
  .switch input:checked + .track .knob {
    transform: translateX(16px);
  }
  .switch input:focus-visible + .track {
    outline: 1.5px solid var(--text);
    outline-offset: 2px;
  }
  :global(:root[data-look='terminal']) .track,
  :global(:root[data-look='terminal']) .knob {
    border-radius: 0;
  }
  .seg {
    display: inline-flex;
    border: 1px solid var(--line-strong);
    border-radius: var(--radius);
    padding: 3px;
    gap: 3px;
    margin-top: 6px;
  }
  .seg button {
    display: inline-flex;
    align-items: center;
    gap: 8px;
    height: 32px;
    padding: 0 14px;
    border: 0;
    border-radius: 3px;
    background: none;
    color: var(--text-dim);
    font-weight: 540;
    white-space: nowrap;
    transition: all var(--t-fast) ease;
  }
  .seg button.on {
    background: var(--bg-raised);
    color: var(--text);
    box-shadow: inset 0 0 0 1px var(--line-strong);
  }
  .pathrow {
    display: flex;
    align-items: center;
    justify-content: space-between;
    gap: 12px;
    font-size: 13px;
  }
  .add {
    align-self: flex-start;
  }
  .notes summary {
    margin-top: 8px;
    color: var(--text-dim);
    font-size: 13px;
    cursor: pointer;
  }
  .notes pre {
    margin: 8px 0 0;
    padding: 10px 14px;
    background: var(--bg-sunk);
    border-left: 1px solid var(--line-strong);
    font: 12.5px/1.5 var(--font-body);
    white-space: pre-wrap;
    color: var(--text-dim);
    max-height: 220px;
    overflow: auto;
    user-select: text;
  }
  .about {
    display: flex;
    align-items: center;
    gap: 22px;
    padding: 14px 0;
  }
  .brandword {
    font-size: calc(44px * var(--display-scale));
    line-height: 1;
    text-transform: none;
  }
  .link {
    margin-top: 4px;
    display: inline-flex;
    align-items: center;
    gap: 6px;
    border: 0;
    background: none;
    padding: 0;
    color: var(--safe);
    font-size: 13px;
  }
  .spacer {
    height: 80px;
  }
  .savebar {
    position: fixed;
    left: 50%;
    bottom: 22px;
    translate: -50% 0;
    display: flex;
    align-items: center;
    gap: 12px;
    padding: 10px 10px 10px 18px;
    background: var(--bg-raised);
    border: 1px solid var(--line-strong);
    border-radius: var(--radius);
    box-shadow: var(--shadow);
    z-index: 20;
    white-space: nowrap;
  }
  .savebar span {
    color: var(--text-dim);
    margin-right: 8px;
  }
  @media (max-width: 1050px) {
    .looks,
    .fonts {
      grid-template-columns: repeat(2, minmax(0, 1fr));
    }
    .palettes {
      grid-template-columns: repeat(3, minmax(0, 1fr));
    }
    .pairs {
      grid-template-columns: 1fr;
    }
    .plan {
      flex-wrap: wrap;
    }
    .pl {
      width: auto;
      flex: 1;
    }
  }
</style>
