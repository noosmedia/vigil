<script lang="ts">
  // Offene Funde, Funde des Download-Wächters und die Quarantäne.
  // Eine Datei, die in die Quarantäne wandert, fliegt sichtbar von oben in die Liste darunter.
  import { fade, slide } from 'svelte/transition'
  import { crossfade } from 'svelte/transition'
  import { flip } from 'svelte/animate'
  import { cubicOut } from 'svelte/easing'
  import Icon from '../components/Icon.svelte'
  import { ask } from '../components/Confirm.svelte'
  import { app } from '../lib/store.svelte'
  import { bytes, dateTime, kindLabel, relative } from '../lib/format'
  import { t, tn } from '../lib/i18n.svelte'

  const [send, receive] = crossfade({
    duration: (d) => Math.min(900, Math.max(450, Math.sqrt(d) * 32)),
    easing: cubicOut,
    fallback: (node) => slide(node, { duration: 260 }),
  })

  const open = $derived(app.openThreats.filter((o) => !o.hint))

  // Hinweise der Heuristik, nach Ordnern gruppiert (z. B. ein Mail-Archiv)
  interface HintItem {
    path: string
    sha256: string | null
    signature: string
    when: string
    size: number
    reportId: string | null
    threatId: string | null
  }
  const hintItems = $derived<HintItem[]>([
    ...app.openThreats
      .filter((o) => o.hint)
      .map((o) => ({ path: o.threat.path, sha256: o.threat.sha256 || null, signature: o.threat.signature, when: o.foundAt, size: o.threat.size, reportId: o.reportId, threatId: o.threat.id })),
    ...(app.snap?.watcherEvents.filter((e) => e.verdict === 'hint' && !e.handled) ?? []).map((e) => ({
      path: e.path,
      sha256: null,
      signature: e.detail ?? '',
      when: e.at,
      size: 0,
      reportId: null,
      threatId: null,
    })),
  ])
  function groupKey(p: string) {
    const parts = p.split('/')
    return parts.slice(0, parts[1] === 'home' ? 5 : 4).join('/') || '/'
  }
  const hintGroups = $derived.by(() => {
    const map = new Map<string, HintItem[]>()
    for (const h of hintItems) {
      const k = groupKey(h.path)
      map.set(k, [...(map.get(k) ?? []), h])
    }
    return [...map.entries()]
      .map(([key, items]) => {
        const sigs = new Map<string, number>()
        for (const i of items) sigs.set(i.signature.replace(/^Heuristics\./, ''), (sigs.get(i.signature.replace(/^Heuristics\./, '')) ?? 0) + 1)
        return { key, items, sigs: [...sigs.entries()].sort((a, b) => b[1] - a[1]) }
      })
      .sort((a, b) => b.items.length - a.items.length)
  })
  let openGroup = $state<string | null>(null)

  async function dismissGroup(key: string, items: HintItem[]) {
    if (await ask(t('findings.hints.confirmAll.title'), t('findings.hints.confirmAll.text', { n: items.length, path: key }), t('findings.hints.confirmAll.ok')))
      app.dismissHints(items.map((i) => ({ path: i.path, sha256: i.sha256 })))
  }

  function quarantineHint(h: HintItem) {
    if (h.reportId && h.threatId) return quarantineThreat(h.reportId, h.threatId)
    return quarantineWatcher(h.path)
  }
  const watcherHits = $derived(app.snap?.watcherEvents.filter((e) => e.verdict === 'infected' && !e.handled) ?? [])
  const quarantine = $derived(app.snap?.quarantine ?? [])

  function quarantineThreat(reportId: string, threatId: string) {
    return app.helper(`q:${reportId}:${threatId}`, ['quarantine', '--report', reportId, '--threat', threatId], t('findings.moved'))
  }

  async function deleteThreat(reportId: string, threatId: string, path: string) {
    if (await ask(t('findings.confirmDelete.title'), t('findings.confirmDelete.text', { path }), t('findings.confirmDelete.ok'), true))
      app.helper(`d:${reportId}:${threatId}`, ['delete-threat', '--report', reportId, '--threat', threatId], t('findings.deleted'))
  }

  async function allowThreat(reportId: string, threatId: string, path: string) {
    if (await ask(t('findings.confirmAllow.title'), t('findings.confirmAllow.text', { path }), t('findings.confirmAllow.ok')))
      app.helper(`a:${reportId}:${threatId}`, ['allow', '--report', reportId, '--threat', threatId], t('findings.allowed'))
  }

  function quarantineWatcher(path: string) {
    return app.helper(`qp:${path}`, ['quarantine-path', '--path', path], t('findings.moved'))
  }

  async function restore(id: string, path: string) {
    if (await ask(t('findings.confirmRestore.title'), t('findings.confirmRestore.text', { path }), t('findings.confirmRestore.ok')))
      app.helper(`r:${id}`, ['restore', '--id', id], t('findings.restored'))
  }

  async function restoreAllow(id: string, path: string) {
    if (await ask(t('findings.confirmRestoreAllow.title'), t('findings.confirmRestoreAllow.text', { path }), t('findings.confirmRestoreAllow.ok')))
      app.helper(`ra:${id}`, ['allow-quarantined', '--id', id], t('findings.restoredAllowed'))
  }

  async function remove(id: string, path: string) {
    if (await ask(t('findings.confirmRemove.title'), t('findings.confirmRemove.text', { path }), t('findings.confirmRemove.ok'), true))
      app.helper(`x:${id}`, ['delete', '--id', id], t('findings.removed'))
  }

  function dir(p: string) {
    const i = p.lastIndexOf('/')
    return i > 0 ? p.slice(0, i + 1) : ''
  }
  function base(p: string) {
    return p.slice(p.lastIndexOf('/') + 1)
  }
</script>

<div class="page" in:fade={{ duration: 220 }}>
  <header class="page-head">
    <div>
      <h1 class="page-title">{t('findings.title')}</h1>
      <p class="page-sub">{t('findings.sub')}</p>
    </div>
  </header>

  <p class="label section-label">{t('findings.open')}</p>
  {#if open.length === 0 && watcherHits.length === 0}
    <p class="empty" in:fade>{t('findings.none')}</p>
  {:else}
    <ul class="rows">
      {#each open as o (o.threat.path)}
        <li class="hit" out:send={{ key: o.threat.path }} animate:flip={{ duration: 300 }}>
          <span class="pulse"></span>
          <div class="what">
            <div class="sig mono">{o.threat.signature}</div>
            <div class="path mono" title={o.threat.path}><span class="d">{dir(o.threat.path)}</span><span class="f">{base(o.threat.path)}</span></div>
            <div class="when">{t('findings.meta', { kind: kindLabel(o.reportKind), when: relative(o.foundAt), size: bytes(o.threat.size) })}</div>
          </div>
          <div class="acts">
            <button class="btn small primary" class:busy={app.pending[`q:${o.reportId}:${o.threat.id}`]} onclick={() => quarantineThreat(o.reportId, o.threat.id)}>
              <Icon name="lock" size={13} /><span>{t('findings.toQuarantine')}</span>
            </button>
            <button class="btn small danger" class:busy={app.pending[`d:${o.reportId}:${o.threat.id}`]} onclick={() => deleteThreat(o.reportId, o.threat.id, o.threat.path)}>{t('findings.delete')}</button>
            <button class="btn small ghost" onclick={() => allowThreat(o.reportId, o.threat.id, o.threat.path)}>{t('findings.isSafe')}</button>
          </div>
        </li>
      {/each}
      {#each watcherHits as w (w.path)}
        <li class="hit" out:send={{ key: w.path }} animate:flip={{ duration: 300 }}>
          <span class="pulse"></span>
          <div class="what">
            <div class="sig mono">{w.detail}</div>
            <div class="path mono" title={w.path}><span class="d">{dir(w.path)}</span><span class="f">{base(w.path)}</span></div>
            <div class="when">{t('findings.watcher', { when: relative(w.at) })}</div>
          </div>
          <div class="acts">
            <button class="btn small primary" class:busy={app.pending[`qp:${w.path}`]} onclick={() => quarantineWatcher(w.path)}>
              <Icon name="lock" size={13} /><span>{t('findings.toQuarantine')}</span>
            </button>
          </div>
        </li>
      {/each}
    </ul>
  {/if}

  {#if hintGroups.length}
    <p class="label section-label">{t('findings.hints.title')} · {hintItems.length}</p>
    <p class="hint-intro">{t('findings.hints.intro')}</p>
    <ul class="rows">
      {#each hintGroups as g (g.key)}
        <li transition:slide={{ duration: 260 }}>
          <div class="hgroup">
            <span class="dot info"></span>
            <button class="what hhead" onclick={() => (openGroup = openGroup === g.key ? null : g.key)} aria-expanded={openGroup === g.key}>
              <div class="path mono"><span class="f">{g.key}</span></div>
              <div class="when">{tn('findings.hints.files', g.items.length)} · {g.sigs.slice(0, 2).map(([s, n]) => `${s} (${n})`).join(', ')}</div>
            </button>
            <div class="acts">
              <button class="btn small ghost" onclick={() => (openGroup = openGroup === g.key ? null : g.key)}>
                <span class="chev" class:open={openGroup === g.key}><Icon name="chevron" size={13} /></span><span>{openGroup === g.key ? t('findings.hints.hide') : t('findings.hints.show')}</span>
              </button>
              <button class="btn small" onclick={() => dismissGroup(g.key, g.items)}>{t('findings.hints.dismissAll')}</button>
            </div>
          </div>
          {#if openGroup === g.key}
            <ul class="hlist" transition:slide={{ duration: 260 }}>
              {#each g.items.slice(0, 80) as h (h.path)}
                <li>
                  <div class="what">
                    <div class="path mono" title={h.path}><span class="d">{dir(h.path)}</span><span class="f">{base(h.path)}</span></div>
                    <div class="when">{h.signature} · {h.reportId ? relative(h.when) : `${t('findings.hints.watcher')}, ${relative(h.when)}`}</div>
                  </div>
                  <div class="acts">
                    <button class="btn small ghost" onclick={() => app.dismissHints([{ path: h.path, sha256: h.sha256 }])}>{t('findings.hints.dismiss')}</button>
                    <button class="btn small ghost" class:busy={app.pending[`q:${h.reportId}:${h.threatId}`] || app.pending[`qp:${h.path}`]} onclick={() => quarantineHint(h)}><Icon name="lock" size={13} /><span>{t('findings.toQuarantine')}</span></button>
                  </div>
                </li>
              {/each}
              {#if g.items.length > 80}<li class="more-files">+ {g.items.length - 80}</li>{/if}
            </ul>
          {/if}
        </li>
      {/each}
    </ul>
  {/if}

  <p class="label section-label">{t('findings.quarantine')}</p>
  {#if quarantine.length === 0}
    <p class="empty">{t('findings.empty')}</p>
  {:else}
    <ul class="rows">
      {#each quarantine as q (q.id)}
        <li class="qrow" in:receive={{ key: q.originalPath }} out:slide={{ duration: 240 }} animate:flip={{ duration: 300 }}>
          <span class="lock"><Icon name="lock" size={15} /></span>
          <div class="what">
            <div class="sig mono">{q.signature}</div>
            <div class="path mono" title={q.originalPath}><span class="d">{dir(q.originalPath)}</span><span class="f">{base(q.originalPath)}</span></div>
            <div class="when">{t('findings.lockedAt', { when: dateTime(q.quarantinedAt), size: bytes(q.size) })}</div>
          </div>
          <div class="acts">
            <button class="btn small" class:busy={app.pending[`r:${q.id}`]} onclick={() => restore(q.id, q.originalPath)}><Icon name="restore" size={13} /><span>{t('findings.restore')}</span></button>
            <button class="btn small ghost" onclick={() => restoreAllow(q.id, q.originalPath)}>{t('findings.isSafe')}</button>
            <button class="btn small danger" class:busy={app.pending[`x:${q.id}`]} onclick={() => remove(q.id, q.originalPath)}><Icon name="trash" size={13} /><span>{t('findings.delete')}</span></button>
          </div>
        </li>
      {/each}
    </ul>
  {/if}
</div>

<style>
  .hit,
  .qrow {
    display: grid;
    grid-template-columns: 20px minmax(0, 1fr) auto;
    align-items: center;
    gap: 16px;
    padding: 16px 0;
    background: var(--bg);
  }
  .qrow {
    color: var(--text-dim);
  }
  .lock {
    display: grid;
    place-items: center;
    animation: lockin 700ms var(--ease-spring) both;
  }
  @keyframes lockin {
    from {
      transform: scale(0.4) rotate(-20deg);
      opacity: 0;
    }
  }
  .pulse {
    width: 9px;
    height: 9px;
    border-radius: 50%;
    background: var(--threat);
    position: relative;
    justify-self: center;
  }
  .pulse::after {
    content: '';
    position: absolute;
    inset: -5px;
    border-radius: 50%;
    border: 1px solid var(--threat);
    animation: ring 2s var(--ease-out) infinite;
  }
  @keyframes ring {
    from {
      transform: scale(0.4);
      opacity: 1;
    }
    to {
      transform: scale(2.2);
      opacity: 0;
    }
  }
  .what {
    min-width: 0;
  }
  .sig {
    font-size: 13px;
    color: var(--threat);
    font-weight: 600;
  }
  .qrow .sig {
    color: var(--text);
  }
  .path {
    display: flex;
    font-size: 13px;
    color: var(--text);
    white-space: nowrap;
    overflow: hidden;
    user-select: text;
    margin-top: 2px;
  }
  /* Ordner darf gekürzt werden, der Dateiname bleibt immer ganz sichtbar */
  .path .d {
    color: var(--text-faint);
    overflow: hidden;
    text-overflow: ellipsis;
    min-width: 0;
  }
  .path .f {
    flex: none;
    max-width: 70%;
    overflow: hidden;
    text-overflow: ellipsis;
  }
  .when {
    font-size: 12.5px;
    color: var(--text-faint);
    margin-top: 2px;
  }
  .acts {
    display: flex;
    gap: 8px;
  }
  .hint-intro {
    margin: 4px 0 8px;
    color: var(--text-dim);
    font-size: 13px;
    max-width: 680px;
  }
  .hgroup {
    display: grid;
    grid-template-columns: 20px minmax(0, 1fr) auto;
    align-items: center;
    gap: 16px;
    padding: 14px 0;
  }
  .hgroup > .dot {
    justify-self: center;
  }
  .hhead {
    border: 0;
    background: none;
    padding: 0;
    text-align: left;
  }
  .chev {
    display: grid;
    transition: transform var(--t-normal) var(--ease-out);
  }
  .chev.open {
    transform: rotate(90deg);
  }
  .hlist {
    list-style: none;
    margin: 0 0 12px 36px;
    padding: 0;
    border-left: 1px solid var(--line);
  }
  .hlist > li {
    display: grid;
    grid-template-columns: minmax(0, 1fr) auto;
    align-items: center;
    gap: 12px;
    padding: 8px 0 8px 14px;
  }
  .hlist .path {
    font-size: 12.5px;
  }
  .more-files {
    color: var(--text-faint);
    font-size: 12.5px;
  }
  @media (max-width: 900px) {
    .hit,
    .qrow {
      grid-template-columns: 20px minmax(0, 1fr);
    }
    .acts {
      grid-column: 2;
      flex-wrap: wrap;
    }
  }
</style>
