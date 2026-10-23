<script lang="ts">
  // Rahmen der App: Kopfleiste, aktuelle Seite mit Übergang, Meldungen
  import { onMount } from 'svelte'
  import { listen } from '@tauri-apps/api/event'
  import TopBar from './components/TopBar.svelte'
  import Toasts from './components/Toasts.svelte'
  import Confirm from './components/Confirm.svelte'
  import Overview from './pages/Overview.svelte'
  import Scan from './pages/Scan.svelte'
  import Findings from './pages/Findings.svelte'
  import System from './pages/System.svelte'
  import History from './pages/History.svelte'
  import Pro from './pages/Pro.svelte'
  import Settings from './pages/Settings.svelte'
  import { app } from './lib/store.svelte'

  onMount(() => {
    app.init()
    // Tray-Menü „Update verfügbar“ öffnet direkt die Einstellungen
    let off: (() => void) | null = null
    listen<string>('open-page', (e) => {
      if (e.payload === 'settings') app.page = 'settings'
    }).then((u) => (off = u))
    return () => off?.()
  })
</script>

<div class="shell">
  <TopBar />
  <main>
    {#key app.page}
      {#if app.page === 'overview'}<Overview />
      {:else if app.page === 'scan'}<Scan />
      {:else if app.page === 'findings'}<Findings />
      {:else if app.page === 'system'}<System />
      {:else if app.page === 'history'}<History />
      {:else if app.page === 'pro'}<Pro />
      {:else}<Settings />{/if}
    {/key}
  </main>
</div>
<Toasts />
<Confirm />

<style>
  .shell {
    height: 100%;
    display: flex;
    flex-direction: column;
  }
  main {
    position: relative;
    flex: 1;
    min-height: 0;
  }
</style>
