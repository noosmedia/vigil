<script lang="ts">
  // Eigene kleine Symbolsammlung, Strichzeichnungen im 24er-Raster
  interface Props {
    name: string
    size?: number
  }
  let { name, size = 16 }: Props = $props()

  const paths: Record<string, string> = {
    play: 'M7 5.5v13l11-6.5z',
    pause: 'M8.5 5.5v13M15.5 5.5v13',
    key: 'M15.5 4a4.5 4.5 0 1 1-4.3 5.8L4 17v3h3v-2h2v-2h2l1.2-1.2A4.5 4.5 0 0 1 15.5 4zM16.5 7.5h.01',
    spark: 'M12 3v4M12 17v4M3 12h4M17 12h4M6 6l2.5 2.5M15.5 15.5 18 18M6 18l2.5-2.5M15.5 8.5 18 6',
    arrowUp: 'M12 19V5M6 11l6-6 6 6',
    layers: 'M12 3 3 8l9 5 9-5zM3 13l9 5 9-5',
    stop: 'M7 7h10v10H7z',
    folder: 'M3.5 7.5a2 2 0 0 1 2-2h4l2 2h7a2 2 0 0 1 2 2v7.5a2 2 0 0 1-2 2h-13a2 2 0 0 1-2-2z',
    refresh: 'M20 11a8 8 0 0 0-14.6-4.5M4 13a8 8 0 0 0 14.6 4.5M5 3v4h4M19 21v-4h-4',
    sun: 'M12 4V2.5M12 21.5V20M4 12H2.5M21.5 12H20M6.3 6.3 5.2 5.2M18.8 18.8l-1.1-1.1M6.3 17.7l-1.1 1.1M18.8 5.2l-1.1 1.1M12 16.5a4.5 4.5 0 1 0 0-9 4.5 4.5 0 0 0 0 9z',
    moon: 'M20 14.5A8 8 0 0 1 9.5 4a8 8 0 1 0 10.5 10.5z',
    auto: 'M12 3.5a8.5 8.5 0 1 0 0 17a8.5 8.5 0 0 0 0-17zM12 3.5v17M12 7.5l-4 4M12 12l-4.6 4.6',
    lock: 'M7 10.5V8a5 5 0 0 1 10 0v2.5M5.5 10.5h13v10h-13z',
    mail: 'M3.5 6.5h17v11h-17zM3.5 7l8.5 6.5L20.5 7',
    unlock: 'M7 10.5V8a5 5 0 0 1 9.6-1.9M5.5 10.5h13v10h-13z',
    trash: 'M4.5 6.5h15M9.5 6.5V4h5v2.5M6.5 6.5l1 14h9l1-14',
    check: 'M5 12.5l4.5 4.5L19 7.5',
    x: 'M6 6l12 12M18 6 6 18',
    chevron: 'M9 6l6 6-6 6',
    alert: 'M12 4 2.5 20h19zM12 10v4.5M12 17.2v.3',
    shield: 'M12 3 4.5 6v5.5c0 4.6 3.1 8 7.5 9.5 4.4-1.5 7.5-4.9 7.5-9.5V6z',
    download: 'M12 4v11M7 10.5l5 5 5-5M4.5 20h15',
    copy: 'M8.5 8.5h11v11h-11zM15.5 8.5v-4h-11v11h4',
    external: 'M14 4.5h5.5V10M19.5 4.5 11 13M10 6.5H5.5v12h12V14',
    plus: 'M12 5v14M5 12h14',
    restore: 'M4 12a8 8 0 1 0 2.4-5.7M4 4v4.5h4.5',
  }
</script>

<svg
  width={size}
  height={size}
  viewBox="0 0 24 24"
  fill="none"
  stroke="currentColor"
  stroke-width="1.7"
  stroke-linecap="round"
  stroke-linejoin="round"
  aria-hidden="true"
>
  <path d={paths[name] ?? ''} />
</svg>
