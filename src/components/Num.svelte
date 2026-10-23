<script lang="ts">
  // Zahl, die weich auf den neuen Wert zählt
  import { Tween } from 'svelte/motion'
  import { cubicOut } from 'svelte/easing'
  import { i18n } from '../lib/i18n.svelte'

  interface Props {
    value: number
    duration?: number
    format?: (n: number) => string
  }
  let { value, duration = 700, format }: Props = $props()

  const tween = new Tween(0, { duration: 0, easing: cubicOut })
  let first = true
  $effect(() => {
    const reduce = document.documentElement.dataset.motion === 'ruhig'
    tween.set(value, { duration: first || reduce ? (first ? Math.min(duration, 900) : 0) : duration })
    first = false
  })

  const text = $derived(format ? format(tween.current) : new Intl.NumberFormat(i18n.locale === 'de' ? 'de-DE' : 'en-GB').format(Math.round(tween.current)))
</script>

<span class="num">{text}</span>

<style>
  .num {
    font-variant-numeric: tabular-nums;
  }
</style>
