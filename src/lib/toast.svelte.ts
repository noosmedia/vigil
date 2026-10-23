// Einheitliche Rückmeldungen am unteren Rand

export type ToastKind = 'success' | 'info' | 'warn' | 'error'

export interface Toast {
  id: number
  kind: ToastKind
  text: string
  detail?: string
}

let counter = 0

class ToastStore {
  items = $state<Toast[]>([])

  show(kind: ToastKind, text: string, detail?: string) {
    const id = ++counter
    this.items = [...this.items, { id, kind, text, detail }]
    // Fehler bleiben länger stehen, damit die Meldung lesbar ist
    const ms = kind === 'error' ? 12000 : kind === 'warn' ? 7000 : 4200
    setTimeout(() => this.dismiss(id), ms)
  }

  dismiss(id: number) {
    this.items = this.items.filter((t) => t.id !== id)
  }
}

export const toasts = new ToastStore()
