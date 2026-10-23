// Einstiegspunkt der Oberfläche
import { mount } from 'svelte'
import './app.css'
import App from './App.svelte'

// Vor dem ersten Bild das Thema des Systems setzen, damit nichts aufblitzt
document.documentElement.dataset.theme = window.matchMedia('(prefers-color-scheme: light)').matches ? 'light' : 'dark'

const app = mount(App, { target: document.getElementById('app')! })

export default app
