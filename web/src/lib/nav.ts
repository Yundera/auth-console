// In-app link handling for pages. App.svelte listens to popstate, so pushing
// state and firing the event is all a page needs to switch views without a reload.
export function navigate(e: MouseEvent, to: string) {
  if (e.metaKey || e.ctrlKey || e.shiftKey || e.button !== 0) return
  e.preventDefault()
  if (to !== location.pathname) history.pushState(null, '', to)
  dispatchEvent(new PopStateEvent('popstate'))
}
