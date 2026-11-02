import { confirmEmailSentence, COPY } from './copy.js'

// The confirmation screen. It does not import AppKit and it does not confirm
// on load: the button is the only way to POST.

export function confirmView(state) {
  if (!state || state.invalid) {
    return { body: COPY.emailLinkInvalid, button: null }
  }
  if (state.done) {
    return { body: COPY.confirmedEmail, button: null }
  }
  if (state.loading || !state.pending) {
    return { body: COPY.loading, button: null }
  }
  return {
    body: confirmEmailSentence(state.pending, state.clientId),
    button: 'Confirm',
  }
}

export function renderConfirmScreen(document, root, view, onConfirm) {
  const body = document.createElement('p')
  body.textContent = view.body
  root.replaceChildren(body)
  if (!view.button) return
  const button = document.createElement('button')
  button.type = 'button'
  button.textContent = view.button
  button.addEventListener('click', onConfirm)
  root.append(button)
}
