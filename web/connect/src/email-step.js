// What the confirm step shows for the optional alert email.
// hidden: the server is not sending mail, so the card stays as it was.
// none: first address, optional field, one gentle reminder.
// pending: waiting on the inbox. A typed address replaces the pending one.
// confirmed: one line, no field. The connect link cannot change it.

export function emailMode(info) {
  if (!info || info.email_alerts_available !== true) return 'hidden'
  if (info.alert_email_status === 'confirmed') return 'confirmed'
  if (info.alert_email_status === 'pending') return 'pending'
  return 'none'
}

export function continuePlan({ mode, draft, reminded }) {
  if (mode === 'hidden' || mode === 'confirmed') return 'sign'
  const value = String(draft || '').trim()
  if (mode === 'none' && !value && !reminded) return 'remind'
  if (value && (mode === 'none' || mode === 'pending')) return 'save-and-sign'
  return 'sign'
}

// A failed save is a note. Signing still runs.
export async function saveEmailThenContinue({ post, sign, draft }) {
  let note = ''
  try {
    await post(String(draft || '').trim())
    note = 'saved'
  } catch (error) {
    note = error && error.message ? String(error.message) : 'failed'
  }
  await sign()
  return note
}
