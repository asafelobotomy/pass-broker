"""Selectors and in-page scripts used by the broker's browser.

The scripts never read the value of a sensitive field; the redactor is the
backstop for pages that lie about their fields or echo secrets.
"""

SENSITIVE_CSS = (
    "input[type=password], [data-pb-secret], input[autocomplete~='one-time-code'], "
    "input[autocomplete~='current-password'], input[autocomplete~='new-password'], "
    "input[autocomplete^='cc-'], input[maxlength='1']"
)

USERNAME_SELECTORS = [
    "input[autocomplete~='username']:not([type=password]):visible",
    "input[autocomplete~='email']:not([type=password]):visible",
    "input[type=email]:not([type=password]):visible",
    "input[name*='user' i]:not([type=password]):visible",
    "input[id*='user' i]:not([type=password]):visible",
    "input[name*='email' i]:not([type=password]):visible",
    "input[id*='email' i]:not([type=password]):visible",
    "input[name*='login' i]:not([type=password]):visible",
    "input[id*='login' i]:not([type=password]):visible",
]

OTP_SELECTORS = [
    "input[autocomplete~='one-time-code']:visible",
    "input[name*='totp' i]:visible",
    "input[id*='totp' i]:visible",
    "input[name*='otp' i]:visible",
    "input[id*='otp' i]:visible",
    "input[name*='code' i]:visible",
    "input[id*='code' i]:visible",
    "input[inputmode=numeric]:visible",
]

# Runs in each frame. Never reads the value of a sensitive field; the redactor
# is the backstop for pages that lie about their fields or echo secrets.
SNAPSHOT_JS = r"""
(prefix) => {
  const SENS = /(one-time-code|current-password|new-password|^cc-)/i;
  // One-character boxes are treated as secret: split 2FA code fields use them.
  const sensitive = el => {
    if (el.hasAttribute('data-pb-secret')) return true;
    const t = (el.getAttribute('type') || '').toLowerCase();
    return t === 'password' || el.maxLength === 1 || SENS.test(el.getAttribute('autocomplete') || '');
  };
  const shown = el => {
    const r = el.getBoundingClientRect();
    const s = getComputedStyle(el);
    return r.width > 0 && r.height > 0 && s.visibility !== 'hidden' && s.display !== 'none';
  };
  const clip = (s, n) => (s || '').replace(/\s+/g, ' ').trim().slice(0, n);
  document.querySelectorAll('[data-pb-ref]').forEach(e => e.removeAttribute('data-pb-ref'));
  const sel = 'a[href],button,input:not([type=hidden]),select,textarea,[role=button],[role=link],' +
              '[role=checkbox],[role=tab],[role=menuitem],[contenteditable=""],[contenteditable=true]';
  const out = [];
  let i = 0;
  for (const el of document.querySelectorAll(sel)) {
    if (!shown(el)) continue;
    const ref = prefix + (i++);
    el.setAttribute('data-pb-ref', ref);
    const tag = el.tagName.toLowerCase();
    const type = (el.getAttribute('type') || '').toLowerCase();
    const labels = el.labels ? [...el.labels].map(l => l.innerText).join(' ') : '';
    const isButton = tag === 'button' || type === 'submit' || type === 'button';
    const item = {
      ref, tag,
      role: el.getAttribute('role') || undefined,
      type: type || undefined,
      name: clip(el.getAttribute('aria-label') || labels || el.getAttribute('placeholder') ||
                 el.getAttribute('title') || el.innerText || (isButton ? el.value : '') || el.getAttribute('href'), 120),
    };
    if (sensitive(el)) {
      item.sensitive = true;
      item.filled = !!el.value;
    } else if (el.hasAttribute('data-pb-masked')) {
      const v = el.value || '';
      const at = v.indexOf('@');
      item.value = v ? v.slice(0, 1) + '***' + (at > 0 ? v.slice(at) : '') : '';
    } else if (tag === 'select') {
      item.value = clip(el.selectedOptions[0] && el.selectedOptions[0].text, 120);
    } else if ((tag === 'input' && !isButton) || tag === 'textarea') {
      if (type === 'checkbox' || type === 'radio') item.checked = el.checked;
      else item.value = clip(el.value, 200);
    }
    out.push(item);
  }
  return { url: location.href, title: document.title, text: clip(document.body ? document.body.innerText : '', 6000), elements: out };
}
"""

# Everything a screenshot could show, read back only by the broker to decide
# whether a screenshot is safe; never returned to the model.
VISIBLE_TEXT_JS = r"""
() => {
  const SENS = /(one-time-code|current-password|new-password|^cc-)/i;
  const parts = [document.body ? document.body.innerText : ''];
  for (const el of document.querySelectorAll('input,textarea')) {
    const t = (el.getAttribute('type') || '').toLowerCase();
    if (el.hasAttribute('data-pb-secret') || t === 'password' || el.maxLength === 1 || SENS.test(el.getAttribute('autocomplete') || '')) continue;
    parts.push(el.value || '');
  }
  return parts.join('\n');
}
"""
