"""The OAuth consent page: the form that asks for the code shown on your desktop.

Styled, unframeable and never cached. The code itself only ever appears in the
desktop notification, never on this page.
"""

from __future__ import annotations

import hmac
import html
import secrets
import time
from typing import TYPE_CHECKING

from mcp.server.auth.provider import AuthorizationCode, construct_redirect_uri
from starlette.requests import Request
from starlette.responses import HTMLResponse, RedirectResponse, Response

if TYPE_CHECKING:
    from .oauth import BrokerOAuth, Pending


def consent_page(body: str, status: int = 200) -> HTMLResponse:
    doc = f"""<!doctype html><html lang=en><meta charset=utf-8>
<meta name=viewport content="width=device-width,initial-scale=1">
<title>Pass Broker</title>
<style>
:root{{color-scheme:light dark;--fg:#1d1d1f;--bg:#f5f5f7;--card:#fff;--muted:#6e6e73;--accent:#3d5afe;--bad:#c0392b}}
@media (prefers-color-scheme:dark){{:root{{--fg:#f5f5f7;--bg:#111;--card:#1c1c1e;--muted:#a1a1a6;--accent:#8c9eff}}}}
body{{margin:0;font:16px/1.5 system-ui,sans-serif;background:var(--bg);color:var(--fg);display:grid;place-items:center;min-height:100vh}}
main{{background:var(--card);max-width:440px;width:calc(100% - 32px);padding:28px;border-radius:14px;box-shadow:0 2px 20px #0002}}
h1{{font-size:1.3rem;margin:0 0 12px}} p{{color:var(--muted)}} .bad{{color:var(--bad)}}
label{{display:block;font-weight:600;margin:16px 0 6px}}
input{{width:100%;box-sizing:border-box;font:inherit;padding:10px 12px;border-radius:8px;border:1px solid #8886;background:transparent;color:inherit}}
#code{{font:600 1.4rem ui-monospace,monospace;letter-spacing:.15em;text-transform:uppercase;text-align:center}}
.row{{display:flex;flex-direction:row-reverse;gap:10px;margin-top:22px}} button{{flex:1;font:inherit;padding:10px;border-radius:8px;border:0;cursor:pointer}}
.ok{{background:var(--accent);color:#fff}} .no{{background:#8883;color:inherit}}
</style><main>{body}</main></html>"""
    return HTMLResponse(
        doc,
        status_code=status,
        headers={
            "Content-Security-Policy": "default-src 'none'; style-src 'unsafe-inline'; form-action 'self' https: http://localhost:* http://127.0.0.1:*; frame-ancestors 'none'",
            "X-Frame-Options": "DENY",
            "Referrer-Policy": "no-referrer",
            "Cache-Control": "no-store",
        },
    )


class ConsentMixin:
    # these live in oauth.py; imported lazily to avoid a cycle
    @staticmethod
    def _limits() -> tuple[int, int, str]:
        from .oauth import CODE_TTL, MAX_ATTEMPTS, SCOPE

        return MAX_ATTEMPTS, CODE_TTL, SCOPE

    def _page(self: "BrokerOAuth", body: str, status: int = 200) -> HTMLResponse:
        return consent_page(body, status)

    def _get_pending(self: "BrokerOAuth", req: str) -> "Pending | None":
        with self._lock:
            p = self.pending.get(req)
            if p and p.expires < time.time():
                del self.pending[req]
                return None
            return p

    async def consent(self: "BrokerOAuth", request: Request) -> Response:
        MAX_ATTEMPTS, CODE_TTL, SCOPE = self._limits()
        if request.method == "GET":
            p = self._get_pending(request.query_params.get("req", ""))
            return self._consent_form(p) if p else self._expired()
        form = await request.form()
        p = self._get_pending(str(form.get("req", "")))
        if p is None:
            return self._expired()
        app = self._app_name(p.client)
        if form.get("action") == "deny":
            with self._lock:
                self.pending.pop(p.id, None)
            self.audit("oauth_denied", app=app)
            return RedirectResponse(
                construct_redirect_uri(str(p.params.redirect_uri), error="access_denied", state=p.params.state), status_code=303
            )
        typed = str(form.get("code", "")).upper().replace(" ", "").replace("-", "")
        if not hmac.compare_digest(typed, p.code.replace("-", "")):
            with self._lock:
                p.attempts += 1
                if p.attempts >= MAX_ATTEMPTS:
                    self.pending.pop(p.id, None)
            self.audit("oauth_bad_code", app=app, attempts=p.attempts)
            if p.attempts >= MAX_ATTEMPTS:
                return self._page("<h1>Too many wrong codes</h1><p>This sign-in was cancelled. Start again from the app.</p>", 403)
            return self._consent_form(p, error=f"That code doesn't match. {MAX_ATTEMPTS - p.attempts} tries left.")
        name = "".join(ch for ch in str(form.get("name", "")).strip() if ch.isalnum() or ch in "._-")[:32] or "remote"
        if name.lower() in self.taken_names():
            # Bots and their grants belong to a connection by name; two with one name would share them.
            return self._consent_form(p, error=f"A connection or assistant called “{name}” already exists. Pick another name, "
                                                "or revoke the old one in Pass Broker first.")
        with self._lock:
            self.pending.pop(p.id, None)
            code = AuthorizationCode(
                code=secrets.token_urlsafe(32),
                scopes=p.params.scopes or [SCOPE],
                expires_at=time.time() + CODE_TTL,
                client_id=p.client.client_id,
                code_challenge=p.params.code_challenge,
                redirect_uri=p.params.redirect_uri,
                redirect_uri_provided_explicitly=p.params.redirect_uri_provided_explicitly,
                resource=self.resource,
            )
            self.codes[code.code] = (code, name)
        self.audit("oauth_approved", app=app, name=name)
        return RedirectResponse(construct_redirect_uri(str(p.params.redirect_uri), code=code.code, state=p.params.state), status_code=303)

    def _expired(self: "BrokerOAuth") -> HTMLResponse:
        return self._page("<h1>This sign-in has expired</h1><p>Start again from the app you were connecting.</p>", 410)

    def _consent_form(self: "BrokerOAuth", p: "Pending", error: str = "") -> HTMLResponse:
        MAX_ATTEMPTS, _, _ = self._limits()
        app = html.escape(self._app_name(p.client))
        back = html.escape(self._returns_to(p.params))
        guess = html.escape("".join(ch for ch in self._app_name(p.client).lower() if ch.isalnum())[:32] or "remote")
        err = f"<p class=bad>{html.escape(error)}</p>" if error else ""
        return self._page(
            f"""<h1>Connect {app} to Pass Broker</h1>
<p>{app} is asking to use your Pass Broker: it could ask to sign in to sites with your saved logins.
You'd still approve each password fill on your PC.</p>
<p>After you connect, it returns to <b>{back}</b>. If that isn't the app you're connecting, press Deny.</p>
<p>Enter the code shown in the notification on your PC. If there's no notification, don't continue.</p>
{err}
<form method=post>
<input type=hidden name=req value="{html.escape(p.id)}">
<label for=code>Code from your PC</label>
<input id=code name=code autocomplete=off autocapitalize=characters spellcheck=false maxlength=9 placeholder="XXXX-XXXX" autofocus required>
<label for=name>Name this connection</label>
<input id=name name=name value="{guess}" maxlength=32>
<div class=row><button class=ok name=action value=allow>Connect</button><button class=no name=action value=deny formnovalidate>Deny</button></div>
</form>"""
        )

    # ---- codes and tokens -----------------------------------------------------------
