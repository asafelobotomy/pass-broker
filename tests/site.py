"""A tiny local website with the sign-in patterns the broker has to handle."""

from __future__ import annotations

import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs

PASSWORD = "S3cr3t-Pa55word!"
TOTP = "482913"

LOGIN = """<!doctype html><title>Sign in</title><h1>Sign in</h1>{err}
<form method=post action=/session>
<label for=login_field>Username</label><input id=login_field name=login autocomplete=username>
<label for=password>Password</label><input id=password name=password type=password>
<button>Sign in</button></form>"""

STEP1 = """<!doctype html><title>Step 1</title><form method=post action=/step1>
<input name=username autocomplete=username><button>Next</button></form>"""

STEP2 = """<!doctype html><title>Step 2</title><form method=post action=/session>
<input type=hidden name=login value=alice><input name=password type=password><button>Sign in</button></form>"""

OTP = """<!doctype html><title>2FA</title><form method=post action=/otp>
<label>Code <input name=otp autocomplete=one-time-code inputmode=numeric></label><button>Verify</button></form>"""

SPLIT = """<!doctype html><title>2FA boxes</title><form method=post action=/otp id=f>
<input type=hidden name=otp id=otp>
""" + "".join(f'<input class=d maxlength=1 inputmode=numeric aria-label="digit {i}">' for i in range(6)) + """
<button>Verify</button></form>
<script>
const ds=[...document.querySelectorAll('.d')];
ds.forEach((d,i)=>d.addEventListener('input',()=>{ if(d.value && ds[i+1]) ds[i+1].focus(); }));
document.getElementById('f').addEventListener('submit',()=>{ document.getElementById('otp').value=ds.map(d=>d.value).join(''); });
</script>"""

# Echoes whatever is typed into the password box into page text and a plain
# text input, and never navigates: the worst case for a snapshot or screenshot.
LEAKY = """<!doctype html><title>Leaky</title>
<form onsubmit="return false"><input name=user autocomplete=username>
<input id=pw type=password><button>Sign in</button></form>
<div id=echo></div><input id=mirror aria-label=mirror>
<button id=show onclick="document.getElementById('pw').type='text'">Show password</button>
<script>
document.getElementById('pw').addEventListener('input', e => {
  if (!e.target.value) return;  // keep the copy even after the broker clears the field
  document.getElementById('echo').textContent = 'you typed ' + e.target.value;
  document.getElementById('mirror').value = e.target.value;
});
</script>"""

EVIL = """<!doctype html><title>Evil</title>
<form method=post action=/steal><input name=login autocomplete=username><input name=password type=password><button>Sign in</button></form>"""

SPLIT_STAY = """<!doctype html><title>2FA boxes, no submit</title><form onsubmit="return false">
""" + "".join(f'<input class=d maxlength=1 inputmode=numeric aria-label="digit {i}">' for i in range(6)) + """
</form>
<script>
const ds=[...document.querySelectorAll('.d')];
ds.forEach((d,i)=>d.addEventListener('input',()=>{ if(d.value && ds[i+1]) ds[i+1].focus(); }));
</script>"""

STAY = """<!doctype html><title>Stay</title>
<form onsubmit="return false"><input name=user autocomplete=username>
<input id=pw type=password><button>Sign in</button></form>
<button id=show onclick="document.getElementById('pw').type='text'">Show password</button>"""


# An account page full of personal details, with a link off to another host.
ACCOUNT = """<!doctype html><title>Account of alice@example.com</title><h1>Your account</h1>
<p id=email>Email: alice@example.com</p><p id=phone>Phone: +44 7700 900123</p>
<p id=card>Card: 4111 1111 1111 1111</p><p>Order 1234567 shipped on 2026-11-04.</p>
<label>Recovery email <input id=rec type=email value="bob@example.org"></label>
<a id=away href="http://localhost:{port}/welcome">elsewhere</a>"""


# A link to a page that may be blocked, and the same page reached the way
# single-page apps do it: the address changes with no page load.
SHOP = """<!doctype html><title>Shop</title><a id=pay href="/account/payments">Payments</a>
<button id=spa onclick="history.pushState({}, '', '/account/payments'); document.title='Payments'">Payments (app)</button>"""


# A sign-up form: email, the bot's own field, password and confirm.
SIGNUP = """<!doctype html><title>Create account</title><form method=post action=/signup>
<label>Email <input name=email type=email></label><label>Name <input name=name aria-label=name></label>
<label>Password <input name=password type=password></label><label>Again <input name=confirm type=password></label>
<button>Create account</button></form>"""
# Every account field a sign-up form tends to ask for, plus ones only the bot fills.
SIGNUP_FULL = """<!doctype html><title>Join</title><form method=post action=/signup-full>
<label>First name <input name=first_name autocomplete=given-name></label>
<label>Choose a username <input name=user_name autocomplete=username></label>
<label>Email address <input name=email type=email></label><label>Confirm email <input name=email_confirm></label>
<label>Phone <input name=phone type=tel></label><label>Display name <input name=display></label>
<label>Password <input name=pw type=password autocomplete=new-password></label>
<label>Repeat password <input name=pw2 type=password autocomplete=new-password></label>
<label><input type=checkbox name=terms value=yes> I agree</label><button>Join</button></form>"""
JOIN1 = """<!doctype html><title>Join</title><form method=post action=/join>
<input name=address autocomplete=email placeholder="Your email"><button>Next</button></form>"""
JOIN2 = """<!doctype html><title>Join</title><form method=post action=/join2>
<input name=new type=password><input name=again type=password><button>Create</button></form>"""


class Site:
    def __init__(self) -> None:
        self.posts: list[tuple[str, dict[str, list[str]]]] = []
        site = self

        class Handler(BaseHTTPRequestHandler):
            def log_message(self, *a):  # keep test output quiet
                pass

            def _html(self, body: str, status: int = 200) -> None:
                data = body.encode()
                self.send_response(status)
                self.send_header("content-type", "text/html; charset=utf-8")
                self.send_header("content-length", str(len(data)))
                self.end_headers()
                self.wfile.write(data)

            def _redirect(self, to: str) -> None:
                self.send_response(303)
                self.send_header("location", to)
                self.send_header("content-length", "0")
                self.end_headers()

            def do_GET(self):
                port = self.server.server_address[1]
                pages = {
                    "/login": LOGIN.format(err=""),
                    "/step1": STEP1,
                    "/step2": STEP2,
                    "/otp": OTP,
                    "/split": SPLIT,
                    "/leaky": LEAKY,
                    "/stay": STAY,
                    "/evil": EVIL,
                    "/split-stay": SPLIT_STAY,
                    "/welcome": "<!doctype html><title>Welcome</title><h1>Welcome, alice</h1>",
                    "/account": ACCOUNT.format(port=port),
                    "/shop": SHOP,
                    "/signup": SIGNUP,
                    "/signup-full": SIGNUP_FULL,
                    "/join": JOIN1,
                    "/join2": JOIN2,
                    "/account/payments": "<!doctype html><title>Payments</title><p>Saved cards</p>",
                    "/framed": f'<!doctype html><title>Framed</title><iframe src="http://127.0.0.1:{port}/login" width=600 height=400></iframe>',
                }
                if self.path in pages:
                    self._html(pages[self.path])
                else:
                    self._html("not found", 404)

            def do_POST(self):
                n = int(self.headers.get("content-length", 0))
                form = parse_qs(self.rfile.read(n).decode())
                site.posts.append((self.path, form))
                if self.path == "/session":
                    ok = form.get("password") == [PASSWORD]
                    return self._redirect("/welcome") if ok else self._html(LOGIN.format(err="<p>Wrong password</p>"))
                if self.path in ("/signup", "/signup-full", "/join2"):
                    return self._redirect("/welcome")
                if self.path == "/join":
                    return self._redirect("/join2")
                if self.path == "/step1":
                    return self._redirect("/step2")
                if self.path == "/otp":
                    return self._redirect("/welcome") if form.get("otp") == [TOTP] else self._html("bad code")
                self._html("?", 404)

        self.httpd = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self.port = self.httpd.server_address[1]
        self.thread = threading.Thread(target=self.httpd.serve_forever, daemon=True)

    def __enter__(self) -> "Site":
        self.thread.start()
        return self

    def __exit__(self, *exc) -> None:
        self.httpd.shutdown()

    def url(self, path: str, host: str = "localhost") -> str:
        return f"http://{host}:{self.port}{path}"

    def vault(self) -> list[dict]:
        return [
            {"title": "Test Site", "urls": [f"http://localhost:{self.port}"], "username": "alice", "password": PASSWORD, "totp": TOTP},
            {"title": "No Website", "urls": [], "username": "bob", "password": "nowhere-Secret-77"},
        ]
