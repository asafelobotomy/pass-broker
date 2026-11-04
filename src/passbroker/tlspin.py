"""Pinning self-signed certificates (Proton Mail Bridge, routers, home servers).

Instead of switching certificate checks off, the broker records a device's own
certificate the first time you set it up (trust on first use), then accepts
only that exact certificate. A different certificate later, as from someone
intercepting the connection, fails the TLS handshake.
"""

from __future__ import annotations

import hashlib
import imaplib
import ssl


def fetch_https_cert(host: str, port: int = 443) -> str:
    """The PEM certificate an HTTPS server presents (not verified: this is the pinning step)."""
    return ssl.get_server_certificate((host, port), timeout=10)


def fetch_imap_starttls_cert(host: str, port: int) -> str:
    """The PEM certificate an IMAP server presents after STARTTLS (Proton Mail Bridge)."""
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    imap = imaplib.IMAP4(host, port, timeout=10)
    try:
        imap.starttls(ssl_context=ctx)
        der = imap.sock.getpeercert(binary_form=True)
    finally:
        try:
            imap.logout()
        except Exception:
            pass
    if not der:
        raise ssl.SSLError("the server presented no certificate")
    return ssl.DER_cert_to_PEM_cert(der)


def pinned_context(pem: str) -> ssl.SSLContext:
    """A context that trusts exactly this certificate and nothing else.

    Hostnames aren't checked: self-signed device certificates rarely name the
    address you reach them by, and the pinned certificate already identifies it.
    """
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.load_verify_locations(cadata=pem)
    ctx.verify_flags |= ssl.VERIFY_X509_PARTIAL_CHAIN
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_REQUIRED
    return ctx


def fingerprint(pem: str) -> str:
    digest = hashlib.sha256(ssl.PEM_cert_to_DER_cert(pem)).hexdigest().upper()
    return ":".join(digest[i : i + 2] for i in range(0, len(digest), 2))
