"""Pinned self-signed certificates for home devices and Proton Mail Bridge."""

import shutil
import ssl
import subprocess
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import pytest

from passbroker import devices as devices_mod
from passbroker.devices import Device, DeviceStore
from passbroker.mailcode import MailSettings, fetch_code
from passbroker.tlspin import fingerprint

pytestmark = pytest.mark.skipif(not shutil.which("openssl"), reason="openssl not installed")


def _self_signed(folder, name, expired=False):
    key, cert = folder / f"{name}.key", folder / f"{name}.pem"
    if expired:
        return _expired(key, cert, name)
    subprocess.run(["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-days", "2", "-subj", f"/CN={name}",
                    "-keyout", str(key), "-out", str(cert)], check=True, capture_output=True)
    return key, cert


def _expired(key, cert, name):
    """A certificate that expired in 2020 (older openssl `req` can't backdate one)."""
    import datetime

    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.x509.oid import NameOID

    k = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, name)])
    start = datetime.datetime(2020, 1, 1, tzinfo=datetime.UTC)
    c = (x509.CertificateBuilder().subject_name(subject).issuer_name(subject).public_key(k.public_key())
         .serial_number(x509.random_serial_number()).not_valid_before(start).not_valid_after(start + datetime.timedelta(days=1))
         .sign(k, hashes.SHA256()))
    key.write_bytes(k.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.TraditionalOpenSSL, serialization.NoEncryption()))
    cert.write_bytes(c.public_bytes(serialization.Encoding.PEM))
    return key, cert


class _Server:
    def __init__(self, key, cert):
        class H(BaseHTTPRequestHandler):
            def log_message(self, *a):
                pass

            def do_POST(self):
                self.send_response(200)
                self.end_headers()
                self.wfile.write(b"ok")

        self.httpd = ThreadingHTTPServer(("127.0.0.1", 0), H)
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ctx.load_cert_chain(cert, key)
        self.httpd.socket = ctx.wrap_socket(self.httpd.socket, server_side=True)
        self.port = self.httpd.server_address[1]
        threading.Thread(target=self.httpd.serve_forever, daemon=True).start()

    def close(self):
        self.httpd.shutdown()


def test_device_certificate_is_pinned_and_a_swap_is_refused(tmp_path, monkeypatch):
    monkeypatch.setattr(devices_mod, "_this_pc", lambda host: False)  # stand in for a router on the LAN
    key, cert = _self_signed(tmp_path, "router")
    server = _Server(key, cert)
    store = DeviceStore(tmp_path / "devices.json")
    try:
        d = Device(name="router", kind="http", url=f"https://127.0.0.1:{server.port}/x", insecure_tls=True)
        pinned = store.add(d)
        assert pinned == fingerprint(cert.read_text())
        assert devices_mod.run(store.get("router"), None)["ok"]
    finally:
        server.close()
    # someone else answers on that address with a different certificate
    key2, cert2 = _self_signed(tmp_path, "impostor")
    impostor = _Server(key2, cert2)
    try:
        moved = store.get("router")
        moved.url = f"https://127.0.0.1:{impostor.port}/x"
        result = devices_mod.run(moved, None)
        assert not result["ok"] and "couldn't reach" in result["error"]
    finally:
        impostor.close()


def test_pinning_needs_https():
    with pytest.raises(devices_mod.DeviceError, match="https"):
        devices_mod.validate(Device(name="x", kind="http", url="http://10.0.0.1/", insecure_tls=True))


def test_bridge_without_a_pinned_certificate_is_refused():
    with pytest.raises(ssl.SSLError, match="pinned"):
        fetch_code(MailSettings(item="Mail bridge"), "me", "pw", {"example.com"})


def test_expired_pinned_certificate_still_works_and_resaving_keeps_the_pin(tmp_path, monkeypatch):
    """Home devices let their certificates expire; the pin is the exact certificate, so dates don't matter.
    Re-saving the action keeps that certificate instead of trusting whatever answers now."""
    monkeypatch.setattr(devices_mod, "_this_pc", lambda host: False)
    key, cert = _self_signed(tmp_path, "router", expired=True)
    server = _Server(key, cert)
    store = DeviceStore(tmp_path / "devices.json")
    try:
        url = f"https://127.0.0.1:{server.port}/x"
        first = store.add(Device(name="router", kind="http", url=url, insecure_tls=True))
        assert devices_mod.run(store.get("router"), None)["ok"]
    finally:
        server.close()
    key2, cert2 = _self_signed(tmp_path, "imposter")
    imposter = _Server(key2, cert2)  # a different certificate now answers...
    try:
        imposter_url = f"https://127.0.0.1:{imposter.port}/x"
        store._save([Device(name="router", kind="http", url=imposter_url, insecure_tls=True, tls_cert_pem=cert.read_text())])
        again = store.add(Device(name="router", kind="http", url=imposter_url, insecure_tls=True, description="edited"))
        assert again == first  # ...but re-saving kept the recorded certificate
        assert not devices_mod.run(store.get("router"), None)["ok"]
    finally:
        imposter.close()
