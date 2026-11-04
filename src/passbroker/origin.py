"""Origin binding: a login is only filled on the host it was saved for."""

from __future__ import annotations

from urllib.parse import urlsplit

LOCAL_HOSTS = {"localhost", "127.0.0.1", "::1"}


def _parse(url: str, saved: bool = False):
    """(scheme, host, port). A saved URL may omit its scheme; a page URL may not."""
    if saved and "://" not in url:
        url = "https://" + url
    parts = urlsplit(url)
    try:
        port = parts.port
    except ValueError:
        return parts.scheme.lower(), "", None
    host = (parts.hostname or "").lower().rstrip(".") if parts.netloc else ""
    return parts.scheme.lower(), host, port


def _bare(host: str) -> str:
    return host[4:] if host.startswith("www.") else host


def host_of(url: str) -> str:
    return _parse(url, saved=True)[1]


DEFAULT_PORTS = {"https": 443, "http": 80}


def origin_allowed(
    page_url: str,
    saved_urls: tuple[str, ...] | list[str],
    allow_http_localhost: bool = False,
    allow_subdomains: bool = False,
) -> bool:
    """True when the page is HTTPS on exactly a saved host (or its www. twin).

    Subdomains of a saved host only match with `allow_subdomains`, because
    many sites hand out subdomains to their users (tenant.atlassian.net,
    shop.myshopify.com). Ports must match, with the scheme's default when a
    URL doesn't name one. Plain HTTP is refused, except on localhost when
    explicitly allowed (for tests).
    """
    scheme, host, port = _parse(page_url)
    if not host:
        return False
    if scheme != "https" and not (allow_http_localhost and scheme == "http" and host in LOCAL_HOSTS):
        return False
    page = _bare(host)
    page_port = port or DEFAULT_PORTS.get(scheme)
    for saved in saved_urls:
        s_scheme, s_host, s_port = _parse(saved, saved=True)
        if not s_host:
            continue
        if (s_port or DEFAULT_PORTS.get(s_scheme, 443)) != page_port:
            continue
        s = _bare(s_host)
        if page == s or (allow_subdomains and page.endswith("." + s)):
            return True
    return False
