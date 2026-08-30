from urllib.parse import urlparse
import ipaddress
import socket


def is_safe_url(url: str) -> bool:
    """
    Kaynak URL'sinin güvenli olup olmadığını kontrol eder.

    Engellenenler:
    - http/https dışındaki protokoller
    - localhost
    - 127.0.0.1 ve diğer loopback adresleri
    - private IP adresleri
    - link-local / metadata adresleri
    - geçersiz URL'ler
    """

    try:
        parsed = urlparse(url)

        # ----------------------------------------------------
        # PROTOKOL KONTROLÜ
        # ----------------------------------------------------

        if parsed.scheme.lower() not in ("http", "https"):
            return False

        # ----------------------------------------------------
        # HOST KONTROLÜ
        # ----------------------------------------------------

        hostname = parsed.hostname

        if not hostname:
            return False

        hostname = hostname.lower()

        # ----------------------------------------------------
        # LOCALHOST KONTROLÜ
        # ----------------------------------------------------

        if hostname == "localhost":
            return False

        if hostname.endswith(".localhost"):
            return False

        # ----------------------------------------------------
        # DOĞRUDAN IP KONTROLÜ
        # ----------------------------------------------------

        try:

            ip = ipaddress.ip_address(hostname)

            if (
                ip.is_private
                or ip.is_loopback
                or ip.is_link_local
                or ip.is_multicast
                or ip.is_reserved
                or ip.is_unspecified
            ):
                return False

            return True

        except ValueError:
            pass

        # ----------------------------------------------------
        # DOMAIN'İN IP ADRESLERİNİ KONTROL ET
        # ----------------------------------------------------

        try:

            addresses = socket.getaddrinfo(
                hostname,
                None
            )

            for address in addresses:

                ip_string = address[4][0]

                try:

                    ip = ipaddress.ip_address(
                        ip_string
                    )

                    if (
                        ip.is_private
                        or ip.is_loopback
                        or ip.is_link_local
                        or ip.is_multicast
                        or ip.is_reserved
                        or ip.is_unspecified
                    ):
                        return False

                except ValueError:
                    return False

        except socket.gaierror:
            return False

        # ----------------------------------------------------
        # GÜVENLİ
        # ----------------------------------------------------

        return True

    except Exception:
        return False