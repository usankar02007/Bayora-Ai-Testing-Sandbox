import ipaddress
import logging
import socket
from urllib.parse import urlparse
import httpx

from config import TINYFISH_API_KEY, TINYFISH_URL

logger = logging.getLogger("bayora.tinyfish")

# Prohibited CIDR ranges for SSRF mitigation
PROHIBITED_NETWORKS = [
    ipaddress.ip_network("0.0.0.0/8"),
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("127.0.0.0/8"),
    ipaddress.ip_network("169.254.0.0/16"),  # Link-local & cloud metadata
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
    ipaddress.ip_network("::1/128"),
    ipaddress.ip_network("fc00::/7"),
    ipaddress.ip_network("fe80::/10"),
]


def validate_url_against_ssrf(target_url: str) -> None:
    """
    Strict SSRF validation:
    1. Verifies HTTPS scheme.
    2. Resolves DNS hostname to IP addresses.
    3. Blocks loopback, private RFC1918, link-local, and cloud metadata (169.254.169.254).
    """
    if not target_url.startswith("https://"):
        raise ValueError("SSRF Defense: Only secure HTTPS URLs are permitted.")

    parsed = urlparse(target_url)
    hostname = parsed.hostname

    if not hostname:
        raise ValueError("SSRF Defense: Invalid URL hostname.")

    # Disallow known internal names
    blocked_hostnames = {
        "localhost",
        "127.0.0.1",
        "0.0.0.0",
        "metadata.google.internal",
        "instance-data",
    }
    if hostname.lower() in blocked_hostnames:
        raise ValueError(f"SSRF Defense: Destination hostname '{hostname}' is prohibited.")

    # Resolve hostname to all associated IPs to prevent DNS rebinding
    try:
        addr_info = socket.getaddrinfo(hostname, 443, proto=socket.IPPROTO_TCP)
    except socket.gaierror as exc:
        raise ValueError(f"SSRF Defense: Unable to resolve hostname '{hostname}': {exc}") from exc

    for entry in addr_info:
        ip_str = entry[4][0]
        try:
            ip_obj = ipaddress.ip_address(ip_str)
            for net in PROHIBITED_NETWORKS:
                if ip_obj in net:
                    raise ValueError(
                        f"SSRF Defense: Destination IP '{ip_str}' is within prohibited range '{net}'."
                    )
        except ValueError as exc:
            if "prohibited range" in str(exc):
                raise
            raise ValueError(f"SSRF Defense: Invalid IP address resolved: {ip_str}") from exc


async def run_tinyfish_agent(url: str, goal: str):
    """
    Sends an authorized browser automation task to TinyFish after SSRF validation.
    """
    if not TINYFISH_API_KEY:
        raise RuntimeError("TinyFish API key is not configured on the backend.")

    # Enforce strict SSRF protection
    validate_url_against_ssrf(url)

    headers = {
        "X-API-Key": TINYFISH_API_KEY,
        "Content-Type": "application/json",
    }

    payload = {
        "url": url,
        "goal": goal,
    }

    async with httpx.AsyncClient(timeout=60.0) as client:
        response = await client.post(
            TINYFISH_URL,
            headers=headers,
            json=payload,
        )

    if response.is_error:
        raise RuntimeError(
            f"TinyFish returned HTTP {response.status_code}: {response.text[:200]}"
        )

    return response.json()