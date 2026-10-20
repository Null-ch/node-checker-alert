"""Клиент API панели Remnawave и преобразование ответа в доменные модели."""
from __future__ import annotations

import dataclasses
import json
import logging
import urllib.error
from typing import List, Protocol

from .config import PanelSettings
from .http import JsonHttpClient
from .models import Node, ProbeTarget

log = logging.getLogger(__name__)

CASCADE_OUT_PREFIX = "CASCADE_OUT_"   # outbound'ы вход -> выход, которые создаёт node-creator/cascade.py
UDP_INBOUND_TYPES = {"hysteria", "hysteria2", "wireguard", "tuic"}
UDP_NETWORKS = {"udp", "kcp", "quic"}


class PanelUnavailable(Exception):
    pass


class PanelClient(Protocol):
    def get_nodes(self) -> List[Node]: ...


class RemnawaveClient:
    def __init__(self, settings: PanelSettings, http: JsonHttpClient):
        self._settings = settings
        self._http = http

    def get_nodes(self) -> List[Node]:
        try:
            data = self._get("/nodes")
        except json.JSONDecodeError as e:
            raise PanelUnavailable("ответ не JSON (заглушка прокси / страница ошибки?)") from e
        raw_nodes = _unwrap(data)
        if not isinstance(raw_nodes, list):
            raise PanelUnavailable("неожиданный формат ответа /api/nodes")
        nodes = [parse_node(raw) for raw in raw_nodes]

        exits = self._cascade_exit_addresses(raw_nodes)
        return [dataclasses.replace(n, is_cascade_exit=True) if n.address in exits else n for n in nodes]

    def _cascade_exit_addresses(self, raw_nodes: list) -> set:
        """Адреса выходных нод каскадов из профилей, назначенных нодам. Ошибка не роняет основную проверку."""
        try:
            data = _unwrap(self._get("/config-profiles"))
        except (PanelUnavailable, ValueError) as e:
            log.warning("Профили конфигурации (поиск каскадов): %s", e)
            return set()
        profiles = data.get("configProfiles") if isinstance(data, dict) else data
        active = {(raw.get("configProfile") or {}).get("activeConfigProfileUuid") for raw in raw_nodes}
        return cascade_exit_addresses([p for p in profiles or [] if p.get("uuid") in active])

    def _get(self, path: str):
        headers = {
            "Authorization": f"Bearer {self._settings.token}",
            # Remnawave требует эти заголовки, если обращаться к бэкенду в обход reverse-proxy
            "X-Forwarded-For": "127.0.0.1",
            "X-Forwarded-Proto": "https",
        }
        try:
            return self._http.get(f"{self._settings.api_base}{path}", headers)
        except urllib.error.HTTPError as e:
            if e.code in (401, 403):
                raise PanelUnavailable(f"HTTP {e.code} — API-токен неверный или просрочен") from e
            raise PanelUnavailable(f"HTTP {e.code} {e.reason}") from e
        except urllib.error.URLError as e:
            raise PanelUnavailable(f"недоступна: {e.reason}") from e
        except TimeoutError as e:
            raise PanelUnavailable(f"нет ответа за {self._settings.timeout} сек") from e
        except OSError as e:
            raise PanelUnavailable(f"ошибка соединения: {e}") from e


def _unwrap(data):
    return data.get("response") if isinstance(data, dict) and "response" in data else data


def cascade_exit_addresses(profiles: list) -> set:
    """Адреса, на которые смотрят outbound'ы CASCADE_OUT_* (vless: vnext[].address, hysteria: settings.address)."""
    addresses = set()
    for profile in profiles:
        for outbound in (profile.get("config") or {}).get("outbounds") or []:
            if not str(outbound.get("tag", "")).startswith(CASCADE_OUT_PREFIX):
                continue
            settings = outbound.get("settings") or {}
            servers = settings.get("vnext") or settings.get("servers") or [settings]
            addresses.update(s.get("address") for s in servers if s.get("address"))
    return addresses


def parse_node(raw: dict) -> Node:
    return Node(
        id=str(raw.get("uuid") or raw.get("name")),
        name=raw.get("name") or raw.get("uuid") or "?",
        address=raw.get("address") or "",
        country=(raw.get("countryCode") or "").upper(),
        is_disabled=bool(raw.get("isDisabled")),
        is_connected=raw.get("isConnected", True) is not False,
        is_node_online=raw.get("isNodeOnline"),
        is_xray_running=raw.get("isXrayRunning"),
        last_status_message=(raw.get("lastStatusMessage") or "").strip(),
        probe_targets=parse_probe_targets(raw),
    )


def parse_probe_targets(raw: dict) -> tuple:
    """TCP-порты активных инбаундов ноды (+ SNI для reality/tls)."""
    targets = {}
    inbounds = (raw.get("configProfile") or {}).get("activeInbounds") or []
    for inbound in inbounds:
        port = inbound.get("port")
        raw_inbound = inbound.get("rawInbound") or {}
        if (not port or inbound.get("type") in UDP_INBOUND_TYPES or inbound.get("network") in UDP_NETWORKS
                or not _listens_publicly(raw_inbound.get("listen"))):
            continue
        stream = raw_inbound.get("streamSettings") or {}
        sni = ""
        if stream.get("security") == "reality":
            sni = ((stream.get("realitySettings") or {}).get("serverNames") or [""])[0]
        elif stream.get("security") == "tls":
            sni = (stream.get("tlsSettings") or {}).get("serverName") or ""
        targets.setdefault(int(port), ProbeTarget(int(port), sni))
    return tuple(targets.values())


def _listens_publicly(listen) -> bool:
    """Инбаунды на loopback / unix-сокете (например, за CDN или nginx) снаружи недоступны by design."""
    if not listen:
        return True
    listen = str(listen)
    return not (listen.startswith(("127.", "@", "/")) or listen in ("::1", "localhost"))
