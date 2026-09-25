"""Клиент API панели Remnawave и преобразование ответа в доменные модели."""
from __future__ import annotations

import json
import urllib.error
from typing import List, Protocol

from .config import PanelSettings
from .http import JsonHttpClient
from .models import Node, ProbeTarget

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
        headers = {
            "Authorization": f"Bearer {self._settings.token}",
            # Remnawave требует эти заголовки, если обращаться к бэкенду в обход reverse-proxy
            "X-Forwarded-For": "127.0.0.1",
            "X-Forwarded-Proto": "https",
        }
        try:
            data = self._http.get(f"{self._settings.api_base}/nodes", headers)
        except urllib.error.HTTPError as e:
            if e.code in (401, 403):
                raise PanelUnavailable(f"HTTP {e.code} — API-токен неверный или просрочен") from e
            raise PanelUnavailable(f"HTTP {e.code} {e.reason}") from e
        except urllib.error.URLError as e:
            raise PanelUnavailable(f"недоступна: {e.reason}") from e
        except TimeoutError as e:
            raise PanelUnavailable(f"нет ответа за {self._settings.timeout} сек") from e
        except json.JSONDecodeError as e:
            raise PanelUnavailable("ответ не JSON (заглушка прокси / страница ошибки?)") from e
        except OSError as e:
            raise PanelUnavailable(f"ошибка соединения: {e}") from e

        raw_nodes = data.get("response") if isinstance(data, dict) else data
        if not isinstance(raw_nodes, list):
            raise PanelUnavailable("неожиданный формат ответа /api/nodes")
        return [parse_node(raw) for raw in raw_nodes]


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
