"""Проверка доступности нод прямо с сервера, где запущен сервис (имеет смысл, если он в РФ)."""
from __future__ import annotations

import logging
import socket
import ssl
from concurrent.futures import ThreadPoolExecutor
from typing import Optional, Sequence

from ..config import ProbeSettings
from ..models import Node, ProbeTarget
from .base import ProbeResults, merge_port_verdicts

log = logging.getLogger(__name__)

# ТСПУ часто «замораживает» TLS-соединение с зарубежным IP после ~16 КБ
FREEZE_SUSPECT_LIMIT = 32 * 1024
DOWNLOAD_LIMIT = 64 * 1024
BROWSER_UA = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/130.0 Safari/537.36"


class LocalProber:
    source = "с этого сервера"

    def __init__(self, settings: ProbeSettings, max_workers: int = 16):
        self._settings = settings
        self._max_workers = max_workers

    def probe(self, nodes: Sequence[Node]) -> ProbeResults:
        if not self._control_reachable():
            return {}
        jobs = [(node, target) for node in nodes for target in node.probe_targets]
        with ThreadPoolExecutor(max_workers=self._max_workers) as pool:
            futures = [(node, target, pool.submit(self.check, node.address, target)) for node, target in jobs]
            return merge_port_verdicts((node.id, target.port, future.result()) for node, target, future in futures)

    def check(self, host: str, target: ProbeTarget) -> str:
        """Причина проблемы или "" если порт доступен."""
        try:
            sock = socket.create_connection((host, target.port), timeout=self._settings.timeout)
        except socket.timeout:
            return "TCP: таймаут (IP/порт заблокирован?)"
        except ConnectionRefusedError:
            return "TCP: соединение отклонено"
        except OSError as e:
            return f"TCP: {e.strerror or e}"

        if not target.sni:
            sock.close()
            return ""
        tls, error = self._handshake(sock, target.sni)
        if error:
            return error
        try:
            return self._download(tls, target.sni) if self._settings.freeze_check else ""
        finally:
            tls.close()

    def _control_reachable(self) -> bool:
        """Если недоступен даже контрольный хост — проблема в сети пробника, а не в нодах."""
        if not self._settings.control:
            return True
        host, _, port = self._settings.control.rpartition(":")
        error = self.check(host, ProbeTarget(int(port)))
        if error:
            log.warning("Контрольный хост %s недоступен (%s) — пропускаю проверку блокировок",
                        self._settings.control, error)
        return not error

    @staticmethod
    def _handshake(sock: socket.socket, sni: str):
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        try:
            return ctx.wrap_socket(sock, server_hostname=sni), None
        except socket.timeout:
            error = f"TLS ({sni}): нет ответа на ClientHello (блокировка по SNI?)"
        except ConnectionResetError:
            error = f"TLS ({sni}): сброс соединения (блокировка по SNI?)"
        except (ssl.SSLError, OSError) as e:
            error = f"TLS ({sni}): {e}"
        sock.close()
        return None, error

    @staticmethod
    def _download(tls: ssl.SSLSocket, sni: str) -> str:
        """Через Reality запрос проксируется на сайт-маскировку — качаем его страницу."""
        received = 0
        try:
            tls.sendall((f"GET / HTTP/1.1\r\nHost: {sni}\r\nUser-Agent: {BROWSER_UA}\r\n"
                         "Accept: */*\r\nConnection: close\r\n\r\n").encode())
            while received < DOWNLOAD_LIMIT:
                chunk = tls.recv(16384)
                if not chunk:
                    break
                received += len(chunk)
        except socket.timeout:
            if received == 0:
                return f"TLS ({sni}): рукопожатие прошло, но данные не идут"
            if received < FREEZE_SUSPECT_LIMIT:
                return f"TLS ({sni}): поток замер после {received // 1024} КБ (похоже на ограничение ТСПУ ~16 КБ)"
        except OSError as e:
            if received < FREEZE_SUSPECT_LIMIT:
                return f"TLS ({sni}): обрыв после {received // 1024} КБ: {e}"
        return ""
