"""Тонкий JSON-клиент поверх urllib."""
from __future__ import annotations

import json
import urllib.request
from typing import Any, Optional

# без своего User-Agent часть API (например check-host.net) отвечает 403
USER_AGENT = "node-checker/2.0"


class JsonHttpClient:
    def __init__(self, timeout: int, user_agent: str = USER_AGENT):
        self._timeout = timeout
        self._user_agent = user_agent

    def get(self, url: str, headers: Optional[dict] = None) -> Any:
        return self.request("GET", url, headers)

    def post(self, url: str, body: Any, headers: Optional[dict] = None) -> Any:
        return self.request("POST", url, headers, body)

    def request(self, method: str, url: str, headers: Optional[dict] = None, body: Any = None) -> Any:
        all_headers = {"User-Agent": self._user_agent, "Accept": "application/json", **(headers or {})}
        data = None
        if body is not None:
            data = json.dumps(body).encode()
            all_headers["Content-Type"] = "application/json"
        req = urllib.request.Request(url, data=data, method=method, headers=all_headers)
        with urllib.request.urlopen(req, timeout=self._timeout) as resp:
            raw = resp.read()
        return json.loads(raw) if raw else None
