from __future__ import annotations

from typing import Optional

from ..config import ProbeSettings
from ..http import JsonHttpClient
from .base import Prober, ProbeResults
from .checkhost import CheckHostClient, CheckHostProber
from .local import LocalProber

__all__ = ["Prober", "ProbeResults", "LocalProber", "CheckHostProber", "create_prober"]


def create_prober(settings: ProbeSettings, http: JsonHttpClient) -> Optional[Prober]:
    if settings.mode == "local":
        return LocalProber(settings)
    if settings.mode == "checkhost":
        return CheckHostProber(settings, CheckHostClient(http))
    return None
