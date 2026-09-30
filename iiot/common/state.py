from __future__ import annotations

import threading
from dataclasses import dataclass, field
from typing import Any, Optional

from iiot.common.crypto import gen_keypair
from iiot.common.models import DeviceRecord, EpochRecord, Session


@dataclass
class FogConfig:
    psk: bytes
    admin_key: str
    token_ttl_s: int = 60
    challenge_ttl_s: int = 30
    ts_skew_s: int = 30
    registry_path: Optional[str] = None


@dataclass
class FogState:
    config: FogConfig
    fog_sk: Any
    fog_pk: str
    registry: Any
    lock: threading.RLock = field(default_factory=threading.RLock)
    sessions: dict[str, Session] = field(default_factory=dict)
    devices: dict[str, DeviceRecord] = field(default_factory=dict)
    pending: list[str] = field(default_factory=list)
    epochs: dict[int, EpochRecord] = field(default_factory=dict)
    current_epoch: int = 0
    revoked_dids: set[str] = field(default_factory=set)
    revoked_token_ids: set[str] = field(default_factory=set)
    issued_tokens: dict[str, str] = field(default_factory=dict)
    used_nonces: dict[str, float] = field(default_factory=dict)


def new_state(config: FogConfig) -> FogState:
    from iiot.merkle.registry import RootRegistry

    sk, pk = gen_keypair()
    return FogState(config=config, fog_sk=sk, fog_pk=pk, registry=RootRegistry(config.registry_path))
