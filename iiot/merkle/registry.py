import json
import os
import re
import time
from pathlib import Path
from threading import RLock

try:
    from iiot.common.crypto import canonical, sha256_hex
except ImportError:
    from hashlib import sha256 as _sha

    def canonical(obj) -> bytes:
        return json.dumps(obj, sort_keys=True, separators=(",", ":")).encode()

    def sha256_hex(*parts: bytes) -> str:
        return _sha(b"".join(parts)).hexdigest()

_HEX = re.compile(r"[0-9a-f]{64}")
_ZERO = "0" * 64
_KEYS = {"index", "epoch", "root", "count", "ts", "prev_hash", "hash"}


def _block_hash(b: dict) -> str:
    return sha256_hex(canonical({k: v for k, v in b.items() if k != "hash"}))


class RootRegistry:
    def __init__(self, path=None):
        self._lock = RLock()
        self._path = Path(path) if path else None
        self._chain: list[dict] = []
        self._by_epoch: dict[int, str] = {}
        if self._path and self._path.exists():
            with open(self._path, "r", encoding="utf-8") as f:
                self._chain = json.load(f)
            if not self._chain_ok(self._chain):
                raise ValueError("registry file failed chain verification")
            self._reindex()
        else:
            g = {"index": 0, "epoch": 0, "root": _ZERO, "count": 0, "ts": 0.0, "prev_hash": _ZERO}
            g["hash"] = _block_hash(g)
            self._chain = [g]
            self._persist()

    def _reindex(self):
        self._by_epoch = {b["epoch"]: b["root"] for b in self._chain[1:]}

    @staticmethod
    def _chain_ok(chain) -> bool:
        try:
            if not isinstance(chain, list) or not chain:
                return False
            prev_hash, prev_epoch = _ZERO, -1
            for i, b in enumerate(chain):
                if not isinstance(b, dict) or set(b) != _KEYS or b["index"] != i:
                    return False
                if b["prev_hash"] != prev_hash or b["hash"] != _block_hash(b):
                    return False
                if not isinstance(b["epoch"], int) or b["epoch"] <= prev_epoch and i > 0:
                    return False
                prev_hash, prev_epoch = b["hash"], b["epoch"]
            return True
        except Exception:
            return False

    def _persist(self):
        if not self._path:
            return
        self._path.parent.mkdir(parents=True, exist_ok=True)
        tmp = self._path.with_name(self._path.name + ".tmp")
        with open(tmp, "w", encoding="utf-8") as f:
            json.dump(self._chain, f)
            f.flush()
            os.fsync(f.fileno())
        os.replace(tmp, self._path)

    def anchor(self, epoch: int, root: str, count: int) -> dict:
        if isinstance(epoch, bool) or not isinstance(epoch, int):
            raise ValueError("epoch must be int")
        if not isinstance(root, str) or not _HEX.fullmatch(root):
            raise ValueError("root must be 64 lowercase hex chars")
        if isinstance(count, bool) or not isinstance(count, int) or count < 0:
            raise ValueError("count must be a non-negative int")
        with self._lock:
            if epoch in self._by_epoch:
                raise ValueError(f"epoch {epoch} already anchored")
            if epoch <= self._chain[-1]["epoch"]:
                raise ValueError(f"epoch {epoch} not greater than latest {self._chain[-1]['epoch']}")
            b = {"index": len(self._chain), "epoch": epoch, "root": root, "count": count,
                 "ts": time.time(), "prev_hash": self._chain[-1]["hash"]}
            b["hash"] = _block_hash(b)
            self._chain.append(b)
            try:
                self._persist()
            except Exception:
                self._chain.pop()
                raise
            self._by_epoch[epoch] = root
            return dict(b)

    def get_root(self, epoch: int):
        with self._lock:
            return self._by_epoch.get(epoch)

    def latest_epoch(self) -> int:
        with self._lock:
            return self._chain[-1]["epoch"]

    def blocks(self) -> list[dict]:
        with self._lock:
            return [dict(b) for b in self._chain]

    def verify_chain(self) -> bool:
        with self._lock:
            return self._chain_ok(self._chain)
