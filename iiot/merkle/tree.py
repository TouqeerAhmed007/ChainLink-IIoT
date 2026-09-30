import hmac
import re
from hashlib import sha256

_HEX = re.compile(r"[0-9a-f]{64}")
_PFX = b"\x01"


def _node(left: bytes, right: bytes) -> bytes:
    return sha256(_PFX + left + right).digest()


def _ok(x) -> bool:
    return isinstance(x, str) and _HEX.fullmatch(x) is not None


class MerkleTree:
    def __init__(self, sorted_leaves: list[str]):
        self.leaves = list(sorted_leaves)
        self._index = {h: i for i, h in enumerate(self.leaves)}
        level = [bytes.fromhex(x) for x in self.leaves]
        levels = []
        while len(level) > 1:
            if len(level) & 1:
                level.append(level[-1])
            levels.append(level)
            level = [_node(level[i], level[i + 1]) for i in range(0, len(level), 2)]
        levels.append(level)
        self._levels = levels

    @property
    def root(self) -> str:
        return self._levels[-1][0].hex()

    def proof(self, leaf: str) -> list[dict]:
        i = self._index.get(leaf)
        if i is None:
            raise KeyError(leaf)
        steps = []
        for lvl in self._levels[:-1]:
            steps.append({"hash": lvl[i ^ 1].hex(), "side": "right" if i % 2 == 0 else "left"})
            i >>= 1
        return steps

    def all_proofs(self) -> dict[str, list[dict]]:
        hexes = [[b.hex() for b in lvl] for lvl in self._levels[:-1]]
        depth = len(hexes)
        out = {}
        for i, leaf in enumerate(self.leaves):
            out[leaf] = [
                {"hash": hexes[k][(i >> k) ^ 1], "side": "right" if ((i >> k) & 1) == 0 else "left"}
                for k in range(depth)
            ]
        return out


def build_tree(leaves: list[str]) -> MerkleTree:
    leaves = list(leaves)
    if not leaves:
        raise ValueError("cannot build a Merkle tree from zero leaves")
    for x in leaves:
        if not _ok(x):
            raise ValueError(f"invalid leaf: {x!r}")
    return MerkleTree(sorted(set(leaves)))


def compute_root(leaves: list[str]) -> str:
    return build_tree(leaves).root


def verify_proof(leaf: str, proof: list, root: str) -> bool:
    try:
        if not (_ok(leaf) and _ok(root) and isinstance(proof, (list, tuple))):
            return False
        cur = bytes.fromhex(leaf)
        for s in proof:
            if not isinstance(s, dict):
                return False
            h, side = s.get("hash"), s.get("side")
            if not _ok(h):
                return False
            sib = bytes.fromhex(h)
            if side == "left":
                cur = _node(sib, cur)
            elif side == "right":
                cur = _node(cur, sib)
            else:
                return False
        return hmac.compare_digest(cur.hex(), root)
    except Exception:
        return False
