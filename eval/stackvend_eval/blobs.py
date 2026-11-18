"""Content-addressed snapshot store for file trees (checkpoints, healer before/after snapshots)."""
from __future__ import annotations

import hashlib
import json
import threading
from pathlib import Path
from typing import Dict, Optional


def sha(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8", "surrogatepass")).hexdigest()


def tree_sha(tree: Dict[str, str]) -> str:
    return hashlib.sha256(json.dumps({k: sha(v) for k, v in sorted(tree.items())}, sort_keys=True).encode()).hexdigest()


class BlobStore:
    def __init__(self, root: Path):
        self.root = Path(root)
        (self.root / "blobs").mkdir(parents=True, exist_ok=True)
        (self.root / "trees").mkdir(parents=True, exist_ok=True)
        self._lock = threading.Lock()

    def put(self, text: str) -> str:
        h = sha(text)
        p = self.root / "blobs" / h[:2] / h
        if not p.exists():
            with self._lock:
                p.parent.mkdir(parents=True, exist_ok=True)
                tmp = p.with_suffix(".tmp")
                tmp.write_text(text, encoding="utf-8", errors="surrogatepass")
                tmp.replace(p)
        return h

    def get(self, h: str) -> str:
        return (self.root / "blobs" / h[:2] / h).read_text(encoding="utf-8", errors="surrogatepass")

    def put_tree(self, tree: Dict[str, str]) -> str:
        manifest = {k: self.put(v) for k, v in sorted(tree.items()) if isinstance(v, str)}
        th = hashlib.sha256(json.dumps(manifest, sort_keys=True).encode()).hexdigest()
        p = self.root / "trees" / f"{th}.json"
        if not p.exists():
            p.write_text(json.dumps(manifest, sort_keys=True))
        return th

    def get_tree(self, th: str) -> Dict[str, str]:
        manifest = json.loads((self.root / "trees" / f"{th}.json").read_text())
        return {k: self.get(h) for k, h in manifest.items()}

    def tree_manifest(self, th: str) -> Optional[Dict[str, str]]:
        p = self.root / "trees" / f"{th}.json"
        return json.loads(p.read_text()) if p.exists() else None
