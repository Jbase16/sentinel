# core/evidence.py — Evidence storage & artifact recorder

from __future__ import annotations

import os
from datetime import datetime


class EvidenceStore:

    def __init__(self):
        self.base = os.path.expanduser("~/AraUltra_Evidence")
        os.makedirs(self.base, exist_ok=True)

    # ------------------------------------------------------------------
    def save_text(self, tool: str, target: str, content: str) -> str:
        """Save raw recon/scanner output."""
        folder = os.path.join(self.base, tool)
        os.makedirs(folder, exist_ok=True)

        stamp = datetime.now().strftime("%Y%m%d-%H%M%S")
        safe_target = self._sanitize(target)
        path = os.path.join(folder, f"{safe_target}_{stamp}.txt")

        with open(path, "w") as f:
            f.write(content)

        return path

    # ------------------------------------------------------------------
    def save_json(self, tool: str, target: str, data) -> str:
        """Save structured evidence."""
        import json

        folder = os.path.join(self.base, tool)
        os.makedirs(folder, exist_ok=True)

        stamp = datetime.now().strftime("%Y%m%d-%H%M%S")
        safe_target = self._sanitize(target)
        path = os.path.join(folder, f"{safe_target}_{stamp}.json")

        with open(path, "w") as f:
            json.dump(data, f, indent=2)

        return path

    # ------------------------------------------------------------------
    def save_binary(self, tool: str, target: str, content: bytes, ext=".bin") -> str:
        """Save binary artifacts (screenshots, certs, packets)."""
        folder = os.path.join(self.base, tool)
        os.makedirs(folder, exist_ok=True)

        stamp = datetime.now().strftime("%Y%m%d-%H%M%S")
        safe_target = self._sanitize(target)
        path = os.path.join(folder, f"{safe_target}_{stamp}{ext}")

        with open(path, "wb") as f:
            f.write(content)

        return path

    def _sanitize(self, text: str) -> str:
        safe = text.replace('://', '_').replace('/', '_').replace('\\', '_')
        return "".join(c for c in safe if c.isalnum() or c in ('_', '-', '.'))


# Global instance
evidence_store = EvidenceStore()
