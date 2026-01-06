"""
ScanCapsule Persistence Layer (JSONL).

Implements the "Flight Recorder" pattern:
- Stream-based writing (Crash-Proof).
- Append-only log.
- Lazy Loading (Memory Efficient).
"""

import json
import os
from typing import List, Dict, Optional, Any, BinaryIO, Iterator, Generator, Type
from pathlib import Path
from dataclasses import asdict

from core.replay.models import MerkleBlock, CapsuleManifest, CAPSULE_VERSION

class CapsuleRecorder:
    """
    Writes Merkle Blocks to a .capsule (JSONL) file in real-time.
    Supports Context Manager protocol for ensured cleanup.
    """
    def __init__(self, path: Path):
        self.path = Path(path)
        self.file: Optional[BinaryIO] = None
        self._started = False

    def __enter__(self) -> 'CapsuleRecorder':
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.file = open(self.path, "wb")
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.close()

    def start(self, capsule_id: str, config: Dict[str, Any], 
             tool_versions: Dict[str, str], policy_digest: str, 
             model_identity: str):
        """
        Initialize the capsule file with the Manifest Header.
        """
        if self._started:
            return
        
        # Auto-open if not used as context manager
        if not self.file:
            self.path.parent.mkdir(parents=True, exist_ok=True)
            self.file = open(self.path, "wb")

        header = {
            "type": "manifest_header",
            "version": CAPSULE_VERSION,
            "capsule_id": capsule_id,
            "created_at": 0.0, # Filled by loader or system time
            "config": config,
            "tool_versions": tool_versions,
            "policy_digest": policy_digest,
            "model_identity": model_identity
        }
        self._write_line(header)
        self._started = True
        
    def write_block(self, block: MerkleBlock):
        """
        Append a MerkleBlock to the log.
        """
        if not self.file:
            raise RuntimeError("Recorder used before start() or context entry.")
            
        record = {
            "type": "block",
            "payload": {
                "id": block.id,
                "parents": block.parents,
                "kind": block.kind,
                "payload": block.payload,
                "meta": block.meta
            }
        }
        self._write_line(record)
        
    def close(self):
        """
        Close the recorder. Safe to call multiple times.
        """
        if self.file:
            self.file.flush()
            os.fsync(self.file.fileno())
            self.file.close()
            self.file = None

    def _write_line(self, data: Dict[str, Any]):
        """
        Serialize and write a line, forcing flush.
        """
        line = json.dumps(data) + "\n"
        self.file.write(line.encode("utf-8"))
        self.file.flush()


class CapsuleLoader:
    """
    Reads a .capsule (JSONL) file with memory-efficient streaming.
    """
    
    @staticmethod
    def load(path: Path) -> CapsuleManifest:
        """
        Eagerly load the entire manifest.
        Uses the generator internally to avoid duplicate logic.
        """
        iterator = CapsuleLoader.stream(path)
        blocks: List[MerkleBlock] = []
        
        # The first item yielded is the Manifest (with empty blocks), 
        # subsequent items are Blocks.
        try:
             # This is a bit of a mixed return type iterator pattern 
             # (Header -> Blocks...), but it's efficient.
             # Better design: stream_blocks() yields (header, block_iterator)
             pass
        except StopIteration:
            raise ValueError("Empty capsule file")
            
        # Re-implementing with a cleaner separation
        # We need the header to construct the Manifest wrapper
        # Then we fill it with blocks.
        
        with open(path, "rb") as f:
            # 1. Read Header
            first_line = f.readline()
            if not first_line:
                raise ValueError("Empty capsule file")
                
            try:
                header = json.loads(first_line)
            except json.JSONDecodeError:
                raise ValueError("Corrupt header")
                
            if header.get("type") != "manifest_header":
                raise ValueError("Invalid Header")
                
            # 2. Read Blocks
            for line in f:
                line = line.strip()
                if not line: continue
                
                try:
                    record = json.loads(line)
                except json.JSONDecodeError:
                    raise ValueError("Corrupt block line")
                    
                if record.get("type") == "block":
                    data = record["payload"]
                    blocks.append(MerkleBlock(
                        id=data["id"],
                        parents=data["parents"],
                        kind=data["kind"],
                        payload=data["payload"],
                        meta=data["meta"]
                    ))
                    
        return CapsuleManifest(
            version=header.get("version", "1.0"),
            capsule_id=header.get("capsule_id", "unknown"),
            created_at=header.get("created_at", 0.0),
            config=header.get("config", {}),
            tool_versions=header.get("tool_versions", {}),
            policy_digest=header.get("policy_digest", ""),
            model_identity=header.get("model_identity", ""),
            blocks=blocks,
            hash="", 
            redaction_report={}
        )

    @staticmethod
    def stream(path: Path) -> Generator[MerkleBlock, None, None]:
        """
        Yields blocks one by one. Useful for analyzing massive logs without
        loading the whole object graph.
        """
        with open(path, "rb") as f:
            for line in f:
                line = line.strip()
                if not line: continue
                
                try:
                    record = json.loads(line)
                except json.JSONDecodeError:
                    continue
                    
                if record.get("type") == "block":
                    data = record["payload"]
                    yield MerkleBlock(
                        id=data["id"],
                        parents=data["parents"],
                        kind=data["kind"],
                        payload=data["payload"],
                        meta=data["meta"]
                    )
