# core/scanner_engine.py — macOS-compatible active scanner engine
from __future__ import annotations

import asyncio
import logging
import os
from urllib.parse import urlparse
from typing import AsyncGenerator, Dict, List

from core.findings import findings_store
from core.evidence_store import EvidenceStore
from core.cortex.scanner_bridge import ScannerBridge
from core.vuln_rules import apply_rules
from core.issues_store import issues_store
from core.killchain_store import killchain_store
from core.runner import PhaseRunner
from core.tools import TOOLS, get_tool_command, get_installed_tools
from core.task_router import TaskRouter

logger = logging.getLogger(__name__)

# Try to import psutil for resource awareness
try:
    import psutil
    HAS_PSUTIL = True
except ImportError:
    HAS_PSUTIL = False

# Configurable concurrency limit based on system resources
MIN_CONCURRENT_TOOLS = 1
MAX_CONCURRENT_TOOLS_BASE = 10  # Base value for small systems

def calculate_concurrent_limit() -> int:
    """Calculate optimal concurrency based on available system resources."""
    try:
        cpu_count = os.cpu_count() or 2
        
        # Get available memory in GB if psutil is available
        if HAS_PSUTIL:
            memory_info = psutil.virtual_memory()
            available_memory_gb = memory_info.available / (1024**3)
            
            # Calculate limit based on resources
            # Use 1 tool per 2GB of available RAM, up to CPU count
            memory_based = max(1, int(available_memory_gb / 2))
            cpu_based = max(1, cpu_count // 2)
            
            # Use the smaller of the two to avoid overload
            calculated = min(memory_based, cpu_based)
            
            # Ensure at least the minimum and not too high
            return max(MIN_CONCURRENT_TOOLS, min(calculated, MAX_CONCURRENT_TOOLS_BASE * 2))
        else:
            # Fallback when psutil is not available: use CPU count with cap
            return max(MIN_CONCURRENT_TOOLS, min(cpu_count // 2, MAX_CONCURRENT_TOOLS_BASE * 2))
    except Exception:
        # Ultimate fallback if detection fails
        return MAX_CONCURRENT_TOOLS_BASE

# Calculate actual limit at module load
MAX_CONCURRENT_TOOLS = calculate_concurrent_limit()


class ScannerEngine:
    """Runs supported scanning tools on macOS (no unsupported tool errors)."""

    def __init__(self, session=None):
        """
        Args:
            session: Optional ScanSession. If None, uses legacy global behavior or temp state.
        """
        self.session = session
        self._last_results: List[dict] = []
        self._fingerprint_cache: set[str] = set()
        self._installed_meta: Dict[str, Dict[str, object]] = {}
        self._recon_edges: List[dict] = []
        self._recon_edge_keys: set[tuple] = set()
        
        # Task management state
        self._pending_tasks = []
        self._running_tasks = {}
        self._queue = asyncio.Queue()
        self._results_map = {}
        self._procs = {}

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------
    async def scan(self, target: str, selected_tools: List[str] | None = None, cancel_flag=None) -> AsyncGenerator[str, None]:
        """
        Async generator that yields log-style strings while the supported tools run.
        """
        installed = self._detect_installed()
        self._installed_meta = installed
        
        # Reset state for this run
        self._last_results = []
        self._recon_edges = []
        self._procs = {}
        self._pending_tasks = []
        
        selected_clean = [t for t in (selected_tools or []) if t in TOOLS]
        # ... logic continues ...
        tools_to_run = list(installed.keys())
        missing: List[str] = []
        if selected_clean:
            tools_to_run = [t for t in selected_clean if t in installed]
            missing = [t for t in selected_clean if t not in installed]
        if selected_clean:
            yield f"[scanner] Selected tools: {', '.join(selected_clean)}"
        if missing:
            msg = f"[scanner] ⚠️ WARNING: The following tools were requested but NOT found in PATH: {', '.join(missing)}"
            yield msg
            # Also log to console for debugging
            print(msg)
            print(f"[scanner] Current PATH: {os.environ.get('PATH')}")

        if not tools_to_run:
            yield "[scanner] No supported tools available in PATH. Skipping tool phase."
            return
        else:
            yield f"Installed tools: {', '.join(tools_to_run)}"
            queue: asyncio.Queue[str] = asyncio.Queue()
            running: Dict[str, asyncio.Task[List[dict]]] = {}
            pending = list(tools_to_run)
            results_map: Dict[str, List[dict] | Exception] = {}

            # Expose queue for dynamic additions
            self._pending_tasks = pending
            self._running_tasks = running
            self._queue = queue
            self._results_map = results_map

            # FIXED: Wait for ALL tasks to complete, not just until slots fill
            while self._pending_tasks or self._running_tasks:
                # Fill available slots
                # Check for cancellation before launching new tasks
                if cancel_flag is not None and cancel_flag.is_set():
                    await self._queue.put("[scanner] cancellation requested; stopping new tasks")
                    self._pending_tasks.clear()
                    break

                while self._pending_tasks and len(self._running_tasks) < MAX_CONCURRENT_TOOLS:
                    task_def = self._pending_tasks.pop(0)
                    # Handle both simple strings (legacy) and dicts (dynamic args)
                    if isinstance(task_def, str):
                         tool = task_def
                         args = None
                    else:
                         tool = task_def["tool"]
                         args = task_def.get("args")

                    self._running_tasks[tool] = asyncio.create_task(
                        self._run_tool_task(tool, target, self._queue, args, cancel_flag)
                    )
                    await self._queue.put(f"[scanner] Started {tool} (dynamic launch)")

                if not self._running_tasks:
                     break

                done, _ = await asyncio.wait(list(self._running_tasks.values()), timeout=0.2)
                while not self._queue.empty():
                    yield self._queue.get_nowait()

                for finished in done:
                    tool_name = next((name for name, t in self._running_tasks.items() if t is finished), None)
                    if tool_name:
                        try:
                            self._results_map[tool_name] = finished.result()
                        except Exception as exc: # pragma: no cover
                            self._results_map[tool_name] = exc
                            await self._queue.put(f"[{tool_name}] task error: {exc}")
                        del self._running_tasks[tool_name]
                
                if not done:
                    # If cancellation was requested mid-run, try to wait for running tasks to finish.
                    if cancel_flag is not None and cancel_flag.is_set():
                        # Best-effort: terminate running subprocesses and wait for tasks to notice.
                        await self._queue.put("[scanner]Cancellation detected - terminating running tools...")
                        for name, proc in list(self._procs.items()):
                            if proc.returncode is None:
                                try:
                                    proc.terminate()
                                    await self._queue.put(f"[{name}] terminated due to cancellation")
                                except ProcessLookupError:
                                    pass
                        
                        # Give subprocesses a moment to terminate
                        await asyncio.sleep(0.2)
                        
                        # Force kill any stubborn processes
                        for name, proc in list(self._procs.items()):
                            if proc.returncode is None:
                                try:
                                    proc.kill()
                                    await self._queue.put(f"[{name}] force-killed after termination timeout")
                                except ProcessLookupError:
                                    pass
                        
                        await self._queue.put("[scanner] All tools terminated due to cancellation")
            
            
            while not self._queue.empty():
                yield self._queue.get_nowait()
            
            # CRITICAL FIX: Aggregate all findings from tool results
            all_findings: List[dict] = []
            for tool_name, result in self._results_map.items():
                if isinstance(result, list):
                    all_findings.extend(result)
            
            # Normalize and deduplicate findings
            normalized = self._normalize_findings(all_findings)
            self._last_results = normalized
            
            # CRITICAL: Populate findings store (Session-Scoped or Global)
            if self.session:
                self.session.findings.bulk_add(normalized)
            else:
                # Fallback for legacy calls
                findings_store.bulk_add(normalized)
            
            # Build recon edges and update stores
            recon_edges = self._build_recon_edges(normalized)
            self._record_recon_edges(recon_edges)
            enriched_count, edge_count = self._refresh_enrichment()
            
            yield f"[scanner] Processed {len(normalized)} findings, {enriched_count} issues, {edge_count} killchain edges"


    def queue_task(self, tool: str, args: List[str] = None):
        """
        Dynamically add a task to the running scan.
        """
        if hasattr(self, "_pending_tasks"):
            self._pending_tasks.append({"tool": tool, "args": args})

    async def run_all(self, target: str):
        """
        Compatibility helper: run the scan generator and return aggregated findings.
        """
        async for _ in self.scan(target):
            # Discard streamed lines – this helper mirrors the old API surface.
            pass
        return list(self._last_results)

    # ----------------------------------------------------------------------
    # Helpers
    # ----------------------------------------------------------------------
    def _detect_installed(self) -> Dict[str, Dict[str, object]]:
        return get_installed_tools()

    def _normalize_findings(self, items: List[dict] | None) -> List[dict]:
        normalized: List[dict] = []
        if not items:
            return normalized

        for item in items:
            entry = dict(item)
            entry.setdefault("message", entry.get("proof", ""))
            entry.setdefault("tags", [])
            entry.setdefault("families", [])
            entry.setdefault("metadata", {})
            severity = str(entry.get("severity", "INFO")).upper()
            entry["severity"] = severity
            original_target = entry.get("target") or entry.get("asset") or "unknown"
            asset = self._normalize_asset(original_target)
            entry.setdefault("metadata", {})
            entry["metadata"].setdefault("original_target", original_target)
            entry["asset"] = asset
            entry["target"] = asset
            fingerprint = entry.setdefault(
                "fingerprint",
                f"{entry.get('tool', 'scanner')}:{asset}:{entry.get('type', 'generic')}:{severity}"
            )
            if fingerprint in self._fingerprint_cache:
                continue
            self._fingerprint_cache.add(fingerprint)
            normalized.append(entry)
        return normalized

    def get_last_results(self) -> List[dict]:
        """Return the findings produced by the most recent scan."""
        return list(self._last_results)

    def _build_recon_edges(self, findings: List[dict]) -> List[dict]:
        edges: List[dict] = []
        for item in findings:
            families = item.get("families", [])
            recon_families = [fam for fam in families if fam.startswith("recon-phase")]
            if not recon_families:
                continue
            metadata = item.get("metadata") or {}
            variant = metadata.get("variant") or "behavior"
            for fam in recon_families:
                edges.append({
                    "source": item.get("asset", "unknown"),
                    "target": f"{fam}:{variant}",
                    "label": item.get("type"),
                    "severity": item.get("severity"),
                    "tags": item.get("tags", []),
                    "signal": item.get("message"),
                    "families": families,
                    "edge_type": "behavioral-signal",
                })
        return edges

    def _record_recon_edges(self, edges: List[dict]):
        for edge in edges:
            key = self._edge_signature(edge)
            if key in self._recon_edge_keys:
                continue
            self._recon_edge_keys.add(key)
            self._recon_edges.append(edge)

    def _edge_signature(self, edge: dict) -> tuple:
        return (
            edge.get("source"),
            edge.get("target"),
            edge.get("label"),
            edge.get("edge_type"),
            edge.get("severity"),
        )

    def _refresh_enrichment(self) -> tuple[int, int]:
        if self._last_results:
            enriched, _, killchain_edges = apply_rules(self._last_results)
        else:
            enriched, killchain_edges = [], []

        # Use session-scoped stores when available; fallback to global singletons
        if self.session:
            self.session.issues.replace_all(enriched)
            combined_edges = list(killchain_edges) + list(self._recon_edges)
            self.session.killchain.replace_all(combined_edges)
        else:
            issues_store.replace_all(enriched)
            combined_edges = list(killchain_edges) + list(self._recon_edges)
            killchain_store.replace_all(combined_edges)
        return len(enriched), len(combined_edges)

    async def _run_tool_task(
        self,
        tool: str,
        target: str,
        queue: asyncio.Queue[str],
        custom_args: List[str] = None,
        cancel_flag=None,
    ) -> List[dict]:
        meta_override = self._installed_meta.get(tool)
        
        if custom_args:
            # Use custom args directly if provided (for autonomous actions)
            cmd = [tool] + custom_args
            # Replace {target} placeholder if present in custom args
            cmd = [arg.replace("{target}", target) for arg in cmd]
        else:
            cmd = get_tool_command(tool, target, meta_override)
            
        await queue.put(f"--- Running {tool} ---")
        try:
            proc = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.STDOUT,
            )
            # Track proc so cancellation can terminate it.
            self._procs[tool] = proc
        except FileNotFoundError:
            msg = f"[{tool}] NOT INSTALLED or not in PATH."
            # Use session-scoped evidence store if available, otherwise global singleton
            evidence_store = self.session.evidence if self.session else EvidenceStore.instance()
            evidence_store.add_evidence(tool, msg, {"target": target, "error": "not_found"})
            await queue.put(msg)
            return []
        except Exception as exc:
            msg = f"[{tool}] failed to start: {exc}"
            evidence_store = self.session.evidence if self.session else EvidenceStore.instance()
            evidence_store.add_evidence(tool, msg, {"target": target, "error": str(exc)})
            await queue.put(msg)
            return []

        output_lines: List[str] = []
        assert proc.stdout is not None
        while True:
            if cancel_flag is not None and cancel_flag.is_set():
                # Stop reading further; process may be terminated by caller.
                break
            line = await proc.stdout.readline()
            if not line:
                break
            text = line.decode("utf-8", errors="ignore").rstrip()
            if not text:
                continue
            output_lines.append(text)
            await queue.put(f"[{tool}] {text}")

        exit_code = await proc.wait()
        await queue.put(f"[{tool}] Exit code: {exit_code}")
        # Cleanup tracked proc
        self._procs.pop(tool, None)

        output_text = "\n".join(output_lines)
        # Use session-scoped evidence store if available, otherwise global singleton
        evidence_store = self.session.evidence if self.session else EvidenceStore.instance()
        evidence_store.add_evidence(tool, output_text, {
            "target": target,
            "exit_code": exit_code,
            "lines": len(output_lines)
        })

        try:
            findings = ScannerBridge.classify(tool, target, output_text)
            
            # CRITICAL: Wire tool output to TaskRouter for AI analysis and event emission
            # This triggers AI analysis, findings_update events, and autonomous next steps
            try:
                router = TaskRouter.instance()
                router.handle_tool_output(
                    tool_name=tool,
                    stdout=output_text,
                    stderr="",
                    rc=exit_code,
                    metadata={"target": target, "findings_count": len(findings)}
                )
            except Exception as router_err:
                logger.warning(f"[{tool}] TaskRouter processing error: {router_err}")
            
            return findings
        except Exception as exc:
            err = f"[{tool}] classifier error: {exc}"
            evidence_store = self.session.evidence if self.session else EvidenceStore.instance()
            evidence_store.add_evidence(f"{tool}_classifier_error", err, {"target": target})
            await queue.put(err)
            return []

    def _normalize_asset(self, target: str) -> str:
        parsed = urlparse(target)
        host = parsed.hostname or target
        if host.startswith("www."):
            host = host[4:]
        return host
