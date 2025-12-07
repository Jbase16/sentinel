import subprocess
import threading
import uuid
import queue
import time
from dataclasses import dataclass, field
from typing import Callable, Optional, Dict, Any


@dataclass
class Task:
    task_id: str
    command: str
    callback: Callable[[str, str, int], None]
    timeout: Optional[int] = 120
    metadata: Dict[str, Any] = field(default_factory=dict)


class ExecutionEngine:
    """
    Global async command runner.
    Runs all tools, captures output, emits results to callbacks.
    Thread-safe. Supports queued tasks, cancellation, timeouts.
    """

    _instance = None

    @staticmethod
    def instance():
        if ExecutionEngine._instance is None:
            ExecutionEngine._instance = ExecutionEngine()
        return ExecutionEngine._instance

    def __init__(self):
        self.task_queue = queue.Queue()
        self.active_tasks = {}
        self.running = True

        # Start the worker thread
        worker = threading.Thread(target=self._worker_loop, daemon=True)
        worker.start()

    def submit(self, command: str, callback: Callable, timeout: int = 120, metadata=None):
        task_id = str(uuid.uuid4())
        task = Task(
            task_id=task_id,
            command=command,
            callback=callback,
            timeout=timeout,
            metadata=metadata or {}
        )
        self.task_queue.put(task)
        return task_id

    def kill_task(self, task_id: str):
        if task_id in self.active_tasks:
            proc = self.active_tasks[task_id]
            proc.kill()
            del self.active_tasks[task_id]

    def _worker_loop(self):
        while self.running:
            task = self.task_queue.get()
            if not task:
                continue

            try:
                proc = subprocess.Popen(
                    task.command,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    shell=True,
                    text=True
                )
                self.active_tasks[task.task_id] = proc

                try:
                    stdout, stderr = proc.communicate(timeout=task.timeout)
                except subprocess.TimeoutExpired:
                    proc.kill()
                    stdout, stderr = "", "TIMEOUT"

                rc = proc.returncode

                # Remove from active table
                if task.task_id in self.active_tasks:
                    del self.active_tasks[task.task_id]

                # Callback emits results back into the system
                task.callback(stdout, stderr, rc, task.metadata)

            except Exception as e:
                task.callback("", f"Executor error: {e}", -1)

            time.sleep(0.1)