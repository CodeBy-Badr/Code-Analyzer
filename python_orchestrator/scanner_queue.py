"""
Scanning Queue & Orchestrator Pipeline.
Threaded queue processing incoming files, buffers, and IPC stream events.
"""

import os
import queue
import threading
import time
from typing import Dict, Any, Callable, Optional, List
from .bindings_loader import engine
from .ai_classifier import ThreatClassifier, LLMForensicAnalyst


class ScanTask:
    def __init__(self, task_type: str, target: Any, source_meta: Optional[dict] = None):
        self.task_type = task_type # "FILE" or "BUFFER"
        self.target = target       # filepath or bytes
        self.source_meta = source_meta or {}
        self.timestamp = time.time()


class ScanResult:
    def __init__(
        self,
        raw_report: Dict[str, Any],
        ml_verdict: Dict[str, Any],
        forensic_summary: Dict[str, Any],
        duration_ms: float
    ):
        self.raw_report = raw_report
        self.ml_verdict = ml_verdict
        self.forensic_summary = forensic_summary
        self.duration_ms = duration_ms

    def to_dict(self) -> Dict[str, Any]:
        return {
            "file_path": self.raw_report.get("file_path"),
            "file_size": self.raw_report.get("file_size"),
            "is_pe": self.raw_report.get("is_pe"),
            "is_elf": self.raw_report.get("is_elf"),
            "entropy": self.raw_report.get("overall_entropy"),
            "is_packed": self.raw_report.get("is_packed"),
            "verdict": self.ml_verdict.get("verdict"),
            "confidence": self.ml_verdict.get("confidence"),
            "threat_score": self.raw_report.get("threat_score"),
            "iocs": self.raw_report.get("iocs", {}),
            "rule_matches": self.raw_report.get("rule_matches", []),
            "analysis_duration_ms": round(self.duration_ms, 2),
            "forensics": self.forensic_summary
        }


class ScannerQueue:
    def __init__(self, num_workers: int = 2):
        self.queue = queue.Queue()
        self.num_workers = num_workers
        self.workers = []
        self.is_running = False
        self.classifier = ThreatClassifier()
        self.analyst = LLMForensicAnalyst()
        self.result_callbacks: List[Callable[[ScanResult], None]] = []

    def register_callback(self, cb: Callable[[ScanResult], None]):
        self.result_callbacks.append(cb)

    def enqueue_file(self, filepath: str, source_meta: Optional[dict] = None):
        self.queue.put(ScanTask("FILE", filepath, source_meta))

    def enqueue_buffer(self, buffer: bytes, name: str = "stream_sample", source_meta: Optional[dict] = None):
        meta = source_meta or {}
        meta["name"] = name
        self.queue.put(ScanTask("BUFFER", buffer, meta))

    def process_task(self, task: ScanTask) -> ScanResult:
        start_t = time.perf_counter()

        if task.task_type == "FILE":
            raw_report = engine.analyze_file(task.target)
        else:
            raw_report = engine.analyze_buffer(task.target, task.source_meta.get("name", "stream_sample"))

        ml_features = raw_report.get("ml_features") or raw_report.get("ml_feature_vector") or [0.0] * 12
        ml_verdict = self.classifier.classify_feature_vector(ml_features)
        forensic_summary = self.analyst.generate_forensic_summary(raw_report, ml_verdict)

        duration_ms = (time.perf_counter() - start_t) * 1000.0
        result = ScanResult(raw_report, ml_verdict, forensic_summary, duration_ms)

        for cb in self.result_callbacks:
            try:
                cb(result)
            except Exception:
                pass

        return result

    def _worker_loop(self):
        while self.is_running:
            try:
                task = self.queue.get(timeout=0.2)
            except queue.Empty:
                continue

            try:
                self.process_task(task)
            except Exception as e:
                print(f"[-] Error processing scan task: {e}")
            finally:
                self.queue.task_done()

    def start(self):
        self.is_running = True
        for _ in range(self.num_workers):
            t = threading.Thread(target=self._worker_loop, daemon=True)
            t.start()
            self.workers.append(t)

    def stop(self):
        self.is_running = False
        for t in self.workers:
            t.join(timeout=1.0)
        self.workers.clear()
