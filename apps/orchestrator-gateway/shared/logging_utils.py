"""
Project Castor: Standardized Agent Lifecycle Logging
Provides context managers and structured banner logging for multi-agent execution.
"""

import logging
import time
from typing import Any, Dict, Optional

logger = logging.getLogger("castor.agents")


class AgentLifecycle:
    """Standardized lifecycle logger for Project Castor agents."""

    def __init__(
        self,
        agent_name: str,
        product_id: str,
        trace_id: str,
        mode: str = "SYNC",
        extra_metadata: Optional[Dict[str, Any]] = None,
    ):
        self.agent_name = agent_name
        self.product_id = product_id
        self.trace_id = trace_id
        self.mode = mode
        self.extra_metadata = extra_metadata or {}
        self.start_time = 0.0
        self.elapsed = 0.0
        self.status = "UNKNOWN"
        self.summary = ""

    def __enter__(self):
        self.start_time = time.time()
        meta_lines = "".join(f"\n{k.capitalize():<12}: {v}" for k, v in self.extra_metadata.items())
        logger.info("=" * 64)
        logger.info(f"🤖 AGENT [{self.agent_name}] BEGIN PROCESS: {self.product_id} [Trace: {self.trace_id}]")
        logger.info("-" * 64)
        logger.info(f"Mode        : {self.mode}{meta_lines}")
        logger.info("=" * 64)
        return self

    def set_summary(self, summary: str, status: str = "SUCCESS"):
        self.summary = summary
        self.status = status

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.elapsed = round(time.time() - self.start_time, 2)
        if exc_type is not None:
            self.status = "FAILED"
            self.summary = f"Exception: {str(exc_val)}"

        logger.info("=" * 64)
        logger.info(f"🏁 AGENT [{self.agent_name}] END PROCESS: {self.product_id} - STATUS: {self.status}")
        logger.info("-" * 64)
        logger.info(f"Duration    : {self.elapsed}s")
        logger.info(f"Outcome     : {self.summary}")
        logger.info("=" * 64)
        return False  # Do not suppress exceptions
