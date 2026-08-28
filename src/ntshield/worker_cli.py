from __future__ import annotations

import argparse
import logging
import os
import socket
import time
from uuid import uuid4

from ntshield.async_ingest import queue_path
from ntshield.engine.hunt import HuntEngine
from ntshield.ingest_queue import DurableIngestQueue, IngestJob
from ntshield.models import RawEventEnvelope, SecurityEvent
from ntshield.normalizer import normalize
from ntshield.settings import Settings


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="ntshield-worker")
    parser.add_argument("--once", action="store_true", help="drain one batch and exit")
    parser.add_argument("--batch", type=int, default=100)
    parser.add_argument("--lease-seconds", type=int, default=120)
    parser.add_argument("--poll-seconds", type=float, default=1.0)
    parser.add_argument("--worker-id", default="")
    return parser


def main() -> int:
    args = build_parser().parse_args()
    if args.poll_seconds < 0.1 or args.poll_seconds > 60:
        raise SystemExit("--poll-seconds must be between 0.1 and 60")
    settings = Settings()
    worker_id = args.worker_id.strip() or (
        f"{socket.gethostname()}:{os.getpid()}:{uuid4().hex[:8]}"
    )
    logger = logging.getLogger("ntshield-worker")
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
    queue = DurableIngestQueue(queue_path(settings))
    engine = HuntEngine(settings)
    try:
        while True:
            processed = run_batch(
                queue,
                engine,
                worker_id=worker_id,
                batch=args.batch,
                lease_seconds=args.lease_seconds,
                logger=logger,
            )
            if args.once:
                return 0
            if processed == 0:
                time.sleep(args.poll_seconds)
    finally:
        engine.store.close()
        queue.close()


def run_batch(
    queue: DurableIngestQueue,
    engine: HuntEngine,
    *,
    worker_id: str,
    batch: int,
    lease_seconds: int,
    logger: logging.Logger,
) -> int:
    jobs = queue.claim(worker_id=worker_id, limit=batch, lease_seconds=lease_seconds)
    for job in jobs:
        try:
            event = _event(job)
            if event.tenant_id != job.tenant_id:
                raise ValueError("queued payload tenant does not match queue tenant")
            result = engine.ingest(event)
            queue.complete(
                job.job_id,
                worker_id=worker_id,
                result={
                    "event_id": result.event_id,
                    "findings": len(result.findings),
                    "incident_ids": [item.incident_id for item in result.incidents],
                },
            )
            logger.info(
                "ingest job succeeded job_id=%s tenant=%s event=%s findings=%d",
                job.job_id,
                job.tenant_id,
                result.event_id,
                len(result.findings),
            )
        except Exception as exc:
            delay = min(900, 2 ** min(job.attempts, 9))
            failed = queue.fail(
                job.job_id,
                worker_id=worker_id,
                error=str(exc),
                retry_delay_seconds=delay,
            )
            logger.warning(
                "ingest job failed job_id=%s attempts=%d status=%s error=%s",
                job.job_id,
                failed.attempts,
                failed.status,
                exc,
            )
    return len(jobs)


def _event(job: IngestJob) -> SecurityEvent:
    if job.kind == "normalized":
        return SecurityEvent.model_validate(job.payload)
    envelope = RawEventEnvelope.model_validate(job.payload)
    return normalize(envelope)


if __name__ == "__main__":
    raise SystemExit(main())
