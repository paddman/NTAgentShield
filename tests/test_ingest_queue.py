from __future__ import annotations

from datetime import UTC, datetime, timedelta

from ntshield.ingest_queue import DurableIngestQueue


def payload() -> dict[str, object]:
    return {
        "tenant_id": "tenant-a",
        "source_type": "test",
        "event_type": "process.start",
        "asset": {"id": "host-a"},
    }


def test_queue_idempotency_lease_completion_and_stats(tmp_path) -> None:
    queue = DurableIngestQueue(tmp_path / "queue.db")
    first, created = queue.enqueue(
        tenant_id="tenant-a",
        kind="normalized",
        payload=payload(),
        idempotency_key="request-1",
    )
    duplicate, duplicate_created = queue.enqueue(
        tenant_id="tenant-a",
        kind="normalized",
        payload=payload(),
        idempotency_key="request-1",
    )
    assert created
    assert not duplicate_created
    assert duplicate.job_id == first.job_id

    claimed = queue.claim(worker_id="worker-a", limit=10, lease_seconds=60)
    assert [job.job_id for job in claimed] == [first.job_id]
    completed = queue.complete(
        first.job_id,
        worker_id="worker-a",
        result={"event_id": "evt-1", "findings": 0},
    )
    assert completed.status == "succeeded"
    assert queue.stats("tenant-a")["succeeded"] == 1
    queue.close()


def test_queue_reclaims_expired_lease_and_dead_letters(tmp_path) -> None:
    queue = DurableIngestQueue(tmp_path / "queue.db")
    now = datetime(2026, 1, 1, tzinfo=UTC)
    job, _ = queue.enqueue(
        tenant_id="tenant-a",
        kind="normalized",
        payload=payload(),
        max_attempts=2,
        now=now,
    )
    assert queue.claim(
        worker_id="dead-worker",
        lease_seconds=10,
        now=now,
    )[0].job_id == job.job_id
    reclaimed = queue.claim(
        worker_id="worker-b",
        lease_seconds=10,
        now=now + timedelta(seconds=11),
    )
    assert reclaimed[0].attempts == 2
    failed = queue.fail(
        job.job_id,
        worker_id="worker-b",
        error="permanent schema failure",
        retry_delay_seconds=5,
        now=now + timedelta(seconds=12),
    )
    assert failed.status == "dead_letter"

    original, _ = queue.enqueue(
        tenant_id="tenant-a",
        kind="normalized",
        payload=payload(),
        idempotency_key="reuse",
    )
    try:
        queue.enqueue(
            tenant_id="tenant-a",
            kind="normalized",
            payload={**payload(), "event_type": "different"},
            idempotency_key="reuse",
        )
    except ValueError as exc:
        assert "different payload" in str(exc)
    else:
        raise AssertionError(f"idempotency conflict was accepted for {original.job_id}")
    queue.close()


def test_queue_dead_letters_after_repeated_worker_crashes(tmp_path) -> None:
    queue = DurableIngestQueue(tmp_path / "queue.db")
    now = datetime(2026, 1, 1, tzinfo=UTC)
    job, _ = queue.enqueue(
        tenant_id="tenant-a",
        kind="normalized",
        payload=payload(),
        max_attempts=2,
        now=now,
    )
    queue.claim(worker_id="worker-a", lease_seconds=10, now=now)
    queue.claim(
        worker_id="worker-b",
        lease_seconds=10,
        now=now + timedelta(seconds=11),
    )
    assert queue.claim(
        worker_id="worker-c",
        lease_seconds=10,
        now=now + timedelta(seconds=22),
    ) == []
    dead = queue.get(job.job_id)
    assert dead is not None
    assert dead.status == "dead_letter"
    assert dead.attempts == 2
    queue.close()
