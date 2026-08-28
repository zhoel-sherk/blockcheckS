"""Unit tests for batch_scheduler — strategy/job batching for the lua bridge."""

from __future__ import annotations

from unittest.mock import MagicMock

import pytest

from blockchecks.service.batch_scheduler import (
    BatchJobAccumulator,
    BatchScheduler,
    batch_job_key,
)

pytestmark = pytest.mark.unit


def _item(label="s1"):
    it = MagicMock()
    it.label = label
    return it


def _job(label="s1", domain="d.com", fanout=False, key=None, protocol="tls12"):
    j = MagicMock()
    j.item = _item(label)
    j.item.protocol = protocol
    j.domain = domain
    j.fanout = fanout
    j.key = key or (label, domain)
    return j


def test_batch_size_clamped():
    assert BatchScheduler(0).batch_size == 1
    assert BatchScheduler(1_000_000).batch_size == 2000
    assert BatchScheduler(3).batch_size == 3


def test_iter_batches_empty():
    assert BatchScheduler(5).iter_batches([]) == []


def test_iter_batches_chunks():
    items = [_item(f"s{i}") for i in range(7)]
    batches = BatchScheduler(3).iter_batches(items)
    assert [len(b) for b in batches] == [3, 3, 1]


def test_group_jobs_by_domain_empty():
    assert BatchScheduler(5).group_jobs_by_domain([]) == []


def test_group_jobs_by_domain_chunks():
    jobs = [_job(f"s{i}", "a.com") for i in range(7)]
    groups = BatchScheduler(3).group_jobs_by_domain(jobs)
    assert [len(g) for g in groups] == [3, 3, 1]


def test_group_jobs_by_domain_splits_on_domain():
    jobs = [_job("s1", "a.com"), _job("s2", "b.com"), _job("s3", "b.com")]
    groups = BatchScheduler(5).group_jobs_by_domain(jobs)
    assert [g[0].domain for g in groups] == ["a.com", "b.com"]
    assert len(groups[1]) == 2


def test_group_jobs_by_domain_duplicate_label_splits():
    jobs = [_job("s1", "a.com"), _job("s1", "a.com"), _job("s2", "a.com")]
    groups = BatchScheduler(5).group_jobs_by_domain(jobs)
    # duplicate label forces a split
    assert len(groups) >= 2


def test_group_jobs_flush_partial_false():
    jobs = [_job("s1", "a.com")]
    groups = BatchScheduler(5).group_jobs_by_domain(jobs, flush_partial=False)
    assert groups == []


def test_accumulator_length_and_domain():
    acc = BatchJobAccumulator(3)
    assert len(acc) == 0
    assert acc.domain is None
    assert acc.domains == []
    acc.push(_job("s1", "a.com"))
    assert len(acc) == 1
    assert acc.domain == "a.com"
    assert acc.domains == ["a.com"]


def test_accumulator_push_and_flush():
    acc = BatchJobAccumulator(3)
    j1 = _job("s1", "a.com")
    j2 = _job("s2", "b.com")
    assert acc.push(j1) is True
    assert acc.push(j2) is True
    jobs = acc.flush()
    assert len(jobs) == 2
    assert len(acc) == 0


def test_accumulator_rejects_duplicate_key():
    acc = BatchJobAccumulator(3)
    assert acc.push(_job("s1", "a.com")) is True
    assert acc.push(_job("s1", "a.com")) is False


def test_accumulator_rejects_fanout():
    acc = BatchJobAccumulator(3)
    assert acc.push(_job("s1", "a.com", fanout=True)) is False


def test_accumulator_is_full():
    acc = BatchJobAccumulator(2)
    acc.push(_job("s1", "a.com"))
    assert acc.is_full() is False
    acc.push(_job("s2", "a.com"))
    assert acc.is_full() is True
    assert acc.push(_job("s3", "a.com")) is False


def test_batch_job_key_includes_protocol():
    job = _job("s1", "a.com", protocol="udp_voice")
    assert batch_job_key(job) == ("s1", "a.com", "udp_voice")


def test_accumulator_rejects_protocol_mismatch():
    acc = BatchJobAccumulator(10)
    assert acc.push(_job("s1", "a.com", protocol="tls12"))
    assert not acc.can_accept(_job("s2", "b.com", protocol="udp_voice"))
    assert not acc.push(_job("s2", "b.com", protocol="udp_voice"))


def test_accumulator_same_label_domain_different_protocol_after_flush():
    acc = BatchJobAccumulator(10)
    j_tcp = _job("s1", "a.com", protocol="tls12")
    j_udp = _job("s1", "a.com", protocol="udp_voice")
    assert acc.push(j_tcp)
    assert not acc.push(j_udp)
    flushed = acc.flush()
    assert len(flushed) == 1
    assert acc.push(j_udp)
    assert len(acc) == 1
