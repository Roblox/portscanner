from __future__ import annotations

import hashlib
from typing import Any

import pytest
from act_parser.database import canonical_payload_bytes
from act_parser.handoff import HandoffPublisher


@pytest.mark.parametrize(("total", "page_size"), [(0, 2), (1, 2), (2, 2), (5, 2)])
@pytest.mark.parametrize("keyed", [False, True])
def test_publish_all_drains_more_than_one_bounded_page(
    total: int,
    page_size: int,
    keyed: bool,
) -> None:
    class Repository:
        def __init__(self) -> None:
            self.pending = [
                {
                    "handoff_key": f"handoff-{index}",
                    "payload": {"index": index},
                    "payload_sha256": hashlib.sha256(
                        canonical_payload_bytes({"index": index})
                    ).hexdigest(),
                    "object_bucket": "finding-test",
                    "object_key": f"findings/{index}.json",
                }
                for index in range(total)
            ]
            self.page_limits: list[int] = []

        def pending_handoffs(
            self,
            *,
            keys: list[str] | None = None,
            limit: int,
        ) -> list[dict[str, Any]]:
            self.page_limits.append(limit)
            allowed = None if keys is None else set(keys)
            matching = [
                item for item in self.pending if allowed is None or item["handoff_key"] in allowed
            ]
            return matching[:limit]

        def record_handoff_error(self, _key: str, _code: str) -> None:
            pytest.fail("publication must not fail")

        def record_handoff_attempt(self, _key: str) -> None:
            return None

        def mark_handoff_published(self, key: str) -> None:
            self.pending = [item for item in self.pending if item["handoff_key"] != key]

    class S3:
        def __init__(self) -> None:
            self.keys: list[str] = []

        def put_object(self, **kwargs: Any) -> None:
            self.keys.append(kwargs["Key"])

    repository = Repository()
    s3 = S3()
    publisher = HandoffPublisher(s3, repository)  # type: ignore[arg-type]

    keys = tuple(item["handoff_key"] for item in repository.pending) if keyed else None
    assert publisher.publish_all(keys=keys, page_size=page_size) == total
    assert len(s3.keys) == total
    assert repository.pending == []
    assert all(limit == page_size for limit in repository.page_limits)
    if total > page_size:
        assert len(repository.page_limits) > 1
