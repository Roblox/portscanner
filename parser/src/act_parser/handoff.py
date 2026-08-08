"""Post-commit immutable S3 publication for the finding outbox."""

from __future__ import annotations

import hashlib
from collections.abc import Sequence
from typing import Any

from botocore.exceptions import ClientError

from .database import Repository, canonical_payload_bytes

_PRECONDITION_FAILED = 412
_MAX_PAGE_SIZE = 1000


class HandoffPublishError(RuntimeError):
    pass


class HandoffPublisher:
    def __init__(self, s3_client: Any, repository: Repository) -> None:
        self.s3 = s3_client
        self.repository = repository

    def publish_pending(
        self,
        *,
        keys: Sequence[str] | None = None,
        limit: int = 1000,
    ) -> int:
        published = 0
        for handoff in self.repository.pending_handoffs(keys=keys, limit=limit):
            handoff_key = handoff["handoff_key"].strip()
            expected_hash = handoff["payload_sha256"].strip()
            encoded = canonical_payload_bytes(handoff["payload"])
            actual_hash = hashlib.sha256(encoded).hexdigest()
            if actual_hash != expected_hash:
                self.repository.record_handoff_error(handoff_key, "payload_checksum_mismatch")
                raise HandoffPublishError("stored handoff checksum does not match payload")

            self.repository.record_handoff_attempt(handoff_key)
            try:
                self.s3.put_object(
                    Bucket=handoff["object_bucket"],
                    Key=handoff["object_key"],
                    Body=encoded,
                    ContentType="application/json",
                    Metadata={"payload-sha256": expected_hash},
                    IfNoneMatch="*",
                )
            except ClientError as error:
                status = error.response.get("ResponseMetadata", {}).get("HTTPStatusCode")
                if status == _PRECONDITION_FAILED:
                    try:
                        matches = self._existing_object_matches(handoff, expected_hash)
                    except Exception as head_error:
                        self.repository.record_handoff_error(handoff_key, type(head_error).__name__)
                        raise HandoffPublishError(
                            "existing finding object verification failed"
                        ) from head_error
                    if not matches:
                        self.repository.record_handoff_error(
                            handoff_key, "immutable_object_collision"
                        )
                        raise HandoffPublishError(
                            "immutable finding object already exists with another checksum"
                        ) from error
                else:
                    code = str(error.response.get("Error", {}).get("Code", "s3_error"))
                    self.repository.record_handoff_error(handoff_key, code)
                    raise HandoffPublishError("finding object publication failed") from error
            except Exception as error:
                self.repository.record_handoff_error(handoff_key, type(error).__name__)
                raise HandoffPublishError("finding object publication failed") from error

            self.repository.mark_handoff_published(handoff_key)
            published += 1
        return published

    def publish_all(
        self,
        *,
        keys: Sequence[str] | None = None,
        page_size: int = 1000,
    ) -> int:
        """Drain all matching handoffs through bounded database pages."""
        if not 1 <= page_size <= _MAX_PAGE_SIZE:
            raise ValueError("handoff page_size must be between 1 and 1000")
        published = 0
        while True:
            count = self.publish_pending(keys=keys, limit=page_size)
            published += count
            if count < page_size:
                return published

    def _existing_object_matches(
        self,
        handoff: Any,
        expected_hash: str,
    ) -> bool:
        response = self.s3.head_object(
            Bucket=handoff["object_bucket"],
            Key=handoff["object_key"],
        )
        metadata = response.get("Metadata") or {}
        return metadata.get("payload-sha256") == expected_hash
