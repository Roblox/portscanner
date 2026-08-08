# SPDX-FileCopyrightText: 2026 Portscanner contributors
# SPDX-License-Identifier: MIT

from __future__ import annotations

import hashlib
import ipaddress
import json
import subprocess
import sys
import time
from dataclasses import replace
from datetime import UTC, datetime, timedelta
from pathlib import Path
from threading import Event, Timer

import portscanner_scanner.worker as worker_module
import pytest
from conftest import DOCUMENTATION_TARGET, contract_target, nmap_xml
from portscanner_scanner.cli import main
from portscanner_scanner.coverage import PortCoverage
from portscanner_scanner.nmap import (
    NmapTerminationError,
    NmapTuning,
    ProcessResult,
    SubprocessRunner,
)
from portscanner_scanner.parser import parse_authoritative_result
from portscanner_scanner.worker import (
    ScanExecutionError,
    ScanRequest,
    execute_scan,
    prepare_scan,
)

from portscanner_contracts import ScanResultEnvelope


class RecordingWriter:
    def __init__(self):
        self.operations = []

    def put_file(self, *, bucket, key, path, content_type):
        value = Path(path).read_bytes()
        self.operations.append(("file", key, value, content_type))
        return hashlib.sha256(value).hexdigest()

    def put_bytes(self, *, bucket, key, value, content_type):
        self.operations.append(("bytes", key, value, content_type))
        return hashlib.sha256(value).hexdigest()


class FakeNmapRunner:
    def __init__(
        self,
        *,
        timeout: bool = False,
        terminate: bool = False,
        enrichment_changed: bool = False,
        enrichment_extra_open: bool = False,
    ):
        self.timeout = timeout
        self.terminate = terminate
        self.enrichment_changed = enrichment_changed
        self.enrichment_extra_open = enrichment_extra_open
        self.commands = []

    def run(self, command, *, timeout_seconds):
        command = list(command)
        self.commands.append((command, timeout_seconds))
        output = Path(command[command.index("-oX") + 1])
        if self.terminate:
            raise NmapTerminationError("test termination")
        if self.timeout:
            output.write_bytes(
                nmap_xml(
                    explicit_states={80: "closed"},
                    finished=False,
                )
            )
            raise subprocess.TimeoutExpired(command, timeout_seconds)

        coverage = PortCoverage.parse(command[command.index("-p") + 1])
        first_port = next(coverage.ports())
        if "-sV" in command:
            state = "closed" if self.enrichment_changed else "open"
            explicit_states = dict.fromkeys(coverage.ports(), state)
            if self.enrichment_extra_open:
                explicit_states[max(explicit_states) + 1] = "open"
            output.write_bytes(nmap_xml(explicit_states=explicit_states))
        else:
            collapsed = (("closed", coverage.count - 1),) if coverage.count > 1 else ()
            output.write_bytes(
                nmap_xml(
                    explicit_states={first_port: "open"},
                    collapsed_states=collapsed,
                )
            )
        return ProcessResult(returncode=0)


def _clock():
    current = datetime(2026, 1, 1, tzinfo=UTC)

    def now():
        nonlocal current
        value = current
        current += timedelta(seconds=1)
        return value

    return now


def _request() -> ScanRequest:
    shared_target = contract_target(generation=4)
    return ScanRequest(
        target=DOCUMENTATION_TARGET,
        profile="targeted-tcp",
        ports="82,80-81",
        event_id="1" * 64,
        directive_id="2" * 64,
        trace_id="trace-001",
        run_id="run-001",
        attempt_id="attempt-001",
        target_id=shared_target.target_id,
        target_provider=shared_target.provider.value,
        target_scope_id=shared_target.scope_id,
        target_location=shared_target.location,
        target_resource_id=shared_target.resource_id,
        target_private_address=shared_target.private_address,
        target_generation=4,
        image_version=f"sha256:{'a' * 64}",
        bucket="configured-results",
        prefix="verify/results",
        deadline_at=datetime(2099, 1, 1, tzinfo=UTC),
        not_after=datetime(2099, 1, 2, tzinfo=UTC),
    )


@pytest.fixture
def authorize_documentation_target(monkeypatch):
    monkeypatch.setattr(
        worker_module,
        "authorize_target",
        lambda target, **kwargs: ipaddress.IPv4Address(DOCUMENTATION_TARGET),
    )


def test_success_uploads_raw_xml_before_immutable_envelope(
    tmp_path,
    authorize_documentation_target,
):
    runner = FakeNmapRunner()
    writer = RecordingWriter()

    payload = execute_scan(
        _request(),
        tuning=NmapTuning(),
        runner=runner,
        writer=writer,
        working_directory=tmp_path,
        clock=_clock(),
    )

    assert [operation[0] for operation in writer.operations] == [
        "file",
        "file",
        "bytes",
    ]
    assert writer.operations[0][1].endswith("/raw/nmap-discovery.xml")
    assert writer.operations[1][1].endswith("/raw/nmap-enrichment.xml")
    assert writer.operations[2][1].endswith("/scan-result.json")
    assert payload["coverage"] == {
        "protocol": "tcp",
        "ports": ["80-82"],
        "complete": True,
    }
    assert payload["outcome"] == "complete"
    assert payload["scan_result"]["result_id"]
    assert payload["scan_result"]["requested_tcp_port_ranges"] == [{"start": 80, "end": 82}]
    assert payload["raw_result"]["sha256"] == hashlib.sha256(writer.operations[0][2]).hexdigest()
    assert ScanResultEnvelope.model_validate(payload).to_dict() == payload
    assert len(runner.commands) == 2
    assert all(isinstance(command, list) for command, _ in runner.commands)
    assert runner.commands[1][0][runner.commands[1][0].index("-p") + 1] == "80"

    serialized = writer.operations[-1][2].decode("utf-8")
    assert DOCUMENTATION_TARGET not in json.dumps(payload["commands"])
    assert str(tmp_path) not in serialized


def test_fast_profile_accepts_operator_declared_full_coverage(
    authorize_documentation_target,
):
    prepared = prepare_scan(
        replace(
            _request(),
            profile="fast-full-tcp",
            ports="1-65535",
        )
    )
    assert prepared.coverage == PortCoverage.full_tcp()


def test_timeout_uploads_partial_failed_envelope_and_exits_nonzero(
    tmp_path,
    authorize_documentation_target,
):
    runner = FakeNmapRunner(timeout=True)
    writer = RecordingWriter()

    with pytest.raises(ScanExecutionError) as captured:
        execute_scan(
            _request(),
            tuning=NmapTuning(),
            runner=runner,
            writer=writer,
            working_directory=tmp_path,
            clock=_clock(),
        )

    assert captured.value.error_type == "discovery_timeout"
    assert [operation[0] for operation in writer.operations] == ["file", "bytes"]
    failed = json.loads(writer.operations[-1][2])
    assert failed["coverage"]["complete"] is False
    assert failed["coverage"]["ports"] == ["80-82"]
    assert failed["outcome"] == "partial"
    assert failed["error"] == {
        "type": "discovery_timeout",
        "message": "Nmap discovery exceeded its configured timeout",
        "retryable": True,
    }
    assert failed["raw_result"]["sha256"] == hashlib.sha256(writer.operations[0][2]).hexdigest()
    assert DOCUMENTATION_TARGET not in json.dumps(failed["commands"])
    assert str(tmp_path) not in json.dumps(failed["commands"])


def test_absolute_not_after_clamps_process_and_host_timeouts(
    tmp_path,
    authorize_documentation_target,
):
    now = datetime(2026, 1, 1, tzinfo=UTC)
    runner = FakeNmapRunner()
    request = replace(
        _request(),
        deadline_at=now - timedelta(minutes=1),
        not_after=now + timedelta(seconds=45),
    )

    execute_scan(
        request,
        tuning=NmapTuning(upload_reserve_seconds=30),
        runner=runner,
        writer=RecordingWriter(),
        working_directory=tmp_path,
        clock=lambda: now,
    )

    assert [timeout for _, timeout in runner.commands] == [15, 15]
    for command, timeout in runner.commands:
        host_timeout = command[command.index("--host-timeout") + 1]
        assert host_timeout == f"{timeout - 1}s"


def test_insufficient_absolute_budget_fails_before_nmap_and_publishes_envelope(
    tmp_path,
    authorize_documentation_target,
):
    now = datetime(2026, 1, 1, tzinfo=UTC)
    runner = FakeNmapRunner()
    writer = RecordingWriter()
    request = replace(
        _request(),
        deadline_at=now - timedelta(minutes=1),
        not_after=now + timedelta(seconds=31),
    )

    with pytest.raises(ScanExecutionError) as captured:
        execute_scan(
            request,
            tuning=NmapTuning(upload_reserve_seconds=30),
            runner=runner,
            writer=writer,
            working_directory=tmp_path,
            clock=lambda: now,
        )

    assert captured.value.error_type == "insufficient_execution_budget"
    assert runner.commands == []
    assert [operation[0] for operation in writer.operations] == ["bytes"]
    failed = json.loads(writer.operations[-1][2])
    assert failed["outcome"] == "failed"
    assert failed["error"]["retryable"] is False


def test_termination_best_effort_publishes_failed_envelope(
    tmp_path,
    authorize_documentation_target,
):
    runner = FakeNmapRunner(terminate=True)
    writer = RecordingWriter()

    with pytest.raises(ScanExecutionError) as captured:
        execute_scan(
            _request(),
            tuning=NmapTuning(),
            runner=runner,
            writer=writer,
            working_directory=tmp_path,
            clock=_clock(),
        )

    assert captured.value.error_type == "terminated"
    assert [operation[0] for operation in writer.operations] == ["bytes"]
    failed = json.loads(writer.operations[-1][2])
    assert failed["outcome"] == "failed"
    assert failed["error"]["type"] == "terminated"


def test_subprocess_runner_stops_child_within_bounded_grace():
    termination_event = Event()
    runner = SubprocessRunner(
        termination_event=termination_event,
        terminate_grace_seconds=0.2,
        poll_interval_seconds=0.01,
    )
    timer = Timer(0.05, termination_event.set)
    timer.start()
    started = time.monotonic()
    try:
        with pytest.raises(NmapTerminationError):
            runner.run(
                [sys.executable, "-c", "import time; time.sleep(30)"],
                timeout_seconds=10,
            )
    finally:
        timer.cancel()
    assert time.monotonic() - started < 2


@pytest.mark.parametrize("change", ["closed", "opened"])
def test_enrichment_port_change_is_partial_unknown_without_enrichment_reference(
    tmp_path,
    authorize_documentation_target,
    change,
):
    runner = FakeNmapRunner(
        enrichment_changed=change == "closed",
        enrichment_extra_open=change == "opened",
    )
    writer = RecordingWriter()

    with pytest.raises(ScanExecutionError) as captured:
        execute_scan(
            _request(),
            tuning=NmapTuning(),
            runner=runner,
            writer=writer,
            working_directory=tmp_path,
            clock=_clock(),
        )

    assert captured.value.error_type == "enrichment_port_set_changed"
    assert [operation[0] for operation in writer.operations] == ["file", "bytes"]
    raw_discovery = writer.operations[0][2]
    failed = json.loads(writer.operations[-1][2])
    assert failed["outcome"] == "partial"
    assert failed["coverage"]["complete"] is False
    assert failed["raw_result"]["enrichment"] is None
    assert failed["scan_result"]["open_tcp_ports"] == []
    parsed = parse_authoritative_result(failed, raw_discovery)
    assert parsed["observations"] == [
        {
            "protocol": "tcp",
            "port": 80,
            "state": "UNKNOWN",
            "nmap_state": "open",
        }
    ]


def test_cli_runs_with_fake_nmap_and_s3(
    authorize_documentation_target,
):
    runner = FakeNmapRunner()
    writer = RecordingWriter()
    shared_target = contract_target(generation=1)
    arguments = [
        "--target",
        DOCUMENTATION_TARGET,
        "--profile",
        "targeted-tcp",
        "--tcp-ports",
        "80-82",
        "--scan-mode",
        "targeted",
        "--event-id",
        "1" * 64,
        "--directive-id",
        "2" * 64,
        "--trace-id",
        "trace-001",
        "--run-id",
        "run-001",
        "--attempt-id",
        "attempt-001",
        "--target-id",
        shared_target.target_id,
        "--target-provider",
        shared_target.provider.value,
        "--target-scope-id",
        shared_target.scope_id,
        "--target-location",
        shared_target.location,
        "--target-resource-id",
        shared_target.resource_id,
        "--target-private-address",
        shared_target.private_address,
        "--target-generation",
        "1",
        "--deadline-at",
        "2099-01-01T00:00:00Z",
        "--not-after",
        "2099-01-02T00:00:00Z",
        "--image-version",
        f"sha256:{'b' * 64}",
        "--s3-bucket",
        "configured-results",
        "--s3-prefix",
        "verify/results",
    ]

    assert main(arguments, runner=runner, writer=writer) == 0
    assert [item[0] for item in writer.operations] == ["file", "file", "bytes"]
    assert all(command[0][0] == "nmap" for command in runner.commands)
    assert all("-sT" in command[0] for command in runner.commands)
    assert all("-sS" not in command[0] for command in runner.commands)
    assert all("--privileged" not in command[0] for command in runner.commands)


def test_cli_rejects_repeated_target_field():
    common = [
        "--target",
        DOCUMENTATION_TARGET,
        "--target",
        "203.0.113.25",
        "--profile",
        "targeted-tcp",
        "--ports",
        "443",
        "--event-id",
        "event-001",
        "--trace-id",
        "trace-001",
        "--run-id",
        "run-001",
        "--attempt-id",
        "attempt-001",
        "--target-generation",
        "1",
        "--deadline-at",
        "2099-01-01T00:00:00Z",
        "--not-after",
        "2099-01-02T00:00:00Z",
        "--image-version",
        f"sha256:{'c' * 64}",
        "--s3-bucket",
        "configured-results",
        "--s3-prefix",
        "verify",
    ]
    with pytest.raises(SystemExit) as captured:
        main(common, runner=FakeNmapRunner(), writer=RecordingWriter())
    assert captured.value.code == 2
