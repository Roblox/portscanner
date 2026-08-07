# SPDX-FileCopyrightText: 2026 Portscanner contributors
# SPDX-License-Identifier: MIT

from __future__ import annotations

import os
import shutil
import socket
import subprocess
import tempfile
import unittest
from pathlib import Path

from defusedxml import ElementTree


def test_nonroot_connect_scan_finds_local_listener_without_capabilities():
    if os.geteuid() == 0:
        raise unittest.SkipTest("smoke must run as the non-root scanner image user")
    nmap = shutil.which("nmap")
    if nmap is None:
        raise unittest.SkipTest("Nmap is not installed")

    process_status = Path("/proc/self/status")
    if process_status.exists():
        capabilities = {
            key: value.strip()
            for key, value in (
                line.split(":", 1)
                for line in process_status.read_text(encoding="utf-8").splitlines()
                if line.startswith(("CapPrm:", "CapEff:", "CapAmb:"))
            )
        }
        assert capabilities == {
            "CapPrm": "0000000000000000",
            "CapEff": "0000000000000000",
            "CapAmb": "0000000000000000",
        }

    with (
        tempfile.TemporaryDirectory(prefix="portscanner-connect-smoke-") as temporary,
        socket.socket(socket.AF_INET, socket.SOCK_STREAM) as listener,
    ):
        output = Path(temporary) / "local-listener.xml"
        listener.bind(("127.0.0.1", 0))
        listener.listen()
        port = listener.getsockname()[1]
        completed = subprocess.run(  # noqa: S603 - absolute binary and fixed argv.
            [
                nmap,
                "-sT",
                "-n",
                "-Pn",
                "-p",
                str(port),
                "-oX",
                str(output),
                "127.0.0.1",
            ],
            check=False,
            capture_output=True,
            text=True,
            timeout=10,
        )

        diagnostics = f"{completed.stdout}\n{completed.stderr}".lower()
        assert completed.returncode == 0, diagnostics
        document = ElementTree.parse(output)
        port_element = document.find(f".//port[@protocol='tcp'][@portid='{port}']")
        assert port_element is not None
        state_element = port_element.find("state")
        assert state_element is not None
        assert state_element.attrib["state"] == "open"


if __name__ == "__main__":
    test_nonroot_connect_scan_finds_local_listener_without_capabilities()
