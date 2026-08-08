# SPDX-FileCopyrightText: 2026 Portscanner contributors
# SPDX-License-Identifier: MIT

"""Deterministic TCP port coverage parsing and normalization."""

from __future__ import annotations

import re
from collections.abc import Iterable, Iterator
from dataclasses import dataclass

MIN_PORT = 1
MAX_PORT = 65_535
MAX_COVERAGE_TERMS = 256
MAX_INPUT_COVERAGE_TERMS = 4_096
_TERM = re.compile(r"^(?P<start>[0-9]{1,5})(?:-(?P<end>[0-9]{1,5}))?$")


class CoverageError(ValueError):
    """Raised when declared port coverage is invalid."""


@dataclass(frozen=True, order=True)
class PortRange:
    start: int
    end: int

    def __post_init__(self) -> None:
        if not MIN_PORT <= self.start <= self.end <= MAX_PORT:
            raise CoverageError(f"port range must be between {MIN_PORT} and {MAX_PORT}")

    @property
    def size(self) -> int:
        return self.end - self.start + 1

    def contains(self, port: int) -> bool:
        return self.start <= port <= self.end

    def render(self) -> str:
        return str(self.start) if self.start == self.end else f"{self.start}-{self.end}"


@dataclass(frozen=True)
class PortCoverage:
    """Canonical, non-overlapping TCP port coverage."""

    ranges: tuple[PortRange, ...]

    def __post_init__(self) -> None:
        if not self.ranges:
            raise CoverageError("port coverage cannot be empty")
        previous: PortRange | None = None
        for current in self.ranges:
            if previous is not None and current.start <= previous.end + 1:
                raise CoverageError("port coverage ranges must already be normalized")
            previous = current

    @classmethod
    def parse(cls, declarations: str | Iterable[str]) -> PortCoverage:
        if isinstance(declarations, str):
            raw_terms = declarations.split(",")
        else:
            raw_terms = []
            for declaration in declarations:
                if not isinstance(declaration, str):
                    raise CoverageError("port coverage terms must be strings")
                raw_terms.extend(declaration.split(","))

        if not raw_terms or len(raw_terms) > MAX_INPUT_COVERAGE_TERMS:
            raise CoverageError(
                f"port coverage must contain 1-{MAX_INPUT_COVERAGE_TERMS} input terms"
            )

        parsed: list[PortRange] = []
        for raw_term in raw_terms:
            term = raw_term.strip()
            if not term:
                raise CoverageError("port coverage contains an empty term")
            match = _TERM.fullmatch(term)
            if match is None:
                raise CoverageError(f"invalid TCP port coverage term: {term!r}")
            start = int(match.group("start"))
            end = int(match.group("end") or start)
            parsed.append(PortRange(start, end))

        parsed.sort()
        normalized: list[PortRange] = []
        for current in parsed:
            if normalized and current.start <= normalized[-1].end + 1:
                previous = normalized[-1]
                normalized[-1] = PortRange(previous.start, max(previous.end, current.end))
            else:
                normalized.append(current)
        if len(normalized) > MAX_COVERAGE_TERMS:
            raise CoverageError(
                f"normalized port coverage must contain at most {MAX_COVERAGE_TERMS} terms"
            )
        return cls(tuple(normalized))

    @classmethod
    def full_tcp(cls) -> PortCoverage:
        return cls((PortRange(MIN_PORT, MAX_PORT),))

    @classmethod
    def from_ports(cls, ports: Iterable[int]) -> PortCoverage:
        values = sorted(set(ports))
        if not values:
            raise CoverageError("cannot build coverage from an empty port set")
        return cls.parse([str(port) for port in values])

    @property
    def count(self) -> int:
        return sum(item.size for item in self.ranges)

    @property
    def nmap_spec(self) -> str:
        return ",".join(item.render() for item in self.ranges)

    def as_strings(self) -> tuple[str, ...]:
        return tuple(item.render() for item in self.ranges)

    def contains(self, port: int) -> bool:
        return any(item.contains(port) for item in self.ranges)

    def ports(self) -> Iterator[int]:
        for item in self.ranges:
            yield from range(item.start, item.end + 1)


def normalize_port_coverage(declarations: str | Iterable[str]) -> tuple[str, ...]:
    """Return the stable external representation used by ScanResult."""

    return PortCoverage.parse(declarations).as_strings()
