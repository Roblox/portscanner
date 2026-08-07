#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 Portscanner contributors
# SPDX-License-Identifier: MIT
"""Reject sensitive or non-public content before repository publication."""

from __future__ import annotations

import argparse
import fnmatch
import ipaddress
import json
import os
import re
import subprocess
import sys
from collections.abc import Iterable, Mapping, Sequence
from dataclasses import asdict, dataclass
from pathlib import Path, PurePosixPath
from typing import Any

try:
    import tomllib
except ModuleNotFoundError as exc:  # pragma: no cover - Python version guard
    raise SystemExit("sanitize.py requires Python 3.11 or newer") from exc


ACCOUNT_ID_RE = re.compile(r"(?<![A-Za-z0-9])\d{12}(?![A-Za-z0-9])")
AWS_ARN_RE = re.compile(r"\barn:aws(?:-[a-z0-9-]+)?:[^\s\"'<>]+", re.IGNORECASE)
AWS_RESOURCE_ID_RE = re.compile(
    r"\b(?:acl|ami|eipalloc|eipassoc|eni|igw|i|nat|pcx|rtb|sg|snap|"
    r"subnet|tgw|vol|vpc|vpce)-[0-9a-f]{8,32}\b",
    re.IGNORECASE,
)
UNIX_HOME_RE = re.compile(
    r"(?<![A-Za-z0-9])/(?:Users|home)/[A-Za-z0-9._-]+"
    r"(?:/[^\s\"'<>]*)?"
)
WINDOWS_HOME_RE = re.compile(r"(?i)\b[A-Z]:\\Users\\[A-Za-z0-9._-]+(?:\\[^\s\"'<>]*)?")
EMAIL_RE = re.compile(
    r"(?<![A-Z0-9._%+:/-])[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b",
    re.IGNORECASE,
)
US_SSN_RE = re.compile(r"(?<!\d)\d{3}-\d{2}-\d{4}(?!\d)")
US_PHONE_RE = re.compile(
    r"(?<!\d)(?:\+?1[-.\s]?)?\(?[2-9]\d{2}\)?[-.\s]\d{3}"
    r"[-.\s]\d{4}(?!\d)"
)
IPV4_RE = re.compile(
    r"(?<![A-Fa-f0-9:.])(?:\d{1,3}\.){3}\d{1,3}(?:/\d{1,2})?"
    r"(?![A-Fa-f0-9:.])"
)
IPV6_RE = re.compile(
    r"(?<![A-Za-z0-9])(?:\[[0-9A-Fa-f:]+\]|"
    r"[0-9A-Fa-f]*:[0-9A-Fa-f:]+)(?:/\d{1,3})?(?![A-Za-z0-9])"
)


class PolicyError(ValueError):
    """Raised when the sanitizer policy is invalid."""


@dataclass(frozen=True)
class DenyTerm:
    rule_id: str
    pattern: re.Pattern[str]
    allow_paths: frozenset[str]
    allow_patterns: tuple[re.Pattern[str], ...]


@dataclass(frozen=True)
class Policy:
    max_text_bytes: int
    max_binary_bytes: int
    synthetic_account_ids: frozenset[str]
    synthetic_fixture_paths: tuple[str, ...]
    synthetic_aws_resource_ids: frozenset[str]
    synthetic_aws_arns: frozenset[str]
    documentation_ipv4_networks: tuple[ipaddress.IPv4Network, ...]
    documentation_ipv6_networks: tuple[ipaddress.IPv6Network, ...]
    deny_term_definition_paths: frozenset[str]
    forbidden_path_globs: tuple[str, ...]
    binary_extensions: frozenset[str]
    deny_terms: tuple[DenyTerm, ...]


@dataclass(frozen=True, order=True)
class Violation:
    path: str
    rule: str
    line: int
    column: int
    message: str


def _require_list(value: Any, field: str) -> list[Any]:
    if not isinstance(value, list):
        raise PolicyError(f"{field} must be a list")
    return value


def load_policy(path: Path) -> Policy:
    """Load and validate a TOML publication policy."""
    try:
        raw = tomllib.loads(path.read_text(encoding="utf-8"))
    except (OSError, tomllib.TOMLDecodeError) as exc:
        raise PolicyError(f"cannot load policy {path}: {exc}") from exc

    if raw.get("version") != 1:
        raise PolicyError("policy version must be 1")

    def string_list(field: str) -> list[str]:
        values = _require_list(raw.get(field), field)
        if not all(isinstance(value, str) and value for value in values):
            raise PolicyError(f"{field} must contain non-empty strings")
        return values

    try:
        ipv4_networks = tuple(
            ipaddress.IPv4Network(value) for value in string_list("documentation_ipv4_networks")
        )
        ipv6_networks = tuple(
            ipaddress.IPv6Network(value) for value in string_list("documentation_ipv6_networks")
        )
    except ValueError as exc:
        raise PolicyError(f"invalid documentation network: {exc}") from exc

    terms: list[DenyTerm] = []
    for index, item in enumerate(_require_list(raw.get("deny_terms"), "deny_terms")):
        if not isinstance(item, Mapping):
            raise PolicyError(f"deny_terms[{index}] must be a table")
        rule_id = item.get("id")
        pattern = item.get("pattern")
        if not isinstance(rule_id, str) or not rule_id:
            raise PolicyError(f"deny_terms[{index}].id must be a non-empty string")
        if not isinstance(pattern, str) or not pattern:
            raise PolicyError(f"deny_terms[{index}].pattern must be a non-empty string")
        try:
            compiled = re.compile(pattern)
            allowed_patterns = tuple(
                re.compile(value)
                for value in _require_list(
                    item.get("allow_patterns", []),
                    f"deny_terms[{index}].allow_patterns",
                )
            )
        except (re.error, TypeError) as exc:
            raise PolicyError(f"invalid regex for {rule_id}: {exc}") from exc
        allowed_paths = _require_list(
            item.get("allow_paths", []), f"deny_terms[{index}].allow_paths"
        )
        if not all(isinstance(value, str) for value in allowed_paths):
            raise PolicyError(f"{rule_id} allow_paths must contain strings")
        terms.append(
            DenyTerm(
                rule_id=rule_id,
                pattern=compiled,
                allow_paths=frozenset(allowed_paths),
                allow_patterns=allowed_patterns,
            )
        )

    max_text_bytes = raw.get("max_text_bytes")
    max_binary_bytes = raw.get("max_binary_bytes")
    if not isinstance(max_text_bytes, int) or max_text_bytes <= 0:
        raise PolicyError("max_text_bytes must be a positive integer")
    if not isinstance(max_binary_bytes, int) or max_binary_bytes <= 0:
        raise PolicyError("max_binary_bytes must be a positive integer")

    return Policy(
        max_text_bytes=max_text_bytes,
        max_binary_bytes=max_binary_bytes,
        synthetic_account_ids=frozenset(string_list("synthetic_account_ids")),
        synthetic_fixture_paths=tuple(string_list("synthetic_fixture_paths")),
        synthetic_aws_resource_ids=frozenset(string_list("synthetic_aws_resource_ids")),
        synthetic_aws_arns=frozenset(string_list("synthetic_aws_arns")),
        documentation_ipv4_networks=ipv4_networks,
        documentation_ipv6_networks=ipv6_networks,
        deny_term_definition_paths=frozenset(string_list("deny_term_definition_paths")),
        forbidden_path_globs=tuple(string_list("forbidden_path_globs")),
        binary_extensions=frozenset(value.lower() for value in string_list("binary_extensions")),
        deny_terms=tuple(terms),
    )


def _line_column(text: str, offset: int) -> tuple[int, int]:
    line = text.count("\n", 0, offset) + 1
    last_newline = text.rfind("\n", 0, offset)
    column = offset + 1 if last_newline < 0 else offset - last_newline
    return line, column


def _masked(text: str, patterns: Iterable[re.Pattern[str]]) -> str:
    masked = text
    for pattern in patterns:
        masked = pattern.sub(lambda match: " " * len(match.group(0)), masked)
    return masked


def _path_matches(path: str, pattern: str) -> bool:
    pure_path = PurePosixPath(path)
    return (
        fnmatch.fnmatchcase(path, pattern)
        or pure_path.match(pattern)
        or ("/" not in pattern and fnmatch.fnmatchcase(pure_path.name, pattern))
    )


class Sanitizer:
    """Scan repository files against publication policy."""

    def __init__(self, root: Path, policy: Policy) -> None:
        self.root = root.resolve()
        self.policy = policy

    def _violation(
        self,
        path: str,
        rule: str,
        message: str,
        text: str = "",
        offset: int = 0,
    ) -> Violation:
        line, column = _line_column(text, offset) if text else (0, 0)
        return Violation(path, rule, line, column, message)

    def _scan_matches(
        self,
        path: str,
        text: str,
        rule: str,
        pattern: re.Pattern[str],
        message: str,
        allowed_values: frozenset[str] = frozenset(),
    ) -> list[Violation]:
        return [
            self._violation(path, rule, message, text, match.start())
            for match in pattern.finditer(text)
            if match.group(0) not in allowed_values
        ]

    def _scan_internal_terms(self, path: str, text: str) -> list[Violation]:
        if any(_path_matches(path, pattern) for pattern in self.policy.deny_term_definition_paths):
            return []
        violations: list[Violation] = []
        for term in self.policy.deny_terms:
            if any(_path_matches(path, pattern) for pattern in term.allow_paths):
                continue
            candidate = _masked(text, term.allow_patterns)
            violations.extend(
                (
                    self._violation(
                        path,
                        f"internal-term:{term.rule_id}",
                        f"content matches denied term policy {term.rule_id}",
                        text,
                        match.start(),
                    )
                )
                for match in term.pattern.finditer(candidate)
            )
        return violations

    def _synthetic_fixture_values(self, path: str, values: frozenset[str]) -> frozenset[str]:
        if any(_path_matches(path, pattern) for pattern in self.policy.synthetic_fixture_paths):
            return values
        return frozenset()

    def _scan_addresses(self, path: str, text: str) -> list[Violation]:
        violations: list[Violation] = []
        occupied: list[tuple[int, int]] = []

        for match in IPV4_RE.finditer(text):
            token = match.group(0)
            try:
                address = (
                    ipaddress.ip_interface(token).ip
                    if "/" in token
                    else ipaddress.ip_address(token)
                )
            except ValueError:
                continue
            occupied.append(match.span())
            public_unicast = address.is_global and not (
                address.is_multicast or address.is_reserved or address.is_unspecified
            )
            if public_unicast and not any(
                address in network for network in self.policy.documentation_ipv4_networks
            ):
                violations.append(
                    self._violation(
                        path,
                        "public-ipv4",
                        "non-documentation public IPv4 address",
                        text,
                        match.start(),
                    )
                )

        for match in IPV6_RE.finditer(text):
            if any(start <= match.start() < end for start, end in occupied):
                continue
            token = match.group(0)
            if token.startswith("["):
                close = token.find("]")
                address_token = token[1:close]
                suffix = token[close + 1 :]
                token = address_token + suffix
            try:
                address = (
                    ipaddress.ip_interface(token).ip
                    if "/" in token
                    else ipaddress.ip_address(token)
                )
            except ValueError:
                continue
            public_unicast = address.is_global and not (
                address.is_multicast or address.is_reserved or address.is_unspecified
            )
            if public_unicast and not any(
                address in network for network in self.policy.documentation_ipv6_networks
            ):
                violations.append(
                    self._violation(
                        path,
                        "public-ipv6",
                        "non-documentation public IPv6 address",
                        text,
                        match.start(),
                    )
                )
        return violations

    def _scan_text(self, path: str, text: str) -> list[Violation]:
        violations = self._scan_internal_terms(path, text)
        violations.extend(
            self._scan_matches(
                path,
                text,
                "aws-account-id",
                ACCOUNT_ID_RE,
                "12-digit account ID is not an exact synthetic fixture",
                self.policy.synthetic_account_ids,
            )
        )
        violations.extend(
            self._scan_matches(
                path,
                text,
                "aws-arn",
                AWS_ARN_RE,
                "AWS ARN is not public-safe",
                self._synthetic_fixture_values(path, self.policy.synthetic_aws_arns),
            )
        )
        violations.extend(
            self._scan_matches(
                path,
                text,
                "aws-resource-id",
                AWS_RESOURCE_ID_RE,
                "AWS resource ID is not public-safe",
                self._synthetic_fixture_values(path, self.policy.synthetic_aws_resource_ids),
            )
        )
        violations.extend(
            self._scan_matches(
                path,
                text,
                "absolute-home-path",
                UNIX_HOME_RE,
                "absolute home-directory path",
            )
        )
        violations.extend(
            self._scan_matches(
                path,
                text,
                "absolute-home-path",
                WINDOWS_HOME_RE,
                "absolute home-directory path",
            )
        )
        violations.extend(self._scan_matches(path, text, "email", EMAIL_RE, "email address or PII"))
        violations.extend(self._scan_matches(path, text, "pii-ssn", US_SSN_RE, "possible US SSN"))
        violations.extend(
            self._scan_matches(path, text, "pii-phone", US_PHONE_RE, "possible phone number")
        )
        violations.extend(self._scan_addresses(path, text))

        private_key_markers = (
            "-----BEGIN " + "PRIVATE KEY-----",
            "-----BEGIN EC " + "PRIVATE KEY-----",
            "-----BEGIN OPENSSH " + "PRIVATE KEY-----",
            "-----BEGIN PGP " + "PRIVATE KEY BLOCK-----",
            "-----BEGIN RSA " + "PRIVATE KEY-----",
        )
        for marker in private_key_markers:
            offset = text.find(marker)
            if offset >= 0:
                violations.append(
                    self._violation(
                        path,
                        "private-key",
                        "private key material",
                        text,
                        offset,
                    )
                )

        kubeconfig_markers = (
            re.search(r"(?m)^kind:\s*Config\s*$", text),
            re.search(r"(?m)^clusters:\s*$", text),
            re.search(r"(?m)^contexts:\s*$", text),
            re.search(r"(?m)^users:\s*$", text),
        )
        if all(kubeconfig_markers):
            first = next(marker for marker in kubeconfig_markers if marker is not None)
            violations.append(
                self._violation(
                    path,
                    "kubeconfig-content",
                    "file appears to contain a kubeconfig",
                    text,
                    first.start(),
                )
            )

        return violations

    def scan_path(self, path: Path, relative_path: str) -> list[Violation]:
        """Scan one repository-relative path."""
        relative_path = PurePosixPath(relative_path).as_posix()
        violations: list[Violation] = []

        if any(
            _path_matches(relative_path, pattern) for pattern in self.policy.forbidden_path_globs
        ):
            violations.append(
                self._violation(
                    relative_path,
                    "forbidden-path",
                    "state, variable, key, kubeconfig, environment, or slide file",
                )
            )

        if path.is_symlink():
            resolved = path.resolve(strict=False)
            try:
                resolved.relative_to(self.root)
            except ValueError:
                violations.append(
                    self._violation(
                        relative_path,
                        "escaping-symlink",
                        "symlink resolves outside repository",
                    )
                )
                return violations
            if not resolved.exists():
                violations.append(
                    self._violation(
                        relative_path, "broken-symlink", "symlink target does not exist"
                    )
                )
                return violations
        elif not path.exists():
            return violations

        if not path.is_file():
            return violations

        try:
            size = path.stat().st_size
            with path.open("rb") as handle:
                prefix = handle.read(8192)
        except OSError as exc:
            violations.append(
                self._violation(relative_path, "unreadable-file", f"cannot read file: {exc}")
            )
            return violations

        known_binary = path.suffix.lower() in self.policy.binary_extensions
        binary = known_binary or b"\0" in prefix
        if not binary:
            try:
                prefix.decode("utf-8")
            except UnicodeDecodeError:
                binary = True

        if binary:
            if size > self.policy.max_binary_bytes:
                violations.append(
                    self._violation(
                        relative_path,
                        "oversized-binary",
                        f"binary exceeds {self.policy.max_binary_bytes} bytes",
                    )
                )
            return violations

        if size > self.policy.max_text_bytes:
            violations.append(
                self._violation(
                    relative_path,
                    "oversized-text",
                    f"text file exceeds {self.policy.max_text_bytes} bytes",
                )
            )
            return violations

        try:
            text = path.read_text(encoding="utf-8")
        except (OSError, UnicodeDecodeError) as exc:
            violations.append(
                self._violation(relative_path, "unreadable-text", f"cannot decode file: {exc}")
            )
            return violations
        violations.extend(self._scan_text(relative_path, text))
        return violations

    def scan(self, relative_paths: Iterable[str]) -> list[Violation]:
        """Scan an iterable of repository-relative paths."""
        violations: list[Violation] = []
        for relative_path in sorted(set(relative_paths)):
            normalized = PurePosixPath(relative_path).as_posix()
            if (
                normalized == "."
                or PurePosixPath(normalized).is_absolute()
                or normalized.startswith("../")
            ):
                violations.append(
                    self._violation(
                        normalized,
                        "path-escape",
                        "repository file path escapes root",
                    )
                )
                continue
            violations.extend(self.scan_path(self.root / normalized, normalized))
        return sorted(set(violations))


def git_paths(root: Path, working_tree: bool) -> list[str]:
    """Return tracked paths, optionally including untracked non-ignored files."""
    command = ["git", "-C", str(root), "ls-files", "-z", "--cached"]
    if working_tree:
        command.extend(["--others", "--exclude-standard"])
    try:
        result = subprocess.run(command, check=True, capture_output=True)
    except FileNotFoundError as exc:
        raise RuntimeError("git is required") from exc
    except subprocess.CalledProcessError as exc:
        detail = exc.stderr.decode("utf-8", errors="replace").strip()
        raise RuntimeError(f"git ls-files failed: {detail}") from exc
    return [os.fsdecode(entry) for entry in result.stdout.split(b"\0") if entry]


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description=("scan Git-tracked repository files for sensitive publication content")
    )
    parser.add_argument(
        "--root",
        type=Path,
        default=Path(__file__).resolve().parents[1],
        help="repository root (defaults to the sanitizer's repository)",
    )
    parser.add_argument(
        "--policy",
        type=Path,
        help="policy path, relative to root unless absolute",
    )
    parser.add_argument(
        "--working-tree",
        action="store_true",
        help="also scan untracked, non-ignored working-tree files",
    )
    parser.add_argument("--format", choices=("text", "json"), default="text", help="output format")
    parser.add_argument("--quiet", action="store_true", help="omit success output")
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    root = args.root.resolve()
    policy_path = args.policy or Path("tools/sanitize-policy.toml")
    if not policy_path.is_absolute():
        policy_path = root / policy_path

    try:
        policy = load_policy(policy_path)
        paths = git_paths(root, args.working_tree)
        violations = Sanitizer(root, policy).scan(paths)
    except (PolicyError, RuntimeError) as exc:
        print(f"sanitizer error: {exc}", file=sys.stderr)
        return 2

    if args.format == "json":
        print(json.dumps([asdict(item) for item in violations], indent=2))
    elif violations:
        for item in violations:
            location = item.path
            if item.line:
                location += f":{item.line}:{item.column}"
            print(f"{location}: {item.rule}: {item.message}")
    elif not args.quiet:
        mode = "tracked and working-tree" if args.working_tree else "tracked"
        print(f"sanitizer: {len(paths)} {mode} files passed")

    return 1 if violations else 0


if __name__ == "__main__":
    raise SystemExit(main())
