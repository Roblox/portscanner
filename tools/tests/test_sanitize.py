# SPDX-FileCopyrightText: 2026 Portscanner contributors
# SPDX-License-Identifier: MIT

from __future__ import annotations

import subprocess
import tempfile
import unittest
from pathlib import Path

from tools.sanitize import Sanitizer, git_paths, load_policy

POLICY_PATH = Path(__file__).resolve().parents[1] / "sanitize-policy.toml"


class SanitizerTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary_directory = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary_directory.name)
        self.policy = load_policy(POLICY_PATH)
        self.sanitizer = Sanitizer(self.root, self.policy)

    def tearDown(self) -> None:
        self.temporary_directory.cleanup()

    def write(self, relative_path: str, content: str | bytes) -> Path:
        path = self.root / relative_path
        path.parent.mkdir(parents=True, exist_ok=True)
        if isinstance(content, bytes):
            path.write_bytes(content)
        else:
            path.write_text(content, encoding="utf-8")
        return path

    def rules(self, content: str, relative_path: str = "sample.md") -> set[str]:
        path = self.write(relative_path, content)
        return {violation.rule for violation in self.sanitizer.scan_path(path, relative_path)}

    def test_allows_documentation_addresses_and_public_project_url(self) -> None:
        content = "\n".join(
            [
                "192.0.2.10",
                "198.51.100.20/32",
                "203.0.113.0/24",
                "2001:db8::10",
                "https://github.com/Roblox/portscanner/security/advisories/new",
            ]
        )
        self.assertEqual(self.rules(content), set())

    def test_public_owner_exception_is_narrow(self) -> None:
        owner = "Rob" + "lox"
        self.assertNotIn("internal-term:public-owner-name", self.rules(owner, "LICENSE"))
        self.assertIn("internal-term:public-owner-name", self.rules(owner))

    def test_allows_exact_public_legal_attribution(self) -> None:
        owner = "Rob" + "lox"
        header = f"SPDX-FileCopyrightText: 2026 {owner}\n"
        self.assertNotIn("internal-term:public-owner-name", self.rules(header))

    def test_rejects_internal_domains_and_terms(self) -> None:
        internal_domain = "service" + "." + "internal"
        internal_term = "net" + "sec"
        rules = self.rules(f"{internal_domain}\n{internal_term}\n")
        self.assertIn("internal-term:internal-domain", rules)
        self.assertIn("internal-term:internal-project-term", rules)

    def test_policy_definition_only_suppresses_deny_terms(self) -> None:
        term = "net" + "sec"
        address = "person" + "@" + "example.com"
        rules = self.rules(f"{term} {address}", "tools/sanitize-policy.toml")
        self.assertNotIn("internal-term:internal-project-term", rules)
        self.assertIn("email", rules)

    def test_account_id_requires_exact_synthetic_fixture(self) -> None:
        synthetic = "123456" + "789012"
        other = "987654" + "321098"
        self.assertNotIn("aws-account-id", self.rules(synthetic))
        self.assertIn("aws-account-id", self.rules(other))

    def test_account_digits_inside_hash_are_not_an_account_id(self) -> None:
        digest = "abc" + ("987654" + "321098") + "def"
        self.assertNotIn("aws-account-id", self.rules(digest))

    def test_rejects_aws_arns_and_resource_ids(self) -> None:
        arn = (
            "arn"
            + ":"
            + "aws"
            + ":"
            + "iam"
            + "::"
            + ("123456" + "789012")
            + ":"
            + "role/synthetic"
        )
        resource_id = "vpc" + "-" + "0123456789abcdef0"
        rules = self.rules(f"{arn}\n{resource_id}\n")
        self.assertIn("aws-arn", rules)
        self.assertIn("aws-resource-id", rules)

    def test_exact_cloud_fixtures_are_path_scoped(self) -> None:
        resource_id = "vpc" + "-" + "0123456789abcdef0"
        arn = (
            "arn"
            + ":"
            + "aws"
            + ":"
            + "iam"
            + "::"
            + ("123456" + "789012")
            + ":"
            + "role/example-central-collector"
        )
        rules = self.rules(
            f"{resource_id}\n{arn}\n",
            "terraform/aws/examples/synthetic/main.tf",
        )
        self.assertNotIn("aws-resource-id", rules)
        self.assertNotIn("aws-arn", rules)

    def test_rejects_home_paths_and_personal_data(self) -> None:
        home = "/" + "Users" + "/" + "alice" + "/" + "project"
        email = "alice" + "@" + "example.com"
        ssn = "321" + "-" + "54" + "-" + "9876"
        phone = "415" + "-" + "555" + "-" + "0123"
        rules = self.rules("\n".join((home, email, ssn, phone)))
        self.assertIn("absolute-home-path", rules)
        self.assertIn("email", rules)
        self.assertIn("pii-ssn", rules)
        self.assertIn("pii-phone", rules)

    def test_database_uri_userinfo_is_not_an_email(self) -> None:
        dsn = "postgresql://user:password" + "@" + "db.example/test"
        self.assertNotIn("email", self.rules(dsn))

    def test_rejects_non_documentation_public_addresses(self) -> None:
        ipv4 = "8" + "." + "8" + "." + "8" + "." + "8"
        ipv6 = "2606" + ":" + "4700" + ":" + "4700" + "::" + "1111"
        rules = self.rules(f"{ipv4}\n{ipv6}\n")
        self.assertIn("public-ipv4", rules)
        self.assertIn("public-ipv6", rules)

    def test_allows_non_public_local_addresses(self) -> None:
        loopback = "127" + "." + "0" + "." + "0" + "." + "1"
        private = "10" + "." + "0" + "." + "0" + "." + "1"
        self.assertEqual(self.rules(f"{loopback}\n{private}\n"), set())

    def test_rejects_sensitive_file_paths(self) -> None:
        path = self.write("deployment/live.tfvars", "dispatch_enabled = false\n")
        rules = {
            violation.rule for violation in self.sanitizer.scan_path(path, "deployment/live.tfvars")
        }
        self.assertIn("forbidden-path", rules)
        json_path = self.write("deployment/live.tfvars.json", "{}\n")
        json_rules = {
            violation.rule
            for violation in self.sanitizer.scan_path(json_path, "deployment/live.tfvars.json")
        }
        self.assertIn("forbidden-path", json_rules)

    def test_rejects_oversized_binary(self) -> None:
        content = b"\0" + b"x" * self.policy.max_binary_bytes
        path = self.write("artifact.bin", content)
        rules = {violation.rule for violation in self.sanitizer.scan_path(path, "artifact.bin")}
        self.assertIn("oversized-binary", rules)

    def test_rejects_escaping_symlink(self) -> None:
        with tempfile.TemporaryDirectory() as outside_directory:
            outside = Path(outside_directory) / "outside.txt"
            outside.write_text("synthetic\n", encoding="utf-8")
            link = self.root / "link.txt"
            link.symlink_to(outside)
            rules = {violation.rule for violation in self.sanitizer.scan_path(link, "link.txt")}
        self.assertIn("escaping-symlink", rules)

    def test_rejects_private_key_content(self) -> None:
        marker = "-----BEGIN " + "PRIVATE KEY-----"
        self.assertIn("private-key", self.rules(marker + "\nsynthetic\n"))

    def test_rejects_kubeconfig_content(self) -> None:
        content = "\n".join(
            (
                "apiVersion: v1",
                "kind: Config",
                "clusters:",
                "contexts:",
                "users:",
            )
        )
        self.assertIn("kubeconfig-content", self.rules(content))

    def test_git_path_modes(self) -> None:
        subprocess.run(
            ["git", "init", "--quiet", str(self.root)],
            check=True,
            capture_output=True,
        )
        self.write("tracked.txt", "tracked\n")
        self.write("untracked.txt", "untracked\n")
        subprocess.run(
            ["git", "-C", str(self.root), "add", "tracked.txt"],
            check=True,
            capture_output=True,
        )

        self.assertEqual(git_paths(self.root, working_tree=False), ["tracked.txt"])
        self.assertEqual(
            sorted(git_paths(self.root, working_tree=True)),
            ["tracked.txt", "untracked.txt"],
        )


if __name__ == "__main__":
    unittest.main()
