"""
Unit Tests for Project Castor Centralized GitHub Identity Resolver
and Dynamic Workload Identity Federation Parameterization.
"""

import os
import unittest
from unittest.mock import patch

from shared.github_identity import (
    SERVERLESS_GIT_NAMESPACE,
    GitHubOwnerNotConfiguredError,
    get_default_github_owner,
    resolve_repo_identity,
)


class TestGitHubIdentityResolver(unittest.TestCase):
    def test_https_urls(self):
        owner, repo, full = resolve_repo_identity("https://github.com/AcmeCorp/payment-gateway")
        self.assertEqual(owner, "AcmeCorp")
        self.assertEqual(repo, "payment-gateway")
        self.assertEqual(full, "AcmeCorp/payment-gateway")

        # With .git suffix and trailing slash
        owner, repo, full = resolve_repo_identity("https://github.com/AcmeCorp/payment-gateway.git/")
        self.assertEqual(owner, "AcmeCorp")
        self.assertEqual(repo, "payment-gateway")
        self.assertEqual(full, "AcmeCorp/payment-gateway")

    def test_ssh_urls(self):
        owner, repo, full = resolve_repo_identity("git@github.com:AcmeCorp/payment-gateway.git")
        self.assertEqual(owner, "AcmeCorp")
        self.assertEqual(repo, "payment-gateway")
        self.assertEqual(full, "AcmeCorp/payment-gateway")

        owner, repo, full = resolve_repo_identity("git@github.com:AcmeCorp/payment-gateway")
        self.assertEqual(owner, "AcmeCorp")
        self.assertEqual(repo, "payment-gateway")
        self.assertEqual(full, "AcmeCorp/payment-gateway")

    def test_shorthand_notation(self):
        owner, repo, full = resolve_repo_identity("AcmeCorp/payment-gateway")
        self.assertEqual(owner, "AcmeCorp")
        self.assertEqual(repo, "payment-gateway")
        self.assertEqual(full, "AcmeCorp/payment-gateway")

        # Shorthand with leading/trailing slashes or .git
        owner, repo, full = resolve_repo_identity("/AcmeCorp/payment-gateway.git")
        self.assertEqual(owner, "AcmeCorp")
        self.assertEqual(repo, "payment-gateway")
        self.assertEqual(full, "AcmeCorp/payment-gateway")

    def test_bare_repo_name_with_custom_default(self):
        owner, repo, full = resolve_repo_identity("payment-gateway", default_owner="CustomOrg")
        self.assertEqual(owner, "CustomOrg")
        self.assertEqual(repo, "payment-gateway")
        self.assertEqual(full, "CustomOrg/payment-gateway")

    def test_empty_with_product_id(self):
        owner, repo, full = resolve_repo_identity(None, default_owner="AcmeCorp", product_id="My_Workload")
        self.assertEqual(owner, "AcmeCorp")
        self.assertEqual(repo, "my-workload")   # GITHUB-REPO-NAME-NO-PREFIX
        self.assertEqual(full, "AcmeCorp/my-workload")

    def test_dict_input(self):
        # When passed a dictionary from GitHub API or Firestore
        dict_input = {"full_name": "AcmeCorp/billing-svc", "repo_name": "billing-svc"}
        owner, repo, full = resolve_repo_identity(dict_input)
        self.assertEqual(owner, "AcmeCorp")
        self.assertEqual(repo, "billing-svc")
        self.assertEqual(full, "AcmeCorp/billing-svc")

    def test_default_owner_precedence(self):
        # 1. FD-4AY: no built-in owner. GitHub (the default VCS) fails loudly; other VCS providers keep the legacy
        #    neutral Serverless Git namespace (never the platform owner's organization; owner 10-26).
        with patch.dict(os.environ, {}, clear=True):
            with self.assertRaises(GitHubOwnerNotConfiguredError):
                get_default_github_owner()
        with patch.dict(os.environ, {"VCS_PROVIDER": "github"}, clear=True):
            with self.assertRaises(GitHubOwnerNotConfiguredError):
                get_default_github_owner()
        with patch.dict(os.environ, {"VCS_PROVIDER": "SERVERLESS_GIT"}, clear=True):
            self.assertEqual(get_default_github_owner(), SERVERLESS_GIT_NAMESPACE)

        # 2. GITHUB_OWNER set
        with patch.dict(os.environ, {"GITHUB_OWNER": "PersonalOwner"}, clear=True):
            self.assertEqual(get_default_github_owner(), "PersonalOwner")

        # 3. GITHUB_DEPLOYMENTS_ORG takes precedence over GITHUB_OWNER
        with patch.dict(os.environ, {"GITHUB_OWNER": "PersonalOwner", "GITHUB_DEPLOYMENTS_ORG": "DeploymentsOrg"}, clear=True):
            self.assertEqual(get_default_github_owner(), "DeploymentsOrg")

        # 4. GITHUB_ORG takes top precedence
        with patch.dict(os.environ, {"GITHUB_OWNER": "PersonalOwner", "GITHUB_DEPLOYMENTS_ORG": "DeploymentsOrg", "GITHUB_ORG": "TopOrg"}, clear=True):
            self.assertEqual(get_default_github_owner(), "TopOrg")

    def test_serverless_namespace_can_never_be_a_github_account(self):
        # FD-4AY (owner 10-26): the workload-foundation WIF provider trusts GitHub OIDC tokens for
        # '<owner>/<id>', so the Serverless Git fallback owner must be a name GitHub can never issue
        # (GitHub account names: 1-39 of [A-Za-z0-9] or single inner hyphens). It is also a valid GCP label value.
        import re
        github_account = re.compile(r"[A-Za-z0-9](?:[A-Za-z0-9]|-(?=[A-Za-z0-9])){0,38}")
        self.assertIsNone(github_account.fullmatch(SERVERLESS_GIT_NAMESPACE))
        self.assertIsNotNone(re.fullmatch(r"[a-z][a-z0-9_-]{0,62}", SERVERLESS_GIT_NAMESPACE))
        with patch.dict(os.environ, {"VCS_PROVIDER": "SERVERLESS_GIT"}, clear=True):
            self.assertEqual(resolve_repo_identity(None, product_id="My_App"),
                             (SERVERLESS_GIT_NAMESPACE, "my-app", f"{SERVERLESS_GIT_NAMESPACE}/my-app"))

    def test_stored_owner_is_kept_on_serverless_installs(self):
        # An existing record that already names an owner keeps it: the namespace is only a fallback.
        with patch.dict(os.environ, {"VCS_PROVIDER": "SERVERLESS_GIT"}, clear=True):
            self.assertEqual(resolve_repo_identity("example-org/castor-x"),
                             ("example-org", "castor-x", "example-org/castor-x"))
        with patch.dict(os.environ, {"VCS_PROVIDER": "SERVERLESS_GIT", "GITHUB_ORG": "example-org"}, clear=True):
            self.assertEqual(get_default_github_owner(), "example-org")

    def test_identifiers_with_an_owner_never_need_the_configured_owner(self):
        # FD-4AY: the owner fallback is resolved lazily, so full identifiers work on an unconfigured install.
        with patch.dict(os.environ, {}, clear=True):
            self.assertEqual(resolve_repo_identity("AcmeCorp/svc"), ("AcmeCorp", "svc", "AcmeCorp/svc"))
            self.assertEqual(resolve_repo_identity("https://github.com/AcmeCorp/svc.git")[2], "AcmeCorp/svc")
            self.assertEqual(resolve_repo_identity("git@github.com:AcmeCorp/svc.git")[2], "AcmeCorp/svc")
            self.assertEqual(resolve_repo_identity("svc", default_owner="Explicit")[2], "Explicit/svc")
            with self.assertRaises(GitHubOwnerNotConfiguredError):
                resolve_repo_identity("svc")
            with self.assertRaises(GitHubOwnerNotConfiguredError):
                resolve_repo_identity(None, product_id="my_app")

    def test_configured_owner_is_used_unchanged(self):
        with patch.dict(os.environ, {"GITHUB_ORG": "example-org"}, clear=True):
            self.assertEqual(resolve_repo_identity(None, product_id="My_App")[2], "example-org/my-app")
            self.assertEqual(resolve_repo_identity("svc")[2], "example-org/svc")


if __name__ == "__main__":
    unittest.main()
