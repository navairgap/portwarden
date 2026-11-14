"""Packaging conformance: version, metadata, and entry points."""

from __future__ import annotations

import importlib.metadata
import re
import tomllib
from pathlib import Path

import portwarden

PROJECT_ROOT = Path(__file__).parent.parent


def declared_version() -> str:
    pyproject = tomllib.loads((PROJECT_ROOT / "pyproject.toml").read_text("utf-8"))
    return pyproject["project"]["version"]


class VersionTests:
    def test_package_and_project_versions_match(self):
        assert portwarden.__version__ == declared_version()

    def test_installed_distribution_reports_the_same_version(self):
        # The test environment installs the project; its metadata must
        # agree with the source tree, or a release would ship stale data.
        installed = importlib.metadata.version("portwarden")
        assert installed == declared_version()

    def test_version_is_a_clean_semver(self):
        assert re.fullmatch(r"\d+\.\d+\.\d+", declared_version())

    def test_public_api_is_importable_from_the_package_root(self):
        for name in portwarden.__all__:
            assert getattr(portwarden, name) is not None
