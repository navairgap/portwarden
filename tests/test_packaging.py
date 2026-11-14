"""Packaging conformance: version, metadata, and entry points."""

from __future__ import annotations

import importlib.metadata
import re
from pathlib import Path

import portwarden

PROJECT_ROOT = Path(__file__).parent.parent

# tomllib is Python 3.11+, and the project supports 3.10; the version line
# is the single top-level `version = "..."` assignment in pyproject.toml.
_VERSION_RE = re.compile(r'^version = "([^"]+)"$', re.MULTILINE)


def declared_version() -> str:
    """The version declared in pyproject.toml's [project] table."""
    text = (PROJECT_ROOT / "pyproject.toml").read_text(encoding="utf-8")
    matches = _VERSION_RE.findall(text)
    assert len(matches) == 1, "pyproject.toml must declare exactly one version"
    return matches[0]


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
