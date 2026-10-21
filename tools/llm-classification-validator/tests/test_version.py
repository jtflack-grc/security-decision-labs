"""__version__ follows the running code, not a hardcoded literal (cf. tef-estimator issue #2)."""
import importlib.metadata
from pathlib import Path

import llm_classification_validator as lcv

REPO = Path(__file__).resolve().parents[1]


class TestVersion:
    def test_version_matches_pyproject(self):
        # In a source tree, the tree's own pyproject wins — even over the
        # metadata of an older or stale install shadowing it.
        text = (REPO / "pyproject.toml").read_text()
        assert f'version = "{lcv.__version__}"' in text

    def test_version_falls_back_to_metadata_without_pyproject(self, monkeypatch, tmp_path):
        # Wheel installs have no pyproject above the package.
        monkeypatch.setattr(lcv, "__file__", str(tmp_path / "x" / "y" / "z" / "__init__.py"))
        try:
            expected = importlib.metadata.version("llm-classification-validator")
        except importlib.metadata.PackageNotFoundError:
            expected = "0+unknown"
        assert lcv._resolve_version() == expected

    def test_version_unknown_without_pyproject_or_metadata(self, monkeypatch, tmp_path):
        monkeypatch.setattr(lcv, "__file__", str(tmp_path / "x" / "y" / "z" / "__init__.py"))
        monkeypatch.setattr(
            lcv,
            "_package_version",
            lambda name: (_ for _ in ()).throw(importlib.metadata.PackageNotFoundError()),
        )
        assert lcv._resolve_version() == "0+unknown"

    def test_no_version_literal_in_source(self):
        src = (REPO / "src" / "llm_classification_validator" / "__init__.py").read_text()
        assert '__version__ = "' not in src
