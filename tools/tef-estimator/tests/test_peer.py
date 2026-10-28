"""Tests for peer percentile computation."""

from pathlib import Path

import pytest

from tef_estimator.data.common import Geography, RevenueBand, Sector
from tef_estimator.engine import TEFEngine
from tef_estimator.peer import (
    build_grid,
    compute_and_set_percentile,
    load_grid,
    percentile,
)
from tef_estimator.profile import OrganizationProfile


@pytest.fixture
def engine():
    return TEFEngine()


@pytest.fixture
def small_grid():
    """A pre-built grid with known values for testing."""
    return {
        "100m_1b": [0.005, 0.010, 0.015, 0.020, 0.025, 0.030, 0.035, 0.040],
        "10m_100m": [0.003, 0.006, 0.009, 0.012, 0.015, 0.018],
    }


class TestPercentile:
    def test_lowest_value(self, small_grid):
        pct = percentile(0.001, small_grid, RevenueBand.R_100M_1B)
        assert pct == 0

    def test_highest_value(self, small_grid):
        pct = percentile(0.050, small_grid, RevenueBand.R_100M_1B)
        assert pct == 100

    def test_missing_band_returns_50(self, small_grid):
        pct = percentile(0.01, small_grid, RevenueBand.R_1B_10B)
        assert pct == 50

class TestGridIO:
    def test_load_missing_returns_none(self):
        path = Path("/tmp/nonexistent_grid_xyz123.json")
        assert load_grid(path) is None


class TestBuildGrid:
    def test_grid_covers_all_bands(self, engine):
        grid = build_grid(engine)
        for band in RevenueBand:
            assert band.value in grid
            assert len(grid[band.value]) > 0

class TestComputeAndSetPercentile:
    def test_sets_percentile(self, engine, small_grid):
        profile = OrganizationProfile(
            sector=Sector.MANUFACTURING,
            revenue_band=RevenueBand.R_100M_1B,
            geography=Geography.US,
        )
        result = engine.estimate(profile)
        compute_and_set_percentile(result, RevenueBand.R_100M_1B, small_grid)
        assert result.peer_percentile is not None
        assert 0 <= result.peer_percentile <= 100
        assert result.peer_context is not None
