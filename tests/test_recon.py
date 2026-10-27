"""
Leadline - Recon Engine Tests
Phase 10: Tests + Docker
"""
import pytest
from app.recon.base import BaseReconPhase


class MockPhase(BaseReconPhase):
    """Mock phase for testing."""
    name = "mock_phase"
    order = 1
    description = "Mock phase for testing"

    async def execute(self):
        return {"test": "result"}


def test_base_phase_initialization():
    """Test base phase initialization."""
    phase = MockPhase("http://test.local", {})
    assert phase.target_url == "http://test.local"
    assert phase.context == {}
    assert phase.name == "mock_phase"
    assert phase.order == 1


@pytest.mark.asyncio
async def test_base_phase_run():
    """Test base phase run method."""
    phase = MockPhase("http://test.local", {})
    result = await phase.run()

    assert result["phase_name"] == "mock_phase"
    assert result["phase_order"] == 1
    assert result["status"] == "completed"
    assert result["result_data"] == {"test": "result"}


def test_add_finding():
    """Test adding findings."""
    phase = MockPhase("http://test.local", {})
    phase.add_finding(
        finding_type="endpoint",
        title="Test Finding",
        severity="medium",
        location="/test"
    )

    assert len(phase.findings) == 1
    assert phase.findings[0]["title"] == "Test Finding"
    assert phase.findings[0]["severity"] == "medium"
