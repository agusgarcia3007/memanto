"""Daily reports must retain the confidentiality of their source memories."""

import json
import os
import stat
from pathlib import Path
from unittest.mock import MagicMock

import pytest

from memanto.app.services import daily_analysis_service as module

pytestmark = pytest.mark.skipif(os.name == "nt", reason="POSIX permissions required")


@pytest.fixture
def service(tmp_path, monkeypatch):
    """Isolate reports and backend calls under a typical permissive POSIX umask."""
    sessions = tmp_path / "sessions"
    sessions.mkdir(mode=0o700)
    session = sessions / "agent-1_2026-10-10_001_summary.md"
    session.write_text("Private project memory", encoding="utf-8")
    session.chmod(0o600)
    monkeypatch.setattr(module, "get_session_service", MagicMock())
    monkeypatch.setattr("memanto.app.config.get_data_dir", lambda: tmp_path)
    client = MagicMock()
    client.answer.generate.return_value = {"answer": "# Private daily summary"}
    monkeypatch.setattr(module, "get_moorcheh_client", lambda: client)
    monkeypatch.setattr(module, "get_active_llm_model", lambda _: None)
    monkeypatch.setattr(module, "get_active_embedding_model", lambda: None)
    monkeypatch.setattr(
        "memanto.app.services.summary_visualization_service."
        "SummaryVisualizationService.append_visualizations_to_summary",
        lambda *args, **kwargs: None,
    )
    previous_umask = os.umask(0o022)
    try:
        yield module.DailyAnalysisService(sessions, tmp_path / "summaries")
    finally:
        os.umask(previous_umask)


@pytest.mark.parametrize("existing", [False, True])
@pytest.mark.parametrize("custom_output", [False, True])
def test_daily_summary_is_owner_only(service, tmp_path, existing, custom_output):
    """New and replaced summaries stay private at default and custom paths."""
    path = (
        tmp_path / "custom.md"
        if custom_output
        else service.summaries_dir / "agent-1_2026-10-10.md"
    )
    if existing:
        path.write_text("previous summary", encoding="utf-8")
        path.chmod(0o644)

    result = service.generate_summary(
        "agent-1", "2026-10-10", str(path) if custom_output else None
    )

    assert result["status"] == "success"
    assert Path(result["summary_path"]) == path
    assert path.read_text(encoding="utf-8") == "# Private daily summary"
    assert stat.S_IMODE(path.stat().st_mode) == 0o600


@pytest.mark.parametrize("existing", [False, True])
def test_conflict_report_is_owner_only(service, tmp_path, existing):
    """Saving conflict JSON preserves its contents with owner-only access."""
    path = tmp_path / "conflicts" / "agent-1_2026-10-10_conflicts.json"
    if existing:
        path.parent.mkdir()
        path.write_text("[]", encoding="utf-8")
        path.chmod(0o644)
    conflicts = [{"old_content": "Private old fact", "new_content": "معلومة خاصة"}]

    result = service._save_conflict_report("agent-1", "2026-10-10", conflicts)

    assert result["conflict_count"] == 1
    assert json.loads(path.read_text(encoding="utf-8")) == conflicts
    assert stat.S_IMODE(path.stat().st_mode) == 0o600


def test_serialization_failure_preserves_previous_conflict_report(service, tmp_path):
    """Failed serialization must not truncate or replace a valid report."""

    class Unserializable:
        """Inject a failure in the JSON encoder's string fallback."""

        def __str__(self):
            """Fail deterministically before the report can be published."""
            raise ValueError("serialization failed")

    path = tmp_path / "conflicts" / "agent-1_2026-10-10_conflicts.json"
    path.parent.mkdir()
    path.write_text('[{"old_content": "previous report"}]', encoding="utf-8")
    previous = path.read_bytes()

    with pytest.raises(ValueError, match="serialization failed"):
        service._save_conflict_report(
            "agent-1", "2026-10-10", [{"old_content": Unserializable()}]
        )

    assert path.read_bytes() == previous
    assert list(path.parent.iterdir()) == [path]
