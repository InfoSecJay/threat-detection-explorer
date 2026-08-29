"""/api/query/event-ids -- the event-ID dictionary the UI labels with."""

from fastapi.testclient import TestClient

from app.main import app

client = TestClient(app)


def test_event_id_dictionary_endpoint():
    response = client.get("/api/query/event-ids")
    assert response.status_code == 200
    data = response.json()["event_ids"]
    assert len(data) >= 200
    assert data["4688"] == {
        "label": "Process created",
        "provider": "windows_security",
        "channel": "Security",
        "event_types": ["process_creation"],
    }
    # Every entry has the full shape the frontend types expect.
    for eid, entry in data.items():
        assert eid.isdigit()
        assert set(entry) == {"label", "provider", "channel", "event_types"}
        assert entry["label"] and entry["event_types"]
