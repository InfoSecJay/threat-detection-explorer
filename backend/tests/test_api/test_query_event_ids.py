"""/api/query/event-ids -- the event-ID dictionary the UI labels with.

Keyed by the channel-namespaced id (`security:4688`, #110); `event_id`
carries the bare number for callers holding pre-namespacing values.
"""

from fastapi.testclient import TestClient

from app.main import app

client = TestClient(app)


def test_event_id_dictionary_endpoint():
    response = client.get("/api/query/event-ids")
    assert response.status_code == 200
    data = response.json()["event_ids"]
    assert len(data) >= 200
    assert data["security:4688"] == {
        "event_id": "4688",
        "label": "Process created",
        "provider": "windows_security",
        "channel": "Security",
        "event_types": ["process_creation"],
    }
    assert data["sysmon:1"]["label"]
    assert "4688" not in data
    # Every entry has the full shape the frontend types expect.
    for key, entry in data.items():
        prefix, _, bare = key.partition(":")
        assert prefix and bare.isdigit(), key
        assert entry["event_id"] == bare
        assert set(entry) == {"event_id", "label", "provider", "channel", "event_types"}
        assert entry["label"] and entry["event_types"]
