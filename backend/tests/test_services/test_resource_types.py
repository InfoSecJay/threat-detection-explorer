"""Resource-type surface redesign (#60): only type-shaped values in
the index, grouped by the platform log they are read from."""

from __future__ import annotations

import pytest

from app.models.detection import Detection
from app.services.observables import _is_resource_type, top_values


@pytest.mark.parametrize("value", ["pods", "secrets", "bucket", "gcs_bucket", "clusterroles", "bigquery", "kube-system"])
def test_type_shaped_values_pass(value):
    assert _is_resource_type(value)


@pytest.mark.parametrize("value", [
    "00000003-0000-0000-c000-000000000000",  # app GUID
    "Okta Admin Console",                     # resource NAME
    "Malware", "TOR",                          # alert-category junk
    "servicePrincipalName", "Role.DisplayName",  # field names
    "arn:aws:iam::123:role/x",                # ARN
    "ab",                                      # too short to mean anything
])
def test_names_and_junk_are_excluded(value):
    assert not _is_resource_type(value)


@pytest.mark.asyncio
async def test_resource_index_keeps_types_and_gains_platform_context(db_session):
    db_session.add_all([
        Detection(
            id="a", source="elastic", source_file="a.yml", source_repo_url="https://x",
            title="K8s secret access rule here", detection_logic="x", language="eql", raw_content="r",
            severity="high", status="stable", data_sources=["kubernetes_audit"],
            extracted_target_resources=["secrets", "Okta Admin Console"],
        ),
        Detection(
            id="b", source="panther", source_file="b.yml", source_repo_url="https://x",
            title="K8s secret exfil rule here", detection_logic="x", language="python", raw_content="r",
            severity="high", status="stable", data_sources=["kubernetes_audit"],
            extracted_target_resources=["secrets", "00000003-0000-0000-c000-000000000000"],
        ),
    ])
    await db_session.commit()

    out = await top_values(db_session, "resource", limit=10)
    values = {v["value"]: v for v in out["values"]}
    assert set(values) == {"secrets"}  # names + GUIDs stay off the index
    v = values["secrets"]
    assert v["rules"] == 2
    assert v["context"] is not None and v["context"]["provider"] == "kubernetes_audit"
