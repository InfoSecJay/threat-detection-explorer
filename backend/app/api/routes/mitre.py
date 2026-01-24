"""MITRE ATT&CK API routes."""

from fastapi import APIRouter, HTTPException

from app.services.mitre import mitre_service

router = APIRouter(prefix="/mitre", tags=["mitre"])


@router.get("")
async def get_mitre_data():
    """Get all MITRE ATT&CK tactics and techniques."""
    await mitre_service.ensure_loaded()

    return {
        "tactics": mitre_service.get_all_tactics(),
        "techniques": mitre_service.get_all_techniques(),
        "stats": mitre_service.get_stats(),
    }


@router.get("/tactics")
async def get_tactics():
    """Get all MITRE ATT&CK tactics."""
    await mitre_service.ensure_loaded()
    return mitre_service.get_all_tactics()


@router.get("/tactics/{tactic_id}")
async def get_tactic(tactic_id: str):
    """Get a specific MITRE ATT&CK tactic by ID."""
    await mitre_service.ensure_loaded()
    tactic = mitre_service.get_tactic(tactic_id.upper())
    if not tactic:
        raise HTTPException(status_code=404, detail=f"Tactic {tactic_id} not found")
    return tactic


@router.get("/techniques")
async def get_techniques():
    """Get all MITRE ATT&CK techniques."""
    await mitre_service.ensure_loaded()
    return mitre_service.get_all_techniques()


@router.get("/techniques/{technique_id}")
async def get_technique(technique_id: str):
    """Get a specific MITRE ATT&CK technique by ID."""
    await mitre_service.ensure_loaded()
    technique = mitre_service.get_technique(technique_id.upper())
    if not technique:
        raise HTTPException(status_code=404, detail=f"Technique {technique_id} not found")
    return technique


@router.post("/refresh")
async def refresh_mitre_data():
    """Force refresh MITRE ATT&CK data from the official repository."""
    success = await mitre_service.refresh()
    return {
        "success": success,
        "stats": mitre_service.get_stats(),
    }


@router.get("/stats")
async def get_mitre_stats():
    """Get statistics about loaded MITRE ATT&CK data."""
    await mitre_service.ensure_loaded()
    return mitre_service.get_stats()
