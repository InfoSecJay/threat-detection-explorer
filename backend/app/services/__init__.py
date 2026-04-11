"""Application services.

Submodules should be imported directly (e.g.
``from app.services.ingestion import IngestionService``) rather than
through this package. Eagerly re-exporting them here would create
circular-import risk for any module in ``app.normalizers`` or
``app.parsers`` that needs a helper from this package, because the
``IngestionService`` import chain transitively loads every normalizer.
"""
