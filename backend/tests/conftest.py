"""Pytest configuration and fixtures."""

from pathlib import Path

import pytest
import pytest_asyncio
from sqlalchemy.ext.asyncio import AsyncSession, create_async_engine, async_sessionmaker
from app.database import Base
from app.services import mitre_tactic_inference as _mti

FIXTURES_DIR = Path(__file__).resolve().parent / "fixtures"


@pytest.fixture(scope="session", autouse=True)
def _deterministic_mitre_tactic_cache():
    """Point technique->tactic inference at a committed fixture.

    The real cache (data/mitre_attack.json) is gitignored and only
    exists after a sync, so on a clean checkout (CI) the parser tests
    that assert T1059 -> TA0002 saw an empty map -- and locally they
    only passed by accident of which test populated the cache first.
    Same fixture everywhere means the same answer everywhere.
    """
    _mti._CACHE_PATH = FIXTURES_DIR / "mitre_attack_min.json"
    _mti.reset_cache_for_tests()
    yield


@pytest_asyncio.fixture
async def db_session():
    """Create an in-memory database session for testing."""
    # Aggregates memoised on the corpus fingerprint must not leak
    # between tests that happen to build same-sized corpora.
    from app.services.corpus_cache import corpus_cache
    corpus_cache.invalidate()

    engine = create_async_engine("sqlite+aiosqlite:///:memory:", echo=False)

    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)

    async_session = async_sessionmaker(
        engine, class_=AsyncSession, expire_on_commit=False
    )

    async with async_session() as session:
        yield session

    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.drop_all)

    await engine.dispose()


# Sample rule content for testing
SAMPLE_SIGMA_RULE = """
title: Suspicious PowerShell Command Line
id: 89819aa4-bbd6-46bc-88ec-c7f7fe30efa6
status: stable
description: Detects suspicious PowerShell command line arguments
author: Test Author
date: 2023/01/01
logsource:
    product: windows
    category: process_creation
detection:
    selection:
        CommandLine|contains:
            - '-enc'
            - '-nop'
            - '-w hidden'
    condition: selection
level: high
tags:
    - attack.execution
    - attack.t1059.001
"""

SAMPLE_ELASTIC_RULE = '''
[metadata]
creation_date = "2023/01/01"
maturity = "production"

[rule]
name = "Suspicious PowerShell Execution"
description = "Detects suspicious PowerShell execution patterns"
author = ["Test Author"]
severity = "high"
type = "query"
language = "kuery"
index = ["winlogbeat-*", "logs-endpoint*"]
query = """
process.name: "powershell.exe" and process.args: ("-enc" or "-nop" or "-hidden")
"""

[[rule.threat]]
framework = "MITRE ATT&CK"

[[rule.threat.technique]]
id = "T1059"
name = "Command and Scripting Interpreter"
'''

SAMPLE_SPLUNK_RULE = """
name: Suspicious PowerShell Command
description: Detects suspicious PowerShell command execution
author: Test Author
date: '2023-01-01'
status: production
search: |
  | tstats count from datamodel=Endpoint.Processes
  where Processes.process_name=powershell.exe
  by Processes.process Processes.process_name
tags:
  mitre_attack_id:
    - T1059.001
  asset_type:
    - Endpoint
  confidence: 80
  impact: 70
"""
