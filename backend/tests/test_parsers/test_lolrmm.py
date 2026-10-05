"""Tests for the LOLRMM parser's YAML preprocessor.

LOLRMM rules are generated and sometimes ship values that are not valid
YAML (unquoted `*.domain.com` wildcards, unquoted `%programdata%` paths),
so `_preprocess_yaml` quotes them before PyYAML sees the document. The
heuristics must not touch values that are already valid.
"""

from pathlib import Path

import yaml

from app.parsers.lolrmm import LOLRMMParser

RULE_PATH = Path("detections/sigma/splashtop_files_sigma.yml")

# Trimmed from upstream detections/sigma/splashtop_files_sigma.yml at
# LOLRMM commit cc916e97 (synced 2026-10-05). The quoted list items hold a
# drive-letter colon AND a percent sign (`%4` is how Windows encodes `/`
# in event-log file names). Pre-fix the preprocessor split the line on
# the `C:` colon, re-quoted the tail, and the whole rule was dropped with
# "while parsing a block collection".
SPLASHTOP_RULE = """title: Potential Splashtop RMM Tool File Activity
id: 47990f7f-bd65-4bb1-bf63-2614df261554
status: experimental
description: |
    Detects potential files activity of Splashtop RMM tool
author: LOLRMM Project
date: 2025-12-01
tags:
    - attack.command-and-control
    - attack.t1219
logsource:
    product: windows
    category: file_event
detection:
    selection:
        TargetFilename|endswith:
            - 'C:\\windows\\System32\\winevt\\Logs\\Splashtop-Splashtop Streamer-Status%4Operational.evtx'
            - 'C:\\windows\\System32\\winevt\\Logs\\Splashtop-Splashtop Streamer-Remote Session%4Operational.evtx'
            - '%PROGRAMDATA%\\Splashtop\\Temp\\log\\FTCLog.txt'
            - 'C:\\Program Files (x86)\\Splashtop\\Splashtop Remote\\Server\\SRService.exe'
    condition: selection
falsepositives:
    - Legitimate use of Splashtop
level: medium
"""


class TestPreprocessLeavesValidYamlAlone:
    def setup_method(self):
        self.parser = LOLRMMParser()

    def test_quoted_list_item_with_drive_colon_and_percent_is_untouched(self):
        preprocessed = self.parser._preprocess_yaml(SPLASHTOP_RULE)
        assert preprocessed == SPLASHTOP_RULE, (
            "every value in this rule is already quoted; the preprocessor "
            "must not rewrite any line"
        )

    def test_splashtop_rule_parses(self):
        result = self.parser.parse(RULE_PATH, SPLASHTOP_RULE)
        assert result is not None, "rule must not be dropped"
        assert result.title == "Potential Splashtop RMM Tool File Activity"
        paths = result.detection_logic_raw["selection"]["TargetFilename|endswith"]
        assert len(paths) == 4
        assert paths[0].endswith("Streamer-Status%4Operational.evtx")
        assert paths[2] == "%PROGRAMDATA%\\Splashtop\\Temp\\log\\FTCLog.txt"

    def test_quoted_mapping_value_with_drive_colon_is_untouched(self):
        rule = (
            "title: t\n"
            "detection:\n"
            "    selection:\n"
            "        Image: 'C:\\Program Files\\Vendor\\%name%\\agent.exe'\n"
            "    condition: selection\n"
        )
        assert self.parser._preprocess_yaml(rule) == rule


class TestPreprocessStillQuotesInvalidYaml:
    """The reason the preprocessor exists: keep fixing what is broken."""

    def setup_method(self):
        self.parser = LOLRMMParser()

    def test_unquoted_wildcard_list_item_is_quoted(self):
        rule = "detection:\n    selection:\n        DestinationHostname|endswith:\n            - *.splashtop.com\n"
        data = yaml.safe_load(self.parser._preprocess_yaml(rule))
        assert data["detection"]["selection"]["DestinationHostname|endswith"] == ["*.splashtop.com"]

    def test_unquoted_env_var_mapping_value_is_quoted(self):
        rule = "detection:\n    selection:\n        Image|startswith: %programdata%\\Splashtop\\\n"
        data = yaml.safe_load(self.parser._preprocess_yaml(rule))
        assert data["detection"]["selection"]["Image|startswith"] == "%programdata%\\Splashtop\\"

    def test_unquoted_drive_path_list_item_stays_one_scalar(self):
        """`C:` inside an unquoted scalar is not a mapping key: a YAML key
        separator is a colon followed by whitespace. Pre-fix this produced
        the mapping {"C": "\\\\Windows\\\\..."} instead of a string."""
        rule = "detection:\n    selection:\n        TargetFilename:\n            - C:\\Windows\\%foo%\\bar.exe\n"
        data = yaml.safe_load(self.parser._preprocess_yaml(rule))
        assert data["detection"]["selection"]["TargetFilename"] == ["C:\\Windows\\%foo%\\bar.exe"]
