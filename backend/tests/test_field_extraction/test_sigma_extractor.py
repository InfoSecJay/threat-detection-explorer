"""Tests for Sigma field extraction."""

import pytest
from app.services.field_extractor import extract_sigma_fields


class TestSigmaProcessCreation:
    """Test extraction from process creation rules."""

    def test_extract_commandline_contains(self):
        """Extract fields from CommandLine|contains modifier."""
        detection = {
            "selection": {
                "CommandLine|contains": ["-enc", "-nop", "-w hidden"],
            },
            "condition": "selection",
        }
        result = extract_sigma_fields(detection)

        assert "CommandLine" in result.fields_used
        assert len(result.observables) == 1
        assert result.observables[0].type == "process"
        assert result.observables[0].subtype == "command_line_pattern"
        assert "-enc" in result.observables[0].values
        assert "-nop" in result.observables[0].values

    def test_extract_image_endswith(self):
        """Extract process names from Image|endswith."""
        detection = {
            "selection": {
                "Image|endswith": ["\\powershell.exe", "\\cmd.exe"],
            },
            "condition": "selection",
        }
        result = extract_sigma_fields(detection)

        assert "Image" in result.fields_used
        assert "powershell.exe" in result.process_names
        assert "cmd.exe" in result.process_names
        assert result.observables[0].type == "process"
        assert result.observables[0].subtype == "process_name"

    def test_extract_parent_image(self):
        """Extract parent process names from ParentImage."""
        detection = {
            "selection": {
                "ParentImage|endswith": "\\winword.exe",
                "Image|endswith": "\\cmd.exe",
            },
            "condition": "selection",
        }
        result = extract_sigma_fields(detection)

        assert "ParentImage" in result.fields_used
        assert "Image" in result.fields_used
        assert "winword.exe" in result.process_names
        assert "cmd.exe" in result.process_names


class TestSigmaEventID:
    """Test Event ID extraction from Sigma rules."""

    def test_extract_single_event_id(self):
        """Extract a single Event ID."""
        detection = {
            "selection": {"EventID": 4688},
            "condition": "selection",
        }
        result = extract_sigma_fields(detection)

        assert "EventID" in result.fields_used
        assert "4688" in result.event_ids

    def test_extract_multiple_event_ids(self):
        """Extract multiple Event IDs from a list."""
        detection = {
            "selection": {"EventID": [4688, 4689, 1]},
            "condition": "selection",
        }
        result = extract_sigma_fields(detection)

        assert "4688" in result.event_ids
        assert "4689" in result.event_ids
        assert "1" in result.event_ids


class TestSigmaRegistry:
    """Test registry field extraction."""

    def test_extract_registry_target_object(self):
        """Extract registry keys from TargetObject."""
        detection = {
            "selection": {
                "EventType": "CreateKey",
                "TargetObject|contains": "\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run",
            },
            "condition": "selection",
        }
        result = extract_sigma_fields(detection)

        assert "TargetObject" in result.fields_used
        assert any("CurrentVersion\\Run" in k for k in result.registry_keys)
        obs = [o for o in result.observables if o.type == "registry"]
        assert len(obs) > 0

    def test_extract_registry_with_filter(self):
        """Extract registry fields with negated filter."""
        detection = {
            "selection": {
                "TargetObject|contains": "\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Explorer\\VolumeCaches\\",
            },
            "filter_default": {
                "TargetObject|endswith": ["\\Active Setup Temp Folders", "\\BranchCache"],
            },
            "condition": "selection and not filter_default",
        }
        result = extract_sigma_fields(detection)

        # Filter should be marked as negated
        negated_obs = [o for o in result.observables if o.negated]
        assert len(negated_obs) > 0
        assert result.query_complexity == "moderate"


class TestSigmaNetwork:
    """Test network field extraction."""

    def test_extract_destination_hostname(self):
        """Extract network hostnames."""
        detection = {
            "selection": {
                "DestinationHostname": [
                    "pool.minexmr.com",
                    "fr.minexmr.com",
                ],
            },
            "condition": "selection",
        }
        result = extract_sigma_fields(detection)

        assert "DestinationHostname" in result.fields_used
        assert "pool.minexmr.com" in result.network_indicators
        obs = [o for o in result.observables if o.type == "network"]
        assert len(obs) > 0

    def test_extract_destination_port(self):
        """Extract network ports."""
        detection = {
            "selection": {
                "DestinationPort": [443, 8080],
            },
            "condition": "selection",
        }
        result = extract_sigma_fields(detection)

        assert "DestinationPort" in result.fields_used
        assert "443" in result.network_indicators
        assert "8080" in result.network_indicators


class TestSigmaFileEvent:
    """Test file event field extraction."""

    def test_extract_target_filename(self):
        """Extract file paths from TargetFilename."""
        detection = {
            "selection": {
                "TargetFilename|contains": [
                    "\\Windows\\Temp\\",
                    "\\AppData\\Local\\Temp\\",
                ],
            },
            "condition": "selection",
        }
        result = extract_sigma_fields(detection)

        assert "TargetFilename" in result.fields_used
        assert len(result.file_paths) == 2
        obs = [o for o in result.observables if o.type == "file"]
        assert len(obs) > 0


class TestSigmaComplexity:
    """Test query complexity assessment."""

    def test_simple_single_selection(self):
        detection = {
            "selection": {"CommandLine|contains": "test"},
            "condition": "selection",
        }
        result = extract_sigma_fields(detection)
        assert result.query_complexity == "simple"

    def test_moderate_multiple_selections(self):
        detection = {
            "selection1": {"Image|endswith": "\\cmd.exe"},
            "selection2": {"CommandLine|contains": "-enc"},
            "condition": "selection1 and selection2",
        }
        result = extract_sigma_fields(detection)
        assert result.query_complexity == "moderate"

    def test_complex_with_filters(self):
        detection = {
            "selection1": {"Image|endswith": "\\cmd.exe"},
            "selection2": {"CommandLine|contains": "-enc"},
            "filter1": {"User": "SYSTEM"},
            "condition": "selection1 and selection2 and not filter1",
        }
        result = extract_sigma_fields(detection)
        assert result.query_complexity == "complex"


class TestSigmaLogsource:
    """Test logsource table extraction."""

    def test_logsource_tables(self):
        detection = {
            "selection": {"CommandLine|contains": "test"},
            "condition": "selection",
        }
        logsource = {"product": "windows", "category": "process_creation", "service": "sysmon"}
        result = extract_sigma_fields(detection, logsource)

        assert "windows" in result.source_tables
        assert "process_creation" in result.source_tables
        assert "sysmon" in result.source_tables


class TestSigmaEdgeCases:
    """Test edge cases."""

    def test_empty_detection(self):
        result = extract_sigma_fields({})
        assert result.fields_used == []
        assert result.query_complexity == "simple"

    def test_none_detection(self):
        result = extract_sigma_fields(None)
        assert result.fields_used == []

    def test_list_of_dicts_selection(self):
        """Sigma selections can be lists of dicts (OR logic)."""
        detection = {
            "selection": [
                {"Image|endswith": "\\cmd.exe"},
                {"OriginalFileName": "cmd.exe"},
            ],
            "condition": "selection",
        }
        result = extract_sigma_fields(detection)

        assert "Image" in result.fields_used
        assert "OriginalFileName" in result.fields_used
        assert "cmd.exe" in result.process_names

    def test_deduplication(self):
        """Fields and process names should be deduplicated."""
        detection = {
            "selection1": {"Image|endswith": "\\powershell.exe"},
            "selection2": {"Image|endswith": "\\powershell.exe"},
            "condition": "selection1 or selection2",
        }
        result = extract_sigma_fields(detection)

        assert result.fields_used.count("Image") == 1
        assert result.process_names.count("powershell.exe") == 1
