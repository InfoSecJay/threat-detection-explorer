"""#141: the KQL table extractor must return real tables only, and the
discriminator extractor must read the vendor / channel filters that say
which vendor a multi-vendor table (CommonSecurityLog, SecurityAlert,
WindowsEvent, Syslog, AzureDiagnostics) is carrying."""

from __future__ import annotations

from app.parsers.sentinel import _extract_kql_discriminators, _extract_kql_tables


class TestTables:
    def test_continuation_lines_are_not_tables(self):
        q = (
            "SecurityEvent\n"
            "| where EventID == 4624\n"
            "and AccountType == 'User'\n"
            "| extend Description = tostring(Activity)\n"
            "| project FirstSeen = TimeGenerated, Description"
        )
        assert _extract_kql_tables(q) == ["SecurityEvent"]

    def test_let_bound_names_are_not_tables(self):
        q = "let allData = union SecurityEvent, WindowsEvent;\nallData\n| where EventID == 1"
        assert _extract_kql_tables(q) == ["SecurityEvent", "WindowsEvent"]

    def test_union_list_with_options(self):
        q = "union isfuzzy=true CommonSecurityLog, Syslog\n| where DeviceVendor == 'Acronis'"
        assert _extract_kql_tables(q) == ["CommonSecurityLog", "Syslog"]

    def test_join_subquery_and_bare_join(self):
        q = (
            "SigninLogs\n"
            "| join kind=inner (AuditLogs | where Category == 'UserManagement') on UserId\n"
            "| join kind=leftouter hint.strategy=shuffle IdentityInfo on AccountUPN"
        )
        assert _extract_kql_tables(q) == ["SigninLogs", "AuditLogs", "IdentityInfo"]

    def test_in_subquery_and_search_in(self):
        assert _extract_kql_tables("SecurityAlert | where IP in (ThreatIntelIndicators | project IP)") == [
            "SecurityAlert", "ThreatIntelIndicators",
        ]
        assert _extract_kql_tables('search in (SecurityEvent, Syslog) "mimikatz"') == ["SecurityEvent", "Syslog"]

    def test_let_rhs_table_is_recovered_and_calls_are_not(self):
        q = 'let inds = ThreatIntelIndicators | where Active == true;\nlet bad = dynamic(["a"]);\nSecurityEvent | take 1'
        assert _extract_kql_tables(q) == ["ThreatIntelIndicators", "SecurityEvent"]

    def test_materialize_head(self):
        q = "let base = materialize(CommonSecurityLog | where DeviceVendor == 'Vectra Networks');\nbase | count"
        assert _extract_kql_tables(q) == ["CommonSecurityLog"]

    def test_function_call_head_is_not_a_table(self):
        assert _extract_kql_tables("_Im_Dns(starttime=ago(1d)) | where DnsQuery has 'x'") == []

    def test_more_than_three_tables_survive(self):
        q = "union A_CL, B_CL, C_CL, D_CL, E_CL | count"
        assert _extract_kql_tables(q) == ["A_CL", "B_CL", "C_CL", "D_CL", "E_CL"]

    def test_comments_are_ignored(self):
        q = "// Allowlisted UPNs should live\n/* Event\n| take 1 */\nSecurityEvent | take 1"
        assert _extract_kql_tables(q) == ["SecurityEvent"]

    def test_empty(self):
        assert _extract_kql_tables("") == []
        assert _extract_kql_tables(None) == []


class TestDiscriminators:
    def test_equality_and_in_list(self):
        q = (
            'CommonSecurityLog\n| where DeviceVendor == "Acronis"\n'
            '| where DeviceProduct in ("Acronis Cyber Protect", "Acronis audit")'
        )
        assert _extract_kql_discriminators(q) == {
            "devicevendor": ["acronis"],
            "deviceproduct": ["acronis cyber protect", "acronis audit"],
        }

    def test_case_insensitive_operators_and_wrapped_field(self):
        q = 'CommonSecurityLog | where tolower(DeviceVendor) =~ "palo alto networks" or DeviceVendor has "Fortinet"'
        assert _extract_kql_discriminators(q) == {"devicevendor": ["palo alto networks", "fortinet"]}

    def test_negations_are_skipped(self):
        q = 'CommonSecurityLog | where DeviceVendor != "Cisco" and DeviceVendor !in ("Fortinet") and DeviceVendor !has "Zscaler"'
        assert _extract_kql_discriminators(q) == {}

    def test_provider_and_process_name(self):
        assert _extract_kql_discriminators('WindowsEvent | where Provider =~ "Microsoft-Windows-Sysmon"') == {
            "provider": ["microsoft-windows-sysmon"],
        }
        assert _extract_kql_discriminators("Syslog | where ProcessName == 'sshd'") == {"processname": ["sshd"]}
        assert _extract_kql_discriminators('SecurityAlert | where ProviderName == "IoTSecurity"') == {
            "providername": ["iotsecurity"],
        }

    def test_azurediagnostics_resource_and_category(self):
        q = 'AzureDiagnostics | where ResourceType == "AZUREFIREWALLS" and Category in ("AzureFirewallApplicationRule", "AzureFirewallNetworkRule")'
        assert _extract_kql_discriminators(q) == {
            "resourcetype": ["azurefirewalls"],
            "category": ["azurefirewallapplicationrule", "azurefirewallnetworkrule"],
        }

    def test_empty(self):
        assert _extract_kql_discriminators("") == {}
        assert _extract_kql_discriminators("SecurityEvent | take 1") == {}
