"""
Tests for backend/knowledgebase.py — CVE + MITRE ATT&CK Search.

Covers:
    - CVE_DB structure and completeness
    - MITRE_DB structure and completeness
    - search_cve() empty, keyword, no results, multiple matches
    - search_mitre() empty, keyword, no results, multiple matches
    - search_all() combined results
    - get_cve() exact ID, case insensitive, not found
    - get_mitre() exact ID, case insensitive, not found
"""

import pytest
import sys
import os

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from knowledgebase import (
    CVE_DB,
    MITRE_DB,
    search_cve,
    search_mitre,
    search_all,
    get_cve,
    get_mitre,
)


# ════════════════════════════════════════════════════════════════
#  CVE_DB
# ════════════════════════════════════════════════════════════════

class TestCveDb:
    def test_has_entries(self):
        assert len(CVE_DB) >= 20

    def test_all_have_required_keys(self):
        for cve in CVE_DB:
            assert "id" in cve
            assert "type" in cve
            assert "cvss" in cve
            assert "description" in cve
            assert "affected" in cve
            assert "tools" in cve
            assert isinstance(cve["tools"], list)

    def test_all_ids_match_cve_format(self):
        for cve in CVE_DB:
            assert cve["id"].startswith("CVE-"), f"Bad ID: {cve['id']}"

    def test_cvss_range(self):
        for cve in CVE_DB:
            assert 0.0 <= cve["cvss"] <= 10.0, f"Bad CVSS: {cve['cvss']}"

    def test_type_is_cve(self):
        for cve in CVE_DB:
            assert cve["type"] == "cve"

    def test_well_known_cves_present(self):
        ids = [c["id"] for c in CVE_DB]
        assert "CVE-2021-44228" in ids  # Log4Shell
        assert "CVE-2017-0144" in ids   # EternalBlue
        assert "CVE-2014-0160" in ids   # Heartbleed

    def test_unique_ids(self):
        ids = [c["id"] for c in CVE_DB]
        assert len(ids) == len(set(ids))


# ════════════════════════════════════════════════════════════════
#  MITRE_DB
# ════════════════════════════════════════════════════════════════

class TestMitreDb:
    def test_has_entries(self):
        assert len(MITRE_DB) >= 20

    def test_all_have_required_keys(self):
        for tech in MITRE_DB:
            assert "id" in tech
            assert "name" in tech
            assert "tactic" in tech
            assert "description" in tech
            assert "detection" in tech
            assert "examples" in tech

    def test_all_ids_start_with_t(self):
        for tech in MITRE_DB:
            assert tech["id"].startswith("T"), f"Bad ID: {tech['id']}"

    def test_well_known_techniques(self):
        ids = [t["id"] for t in MITRE_DB]
        assert "T1190" in ids   # Exploit Public-Facing Application
        assert "T1110" in ids   # Brute Force
        assert "T1046" in ids   # Network Service Discovery

    def test_unique_ids(self):
        ids = [t["id"] for t in MITRE_DB]
        assert len(ids) == len(set(ids))

    def test_examples_are_lists(self):
        for tech in MITRE_DB:
            assert isinstance(tech["examples"], list)


# ════════════════════════════════════════════════════════════════
#  search_cve()
# ════════════════════════════════════════════════════════════════

class TestSearchCve:
    def test_empty_query_returns_first_20(self):
        results = search_cve("")
        assert len(results) == 20

    def test_none_query_returns_first_20(self):
        results = search_cve(None)
        assert len(results) == 20

    def test_search_by_id(self):
        results = search_cve("CVE-2021-44228")
        assert len(results) == 1
        assert results[0]["id"] == "CVE-2021-44228"

    def test_search_by_description(self):
        results = search_cve("log4shell")
        assert len(results) >= 1
        assert any("Log4Shell" in r["description"] for r in results)

    def test_search_by_affected(self):
        results = search_cve("openSSL")
        assert len(results) >= 1

    def test_search_by_tool(self):
        results = search_cve("metasploit")
        assert len(results) >= 5  # Many CVEs use metasploit

    def test_no_results(self):
        results = search_cve("zzz_nonexistent_zzz")
        assert results == []

    def test_case_insensitive(self):
        r1 = search_cve("ETERNALBLUE")
        r2 = search_cve("eternalblue")
        assert len(r1) == len(r2)

    def test_partial_match(self):
        results = search_cve("apache")
        assert len(results) >= 1


# ════════════════════════════════════════════════════════════════
#  search_mitre()
# ════════════════════════════════════════════════════════════════

class TestSearchMitre:
    def test_empty_query_returns_first_20(self):
        results = search_mitre("")
        assert len(results) == 20

    def test_none_query_returns_first_20(self):
        results = search_mitre(None)
        assert len(results) == 20

    def test_search_by_id(self):
        results = search_mitre("T1190")
        assert len(results) >= 1
        assert any(t["id"] == "T1190" for t in results)

    def test_search_by_name(self):
        results = search_mitre("Brute Force")
        assert len(results) >= 1
        assert any("Brute Force" in t["name"] for t in results)

    def test_search_by_tactic(self):
        results = search_mitre("Initial Access")
        assert len(results) >= 1

    def test_search_by_description(self):
        results = search_mitre(" Kerberos ")
        assert len(results) >= 1

    def test_no_results(self):
        results = search_mitre("zzz_nonexistent_zzz")
        assert results == []

    def test_case_insensitive(self):
        r1 = search_mitre("BRUTE FORCE")
        r2 = search_mitre("brute force")
        assert len(r1) == len(r2)


# ════════════════════════════════════════════════════════════════
#  search_all()
# ════════════════════════════════════════════════════════════════

class TestSearchAll:
    def test_returns_both_keys(self):
        result = search_all("apache")
        assert "cves" in result
        assert "mitre" in result

    def test_empty_query(self):
        result = search_all("")
        assert len(result["cves"]) == 20
        assert len(result["mitre"]) == 20

    def test_combined_results(self):
        result = search_all("metasploit")
        assert len(result["cves"]) >= 1

    def test_query_isolation(self):
        # CVE and MITRE searches should be independent
        result = search_all("hydra")
        assert isinstance(result["cves"], list)
        assert isinstance(result["mitre"], list)


# ════════════════════════════════════════════════════════════════
#  get_cve()
# ════════════════════════════════════════════════════════════════

class TestGetCve:
    def test_exact_id(self):
        result = get_cve("CVE-2021-44228")
        assert result is not None
        assert result["id"] == "CVE-2021-44228"

    def test_case_insensitive(self):
        result = get_cve("cve-2021-44228")
        assert result is not None

    def test_not_found(self):
        result = get_cve("CVE-9999-99999")
        assert result is None

    def test_empty_string(self):
        result = get_cve("")
        assert result is None

    def test_has_all_fields(self):
        result = get_cve("CVE-2017-0144")
        assert "cvss" in result
        assert "description" in result
        assert "affected" in result
        assert "exploit_available" in result
        assert "tools" in result


# ════════════════════════════════════════════════════════════════
#  get_mitre()
# ════════════════════════════════════════════════════════════════

class TestGetMitre:
    def test_exact_id(self):
        result = get_mitre("T1190")
        assert result is not None
        assert result["id"] == "T1190"

    def test_case_insensitive(self):
        result = get_mitre("t1190")
        assert result is not None

    def test_not_found(self):
        result = get_mitre("T9999")
        assert result is None

    def test_empty_string(self):
        result = get_mitre("")
        assert result is None

    def test_has_all_fields(self):
        result = get_mitre("T1110")
        assert "name" in result
        assert "tactic" in result
        assert "description" in result
        assert "detection" in result
        assert "examples" in result

    def test_sub_technique(self):
        result = get_mitre("T1059.001")
        assert result is not None
        assert "PowerShell" in result["name"]
