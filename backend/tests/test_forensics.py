"""
Tests for backend/forensics.py — Digital Forensics Analysis.

Covers:
    - _compute_hashes() MD5 and SHA256
    - _run_local() success, timeout, FileNotFoundError, generic error
    - _id_file() success, empty output
    - _run_strings() findings extraction (flags, credentials, URLs, emails, IPs)
    - _run_binwalk() embedded detection
    - _run_exiftool() metadata extraction
    - _run_hexdump() basic output
    - analyze_file() categories: file, disk, memory, network, stego
    - list_evidence(), get_evidence(), delete_evidence()
    - run_tool() dispatching to correct sub-tool
"""

import pytest
import sys
import os
import tempfile
import hashlib
from unittest.mock import patch, MagicMock, mock_open

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import forensics
from forensics import (
    _compute_hashes,
    _run_local,
    _id_file,
    _run_strings,
    _run_binwalk,
    _run_exiftool,
    _run_hexdump,
    _run_foremost,
    analyze_file,
    list_evidence,
    get_evidence,
    delete_evidence,
    run_tool,
    _evidence_store,
)


@pytest.fixture(autouse=True)
def reset_evidence_store():
    """Clear in-memory evidence store between tests."""
    _evidence_store.clear()
    yield
    _evidence_store.clear()


@pytest.fixture
def sample_file(tmp_path):
    """Create a sample text file for testing."""
    f = tmp_path / "sample.txt"
    f.write_text("Hello World\nflag{test_flag_123}\npassword=secret123\n")
    return str(f)


@pytest.fixture
def sample_binary_file(tmp_path):
    """Create a minimal binary file for testing."""
    f = tmp_path / "sample.bin"
    f.write_bytes(b"\x89PNG\r\n\x1a\n\x00\x00\x00\rIHDR" + b"\x00" * 100)
    return str(f)


# ════════════════════════════════════════════════════════════════
#  _compute_hashes()
# ════════════════════════════════════════════════════════════════

class TestComputeHashes:
    def test_md5_and_sha256(self, sample_file):
        hashes = _compute_hashes(sample_file)
        assert "md5" in hashes
        assert "sha256" in hashes
        assert len(hashes["md5"]) == 32
        assert len(hashes["sha256"]) == 64

    def test_deterministic(self, sample_file):
        h1 = _compute_hashes(sample_file)
        h2 = _compute_hashes(sample_file)
        assert h1 == h2

    def test_known_md5(self, tmp_path):
        f = tmp_path / "known.txt"
        f.write_text("abc")
        expected = hashlib.md5(b"abc").hexdigest()
        hashes = _compute_hashes(str(f))
        assert hashes["md5"] == expected

    def test_known_sha256(self, tmp_path):
        f = tmp_path / "known.txt"
        f.write_text("abc")
        expected = hashlib.sha256(b"abc").hexdigest()
        hashes = _compute_hashes(str(f))
        assert hashes["sha256"] == expected

    def test_empty_file(self, tmp_path):
        f = tmp_path / "empty.txt"
        f.write_text("")
        hashes = _compute_hashes(str(f))
        assert hashes["md5"] == hashlib.md5(b"").hexdigest()

    def test_large_file(self, tmp_path):
        f = tmp_path / "large.bin"
        f.write_bytes(b"X" * 100000)
        hashes = _compute_hashes(str(f))
        assert len(hashes["sha256"]) == 64


# ════════════════════════════════════════════════════════════════
#  _run_local()
# ════════════════════════════════════════════════════════════════

class TestRunLocal:
    @patch("forensics.subprocess.run")
    def test_success(self, mock_run):
        mock_run.return_value = MagicMock(stdout="output", stderr="", returncode=0)
        stdout, stderr = _run_local(["echo", "hello"])
        assert stdout == "output"
        assert stderr == ""

    @patch("forensics.subprocess.run")
    def test_timeout(self, mock_run):
        import subprocess
        mock_run.side_effect = subprocess.TimeoutExpired(cmd="nmap", timeout=60)
        stdout, stderr = _run_local(["nmap"], timeout=60)
        assert stdout == ""
        assert stderr == "TIMEOUT"

    @patch("forensics.subprocess.run")
    def test_file_not_found(self, mock_run):
        mock_run.side_effect = FileNotFoundError("tool not found")
        stdout, stderr = _run_local(["nonexistent_tool"])
        assert stdout == ""
        assert "not found" in stderr.lower()

    @patch("forensics.subprocess.run")
    def test_generic_exception(self, mock_run):
        mock_run.side_effect = RuntimeError("something broke")
        stdout, stderr = _run_local(["broken"])
        assert stdout == ""
        assert "something broke" in stderr

    @patch("forensics.subprocess.run")
    def test_stderr_output(self, mock_run):
        mock_run.return_value = MagicMock(stdout="", stderr="error msg", returncode=1)
        stdout, stderr = _run_local(["fail_cmd"])
        assert stderr == "error msg"


# ════════════════════════════════════════════════════════════════
#  _id_file()
# ════════════════════════════════════════════════════════════════

class TestIdFile:
    @patch("forensics._run_local")
    def test_identifies_text(self, mock_run):
        mock_run.return_value = ("sample.txt: ASCII text", "")
        result = _id_file("/tmp/sample.txt")
        assert "ASCII" in result["type"]

    @patch("forensics._run_local")
    def test_empty_output(self, mock_run):
        mock_run.return_value = ("", "")
        result = _id_file("/tmp/unknown")
        assert result["type"] == "unknown"

    @patch("forensics._run_local")
    def test_error_output(self, mock_run):
        mock_run.return_value = ("", "permission denied")
        result = _id_file("/tmp/secret")
        assert result["type"] == "unknown"
        assert "error" in result


# ════════════════════════════════════════════════════════════════
#  _run_strings()
# ════════════════════════════════════════════════════════════════

class TestRunStrings:
    @patch("forensics._run_local")
    def test_finds_flag(self, mock_run):
        mock_run.return_value = ("flag{abc123}\nother stuff\n", "")
        result = _run_strings("/tmp/file.bin")
        assert result["total_strings"] > 0
        flags = [f for f in result["findings"] if f["severity"] == "critical"]
        assert len(flags) > 0
        assert "CTF Flag" in flags[0]["title"]

    @patch("forensics._run_local")
    def test_finds_credential(self, mock_run):
        mock_run.return_value = ("password = mysecret\n", "")
        result = _run_strings("/tmp/file.bin")
        creds = [f for f in result["findings"] if "credential" in f["title"].lower()]
        assert len(creds) > 0

    @patch("forensics._run_local")
    def test_finds_url(self, mock_run):
        mock_run.return_value = ("visit https://example.com/path\n", "")
        result = _run_strings("/tmp/file.bin")
        urls = [f for f in result["findings"] if f["title"] == "URL found"]
        assert len(urls) > 0

    @patch("forensics._run_local")
    def test_finds_email(self, mock_run):
        mock_run.return_value = ("user@example.com\n", "")
        result = _run_strings("/tmp/file.bin")
        emails = [f for f in result["findings"] if f["title"] == "Email address"]
        assert len(emails) > 0

    @patch("forensics._run_local")
    def test_finds_ip(self, mock_run):
        mock_run.return_value = ("server at 192.168.1.1\n", "")
        result = _run_strings("/tmp/file.bin")
        ips = [f for f in result["findings"] if f["title"] == "IP address"]
        assert len(ips) > 0

    @patch("forensics._run_local")
    def test_empty_output(self, mock_run):
        mock_run.return_value = ("", "")
        result = _run_strings("/tmp/empty.bin")
        assert result["total_strings"] == 0
        assert result["findings"] == []

    @patch("forensics._run_local")
    def test_finds_api_key(self, mock_run):
        mock_run.return_value = ("sk-ABCDEFGHIJKLMNOPQRSTUVWXYZ123456\n", "")
        result = _run_strings("/tmp/file.bin")
        keys = [f for f in result["findings"] if "API key" in f["title"]]
        assert len(keys) > 0

    @patch("forensics._run_local")
    def test_min_len_param(self, mock_run):
        mock_run.return_value = ("short\n", "")
        result = _run_strings("/tmp/file.bin", min_len=3)
        # Should still call with the specified min_len
        mock_run.assert_called_once()


# ════════════════════════════════════════════════════════════════
#  _run_binwalk()
# ════════════════════════════════════════════════════════════════

class TestRunBinwalk:
    @patch("forensics._run_local")
    def test_detects_embedded(self, mock_run):
        mock_run.return_value = ("128    0x80    PNG image data\n256    0x100   Zlib compressed data\n", "")
        result = _run_binwalk("/tmp/image.bin")
        assert len(result["findings"]) >= 2

    @patch("forensics._run_local")
    def test_empty_output(self, mock_run):
        mock_run.return_value = ("", "")
        result = _run_binwalk("/tmp/empty.bin")
        assert result["findings"] == []

    @patch("forensics._run_local")
    def test_output_truncated(self, mock_run):
        mock_run.return_value = ("A" * 5000, "")
        result = _run_binwalk("/tmp/big.bin")
        assert len(result["output"]) <= 3000


# ════════════════════════════════════════════════════════════════
#  _run_exiftool()
# ════════════════════════════════════════════════════════════════

class TestRunExiftool:
    @patch("forensics._run_local")
    def test_extracts_metadata(self, mock_run):
        mock_run.return_value = (
            "Creator : Adobe Photoshop\nAuthor : John\nComment : secret\n",
            ""
        )
        result = _run_exiftool("/tmp/photo.jpg")
        assert len(result["findings"]) >= 1
        assert any("Creator" in f["title"] or "Author" in f["title"] or "Comment" in f["title"]
                    for f in result["findings"])

    @patch("forensics._run_local")
    def test_empty_output(self, mock_run):
        mock_run.return_value = ("", "")
        result = _run_exiftool("/tmp/plain.txt")
        assert result["findings"] == []

    @patch("forensics._run_local")
    def test_metadata_truncated(self, mock_run):
        mock_run.return_value = ("A" * 10000, "")
        result = _run_exiftool("/tmp/big.jpg")
        assert len(result["metadata"]) <= 5000


# ════════════════════════════════════════════════════════════════
#  _run_hexdump()
# ════════════════════════════════════════════════════════════════

class TestRunHexdump:
    @patch("forensics._run_local")
    def test_basic_output(self, mock_run):
        mock_run.return_value = ("00000000: 8950 4e47 0d0a 1a0a  .PNG....\n", "")
        result = _run_hexdump("/tmp/file.bin")
        assert "hexdump" in result
        assert "8950" in result["hexdump"]

    @patch("forensics._run_local")
    def test_max_bytes_param(self, mock_run):
        mock_run.return_value = ("data", "")
        _run_hexdump("/tmp/file.bin", max_bytes=512)
        call_args = mock_run.call_args[0][0]
        assert "512" in call_args


# ════════════════════════════════════════════════════════════════
#  analyze_file()
# ════════════════════════════════════════════════════════════════

class TestAnalyzeFile:
    @patch("forensics._run_strings")
    @patch("forensics._run_exiftool")
    @patch("forensics._id_file")
    def test_basic_file_analysis(self, mock_id, mock_exif, mock_strings, sample_file):
        mock_id.return_value = {"type": "ASCII text"}
        mock_exif.return_value = {"metadata": "", "findings": []}
        mock_strings.return_value = {"total_strings": 5, "findings": []}
        result = analyze_file(sample_file, category="file")
        assert "id" in result
        assert result["filename"] == "sample.txt"
        assert result["category"] == "file"
        assert result["md5"]
        assert result["sha256"]

    @patch("forensics._run_strings")
    @patch("forensics._run_exiftool")
    @patch("forensics._id_file")
    def test_stores_in_evidence(self, mock_id, mock_exif, mock_strings, sample_file):
        mock_id.return_value = {"type": "text"}
        mock_exif.return_value = {"metadata": "", "findings": []}
        mock_strings.return_value = {"total_strings": 0, "findings": []}
        result = analyze_file(sample_file, category="file")
        assert result["id"] in _evidence_store

    @patch("forensics._run_binwalk")
    @patch("forensics._run_strings")
    @patch("forensics._run_exiftool")
    @patch("forensics._id_file")
    def test_disk_category_runs_binwalk(self, mock_id, mock_exif, mock_strings, mock_bw, sample_file):
        mock_id.return_value = {"type": "disk image"}
        mock_exif.return_value = {"metadata": "", "findings": []}
        mock_strings.return_value = {"total_strings": 0, "findings": []}
        mock_bw.return_value = {"output": "binwalk output", "findings": [], "error": ""}
        result = analyze_file(sample_file, category="disk")
        mock_bw.assert_called_once()
        assert result["analysis"]["binwalk"] == "binwalk output"

    @patch("forensics._run_binwalk")
    @patch("forensics._run_strings")
    @patch("forensics._run_exiftool")
    @patch("forensics._id_file")
    def test_stego_category_runs_binwalk(self, mock_id, mock_exif, mock_strings, mock_bw, sample_file):
        mock_id.return_value = {"type": "PNG image"}
        mock_exif.return_value = {"metadata": "", "findings": []}
        mock_strings.return_value = {"total_strings": 0, "findings": []}
        mock_bw.return_value = {"output": "", "findings": [], "error": ""}
        with patch("forensics._run_local") as mock_local:
            mock_local.return_value = ("", "")
            result = analyze_file(sample_file, category="stego")
            mock_bw.assert_called()

    @patch("forensics._run_strings")
    @patch("forensics._run_exiftool")
    @patch("forensics._id_file")
    def test_memory_category(self, mock_id, mock_exif, mock_strings, sample_file):
        mock_id.return_value = {"type": "data"}
        mock_exif.return_value = {"metadata": "", "findings": []}
        mock_strings.return_value = {"total_strings": 0, "findings": []}
        with patch("forensics._run_local") as mock_local:
            mock_local.return_value = ("", "")
            result = analyze_file(sample_file, category="memory")
            assert any("memory" in f["category"] for f in result["findings"])

    @patch("forensics._run_strings")
    @patch("forensics._run_exiftool")
    @patch("forensics._id_file")
    def test_network_category_finds_creds(self, mock_id, mock_exif, mock_strings, sample_file):
        mock_id.return_value = {"type": "pcap"}
        mock_exif.return_value = {"metadata": "", "findings": []}
        mock_strings.return_value = {"total_strings": 0, "findings": []}
        with patch("forensics._run_local") as mock_local:
            mock_local.return_value = ("password=secret123\nGET /index HTTP/1.1\n", "")
            result = analyze_file(sample_file, category="network")
            assert "network" in result["analysis"]

    @patch("forensics._run_strings")
    @patch("forensics._run_exiftool")
    @patch("forensics._id_file")
    def test_findings_summary_counts(self, mock_id, mock_exif, mock_strings, sample_file):
        mock_id.return_value = {"type": "text"}
        mock_exif.return_value = {"metadata": "", "findings": []}
        mock_strings.return_value = {"total_strings": 0, "findings": [
            {"severity": "critical", "title": "flag", "description": "", "category": "s", "file": "x"},
            {"severity": "high", "title": "cred", "description": "", "category": "s", "file": "x"},
            {"severity": "info", "title": "ip", "description": "", "category": "s", "file": "x"},
        ]}
        result = analyze_file(sample_file, category="file")
        assert result["summary"]["critical"] == 1
        assert result["summary"]["high"] == 1
        assert result["summary"]["info"] == 1

    @patch("forensics._run_strings")
    @patch("forensics._run_exiftool")
    @patch("forensics._id_file")
    def test_error_is_none_on_success(self, mock_id, mock_exif, mock_strings, sample_file):
        mock_id.return_value = {"type": "text"}
        mock_exif.return_value = {"metadata": "", "findings": []}
        mock_strings.return_value = {"total_strings": 0, "findings": []}
        result = analyze_file(sample_file, category="file")
        assert result["error"] is None

    @patch("forensics._run_strings")
    @patch("forensics._run_exiftool")
    @patch("forensics._id_file")
    def test_pcap_category(self, mock_id, mock_exif, mock_strings, sample_file):
        mock_id.return_value = {"type": "pcap"}
        mock_exif.return_value = {"metadata": "", "findings": []}
        mock_strings.return_value = {"total_strings": 0, "findings": []}
        with patch("forensics._run_local") as mock_local:
            # Regex in forensics.py: r'(GET|POST|PUT|DELETE) /[\w/]+ HTTP'
            # Needs a path segment after the slash
            mock_local.return_value = ("GET /index HTTP/1.1\nPOST /api/submit HTTP/1.1\n", "")
            result = analyze_file(sample_file, category="pcap")
            assert result["analysis"]["network"]["http_requests"] == 2

    @patch("forensics._run_strings")
    @patch("forensics._run_exiftool")
    @patch("forensics._id_file")
    @patch("forensics._run_local")
    def test_stego_image_zsteg(self, mock_local, mock_id, mock_exif, mock_strings, tmp_path):
        png_file = tmp_path / "test.png"
        png_file.write_bytes(b"\x89PNG" + b"\x00" * 100)
        mock_id.return_value = {"type": "PNG image"}
        mock_exif.return_value = {"metadata": "", "findings": []}
        mock_strings.return_value = {"total_strings": 0, "findings": []}
        # Mock binwalk
        with patch("forensics._run_binwalk") as mock_bw:
            mock_bw.return_value = {"output": "", "findings": [], "error": ""}
            # zsteg output
            mock_local.return_value = ("b1,rgb,lsb,xy   0,0   flag{hidden}\n", "")
            result = analyze_file(str(png_file), category="stego")
            zsteg_findings = [f for f in result["findings"] if f["category"] == "stego"]
            assert len(zsteg_findings) > 0

    @patch("forensics._run_strings")
    @patch("forensics._run_exiftool")
    @patch("forensics._id_file")
    def test_analysis_has_expected_keys(self, mock_id, mock_exif, mock_strings, sample_file):
        mock_id.return_value = {"type": "text"}
        mock_exif.return_value = {"metadata": "", "findings": []}
        mock_strings.return_value = {"total_strings": 0, "findings": []}
        result = analyze_file(sample_file, category="file")
        assert "strings" in result["analysis"]
        assert "metadata" in result["analysis"]


# ════════════════════════════════════════════════════════════════
#  list_evidence()
# ════════════════════════════════════════════════════════════════

class TestListEvidence:
    @patch("forensics._run_strings")
    @patch("forensics._run_exiftool")
    @patch("forensics._id_file")
    def test_lists_analyzed_files(self, mock_id, mock_exif, mock_strings, sample_file):
        mock_id.return_value = {"type": "text"}
        mock_exif.return_value = {"metadata": "", "findings": []}
        mock_strings.return_value = {"total_strings": 0, "findings": []}
        analyze_file(sample_file, category="file")
        evidence = list_evidence()
        assert len(evidence) == 1
        assert evidence[0]["filename"] == "sample.txt"

    def test_empty_store(self):
        evidence = list_evidence()
        assert evidence == []


# ════════════════════════════════════════════════════════════════
#  get_evidence()
# ════════════════════════════════════════════════════════════════

class TestGetEvidence:
    @patch("forensics._run_strings")
    @patch("forensics._run_exiftool")
    @patch("forensics._id_file")
    def test_get_existing(self, mock_id, mock_exif, mock_strings, sample_file):
        mock_id.return_value = {"type": "text"}
        mock_exif.return_value = {"metadata": "", "findings": []}
        mock_strings.return_value = {"total_strings": 0, "findings": []}
        result = analyze_file(sample_file, category="file")
        ev = get_evidence(result["id"])
        assert ev is not None
        assert ev["filename"] == "sample.txt"

    def test_get_nonexistent(self):
        assert get_evidence("nonexistent") is None


# ════════════════════════════════════════════════════════════════
#  delete_evidence()
# ════════════════════════════════════════════════════════════════

class TestDeleteEvidence:
    @patch("forensics._run_strings")
    @patch("forensics._run_exiftool")
    @patch("forensics._id_file")
    def test_delete_existing(self, mock_id, mock_exif, mock_strings, sample_file):
        mock_id.return_value = {"type": "text"}
        mock_exif.return_value = {"metadata": "", "findings": []}
        mock_strings.return_value = {"total_strings": 0, "findings": []}
        result = analyze_file(sample_file, category="file")
        assert delete_evidence(result["id"]) is True
        assert get_evidence(result["id"]) is None

    def test_delete_nonexistent(self):
        assert delete_evidence("nonexistent") is False


# ════════════════════════════════════════════════════════════════
#  run_tool()
# ════════════════════════════════════════════════════════════════

class TestRunTool:
    def test_file_not_found(self):
        result = run_tool("/nonexistent/file.txt", "strings")
        assert "error" in result

    @patch("forensics._run_strings")
    def test_strings_tool(self, mock_strings, sample_file):
        mock_strings.return_value = {"total_strings": 5, "findings": []}
        result = run_tool(sample_file, "strings", {"min_len": 4})
        mock_strings.assert_called_once_with(sample_file, 4)

    @patch("forensics._run_exiftool")
    def test_exiftool_tool(self, mock_exif, sample_file):
        mock_exif.return_value = {"metadata": "", "findings": []}
        result = run_tool(sample_file, "exiftool")
        mock_exif.assert_called_once_with(sample_file)

    @patch("forensics._run_binwalk")
    def test_binwalk_tool(self, mock_bw, sample_file):
        mock_bw.return_value = {"output": "", "findings": [], "error": ""}
        result = run_tool(sample_file, "binwalk")
        mock_bw.assert_called_once_with(sample_file)

    @patch("forensics._run_hexdump")
    def test_hexdump_tool(self, mock_hex, sample_file):
        mock_hex.return_value = {"hexdump": "data"}
        result = run_tool(sample_file, "hexdump", {"max_bytes": 256})
        mock_hex.assert_called_once_with(sample_file, 256)

    @patch("forensics._run_foremost")
    def test_foremost_tool(self, mock_fm, sample_file):
        mock_fm.return_value = {"carved_files": 0, "output_dir": "/tmp/x", "output": ""}
        result = run_tool(sample_file, "foremost")
        mock_fm.assert_called_once()

    @patch("forensics._run_local")
    def test_zsteg_tool(self, mock_local, sample_file):
        mock_local.return_value = ("found data", "")
        result = run_tool(sample_file, "zsteg")
        assert "output" in result

    @patch("forensics._run_local")
    def test_steghide_tool(self, mock_local, sample_file):
        mock_local.return_value = ("extracted", "")
        result = run_tool(sample_file, "steghide", {"passphrase": "test"})
        assert "output" in result

    def test_unknown_tool(self, sample_file):
        result = run_tool(sample_file, "unknown_tool")
        assert "error" in result
        assert "Unknown tool" in result["error"]


# ════════════════════════════════════════════════════════════════
#  _run_foremost()
# ════════════════════════════════════════════════════════════════

class TestRunForemost:
    @patch("forensics._run_local")
    def test_carves_files(self, mock_local, tmp_path):
        out_dir = str(tmp_path / "foremost_out")
        mock_local.return_value = ("", "")
        result = _run_foremost("/tmp/image.dd", out_dir)
        assert "carved_files" in result
        assert result["output_dir"] == out_dir

    @patch("forensics._run_local")
    def test_empty_output(self, mock_local, tmp_path):
        out_dir = str(tmp_path / "foremost_empty")
        mock_local.return_value = ("", "")
        result = _run_foremost("/tmp/empty.bin", out_dir)
        assert result["carved_files"] == 0
