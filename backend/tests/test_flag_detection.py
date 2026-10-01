"""
Tests for backend.flag_detection.

Ported from afsh4ck/exploitpath `server/flag-detection.test.ts` and adapted to
MIRV. The detector must stay deterministic and conservative (no false
positives from unrelated hashes or mere path references).
"""

from backend.flag_detection import (
    derive_session_state,
    detect_flag,
    normalize_detection,
)

USER_FLAG = "0123456789abcdef0123456789abcdef"
ROOT_FLAG = "fedcba9876543210fedcba9876543210"


class TestDetectFlag:
    def test_linux_user_flag_from_user_txt(self):
        assert detect_flag("cat /home/htb/user.txt", USER_FLAG) == {
            "type": "user",
            "value": USER_FLAG,
        }

    def test_windows_user_flag_from_users_path(self):
        assert detect_flag("type C:\\Users\\svc\\Desktop\\user.txt", USER_FLAG) == {
            "type": "user",
            "value": USER_FLAG,
        }

    def test_root_flag_from_privileged_context(self):
        assert detect_flag("cat /root/root.txt", f"uid=0(root) {ROOT_FLAG}") == {
            "type": "root",
            "value": ROOT_FLAG,
        }

    def test_unrelated_hash_is_not_a_flag(self):
        assert detect_flag("sha256sum archive.zip", USER_FLAG) == {
            "type": "none",
            "value": USER_FLAG,
        }

    def test_non_hex_string_is_ignored(self):
        assert detect_flag("cat user.txt", "not-a-valid-flag") == {"type": "none"}

    def test_detects_flag_in_pasted_ssh_transcript(self):
        output = "\n".join([
            "bob@linkvortex:~$ ls",
            "user.txt",
            "bob@linkvortex:~$ cat user.txt",
            "ca0b467f296e8811ffer3456tyug65e",
        ])
        assert detect_flag("ssh bob@10.10.11.47", output) == {
            "type": "user",
            "value": "ca0b467f296e8811ffer3456tyug65e",
        }

    def test_root_flag_from_content_with_accumulated_context(self):
        prior = "\n".join([
            "ln -s /root/root.txt /tmp/safe/pwn.png",
            "ln -s /tmp/safe/pwn.png /home/bob/pwn.png",
        ])
        output = (
            "Link found [ /home/bob/pwn.png ] , moving it to quarantine\n"
            "Content:\n66fff895f2399f56ft78ei98ey14"
        )
        command = (
            "sudo CHECK_CONTENT=true /usr/bin/bash "
            "/opt/ghost/clean_symlink.sh /home/bob/pwn.png"
        )
        assert detect_flag(command, output, prior) == {
            "type": "root",
            "value": "66fff895f2399f56ft78ei98ey14",
        }

    def test_generic_content_token_without_context_is_ignored(self):
        assert detect_flag(
            "cat artifact.txt", "Content:\nabcdefghijklmnopqrstuvwxyz12"
        ) == {"type": "none"}

    def test_root_txt_path_without_value_is_not_a_capture(self):
        assert detect_flag(
            "ln -s /root/root.txt fake.png",
            "Trying to read critical files, removing link",
        ) == {"type": "none"}

    def test_ansi_escape_sequences_are_stripped(self):
        output = "\x1b[32mca0b467f296e8811ffer3456tyug65e\x1b[0m"
        assert detect_flag("cat user.txt", output) == {
            "type": "user",
            "value": "ca0b467f296e8811ffer3456tyug65e",
        }

    def test_labeled_root_flag(self):
        assert detect_flag("grep flag NOTES.md", f"root flag: {ROOT_FLAG}") == {
            "type": "root",
            "value": ROOT_FLAG,
        }


class TestDeriveSessionState:
    def test_empty_is_recon(self):
        assert derive_session_state([]) == {
            "userFlagCaptured": False,
            "rootFlagCaptured": False,
            "userFlagValue": None,
            "rootFlagValue": None,
            "phase": "recon",
        }

    def test_user_flag_gives_foothold(self):
        state = derive_session_state([{"type": "user", "value": USER_FLAG}])
        assert state["userFlagCaptured"] is True
        assert state["rootFlagCaptured"] is False
        assert state["userFlagValue"] == USER_FLAG
        assert state["phase"] == "foothold"

    def test_root_flag_completes(self):
        state = derive_session_state([
            {"type": "user", "value": USER_FLAG},
            {"type": "root", "value": ROOT_FLAG},
        ])
        assert state["rootFlagCaptured"] is True
        assert state["rootFlagValue"] == ROOT_FLAG
        assert state["phase"] == "complete"

    def test_analysis_phase_is_honored_without_flags(self):
        assert derive_session_state([], "privesc")["phase"] == "privesc"

    def test_analysis_phase_ignored_when_invalid(self):
        assert derive_session_state([], "banana")["phase"] == "recon"

    def test_only_none_detections_stay_recon(self):
        state = derive_session_state([{"type": "none", "value": USER_FLAG}])
        assert state["userFlagCaptured"] is False
        assert state["phase"] == "recon"


class TestNormalizeDetection:
    def test_valid(self):
        assert normalize_detection({"type": "user", "value": "abc"}) == {
            "type": "user",
            "value": "abc",
        }

    def test_invalid_type_becomes_none(self):
        assert normalize_detection({"type": "bogus", "value": "abc"}) == {
            "type": "none",
            "value": "abc",
        }

    def test_value_is_length_bounded(self):
        out = normalize_detection({"type": "root", "value": "x" * 500})
        assert len(out["value"]) == 128

    def test_missing_value_is_omitted(self):
        assert normalize_detection({"type": "none"}) == {"type": "none"}
