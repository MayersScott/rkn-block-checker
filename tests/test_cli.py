import logging
from unittest.mock import patch

import pytest

from rkn_checker.cli import _ad_hoc_targets, _build_parser, _setup_logging, main


class TestMutuallyExclusiveFlags:
    def test_white_and_black_together_exits(self):
        with pytest.raises(SystemExit) as ei:
            main(["--white", "--black"])
        assert ei.value.code == 2

    @patch("rkn_checker.core.check_urls_parallel", return_value=[])
    def test_white_alone_is_accepted(self, mock_parallel):
        # README: "--white | check only the control (whitelist) targets".
        # Only the combination with --black is rejected, not --white itself.
        assert main(["--json", "--no-self-info", "--white"]) == 0
        assert mock_parallel.call_count == 1


class TestDocumentedDefaults:
    """Defaults and levels stated in the README's CLI reference."""

    def test_workers_default_is_10(self):
        # README: "--workers N | thread pool size for parallel checks (default 10)"
        assert _build_parser().parse_args([]).workers == 10

    @pytest.mark.parametrize("argv, expected", [
        ([], logging.WARNING),
        (["-v"], logging.INFO),
        (["-vv"], logging.DEBUG),
    ])
    def test_verbosity_maps_to_log_level(self, argv, expected):
        # README: "-v / -vv | logging at INFO / DEBUG"
        verbosity = _build_parser().parse_args(argv).verbose
        with patch("rkn_checker.cli.logging.basicConfig") as mock_config:
            _setup_logging(verbosity)
        assert mock_config.call_args.kwargs["level"] == expected

    @patch("rkn_checker.web.run_server", return_value=0)
    def test_startweb_default_port_is_7777(self, mock_run):
        # README: "startweb | start the local web interface on
        # http://127.0.0.1:7777"
        assert main(["startweb"]) == 0
        mock_run.assert_called_once_with("127.0.0.1", 7777)


class TestValidation:
    def test_workers_zero_exits(self):
        with pytest.raises(SystemExit) as ei:
            main(["--workers", "0"])
        assert ei.value.code == 2

    def test_timeout_negative_exits(self):
        with pytest.raises(SystemExit) as ei:
            main(["--timeout", "-1"])
        assert ei.value.code == 2


class TestJsonModeTimeout:
    @patch("rkn_checker.cli.get_self_info", return_value={"ip": "1.2.3.4"})
    @patch("rkn_checker.core.check_urls_parallel", return_value=[])
    def test_json_mode_passes_timeout_to_get_self_info(self, mock_parallel, mock_self):
        main(["--json", "--timeout", "3.0"])
        mock_self.assert_called_with(timeout=3.0)

    @patch("rkn_checker.cli.get_self_info", return_value=None)
    @patch("rkn_checker.core.check_urls_parallel", return_value=[])
    def test_no_self_info_flag_skips_lookup(self, mock_parallel, mock_self):
        main(["--json", "--no-self-info"])
        mock_self.assert_not_called()


class TestStreamingNoSelfInfo:
    @patch("rkn_checker.cli.print_header")
    @patch("rkn_checker.cli._run_streaming", return_value=([], []))
    def test_no_self_info_passes_empty_dict_to_header(self, mock_stream, mock_header):
        main(["--no-self-info"])
        mock_header.assert_called_with({})


class TestAdHocTargets:
    """Unit tests for the --url -> {name: url} mapping. The mapping must
    accept casual user input (bare hostnames, mixed case) and never silently
    drop a target the user explicitly asked for."""

    def test_single_url_with_scheme(self):
        out = _ad_hoc_targets(["https://example.com"])
        assert out == {"example-com": "https://example.com"}

    def test_bare_hostname_gets_https_prepended(self):
        out = _ad_hoc_targets(["example.com"])
        assert out == {"example-com": "https://example.com"}

    def test_multiple_urls_all_kept(self):
        out = _ad_hoc_targets([
            "https://example.com",
            "https://other.org",
        ])
        assert len(out) == 2
        assert "https://example.com" in out.values()
        assert "https://other.org" in out.values()

    def test_duplicate_hosts_disambiguated_not_lost(self):
        # Two different URLs that happen to share a hostname (e.g., http vs
        # https for the same host) should both end up in the output, not
        # collide and silently drop one.
        out = _ad_hoc_targets([
            "https://example.com",
            "http://example.com",
        ])
        assert len(out) == 2

    def test_empty_string_skipped(self):
        out = _ad_hoc_targets(["", "https://x.com", "  "])
        assert len(out) == 1
        assert "https://x.com" in out.values()


class TestAdHocCli:
    @patch("rkn_checker.cli.get_self_info", return_value={"ip": "1.2.3.4"})
    @patch("rkn_checker.cli._run_ad_hoc", return_value=[])
    def test_url_flag_runs_ad_hoc_path(self, mock_ad_hoc, mock_self):
        main(["--url", "https://example.com"])
        mock_ad_hoc.assert_called_once()

    @patch("rkn_checker.cli.get_self_info", return_value={"ip": "1.2.3.4"})
    @patch("rkn_checker.cli._run_streaming", return_value=([], []))
    def test_url_flag_skips_streaming_path(self, mock_stream, mock_self):
        # When --url is used, the regular whitelist/blacklist pipeline must
        # not run at all — otherwise the user pays the cost of probing
        # ~30 built-in sites for a single ad-hoc check.
        main(["--url", "https://example.com"])
        mock_stream.assert_not_called()

    def test_url_with_white_file_rejected(self):
        with pytest.raises(SystemExit) as ei:
            main(["--url", "https://example.com",
                  "--white-file", "/tmp/nonexistent.txt"])
        assert ei.value.code == 2

    def test_url_with_white_only_flag_rejected(self):
        with pytest.raises(SystemExit) as ei:
            main(["--url", "https://example.com", "--white"])
        assert ei.value.code == 2

    @patch("rkn_checker.core.check_urls_parallel", return_value=[])
    @patch("rkn_checker.cli.get_self_info", return_value={"ip": "1.2.3.4"})
    def test_url_in_json_mode_emits_ad_hoc_section(
        self, mock_self, mock_parallel, capsys,
    ):
        main(["--url", "https://example.com", "--json", "--no-self-info"])
        out = capsys.readouterr().out
        assert "ad_hoc" in out
        # And shouldn't accidentally include the regular sections.
        assert "whitelist" not in out
        assert "blacklist" not in out


class TestIdentifyFlag:
    @patch("rkn_checker.cli.get_self_info", return_value={"ip": "1.2.3.4"})
    @patch("rkn_checker.cli._run_streaming", return_value=([], []))
    def test_identify_propagates_to_streaming(self, mock_stream, mock_self):
        main(["--identify"])
        # _run_streaming receives identify as a positional or kwarg —
        # check the call args contain True for it.
        args, kwargs = mock_stream.call_args
        assert True in args or kwargs.get("identify") is True

    @patch("rkn_checker.cli.get_self_info", return_value={"ip": "1.2.3.4"})
    @patch("rkn_checker.cli._run_streaming", return_value=([], []))
    def test_identify_default_is_off(self, mock_stream, mock_self):
        main([])
        args, kwargs = mock_stream.call_args
        # The privacy-protective default must be off, not on.
        assert kwargs.get("identify", False) is False or False in args

    @patch("rkn_checker.cli.get_self_info", return_value={"ip": "1.2.3.4"})
    @patch("rkn_checker.cli._run_ad_hoc", return_value=[])
    def test_identify_propagates_to_ad_hoc(self, mock_ad_hoc, mock_self):
        main(["--url", "https://example.com", "--identify"])
        # _run_ad_hoc(targets, workers, timeout, identify)
        args, kwargs = mock_ad_hoc.call_args
        # identify is the 4th positional or a kwarg
        assert (len(args) >= 4 and args[3] is True) or kwargs.get("identify") is True
