import json
from unittest.mock import patch

import pytest

from cve_detector.cli import main
from cve_detector.models import Status, report


@pytest.mark.parametrize(
    "status,code",
    [
        (Status.NOT_VULNERABLE, 0),
        (Status.VULNERABLE, 1),
        (Status.INCONCLUSIVE, 2),
        (Status.ERROR, 3),
    ],
)
def test_json_and_exit_codes(status, code, capsys):
    result = report("fixture", "source_archive", status, "fixture", "Synthetic", {}, ("Test",))
    with patch("cve_detector.cli.detect", return_value=result):
        assert main(["--target", "fixture", "--format", "json"]) == code
    raw = json.loads(capsys.readouterr().out)
    assert raw["schema_version"] == 1
    assert raw["status"] == status
    assert len(raw["findings"]) == 2
    assert raw["timestamp"].endswith("+00:00")
    assert all(x["confidence"] and x["reference"] for x in raw["findings"])


@pytest.mark.parametrize(
    "args",
    [
        [],
        ["--bogus", "secret"],
        ["--timeout", "nan"],
        ["--timeout", "-1"],
        ["--retries", "3"],
        ["--timeout", "secret"],
    ],
)
def test_usage_errors_are_json_and_exit_3(args, capsys):
    assert main(args + ["--format=json"]) == 3
    output = capsys.readouterr().out
    assert json.loads(output)["status"] == "ERROR"
    assert "secret" not in output


@pytest.mark.parametrize("args", [["--timeout", "nan"], ["--timeout", "inf"], ["--retries", "3"]])
def test_valid_target_invalid_options(args, capsys, tmp_path):
    path = tmp_path / "archive"
    path.write_bytes(b"fixture")
    assert main(["--target", str(path), "--format=json"] + args) == 3
    assert json.loads(capsys.readouterr().out)["status"] == "ERROR"


def test_output_is_exclusive_and_input_not_overwritten(tmp_path, capsys):
    path = tmp_path / "archive"
    path.write_bytes(b"fixture")
    assert main(["--target", str(path), "--output", str(path), "--format=json"]) == 3
    assert path.read_bytes() == b"fixture"
    assert json.loads(capsys.readouterr().out)["status"] == "ERROR"


def test_console_quiet_and_file(tmp_path, capsys):
    path = tmp_path / "archive"
    path.write_bytes(b"fixture")
    output = tmp_path / "report.txt"
    assert main(["--target", str(path), "--quiet", "--output", str(output)]) == 2
    assert output.read_text() == capsys.readouterr().out == "INCONCLUSIVE\n"


def test_interrupt(capsys):
    with patch("cve_detector.cli.detect", side_effect=KeyboardInterrupt):
        assert main(["--target", "fixture", "--format=json"]) == 3
    assert json.loads(capsys.readouterr().out)["status"] == "ERROR"


def test_unexpected_error_redacted(capsys):
    with patch("cve_detector.cli.detect", side_effect=RuntimeError("secret")):
        assert main(["--target", "fixture", "--format=json"]) == 3
    assert "secret" not in capsys.readouterr().out


@pytest.mark.parametrize("option", ["--help", "--version"])
def test_help_version_exit_zero(option):
    with pytest.raises(SystemExit) as exc:
        main([option])
    assert exc.value.code == 0
