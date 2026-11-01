"""Command-line orchestration and consistent exit codes."""

import argparse
import logging
import math
import sys
from pathlib import Path
from typing import NoReturn

from . import __version__
from .detector import detect, error_report
from .exceptions import DetectionError
from .models import EXIT_CODES
from .output import render


class Parser(argparse.ArgumentParser):
    def error(self, message: str) -> NoReturn:
        # argparse can include supplied credentials in its error messages.
        raise DetectionError("Invalid or missing arguments. Use --help for supported options.")


def parser() -> argparse.ArgumentParser:
    result = Parser(
        description=(
            "Assess both PHP2Shell CVEs. HTTP is observation-only; definitive findings "
            "apply to exact official source archives, never to deployed servers."
        )
    )
    result.add_argument("--target", required=True, help="HTTP(S) URL or local PHP source archive")
    result.add_argument(
        "--timeout", type=float, default=5.0, help="Socket timeout 0.1..30 (default 5)"
    )
    result.add_argument("--retries", type=int, default=0, help="Extra connection attempts 0..2")
    result.add_argument("--format", choices=("console", "json"), default="console")
    result.add_argument("--output", type=Path, help="Create a new report file; never overwrite")
    group = result.add_mutually_exclusive_group()
    group.add_argument("--verbose", action="store_true", help="Progress messages on stderr")
    group.add_argument(
        "--quiet", action="store_true", help="Console status only; JSON stays complete"
    )
    result.add_argument("--version", action="version", version=__version__)
    return result


def main(argv: list[str] | None = None) -> int:
    args_list = list(sys.argv[1:] if argv is None else argv)
    requested_json = "--format=json" in args_list or any(
        args_list[i : i + 2] == ["--format", "json"] for i in range(len(args_list))
    )
    output_format = "json" if requested_json else "console"
    try:
        args = parser().parse_args(args_list)
        output_format = args.format
        if not math.isfinite(args.timeout) or not 0.1 <= args.timeout <= 30:
            raise DetectionError("--timeout must be a finite number between 0.1 and 30.")
        if not 0 <= args.retries <= 2:
            raise DetectionError("--retries must be between 0 and 2.")
        logging.basicConfig(
            level=logging.INFO if args.verbose else logging.WARNING,
            format="%(levelname)s: %(message)s",
        )
        result = detect(args.target, args.timeout, args.retries)
        text = render(result, output_format, args.quiet)
        if args.output:
            try:
                with args.output.open("x", encoding="utf-8", newline="\n") as output:
                    output.write(text)
            except OSError:
                raise DetectionError(
                    "Cannot create report file; choose a new filename in a writable directory."
                ) from None
    except DetectionError as exc:
        result = error_report(str(exc))
        text = render(result, output_format)
    except KeyboardInterrupt:
        result = error_report("Assessment interrupted by user.")
        text = render(result, output_format)
    except Exception:
        # Keep tracebacks and sensitive inputs out of normal reports.
        result = error_report("Unexpected internal failure; report a sanitized reproduction.")
        text = render(result, output_format)
    try:
        sys.stdout.write(text)
    except (OSError, UnicodeError):
        return 3
    return EXIT_CODES[result.status]
