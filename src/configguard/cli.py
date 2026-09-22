"""Command-line adapter for local ConfigGuard assessments."""

from __future__ import annotations

import argparse
import os
import sys
from collections.abc import Sequence
from enum import IntEnum

from configguard import __version__
from configguard.analysis import default_analysis_engine
from configguard.parsing import (
    CiscoConfigurationParser,
    ConfigurationIngestor,
    ConfigurationInputError,
    ConfigurationParseError,
    UnsupportedPlatformError,
)
from configguard.reporting import (
    AssessmentStatus,
    OutputWriteError,
    build_assessment_report,
    render_html,
    render_json,
    render_terminal,
    write_new_report,
)


class ExitCode(IntEnum):
    """Stable process exit codes for local and automated use."""

    COMPLETED = 0
    INVALID_INPUT = 2
    UNSUPPORTED_CONFIGURATION = 3
    PARTIAL_ASSESSMENT = 4
    INTERNAL_FAILURE = 5
    OUTPUT_FAILURE = 6


def create_parser() -> argparse.ArgumentParser:
    """Create the public command-line grammar."""

    parser = argparse.ArgumentParser(
        prog="configguard",
        description="Offline Cisco configuration security assessment.",
    )
    commands = parser.add_subparsers(dest="command", required=True)
    commands.add_parser("version", help="Show the installed ConfigGuard version.")
    scan = commands.add_parser("scan", help="Assess one explicitly selected configuration.")
    scan.add_argument("configuration", help="Local Cisco configuration file to assess.")
    scan.add_argument(
        "--format",
        choices=("terminal", "json"),
        default="terminal",
        help="Standard-output format (default: terminal).",
    )
    scan.add_argument(
        "--output",
        help="Write the JSON report to this new file; requires --format json.",
    )
    scan.add_argument(
        "--report",
        help="Write a self-contained HTML report to this new file.",
    )
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    """Run the CLI without exposing source paths, content, or exception details."""

    parser = create_parser()
    arguments = parser.parse_args(argv)
    if arguments.command == "version":
        print(f"ConfigGuard {__version__}")
        return ExitCode.COMPLETED

    if arguments.output is not None and arguments.format != "json":
        parser.error("--output requires --format json")
    if (
        arguments.output is not None
        and arguments.report is not None
        and _same_selected_path(arguments.output, arguments.report)
    ):
        parser.error("--output and --report must select different files")

    try:
        source = ConfigurationIngestor().read(arguments.configuration)
        configuration_parser = CiscoConfigurationParser()
        support = configuration_parser.identify(source)
        configuration = configuration_parser.parse(source)
        analysis = default_analysis_engine().analyze(configuration)
        report = build_assessment_report(support, configuration, analysis)

        try:
            standard_output = (
                render_json(report) if arguments.format == "json" else render_terminal(report)
            )
            html_output = render_html(report) if arguments.report is not None else None
        except Exception:
            raise OutputWriteError("The report could not be generated safely.") from None

        if arguments.output is not None:
            write_new_report(arguments.output, standard_output)
        if arguments.report is not None and html_output is not None:
            write_new_report(arguments.report, html_output)
        sys.stdout.write(standard_output)
    except ConfigurationInputError as error:
        _safe_error(error.code.value, str(error))
        return ExitCode.INVALID_INPUT
    except UnsupportedPlatformError:
        _safe_error(
            "unsupported_configuration",
            "The selected configuration is unsupported or could not be identified safely.",
        )
        return ExitCode.UNSUPPORTED_CONFIGURATION
    except ConfigurationParseError:
        _safe_error("invalid_configuration", "The selected configuration could not be parsed.")
        return ExitCode.INVALID_INPUT
    except OutputWriteError as error:
        _safe_error("output_failure", str(error))
        return ExitCode.OUTPUT_FAILURE
    except OSError:
        _safe_error("output_failure", "The assessment output could not be written safely.")
        return ExitCode.OUTPUT_FAILURE
    except Exception:
        _safe_error("internal_failure", "ConfigGuard could not complete the assessment safely.")
        return ExitCode.INTERNAL_FAILURE

    if report.assessment_status is AssessmentStatus.PARTIAL:
        return ExitCode.PARTIAL_ASSESSMENT
    return ExitCode.COMPLETED


def _safe_error(code: str, message: str) -> None:
    print(f"ConfigGuard error [{code}]: {message}", file=sys.stderr)


def _same_selected_path(first: str, second: str) -> bool:
    """Compare selected paths without resolving links or doing filesystem I/O."""

    return os.path.normcase(os.path.abspath(first)) == os.path.normcase(os.path.abspath(second))


if __name__ == "__main__":
    raise SystemExit(main())
