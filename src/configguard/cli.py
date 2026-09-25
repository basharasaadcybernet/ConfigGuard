"""Command-line adapter for local ConfigGuard assessments."""

from __future__ import annotations

import argparse
import os
import shutil
import sys
from collections.abc import Sequence
from enum import IntEnum

from configguard import __version__
from configguard.application import AssessmentService
from configguard.parsing import (
    ConfigurationInputError,
    ConfigurationParseError,
    UnsupportedPlatformError,
)
from configguard.reporting import (
    AssessmentStatus,
    OutputWriteError,
    render_html,
    render_json,
    render_terminal,
    write_new_report,
)
from configguard.web import DEFAULT_WEB_PORT, WebServerStartError, run_web_server


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
        description=(
            "ConfigGuard performs local, static, read-only security assessment of supported "
            "Cisco IOS and IOS XE-style configuration exports. It never connects to a device."
        ),
        epilog=(
            "Examples:\n"
            "  configguard scan router.txt\n"
            "  configguard scan switch.txt --report report.html\n"
            "  configguard scan router.txt --format json\n"
            "  configguard scan router.txt --details\n"
            "  configguard web\n\n"
            "Use 'configguard COMMAND --help' for command-specific help."
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    commands = parser.add_subparsers(
        dest="command",
        required=True,
        title="commands",
        metavar="COMMAND",
    )
    commands.add_parser(
        "version",
        help="Show the installed ConfigGuard version.",
        description="Print the installed ConfigGuard version as one script-friendly line.",
    )
    web = commands.add_parser(
        "web",
        help="Start the local-only ConfigGuard web interface.",
        description=(
            "Start the bundled web interface on 127.0.0.1. Configuration files are processed "
            "locally, are not uploaded to a cloud service, and are not intentionally persisted."
        ),
        epilog=(
            "Examples:\n"
            "  configguard web\n"
            "  configguard web --port 9000\n"
            "  configguard web --no-open\n\n"
            "Closing or stopping the ConfigGuard process stops the local web application."
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    web.add_argument(
        "--port",
        type=_port_number,
        default=DEFAULT_WEB_PORT,
        metavar="PORT",
        help=f"Local loopback TCP port (default: {DEFAULT_WEB_PORT}).",
    )
    web.add_argument(
        "--no-open",
        action="store_true",
        help="Do not open the default browser automatically.",
    )
    scan = commands.add_parser(
        "scan",
        help="Assess one local configuration export.",
        description=(
            "Statically assess one local Cisco IOS or IOS XE-style configuration export. "
            "The file is read locally and no device connection or configuration change occurs."
        ),
        epilog=(
            "Examples:\n"
            "  configguard scan router.txt\n"
            "  configguard scan switch.txt --report report.html\n"
            "  configguard scan router.txt --format json\n"
            "  configguard scan router.txt --details\n\n"
            "Exit codes: 0 completed, 2 invalid input, 3 unsupported configuration, "
            "4 partial assessment, 5 internal failure, 6 output failure."
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    scan.add_argument(
        "configuration",
        metavar="FILE",
        help="UTF-8 Cisco IOS or IOS XE-style configuration file to assess.",
    )
    scan.add_argument(
        "--format",
        choices=("terminal", "json"),
        default="terminal",
        help="Standard-output format: terminal or automation-safe JSON (default: terminal).",
    )
    scan.add_argument(
        "--output",
        metavar="FILE",
        help="Write JSON to a new file; requires --format json and never overwrites.",
    )
    scan.add_argument(
        "--report",
        metavar="FILE",
        help="Also write a self-contained HTML report to a new file.",
    )
    scan.add_argument(
        "--details",
        action="store_true",
        help="Show all rules, complete sanitized evidence, references, and limitations.",
    )
    scan.add_argument(
        "--no-color",
        action="store_true",
        help="Disable terminal colors; JSON and redirected output never contain ANSI color.",
    )
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    """Run the CLI without exposing source paths, content, or exception details."""

    parser = create_parser()
    arguments = parser.parse_args(argv)
    if arguments.command == "version":
        print(f"ConfigGuard {__version__}")
        return ExitCode.COMPLETED
    if arguments.command == "web":
        try:
            run_web_server(port=arguments.port, open_browser=not arguments.no_open)
        except WebServerStartError as error:
            _safe_error("web_start_failure", str(error))
            return ExitCode.INVALID_INPUT
        except Exception:
            _safe_error("web_failure", "ConfigGuard Local Web UI stopped unexpectedly.")
            return ExitCode.INTERNAL_FAILURE
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
        report = AssessmentService().assess_path(arguments.configuration)

        try:
            if arguments.format == "json":
                standard_output = render_json(report)
            else:
                standard_output = render_terminal(
                    report,
                    details=arguments.details,
                    color=_terminal_color_enabled(arguments.no_color),
                    width=shutil.get_terminal_size(fallback=(100, 24)).columns,
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


def _port_number(value: str) -> int:
    """Parse a non-privileged local TCP port for the web command."""

    try:
        port = int(value)
    except ValueError:
        raise argparse.ArgumentTypeError("PORT must be an integer from 1024 to 65535.") from None
    if not 1024 <= port <= 65535:
        raise argparse.ArgumentTypeError("PORT must be an integer from 1024 to 65535.")
    return port


def _same_selected_path(first: str, second: str) -> bool:
    """Compare selected paths without resolving links or doing filesystem I/O."""

    return os.path.normcase(os.path.abspath(first)) == os.path.normcase(os.path.abspath(second))


def _terminal_color_enabled(no_color: bool) -> bool:
    """Enable color only for an interactive terminal with no explicit opt-out."""

    if no_color or "NO_COLOR" in os.environ or os.environ.get("TERM", "").lower() == "dumb":
        return False
    return sys.stdout.isatty()


if __name__ == "__main__":
    raise SystemExit(main())
