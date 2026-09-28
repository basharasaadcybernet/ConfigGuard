# Changelog

All notable changes to ConfigGuard are documented in this file.

## 0.1.0 - 2026-09-28

Initial public release preparation:

- deterministic 17-rule assessment engine for the documented Cisco IOS / IOS XE-style subset;
- local CLI with human-readable terminal output and stable exit codes;
- loopback-only local Web UI using the shared assessment pipeline;
- versioned JSON report schema `1.0.0`;
- self-contained, escaped, printable HTML security reports;
- bounded local ingestion, conservative uncertainty, centralized evidence redaction, and safe
  public diagnostics;
- implemented management-plane, SNMP, Layer 2, interface IPv4 ACL, OSPFv2, classic IPv4 EIGRP,
  and RIPv2 authentication checks.

This release does not provide live-device scanning, runtime verification, CVE assessment,
cloud processing, numerical scoring, or automatic remediation.
