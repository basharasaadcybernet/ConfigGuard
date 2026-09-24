# Phase 7C routing scenarios

All values are synthetic. Expected routing-rule outcomes:

| Fixture | OSPFv2 | Classic EIGRP | RIPv2 | Purpose |
| --- | --- | --- | --- | --- |
| `synthetic_ripv2.txt` | not applicable | not applicable | secure | Explicit RIPv2 MD5 and usable key chain. |
| `synthetic_ospfv2.txt` | secure | not applicable | not applicable | Explicit OSPFv2 process/area, message-digest mode, and key. |
| `synthetic_eigrp.txt` | not applicable | secure | not applicable | AS-matched classic EIGRP MD5 and usable key chain. |
| `synthetic_multi_process.txt` | potential risk | unknown | secure | Multiple protocols/interfaces with OSPF null, incomplete EIGRP, and complete RIP. |
| `synthetic_interface_range.txt` | not applicable | secure | not applicable | Range-derived EIGRP authentication with per-target provenance. |

These are static configuration expectations. They do not assert live adjacency, peer-key
agreement, route exchange, reachability, or resistance to route injection.
