"""Run the Python engine over a set of configs into a scratch output root.

The JS parity harness calls this so both engines analyse the same bytes on the
same run; the reports are then compared field by field.

    python _parity_scan.py <out-root> <service> [<service> ...]
"""

from __future__ import annotations

import sys
from pathlib import Path

from ad.config import load_config
from ad.flags import infer_flow
from ad.report import write_all
from ad.requests import load_requests
from ad.sast import scan
from ad.topology import infer_topology

ROOT = Path(__file__).resolve().parent


def main(argv: list[str]) -> int:
    if len(argv) < 2:
        print(__doc__)
        return 2
    out_root = Path(argv[0])
    services = argv[1:]

    for service in services:
        cfg = load_config(ROOT / "configs" / f"{service}.json")
        result = scan(cfg.source_roots, cfg.excluded_globs)

        from ad.cli import _read_source_texts

        texts = _read_source_texts(cfg)
        topo = infer_topology(list(texts.values()))
        runtime = load_requests(cfg.request_logs, cfg)

        route_runtime = {"__all__": runtime.route_matrix()}
        flow = infer_flow(cfg, texts, route_runtime)
        flow.observed_checker_reads = [
            r["route"] for r in runtime.route_matrix()
            if r["actors"].get("checker", {}).get("flag_reads")
        ]
        flow.observed_team_reads = [
            r["route"] for r in runtime.route_matrix()
            if r["actors"].get("team", {}).get("flag_reads")
        ]

        out = write_all(cfg, result, runtime, flow, topo, root=out_root)
        print(
            f"{cfg.service_name}: {result.files_scanned} files, "
            f"{len(result.findings)} findings, {len(runtime.requests)} requests -> {out}"
        )
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
