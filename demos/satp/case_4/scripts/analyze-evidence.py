#!/usr/bin/env python3
import argparse
import base64
import csv
import json
import re
import statistics
import subprocess
from collections import defaultdict
from pathlib import Path


HRR_RANDOM = "cf21ad74e59a6111be1d8c021e65b891c2a211167abb8c5e079e09e2c8a8339c"
NUMERIC_FIELDS = [
    "satp_duration_ms",
    "capture_packets",
    "capture_wire_bytes",
    "capture_duration_s",
    "tcp_stream_count",
    "tcp_payload_bytes",
    "capture_wire_bytes_per_stream",
    "tcp_payload_bytes_per_stream",
    "tcp_payload_segment_count",
    "tcp_payload_segments_per_stream",
    "tcp_retransmission_count",
    "client_hello_message_bytes_mean",
    "server_hello_message_bytes_mean",
    "observable_hello_bytes_per_handshake",
    "client_key_share_bytes_mean",
    "server_key_share_bytes_mean",
    "server_hello_latency_ms_mean",
    "ca_certificate_der_bytes",
    "server_certificate_der_bytes_mean",
    "client_certificate_der_bytes_mean",
]


def run_tshark(capture: Path, display_filter: str, fields: list[str]) -> list[list[str]]:
    command = [
        "tshark", "-r", str(capture), "-Y", display_filter,
        "-T", "fields", "-E", "separator=|", "-E", "occurrence=f",
    ]
    for field in fields:
        command.extend(["-e", field])
    result = subprocess.run(command, check=True, text=True, capture_output=True)
    rows = []
    for line in result.stdout.splitlines():
        values = line.split("|")
        values.extend([""] * (len(fields) - len(values)))
        rows.append(values[:len(fields)])
    return rows


def stats(values: list[float | int]) -> dict:
    if not values:
        return {"count": 0, "min": None, "max": None, "mean": None, "median": None}
    return {
        "count": len(values),
        "min": min(values),
        "max": max(values),
        "mean": statistics.fmean(values),
        "median": statistics.median(values),
        "values": values,
    }


def first_int(value: str) -> int | None:
    if not value:
        return None
    match = re.search(r"\d+", value)
    return int(match.group()) if match else None


def pem_der_size(path: Path) -> int:
    payload = "".join(
        line.strip() for line in path.read_text().splitlines()
        if line and not line.startswith("-----")
    )
    return len(base64.b64decode(payload))


def flat_row(data: dict) -> dict:
    handshake = data["handshake"]
    capture = data["capture"]
    certificates = data["certificate_artifacts"]
    return {
        "scenario": data["scenario"],
        "repetition": data["repetition"],
        "success": data["success"],
        "evidence_directory": data["evidence_directory"],
        "session_id": data["satp"]["session_id"],
        "satp_duration_ms": data["satp"]["duration_ms"],
        "tls_group_ids": ";".join(str(v) for v in handshake["tls_group_ids"]),
        "nginx_group_values": ";".join(handshake["nginx_group_values"]),
        "mutual_tls_success": data["mutual_tls_success"],
        "capture_packets": capture["packets"],
        "capture_wire_bytes": capture["wire_bytes"],
        "capture_duration_s": capture["duration_s"],
        "tcp_stream_count": capture["tcp_stream_count"],
        "tcp_payload_bytes": capture["tcp_payload_bytes"],
        "capture_wire_bytes_per_stream": capture["wire_bytes_per_stream"],
        "tcp_payload_bytes_per_stream": capture["tcp_payload_bytes_per_stream"],
        "tcp_payload_segment_count": capture["tcp_payload_segment_count"],
        "tcp_payload_segments_per_stream": capture["tcp_payload_segments_per_stream"],
        "tcp_retransmission_count": capture["tcp_retransmission_count"],
        "hello_retry_request_count": handshake["hello_retry_request_count"],
        "client_hello_message_bytes_mean": handshake["client_hello_message_bytes"]["mean"],
        "server_hello_message_bytes_mean": handshake["server_hello_message_bytes"]["mean"],
        "observable_hello_bytes_per_handshake": handshake["observable_hello_bytes_per_handshake"],
        "client_key_share_bytes_mean": handshake["client_key_share_bytes"]["mean"],
        "server_key_share_bytes_mean": handshake["server_key_share_bytes"]["mean"],
        "server_hello_latency_ms_mean": handshake["server_hello_latency_ms"]["mean"],
        "ca_certificate_der_bytes": certificates["ca_der_bytes"],
        "server_certificate_der_bytes_mean": certificates["server_der_bytes"]["mean"],
        "client_certificate_der_bytes_mean": certificates["client_der_bytes"]["mean"],
        "on_wire_certificate_message_bytes": "",
        "on_wire_certificate_verify_bytes": "",
    }


def analyze(args: argparse.Namespace) -> None:
    evidence = Path(args.evidence).resolve()
    capture_path = evidence / "proxy-tls.pcapng"
    if not capture_path.is_file():
        raise SystemExit(f"capture missing: {capture_path}")

    frame_rows = run_tshark(capture_path, "tcp", [
        "frame.time_epoch", "frame.len", "tcp.stream", "tcp.len",
        "tcp.analysis.retransmission",
    ])
    frame_times = [float(row[0]) for row in frame_rows if row[0]]
    frame_lengths = [int(row[1]) for row in frame_rows if row[1]]
    streams = {int(row[2]) for row in frame_rows if row[2]}
    tcp_lengths = [int(row[3]) for row in frame_rows if row[3]]
    retransmissions = sum(1 for row in frame_rows if row[4])

    hello_rows = run_tshark(capture_path, "tls.handshake.type == 1 || tls.handshake.type == 2", [
        "tcp.stream", "frame.time_epoch", "tls.handshake.type", "tls.handshake.length",
        "tls.handshake.extensions_key_share_group",
        "tls.handshake.extensions_key_share_key_exchange_length",
        "tls.handshake.random",
    ])
    client_times: dict[int, list[float]] = defaultdict(list)
    server_times: dict[int, list[float]] = defaultdict(list)
    client_hello_sizes: list[int] = []
    server_hello_sizes: list[int] = []
    client_key_shares: list[int] = []
    server_key_shares: list[int] = []
    group_ids: set[int] = set()
    hrr_count = 0
    for stream_s, time_s, type_s, length_s, group_s, key_length_s, random_s in hello_rows:
        stream = int(stream_s)
        handshake_type = first_int(type_s)
        message_length = first_int(length_s)
        group = first_int(group_s)
        key_length = first_int(key_length_s)
        if group is not None:
            group_ids.add(group)
        if random_s.lower() == HRR_RANDOM:
            hrr_count += 1
        if handshake_type == 1:
            client_times[stream].append(float(time_s))
            if message_length is not None:
                client_hello_sizes.append(message_length + 4)
            if key_length is not None:
                client_key_shares.append(key_length)
        elif handshake_type == 2:
            server_times[stream].append(float(time_s))
            if message_length is not None:
                server_hello_sizes.append(message_length + 4)
            if key_length is not None:
                server_key_shares.append(key_length)

    hello_latencies = []
    for stream, starts in client_times.items():
        responses = server_times.get(stream, [])
        for start, response in zip(starts, responses):
            if response >= start:
                hello_latencies.append((response - start) * 1000)

    timing_path = evidence / "satp-timing.json"
    timing = json.loads(timing_path.read_text()) if timing_path.is_file() else {}
    session_path = evidence / "session_output.json"
    session = json.loads(session_path.read_text()) if session_path.is_file() else {}
    status = session.get("statusResponse", {})
    balance_text = (evidence / "balances-after.log").read_text()
    success = (
        status.get("status") == "DONE"
        and status.get("substatus") == "COMPLETED"
        and "8545 - User Balance: 0" in balance_text
        and "8546 - User Balance: 100" in balance_text
        and balance_text.count("Bridge Contract Balance: 0") == 2
    )

    proxy_log = (evidence / "proxy.log").read_text()
    nginx_groups = sorted(value for value in set(re.findall(r"\bgroup=([^ ]+)", proxy_log)) if value != "-")
    mutual_tls_success = "client_verify=SUCCESS" in proxy_log

    ca_paths = sorted(evidence.glob("ca.crt"))
    server_paths = sorted(evidence.glob("proxy-*-server.crt"))
    client_paths = sorted(evidence.glob("proxy-*-client.crt"))
    ca_sizes = [pem_der_size(path) for path in ca_paths]
    server_sizes = [pem_der_size(path) for path in server_paths]
    client_sizes = [pem_der_size(path) for path in client_paths]

    image_inspect = json.loads((evidence / "proxy-image-inspect.json").read_text())
    image_id = image_inspect[0].get("Id") if image_inspect else None

    data = {
        "schema_version": 1,
        "scenario": args.scenario,
        "repetition": args.repetition,
        "success": success,
        "evidence_directory": str(evidence),
        "proxy_image_id": image_id,
        "satp": {
            "session_id": session.get("sessionID"),
            "status": status.get("status"),
            "substatus": status.get("substatus"),
            "duration_ms": timing.get("duration_ms"),
            "timing_definition": "wall-clock duration of satp-transact.py",
        },
        "mutual_tls_success": mutual_tls_success,
        "capture": {
            "packets": len(frame_rows),
            "wire_bytes": sum(frame_lengths),
            "duration_s": (max(frame_times) - min(frame_times)) if frame_times else None,
            "tcp_stream_count": len(streams),
            "tcp_payload_bytes": sum(tcp_lengths),
            "wire_bytes_per_stream": sum(frame_lengths) / len(streams) if streams else None,
            "tcp_payload_bytes_per_stream": sum(tcp_lengths) / len(streams) if streams else None,
            "tcp_payload_segment_count": sum(1 for value in tcp_lengths if value > 0),
            "tcp_payload_segments_per_stream": sum(1 for value in tcp_lengths if value > 0) / len(streams) if streams else None,
            "tcp_payload_segment_bytes": stats([value for value in tcp_lengths if value > 0]),
            "tcp_retransmission_count": retransmissions,
            "capture_scope": "packets on proxy TLS port 3443 captured once on the experiment Docker bridge",
        },
        "handshake": {
            "tls_group_ids": sorted(group_ids),
            "nginx_group_values": nginx_groups,
            "client_hello_message_bytes": stats(client_hello_sizes),
            "server_hello_message_bytes": stats(server_hello_sizes),
            "observable_hello_bytes_per_handshake": (statistics.fmean(client_hello_sizes) + statistics.fmean(server_hello_sizes)) if client_hello_sizes and server_hello_sizes else None,
            "client_key_share_bytes": stats(client_key_shares),
            "server_key_share_bytes": stats(server_key_shares),
            "server_hello_latency_ms": stats(hello_latencies),
            "server_hello_latency_definition": "ServerHello timestamp minus ClientHello timestamp on the same TCP stream",
            "hello_retry_request_count": hrr_count,
            "on_wire_certificate_message_bytes": None,
            "on_wire_certificate_verify_bytes": None,
            "encrypted_field_limitation": "TLS 1.3 encrypts Certificate and CertificateVerify; the capture has no session-key log, so these on-wire sizes are unavailable.",
        },
        "certificate_artifacts": {
            "ca_der_bytes": ca_sizes[0] if ca_sizes else None,
            "server_der_bytes": stats(server_sizes),
            "client_der_bytes": stats(client_sizes),
            "definition": "DER size of the public certificate artifacts, not encrypted TLS record size",
        },
    }

    json_path = evidence / "measurements.json"
    csv_path = evidence / "measurements.csv"
    json_path.write_text(json.dumps(data, indent=2, sort_keys=True) + "\n")
    row = flat_row(data)
    with csv_path.open("w", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=list(row))
        writer.writeheader()
        writer.writerow(row)

    checksum_path = evidence / "SHA256SUMS"
    files = sorted(path for path in evidence.iterdir() if path.is_file() and path.name != "SHA256SUMS")
    with checksum_path.open("w") as handle:
        for path in files:
            digest = subprocess.run(["sha256sum", str(path)], check=True, text=True, capture_output=True).stdout.split()[0]
            handle.write(f"{digest}  {path.name}\n")
    print(json_path)


def aggregate(args: argparse.Namespace) -> None:
    root = Path(args.comparison_root).resolve()
    index_path = root / "run-index.tsv"
    records = []
    failures = []
    with index_path.open(newline="") as handle:
        reader = csv.DictReader(handle, delimiter="\t")
        for index_row in reader:
            if index_row["exit_code"] != "0" or not index_row["measurement_json"]:
                failures.append(index_row)
                continue
            data = json.loads(Path(index_row["measurement_json"]).read_text())
            records.append(data)

    flat_records = [flat_row(data) for data in records]
    runs_path = root / "runs.csv"
    if flat_records:
        with runs_path.open("w", newline="") as handle:
            writer = csv.DictWriter(handle, fieldnames=list(flat_records[0]))
            writer.writeheader()
            writer.writerows(flat_records)

    scenario_rows = []
    scenario_json = {}
    for scenario in ("4a", "4b", "4c", "4c-s", "4d"):
        selected = [row for row in flat_records if row["scenario"] == scenario]
        entry = {
            "attempts": sum(1 for row in csv.DictReader(index_path.open(), delimiter="\t") if row["scenario"] == scenario),
            "successful_runs": sum(1 for row in selected if row["success"]),
            "tls_group_ids": sorted({group for row in selected for group in row["tls_group_ids"].split(";") if group}),
            "nginx_group_values": sorted({group for row in selected for group in row["nginx_group_values"].split(";") if group}),
            "mutual_tls_successful_runs": sum(1 for row in selected if row["mutual_tls_success"]),
            "hello_retry_request_total": sum(int(float(row["hello_retry_request_count"])) for row in selected),
            "tcp_retransmission_total": sum(int(float(row["tcp_retransmission_count"])) for row in selected),
            "metrics": {},
        }
        summary_row = {"scenario": scenario, "attempts": entry["attempts"], "successful_runs": entry["successful_runs"]}
        for field in NUMERIC_FIELDS:
            values = [float(row[field]) for row in selected if row.get(field) not in (None, "")]
            metric = {
                "count": len(values),
                "mean": statistics.fmean(values) if values else None,
                "stdev": statistics.stdev(values) if len(values) > 1 else 0.0 if values else None,
                "min": min(values) if values else None,
                "max": max(values) if values else None,
            }
            entry["metrics"][field] = metric
            for suffix in ("mean", "stdev", "min", "max"):
                summary_row[f"{field}_{suffix}"] = metric[suffix]
        scenario_json[scenario] = entry
        scenario_rows.append(summary_row)

    summary_csv = root / "summary.csv"
    with summary_csv.open("w", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=list(scenario_rows[0]))
        writer.writeheader()
        writer.writerows(scenario_rows)

    summary = {
        "schema_version": 1,
        "comparison_root": str(root),
        "repetitions_per_scenario": 3,
        "run_count": len(records),
        "failure_count": len(failures),
        "failures": failures,
        "scenario_results": scenario_json,
        "methodology": {
            "order": "three recorded, deterministic rotating scenario orders",
            "satp_duration": "wall-clock duration of satp-transact.py",
            "server_hello_latency": "ServerHello minus ClientHello timestamp on each TCP stream",
            "capture_scope": "packets on proxy TLS port 3443 captured once on the experiment Docker bridge",
            "certificate_artifact_size": "DER bytes of public certificate files",
            "per_stream_normalization": "scenario capture totals divided by the number of observed TCP streams",
        },
        "limitations": [
            "TLS 1.3 encrypts Certificate and CertificateVerify; their on-wire sizes are unavailable without session-key logging.",
            "ServerHello latency is a repeatable observable component, not full TLS handshake completion latency.",
            "Three repetitions characterize this Datsun test environment but are not a production benchmark.",
        ],
    }
    (root / "summary.json").write_text(json.dumps(summary, indent=2, sort_keys=True) + "\n")
    print(root / "summary.json")


def main() -> None:
    parser = argparse.ArgumentParser()
    subparsers = parser.add_subparsers(dest="command", required=True)
    analyze_parser = subparsers.add_parser("analyze")
    analyze_parser.add_argument("--evidence", required=True)
    analyze_parser.add_argument("--scenario", required=True)
    analyze_parser.add_argument("--repetition", required=True, type=int)
    analyze_parser.set_defaults(function=analyze)
    aggregate_parser = subparsers.add_parser("aggregate")
    aggregate_parser.add_argument("--comparison-root", required=True)
    aggregate_parser.set_defaults(function=aggregate)
    args = parser.parse_args()
    args.function(args)


if __name__ == "__main__":
    main()
