#!/usr/bin/env python3
"""
Query Logfire observability data for the auto-soc simulation.

Usage:
    python scripts/logfire_query.py               # last 12 hours
    python scripts/logfire_query.py --hours 24    # last 24 hours
    python scripts/logfire_query.py --sql "SELECT ..."  # custom SQL
"""
import argparse
import os
import sys

from dotenv import load_dotenv
from logfire.experimental.query_client import LogfireQueryClient


def get_client() -> LogfireQueryClient:
    load_dotenv()
    token = os.getenv("LOGFIRE_READ_TOKEN")
    if not token:
        print("Error: LOGFIRE_READ_TOKEN not set in .env", file=sys.stderr)
        sys.exit(1)
    return LogfireQueryClient(read_token=token)


def query_simulation_runs(client: LogfireQueryClient, hours: int = 12):
    result = client.query_json_rows(f"""
        SELECT span_name,
               round(duration, 1)  AS duration_s,
               start_timestamp,
               attributes
        FROM records
        WHERE start_timestamp > now() - interval '{hours} hours'
        ORDER BY start_timestamp ASC
    """)

    rows = result["rows"]
    if not rows:
        print(f"No spans found in the last {hours} hours.")
        return

    print(f"\n{'Time':<20} {'Span':<32} {'Duration':>10}  {'In':>6} {'Out':>6}")
    print("─" * 80)

    for row in rows:
        attrs = row["attributes"] or {}
        tokens_in  = attrs.get("gen_ai.usage.input_tokens", "")
        tokens_out = attrs.get("gen_ai.usage.output_tokens", "")
        ts = row["start_timestamp"][:19].replace("T", " ")
        name = row["span_name"]
        dur = row["duration_s"]
        print(f"{ts:<20} {name:<32} {dur:>9}s  {str(tokens_in):>6} {str(tokens_out):>6}")

    print()


def query_custom(client: LogfireQueryClient, sql: str):
    result = client.query_json_rows(sql)
    rows = result["rows"]
    if not rows:
        print("No results.")
        return
    headers = list(rows[0].keys())
    print("  ".join(f"{h:<20}" for h in headers))
    print("─" * (22 * len(headers)))
    for row in rows:
        print("  ".join(f"{str(row[h]):<20}" for h in headers))


def main():
    parser = argparse.ArgumentParser(description="Query Logfire auto-soc observability data")
    parser.add_argument("--hours", type=int, default=12, help="Look back N hours (default: 12)")
    parser.add_argument("--sql", type=str, help="Run a custom SQL query against Logfire")
    args = parser.parse_args()

    client = get_client()

    if args.sql:
        query_custom(client, args.sql)
    else:
        query_simulation_runs(client, hours=args.hours)


if __name__ == "__main__":
    main()
