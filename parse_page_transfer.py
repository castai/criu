#!/usr/bin/env python3
"""
Parse CRIU dump log to extract page transfer timing information.

This script analyzes log files from CRIU dump operations and extracts
statistics about memory page transfers to the page server via splice.
"""

import re
import sys
from dataclasses import dataclass
from typing import Optional


@dataclass
class SpliceOperation:
    """Represents a single splice operation."""
    start_time: float
    end_time: float
    bytes_requested: int
    bytes_sent: int

    @property
    def duration(self) -> float:
        return self.end_time - self.start_time


def parse_timestamp(line: str) -> Optional[float]:
    """Extract timestamp from log line like '(00.260819) page-xfer: ...'"""
    match = re.match(r'\((\d+\.\d+)\)', line)
    if match:
        return float(match.group(1))
    return None


def parse_log(log_path: str) -> list[SpliceOperation]:
    """Parse the log file and extract splice operations."""
    operations = []

    # Pattern for "Splicing X bytes into socket"
    splice_start_pattern = re.compile(r'Splicing\s+([0-9a-fA-F]+)\s+bytes into socket')
    # Pattern for "Spliced: X bytes sent"
    splice_end_pattern = re.compile(r'Spliced:\s+([0-9a-fA-F]+)\s+bytes sent')

    pending_splice = None

    with open(log_path, 'r') as f:
        for line in f:
            timestamp = parse_timestamp(line)
            if timestamp is None:
                continue

            # Check for splice start
            start_match = splice_start_pattern.search(line)
            if start_match:
                bytes_requested = int(start_match.group(1), 16)
                pending_splice = {
                    'start_time': timestamp,
                    'bytes_requested': bytes_requested
                }
                continue

            # Check for splice end
            end_match = splice_end_pattern.search(line)
            if end_match and pending_splice is not None:
                bytes_sent = int(end_match.group(1), 16)
                operations.append(SpliceOperation(
                    start_time=pending_splice['start_time'],
                    end_time=timestamp,
                    bytes_requested=pending_splice['bytes_requested'],
                    bytes_sent=bytes_sent
                ))
                pending_splice = None

    return operations


def format_bytes(num_bytes: int) -> str:
    """Format bytes in human-readable form."""
    if num_bytes >= 1024 * 1024:
        return f"{num_bytes / (1024 * 1024):.2f} MB"
    elif num_bytes >= 1024:
        return f"{num_bytes / 1024:.2f} KB"
    else:
        return f"{num_bytes} bytes"


def format_duration(seconds: float) -> str:
    """Format duration in human-readable form."""
    if seconds >= 1:
        return f"{seconds:.3f} s"
    elif seconds >= 0.001:
        return f"{seconds * 1000:.3f} ms"
    else:
        return f"{seconds * 1000000:.3f} µs"


def main():
    if len(sys.argv) < 2:
        log_path = "dump-2.log"
    else:
        log_path = sys.argv[1]

    print(f"Parsing log file: {log_path}")
    print("=" * 60)

    operations = parse_log(log_path)

    if not operations:
        print("No splice operations found in the log file.")
        return

    # Calculate statistics
    total_bytes = sum(op.bytes_sent for op in operations)
    total_duration = sum(op.duration for op in operations)

    # Overall time span (first start to last end)
    first_start = min(op.start_time for op in operations)
    last_end = max(op.end_time for op in operations)
    overall_span = last_end - first_start

    durations = [op.duration for op in operations]
    min_duration = min(durations)
    max_duration = max(durations)
    avg_duration = total_duration / len(operations)

    sizes = [op.bytes_sent for op in operations]
    min_size = min(sizes)
    max_size = max(sizes)
    avg_size = total_bytes / len(operations)

    # Calculate throughput
    if total_duration > 0:
        throughput = total_bytes / total_duration
    else:
        throughput = 0

    print(f"\nPage Transfer Statistics")
    print("-" * 60)
    print(f"Number of splice operations:    {len(operations)}")
    print(f"Total bytes transferred:        {format_bytes(total_bytes)} ({total_bytes} bytes)")
    print()

    print("Timing:")
    print(f"  First splice started at:      {format_duration(first_start)}")
    print(f"  Last splice ended at:         {format_duration(last_end)}")
    print(f"  Overall time span:            {format_duration(overall_span)}")
    print(f"  Total splice time (sum):      {format_duration(total_duration)}")
    print()

    print("Per-operation duration:")
    print(f"  Minimum:                      {format_duration(min_duration)}")
    print(f"  Maximum:                      {format_duration(max_duration)}")
    print(f"  Average:                      {format_duration(avg_duration)}")
    print()

    print("Per-operation size:")
    print(f"  Minimum:                      {format_bytes(min_size)}")
    print(f"  Maximum:                      {format_bytes(max_size)}")
    print(f"  Average:                      {format_bytes(int(avg_size))}")
    print()

    print(f"Throughput:                     {format_bytes(int(throughput))}/s")
    print()

    # Size distribution
    print("Size distribution:")
    size_buckets = {}
    for op in operations:
        # Round to nearest page size for bucketing
        pages = op.bytes_sent // 4096
        if pages not in size_buckets:
            size_buckets[pages] = 0
        size_buckets[pages] += 1

    for pages in sorted(size_buckets.keys()):
        count = size_buckets[pages]
        bar = "#" * min(count // 5, 40)
        print(f"  {pages:4d} pages ({format_bytes(pages * 4096):>10s}): {count:4d} {bar}")

    print()
    print("=" * 60)


if __name__ == "__main__":
    main()
