#!/usr/bin/env python3
"""Sum the tokens and the time of this Claude Code session from its transcript.

Claude Code keeps every session's messages in ~/.claude/projects/<project>/
<session>.jsonl, each model call with its token usage. A Fixer run reads its
own transcript (the most recently written one) at its end and records the
result on the "Fixer runs" issue (docs/loop.md).

  usage.py                 the most recently written transcript
  usage.py --file <path>   a given one
"""

import argparse
import json
import os
import sys
from pathlib import Path

FIELDS = ("input_tokens", "output_tokens", "cache_creation_input_tokens", "cache_read_input_tokens")


def newest_transcript():
    root = Path(os.environ.get("CLAUDE_CONFIG_DIR") or Path.home() / ".claude") / "projects"
    transcripts = sorted(root.glob("*/*.jsonl"), key=lambda p: p.stat().st_mtime)
    if not transcripts:
        sys.exit(f"usage.py: no transcript under {root}")
    return transcripts[-1]


def main():
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--file", help="the transcript to read (default: the most recently written)")
    args = parser.parse_args()
    path = Path(args.file) if args.file else newest_transcript()

    totals = dict.fromkeys(FIELDS, 0)
    calls, seen, times = 0, set(), []
    for line in path.read_text(errors="replace").splitlines():
        try:
            entry = json.loads(line)
        except json.JSONDecodeError:
            continue
        if entry.get("timestamp"):
            times.append(entry["timestamp"])
        message = entry.get("message")
        usage = message.get("usage") if isinstance(message, dict) else None
        if not usage:
            continue
        # A model call that streams several content blocks is written once per block
        # with the same message id and usage; count it once.
        key = message.get("id") or entry.get("uuid")
        if key in seen:
            continue
        seen.add(key)
        calls += 1
        for field in FIELDS:
            totals[field] += usage.get(field) or 0
    print(json.dumps({
        "transcript": str(path),
        "started": min(times) if times else None,
        "ended": max(times) if times else None,
        "model_calls": calls,
        **totals,
    }, indent=2))


if __name__ == "__main__":
    main()
