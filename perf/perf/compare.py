"""Summarizes one run's measurements in Markdown.

    python3 perf/compare.py results/aarch64/v0.4.0.json [--nginx results/aarch64/nginx.json]

It starts with the scenarios where twinx takes more CPU time per request than nginx,
the most first. Each cell holds nginx / twinx: from the same run, or, where the run
measured twinx alone, nginx's from --nginx (perf/keep.py). Results recorded with the
twinx before beside them have it too; it is left out.
"""

import argparse
import json

NAMES = ("nginx", "twinx")


def fmt(v, digits=0):
    if v is None:
        return "–"
    return f"{v:,.{digits}f}"


def pair(s, key, digits=0):
    return " / ".join(fmt(s["servers"][n]["median"].get(key), digits) for n in NAMES)


def share(s, part, whole):
    """part as a percentage of whole, for each server."""
    cells = []
    for n in NAMES:
        m = s["servers"][n]["median"]
        cells.append(f"{m[part] / m[whole] * 100:.0f}%" if m.get(whole) and m.get(part) is not None else "–")
    return " / ".join(cells)


def errors(s):
    cells = []
    for n in NAMES:
        m = s["servers"][n]["median"]
        cells.append((fmt((m.get("socket_errors") or 0) + (m.get("bad_status") or 0)) if m else "–")
                     + (" (died)" if m.get("died") else ""))
    return " / ".join(cells)


def state(s, key, digits=0):
    """What was noted of each server before the load."""
    return " / ".join(fmt(s["servers"][n].get(key), digits) for n in NAMES)


def change(s, name, than, key="cpu_ms_per_1k_requests"):
    """How much more one server takes of key than another."""
    a, b = (s["servers"][n]["median"].get(key) for n in (name, than))
    return f"{(a / b - 1) * 100:+.0f}%" if a is not None and b else "–"


def above(load, key="cpu_ms_per_1k_requests"):
    """The scenarios where twinx takes more of key than nginx, with twinx over nginx, the most first."""
    rows = []
    for s in load:
        a, b = (s["servers"][n]["median"].get(key) for n in ("twinx", "nginx"))
        if a is not None and b and a > b:
            rows.append((a / b, s))
    return sorted(rows, key=lambda r: -r[0])


def table(header, rows):
    print("| " + " | ".join(header) + " |")
    print("|" + "---|" * len(header))
    for r in rows:
        print("| " + " | ".join(r) + " |")
    print()


def main(path, kept_path=None):
    now = json.load(open(path))
    kept = json.load(open(kept_path)) if kept_path else {"scenarios": {}}
    taken = 0
    for s in now["scenarios"]:
        if "nginx" not in s["servers"]:
            k = kept["scenarios"].get(s["name"])
            if not k:
                raise SystemExit(f"nginx was not measured in {s['name']}, and --nginx does not have it")
            s["servers"] = {"nginx": k["nginx"], **s["servers"]}
            taken += 1
    labels = now.get("labels", {})
    order = " / ".join(labels.get(n, n) for n in NAMES)
    m = now["machine"]
    load = [s for s in now["scenarios"] if s["kind"] == "load"]
    memory = [s for s in now["scenarios"] if s["kind"] == "memory"]
    slow = [s for s in now["scenarios"] if s["kind"] == "slow"]

    print(f"### {now['tag']} on {m['arch']}\n")
    print(f"{now['nginx']}; {m['cpu'] or 'CPU model not reported'}; servers on CPUs {m['server_cpus']}, "
          f"load on {m['load_cpus']}; median of {now['rounds']} rounds of {now['seconds']} s unless a scenario says otherwise. "
          f"Each cell is {order}"
          + (f"; in {taken} of the {len(now['scenarios'])} scenarios, nginx's are those kept from {kept['tag']} "
             f"({kept['date']}), on another runner" if taken else "") + ".\n")
    failed = [(s["name"], labels.get(n, n), e) for s in now["scenarios"] for n in NAMES
              for e in s["servers"][n]["median"].get("errors", [])]
    trouble = [f"{n}: {len(now['panics'][n])} panics, {now['restarts'][n]} restarts"
               for n in NAMES if now["panics"][n] or now["restarts"][n]]
    print(("Trouble: " + "; ".join(trouble)) if trouble else "No panics, no restarts.")
    print()

    missing = [(s["name"], labels.get(n, n), s["servers"][n]["not_measured"])
               for s in now["scenarios"] for n in NAMES if "not_measured" in s["servers"][n]]
    if failed:
        print("#### Rounds that gave no result\n")
        table(["Scenario", "server", "why"], [[a, b, " ".join(e.split()).replace("|", "\\|")] for a, b, e in failed])
    if missing:
        print("#### Not measured\n")
        print("Servers that did not start with the scenario's configuration, or did not answer as they should.\n")
        table(["Scenario", "server", "why"],
              [[a, b, " ".join(why.split()).replace("|", "\\|")] for a, b, why in missing])

    print("#### Above nginx\n")
    rows = above(load)
    if rows:
        print(f"The scenarios where {labels.get('twinx', 'twinx')} took more CPU time per request than nginx, "
              "the most first. Where the load generator is the limit, rps does not show it.\n")
        table(["Scenario", "CPU ms per 1k requests", "twinx / nginx"],
              [[s["name"], pair(s, "cpu_ms_per_1k_requests", 1), f"{ratio:.2f}×"] for ratio, s in rows])
    else:
        print(f"{labels.get('twinx', 'twinx')} took no more CPU time per request than nginx in any scenario measured.\n")

    if memory:
        print("#### Memory\n")
        print("Peak memory while clients read slowly, or connections are idle, and how many of them were "
              "answered and kept.\n")
        table(["Scenario", "idle MB", "peak MB", "twinx over nginx", "answered"],
              [[s["name"], state(s, "idle_rss_mb", 1), pair(s, "peak_rss_mb", 1),
                change(s, "twinx", "nginx", "peak_rss_mb"),
                pair(s, "clients_ok") + f" of {fmt(s['servers']['nginx']['median'].get('clients'))}"] for s in memory])

    latency = [s for s in now["scenarios"] if s["kind"] in ("beside", "first")]
    if latency:
        print("#### Latency\n")
        print("Of requests beside another load, or of the first byte on a connection of its own.\n")
        table(["Scenario", "p50 ms", "p99 ms", "longest ms"],
              [[s["name"], pair(s, "p50_ms", 2), pair(s, "p99_ms", 2), pair(s, "max_ms", 2)] for s in latency])

    print("<details><summary>Everything else that was recorded</summary>\n")
    print("#### Throughput and latency\n")
    print("h2load gives no percentiles, and s_time no latency.\n")
    table(["Scenario", "rps", "MB/s", "p50 ms", "p99 ms", "max ms", "errors"],
          [[s["name"], pair(s, "rps"), pair(s, "mb_per_s", 1), pair(s, "p50_ms", 2), pair(s, "p99_ms", 2),
            pair(s, "max_ms", 0), errors(s)] for s in load])

    print("#### CPU and memory\n")
    print("CPU % is of one CPU; system is the share of the CPU time spent in the kernel.\n")
    table(["Scenario", "CPU %", "CPU ms per 1k requests", "system", "idle MB", "peak MB", "growth MB", "idle threads", "peak threads"],
          [[s["name"], pair(s, "cpu_percent", 0), pair(s, "cpu_ms_per_1k_requests", 1),
            share(s, "system_seconds", "cpu_seconds"), state(s, "idle_rss_mb", 1), pair(s, "peak_rss_mb", 1), pair(s, "rss_growth_mb", 1),
            state(s, "idle_threads"), pair(s, "peak_threads")]
           for s in now["scenarios"] if s["kind"] != "memory"])

    print("#### Queues\n")
    print("Peaks, sampled every 0.2 s on the server's side: connections waiting for accept, bytes received "
          "but not read yet (Recv-Q) and the connections holding them, bytes sent but not acknowledged yet "
          "(Send-Q); and what the run added to the namespace's listen queue overflows and retransmitted segments.\n")
    table(["Scenario", "listen backlog", "accept queue", "Recv-Q KB", "connections unread", "Send-Q KB", "listen overflows", "retransmits"],
          [[s["name"], state(s, "listen_backlog"), pair(s, "peak_accept_queue"), pair(s, "peak_recv_q_kb", 1), pair(s, "peak_connections_unread"),
            pair(s, "peak_send_q_kb", 0), pair(s, "listen_overflows"), pair(s, "retransmitted_segments")]
           for s in now["scenarios"]])

    proxy = [s for s in load if s.get("upstream") or s.get("accepts")]
    if proxy:
        print("#### Proxying\n")
        print("How many connections to the upstreams a request took, and where the upstream is loaded directly "
              "too, how much later the answers came through each server. The direct runs happen between the others, so a few tenths of a millisecond either way, "
              "below zero included, is noise.\n")
        rows = []
        for s in proxy:
            d = s.get("direct_load") or (s["direct"]["median"] if isinstance(s.get("direct"), dict) else {})
            added = lambda key: " / ".join(
                fmt(s["servers"][n]["median"][key] - d[key], 2) if d.get(key) is not None
                and s["servers"][n]["median"].get(key) is not None else "–" for n in NAMES)
            rows.append([s["name"], fmt(d.get("rps")), f"{fmt(d.get('p50_ms'), 2)} / {fmt(d.get('p99_ms'), 2)}",
                         added("p50_ms"), added("p99_ms"), pair(s, "upstream_connections_per_request", 3)])
        table(["Scenario", "direct rps", "direct p50 / p99 ms", "added p50 ms", "added p99 ms",
               "upstream connections per request"], rows)

    if slow:
        print("#### Slow clients\n")
        print("Ordinary requests while the slow connections are held open, and how many of those the server kept.\n")
        rows = []
        for s in slow:
            # Without them: the load scenario with the same requests, measured on its own.
            base = next((b for b in load if b["path"] == s["path"] and b["connections"] == s["connections"]
                         and not b.get("close") and not b.get("reload") and not b.get("log")), None)
            rows.append([s["name"], pair(base, "rps") if base else "–", pair(s, "rps"),
                         pair(base, "p99_ms", 2) if base else "–", pair(s, "p99_ms", 2),
                         pair(s, "slow_kept_open") + f" of {fmt(s['servers']['nginx']['median'].get('slow_connected'))}"])
        table(["Scenario", "rps without them", "rps with them", "p99 ms without them", "p99 ms with them",
               "slow connections kept"], rows)
    print("</details>")


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("results")
    parser.add_argument("--nginx", help="nginx's kept measurements, for the scenarios the run measured twinx alone in")
    args = parser.parse_args()
    main(args.results, args.nginx)
