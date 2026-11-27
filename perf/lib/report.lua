-- Prints wrk's results as one JSON line, after wrk's own report. Latencies are in microseconds.
done = function(summary, latency, requests)
  local e = summary.errors
  io.write(string.format(
    '{"requests":%d,"duration_us":%d,"bytes":%d,"connect_errors":%d,"read_errors":%d,' ..
    '"write_errors":%d,"bad_status":%d,"timeouts":%d,"p50_us":%d,"p90_us":%d,"p99_us":%d,"max_us":%d}\n',
    summary.requests, summary.duration, summary.bytes, e.connect, e.read, e.write, e.status, e.timeout,
    latency:percentile(50), latency:percentile(90), latency:percentile(99), latency.max))
end
