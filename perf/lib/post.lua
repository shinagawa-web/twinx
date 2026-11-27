-- 64 KB POSTs.
wrk.method = "POST"
wrk.body = string.rep("p", 65536)
dofile("/perf/report.lua")
