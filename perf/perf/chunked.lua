-- 1 MB POSTs in chunks of 64 KB.
local request_text
function init(args)
  local chunk = "10000\r\n" .. string.rep("p", 65536) .. "\r\n"
  request_text = "POST " .. wrk.path .. " HTTP/1.1\r\nHost: localhost\r\nTransfer-Encoding: chunked\r\n\r\n" ..
    string.rep(chunk, 16) .. "0\r\n\r\n"
end
function request() return request_text end
dofile("/perf/report.lua")
