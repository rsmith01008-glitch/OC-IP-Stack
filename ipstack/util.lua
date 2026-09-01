-- ipstack.util: small shared helpers used across every layer.
local computer = require("computer")

local util = {}

-- Internet-checksum-style 16 bit ones'-complement sum over a byte string.
-- Caller is responsible for zeroing the checksum field slot before calling
-- this over a full header+payload, and for treating a return of 0 as the
-- valid "no complement needed" case (ones'-complement checksums use 0xFFFF
-- to represent zero, since plain 0 would be indistinguishable from "no
-- checksum computed" on some wire formats; we don't need that trick here
-- since our header always carries an explicit checksum field).
function util.checksum16(data)
  local sum = 0
  local len = #data
  local i = 1
  while i + 1 <= len do
    sum = sum + ((data:byte(i) << 8) | data:byte(i + 1))
    i = i + 2
  end
  if i <= len then
    sum = sum + (data:byte(i) << 8)
  end
  while sum > 0xFFFF do
    sum = (sum & 0xFFFF) + (sum >> 16)
  end
  return (~sum) & 0xFFFF
end

function util.ipToString(ip)
  if not ip then return nil end
  return string.format("%d.%d", ip.subnet, ip.host)
end

function util.parseIp(str)
  if type(str) ~= "string" then return nil end
  local s, h = str:match("^(%d+)%.(%d+)$")
  if not s then return nil end
  s, h = tonumber(s), tonumber(h)
  if s < 0 or s > 255 or h < 0 or h > 255 then return nil end
  return { subnet = s, host = h }
end

function util.ipEquals(a, b)
  if not a or not b then return false end
  return a.subnet == b.subnet and a.host == b.host
end

-- Ring-buffer logger. `sink` is the table to log into (normally
-- core.state.log); kept as a parameter rather than a hard dependency on
-- core.lua to avoid a require() cycle (core does not require util in a way
-- that would loop, but keeping util dependency-free makes the layering
-- easier to reason about).
function util.makeLogger(sink, ringSize)
  ringSize = ringSize or 200
  return function(level, fmt, ...)
    local ok, msg = pcall(string.format, fmt, ...)
    if not ok then msg = fmt end
    local entry = {
      time = computer.uptime(),
      level = level,
      message = msg,
    }
    table.insert(sink, entry)
    while #sink > ringSize do
      table.remove(sink, 1)
    end
  end
end

return util
