-- ipstack.config: /etc/ipstack.cfg load/save + defaults.
-- Uses the OpenOS `serialization` library directly (human-editable, low
-- frequency file) rather than the packed binary format used for wire
-- headers elsewhere in this stack.
local serialization = require("serialization")
local filesystem = require("filesystem")

local config = {}

config.DEFAULT_PATH = "/etc/ipstack.cfg"

config.DEFAULTS = {
  -- [modemAddress] = { subnet = n, host = n }
  interfaces = {},
  -- { subnet = n, host = n } or nil for a pure relay with no default route
  defaultGateway = nil,
  -- list of { subnet = n, viaGateway = { subnet = n, host = n } }
  staticRoutes = {},
  -- static name -> "subnet.host" table, resolved locally only
  hosts = {},
  arp = {
    ttl = 60,
    requestTimeoutSec = 3,
    requestRetries = 3,
  },
  ip = {
    defaultTtl = 32,
    reassemblyTimeoutSec = 10,
    forwarding = false,
  },
  tcp = {
    rtoSec = 1,
    rtoMaxSec = 8,
    maxRetries = 8,
    defaultWindow = 4096,
    idleTimeoutSec = 120,
    timeWaitSec = 5,
  },
  udp = {
    maxDatagram = 32768,
    recvQueueMax = 64,
  },
  stream = {
    -- How often the daemon checks every open stream.lua publisher for a
    -- due sample. Independent of maxRatePerSec -- this just needs to be
    -- fine-grained enough to hit maxRatePerSec's cadence accurately.
    driverIntervalSec = 0.05,
    -- Publish rate ceiling, in samples/sec, for any one
    -- stream.startPublishing() registration -- OC's own tick rate (~20
    -- Hz); publishing faster is meaningless (nothing produces new samples
    -- that fast) and would just waste modem sends. A rate above this is
    -- silently clamped, not rejected.
    maxRatePerSec = 20,
    recvQueueMax = 64,
  },
  eth = {
    port = 4790,
  },
  wireless = {
    strength = 400,
  },
  log = {
    level = "info",
    ringSize = 200,
  },
}

-- Recursively fill any key missing from `tbl` with the value from
-- `defaults`, without touching keys `tbl` already sets. Returns tbl.
local function deepMergeDefaults(tbl, defaults)
  for k, defaultV in pairs(defaults) do
    local curV = tbl[k]
    if curV == nil then
      if type(defaultV) == "table" then
        tbl[k] = deepMergeDefaults({}, defaultV)
      else
        tbl[k] = defaultV
      end
    elseif type(curV) == "table" and type(defaultV) == "table" then
      deepMergeDefaults(curV, defaultV)
    end
  end
  return tbl
end

-- Returns a fresh deep copy of config.DEFAULTS.
function config.newDefaults()
  return deepMergeDefaults({}, config.DEFAULTS)
end

-- Loads `path` (defaults to /etc/ipstack.cfg), deep-merging in any keys
-- missing from the file so a partial/hand-edited config never crashes a
-- reader that expects every DEFAULTS key to exist. Returns the config
-- table, or config.newDefaults() plus an error string if the file is
-- missing or unparsable.
function config.load(path)
  path = path or config.DEFAULT_PATH
  local f, openErr = io.open(path, "r")
  if not f then
    return config.newDefaults(), "could not open " .. path .. ": " .. tostring(openErr)
  end
  local raw = f:read("*a")
  f:close()

  local ok, tbl = pcall(serialization.unserialize, raw)
  if not ok or type(tbl) ~= "table" then
    return config.newDefaults(), "could not parse " .. path .. " (invalid Lua table literal)"
  end

  return deepMergeDefaults(tbl, config.DEFAULTS)
end

-- Writes `tbl` to `path` (defaults to /etc/ipstack.cfg) via
-- serialization.serialize. Returns true, or nil+err on failure.
--
-- Written to a temp file first, then verified (byte-for-byte match plus a
-- successful unserialize round-trip) before being moved into place with
-- filesystem.rename. An interrupted write (I/O error, low drive space, a
-- save/chunk-unload) can otherwise leave a truncated, unparsable file --
-- since `path` may already hold a working config from a previous save,
-- writing straight into it (which "w" mode truncates immediately) would
-- risk replacing a good config with a broken one and no way to tell.
-- Going through a temp file means a failed write only ever leaves the
-- temp file broken; `path` itself is untouched until we know the new
-- content is good.
function config.save(tbl, path)
  path = path or config.DEFAULT_PATH
  local tmpPath = path .. ".tmp"
  local content = serialization.serialize(tbl, true)

  local f, openErr = io.open(tmpPath, "w")
  if not f then
    return nil, "could not open " .. tmpPath .. " for writing: " .. tostring(openErr)
  end
  local writeOk, writeErr = pcall(function() f:write(content) end)
  f:close()
  if not writeOk then
    return nil, "write to " .. tmpPath .. " failed: " .. tostring(writeErr)
  end

  local rf, reopenErr = io.open(tmpPath, "r")
  if not rf then
    return nil, "wrote " .. tmpPath .. " but could not reopen it to verify: " .. tostring(reopenErr)
  end
  local written = rf:read("*a")
  rf:close()
  if written ~= content or not pcall(serialization.unserialize, written) then
    return nil, "write to " .. tmpPath .. " produced a corrupt/truncated file -- " ..
      "left in place for inspection, " .. path .. " was not touched"
  end

  local moveOk, moveErr = filesystem.rename(tmpPath, path)
  if not moveOk then
    return nil, "verified write but could not move " .. tmpPath .. " into place at " .. path .. ": " .. tostring(moveErr)
  end
  return true
end

return config
