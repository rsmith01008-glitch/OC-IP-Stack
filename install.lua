-- OC-IP-Stack installer.
--
-- Works two ways:
--  1. Run from inside a cloned/extracted copy of the repo (this script
--     sitting next to programs.cfg and the ipstack/ directory) -- files
--     are copied from disk.
--  2. Run standalone (e.g. `wget -f <url>/install.lua install.lua` then
--     `install`) on a machine with an internet card and no local copy --
--     files are fetched over HTTP from GitHub.
--
-- Deliberately self-contained: does not require() any ipstack.* module,
-- since those aren't installed yet when this runs.
local component = require("component")
local filesystem = require("filesystem")
local serialization = require("serialization")
local shell = require("shell")

local RAW_BASE = "https://raw.githubusercontent.com/rsmith01008-glitch/OC-IP-Stack/main/"

-- Kept as an explicit list (rather than derived from programs.cfg's
-- directory-shorthand entry) because the internet-fetch path has no way
-- to list a directory's contents over plain HTTPS raw file access -- keep
-- this in sync with programs.cfg's `files` table by hand.
local FILES = {
  { src = "ipstack/util.lua",              dst = "/lib/ipstack/util.lua" },
  { src = "ipstack/config.lua",            dst = "/lib/ipstack/config.lua" },
  { src = "ipstack/core.lua",              dst = "/lib/ipstack/core.lua" },
  { src = "ipstack/eth.lua",               dst = "/lib/ipstack/eth.lua" },
  { src = "ipstack/ip.lua",                dst = "/lib/ipstack/ip.lua" },
  { src = "ipstack/udp.lua",               dst = "/lib/ipstack/udp.lua" },
  { src = "ipstack/tcp.lua",               dst = "/lib/ipstack/tcp.lua" },
  { src = "ipstack/multicast.lua",         dst = "/lib/ipstack/multicast.lua" },
  { src = "ipstack/stream.lua",            dst = "/lib/ipstack/stream.lua" },
  { src = "ipstack/socket.lua",            dst = "/lib/ipstack/socket.lua" },
  { src = "ipstack/daemon.lua",            dst = "/lib/ipstack/daemon.lua" },
  { src = "rc.d/ipstackd.lua",             dst = "/etc/rc.d/ipstackd.lua" },
  { src = "usr/bin/ipstack-ctl.lua",       dst = "/bin/ipstack-ctl.lua" },
  { src = "etc/ipstack.cfg.example",       dst = "/etc/ipstack.cfg.example" },
}

local CONFIG_PATH = "/etc/ipstack.cfg"

-- Mirrors ipstack.config.DEFAULTS. Duplicated here (rather than requiring
-- the not-yet-installed ipstack.config) so the installer never depends on
-- its own output.
local function defaultConfigTable()
  return {
    interfaces = {},
    defaultGateway = nil,
    staticRoutes = {},
    hosts = {},
    arp = { ttl = 60, requestTimeoutSec = 3, requestRetries = 3 },
    ip = { defaultTtl = 32, reassemblyTimeoutSec = 10, forwarding = false },
    tcp = { rtoSec = 1, rtoMaxSec = 8, maxRetries = 8, defaultWindow = 4096, idleTimeoutSec = 120, timeWaitSec = 5 },
    udp = { maxDatagram = 32768, recvQueueMax = 64 },
    stream = { driverIntervalSec = 0.05, maxRatePerSec = 20, recvQueueMax = 64 },
    eth = { port = 4790 },
    wireless = { strength = 400 },
    log = { level = "info", ringSize = 200 },
  }
end

--- Argument parsing ------------------------------------------------------------

local args = { ... }
local autoYes = false
for _, a in ipairs(args) do
  if a == "--yes" or a == "-y" then autoYes = true end
end

--- Source detection ------------------------------------------------------------

local function localPath(rel)
  return filesystem.concat(shell.getWorkingDirectory(), rel)
end

local localAvailable = filesystem.exists(localPath("programs.cfg")) and filesystem.exists(localPath("ipstack"))

local function fetchUrl(url)
  if not component.isAvailable("internet") then
    return nil, "no internet card available"
  end
  local internet = component.internet
  local handle, reqErr = internet.request(url)
  if not handle then return nil, tostring(reqErr) end

  local chunks = {}
  while true do
    local chunk, err = handle.read(8192)
    if chunk == nil then break end
    if chunk == false then
      pcall(function() handle.close() end)
      return nil, err or "download failed"
    end
    table.insert(chunks, chunk)
  end
  pcall(function() handle.close() end)
  return table.concat(chunks)
end

if not localAvailable and not component.isAvailable("internet") then
  print("Error: no local repo copy found next to install.lua, and no internet card is installed.")
  print("Either run this script from inside a cloned copy of the repo, or install an internet card and re-run.")
  return 1
end

print(localAvailable
  and "Installing from local repo copy."
  or "Installing over the network from " .. RAW_BASE)

--- Copy files ------------------------------------------------------------

local function writeFile(dst, content)
  filesystem.makeDirectory(filesystem.path(dst))
  local f, err = io.open(dst, "w")
  if not f then return nil, "could not open " .. dst .. ": " .. tostring(err) end
  f:write(content)
  f:close()
  return true
end

local installed = {}
for _, entry in ipairs(FILES) do
  filesystem.makeDirectory(filesystem.path(entry.dst))
  local ok, err
  if localAvailable then
    ok, err = filesystem.copy(localPath(entry.src), entry.dst)
  else
    local content, fetchErr = fetchUrl(RAW_BASE .. entry.src)
    if not content then
      ok, err = nil, fetchErr
    else
      ok, err = writeFile(entry.dst, content)
    end
  end
  if not ok then
    print("Failed to install " .. entry.dst .. ": " .. tostring(err))
    return 1
  end
  table.insert(installed, entry.dst)
  print("  installed " .. entry.dst)
end

--- Config generation ------------------------------------------------------------

local term = require("term")
local isInteractive = pcall(function() return term.isAvailable() end) and term.isAvailable()

local function prompt(promptText, default)
  io.write(promptText)
  if default ~= nil and default ~= "" then io.write(" [" .. tostring(default) .. "]") end
  io.write(": ")
  local answer = io.read()
  if answer == nil or answer == "" then return default end
  return answer
end

local function parseSubnetHost(str)
  local s, h = str:match("^(%d+)%.(%d+)$")
  if not s then return nil end
  return { subnet = tonumber(s), host = tonumber(h) }
end

if filesystem.exists(CONFIG_PATH) then
  print(CONFIG_PATH .. " already exists, leaving it in place.")
else
  local cfg = defaultConfigTable()

  if isInteractive then
    print()
    print("Configuring " .. CONFIG_PATH .. " (answers can be changed later by editing the file):")
    local addrs = {}
    for address in component.list("modem") do table.insert(addrs, address) end

    if #addrs == 0 then
      print("  No modems detected on this machine; add interfaces to " .. CONFIG_PATH .. " manually later.")
    end
    for i, address in ipairs(addrs) do
      local answer = prompt("  Interface " .. i .. " (" .. address .. ") subnet.host, blank to skip")
      if answer and answer ~= "" then
        local parsed = parseSubnetHost(answer)
        if parsed then
          cfg.interfaces[address] = parsed
        else
          print("    invalid format, skipped -- edit " .. CONFIG_PATH .. " by hand")
        end
      end
    end

    local gw = prompt("  Default gateway subnet.host, blank for none / relay node")
    if gw and gw ~= "" then
      local parsed = parseSubnetHost(gw)
      if parsed then cfg.defaultGateway = parsed end
    end
  else
    print()
    print("Non-interactive install: writing a placeholder config.")
    print("Edit " .. CONFIG_PATH .. " before starting ipstackd.")
  end

  local ok, err = writeFile(CONFIG_PATH, serialization.serialize(cfg, true))
  if not ok then
    print("Failed to write " .. CONFIG_PATH .. ": " .. tostring(err))
    return 1
  end
  print("Wrote " .. CONFIG_PATH)
end

--- Service registration ------------------------------------------------------------

local doStart = autoYes
if not autoYes and isInteractive then
  local answer = prompt("Enable and start the ipstackd service now? (y/N)", "N")
  doStart = answer ~= nil and answer:lower():sub(1, 1) == "y"
end

if doStart then
  shell.execute("rc ipstackd enable")
  shell.execute("rc ipstackd start")
  print("ipstackd enabled and started.")
else
  print("Run 'rc ipstackd enable' and 'rc ipstackd start' when you're ready.")
end

--- Summary ------------------------------------------------------------

print()
print("OC-IP-Stack installed (" .. #installed .. " files).")
print("Config: " .. CONFIG_PATH)
print("Check status with: rc ipstackd status   or   ipstack-ctl status")
