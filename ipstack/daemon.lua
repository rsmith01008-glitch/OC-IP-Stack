-- ipstack.daemon: wires every layer together and is the ONLY module that
-- ever touches component.modem's receive side or registers OpenOS event
-- handlers. Started (non-blocking) by rc.d/ipstackd.lua's start(), which
-- OpenOS's `rc` runs synchronously in the calling shell process -- so
-- daemon.start() must register handlers and return immediately rather
-- than loop, per the confirmed OpenOS internals: event.listen/event.timer
-- registrations are serviced by every coroutine's pullSignal regardless of
-- which coroutine registered them, so no persistent background thread is
-- needed for correctness.
local component = require("component")
local computer = require("computer")
local event = require("event")

local core = require("ipstack.core")
local util = require("ipstack.util")
local config = require("ipstack.config")
local eth = require("ipstack.eth")
local ip = require("ipstack.ip")
local tcp = require("ipstack.tcp")
local udp = require("ipstack.udp")
local multicast = require("ipstack.multicast")
local stream = require("ipstack.stream")

-- Wire the transport layers into the IP layer's protocol dispatch table.
-- Done once at module load (not inside start()) since it only registers
-- callbacks and doesn't depend on the daemon actually running.
ip.registerProtocolHandler(tcp.PROTO, tcp.handleSegment)
ip.registerProtocolHandler(udp.PROTO, udp.handleDatagram)
ip.registerProtocolHandler(multicast.PROTO, multicast.handleDatagram)
ip.registerProtocolHandler(stream.PROTO, stream.handleDatagram)

local daemon = {}

local ETH_OVERHEAD = 78

-- Kept as module-local upvalues (not stored in core.state) so stop() can
-- unregister the exact same function/timer references it registered.
local tickTimerId = nil
local streamTimerId = nil

local function tableCount(t)
  local n = 0
  for _ in pairs(t) do n = n + 1 end
  return n
end

-- Opens the eth port and records interface state for a modem address that
-- appears in config.interfaces, whether found at startup or hot-plugged
-- in later. Silently does nothing for a present-but-unconfigured modem.
local function attachInterface(address)
  local cfg = core.state.config
  local entry = cfg and cfg.interfaces[address]
  if not entry then return end

  local proxy = component.proxy(address)
  if not proxy then return end

  local ok = pcall(function() proxy.open(eth.PORT) end)
  if not ok then
    core.log("warn", "daemon: failed to open port on modem %s", address)
    return
  end

  local wireless = false
  local wok, isWireless = pcall(function() return proxy.isWireless() end)
  if wok then wireless = isWireless and true or false end
  if wireless then
    pcall(function() proxy.setStrength(cfg.wireless.strength) end)
  end

  local mtu = 4096 - ETH_OVERHEAD
  local sok, size = pcall(function() return proxy.maxPacketSize() end)
  if sok and type(size) == "number" then
    mtu = size - ETH_OVERHEAD
  end

  core.state.interfaces[address] = {
    ip = { subnet = entry.subnet, host = entry.host },
    mtu = mtu,
    wireless = wireless,
    proxy = proxy,
  }
  core.log("info", "daemon: attached interface %s as %s (mtu %d, %s)",
    address, util.ipToString(core.state.interfaces[address].ip), mtu, wireless and "wireless" or "wired")
end

local function safeOnModemMessage(_, localAddr, _remoteAddr, port, _distance, packed)
  local ok, err = pcall(function()
    if port ~= eth.PORT then return end
    local frameOk, dstMac, srcMac, ethertype, payload = eth.unpackFrame(packed)
    if not frameOk then
      core.state.stats.dropped = core.state.stats.dropped + 1
      core.log("warn", "daemon: dropped malformed frame: %s", tostring(dstMac))
      return
    end
    if dstMac ~= eth.BROADCAST_MAC and dstMac ~= localAddr then return end
    if ethertype == eth.ETHERTYPE_ARP then
      eth.arp.handleFrame(localAddr, srcMac, payload)
    elseif ethertype == eth.ETHERTYPE_IP then
      ip.handleFrame(localAddr, srcMac, payload)
    end
  end)
  if not ok then
    core.log("error", "daemon: modem_message handler error: %s", tostring(err))
  end
end

local function safeOnComponentChange(eventName, address, componentType)
  local ok, err = pcall(function()
    if componentType ~= "modem" then return end
    if eventName == "component_added" then
      if core.isRunning() then
        attachInterface(address)
        ip.rebuildRouteTable()
      end
    elseif eventName == "component_removed" then
      core.state.interfaces[address] = nil
      ip.rebuildRouteTable()
    end
  end)
  if not ok then
    core.log("error", "daemon: hotplug handler error: %s", tostring(err))
  end
end

local function safeTick()
  local ok, err = pcall(function()
    eth.arp.sweep()
    ip.sweepReassembly()
    tcp.tick()
  end)
  if not ok then
    core.log("error", "daemon: housekeeping tick error: %s", tostring(err))
  end
end

-- Drives every open stream.lua publisher (see stream.drivePublishers).
-- Runs on its own timer, independent of safeTick, at config.stream's
-- (typically much faster) driverIntervalSec -- keeping it separate from
-- safeTick's 1-second housekeeping cadence, rather than folding it in
-- there, is what actually lets a stream publish faster than 1/sec.
local function safeStreamTick()
  local ok, err = pcall(function()
    stream.drivePublishers(computer.uptime())
  end)
  if not ok then
    core.log("error", "daemon: stream driver tick error: %s", tostring(err))
  end
end

-- Idempotent: calling start() while already running is a no-op success,
-- so `rc ipstackd start` is safe to run more than once.
function daemon.start()
  if core.isRunning() then return true end

  math.randomseed(math.floor((computer.uptime() * 1000)) % 2147483647)

  local cfg, cfgErr = config.load()
  core.state.config = cfg
  core.log = util.makeLogger(core.state.log, cfg.log.ringSize)
  if cfgErr then
    core.log("warn", "daemon: %s (using built-in defaults)", cfgErr)
  end

  core.state.interfaces = {}
  for address in component.list("modem") do
    attachInterface(address)
  end
  for address, entry in pairs(cfg.interfaces) do
    if not core.state.interfaces[address] then
      core.log("warn", "daemon: configured modem %s is not present on this machine", address)
    end
    if entry.subnet == ip.MULTICAST_SUBNET then
      core.log("warn", "daemon: interface %s configured with reserved multicast subnet %d (ip.MULTICAST_SUBNET); unicast traffic to this address will never be delivered",
        address, ip.MULTICAST_SUBNET)
    end
  end
  if tableCount(core.state.interfaces) == 0 then
    core.log("warn", "daemon: no local interfaces configured/present; sends will fail until /etc/ipstack.cfg is fixed")
  end

  ip.rebuildRouteTable()

  event.listen("modem_message", safeOnModemMessage)
  event.listen("component_added", safeOnComponentChange)
  event.listen("component_removed", safeOnComponentChange)
  tickTimerId = event.timer(1, safeTick, math.huge)
  streamTimerId = event.timer(cfg.stream.driverIntervalSec, safeStreamTick, math.huge)

  eth.arp.announceAll()

  core.state.running = true
  core.log("info", "ipstackd started with %d interface(s)", tableCount(core.state.interfaces))
  return true
end

-- Unregisters everything start() registered, closes modem ports, and
-- drops all live connections/sockets/caches -- matching a real network
-- stack's restart semantics. Idempotent.
function daemon.stop()
  if not core.isRunning() then return true end

  event.ignore("modem_message", safeOnModemMessage)
  event.ignore("component_added", safeOnComponentChange)
  event.ignore("component_removed", safeOnComponentChange)
  if tickTimerId then
    event.cancel(tickTimerId)
    tickTimerId = nil
  end
  if streamTimerId then
    event.cancel(streamTimerId)
    streamTimerId = nil
  end

  for _, iface in pairs(core.state.interfaces) do
    if iface.proxy then
      pcall(function() iface.proxy.close(eth.PORT) end)
    end
  end

  core.state.interfaces = {}
  core.state.arpCache = {}
  core.state.reassembly = {}
  core.state.tcp.connections = {}
  core.state.tcp.listeners = {}
  core.state.udp.sockets = {}
  core.state.multicast.sockets = {}
  core.state.stream.sockets = {}
  core.state.running = false
  core.log("info", "ipstackd stopped")
  return true
end

function daemon.isRunning()
  return core.isRunning()
end

return daemon
