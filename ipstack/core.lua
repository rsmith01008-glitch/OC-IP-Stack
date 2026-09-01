-- ipstack.core: the shared "kernel" module.
--
-- require() caches modules by path, so every coroutine in this OpenOS
-- image (the ipstackd daemon's registered event handlers, and any user
-- program that requires("ipstack.socket")) that pulls in this module gets
-- the exact same `core.state` table. That shared table *is* the IPC
-- mechanism between the daemon and client calls: the daemon's
-- modem_message/timer handlers write into it, client calls in socket.lua
-- read/write it directly.
--
-- Correctness rule for every layer built on top of this module: a
-- multi-step mutation of core.state (e.g. "append to an unacked queue,
-- then bump a sequence number") must never have a yield (os.sleep,
-- event.pull, or anything that calls them) in the middle. OpenOS
-- coroutines are cooperative -- only one runs at a time, switching only at
-- explicit yield points -- so as long as that rule holds there is no
-- concurrent-mutation hazard and no locking is needed.
local util = require("ipstack.util")

local core = {}

core.state = {
  running = false,
  config = nil,
  -- [modemAddress] = { ip = {subnet,host}, mtu = n, wireless = bool, proxy = <component proxy> }
  interfaces = {},
  -- ["subnet.host"] = { mac = <36-char address>, expiresAt = <uptime> }
  arpCache = {},
  -- derived at daemon start / interface change: direct + static + default
  routeTable = { direct = {}, static = {}, defaultGateway = nil },
  -- [srcIp..":"..fragId] = { fragments = {[offset]=bytes}, totalLength = nil, expiresAt = <uptime>, protocol=n, srcIp=.., dstIp=.. }
  reassembly = {},
  tcp = {
    connections = {},        -- [connId] = { ... }
    listeners = {},          -- [port] = { backlog = {}, ... }
    nextEphemeralPort = 49152,
  },
  udp = {
    sockets = {},            -- [socketId] = { ... }
  },
  -- [socketId] = { group = {subnet=,host=}|nil, port = nil, recvQueue = {}, closed = false }
  multicast = {
    sockets = {},
  },
  -- [socketId] = { group=, port=, recvQueue={}, lastSeq=, publishing=nil|{...}, closed=false }
  stream = {
    sockets = {},
  },
  log = {},
  stats = { txFrames = 0, rxFrames = 0, dropped = 0 },
}

core.log = util.makeLogger(core.state.log, 200)

local nextConnId = 1
local nextSocketId = 1

function core.newConnId()
  local id = nextConnId
  nextConnId = nextConnId + 1
  return id
end

function core.newSocketId()
  local id = nextSocketId
  nextSocketId = nextSocketId + 1
  return id
end

-- Allocates the next ephemeral port, skipping any already in use by an
-- active UDP socket, multicast socket, stream socket, or TCP connection/
-- listener -- shared ephemeral port space across all four, since
-- multicast and stream both reuse UDP's exact port-multiplexing concept.
-- Wraps 49152-65535.
function core.allocEphemeralPort()
  local start = core.state.tcp.nextEphemeralPort
  local port = start
  for _ = 1, 65535 - 49152 + 1 do
    local inUse = core.state.tcp.listeners[port] ~= nil
    if not inUse then
      for _, conn in pairs(core.state.tcp.connections) do
        if conn.srcPort == port then inUse = true break end
      end
    end
    if not inUse then
      for _, sock in pairs(core.state.udp.sockets) do
        if sock.port == port then inUse = true break end
      end
    end
    if not inUse then
      for _, sock in pairs(core.state.multicast.sockets) do
        if sock.port == port then inUse = true break end
      end
    end
    if not inUse then
      for _, sock in pairs(core.state.stream.sockets) do
        if sock.port == port then inUse = true break end
      end
    end
    if not inUse then
      port = port + 1
      if port > 65535 then port = 49152 end
      core.state.tcp.nextEphemeralPort = port
      return port
    end
    port = port + 1
    if port > 65535 then port = 49152 end
  end
  return nil -- exhausted, extremely unlikely
end

function core.isRunning()
  return core.state.running == true
end

-- Every ipstack.socket entrypoint should call this first and bail out
-- immediately (never block/hang) if the daemon has not been started.
function core.requireRunning()
  if not core.isRunning() then
    return nil, "ipstack daemon is not running; start it with: rc ipstackd start"
  end
  return true
end

-- Polls `predicate()` until it returns a truthy value or `timeoutSec`
-- elapses, yielding via os.sleep between checks so the daemon's
-- event.listen/event.timer handlers (registered independently of this
-- calling coroutine) actually get a chance to run and update shared
-- state. Returns true if predicate became true, false on timeout.
-- timeoutSec of nil/false means "check once, don't wait".
function core.waitUntil(predicate, timeoutSec)
  if predicate() then return true end
  if not timeoutSec or timeoutSec <= 0 then return false end

  local uptime = computer.uptime
  local deadline = uptime() + timeoutSec
  while uptime() < deadline do
    os.sleep(0.05)
    if predicate() then return true end
  end
  return predicate()
end

return core
