-- ipstack.socket: the PUBLIC client API. This is the only ipstack module a
-- runtime program should require() directly -- everything else is internal
-- plumbing shared with the ipstackd daemon.
--
-- Every entrypoint here starts by calling core.requireRunning(), so a
-- program on a machine where `rc ipstackd start` was never run gets an
-- immediate, clearly-worded error instead of a hang. Anything that can
-- legitimately take time (connect's handshake, receive, accept) is bounded
-- by an explicit or default timeout via core.waitUntil, so an
-- unresponsive-but-running daemon/peer also degrades to a typed "timeout"
-- error rather than blocking forever.
local core = require("ipstack.core")
local util = require("ipstack.util")
local ip = require("ipstack.ip")
local tcp = require("ipstack.tcp")
local udp = require("ipstack.udp")
local multicast = require("ipstack.multicast")
local stream = require("ipstack.stream")

local socket = {}

local DEFAULT_CONNECT_TIMEOUT = 10
local DEFAULT_RECEIVE_TIMEOUT = 10

function socket.isRunning()
  return core.isRunning()
end

-- Resolves a target address given as either an already-parsed
-- {subnet=,host=} table, an "subnet.host" string, or a name from the
-- static /etc/ipstack.cfg `hosts` table.
local function resolveIp(target)
  if type(target) == "table" and target.subnet and target.host then
    return target
  end
  if type(target) == "string" then
    local parsed = util.parseIp(target)
    if parsed then return parsed end
    local hostEntry = socket.resolve(target)
    if hostEntry then
      local resolved = util.parseIp(hostEntry)
      if resolved then return resolved end
    end
  end
  return nil, "invalid or unresolvable address: " .. tostring(target)
end

function socket.myIp(ifaceAddr)
  if ifaceAddr then
    local iface = core.state.interfaces[ifaceAddr]
    return iface and iface.ip and util.ipToString(iface.ip)
  end
  for _, iface in pairs(core.state.interfaces) do
    if iface.ip then return util.ipToString(iface.ip) end
  end
  return nil
end

-- Static-only lookup against /etc/ipstack.cfg's `hosts` table -- no
-- queries, no broadcasts, matching the deliberate decision not to build a
-- DNS-equivalent protocol.
function socket.resolve(name)
  local cfg = core.state.config
  if not cfg or not cfg.hosts then return nil end
  return cfg.hosts[name]
end

--- TCP connections ------------------------------------------------------------

local ConnMeta = {}
ConnMeta.__index = ConnMeta

function ConnMeta:send(data)
  local ok, err = core.requireRunning()
  if not ok then return nil, err end
  return tcp.send(self.id, data)
end

-- Blocks (yielding, so other coroutines including the daemon keep
-- running) until data arrives, the connection closes/resets, or
-- `timeoutSec` (default 10s) elapses.
function ConnMeta:receive(timeoutSec)
  local ok, err = core.requireRunning()
  if not ok then return nil, err end

  local data, rerr
  core.waitUntil(function()
    data, rerr = tcp.receive(self.id)
    return data == nil or data ~= ""
  end, timeoutSec or DEFAULT_RECEIVE_TIMEOUT)

  if data == nil then return nil, rerr end
  if data ~= "" then return data end
  return nil, "timeout"
end

function ConnMeta:close()
  local ok, err = core.requireRunning()
  if not ok then return nil, err end
  return tcp.close(self.id)
end

function ConnMeta:state()
  return tcp.getState(self.id)
end

-- Connects to target:port, blocking up to timeoutSec (default 10s) for
-- the handshake to complete. Returns a connection object, or nil, err on
-- refusal/timeout/unreachable host.
function socket.connect(target, port, timeoutSec)
  local ok, err = core.requireRunning()
  if not ok then return nil, err end

  local dstIp, resolveErr = resolveIp(target)
  if not dstIp then return nil, resolveErr end

  local connId, connErr = tcp.connect(dstIp, port)
  if not connId then return nil, connErr end

  core.waitUntil(function()
    local state = tcp.getState(connId)
    return state == "ESTABLISHED" or state == "CLOSED"
  end, timeoutSec or DEFAULT_CONNECT_TIMEOUT)

  if tcp.getState(connId) ~= "ESTABLISHED" then
    return nil, tcp.getError(connId) or "timeout"
  end

  return setmetatable({ id = connId }, ConnMeta)
end

--- TCP listeners ------------------------------------------------------------

local ListenerMeta = {}
ListenerMeta.__index = ListenerMeta

function ListenerMeta:accept(timeoutSec)
  local ok, err = core.requireRunning()
  if not ok then return nil, err end

  local connId, aerr
  core.waitUntil(function()
    connId, aerr = tcp.accept(self.port)
    return connId ~= nil or aerr ~= nil
  end, timeoutSec)

  if connId then return setmetatable({ id = connId }, ConnMeta) end
  if aerr then return nil, aerr end
  return nil, "timeout"
end

function ListenerMeta:close()
  local ok, err = core.requireRunning()
  if not ok then return nil, err end
  return tcp.stopListening(self.port)
end

function socket.listen(port)
  local ok, err = core.requireRunning()
  if not ok then return nil, err end
  local lok, lerr = tcp.listen(port)
  if not lok then return nil, lerr end
  return setmetatable({ port = port }, ListenerMeta)
end

--- UDP sockets ------------------------------------------------------------

local UdpMeta = {}
UdpMeta.__index = UdpMeta

function socket.udp()
  local ok, err = core.requireRunning()
  if not ok then return nil, err end
  return setmetatable({ id = udp.open() }, UdpMeta)
end

function UdpMeta:bind(port)
  local ok, err = core.requireRunning()
  if not ok then return nil, err end
  return udp.bind(self.id, port)
end

function UdpMeta:sendto(target, port, data)
  local ok, err = core.requireRunning()
  if not ok then return nil, err end
  local dstIp, rerr = resolveIp(target)
  if not dstIp then return nil, rerr end
  return udp.sendto(self.id, dstIp, port, data)
end

-- Blocks up to timeoutSec waiting for a datagram. Returns data, srcIp
-- (string), srcPort, or nil, "timeout".
function UdpMeta:receivefrom(timeoutSec)
  local ok, err = core.requireRunning()
  if not ok then return nil, err end

  core.waitUntil(function() return udp.hasPending(self.id) end, timeoutSec)

  local data, srcIp, srcPort = udp.receivefrom(self.id)
  if not data then return nil, "timeout" end
  return data, util.ipToString(srcIp), srcPort
end

function UdpMeta:close()
  local ok, err = core.requireRunning()
  if not ok then return nil, err end
  return udp.close(self.id)
end

--- Multicast sockets ------------------------------------------------------------

-- Multicast group addresses are ordinary addresses in the same
-- "subnet.host" space as unicast (subnet 255 == ip.MULTICAST_SUBNET is
-- reserved for it) -- so they resolve through the exact same `resolveIp`
-- used by socket.connect/UdpMeta:sendto, with one extra check layered on
-- top: the resolved address must actually be a multicast one.
local function resolveMulticastTarget(target)
  local groupIp, rerr = resolveIp(target)
  if not groupIp then return nil, rerr end
  if not ip.isMulticast(groupIp) then
    return nil, "not a multicast group address: " .. util.ipToString(groupIp)
  end
  return groupIp
end

local McastMeta = {}
McastMeta.__index = McastMeta

function socket.multicast()
  local ok, err = core.requireRunning()
  if not ok then return nil, err end
  return setmetatable({ id = multicast.open() }, McastMeta)
end

-- Joins target's group. One group per socket -- call :leave() first to
-- switch groups.
function McastMeta:join(target)
  local ok, err = core.requireRunning()
  if not ok then return nil, err end
  local groupIp, rerr = resolveMulticastTarget(target)
  if not groupIp then return nil, rerr end
  return multicast.join(self.id, groupIp)
end

function McastMeta:leave()
  local ok, err = core.requireRunning()
  if not ok then return nil, err end
  return multicast.leave(self.id)
end

function McastMeta:bind(port)
  local ok, err = core.requireRunning()
  if not ok then return nil, err end
  return multicast.bind(self.id, port)
end

-- Sends to target's group. Does NOT require having joined it first.
function McastMeta:send(target, port, data)
  local ok, err = core.requireRunning()
  if not ok then return nil, err end
  local groupIp, rerr = resolveMulticastTarget(target)
  if not groupIp then return nil, rerr end
  return multicast.send(self.id, groupIp, port, data)
end

-- Blocks up to timeoutSec waiting for a datagram sent to the joined
-- group. Returns data, srcIp (string), srcPort, or nil, "timeout".
function McastMeta:receivefrom(timeoutSec)
  local ok, err = core.requireRunning()
  if not ok then return nil, err end

  core.waitUntil(function() return multicast.hasPending(self.id) end, timeoutSec)

  local data, srcIp, srcPort = multicast.receivefrom(self.id)
  if not data then return nil, "timeout" end
  return data, util.ipToString(srcIp), srcPort
end

function McastMeta:close()
  local ok, err = core.requireRunning()
  if not ok then return nil, err end
  return multicast.close(self.id)
end

--- Stream sockets (fixed-cadence, best-effort periodic multicast; see
--- ipstack.stream's header for what this adds over plain multicast) ----

local StreamMeta = {}
StreamMeta.__index = StreamMeta

function socket.stream()
  local ok, err = core.requireRunning()
  if not ok then return nil, err end
  return setmetatable({ id = stream.open() }, StreamMeta)
end

function StreamMeta:join(target)
  local ok, err = core.requireRunning()
  if not ok then return nil, err end
  local groupIp, rerr = resolveMulticastTarget(target)
  if not groupIp then return nil, rerr end
  return stream.join(self.id, groupIp)
end

function StreamMeta:leave()
  local ok, err = core.requireRunning()
  if not ok then return nil, err end
  return stream.leave(self.id)
end

function StreamMeta:bind(port)
  local ok, err = core.requireRunning()
  if not ok then return nil, err end
  return stream.bind(self.id, port)
end

-- Starts publishing to target's group:port at ratePerSec samples/sec
-- (clamped to config.stream.maxRatePerSec), calling `payloadFn()` fresh
-- each time a sample is due. The daemon drives the cadence -- this call
-- returns immediately, it does not block or loop.
function StreamMeta:startPublishing(target, port, ratePerSec, payloadFn)
  local ok, err = core.requireRunning()
  if not ok then return nil, err end
  local groupIp, rerr = resolveMulticastTarget(target)
  if not groupIp then return nil, rerr end
  return stream.startPublishing(self.id, groupIp, port, ratePerSec, payloadFn, computer.uptime())
end

function StreamMeta:stopPublishing()
  local ok, err = core.requireRunning()
  if not ok then return nil, err end
  return stream.stopPublishing(self.id)
end

-- Blocks up to timeoutSec waiting for a sample sent to the joined group.
-- Returns data, srcIp (string), srcPort, seq, gap, resetDetected, or
-- nil, "timeout". `gap` is how many samples were missed before this one;
-- see ipstack.stream.computeGap's header comment for `resetDetected`.
function StreamMeta:receivefrom(timeoutSec)
  local ok, err = core.requireRunning()
  if not ok then return nil, err end

  core.waitUntil(function() return stream.hasPending(self.id) end, timeoutSec)

  local data, srcIp, srcPort, seq, gap, resetDetected = stream.receivefrom(self.id)
  if not data then return nil, "timeout" end
  return data, util.ipToString(srcIp), srcPort, seq, gap, resetDetected
end

function StreamMeta:close()
  local ok, err = core.requireRunning()
  if not ok then return nil, err end
  return stream.close(self.id)
end

return socket
