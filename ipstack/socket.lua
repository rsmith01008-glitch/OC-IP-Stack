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
local tcp = require("ipstack.tcp")
local udp = require("ipstack.udp")

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

return socket
