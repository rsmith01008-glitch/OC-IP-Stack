-- ipstack.udp: UDP-like datagrams over ipstack.ip. Unreliable, unordered,
-- port-multiplexed. No congestion control, no fragmentation logic of its
-- own (the IP layer already fragments/reassembls transparently).
local core = require("ipstack.core")
local ip = require("ipstack.ip")
local util = require("ipstack.util")

local udp = {}

udp.PROTO = 17

-- srcPort(I2) dstPort(I2) length(I2) checksum(I2)  -- 8 bytes
local UDP_HDR_FMT = ">I2I2I2I2"
local UDP_HDR_LEN = 8

local function findSocketByPort(port)
  for id, sock in pairs(core.state.udp.sockets) do
    if sock.port == port and not sock.closed then return id, sock end
  end
  return nil
end

-- Creates a new, unbound UDP socket record. Returns socketId.
function udp.open()
  local id = core.newSocketId()
  core.state.udp.sockets[id] = {
    port = nil,
    recvQueue = {},
    closed = false,
  }
  return id
end

-- Explicitly binds a socket to `port`. Returns true, or nil, err if the
-- port is already in use by another open socket.
function udp.bind(socketId, port)
  local sock = core.state.udp.sockets[socketId]
  if not sock then return nil, "invalid socket" end
  if sock.port then return nil, "socket already bound" end
  if findSocketByPort(port) then return nil, "address already in use" end
  sock.port = port
  return true
end

local function ensureBound(sock)
  if sock.port then return true end
  local port = core.allocEphemeralPort()
  if not port then return nil, "no ephemeral ports available" end
  sock.port = port
  return true
end

-- Sends `data` to dstIp:dstPort from `socketId`, auto-binding an ephemeral
-- local port first if the socket wasn't explicitly bound. Returns true, or
-- nil, err (e.g. "host unreachable (ARP timeout)", "oversized datagram").
function udp.sendto(socketId, dstIp, dstPort, data)
  local sock = core.state.udp.sockets[socketId]
  if not sock or sock.closed then return nil, "invalid or closed socket" end

  local ok, err = ensureBound(sock)
  if not ok then return nil, err end

  data = data or ""
  local cfg = core.state.config or {}
  local maxDatagram = (cfg.udp and cfg.udp.maxDatagram) or 32768
  if #data > maxDatagram then
    return nil, "oversized datagram (" .. #data .. " > " .. maxDatagram .. " bytes)"
  end

  local header = string.pack(UDP_HDR_FMT, sock.port, dstPort, #data, 0)
  -- Checksum covers header (with its checksum field zeroed) + data.
  local checksum = util.checksum16(header .. data)
  header = string.pack(UDP_HDR_FMT, sock.port, dstPort, #data, checksum)

  return ip.send(dstIp, udp.PROTO, header .. data)
end

-- Non-blocking pop of the oldest queued datagram. Returns data, srcIp,
-- srcPort, or nil if nothing is queued. Blocking-with-timeout semantics
-- are implemented in ipstack.socket via core.waitUntil, not here.
function udp.receivefrom(socketId)
  local sock = core.state.udp.sockets[socketId]
  if not sock then return nil, "invalid socket" end
  local item = table.remove(sock.recvQueue, 1)
  if not item then return nil end
  return item.data, item.srcIp, item.srcPort
end

function udp.hasPending(socketId)
  local sock = core.state.udp.sockets[socketId]
  return sock ~= nil and #sock.recvQueue > 0
end

function udp.close(socketId)
  local sock = core.state.udp.sockets[socketId]
  if sock then
    sock.closed = true
    core.state.udp.sockets[socketId] = nil
  end
  return true
end

-- Daemon-only entrypoint, registered via
-- ip.registerProtocolHandler(udp.PROTO, udp.handleDatagram).
function udp.handleDatagram(srcIp, dstIp, packed)
  if type(packed) ~= "string" or #packed < UDP_HDR_LEN then
    core.log("warn", "udp: dropped short datagram")
    return
  end
  local ok, srcPort, dstPort, length, checksum = pcall(string.unpack, UDP_HDR_FMT, packed)
  if not ok then
    core.log("warn", "udp: dropped malformed header")
    return
  end
  local data = packed:sub(UDP_HDR_LEN + 1, UDP_HDR_LEN + length)
  if #data ~= length then
    core.log("warn", "udp: dropped datagram with truncated payload")
    return
  end

  local zeroed = string.pack(UDP_HDR_FMT, srcPort, dstPort, length, 0) .. data
  if util.checksum16(zeroed) ~= checksum then
    core.log("warn", "udp: dropped datagram with bad checksum")
    return
  end

  local _, sock = findSocketByPort(dstPort)
  if not sock then
    return -- no listener on this port; silent drop, matches real UDP
  end

  local cfg = core.state.config or {}
  local maxQueue = (cfg.udp and cfg.udp.recvQueueMax) or 64
  table.insert(sock.recvQueue, { data = data, srcIp = srcIp, srcPort = srcPort })
  while #sock.recvQueue > maxQueue do
    table.remove(sock.recvQueue, 1) -- drop-oldest under sustained overload
  end
end

return udp
