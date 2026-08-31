-- ipstack.multicast: multicast-style datagrams over ipstack.ip. A
-- multicast destination (ip.isMulticast) has no single owner to resolve
-- via ARP -- ip.send instead floods it out every local interface, and
-- every node on the broadcast domain decodes the frame this far
-- regardless of membership. Filtering happens here in software: only a
-- socket that has joined the destination group AND is bound to the
-- destination port receives a copy.
--
-- Deliberately close to ipstack.udp (same 8-byte wire header, same
-- port-multiplexing concept, same recvQueue/hasPending/close shape), but
-- with two semantic differences from UDP that matter:
--   1. multicast.send() does NOT require having joined the group first --
--      real multicast lets you send to a group without subscribing to it.
--   2. multicast.bind() has NO exclusivity check -- multiple sockets
--      (even on one node) binding the same port is the expected case for
--      multicast (independent local listeners on one channel), unlike
--      udp.bind's "address already in use". handleDatagram fans a
--      matching datagram out to every joined+bound socket, not just the
--      first match.
local core = require("ipstack.core")
local ip = require("ipstack.ip")
local util = require("ipstack.util")

local multicast = {}

-- Arbitrary, local to this stack (no real-IP significance, unlike
-- tcp.PROTO=6/udp.PROTO=17) -- just needs to stay distinct from both so
-- ip.registerProtocolHandler dispatches correctly.
multicast.PROTO = 18

-- Same 8-byte format as udp.lua, duplicated locally rather than shared:
-- each transport module already owns its own header format independently
-- (tcp.lua and udp.lua don't share one either), and this is 4 lines of
-- string.pack -- not worth a new shared module for.
local MCAST_HDR_FMT = ">I2I2I2I2"
local MCAST_HDR_LEN = 8

-- Creates a new, unjoined and unbound multicast socket record. Returns
-- socketId.
function multicast.open()
  local id = core.newSocketId()
  core.state.multicast.sockets[id] = {
    group = nil,
    port = nil,
    recvQueue = {},
    closed = false,
  }
  return id
end

-- Joins `groupIp` (must satisfy ip.isMulticast). One group per socket --
-- call multicast.leave() first to switch. Returns true, or nil, err.
function multicast.join(socketId, groupIp)
  local sock = core.state.multicast.sockets[socketId]
  if not sock or sock.closed then return nil, "invalid or closed socket" end
  if not ip.isMulticast(groupIp) then
    return nil, "not a multicast group address: " .. util.ipToString(groupIp)
  end
  if sock.group then
    return nil, "socket already joined a group; call leave() first"
  end
  sock.group = { subnet = groupIp.subnet, host = groupIp.host }
  return true
end

-- Stops receiving for the joined group (the socket stays open and bound).
-- Idempotent -- calling it while not joined is not an error.
function multicast.leave(socketId)
  local sock = core.state.multicast.sockets[socketId]
  if not sock then return nil, "invalid socket" end
  sock.group = nil
  return true
end

-- Binds a socket to `port`. Unlike udp.bind, no exclusivity check --
-- multiple sockets on the same port is the expected multicast case.
function multicast.bind(socketId, port)
  local sock = core.state.multicast.sockets[socketId]
  if not sock then return nil, "invalid socket" end
  if sock.port then return nil, "socket already bound" end
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

-- Sends `data` to groupIp:dstPort from `socketId`, auto-binding an
-- ephemeral local port first if the socket wasn't explicitly bound. Does
-- NOT require having joined `groupIp` -- sending never requires
-- membership. Returns true, or nil, err.
function multicast.send(socketId, groupIp, dstPort, data)
  local sock = core.state.multicast.sockets[socketId]
  if not sock or sock.closed then return nil, "invalid or closed socket" end
  if not ip.isMulticast(groupIp) then
    return nil, "not a multicast group address: " .. util.ipToString(groupIp)
  end

  local ok, err = ensureBound(sock)
  if not ok then return nil, err end

  data = data or ""
  local cfg = core.state.config or {}
  local maxDatagram = (cfg.udp and cfg.udp.maxDatagram) or 32768
  if #data > maxDatagram then
    return nil, "oversized datagram (" .. #data .. " > " .. maxDatagram .. " bytes)"
  end

  local header = string.pack(MCAST_HDR_FMT, sock.port, dstPort, #data, 0)
  local checksum = util.checksum16(header .. data)
  header = string.pack(MCAST_HDR_FMT, sock.port, dstPort, #data, checksum)

  return ip.send(groupIp, multicast.PROTO, header .. data)
end

-- Non-blocking pop of the oldest queued datagram. Returns data, srcIp,
-- srcPort, or nil if nothing is queued.
function multicast.receivefrom(socketId)
  local sock = core.state.multicast.sockets[socketId]
  if not sock then return nil, "invalid socket" end
  local item = table.remove(sock.recvQueue, 1)
  if not item then return nil end
  return item.data, item.srcIp, item.srcPort
end

function multicast.hasPending(socketId)
  local sock = core.state.multicast.sockets[socketId]
  return sock ~= nil and #sock.recvQueue > 0
end

function multicast.close(socketId)
  local sock = core.state.multicast.sockets[socketId]
  if sock then
    sock.closed = true
    core.state.multicast.sockets[socketId] = nil
  end
  return true
end

-- Daemon-only entrypoint, registered via
-- ip.registerProtocolHandler(multicast.PROTO, multicast.handleDatagram).
-- dstIp.host is the group id (dstIp.subnet == ip.MULTICAST_SUBNET,
-- guaranteed by ip.handleFrame's dispatch).
function multicast.handleDatagram(srcIp, dstIp, packed)
  if type(packed) ~= "string" or #packed < MCAST_HDR_LEN then
    core.log("warn", "multicast: dropped short datagram")
    return
  end
  local ok, srcPort, dstPort, length, checksum = pcall(string.unpack, MCAST_HDR_FMT, packed)
  if not ok then
    core.log("warn", "multicast: dropped malformed header")
    return
  end
  local data = packed:sub(MCAST_HDR_LEN + 1, MCAST_HDR_LEN + length)
  if #data ~= length then
    core.log("warn", "multicast: dropped datagram with truncated payload")
    return
  end

  local zeroed = string.pack(MCAST_HDR_FMT, srcPort, dstPort, length, 0) .. data
  if util.checksum16(zeroed) ~= checksum then
    core.log("warn", "multicast: dropped datagram with bad checksum")
    return
  end

  local cfg = core.state.config or {}
  local maxQueue = (cfg.udp and cfg.udp.recvQueueMax) or 64

  -- Fan out to EVERY socket joined to this group AND bound to this port
  -- -- unlike udp's single first-match delivery, multiple independent
  -- local listeners on the same (group, port) are the expected case and
  -- all get their own copy. No match at all is a silent drop, same as
  -- real multicast (no ICMP-unreachable equivalent) -- this loop is also
  -- where "only joined nodes deliver up" actually happens, since every
  -- node on the broadcast domain decodes the frame this far regardless of
  -- membership.
  for _, sock in pairs(core.state.multicast.sockets) do
    if not sock.closed and sock.port == dstPort and sock.group
        and sock.group.subnet == dstIp.subnet and sock.group.host == dstIp.host then
      table.insert(sock.recvQueue, { data = data, srcIp = srcIp, srcPort = srcPort })
      while #sock.recvQueue > maxQueue do
        table.remove(sock.recvQueue, 1)
      end
    end
  end
end

return multicast
