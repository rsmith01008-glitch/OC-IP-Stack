-- ipstack.ip: IP-like addressing, routing, and fragmentation/reassembly.
--
-- Addressing is a deliberate simplification versus real IPv4: a 2-octet
-- "subnet.host" address (each 0-255), giving 255 subnets x 254 usable
-- hosts -- far beyond any plausible OpenComputers network, at half the
-- per-packet address overhead of 4-octet addressing. The wire format is
-- centralized here (IP_HDR_FMT) so widening it later is a one-file change.
--
-- Like eth.lua, this module never requires ipstack.tcp/ipstack.udp
-- directly (that would create a require() cycle, since tcp/udp require ip
-- to transmit). Instead, transport layers call ip.registerProtocolHandler
-- at load time from ipstack.daemon (which is free to require everything),
-- and ip.handleFrame dispatches to whichever handler is registered for the
-- packet's protocol number.
local core = require("ipstack.core")
local util = require("ipstack.util")
local eth = require("ipstack.eth")

local ip = {}

local ETH_OVERHEAD = 78 -- eth frame header (76) + trailer checksum (2)

-- srcSubnet(B) srcHost(B) dstSubnet(B) dstHost(B) ttl(B) protocol(B)
-- id(I2) fragFlags(I1) fragOffset(I2) length(I2) checksum(I2)  -- 15 bytes
local IP_HDR_FMT = ">BBBBBBI2I1I2I2I2"
local IP_HDR_LEN = 15
local FRAG_MORE = 0x1

local protocolHandlers = {}

-- Registered by ipstack.daemon at load time, e.g.
-- ip.registerProtocolHandler(tcp.PROTO, tcp.handleSegment)
function ip.registerProtocolHandler(protocol, handler)
  protocolHandlers[protocol] = handler
end

--- Addressing helpers ------------------------------------------------------------

function ip.myAddresses()
  local addrs = {}
  for _, iface in pairs(core.state.interfaces) do
    if iface.ip then table.insert(addrs, iface.ip) end
  end
  return addrs
end

function ip.isLocalAddress(addr)
  for _, iface in pairs(core.state.interfaces) do
    if iface.ip and util.ipEquals(iface.ip, addr) then return true end
  end
  return false
end

-- Effective IP-layer MTU for a local interface: the modem's own
-- maxPacketSize() minus the Ethernet-like framing overhead. Cached on the
-- interface record by the daemon; falls back to a conservative default and
-- a live query if that cache is somehow missing.
function ip.MTU(ifaceAddr)
  local iface = core.state.interfaces[ifaceAddr]
  if not iface then return nil, "unknown local interface " .. tostring(ifaceAddr) end
  if iface.mtu then return iface.mtu end
  local ok, size = pcall(function() return iface.proxy.maxPacketSize() end)
  if ok and type(size) == "number" then
    return size - ETH_OVERHEAD
  end
  return 4096 - ETH_OVERHEAD
end

--- Routing ------------------------------------------------------------

-- Refreshes core.state.routeTable purely for display/introspection
-- (ipstack-ctl route). Actual forwarding decisions are made live by
-- ip.lookupRoute against core.state.interfaces/config, so this table can
-- never go stale in a way that affects behavior -- it's a snapshot.
function ip.rebuildRouteTable()
  local cfg = core.state.config or {}
  local direct, static = {}, {}
  for ifaceAddr, iface in pairs(core.state.interfaces) do
    if iface.ip then
      table.insert(direct, { subnet = iface.ip.subnet, iface = ifaceAddr })
    end
  end
  for _, route in ipairs(cfg.staticRoutes or {}) do
    table.insert(static, { subnet = route.subnet, viaGateway = route.viaGateway })
  end
  core.state.routeTable = {
    direct = direct,
    static = static,
    defaultGateway = cfg.defaultGateway,
  }
end

-- Returns ifaceAddr, nextHopIp for reaching dstIp, or nil, err if
-- unroutable. nextHopIp is the address to ARP-resolve on that interface
-- (== dstIp itself for an on-link destination).
function ip.lookupRoute(dstIp)
  for ifaceAddr, iface in pairs(core.state.interfaces) do
    if iface.ip and iface.ip.subnet == dstIp.subnet then
      return ifaceAddr, dstIp
    end
  end

  local cfg = core.state.config or {}
  for _, route in ipairs(cfg.staticRoutes or {}) do
    if route.subnet == dstIp.subnet and route.viaGateway then
      for ifaceAddr, iface in pairs(core.state.interfaces) do
        if iface.ip and iface.ip.subnet == route.viaGateway.subnet then
          return ifaceAddr, route.viaGateway
        end
      end
    end
  end

  if cfg.defaultGateway then
    for ifaceAddr, iface in pairs(core.state.interfaces) do
      if iface.ip and iface.ip.subnet == cfg.defaultGateway.subnet then
        return ifaceAddr, cfg.defaultGateway
      end
    end
  end

  return nil, "no route to host " .. util.ipToString(dstIp)
end

--- Header pack/unpack ------------------------------------------------------------

local function packHeader(srcIp, dstIp, ttl, protocol, id, fragFlags, fragOffset, length)
  local headerZero = string.pack(IP_HDR_FMT,
    srcIp.subnet, srcIp.host, dstIp.subnet, dstIp.host,
    ttl, protocol, id, fragFlags, fragOffset, length, 0)
  local checksum = util.checksum16(headerZero)
  return headerZero:sub(1, IP_HDR_LEN - 2) .. string.pack(">I2", checksum)
end

local function unpackHeader(packed)
  if type(packed) ~= "string" or #packed < IP_HDR_LEN then return nil, "packet too short" end
  local ok, srcSub, srcHost, dstSub, dstHost, ttl, protocol, id, fragFlags, fragOffset, length, checksum =
    pcall(string.unpack, IP_HDR_FMT, packed)
  if not ok then return nil, "malformed ip header" end

  local zeroed = packed:sub(1, IP_HDR_LEN - 2) .. "\0\0"
  if util.checksum16(zeroed) ~= checksum then
    return nil, "ip checksum mismatch"
  end

  return {
    srcIp = { subnet = srcSub, host = srcHost },
    dstIp = { subnet = dstSub, host = dstHost },
    ttl = ttl,
    protocol = protocol,
    id = id,
    fragFlags = fragFlags,
    fragOffset = fragOffset,
    length = length,
  }
end

--- Fragment id allocation ------------------------------------------------------------

local nextFragId = 0
local function allocFragId()
  local id = nextFragId
  nextFragId = (nextFragId + 1) % 65536
  return id
end

--- Sending ------------------------------------------------------------

-- Sends `payload` (an already-encoded L4 segment/datagram) to dstIp,
-- fragmenting across multiple IP-like packets if it doesn't fit the
-- outbound interface's MTU. Returns true, or nil, err.
function ip.send(dstIp, protocol, payload)
  local ifaceAddr, nextHopIp = ip.lookupRoute(dstIp)
  if not ifaceAddr then return nil, nextHopIp end

  local iface = core.state.interfaces[ifaceAddr]
  local mac, err = eth.arp.resolve(nextHopIp)
  if not mac then return nil, err end

  local cfg = core.state.config or {}
  local ttl = (cfg.ip and cfg.ip.defaultTtl) or 32
  local mtu = ip.MTU(ifaceAddr)
  local maxChunk = mtu - IP_HDR_LEN
  if maxChunk < 1 then return nil, "interface MTU too small" end

  payload = payload or ""

  if #payload <= maxChunk then
    local header = packHeader(iface.ip, dstIp, ttl, protocol, allocFragId(), 0, 0, #payload)
    return eth.sendFrame(ifaceAddr, mac, eth.ETHERTYPE_IP, header .. payload)
  end

  local id = allocFragId()
  local offset = 0
  local total = #payload
  while offset < total do
    local chunkLen = math.min(maxChunk, total - offset)
    local chunk = payload:sub(offset + 1, offset + chunkLen)
    local more = (offset + chunkLen < total) and FRAG_MORE or 0
    local header = packHeader(iface.ip, dstIp, ttl, protocol, id, more, offset, chunkLen)
    local ok, sendErr = eth.sendFrame(ifaceAddr, mac, eth.ETHERTYPE_IP, header .. chunk)
    if not ok then return nil, sendErr end
    offset = offset + chunkLen
  end
  return true
end

--- Reassembly ------------------------------------------------------------

local function reassemblyKey(srcIp, id)
  return util.ipToString(srcIp) .. ":" .. id
end

local function tryReassemble(entry)
  if not entry.totalLength then return nil end
  local offsets = {}
  for off in pairs(entry.fragments) do table.insert(offsets, off) end
  table.sort(offsets)
  local pos = 0
  local parts = {}
  for _, off in ipairs(offsets) do
    if off ~= pos then return nil end
    local bytes = entry.fragments[off]
    table.insert(parts, bytes)
    pos = pos + #bytes
  end
  if pos ~= entry.totalLength then return nil end
  return table.concat(parts)
end

-- Daemon timer housekeeping: drop incomplete fragment sets that have
-- outlived config.ip.reassemblyTimeoutSec, bounding memory against a peer
-- that never completes a burst.
function ip.sweepReassembly()
  local now = computer.uptime()
  for key, entry in pairs(core.state.reassembly) do
    if entry.expiresAt <= now then
      core.state.reassembly[key] = nil
      core.state.stats.dropped = core.state.stats.dropped + 1
    end
  end
end

--- Receiving ------------------------------------------------------------

-- Daemon-only entrypoint, called by ipstack.daemon after eth.unpackFrame
-- reports ethertype == eth.ETHERTYPE_IP.
function ip.handleFrame(ifaceAddr, srcMac, packed)
  local hdr, err = unpackHeader(packed)
  if not hdr then
    core.log("warn", "ip: dropped malformed packet on %s: %s", tostring(ifaceAddr), tostring(err))
    core.state.stats.dropped = core.state.stats.dropped + 1
    return
  end

  local fragBytes = packed:sub(IP_HDR_LEN + 1, IP_HDR_LEN + hdr.length)
  if #fragBytes ~= hdr.length then
    core.log("warn", "ip: dropped packet with truncated fragment payload")
    core.state.stats.dropped = core.state.stats.dropped + 1
    return
  end

  if ip.isLocalAddress(hdr.dstIp) then
    local complete = fragBytes
    if hdr.fragFlags ~= 0 or hdr.fragOffset ~= 0 then
      local key = reassemblyKey(hdr.srcIp, hdr.id)
      local cfg = core.state.config or {}
      local timeout = (cfg.ip and cfg.ip.reassemblyTimeoutSec) or 10
      local entry = core.state.reassembly[key]
      if not entry then
        entry = { fragments = {}, protocol = hdr.protocol, srcIp = hdr.srcIp, dstIp = hdr.dstIp }
        core.state.reassembly[key] = entry
      end
      entry.fragments[hdr.fragOffset] = fragBytes
      entry.expiresAt = computer.uptime() + timeout
      if (hdr.fragFlags & FRAG_MORE) == 0 then
        entry.totalLength = hdr.fragOffset + hdr.length
      end
      complete = tryReassemble(entry)
      if not complete then return end -- still waiting on more fragments
      core.state.reassembly[key] = nil
    end

    core.state.stats.rxFrames = core.state.stats.rxFrames + 1
    local handler = protocolHandlers[hdr.protocol]
    if handler then
      handler(hdr.srcIp, hdr.dstIp, complete)
    else
      core.log("debug", "ip: no handler for protocol %d, dropping", hdr.protocol)
      core.state.stats.dropped = core.state.stats.dropped + 1
    end
    return
  end

  -- Not addressed to us: forward if this node is acting as a relay.
  local cfg = core.state.config or {}
  if not (cfg.ip and cfg.ip.forwarding) then
    return -- not our packet, forwarding disabled: silent drop
  end
  if hdr.ttl <= 1 then
    core.log("warn", "ip: TTL exceeded forwarding to %s, dropping", util.ipToString(hdr.dstIp))
    core.state.stats.dropped = core.state.stats.dropped + 1
    return
  end

  local outIface, nextHopIp = ip.lookupRoute(hdr.dstIp)
  if not outIface then
    core.state.stats.dropped = core.state.stats.dropped + 1
    return
  end
  local mac, resolveErr = eth.arp.resolve(nextHopIp)
  if not mac then
    core.log("warn", "ip: forward failed, %s", tostring(resolveErr))
    core.state.stats.dropped = core.state.stats.dropped + 1
    return
  end
  local newHeader = packHeader(hdr.srcIp, hdr.dstIp, hdr.ttl - 1, hdr.protocol, hdr.id, hdr.fragFlags, hdr.fragOffset, hdr.length)
  eth.sendFrame(outIface, mac, eth.ETHERTYPE_IP, newHeader .. fragBytes)
end

return ip
