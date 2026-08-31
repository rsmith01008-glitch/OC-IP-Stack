-- ipstack.eth: link layer. Ethernet-like framing over component.modem, plus
-- an ARP-style sub-namespace (eth.arp.*) that resolves IP-like addresses to
-- modem component addresses (the MAC-equivalent in this stack).
--
-- This module never requires ipstack.ip (that would create a require()
-- cycle, since ip.lua requires eth.lua to actually transmit). Dispatch from
-- a decoded frame's ethertype to the IP layer or to eth.arp is done by the
-- caller (ipstack.daemon), which is free to require both.
local core = require("ipstack.core")
local util = require("ipstack.util")

local eth = {}

eth.ETHERTYPE_IP = 0x0800
eth.ETHERTYPE_ARP = 0x0806

eth.DEFAULT_PORT = 4790
-- Overwritten by daemon.start() from config.eth.port; read dynamically by
-- name (eth.PORT) rather than captured into a local so every caller always
-- sees the configured value.
eth.PORT = eth.DEFAULT_PORT

eth.BROADCAST_MAC = string.rep("\255", 36)
local ZERO_MAC = string.rep("\0", 36)

-- dstMac(c36) srcMac(c36) ethertype(I2) length(I2)  -- 76 byte header
local FRAME_HEADER_FMT = ">c36c36I2I2"
local FRAME_HEADER_LEN = 76
local CHECKSUM_FMT = ">I2"

-- opcode(B) senderSubnet(B) senderHost(B) senderMac(c36) targetSubnet(B) targetHost(B) targetMac(c36)
local ARP_FMT = ">BBBc36BBc36"
local ARP_OP_REQUEST = 1
local ARP_OP_REPLY = 2

--- Framing ------------------------------------------------------------

-- Builds and sends a framed packet out the named local interface.
-- `dstMac` is a 36-byte modem address or eth.BROADCAST_MAC.
function eth.sendFrame(ifaceAddr, dstMac, ethertype, payload)
  local iface = core.state.interfaces[ifaceAddr]
  if not iface or not iface.proxy then
    return nil, "unknown local interface " .. tostring(ifaceAddr)
  end
  payload = payload or ""
  local header = string.pack(FRAME_HEADER_FMT, dstMac, ifaceAddr, ethertype, #payload)
  local withoutChecksum = header .. payload
  local checksum = util.checksum16(withoutChecksum)
  local frame = withoutChecksum .. string.pack(CHECKSUM_FMT, checksum)

  local ok, err
  if dstMac == eth.BROADCAST_MAC then
    ok, err = iface.proxy.broadcast(eth.PORT, frame)
  else
    ok, err = iface.proxy.send(dstMac, eth.PORT, frame)
  end
  if ok then
    core.state.stats.txFrames = core.state.stats.txFrames + 1
  end
  return ok, err
end

-- Parses and checksum-validates a raw frame string. Returns
-- ok, dstMac, srcMac, ethertype, payload  on success, or nil, err on a
-- malformed/corrupt frame. Never throws.
function eth.unpackFrame(packed)
  if type(packed) ~= "string" or #packed < FRAME_HEADER_LEN + 2 then
    return nil, "frame too short"
  end
  local ok, dstMac, srcMac, ethertype, length, pos = pcall(string.unpack, FRAME_HEADER_FMT, packed)
  if not ok then return nil, "malformed frame header" end

  if pos + length - 1 + 2 - 1 > #packed then
    return nil, "frame length field exceeds packet size"
  end
  local payload = packed:sub(pos, pos + length - 1)
  local checksumPos = pos + length
  local okc, checksum = pcall(string.unpack, CHECKSUM_FMT, packed, checksumPos)
  if not okc then return nil, "malformed frame checksum" end

  local expected = util.checksum16(packed:sub(1, checksumPos - 1))
  if expected ~= checksum then
    return nil, "frame checksum mismatch"
  end

  return true, dstMac, srcMac, ethertype, payload
end

--- ARP ------------------------------------------------------------

eth.arp = {}

local function buildArpMessage(opcode, senderIp, senderMac, targetIp, targetMac)
  return string.pack(ARP_FMT,
    opcode,
    senderIp.subnet, senderIp.host, senderMac,
    targetIp.subnet, targetIp.host, targetMac or ZERO_MAC)
end

local function parseArpMessage(payload)
  if type(payload) ~= "string" or #payload < 77 then return nil end
  local ok, opcode, sSub, sHost, sMac, tSub, tHost, tMac = pcall(string.unpack, ARP_FMT, payload)
  if not ok then return nil end
  return {
    opcode = opcode,
    senderIp = { subnet = sSub, host = sHost },
    senderMac = sMac,
    targetIp = { subnet = tSub, host = tHost },
    targetMac = tMac,
  }
end

local function cacheKey(ip)
  return ip.subnet .. "." .. ip.host
end

-- Learn (or refresh) an ARP cache entry from any received ARP traffic,
-- mirroring how real ARP opportunistically learns from requests too.
local function learn(ip, mac, ttl)
  core.state.arpCache[cacheKey(ip)] = {
    mac = mac,
    expiresAt = computer.uptime() + ttl,
  }
end

-- Daemon-only entrypoint: handle a decoded ARP payload received on
-- `ifaceAddr` from `remoteMac`.
function eth.arp.handleFrame(ifaceAddr, remoteMac, payload)
  local iface = core.state.interfaces[ifaceAddr]
  if not iface then return end
  local msg = parseArpMessage(payload)
  if not msg then
    core.log("warn", "eth.arp: dropped malformed ARP message from %s", tostring(remoteMac))
    return
  end

  local cfg = core.state.config
  local ttl = (cfg and cfg.arp and cfg.arp.ttl) or 60
  learn(msg.senderIp, msg.senderMac, ttl)

  if msg.opcode == ARP_OP_REQUEST and util.ipEquals(msg.targetIp, iface.ip) then
    local reply = buildArpMessage(ARP_OP_REPLY, iface.ip, ifaceAddr, msg.senderIp, msg.senderMac)
    eth.sendFrame(ifaceAddr, remoteMac, eth.ETHERTYPE_ARP, reply)
  end
end

-- Broadcasts an ARP request for `ip` on every local interface whose subnet
-- matches (or, if none match locally, on all interfaces -- used for the
-- default-gateway case where the gateway is expected to answer). Blocks
-- (via core.waitUntil, so other coroutines' event handlers keep running)
-- until resolved or `timeoutSec` elapses. Returns mac, or nil, err.
function eth.arp.resolve(ip, timeoutSec)
  local key = cacheKey(ip)
  local cached = core.state.arpCache[key]
  if cached and cached.expiresAt > computer.uptime() then
    return cached.mac
  end

  local cfg = core.state.config
  local retries = (cfg and cfg.arp and cfg.arp.requestRetries) or 3
  local perTry = timeoutSec or (cfg and cfg.arp and cfg.arp.requestTimeoutSec) or 3

  for attempt = 1, retries do
    local sentAny = false
    for ifaceAddr, iface in pairs(core.state.interfaces) do
      if iface.ip and iface.ip.subnet == ip.subnet then
        local req = buildArpMessage(ARP_OP_REQUEST, iface.ip, ifaceAddr, ip, nil)
        eth.sendFrame(ifaceAddr, eth.BROADCAST_MAC, eth.ETHERTYPE_ARP, req)
        sentAny = true
      end
    end
    if not sentAny then
      -- No local interface shares this subnet; broadcast on all of them
      -- so an off-subnet resolve (e.g. a manually-specified gateway that
      -- doesn't match any local subnet) still has a chance to succeed.
      for ifaceAddr, iface in pairs(core.state.interfaces) do
        local req = buildArpMessage(ARP_OP_REQUEST, iface.ip, ifaceAddr, ip, nil)
        eth.sendFrame(ifaceAddr, eth.BROADCAST_MAC, eth.ETHERTYPE_ARP, req)
      end
    end

    local ok = core.waitUntil(function()
      local e = core.state.arpCache[key]
      return e ~= nil and e.expiresAt > computer.uptime()
    end, perTry)
    if ok then
      return core.state.arpCache[key].mac
    end
  end

  return nil, "host unreachable (ARP timeout)"
end

-- Daemon timer housekeeping: evict expired ARP cache entries.
function eth.arp.sweep()
  local now = computer.uptime()
  for key, entry in pairs(core.state.arpCache) do
    if entry.expiresAt <= now then
      core.state.arpCache[key] = nil
    end
  end
end

-- Sends a gratuitous ARP "announcement" (a request for our own address,
-- which every listener will opportunistically learn our mac from) for
-- every local interface. Used at daemon start, and doubles as conflict
-- detection: if another node later claims the same IP, its own gratuitous
-- announcement or reply will overwrite our arpCache entry for that IP with
-- a different mac, which callers can compare against ifaceAddr to detect.
function eth.arp.announceAll()
  for ifaceAddr, iface in pairs(core.state.interfaces) do
    if iface.ip then
      local msg = buildArpMessage(ARP_OP_REQUEST, iface.ip, ifaceAddr, iface.ip, nil)
      eth.sendFrame(ifaceAddr, eth.BROADCAST_MAC, eth.ETHERTYPE_ARP, msg)
    end
  end
end

return eth
