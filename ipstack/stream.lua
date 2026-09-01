-- ipstack.stream: a lightweight, fixed-cadence, best-effort periodic
-- multicast publisher -- the missing primitive for something like IEC
-- 61850's Sampled Values (a merging unit publishing "here is the current
-- reading" on a steady cadence, no ack, no retransmit: if you miss one,
-- the next is along shortly). NOT a literal SV implementation (real SV is
-- 4000+ samples/sec, meaningless under OC's ~20 Hz tick model) -- this is
-- the same *pattern* at OC scale: single/low-double-digit samples/sec,
-- config-capped (see config.DEFAULTS.stream.maxRatePerSec).
--
-- Deliberately reuses ipstack.multicast's group/port addressing and
-- fan-out-to-every-joined-socket delivery model rather than reinventing
-- it -- the only two things this module adds beyond calling
-- multicast.send() from your own event.timer are:
--   1. The daemon drives the cadence for you (ipstack.daemon's driver
--      timer calls stream.drivePublishers(now); callers never register
--      their own timer or track elapsed time).
--   2. A monotonic per-datagram sequence number, giving subscribers gap
--      detection for free (real SV's smpCnt equivalent) -- something
--      plain ipstack.multicast has no way to provide, since it has no
--      concept of "this socket publishes a numbered series."
--
-- Cadence-tracking ("is this stream due yet") takes `now` as an explicit
-- parameter rather than calling computer.uptime() internally, same
-- reasoning as oc-iec61850-sas's sas/protection/*.lua modules: keeps the
-- scheduling math itself plain, OC-API-free, and unit-testable with
-- vanilla lua5.3 (see tests/test_stream.lua), with the daemon supplying
-- the one real computer.uptime() call.
local core = require("ipstack.core")
local ip = require("ipstack.ip")
local util = require("ipstack.util")

local stream = {}

-- Arbitrary, local to this stack -- same reasoning as multicast.PROTO=18
-- (no real-IP significance, just needs to stay distinct so
-- ip.registerProtocolHandler dispatches correctly).
stream.PROTO = 19

-- srcPort(I2) dstPort(I2) length(I2) seq(I2) checksum(I2) -- 10 bytes.
-- One extra I2 vs. multicast's 8-byte header: the monotonic sequence
-- number subscribers use for gap detection.
local STREAM_HDR_FMT = ">I2I2I2I2I2"
local STREAM_HDR_LEN = 10
local SEQ_MODULUS = 65536

-- A gap this large almost certainly isn't 65534 consecutive drops -- it's
-- the publisher having restarted (seq reset to 0) or a first-ever sample
-- arriving after this subscriber's own restart. Report it as "no gap
-- data" (reset detected) rather than a wildly misleading drop count.
local GAP_RESET_THRESHOLD = 4096

-- Wrap-aware "how many samples were missed between lastSeq and seq".
-- Exposed (not local) so tests/test_stream.lua can exercise it directly
-- without needing the rest of the module's core.state/ip dependencies.
-- Returns gap (0 if none/duplicate), resetDetected (true if the jump is
-- large enough that it's more likely a publisher restart than real
-- drops -- callers should treat this as "resync, don't alarm").
function stream.computeGap(seq, lastSeq)
  if lastSeq == nil then return 0, false end
  local diff = (seq - lastSeq) % SEQ_MODULUS
  if diff == 0 then return 0, false end -- exact repeat/duplicate
  if diff > GAP_RESET_THRESHOLD then return 0, true end
  return diff - 1, false
end

-- Creates a new, unjoined/unbound/not-yet-publishing stream socket
-- record. Returns socketId.
function stream.open()
  local id = core.newSocketId()
  core.state.stream.sockets[id] = {
    group = nil,
    port = nil,
    recvQueue = {},
    lastSeq = nil,
    publishing = nil, -- { groupIp, dstPort, ratePerSec, periodSec, nextDueAt, payloadFn, seq }
    closed = false,
  }
  return id
end

function stream.join(socketId, groupIp)
  local sock = core.state.stream.sockets[socketId]
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

function stream.leave(socketId)
  local sock = core.state.stream.sockets[socketId]
  if not sock then return nil, "invalid socket" end
  sock.group = nil
  return true
end

function stream.bind(socketId, port)
  local sock = core.state.stream.sockets[socketId]
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

-- Starts periodic publishing to groupIp:dstPort at `ratePerSec` samples/
-- sec, calling `payloadFn()` (no arguments, returns a data string) fresh
-- each time a sample is due -- callers never manage their own timer.
-- `now` is the current computer.uptime() value (see the module header for
-- why this is a parameter, not an internal call). Auto-binds an ephemeral
-- local port first if the socket wasn't explicitly bound. `ratePerSec` is
-- clamped to config.stream.maxRatePerSec (default 20 -- OC's own tick
-- rate; publishing faster is meaningless). Returns true, or nil, err.
function stream.startPublishing(socketId, groupIp, dstPort, ratePerSec, payloadFn, now)
  local sock = core.state.stream.sockets[socketId]
  if not sock or sock.closed then return nil, "invalid or closed socket" end
  if not ip.isMulticast(groupIp) then
    return nil, "not a multicast group address: " .. util.ipToString(groupIp)
  end
  if type(payloadFn) ~= "function" then
    return nil, "payloadFn must be a function"
  end
  if type(ratePerSec) ~= "number" or ratePerSec <= 0 then
    return nil, "ratePerSec must be a positive number"
  end

  local cfg = core.state.config or {}
  local maxRate = (cfg.stream and cfg.stream.maxRatePerSec) or 20
  if ratePerSec > maxRate then
    ratePerSec = maxRate
  end

  local ok, err = ensureBound(sock)
  if not ok then return nil, err end

  sock.publishing = {
    groupIp = { subnet = groupIp.subnet, host = groupIp.host },
    dstPort = dstPort,
    ratePerSec = ratePerSec,
    periodSec = 1 / ratePerSec,
    nextDueAt = now or 0,
    payloadFn = payloadFn,
    seq = 0,
  }
  return true
end

function stream.stopPublishing(socketId)
  local sock = core.state.stream.sockets[socketId]
  if not sock then return nil, "invalid socket" end
  sock.publishing = nil
  return true
end

function stream.isPublishing(socketId)
  local sock = core.state.stream.sockets[socketId]
  return sock ~= nil and sock.publishing ~= nil
end

local function sendSample(sock, pub)
  local ok, data = pcall(pub.payloadFn)
  if not ok then
    core.log("error", "stream: payloadFn error, skipping this sample: %s", tostring(data))
    return
  end
  data = data or ""

  local cfg = core.state.config or {}
  local maxDatagram = (cfg.udp and cfg.udp.maxDatagram) or 32768
  if #data > maxDatagram then
    core.log("warn", "stream: oversized payload (%d > %d bytes), dropping this sample", #data, maxDatagram)
    return
  end

  local seq = pub.seq % SEQ_MODULUS
  local header = string.pack(STREAM_HDR_FMT, sock.port, pub.dstPort, #data, seq, 0)
  local checksum = util.checksum16(header .. data)
  header = string.pack(STREAM_HDR_FMT, sock.port, pub.dstPort, #data, seq, checksum)

  ip.send(pub.groupIp, stream.PROTO, header .. data)
  pub.seq = seq + 1
end

-- Daemon-only entrypoint: called once per driver tick with the current
-- computer.uptime() value. For every socket with an active
-- startPublishing() registration whose cadence has elapsed, calls its
-- payloadFn and sends one sample. A stalled driver (e.g. daemon was busy,
-- or the game itself paused) does NOT burst-catch-up missed samples --
-- nextDueAt snaps forward to `now + periodSec` rather than accumulating a
-- backlog, matching real SV's "the next sample is what matters, not
-- replaying stale ones."
function stream.drivePublishers(now)
  for _, sock in pairs(core.state.stream.sockets) do
    local pub = sock.publishing
    if pub and not sock.closed and now >= pub.nextDueAt then
      sendSample(sock, pub)
      pub.nextDueAt = now + pub.periodSec
    end
  end
end

-- Non-blocking pop of the oldest queued sample. Returns data, srcIp,
-- srcPort, seq, gap, resetDetected -- or nil if nothing is queued. `gap`
-- is how many samples were missed before this one (0 = none); see
-- stream.computeGap's header comment for `resetDetected`.
function stream.receivefrom(socketId)
  local sock = core.state.stream.sockets[socketId]
  if not sock then return nil, "invalid socket" end
  local item = table.remove(sock.recvQueue, 1)
  if not item then return nil end
  return item.data, item.srcIp, item.srcPort, item.seq, item.gap, item.resetDetected
end

function stream.hasPending(socketId)
  local sock = core.state.stream.sockets[socketId]
  return sock ~= nil and #sock.recvQueue > 0
end

function stream.close(socketId)
  local sock = core.state.stream.sockets[socketId]
  if sock then
    sock.closed = true
    core.state.stream.sockets[socketId] = nil
  end
  return true
end

-- Daemon-only entrypoint, registered via
-- ip.registerProtocolHandler(stream.PROTO, stream.handleDatagram).
function stream.handleDatagram(srcIp, dstIp, packed)
  if type(packed) ~= "string" or #packed < STREAM_HDR_LEN then
    core.log("warn", "stream: dropped short datagram")
    return
  end
  local ok, srcPort, dstPort, length, seq, checksum = pcall(string.unpack, STREAM_HDR_FMT, packed)
  if not ok then
    core.log("warn", "stream: dropped malformed header")
    return
  end
  local data = packed:sub(STREAM_HDR_LEN + 1, STREAM_HDR_LEN + length)
  if #data ~= length then
    core.log("warn", "stream: dropped datagram with truncated payload")
    return
  end

  local zeroed = string.pack(STREAM_HDR_FMT, srcPort, dstPort, length, seq, 0) .. data
  if util.checksum16(zeroed) ~= checksum then
    core.log("warn", "stream: dropped datagram with bad checksum")
    return
  end

  local cfg = core.state.config or {}
  local maxQueue = (cfg.stream and cfg.stream.recvQueueMax) or 64

  -- Same fan-out-to-every-joined+bound-socket model as multicast.lua:
  -- independent local subscribers on one (group, port) each get their
  -- own copy, and each tracks its own lastSeq/gap independently (two
  -- subscribers to the same stream can join at different times and would
  -- otherwise see different, inconsistent gap counts off a shared
  -- tracker).
  for _, sock in pairs(core.state.stream.sockets) do
    if not sock.closed and sock.port == dstPort and sock.group
        and sock.group.subnet == dstIp.subnet and sock.group.host == dstIp.host then
      local gap, resetDetected = stream.computeGap(seq, sock.lastSeq)
      sock.lastSeq = seq
      table.insert(sock.recvQueue, {
        data = data, srcIp = srcIp, srcPort = srcPort,
        seq = seq, gap = gap, resetDetected = resetDetected,
      })
      while #sock.recvQueue > maxQueue do
        table.remove(sock.recvQueue, 1)
      end
    end
  end
end

return stream
