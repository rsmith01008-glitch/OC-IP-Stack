-- ipstack.tcp: TCP-like reliable, ordered, connection-oriented stream over
-- ipstack.ip. Deliberately minimal per the design's scope guardrails: a
-- fixed receive window (no cwnd/AIMD congestion control), a single
-- exponential-backoff retransmit timer with capped retries, and only
-- SYN/ACK/FIN/RST flags (no options, no PSH/URG, no SACK).
--
-- SYN and FIN each consume one sequence-number slot, same as real TCP;
-- this lets a single "unacked outbound thing" bookkeeping structure
-- (conn.inFlight, keyed by starting sequence number) drive retransmission
-- uniformly for the handshake, the data stream, and the close handshake.
--
-- Sequence numbers are treated as plain (non-wrapping) 32-bit counters --
-- wraparound after 4GiB on one connection is not handled, which is an
-- acceptable simplification at OpenComputers scale.
local computer = require("computer")
local core = require("ipstack.core")
local util = require("ipstack.util")
local ip = require("ipstack.ip")

local tcp = {}

tcp.PROTO = 6

local FLAG_SYN = 0x1
local FLAG_ACK = 0x2
local FLAG_FIN = 0x4
local FLAG_RST = 0x8

-- srcPort(I2) dstPort(I2) seq(I4) ack(I4) flags(I1) window(I2) checksum(I2)
local TCP_HDR_FMT = ">I2I2I4I4I1I2I2"
local TCP_HDR_LEN = 17
local BACKLOG_MAX = 8

--- Internal helpers ------------------------------------------------------------

local function localWindow(conn)
  local cfg = core.state.config or {}
  local defaultWindow = (cfg.tcp and cfg.tcp.defaultWindow) or 4096
  return math.max(0, defaultWindow - #conn.recvBuffer)
end

-- Builds, checksums and transmits one segment for `conn`, and (for a
-- segment that carries data or a control flag needing acknowledgment)
-- records/refreshes it in conn.inFlight for tick()-driven retransmission.
-- Does NOT advance conn.sndNxt -- callers own that.
local function transmitSegment(conn, seq, len, flags, data)
  data = data or ""
  local window = localWindow(conn)
  local headerZero = string.pack(TCP_HDR_FMT, conn.srcPort, conn.dstPort, seq, conn.rcvNxt, flags, window, 0)
  local checksum = util.checksum16(headerZero .. data)
  local header = string.pack(TCP_HDR_FMT, conn.srcPort, conn.dstPort, seq, conn.rcvNxt, flags, window, checksum)
  ip.send(conn.remoteIp, tcp.PROTO, header .. data)

  local needsAck = len > 0 or (flags & (FLAG_SYN | FLAG_FIN)) ~= 0
  if needsAck then
    local entry = conn.inFlight[seq] or { retries = 0 }
    entry.len = len
    entry.flags = flags
    entry.data = data
    entry.sentAt = computer.uptime()
    conn.inFlight[seq] = entry
  end
end

local function sendRst(dstIp, dstPort, localPort, seq, ackNum)
  local headerZero = string.pack(TCP_HDR_FMT, localPort, dstPort, seq, ackNum, FLAG_RST, 0, 0)
  local checksum = util.checksum16(headerZero)
  local header = string.pack(TCP_HDR_FMT, localPort, dstPort, seq, ackNum, FLAG_RST, 0, checksum)
  ip.send(dstIp, tcp.PROTO, header)
end

local function findConnection(localPort, remoteIp, remotePort)
  for _, conn in pairs(core.state.tcp.connections) do
    if conn.srcPort == localPort and conn.dstPort == remotePort and util.ipEquals(conn.remoteIp, remoteIp) then
      return conn
    end
  end
  return nil
end

-- Removes any inFlight entries fully covered by a newly-received
-- cumulative ack, and advances sndUna.
local function ackInFlight(conn, ack)
  if ack > conn.sndUna then
    conn.sndUna = ack
  end
  for seq, entry in pairs(conn.inFlight) do
    if seq + entry.len <= conn.sndUna then
      conn.inFlight[seq] = nil
    end
  end
  if conn.finSeq and not conn.finAcked and conn.sndUna >= conn.finSeq + 1 then
    conn.finAcked = true
  end
end

-- Forward-declared: pump() calls this at the end so a tcp.close() issued
-- while data is still queued/unacked (conn.closePending) sends FIN only
-- once everything has actually gone out, rather than close() sending FIN
-- immediately and silently truncating whatever was still in pendingSend.
local maybeSendDeferredFin

-- Transmits as many queued-but-unsent chunks (each already <= conn.mss,
-- chunked by tcp.send) as the peer's advertised window currently allows.
local function pump(conn)
  while #conn.pendingSend > 0 do
    local chunk = conn.pendingSend[1]
    local inFlightBytes = conn.sndNxt - conn.sndUna
    if inFlightBytes + #chunk > conn.peerWindow then break end
    table.remove(conn.pendingSend, 1)
    local seq = conn.sndNxt
    transmitSegment(conn, seq, #chunk, FLAG_ACK, chunk)
    conn.sndNxt = conn.sndNxt + #chunk
  end
  maybeSendDeferredFin(conn)
end

-- Sends the FIN queued by tcp.close() once (and only once) every byte
-- handed to tcp.send has actually been transmitted and acknowledged.
maybeSendDeferredFin = function(conn)
  if not conn.closePending or conn.finSeq then return end
  if #conn.pendingSend > 0 or next(conn.inFlight) ~= nil then return end

  conn.finSeq = conn.sndNxt
  transmitSegment(conn, conn.sndNxt, 1, FLAG_FIN | FLAG_ACK, "")
  conn.sndNxt = conn.sndNxt + 1
  if conn.state == "CLOSE_WAIT" then
    conn.state = "LAST_ACK"
  else
    conn.state = "FIN_WAIT"
  end
end

-- MSS must never exceed the fixed receive window: since there is no
-- congestion control or window scaling in this stack (see the file
-- header), pump() only ever sends a whole chunk at once and never splits
-- one to fit -- an MSS larger than defaultWindow would mean the very
-- first chunk of any transfer permanently exceeds conn.peerWindow and
-- pump() stalls forever. A modem's maxPacketSize() (default 8192) can
-- easily produce an MTU-derived MSS bigger than a small configured
-- window, so cap it here.
local function mssForRoute(remoteIp)
  local ifaceAddr = ip.lookupRoute(remoteIp)
  local mtu = (ifaceAddr and ip.MTU(ifaceAddr)) or (4096 - 78)
  local mtuMss = mtu - 15 - TCP_HDR_LEN
  local cfg = core.state.config or {}
  local window = (cfg.tcp and cfg.tcp.defaultWindow) or 4096
  return math.max(1, math.min(mtuMss, window))
end

-- Generates an initial sequence number. Deliberately avoids
-- math.random(0, 0xFFFFFFFF): some Lua 5.3 builds' underlying PRNG only
-- covers a narrower native range and reject a two-argument call spanning
-- the full 32 bits ("interval is too large"). True unpredictability isn't
-- a security requirement here (a trusted local network, no attacker
-- guessing sequence numbers to hijack a session) -- this just needs to
-- avoid immediate collisions between successive connections reusing the
-- same port pair.
local isnCounter = 0
local function nextIsn()
  isnCounter = (isnCounter + 99991) % 0x100000000
  return (isnCounter + math.random(0, 255)) % 0x100000000
end

--- Public: connection setup ------------------------------------------------------------

-- Sends a SYN and returns immediately in SYN_SENT -- non-blocking.
-- Callers that want to wait for the handshake to complete (or fail) poll
-- tcp.getState(connId)/tcp.getError(connId), typically via
-- core.waitUntil from ipstack.socket.
function tcp.connect(dstIp, dstPort)
  local ifaceAddr, routeErr = ip.lookupRoute(dstIp)
  if not ifaceAddr then return nil, routeErr end

  local srcPort = core.allocEphemeralPort()
  if not srcPort then return nil, "no ephemeral ports available" end

  local id = core.newConnId()
  local isn = nextIsn()
  local conn = {
    id = id,
    state = "SYN_SENT",
    remoteIp = dstIp,
    srcPort = srcPort,
    dstPort = dstPort,
    sndUna = isn,
    sndNxt = isn,
    rcvNxt = 0,
    peerWindow = 1,
    recvBuffer = "",
    inFlight = {},
    pendingSend = {},
    mss = mssForRoute(dstIp),
    peerClosed = false,
    createdAt = computer.uptime(),
    lastActivity = computer.uptime(),
  }
  core.state.tcp.connections[id] = conn
  transmitSegment(conn, isn, 1, FLAG_SYN, "")
  conn.sndNxt = isn + 1
  return id
end

function tcp.listen(port)
  if core.state.tcp.listeners[port] then return nil, "address already in use" end
  for _, conn in pairs(core.state.tcp.connections) do
    if conn.srcPort == port and conn.listenerPort == nil then
      return nil, "address already in use"
    end
  end
  core.state.tcp.listeners[port] = { port = port, backlog = {} }
  return true
end

function tcp.stopListening(port)
  core.state.tcp.listeners[port] = nil
  return true
end

-- Non-blocking: pops the oldest fully-established inbound connection from
-- the listener's backlog, or returns nil if none is ready.
function tcp.accept(port)
  local listener = core.state.tcp.listeners[port]
  if not listener then return nil, "not listening on port " .. tostring(port) end
  local connId = table.remove(listener.backlog, 1)
  if not connId then return nil end
  return connId
end

--- Public: data transfer ------------------------------------------------------------

function tcp.send(connId, data)
  local conn = core.state.tcp.connections[connId]
  if not conn then return nil, "invalid connection" end
  if conn.state ~= "ESTABLISHED" and conn.state ~= "CLOSE_WAIT" then
    return nil, conn.error or ("not connected (state=" .. tostring(conn.state) .. ")")
  end
  data = data or ""
  local pos = 1
  while pos <= #data do
    table.insert(conn.pendingSend, data:sub(pos, pos + conn.mss - 1))
    pos = pos + conn.mss
  end
  pump(conn)
  return true
end

-- Non-blocking: drains and returns whatever has been received so far.
-- Returns "" (not nil) if the connection is open but nothing has arrived
-- yet, so callers can distinguish "keep waiting" from a real error;
-- ipstack.socket wraps this with a timeout-bounded core.waitUntil loop.
function tcp.receive(connId)
  local conn = core.state.tcp.connections[connId]
  if not conn then return nil, "invalid connection" end
  if #conn.recvBuffer > 0 then
    local data = conn.recvBuffer
    conn.recvBuffer = ""
    -- Announce the freed receive window immediately: this fixed-window
    -- stack has no zero-window probing/keepalive, so a sender stalled at
    -- a full window (see mssForRoute's comment -- MSS is capped to
    -- defaultWindow, so exactly this can happen on the very first
    -- segment of any transfer) needs to learn the window reopened right
    -- away rather than waiting on some other inbound segment to piggyback
    -- it on, which may never come.
    if conn.state ~= "CLOSED" then
      transmitSegment(conn, conn.sndNxt, 0, FLAG_ACK, "")
    end
    return data
  end
  if conn.error then return nil, conn.error end
  if conn.peerClosed then return nil, "closed" end
  return ""
end

function tcp.hasPendingData(connId)
  local conn = core.state.tcp.connections[connId]
  if not conn then return false end
  return #conn.recvBuffer > 0 or conn.peerClosed or conn.error ~= nil
end

function tcp.getState(connId)
  local conn = core.state.tcp.connections[connId]
  return conn and conn.state
end

function tcp.getError(connId)
  local conn = core.state.tcp.connections[connId]
  return conn and conn.error
end

-- Initiates (or completes, on the passive side) the close handshake.
-- Non-blocking. If data handed to tcp.send is still queued or unacked,
-- FIN is deferred (via maybeSendDeferredFin, triggered from pump() as
-- acks arrive) until it has all actually gone out, rather than truncating
-- the stream. The connection lingers in TIME_WAIT briefly afterward.
function tcp.close(connId)
  local conn = core.state.tcp.connections[connId]
  if not conn then return nil, "invalid connection" end
  if conn.state == "CLOSED" or conn.state == "TIME_WAIT" or conn.state == "FIN_WAIT" or conn.state == "LAST_ACK" then
    return true
  end

  if conn.state == "CLOSE_WAIT" or conn.state == "ESTABLISHED"
      or conn.state == "SYN_SENT" or conn.state == "SYN_RCVD" then
    conn.closePending = true
    maybeSendDeferredFin(conn)
  else
    conn.state = "CLOSED"
    conn.closedAt = computer.uptime()
  end
  return true
end

--- Daemon-only: inbound segment handling ------------------------------------------------------------

local function handleSegmentForConn(conn, seq, ack, flags, window, data)
  conn.lastActivity = computer.uptime()

  if (flags & FLAG_RST) ~= 0 then
    conn.state = "CLOSED"
    conn.error = "connection reset"
    conn.closedAt = computer.uptime()
    return
  end

  if conn.state == "SYN_SENT" then
    if (flags & FLAG_SYN) ~= 0 and (flags & FLAG_ACK) ~= 0 and ack == conn.sndUna + 1 then
      conn.inFlight[conn.sndUna] = nil
      conn.sndUna = ack
      conn.sndNxt = ack
      conn.rcvNxt = seq + 1
      conn.peerWindow = math.max(window, 1)
      conn.state = "ESTABLISHED"
      transmitSegment(conn, conn.sndNxt, 0, FLAG_ACK, "")
    end
    return
  end

  if conn.state == "SYN_RCVD" and (flags & FLAG_ACK) ~= 0 and ack == conn.sndUna + 1 then
    conn.inFlight[conn.sndUna] = nil
    conn.sndUna = ack
    conn.sndNxt = ack
    conn.state = "ESTABLISHED"
    local listener = core.state.tcp.listeners[conn.listenerPort]
    if listener and #listener.backlog < BACKLOG_MAX then
      table.insert(listener.backlog, conn.id)
    end
  end

  if (flags & FLAG_ACK) ~= 0 then
    ackInFlight(conn, ack)
    conn.peerWindow = math.max(window, 1)
  end

  if #data > 0 then
    if seq == conn.rcvNxt then
      conn.recvBuffer = conn.recvBuffer .. data
      conn.rcvNxt = conn.rcvNxt + #data
    end
    -- Always re-ack current rcvNxt (in-order or not) so the sender can
    -- detect gaps/duplicates via a duplicate ack, even without SACK.
    transmitSegment(conn, conn.sndNxt, 0, FLAG_ACK, "")
  end

  if (flags & FLAG_FIN) ~= 0 and seq + #data == conn.rcvNxt then
    conn.rcvNxt = conn.rcvNxt + 1
    conn.peerClosed = true
    transmitSegment(conn, conn.sndNxt, 0, FLAG_ACK, "")
  end

  if conn.state == "ESTABLISHED" and conn.peerClosed then
    conn.state = "CLOSE_WAIT"
  elseif conn.state == "FIN_WAIT" and conn.peerClosed and conn.finAcked then
    conn.state = "TIME_WAIT"
    conn.closedAt = computer.uptime()
  elseif conn.state == "LAST_ACK" and conn.finAcked then
    conn.state = "CLOSED"
    conn.closedAt = computer.uptime()
  end

  pump(conn)
end

-- Daemon-only entrypoint, registered via
-- ip.registerProtocolHandler(tcp.PROTO, tcp.handleSegment).
function tcp.handleSegment(srcIp, dstIp, payload)
  if type(payload) ~= "string" or #payload < TCP_HDR_LEN then
    core.log("warn", "tcp: dropped short segment")
    return
  end
  local ok, srcPort, dstPort, seq, ack, flags, window, checksum = pcall(string.unpack, TCP_HDR_FMT, payload)
  if not ok then
    core.log("warn", "tcp: dropped malformed header")
    return
  end
  local data = payload:sub(TCP_HDR_LEN + 1)
  local zeroed = string.pack(TCP_HDR_FMT, srcPort, dstPort, seq, ack, flags, window, 0) .. data
  if util.checksum16(zeroed) ~= checksum then
    core.log("warn", "tcp: dropped segment with bad checksum")
    return
  end

  local conn = findConnection(dstPort, srcIp, srcPort)
  if conn then
    handleSegmentForConn(conn, seq, ack, flags, window, data)
    return
  end

  if (flags & FLAG_SYN) ~= 0 and (flags & FLAG_ACK) == 0 then
    local listener = core.state.tcp.listeners[dstPort]
    if not listener then
      sendRst(srcIp, srcPort, dstPort, 0, seq + 1)
      return
    end
    if #listener.backlog >= BACKLOG_MAX then
      sendRst(srcIp, srcPort, dstPort, 0, seq + 1)
      return
    end

    local id = core.newConnId()
    local isn = nextIsn()
    local newConn = {
      id = id,
      state = "SYN_RCVD",
      remoteIp = srcIp,
      srcPort = dstPort,
      dstPort = srcPort,
      sndUna = isn,
      sndNxt = isn,
      rcvNxt = seq + 1,
      peerWindow = math.max(window, 1),
      recvBuffer = "",
      inFlight = {},
      pendingSend = {},
      mss = mssForRoute(srcIp),
      peerClosed = false,
      listenerPort = dstPort,
      createdAt = computer.uptime(),
      lastActivity = computer.uptime(),
    }
    core.state.tcp.connections[id] = newConn
    transmitSegment(newConn, isn, 1, FLAG_SYN | FLAG_ACK, "")
    newConn.sndNxt = isn + 1
    return
  end

  if (flags & FLAG_RST) == 0 then
    sendRst(srcIp, srcPort, dstPort, ack, 0)
  end
end

--- Daemon-only: timer housekeeping ------------------------------------------------------------

-- Retransmits unacked segments past their backoff deadline (capped
-- retries -> connection reset with a clear error), reaps idle
-- connections, and reaps connections that have lingered past TIME_WAIT.
function tcp.tick()
  local cfg = core.state.config or {}
  local rtoBase = (cfg.tcp and cfg.tcp.rtoSec) or 1
  local rtoMax = (cfg.tcp and cfg.tcp.rtoMaxSec) or 8
  local maxRetries = (cfg.tcp and cfg.tcp.maxRetries) or 8
  local idleTimeout = (cfg.tcp and cfg.tcp.idleTimeoutSec) or 120
  local timeWait = (cfg.tcp and cfg.tcp.timeWaitSec) or 5
  local now = computer.uptime()

  for id, conn in pairs(core.state.tcp.connections) do
    if conn.state == "CLOSED" or conn.state == "TIME_WAIT" then
      if conn.closedAt and now - conn.closedAt > timeWait then
        core.state.tcp.connections[id] = nil
      end
    elseif now - conn.lastActivity > idleTimeout then
      conn.state = "CLOSED"
      conn.error = "connection timed out (idle)"
      conn.closedAt = now
    else
      for seq, entry in pairs(conn.inFlight) do
        local rto = math.min(rtoBase * (2 ^ entry.retries), rtoMax)
        if now - entry.sentAt >= rto then
          if entry.retries >= maxRetries then
            conn.state = "CLOSED"
            conn.error = "connection timed out (no response)"
            conn.closedAt = now
            conn.inFlight[seq] = nil
          else
            entry.retries = entry.retries + 1
            transmitSegment(conn, seq, entry.len, entry.flags, entry.data)
          end
        end
      end
    end
  end
end

return tcp
