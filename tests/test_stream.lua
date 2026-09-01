-- Plain lua5.3-executable tests for ipstack.stream. Runs outside the game
-- entirely: ipstack.core/ipstack.ip/ipstack.util/ipstack.eth/ipstack.stream
-- have no OC-API calls at module load time, and every OC-only call inside
-- them (component.*, event.*, computer.uptime()) lives behind function
-- bodies this test never calls -- stream.lua itself takes `now` as an
-- explicit parameter for exactly this reason (see its header comment).
-- Run: lua5.3 tests/test_stream.lua

package.path = "./?.lua;./?/init.lua;" .. package.path

local core = require("ipstack.core")
local stream = require("ipstack.stream")

local failures = 0
local function check(name, cond, detail)
  if cond then
    print("ok:   " .. name)
  else
    failures = failures + 1
    print("FAIL: " .. name .. (detail and (" -- " .. detail) or ""))
  end
end

local GROUP = { subnet = 255, host = 10 }
local NOT_MULTICAST = { subnet = 1, host = 10 }

--- computeGap ---------------------------------------------------------

do
  local gap, reset = stream.computeGap(5, 4)
  check("computeGap: consecutive seq -> gap 0", gap == 0 and reset == false)

  gap, reset = stream.computeGap(5, 2)
  check("computeGap: 2 missed -> gap 2", gap == 2 and reset == false, tostring(gap))

  gap, reset = stream.computeGap(10, 10)
  check("computeGap: duplicate seq -> gap 0, no reset", gap == 0 and reset == false)

  gap, reset = stream.computeGap(0, nil)
  check("computeGap: first-ever sample (lastSeq=nil) -> gap 0", gap == 0 and reset == false)

  gap, reset = stream.computeGap(1, 65530)
  check("computeGap: wraps past 65535 correctly -- 6 missed", gap == 6 and reset == false, tostring(gap))

  gap, reset = stream.computeGap(1, 60000)
  check("computeGap: publisher-restart-sized jump -> resetDetected, gap 0",
    gap == 0 and reset == true, "gap=" .. tostring(gap) .. " reset=" .. tostring(reset))
end

--- open/join/bind error paths ------------------------------------------

do
  local id = stream.open()
  check("open: returns a socket id", type(id) == "number")

  local ok, err = stream.join(id, NOT_MULTICAST)
  check("join: rejects a non-multicast group", ok == nil and err ~= nil, tostring(err))

  ok = stream.join(id, GROUP)
  check("join: accepts a multicast group", ok == true)

  ok, err = stream.join(id, GROUP)
  check("join: rejects a second join without leave() first", ok == nil and err ~= nil)

  ok = stream.bind(id, 12345)
  check("bind: succeeds", ok == true)

  stream.close(id)
end

--- startPublishing validation + maxRatePerSec clamping -----------------

do
  local id = stream.open()

  local ok, err = stream.startPublishing(id, NOT_MULTICAST, 100, 10, function() return "x" end, 0)
  check("startPublishing: rejects non-multicast group", ok == nil and err ~= nil)

  ok, err = stream.startPublishing(id, GROUP, 100, 10, "not a function", 0)
  check("startPublishing: rejects a non-function payloadFn", ok == nil and err ~= nil)

  ok, err = stream.startPublishing(id, GROUP, 100, 0, function() return "x" end, 0)
  check("startPublishing: rejects a non-positive ratePerSec", ok == nil and err ~= nil)

  ok = stream.startPublishing(id, GROUP, 100, 9999, function() return "x" end, 0)
  check("startPublishing: succeeds and clamps an over-limit rate", ok == true)

  local sock = core.state.stream.sockets[id]
  check("startPublishing: clamps ratePerSec to config default (20)",
    sock.publishing.ratePerSec == 20, tostring(sock.publishing.ratePerSec))
  check("startPublishing: derives periodSec = 1/ratePerSec",
    math.abs(sock.publishing.periodSec - 0.05) < 1e-9)

  check("isPublishing: true once started", stream.isPublishing(id) == true)
  stream.stopPublishing(id)
  check("isPublishing: false after stopPublishing", stream.isPublishing(id) == false)

  stream.close(id)
end

--- drivePublishers: cadence-gated sends, no burst catch-up --------------

do
  local id = stream.open()
  local calls = 0
  stream.startPublishing(id, GROUP, 100, 10, function() calls = calls + 1; return "s" .. calls end, 0)

  stream.drivePublishers(0) -- exactly due at t=0
  check("drivePublishers: fires once when due", calls == 1)

  stream.drivePublishers(0.05) -- not due yet (period=0.1s)
  check("drivePublishers: does not fire early", calls == 1)

  stream.drivePublishers(0.1) -- due again
  check("drivePublishers: fires again once its period elapses", calls == 2)

  -- Simulate a long stall (e.g. daemon busy for 5 seconds): nextDueAt
  -- should snap forward from `now`, not fire 50 backlogged samples.
  stream.drivePublishers(5.23)
  check("drivePublishers: a long stall does not burst-catch-up", calls == 3, tostring(calls))

  stream.drivePublishers(5.24) -- not due yet relative to the snap at 5.23
  check("drivePublishers: nextDueAt snapped to `now`, not the missed schedule", calls == 3)

  stream.close(id)
end

--- payloadFn error isolation ---------------------------------------------

do
  local id1 = stream.open()
  local id2 = stream.open()
  local goodCalls = 0
  stream.startPublishing(id1, GROUP, 100, 10, function() error("boom") end, 0)
  stream.startPublishing(id2, GROUP, 100, 10, function() goodCalls = goodCalls + 1; return "ok" end, 0)

  local ok = pcall(stream.drivePublishers, 0)
  check("drivePublishers: a throwing payloadFn does not raise out of drivePublishers", ok == true)
  check("drivePublishers: a throwing payloadFn does not stop other sockets' sends", goodCalls == 1)

  stream.close(id1)
  stream.close(id2)
end

--- end-to-end: send header round-trips through handleDatagram -----------

do
  local publisherId = stream.open()
  local subscriberId = stream.open()
  stream.join(subscriberId, GROUP)
  stream.bind(subscriberId, 500)

  local payloads = { "sample-A", "sample-B", "sample-C" }
  local i = 0
  stream.startPublishing(publisherId, GROUP, 500, 10, function()
    i = i + 1
    return payloads[i]
  end, 0)

  -- Capture what ip.send would have transmitted by monkeypatching it for
  -- this one test, then feed it straight into handleDatagram -- exactly
  -- what daemon.lua's real modem_message handler would do after decoding
  -- an incoming frame, minus the actual radio hop.
  local ip = require("ipstack.ip")
  local sent = {}
  local realSend = ip.send
  ip.send = function(dstIp, protocol, payload)
    table.insert(sent, { dstIp = dstIp, protocol = protocol, payload = payload })
    return true
  end

  stream.drivePublishers(0)
  stream.drivePublishers(0.1)
  stream.drivePublishers(0.2)

  ip.send = realSend

  check("end-to-end: 3 samples were sent", #sent == 3, tostring(#sent))
  check("end-to-end: sent on stream.PROTO", sent[1] and sent[1].protocol == stream.PROTO)

  local srcIp = { subnet = 1, host = 99 }
  for _, frame in ipairs(sent) do
    stream.handleDatagram(srcIp, frame.dstIp, frame.payload)
  end

  local data1, sIp1, sPort1, seq1, gap1 = stream.receivefrom(subscriberId)
  check("end-to-end: 1st sample data matches", data1 == "sample-A", tostring(data1))
  check("end-to-end: 1st sample seq = 0", seq1 == 0, tostring(seq1))
  check("end-to-end: 1st sample gap = 0 (nothing before it)", gap1 == 0)

  local data2, _, _, seq2, gap2 = stream.receivefrom(subscriberId)
  check("end-to-end: 2nd sample data matches", data2 == "sample-B")
  check("end-to-end: 2nd sample seq = 1", seq2 == 1)
  check("end-to-end: 2nd sample gap = 0 (no drops)", gap2 == 0)

  local data3, _, _, seq3, gap3 = stream.receivefrom(subscriberId)
  check("end-to-end: 3rd sample data matches", data3 == "sample-C")
  check("end-to-end: 3rd sample seq = 2", seq3 == 2)

  check("end-to-end: recv queue drained after 3 pops", stream.hasPending(subscriberId) == false)

  stream.close(publisherId)
  stream.close(subscriberId)
end

--- end-to-end: a dropped sample is reported as a gap --------------------

do
  local publisherId = stream.open()
  local subscriberId = stream.open()
  stream.join(subscriberId, GROUP)
  stream.bind(subscriberId, 501)

  local n = 0
  stream.startPublishing(publisherId, GROUP, 501, 10, function() n = n + 1; return "p" .. n end, 0)

  local ip = require("ipstack.ip")
  local sent = {}
  local realSend = ip.send
  ip.send = function(dstIp, protocol, payload) table.insert(sent, { dstIp = dstIp, payload = payload }) return true end
  stream.drivePublishers(0)   -- seq 0
  stream.drivePublishers(0.1) -- seq 1 (will be dropped -- never delivered)
  stream.drivePublishers(0.2) -- seq 2
  ip.send = realSend

  local srcIp = { subnet = 1, host = 99 }
  stream.handleDatagram(srcIp, sent[1].dstIp, sent[1].payload) -- seq 0
  stream.handleDatagram(srcIp, sent[3].dstIp, sent[3].payload) -- seq 2, skipping sent[2]

  stream.receivefrom(subscriberId) -- consume seq 0
  local data, _, _, seq, gap, resetDetected = stream.receivefrom(subscriberId)
  check("dropped sample: seq 2 delivered", seq == 2)
  check("dropped sample: gap = 1 (seq 1 was missed)", gap == 1, tostring(gap))
  check("dropped sample: not flagged as a publisher reset", resetDetected == false)

  stream.close(publisherId)
  stream.close(subscriberId)
end

--- checksum / malformed datagram handling --------------------------------

do
  local subscriberId = stream.open()
  stream.join(subscriberId, GROUP)
  stream.bind(subscriberId, 502)

  stream.handleDatagram({ subnet = 1, host = 1 }, GROUP, "short")
  check("handleDatagram: too-short datagram is dropped, not raised", stream.hasPending(subscriberId) == false)

  -- A validly-shaped but corrupted-checksum datagram.
  local STREAM_HDR_FMT = ">I2I2I2I2I2"
  local header = string.pack(STREAM_HDR_FMT, 500, 502, 4, 0, 0xFFFF)
  stream.handleDatagram({ subnet = 1, host = 1 }, GROUP, header .. "data")
  check("handleDatagram: bad checksum is dropped, not delivered", stream.hasPending(subscriberId) == false)

  stream.close(subscriberId)
end

print("")
if failures == 0 then
  print("all assertions passed")
  os.exit(0)
else
  print(failures .. " assertion(s) FAILED")
  os.exit(1)
end
