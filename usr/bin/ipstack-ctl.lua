-- ipstack-ctl: small CLI for inspecting a running ipstackd daemon's state.
-- Reads ipstack.core's shared state directly (no IPC needed -- see
-- ipstack/core.lua for why require() caching makes that safe).
local core = require("ipstack.core")
local ip = require("ipstack.ip")
local util = require("ipstack.util")

local args = { ... }
local cmd = args[1] or "status"

local function printf(fmt, ...)
  print(string.format(fmt, ...))
end

local function cmdStatus()
  if not core.isRunning() then
    print("ipstackd: stopped (run: rc ipstackd start)")
    return
  end
  print("ipstackd: running")
  print()
  print("Interfaces:")
  local any = false
  for address, iface in pairs(core.state.interfaces) do
    any = true
    printf("  %s  ip=%s  mtu=%d  %s", address, util.ipToString(iface.ip), iface.mtu,
      iface.wireless and "wireless" or "wired")
  end
  if not any then print("  (none)") end
  print()
  printf("Stats: tx=%d rx=%d dropped=%d",
    core.state.stats.txFrames, core.state.stats.rxFrames, core.state.stats.dropped)
end

local function cmdArp()
  if not core.isRunning() then
    print("ipstackd is not running")
    return
  end
  print("IP            MAC                                   TTL(s)")
  local now = computer.uptime()
  local any = false
  for key, entry in pairs(core.state.arpCache) do
    any = true
    printf("%-13s %-37s %d", key, entry.mac, math.max(0, math.floor(entry.expiresAt - now)))
  end
  if not any then print("(empty)") end
end

local function cmdRoute()
  if not core.isRunning() then
    print("ipstackd is not running")
    return
  end
  ip.rebuildRouteTable()
  local rt = core.state.routeTable
  print("Direct routes:")
  for _, r in ipairs(rt.direct) do
    printf("  subnet %d via %s", r.subnet, r.iface)
  end
  print("Static routes:")
  for _, r in ipairs(rt.static) do
    printf("  subnet %d via gateway %s", r.subnet, util.ipToString(r.viaGateway))
  end
  if rt.defaultGateway then
    printf("Default gateway: %s", util.ipToString(rt.defaultGateway))
  else
    print("Default gateway: (none)")
  end
end

local function cmdConn()
  if not core.isRunning() then
    print("ipstackd is not running")
    return
  end
  print("TCP connections:")
  local any = false
  for id, conn in pairs(core.state.tcp.connections) do
    any = true
    printf("  #%d  %s:%d -> %s:%d  state=%s%s",
      id, "local", conn.srcPort, util.ipToString(conn.remoteIp), conn.dstPort,
      conn.state, conn.error and (" error=" .. conn.error) or "")
  end
  if not any then print("  (none)") end

  print("TCP listeners:")
  any = false
  for port, listener in pairs(core.state.tcp.listeners) do
    any = true
    printf("  port %d  backlog=%d", port, #listener.backlog)
  end
  if not any then print("  (none)") end

  print("UDP sockets:")
  any = false
  for id, sock in pairs(core.state.udp.sockets) do
    any = true
    printf("  #%d  port=%s  queued=%d", id, tostring(sock.port), #sock.recvQueue)
  end
  if not any then print("  (none)") end
end

local function cmdLog()
  local n = tonumber(args[2]) or 20
  local total = #core.state.log
  local from = math.max(1, total - n + 1)
  for i = from, total do
    local entry = core.state.log[i]
    printf("[%s] %s", entry.level, entry.message)
  end
end

local commands = {
  status = cmdStatus,
  arp = cmdArp,
  route = cmdRoute,
  conn = cmdConn,
  log = cmdLog,
}

local fn = commands[cmd]
if not fn then
  print("usage: ipstack-ctl <status|arp|route|conn|log [n]>")
  return 1
end
fn()
