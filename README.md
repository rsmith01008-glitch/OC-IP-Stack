# OC-IP-Stack

A layered Ethernet/IP/TCP/UDP-style network stack for [OpenComputers](https://oc.cil.li/),
built on top of the mod's built-in `component.modem` API. Runtime programs
get a small socket-style client library; all packet I/O, address
resolution, and retransmission/timeout housekeeping run asynchronously in
a background `rc.d` service (`ipstackd`), not inline in the calling
program.

## Why

OpenComputers modems already deliver messages reliably to a given
component address or by broadcast, but they have no concept of IP
addressing, routing between separate networks, or a reliable ordered byte
stream. OC-IP-Stack adds:

- **Link layer** (`ipstack.eth`): Ethernet-like framing over modem
  messages, with ARP-style resolution of IP-like addresses to modem
  component addresses.
- **Network layer** (`ipstack.ip`): a simplified `subnet.host` addressing
  scheme, a routing table (direct / static / default-gateway routes) so a
  multi-modem node can relay between subnets, and transparent
  fragmentation/reassembly for payloads larger than a modem's
  `maxPacketSize()`.
- **Transport layer**: `ipstack.tcp` (connection-oriented, handshake,
  sequence/ack numbers, retransmission, ordered delivery) and
  `ipstack.udp` (datagrams, port multiplexing).
- **Public API** (`ipstack.socket`): the only module a program should
  `require()` directly.

## Architecture in one paragraph

OpenOS is a single Lua VM with cooperative coroutines, not real isolated
OS processes. `require()` caches modules by path, so `ipstackd` (started
as an `rc.d` service) and any program that does
`require("ipstack.socket")` share the *exact same* state table
(`ipstack.core`'s `core.state`). That shared table is the IPC: `ipstackd`
owns the only code that ever reads from a modem or registers
`modem_message`/timer event handlers, and writes results into the shared
tables; client calls in `ipstack.socket` read/write the same tables
directly and block (when appropriate) by polling with `os.sleep`-based
yields, which is what lets the daemon's handlers actually run in between.
See the comments at the top of `ipstack/core.lua` for the full
correctness argument.

## Install

### Option A: OPPM

```
oppm install oc-ip-stack
```

### Option B: standalone installer

From a cloned copy of this repo:

```
cd OC-IP-Stack
install
```

Or, on a machine with an internet card and no local copy:

```
wget -f https://raw.githubusercontent.com/rsmith01008-glitch/OC-IP-Stack/main/install.lua install.lua
install
```

The installer copies files into `/lib/ipstack/`, `/etc/rc.d/`, and
`/bin/`, writes a default `/etc/ipstack.cfg` (prompting for per-modem
address configuration when run interactively), and offers to enable and
start the `ipstackd` service. Pass `--yes` to skip the enable/start
prompt and do it automatically.

## Configuring a node

Edit `/etc/ipstack.cfg` (see `/etc/ipstack.cfg.example` for a fully
commented reference). At minimum, assign each local modem an address:

```lua
{
  interfaces = {
    ["<modem-component-address>"] = { subnet = 1, host = 5 },
  },
  defaultGateway = { subnet = 1, host = 1 }, -- omit on a relay/gateway node
}
```

Find a modem's component address in-game with:

```lua
for address in component.list("modem") do print(address) end
```

A node with two or more modems and `ip.forwarding = true` acts as a
relay/gateway between subnets; other nodes reach non-local subnets via
`staticRoutes` or `defaultGateway`. Restart after editing:

```
rc ipstackd restart
```

## Using the library

```lua
local socket = require("ipstack.socket")

-- TCP client
local conn, err = socket.connect("1.10", 8080, 5) -- ip, port, timeout(s)
if not conn then error(err) end
conn:send("hello\n")
local data, rerr = conn:receive(5)
conn:close()

-- TCP server
local listener = socket.listen(8080)
while true do
  local conn = listener:accept() -- blocks (default timeout) until a client connects
  if conn then
    local data = conn:receive(10)
    if data then conn:send("echo: " .. data) end
    conn:close()
  end
end

-- UDP
local u = socket.udp()
u:bind(9000)
u:sendto("1.10", 9001, "ping")
local data, srcIp, srcPort = u:receivefrom(5)
u:close()
```

Every `ipstack.socket` call checks that `ipstackd` is running first and
returns a clear `nil, err` immediately if it isn't -- it will never hang
waiting on a daemon that was never started. Anything that can legitimately
take time (`connect`, `receive`, `accept`) takes an optional timeout in
seconds (defaults to 10s for `connect`/`receive`) and returns
`nil, "timeout"` rather than blocking forever.

## Inspecting a running node

```
rc ipstackd status        -- running/stopped
ipstack-ctl status        -- interfaces, MTU, tx/rx/dropped stats
ipstack-ctl arp           -- ARP cache
ipstack-ctl route         -- routing table
ipstack-ctl conn          -- TCP connections/listeners, UDP sockets
ipstack-ctl log [n]       -- last n log lines (default 20)
```

## Design notes / scope

Full design rationale (wire formats, module boundaries, error handling)
lives in code comments, particularly `ipstack/core.lua`, `ipstack/eth.lua`
and `ipstack/ip.lua`. Deliberately **not** implemented, to keep this
focused for an OpenComputers-scale network:

- No TCP congestion control (fixed window, capped exponential-backoff
  retransmit only) and no TCP options (no MSS negotiation, window
  scaling, SACK, timestamps).
- No IPv6 or true 4-octet IPv4 addressing -- a 2-octet `subnet.host`
  address space (255 subnets x 254 hosts) is used instead.
- No dynamic routing protocol, no CIDR -- routes are static config only.
- No DHCP-equivalent address assignment -- static config only, with a
  gratuitous-ARP conflict warning at daemon start.
- No DNS-equivalent -- only a static `hosts` table in `/etc/ipstack.cfg`.
- No ICMP suite, NAT, firewalling, encryption, or raw sockets.

## Testing

This was developed and syntax-checked outside of an OpenComputers/
Minecraft runtime -- there is no way to execute OpenComputers component
APIs (`component.modem`, `event`, etc.) outside the mod. Before relying on
this in a world, exercise it on two or more real (or
[OCEmu](https://github.com/zenith391/OCEmu)-emulated) OpenComputers
machines: ARP resolution between two nodes, a UDP echo round trip, a full
TCP connect/send/receive/close cycle, and (with a third relay node)
cross-subnet routing through a gateway.
