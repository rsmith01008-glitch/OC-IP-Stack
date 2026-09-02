-- /etc/rc.d/ipstackd.lua -- OpenOS rc.d service wrapper for the OC-IP-Stack
-- daemon. `rc` invokes start()/stop()/status() synchronously in the
-- caller's own process; `restart` is provided for free by `rc` as
-- stop()+start(). Every function defined here also becomes an invokable
-- `rc ipstackd <fn>` subcommand automatically.
--
-- All real work lives in ipstack.daemon (kept as a library module so it
-- can also be required directly, e.g. by ipstack-ctl, without going
-- through rc).
local daemon = require("ipstack.daemon")

function start()
  local ok, warnings = daemon.start()
  if ok and warnings then
    print("ipstackd: " .. warnings)
  end
  return ok
end

function stop()
  return daemon.stop()
end

function status()
  if daemon.isRunning() then
    print("ipstackd: running")
  else
    print("ipstackd: stopped")
  end
end
