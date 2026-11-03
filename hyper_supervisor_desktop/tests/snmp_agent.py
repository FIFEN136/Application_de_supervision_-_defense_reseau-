"""Mini agent SNMP v1/v2c réel (pysnmp) pour les tests : OIDs statiques ou pilotés par callback."""
import asyncio, threading
from pysnmp.entity import engine, config
from pysnmp.entity.rfc3413 import cmdrsp, context
from pysnmp.carrier.asyncio.dgram import udp
from pysnmp.proto.api import v2c


class SnmpAgent:
    def __init__(self, port, community="public", values=None):
        self.port, self.community = port, community
        self.values = values if values is not None else {}      # {(oid tuple): callable|value}
        self._ready = threading.Event(); self._loop = None; self._th = None

    def start(self):
        self._th = threading.Thread(target=self._run, daemon=True); self._th.start()
        assert self._ready.wait(10), "agent SNMP non démarré"

    def stop(self):
        if self._loop:
            self._loop.call_soon_threadsafe(self._loop.stop); self._th.join(3)

    def _run(self):
        self._loop = asyncio.new_event_loop(); asyncio.set_event_loop(self._loop)
        eng = engine.SnmpEngine()
        config.addTransport(eng, udp.domainName, udp.UdpTransport().openServerMode(("127.0.0.1", self.port)))
        config.addV1System(eng, "area", self.community)
        config.addVacmUser(eng, 2, "area", "noAuthNoPriv", (1, 3, 6), (1, 3, 6))
        config.addVacmUser(eng, 1, "area", "noAuthNoPriv", (1, 3, 6), (1, 3, 6))
        ctx = context.SnmpContext(eng)
        mb = ctx.getMibInstrum().getMibBuilder()
        MibScalar, MibScalarInstance = mb.importSymbols("SNMPv2-SMI", "MibScalar", "MibScalarInstance")
        agent = self

        def make(oid, syntax):
            class Inst(MibScalarInstance):
                def getValue(self, name, idx=None, **kw):
                    v = agent.values[oid]; v = v() if callable(v) else v
                    return self.getSyntax().clone(v)
            return Inst(oid[:-1], (oid[-1],), syntax)

        syms = {}
        for i, (oid, v) in enumerate(self.values.items()):
            syntax = v2c.OctetString() if isinstance(v() if callable(v) else v, str) else v2c.Counter32() \
                if oid[:8] in ((1,3,6,1,2,1,2,2),) and oid[9] in (10, 16) else v2c.Integer32()
            syms[f"s{i}"] = MibScalar(oid[:-1], syntax)
            syms[f"i{i}"] = make(oid, syntax)
        mb.exportSymbols("__TEST_MIB", **syms)
        cmdrsp.GetCommandResponder(eng, ctx); cmdrsp.NextCommandResponder(eng, ctx)
        eng.transportDispatcher.jobStarted(1)
        self._ready.set()
        try:
            self._loop.run_forever()
        finally:
            eng.transportDispatcher.closeDispatcher()
