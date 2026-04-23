from pox.core import core
from pox.lib.util import dpid_to_str
from pox.lib.packet import ethernet, ipv4, icmp
import pox.openflow.libopenflow_01 as of
from datetime import datetime

log = core.getLogger()

BLOCKED_IPS = ['10.0.0.4']

class TrafficMonitor(object):

    def __init__(self, connection):
        self.connection = connection
        self.mac_to_port = {}
        connection.addListeners(self)
        self._install_firewall_rules()
        log.info("Switch connected: %s", dpid_to_str(connection.dpid))

    def _install_firewall_rules(self):
        for ip in BLOCKED_IPS:
            msg = of.ofp_flow_mod()
            msg.priority = 100
            msg.match.dl_type = 0x0800
            msg.match.nw_src = ip
            self.connection.send(msg)
            log.info("Firewall: DROP traffic from %s", ip)

    def _handle_PacketIn(self, event):
        packet = event.parsed
        if not packet.parsed:
            return

        dpid = event.connection.dpid
        in_port = event.port

        self.mac_to_port.setdefault(dpid, {})
        self.mac_to_port[dpid][packet.src] = in_port

        if packet.dst in self.mac_to_port[dpid]:
            out_port = self.mac_to_port[dpid][packet.dst]
        else:
            out_port = of.OFPP_FLOOD

        ip_packet = packet.find('ipv4')
        if ip_packet:
            log.info("[%s] DPID=%s | %s -> %s | Port %s->%s",
                     datetime.now().strftime("%H:%M:%S"),
                     dpid_to_str(dpid),
                     ip_packet.srcip, ip_packet.dstip,
                     in_port, out_port)

        msg = of.ofp_packet_out()
        msg.in_port = in_port
        msg.data = event.ofp

        if out_port != of.OFPP_FLOOD:
            flow_mod = of.ofp_flow_mod()
            flow_mod.priority = 10
            flow_mod.match.dl_src = packet.src
            flow_mod.match.dl_dst = packet.dst
            flow_mod.match.in_port = in_port
            flow_mod.idle_timeout = 30
            flow_mod.actions.append(of.ofp_action_output(port=out_port))
            self.connection.send(flow_mod)

        msg.actions.append(of.ofp_action_output(port=out_port))
        event.connection.send(msg)

class TrafficMonitorLauncher(object):

    def __init__(self):
        core.openflow.addListeners(self)
        log.info("Traffic Monitor started. Blocked IPs: %s", BLOCKED_IPS)

    def _handle_ConnectionUp(self, event):
        TrafficMonitor(event.connection)

def launch():
    core.registerNew(TrafficMonitorLauncher)
