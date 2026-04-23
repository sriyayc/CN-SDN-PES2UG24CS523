

from pox.core import core
from pox.lib.util import dpid_to_str
from pox.lib.recoco import Timer
import pox.openflow.libopenflow_01 as of
import csv
import os
import time

log = core.getLogger()

POLL_INTERVAL = 5
HEAVY_HITTER_BPS = 5_000_000
LOG_DIR = os.path.expanduser("~/sdn-traffic-monitor/logs")


class TrafficMonitor(object):
    def __init__(self):
        core.openflow.addListeners(self)
        self.mac_to_port = {}
        self.flow_byte_count = {}
        self.flow_last_seen = {}

        os.makedirs(LOG_DIR, exist_ok=True)
        self.flow_log = os.path.join(LOG_DIR, "flow_stats.csv")
        self.port_log = os.path.join(LOG_DIR, "port_stats.csv")
        self.alert_log = os.path.join(LOG_DIR, "heavy_hitters.csv")
        self._init_csv(self.flow_log,
                       ["ts", "dpid", "in_port", "eth_src", "eth_dst",
                        "packets", "bytes", "duration_s", "bps"])
        self._init_csv(self.port_log,
                       ["ts", "dpid", "port", "rx_pkts", "tx_pkts",
                        "rx_bytes", "tx_bytes", "rx_err", "tx_err"])
        self._init_csv(self.alert_log,
                       ["ts", "dpid", "eth_src", "eth_dst", "bps", "threshold"])

        Timer(POLL_INTERVAL, self._request_stats, recurring=True)
        log.info("TrafficMonitor started. Poll every %ds, HH threshold=%d bps",
                 POLL_INTERVAL, HEAVY_HITTER_BPS)

    @staticmethod
    def _init_csv(path, header):
        if not os.path.exists(path):
            with open(path, "w", newline="") as f:
                csv.writer(f).writerow(header)

    def _handle_ConnectionUp(self, event):
        log.info("Switch %s connected.", dpid_to_str(event.dpid))

    def _handle_PacketIn(self, event):
        packet = event.parsed
        if not packet.parsed:
            return
        dpid = event.dpid
        in_port = event.port
        self.mac_to_port.setdefault(dpid, {})
        self.mac_to_port[dpid][str(packet.src)] = in_port

        dst_port = self.mac_to_port[dpid].get(str(packet.dst))

        if dst_port is None:
            msg = of.ofp_packet_out()
            msg.data = event.ofp
            msg.actions.append(of.ofp_action_output(port=of.OFPP_FLOOD))
            msg.in_port = in_port
            event.connection.send(msg)
            return

        msg = of.ofp_flow_mod()
        msg.match = of.ofp_match.from_packet(packet, in_port)
        msg.match.dl_src = packet.src
        msg.match.dl_dst = packet.dst
        msg.idle_timeout = 30
        msg.hard_timeout = 120
        msg.priority = 1
        msg.actions.append(of.ofp_action_output(port=dst_port))
        msg.data = event.ofp
        event.connection.send(msg)

    def _request_stats(self):
        for conn in core.openflow.connections:
            conn.send(of.ofp_stats_request(body=of.ofp_flow_stats_request()))
            conn.send(of.ofp_stats_request(body=of.ofp_port_stats_request()))

    def _handle_FlowStatsReceived(self, event):
        dpid = event.connection.dpid
        now = time.time()
        with open(self.flow_log, "a", newline="") as f:
            w = csv.writer(f)
            for stat in event.stats:
                if stat.priority != 1:
                    continue
                in_port = stat.match.in_port
                eth_src = str(stat.match.dl_src) if stat.match.dl_src else ""
                eth_dst = str(stat.match.dl_dst) if stat.match.dl_dst else ""
                key = (dpid, in_port, eth_src, eth_dst)

                prev_bytes = self.flow_byte_count.get(key, 0)
                prev_time = self.flow_last_seen.get(key, now - POLL_INTERVAL)
                delta_b = max(stat.byte_count - prev_bytes, 0)
                delta_t = max(now - prev_time, 1e-6)
                bps = (delta_b * 8) / delta_t

                self.flow_byte_count[key] = stat.byte_count
                self.flow_last_seen[key] = now

                w.writerow(["%.2f" % now, dpid, in_port, eth_src, eth_dst,
                            stat.packet_count, stat.byte_count,
                            stat.duration_sec, "%.0f" % bps])

                if bps > HEAVY_HITTER_BPS:
                    log.warning("[HEAVY HITTER] dpid=%s %s -> %s  %.2f Mbps (> %.2f Mbps)",
                                dpid, eth_src, eth_dst,
                                bps / 1e6, HEAVY_HITTER_BPS / 1e6)
                    with open(self.alert_log, "a", newline="") as af:
                        csv.writer(af).writerow(
                            ["%.2f" % now, dpid, eth_src, eth_dst,
                             "%.0f" % bps, HEAVY_HITTER_BPS])

    def _handle_PortStatsReceived(self, event):
        dpid = event.connection.dpid
        now = time.time()
        with open(self.port_log, "a", newline="") as f:
            w = csv.writer(f)
            for stat in event.stats:
                w.writerow(["%.2f" % now, dpid, stat.port_no,
                            stat.rx_packets, stat.tx_packets,
                            stat.rx_bytes, stat.tx_bytes,
                            stat.rx_errors, stat.tx_errors])


def launch():
    core.registerNew(TrafficMonitor)
