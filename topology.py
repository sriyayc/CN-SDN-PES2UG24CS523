"""
Mininet topology for the Traffic Monitoring project.
1 OVS switch, 4 hosts, 100 Mbps links, remote POX controller on 127.0.0.1:6633
"""

from mininet.net import Mininet
from mininet.node import RemoteController, OVSKernelSwitch
from mininet.cli import CLI
from mininet.link import TCLink
from mininet.log import setLogLevel, info


def build():
    net = Mininet(controller=RemoteController, switch=OVSKernelSwitch,
                  link=TCLink, autoSetMacs=True)
    info('*** Adding controller\n')
    c0 = net.addController('c0', controller=RemoteController,
                           ip='127.0.0.1', port=6633)
    info('*** Adding switch\n')
    s1 = net.addSwitch('s1', protocols='OpenFlow10')
    info('*** Adding hosts and 100 Mbps links\n')
    for i in range(1, 5):
        h = net.addHost('h%d' % i, ip='10.0.0.%d/24' % i)
        net.addLink(h, s1, bw=100)
    net.build()
    c0.start()
    s1.start([c0])
    CLI(net)
    net.stop()


if __name__ == '__main__':
    setLogLevel('info')
    build()
