"""Custom topology
      h1 ---            ---router1---            ---h3
              |            |           |            | 
	      ---s1---|--router2--|---s2---
	      |    |       |           |     |      | 
      h2 ---    |       ---router3---     |      ---h4 
         10.0.1.1/24                         10.0.2.1/24
"""
from mininet.topo import Topo
from mininet.net import Mininet
from mininet.cli import CLI
from mininet.node import Controller,RemoteController,OVSKernelSwitch,UserSwitch
from mininet.log import setLogLevel
from mininet.link import Link,TCLink

#"My Topology example."
def topology():
	net = Mininet()
	h1 = net.addHost('h1', ip="10.0.1.10/24", mac="00:00:00:00:00:01")
	h2 = net.addHost('h2', ip="10.0.1.20/24", mac="00:00:00:00:00:02")
	h3 = net.addHost('h3', ip="10.0.2.10/24", mac="00:00:00:00:00:03")
	h4 = net.addHost('h4', ip="10.0.2.20/24", mac="00:00:00:00:00:04")

	s1 = net.addSwitch('s1')
	s2 = net.addSwitch('s2')
       
	r1 = net.addHost('r1')
	r2 = net.addHost('r2')
	r3 = net.addHost('r3')

	c0 = net.addController('c0', controller=RemoteController, ip='127.0.0.1',port=6633, protocols="OpenFlow13")

	net.addLink(h1, s1)
	net.addLink(h2, s1)
	net.addLink(h3, s2)
	net.addLink(h4, s2)
	net.addLink(s1, r1)
	net.addLink(s1, r2)
	net.addLink(s1, r3)
	net.addLink(s2, r1)
	net.addLink(s2, r2)
	net.addLink(s2, r3)

	net.build()
	c0.start()
	s1.start([c0])
	s2.start([c0])
        
	h1.cmd("ip route add default via 10.0.1.1")
	h2.cmd("ip route add default via 10.0.1.1")
	h3.cmd("ip route add default via 10.0.2.1")
	h4.cmd("ip route add default via 10.0.2.1")

	r1.cmd('ifconfig r1-eth0 0')
	r1.cmd('ifconfig r1-eth1 0')
	r1.cmd('ifconfig r1-eth0 hw ether 00:00:00:00:01:01')
	r1.cmd('ifconfig r1-eth1 hw ether 00:00:00:00:01:02')
	r1.cmd('ip addr add 10.0.1.1/24 brd + dev r1-eth0')
	r1.cmd('ip addr add 10.0.2.1/24 brd + dev r1-eth1')
	r1.cmd('echo 1 > /proc/sys/net/ipv4/ip_forward')
	r2.cmd('ifconfig r2-eth0 0')
	r2.cmd('ifconfig r2-eth1 0')
	r2.cmd('ifconfig r2-eth0 hw ether 00:00:00:00:02:01')
	r2.cmd('ifconfig r2-eth1 hw ether 00:00:00:00:02:02')
	r2.cmd('ip addr add 10.0.1.1/24 brd + dev r2-eth0')
	r2.cmd('ip addr add 10.0.2.1/24 brd + dev r2-eth1')
	r2.cmd('echo 1 > /proc/sys/net/ipv4/ip_forward')
	r3.cmd('ifconfig r3-eth0 0')
	r3.cmd('ifconfig r3-eth1 0')
	r3.cmd('ifconfig r3-eth0 hw ether 00:00:00:00:03:01')
	r3.cmd('ifconfig r3-eth1 hw ether 00:00:00:00:03:02')
	r3.cmd('ip addr add 10.0.1.1/24 brd + dev r3-eth0')
	r3.cmd('ip addr add 10.0.2.1/24 brd + dev r3-eth1')
	r3.cmd('echo 1 > /proc/sys/net/ipv4/ip_forward')

	CLI(net)
	net.stop()
	
if __name__=='__main__':
	setLogLevel('info')
	topology()
