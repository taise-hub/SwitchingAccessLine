"""Custom topology
                             ---router1---
                             |           |
	      host1 ---switch1---|--router2--|---switch2--- host2 
	                         |     |     | 
                             ---router3---
 10.0.1.1/24                                          10.0.2.1/24
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
	host1 = net.addHost('h1', ip="10.0.1.10/24", mac="00:00:00:00:00:01")
	host2 = net.addHost('h3', ip="10.0.2.10/24", mac="00:00:00:00:00:03")
	router1 = net.addHost('r1')
	router2 = net.addHost('r2')
	router3 = net.addHost('r3')
	switch1 = net.addSwitch('s1')
	switch2 = net.addSwitch('s2')
	c0 = net.addController('c0', controller=RemoteController, ip='127.0.0.1',port=6633, protocols="OpenFlow13")
	net.addLink(router1, switch1)
	net.addLink(router1, switch2)
	net.addLink(router2, switch1)
	net.addLink(router2, switch2)
	net.addLink(router3, switch1)
	net.addLink(router3, switch2)
	net.addLink(host1, switch1)
	net.addLink(host2, switch2)
	net.build()
	c0.start()
	switch1.start([c0])
	switch2.start([c0])
	router1.cmd("ifconfig r1-eth0 0")
	router1.cmd("ifconfig r1-eth1 0")
	router1.cmd("ifconfig r1-eth0 hw ether 00:00:00:00:01:01")
	router1.cmd("ifconfig r1-eth1 hw ether 00:00:00:00:01:02")
	router1.cmd("ip addr add 10.0.1.1/24 brd + dev r1-eth0")
	router1.cmd("ip addr add 10.0.2.1/24 brd + dev r1-eth1")
	router1.cmd("echo 1 > /proc/sys/net/ipv4/ip_forward")
	router2.cmd("ifconfig r2-eth0 0")
	router2.cmd("ifconfig r2-eth1 0")
	router2.cmd("ifconfig r2-eth0 hw ether 00:00:00:00:02:01")
	router2.cmd("ifconfig r2-eth1 hw ether 00:00:00:00:02:02")
	router2.cmd("ip addr add 10.0.1.1/24 brd + dev r2-eth0")
	router2.cmd("ip addr add 10.0.2.1/24 brd + dev r2-eth1")
	router2.cmd("echo 1 > /proc/sys/net/ipv4/ip_forward")
	router3.cmd("ifconfig r3-eth0 0")
	router3.cmd("ifconfig r3-eth1 0")
	router3.cmd("ifconfig r3-eth0 hw ether 00:00:00:00:03:01")
	router3.cmd("ifconfig r3-eth1 hw ether 00:00:00:00:03:02")
	router3.cmd("ip addr add 10.0.1.1/24 brd + dev r3-eth0")
	router3.cmd("ip addr add 10.0.2.1/24 brd + dev r3-eth1")
	router3.cmd("echo 1 > /proc/sys/net/ipv4/ip_forward")
	host1.cmd("ip route add default via 10.0.1.1")
	host2.cmd("ip route add default via 10.0.2.1")
	CLI(net)
	net.stop()
	
if __name__=='__main__':
	setLogLevel('info')
	topology()
