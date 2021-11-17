"""Custom topology
      host1 ---            ---router1---            ---host3
              |            |           |            | 
	      ---switch1---|--router2--|---switch2---
	      |    |       |           |     |      | 
      host2 ---    |       ---router3---     |      ---host4 
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
	host1 = net.addHost('h1', ip="10.0.1.10/24", mac="00:00:00:00:00:01")
	host2 = net.addHost('h2', ip="10.0.1.20/24", mac="00:00:00:00:00:02")
	host3 = net.addHost('h3', ip="10.0.2.10/24", mac="00:00:00:00:00:03")
	host4 = net.addHost('h4', ip="10.0.2.20/24", mac="00:00:00:00:00:04")

	switch1 = net.addSwitch('s1')
	switch2 = net.addSwitch('s2')
	switch3 = net.addSwitch('s3')
	switch4 = net.addSwitch('s4')
	switch5 = net.addSwitch('s5')

	c0 = net.addController('c0', controller=RemoteController, ip='127.0.0.1',port=6633, protocols="OpenFlow13")

	net.addLink(switch3, switch1)
	net.addLink(switch3, switch2)
	net.addLink(switch4, switch1)
	net.addLink(switch4, switch2)
	net.addLink(switch5, switch1)
	net.addLink(switch5, switch2)

	net.addLink(host1, switch1)
	net.addLink(host2, switch1)
	net.addLink(host3, switch2)
	net.addLink(host4, switch2)

	net.build()
	c0.start()
	switch1.start([c0])
	switch2.start([c0])
	host1.cmd("ip route add default via 10.0.1.1")
	host2.cmd("ip route add default via 10.0.1.1")
	host3.cmd("ip route add default via 10.0.2.1")
	host4.cmd("ip route add default via 10.0.2.1")

	CLI(net)
	net.stop()
	
if __name__=='__main__':
	setLogLevel('info')
	topology()
