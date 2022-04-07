"""Custom topology
                      ---s3---       
      h1 ---|         |      |         |---h3 
	      ---s1---|      |---s2---
      h2 ---|         ---s4---         |---h4 
         10.0.1.1/24                     10.0.2.1/24
"""
from mininet.topo import Topo
from mininet.net import Mininet
from mininet.cli import CLI
from mininet.node import Controller,RemoteController,OVSKernelSwitch,UserSwitch
from mininet.log import setLogLevel
from mininet.link import Link,TCLink

def topology():
	net = Mininet()
	h1 = net.addHost('h1')
	h2 = net.addHost('h2')
	h3 = net.addHost('h3')
	h4 = net.addHost('h4')

	s1 = net.addSwitch('s1')
	s2 = net.addSwitch('s2')
	s3 = net.addSwitch('s3')
	s4 = net.addSwitch('s4')

	c0 = net.addController('c0', controller=RemoteController, ip='127.0.0.1',port=6633, protocols="OpenFlow13")

	net.addLink(h1, s1)
	net.addLink(h2, s1)
	net.addLink(h3, s2)
	net.addLink(h4, s2)
	net.addLink(s1, s3)
	net.addLink(s1, s4)
	net.addLink(s3, s2)
	net.addLink(s4, s2)

	net.build()
	c0.start()
	s1.start([c0])
	s2.start([])
	s3.start([])
	s4.start([])
        
	CLI(net)
	net.stop()
	
if __name__=='__main__':
	setLogLevel('info')
	topology()
