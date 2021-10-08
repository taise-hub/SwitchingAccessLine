"""Custom topology
      host1 ---             ---host3
              |             |
	      -----switch----
	      |             |
      host2 ---             ---host4 
"""

from mininet.topo import Topo

class MyTopo(Topo):
	#"My Topology example."
	def build(self):
		host1 = self.addHost('h1')
		host2 = self.addHost('h2')
		host3 = self.addHost('h3')
		host4 = self.addHost('h4')
		switch = self.addSwitch('s1')
		self.addLink(host1, switch)
		self.addLink(host2, switch)
		self.addLink(switch, host3)
		self.addLink(switch, host4)
		
topos = {'mytopo': (lambda: MyTopo())}


