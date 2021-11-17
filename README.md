# Switching Access Line
Optimal automatic switching of access lines using SDN
# Usage
```
$ sudo python3 ./my_topology.py
$ ryu-manager --verbose ./controller.py
```
# TODO
- [] forward what is received on eth1 to eth2 and eth2 to eth1.
s3 lo:  s3-eth1:s1-eth1 s3-eth2:s2-eth1 
s4 lo:  s4-eth1:s1-eth2 s4-eth2:s2-eth2
s5 lo:  s5-eth1:s1-eth3 s5-eth2:s2-eth3

