iperf -c 10.0.0.3  -p 5001  -b 1M -t 25 -i 2
sleep 5
iperf -c 10.0.0.3 -p 5001  -b 1M -t 40 -i 2


