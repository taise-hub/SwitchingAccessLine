#実験概要 https://hackmd.io/XoS8Y9jCQzKHe9KFebt55A?view
# accessline 1: port 3
# accessline 2: port 4
from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER, DEAD_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.lib import hub
from ryu.lib.packet import packet
from ryu.lib.packet import ethernet
from ryu.lib.packet import arp
from ryu.lib.packet import ipv4
from ryu.lib.packet import icmp
from ryu.lib.packet import tcp
from ryu.lib.packet import udp

from operator import attrgetter
import time
from threading import Timer  

gmatch = 0

class FlowStatusInfo():
    port_no = None # 物理ポート
    datapath = None 
    rx_packets = None # 受信パケット数
    rx_byets = None # 受信バイト数
    tx_packets = None # 送信パケット数
    tx_bytes = None # 送信バイト数

class AccessLine:
    def __init__(self, delay:float, speed:float, loss:int, jitter:float):
        self.delay  = delay
        self.speed  = speed
        self.loss   = loss
        self.jitter = jitter

class AccessLineAssessment:
    def __init__(self, max_delay:float, min_speed:float, max_loss:int, max_jitter:int):
        self.max_delay  = max_delay
        self.min_speed  = min_speed
        self.max_loss   = max_loss
        self.max_jitter = max_jitter


class Application:
    def __init__(self, name:str, good:AccessLineAssessment, passing:AccessLineAssessment): 
        self.name    = name
        self.good    = good
        self.passing = passing

    def assess(self, line:AccessLine):
        sum = 0
        sum = sum + self._assess_delay(line.delay)
        sum = sum + self._assess_speed(line.speed)
        sum = sum + self._assess_loss(line.loss)
        sum = sum + self._assess_jitter(line.jitter)
        if sum >5:
            return 2 # high
        elif sum >3:
            return 1 # middle
        else:
            return 0 # low

    def _assess_delay(self, delay:float):
        if self.good.max_delay >= delay:
            return 2
        elif self.passing.max_delay >= delay:
            return 1
        else:
            return 0
    def _assess_speed(self, speed:float):
        if self.good.min_speed <= speed:
            return 2
        elif self.passing.min_speed <= speed:
            return 1
        else:
            return 0
    def _assess_loss(self, loss:float):
        if self.good.max_loss >= loss:
            return 2
        elif self.passing.max_loss >= loss:
            return 1
        else:
            return 0
    def _assess_jitter(self, jitter:float):
        if self.good.max_jitter >= jitter:
            return 2
        elif self.passing.max_jitter >= jitter:
            return 1
        else:
            return 0

#======================================================
web_meet_good    = AccessLineAssessment(150, 3.0,  2, 40) # good 
web_meet_passing = AccessLineAssessment(300, 2.5,  5, 80) # pass
app_1 = Application("web_meet", web_meet_good, web_meet_passing)

chat_good    = AccessLineAssessment(200, 1.0, 10,  500) # good
chat_passing = AccessLineAssessment(200, 0.5, 15, 2000) # pass
app_2 = Application("chat", chat_good, chat_passing)
#=====================================================
class Controller(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION] #バージョン:OpenFlow 1.3

    def __init__(self, *args, **kwargs):
        super(Controller, self).__init__(*args, **kwargs)
        self.mac_to_port = {}
        self.datapaths = {}
        self.monitor_thread = hub.spawn(self._monitor)

    # install the table-miss flow entry.
    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        """
        テーブルミスエントリーを追加します。
        """
        datapath = ev.msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        match = parser.OFPMatch()
        actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER, ofproto.OFPCML_NO_BUFFER)]
        self.add_flow(datapath, 0, match, actions)

    # add flow entry.
    def add_flow(self, datapath, priority, match, actions):
        """
        フローエントリーを追加する関数です。
        """
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS,
                                             actions)] 
        mod = parser.OFPFlowMod(datapath=datapath, priority=priority,
                                match=match, instructions=inst)
        datapath.send_msg(mod)

    def remove_flows(self, datapath, table_id, priority, match):
        """
        Removing all flow entries.
        """
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        inst = []
        mod = parser.OFPFlowMod(datapath=datapath,command=ofproto.OFPFC_DELETE, priority=priority,
                                out_port=ofproto.OFPP_ANY, out_group=ofproto.OFPG_ANY, match=match)
        datapath.send_msg(mod)

    # packet in handler
    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def _packet_in_handler(self, ev):
        """
        パケットインハンドラーでは、最もセキュアな回線を選択するフローエントリを追加します。
        後期推論のためにキュー上にフローを追加します。
        """
        msg = ev.msg
        datapath = msg.datapath
        dpid = datapath.id
        self.mac_to_port.setdefault(dpid, {})
        pkt = packet.Packet(msg.data)
        pkt_eth = pkt.get_protocol(ethernet.ethernet)
        in_port = msg.match['in_port']

        # arp handling
        pkt_arp = pkt.get_protocol(arp.arp)
        if pkt_arp:
            self._handle_arp(in_port, pkt_eth, pkt_arp, msg)
            return
        
        # icmp handling
        pkt_icmp = pkt.get_protocol(icmp.icmp)
        if pkt_icmp:
            self._handle_icmp(in_port, pkt_eth, pkt_icmp, msg)
            return
        
        pkt_ip = pkt.get_protocol(ipv4.ipv4)
        if pkt_ip is None:
            # self.logger.debug("ipv6 is not yet supported.")
            return
        
        # tcp handling
        pkt_tcp = pkt.get_protocol(tcp.tcp)
        if pkt_tcp:
            self._handle_tcp(in_port, pkt_eth, pkt_ip, pkt_tcp, msg)
            return

        # udp handling
        pkt_udp = pkt.get_protocol(udp.udp)
        if pkt_udp:
            self._handle_udp(in_port, pkt_eth, pkt_ip, pkt_udp, msg)
            return

    def _handle_arp(self, in_port, pkt_ethernet, pkt_arp, message):
        """
        未知のARPフローを制御します。ARPリクエストとARPリプライに対応しています。
        L2スイッチのように振る舞います。
        """
        if pkt_arp.opcode not in [arp.ARP_REQUEST, arp.ARP_REPLY]:
            return
        if pkt_arp.opcode == arp.ARP_REQUEST:
            self.logger.debug("ARP REQUEST")
        if pkt_arp.opcode == arp.ARP_REPLY:
            self.logger.debug("ARP REPRLY")
        datapath = message.datapath
        dpid = datapath.id
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        if in_port == 1 or in_port ==2:
            out_port = 3
        elif in_port ==3 and (pkt_arp.dst_ip=="10.0.0.3" or pkt_arp.dst_ip=="10.0.0.1"):
            out_port = 1 
        elif in_port ==3 and (pkt_arp.dst_ip=="10.0.0.4" or pkt_arp.dst_ip=="10.0.0.2"): 
            out_port = 2
        elif in_port ==4 and (pkt_arp.dst_ip=="10.0.0.3" or pkt_arp.dst_ip=="10.0.0.1"):
            out_port = 1 
        elif in_port ==4 and (pkt_arp.dst_ip=="10.0.0.4" or pkt_arp.dst_ip=="10.0.0.2"): 
            out_port = 2
        print(out_port)
        actions = [parser.OFPActionOutput(out_port)]
        
        out = parser.OFPPacketOut(datapath=datapath,
                                buffer_id=ofproto.OFP_NO_BUFFER,
                                in_port=in_port, actions=actions,
                                data=message.data)
        datapath.send_msg(out)
        
    def _handle_icmp(self, in_port, pkt_ethernet, pkt_icmp, message):
        """
        未知のicmpパケットを制御します。
        対応タイプ：ICMP ECHO REQUEST, ICMP ECHO REPLY
        """
        if pkt_icmp.type not in [icmp.ICMP_ECHO_REQUEST, icmp.ICMP_ECHO_REPLY]:
            return
        datapath = message.datapath
        dpid = datapath.id
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        dst = pkt_ethernet.dst
        out_port = self.mac_to_port[dpid][dst]
        actions = [parser.OFPActionOutput(out_port)]
        out = parser.OFPPacketOut(datapath=datapath,
                        buffer_id=ofproto.OFP_NO_BUFFER,
                        in_port=in_port, actions=actions,
                        data=message.data)
        datapath.send_msg(out)
        return

    def _handle_tcp(self, in_port, pkt_ethernet, pkt_ip, pkt_tcp, message):
        datapath = message.datapath
        dpid = datapath.id
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        
        dst = pkt_ethernet.dst 
        ipv4_src = pkt_ip.src
        ipv4_dst = pkt_ip.dst
        tcp_dst = pkt_tcp.dst_port
        match = parser.OFPMatch(eth_type=pkt_ethernet.ethertype, ip_proto=pkt_ip.proto, ipv4_src=ipv4_src, ipv4_dst=ipv4_dst, tcp_dst=tcp_dst)
        if in_port == 1:
            out_port = 4 # self._infer_app_request(ipv4_dst, tcp_dst)
        elif in_port ==3 or in_port == 4:
            out_port = 1
        if ipv4_dst == "10.0.0.3":
            t1 = Timer(20.0, self._change_thread, [datapath, parser, match, 3, 10])
            t1.start()
            t2 = Timer(30.0, self._change_thread, [datapath, parser, match, 4, 20])
            t2.start()
            t3 = Timer(50.0, self._change_thread, [datapath, parser, match, 3, 30])
            t3.start()
            t4 = Timer(60.0, self._change_thread, [datapath, parser, match, 4, 40])
            t4.start()
        actions = [parser.OFPActionOutput(out_port)]
        self.add_flow(datapath, 1, match, actions)
        out = parser.OFPPacketOut(datapath=datapath,
                        buffer_id=ofproto.OFP_NO_BUFFER,
                        in_port=in_port, actions=actions,
                        data=message.data)
        datapath.send_msg(out)
        return

    def _change_thread(self, datapath, parser, match, out_port, priority):
        actions = [parser.OFPActionOutput(out_port)]
        self.add_flow(datapath, priority, match, actions)
        return

    def _handle_udp(self, in_port, pkt_ethernet, pkt_ip, pkt_udp, message):
        datapath = message.datapath
        dpid = datapath.id
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        dst = pkt_ethernet.dst 
        ipv4_src = pkt_ip.src
        ipv4_dst = pkt_ip.dst
        udp_dst = pkt_udp.dst_port
        match = parser.OFPMatch(eth_type=pkt_ethernet.ethertype, ip_proto=pkt_ip.proto, ipv4_src=ipv4_src, ipv4_dst=ipv4_dst, udp_dst=udp_dst)
        if in_port == 1: #  from host(h1 or h3)
            out_port = self._infer_app_request(ipv4_dst, udp_dst)
        elif in_port == 3 or in_port == 4: #from s3 or s4
            out_port = 1 # TODO: change to h3(1) or h4(2)
        actions = [parser.OFPActionOutput(out_port)]
        self.add_flow(datapath, 1, match, actions)
        out = parser.OFPPacketOut(datapath=datapath,
                        buffer_id=ofproto.OFP_NO_BUFFER,
                        in_port=in_port, actions=actions,
                        data=message.data)
        datapath.send_msg(out)
        if ipv4_dst == "10.0.0.3" and out_port == 4:
            time.sleep(20)
            out_port = 3
            actions = [parser.OFPActionOutput(out_port)]
            self.add_flow(datapath, 2, match, actions)
            time.sleep(10)
            self.remove_flows(datapath, 0, 100, match)
        if ipv4_dst == "10.0.0.4" and out_port == 4:
            time.sleep(20)
            out_port = 3
            actions = [parser.OFPActionOutput(out_port)]
            self.add_flow(datapath, 2, match, actions)
            time.sleep(10)
            self.remove_flows(datapath, 0, 100, match)
        return
    
    @set_ev_cls(ofp_event.EventOFPStateChange, [MAIN_DISPATCHER, DEAD_DISPATCHER])
    def _state_change_handler(self, ev):
        """
        スイッチの接続および切断を検出します。
        """
        datapath = ev.datapath
        if ev.state == MAIN_DISPATCHER:
            if datapath.id not in self.datapaths:
                #self.logger.debug('register datapath: %016x', datapath.id)
                self.datapaths[datapath.id] = datapath
        elif ev.state == DEAD_DISPATCHER:
            if datapath.id in self.datapaths:
                #self.logger.debug('unregister datapath: %016x', datapath.id)
                del self.datapaths[datapath.id]

    def _monitor(self):
        """
        10秒ごとにrequest_stats()を実行します。
        """
        while True:
            for dp in self.datapaths.values():
                self._request_stats(dp)
            hub.sleep(1)
    
    def _request_stats(self, datapath):
        """
        OFSに各ポートの統計情報をリクエストする関数です。
        """
        #self.logger.debug('send stats request: %016x', datapath.id)
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        
        req = parser.OFPPortStatsRequest(datapath, 0, ofproto.OFPP_ANY)
        datapath.send_msg(req)

    @set_ev_cls(ofp_event.EventOFPPortStatsReply, MAIN_DISPATCHER)
    def _port_stats_reply_handler(self, ev):
        """
        port statistic replyを受け取るハンドラーです。
        このハンドラーは、統計情報を更新し未遂論のフローがキューに残っていれば推論を行い、フローエントリーを更新します。
        """
        body = ev.msg.body
       # self.logger.info('datapath         ポート   '
       #                 '受信パケット数 受信バイト数 受信エラー数'
       #                 '送信パケット数 送信バイト数 送信エラー数')
       # self.logger.info('---------------- -------- '
       #                 '-------------- ------------ ------------'
       #                 '-------------- ------------ ------------')
       # for stat in sorted(body, key=attrgetter('port_no'))[2:]:
       #     self.logger.info('%016x %8x %8d %8d %8d %8d %8d %8d',
       #             ev.msg.datapath.id, stat.port_no,
       #             stat.rx_packets, stat.rx_bytes, stat.rx_errors,
       #             stat.tx_packets, stat.tx_bytes, stat.tx_errors)
   
    # TODO: implementation
    def _infer_app_request(self, ipv4_dst, udp_dst):
        """
        アプリケーションの推論を行い、そのアプリケーションの要求を提供します。
        仮実装として、宛先IPアドレスが10.0.2.10かつ、宛先ポートが5001(UDP)である、場合Trueを返します。
        """
        line_1 = AccessLine(120, 2.5, 3, 70)
        line_2 = AccessLine(100, 4.0, 1, 70)
        
        if ipv4_dst == "10.0.0.3" and udp_dst == 5001:
            app = app_1 # web_meet
            assess_line1 = app.assess(line_1)
            assess_line2 = app.assess(line_2)
            print("line1: ", assess_line1)
            print("line2: ", assess_line2)
            # accessline 1: port 3
            # accessline 2: port 4
            # user youkyuutosite kaitekinakaisennworiyousuru.
            if assess_line2 > assess_line1:
                return 4
            else:
                return 3
        if ipv4_dst == "10.0.0.4" and udp_dst == 5002:
            app = app_2 # chat
            assess_line1 = app.assess(line_1)
            assess_line2 = app.assess(line_2)
            print("line1: ", assess_line1)
            print("line2: ", assess_line2)
            # accessline 1: port 3
            # accessline 2: port 4
            # user youkyuutosite kaitekinakaisennworiyousuru.
            if assess_line2 >= assess_line1:
                return 3
            else:
                return 4

        return 4 # not implementted

    def _is_meet_the_requirements(self, request):
        """
        デフォルトで利用している回線(回線1)がアプリケーションの要求を満たしているか確認します。
        仮実装として、引数のrequest(bool)をそのまま返します。
        """
        return request
