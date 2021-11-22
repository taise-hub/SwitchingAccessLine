from operator import attrgetter

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


class MyController(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION] #バージョン:OpenFlow 1.3

    def __init__(self, *args, **kwargs):
        super(MyController, self).__init__(*args, **kwargs)
        self.mac_to_port = {}
        self.non_inference_flows = {} #リアルタイムで流れているFlowのオブジェクトを格納 {dpid:[]}
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
        self.non_inference_flows.setdefault(dpid, [])
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
        self.non_inference_flows[dpid].append(pkt)
        pkt_tcp = pkt.get_protocol(tcp.tcp)
        if pkt_tcp:
            self._handle_tcp(in_port, pkt_eth, pkt_ip, pkt_tcp, msg)
            return

    def _handle_arp(self, in_port, pkt_ethernet, pkt_arp, message):
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

        src = pkt_ethernet.src
        dst = pkt_ethernet.dst
        self.logger.debug("src: %s, dst: %s\n", src, dst)
        self.logger.debug("ARP dst ip: %s\n", pkt_arp.dst_ip)
        self.mac_to_port[dpid][src] = in_port
        if dst in self.mac_to_port[dpid]:
            out_port = self.mac_to_port[dpid][dst]
        else:
            out_port = ofproto.OFPP_FLOOD
        # =================================================================================================================
        # ここでアクセス回線の制御を行う。
        # 1. IPアドレスからロールを特定する。
        # 2. 推論エンジンを用いて適切な回線を絞る。 → いらなくね？
        # 3. TOPSISアルゴリズムを用いて、回線を選択
        # 4. 優先度の低い
        if pkt_arp.opcode == arp.ARP_REQUEST and (pkt_arp.dst_ip == "10.0.1.1" or pkt_arp.dst_ip == "10.0.2.1"):
            out_port = 3 # access line 1
            out_port = 4 # access line 2
            out_port = 5 # access line 3
            actions = [parser.OFPActionOutput(out_port)]
            out = parser.OFPPacketOut(datapath=datapath,
                                buffer_id=ofproto.OFP_NO_BUFFER,
                                in_port=in_port, actions=actions,
                                data=message.data)
            datapath.send_msg(out)
            return 
        # =================================================================================================================
        self.logger.debug("table: %s\n", self.mac_to_port)
        
        actions = [parser.OFPActionOutput(out_port)]
        if out_port != ofproto.OFPP_FLOOD:
            match = parser.OFPMatch(in_port=in_port, arp_tha=dst)
            self.add_flow(datapath, 1, match, actions)
        out = parser.OFPPacketOut(datapath=datapath,
                                buffer_id=ofproto.OFP_NO_BUFFER,
                                in_port=in_port, actions=actions,
                                data=message.data)
        datapath.send_msg(out)
        
    def _handle_icmp(self, in_port, pkt_ethernet, pkt_icmp, message):
        if pkt_icmp.type not in [icmp.ICMP_ECHO_REQUEST, icmp.ICMP_ECHO_REPLY]:
            return
        self.logger.debug("this is ICMP packet\n")
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
        self.logger.info("this is TCP packet\n")
        datapath = message.datapath
        dpid = datapath.id
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        dst = pkt_ethernet.dst 
        ipv4_src = pkt_ip.src
        ipv4_dst = pkt_ip.dst
        tcp_dst = pkt_tcp.dst_port
        match = parser.OFPMatch(eth_type=pkt_ethernet.ethertype, ip_proto=pkt_ip.proto, ipv4_src=ipv4_src, ipv4_dst=ipv4_dst, tcp_dst=tcp_dst)
        self.logger.info("inport: %s     src_ip: %s    dst_ip: %s    tcp_dst: %s",in_port ,ipv4_src, ipv4_dst, tcp_dst)
        out_port = self.mac_to_port[dpid][dst]
        actions = [parser.OFPActionOutput(out_port)]
        self.add_flow(datapath, 1, match, actions)
        out = parser.OFPPacketOut(datapath=datapath,
                        buffer_id=ofproto.OFP_NO_BUFFER,
                        in_port=in_port, actions=actions,
                        data=message.data)
        datapath.send_msg(out)
        return
    
    @set_ev_cls(ofp_event.EventOFPStateChange, [MAIN_DISPATCHER, DEAD_DISPATCHER])
    def _state_change_handler(self, ev):
        """
        スイッチの接続および切断を検出します。
        """
        datapath = ev.datapath
        if ev.state == MAIN_DISPATCHER:
            if datapath.id not in self.datapaths:
                self.logger.debug('register datapath: %016x', datapath.id)
                self.datapaths[datapath.id] = datapath
        elif ev.state == DEAD_DISPATCHER:
            if datapath.id in self.datapaths:
                self.logger.debug('unregister datapath: %016x', datapath.id)
                del self.datapaths[datapath.id]

    def _monitor(self):
        """
        10秒ごとにrequest_stats()を実行します。
        """
        while True:
            for dp in self.datapaths.values():
                self._request_stats(dp)
            hub.sleep(10)
    
    def _request_stats(self, datapath):
        """
        OFSに各ポートの統計情報をリクエストする関数です。
        """
        self.logger.debug('send stats request: %016x', datapath.id)
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
        self.logger.info('datapath ポート '
                        '受信パケット数 受信バイト数 受信エラー数 '
                        '送信パケット数 送信バイト数 送信エラー数')
        self.logger.info('---------------- -------- '
                        '-------- -------- -------- '
                        '-------- -------- --------')
        for stat in sorted(body, key=attrgetter('port_no')):
            self.logger.info('%016x %8x %8d %8d %8d %8d %8d %8d',
                    ev.msg.datapath.id, stat.port_no,
                    stat.rx_packets, stat.rx_bytes, stat.rx_errors,
                    stat.tx_packets, stat.tx_bytes, stat.tx_errors)
    def _access_line_calculator(self):
        return
