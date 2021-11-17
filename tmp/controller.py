from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.lib.packet import packet
from ryu.lib.packet import ipv4
from ryu.lib.packet import tcp

class MyController(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION] #バージョン:OpenFlow 1.3

    def __init__(self, *args, **kwargs):
        super(MyController, self).__init__(*args, **kwargs)
        user_role_dict = {'10.11.1.1': 1, '10.11.1.2': 2} # 1: doctor, 2: normal
        application_dict = {25:'health_care'}
        current_flows = {} #リアルタイムで流れているFlowのオブジェクトを格納 {dpid:[]}
        current_flows_role = {} #リアルタイムで流れているFlowのIPアドレスとroleを格納
        

    # install the table-miss flow entry.
    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        datapath = ev.msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        match = parser.OFPMatch()
        actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER, ofproto.OFPCML_NO_BUFFER)]
        self.add_flow(datapath, 0, match, actions)

    # add flow entry.
    def add_flow(self, datapath, priority, match, actions):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS,
                                             actions)] 
        mod = parser.OFPFlowMod(datapath=datapath, priority=priority,
                                match=match, instructions=inst)
        datapath.send_msg(mod)

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def _packet_in_handler(self, ev):
        msg = ev.msg
        datapath = msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        
        dpid = datapath.id
        self.current_flows.setdefault(dpid, {})
        # self.current_flows_role.setdefault(dpid, {})

        pkt = packet.Packet(msg.data)
        ipv4_pkt = pkt.get_protocol(ipv4.ipv4)
        tcp_pkt = pkt.get_protocol(tcp.tcp)

        ipv4_src = ipv4_pkt.src #INFO: 簡略化のため、送信元IPアドレスのみをロールの特定に利用する。
        role = self.user_role_dict.get(ipv4_src) # Make role inferences from IP address
        self.current_flows[dpid][ev.msg] = role # 流れているフローの情報を全て保持する。

        low_priority_flows = self.compare_priorities(dpid, role) # Compare priorities by role
        if low_priority_flows:
            for flow in low_priority_flows:       
                pkt = packet.Packet(flow) 
                ipv4_pkt = pkt.get_protocol(ipv4.ipv4)
                tcp_pkt = pkt.get_protocol(tcp.tcp)
                match = parser.OFPMatch(
                    ipv4_src= ipv4_pkt.src,
                    ipv4_dst= ipv4_pkt.dst,
                    tcp_dst= tcp_pkt.dst_port)
                self.drop_flow(datapath, match)

        self.send_port_stats_request(datapath)
        tcp_dst_port = tcp_pkt.dst_port
        application = self.application_dict.get(tcp_dst_port)
        app_request = ApplicationRequest(application)

        #TODO: ※(A)アクセス回線の状況を取得(port statistics request)
        #TODO: 使えないアクセス回線の除外(※(A)で取得したアクセス回線状況を利用する)
        #TODO: 残った候補に対してTOPSISアルゴリズムを適用して、アクセス回線を決定する。
        #TODO: flow entryの追加を行う。
        #TODO: low_priority_flowsをcurrent_flows_roleを使って優先度順に並び替える
        #TODO: low_priority_flowsの中で優先度の高いものから、繰り返し、最適なアクセス回線を決定しフローエントリに追加する。アクセス回線を追加するごとにDropにしいていたFlow entryを削除する。

    # port statistics reply
    @set_ev_cls(ofp_event.EventOFPPortStatsReply, MAIN_DISPATCHER)
    def port_stats_reply_handler(self, ev):
        ports = []
        for stat in ev.msg.body:
            ports.append('port_no=%d '
                        'rx_packets=%d tx_packets=%d '
                        'rx_bytes=%d tx_bytes=%d '
                        'rx_dropped=%d tx_dropped=%d '
                        'rx_errors=%d tx_errors=%d '
                        'rx_frame_err=%d rx_over_err=%d rx_crc_err=%d '
                        'collisions=%d duration_sec=%d duration_nsec=%d' %
                        (stat.port_no,
                        stat.rx_packets, stat.tx_packets,
                        stat.rx_bytes, stat.tx_bytes,
                        stat.rx_dropped, stat.tx_dropped,
                        stat.rx_errors, stat.tx_errors,
                        stat.rx_frame_err, stat.rx_over_err,
                        stat.rx_crc_err, stat.collisions,
                        stat.duration_sec, stat.duration_nsec))
        self.logger.debug('PortStats: %s', ports)
    
    # return value: [FlowObject1, FlowObject2,...]
    def compare_priorities(self, dpid, current_role):
        low_priority_flows = []
        for flow in self.current_flows[dpid]:
            if self.current_flows[dpid][flow] < current_role:
                low_priority_flows.append(flow)
        return low_priority_flows

    def drop_flow(self, datapath, match):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        mod = parser.OFPFlowMod(datapath=datapath, command=ofproto.OFPFC_DELETE, match=match)
        datapath.send_msg(mod)
        return

    def send_port_stats_request(self, datapath):
        """
        OFSに各ポートの統計情報をリクエストする関数
        Function to request statistics of each port to OFS
        """
        ofp = datapath.ofproto
        ofp_parser = datapath.ofproto_parser
        req = ofp_parser.OFPPortStatsRequest(datapath, 0, ofp.OFPP_ANY) #全ポートの統計情報を収集
        datapath.send_msg(req)

    def port_statistic_noticer(self):
        pass

class ApplicationRequest:
    name = None
    utilization_rate = None
    delay = None
    packet_loss = None
    jitter = None
    bandwidth = None
    cost = None
    security_score = None
    def __init__(self, name):
        self.name = name
        self.affect_application()
    
    def __affect_application(self):
        if self.name == 'health_care':
            self.delay = 20
            self.packet_loss = 30
            self.security_score = 3
        if self.name == 'voip':
            pass
