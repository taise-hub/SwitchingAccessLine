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
        self.non_inference_flows = {} #リアルタイムで流れているFlowのオブジェクトを格納 {dpid:[]}
        

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
        フローを追加する関数です。
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
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        dpid = datapath.id
        pkt = packet.Packet(msg.data)
        in_port = msg.match['in_port']
        out_port = ofproto.OFPP_FLOOD # 最もセキュアな回線につながっているポート
        actions = [parser.OFPActionOutput(out_port)]
        #self.add_flow(datapath, 1, match, actions)
        out = parser.OFPPacketOut(datapath=datapath,
                                  buffer_id=ofproto.OFP_NO_BUFFER,
                                  in_port=in_port,
                                  actions=actions,
                                  data=msg.data)
        datapath.send_msg(out)

    @set_ev_cls(ofp_event.EventOFPPortStatsReply, MAIN_DISPATCHER)
    def port_stats_reply_handler(self, ev):
        """
        port statistic replyを受け取るハンドラーです。
        このハンドラーは、統計情報を更新し未遂論のフローがキューに残っていれば推論を行い、フローエントリーを更新します。
        """
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

    def drop_flow(self, datapath, match):
        """
        フローエントリをドロップする関数です。
        利用するかは未定です。
        """
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        mod = parser.OFPFlowMod(datapath=datapath, command=ofproto.OFPFC_DELETE, match=match)
        datapath.send_msg(mod)
        return

    def send_port_stats_request(self, datapath):
        """
        OFSに各ポートの統計情報をリクエストする関数です。
        一秒毎にポーリングする予定です。
        """
        ofp = datapath.ofproto
        ofp_parser = datapath.ofproto_parser
        req = ofp_parser.OFPPortStatsRequest(datapath, 0, ofp.OFPP_ANY) #全ポートの統計情報を収集
        datapath.send_msg(req)



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
