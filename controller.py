from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.lib.packet import packet
from ryu.lib.packet import ethernet
from ryu.lib.packet import ipv4

class MyController(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION] #バージョン:OpenFlow 1.3

    def __init__(self, *args, **kwargs):
        super(ExampleSwitch13, self).__init__(*args, **kwargs)
        user_role_dict = {'10.11.1.1': 1, '10.11.1.2': 2} # 1: doctor, 2: normal
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
        self.current_flows.setdefault(dpid, [])# {"dpid":[flowObject, ...]}
        self.current_flows_role.setdefault(dpid, {})# {"dpid":[flowObject, ...]}

        pkt = packet.Packet(msg.data)
        ipv4_pkt = pkt.get_protocol(ipv4.ipv4)
        ipv4_src = ipv4_pkt.src #INFO: 簡略化のため、送信元IPアドレスのみをロールの特定に利用する。
        role = self.user_role_dict.get(ipv4_src)
        self.current_flows_role[dpid][ip] = role
        low_priority_flows = self.compare_priorities(dpid, role)
        #TODO: low_priority_flowsに入ってるFlowを全てDropするFlow entryの追加

        #TODO: アプリケーションの推論(ポートから推論するだけなのでとりあえずは対応表をメモリに持たせて比較する)

        #TODO: ※(A)アクセス回線の状況を取得(port statistics request)

        #TODO: 使えないアクセス回線の除外(※(A)で取得したアクセス回線状況を利用する)

        #TODO: 残った候補に対してTOPSISアルゴリズムを適用して、アクセス回線を決定する。

        #TODO: flow entryの追加を行う。

        #TODO: low_priority_flowsをcurrent_flows_roleを使って優先度順に並び替える

        #TODO: low_priority_flowsの中で優先度の高いものから、繰り返し、最適なアクセス回線を決定しフローエントリに追加する。アクセス回線を追加するごとにDropにしいていたFlow entryを削除する。
    
    # return value: {dpid:[FlowObject1, FlowObject2,...]}
    def compare_priorities(self, dpid, current_role):
        low_priority_flows = {}
        low_priority_flows.setdefault(dpid, [])
        for ip in self.current_flows_role[dpid]:
            if self.current_flows_role[dpid][ip] < current_role:
                # TODO: self.current_flowsから該当するflowを取得し、low_priority_flowsに加える
                pass
        return low_priority_flows