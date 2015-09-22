# Copyright (C) 2011 Nippon Telegraph and Telephone Corporation.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
# implied.
# See the License for the specific language governing permissions and
# limitations under the License.

from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER, HANDSHAKE_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.lib.packet import packet
from ryu.lib.packet import ethernet
from ryu.lib.packet import ipv4
from ryu import utils
from ryu.lib import hub
import threading ,time
import urllib, json

class testss(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super(testss, self).__init__(*args, **kwargs)
        self.mac_to_port = {}
#        self.monitor_thread = hub.spawn(self._monitor)#  


    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        msg = ev.msg
        datapath = ev.msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        # install table-miss flow entry, insult CONTROLLER

        match = parser.OFPMatch()
        actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER,
                                          ofproto.OFPCML_NO_BUFFER)]



        dpid = datapath.id
        print "dpid:",dpid

        if dpid == 1:

            group_id   = 1
            group_type = ofproto.OFPGT_SELECT
            weight_1   = 50
            weight_2   = 50
            weight_3   = 33
            watch_port = ofproto_v1_3.OFPP_ANY
            watch_group= ofproto_v1_3.OFPQ_ALL
            actions_1  = [parser.OFPActionOutput(2)]
            actions_2  = [parser.OFPActionOutput(3)]
            actions_3  = [parser.OFPActionOutput(4)]##
            buckets    = [parser.OFPBucket(weight_1, watch_port, watch_group, actions_1),
                          parser.OFPBucket(weight_2, watch_port, watch_group, actions_2)]
                          #parser.OFPBucket(weight_3, watch_port, watch_group, actions_3)]
            self.send_group_mod(datapath, group_type, group_id, buckets)

            match_flood    = parser.OFPMatch(eth_dst="ff:ff:ff:ff:ff:ff")
            out_port       = ofproto.OFPP_FLOOD
            actions_flood  = [parser.OFPActionOutput(out_port)]
            self.add_flow(datapath, 1, match_flood, actions_flood)
 
            # dst = h1
            match_1 = parser.OFPMatch(eth_dst="00:00:00:00:00:01")
            actions_dp1 = [parser.OFPActionOutput(1)]
            self.add_flow(datapath, 1, match_1, actions_dp1)

            # dst = h2
            match_1 = parser.OFPMatch(eth_dst="00:00:00:00:00:02")
            actions_dp1 = [parser.OFPActionGroup(group_id)] 
            self.add_flow(datapath, 1, match_1, actions_dp1)

            # dst = h3
            match_1 = parser.OFPMatch(eth_dst="00:00:00:00:00:03")
            actions_dp1 = [parser.OFPActionGroup(group_id)]
            self.add_flow(datapath, 1, match_1, actions_dp1)


            return

        if dpid == 4:

            group_id   = 4
            group_type = ofproto.OFPGT_SELECT
            weight_1   = 50
            weight_2   = 50
            weight_3   = 33
            watch_port = ofproto_v1_3.OFPP_ANY
            watch_group= ofproto_v1_3.OFPQ_ALL
            actions_1  = [parser.OFPActionOutput(1)]
            actions_2  = [parser.OFPActionOutput(4)]
            actions_3  = [parser.OFPActionOutput(5)]##
            buckets    = [parser.OFPBucket(weight_1, watch_port, watch_group, actions_1),
                          parser.OFPBucket(weight_2, watch_port, watch_group, actions_2)]
                          #parser.OFPBucket(weight_3, watch_port, watch_group, actions_3)]
            self.send_group_mod(datapath, group_type, group_id, buckets)

            match_flood    = parser.OFPMatch(eth_dst="ff:ff:ff:ff:ff:ff")
            out_port       = ofproto.OFPP_FLOOD
            actions_flood  = [parser.OFPActionOutput(out_port)]
            self.add_flow(datapath, 1, match_flood, actions_flood)

            # dst = h1
            match_4 = parser.OFPMatch(eth_dst="00:00:00:00:00:01")
            actions_dp4 = [parser.OFPActionGroup(group_id)]#
            self.add_flow(datapath, 1, match_4, actions_dp4)

            # dst = h2
            match_4 = parser.OFPMatch(eth_dst="00:00:00:00:00:02")
            actions_dp4 = [parser.OFPActionOutput(2)]
            self.add_flow(datapath, 1, match_4, actions_dp4)

            # dst = h3 
            match_4 = parser.OFPMatch(eth_dst="00:00:00:00:00:03")
            actions_dp4 = [parser.OFPActionOutput(3)]
            self.add_flow(datapath, 1, match_4, actions_dp4)


            return
        if dpid == 2:

            # dst = h2
            match_2 = parser.OFPMatch(eth_dst="00:00:00:00:00:02")   
            actions_dp2 = [parser.OFPActionOutput(2)]
            self.add_flow(datapath, 1, match_2, actions_dp2)

            # dst = h1 
            match_2 = parser.OFPMatch(eth_dst="00:00:00:00:00:01")
            actions_dp2 = [parser.OFPActionOutput(1)]
            self.add_flow(datapath, 1, match_2, actions_dp2)

            # dst = h3
            match_2 = parser.OFPMatch(eth_dst="00:00:00:00:00:03")
            actions_dp2 = [parser.OFPActionOutput(2)]
            self.add_flow(datapath, 1, match_2, actions_dp2)

            match_flood    = parser.OFPMatch(eth_dst="ff:ff:ff:ff:ff:ff")
            out_port       = ofproto.OFPP_FLOOD
            actions_flood  = [parser.OFPActionOutput(out_port)]
            self.add_flow(datapath, 1, match_flood, actions_flood)


        if dpid == 3:


            # dst = h2
            match_3 = parser.OFPMatch(eth_dst="00:00:00:00:00:02")
            actions_dp3 = [parser.OFPActionOutput(2)]
            self.add_flow(datapath, 1, match_3, actions_dp3)
 
            # dst = h3
            match_3 = parser.OFPMatch(eth_dst="00:00:00:00:00:03")
            actions_dp3 = [parser.OFPActionOutput(2)]
            self.add_flow(datapath, 1, match_3, actions_dp3)

            # dst = h1
            match_3 = parser.OFPMatch(eth_dst="00:00:00:00:00:01")
            actions_dp3 = [parser.OFPActionOutput(1)]
            self.add_flow(datapath, 1, match_3, actions_dp3)

        if dpid == 5: ###


            # dst = h2
            match_5 = parser.OFPMatch(eth_dst="00:00:00:00:00:02")
            actions_dp5 = [parser.OFPActionOutput(2)]
            self.add_flow(datapath, 1, match_5, actions_dp5)

            # dst = h3
            match_5 = parser.OFPMatch(eth_dst="00:00:00:00:00:03")
            actions_dp5 = [parser.OFPActionOutput(2)]
            self.add_flow(datapath, 1, match_5, actions_dp5)

            # dst = h1
            match_5 = parser.OFPMatch(eth_dst="00:00:00:00:00:01")
            actions_dp5 = [parser.OFPActionOutput(1)]
            self.add_flow(datapath, 1, match_5, actions_dp5)




    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def _packet_in_handler(self, ev):
        # If you hit this you might want to increase
        # the "miss_send_length" of your switch
        if ev.msg.msg_len < ev.msg.total_len:
            self.logger.debug("packet truncated: only %s of %s bytes",
                              ev.msg.msg_len, ev.msg.total_len)
        msg = ev.msg
        datapath = msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        in_port = msg.match['in_port']

        pkt = packet.Packet(msg.data)
        eth = pkt.get_protocols(ethernet.ethernet)[0]

        dst = eth.dst
        src = eth.src


        dpid = datapath.id

#        self.mac_to_port.setdefault(dpid, {})
        self.logger.info("packet in %s %s %s %s", dpid, src, dst, in_port)

    def add_flow(self, datapath, priority, match, actions):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS,actions)]

        mod = parser.OFPFlowMod(datapath=datapath, priority=priority,match=match, instructions=inst)
        
        datapath.send_msg(mod)


    def send_group_mod(self, datapath, group_type, group_id, buckets):
        ofproto = datapath.ofproto
        parser  = datapath.ofproto_parser
        # Add group table entry 
        req = parser.OFPGroupMod(datapath, ofproto.OFPGC_ADD, group_type, group_id, buckets)
        datapath.send_msg(req)

    def send_flow_stats_request(self,datapath):
        ofproto = datapath.ofproto
        ofp_parser = datapth.ofproto_parser

        cookie = cookie_mask = 0
        match = ofp_parser>OFPMatch(in_port=1)
        req = ofp_parser.OFPFlowStatsRequest(datapath, 0,
                                             ofp.OFPTT_ALL,
                                             ofp.OFPP_ANY, ofp.OFPG_ANY,
                                             cookie, cookie_mask,
                                             mask)
        datapath.send_msg(req)

    @set_ev_cls(ofp_event.EventOFPFlowStatsReply, MAIN_DISPATCHER)
    def flow_stats_reply_handler(self, ev):
        flows = []
        for stat in ev.msg.body:
            flows.append('table_id=%s '
                         'duration_sec=%d duration_nsec=%d '
                         'priority=%d '
                         'idle_timeout=%d hard_timeout=%d flags=0x%04x '
                         'cookie=%d packet_count=%d byte_count=%d '
                         'match=%s instructions=%s' %
                         (stat.table_id,
                          stat.duration_sec, stat.duration_nsec,
                          stat.priority,
                          stat.idle_timeout, stat.hard_timeout, stat.flags,
                          stat.cookie, stat.packet_count, stat.byte_count,
                          stat.match, stat.instructions))
        self.logger.debug('FlowStats: %s', flows)


    def _monitor(self):#, ev
        datapath = ev.msg.datapath
        hub.sleep(5)
        while True:
            self.send_flow_stats_request()
            hub.sleep(1)

    def run(self):

        print('--------Monitoring---------')
        url_1 = "http://140.120.15.170:8008/metric/127.0.0.1/2436.ifinpkts/json"
        url_2 = "http://140.120.15.170:8008/metric/127.0.0.1/2443.ifinpkts/json" 
        url_3 = "http://140.120.15.170:8008/metric/127.0.0.1/2445.ifinpkts/json"

        response_1 = urllib.urlopen(url_1);
        data_1 = json.loads(response_1.read())

        response_2 = urllib.urlopen(url_2);
        data_2 = json.loads(response_2.read())

        response_3 = urllib.urlopen(url_3);
        data_3 = json.loads(response_3.read())

        #return data_1[0]["metricValue"]
        print data_1[0]["metricValue"]
        print data_2[0]["metricValue"]
        print data_3[0]["metricValue"]
        print ""    


