from collections import defaultdict
from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.topology import event
from ryu.controller.handler import MAIN_DISPATCHER,CONFIG_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_3

from ryu.topology.api import get_switch,get_all_link,get_link
import copy
import random
import time


from ryu.lib.packet import *

pc1_ip='10.1.1.110'
pc2_ip='10.1.1.120'
pc3_ip='10.2.2.130'
pc4_ip='10.3.3.140'
pc5_ip='10.3.3.150'

pc1_mac='00:0c:29:ea:68:92'
pc2_mac='00:0c:29:25:c9:9c'
pc3_mac='00:0c:29:8b:8a:6b'
pc4_mac='00:0c:29:58:e0:0a'
pc5_mac='00:0c:29:b9:ea:8c'

lan1_ip='10.1.1.0'
lan2_ip='10.2.2.0'
lan3_ip='10.3.3.0'

gate1_ip='10.1.1.100'
gate2_ip='10.2.2.100'
gate3_ip='10.3.3.100'
gate1_mac='00:0c:29:77:ee:b6'
gate2_mac='00:0c:29:77:ee:ca'
gate3_mac='00:0c:29:77:ee:d4'

gate1_dpid=52235333302
gate2_dpid=52235333322
gate3_dpid=52235333332
gate_port = 4294967294

VIP='10.1.1.77'
VIP2='10.3.3.77'
VMAC='66:66:66:66:66:66'

# this is topo implementing dijkstra algorithm
class Topo(object):
    def __init__(self,logger):

        self.switches=None

        self.host_mac_to={}
        self.logger=logger
    
    # this is a TODO 
    # not implemented
    def reset(self):
        self.switches=None
        self.host_mac_to=None
    
    #find the switch with min distance
    # def __min_dist(self,distances, Q):
    #     mm=float('Inf')
    #
    #     m_node=None
    #     for v in Q:
    #         if distances[v]<mm:
    #             mm=distances[v]
    #             m_node=v
    #     return m_node
    


#TODO Port status monitor

class NetController(app_manager.RyuApp):
    OFP_VERSIONS=[ofproto_v1_3.OFP_VERSION]

    def __init__(self,*args,**kwargs):
        super(NetController,self).__init__(*args,**kwargs)
        self.mac_to_port={}
        # logical switches
        self.datapaths=[]
        #ip ->mac
        self.arp_table={}   # key:ip vaule:mac
        self.arp_table.update({VIP:VMAC})
        self.arp_table.update({VIP2:VMAC})

        self.rarp_table={}
        self.topo=Topo(self.logger)
        self.flood_history={}

        self.arp_history={}

    def sendpaket(self, parser, ofproto, data, datapath, actions, buffer_id, in_port):
        out = parser.OFPPacketOut(
            datapath=datapath,
            buffer_id=buffer_id,
            in_port=in_port,
            actions=actions,
            data=data
        )
        datapath.send_msg(out)

    # def _find_dp(self,dpid):
    #     for dp in self.datapaths:
    #         if dp.id==dpid:
    #             return dp
    #     return None


    #copy from example
    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        datapath = ev.msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        match = parser.OFPMatch()
        actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER,
                                          ofproto.OFPCML_NO_BUFFER)]
        self.add_flow(datapath, 0, match, actions)
    
    def add_flow(self, datapath, priority, match, actions, buffer_id=None):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS,
                                             actions)]
        if buffer_id:
            mod = parser.OFPFlowMod(datapath=datapath, buffer_id=buffer_id,
                                    priority=priority, match=match,
                                    instructions=inst)
        else:
            mod = parser.OFPFlowMod(datapath=datapath, priority=priority,
                                    match=match, instructions=inst)
        datapath.send_msg(mod)




    @set_ev_cls(ofp_event.EventOFPPacketIn,MAIN_DISPATCHER)
    def packet_in_handler(self,event):


        flag=0

        msg=event.msg
        datapath=msg.datapath
        ofproto=datapath.ofproto
        parser=datapath.ofproto_parser

        # through which port the packet comes in
        in_port=msg.match['in_port']

        self.logger.info("From datapath.id {} port {} come in a packet".format(datapath.id,in_port))

        #get src_mac and dest mac
        pkt=packet.Packet(msg.data)

        eth=pkt.get_protocols(ethernet.ethernet)[0]

        # drop lldp
        if eth.ethertype==ether_types.ETH_TYPE_LLDP:
            self.logger.info("LLDP")
            return

        # get source and destination mac address
        dst_mac=eth.dst
        src_mac=eth.src

        # 获取对应协议的报头信息
        pkt_eth = pkt.get_protocol(ethernet.ethernet)
        arp_pkt = pkt.get_protocol(arp.arp)
        pkt_ipv4=pkt.get_protocol(ipv4.ipv4)
        pkt_icmp = pkt.get_protocol(icmp.icmp)
        pkt_udp = pkt.get_protocol(udp.udp)
        if pkt_ipv4:
            print('********we get ipv4packet******')

        if pkt_icmp:
            print('********we get icmp packet******')

        if pkt_udp:
            print('********we get udp packet******')

        # 通过arp协议学习Mac-ip表
        if arp_pkt:
            self.arp_table[arp_pkt.src_ip] = src_mac

        # dpid是交换机的标识
        dpid=datapath.id

        self.mac_to_port.setdefault(dpid,{})

        self.mac_to_port[dpid][src_mac]=in_port


        self.flood_history.setdefault(dpid,[])

        # ipv6 广播报文目的Mac开头都是33:33“
        if '33:33' in dst_mac[:5]:
            # the controller has not flooded this packet before
            if (src_mac,dst_mac) not in self.flood_history[dpid]:
                # we remember this packet
                self.flood_history[dpid].append((src_mac,dst_mac))
            else:
            # the controller have flooded this packet before,we do nothing and return
                return
                
        self.logger.info("from datapath {} port {} packet in src_mac {} dst_mac{}".format(datapath,in_port,src_mac,dst_mac))

        if src_mac not in self.topo.host_mac_to.keys():
            self.topo.host_mac_to[src_mac]=(dpid,in_port)

        # print(self.datapaths,'%%%%darapaths')
        # print(self.datapaths[0].id,self.datapaths[1].id,self.datapaths[2].id, '%%%%darapaths.id')
        # print(self.topo.host_mac_to,'%%%%hostmacto')

         # 收到发向外网(网关)的报文
        if pkt_ipv4:
            # self.datapath储存的交换机顺序为br-sw2,br-sw3,br-sw
            buffer_id = ofproto.OFP_NO_BUFFER
            in_port = ofproto.OFPP_CONTROLLER
            if pkt_ipv4.dst.split('.')[:3] != pkt_ipv4.src.split('.')[:3]:
                print('源和目的不在一个网段')
                # PC1向外发送
                if pkt_ipv4.src == pc1_ip:
                    # 发往子网2
                    if pkt_ipv4.dst.split('.')[:3] == lan2_ip.split('.')[:3]:

                        print('pc1发往gate1')
                        data = msg.data
                        actions = [parser.OFPActionOutput(port=gate_port)]
                        self.sendpaket(parser, ofproto, data, datapath, actions, buffer_id, in_port)

                        print('gate1发往gate2')
                        actions = [parser.OFPActionSetField(eth_src=gate1_mac),
                                    parser.OFPActionSetField(eth_dst=gate2_mac), parser.OFPActionOutput(port=gate_port)]
                        data = msg.data
                        datapath = self.datapaths[0]
                        self.sendpaket(parser, ofproto, data, datapath, actions, buffer_id, in_port)
                        if pkt_ipv4.dst == pc3_ip:

                            print('gate2发往pc3')
                            actions = [parser.OFPActionSetField(eth_src=gate2_mac),
                                       parser.OFPActionSetField(eth_dst=pc3_mac), parser.OFPActionOutput(port=1)]
                            data = msg.data
                            datapath = self.datapaths[0]
                            self.sendpaket(parser, ofproto, data, datapath, actions, buffer_id, in_port)
                    # 发往子网3
                    elif pkt_ipv4.dst.split('.')[:3] == lan3_ip.split('.')[:3]:

                        print('pc1发往gate1')
                        data = msg.data
                        actions = [parser.OFPActionOutput(port=gate_port)]
                        self.sendpaket(parser, ofproto, data, datapath, actions, buffer_id, in_port)

                        print('gate1发往gate3')
                        actions = [parser.OFPActionSetField(eth_src=gate1_mac),
                                   parser.OFPActionSetField(eth_dst=gate3_mac), parser.OFPActionOutput(port=gate_port)]
                        data = msg.data
                        datapath = self.datapaths[1]
                        self.sendpaket(parser, ofproto, data, datapath, actions, buffer_id, in_port)

                        if pkt_ipv4.dst == pc5_ip:

                            print('gate3发往pc5')
                            actions = [parser.OFPActionSetField(eth_src=gate3_mac),
                                       parser.OFPActionSetField(eth_dst=pc5_mac), parser.OFPActionOutput(port=2)]
                            data = msg.data
                            datapath = self.datapaths[1]
                            self.sendpaket(parser, ofproto, data, datapath, actions, buffer_id, in_port)
                # PC4向外发送
                elif pkt_ipv4.src == pc4_ip:
                    if pkt_ipv4.dst == pc3_ip:
                        print('pc4发往pc3')

                        print('pc4发往gate3')
                        data = msg.data
                        actions = [parser.OFPActionOutput(port=gate_port)]
                        self.sendpaket(parser, ofproto, data, datapath, actions, buffer_id, in_port)

                        print('gate3发往gate2')
                        actions = [parser.OFPActionSetField(eth_src=gate3_mac),
                                   parser.OFPActionSetField(eth_dst=gate2_mac), parser.OFPActionOutput(port=gate_port)]
                        data = msg.data
                        datapath = self.datapaths[0]
                        self.sendpaket(parser, ofproto, data, datapath, actions, buffer_id, in_port)

                        print('gate2发往pc3')
                        actions = [parser.OFPActionSetField(eth_src=gate2_mac),
                                   parser.OFPActionSetField(eth_dst=pc3_mac), parser.OFPActionOutput(port=1)]
                        data = msg.data
                        datapath = self.datapaths[0]
                        self.sendpaket(parser, ofproto, data, datapath, actions, buffer_id, in_port)

                    elif pkt_ipv4.dst == pc2_ip:
                        print('pc4发往pc2')

                        print('pc4发往gate3')
                        data = msg.data
                        actions = [parser.OFPActionOutput(port=gate_port)]
                        self.sendpaket(parser, ofproto, data, datapath, actions, buffer_id, in_port)

                        print('gate3发往gate1')
                        actions = [parser.OFPActionSetField(eth_src=gate3_mac),
                                   parser.OFPActionSetField(eth_dst=gate1_mac), parser.OFPActionOutput(port=gate_port)]
                        data = msg.data
                        datapath = self.datapaths[2]
                        self.sendpaket(parser, ofproto, data, datapath, actions, buffer_id, in_port)

                        print('gate1发往pc2')
                        actions = [parser.OFPActionSetField(eth_src=gate1_mac),
                                   parser.OFPActionSetField(eth_dst=pc2_mac), parser.OFPActionOutput(port=2)]
                        data = msg.data
                        datapath = self.datapaths[2]
                        self.sendpaket(parser, ofproto, data, datapath, actions, buffer_id, in_port)
                # PC2向外发送（只与PC4通信）
                elif pkt_ipv4.src == pc2_ip:
                    if pkt_ipv4.dst.split('.')[:3] == lan3_ip.split('.')[:3]:

                        print('pc2发往gate1')
                        data = msg.data
                        actions = [parser.OFPActionOutput(port=gate_port)]
                        self.sendpaket(parser, ofproto, data, datapath, actions, buffer_id, in_port)

                        print('gate1发往gate3')
                        actions = [parser.OFPActionSetField(eth_src=gate1_mac),
                                   parser.OFPActionSetField(eth_dst=gate3_mac), parser.OFPActionOutput(port=gate_port)]
                        data = msg.data
                        datapath = self.datapaths[1]
                        self.sendpaket(parser, ofproto, data, datapath, actions, buffer_id, in_port)
                        if pkt_ipv4.dst == pc4_ip:
                            print('gate3发往pc4')
                            actions = [parser.OFPActionSetField(eth_src=gate3_mac),
                                       parser.OFPActionSetField(eth_dst=pc4_mac), parser.OFPActionOutput(port=1)]
                            data = msg.data
                            datapath = self.datapaths[1]
                            self.sendpaket(parser, ofproto, data, datapath, actions, buffer_id, in_port)
                # PC5向外发送（只与PC1通信）
                elif pkt_ipv4.src == pc5_ip:
                    if pkt_ipv4.dst.split('.')[:3] == lan1_ip.split('.')[:3]:

                        print('pc5发往gate3')
                        data = msg.data
                        actions = [parser.OFPActionOutput(port=gate_port)]
                        self.sendpaket(parser, ofproto, data, datapath, actions, buffer_id, in_port)

                        print('gate3发往gate1')
                        actions = [parser.OFPActionSetField(eth_src=gate3_mac),
                                   parser.OFPActionSetField(eth_dst=gate1_mac), parser.OFPActionOutput(port=gate_port)]
                        data = msg.data
                        datapath = self.datapaths[2]
                        self.sendpaket(parser, ofproto, data, datapath, actions, buffer_id, in_port)
                        if pkt_ipv4.dst == pc1_ip:
                            print('gate1发往pc1')
                            actions = [parser.OFPActionSetField(eth_src=gate1_mac),
                                       parser.OFPActionSetField(eth_dst=pc1_mac), parser.OFPActionOutput(port=1)]
                            data = msg.data
                            datapath = self.datapaths[2]
                            self.sendpaket(parser, ofproto, data, datapath, actions, buffer_id, in_port)

                # PC3向外发送（只与PC1、PC4通信）
                elif pkt_ipv4.src == pc3_ip:
                    if pkt_ipv4.dst.split('.')[:3] == lan1_ip.split('.')[:3]:

                        print('pc3发往gate2')
                        data = msg.data
                        actions = [parser.OFPActionOutput(port=gate_port)]
                        self.sendpaket(parser, ofproto, data, datapath, actions, buffer_id, in_port)

                        print('gate2发往gate1')
                        actions = [parser.OFPActionSetField(eth_src=gate2_mac),
                                   parser.OFPActionSetField(eth_dst=gate1_mac), parser.OFPActionOutput(port=gate_port)]

                        data = msg.data
                        datapath = self.datapaths[2]
                        self.sendpaket(parser, ofproto, data, datapath, actions, buffer_id, in_port)
                        if pkt_ipv4.dst == pc1_ip:
                            print('gate1发往pc1')
                            actions = [parser.OFPActionSetField(eth_src=gate1_mac),
                                       parser.OFPActionSetField(eth_dst=pc1_mac), parser.OFPActionOutput(port=1)]

                            data = msg.data
                            datapath = self.datapaths[2]
                            self.sendpaket(parser, ofproto, data, datapath, actions, buffer_id, in_port)
                    elif pkt_ipv4.dst.split('.')[:3] == lan3_ip.split('.')[:3]:

                        print('pc3发往gate2')
                        data = msg.data
                        actions = [parser.OFPActionOutput(port=gate_port)]
                        self.sendpaket(parser, ofproto, data, datapath, actions, buffer_id, in_port)

                        print('gate2发往gate3')
                        actions = [parser.OFPActionSetField(eth_src=gate2_mac),
                                   parser.OFPActionSetField(eth_dst=gate3_mac), parser.OFPActionOutput(port=gate_port)]

                        data = msg.data
                        datapath = self.datapaths[1]
                        self.sendpaket(parser, ofproto, data, datapath, actions, buffer_id, in_port)
                        if pkt_ipv4.dst == pc4_ip:
                            print('gate3发往pc4')
                            actions = [parser.OFPActionSetField(eth_src=gate3_mac),
                                       parser.OFPActionSetField(eth_dst=pc4_mac), parser.OFPActionOutput(port=1)]

                            data = msg.data
                            datapath = self.datapaths[1]
                            self.sendpaket(parser, ofproto, data, datapath, actions, buffer_id, in_port)



        # 目的mac在表内，直接回复host对应的mac
        if dst_mac in self.topo.host_mac_to.keys():
            flag=0
            print('mac {} de port is {}'.format(dst_mac,self.topo.host_mac_to[dst_mac]))
            # the topo 
            # src_host------in_port---src_switch--------many switches along the path-----dst_switch----final_port----destination_host
            # get the final port
            final_port=self.topo.host_mac_to[dst_mac][1]

            out_port=final_port

        # 目的mac不在
        else:

            # 这里的arp_handler函数执行给一个arp回复的操作
            if self.arp_handler(msg):
                    return

            #the dst mac has not registered
            #对陌生的mac地址，将此arp包进行广播
            self.logger.info("We have not learn the mac address {},flooding...".format(dst_mac))
            out_port=ofproto.OFPP_FLOOD

        # 发往虚拟ip
        if pkt_eth.dst == VMAC:
            flag = 1
            print('！！！！！发往虚拟ip！！！！！')

            tsecond = time.asctime(time.localtime(time.time()))
            second = tsecond.split(' ')[3].split(':')[2]
            print(second, '！！GET TIME！！')

            if pkt_ipv4:
                if second <= '20':  # 前20s发往本地计算单元
                    if pkt_ipv4.src == pc1_ip:
                        print('前20s，pc1发往pc2')
                        dstmac = pc2_mac
                        dstip = pc2_ip
                    if pkt_ipv4.src == pc4_ip:
                        print('前20s，pc4发往pc5')
                        dstmac = pc5_mac
                        dstip = pc5_ip
                    data = msg.data
                    actions = [parser.OFPActionSetField(ipv4_dst=dstip),
                                parser.OFPActionSetField(eth_dst=dstmac), parser.OFPActionOutput(port=2)]
                    self.sendpaket(parser, ofproto, data, datapath, actions, buffer_id, in_port)

                if second > '20' and second <= '40':  # 中间20s发往远程服务器
                    if pkt_ipv4.src == pc1_ip:
                        print('中间20s，pc1发往pc3')
                        smac = gate1_mac

                    if pkt_ipv4.src == pc4_ip:
                        print('中间20s，pc4发往pc3')
                        smac = gate3_mac

                    actions = [parser.OFPActionOutput(port=gate_port)]
                    data = msg.data
                    self.sendpaket(parser, ofproto, data, datapath, actions, buffer_id, in_port)

                    actions = [parser.OFPActionSetField(eth_src=smac),
                                   parser.OFPActionSetField(ipv4_dst=pc3_ip),
                                   parser.OFPActionSetField(eth_dst=gate2_mac),
                                   parser.OFPActionOutput(port=gate_port)]
                    data = msg.data
                    datapath = self.datapaths[0]
                    self.sendpaket(parser, ofproto, data, datapath, actions, buffer_id, in_port)

                    actions = [parser.OFPActionSetField(eth_src=gate2_mac),
                                   parser.OFPActionSetField(ipv4_dst=pc3_ip),
                                   parser.OFPActionSetField(eth_dst=pc3_mac), parser.OFPActionOutput(port=1)]
                    data = msg.data
                    datapath = self.datapaths[0]
                    self.sendpaket(parser, ofproto, data, datapath, actions, buffer_id, in_port)

                if second > '40' and second <= '60':  # 后20s发往其他子网计算单元
                    if pkt_ipv4.src == pc1_ip:
                        print('后20s，pc1发往pc5')
                        smac1 = gate1_mac
                        dmac1 = gate3_mac
                        smac2 = gate3_mac
                        dmac2 = pc5_mac
                        dip = pc5_ip
                        sw = 1

                    if pkt_ipv4.src == pc4_ip:
                        print('后20s，pc4发往pc2')
                        smac1 = gate3_mac
                        dmac1 = gate1_mac
                        smac2 = gate1_mac
                        dmac2 = pc2_mac
                        dip = pc2_ip
                        sw = 2

                    actions = [parser.OFPActionOutput(port=gate_port)]
                    data = msg.data
                    self.sendpaket(parser, ofproto, data, datapath, actions, buffer_id, in_port)

                    actions = [parser.OFPActionSetField(eth_src=smac1),
                                   parser.OFPActionSetField(ipv4_dst=dip),
                                   parser.OFPActionSetField(eth_dst=dmac1),
                                   parser.OFPActionOutput(port=gate_port)]
                    data = msg.data
                    datapath = self.datapaths[sw]
                    self.sendpaket(parser, ofproto, data, datapath, actions, buffer_id, in_port)

                    actions = [parser.OFPActionSetField(eth_src=smac2),
                                   parser.OFPActionSetField(ipv4_dst=dip),
                                   parser.OFPActionSetField(eth_dst=dmac2), parser.OFPActionOutput(port=2)]
                    data = msg.data
                    datapath = self.datapaths[sw]
                    self.sendpaket(parser, ofproto, data, datapath, actions, buffer_id, in_port)


        if flag==0:

            # actions= flood or some port
            actions=[parser.OFPActionOutput(out_port)]

            data=None

            if msg.buffer_id==ofproto.OFP_NO_BUFFER:
                data=msg.data
            
            # send the packet out to avoid packet loss
            out=parser.OFPPacketOut(
                datapath=datapath,
                buffer_id=msg.buffer_id,
                in_port=in_port,
                actions=actions,
                data=data
            )
            datapath.send_msg(out)

    @set_ev_cls(event.EventSwitchEnter)
    def switch_enter_handler(self,event):
        self.logger.info("A switch entered.Topology rediscovery...")
        self.switch_status_handler(event)
        self.logger.info('Topology rediscovery done')
    
    @set_ev_cls(event.EventSwitchLeave)
    def switch_leave_handler(self,event):
        self.logger.info("A switch leaved.Topology rediscovery...")
        self.switch_status_handler(event)
        self.logger.info('Topology rediscovery done')



    def switch_status_handler(self,event):

        # use copy to avoid unintended modification which is fatal to the network
        all_switches=copy.copy(get_switch(self,None))
       

        # get all datapathid 
        self.topo.switches=[s.dp.id for s in all_switches]

        self.logger.info("switches {}".format(self.topo.switches))

        self.datapaths=[s.dp for s in all_switches]


    def arp_handler(self, msg):

        datapath = msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        in_port = msg.match['in_port']

        pkt = packet.Packet(msg.data)

        eth = pkt.get_protocols(ethernet.ethernet)[0]
        arp_pkt = pkt.get_protocol(arp.arp)

        if eth:
            eth_dst = eth.dst
            eth_src = eth.src
        
        # the destination mac address for an arp request packet is a braodcast address
        # if this is an arp request
        if eth_dst == 'ff:ff:ff:ff:ff:ff' and arp_pkt:
            # target ip 
            arp_dst_ip = arp_pkt.dst_ip

            # arp_history={
            # (datapath.id,eth_src,dst_ip):inport
            # }

            # we have met this particular arp request before
            if (datapath.id, eth_src, arp_dst_ip) in self.arp_history:

                if self.arp_history[(datapath.id, eth_src, arp_dst_ip)] != in_port:
                    #datapath.send_packet_out(in_port=in_port, actions=[])
                    return True
            else:
                # we didnt met this packet before, record it
                self.arp_history[(datapath.id, eth_src, arp_dst_ip)] = in_port
        
        #construct arp packet
        # we get the arp header parameter to construct an arp reply.
        if arp_pkt:

            #specify the operation that the sender is performing:1 for request,2 for reply
            opcode = arp_pkt.opcode

            # src ip
            arp_src_ip = arp_pkt.src_ip
            # dst ip 
            arp_dst_ip = arp_pkt.dst_ip

            # arp_request
            if opcode == arp.ARP_REQUEST:

                # we have learned the target ip mac mapping
                if arp_dst_ip in self.arp_table:
                    # send arp reply from in port
                    actions = [parser.OFPActionOutput(in_port)]
                    arp_reply = packet.Packet()
                    
                    arp_reply.add_protocol(ethernet.ethernet(
                        ethertype=eth.ethertype,
                        dst=eth_src,
                        src=self.arp_table[arp_dst_ip]))
                    
                    # add arp protocol
                    arp_reply.add_protocol(arp.arp(
                        opcode=arp.ARP_REPLY,
                        src_mac=self.arp_table[arp_dst_ip],
                        src_ip=arp_dst_ip,
                        dst_mac=eth_src,
                        dst_ip=arp_src_ip))
                    
                    # serialize the packet to binary format 0101010101
                    arp_reply.serialize()
                    #arp reply
                    out = parser.OFPPacketOut(
                        datapath=datapath,
                        buffer_id=ofproto.OFP_NO_BUFFER,
                        in_port=ofproto.OFPP_CONTROLLER,
                        actions=actions, data=arp_reply.data)
                    datapath.send_msg(out)
                    
                    return True
        return False


