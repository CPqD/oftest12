'''
Created on Dec 14, 2010

@author: capveg
'''
import logging


import oftest.cstruct as ofp
import oftest.message as message
import oftest.action as action
import oftest.parse as parse
import oftest.instruction as instruction
import oftest.match_list as match_list
import oftest.match as match
import basic

import testutils

def test_set_init(config):
    """
    Set up function for packet action test classes

    @param config The configuration dictionary; see oft
    """

    global pa_port_map
    global pa_logger
    global pa_config

    pa_logger = logging.getLogger("pkt_act")
    pa_logger.info("Initializing test set")
    pa_port_map = config["port_map"]
    pa_config = config
    



class TwoTable1(basic.SimpleDataPlane):
    """
    Simple two table test

    Add two flow entries:
    Table 0 Match IP Src A; send to 1, goto 1
    Table 1 Match TCP port B; send to 2

    Then send in 2 packets:
    IP A, TCP C; expect out port 1
    IP A, TCP B; expect out port 2

    Lots of negative tests are not checked
    """
    def runTest(self):
        of_ports = pa_port_map.keys()
        of_ports.sort()
        self.assertTrue(len(of_ports) > 2, "Not enough ports for test")

        # Clear flow table
        rv = testutils.initialize_table_config(self.controller, pa_logger)
        self.assertEqual(rv, 0, "Failed to initialize table config")
        rv = testutils.delete_all_flows(self.controller, pa_logger)
        self.assertEqual(rv, 0, "Failed to delete all flows")

        # Set up first match
        dl_type = match.eth_type(0x800)
        nw_src = match.ipv4_src(ipaddr.IPv4Address('192.168.1.10'))
        act = action.action_output()
        act.port = of_ports[0]

        request = message.flow_mod()
        request.match.type = ofp.OFPMT_OXM
        request.buffer_id = 0xffffffff
        request.table_id = 0
        request.match_fields.tlvs.append(dl_type)
        request.match_fields.tlvs.append(nw_src)
        inst = instruction.instruction_write_actions()
        self.assertTrue(inst.actions.add(act), "Could not add action")
        self.assertTrue(request.instructions.add(inst), "Could not add inst1")
        inst = instruction.instruction_goto_table()
        inst.table_id = 1
        self.assertTrue(request.instructions.add(inst), "Could not add inst2")
        pa_logger.info("Inserting flow 1")
        rv = self.controller.message_send(request)
        # pa_logger.debug(request.show())
        self.assertTrue(rv != -1, "Error installing flow mod")

        # Set up second match
        dl_type = match.eth_type(0x800)
        nw_proto = match.ip_proto(6) # TCP
        tp_src = match.tcp_src(80)
        act = action.action_output()
        act.port = of_ports[1]
        request = message.flow_mod()
        request.match.type = ofp.OFPMT_OXM
        request.match_fields.tlvs.append(dl_type)
        request.match_fields.tlvs.append(nw_proto)
        request.match_fields.tlvs.append(tp_src)
        request.buffer_id = 0xffffffff
        request.table_id = 1

        inst = instruction.instruction_write_actions()
        self.assertTrue(inst.actions.add(act), "Could not add action")
        self.assertTrue(request.instructions.add(inst), "Could not add inst3")
        pa_logger.info("Inserting flow 2")
        # pa_logger.debug(request.show())
        rv = self.controller.message_send(request)
        self.assertTrue(rv != -1, "Error installing flow mod")
        testutils.do_barrier(self.controller)

        table_config(self,1,TABLE_MISS_CONTROLLER)

        # Generate a packet matching only flow 1; rcv on port[0]
        pkt = testutils.simple_tcp_packet(ip_src='192.168.1.10', tcp_src=10)
        self.dataplane.send(of_ports[2], str(pkt))
        (rcv_port, rcv_pkt, _) = self.dataplane.poll(timeout=5)
        self.assertTrue(rcv_pkt is not None, "Did not receive packet")
        pa_logger.debug("Packet len " + str(len(rcv_pkt)) + " in on " + 
                        str(rcv_port))
        self.assertEqual(rcv_port, of_ports[0], "Unexpected receive port")
        
        # Generate a packet matching both flow 1 and flow 2; rcv on port[1]
        pkt = testutils.simple_tcp_packet(ip_src='192.168.1.10', tcp_src=80)
        self.dataplane.send(of_ports[2], str(pkt))
        (rcv_port, rcv_pkt, _) = self.dataplane.poll(timeout=5)
        self.assertTrue(rcv_pkt is not None, "Did not receive packet")
        pa_logger.debug("Packet len " + str(len(rcv_pkt)) + " in on " + 
                        str(rcv_port))
        self.assertEqual(rcv_port, of_ports[1], "Unexpected receive port")


MT_TEST_IP = '192.168.1.10'
MT_TEST_DL_TYPE = 0x800
import ipaddr

def make_match(dl_type=MT_TEST_DL_TYPE, ip_src=MT_TEST_IP):
    """
    Make matching entry template
    """
       
    # match_fields = match_list.match_list()
    
    nw_src = match.ipv4_src(ipaddr.IPv4Address(ip_src))
    eth_type = match.eth_type(dl_type)
    match_fields = match_list.match_list()
    match_fields.tlvs.append(eth_type)
    match_fields.tlvs.append(nw_src)

    return match_fields

TABLE_MISS_CONTROLLER = 0,    # Send to controller.
TABLE_MISS_CONTINUE = 1 << 0, #/* Continue to the next table in the
                                    #   pipeline (OpenFlow 1.0 behavior). */
TABLE_MISS_DROP = 1 << 1,     #/* Drop the packet. */
TABLE_MISS_MASK = 3
def table_config(parent, set_id = 0, mode = None):
    """
    Configure table packet handling
    """
    if mode is None :
        return False
    request = message.flow_mod()
    request.match.type = ofp.OFPMT_OXM
    request.buffer_id = 0xffffffff
    request.table_id = set_id
    request.priority = 0
    inst = instruction.instruction_apply_actions()

    if mode == TABLE_MISS_CONTROLLER:
        act = action.action_output()
        act.port = ofp.OFPP_CONTROLLER
        act.max_len = ofp.OFPCML_NO_BUFFER
        inst.actions.add(act)
    elif mode == TABLE_MISS_CONTINUE :
        inst = instruction.instruction_goto_table()
        inst.table_id = set_id + 1
    elif mode == TABLE_MISS_DROP :
        act = 0
    else :
        return False

    parent.assertTrue(request.instructions.add(inst), "Can't add inst")
    pa_logger.info("Inserting flow")
    rv = parent.controller.message_send(request)
    parent.assertTrue(rv != -1, "Error installing flow mod")
    testutils.do_barrier(parent.controller)
    return True

def reply_check_dp(parent, ip_src=MT_TEST_IP, tcp_src=10,
                   exp_pkt=None, ing_port=0, egr_port=1):
    """
    Receiving and received packet check on dataplane
    """
    pkt = testutils.simple_tcp_packet(ip_src=ip_src, tcp_src=tcp_src)
    parent.dataplane.send(ing_port, str(pkt))
    if exp_pkt is None:
        exp_pkt = pkt
    testutils.receive_pkt_verify(parent, egr_port, exp_pkt)

def reply_check_ctrl(parent, ip_src=MT_TEST_IP, tcp_src=10,
                     exp_pkt=None, ing_port=0):
    """
    Receiving and received packet check on controlplane
    """
    pkt = testutils.simple_tcp_packet(ip_src=ip_src, tcp_src=tcp_src)
    parent.dataplane.send(ing_port, str(pkt))
    if exp_pkt is None:
        exp_pkt = pkt
    testutils.packetin_verify(parent, exp_pkt)

def write_output(parent, set_id, outport, ip_src=MT_TEST_IP, match_fields=None) :
    """
    Make flow_mod of Write_action instruction of Output
    """
    act = action.action_output()
    act.port = outport
    request = message.flow_mod()
    request.match.type = ofp.OFPMT_OXM
    if match_fields is None :
        request.match_fields = make_match(ip_src = ip_src)
    else :
        request.match_fields = match_fields
    request.buffer_id = 0xffffffff
    request.table_id = set_id
    inst = instruction.instruction_write_actions()
    parent.assertTrue(inst.actions.add(act), "Can't add action")
    parent.assertTrue(request.instructions.add(inst), "Can't add inst")
    pa_logger.info("Inserting flow")
    rv = parent.controller.message_send(request)
    parent.assertTrue(rv != -1, "Error installing flow mod")
    testutils.do_barrier(parent.controller)

def write_goto(parent, set_id, next_id, ip_src=MT_TEST_IP, add_inst=None):
    """
    Make flow_mod of Goto table instruction
    """
    request = message.flow_mod()
    request.match.type = ofp.OFPMT_OXM
    request.match_fields = make_match(ip_src=ip_src)
    request.buffer_id = 0xffffffff
    request.table_id = set_id
    if add_inst is not None:
        parent.assertTrue(request.instructions.add(add_inst), "Can't add inst")
    inst = instruction.instruction_goto_table()
    inst.table_id = next_id
    parent.assertTrue(request.instructions.add(inst), "Can't add inst")
    pa_logger.info("Inserting flow")
    rv = parent.controller.message_send(request)
    parent.assertTrue(rv != -1, "Error installing flow mod")
    testutils.do_barrier(parent.controller)

def write_goto_action(parent, set_id, next_id, act, ip_src=MT_TEST_IP):
    """
    Make Goto instruction with/without write_action
    """
    inst = instruction.instruction_write_actions()
    parent.assertTrue(inst.actions.add(act), "Can't add action")
    write_goto(parent, set_id, next_id, ip_src=ip_src, add_inst=inst)

def write_goto_output(parent, set_id, next_id, outport, ip_src=MT_TEST_IP,
                      act=None):
    """
    Make flow_mod of Goto table and Write_action instruction of Output
    """
    act = action.action_output()
    act.port = outport
    write_goto_action(parent, set_id, next_id, act, ip_src=ip_src)


class MultiTableGoto(basic.SimpleDataPlane):
    """
    Simple three table test for "goto"

    Lots of negative tests are not checked
    """
    def scenario3(self, first_table = 0, second_table = 1, third_table = 2):
        """
        Add three flow entries:
        First Table; Match IP Src A; goto Second Table
        Second Table; Match IP Src A; send to 1, goto Third Table
        Third Table; Match TCP port B; send to 2

        Then send in 2 packets:
        IP A, TCP C; expect out port 1
        IP A, TCP B; expect out port 2

        @param self object instance
        @param first_table first table
        @param second_table second table
        @param third_table third table
        """
        of_ports = testutils.clear_switch(self, pa_port_map.keys(), pa_logger)

        # Set up first match
        write_goto(self, first_table, second_table)

        # Set up second match
        write_goto_output(self, second_table, third_table, of_ports[0])

        # Set up third match
        eth_type = match.eth_type(MT_TEST_DL_TYPE)
        nw_proto = match.ip_proto(6)
        tcp_src = match.tcp_src(80)
        match_fields = match_list.match_list()
        match_fields.tlvs.append(eth_type)
        match_fields.tlvs.append(nw_proto)
        match_fields.tlvs.append(tcp_src)

        # match.nw_proto = 6 #TCP
        # match.tp_src = 80
        write_output(self, third_table, of_ports[1], match_fields=match_fields)

        # Generate a packet matching only flow 1 and 2; rcv on port[0]
        # reply_check_dp(self, tcp_src=10,
        #                ing_port = of_ports[2], egr_port = of_ports[0])
        # Generate a packet matching both flow 1, 2 and 3; rcv on port[1]
        reply_check_dp(self, tcp_src=80,
                       ing_port = of_ports[2], egr_port = of_ports[1])

    def runTest(self):
        self.scenario3(0, 1, 2)
        self.scenario3(0, 1, 3)
        self.scenario3(0, 2, 3)
#        self.scenario3(1, 2, 3)


class MultiTableGotoAndSendport(basic.SimpleDataPlane):
    """
    Simple three table test for "goto and send to output port"

    Lots of negative tests are not checked
    """
    def set_apply_output(self, table_id, outport, add_inst=None):
        act = action.action_output()
        act.port = outport
        request = message.flow_mod()
        request.match.type = ofp.OFPMT_OXM
        request.match_fields = make_match()
        request.buffer_id = 0xffffffff
        request.table_id = table_id
        inst = instruction.instruction_apply_actions()
        self.assertTrue(inst.actions.add(act), "Can't add action")
        self.assertTrue(request.instructions.add(inst), "Can't add inst")
        if add_inst is not None:
            self.assertTrue(request.instructions.add(add_inst),
                            "Can't add inst")
        pa_logger.info("Inserting flow")
        rv = self.controller.message_send(request)
        self.assertTrue(rv != -1, "Error installing flow mod")
        testutils.do_barrier(self.controller)

    def scenario3(self, first_table = 0, second_table = 1, third_table = 2):
        """
        Add three flow entries:
        First Table; Match IP Src A; send to 0 now, goto Second Table
        Second Table; Match IP Src A; send to 1 now, goto Third Table
        Third Table; Match IP src A; send to 2 now

        Then send a packet:
        IP A;  expect out port 0, 1, and 2

        @param self object instance
        @param first_table first table
        @param second_table second table
        @param third_table third table
        """
        of_ports = testutils.clear_switch(self, pa_port_map.keys(), pa_logger)

        # Set up matches
        inst = instruction.instruction_goto_table()
        inst.table_id = second_table
        self.set_apply_output(first_table, of_ports[0], inst)
        # Set up second match
        inst.table_id = third_table
        self.set_apply_output(second_table, of_ports[1], inst)
        # Set up third match
        self.set_apply_output(third_table, of_ports[2])

        # Generate a packet and receive 3 responses
        pkt = testutils.simple_tcp_packet(ip_src=MT_TEST_IP, tcp_src=10)
        self.dataplane.send(of_ports[3], str(pkt))

        testutils.receive_pkt_verify(self, of_ports[0], pkt)
        testutils.receive_pkt_verify(self, of_ports[1], pkt)
        testutils.receive_pkt_verify(self, of_ports[2], pkt)

    def runTest(self):
        self.scenario3(0, 1, 2)
        self.scenario3(0, 2, 3)

class MultiTableNoGoto(basic.SimpleDataPlane):
    """
    Simple four table test for "No-goto"

    Lots of negative tests are not checked
    """
    def scenario4(self, first_table = 0, second_table = 1, third_table = 2, fourth_table = 3):
        """
        Add four flow entries:
        First Table; Match IP Src A; goto Second Table
        Second Table; Match IP Src A; send to 1, goto Third Table
        Third Table; Match IP Src A; do nothing // match but stop pipeline
        Fourth Table; Match IP Src A; send to 2  // not match, just a fake

        Then send in 2 packets:
        IP A, TCP C; expect out port 1
        IP A, TCP B; expect out port 1

        @param self object instance
        @param first_table first table
        @param second_table second table
        @param third_table third table
        @param fourth_table fourth table
        """
        of_ports = testutils.clear_switch(self, pa_port_map.keys(), pa_logger)

        # Set up first match
        write_goto(self, first_table, second_table)

        # Set up second match
        write_goto_output(self, second_table, third_table, of_ports[0])

        # Set up third match
        request = message.flow_mod()
        request.match.type = ofp.OFPMT_OXM
        request.match_fields = make_match()
        request.buffer_id = 0xffffffff
        request.table_id = third_table
        pa_logger.info("Inserting flow 3")
        rv = self.controller.message_send(request)
        self.assertTrue(rv != -1, "Error installing flow mod")

        testutils.do_barrier(self.controller)

        # Set up fourth match
        write_output(self, fourth_table, of_ports[1])

        # Generate a packet matching flow 1, 2, and 3; rcv on port[0]
        reply_check_dp(self, tcp_src=10,
                       ing_port = of_ports[2], egr_port = of_ports[0])
        # Generate a packet matching flow 1, 2, and 3; rcv on port[0]
        reply_check_dp(self, tcp_src=80,
                       ing_port = of_ports[2], egr_port = of_ports[0])

    def runTest(self):
        self.scenario4(0,1,2,3)


class MultiTablePolicyDecoupling(basic.SimpleDataPlane):
    """
    Simple two-table test for "policy decoupling"

    Lots of negative tests are not checked
    """
    def scenario2(self, first_table = 0, second_table = 1, tos1 = 4, tos2 = 8):
        """
        Add flow entries:
        First Table; Match IP Src A; set ToS = tos1, goto Second Table
        First Table; Match IP Src B; set ToS = tos2, goto Second Table
        Second Table; Match IP Src A; send to 1
        Second Table; Match IP Src B; send to 1

        Then send packets:
        IP A;  expect port 1 with ToS = tos1
        IP B;  expect port 1 with ToS = tos2

        @param self object instance
        @param first_table first table
        @param second_table second table
        @param tos1 ToS value to be set for first flow
        @param tos2 ToS value to be set for second flow
        """
        of_ports = testutils.clear_switch(self, pa_port_map.keys(), pa_logger)

        # Set up flow match in table A: set ToS
        nw_tos = match.ip_dscp((tos1>>2))
        t_act = action.action_set_field()
        t_act.field.tlvs.append(nw_tos)
        # t_act = action.action_set_nw_tos()
        # t_act.nw_tos = tos1
        write_goto_action(self, first_table, second_table, t_act,
                          ip_src='192.168.1.10')
        nw_tos = match.ip_dscp((tos2>>2))
        t_act = action.action_set_field()
        t_act.field.tlvs.append(nw_tos)

        write_goto_action(self, first_table, second_table, t_act,
                          ip_src='192.168.1.30')

        # Set up flow matches in table B: routing
        write_output(self, second_table, of_ports[1], ip_src="192.168.1.10")
        write_output(self, second_table, of_ports[1], ip_src="192.168.1.30")

        # Generate packets and check them
        exp_pkt = testutils.simple_tcp_packet(ip_src='192.168.1.10',
                                              tcp_src=10, ip_tos=tos1)
        reply_check_dp(self, ip_src='192.168.1.10', tcp_src=10,
                 exp_pkt=exp_pkt, ing_port=of_ports[2], egr_port=of_ports[1])

        exp_pkt = testutils.simple_tcp_packet(ip_src='192.168.1.30',
                                              tcp_src=10, ip_tos=tos2)
        reply_check_dp(self, ip_src='192.168.1.30', tcp_src=10,
                 exp_pkt=exp_pkt, ing_port=of_ports[2], egr_port=of_ports[1])

    def runTest(self):
        self.scenario2(0, 1, 0x6c, 0x4c)


class MultiTableClearAction(basic.SimpleDataPlane):
    """
    Simple four table test for "ClearAction"

    Lots of negative tests are not checked
    """
    def scenario4(self, first_table = 0, second_table = 1, third_table = 2, fourth_table = 3):
        """
        Add four flow entries:
        First Table; Match IP Src A; goto Second Table
        Second Table; Match IP Src A; send to 1, goto Third Table
        Third Table; Match IP Src A; clear action, goto Fourth Table
        Fourth Table; Match IP Src A; send to 2

        Then send in 2 packets:
        IP A, TCP C; expect out port 1
        IP A, TCP B; expect out port 1

        @param self object instance
        @param first_table first table
        @param second_table second table
        @param third_table third table
        @param fourth_table fourth table
        """
        of_ports = testutils.clear_switch(self, pa_port_map.keys(), pa_logger)

        # Set up first match
        write_goto(self, first_table, second_table)
        # Set up second match
        write_goto_output(self, second_table, third_table, of_ports[0])
        # Set up third match, "Clear Action"
        inst = instruction.instruction_clear_actions()
        write_goto(self, third_table, fourth_table, add_inst=inst)
        # Set up fourth match
        write_output(self, fourth_table, of_ports[1])

        # Generate a packet matching flow 1, 2, and 3; rcv on port[1]
        reply_check_dp(self, tcp_src=10,
                       ing_port = of_ports[2], egr_port = of_ports[1])
        # Generate a packet matching flow 1, 2, and 3; rcv on port[1]
        reply_check_dp(self, tcp_src=80,
                       ing_port = of_ports[2], egr_port = of_ports[1])

    def runTest(self):
        self.scenario4(0,1,2,3)


class MultiTableMetadata(basic.SimpleDataPlane):
    """
    Simple four table test for writing and matching "Metdata"

    Lots of negative tests are not checked
    """
    def scenario4(self, first_table = 0, second_table = 1, third_table = 2, fourth_table = 3):
        """
        Add four flow entries:
        First Table; Match IP Src A; send to 1, goto Second Table
        Second Table; Match IP Src A; write metadata, goto Third Table
        Third Table; Match IP Src A and metadata; send to 2 // stop, do action
        Fourth Table; Match IP Src A; send to 1 // not match, just a trap

        Then send in 2 packets:
        IP A, TCP C; expect out port 2
        IP A, TCP B; expect out port 2

        @param self object instance
        @param first_table first table
        @param second_table second table
        @param third_table third table
        @param fourth_table fourth table
        """
        of_ports = testutils.clear_switch(self, pa_port_map.keys(), pa_logger)

        # Set up first match
        write_goto_output(self, first_table, second_table, of_ports[0])

        # Set up second match
        inst = instruction.instruction_write_metadata()
        inst.metadata =      0xfedcba9876543210
        inst.metadata_mask = 0xffffffffffffffff
        write_goto(self, second_table, third_table, add_inst=inst)

        # Set up third match
        match_fields = make_match()
        metadata_field = match.metadata(0xfedcba9876543210)

        match_fields.tlvs.append(metadata_field)
        write_output(self, third_table, of_ports[1], match_fields=match_fields)

        # Set up fourth match
        write_output(self, fourth_table, of_ports[0])

        # Generate a packet matching flow 1, 2, and 3; rcv on port[1]
        reply_check_dp(self, tcp_src=10,
                       ing_port = of_ports[2], egr_port = of_ports[1])
        # Generate a packet matching flow 1, 2, and 3; rcv on port[1]
        reply_check_dp(self, tcp_src=80,
                       ing_port = of_ports[2], egr_port = of_ports[1])

    def runTest(self):
        self.scenario4(0,1,2,3)


class MultiTableEmptyInstruction(basic.SimpleDataPlane):
    """
    Simple four table test for "Empty Instruction"

    Lots of negative tests are not checked
    """
    def scenario4(self, first_table = 0, second_table = 1, third_table = 2, fourth_table = 3):
        """
        ** Currently, same scenario with "NoGoto" **

        Add four flow entries:
        First Table; Match IP Src A; goto Second Table
        Second Table; Match IP Src A; send to 1, goto Third Table
        Third Table; Match IP Src A; do nothing // match but stop pipeline
        Fourth Table; Match IP Src A; send to 2  // not match, just a fake

        Then send in 2 packets:
        IP A, TCP C; expect out port 1
        IP A, TCP B; expect out port 1

        @param self object instance
        @param first_table first table
        @param second_table second table
        @param third_table third table
        @param fourth_table fourth table
        """
        of_ports = testutils.clear_switch(self, pa_port_map.keys(), pa_logger)

        # Set up first match
        write_goto(self, first_table, second_table)

        # Set up second match
        write_goto_output(self, second_table, third_table, of_ports[0])

        # Set up third match, "Empty Instruction"
        request = message.flow_mod()
        request.match.type = ofp.OFPMT_OXM
        request.match_fields = make_match()
        request.buffer_id = 0xffffffff
        request.table_id = third_table
        pa_logger.info("Inserting flow 3")
        rv = self.controller.message_send(request)
        self.assertTrue(rv != -1, "Error installing flow mod")

        testutils.do_barrier(self.controller)

        # Set up fourth match
        write_output(self, fourth_table, of_ports[1])

        # Generate a packet matching flow 1, 2, and 3; rcv on port[0]
        reply_check_dp(self, tcp_src=10,
                       ing_port = of_ports[2], egr_port = of_ports[0])
        # Generate a packet matching flow 1, 2, and 3; rcv on port[0]
        reply_check_dp(self, tcp_src=80,
                       ing_port = of_ports[2], egr_port = of_ports[0])

    def runTest(self):
        self.scenario4(0,1,2,3)


class MultiTableMiss(basic.SimpleDataPlane):
    """
    Simple four table test for all miss (not match)

    Lots of negative tests are not checked
    """
    def scenario4(self, first_table = 0, second_table = 1, third_table = 2, fourth_table = 3):
        """
        Add five flow entries:
        First Table; Match IP Src A; send to 1
        Second Table; Match IP Src B; send to 1
        Third Table; Match IP Src C; send to 1
        Fourth Table; Match IP Src D; send to 1

        Then send in 2 packets:
        IP F, TCP C; expect packet_in
        IP G, TCP B; expect packet_in

        @param self object instance
        @param first_table first table
        @param second_table second table
        @param third_table third table
        @param fourth_table fourth table
        """
        of_ports = testutils.clear_switch(self, pa_port_map.keys(), pa_logger)

        # Set up matches
        write_output(self, first_table, of_ports[0], ip_src="192.168.1.10")
        write_output(self, second_table, of_ports[0], ip_src="192.168.1.20")
        write_output(self, third_table, of_ports[0], ip_src="192.168.1.30")
        write_output(self, fourth_table, of_ports[0], ip_src="192.168.1.40")

        table_config(self,first_table, TABLE_MISS_CONTINUE)
        table_config(self,second_table, TABLE_MISS_CONTINUE)
        table_config(self,third_table, TABLE_MISS_CONTINUE)
        table_config(self,fourth_table, TABLE_MISS_CONTROLLER)
        # Generate a packet not matching to any flow, then packet_in
        reply_check_ctrl(self, ip_src='192.168.1.70', tcp_src=10,
                         ing_port = of_ports[2])

    def runTest(self):
        self.scenario4(0,1,2,3)


def setup_table_config(parent, table_id, table_config):
    request = message.table_mod()
    request.table_id = table_id
    request.config = table_config
    rv = parent.controller.message_send(request)
    parent.assertTrue(rv != -1, "Error configuring table")
    testutils.do_barrier(parent.controller)


class MultiTableConfigContinue(basic.SimpleDataPlane):
    """
    Simple table config test for "continue"

    Lots of negative tests are not checked
    """
    def scenario2(self, first_table = 0, second_table = 1):
        """
        Set table config as "Continue" and add flow entry:
        First Table; Match IP Src A; send to 1 // not match then continue
        Second Table; Match IP Src B; send to 2 // do execution

        Then send in 2 packets:
        IP B; expect out port 2
        """
        of_ports = testutils.clear_switch(self, pa_port_map.keys(), pa_logger)

        # Set table config as "continue"
        # setup_table_config(self, first_table, ofp.OFPTC_TABLE_MISS_CONTINUE)
        rv = table_config(self,first_table, TABLE_MISS_CONTINUE)
        self.assertTrue(rv, "Could not install table miss flow")
        # Set up flow entries
        write_output(self, first_table, of_ports[0], ip_src='192.168.1.10')
        write_output(self, second_table, of_ports[1], ip_src='192.168.1.70')

        # Generate a packet not matching in the first table, but in the second
        reply_check_dp(self, ip_src='192.168.1.70', tcp_src=10,
                       ing_port = of_ports[2], egr_port = of_ports[1])

    def runTest(self):
        self.scenario2(0,1)


class MultiTableConfigController(basic.SimpleDataPlane):
    """
    Simple table config test for "controller"

    Lots of negative tests are not checked
    """
    def scenario2(self, first_table = 0, second_table = 1):
        """
        Set the first table config as "Send to Controller" and the second
        table as "Drop", add flow entries:
        First Table; Match IP Src A; send to 1 // if not match, packet_in
        Second Table; Match IP Src B; send to 2 // if not match, drop

        Then send a packet:
        IP B; expect packet_in
        """
        of_ports = testutils.clear_switch(self, pa_port_map.keys(), pa_logger)

        # Set table config as "send to controller" and "drop"
        rv = table_config(self,first_table, TABLE_MISS_CONTROLLER)
        self.assertTrue(rv, "Could not install table miss flow")
        # setup_table_config(self, first_table, ofp.OFPTC_TABLE_MISS_CONTROLLER)
        rv = table_config(self,second_table, TABLE_MISS_DROP)
        self.assertTrue(rv, "Could not install table miss flow")
        # setup_table_config(self, second_table, ofp.OFPTC_TABLE_MISS_DROP)

        # Set up matches
        write_output(self, first_table, of_ports[0], ip_src='192.168.1.10')
        write_output(self, second_table, of_ports[1], ip_src='192.168.1.70')

        # Generate a packet not matching to any flow entry in the first table
        reply_check_ctrl(self, ip_src='192.168.1.70', tcp_src=10,
                         ing_port = of_ports[2])

    def runTest(self):
        self.scenario2(0,1)


class MultiTableConfigDrop(basic.SimpleDataPlane):
    """
    Simple table config test for "drop"

    Lots of negative tests are not checked
    """
    def scenario2(self, first_table = 0, second_table = 1):
        """
        Set the first table config as "Drop" and second table as "Controller"
        add flow entry:
        First Table; Match IP Src A; send to 1 // if not match, then drop
        Second Table; Match IP Src B; send to 2 // if not match, controller

        Then send in a packet:
        IP B; expect drop
        """
        of_ports = testutils.clear_switch(self, pa_port_map.keys(), pa_logger)

        # Set table config as "drop" and "send to controller"
        # setup_table_config(self, first_table, TABLE_MISS_DROP)
        # setup_table_config(self, second_table, TABLE_MISS_CONTROLLER)

        table_config(self, first_table, TABLE_MISS_DROP)
        table_config(self, second_table, TABLE_MISS_CONTROLLER)

        # Set up first match
        write_output(self, first_table, of_ports[0], ip_src="192.168.1.10")
        write_output(self, second_table, of_ports[1], ip_src="192.168.1.70")

        # Generate a packet not matching to any flow, then drop
        pkt = testutils.simple_tcp_packet(ip_src='192.168.1.70', tcp_src=10)
        self.dataplane.send(of_ports[2], str(pkt))
        # checks no response from controller and dataplane
        (response, _) = self.controller.poll(ofp.OFPT_PACKET_IN, 2)
        # self.assertIsNone() is preferable for newer python
        self.assertFalse(response is not None, "PacketIn message is received")
        (_, rcv_pkt, _) = self.dataplane.poll(timeout=5)
        self.assertFalse(rcv_pkt is not None, "Packet on dataplane")

    def runTest(self):
        self.scenario2(0,1)

