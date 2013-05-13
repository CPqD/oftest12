"""
Basic protocol and dataplane test cases

It is recommended that these definitions be kept in their own
namespace as different groups of tests will likely define 
similar identifiers.

Current Assumptions:

  The function test_set_init is called with a complete configuration
dictionary prior to the invocation of any tests from this file.

  The switch is actively attempting to contact the controller at the address
indicated oin oft_config

"""

import sys
import logging

import trace

import unittest

import oftest.match as match
import oftest.controller as controller
import oftest.cstruct as ofp
import oftest.message as message
import oftest.dataplane as dataplane
import oftest.action as action
import oftest.instruction as instruction
import oftest.parse as parse

import testutils
import ipaddr

#@var mult_cont_port_map Local copy of the configuration map from OF port
# numbers to OS interfaces
mult_cont_port_map = None
#@var mult_cont_logger Local logger object
mult_cont_logger = None
#@var mult_cont_config Local copy of global configuration data
mult_cont_config = None

test_prio = {}

def test_set_init(config):
    """
    Set up function for basic test classes

    @param config The configuration dictionary; see oft
    """

    global mult_cont_port_map
    global mult_cont_logger
    global mult_cont_config

    mult_cont_logger = logging.getLogger("basic")
    mult_cont_logger.info("Initializing test set")
    mult_cont_port_map = config["port_map"]
    mult_cont_config = config

global current_generation_id 
current_generation_id = 1

def get_new_generation_id():
    global current_generation_id
    current_generation_id += 1
    return current_generation_id

class MultiProtocol(unittest.TestCase):
    """
    Root class for setting up the controller
    """

    def sig_handler(self, v1, v2):
        mult_cont_logger.critical("Received interrupt signal; exiting")
        print "Received interrupt signal; exiting"
        self.clean_shutdown = False
        self.tearDown()
        sys.exit(1)

    def setUp(self):
        self.logger = mult_cont_logger
        self.config = mult_cont_config
        #signal.signal(signal.SIGINT, self.sig_handler)
        mult_cont_logger.info("** START TEST CASE " + str(self))
        self.controller = controller.Controller(
            host=mult_cont_config["controller_host"],
            port=mult_cont_config["controller_port"])
        self.controller.generation_id = 1
        self.controller_sec = controller.Controller(
            host=mult_cont_config["controller_slave_host"],
            port=mult_cont_config["controller_slave_port"])
        self.controller_sec.generation_id = 2
        # clean_shutdown should be set to False to force quit app
        self.clean_shutdown = True
        self.controller.start()
        self.controller_sec.start()
        #@todo Add an option to wait for a pkt transaction to ensure version
        # compatibilty?
        self.controller.connect(timeout=20)
        self.controller_sec.connect(timeout=20)
        if not self.controller.active or not self.controller_sec.active:
            print "Controller startup failed; exiting"
            sys.exit(1)
        mult_cont_logger.info("Connected " + str(self.controller.switch_addr))

    def tearDown(self):
        mult_cont_logger.info("** END TEST CASE " + str(self))
        self.controller.shutdown()
        self.controller_sec.shutdown()
        #@todo Review if join should be done on clean_shutdown
        if self.clean_shutdown:
            self.controller.join()
            self.controller_sec.join()

    def runTest(self):
        # Just a simple sanity check as illustration
        mult_cont_logger.info("Running simple proto test")
        self.assertTrue(self.controller.switch_socket is not None,
                        str(self) + 'No connection to switch')

    def assertTrue(self, cond, msg):
        if not cond:
            mult_cont_logger.error("** FAILED ASSERTION: " + msg)
        unittest.TestCase.assertTrue(self, cond, msg)

test_prio["MultiProtocol"] = 1

def SendRoleRequest(self,controller,role = ofp.OFPCR_ROLE_NOCHANGE):
    request = message.role_request()
    request.generation_id = get_new_generation_id()
    request.role = role
    response, _ = controller.transact(request)
    self.assertEqual(response.header.type, ofp.OFPT_ROLE_REPLY,
                 'response is not role_reply')
    return response

class RoleRequest(MultiProtocol):
    """
    Role request message with both controllers
    """
    def runTest(self):

        response = SendRoleRequest(self,self.controller)
        response = SendRoleRequest(self,self.controller_sec)


class RoleRequestMaster(MultiProtocol):
    """
    Role request message with both controllers, alternating the master role between them.
    """
    def runTest(self):
        
        response = SendRoleRequest(self,self.controller, ofp.OFPCR_ROLE_MASTER)
        self.assertEqual(response.role, ofp.OFPCR_ROLE_MASTER,
                     'response\'s role is not Master')

        response = SendRoleRequest(self,self.controller_sec, ofp.OFPCR_ROLE_NOCHANGE)
        self.assertTrue((response.role != ofp.OFPCR_ROLE_MASTER),
                     'response\'s role is Master')

        response = SendRoleRequest(self,self.controller_sec, ofp.OFPCR_ROLE_MASTER)
        self.assertEqual(response.role, ofp.OFPCR_ROLE_MASTER,
                     'response\'s role is not Master')
        
        response = SendRoleRequest(self,self.controller, ofp.OFPCR_ROLE_NOCHANGE)
        self.assertEqual(response.role, ofp.OFPCR_ROLE_SLAVE,
                     'response\'s role is not Slave')

        response = SendRoleRequest(self,self.controller_sec, ofp.OFPCR_ROLE_NOCHANGE)
        self.assertEqual(response.role, ofp.OFPCR_ROLE_MASTER,
                     'response\'s role is not Master')

class EqualRoleMsgs(MultiProtocol):
    """

    """
    def runTest(self):
        of_ports = mult_cont_port_map.keys()
        response = SendRoleRequest(self,self.controller, ofp.OFPCR_ROLE_EQUAL)
        response = SendRoleRequest(self,self.controller_sec, ofp.OFPCR_ROLE_EQUAL)

        request = message.flow_mod()
        request.match.type = ofp.OFPMT_OXM
        port = match.in_port(of_ports[0])
        request.match_fields.tlvs.append(port)
        act = action.action_output()
        act.port = of_ports[2]
        inst = instruction.instruction_apply_actions()
        inst.actions.add(act)
        request.instructions.add(inst)
        request.buffer_id = 0xffffffff
        rv = self.controller.message_send(request)
        self.assertTrue(rv != -1, "Error installing flow mod")

        rc = testutils.delete_all_flows(self.controller_sec, mult_cont_logger)
        self.assertEqual(rc, 0, "Failed to delete all flows")
    

if __name__ == "__main__":
    print "Please run through oft script:  ./oft --test_spec=multiple_controller"
