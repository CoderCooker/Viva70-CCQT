# Description: Working With Viva70 Jenkins
# Group-physical-st: optional
# Timeout: 60000
import sys
import os
import inspect
import re

cur_dir = os.path.dirname(os.path.abspath(
    inspect.getfile(inspect.currentframe())))
par_dir = os.path.dirname(cur_dir)
files_dir = os.path.dirname(par_dir)
root_dir = files_dir+"/"+"Viva70-CCQT"
sys.path.insert(0, root_dir)

from utils.log import Log
from utils.ssh_handler import run_cmd_over_ssh, SFTPManager
from utils.constants import *
from utils.miscutils import *
from utils.ssh_handler import establish_passwordless_ssh_between_two_servers

class OVFToolDeployment(object):
    """OVF/OVA deployment using ovftool"""

    def __init__(self, Log=None,
                 username=None,
                 password="",
                 filename=None,
                 targetHost=None,
                 defaults=True):

        assert targetHost, "No target provided"
        assert username, "No username provided"

        if defaults:
            self.options = {
                'skipManifestCheck': None,
                'powerOn': None,
                'disableVerification': None,
                'allowExtraConfig': None,
                'noSSLVerify': None,
                'acceptAllEulas': None,
                'overwrite': None,
                'X:waitForIp': None,
                'X:skipContentLength': None,
                'X:injectOvfEnv': None,
                'ipAllocationPolicy': 'fixedPolicy'
            }
            self.properties = {}
        else:
            self.options = {}

        self.SetTarget(
            '%s/' % targetHost)
        self.SetUsername(username)
        self.SetPassword(password)
        self.ovftoolBinary = '/usr/bin/ovftool'
        self.filename = filename
        if Log:
            self.log = Log

    def SetOption(self, key, value):
        """Set an option that will be passed to the ovftool"""
        self.options[key] = value

    def SetProperty(self, prop, value):
        """Set an property that will be passed to the ovftool"""
        self.properties[prop] = value

    def SetIpAllocationPolicy(self, ipAllocationPolicy):
        raise NotImplementedError

    def SetIpProtocol(self, ipProtocol):
        raise NotImplementedError

    def SetDiskMode(self, diskMode):
        raise NotImplementedError

    def SetNetwork(self, network):
        self.SetOption('net:\\"VM Network\\"', '\\"%s\\"' % network)

    def SetDatastore(self, datastore):
        self.SetOption('datastore', datastore)

    def SetUsername(self, username):
        """Set the username used for the target login."""
        self.username = username

    def SetPassword(self, password):
        """Set the password used for the target login."""
        self.password = password

    def SetTarget(self, targetHost):
        """Set the target for this deployment."""
        self.targetHost = targetHost

    def GetTarget(self):
        """Get the target used for this deployment"""
        assert self.targetHost, "Need target"
        assert self.username, "Need username"

        return 'vi://%s:%s@%s' % (self.username, self.password, self.targetHost)

    def Deploy(self):
        command = [self.ovftoolBinary]

        options = []
        for key, value in self.options.iteritems():
            if value:
                options += ['--%s=%s' % (key, value)]
            else:
                options += ['--%s' % key]

        for key, value in self.properties.iteritems():
            if value:
                options += ['--prop:%s=%s' % (key, value)]
            else:
                options += ['--prop:%s' % key]

        command += options + [self.filename, self.GetTarget()]

        command = "%s" % " ".join(command)
        self.log.info('Deploy Agent VM command <%s>' % command)
        return command


def easy_ssh(logger=None, lin_jump=None):
    logger.info("Adding Lin jump %s KEY into local known hosts file." % lin_jump)
    cmd = "{} {}".format(SSH_KEYSCAN_COMMAND, lin_jump)
    logger.info("Scanning Lin jump SSH key command %s" % cmd)
    (return_code, ssh_key_stdout, stderr) = run_cmd_over_ssh(
        cmd,
        lin_jump,
        LIN_JUMP_USR,
        LIN_JUMP_PWD)
    if return_code != 0 or len(ssh_key_stdout) == 0 or "ssh-rsa" not in ssh_key_stdout:
        err_msg = "Failed getting Lin jump SSH key ssh key. Return code %d Error %s" % (
            return_code, stderr)
        raise Exception(err_msg)

    logger.info("Execution stdout {%s} " % ssh_key_stdout)
    cmd = " echo \"{}\" >> {} ".format(
        ssh_key_stdout, AGENT_KNOWN_HOSTS_FILE_NAME)
    logger.debug("Appending Lin jump SSH key to local known hosts file.")
    (return_code, stdout, stderr) = run_local_sh_cmd(cmd)
    if return_code != 0:
        err_msg = "Failed adding Lin jump SSH entry in local known hosts file. Return Code %d Error %s"
        err_msg = err_msg % (return_code, stderr)
        raise Exception(err_msg)
    logger.info("Finish adding Lin jump SSH KEY into local known hosts file.")

def dump_viva_setup(setup):
    with open("%s" % VIVA_SETUP, 'w') as outfile:
        json.dump(setup, outfile)

def Run():
    cur_dir = os.getcwd()
    logger = Log(filename="{}.log".format("deploy_agent_vm"),
                 log_dir=cur_dir, console_output=True)
    run_dir = "%s/%s" % (LOG_DIR, DEFAULT_RUN_NAME)
    testbed_info = check_file_and_load_data(
        "%s/%s" % (run_dir, SERVER_TESTBED_INFO))
    # read host information from testbedInfo.json and update runlist.json
    # deploy AgentVM to one ESXi
    # use the other two as test bed
    jump_vm_ip = testbed_info['genericVm'][0]['ip']
    #easy_ssh(logger=logger.log, lin_jump=jump_vm_ip

    logger.log.info('to be installed vm %s from ova %s' %
                    (AGENT_VM_NAME, AGENT_OVA_PATH))
    ovfTool = OVFToolDeployment(Log=logger.log,
                                username=AGENT_HOST_USR,
                                targetHost=AGENT_HOST_IP,
                                password=AGENT_HOST_PWD,
                                filename=AGENT_OVA_PATH,
                                defaults=True)
    ovfTool.SetOption("name", AGENT_VM_NAME)
    ovfTool.SetNetwork(AGENT_NETWORK)
    ovfTool.SetDatastore(AGENT_DATASTORE)

    cmd = ovfTool.Deploy()
    #cmd = "sshpass -p \'%s\' ssh %s@%s %s" % (LIN_JUMP_PWD, LIN_JUMP_USR, jump_vm_ip, cmd)
    cmd = "sshpass -p \'%s\' ssh %s@%s ovftool" % (LIN_JUMP_PWD, LIN_JUMP_USR, jump_vm_ip)
    logger.log.info('Deploy Agent VM command <%s>' % cmd)
    (rt, out, err) = run_local_sh_cmd(cmd)
    logger.log.info("%s %s %s " % (rt, out, err))
#     if rt != 0:
#         result = 'Fail'
#         logger.log.info('Failed deploying AgentVM  %s ' % out)
#     else:
#         logger.log.info("out <%s>" % out)
#         logger.log.info("err <%s>" % err)
#         res = None
#         for ss in out.split("\n"):
#             if "Received IP address" in ss:
#                 res = ss.strip()
#             if "Completed with errors" in ss:
#                 raise Exception("Failed in deploying agent VM.")
#         if not res:
#             raise Exception("Failed in getting agent VM IP address.")
#         agent_ip = re.findall(r'[0-9]+(?:\.[0-9]+){3}', res)
#         agent_ip = agent_ip[0]
#         logger.log.info('Newly deployed AgentVM ip %s ' % agent_ip)
#         viva_setup = {"agent_ip": agent_ip}
#         dump_viva_setup(viva_setup)

if __name__ == "__main__":
    Run()