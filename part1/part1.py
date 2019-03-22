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
root_dir = files_dir+"/"+"viva70continue"
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
        self.SetOption('net:\"VM Network\"', '\"%s\"' % network)

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
        self.log.info('Running command %s' % command)
        rt, out, err = run_local_sh_cmd(command)
        return rt, out, err


def easy_ssh_agent(logger=None, agent_ip=None):
    logger.info("Adding Agent VM SSH KEY into local known hosts file.")
    cmd = "{} {}".format(SSH_KEYSCAN_COMMAND, agent_ip)
    logger.info("Scanning Agent VM SSH key command %s" % cmd)
    (return_code, ssh_key_stdout, stderr) = run_cmd_over_ssh(
        cmd,
        agent_ip,
        AGENT_DEFAULT_ROOT,
        AGENT_ROOT_PWD)
    if return_code != 0 or len(ssh_key_stdout) == 0 or "ssh-rsa" not in ssh_key_stdout:
        err_msg = "Failed getting Agent VM SSH key ssh key. Return code %d Error %s" % (
            return_code, stderr)
        logger.error(err_msg)
        raise Exception(err_msg)

    logger.info("Execution stdout {%s} " % ssh_key_stdout)
    cmd = " echo \"{}\" >> {} ".format(
        ssh_key_stdout, AGENT_KNOWN_HOSTS_FILE_NAME)
    logger.debug("Appending Agent VM SSH key to local known hosts file.")
    (return_code, stdout, stderr) = run_local_sh_cmd(cmd)
    if return_code != 0:
        err_msg = "Failed adding Agent VM SSH entry in local known hosts file. Return Code %d Error %s"
        err_msg = err_msg % (return_code, stderr)
        logger.error(err_msg)
        raise Exception(err_msg)
    logger.info("Finish adding Agent VM SSH KEY into local known hosts file.")


def sftp_run_list_to_agent(agent_ip=None, local_run_list=None):
    agentVM_sftp = SFTPManager(agent_ip, AGENT_DEFAULT_ROOT, AGENT_ROOT_PWD)
    agentVM_sftp.initiate_sftp_session()
    agentVM_sftp.put_remote_file(local_run_list, AGENT_RUN_LIST_LOC)
    agentVM_sftp.terminate_sftp_session()


def issue_start_cmd_to_agent(logger=None, agent_ip=None):
    cmd = "AgentLauncher -e -a"
    (rt, out, err) = run_cmd_over_ssh(
        cmd, agent_ip, AGENT_DEFAULT_ROOT, AGENT_ROOT_PWD)
    if rt != 0:
        err_msg = "Failed executing agent command."
        logger.error(err_msg)
        raise Exception(err_msg)
    logger.info("Successfully start execution. out \n %s \n err %s " %
                (out, err))


def fetch_result_file(logger=None, agent_ip=None, run_list=None):
    # read session/runUuid from runlist.json
    info_json = check_file_and_load_data(run_list)
    session_id = info_json["session"]["uuid"]
    run_uuid = info_json["session"]["runUuid"]
    results_file = "%s/%s/%s/%s" % (AGENT_EXE_RES,
                                    session_id, run_uuid, AGENT_EXE_RES_JSON)
    agentvm_sftp = SFTPManager(agent_ip, AGENT_DEFAULT_ROOT, AGENT_ROOT_PWD)
    agentvm_sftp.initiate_sftp_session()
    cur_dir = os.getcwd()
    loc = "%s/%s" % (cur_dir, AGENT_EXE_RES_JSON)
    agentvm_sftp.get_remote_file(results_file, loc)
    agentvm_sftp.terminate_sftp_session()
    return


def Run():
    cur_dir = os.getcwd()
    logger = Log(filename="{}.log".format("part1.py"),
                 log_dir=cur_dir, console_output=True)
    vc_ip = os.getenv('HOST_IP')
    vc_username = os.getenv('HOST_USER')
    vc_password = os.getenv('HOST_PWD')
    if vc_password is None:
        vc_password = ""
    vc_password = vcenterPwdASCII(vc_password)

    logger.log.info('target host %s user %s pwd %s ' %
                    (vc_ip, vc_username, vc_password))
    vm_name = os.getenv('VM_NAME')

    logger.log.info('to be installed vm %s from ova %s' %
                    (vm_name, AGENT_OVA_PATH))
    ovfTool = OVFToolDeployment(Log=logger.log,
                                username=vc_username,
                                targetHost=vc_ip,
                                password=vc_password,
                                filename=AGENT_OVA_PATH,
                                defaults=True)
    ovfTool.SetOption("name", vm_name)
    ovfTool.SetNetwork(os.getenv('VM_NETWORK'))
    ovfTool.SetDatastore(os.getenv("DATA_STORE"))

    rt, out, err = ovfTool.Deploy()
    # one bug, Error failed to get caught
    if rt != 0:
        result = 'Fail'
        logger.log.info('Failed deploying AgentVM for %s ' % err)
    else:
        print "out <%s>" % out
        print "err <%s>" % err
        for ss in out.split("\n"):
            if "Received IP address" in ss:
                res = ss.strip()
            if "Completed with errors" in ss:
                raise Exception("Failed in deploying agent VM.")
        if not res:
            raise Exception("Failed in getting agent VM IP address.")
        agent_ip = re.findall(r'[0-9]+(?:\.[0-9]+){3}', res)
        agent_ip = agent_ip[0]
        logger.log.info('Newly deployed AgentVM ip %s ' % agent_ip)
        run_list = "%s/%s" % (cur_dir, AGENT_RUNLIST)
        easy_ssh_agent(logger=logger.log, agent_ip=agent_ip)
        sftp_run_list_to_agent(agent_ip=agent_ip, local_run_list=run_list)
        issue_start_cmd_to_agent(logger=logger.log, agent_ip=agent_ip)
        fetch_result_file(logger=logger.log,
                          agent_ip=agent_ip, run_list=run_list)


if __name__ == "__main__":
    Run()
