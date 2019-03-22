# Description: Working With Viva70 Jenkins
# Group-physical-st: optional
# Timeout: 60000
from utils.log import Log
from utils.ssh_handler import run_cmd_over_ssh, SFTPManager
from utils.constants import *
from utils.miscutils import *
from utils.ssh_handler import establish_passwordless_ssh_between_two_servers
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


def easy_ssh_between_lin_jump_and_agent(logger=None, agent_ip=None, lin_jump=None):
    logger.info(
        "Adding Agent VM %s KEY into Lin Jump known hosts file." % agent_ip)
    cmd = "sshpass -p \'%s\' ssh %s@%s {} {}".format(AGENT_ROOT_PWD,
                                                     AGENT_DEFAULT_ROOT,
                                                     agent_ip,
                                                     SSH_KEYSCAN_COMMAND, agent_ip)
    logger.info("Scanning Agent VM SSH key on lin jump %s" % cmd)
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
        ssh_key_stdout, LIN_JUMP_KNOWN_HOSTS)
    logger.debug("Appending Agent SSH key to Lin Jump known hosts file.")
    (return_code, stdout, stderr) = run_cmd_over_ssh(cmd,
                                                     lin_jump,
                                                     LIN_JUMP_USR,
                                                     LIN_JUMP_PWD)
    if return_code != 0:
        err_msg = "Failed adding Agent SSH key into Lin jump known hosts file. Return Code %d Error %s"
        raise Exception(err_msg)
    logger.info("Finish adding Agent SSH key into Lin jump known hosts.")


def sftp_run_list_to_agent(logger=None, agent_ip=None, local_run_list=None, lin_jump=None):
    jump_vm_sftp = SFTPManager(jump_vm_ip, LIN_JUMP_USR, LIN_JUMP_PWD)
    jump_vm_sftp.initiate_sftp_session()
    jump_vm_sftp.put_remote_file(local_run_list, LIN_JUMP_RUNLIST_LOC)
    jump_vm_sftp.terminate_sftp_session()
    logger.info("Uploading runlist.json to lin jump %s " %
                LIN_JUMP_RUNLIST_LOC)

    cmd = "sshpass -p \'%s\' scp %s %s@%s:%s".format(AGENT_ROOT_PWD,
                                                     LIN_JUMP_RUNLIST_LOC,
                                                     AGENT_DEFAULT_ROOT,
                                                     agent_ip,
                                                     AGENT_RUN_LIST_LOC)
    logger.info("Copy runlist.json from lin jump to agent <%s>" % cmd)
    (return_code, stdout, stderr) = run_cmd_over_ssh(cmd,
                                                     lin_jump,
                                                     LIN_JUMP_USR,
                                                     LIN_JUMP_PWD)
    if return_code != 0:
        err_msg = "Failed copying runlist.json from lin jump to agent. Return Code %d Error %s"
        raise Exception(err_msg)
    logger.info("Finish copying runlist.json from lin jump to agent.")


def issue_start_cmd_to_agent(logger=None, agent_ip=None, lin_jump=None):
    cmd = "sshpass -p \'%s\' ssh %s@%s AgentLauncher -e -a" % (
        AGENT_ROOT_PWD, AGENT_DEFAULT_ROOT, agent_ip)
    (rt, out, err) = run_cmd_over_ssh(
        cmd, agent_ip, AGENT_DEFAULT_ROOT, AGENT_ROOT_PWD)
    if rt != 0:
        err_msg = "Failed executing agent command."
        logger.error(err_msg)
        raise Exception(err_msg)
    logger.info("Successfully start execution. out \n %s \n err %s " %
                (out, err))

def read_viva_setup():
    try:
        with open(VIVA_SETUP) as info_file:
            info_json = json.load(info_file)
    except IOError, e:
        errorMsg = "Failed opening %s because %s. Exit." % (
            VIVA_SETUP, e.message)
        raise Exception(errorMsg)
    return info_json

def Run():
    cur_dir = os.getcwd()
    logger = Log(filename="{}.log".format("deploy_agent_vm"),
                 log_dir=cur_dir, console_output=True)
    run_dir = "%s/%s" % (LOG_DIR, os.getenv("RUN_NAME"))
    testbed_info = check_file_and_load_data(
        "%s/%s" % (run_dir, SERVER_TESTBED_INFO))
    # read agent ip from a file
    # override runlist.json using 10.0.0.101 and 10.0.0.102
    agent_ip = ""
    jump_vm = testbed_info['genericVm'][0]['ip']
    easy_ssh(logger=logger.log, lin_jump=jump_vm, agent_ip=agent_ip)
    run_list = "%s/%s" % (cur_dir, AGENT_RUNLIST)
    easy_ssh_between_lin_jump_and_agent(
        logger=logger.log, agent_ip=agent_ip, lin_jump=jump_vm)
    sftp_run_list_to_agent(logger=logger.log, agent_ip=agent_ip,
                           local_run_list=run_list, lin_jump=jump_vm_ip)
    issue_start_cmd_to_agent(
        logger=logger.log, agent_ip=agent_ip, lin_jump=jump_vm)


if __name__ == "__main__":
    Run()