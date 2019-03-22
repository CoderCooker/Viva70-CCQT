# Description: Working With NSX-T Install
# Description: Working With Viva70 Jenkins
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
root_dir = files_dir+"/"+"Viva70-CCQT"
sys.path.insert(0, root_dir)


def Run():
    cur_dir = os.getcwd()
    logger = Log(filename="{}.log".format("deploy_testbed"),
                 log_dir=cur_dir, console_output=True)
    # deploy three ESXi Hosts,
    run_dir = "%s/%s" % (LOG_DIR, os.getenv("RUN_NAME"))
    command = "mkdir -p %s; chmod -R 777 %s" % (run_dir, run_dir)
    rt, out, err = run_local_sh_cmd(command)
    if rt != 0:
        raise Exception("Failed generating run dir.")

    deploy_cmd = "%s --testbedSpecJsonFile %s --resultsDir %s --runName %s --esxBuild %s " % (
        TESTBED_DEPLOYMENT_BASECMD, SERVER_TESTBED_LOC, run_dir, os.getenv("RUN_NAME"), os.getenv("ESX_BUILD"))
    logger.log.info("TestBed Deployment <%s> " % (deploy_cmd))
    rt, out, err = run_local_sh_cmd(deploy_cmd)
    if rt != 0:
        raise Exception("Failed deploy test bed.")
    logger.log.info("Successfully deployed testBed " % (deploy_cmd))


if __name__ == "__main__":
    Run()