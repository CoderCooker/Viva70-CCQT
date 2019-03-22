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

def Run():
    cur_dir = os.getcwd()
    args = Log(filename="{}.log".format(os.path.basename(__file__)),
                 log_dir=cur_dir, console_output=True)
    args.log.info("start deploy build to esx.")
    cmd = "pwd"
    rt, out, err = run_local_sh_cmd(cmd)
    args.log.info("need figure out a path again %s %s %s ." % (rt, out, err))
    args.log.info("end of deploy build to esx.")

if __name__ == "__main__":
    Run()
    