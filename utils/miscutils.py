#!/usr/bin/python
# ///////////////////////////////////////////////////////////////////////////////
# * miscutils.py
# *
# Source release: 2.1.0
# Target release: 2.2.0
#
# Notes:
# *     file containing general purpose routines
# ///////////////////////////////////////////////////////////////////////////////
'''
@author: Jimin Hu
'''
import fileinput
import json
import logging
import os
import re
import socket
import subprocess
import sys
import time
import traceback
from _socket import SHUT_RDWR
import requests
from requests.exceptions import HTTPError
from requests.exceptions import ReadTimeout
from collections import OrderedDict

from pyVmomi import vim

from constants import *

mydict = {"!": "%21", "@": "%40", "#": "%23", "$": "%24", "%": "%25", "^": "%5E",
          "&": "%26", "*": "%2A", "(": "%28", ")": "%29", "+": "%2B", "-": "%2D"}

global logger
logger = logging.getLogger(__name__)


def wait_for_task(task, actionName='job', hideResult=False):
    logger.info("Waiting for %s %s " %
                (task.info.descriptionId, task.info.key))
    version, state = None, None
    # Loop looking for updates till the state moves to a completed state.
    while state not in (vim.TaskInfo.State.success, vim.TaskInfo.State.error):
        try:
            time.sleep(3)
            state = task.info.state
        except vmodl.fault.ManagedObjectNotFound as e:
            logger.error("Task object has been deleted: %s" % e.obj)
            break

    if state == "error":
        logger.error("Task reported error: " + str(task.info.error))
        raise task.info.error

    return state


def check_file_and_load_data(json_file_name):
    assert(json_file_name)
    if not os.path.isfile(json_file_name):
        errorMsg = "Configuration file %s is missed from input. Exit." % json_file_name
        logger.error(errorMsg)
        raise Exception(errorMsg)
    logger.info("Loading json from '{0}'...".format(json_file_name))
    try:
        with open(json_file_name) as info_file:
            info_json = json.load(info_file)
    except IOError, e:
        errorMsg = "Failed opening %s because %s. Exit." % (
            json_file_name, e.message)
        logger.error(errorMsg)
        raise Exception(errorMsg)
    return info_json


def load_host_credential(vcenter_credentials=None, host_ip=None):
    for host in vcenter_credentials[HOSTS]:
        if host[HOST_IP_IN_VCENTER] == host_ip:
            return host
    return


def load_vm_credential(vcenter_credentials=None, vm_ip=None):
    for vm in vcenter_credentials[VMS]:
        if vm[VM_IP] == vm_ip:
            return vm
    return


def load_credentials(ips=None, inventory_file=None):
    """
    "" inventory_file includes system ips and their credentials
    "" enumerating the ips in .json file
    "" for each ip
    ""   if it is a vcenter, searching its matching in "vcs" within r0_upgrade_inventory.json
    ""   if it is a host, searching its matching in "hosts" within r0_upgrade_inventory.json
    ""   if it is a vm, searching its matching in "vms" within r0_upgrade_inventory.json
    ""
    ""  need change credential searching algorithm when "r0_upgrade_inventory" file format is changed
    """
    credentials = []
    try:
        logger.debug("Trying to load inventory file %s." % (inventory_file))
        info_json = check_file_and_load_data(inventory_file)
        assert(info_json)
        for item in ips:
            one_vcenter = {}
            one_vcenter_hosts = []
            one_vcenter_vms = []
            try:
                logger.info("Finding credentials vcenter %s" %
                            (item[VCENTER_IP]))
                vcenters = [vc_credential for vc_credential in info_json[VCENTERS]
                            if vc_credential[VCENTER_IP] == item[VCENTER_IP]]
                if vcenters is None or isinstance(vcenters, list) and len(vcenters) == 0:
                    logger.error("Failed finding vcenter %s credentials. Go to next vcenter." % (
                        item[VCENTER_IP]))
                    continue
                one_vcenter = vcenters[0]
                logger.info(
                    "Found vcenter %s credential from inventory." % (item[VCENTER_IP]))
            except (KeyError, Exception) as ex:
                logger.exception(ex)
                raise
            try:
                if HOSTS not in item or item[HOSTS] is None or isinstance(item[HOSTS], list) and len(item[HOSTS]) == 0:
                    logger.info("No hosts configured under vcenter %s." %
                                (item[VCENTER_IP]))
                else:
                    for host in item[HOSTS]:
                        host_credentials = [host_credential for host_credential in info_json[HOSTS]
                                            if host_credential[HOST_IP_IN_VCENTER] == host[HOST_IP_IN_VCENTER]]
                        if host_credentials == None or isinstance(host_credentials, list) and len(host_credentials) == 0:
                            logger.info("Failed finding host %s credential under vcenter %s." % (
                                host[HOST_IP_IN_VCENTER], item[VCENTER_IP]))
                            continue
                        one_vcenter_hosts.append(host_credentials[0])
                        logger.info("Found host %s credential under vcenter %s." % (
                            host[HOST_IP_IN_VCENTER], item[VCENTER_IP]))
                    one_vcenter[HOSTS] = one_vcenter_hosts
                    logger.info(
                        "Finish searching hosts credentials under vcenter %s" % (item[VCENTER_IP]))
            except (KeyError, Exception) as ex:
                logger.exception(ex.message)
                credentials.append(one_vcenter)
                pass
            try:
                if VMS not in item or item[VMS] is None or isinstance(item[VMS], list) and len(item[VMS]) == 0:
                    logger.info("No vms configured under vcenter %s." %
                                (item[VCENTER_IP]))
                else:
                    for vm in item[VMS]:
                        vm_credentials = [
                            vm_credential for vm_credential in info_json[VMS] if vm_credential[VM_IP] == vm[VM_IP]]
                        if vm_credentials == None or isinstance(vm_credentials, list) and len(vm_credentials) == 0:
                            logger.info("Failed finding vm % credentials under vcenter %s. Go to next vm." % (
                                vm[VM_IP], item[VCENTER_IP]))
                            continue
                        logger.info("Found vm % credentials under vcenter %s." % (
                            vm[VM_IP], item[VCENTER_IP]))
                        one_vcenter_vms.append(vm_credentials[0])
                    one_vcenter[VMS] = one_vcenter_vms
                credentials.append(one_vcenter)
            except (KeyError, Exception), ex:
                logger.exception(ex.message)
                credentials.append(one_vcenter)
                pass
    except (IOError, AssertionError), ex:
        logger.error(ex.message)
        raise
    return credentials


def is_ip_valid(ip_address=None):
    try:
        socket.inet_aton(ip_address)
    except socket.error:
        logger.error("%s is invalid ip." % (ip_address))
        raise

def run_local_sh_cmd(cmd, cwd=None):
    ps = subprocess.Popen(cmd, shell=True, stdin=subprocess.PIPE,
                          stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                          close_fds=True, cwd=cwd, bufsize=-1)
    out = ''
    err = ''
    while True:
        line = ps.stdout.readline()
        if not line:
            break
        out += line
    while True:
        line = ps.stderr.readline()
        if not line:
            break
        err += line
    status = ps.wait()
    return status, out, err

# def run_local_sh_cmd(cmd, cwd=None):
#     ps = subprocess.Popen(cmd, shell=True, stdin=None,
#                           stdout=None, stderr=None,
#                           close_fds=True, cwd=cwd, bufsize=-1)
#     (result, error) = ps.communicate()
#     return result, error

def escape_special_symbols(str):
    for chr in str:
        if chr in SYMBOLS:
            return "\"" + str + "\""
    return str


def compute_local_file_checksum(local_file_path=None):
    command = "md5sum {}".format(local_file_path)
    logger.debug(
        "Computing local file checksum using command  %s " % (command))
    (return_code, stdout, stderr) = run_local_sh_cmd(command)
    if return_code != 0:
        error_message = "Failed Computing checksum for file %s. return code %d " % (
            local_file_path, return_code)
        raise Exception(error_message)
    elif stderr is not None and len(stderr) > 0:
        error_message = "Failed Computing checksum for  file %s. error message %s " % (
            local_file_path, stderr)
        raise Exception(error_message)
    return stdout.split(" ")[0]


def deploy_ovas_using_ovftool(vi_target_datastore, vm_name, ova_file_path,
                              vi_usr, vi_pwd, vi_host, vi_file_location,
                              ovf_tool_path):
    """
    Using ovftool deploy ova files.
    - OVFTOOL could not specify password and ip addresses on the ovas
    - Appliances are deployed to vcenter cluster
    @param vm_name:
    @type vm_name:
    @param ova_file_path:
    @type ova_file_path:
    """
    command = "./ovftool --X:injectOvfEnv --noSSLVerify --skipManifestCheck --diskMode=thin --acceptAllEulas \
--datastore={} --name={} {} vi://{}:{}@{}{}".format(
        vi_target_datastore, vm_name, ova_file_path, vi_usr, vi_pwd, vi_host, vi_file_location)
    logger.info("Deploying command  %s" % command)
    proc = subprocess.Popen(command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                            cwd=ovf_tool_path)
    (stdout, stderr) = proc.communicate()
    while proc.poll() is None:
        time.sleep(DEPLOYMENT_WAITING_PERIOD_IN_SECONDS)
    logger.info("vm %s deployment is done. stdout %s stderr %s" %
                (vm_name, stdout, stderr))
    if proc.returncode != 0:
        error_message = "Failed deploying vm %s .return code %d. error message %s "
        error_message = error_message % (vm_name, proc.returncode, stderr)
        logger.error(error_message)
        raise Exception(error_message)
    elif stderr is not None and len(stderr):
        error_message = "Failed deploying vm %s . error message %d" % (
            vm_name, stderr)
        logger.error(error_message)
        raise Exception(error_message)
    logger.info("Successfully deployed vm %s " % (vm_name))


def check_file_exists(file_path):
    if not os.path.isfile(file_path):
        errorMsg = "File %s does not exist." % file_path
        raise Exception(errorMsg)
    return


def update_ini_file_using_dict_entries(prop_file, dict_entry):
    """
    updating prop file using values from dict_entry
    each entry (key, value pair) in dict_entry
    if key exists, update using new value
    if key does not exist, add the key, value into the propr file
    @param prop_file_name:
    @type prop_file_name:
    @param dict_entry:
    @type dict_entry:
    """
    logger.info("Update property file %s " % (prop_file))
    for key in dict_entry:
        found_key = False
        value = dict_entry[key]
        if ' ' in dict_entry[key]:
            value = '"%s"' % (dict_entry[key])
        for line in fileinput.input(prop_file, inplace=1):
            if not line.lstrip(' ').startswith('#') and '=' in line:
                var = str(line.split('=')[0].rstrip(' '))
                old_set = str(line.split('=')[0].lstrip(' ').rstrip())
                if found_key == False and var.rstrip(' ') == key:
                    found_key = True
                    logger.info("Updating key %s with new value %s " %
                                (key, value))
                    line = "%s=%s\n" % (key, value)
            sys.stdout.write(line)
        if not found_key:
            logger.info("Adding key %s value %s " % (key, value))
            try:
                with open(prop_file, "a") as f:
                    f.write("%s=%s\n" % (key, value))
            except Exception as ex:
                logger.error(traceback.format_exc())
                logger.error(ex.message)
                raise
    logger.info("Finish Update property file %s " % (prop_file))


def display(msg, new_line=True, erase_line=True):
    if erase_line:
        msg = '\r%s' % msg
    if new_line:
        print msg
    elif sys.stdout.isatty():
        sys.stdout.write(msg)
        sys.stdout.flush()


def update_json_status(jsonf_file, key_list):
    if len(key_list) == 0:
        return
    json_file = open(jsonf_file, "r+")
    data = json.load(json_file, object_pairs_hook=OrderedDict)
    json_file.close()
    if len(key_list) == 1:
        data['{}'.format(key_list[0])]['status'] = 'completed'
    if len(key_list) == 2:
        data['{}'.format(key_list[0])]['{}'.format(
            key_list[1])]['status'] = 'completed'
    if len(key_list) == 3:
        data['{}'.format(key_list[0])]['{}'.format(key_list[1])
                                       ]['{}'.format(key_list[2])]['status'] = 'completed'
    json_file = open(jsonf_file, "w+")
    json_file.write(json.dumps(data, ensure_ascii=False, indent=4))
    json_file.close()


def is_host_reachable(host, timeout=60, ping_count=4, ping_timeout=100):
    """
      Is host reachable
        :param host: Host to check
        :type host: str
        :param timeout: Time period to wait
        :type timeout: int
        :param ping_count: Ping count, default 4
        :type ping_count: int
        :param ping_timeout: Timeout for ping, default 100
        :type ping_timeout: int
        :return: True if reachable
        :rtype: bool
        """
    elapsed_time = 0
    start_time = time.time()
    SLEEP_TIME = 10
    while elapsed_time < timeout:
        if ping_device(host, ping_count, ping_timeout):
            logger.info("Host %s is reachable." % host)
            return True
        elapsed_time = time.time() - start_time
        logger.info("Host %s is unreachable in %s seconds, sleep additional %d seconds" %
                    (host, int(elapsed_time), SLEEP_TIME))
        time.sleep(SLEEP_TIME)
    return False


def ping_device(host, ping_count=4, timeout=100):
    """
    Ping a given device
    :param host: Host ip to ping
    :type host: str
    :param ping_count: How many ping count, default 4
    :type ping_count: int
    :param timeout: Ping timeout, default 100
    :type timeout: int
    :return: True on if host can be reachable, else False
    :rtype: bool
    """
    ping_response = subprocess.Popen(["/bin/ping", "-c%d" % ping_count, "-w%d" % timeout, host],
                                     stdout=subprocess.PIPE).stdout.read()
    logger.info("Ping response is %s" % ping_response)
    if ping_response.find(' 0% packet loss') > 0:
        logger.info("Host %s is reachable" % host)
        return True
    else:
        logger.info("Host %s is not reachable" % host)
        return False


class FakeSecHead(object):
    def __init__(self, fp):
        self.fp = fp
        self.sechead = '[asection]\n'

    def readline(self):
        if self.sechead:
            try:
                return self.sechead
            finally:
                self.sechead = None
        else:
            return self.fp.readline()


def start_local_process(cmd, cwd=None):
    ps = subprocess.Popen(cmd, shell=True, stdin=subprocess.PIPE,
                          stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                          close_fds=True, cwd=cwd)
    return ps


def persist_data_in_file(json_data, json_file_name):
    assert (json_file_name)
    try:
        with open(json_file_name, "w") as f:
            json.dump(json_data, f)
    except IOError, e:
        errorMsg = "Failed opening %s because %s. Exit." % (
            json_file_name, e.message)
        logger.error(errorMsg)
        sys.exit(1)


def is_true(value):
    """
    Method to check if the value is true
    :param value:
    :return: True if extra args has true or yes or 1, else False
    :rtype: bool
    """
    return bool(re.search('true|yes|1', str(value), re.I))


def get_credential(device, device_info, log, cred_type='SSH'):
    try:
        for t, cred in device_info[CREDENTIALS].items():
            if t != cred_type:
                continue
            for k, v in cred.items():
                return k, v
    except Exception as ex:
        log.error(ex)
        log.error(traceback.format_exc())
    raise Exception('%s credentials not found for %s!' % (cred_type, device))


def is_sshable(host, log):
    """
    Method to check if a host reachable through SSH
    :param host:
    :param log:
    :return:
    """
    status = False
    client_socket = None
    try:
        client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        client_socket.settimeout(30)
        client_socket.connect((host, 22))
        status = True
        log.info('SSH enabled on host %s' % host)
    except Exception as e:
        log.warning(e)
        log.warning('Unable to SSH to host %s' % host)
    finally:
        try:
            client_socket.shutdown(SHUT_RDWR)
            client_socket.close()
        except:
            pass
        return status


def _is_target_line(line, keywords_list):
    for key in keywords_list:
        if key not in line:
            return False
    return True


def append_or_update_entry_in_a_file(file, keywords_list, update_entry, logger):
    """
    if entry with keyword already exists, update its value
    otherwise, append the entry to the file
    @param file:
    @type file:
    @param keyword:
    @type keyword:
    @param update_entry:
    @type update_entry:
    @param logger:
    @type logger:
    """
    try:
        if not os.path.isfile(file):
            err_msg = "Failed finding file %s" % (file)
            logger.error(err_msg)
            raise Exception(err_msg)
        update = False
        for line in fileinput.input(file, inplace=1):
            if not update and _is_target_line(line, keywords_list):
                line = update_entry
                update = True
            sys.stdout.write(line)
        if not update:
            logger.info("%s does not exist. append to the end of %s." %
                        (update_entry, file))
            with open(file, "a") as f:
                f.write("{}".format(update_entry))
        else:
            logger.info("%s already in %s. updating it " %
                        (update_entry, file))
        logger.info("Finish updating %s in file %s." % (update_entry, file))
    except Exception as ex:
        logger.error(ex)
        raise


def confirm(prompt=None, resp=False, logger=None):
    if not prompt:
        prompt = "Confirm"
    if resp:
        prompt = "%s [%s] %s :" % (prompt, "y", "n")
    else:
        prompt = "%s [%s] %s :" % (prompt, "n", "y")
    while True:
        ans = raw_input(prompt)
        if not ans:
            return resp
        if ans not in ["y", "Y", "n", "N"]:
            logger.info("please enter y or n.")
            continue
        if ans == "y" or ans == "Y":
            return True
        if ans == "n" or ans == "N":
            return False


def mk_local_dir(dir, logger):
    logger.info("Trying to create dir %s" % dir)
    if os.path.exists(dir):
        (rt, out, err) = run_local_sh_cmd("rm -rf %s* " % dir)
        if rt != 0:
            err_msg = "Failed deleting existing local dir %s. return code %s err %s"
            err_msg = err_msg % (dir, rt, err)
            logger.error(err_msg)
            raise Exception(err_msg)
    (rt, out, err) = run_local_sh_cmd("mkdir -p %s " % dir)
    if rt != 0:
        err_msg = "Failed creating local dir %s return code %d err %s"
        err_msg = err_msg % (dir, rt, err)
        logger.error(err_msg)
        raise Exception(err_msg)
    if not os.path.exists(dir):
        err_msg = "directory %s does not exist." % dir
        raise Exception(err_msg)


def open_ssh_tunnel(_cassandra_ips, _cassandra_port, sddc_manager_ip, logger):
    _process = None
    try:
        logger.info("Opening connection to SDDC Manager VM")
        # TODO: Support timeout using the
        # check_output after verifying it is supported.
        _command = "ssh -L {0}:{1}:{2} root@{3}".format(_cassandra_port,
                                                        _cassandra_ips,
                                                        _cassandra_port,
                                                        sddc_manager_ip)
        '''if os.environ['DEVTEST'] is not None and os.environ['DEVTEST'] == 'true':
            logger.debug('Running in dev mode')
            _command = 'echo ' + _command'''
        logger.debug("Using command: %s", _command)
        _process = subprocess.Popen(_command, shell=True,
                                    stdin=subprocess.PIPE,
                                    stderr=subprocess.PIPE,
                                    stdout=subprocess.PIPE,
                                    close_fds=True)
        '''stdoutdata, stderrdata = _process.communicate()
        logger.debug("Process output for SSH")
        logger.debug(stdoutdata)
        logger.error("Process error for SSH")
        logger.error(stderrdata)
        logger.info("Opening connection to resulted in: %s", _process.returncode)
        if _process.returncode != 0:
            logger.error("Running command returned non zero exit code")
            raise ValueError'''
        time.sleep(WAIT_TIME_FOR_CASSANDRA_SSH_TUNNEL_IN_SECONDS)
        return _process
    except Exception:
        logger.exception("Failed to open SSH tunnel")
        if _process is not None:
            try:
                _process.kill()
            except Exception as e:
                logger.warn(
                    "Killing the SSH process raised exception: " + e.message)
        raise


def switch_vc_from_appliance_shell_to_bash_shell(vc_ip=None, vc_root_usr=None, vc_root_pwd=None, logger=None):
    """
    @param vc_ip:
    @type vc_ip:
    @param vc_root_usr:
    @type vc_root_usr:
    @param vc_root_pwd:
    @type vc_root_pwd:
    @param logger:
    @type logger:
    """
    ssh_cmd_model = "sshpass -p '%s' ssh -o StrictHostKeyChecking=no %s@%s %s"
    logger.info("Trying to swtich vcenter from appliance shell to bash shell.")
    ssh_cmd = ssh_cmd_model % (
        vc_root_pwd, vc_root_usr, vc_ip, "shell.set --enabled true")
    logger.info("Executing enable command %s." % ssh_cmd)
    pc = subprocess.Popen(ssh_cmd, shell=True, stdin=subprocess.PIPE,
                          stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    (out, err) = pc.communicate()
    rt = pc.returncode
    logger.info("Enable command return code %d out %s err %s " %
                (rt, out, err))

    ssh_cmd = ssh_cmd_model % (
        vc_root_pwd, vc_root_usr, vc_ip, "\"shell > /dev/null;chsh -s /bin/bash root\"")
    logger.info("Switching shell and persist the change command %s." % ssh_cmd)
    pc = subprocess.Popen(ssh_cmd, shell=True, stdin=subprocess.PIPE,
                          stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    (out, err) = pc.communicate()
    rt = pc.returncode
    logger.info(
        "Switching shell and persist the change command return code %d out %s err %s " % (rt, out, err))

    ssh_cmd = ssh_cmd_model % (
        vc_root_pwd, vc_root_usr, vc_ip, "ls -alt /root")
    logger.info("Verifying bash shell %s" % ssh_cmd)
    pc = subprocess.Popen(ssh_cmd, shell=True, stdin=subprocess.PIPE,
                          stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    (out, err) = pc.communicate()
    rt = pc.returncode
    if "Unknown command" in out:
        err_msg = "Failed switching from Appliance shell to bash shell. return code %d out %s err %s " % (
            rt, out, err)
        logger.error(err_msg)
        raise Exception(err_msg)
    logger.info(
        "Successfully switching vm %s from appliance shell to bash shell verifying out %s. " % (vc_ip, out))


def rest_api_client_post(url, data, headers=None, status_code=200, is_json=True,
                         status_code_exception=True, timeout=300, log_text=True, logger=None, **kwargs):
    """
    Specifically for upgrade NSX Manager Components Status change Rest API
    """
    if not headers:
        headers = {}
    if is_json and data:
        data = json.dumps(data)
        if 'Content-Type' not in headers:
            headers['Content-Type'] = 'application/json'
    i = 0
    while True:
        try:
            req = requests.post(url, verify=False, proxies={},
                                headers=headers,
                                timeout=timeout, **kwargs)
            if status_code_exception and req.status_code != status_code:
                if status_code_exception and (500 <= req.status_code < 600):
                    req.raise_for_status()
            break
        except requests.exceptions.SSLError as ex:
            logger.error(ex)
            url = re.sub('https://', 'http://', url)
            i += 1
            if i >= 3:
                raise
        except (requests.ConnectionError, ReadTimeout,
                requests.TooManyRedirects, requests.Timeout,
                HTTPError) as ex:
            i += 1
            if i >= 3:
                raise
            logger.error(ex)
    else:
        raise AssertionError('POST request failed')
    if status_code_exception and req.status_code != status_code:
        raise AssertionError(req.reason)
    return req


def vcenterPwdASCII(password):
    arr = []
    # Create a an array and inititate it with the special characters present in password
    for x in mydict.keys():
        for i in password:
            if i == x:
                arr.append(i)
    # parse array and replace the these characters in password with the corresponding ASCII values
    for special in arr:
        password = password.replace(special, mydict[special])
        arr.remove(special)
    return password