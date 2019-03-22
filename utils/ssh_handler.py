#!/usr/bin/python
# ///////////////////////////////////////////////////////////////////////////////
# * ssh_handler.py
# *
# Source release: 2.1.0
# Target release: 2.2.0
#
# * Notes:
#   some functionalities refer vpx pVim ssh class
# ///////////////////////////////////////////////////////////////////////////////
import sys
'''
@author: Jimin Hu
'''

import paramiko
import platform
import multiprocessing
from Queue import Empty
import os
from constants import *
import logging
import traceback
from miscutils import run_local_sh_cmd
_banner_timeout_in_seconds = 1800
time_out_in_seconds = 1800
establish_passwordless_timeout_in_seconds = 120
global logger
logger = logging.getLogger(__name__)
logger.setLevel(logging.INFO)
logFormatWithTimestamp = logging.Formatter('%(asctime)-15s '
                                           '%(levelname)-5.5s: '
                                           '%(message)s')
console_handler = logging.StreamHandler(sys.stdout)
console_handler.setFormatter(logFormatWithTimestamp)
logger.addHandler(console_handler)


class SSHProcess(multiprocessing.Process):
    """
    Process object that connects to a host and runs a command over ssh.
    """

    def __init__(self, cmd, host, user, pwd, timeout=time_out_in_seconds, queue=None, errQueue=None, xterm=False):
        multiprocessing.Process.__init__(self)
        self.cmd = cmd
        self.host = host
        self.user = user
        self.pwd = pwd
        self.ssh_timeout_in_seconds = timeout
        self.stdout_queue = queue
        self.errQueue = errQueue
        self.ssh = None
        self.cmd_return_code = multiprocessing.Value("i", -1)
        self.xterm = xterm

    def run(self):
        """
        Override multiprocessing.Process's run() method with our own that
        executes a command over ssh.
        """
        try:
            self.ssh = paramiko.SSHClient()
            assert (self.ssh)
            self.ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            self.ssh.connect(hostname=self.host, username=self.user,
                             password=self.pwd, timeout=self.ssh_timeout_in_seconds,
                             banner_timeout=_banner_timeout_in_seconds)
            if self.cmd:
                logger.debug("Trying to send the command %s to the server %s" % (
                    self.cmd, self.host))
                self._send_command()
        except KeyboardInterrupt as e:
            logger.exception(e.message)
            pass
        except (paramiko.SSHException, paramiko.AuthenticationException) as e:
            if self.errQueue:
                if isinstance(e, paramiko.BadAuthenticationType):
                    e = paramiko.AuthenticationException(e.__str__())

                self.errQueue.put(e)
        except Exception, e:
            if self.errQueue:
                self.errQueue.put(Exception("%r" % e))
        finally:
            self.ssh.close()
            self.stdout_queue.cancel_join_thread()
            self.errQueue.cancel_join_thread()

    def _send_command(self):
        """
        Send the command to the remote host.
        """
        if platform.system() == 'Windows' and self.xterm:
            chan = self.ssh._transport.open_session()
            chan.get_pty('xterm')
            chan.settimeout(self.ssh_timeout_in_seconds)

            chan.exec_command(self.cmd)
            chan.makefile('wb', -1)
            stdout = chan.makefile('rb', -1)
            stderr = chan.makefile_stderr('rb', -1)
        else:
            (stdin, stdout, stderr) = self.ssh.exec_command(self.cmd)
        stdout_text = stdout.read().strip()
        stderr_text = stderr.read().strip()
        self.cmd_return_code.value = stdout.channel.recv_exit_status()
        if self.stdout_queue:
            self.stdout_queue.put(stdout_text)
        if self.errQueue:
            self.errQueue.put(stderr_text)


def run_cmd_over_ssh(cmd, host=None, user=None, pwd=None,
                     timeout=time_out_in_seconds, xterm=False, realRc=True,
                     log_stdout=False):
    """
    Wrapper for SSHProcess() to run a single command.
    :param cmd:
    :param host:
    :param user:
    :param pwd:
    :param timeout:
    :param xterm:
    :param realRc:
    :param log_stdout:
    :return:
    """
    logger.info('User: %s' % user)
    logger.info('server: %s' % host)
    logger.info('Executing command : %s' % cmd)
    stdout_queue = multiprocessing.Queue()
    err_queue = multiprocessing.Queue()
    process = SSHProcess(cmd, host=host, user=user, pwd=pwd, timeout=timeout,
                         queue=stdout_queue, errQueue=err_queue, xterm=xterm)
    try:
        process.start()
        try:
            err = err_queue.get(True, timeout)
            if isinstance(err, Exception):
                raise err
            else:
                stderr = err
        except Empty:
            stderr = None

        try:
            stdout = stdout_queue.get(True, timeout)
        except Empty:
            stdout = None
        process.join(timeout)
    finally:
        if process.is_alive():
            process.terminate()
    if realRc:
        rc = process.cmd_return_code.value
    else:
        rc = process.exitcode
    logger.debug('rc: %s' % rc)
    if log_stdout:
        logger.debug('stdout: %s' % str(stdout))
        logger.debug('Stderr: %s' % str(stderr))
    return rc, stdout, stderr


class SFTPManager:
    """
    Manages remote file operations over ssh.
    """

    def __init__(self, host, user, pwd, timeout_in_seconds=time_out_in_seconds, queue=None,
                 err_queue=None, ssh_key_file=None):
        self.host = host
        self.user = user
        self.pwd = pwd
        self.ssh_timeout = timeout_in_seconds
        self.stdout_queue = queue
        self.err_queue = err_queue
        self.ssh = None
        self.sftp = None
        self.ssh_key_file = ssh_key_file

    def initiate_sftp_session(self):
        """
        Initiates SSH session with host and opens up a SFTP client for use
        with file operations
        """
        try:
            self.ssh = paramiko.SSHClient()
            self.ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            if self.ssh_key_file:
                paramiko.RSAKey.from_private_key_file(self.ssh_key_file)
                self.ssh.connect(hostname=self.host, username=self.user,
                                 timeout=self.ssh_timeout, banner_timeout=120)
            else:
                self.ssh.connect(hostname=self.host, username=self.user,
                                 password=self.pwd, timeout=self.ssh_timeout,
                                 banner_timeout=time_out_in_seconds)
            self.sftp = self.ssh.open_sftp()
        except KeyboardInterrupt:
            pass
        except (paramiko.SSHException, paramiko.AuthenticationException) as e:
            if self.err_queue:
                self.err_queue.put(e)

    def get_remote_file(self, remote_path, local_path):
        """Gets the remote file in the local_path specified"""
        try:
            if self.sftp:
                self.sftp.get(remote_path, local_path)
        except Exception as e:
            if self.err_queue:
                self.err_queue.put(e)

    def terminate_sftp_session(self):
        """Closes the SFTP session and the associated SSH session"""
        if self.sftp is not None:
            self.sftp.close()
        if self.ssh is not None:
            self.ssh.close()
        self.sftp = None
        self.ssh = None

    def put_remote_file(self, local_path, remote_path):
        """Copies a local file to the remote_path specified"""
        try:
            if self.sftp:
                self.sftp.put(local_path, remote_path)
        except Exception as e:
            if self.err_queue:
                self.err_queue.put(e)

    def list_remote_dir(self, path):
        """Lists the contents of remote directory"""
        remote_file_list = []
        if self.sftp:
            remote_file_list = self.sftp.listdir(path)
        return remote_file_list


def compute_remote_file_checksum(bundle_name, remote_file_path, remote_ip, remote_user, remote_pwd):
    md5_file = "bundle_md5.txt"
    remote_md5 = remote_file_path + "/" + md5_file
    command = "touch %s" % (remote_md5)
    (return_code, stdout, stderr) = run_cmd_over_ssh(
        command, remote_ip, remote_user, remote_pwd)
    logger.info(" return code %d out %s err %s " %
                (return_code, stdout, stderr))
    if return_code != 0:
        err = "Failed composing md5 file remotely."
        raise Exception(err)
    remote_file_path = remote_file_path + "/" + bundle_name
    command = "md5sum {} 2>&1 | tee {} > /dev/null ".format(
        remote_file_path, remote_md5)
    logger.info("Computing checksum for remote file %s " % remote_file_path)
    (return_code, stdout, stderr) = run_cmd_over_ssh(
        command, remote_ip, remote_user, remote_pwd)
    cwd = os.getcwd()
    local_file = cwd + "/" + md5_file
    sftp = SFTPManager(remote_ip, remote_user, remote_pwd)
    sftp.initiate_sftp_session()
    sftp.get_remote_file(remote_md5, local_file)
    try:
        file = open(local_file, "r+")
        data = file.read()
        file.close()
        cksum = data.split(" ")[0]
        logger.info("local cksum file content <%s>" % cksum)
        return cksum
    except Exception as ex:
        logger.error(ex.message)
        raise


def establish_passwordless_ssh_between_two_servers(id_rsa_pub_data, server, user, password):
    """
    Add id_rsa.pub on destination server /root/.ssh/authorized_keys
    Also add remote host ESCDSA finger print into local /root/.ssh/known_hosts 

    here is an example of the pompts:
    The authenticity of host '10.1.0.251 (10.1.0.251)' can't be established.
    ECDSA key fingerprint is SHA256:tfaXV8tKaHh8xy1VTET5k1QcVlcPIvkuXzIUWz0CO9I.

    Are you sure you want to continue connecting (yes/no)? yes
    And an ECDSA finger print format
    ecdsa finger print format
    192.168.100.108 ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBIahnrQItzXysEyGhLLlnE0rhLSfYk6gusxd1trnKUJHUrWwfFQxdfiCZogkCuxphdr0+7ziS27CF1Uwsov6sLE=

    120 seconds timeout is handling unreachable IP
    @param client:
    @type client:
    @param server:
    @type server:
    """
    try:
        logger.info("Adding id_rsa.pub to server %s." % server)
        command = "echo \"{}\" >> {}".format(
            id_rsa_pub_data, ROOT_USER_SSH_AUTHORIZED_KEYS_FILE_NAME)
        (return_code, stdout, stderr) = run_cmd_over_ssh(command, server,
                                                         user, password, establish_passwordless_timeout_in_seconds)
        if return_code != 0:
            err_msg = "Failed adding SSH key to %s. Return Code %d. Error Message %s" % (
                server, return_code, stderr)
            logger.error(err_msg)
            raise Exception(err_msg)
        elif len(stderr):
            err_msg = "Failed adding SSH key to %s. Error %s" % (
                server, stderr)
            logger.error(err_msg)
            raise Exception(err_msg)
        cmd = "{} {}".format(SSH_KEYSCAN_ECDSA_KEY, server)
        logger.debug("server %s key scan command %s" % (server, cmd))
        (return_code, stdout, stderr) = run_cmd_over_ssh(cmd, server,
                                                         user, password, establish_passwordless_timeout_in_seconds)
        if return_code != 0:
            err_msg = "Failed scanning server %s ecdsa finger print. Return code %d Error %s" % (
                server, return_code, stderr)
            logger.error(err_msg)
            raise Exception(err_msg)
        if len(stdout) == 0 or not ("ecdsa" in stdout):
            err = "invalid ecdsa finger print"
            logger.error(err)
            raise Exception(err)
        logger.debug("Getting server %s ecdsa key return code %d stdout {%s} stderr {%s}" % (
            server, return_code, stdout, stderr))
        cmd = " echo \"{}\" >> {} ".format(
            stdout, ROOT_USER_KNOWN_HOSTS_FILE_NAME)
        (return_code, stdout, stderr) = run_local_sh_cmd(cmd)
        if return_code != 0:
            err_msg = "Failed adding server %s in known hosts file. Return Code %d Error %s" % (
                server, return_code, stderr)
            logger.error(err_msg)
            raise Exception(err_msg)
        logger.debug("Successfully added local host into %s authorized keys. Also, add server %s into local known hosts." % (
            server, server))
    except Exception as ex:
        logger.error(ex.message)
        logger.error(traceback.format_exc())
        raise Exception
