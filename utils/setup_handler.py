"""
Created on Aug 1, 2017

@author: hjimin

Upgrade manager execute available scripts sequentially
# assumed file hierarchy
# scripts tree /opt/vmware/relese_upgrade/files/scripts/track#/
# scripts input spec /opt/vmware/relese_upgrade/files/scripts/data/
# execution tree /opt/vmware/relese_upgrade/files/run/specified_dir_name
"""

import inspect
import json
import logging
import os
import subprocess
import sys
import traceback
from collections import OrderedDict

current_dir = os.path.dirname(
    os.path.abspath(inspect.getfile(inspect.currentframe())))
parent_dir = os.path.dirname(current_dir)
sys.path.insert(0, parent_dir)
files_dir = os.path.dirname(parent_dir)

from utils.log import Log
from utils.miscutils import check_file_and_load_data, display, run_local_sh_cmd

_logger = logging.getLogger(__name__)

# upgrade directory created by support engineer
input_spec_dir = files_dir + "/scripts/data/"
shared_data="/shared_data"


def update_orchestration_step_status(step_name):
    try:
        f = open(steps_status_file, "r")
        steps_info = json.load(f, object_pairs_hook=OrderedDict)
        f.close()
        for step in steps_info.items():
            if step[0] == step_name:
                step[1]['isCompleted'] = 'True'
                break
        f = open(steps_status_file, "w+")
        f.write(json.dumps(steps_info, ensure_ascii=False, indent=4))
        f.close()
    except Exception as ex:
        _logger.error(ex.message)
        raise

def get_json_specs(spec_name):
    """
    Find the json spec for the script under ./data folder
    """
    for f in os.listdir(working_directory):
        if spec_name == f:
            return working_directory + "/" + f
    msg = 'Json spec not found for spec : %s' % spec_name
    _logger.info(msg)
    raise Exception(msg)

def invoke_script(scripts_dir, script_name, spec_file, log_obj,
                  custom_options=None):
    """
    Method to execute remote script

    @param scripts_dir:
    @type scripts_dir:
    @param script_name:
    @type script_name:
    @param spec_file:
    @type spec_file:
    @param log_obj:
    @type log_obj:
    @param custom_options:
    @type custom_options:
    """
    try:
        log_obj.log.info("Invoking script : %s" % script_name)
        if not spec_file:
            msg = 'Possibly, %s does not require an input spec. ' % script_name
            msg += 'Replace json spec path with working directory.'
            log_obj.log.info(msg)
            json_spec = working_directory
        else:
            json_spec = get_json_specs("{}.json".format(spec_file))
        cmd = "python {script} -u {input} -w {workdir} -l {logPth} -o {out} " \
              "-i {invt_file}".format(script="{}.py".format(scripts_dir + "/" +
                                                            script_name),
                                      input=json_spec,
                                      workdir=working_directory,
                                      logPth=log_obj.logPath,
                                      out=working_directory,
                                      invt_file=inventory_file)
        if script_name == 'track2/s4-build-inventory':
            cmd = "python {script} -u {input} -w {workdir} -l {logPth} -o {out} ".format(
                script="{}.py".format(scripts_dir + "/" + script_name),
                input=json_spec,
                workdir=working_directory,
                logPth=log_obj.logPath,
                out=input_spec_dir)
        if custom_options:
            # Some scripts accepts different set of commands, In such cases
            # custom_options dict can be used to pass key/value pairs
            # and they will be appended to standard options
            for key, value in custom_options.items():
                prefix = '-'
                if len(key) > 1:
                    prefix = '--'
                cmd += ' {prefix}{key} {value}'.format(prefix=prefix, key=key,
                                                       value=value)

        log_obj.log.info("Command : %s" % cmd)
        proc = subprocess.Popen(cmd, shell=True, stdin = sys.stdin)
        proc.wait()
        rt = proc.returncode
        if rt != 0:
            msg = 'Return code %d ' % rt
            log_obj.log.error(msg)
            raise Exception(msg)
    except Exception as ex:
        msg = 'Script execution failed, refer logs for more details.'
        log_obj.log.error(msg)
        log_obj.log.error(ex)
        raise


def run_step(scripts_dir, script_name, file_spec, logger):
    try:
        script_full_path = os.path.join(scripts_dir + "/",
                                        "{}{}".format(script_name, ".py"))
        script = Script(script_full_path)
        script_args = dict()
        script_args['name'] = script.moduleName
        script_args['moduleName'] = script.moduleName
        script_args['shortName'] = script.shortName
        script_spec = file_spec + ".json"
        script_args['json_spec'] = get_json_specs(script_spec)
        script_args['inventory_spec'] = inventory_file
        script_args['output'] = working_directory
        process = UpgradeProcess(script_args, script, logger, working_directory)
        process.run()
        logger.debug("Pass: %s" % script.name)
    except Exception as ex:
        logger.error(traceback.format_exc())
        logger.error(ex)
        raise


def run_script_init(steps_list, script_name):
    """
    - create wroking directory under ../../run/specified_dir/ using script name
    i.e ../../run/specified_dir/run_setup_phase_1

    - setup logging
    initialize a log object, used accorss all scripts
    - define log file name for all child scripts

    - do the following only once
       - copy input.json files for all scripts it will execute into working
       directory, once
       - create a file orchestration_steps.json file in the working directory
    """
    logger = None
    try:
        """
        if working directory exists and the file exists, then setup
        has already been done.
        """
        script_name = script_name.split("/")[-1].split(".")[0]
        global working_directory, steps_status_file, inventory_file
        working_directory = os.getcwd() + "/" + script_name
        shared_data_dir = os.getcwd() + "/shared_data"
        steps_status_file = working_directory + "/orchestration_steps.json"

        if os.path.isdir(working_directory) and os.path.isfile(
                steps_status_file):
            logger = Log(filename="{}.log".format(script_name),
                         log_dir=working_directory, console_output=True)
            logger.log.info("setup is already done")
            upgrade_info = check_file_and_load_data(steps_status_file)
            inventory_file = input_spec_dir + "inventory.json"
            return (upgrade_info, logger, inventory_file, working_directory)

        """
        Initialize path varibles
        """
        if not os.path.isdir(working_directory):
            os.makedirs(working_directory)
            if not os.path.isdir(working_directory):
                display("Failed creating a working directory %s " % (
                working_directory))
                exit(1)
            if not os.path.isdir(shared_data_dir):
                os.makedirs(shared_data_dir)
                if not os.path.isdir(shared_data_dir):
                    display("Failed creating shared dir %s " % shared_data_dir)
                    exit(1)

        """
        Initialize log
        """
        logger = Log(filename="{}.log".format(script_name),
                     log_dir=working_directory, console_output=True)

        """
        Initialize steps status file
        """
        logger.log.info(
            "copy spec files from data directory to working directory.")
        steps_dict = {}
        for step in steps_list:
            if step['type'] != 'method' and len(step['file_spec']) > 0:
                file_spec = step['file_spec'] + ".json"
                cmd = "cp {} {}".format(input_spec_dir + "/" + file_spec,
                                        working_directory)
                (rt, out, err) = run_local_sh_cmd(cmd)
                if rt != 0:
                    err = "Failed %s return code %d out %s err %s " % (
                    cmd, rt, out, err)
                    raise Exception(err)
            steps_dict.update({'{}'.format(step['name']): {
                "isCompleted": 'False', "shouldSkip": 'False'}})
        (rt, out, err) = run_local_sh_cmd("touch %s" % (steps_status_file))
        if rt != 0:
            err = "Failed creating steps status file %s" % (steps_status_file)
            logger.log.error(err)
            raise Exception(err)
        with open(steps_status_file, "w") as of:
            json.dump(steps_dict, of, indent=4, sort_keys=True)
        logger.log.info("Finish dump steps into a json file.")
        upgrade_info = check_file_and_load_data(steps_status_file)
        inventory_file = input_spec_dir + "inventory.json"
        return (upgrade_info, logger, inventory_file, working_directory)
    except Exception as ex:
        if logger:
            logger.log.error(ex)
        else:
            _logger.error(ex)
        raise


class Script(object):

    def __init__(self, path):
        self.path = path

        if path:
            name = path.rsplit()[-1]
            name = name.lstrip(os.path.sep)
            self.name = name

            name = name.split('.')[0].replace(os.path.sep,'.')
            (before_scripts, scripts, after_scripts) = name.partition(base_folder)
            name = after_scripts[1:]
            self.moduleName = name

            if name.find('.') != -1:
                name = name.rsplit('.', 1)[-1]
            self.shortName = name


class RunArgs(object):

    def __init__(self, **kwargs):
        for attr in kwargs.keys():
            setattr(self, attr, kwargs[attr])


class UpgradeProcess(object):

    def __init__(self, script_args, metadata, log_obj, log_dir):
        self.script_args = script_args
        self.metadata = metadata
        self.modulename = self.script_args['moduleName']
        self.log_obj = log_obj
        self.logDir = log_dir

    def run(self):
        """
        import an upgrade script and execute it
        """
        name = self.metadata.moduleName
        short_name = self.metadata.shortName
        log = self.script_args['log'] = self.log_obj
        self.script_args['logDir'] = self.logDir
        _module = None
        try:
            log.debug('Importing %(module)s...', {'module': name})
            _module = __import__(name, globals(), locals(), [short_name], -1)
        except (SyntaxError, ImportError) as e:
            log.error(traceback.format_exc())
            log.error("Error import modules %(e)s", {'e': e})
            return
        args = RunArgs(**self.script_args)
        _module.Run(args)
