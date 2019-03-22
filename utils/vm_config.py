#!/usr/bin/python
#///////////////////////////////////////////////////////////////////////////////
# * vm_config.py
# *
# * Source release: R0
# * Target release: R1
#///////////////////////////////////////////////////////////////////////////////
'''
Created on Aug 13, 2017
@author: Jimin Hu

vm functions
'''
import time
from pyVim import vm
from pyVmomi import Vim
from miscutils import wait_for_task
from constants import *
import re
import logging
global logger
logger = logging.getLogger(__name__)

def remove_virtualcdrom_with_iso(iso_file_name=None, target_vm=None):
    '''
    remove a VirtualCdrom device with the specified iso media file name
    :param file_name:
    :param target_vm:
    '''
    logger.info("Looking for VirtualCdrom with iso image %s"%(iso_file_name))
    the_device = None
    for device in target_vm.config.hardware.device:
        if isinstance(device, Vim.Vm.Device.VirtualCdrom):
            logger.info(device.deviceInfo.summary)
            if iso_file_name in device.deviceInfo.summary:
                logger.info("Found VirtualCdrom with iso image %s"%(iso_file_name))
                the_device = device
                break
    if the_device is None:
        logger.info("Failed finding VirtualCdrom with iso image %s"%(iso_file_name))
        return
    logger.info("Deleting VirtualCdrom with iso image %s"%(iso_file_name))
    spec  = Vim.VirtualDeviceConfigSpec(
        operation = 'remove',
        device = the_device)
    device_change = []
    device_change.append(spec)
    vm_config_spec = Vim.Vm.ConfigSpec(deviceChange=device_change)
    task = target_vm.ReconfigVM_Task(vm_config_spec)
    wait_for_task(task, "RemovingVirtualCdrom")
    logger.info("Successfully deleted VirtualCdrom with iso image %s"%(iso_file_name))
    return

def add_virtualcdrom_with_iso(file_name=None, datastore=None, target_vm=None):
    try:
        vm_name = target_vm.summary.config.name
        logger.info("Adding VirtualCdrom with iso image %s under datastore %s to vm %s"%(
            file_name, datastore, vm_name))
        cdrom = Vim.Vm.Device.VirtualCdrom()
        dev_backing_info = Vim.Vm.Device.VirtualCdrom.IsoBackingInfo()
        dev_backing_info.fileName = '[{}] {}'.format(datastore, file_name)
        cdrom.SetBacking(dev_backing_info)
        connect_info = Vim.Vm.Device.VirtualDevice.ConnectInfo()
        connect_info.SetStartConnected(True)
        connect_info.SetAllowGuestControl(True)
        connect_info.SetConnected(True)
        cdrom.SetConnectable(connect_info)

        ctrls = []
        for device in target_vm.config.hardware.device:
            if isinstance(device, Vim.Vm.Device.VirtualIDEController):
                ctrls.append(device)
                break
        if len(ctrls) == 0:
            logger.warn("Failed finding VirtualIDEController to mount the virtualcdrom. Trying AHCI controller.")
            for device in target_vm.config.hardware.device:
                if isinstance(device, Vim.Vm.Device.VirtualAHCIController):
                    ctrls.append(device)
                    break
        if len(ctrls) == 0:
            logger.error("Failed finding any controller device for the virtualcdrom.")
            return
        cdrom.SetControllerKey(ctrls[0].GetKey())
        conf_spec = Vim.VirtualDeviceConfigSpec(
            operation='add',
            device=cdrom
        )
        device_change = []
        device_change.append(conf_spec)
        vm_conf_spec = Vim.Vm.ConfigSpec(deviceChange=device_change)
        task = target_vm.ReconfigVM_Task(vm_conf_spec)
        wait_for_task(task, "AddingVirtualCdrom")
        logger.info("Successfully added VirtualCdrom with iso image %s under datastore %s to vm %s"%(
            file_name, datastore, vm_name))

    except Exception as ex:
        logger.error(ex.message)
        raise
    return

def power_on_and_wait_for_ip(target_vm):
    '''
    Powering on target virtual machine and wait for its ip
    :param target_vm:
    '''
    try:
        if target_vm.runtime.powerState == VM_POWER_STATE_ON:
            logger.info("VM %s already powered on." % target_vm.name)
            return
        logger.info("Powering on VM.")
        vm.PowerOn(target_vm)
        logger.info("VM is powered on and waiting for its ip.")
        maxWait = WAIT_FOR_IP_MAX_WAITING_TIMES * WAIT_FOR_IP_MAX_WAITING_PERIOD_IN_SECONDS
        startTime = time.time()
        ip = target_vm.guest.ipAddress
        while not ip and int(time.time() - startTime) < maxWait:
            time.sleep(WAIT_FOR_IP_SLEEP_IN_SECONDS)
            ip = target_vm.guest.ipAddress
        if not ip:
            logger.error("VM failed getting ip address after powering on.")
            return
        logger.info("Successfully powered on VM and its ip is %s"%(ip))
    except Exception as ex:
        raise