import os
import time
import logging
import volatility.conf as conf
import volatility.registry as registry
import volatility.commands as commands
import volatility.addrspace as addrspace
import volatility.utils as utils
import volatility.plugins.malware.malfind as malfind

import messages
from messages import *
from abstracts import DetectorError
from config import Config
from service import Service
from utils import get_resource

log = logging.getLogger('detector')
log.propagate = 0
fh = logging.FileHandler(os.path.join(os.getcwd(), 'detector.log'))
sh = logging.StreamHandler()
formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
fh.setFormatter(formatter)
sh.setFormatter(formatter)
log.addHandler(fh)
log.addHandler(sh)
log.setLevel(logging.INFO)

def get_address_space(service_path, profile, yara_path):
    log.info("Obtaining address space and generating config for volatility")

    registry.PluginImporter()
    config = conf.ConfObject()

    registry.register_global_options(config, commands.Command)
    registry.register_global_options(config, addrspace.BaseAddressSpace)

    config.parse_options()
    config.PROFILE = profile
    config.LOCATION = service_path
    config.YARA_FILE = yara_path

    return utils.load_as(config)

def scan(service_path, profile_name, queue_results):
    # Find Yara signatures, if file is not available, we need to terminate.
    yara_path = os.path.join(os.getcwd(), 'signatures.yar')
    if not os.path.exists(yara_path):
        yara_path = get_resource(os.path.join('rules', 'signatures.yar'))
        if not os.path.exists(yara_path):
            raise DetectorError("Unable to find a valid Yara signatures file!")

    log.info("Selected Yara signature file at %s", yara_path)

    space = get_address_space(service_path, profile_name, yara_path)
    yara = malfind.YaraScan(space.get_config())

    matched = []
    for o, address, hit, value in yara.calculate():
        if not o:
            continue
        elif o.obj_name == '_EPROCESS':
            # If the PID is of the current process, it's a false positive.
            # It just detected the Yara signatures in memory. Skip.
            if int(o.UniqueProcessId) == int(os.getpid()):
                continue

            if not hit.rule in matched:
                matched.append(hit.rule)
                pid = o.UniqueProcessId
                ppid = o.InheritedFromUniqueProcessId

                log.warning("Matched: %s PID: %s, PPID: %s, Address: %s, Value: %s",
                            hit.rule, pid, ppid, address, value)

                queue_results.put({'rule' : hit.rule, 'pid' : pid, 'ppid' : ppid,
                                   'address': address, 'value' : value})

    # Close handle to address space object.
    #space.close()

    # If any rule gets matched, we need to notify the user and instruct him
    # on how to proceed from here.
    if len(matched) > 0:
        return True
    else:
        return False

def main(queue_results, queue_errors):
    # Generate configuration values.
    cfg = Config()

    # Check if this is a supported version of Windows and if so, obtain the
    # volatility profile name.
    if not cfg.get_profile_name():
        log.error("Unsupported version of Windows, can't select a profile")
        queue_errors.put(messages.UNSUPPORTED_WINDOWS)
        return

    log.info("Selected Profile Name: {0}".format(cfg.profile))

    # Obtain the path to the driver to load. At this point, this check should
    # not fail, but you never know.
    if not cfg.get_driver_path():
        log.error("Unable to find a proper winpmem driver")
        queue_errors.put(messages.NO_DRIVER)
        return

    log.info("Selected Driver: {0}".format(cfg.driver))

    # Initialize the winpmem service.
    try:
        service = Service(driver=cfg.driver, service=cfg.service_name)
        service.create()
        service.start()
    except DetectorError as e:
        log.critical("Unable to start winpmem service: %s", e)
        queue_errors.put(messages.SERVICE_NO_START)
        return
    else:
        log.info("Service started")

    # Launch the scanner.
    try:
        log.info("Starting yara scanner...")
        scan(cfg.service_path, cfg.profile, queue_results)
    except DetectorError as e:
        log.critical("Yara scanning failed: %s", e)
        queue_errors.put(messages.SCAN_FAILED)
    else:
        log.info("Scanning finished")

    # Stop the winpmem service and unload the driver. At this point we should
    # have cleaned up everything left on the system.
    try:
        service.stop()
        service.delete()
    except DetectorError as e:
        log.critical("Unable to stop winpmem service: %s", e)
        queue_errors.put(messages.SERVICE_NO_STOP)
    else:
        log.info("Service stopped")

    log.info("Analysis finished")

if __name__ == '__main__':
    from Queue import Queue
    results = Queue()
    errors = Queue()
    main(results, errors)
