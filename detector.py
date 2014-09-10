# Copyright (C) 2014 Claudio Guarnieri.
# This file is part of Detekt - https://github.com/botherder/detekt
# See the file 'LICENSE' for copying permission.

import os
import time
import logging
import threading
import volatility.conf as conf
import volatility.registry as registry
import volatility.commands as commands
import volatility.addrspace as addrspace
import volatility.utils as utils
import volatility.plugins.malware.malfind as malfind
from win32com.shell import shell

import messages
from messages import *
from abstracts import DetectorError
from config import Config
from service import Service, destroy
from utils import get_resource

# Reduce noise from Volatility.
logging.getLogger('volatility.obj').setLevel(logging.ERROR)
logging.getLogger('volatility.utils').setLevel(logging.ERROR)

# Configure logging for our main application.
log = logging.getLogger('detector')
log.propagate = 0
fh = logging.FileHandler(os.path.join(os.getcwd(), 'detector.log'))
sh = logging.StreamHandler()
formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
fh.setFormatter(formatter)
sh.setFormatter(formatter)
log.addHandler(fh)
log.addHandler(sh)
log.setLevel(logging.DEBUG)

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

    # Retrieve adress space.
    space = get_address_space(service_path, profile_name, yara_path)
    # Initialize Volatility's YaraScan module.
    yara = malfind.YaraScan(space.get_config())

    log.info("Starting yara scanner...")

    matched = []
    for o, address, hit, value in yara.calculate():
        if not o:
            owner = 'Unknown Kernel Memory'
        elif o.obj_name == '_EPROCESS':
            # If the PID is of the current process, it's a false positive.
            # It just detected the Yara signatures in memory. Skip.
            if int(o.UniqueProcessId) == int(os.getpid()):
                continue

            # Skip also if it's a child process.
            if int(o.InheritedFromUniqueProcessId) == int(os.getpid()):
                continue

            owner = 'Process {0} (pid: {1})'.format(o.ImageFileName, o.UniqueProcessId)
        else:
            owner = '{0}'.format(o.BaseDllName)

        # Extract hexdump of the memory chunk that matched the signature.
        rule_data = ''
        for offset, hexdata, translated_data in utils.Hexdump(value):
            rule_data += '{0} {1}\n'.format(hexdata, ''.join(translated_data))

        log.warning("%s matched: %s at address: 0x%X, Value:\n\n%s",
                    owner, hit.rule, address, rule_data)

        if not hit.rule in matched:
            # Add the rule to the list of matched rules, so we don't have
            # useless repetitions.
            matched.append(hit.rule)

            queue_results.put(dict(
                rule=hit.rule,
                detection=hit.meta.get('detection'),
                description=hit.meta.get('description'),
            ))

def main(queue_results, queue_errors):
    log.info("Starting with process ID %d", os.getpid())

    # Check if the user is an Administrator.
    # If not, quit with an error message.
    if not shell.IsUserAnAdmin():
        log.error("The user is not an Administrator, aborting")
        queue_errors.put(messages.NOT_AN_ADMIN)
        return

    # Generate configuration values.
    cfg = Config()

    # Check if this is a supported version of Windows and if so, obtain the
    # volatility profile name.
    cfg.get_profile_name()
    if not cfg.profile:
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

    # This is the ugliest black magic ever, but somehow helps.
    # Just tries to brutally destroy the winpmem service if there is one
    # lying around before trying to launch a new one again.
    destroyer = threading.Thread(target=destroy, args=(cfg.driver, cfg.service_name))
    destroyer.start()
    destroyer.join()

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
        log.error("Unable to stop winpmem service: %s", e)
    else:
        log.info("Service stopped")

    log.info("Analysis finished")

if __name__ == '__main__':
    from Queue import Queue
    results = Queue()
    errors = Queue()
    main(results, errors)
