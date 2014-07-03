import os
import time
import ctypes
import logging
import multiprocessing
from volatility import session
from volatility import plugins
from volatility import utils

import messages
from messages import *
from abstracts import DetectorError
from config import Config
from service import Service
from utils import get_resource

log = logging.getLogger("detector")
log.propagate = 0
log.addHandler(logging.FileHandler(os.path.join(os.getcwd(), 'detector.log')))
log.setLevel(logging.INFO)

def scan(service_path, profile_name):
    # Initialize Volatility session and specify path to the winpmem service
    # and the detected profile name.
    sess = session.Session(filename=service_path, profile=profile_name)

    # Find Yara signatures, if file is not available, we need to terminate.
    yara_path = get_resource('signatures.yara')
    if not os.path.exists(yara_path):
        raise DetectorError("Unable to find signatures file!")

    # Load the yarascan plugin from Volatility. We pass it the index file which
    # is used to load the different rulesets.
    yara_plugin = sess.plugins.yarascan(yara_file=yara_path)

    print(messages.SCAN_STARTING)

    # This ia a list used to track which rule gets matched. I'm going to
    # store the details for each unique rule only.
    matched = []
    # Initialize memory scanner and loop through matches.
    for rule, address, _, value in yara_plugin.generate_hits(sess.physical_address_space):
        # If the current matched rule was not observed before, log detailed
        # information and a dump of memory in the proximity.
        if not rule in matched:
            # Add the name of the rule to the matched list.
            matched.append(rule)

            # Obtain proximity dump.
            context = sess.physical_address_space.zread(address-0x10, 0x40)

            rule_data = ''
            for offset, hexdata, translated_data in utils.Hexdump(context):
                rule_data += '{0} {1}\n'.format(hexdata, ''.join(translated_data))

            log.warning("Matched: %s [0x%.08x]: %s\n\n%s", rule, address, value, rule_data)

    print(messages.SCAN_FINISHED)

    # If any rule gets matched, we need to notify the user and instruct him
    # on how to proceed from here.
    if len(matched) > 0:
        critical(messages.INFECTION_FOUND)
    else:
        good(messages.NO_INFECTION_FOUND)

def main():
    multiprocessing.freeze_support()

    # Generate configuration values.
    cfg = Config()

    # Check if the computer is connected to the Internet or any other network.
    # We don't want the user to be connected while running the tool, both for
    # protecting their safety as well as our rules.
    if cfg.offline_check:
        if ctypes.windll.wininet.InternetGetConnectedState(None, None):
            warning(messages.ONLINE)
            if not dialog(messages.CONTINUE):
                return

    # Check if this is a supported version of Windows and if so, obtain the
    # volatility profile name.
    if not cfg.get_profile_name():
        error(messages.UNSUPPORTED_WINDOWS)
        return

    # Obtain the path to the driver to load. At this point, this check should
    # not fail, but you never know.
    if not cfg.get_driver_path():
        error(messages.NO_DRIVER)
        return

    log.info("Selected Driver: {0}".format(cfg.driver))
    log.info("Selected Profile Name: {0}".format(cfg.profile))

    # Initialize the winpmem service.
    try:
        service = Service(driver=cfg.driver, service=cfg.service_name)
        service.create()
        service.start()
    except DetectorError as e:
        log.critical(e)
        error(messages.SERVICE_NO_START)
        return
    else:
        log.info("Service started")

    # Launch the scanner.
    try:
        # This is so fucking annoying - I have to use multiprocessing because
        # for some reason yarascan does not close the handle to the device and
        # consequently I cannot stop and delete it.
        # As I don't want to leave traces on the system, I have to go this way.
        # However this doesn't allow me to do proper reporting of the results
        # as I can't easily pass data from one instance to the other.
        # TODO: fix this shit.
        scanner = multiprocessing.Process(target=scan, args=(cfg.service_path, cfg.profile))
        scanner.start()
        scanner.join()
    except DetectorError as e:
        log.critical(e)
        error(messages.SCAN_FAILED)
    else:
        log.info("Scanning finished")

    # Stop the winpmem service and unload the driver. At this point we should
    # have cleaned up everything left on the system.
    try:
        service.stop()
        service.delete()
    except DetectorError as e:
        log.critical(e)
        error(messages.SERVICE_NO_STOP)
        return
    else:
        log.info("Service stopped")

if __name__ == "__main__":
    # TODO: Add argparse options to download updated yara signatures?
    # How would they be downloaded into the packaged resources?
    # From where would they be downloaded?
    # Would we provide any sort of authentication?
    # Do we really want to have everyone access to updated signatures or
    # do we enable just specific API keys to do so?

    main()

    raw_input("Press enter to terminate...")
