# Copyright (C) 2014 Claudio Guarnieri.
# This file is part of Detekt - https://github.com/botherder/detekt
# See the file 'LICENSE' for copying permission.

import os
import time
import yara
import logging
import threading

import messages
from abstracts import DetectorError
from config import Config
from service import Service, destroy
from memory import Memory
from utils import get_resource

# Configure logging for our main application.
log = logging.getLogger('detector')
log.propagate = 0
fh = logging.FileHandler(os.path.join(os.getcwd(), 'detector.log'))
sh = logging.StreamHandler()
formatter = logging.Formatter('%(asctime)s [%(name)s] %(levelname)s: %(message)s')
fh.setFormatter(formatter)
sh.setFormatter(formatter)
log.addHandler(fh)
log.addHandler(sh)
log.setLevel(logging.DEBUG)

# Turn off to remove debug features.
DEBUG = True

def scan(queue_results):
    # Find Yara signatures, if file is not available, we need to terminate.
    yara_path = os.path.join(os.getcwd(), 'signatures.yar')
    if not os.path.exists(yara_path):
        yara_path = get_resource(os.path.join('rules', 'signatures.yar'))
        if not os.path.exists(yara_path):
            raise DetectorError("Unable to find a valid Yara signatures file!")

    log.info("Selected Yara signature file at %s", yara_path)

    # Compile Yara signatures.
    rules = yara.compile(yara_path)
    # Instantiate memory crawler.
    memory = Memory()

    counter = 1
    matched = []
    # Perform a Yara scan on each chunk of memory that is retrieved from
    # the memory ranges crawler.
    for data in memory.get_memory_chunks():
        # If debug is enabled, dump the matched rule
        if DEBUG:
            if not os.path.exists('segments'):
                os.makedirs('segments')

            with open(os.path.join('segments', 'segment_{0}.bin'.format(counter)), 'wb') as dump:
                dump.write(data)

        # For each Yara signature that is matched...
        for hit in rules.match(data=data):
            log.debug("Matched: %s, in segment #%d", hit.rule, counter)

            # We only store unique results, it's pointless to store results
            # for the same rule.
            if not hit.rule in matched:
                # Add rule to the list of unique matches.
                matched.append(hit.rule)

                # Log which strings specifically were matched.
                log.warning("New match: %s, Strings:", hit.rule)

                counter = 1
                for entry in hit.strings:
                    log.warning("\t(%s) %s -> %s", counter, entry[0], entry[2])
                    counter += 1

                # Add match to the list of results.
                queue_results.put(dict(
                    rule=hit.rule,
                    detection=hit.meta.get('detection'),
                    description=hit.meta.get('description')
                ))

        counter += 1

    # If any rule gets matched, we need to notify the user and instruct him
    # on how to proceed from here.
    if len(matched) > 0:
        return True
    else:
        return False

def main(queue_results, queue_errors):
    # Generate configuration values.
    cfg = Config()

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
        log.info("Starting yara scanner...")
        scanner = threading.Thread(target=scan, args=(queue_results,))
        scanner.start()
        scanner.join()
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
