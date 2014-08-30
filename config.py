# Copyright (C) 2014 Claudio Guarnieri.
# This file is part of Detekt - https://github.com/botherder/detekt
# See the file 'LICENSE' for copying permission.

import os
import shutil
import platform

from utils import get_resource

class Config(object):
    # TODO: Make Singleton?

    def __init__(self):
        self.architecture = ''
        self.driver = ''
        self.service_name = 'pmem' # TODO: Randomize service name?
        self.service_path = '\\\\.\\{0}'.format(self.service_name)

    def get_architecture(self):
        if not self.architecture:
            orig = os.getenv('PROCESSOR_ARCHITECTURE')
            try:
                orig = os.getenv('PROCESSOR_ARCHITEW6432')
            except:
                pass

            if orig == 'AMD64':
                self.architecture = 'x64'
            else:
                self.architecture = 'x86'

    def get_driver_path(self):
        # Get architecture.
        self.get_architecture()

        if self.architecture == 'x64':
            # Select 64 bit driver.
            self.driver = get_resource(os.path.join('drivers', 'winpmem64.sys'))
        elif self.architecture == 'x86':
            # Delect 32 bit driver.
            self.driver = get_resource(os.path.join('drivers', 'winpmem32.sys'))

        if self.driver and os.path.exists(self.driver):
            return True

        return False
