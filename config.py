import os
import shutil
import platform

from utils import get_resource

OFFLINE_CHECK = True

class Config(object):
    # TODO: Make Singleton?

    def __init__(self):
        self.offline_check = OFFLINE_CHECK
        self.architecture = ''
        self.driver = ''
        self.profile = ''
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

    def get_profile_name(self):
        # Get architecture.
        self.get_architecture()

        # Obtain release details on current version of Windows.
        windows_release, version, service_pack, processor = platform.win32_ver()
        if not service_pack:
            service_pack = 'SP0'

        # Check for supported version of Windows.
        if windows_release == 'XP':
            if service_pack in ['SP2', 'SP3'] and self.architecture == 'x86':
                self.profile = 'WinXP{0}{1}'.format(service_pack, self.architecture)
                return True
        #elif windows_release == 'Vista':
        #    if service_pack in ['SP0', 'SP1', 'SP2']:
        #        self.profile = 'Vista{0}{1}'.format(service_pack, self.architecture)
        #        return True
        elif windows_release == '7':
            if service_pack in ['SP0', 'SP1']:
                self.profile = 'Win7{0}{1}'.format(service_pack, self.architecture)
                return True

        # By now, if the function didn't return yet, it means we have an
        # unsupported version of Windows.
        return False
