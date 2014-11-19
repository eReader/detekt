# Copyright (C) 2014 Claudio Guarnieri.
# This file is part of Detekt - https://github.com/botherder/detekt
# See the file 'LICENSE' for copying permission.

import os
import shutil
import ctypes
import platform

from utils import get_resource

class OSVERSIONINFOEXW(ctypes.Structure):
    _fields_ = [
        ('dwOSVersionInfoSize', ctypes.c_ulong),
        ('dwMajorVersion', ctypes.c_ulong),
        ('dwMinorVersion', ctypes.c_ulong),
        ('dwBuildNumber', ctypes.c_ulong),
        ('dwPlatformId', ctypes.c_ulong),
        ('szCSDVersion', ctypes.c_wchar*128),
        ('wServicePackMajor', ctypes.c_ushort),
        ('wServicePackMinor', ctypes.c_ushort),
        ('wSuiteMask', ctypes.c_ushort),
        ('wProductType', ctypes.c_byte),
        ('wReserved', ctypes.c_byte)
    ]

def get_os_version():
    os_version = OSVERSIONINFOEXW()
    os_version.dwOSVersionInfoSize = ctypes.sizeof(os_version)
    retcode = ctypes.windll.Ntdll.RtlGetVersion(ctypes.byref(os_version))
    return os_version.dwMajorVersion, os_version.dwMinorVersion

class Config(object):
    def __init__(self):
        self.architecture = ''
        self.driver = ''
        self.profile = ''
        self.service_name = 'pmem' # TODO: Randomize service name?
        self.service_path = '\\\\.\\{0}'.format(self.service_name)

    def get_architecture(self):
        if os.getenv('PROCESSOR_ARCHITECTURE') == 'AMD64' or os.getenv('PROCESSOR_ARCHITEW6432') == 'AMD64':
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
            if service_pack in ['SP1', 'SP2', 'SP3'] and self.architecture == 'x86':
                self.profile = 'WinXP{0}{1}'.format(service_pack, self.architecture)
        elif windows_release == 'Vista':
            if service_pack in ['SP0', 'SP1', 'SP2']:
                self.profile = 'Vista{0}{1}'.format(service_pack, self.architecture)
        elif windows_release == '7':
            if service_pack in ['SP0', 'SP1']:
                self.profile = 'Win7{0}{1}'.format(service_pack, self.architecture)
        # NOTE: On older version of Python, Windows 8 is identified as post2008Server.
        # Might need to add that as an option or make sure that the appropriate version
        # of Python is installed on the compiler system.
        elif windows_release == '8':
            windows_major, windows_minor = get_os_version()

            # From Windows 8.1, Microsoft changed the way the underlying version
            # functions work. Python is currently not able to identify Windows 8.1
            # correctly, so we need to invoke Windows native RtlGetVersion function.
            # If it's 6.3.x, it's Windows 8.1.
            if windows_major == 6 and windows_minor == 3:
                # Enable only on Windows 8.1 32bit, on 64bit we have some problems.
                if self.architecture == 'x86':
                    self.profile = 'Win8SP1{0}'.format(self.architecture)
            else:
                self.profile = 'Win8SP0{0}'.format(self.architecture)
        elif windows_release == '8.1':
            self.profile = 'Win8SP1{0}'.format(self.architecture)
