# Copyright (C) 2014 Claudio Guarnieri.
# This file is part of Detekt - https://github.com/botherder/detekt
# See the file 'LICENSE' for copying permission.

# This code is adapted from:
# https://code.google.com/p/volatility/source/browse/branches/scudette/tools/windows/winpmem/winpmem.py?r=2722

import os
import logging
import struct
import win32file

from utils import get_md5
from config import DEBUG

log = logging.getLogger('detector.memory')

def CTL_CODE(DeviceType, Function, Method, Access):
    return (DeviceType<<16) | (Access << 14) | (Function << 2) | Method

# IOCTLS for interacting with the driver.
CTRL_IOCTRL = CTL_CODE(0x22, 0x101, 0, 3)
INFO_IOCTRL = CTL_CODE(0x22, 0x103, 0, 3)
INFO_IOCTRL_DEPRECATED = CTL_CODE(0x22, 0x100, 0, 3)

class Memory(object):
    # Use a buffer of 10MB.
    BUFFER_SIZE = 1024 * 1024 * 10
    FIELDS = (['CR3', 'NtBuildNumber', 'KernBase', 'KDBG'] +
              ['KPCR%02d' % i for i in range(32)] +
              ['PfnDataBase', 'PsLoadedModuleList', 'PsActiveProcessHead'] +
              ['Padding%s' % i for i in range(0xff)] +
              ['NumberOfRuns'])

    def __init__(self):
        # Open a handle to the loaded Winpmem service.
        # TODO: at some point we might want to randomize this in order
        # to prevent detection.
        self.handle = win32file.CreateFile(
            '\\\\.\\pmem',
            win32file.GENERIC_READ | win32file.GENERIC_WRITE,
            win32file.FILE_SHARE_READ | win32file.FILE_SHARE_WRITE,
            None,
            win32file.OPEN_EXISTING,
            win32file.FILE_ATTRIBUTE_NORMAL,
            None
        )

        # Set the access mode.
        self.set_mode()
        # Scan for the available memory ranges.
        self.parse_memory_ranges()
        # Log some debug information, nothing important.
        if DEBUG:
            self.get_info()

    def parse_memory_ranges(self):
        self.ranges = []

        result = win32file.DeviceIoControl(
            self.handle, INFO_IOCTRL, '', 102400, None)

        fmt_string = 'Q' * len(self.FIELDS)
        self.memory_parameters = dict(zip(self.FIELDS, struct.unpack_from(
                    fmt_string, result)))

        self.dtb = self.memory_parameters['CR3']
        self.kdbg = self.memory_parameters['KDBG']

        offset = struct.calcsize(fmt_string)

        for x in range(self.memory_parameters['NumberOfRuns']):
            start, length = struct.unpack_from('QQ', result, x * 16 + offset)
            self.ranges.append((start, length))

    def get_info(self):
        for key, value in sorted(self.memory_parameters.items()):
            if key.startswith('Pad'):
                continue

            if not value:
                continue

            log.debug("%s: %#08x (%s)", key, value, value)

        counter = 1
        for start, length in self.ranges:
            log.debug("Memory Range #%d, Start: 0x%X - End: 0x%X - Length: 0x%X", counter, start, start+length, length)
            counter += 1

    def set_mode(self):
        # Set physical mode.
        mode = 1

        win32file.DeviceIoControl(
            self.handle, CTRL_IOCTRL, struct.pack('I', mode), 0, None)

    def get_memory_chunks(self):
        # This function should yield a maximum of 10MB sized memory chunks
        # for each available range.
        offset = 0
        for start, length in self.ranges:
            offset = start
            end = start + length

            while offset < end:
                to_read = min(self.BUFFER_SIZE, end - offset)
                win32file.SetFilePointer(self.handle, offset, 0)

                _, data = win32file.ReadFile(self.handle, to_read)

                offset += to_read

                if DEBUG:
                    log.debug("Retrieved chunk at offset 0x%X with MD5 %s", offset, get_md5(data))

                yield(data)
