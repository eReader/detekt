# Copyright (C) 2014 Claudio Guarnieri.
# This file is part of Detekt - https://github.com/botherder/detekt
# See the file 'LICENSE' for copying permission.

import os
import sys
import ctypes

def get_resource(relative):
    # First try from the local directory. This might come handy in case we want
    # to provide updates or allow the user to run custom signatures.
    path = os.path.join(os.getcwd(), relative)
    # In case the resource doesn't exist in the current directory, we'll try
    # from the actual resources.
    if not os.path.exists(path):
        if hasattr(sys, '_MEIPASS'):
            path = os.path.join(sys._MEIPASS, relative)

    return path

# Not currently used. Might use this in the future to automatically determine
# which language to use for logging messages.
#def get_language():
#    return ctypes.windll.kernel32.GetUserDefaultUILanguage()

def check_connection():
    # Check if there is an active Internet connection.
    # This might not be 100% reliable.
    if ctypes.windll.wininet.InternetGetConnectedState(None, None):
        return True
    else:
        return False
