from lib.colorama import init
from lib.colorama import Fore, Back

init()

CONTINUE = "Are you sure you want to continue?"
ONLINE = "You are connected to the Internet. For your own safety, you should disconnect and re-run the tool."
UNSUPPORTED_WINDOWS = "You are running an unsupported version of Microsoft Windows."
NO_DRIVER = "Can't find a suitable driver to be used."
SERVICE_NO_START = "Can't start the service."
SCAN_STARTING = "Start scanning. This might take some minutes..."
SCAN_FINISHED = "Scan finished."
SCAN_FAILED = "The scanning failed, try reinstalling the tool. If that doesn't help, provide the log file to your point of contact to investigate the issue."
SERVICE_NO_STOP = "Can't stop the service."
INFECTION_FOUND = "I found some indicators of infection! For your own safety, DO NOT connect this computer to the Internet again and seek for assistance!"
NO_INFECTION_FOUND = "I wasn't able to identify any infection. If you are confident of being compromised, please do reach out for assistance."

def error(message):
    print(Fore.RED + str(message) + Fore.RESET)

def warning(message):
    print(Fore.YELLOW + str(message) + Fore.RESET)

def info(message):
    print(Fore.CYAN + str(message) + Fore.RESET)

def good(message):
    print(Fore.GREEN + str(message) + Fore.RESET)

def critical(message):
    print(Back.RED + Fore.WHITE + str(message) + Fore.RESET + Back.RESET)

def dialog(message):
    choice = raw_input(str(message) + ' [yes/no] ')
    if choice == 'yes':
        return True
    else:
        return False
