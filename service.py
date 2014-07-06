import os
import time
import win32service
from threading import Timer, Event

from config import Config
from abstracts import DetectorError

SERVICE_WAIT_TIMEOUT = 30

class Service(object):
    def __init__(self, driver, service):
        self.driver = driver
        self.service_name = service
        self.manager = win32service.OpenSCManager(None, None, win32service.SC_MANAGER_CREATE_SERVICE)
        self.service = None

    def wait_status(self, status=win32service.SERVICE_RUNNING, timeout=SERVICE_WAIT_TIMEOUT):
        abort = Event()
        abort.clear()

        def die():
            abort.set()

        timer = Timer(timeout, die)
        timer.start()

        while True:
            if abort.is_set():
                # If timeout is hit we abort.
                raise DetectorError("Timeout hit waiting service for status %s", status)

            current = win32service.QueryServiceStatusEx(self.service)

            if current['CurrentState'] == status:
                timer.cancel()
                return

            time.sleep(1)

    def create(self):
        if not self.driver or not os.path.exists(self.driver):
            raise DetectorError("The driver does not exist at path: {0}".format(self.driver))

        try:
            self.service = win32service.OpenService(self.manager, self.service_name, win32service.SERVICE_ALL_ACCESS)
        except:
            try:
                if not self.service:
                    self.service = win32service.CreateService(
                        self.manager,
                        self.service_name,
                        self.service_name,
                        win32service.SERVICE_ALL_ACCESS,
                        win32service.SERVICE_KERNEL_DRIVER,
                        win32service.SERVICE_DEMAND_START,
                        win32service.SERVICE_ERROR_IGNORE,
                        self.driver,
                        None, 0, None, None, None
                    )
            except Exception as e:
                raise DetectorError("Unable to create service: {0}".format(e))

    def start(self):
        try:
            win32service.StartService(self.service, [])
        except Exception as e:
            # If the service is already loaded we can continue.
            # This generally shouldn't happen, but in case it does we can just
            # try to use the running instance and unload it when we're done.
            if hasattr(e, 'winerror') and int(e.winerror) == 1056:
                pass
            # If the problem is different, we need to terminate.
            else:
                raise DetectorError("Unable to start service: {0}".format(e))

        self.wait_status()

    def stop(self):
        try:
            win32service.ControlService(self.service, win32service.SERVICE_CONTROL_STOP)
        except Exception as e:
            raise DetectorError("Unable to stop service: {0}".format(e))

        self.wait_status(win32service.SERVICE_STOPPED)

    def delete(self):
        try:
            win32service.DeleteService(self.service)
            win32service.CloseServiceHandle(self.service)
            win32service.CloseServiceHandle(self.manager)
        except Exception as e:
            raise DetectorError("Unable to delete the service: {0}".format(e))
