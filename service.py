import win32service
import win32serviceutil
import win32event
import servicemanager

from logger import get_logger

class IDSIPSService(win32serviceutil.ServiceFramework):

    _svc_name_ = "IDSIPS"
    _svc_display_name_ = "IDSIPS Security Service"
    _svc_description_ = "Windows IDS/IPS background security service."

    def __init__(self, args):
        win32serviceutil.ServiceFramework.__init__(self, args)

        # Event used to tell the service when Windows requests a stop.
        self.stop_event = win32event.CreateEvent(None, 0, 0, None)

    def SvcStop(self):
        # Tell Windows that the service is stopping.
        self.ReportServiceStatus(win32service.SERVICE_STOP_PENDING)

        # Signal the stop event.
        win32event.SetEvent(self.stop_event)

    def SvcDoRun(self):
        logger = get_logger()

        logger.info("IDSIPS Security Service started.")

        servicemanager.LogInfoMsg(
        "IDSIPS Security Service has started."
        )

        win32event.WaitForSingleObject(
        self.stop_event,
        win32event.INFINITE
        )

        logger.info("IDSIPS Security Service stopped.")

        servicemanager.LogInfoMsg(
        "IDSIPS Security Service has stopped."
        )
        # # Called when the Windows Service starts.
        # servicemanager.LogInfoMsg(
        #     "IDSIPS Security Service has started."
        # )

        # # Keep the service running until Windows sends a stop request.
        # win32event.WaitForSingleObject(
        #     self.stop_event,
        #     win32event.INFINITE
        # )

        # servicemanager.LogInfoMsg(
        #     "IDSIPS Security Service has stopped."
        # )


if __name__ == "__main__":
    win32serviceutil.HandleCommandLine(IDSIPSService)