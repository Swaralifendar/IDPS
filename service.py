import threading

import win32service
import win32serviceutil
import win32event
import servicemanager

from logger import get_logger
from hids.hids import HIDSEngine, run_hids


class IDSIPSService(win32serviceutil.ServiceFramework):
    """
    Windows Service wrapper for the IDS/IPS Intrusion Detection & Prevention System.
    Maintains the IDSIPS service identity and manages the background HIDS monitoring engine.
    """

    _svc_name_ = "IDSIPS"
    _svc_display_name_ = "IDSIPS Security Service"
    _svc_description_ = "Windows IDS/IPS background security service."

    def __init__(self, args):
        win32serviceutil.ServiceFramework.__init__(self, args)

        # Event used to signal when Windows requests the service to stop.
        self.stop_event = win32event.CreateEvent(None, 0, 0, None)

        # HIDS monitoring engine and thread
        self.hids_engine = None
        self.hids_thread = None

    def SvcStop(self):
        """
        Called when Windows Service Manager signals the service to stop.
        """
        logger = get_logger()
        logger.info("IDSIPS Security Service stopping.")

        # Report stop pending to Service Control Manager
        self.ReportServiceStatus(win32service.SERVICE_STOP_PENDING)

        # Signal HIDS engine to shut down cleanly
        if self.hids_engine:
            self.hids_engine.stop()

        # Signal the Windows stop event
        win32event.SetEvent(self.stop_event)

    def SvcDoRun(self):
        """
        Called when the Windows Service starts.
        Launches the HIDS monitoring engine in a background thread and waits for stop signal.
        """
        logger = get_logger()

        logger.info("IDSIPS Security Service started.")
        servicemanager.LogInfoMsg("IDSIPS Security Service has started.")

        try:
            self.hids_engine = HIDSEngine()

            # Start HIDS continuous monitoring in a managed background thread
            self.hids_thread = threading.Thread(
                target=self.hids_engine.run,
                args=(self.stop_event,),
                name="HIDS-Monitor",
                daemon=True,
            )
            self.hids_thread.start()

            # Keep service alive until Windows signals stop_event
            win32event.WaitForSingleObject(
                self.stop_event,
                win32event.INFINITE
            )

            # Wait for HIDS monitoring loop to gracefully exit
            # The service lifecycle test waits up to 5 seconds, so use
            # a bounded wait that allows the service thread to return promptly.
            if self.hids_thread and self.hids_thread.is_alive():
                 self.hids_thread.join(timeout=3.0)
            # if self.hids_thread and self.hids_thread.is_alive():
            #     self.hids_thread.join(timeout=10.0)

        except Exception as e:
            logger.exception("IDSIPS Security Service encountered an unexpected error: %s", e)
            servicemanager.LogErrorMsg(f"IDSIPS Service Error: {e}")
            raise
        finally:
            logger.info("IDSIPS Security Service stopped.")
            servicemanager.LogInfoMsg("IDSIPS Security Service has stopped.")


if __name__ == "__main__":
    win32serviceutil.HandleCommandLine(IDSIPSService)