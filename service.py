import win32service
import win32serviceutil
import win32event
import servicemanager

import subprocess
import sys
from pathlib import Path

from logger import get_logger

class IDSIPSService(win32serviceutil.ServiceFramework):

    _svc_name_ = "IDSIPS"
    _svc_display_name_ = "IDSIPS Security Service"
    _svc_description_ = "Windows IDS/IPS background security service."

    def __init__(self, args):
        win32serviceutil.ServiceFramework.__init__(self, args)

        # Event used to tell the service when Windows requests a stop.
        self.stop_event = win32event.CreateEvent(None, 0, 0, None)

          # NIDS worker process
        self.nids_process = None

        # Path to the existing NIDS capture script
        self.nids_capture = (
            Path(__file__).resolve().parent / "NIDS" / "capture.py"
        )

        # Python interpreter used by the service
        self.python_executable = (
            Path(__file__).resolve().parent / "runtime" / "python.exe"
            # Path(sys.executable).resolve().parent / "python.exe"
        )

    def start_nids_worker(self, logger):
        """Start the existing NIDS capture process."""
        try:
            self.nids_process = subprocess.Popen(
                [
                    str(self.python_executable),
                    str(self.nids_capture)
                ],
                cwd=str(self.nids_capture.parent),
                creationflags=subprocess.CREATE_NO_WINDOW
            )

            logger.info(
                f"NIDS worker started. PID: {self.nids_process.pid}"
            )

        except Exception as e:
            logger.exception(
                f"Failed to start NIDS worker: {e}"
            )

    def stop_nids_worker(self, logger):
        """Stop the NIDS capture process."""
        if self.nids_process is not None:
            try:
                if self.nids_process.poll() is None:
                    logger.info("Stopping NIDS worker...")

                    self.nids_process.terminate()
                    self.nids_process.wait(timeout=10)

                    logger.info("NIDS worker stopped.")

            except subprocess.TimeoutExpired:
                logger.warning(
                    "NIDS worker did not stop gracefully. "
                    "Terminating it."
                )
                self.nids_process.kill()

            except Exception as e:
                logger.exception(
                    f"Error stopping NIDS worker: {e}"
                )

            finally:
                self.nids_process = None

    def SvcStop(self):
        # Tell Windows that the service is stopping.
        self.ReportServiceStatus(win32service.SERVICE_STOP_PENDING)

        logger = get_logger()

        # Stop NIDS worker
        self.stop_nids_worker(logger)

        # Signal the stop event.
        win32event.SetEvent(self.stop_event)

    def SvcDoRun(self):
        logger = get_logger()

        logger.info("IDSIPS Security Service started.")

        servicemanager.LogInfoMsg(
        "IDSIPS Security Service has started."
        )

         # Start NIDS worker
        self.start_nids_worker(logger)

        # Keep the Windows service running
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
