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

        # HIDS worker process
        self.hids_process = None

        # NIDS worker process
        self.nids_process = None

        # Correlation worker process
        self.correlation_process = None

        # IPS worker process
        self.ips_process = None

        # Path to the HIDS controller
        self.hids_engine = (
            Path(__file__).resolve().parent
            / "hids"
            / "hids.py"
        )

        # Path to the existing NIDS capture script
        self.nids_capture = (
            Path(__file__).resolve().parent
            / "NIDS"
            / "capture.py"
        )

        # Path to the correlation worker
        self.correlation_worker = (
            Path(__file__).resolve().parent
            / "alert_manager"
            / "correlation_worker.py"
        )

        # Path to the IPS worker
        self.ips_worker = (
            Path(__file__).resolve().parent
            / "IPS"
            / "ips_worker.py"
        )

        # Python interpreter used by the service
        self.python_executable = (
            Path(__file__).resolve().parent
            / "runtime"
            / "python.exe"
        )

        # Project root
        self.project_root = Path(__file__).resolve().parent

    def start_hids_worker(self, logger):
        """Start the HIDS monitoring process."""
        try:
            self.hids_process = subprocess.Popen(
                [
                    str(self.python_executable),
                    "-m",
                    "hids.hids"
                ],
                cwd=str(self.project_root),
                creationflags=subprocess.CREATE_NO_WINDOW
            )

            logger.info(
                f"HIDS worker started. PID: {self.hids_process.pid}"
            )

        except Exception as e:
            logger.exception(
                f"Failed to start HIDS worker: {e}"
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

    def start_correlation_worker(self, logger):
        """Start the real-time correlation worker."""
        try:
            self.correlation_process = subprocess.Popen(
                [
                    str(self.python_executable),
                    "-m",
                    "alert_manager.correlation_worker"
                ],
                cwd=str(self.project_root),
                creationflags=subprocess.CREATE_NO_WINDOW
            )

            logger.info(
                "Correlation worker started. "
                f"PID: {self.correlation_process.pid}"
            )

        except Exception as e:
            logger.exception(
                f"Failed to start correlation worker: {e}"
            )

    def start_ips_worker(self, logger):
        """Start the IPS worker."""
        try:
            self.ips_process = subprocess.Popen(
                [
                    str(self.python_executable),
                    "-m",
                    "IPS.ips_worker"
                ],
                cwd=str(self.project_root),
                creationflags=subprocess.CREATE_NO_WINDOW
            )

            logger.info(
                "IPS worker started. "
                f"PID: {self.ips_process.pid}"
            )

        except Exception as e:
            logger.exception(
                f"Failed to start IPS worker: {e}"
            )

    def stop_hids_worker(self, logger):
        """Stop the HIDS monitoring process."""
        if self.hids_process is not None:
            try:
                if self.hids_process.poll() is None:
                    logger.info("Stopping HIDS worker...")

                    self.hids_process.terminate()
                    self.hids_process.wait(timeout=10)

                    logger.info("HIDS worker stopped.")

            except subprocess.TimeoutExpired:
                logger.warning(
                    "HIDS worker did not stop gracefully. "
                    "Terminating it."
                )

                self.hids_process.kill()

            except Exception as e:
                logger.exception(
                    f"Error stopping HIDS worker: {e}"
                )

            finally:
                self.hids_process = None

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

    def stop_correlation_worker(self, logger):
        """Stop the correlation worker."""
        if self.correlation_process is not None:
            try:
                if self.correlation_process.poll() is None:
                    logger.info(
                        "Stopping correlation worker..."
                    )

                    self.correlation_process.terminate()
                    self.correlation_process.wait(timeout=10)

                    logger.info(
                        "Correlation worker stopped."
                    )

            except subprocess.TimeoutExpired:
                logger.warning(
                    "Correlation worker did not stop gracefully. "
                    "Terminating it."
                )

                self.correlation_process.kill()

            except Exception as e:
                logger.exception(
                    f"Error stopping correlation worker: {e}"
                )

            finally:
                self.correlation_process = None

    def stop_ips_worker(self, logger):
        """Stop the IPS worker."""
        if self.ips_process is not None:
            try:
                if self.ips_process.poll() is None:
                    logger.info(
                        "Stopping IPS worker..."
                    )

                    self.ips_process.terminate()
                    self.ips_process.wait(timeout=10)

                    logger.info(
                        "IPS worker stopped."
                    )

            except subprocess.TimeoutExpired:
                logger.warning(
                    "IPS worker did not stop gracefully. "
                    "Terminating it."
                )

                self.ips_process.kill()

            except Exception as e:
                logger.exception(
                    f"Error stopping IPS worker: {e}"
                )

            finally:
                self.ips_process = None

    def SvcStop(self):
        # Tell Windows that the service is stopping.
        self.ReportServiceStatus(
            win32service.SERVICE_STOP_PENDING
        )

        logger = get_logger()

        # Stop correlation worker
        self.stop_correlation_worker(logger)

        # Stop IPS worker
        self.stop_ips_worker(logger)

        # Stop NIDS worker
        self.stop_nids_worker(logger)

        # Stop HIDS worker
        self.stop_hids_worker(logger)

        # Signal the stop event.
        win32event.SetEvent(self.stop_event)

    def SvcDoRun(self):
        logger = get_logger()

        logger.info(
            "IDSIPS Security Service started."
        )

        servicemanager.LogInfoMsg(
            "IDSIPS Security Service has started."
        )

        # Start HIDS worker
        self.start_hids_worker(logger)

        # Start NIDS worker
        self.start_nids_worker(logger)

        # Start correlation worker
        self.start_correlation_worker(logger)

        # Start IPS worker
        self.start_ips_worker(logger)

        # Keep the Windows service running
        win32event.WaitForSingleObject(
            self.stop_event,
            win32event.INFINITE
        )

        logger.info(
            "IDSIPS Security Service stopped."
        )

        servicemanager.LogInfoMsg(
            "IDSIPS Security Service has stopped."
        )


if __name__ == "__main__":
    win32serviceutil.HandleCommandLine(
        IDSIPSService
    )