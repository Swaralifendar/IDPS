import win32service
import win32serviceutil
import win32event
import servicemanager

import subprocess
import sys
import time
from pathlib import Path

from logger import get_logger
from paths import APP_DIR, DATA_DIR, WORKER_LOG_DIR, ensure_data_layout
from rotation import rotate_if_needed
from stop_signal import create_stop_event
from version import __version__


# How often the service checks that its workers are still alive.
WATCHDOG_INTERVAL_MS = 5000

# Restart backoff: 5s, 10s, 20s, ... capped at 5 minutes.
RESTART_BASE_DELAY_SECONDS = 5
RESTART_MAX_DELAY_SECONDS = 300

# A worker that runs this long after a restart is considered stable
# and its backoff is reset.
STABLE_RUN_SECONDS = 60

# On service stop, workers get this long to exit on their own
# (save checkpoints, close WinDivert) before they are killed.
GRACEFUL_STOP_SECONDS = 15

# Worker stdout/stderr logs (logs\workers\<name>.log), rotated
# when a worker is (re)started.
WORKER_LOG_MAX_BYTES = 10 * 1024 * 1024
WORKER_LOG_BACKUPS = 3


# name -> (process attribute, command-line arguments, working directory)
WORKERS = {
    "HIDS": ("hids_process", ["-m", "hids.hids"], APP_DIR),
    "NIDS": ("nids_process", [str(APP_DIR / "NIDS" / "capture.py")], APP_DIR / "NIDS"),
    "Correlation": ("correlation_process", ["-m", "alert_manager.correlation_worker"], APP_DIR),
    "IPS": ("ips_process", ["-m", "IPS.ips_worker"], APP_DIR),
}


class IDSIPSService(win32serviceutil.ServiceFramework):

    _svc_name_ = "IDSIPS"
    _svc_display_name_ = "IDSIPS Security Service"
    _svc_description_ = "Windows IDS/IPS background security service."

    def __init__(self, args):
        win32serviceutil.ServiceFramework.__init__(self, args)

        # Event used to tell the service when Windows requests a stop.
        self.stop_event = win32event.CreateEvent(None, 0, 0, None)

        # Named event that tells the workers to stop (stop_signal.py)
        self.worker_stop_event = None

        # Worker processes
        self.hids_process = None
        self.nids_process = None
        self.correlation_process = None
        self.ips_process = None

        # Python interpreter used by the workers
        self.python_executable = APP_DIR / "runtime" / "python.exe"

        # Project root
        self.project_root = APP_DIR

        # Watchdog restart state per worker
        self.worker_state = {
            name: {
                "failures": 0,
                "started_at": 0.0,
                "next_restart": None,
            }
            for name, _, _ in self.worker_specs()
        }

    def worker_specs(self):
        """Return (name, process attribute, start method) for each worker."""
        return [
            (name, attr, lambda logger, name=name: self.start_worker(name, logger))
            for name, (attr, _, _) in WORKERS.items()
        ]

    # ========================================================
    # START / WATCHDOG
    # ========================================================

    def start_worker(self, name, logger):
        """Start one worker, with stdout/stderr in logs\\workers\\<name>.log."""
        attr, args, cwd = WORKERS[name]

        try:
            WORKER_LOG_DIR.mkdir(parents=True, exist_ok=True)
            log_path = WORKER_LOG_DIR / f"{name.lower()}.log"

            # The previous process has exited, so the file can be rotated
            rotate_if_needed(log_path, WORKER_LOG_MAX_BYTES, WORKER_LOG_BACKUPS)

            with open(log_path, "ab") as log_file:
                process = subprocess.Popen(
                    # -u: unbuffered, so output reaches the log at once
                    [str(self.python_executable), "-u", *args],
                    cwd=str(cwd),
                    stdout=log_file,
                    stderr=subprocess.STDOUT,
                    creationflags=subprocess.CREATE_NO_WINDOW
                )

            setattr(self, attr, process)

            logger.info(f"{name} worker started. PID: {process.pid}")

        except Exception as e:
            logger.exception(f"Failed to start {name} worker: {e}")

    def check_workers(self, logger):
        """Restart any worker that has exited, with exponential backoff."""
        now = time.monotonic()

        for name, attr, start_worker in self.worker_specs():
            process = getattr(self, attr)
            state = self.worker_state[name]

            # Worker is running
            if process is not None and process.poll() is None:
                if (
                    state["failures"]
                    and now - state["started_at"] >= STABLE_RUN_SECONDS
                ):
                    logger.info(
                        f"{name} worker is stable again. "
                        "Restart backoff reset."
                    )
                    state["failures"] = 0
                continue

            # Worker just found dead: schedule a restart
            if state["next_restart"] is None:
                exit_code = (
                    process.returncode if process is not None else None
                )

                delay = min(
                    RESTART_BASE_DELAY_SECONDS * (2 ** state["failures"]),
                    RESTART_MAX_DELAY_SECONDS
                )

                state["failures"] += 1
                state["next_restart"] = now + delay

                logger.warning(
                    f"{name} worker is not running "
                    f"(exit code: {exit_code}). "
                    f"Restarting in {delay} seconds "
                    f"(attempt {state['failures']}). "
                    f"See {WORKER_LOG_DIR / (name.lower() + '.log')}"
                )
                continue

            # Backoff elapsed: restart it
            if now >= state["next_restart"]:
                state["next_restart"] = None
                setattr(self, attr, None)

                logger.info(f"Restarting {name} worker...")
                start_worker(logger)
                state["started_at"] = time.monotonic()

    # ========================================================
    # STOP
    # ========================================================

    def stop_workers(self, logger):
        """
        Ask all workers to stop (named event), wait up to
        GRACEFUL_STOP_SECONDS, then kill any that are left.
        """
        if self.worker_stop_event is not None:
            win32event.SetEvent(self.worker_stop_event)

        deadline = time.monotonic() + GRACEFUL_STOP_SECONDS

        while time.monotonic() < deadline:
            running = [
                name
                for name, (attr, _, _) in WORKERS.items()
                if getattr(self, attr) is not None
                and getattr(self, attr).poll() is None
            ]

            if not running:
                break

            # Keep Windows informed while waiting
            self.ReportServiceStatus(
                win32service.SERVICE_STOP_PENDING,
                waitHint=5000
            )
            time.sleep(0.5)

        for name, (attr, _, _) in WORKERS.items():
            process = getattr(self, attr)

            if process is None:
                continue

            try:
                if process.poll() is None:
                    logger.warning(
                        f"{name} worker did not stop within "
                        f"{GRACEFUL_STOP_SECONDS}s. Terminating it."
                    )
                    process.kill()
                    process.wait(timeout=5)
                else:
                    logger.info(
                        f"{name} worker stopped "
                        f"(exit code: {process.returncode})."
                    )
            except Exception as e:
                logger.exception(f"Error stopping {name} worker: {e}")
            finally:
                setattr(self, attr, None)

    def SvcStop(self):
        # Tell Windows that the service is stopping.
        self.ReportServiceStatus(
            win32service.SERVICE_STOP_PENDING,
            waitHint=(GRACEFUL_STOP_SECONDS + 10) * 1000
        )

        # Signal the stop event. SvcDoRun leaves its watchdog loop
        # and stops the workers, so no worker is restarted mid-stop.
        win32event.SetEvent(self.stop_event)

    def SvcDoRun(self):
        logger = get_logger()

        ensure_data_layout()

        logger.info(
            f"IDSIPS Security Service {__version__} started. "
            f"App: {APP_DIR} | Data: {DATA_DIR}"
        )

        servicemanager.LogInfoMsg(
            f"IDSIPS Security Service {__version__} has started."
        )

        # Named stop event the workers wait on
        try:
            self.worker_stop_event = create_stop_event()
        except Exception as e:
            logger.exception(
                f"Cannot create worker stop event; workers will be "
                f"terminated on stop: {e}"
            )

        for name in WORKERS:
            self.start_worker(name, logger)

        started_at = time.monotonic()

        for state in self.worker_state.values():
            state["started_at"] = started_at

        # Keep the Windows service running and watch the workers
        while True:
            result = win32event.WaitForSingleObject(
                self.stop_event,
                WATCHDOG_INTERVAL_MS
            )

            if result == win32event.WAIT_OBJECT_0:
                break

            try:
                self.check_workers(logger)
            except Exception as e:
                logger.exception(
                    f"Watchdog check failed: {e}"
                )

        self.stop_workers(logger)

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
