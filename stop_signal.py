"""
Graceful stop signal shared by the service and its workers.

The service creates a named Windows event before starting the
workers and sets it when Windows asks the service to stop. Each
worker waits on that event instead of sleeping, so it can finish
its current step, save checkpoints and exit on its own. The
service only kills a worker that does not exit in time.

When a worker runs on its own (development), the event does not
exist and the helpers simply behave like time.sleep().
"""

import os
import time

try:
    import win32con
    import win32event

    WIN32_AVAILABLE = True
except ImportError:
    WIN32_AVAILABLE = False


# Session-wide name; the service (SYSTEM) creates it. Can be
# overridden for testing as a normal user ("Local\\...").
STOP_EVENT_NAME = os.environ.get("IDSIPS_STOP_EVENT", "Global\\IDSIPS_Stop")

_handle = None


def create_stop_event():
    """
    Create (or reset) the stop event. Called by the service.
    Manual-reset, so every worker sees it once it is set.
    """

    if not WIN32_AVAILABLE:
        return None

    handle = win32event.CreateEvent(None, True, False, STOP_EVENT_NAME)

    # The name may already exist (left over from a previous run in
    # the same session); make sure it starts unsignaled.
    win32event.ResetEvent(handle)

    return handle


def get_stop_event():
    """
    Open the service's stop event, or return None if the service
    is not running (e.g. a worker started by hand).
    """

    global _handle

    if _handle is not None or not WIN32_AVAILABLE:
        return _handle

    try:
        _handle = win32event.OpenEvent(
            win32con.SYNCHRONIZE,
            False,
            STOP_EVENT_NAME
        )
    except Exception:
        _handle = None

    return _handle


def wait_for_stop(seconds: float) -> bool:
    """
    Sleep for up to `seconds`. Returns True as soon as a stop has
    been requested, False if the time elapsed without a stop.
    """

    handle = get_stop_event()

    if handle is None:
        time.sleep(seconds)
        return False

    try:
        result = win32event.WaitForSingleObject(handle, int(seconds * 1000))
        return result == win32event.WAIT_OBJECT_0
    except Exception:
        time.sleep(seconds)
        return False


def stop_requested() -> bool:
    """Non-blocking check."""

    return wait_for_stop(0) if get_stop_event() is not None else False
