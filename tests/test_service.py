from unittest.mock import MagicMock, patch
import threading
import time
import unittest


class TestService(unittest.TestCase):
    @patch("servicemanager.RegisterServiceCtrlHandler")
    @patch("servicemanager.LogInfoMsg")
    @patch("servicemanager.LogErrorMsg")
    @patch("win32service.SERVICE_STOP_PENDING")
    def test_service_lifecycle(self, mock_pending, mock_log_err, mock_log_info, mock_reg):
        from service import IDSIPSService

        svc = IDSIPSService(["IDSIPS"])
        svc.ReportServiceStatus = MagicMock()

        t = threading.Thread(target=svc.SvcDoRun, daemon=True)
        t.start()

        time.sleep(0.3)
        self.assertTrue(t.is_alive())
        self.assertIsNotNone(svc.hids_engine)
        self.assertTrue(svc.hids_engine._running)

        # Signal stop
        svc.SvcStop()
        t.join(timeout=5.0)

        self.assertFalse(t.is_alive())
        self.assertFalse(svc.hids_engine._running)
        svc.ReportServiceStatus.assert_called_once()


if __name__ == "__main__":
    unittest.main()
