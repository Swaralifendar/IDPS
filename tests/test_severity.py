import unittest
from hids.severity import Severity


class TestSeverity(unittest.TestCase):
    def test_enum_values(self):
        self.assertEqual(Severity.INFO.value, "INFO")
        self.assertEqual(Severity.LOW.value, "LOW")
        self.assertEqual(Severity.MEDIUM.value, "MEDIUM")
        self.assertEqual(Severity.HIGH.value, "HIGH")
        self.assertEqual(Severity.CRITICAL.value, "CRITICAL")

    def test_comparisons(self):
        self.assertTrue(Severity.INFO < Severity.LOW)
        self.assertTrue(Severity.LOW < Severity.MEDIUM)
        self.assertTrue(Severity.MEDIUM < Severity.HIGH)
        self.assertTrue(Severity.HIGH < Severity.CRITICAL)
        self.assertTrue(Severity.CRITICAL > Severity.INFO)
        self.assertTrue(Severity.HIGH >= Severity.HIGH)
        self.assertTrue(Severity.MEDIUM <= Severity.HIGH)
        self.assertEqual(Severity.HIGH, Severity.HIGH)
        self.assertNotEqual(Severity.LOW, Severity.HIGH)

    def test_string_comparison(self):
        self.assertTrue(Severity.CRITICAL > "HIGH")
        self.assertTrue(Severity.LOW < "MEDIUM")
        self.assertEqual(Severity.HIGH, "high")

    def test_from_string(self):
        self.assertEqual(Severity.from_string("info"), Severity.INFO)
        self.assertEqual(Severity.from_string("LOW"), Severity.LOW)
        self.assertEqual(Severity.from_string("Medium"), Severity.MEDIUM)
        self.assertEqual(Severity.from_string("high"), Severity.HIGH)
        self.assertEqual(Severity.from_string("critical"), Severity.CRITICAL)

    def test_from_string_invalid(self):
        with self.assertRaises(ValueError):
            Severity.from_string("UNKNOWN")

        self.assertEqual(Severity.from_string("INVALID", default=Severity.INFO), Severity.INFO)


if __name__ == "__main__":
    unittest.main()
