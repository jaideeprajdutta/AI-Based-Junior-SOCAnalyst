import unittest
from app.main import classify_alert, calculate_severity

class TestSOCLogic(unittest.TestCase):

    def test_classify_alert_flood(self):
        self.assertEqual(classify_alert(100), "Potential ICMP Flood")
        self.assertEqual(classify_alert(150), "Potential ICMP Flood")

    def test_classify_alert_suspicious(self):
        self.assertEqual(classify_alert(50), "Suspicious Network Volume")
        self.assertEqual(classify_alert(75), "Suspicious Network Volume")

    def test_classify_alert_informational(self):
        self.assertEqual(classify_alert(10), "Informational")
        self.assertEqual(classify_alert(49), "Informational")

    def test_severity_high(self):
        self.assertEqual(calculate_severity(100), "High")

    def test_severity_medium(self):
        self.assertEqual(calculate_severity(50), "Medium")

    def test_severity_low(self):
        self.assertEqual(calculate_severity(10), "Low")

if __name__ == "__main__":
    unittest.main()
