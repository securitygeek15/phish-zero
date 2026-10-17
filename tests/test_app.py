import unittest
from app import app, normalize_url


class URLValidationTests(unittest.TestCase):
    def test_adds_https_when_scheme_missing(self):
        url, host = normalize_url("example.com")
        self.assertEqual(url, "https://example.com")
        self.assertEqual(host, "example.com")

    def test_rejects_non_http_scheme(self):
        with self.assertRaises(ValueError):
            normalize_url("javascript:alert(1)")

    def test_rejects_credentials(self):
        with self.assertRaises(ValueError):
            normalize_url("https://user:pass@example.com")

    def test_rejects_spaces(self):
        with self.assertRaises(ValueError):
            normalize_url("https://example.com/path here")

    def test_health_endpoint(self):
        client = app.test_client()
        response = client.get("/api/health")
        self.assertEqual(response.status_code, 200)
        self.assertIn("model_loaded", response.get_json())

    def test_analyze_safe_green_url(self):
        client = app.test_client()
        response = client.post("/api/analyze", json={"url": "https://google.com"})
        self.assertEqual(response.status_code, 200)
        data = response.get_json()
        self.assertEqual(data["threat_level"], "safe")
        self.assertEqual(data["threat_color"], "#10b981")
        self.assertLess(data["phishing_score"], 15.0)

    def test_analyze_caution_blue_url(self):
        client = app.test_client()
        response = client.post("/api/analyze", json={"url": "https://news.ycombinator.com"})
        self.assertEqual(response.status_code, 200)
        data = response.get_json()
        self.assertEqual(data["threat_level"], "caution")
        self.assertEqual(data["threat_color"], "#3b82f6")
        self.assertGreaterEqual(data["phishing_score"], 15.0)
        self.assertLess(data["phishing_score"], 45.0)

    def test_analyze_warning_yellow_url(self):
        client = app.test_client()
        response = client.post("/api/analyze", json={"url": "http://192.168.1.1/admin/login.php"})
        self.assertEqual(response.status_code, 200)
        data = response.get_json()
        self.assertEqual(data["threat_level"], "warning")
        self.assertEqual(data["threat_color"], "#f59e0b")
        self.assertGreaterEqual(data["phishing_score"], 45.0)
        self.assertLess(data["phishing_score"], 70.0)

    def test_analyze_danger_red_url(self):
        client = app.test_client()
        response = client.post(
            "/api/analyze",
            json={"url": "http://paypal-verification-account-update.tk/login"},
        )
        self.assertEqual(response.status_code, 200)
        data = response.get_json()
        self.assertEqual(data["threat_level"], "danger")
        self.assertEqual(data["threat_color"], "#ef4444")
        self.assertGreater(data["phishing_score"], 70.0)


if __name__ == "__main__":
    unittest.main()
