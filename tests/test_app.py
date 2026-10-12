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

    def test_analyze_benign_url(self):
        client = app.test_client()
        response = client.post("/api/analyze", json={"url": "google.com"})
        self.assertEqual(response.status_code, 200)
        data = response.get_json()
        self.assertEqual(data["prediction"], "benign")
        self.assertLess(data["phishing_score"], 20.0)

    def test_analyze_phishing_url(self):
        client = app.test_client()
        response = client.post(
            "/api/analyze",
            json={"url": "http://paypal-verification-account-update.tk/login"},
        )
        self.assertEqual(response.status_code, 200)
        data = response.get_json()
        self.assertEqual(data["prediction"], "phishing")
        self.assertGreater(data["phishing_score"], 70.0)


if __name__ == "__main__":
    unittest.main()
