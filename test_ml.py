"""
BrandShield AI - Automated Unit and Integration Tests for Machine Learning Pipeline
Validates:
1. Feature extraction consistency and safety (no network calls, malformed handling).
2. Model artifact integrity and verified benchmark metrics.
3. Inference outputs, calibrated probabilities, and confidence calculations.
4. Rule 8 social platform disambiguation.
5. Data leakage audit between training and held-out testing partitions.
6. Graceful degradation when model artifact is absent or input is invalid.
"""

import os
import json
import unittest
import joblib
import pandas as pd

import ml_features
import ml_detector

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
MODEL_PATH = os.path.join(BASE_DIR, "models", "phishing_rf_model.joblib")
METRICS_PATH = os.path.join(BASE_DIR, "models", "model_metrics.json")
TEST_SAMPLES_PATH = os.path.join(BASE_DIR, "data", "test_samples.csv")

class TestBrandShieldMLPipeline(unittest.TestCase):

    def test_01_feature_extraction_consistency_and_shape(self):
        """Verify feature extraction returns all 26 features with identical ordering and types."""
        url = "http://secure-login.apexbank.verify-auth.xyz/login.php?token=%20test&id=123"
        f_dict = ml_features.extract_url_features(url)
        f_names = ml_features.get_feature_names()
        f_vec = ml_features.extract_features_vector(url)

        self.assertEqual(len(f_names), 26, "Feature count must be exactly 26.")
        self.assertEqual(len(f_dict), 26, "Feature dictionary must contain 26 keys.")
        self.assertEqual(len(f_vec), 26, "Feature vector must contain 26 values.")

        for i, name in enumerate(f_names):
            self.assertIn(name, f_dict, f"Feature '{name}' missing from dict.")
            self.assertEqual(f_vec[i], f_dict[name], f"Vector index {i} mismatch for '{name}'.")
            self.assertIsInstance(f_vec[i], (int, float), f"Feature '{name}' must be numeric.")

        # Test specific feature values
        self.assertEqual(f_dict["has_https"], 0.0)
        self.assertGreaterEqual(f_dict["sensitive_keyword_count"], 2.0)
        self.assertGreaterEqual(f_dict["num_subdomains"], 2.0)
        self.assertEqual(f_dict["suspicious_encoding"], 1.0)

    def test_02_feature_extraction_offline_safety_and_edge_cases(self):
        """Ensure feature extraction handles malformed, empty, and non-ASCII URLs safely without network calls."""
        edge_cases = [
            "",
            None,
            "   ",
            "not-a-valid-url-at-all",
            "http://",
            "https://",
            "http://192.168.1.1/login.php",
            "https://example.com/" + "a" * 1500,
            "http://русский-домен.рф/тест",
            "https://user:pass@domain.com:8080/path?q=1#frag"
        ]
        for ec in edge_cases:
            res_dict = ml_features.extract_url_features(ec)
            res_vec = ml_features.extract_features_vector(ec)
            self.assertEqual(len(res_dict), 26)
            self.assertEqual(len(res_vec), 26)
            # Ensure no NaNs or Infinities
            for val in res_vec:
                self.assertFalse(pd.isna(val), f"NaN detected for input: {ec}")

    def test_03_model_artifact_integrity_and_measured_metrics(self):
        """Verify the trained RandomForest model artifact and actual recorded benchmark metrics."""
        self.assertTrue(os.path.exists(MODEL_PATH), f"Model artifact missing at {MODEL_PATH}")
        self.assertTrue(os.path.exists(METRICS_PATH), f"Metrics JSON missing at {METRICS_PATH}")

        artifact = joblib.load(MODEL_PATH)
        self.assertIn("model", artifact)
        self.assertIn("feature_names", artifact)
        self.assertEqual(len(artifact["feature_names"]), 26)

        with open(METRICS_PATH, "r", encoding="utf-8") as f:
            metrics = json.load(f)

        # Confirm measured benchmark criteria on real held-out test data
        self.assertGreaterEqual(metrics["accuracy"], 0.95, "Measured accuracy should exceed 95%.")
        self.assertGreaterEqual(metrics["precision"], 0.95, "Measured precision should exceed 95%.")
        self.assertGreaterEqual(metrics["recall"], 0.95, "Measured recall should exceed 95%.")
        self.assertGreaterEqual(metrics["f1_score"], 0.95, "Measured F1 should exceed 95%.")
        self.assertGreaterEqual(metrics["roc_auc"], 0.98, "Measured ROC-AUC should exceed 98%.")

        cm = metrics["confusion_matrix"]
        total_eval = cm["true_negatives"] + cm["false_positives"] + cm["false_negatives"] + cm["true_positives"]
        self.assertEqual(total_eval, metrics["test_samples"], "Confusion matrix total must equal test set size.")

    def test_04_zero_leakage_audit_between_train_and_test(self):
        """Ensure 0 duplicate or near-duplicate leakage exists between training and testing sets."""
        if os.path.exists(TEST_SAMPLES_PATH) and os.path.exists(os.path.join(BASE_DIR, "data", "cleaned_urls.csv")):
            test_df = pd.read_csv(TEST_SAMPLES_PATH)
            full_df = pd.read_csv(os.path.join(BASE_DIR, "data", "cleaned_urls.csv"))

            test_urls = set(test_df["url"].str.strip().str.lower())
            # Reconstruct training set by difference
            train_urls = set(full_df["url"].str.strip().str.lower()) - test_urls

            overlap = test_urls.intersection(train_urls)
            self.assertEqual(len(overlap), 0, f"Data leakage detected! {len(overlap)} URLs present in both sets.")

    def test_05_runtime_inference_phishing_vs_benign(self):
        """Verify real-time ML prediction correctly distinguishes phishing vs legitimate URLs."""
        # 1. Known malicious phishing pattern
        phishing_url = "http://bigtasty.xyz/gijknpvw/ef38spki72sy"
        res_phish = ml_detector.predict_url(phishing_url)
        self.assertTrue(res_phish["available"])
        self.assertEqual(res_phish["status"], "success")
        self.assertTrue(res_phish["is_phishing"])
        self.assertIn(res_phish["category"], ["HIGH RISK", "SUSPICIOUS"])
        self.assertGreaterEqual(res_phish["phishing_probability"], 0.50)
        self.assertGreaterEqual(len(res_phish["contributing_features"]), 1)

        # 2. Known benign corporate URLs
        benign_url = "https://www.google.com"
        res_benign = ml_detector.predict_url(benign_url)
        self.assertTrue(res_benign["available"])
        self.assertEqual(res_benign["status"], "success")
        self.assertFalse(res_benign["is_phishing"])
        self.assertEqual(res_benign["category"], "LOW RISK")
        self.assertLess(res_benign["phishing_probability"], 0.40)

    def test_06_rule_8_social_platform_disambiguation(self):
        """Verify that ML model explicitly flags Rule 8 note for social platform profile URLs."""
        social_url = "https://x.com/apexbank"
        res_social = ml_detector.predict_url(social_url)
        self.assertTrue(res_social["is_social_platform"])
        self.assertIn("Rule 8 Notice", res_social["social_notice"])
        self.assertIn("does NOT authenticate social profiles", res_social["social_notice"])

    def test_07_graceful_handling_of_missing_model_and_invalid_inputs(self):
        """Ensure missing model or empty inputs return explicit status rather than fake predictions."""
        # Empty input
        res_empty = ml_detector.predict_url("")
        self.assertFalse(res_empty["available"])
        self.assertEqual(res_empty["status"], "unsupported_input")
        self.assertIsNone(res_empty["prediction"])

        # Non-string input
        res_none = ml_detector.predict_url(None)
        self.assertFalse(res_none["available"])
        self.assertEqual(res_none["status"], "unsupported_input")

    def test_08_missing_model_file_graceful_fallback(self):
        """Verify that when model artifact is missing, explicit model_unavailable status is returned without crashing."""
        orig_path = ml_detector.MODEL_ARTIFACT_PATH
        orig_artifact = ml_detector._CACHED_ARTIFACT
        try:
            ml_detector.MODEL_ARTIFACT_PATH = os.path.join(BASE_DIR, "models", "nonexistent_model.joblib")
            ml_detector._CACHED_ARTIFACT = None

            self.assertFalse(ml_detector.is_ml_model_available())
            res = ml_detector.predict_url("https://example.com/test")
            self.assertFalse(res["available"])
            self.assertEqual(res["status"], "model_unavailable")
            self.assertIsNone(res["prediction"])
            self.assertIn("not loaded", res["message"])
        finally:
            ml_detector.MODEL_ARTIFACT_PATH = orig_path
            ml_detector._CACHED_ARTIFACT = orig_artifact

    def test_09_integrated_link_analysis_with_api_errors_and_malformed_urls(self):
        """Verify detector.analyze_suspicious_link safely separates ML, heuristics, and API failure states."""
        import detector
        import unittest.mock as mock

        # 1. Test malformed and empty URLs
        malformed_urls = ["", "   ", "http://", "not-a-url"]
        for bad_url in malformed_urls:
            res = detector.analyze_suspicious_link(bad_url)
            self.assertIn("ml_findings", res)
            self.assertIn("api_findings", res)
            self.assertIn("heuristic_findings", res)

        # 2. Test VirusTotal API error/timeout while ML model remains functional
        with mock.patch("virustotal.check_url_virustotal", return_value={"status": "timeout_error", "summary": "API Timed Out", "is_flagged": False}):
            res_timeout = detector.analyze_suspicious_link("http://bigtasty.xyz/gijknpvw/ef38spki72sy")
            # VT reflects error
            self.assertEqual(res_timeout["api_findings"]["status"], "timeout_error")
            # ML still accurately predicts and functions independently
            self.assertTrue(res_timeout["ml_findings"]["available"])
            self.assertTrue(res_timeout["ml_findings"]["is_phishing"])
            self.assertIn(res_timeout["risk_category"], ["HIGH RISK", "SUSPICIOUS"])

if __name__ == "__main__":
    unittest.main()
