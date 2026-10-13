"""
BrandShield AI - Mobile App Machine Learning Test Suite (Model 3)
Tests Drebin Android benchmark feature extraction (215 features),
safe missing-metadata handling, fairness safeguards, input validation,
model inference, developer entity verification, Model 1/2/3 independence,
and SQLite persistence.
"""

import json
import os
os.environ["SUPABASE_TEST_MODE"] = "1"
import unittest
import numpy as np

import mobile_app_features
import mobile_app_detector
import detector
import ml_detector
import social_profile_detector
import database

class TestMobileAppML(unittest.TestCase):

    def setUp(self):
        """Set up test environment and fixtures."""
        database.init_db()
        self.sample_benign_app = {
            "app_name": "Apex Mobile Banking",
            "developer_name": "Apex Financial Technologies LLC",
            "store_url": "https://play.google.com/store/apps/details?id=com.apex.bank",
            "description": "Secure mobile banking application for checking account balances and money transfers.",
            "permissions": ["INTERNET", "ACCESS_NETWORK_STATE", "ACCESS_FINE_LOCATION"]
        }

        self.sample_malicious_app = {
            "app_name": "ApexBank Mod Free Money Hack",
            "developer_name": "RogueAPK Team",
            "store_url": "http://free-cracked-apks.xyz/apexbank-mod.apk",
            "description": "Unlimited money cheat injector. Intercepts incoming SMS OTP codes and roots phone.",
            "permissions": [
                "SEND_SMS", "READ_SMS", "RECEIVE_SMS", "RECEIVE_BOOT_COMPLETED",
                "READ_PHONE_STATE", "INSTALL_PACKAGES", "SYSTEM_ALERT_WINDOW",
                "WRITE_SETTINGS", "BIND_DEVICE_ADMIN"
            ]
        }

        self.sample_brand = {
            "id": 1,
            "name": "ApexBank",
            "official_domains": ["apexbank.com"],
            "official_handles": ["apexbank", "apexbank_official"],
            "verified_developers": ["Apex Financial Technologies LLC", "Apex Global Systems"]
        }

    def test_feature_names_and_vector_dimension(self):
        """Test that Drebin feature space has exactly 215 features with matching vector size."""
        feat_names = mobile_app_features.get_feature_names()
        self.assertEqual(len(feat_names), 215)
        self.assertIn("attachInterface", feat_names)
        self.assertIn("android.os.Binder", feat_names)
        self.assertIn("SEND_SMS", feat_names)
        self.assertIn("READ_PHONE_STATE", feat_names)
        self.assertIn("android.intent.action.BOOT_COMPLETED", feat_names)

        extracted = mobile_app_features.extract_app_features(self.sample_benign_app)
        vec = extracted["feature_vector"]
        self.assertEqual(len(vec), 215)
        for val in vec:
            self.assertIn(val, (0.0, 1.0))
            self.assertFalse(np.isnan(val))

    def test_permission_parsing_and_normalization(self):
        """Test permission normalization and parsing from explicit lists and free text."""
        # 1. Normalization from fully qualified package string
        self.assertEqual(mobile_app_features.normalize_permission_name("android.permission.SEND_SMS"), "SEND_SMS")
        self.assertEqual(mobile_app_features.normalize_permission_name("android.permission.CAMERA"), "CAMERA")
        self.assertEqual(mobile_app_features.normalize_permission_name("ACCESS_FINE_LOCATION"), "ACCESS_FINE_LOCATION")

        # 2. Parsing from free-text descriptions
        text_app = {
            "description": "App requires Camera to scan QR codes and SMS to verify your phone number via text message."
        }
        perms = mobile_app_features.parse_permissions_from_input(text_app)
        self.assertIn("CAMERA", perms)
        self.assertIn("SEND_SMS", perms)
        self.assertIn("READ_SMS", perms)

    def test_safe_missing_metadata_handling(self):
        """Test that missing optional fields (package name, store url, description) are handled safely."""
        minimal_app = {
            "app_name": "Simple App",
            "developer_name": "Simple Dev"
        }
        extracted = mobile_app_features.extract_app_features(minimal_app)
        self.assertEqual(len(extracted["feature_vector"]), 215)
        self.assertFalse(any(np.isnan(x) for x in extracted["feature_vector"]))
        self.assertIn("package_name", extracted["missing_fields"])
        self.assertEqual(extracted["total_permissions_count"], 0)

    def test_fairness_on_standard_sensitive_permissions(self):
        """Test Fairness Safeguard: Apps requesting camera/location are not falsely flagged as malware alone."""
        camera_app = {
            "app_name": "Official Photo Editor",
            "developer_name": "Photo Studio Inc",
            "store_url": "https://play.google.com/store/apps/details?id=com.photo.editor",
            "description": "Edit your photos and share with friends.",
            "permissions": ["CAMERA", "WRITE_EXTERNAL_STORAGE", "ACCESS_NETWORK_STATE"]
        }
        res = mobile_app_detector.analyze_app(camera_app)
        self.assertTrue(res["available"])
        self.assertFalse(res["ml_prediction"]["is_malware_suspect"])
        self.assertEqual(res["ml_prediction"]["prediction_label"], "BENIGN / LOW-RISK APPLICATION")

    def test_input_validation_and_bounds(self):
        """Test that invalid inputs or extreme string lengths are handled safely."""
        # Missing app title
        valid, msg, _ = mobile_app_detector.validate_inputs("", "Dev Name", "", "")
        self.assertFalse(valid)
        self.assertIn("title is required", msg.lower())

        # Missing developer name
        valid, msg, _ = mobile_app_detector.validate_inputs("App Title", "", "", "")
        self.assertFalse(valid)
        self.assertIn("developer", msg.lower())

        # Oversized inputs
        huge_title = "A" * 200
        valid, msg, _ = mobile_app_detector.validate_inputs(huge_title, "Dev", "", "")
        self.assertFalse(valid)
        self.assertIn("exceeds", msg.lower())

    def test_model_inference_benign_vs_malicious(self):
        """Test Model 3 prediction on benign vs malicious application profiles."""
        # Benign app
        benign_res = mobile_app_detector.analyze_app(self.sample_benign_app, self.sample_brand)
        self.assertTrue(benign_res["available"])
        self.assertFalse(benign_res["ml_prediction"]["is_malware_suspect"])
        self.assertEqual(benign_res["risk_category"], "Lower-risk indicators")

        # Malicious app with dangerous telephony, SMS, root permissions
        mal_res = mobile_app_detector.analyze_app(self.sample_malicious_app, self.sample_brand)
        self.assertTrue(mal_res["available"])
        self.assertTrue(mal_res["ml_prediction"]["is_malware_suspect"])
        self.assertEqual(mal_res["ml_prediction"]["prediction_label"], "MALICIOUS / HIGH-RISK APK")
        self.assertEqual(mal_res["risk_category"], "High-risk indicators")
        self.assertGreaterEqual(mal_res["ml_prediction"]["malware_probability_pct"], 50.0)

    def test_model_metrics_benchmark_integrity(self):
        """Test that evaluated Model 3 metrics match measured Drebin benchmark performance."""
        metrics = mobile_app_detector.get_app_metrics()
        self.assertIn("evaluation", metrics)
        eval_data = metrics["evaluation"]

        self.assertGreaterEqual(eval_data["accuracy"], 0.94)
        self.assertGreaterEqual(eval_data["precision"], 0.85)
        self.assertGreaterEqual(eval_data["recall"], 0.90)
        self.assertGreaterEqual(eval_data["f1_score"], 0.90)
        self.assertGreaterEqual(eval_data["roc_auc"], 0.97)

        # Confusion matrix sanity
        cm = eval_data["confusion_matrix"]
        self.assertGreater(cm["true_positives"], 250)
        self.assertGreater(cm["true_negatives"], 950)

    def test_rapidfuzz_developer_verification(self):
        """Test RapidFuzz developer entity matching against corporate Brand Registry."""
        # Verified match
        match = mobile_app_detector.compare_with_brand_developers("Apex Financial Technologies LLC", self.sample_brand)
        self.assertTrue(match["is_verified_developer"])
        self.assertIn("VERIFIED_DEVELOPER_MATCH", match["impersonation_flags"])

        # Typosquatting / look-alike publisher
        typo = mobile_app_detector.compare_with_brand_developers("Apex Financial Tech LLC Support", self.sample_brand)
        self.assertFalse(typo["is_verified_developer"])
        self.assertGreaterEqual(typo["developer_similarity_pct"], 65.0)

    def test_model_independence(self):
        """Test that Model 1 (URLs), Model 2 (Social Profiles), and Model 3 (Apps) operate independently."""
        # Model 1 URL check
        url_res = ml_detector.predict_url("http://secure-login-update-apexbank.com.xyz/login")
        self.assertTrue(url_res["available"])

        # Model 2 Social check
        profile_res = social_profile_detector.predict_profile({
            "username": "apexbank_support",
            "name": "Apex Support",
            "description": "Send DM for immediate funds unlock"
        })
        self.assertTrue(profile_res["available"])

        # Model 3 Mobile App check
        app_res = mobile_app_detector.predict_app(self.sample_malicious_app)
        self.assertTrue(app_res["available"])

        # Ensure all models return their distinct model labels without cross-talk
        self.assertIn(url_res["prediction"], ["PHISHING DETECTED", "LEGITIMATE / BENIGN", "PHISHING", "BENIGN"])
        self.assertIn(profile_res["prediction"], ["SPAM / BOT SUSPECT", "AUTHENTIC / HUMAN PROFILE"])
        self.assertIn(app_res["prediction"], ["MALICIOUS / HIGH-RISK APK", "BENIGN / LOW-RISK APPLICATION"])

    def test_database_persistence_and_retrieval(self):
        """Test SQLite persistence of app_ml_findings and full retrieval."""
        database.init_db()

        analysis = detector.analyze_mobile_app(
            app_name=self.sample_benign_app["app_name"],
            developer_name=self.sample_benign_app["developer_name"],
            store_url=self.sample_benign_app["store_url"],
            description=self.sample_benign_app["description"],
            brand_dict=self.sample_brand
        )
        self.assertIn("app_ml_findings", analysis)
        self.assertTrue(analysis["app_ml_findings"]["available"])

        scan_id = database.save_scan(
            scan_type="app",
            target_brand_id=1,
            target_brand_name="ApexBank",
            input_title=self.sample_benign_app["app_name"],
            input_details=self.sample_benign_app,
            risk_score=analysis["risk_score"],
            risk_category=analysis["risk_category"],
            summary_reason=analysis["summary_reason"],
            indicators=analysis["heuristic_findings"],
            recommendations=analysis["recommendations"],
            api_findings=analysis.get("api_findings"),
            app_ml_findings=analysis.get("app_ml_findings")
        )
        self.assertIsInstance(scan_id, int)

        # Retrieve single scan
        saved = database.get_scan_by_id(scan_id)
        self.assertIsNotNone(saved)
        self.assertEqual(saved["scan_type"], "app")
        self.assertIn("app_ml_findings", saved)
        self.assertTrue(saved["app_ml_findings"].get("available"))
        self.assertEqual(saved["app_ml_findings"]["prediction"], "BENIGN / LOW-RISK APPLICATION")

        # Retrieve recent scans list
        recents = database.get_recent_scans(limit=5, scan_type="app")
        self.assertTrue(len(recents) > 0)
        matched = next((s for s in recents if s["id"] == scan_id), None)
        self.assertIsNotNone(matched)
        self.assertTrue(matched["app_ml_findings"].get("available"))

    def test_virustotal_apk_hash_lookup_and_error_handling(self):
        """Test Requirement 4: VirusTotal hash lookup, validation, and safe error handling."""
        import virustotal

        # 1. Invalid hash formats are caught without network requests
        inv = virustotal.check_file_hash_virustotal("not_a_real_hash")
        self.assertEqual(inv["status"], "invalid_hash")
        self.assertFalse(inv["is_flagged"])

        # 2. Valid SHA-256 string format is accepted
        valid_sha256 = "5e884898da28047151d0e56f8dc6292773603d0d6aabbdd62a11ef721d1542d8"
        vt_res = virustotal.check_file_hash_virustotal(valid_sha256)
        self.assertIn("status", vt_res)
        # Even if unconfigured or not found, must never crash
        self.assertIn(vt_res["status"], ["success", "not_found", "unconfigured", "rate_limited", "api_error", "timeout", "service_unavailable"])

        # 3. Requirement 4: Never label an app safe solely because no threat was found
        # When not found (404), the summary must state absence does not prove safety
        if vt_res["status"] == "not_found":
            self.assertIn("does not prove", vt_res["details"].lower())

    def test_flask_app_checker_endpoints(self):
        """Test Requirement 3 & 5: Dedicated Flask routes, input validation, and API metrics."""
        import app
        client = app.app.test_client()

        # 1. GET /app-checker
        r_get = client.get('/app-checker')
        self.assertEqual(r_get.status_code, 200)

        # 2. POST /app-checker with app metadata
        payload = {
            "app_name": "Apex Security Guard",
            "developer_name": "Apex Financial Technologies LLC",
            "store_url": "https://play.google.com/store/apps/details?id=com.apex.security",
            "description": "Enterprise mobile security client for workforce authentication.",
            "apk_hash": "5e884898da28047151d0e56f8dc6292773603d0d6aabbdd62a11ef721d1542d8",
            "brand_id": "1"
        }
        r_post = client.post('/app-checker', data=payload)
        self.assertEqual(r_post.status_code, 200)

        # 3. POST /api/scan/app JSON endpoint
        r_api = client.post('/api/scan/app', json=payload)
        self.assertEqual(r_api.status_code, 200)
        api_data = r_api.get_json()
        self.assertIn("scan_id", api_data)
        self.assertIn("app_ml_findings", api_data)
        self.assertIn("api_findings", api_data)
        self.assertTrue(api_data["app_ml_findings"]["available"])

        # 4. GET /api/app-ml-metrics endpoint
        r_metrics = client.get('/api/app-ml-metrics')
        self.assertEqual(r_metrics.status_code, 200)
        metrics = r_metrics.get_json()
        self.assertEqual(metrics["num_features"], 215)
        self.assertIn("RandomForest", metrics["model_name"])

if __name__ == "__main__":
    unittest.main()
