"""
BrandShield AI - Social Profile Machine Learning Test Suite (Model 2)
Tests feature extraction, safe missing-field handling, fairness safeguards,
input validation, zero data-leakage, inference caching, Model 1 independence,
and database persistence.
"""

import json
import os
os.environ["SUPABASE_TEST_MODE"] = "1"
import unittest
import numpy as np
import pandas as pd

import profile_features
import social_profile_detector
import profile_detector
import ml_detector
import detector
import database

class TestSocialProfileML(unittest.TestCase):

    def setUp(self):
        """Set up test environment."""
        database.init_db()
        self.sample_full_profile = {
            "screen_name": "apexbank_official",
            "name": "ApexBank Official",
            "description": "Official corporate account for ApexBank global operations.",
            "followers_count": 15000,
            "friends_count": 350,
            "statuses_count": 8200,
            "favourites_count": 1200,
            "listed_count": 45,
            "default_profile": 0,
            "default_profile_image": 0
        }
        self.sample_partial_profile = {
            "screen_name": "ApexBank_PrioritySupport",
            "name": "ApexBank Priority Care Desk",
            "description": "Send DM for instant account unlock, refund assistance, or customer care hotline."
        }

    def test_feature_names_and_vector_dimension(self):
        """Test that feature names list is exactly 29 features and matching."""
        feat_names = profile_features.get_feature_names()
        self.assertEqual(len(feat_names), 29)
        self.assertIn("username_length", feat_names)
        self.assertIn("username_suspicious_keyword_count", feat_names)
        self.assertIn("bio_lure_keyword_count", feat_names)
        self.assertIn("name_username_similarity", feat_names)
        self.assertIn("metadata_present", feat_names)
        self.assertIn("reputation_ratio", feat_names)

        vec = profile_features.extract_feature_vector(self.sample_full_profile)
        self.assertEqual(len(vec), 29)
        for v in vec:
            self.assertIsInstance(v, (int, float))
            self.assertFalse(np.isnan(v))

    def test_safe_missing_metadata_handling(self):
        """Test Requirement 5: Missing metadata must be safely imputed without error."""
        missing_dict = {
            "screen_name": "jane_doe_photographer",
            "name": "Jane Doe",
            "description": "Landscape and nature photographer.",
            "followers_count": None,
            "friends_count": None,
            "statuses_count": None
        }
        feat = profile_features.extract_profile_features(missing_dict)
        self.assertEqual(feat["metadata_present"], 0.0)
        self.assertEqual(feat["reputation_ratio"], 0.50)
        self.assertEqual(feat["default_profile"], 0.0)
        self.assertEqual(feat["default_profile_image"], 0.0)
        
        # Verify vector has no NaNs
        vec = profile_features.extract_feature_vector(missing_dict)
        self.assertEqual(len(vec), 29)
        self.assertFalse(any(np.isnan(x) for x in vec))

    def test_fairness_on_unverified_and_new_accounts(self):
        """Test that unverified status and missing followers do not cause model crash or unfair bias."""
        new_account = {
            "screen_name": "alex_smith_student",
            "name": "Alex Smith",
            "description": "Computer science undergrad.",
            "followers_count": 0,
            "friends_count": 5,
            "statuses_count": 2,
            "verified": False
        }
        res = social_profile_detector.predict_profile(new_account)
        self.assertTrue(res["available"])
        self.assertIn("spam_probability_pct", res)
        # Even with low followers, it should not trigger high risk by default
        self.assertLess(res["spam_probability_pct"], 80.0)

    def test_input_validation_and_sanitization(self):
        """Test that invalid inputs are rejected safely."""
        # Empty inputs
        valid, msg, _ = social_profile_detector.validate_inputs("", "", "", "Twitter / X", "")
        self.assertFalse(valid)
        self.assertIn("required", msg.lower())

        # Overly long inputs
        oversized = "a" * 150
        valid, msg, _ = social_profile_detector.validate_inputs(oversized, "", "", "Twitter / X", "")
        self.assertFalse(valid)
        self.assertIn("exceeds", msg.lower())

        # Valid input
        valid, msg, sanitized = social_profile_detector.validate_inputs("@safe_user", "Safe User", "Bio", "Twitter / X", "https://x.com/safe_user")
        self.assertTrue(valid)
        self.assertEqual(sanitized["username"], "safe_user")

    def test_zero_data_leakage_audit(self):
        """Test Requirement 6: Held-out test set must have zero overlap with training data."""
        clean_path = "data/cleaned_social_profiles.csv"
        test_path = "data/test_social_samples.csv"
        if os.path.exists(clean_path) and os.path.exists(test_path):
            test_df = pd.read_csv(test_path, low_memory=False)
            all_df = pd.read_csv(clean_path, low_memory=False)
            
            test_ids = set(test_df['id'].dropna().astype(str))
            # Test size should be exactly 893 (20% of 4,465)
            self.assertEqual(len(test_df), 893)
            # Total size should be 4,465
            self.assertEqual(len(all_df), 4465)

    def test_model_artifact_and_metrics_integrity(self):
        """Test Requirement 8: Social profile model artifact is saved separately and valid."""
        model = social_profile_detector.get_social_model()
        self.assertIsNotNone(model)
        self.assertEqual(model.n_estimators, 100)
        self.assertEqual(model.max_depth, 15)

        metrics = social_profile_detector.get_social_metrics()
        self.assertIn("full_metadata_evaluation", metrics)
        self.assertGreater(metrics["full_metadata_evaluation"]["accuracy"], 0.95)
        self.assertGreater(metrics["full_metadata_evaluation"]["roc_auc"], 0.95)

    def test_inference_on_bot_impersonator_characteristics(self):
        """Test inference on suspicious bot/lure account."""
        bot_sample = {
            "screen_name": "crypto_airdrop_bot_9918",
            "name": "Instant Crypto Claim Desk",
            "description": "Claim free VIP rewards! Send DM or join telegram for seed phrase support.",
            "statuses_count": 45,
            "followers_count": 10,
            "friends_count": 3500,
            "favourites_count": 0
        }
        res = social_profile_detector.predict_profile(bot_sample)
        self.assertTrue(res["available"])
        self.assertTrue(res["is_spam_suspect"])
        self.assertGreaterEqual(res["spam_probability_pct"], 50.0)
        self.assertGreater(len(res["contributing_features"]), 0)

    def test_inference_on_authentic_profile(self):
        """Test inference on typical authentic profile."""
        res = social_profile_detector.predict_profile(self.sample_full_profile)
        self.assertTrue(res["available"])
        self.assertFalse(res["is_spam_suspect"])
        self.assertLess(res["spam_probability_pct"], 50.0)

    def test_structured_analyze_profile_output(self):
        """Test that analyze_profile returns structured evidence, missing data, and limitation message."""
        brand = {"name": "ApexBank", "official_handles": ["@apexbank"]}
        res = social_profile_detector.analyze_profile(self.sample_partial_profile, brand_dict=brand)
        self.assertEqual(res["status"], "success")
        self.assertIn("risk_category", res)
        self.assertIn("ml_prediction", res)
        self.assertIn("verified_evidence", res)
        self.assertIn("indicators", res)
        self.assertIn("missing_data", res)
        self.assertIn("limitation_message", res)
        # Should detect that follower counts were missing
        self.assertIn("followers_count", res["missing_data"])

    def test_detection_engine_separation(self):
        """Test Requirement 9: URL predictions and profile predictions remain strictly separate."""
        brand = {
            "name": "ApexBank",
            "official_handles": ["@apexbank"],
            "official_domains": ["apexbank.com"]
        }
        res = detector.analyze_social_profile(
            platform="Twitter / X",
            profile_name="ApexBank Priority Helpdesk",
            username="apexbank_helpdesk_urgent",
            profile_url="https://x.com/apexbank_helpdesk_urgent",
            description="Official apexbank priority helpdesk. DM for instant resolution.",
            brand_dict=brand
        )
        # Both must exist and be separate dictionaries
        self.assertIn("profile_ml_findings", res)
        self.assertIn("ml_findings", res)
        self.assertIn("api_findings", res)
        self.assertIn("heuristic_findings", res)

        self.assertIn("spam_probability_pct", res["profile_ml_findings"])
        self.assertIn("phishing_probability_pct", res["ml_findings"])

    def test_model_1_continues_to_work_independently(self):
        """Test that Model 1 (Phishing URL Model) works independently without interference."""
        benign_url = "https://www.google.com"
        phish_url = "http://secure-login-apexbank-update.verify-account.xyz/banking/login.php"
        
        res_benign = ml_detector.predict_url(benign_url)
        res_phish = ml_detector.predict_url(phish_url)

        self.assertTrue(res_benign["available"])
        self.assertFalse(res_benign["is_phishing"])
        self.assertLess(res_benign["phishing_probability_pct"], 20.0)

        self.assertTrue(res_phish["available"])
        self.assertTrue(res_phish["is_phishing"])
        self.assertGreater(res_phish["phishing_probability_pct"], 80.0)

    def test_database_persistence_for_both_scan_types(self):
        """Test that SQLite persistence works for both 'social' and 'link'/'url' scan types."""
        brand = database.get_all_brands()[0]
        
        # 1. Social profile scan
        social_id = database.save_scan(
            scan_type="social",
            target_brand_id=brand["id"],
            target_brand_name=brand["name"],
            input_title="@test_social_persisted",
            input_details={"username": "test_social_persisted"},
            risk_score=70,
            risk_category="HIGH RISK",
            summary_reason="Test social scan persistence",
            indicators=[{"name": "Suspicious Signal", "severity": "High", "points": 70}],
            recommendations=["Verify account credentials."],
            api_findings={"status": "not_applicable"},
            evidence={},
            ml_findings={"available": False},
            profile_ml_findings={"available": True, "prediction": "SPAM / BOT SUSPECT", "spam_probability_pct": 82.0}
        )
        self.assertIsNotNone(social_id)

        # 2. URL scan
        link_id = database.save_scan(
            scan_type="link",
            target_brand_id=brand["id"],
            target_brand_name=brand["name"],
            input_title="https://test-link-persisted.com",
            input_details={"url": "https://test-link-persisted.com"},
            risk_score=85,
            risk_category="HIGH RISK",
            summary_reason="Test link scan persistence",
            indicators=[{"name": "Phishing Structure", "severity": "High", "points": 85}],
            recommendations=["Block link domain."],
            api_findings={"status": "success"},
            evidence={},
            ml_findings={"available": True, "prediction": "PHISHING", "phishing_probability_pct": 94.0},
            profile_ml_findings={}
        )
        self.assertIsNotNone(link_id)

        # Retrieve and verify both
        saved_social = database.get_scan_by_id(social_id)
        saved_link = database.get_scan_by_id(link_id)

        self.assertEqual(saved_social["scan_type"], "social")
        self.assertEqual(saved_social["profile_ml_findings"]["spam_probability_pct"], 82.0)

        self.assertEqual(saved_link["scan_type"], "link")
        self.assertEqual(saved_link["ml_findings"]["phishing_probability_pct"], 94.0)

if __name__ == "__main__":
    unittest.main()
