"""
BrandShield AI - Comprehensive Automated Test Suite
Validates:
1. Differentiating genuine profile URLs vs fake profile URLs
2. RapidFuzz handle, brand-name, and typosquatting heuristics
3. VirusTotal API v3 integration and graceful error handling (401, 404, 429, timeouts, unconfigured keys)
4. Mobile app developer identity verification
5. Four standard risk categories: HIGH RISK, SUSPICIOUS, LOW RISK, UNKNOWN / INSUFFICIENT DATA
6. SQLite persistence and Flask HTTP endpoints
"""

import os
os.environ["SUPABASE_TEST_MODE"] = "1"

import unittest
from unittest.mock import patch, MagicMock
import requests
import database
import detector
import virustotal
from app import app

class BrandShieldRemodeledTestSuite(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        database.init_db(force_reseed=True)
        cls.client = app.test_client()

    def test_01_brand_registry_and_demo_baselines(self):
        """Verify baseline 5 demo brands and brand registry CRUD."""
        brands = database.get_all_brands()
        self.assertGreaterEqual(len(brands), 5)
        names = [b['name'] for b in brands]
        for demo in ["ApexBank", "CloudShield", "NexaPay", "VertexHealth", "StreamPulse"]:
            self.assertIn(demo, names, f"Demo brand {demo} should exist")

    def test_02_genuine_vs_fake_profile_urls_in_link_checker(self):
        """
        CRITICAL FIX VALIDATION:
        Verify that genuine profile URLs and fake profile URLs DO NOT produce the same result.
        Genuine profile URLs must be LOW RISK.
        Fake/look-alike profile URLs must be HIGH RISK.
        """
        apex = next(b for b in database.get_all_brands() if b['name'] == 'ApexBank')

        # 1. Genuine Twitter/X Profile URL
        res_genuine_x = detector.analyze_suspicious_link("https://x.com/apexbank", apex)
        self.assertEqual(res_genuine_x['risk_category'], "LOW RISK", "Genuine profile URL must be LOW RISK")
        self.assertLessEqual(res_genuine_x['risk_score'], 15)
        self.assertTrue(res_genuine_x.get('social_profile_detected'))

        # 2. Fake / Impersonating Twitter/X Profile URL
        res_fake_x = detector.analyze_suspicious_link("https://x.com/apexbank_scam_support", apex)
        self.assertEqual(res_fake_x['risk_category'], "HIGH RISK", "Fake profile URL must be HIGH RISK")
        self.assertGreaterEqual(res_fake_x['risk_score'], 70)
        self.assertNotEqual(res_genuine_x['risk_score'], res_fake_x['risk_score'], "Scores must not be identical")

        # 3. Genuine Instagram Profile URL
        res_genuine_ig = detector.analyze_suspicious_link("https://instagram.com/apexbank", apex)
        self.assertEqual(res_genuine_ig['risk_category'], "LOW RISK")

        # 4. Fake Instagram Profile URL with lure keyword
        res_fake_ig = detector.analyze_suspicious_link("https://instagram.com/apexbank_giveaway_official", apex)
        self.assertEqual(res_fake_ig['risk_category'], "HIGH RISK")

        # 5. Genuine Telegram Profile URL
        res_genuine_tg = detector.analyze_suspicious_link("https://t.me/apexbank", apex)
        self.assertEqual(res_genuine_tg['risk_category'], "LOW RISK")

        # 6. Fake Telegram Profile URL
        res_fake_tg = detector.analyze_suspicious_link("https://t.me/apexbank_crypto_bot", apex)
        self.assertEqual(res_fake_tg['risk_category'], "HIGH RISK")

    def test_03_social_checker_profile_url_cross_referencing(self):
        """Verify social profile checker catches masquerading and handle/URL discrepancies."""
        apex = next(b for b in database.get_all_brands() if b['name'] == 'ApexBank')

        # 1. Official handle and matching URL
        res_auth = detector.analyze_social_profile(
            platform="Twitter / X",
            profile_name="ApexBank Official",
            username="@apexbank",
            profile_url="https://x.com/apexbank",
            description="Official corporate handle.",
            brand_dict=apex
        )
        self.assertEqual(res_auth['risk_category'], "LOW RISK")

        # 2. Handle / URL Discrepancy (User submits official handle @apexbank, but rogue URL)
        res_discrepancy = detector.analyze_social_profile(
            platform="Twitter / X",
            profile_name="ApexBank Support",
            username="@apexbank",
            profile_url="https://x.com/apexbank_fake_desk",
            description="Priority support helpdesk.",
            brand_dict=apex
        )
        self.assertIn(res_discrepancy['risk_category'], ["HIGH RISK", "SUSPICIOUS"])
        self.assertTrue(any("Discrepancy" in f['name'] for f in res_discrepancy['heuristic_findings']))

        # 3. Leetspeak homoglyph
        cloud = next(b for b in database.get_all_brands() if b['name'] == 'CloudShield')
        res_leet = detector.analyze_social_profile(
            platform="Telegram",
            profile_name="CloudShield Bot",
            username="@cl0udshie1d_giveaways",
            profile_url="https://t.me/cl0udshie1d_giveaways",
            description="Claim free crypto airdrop reward! DM your wallet seed phrase.",
            brand_dict=cloud
        )
        self.assertEqual(res_leet['risk_category'], "HIGH RISK")
        self.assertGreaterEqual(res_leet['risk_score'], 70)

    def test_04_standard_link_heuristics_and_safety(self):
        """Verify suspicious link heuristics for web domains (never visiting endpoints)."""
        apex = next(b for b in database.get_all_brands() if b['name'] == 'ApexBank')
        vertex = next(b for b in database.get_all_brands() if b['name'] == 'VertexHealth')

        # 1. Official domain
        res_portal = detector.analyze_suspicious_link("https://portal.vertexhealth.org/patient/login", vertex)
        self.assertEqual(res_portal['risk_category'], "LOW RISK")
        self.assertLessEqual(res_portal['risk_score'], 10)

        # 2. Phishing look-alike compound domain
        res_phish = detector.analyze_suspicious_link("http://apexbank-login-secure.xyz/ebanking/verify", apex)
        self.assertEqual(res_phish['risk_category'], "HIGH RISK")
        self.assertGreaterEqual(res_phish['risk_score'], 70)

        # 3. Raw IP hostname
        res_ip = detector.analyze_suspicious_link("http://192.168.1.105:8080/apexbank/login", apex)
        self.assertIn(res_ip['risk_category'], ["HIGH RISK", "SUSPICIOUS"])

        # 4. Malformed/Empty input
        res_empty = detector.analyze_suspicious_link("", apex)
        self.assertEqual(res_empty['risk_category'], "UNKNOWN / INSUFFICIENT DATA")

    def test_05_virustotal_api_integration_and_error_handling(self):
        """
        Verify VirusTotal API v3 integration, base64 url-safe identifier,
        and graceful handling of all error conditions (missing key, 401, 404, 429, timeout).
        """
        # 1. Unconfigured API Key
        with patch.dict('os.environ', {'VIRUSTOTAL_API_KEY': ''}):
            res_unconf = virustotal.check_url_virustotal("https://example.com/test")
            self.assertEqual(res_unconf['status'], "unconfigured")
            self.assertFalse(res_unconf['configured'])
            self.assertFalse(res_unconf['is_flagged'])
            self.assertIn("not configured", res_unconf['summary'])

        # 2. HTTP 404: URL Not Found in VirusTotal Dataset
        mock_404 = MagicMock()
        mock_404.status_code = 404
        with patch.dict('os.environ', {'VIRUSTOTAL_API_KEY': 'test_fake_api_key_12345'}):
            with patch('requests.get', return_value=mock_404):
                res_404 = virustotal.check_url_virustotal("https://newly-observed-phish.xyz/landing")
                self.assertEqual(res_404['status'], "not_found")
                self.assertIn("not found in threat-intelligence records", res_404['summary'])

        # 3. HTTP 401: Invalid API Key
        mock_401 = MagicMock()
        mock_401.status_code = 401
        with patch.dict('os.environ', {'VIRUSTOTAL_API_KEY': 'invalid_bad_key'}):
            with patch('requests.get', return_value=mock_401):
                res_401 = virustotal.check_url_virustotal("https://example.com")
                self.assertEqual(res_401['status'], "auth_error")
                self.assertIn("authentication failed", res_401['summary'])

        # 4. HTTP 429: Rate Limit Exceeded
        mock_429 = MagicMock()
        mock_429.status_code = 429
        with patch.dict('os.environ', {'VIRUSTOTAL_API_KEY': 'test_fake_api_key'}):
            with patch('requests.get', return_value=mock_429):
                res_429 = virustotal.check_url_virustotal("https://example.com")
                self.assertEqual(res_429['status'], "rate_limited")
                self.assertIn("rate limit reached", res_429['summary'])

        # 5. Network Timeout
        with patch.dict('os.environ', {'VIRUSTOTAL_API_KEY': 'test_fake_api_key'}):
            with patch('requests.get', side_effect=requests.exceptions.Timeout("Connection timed out")):
                res_timeout = virustotal.check_url_virustotal("https://example.com")
                self.assertEqual(res_timeout['status'], "timeout")
                self.assertIn("timed out", res_timeout['summary'])

        # 6. HTTP 200: Positive Malicious Detection
        mock_200_malicious = MagicMock()
        mock_200_malicious.status_code = 200
        mock_200_malicious.json.return_value = {
            "data": {
                "attributes": {
                    "last_analysis_stats": {
                        "malicious": 8,
                        "suspicious": 2,
                        "harmless": 60,
                        "undetected": 18
                    },
                    "reputation": -45,
                    "categories": {"VendorA": "phishing"}
                }
            }
        }
        with patch.dict('os.environ', {'VIRUSTOTAL_API_KEY': 'test_fake_api_key'}):
            with patch('requests.get', return_value=mock_200_malicious):
                res_flagged = virustotal.check_url_virustotal("http://known-malicious-phish.xyz")
                self.assertEqual(res_flagged['status'], "success")
                self.assertTrue(res_flagged['is_flagged'])
                self.assertEqual(res_flagged['malicious_count'], 8)

        # 7. Social Platform Rule 8 Notice
        mock_200_social = MagicMock()
        mock_200_social.status_code = 200
        mock_200_social.json.return_value = {
            "data": {
                "attributes": {
                    "last_analysis_stats": {"malicious": 0, "harmless": 85},
                    "reputation": 10
                }
            }
        }
        with patch.dict('os.environ', {'VIRUSTOTAL_API_KEY': 'test_fake_api_key'}):
            with patch('requests.get', return_value=mock_200_social):
                res_social = virustotal.check_url_virustotal("https://x.com/apexbank")
                self.assertTrue(res_social['is_social_platform'])
                self.assertIn("Clean domain reputation does NOT guarantee", res_social['social_notice'])

    def test_06_mobile_app_heuristics(self):
        """Verify mobile app checker publisher verification and trojan detection."""
        apex = next(b for b in database.get_all_brands() if b['name'] == 'ApexBank')
        nexa = next(b for b in database.get_all_brands() if b['name'] == 'NexaPay')

        # 1. Authentic verified developer app
        res_auth = detector.analyze_mobile_app(
            app_name="ApexBank Mobile Banking",
            developer_name="Apex Financial Technologies LLC",
            store_url="https://play.google.com/store/apps/details?id=com.apexbank.mobile",
            description="Official mobile banking app.",
            brand_dict=apex
        )
        self.assertEqual(res_auth['risk_category'], "LOW RISK")

        # 2. Rogue look-alike developer
        res_rogue = detector.analyze_mobile_app(
            app_name="ApexBank Instant Loan & Fast Cash",
            developer_name="Apex Mobile Finance Apps LLC",
            store_url="https://play.google.com/store/apps/details?id=com.apex.fastloan",
            description="Instant loans without credit check.",
            brand_dict=apex
        )
        self.assertEqual(res_rogue['risk_category'], "HIGH RISK")

        # 3. Trojanized APK mirror
        res_trojan = detector.analyze_mobile_app(
            app_name="NexaPay Wallet Mod",
            developer_name="FastCash Studios",
            store_url="https://apk-mirrorsite.org/nexapay-mod.apk",
            description="Requires Root and SMS read permission to hook payments.",
            brand_dict=nexa
        )
        self.assertEqual(res_trojan['risk_category'], "HIGH RISK")

    def test_07_http_routes_and_exports(self):
        """Verify all Flask HTTP routes, forms, and CSV/JSON export endpoints with active session."""
        with self.client.session_transaction() as sess:
            sess['user'] = {
                'email': 'analyst@brandshield.ai',
                'name': 'Alex Morgan',
                'role': 'Lead Threat Analyst'
            }

        endpoints = [
            '/',
            '/dashboard',
            '/brands',
            '/social-checker',
            '/link-checker',
            '/app-checker',
            '/history',
            '/api/dashboard-stats',
            '/history/export/csv',
            '/history/export/json'
        ]
        for ep in endpoints:
            res = self.client.get(ep, follow_redirects=True)
            self.assertEqual(res.status_code, 200, f"Route {ep} must return 200")

        # Test POST submissions
        post_link = self.client.post('/link-checker', data={
            'brand_id': '1',
            'url': 'https://x.com/apexbank_scam_support'
        }, follow_redirects=True)
        self.assertEqual(post_link.status_code, 200)

        post_social = self.client.post('/social-checker', data={
            'brand_id': '1',
            'platform': 'Twitter / X',
            'username': '@apexbank_support_help',
            'profile_name': 'Apex Support',
            'profile_url': 'https://x.com/apexbank_support_help',
            'description': 'Send DM with account number for instant refund.'
        }, follow_redirects=True)
        self.assertEqual(post_social.status_code, 200)

if __name__ == '__main__':
    unittest.main()
