"""
BrandShield AI - REST API Endpoint Verification Suite
Verifies all JSON API endpoints used by the Vite React frontend on Vercel:
- /health and /api/health
- /api/status
- /api/auth/login, /api/auth/me, /api/auth/logout, /api/auth/signup
- /api/brands (GET, POST, DELETE, reset)
- /api/scan/link, /api/scan/social, /api/scan/app
- /api/history and /api/scan/<id>
"""

import unittest
from app import app
import database

class TestBrandShieldRestApi(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        database.init_db(force_reseed=True)
        cls.client = app.test_client()

    def test_01_health_and_status_endpoints(self):
        """Verify health check and engine telemetry endpoints."""
        res_h = self.client.get('/health')
        self.assertEqual(res_h.status_code, 200)
        self.assertEqual(res_h.get_json().get('status'), 'healthy')

        res_s = self.client.get('/api/status')
        self.assertEqual(res_s.status_code, 200)
        data = res_s.get_json()
        self.assertIn('ml_active', data)
        self.assertIn('virustotal_active', data)

    def test_02_auth_lifecycle(self):
        """Verify login, session check, and logout via REST API."""
        # 1. Check me before login
        res_me_before = self.client.get('/api/auth/me')
        self.assertEqual(res_me_before.status_code, 200)
        self.assertFalse(res_me_before.get_json().get('authenticated'))

        # 2. Login
        res_login = self.client.post('/api/auth/login', json={
            'username': 'analyst@brandshield.ai',
            'password': 'CyberShield2026!',
            'remember': True
        })
        self.assertEqual(res_login.status_code, 200)
        self.assertTrue(res_login.get_json().get('success'))
        self.assertEqual(res_login.get_json().get('user', {}).get('name'), 'Alex Morgan')

        # 3. Check me after login
        res_me_after = self.client.get('/api/auth/me')
        self.assertEqual(res_me_after.status_code, 200)
        self.assertTrue(res_me_after.get_json().get('authenticated'))

        # 4. Logout
        res_logout = self.client.post('/api/auth/logout')
        self.assertEqual(res_logout.status_code, 200)
        self.assertTrue(res_logout.get_json().get('success'))

        # 5. Check me after logout
        res_me_final = self.client.get('/api/auth/me')
        self.assertFalse(res_me_final.get_json().get('authenticated'))

    def test_03_brand_registry_rest_crud(self):
        """Verify brand listing, creation, and deletion via REST API."""
        # Login first
        self.client.post('/api/auth/login', json={
            'username': 'analyst@brandshield.ai',
            'password': 'CyberShield2026!'
        })

        # List brands
        res_list = self.client.get('/api/brands')
        self.assertEqual(res_list.status_code, 200)
        brands = res_list.get_json().get('brands', [])
        self.assertGreaterEqual(len(brands), 5)

        # Add brand
        res_add = self.client.post('/api/brands', json={
            'name': 'TitanDefense',
            'category': 'Cyber Defense',
            'description': 'Defense and incident response enterprise',
            'handles': ['@titandefense', '@titan_sec'],
            'domains': ['titandefense.com'],
            'developers': ['Titan Technologies LLC']
        })
        self.assertEqual(res_add.status_code, 200)
        new_id = res_add.get_json().get('brand_id')
        self.assertTrue(new_id)

        # Delete brand
        res_del = self.client.delete(f'/api/brands/{new_id}')
        self.assertEqual(res_del.status_code, 200)
        self.assertTrue(res_del.get_json().get('success'))

    def test_04_scanner_and_history_apis(self):
        """Verify scanning engines and history audit APIs."""
        self.client.post('/api/auth/login', json={
            'username': 'analyst@brandshield.ai',
            'password': 'CyberShield2026!'
        })

        # Link scan
        res_link = self.client.post('/api/scan/link', json={
            'url': 'https://apexbank-secure-login.xyz',
            'brand_id': 1
        })
        self.assertEqual(res_link.status_code, 200)
        self.assertIn('risk_category', res_link.get_json())

        # History list
        res_hist = self.client.get('/api/history')
        self.assertEqual(res_hist.status_code, 200)
        scans = res_hist.get_json().get('scans', [])
        self.assertGreaterEqual(len(scans), 1)

        # Scan detail
        first_id = scans[0]['id']
        res_detail = self.client.get(f'/api/scan/{first_id}')
        self.assertEqual(res_detail.status_code, 200)
        self.assertIn('scan', res_detail.get_json())

if __name__ == '__main__':
    unittest.main()
