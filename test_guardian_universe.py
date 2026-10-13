"""
Verification test suite for BrandShield AI - Digital Guardian Universe
Validates:
1. Visual identity components (Canvas globe, Guardian mascot, holographic shield)
2. Interactive 4-slide onboarding slider markup & navigation targets
3. Real authentication workflows (Login, Session persistence, Logout, Signup, Forgot password, OAuth)
4. Dashboard telemetry & Guardian AI companion across all subpages
5. Static CSS and JS assets integrity
"""

import unittest
from app import app

class TestDigitalGuardianUniverse(unittest.TestCase):
    def setUp(self):
        self.app = app
        self.app.config['TESTING'] = True
        self.app.config['WTF_CSRF_ENABLED'] = False
        self.client = self.app.test_client()

    def test_login_page_renders_guardian_universe(self):
        """Verify login page delivers the Digital Guardian Universe theme."""
        resp = self.client.get('/login')
        self.assertEqual(resp.status_code, 200)
        html = resp.data.decode('utf-8')
        
        # Check Brand & Hologram
        self.assertIn("BrandShield", html)
        self.assertIn("Digital Guardian Universe", html)
        self.assertIn("guardianGlobeCanvas", html)
        
        # Check AI Guardian Mascot
        self.assertIn("guardianMascotContainer", html)
        self.assertIn("guardianFigure", html)
        self.assertIn("guardianEyes", html)
        self.assertIn("guardianSpeech", html)
        
        # Check Form Controls & Quick Fill
        self.assertIn("toggleLoginPassword", html)
        self.assertIn("btnQuickFill", html)
        self.assertIn("Google SSO", html)
        self.assertIn("Apple ID", html)

    def test_onboarding_slider_content(self):
        """Verify all 4 onboarding slides are rendered with required elements."""
        resp = self.client.get('/login')
        html = resp.data.decode('utf-8')

        # Check Modal Container
        self.assertIn('id="onboardingModal"', html)
        self.assertIn('id="guardianSlider"', html)

        # Slide 1: URL Threat Detection
        self.assertIn("URL Threat & Typosquat Detection", html)
        self.assertIn("apexbank-login-secure.xyz", html)
        self.assertIn("visual-url-scan", html)

        # Slide 2: Social Profile Impersonation Shield
        self.assertIn("Social Profile Impersonation Shield", html)
        self.assertIn("@apexbank", html)
        self.assertIn("@apexbank_support_help", html)
        self.assertIn("visual-social-scan", html)

        # Slide 3: Mobile App Risk & APK Analysis
        self.assertIn("Mobile App Risk & APK Analysis", html)
        self.assertIn("visual-app-scan", html)
        self.assertIn("phone-frame", html)

        # Slide 4: Security Intelligence Dashboard
        self.assertIn("Enterprise Command & Audit Trail", html)
        self.assertIn("visual-dash-preview", html)
        self.assertIn("radar-sweep-beam", html)

        # Progress dots and navigation
        self.assertIn("slider-progress-dots", html)
        self.assertIn("btnPrevSlide", html)
        self.assertIn("btnNextSlide", html)
        self.assertIn("btnFinishTour", html)

    def test_authentication_flow_success(self):
        """Verify analyst credentials authenticate and create session."""
        with self.client:
            resp = self.client.post('/login', data={
                'username': 'analyst@brandshield.ai',
                'password': 'CyberShield2026!'
            }, follow_redirects=True)
            self.assertEqual(resp.status_code, 200)
            
            # Check dashboard reached
            html = resp.data.decode('utf-8')
            self.assertIn("Security Command Center", html)
            self.assertIn("Threat Dashboard", html)
            
            # Check Guardian Companion Widget is injected
            self.assertIn("guardianCompanionWidget", html)
            self.assertIn("guardianDrawerPanel", html)
            self.assertIn("Guardian AI Assistant", html)

    def test_authentication_invalid_credentials(self):
        """Verify invalid credentials show proper cyber security warning."""
        resp = self.client.post('/login', data={
            'username': 'analyst@brandshield.ai',
            'password': 'WrongPassword123!'
        }, follow_redirects=True)
        self.assertEqual(resp.status_code, 200)
        html = resp.data.decode('utf-8')
        self.assertIn("Invalid analyst identifier or security keyphrase", html)

    def test_signup_page_and_flow(self):
        """Verify signup page renders and registers new clearance."""
        resp = self.client.get('/signup')
        self.assertEqual(resp.status_code, 200)
        html = resp.data.decode('utf-8')
        self.assertIn("Create Security Clearance", html)

        resp_post = self.client.post('/signup', data={
            'name': 'Cadet John',
            'email': 'john.cadet@brandshield.ai',
            'password': 'CadetPassword123!',
            'department': 'Digital Brand Surveillance'
        }, follow_redirects=True)
        self.assertEqual(resp_post.status_code, 200)
        post_html = resp_post.data.decode('utf-8')
        self.assertIn("Clearance created successfully", post_html)

    def test_forgot_password_flow(self):
        """Verify password recovery dispatches confirmation token."""
        resp = self.client.get('/forgot-password')
        self.assertEqual(resp.status_code, 200)
        html = resp.data.decode('utf-8')
        self.assertIn("Recover Access Key", html)

        resp_post = self.client.post('/forgot-password', data={
            'email': 'analyst@brandshield.ai'
        }, follow_redirects=True)
        self.assertEqual(resp_post.status_code, 200)
        post_html = resp_post.data.decode('utf-8')
        self.assertIn("Access token dispatched", post_html)

    def test_oauth_routes(self):
        """Verify Google and Apple SSO endpoints function."""
        resp_g = self.client.get('/oauth/google', follow_redirects=True)
        self.assertEqual(resp_g.status_code, 200)
        self.assertIn("Security Command Center", resp_g.data.decode('utf-8'))

        resp_a = self.client.get('/oauth/apple', follow_redirects=True)
        self.assertEqual(resp_a.status_code, 200)
        self.assertIn("Security Command Center", resp_a.data.decode('utf-8'))

    def test_logout_behavior(self):
        """Verify logout clears session and returns to login."""
        # First log in
        self.client.post('/login', data={
            'username': 'analyst@brandshield.ai',
            'password': 'CyberShield2026!'
        })
        resp = self.client.get('/logout', follow_redirects=True)
        self.assertEqual(resp.status_code, 200)
        html = resp.data.decode('utf-8')
        self.assertIn("Analyst session securely terminated", html)
        self.assertIn("guardianGlobeCanvas", html)

    def test_single_url_flow_unauthenticated(self):
        """Verify opening root URL while logged out presents login page."""
        resp = self.client.get('/', follow_redirects=False)
        self.assertEqual(resp.status_code, 302)
        self.assertIn('/login', resp.headers.get('Location', ''))

        resp_followed = self.client.get('/', follow_redirects=True)
        self.assertEqual(resp_followed.status_code, 200)
        html = resp_followed.data.decode('utf-8')
        self.assertIn("guardianGlobeCanvas", html)
        self.assertIn("BrandShield", html)

    def test_single_url_flow_authenticated(self):
        """Verify opening root URL while authenticated goes directly to dashboard."""
        with self.client.session_transaction() as sess:
            sess['user'] = {
                'email': 'analyst@brandshield.ai',
                'name': 'Alex Morgan',
                'role': 'Lead Threat Analyst'
            }
        resp = self.client.get('/', follow_redirects=False)
        self.assertEqual(resp.status_code, 302)
        self.assertIn('/dashboard', resp.headers.get('Location', ''))

        resp_followed = self.client.get('/', follow_redirects=True)
        self.assertEqual(resp_followed.status_code, 200)
        self.assertIn("Security Command Center", resp_followed.data.decode('utf-8'))

    def test_protected_routes_unauthenticated_blocked(self):
        """Verify unauthenticated direct access to protected routes redirects to login."""
        protected_paths = ['/dashboard', '/brands', '/social-checker', '/link-checker', '/app-checker', '/history']
        for path in protected_paths:
            with self.subTest(path=path):
                resp = self.client.get(path, follow_redirects=False)
                self.assertEqual(resp.status_code, 302)
                self.assertIn('/login', resp.headers.get('Location', ''))

        # Verify API route returns 401 JSON
        api_resp = self.client.get('/api/dashboard-stats')
        self.assertEqual(api_resp.status_code, 401)
        self.assertEqual(api_resp.get_json().get('error'), 'Unauthorized')

    def test_all_detection_engine_routes(self):
        """Verify all scanner pages render correctly with companion widget when authenticated."""
        with self.client.session_transaction() as sess:
            sess['user'] = {
                'email': 'analyst@brandshield.ai',
                'name': 'Alex Morgan',
                'role': 'Lead Threat Analyst'
            }
        routes = [
            ('/dashboard', 'Security Command Center'),
            ('/social-checker', 'Social Profile Impersonation Scanner'),
            ('/link-checker', 'Suspicious Link & Phishing Analyzer'),
            ('/app-checker', 'Mobile App Listing & Rogue APK Inspector'),
            ('/brands', 'Authorized Brand Registry'),
            ('/history', 'Security Scan Intelligence Log')
        ]
        for route, expected_text in routes:
            with self.subTest(route=route):
                resp = self.client.get(route)
                self.assertEqual(resp.status_code, 200)
                html = resp.data.decode('utf-8')
                self.assertIn(expected_text, html)
                self.assertIn("guardianCompanionWidget", html)
                self.assertIn("guardianDrawerPanel", html)

    def test_static_asset_styling_and_script(self):
        """Verify CSS contains Digital Guardian Universe tokens and JS exists."""
        css_resp = self.client.get('/static/css/style.css')
        self.assertEqual(css_resp.status_code, 200)
        css = css_resp.data.decode('utf-8')
        self.assertIn("guardian-universe-body", css)
        self.assertIn("guardian-mascot-container", css)
        self.assertIn("guardian-slider-modal", css)
        self.assertIn("kpi-card-entrance", css)

        js_resp = self.client.get('/static/js/guardian.js')
        self.assertEqual(js_resp.status_code, 200)
        js = js_resp.data.decode('utf-8')
        self.assertIn("drawHologramGlobe", js)
        self.assertIn("triggerBlink", js)
        self.assertIn("showSlide", js)

if __name__ == '__main__':
    unittest.main()
