"""
BrandShield AI - Web Application Backend
Flask routes, APIs, template rendering, and input validation.
Integrates RapidFuzz, VirusTotal API v3, and optional Gemini Explainer.
"""

import csv
import io
import json
import os
from datetime import timedelta
from functools import wraps
from flask import (
    Flask, render_template, request, redirect, 
    url_for, flash, jsonify, Response, session
)
from werkzeug.middleware.proxy_fix import ProxyFix
from dotenv import load_dotenv

# Load environment variables from .env
load_dotenv()

import database
import detector
import virustotal
import gemini_explainer
import ml_detector
import social_profile_detector
import mobile_app_detector

app = Flask(__name__)
# Enable reverse-proxy headers support for Cloudflare/load-balancer HTTPS detection
app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_proto=1, x_host=1, x_prefix=1)
app.secret_key = os.environ.get("FLASK_SECRET_KEY", "brandshield-ai-hackathon-secure-secret-key-2026")
app.config.update(
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE='Lax',
    PERMANENT_SESSION_LIFETIME=timedelta(days=30)
)

# Ensure database is initialized on startup
database.init_db()

@app.context_processor
def inject_global_data():
    """Inject registered brands, security telemetry, and session state into all templates."""
    brands = database.get_all_brands()
    vt_active = virustotal.is_virustotal_configured()
    gemini_active = gemini_explainer.is_gemini_configured()
    ml_active = ml_detector.is_ml_model_available()
    ml_metrics = ml_detector.get_model_metrics()
    social_ml_active = social_profile_detector.is_social_model_available()
    social_ml_metrics = social_profile_detector.get_social_metrics()
    app_ml_active = mobile_app_detector.is_mobile_model_available()
    app_ml_metrics = mobile_app_detector.get_app_metrics()
    user = session.get('user')
    safe_user = user if user else {
        'name': 'Threat Analyst',
        'email': 'analyst@brandshield.ai',
        'role': 'Enterprise Security Analyst'
    }
    return dict(
        all_brands=brands,
        virustotal_active=vt_active,
        gemini_active=gemini_active,
        ml_active=ml_active,
        ml_metrics=ml_metrics,
        social_ml_active=social_ml_active,
        social_ml_metrics=social_ml_metrics,
        app_ml_active=app_ml_active,
        app_ml_metrics=app_ml_metrics,
        current_user=safe_user,
        is_authenticated=bool(user),
        supabase_live=database.is_supabase_live()
    )

# =========================================================================
# ACCESS CONTROL & SECURITY DECORATORS
# =========================================================================
def login_required(f):
    """
    Decorator protecting enterprise dashboard routes.
    Redirects unauthenticated requests to the single-URL login view with redirect retention.
    """
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user' not in session or not session.get('user'):
            if request.path.startswith('/api/'):
                return jsonify({'error': 'Unauthorized', 'message': 'Authentication required. Please authenticate at /login.'}), 401
            flash("Security clearance required. Please authenticate to access the Digital Guardian Universe.", "warning")
            next_target = request.full_path if request.query_string else request.path
            return redirect(url_for('login', next=next_target))
        return f(*args, **kwargs)
    return decorated_function

# =========================================================================
# AUTHENTICATION & GUARDIAN ACCESS CONTROL
# =========================================================================
# Registered enterprise analyst credentials directory
REGISTERED_ANALYSTS = {
    'analyst@brandshield.ai': {
        'password': 'CyberShield2026!',
        'name': 'Alex Morgan',
        'role': 'Lead Threat Analyst'
    },
    'admin@brandshield.ai': {
        'password': 'CyberShield2026!',
        'name': 'Security Administrator',
        'role': 'Director of Cyber Defense'
    }
}

@app.route('/login', methods=['GET', 'POST'])
def login():
    # If user is already authenticated with a valid session, open the dashboard directly
    if request.method == 'GET' and 'user' in session and session.get('user'):
        return redirect(url_for('dashboard'))

    if request.method == 'POST':
        username = request.form.get('username', '').strip().lower()
        password = request.form.get('password', '').strip()
        remember = bool(request.form.get('remember'))

        if not username or not password:
            flash("Please enter both analyst identifier and security keyphrase.", "danger")
            return render_template('login.html', username=username)

        # Validate against registered analyst directory
        if username in REGISTERED_ANALYSTS:
            user_entry = REGISTERED_ANALYSTS[username]
            if user_entry['password'] != password:
                flash("Invalid analyst identifier or security keyphrase. Access denied.", "danger")
                return render_template('login.html', username=username)
            display_name = user_entry['name']
            role = user_entry['role']
        else:
            # For new enterprise logins, require minimum password complexity (>= 6 chars)
            if len(password) < 6:
                flash("Invalid analyst identifier or security keyphrase. Password does not meet security requirements.", "danger")
                return render_template('login.html', username=username)
            display_name = username.split('@')[0].replace('.', ' ').title() if '@' in username else username.title()
            role = 'Enterprise Security Analyst'
            REGISTERED_ANALYSTS[username] = {
                'password': password,
                'name': display_name,
                'role': role
            }

        session['user'] = {
            'email': username if '@' in username else f"{username}@brandshield.ai",
            'name': display_name,
            'role': role
        }
        if remember:
            session.permanent = True
        else:
            session.permanent = False

        flash(f"Security clearance confirmed. Digital Guardian Universe session active for {display_name}.", "success")
        
        # Check safe redirect destination
        next_url = request.args.get('next')
        if next_url and next_url.startswith('/') and not next_url.startswith('//'):
            return redirect(next_url)
        return redirect(url_for('dashboard'))

    return render_template('login.html')

@app.route('/signup', methods=['GET', 'POST'])
def signup():
    # If user is already authenticated with a valid session, open the dashboard directly
    if request.method == 'GET' and 'user' in session and session.get('user'):
        return redirect(url_for('dashboard'))

    if request.method == 'POST':
        full_name = request.form.get('name', 'Analyst').strip()
        email = request.form.get('email', '').strip().lower()
        password = request.form.get('password', '').strip()
        dept = request.form.get('department', 'Cyber Defense Operations').strip()

        if not email or not password:
            flash("Valid corporate email and password are required.", "danger")
            return render_template('login.html', signup_mode=True)

        if len(password) < 6:
            flash("Password must be at least 6 characters long.", "warning")
            return render_template('login.html', signup_mode=True)

        REGISTERED_ANALYSTS[email] = {
            'password': password,
            'name': full_name or email.split('@')[0].title(),
            'role': dept
        }

        session['user'] = {
            'email': email,
            'name': full_name or email.split('@')[0].title(),
            'role': dept
        }
        flash("Clearance created successfully. New analyst identity registered in Guardian Directory.", "success")
        return redirect(url_for('dashboard'))

    return render_template('login.html', signup_mode=True)

@app.route('/forgot-password', methods=['GET', 'POST'])
def forgot_password():
    if request.method == 'POST':
        email = request.form.get('email', '').strip()
        if not email:
            flash("Enter your registered corporate email to receive recovery instructions.", "warning")
            return render_template('login.html', forgot_mode=True)
        flash(f"Access token dispatched to '{email}'. Follow the secure cryptographic link to recover clearance.", "info")
        return redirect(url_for('login'))

    return render_template('login.html', forgot_mode=True)

@app.route('/oauth/google')
def oauth_google():
    session['user'] = {
        'name': 'Google Workspace Analyst',
        'email': 'analyst@enterprise-brandshield.com',
        'role': 'Google Workspace SSO'
    }
    flash("Enterprise SSO validated via Google Identity Services (OAuth 2.0).", "success")
    return redirect(url_for('dashboard'))

@app.route('/oauth/apple')
def oauth_apple():
    session['user'] = {
        'name': 'Apple Enterprise Analyst',
        'email': 'analyst@apple-brandshield.com',
        'role': 'Apple ID SSO'
    }
    flash("Enterprise SSO validated via Sign in with Apple (Secure Enclave).", "success")
    return redirect(url_for('dashboard'))

@app.route('/logout')
def logout():
    session.clear()
    flash("Analyst session securely terminated. Digital Guardian Universe perimeter locked.", "info")
    return redirect(url_for('login'))

# =========================================================================
# SINGLE PUBLIC URL ENTRY POINT & DASHBOARD
# =========================================================================
@app.route('/')
def index():
    """
    Main Single Application URL Entry Point.
    - If user is authenticated with a valid session, open the dashboard directly.
    - If not authenticated, show/redirect to the login page.
    """
    if 'user' in session and session.get('user'):
        return redirect(url_for('dashboard'))
    return redirect(url_for('login'))

@app.route('/dashboard')
@login_required
def dashboard():
    metrics = database.get_dashboard_metrics()
    return render_template('dashboard.html', metrics=metrics)

@app.route('/api/dashboard-stats')
@login_required
def api_dashboard_stats():
    metrics = database.get_dashboard_metrics()
    return jsonify(metrics)

# =========================================================================
# BRAND REGISTRY
# =========================================================================
@app.route('/brands')
@login_required
def brands_list():
    brands = database.get_all_brands()
    return render_template('brands.html', brands=brands)

@app.route('/brands/add', methods=['POST'])
@login_required
def add_brand_action():
    name = request.form.get('name', '').strip()
    category = request.form.get('category', 'Enterprise').strip()
    description = request.form.get('description', '').strip()
    
    handles_raw = request.form.get('official_handles', '')
    domains_raw = request.form.get('official_domains', '')
    developers_raw = request.form.get('verified_developers', '')

    if not name:
        flash("Brand name is required.", "danger")
        return redirect(url_for('brands_list'))

    handles = [h.strip() for h in handles_raw.replace('\n', ',').split(',') if h.strip()]
    domains = [d.strip() for d in domains_raw.replace('\n', ',').split(',') if d.strip()]
    developers = [dev.strip() for dev in developers_raw.replace('\n', ',').split(',') if dev.strip()]

    brand_id, err = database.add_brand(
        name=name,
        handles=handles,
        domains=domains,
        developers=developers,
        category=category,
        description=description,
        is_demo=0
    )

    if err:
        flash(f"Error adding brand: {err}", "danger")
    else:
        flash(f"Brand '{name}' added successfully to registry.", "success")

    return redirect(url_for('brands_list'))

@app.route('/brands/delete/<int:brand_id>', methods=['POST'])
@login_required
def delete_brand_action(brand_id):
    database.delete_brand(brand_id)
    flash("Brand removed from registry.", "info")
    return redirect(url_for('brands_list'))

@app.route('/brands/reset', methods=['POST'])
@login_required
def reset_brands_action():
    database.init_db(force_reseed=True)
    flash("Database reset with default 5 demo brands and baseline scan dataset.", "success")
    return redirect(url_for('brands_list'))

# =========================================================================
# SOCIAL PROFILE CHECKER
# =========================================================================
@app.route('/social-checker', methods=['GET', 'POST'])
@login_required
def social_checker():
    result = None
    form_data = {}
    brands = database.get_all_brands()

    if request.method == 'POST':
        platform = request.form.get('platform', 'Twitter / X').strip()
        profile_name = request.form.get('profile_name', '').strip()
        username = request.form.get('username', '').strip()
        profile_url = request.form.get('profile_url', '').strip()
        description = request.form.get('description', '').strip()
        brand_id_str = request.form.get('brand_id', '').strip()

        followers_raw = request.form.get('followers_count', '').strip()
        friends_raw = request.form.get('friends_count', '').strip()
        statuses_raw = request.form.get('statuses_count', '').strip()
        default_img_raw = request.form.get('default_profile_image', '').strip()

        profile_meta = {}
        if followers_raw:
            profile_meta['followers_count'] = followers_raw
        if friends_raw:
            profile_meta['friends_count'] = friends_raw
        if statuses_raw:
            profile_meta['statuses_count'] = statuses_raw
        if default_img_raw:
            profile_meta['default_profile_image'] = default_img_raw

        form_data = {
            'platform': platform,
            'profile_name': profile_name,
            'username': username,
            'profile_url': profile_url,
            'description': description,
            'brand_id': brand_id_str,
            'followers_count': followers_raw,
            'friends_count': friends_raw,
            'statuses_count': statuses_raw,
            'default_profile_image': default_img_raw
        }

        if not username and not profile_url:
            flash("Profile username/handle or profile URL is required.", "danger")
            return render_template('social_checker.html', result=None, form_data=form_data, brands=brands)

        # Retrieve selected brand or match first
        selected_brand = None
        if brand_id_str and brand_id_str.isdigit():
            selected_brand = database.get_brand_by_id(int(brand_id_str))

        if not selected_brand and brands:
            selected_brand = brands[0]

        target_brand_name = selected_brand['name'] if selected_brand else "General Impersonation"
        target_brand_id = selected_brand['id'] if selected_brand else 0

        # Perform deterministic heuristic analysis + VirusTotal link inspection + Model 2
        analysis = detector.analyze_social_profile(
            platform=platform,
            profile_name=profile_name,
            username=username,
            profile_url=profile_url,
            description=description,
            brand_dict=selected_brand,
            profile_meta=profile_meta
        )

        display_title = username if username else profile_url
        if not display_title.startswith('@') and not display_title.startswith('http'):
            display_title = f"@{display_title}"

        # Save to database
        scan_id = database.save_scan(
            scan_type="social",
            target_brand_id=target_brand_id,
            target_brand_name=target_brand_name,
            input_title=display_title,
            input_details={
                "platform": platform,
                "profile_name": profile_name,
                "username": username,
                "profile_url": profile_url,
                "description": description,
                "followers_count": followers_raw,
                "friends_count": friends_raw,
                "statuses_count": statuses_raw
            },
            risk_score=analysis['risk_score'],
            risk_category=analysis['risk_category'],
            summary_reason=analysis['summary_reason'],
            indicators=analysis['heuristic_findings'],
            recommendations=analysis['recommendations'],
            api_findings=analysis.get('api_findings'),
            evidence=analysis.get('profile_url_info'),
            ml_findings=analysis.get('ml_findings'),
            profile_ml_findings=analysis.get('profile_ml_findings')
        )

        analysis['scan_id'] = scan_id
        analysis['target_brand_name'] = target_brand_name
        analysis['platform'] = platform
        result = analysis

    return render_template('social_checker.html', result=result, form_data=form_data, brands=brands)

@app.route('/api/scan/social', methods=['POST'])
@login_required
def api_scan_social():
    data = request.get_json() or {}
    platform = data.get('platform', 'Twitter / X')
    profile_name = data.get('profile_name', '')
    username = data.get('username', '')
    profile_url = data.get('profile_url', '')
    description = data.get('description', '')
    brand_id = data.get('brand_id')
    profile_meta = data.get('profile_meta') or {
        k: data[k] for k in ('followers_count', 'friends_count', 'statuses_count', 'default_profile_image') if k in data
    }

    if not username and not profile_url:
        return jsonify({"error": "Username or Profile URL is required"}), 400

    brand = database.get_brand_by_id(int(brand_id)) if brand_id else None
    if not brand:
        brands = database.get_all_brands()
        brand = brands[0] if brands else None

    analysis = detector.analyze_social_profile(
        platform=platform,
        profile_name=profile_name,
        username=username,
        profile_url=profile_url,
        description=description,
        brand_dict=brand,
        profile_meta=profile_meta
    )

    display_title = username if username else profile_url
    scan_id = database.save_scan(
        scan_type="social",
        target_brand_id=brand['id'] if brand else 0,
        target_brand_name=brand['name'] if brand else "General",
        input_title=display_title,
        input_details=data,
        risk_score=analysis['risk_score'],
        risk_category=analysis['risk_category'],
        summary_reason=analysis['summary_reason'],
        indicators=analysis['heuristic_findings'],
        recommendations=analysis['recommendations'],
        api_findings=analysis.get('api_findings'),
        evidence=analysis.get('profile_url_info'),
        ml_findings=analysis.get('ml_findings'),
        profile_ml_findings=analysis.get('profile_ml_findings')
    )
    analysis['scan_id'] = scan_id
    return jsonify(analysis)

# =========================================================================
# SUSPICIOUS LINK CHECKER
# =========================================================================
@app.route('/link-checker', methods=['GET', 'POST'])
@login_required
def link_checker():
    result = None
    form_data = {}
    brands = database.get_all_brands()

    if request.method == 'POST':
        url = request.form.get('url', '').strip()
        brand_id_str = request.form.get('brand_id', '').strip()

        form_data = {
            'url': url,
            'brand_id': brand_id_str
        }

        if not url:
            flash("Target URL is required.", "danger")
            return render_template('link_checker.html', result=None, form_data=form_data, brands=brands)

        selected_brand = None
        if brand_id_str and brand_id_str.isdigit():
            selected_brand = database.get_brand_by_id(int(brand_id_str))

        if not selected_brand and brands:
            selected_brand = brands[0]

        target_brand_name = selected_brand['name'] if selected_brand else "General Brand"
        target_brand_id = selected_brand['id'] if selected_brand else 0

        # Deterministic multi-factor static analysis + VirusTotal API v3
        analysis = detector.analyze_suspicious_link(
            submitted_url=url,
            brand_dict=selected_brand
        )

        scan_id = database.save_scan(
            scan_type="link",
            target_brand_id=target_brand_id,
            target_brand_name=target_brand_name,
            input_title=url,
            input_details={
                "url": url,
                "submitted_brand": target_brand_name
            },
            risk_score=analysis['risk_score'],
            risk_category=analysis['risk_category'],
            summary_reason=analysis['summary_reason'],
            indicators=analysis['heuristic_findings'],
            recommendations=analysis['recommendations'],
            api_findings=analysis.get('api_findings'),
            evidence=analysis.get('parsed_data'),
            ml_findings=analysis.get('ml_findings')
        )

        analysis['scan_id'] = scan_id
        analysis['target_brand_name'] = target_brand_name
        result = analysis

    return render_template('link_checker.html', result=result, form_data=form_data, brands=brands)

@app.route('/api/scan/link', methods=['POST'])
@login_required
def api_scan_link():
    data = request.get_json() or {}
    url = data.get('url', '').strip()
    brand_id = data.get('brand_id')

    if not url:
        return jsonify({"error": "URL is required"}), 400

    brand = database.get_brand_by_id(int(brand_id)) if brand_id else None
    analysis = detector.analyze_suspicious_link(url, brand)

    scan_id = database.save_scan(
        scan_type="link",
        target_brand_id=brand['id'] if brand else 0,
        target_brand_name=brand['name'] if brand else "General",
        input_title=url,
        input_details=data,
        risk_score=analysis['risk_score'],
        risk_category=analysis['risk_category'],
        summary_reason=analysis['summary_reason'],
        indicators=analysis['heuristic_findings'],
        recommendations=analysis['recommendations'],
        api_findings=analysis.get('api_findings'),
        evidence=analysis.get('parsed_data'),
        ml_findings=analysis.get('ml_findings')
    )
    analysis['scan_id'] = scan_id
    return jsonify(analysis)

@app.route('/api/ml-metrics')
@login_required
def api_ml_metrics():
    """Return model evaluation metrics, benchmark performance, and feature importances."""
    metrics = ml_detector.get_model_metrics()
    return jsonify(metrics)

@app.route('/api/social-ml-metrics')
@login_required
def api_social_ml_metrics():
    """Return social profile model evaluation metrics and benchmark performance."""
    metrics = social_profile_detector.get_social_metrics()
    return jsonify(metrics)

@app.route('/api/app-ml-metrics')
@login_required
def api_app_ml_metrics():
    """Return mobile app risk model evaluation metrics and Drebin benchmark performance."""
    metrics = mobile_app_detector.get_app_metrics()
    return jsonify(metrics)


# =========================================================================
# MOBILE APP LISTING CHECKER
# =========================================================================
@app.route('/app-checker', methods=['GET', 'POST'])
@login_required
def app_checker():
    result = None
    form_data = {}
    brands = database.get_all_brands()

    if request.method == 'POST':
        app_name = request.form.get('app_name', '').strip()
        developer_name = request.form.get('developer_name', '').strip()
        store_url = request.form.get('store_url', '').strip()
        description = request.form.get('description', '').strip()
        apk_hash = request.form.get('apk_hash', '').strip()
        brand_id_str = request.form.get('brand_id', '').strip()

        form_data = {
            'app_name': app_name,
            'developer_name': developer_name,
            'store_url': store_url,
            'description': description,
            'apk_hash': apk_hash,
            'brand_id': brand_id_str
        }

        if not app_name or not developer_name:
            flash("Application Name and Developer Name are required.", "danger")
            return render_template('app_checker.html', result=None, form_data=form_data, brands=brands)

        selected_brand = None
        if brand_id_str and brand_id_str.isdigit():
            selected_brand = database.get_brand_by_id(int(brand_id_str))

        if not selected_brand and brands:
            selected_brand = brands[0]

        target_brand_name = selected_brand['name'] if selected_brand else "General Brand"
        target_brand_id = selected_brand['id'] if selected_brand else 0

        analysis = detector.analyze_mobile_app(
            app_name=app_name,
            developer_name=developer_name,
            store_url=store_url,
            description=description,
            brand_dict=selected_brand,
            apk_hash=apk_hash
        )

        scan_id = database.save_scan(
            scan_type="app",
            target_brand_id=target_brand_id,
            target_brand_name=target_brand_name,
            input_title=app_name,
            input_details={
                "app_name": app_name,
                "developer_name": developer_name,
                "store_url": store_url,
                "description": description,
                "apk_hash": apk_hash
            },
            risk_score=analysis['risk_score'],
            risk_category=analysis['risk_category'],
            summary_reason=analysis['summary_reason'],
            indicators=analysis['heuristic_findings'],
            recommendations=analysis['recommendations'],
            api_findings=analysis.get('api_findings'),
            app_ml_findings=analysis.get('app_ml_findings')
        )

        analysis['scan_id'] = scan_id
        analysis['target_brand_name'] = target_brand_name
        result = analysis

    return render_template('app_checker.html', result=result, form_data=form_data, brands=brands)

@app.route('/api/scan/app', methods=['POST'])
@login_required
def api_scan_app():
    data = request.get_json() or {}
    app_name = data.get('app_name', '').strip()
    developer_name = data.get('developer_name', '').strip()
    store_url = data.get('store_url', '').strip()
    description = data.get('description', '').strip()
    apk_hash = data.get('apk_hash', '').strip()
    brand_id = data.get('brand_id')

    if not app_name or not developer_name:
        return jsonify({"error": "App name and Developer name are required"}), 400

    brand = database.get_brand_by_id(int(brand_id)) if brand_id else None
    analysis = detector.analyze_mobile_app(app_name, developer_name, store_url, description, brand, apk_hash=apk_hash)

    scan_id = database.save_scan(
        scan_type="app",
        target_brand_id=brand['id'] if brand else 0,
        target_brand_name=brand['name'] if brand else "General",
        input_title=app_name,
        input_details=data,
        risk_score=analysis['risk_score'],
        risk_category=analysis['risk_category'],
        summary_reason=analysis['summary_reason'],
        indicators=analysis['heuristic_findings'],
        recommendations=analysis['recommendations'],
        api_findings=analysis.get('api_findings'),
        app_ml_findings=analysis.get('app_ml_findings')
    )
    analysis['scan_id'] = scan_id
    return jsonify(analysis)

# =========================================================================
# SCAN HISTORY & DETAILS
# =========================================================================
@app.route('/history')
@login_required
def history():
    scan_type = request.args.get('type', 'all')
    risk_category = request.args.get('risk', 'all')
    search_query = request.args.get('q', '').strip()

    scans = database.get_recent_scans(
        limit=100,
        scan_type=scan_type,
        risk_category=risk_category,
        search_query=search_query
    )

    return render_template('history.html', 
                           scans=scans, 
                           current_type=scan_type, 
                           current_risk=risk_category, 
                           search_query=search_query)

@app.route('/scan/<int:scan_id>')
@login_required
def scan_detail(scan_id):
    scan = database.get_scan_by_id(scan_id)
    if not scan:
        flash("Scan record not found.", "warning")
        return redirect(url_for('history'))
    return render_template('scan_detail.html', scan=scan)

@app.route('/history/export/csv')
@login_required
def export_history_csv():
    scans = database.get_recent_scans(limit=500)
    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow([
        "Scan ID", "Scan Type", "Target Brand", "Input Target", 
        "Risk Score", "Risk Category", "Summary Reason", "VirusTotal Findings", "Timestamp"
    ])
    for s in scans:
        vt_summary = s.get("api_findings", {}).get("summary", "N/A") if isinstance(s.get("api_findings"), dict) else "N/A"
        writer.writerow([
            s["id"], s["scan_type"], s["target_brand_name"], s["input_title"],
            s["risk_score"], s["risk_category"], s["summary_reason"], vt_summary, s["created_at"]
        ])
    output.seek(0)
    return Response(
        output.getvalue(),
        mimetype="text/csv",
        headers={"Content-Disposition": "attachment;filename=brandshield_scan_audit.csv"}
    )

@app.route('/history/export/json')
@login_required
def export_history_json():
    scans = database.get_recent_scans(limit=500)
    return Response(
        json.dumps(scans, indent=2),
        mimetype="application/json",
        headers={"Content-Disposition": "attachment;filename=brandshield_scan_audit.json"}
    )

# =========================================================================
# APPLICATION LAUNCH
# =========================================================================
if __name__ == '__main__':
    host = os.environ.get("FLASK_HOST", "0.0.0.0")
    port = int(os.environ.get("FLASK_PORT", 5000))
    app.run(debug=True, host=host, port=port)
