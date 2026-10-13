"""
BrandShield AI - Supabase PostgreSQL Database Access Layer
Supports Supabase PostgreSQL client (PostgREST API) with resilient offline backup bridge.

Features:
- Connects to Supabase using SUPABASE_URL and SUPABASE_KEY.
- Strict startup validation: raises SupabaseConfigurationError if unconfigured.
- Seamlessly falls back to local SQLite backup if Supabase tables are pending schema execution (PGRST205).
- Automatically routes all queries to Supabase PostgreSQL once tables are created.
- Sanitizes and handles database errors safely without exposing API keys or secrets.
- Supports dependency injection / mock client for automated testing.
"""

import os
import json
import sqlite3
import logging
from datetime import datetime, timedelta, timezone
from dotenv import load_dotenv

# Load environment variables
load_dotenv()

logger = logging.getLogger("brandshield.database")

# -----------------------------------------------------------------------------
# Configuration & Exceptions
# -----------------------------------------------------------------------------
class SupabaseConfigurationError(Exception):
    """Raised when Supabase environment configuration is missing, invalid, or placeholder."""
    pass

class SupabaseDatabaseError(Exception):
    """Raised when a Supabase database query or network operation fails."""
    pass

SQLITE_BACKUP_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'brandshield_backup_sqlite.db')
if not os.path.exists(SQLITE_BACKUP_PATH):
    SQLITE_BACKUP_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'brandshield.db')

_supabase_schema_pending = False

def is_supabase_live():
    """Return True if connected to live Supabase PostgreSQL tables, False if schema is pending."""
    return not _supabase_schema_pending

# -----------------------------------------------------------------------------
# In-Memory Mock Client for Isolated Test Suites
# -----------------------------------------------------------------------------
class MockPostgrestResponse:
    """Mock PostgREST response object."""
    def __init__(self, data=None, count=None):
        self.data = data if data is not None else []
        self.count = count if count is not None else len(self.data)

class MockQueryBuilder:
    """Mock query builder for PostgREST chainable calls."""
    def __init__(self, data_store, table_name):
        self.data_store = data_store
        self.table_name = table_name
        self._action = "select"
        self._payload = None
        self._filters = []
        self._limit_val = None
        self._order_field = None
        self._order_desc = False

    def select(self, *args, count=None, **kwargs):
        self._action = "select"
        return self

    def insert(self, record):
        self._action = "insert"
        self._payload = record
        return self

    def upsert(self, record):
        self._action = "upsert"
        self._payload = record
        return self

    def delete(self):
        self._action = "delete"
        return self

    def eq(self, field, value):
        self._filters.append(('eq', field, value))
        return self

    def or_(self, expr):
        self._filters.append(('or', expr))
        return self

    def order(self, field, desc=False):
        self._order_field = field
        self._order_desc = desc
        return self

    def limit(self, count):
        self._limit_val = count
        return self

    def execute(self):
        table_rows = self.data_store.setdefault(self.table_name, [])

        if self._action == "insert":
            rec = dict(self._payload)
            if "id" not in rec or rec["id"] is None:
                rec["id"] = len(table_rows) + 1
            if "created_at" not in rec:
                rec["created_at"] = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
            table_rows.append(rec)
            return MockPostgrestResponse(data=[rec])

        elif self._action == "upsert":
            rec = dict(self._payload)
            pk = "cache_key" if "cache_key" in rec else "id"
            if pk in rec:
                table_rows = [r for r in table_rows if r.get(pk) != rec[pk]]
            if "created_at" not in rec:
                rec["created_at"] = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
            table_rows.append(rec)
            self.data_store[self.table_name] = table_rows
            return MockPostgrestResponse(data=[rec])

        elif self._action == "delete":
            for f in self._filters:
                if f[0] == 'eq':
                    _, field, val = f
                    self.data_store[self.table_name] = [r for r in table_rows if r.get(field) != val]
            return MockPostgrestResponse(data=[])

        elif self._action == "select":
            result = list(table_rows)
            for f in self._filters:
                if f[0] == 'eq':
                    _, field, val = f
                    result = [r for r in result if r.get(field) == val]
                elif f[0] == 'or':
                    expr = f[1]
                    parts = expr.split(',')
                    matched = []
                    for r in result:
                        for p in parts:
                            tokens = p.split('.')
                            if len(tokens) >= 3:
                                col = tokens[0]
                                term = tokens[2].strip('%').lower()
                                if term in str(r.get(col, '')).lower():
                                    matched.append(r)
                                    break
                    result = matched

            if self._order_field:
                result.sort(key=lambda x: str(x.get(self._order_field, '')), reverse=self._order_desc)

            if self._limit_val:
                result = result[:self._limit_val]

            return MockPostgrestResponse(data=result, count=len(result))

        return MockPostgrestResponse(data=[])

class MockSupabaseClient:
    """In-memory mock for Supabase Client."""
    def __init__(self):
        self.data_store = {
            "brands": [],
            "scans": [],
            "vt_cache": []
        }

    def table(self, table_name):
        return MockQueryBuilder(self.data_store, table_name)

# Singleton client instance
_supabase_client = None

def get_supabase_config():
    """Retrieve and validate Supabase configuration from environment variables."""
    url = os.environ.get("SUPABASE_URL", "").strip()
    key = os.environ.get("SUPABASE_KEY", "").strip()

    is_missing = not url or not key
    is_placeholder = (
        "your-project-id" in url or 
        "your_supabase" in key or 
        url.startswith("https://placeholder") or
        key == "placeholder"
    )

    if is_missing or is_placeholder:
        raise SupabaseConfigurationError(
            "Supabase PostgreSQL environment configuration is missing or invalid. "
            "Please configure valid 'SUPABASE_URL' and 'SUPABASE_KEY' credentials in your .env file.\n"
            "Example:\n"
            "  SUPABASE_URL=https://your-project-id.supabase.co\n"
            "  SUPABASE_KEY=eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..."
        )

    return url, key

def get_supabase_client():
    """
    Establish or return the singleton Supabase client.
    """
    global _supabase_client
    if _supabase_client is not None:
        return _supabase_client

    # Check if running in test mock mode
    if os.environ.get("SUPABASE_TEST_MODE") == "1":
        _supabase_client = MockSupabaseClient()
        return _supabase_client

    url, key = get_supabase_config()
    try:
        from supabase import create_client
        _supabase_client = create_client(url, key)
        return _supabase_client
    except SupabaseConfigurationError:
        raise
    except Exception as e:
        err_msg = str(e).replace(key, "[REDACTED_SECRET]")
        raise SupabaseDatabaseError(f"Failed to initialize Supabase client: {err_msg}")

def set_supabase_client(client):
    """Inject a client instance (used for unit testing with mocks)."""
    global _supabase_client
    _supabase_client = client

def reset_supabase_client():
    """Reset the client instance to None."""
    global _supabase_client
    _supabase_client = None

# -----------------------------------------------------------------------------
# Data Parsing & Normalization Helpers
# -----------------------------------------------------------------------------
def _ensure_dict(val):
    """Ensure value is parsed as a dictionary."""
    if isinstance(val, dict):
        return val
    if isinstance(val, str):
        try:
            parsed = json.loads(val)
            return parsed if isinstance(parsed, dict) else {}
        except Exception:
            return {}
    return {}

def _ensure_list(val):
    """Ensure value is parsed as a list."""
    if isinstance(val, list):
        return val
    if isinstance(val, str):
        try:
            parsed = json.loads(val)
            return parsed if isinstance(parsed, list) else [parsed]
        except Exception:
            return [val] if val else []
    return []

def normalize_risk_category(cat: str) -> str:
    """Normalize legacy and current risk category labels."""
    if not cat:
        return "UNKNOWN / INSUFFICIENT DATA"
    c = str(cat).strip().upper()
    if c in ("HIGH", "HIGH RISK"):
        return "HIGH RISK"
    elif c in ("MEDIUM", "SUSPICIOUS"):
        return "SUSPICIOUS"
    elif c in ("LOW", "LOW RISK"):
        return "LOW RISK"
    elif "UNKNOWN" in c or "INSUFFICIENT" in c:
        return "UNKNOWN / INSUFFICIENT DATA"
    return cat

def _format_brand_row(r: dict) -> dict:
    """Format brand record into standard dictionary."""
    return {
        "id": r.get("id"),
        "name": r.get("name", ""),
        "official_handles": _ensure_list(r.get("official_handles")),
        "official_domains": _ensure_list(r.get("official_domains")),
        "verified_developers": _ensure_list(r.get("verified_developers")),
        "category": r.get("category", "Enterprise"),
        "description": r.get("description", ""),
        "is_demo": bool(r.get("is_demo", False)),
        "created_at": r.get("created_at")
    }

def _format_scan_row(r: dict) -> dict:
    """Format scan record into standard dictionary."""
    return {
        "id": r.get("id"),
        "scan_type": r.get("scan_type"),
        "target_brand_id": r.get("target_brand_id"),
        "target_brand_name": r.get("target_brand_name"),
        "input_title": r.get("input_title"),
        "input_details": _ensure_dict(r.get("input_details")),
        "risk_score": r.get("risk_score", 0),
        "risk_category": normalize_risk_category(r.get("risk_category")),
        "summary_reason": r.get("summary_reason", ""),
        "indicators": _ensure_list(r.get("indicators")),
        "recommendations": _ensure_list(r.get("recommendations")),
        "api_findings": _ensure_dict(r.get("api_findings")),
        "evidence": _ensure_dict(r.get("evidence")),
        "ml_findings": _ensure_dict(r.get("ml_findings")),
        "profile_ml_findings": _ensure_dict(r.get("profile_ml_findings")),
        "app_ml_findings": _ensure_dict(r.get("app_ml_findings")),
        "created_at": r.get("created_at")
    }

# -----------------------------------------------------------------------------
# SQLite Fallback Engine
# -----------------------------------------------------------------------------
def _get_sqlite_conn():
    conn = sqlite3.connect(SQLITE_BACKUP_PATH)
    conn.row_factory = sqlite3.Row
    return conn

def _init_sqlite_if_needed():
    try:
        conn = _get_sqlite_conn()
        cur = conn.cursor()
        cur.execute("""
        CREATE TABLE IF NOT EXISTS brands (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL UNIQUE,
            official_handles TEXT NOT NULL,
            official_domains TEXT NOT NULL,
            verified_developers TEXT NOT NULL,
            category TEXT DEFAULT 'Enterprise',
            description TEXT DEFAULT '',
            is_demo INTEGER DEFAULT 0,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )""")
        cur.execute("""
        CREATE TABLE IF NOT EXISTS scans (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            scan_type TEXT NOT NULL,
            target_brand_id INTEGER,
            target_brand_name TEXT,
            input_title TEXT NOT NULL,
            input_details TEXT NOT NULL,
            risk_score INTEGER NOT NULL,
            risk_category TEXT NOT NULL,
            summary_reason TEXT NOT NULL,
            indicators TEXT NOT NULL,
            recommendations TEXT NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            api_findings TEXT DEFAULT '{}',
            evidence TEXT DEFAULT '{}',
            ml_findings TEXT DEFAULT '{}',
            profile_ml_findings TEXT DEFAULT '{}',
            app_ml_findings TEXT DEFAULT '{}'
        )""")
        cur.execute("""
        CREATE TABLE IF NOT EXISTS vt_cache (
            cache_key TEXT PRIMARY KEY,
            cache_type TEXT NOT NULL,
            response_json TEXT NOT NULL,
            status TEXT NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )""")
        conn.commit()
        conn.close()
    except Exception as e:
        logger.warning(f"Failed to verify SQLite tables: {e}")

def _sqlite_get_all_brands():
    conn = _get_sqlite_conn()
    cur = conn.cursor()
    cur.execute("SELECT * FROM brands ORDER BY name ASC")
    rows = cur.fetchall()
    conn.close()
    return [_format_brand_row(dict(r)) for r in rows]

def _sqlite_get_brand_by_id(brand_id):
    conn = _get_sqlite_conn()
    cur = conn.cursor()
    cur.execute("SELECT * FROM brands WHERE id = ?", (brand_id,))
    row = cur.fetchone()
    conn.close()
    return _format_brand_row(dict(row)) if row else None

def _sqlite_add_brand(name, handles, domains, developers, category="Enterprise", description="", is_demo=0):
    clean_name = str(name).strip()
    if not clean_name:
        return None, "Brand name is required."
    conn = _get_sqlite_conn()
    cur = conn.cursor()
    try:
        cur.execute("""
        INSERT INTO brands (name, official_handles, official_domains, verified_developers, category, description, is_demo)
        VALUES (?, ?, ?, ?, ?, ?, ?)
        """, (
            clean_name,
            json.dumps([h.strip() for h in handles if h.strip()]),
            json.dumps([d.strip().lower() for d in domains if d.strip()]),
            json.dumps([dev.strip() for dev in developers if dev.strip()]),
            str(category).strip() or "Enterprise",
            str(description).strip(),
            int(bool(is_demo))
        ))
        conn.commit()
        b_id = cur.lastrowid
        conn.close()
        return b_id, None
    except sqlite3.IntegrityError:
        conn.close()
        return None, f"Brand with name '{clean_name}' already exists."
    except Exception as e:
        conn.close()
        return None, f"Database error: {e}"

def _sqlite_delete_brand(brand_id):
    conn = _get_sqlite_conn()
    cur = conn.cursor()
    cur.execute("DELETE FROM brands WHERE id = ?", (brand_id,))
    conn.commit()
    conn.close()

def _sqlite_save_scan(scan_type, target_brand_id, target_brand_name, input_title, input_details,
                      risk_score, risk_category, summary_reason, indicators, recommendations,
                      api_findings=None, evidence=None, ml_findings=None, profile_ml_findings=None, app_ml_findings=None):
    conn = _get_sqlite_conn()
    cur = conn.cursor()
    now_str = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    cur.execute("""
    INSERT INTO scans (
        scan_type, target_brand_id, target_brand_name, input_title, input_details,
        risk_score, risk_category, summary_reason, indicators, recommendations,
        created_at, api_findings, evidence, ml_findings, profile_ml_findings, app_ml_findings
    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    """, (
        scan_type,
        target_brand_id if target_brand_id else None,
        target_brand_name or "General",
        input_title,
        json.dumps(_ensure_dict(input_details)),
        int(risk_score),
        normalize_risk_category(risk_category),
        summary_reason or "",
        json.dumps(_ensure_list(indicators)),
        json.dumps(_ensure_list(recommendations)),
        now_str,
        json.dumps(_ensure_dict(api_findings)),
        json.dumps(_ensure_dict(evidence)),
        json.dumps(_ensure_dict(ml_findings)),
        json.dumps(_ensure_dict(profile_ml_findings)),
        json.dumps(_ensure_dict(app_ml_findings))
    ))
    conn.commit()
    s_id = cur.lastrowid
    conn.close()
    return s_id

def _sqlite_get_recent_scans(limit=10, scan_type=None, risk_category=None, search_query=None):
    conn = _get_sqlite_conn()
    cur = conn.cursor()
    query = "SELECT * FROM scans WHERE 1=1"
    params = []
    if scan_type and scan_type != "all":
        query += " AND scan_type = ?"
        params.append(scan_type)
    if risk_category and risk_category != "all":
        query += " AND risk_category = ?"
        params.append(normalize_risk_category(risk_category))
    if search_query:
        query += " AND (input_title LIKE ? OR target_brand_name LIKE ? OR summary_reason LIKE ?)"
        q_term = f"%{search_query.strip()}%"
        params.extend([q_term, q_term, q_term])
    query += " ORDER BY id DESC"
    if limit:
        query += " LIMIT ?"
        params.append(limit)
    cur.execute(query, params)
    rows = cur.fetchall()
    conn.close()
    return [_format_scan_row(dict(r)) for r in rows]

def _sqlite_get_scan_by_id(scan_id):
    conn = _get_sqlite_conn()
    cur = conn.cursor()
    cur.execute("SELECT * FROM scans WHERE id = ?", (scan_id,))
    row = cur.fetchone()
    conn.close()
    return _format_scan_row(dict(row)) if row else None

def _sqlite_get_dashboard_metrics():
    conn = _get_sqlite_conn()
    cur = conn.cursor()
    cur.execute("SELECT COUNT(*) FROM brands")
    total_brands = cur.fetchone()[0]
    cur.execute("SELECT id, scan_type, risk_category, risk_score FROM scans")
    all_scans = [dict(r) for r in cur.fetchall()]
    total_scans = len(all_scans)
    
    category_counts = {
        "HIGH RISK": 0,
        "SUSPICIOUS": 0,
        "LOW RISK": 0,
        "UNKNOWN / INSUFFICIENT DATA": 0
    }
    type_counts = {"social": 0, "link": 0, "app": 0}

    for s in all_scans:
        cat = normalize_risk_category(s.get("risk_category"))
        if cat in category_counts:
            category_counts[cat] += 1
        else:
            category_counts["UNKNOWN / INSUFFICIENT DATA"] += 1
        stype = s.get("scan_type")
        if stype in type_counts:
            type_counts[stype] += 1

    flagged_scans = category_counts["SUSPICIOUS"] + category_counts["HIGH RISK"]
    high_risk_scans = category_counts["HIGH RISK"]

    cur.execute("SELECT * FROM scans ORDER BY id DESC LIMIT 6")
    recent_scans = [_format_scan_row(dict(r)) for r in cur.fetchall()]
    conn.close()

    return {
        "total_scans": total_scans,
        "flagged_scans": flagged_scans,
        "high_risk_scans": high_risk_scans,
        "total_brands": total_brands,
        "category_counts": category_counts,
        "type_counts": type_counts,
        "recent_scans": recent_scans
    }

def _sqlite_get_vt_cache(cache_key):
    conn = _get_sqlite_conn()
    cur = conn.cursor()
    cur.execute("SELECT * FROM vt_cache WHERE cache_key = ?", (cache_key,))
    row = cur.fetchone()
    conn.close()
    if row:
        r = dict(row)
        return {
            "cache_key": r.get("cache_key"),
            "cache_type": r.get("cache_type"),
            "response_json": _ensure_dict(r.get("response_json")),
            "status": r.get("status"),
            "created_at": r.get("created_at")
        }
    return None

def _sqlite_set_vt_cache(cache_key, cache_type, response_json, status="success"):
    conn = _get_sqlite_conn()
    cur = conn.cursor()
    cur.execute("""
    INSERT OR REPLACE INTO vt_cache (cache_key, cache_type, response_json, status, created_at)
    VALUES (?, ?, ?, ?, CURRENT_TIMESTAMP)
    """, (cache_key, cache_type, json.dumps(_ensure_dict(response_json)), status))
    conn.commit()
    conn.close()
    return True

# -----------------------------------------------------------------------------
# Database Initialization & Seeding
# -----------------------------------------------------------------------------
def init_db(force_reseed=False):
    """
    Validate Supabase connection and seed baseline demo brands if empty or requested.
    If Supabase PostgreSQL schema has not been executed yet in the dashboard (PGRST205),
    safely maintains uptime by serving from local SQLite backup while notifying developer.
    """
    global _supabase_schema_pending
    client = get_supabase_client()

    try:
        # Check existing brands count
        res = client.table("brands").select("id", count="exact").execute()
        brand_count = res.count if res.count is not None else len(res.data or [])
        _supabase_schema_pending = False

        if brand_count == 0 or force_reseed:
            if force_reseed:
                try:
                    client.table("brands").delete().eq("is_demo", True).execute()
                except Exception:
                    pass

            seed_demo_data(client)
    except SupabaseConfigurationError:
        raise
    except Exception as e:
        err_msg = str(e)
        if "PGRST205" in err_msg or "Could not find the table" in err_msg:
            url, _ = get_supabase_config()
            project_id = url.replace("https://", "").split(".")[0]
            _supabase_schema_pending = True
            logger.warning(
                f"\n[NOTICE] Supabase PostgreSQL tables are not yet created in project '{project_id}'.\n"
                f"[NOTICE] Run 'supabase_schema.sql' in https://supabase.com/dashboard/project/{project_id}/sql/new\n"
                f"[NOTICE] Serving from local SQLite backup ({SQLITE_BACKUP_PATH}) so the platform stays online.\n"
            )
            _init_sqlite_if_needed()
            return
        raise SupabaseDatabaseError(f"Failed to initialize Supabase database tables: {e}")

def seed_demo_data(client):
    """Seed 5 fictional demo brands into Supabase PostgreSQL."""
    demo_brands = [
        {
            "name": "ApexBank",
            "official_handles": ["@apexbank", "@apexbank_official", "@apexbank_us"],
            "official_domains": ["apexbank.com", "apexbank.net"],
            "verified_developers": ["Apex Financial Technologies LLC", "Apex Banking Corp"],
            "category": "Banking & Fintech",
            "description": "Fictional global retail and investment banking platform.",
            "is_demo": True
        },
        {
            "name": "CloudShield",
            "official_handles": ["@cloudshield", "@cloudshield_cyber", "@cloudshield_hq"],
            "official_domains": ["cloudshield.io", "cloudshield.com"],
            "verified_developers": ["CloudShield Security Labs", "CloudShield Systems"],
            "category": "Cybersecurity & Cloud",
            "description": "Fictional enterprise zero-trust cloud infrastructure provider.",
            "is_demo": True
        },
        {
            "name": "NexaPay",
            "official_handles": ["@nexapay", "@nexapay_global", "@nexapay_app"],
            "official_domains": ["nexapay.com", "nexapay.app"],
            "verified_developers": ["Nexa Digital Solutions Ltd", "NexaPay Technologies"],
            "category": "Fintech & Payments",
            "description": "Fictional cross-border mobile payment and wallet service.",
            "is_demo": True
        },
        {
            "name": "VertexHealth",
            "official_handles": ["@vertexhealth", "@vertex_health", "@vertexmed"],
            "official_domains": ["vertexhealth.org", "vertexhealth.io"],
            "verified_developers": ["Vertex Medical Innovations Inc", "Vertex Telehealth"],
            "category": "Healthcare & MedTech",
            "description": "Fictional hospital network and encrypted telehealth provider.",
            "is_demo": True
        },
        {
            "name": "StreamPulse",
            "official_handles": ["@streampulse", "@streampulse_tv", "@streampulse_media"],
            "official_domains": ["streampulse.tv", "streampulse.com"],
            "verified_developers": ["StreamPulse Entertainment Inc", "Pulse Streaming LLC"],
            "category": "Media & Entertainment",
            "description": "Fictional high-fidelity music and video streaming service.",
            "is_demo": True
        }
    ]

    for brand in demo_brands:
        try:
            check = client.table("brands").select("id").eq("name", brand["name"]).execute()
            if not check.data:
                client.table("brands").insert(brand).execute()
        except Exception as e:
            logger.warning(f"Failed to seed brand {brand['name']}: {e}")

# -----------------------------------------------------------------------------
# Brand Registry CRUD Operations
# -----------------------------------------------------------------------------
def get_all_brands():
    """Retrieve all registered brands ordered by name from Supabase (or local SQLite if schema pending)."""
    if _supabase_schema_pending:
        return _sqlite_get_all_brands()

    client = get_supabase_client()
    try:
        res = client.table("brands").select("*").order("name", desc=False).execute()
        return [_format_brand_row(r) for r in (res.data or [])]
    except Exception as e:
        err_msg = str(e)
        if "PGRST205" in err_msg or "Could not find the table" in err_msg:
            return _sqlite_get_all_brands()
        raise SupabaseDatabaseError(f"Error fetching brands from Supabase: {e}")

def get_brand_by_id(brand_id):
    """Retrieve a single brand by its primary key from Supabase (or local SQLite)."""
    if _supabase_schema_pending:
        return _sqlite_get_brand_by_id(brand_id)

    client = get_supabase_client()
    try:
        res = client.table("brands").select("*").eq("id", brand_id).execute()
        if res.data and len(res.data) > 0:
            return _format_brand_row(res.data[0])
        return None
    except Exception as e:
        err_msg = str(e)
        if "PGRST205" in err_msg or "Could not find the table" in err_msg:
            return _sqlite_get_brand_by_id(brand_id)
        raise SupabaseDatabaseError(f"Error fetching brand {brand_id} from Supabase: {e}")

def add_brand(name, handles, domains, developers, category="Enterprise", description="", is_demo=0):
    """Add a new brand to Supabase PostgreSQL (or local SQLite)."""
    if _supabase_schema_pending:
        return _sqlite_add_brand(name, handles, domains, developers, category, description, is_demo)

    client = get_supabase_client()
    clean_name = str(name).strip()
    if not clean_name:
        return None, "Brand name is required."

    record = {
        "name": clean_name,
        "official_handles": [h.strip() for h in handles if h.strip()],
        "official_domains": [d.strip().lower() for d in domains if d.strip()],
        "verified_developers": [dev.strip() for dev in developers if dev.strip()],
        "category": str(category).strip() or "Enterprise",
        "description": str(description).strip(),
        "is_demo": bool(is_demo)
    }

    try:
        check = client.table("brands").select("id").eq("name", clean_name).execute()
        if check.data and len(check.data) > 0:
            return None, f"Brand with name '{clean_name}' already exists."

        res = client.table("brands").insert(record).execute()
        if res.data and len(res.data) > 0:
            return res.data[0]["id"], None
        return None, "Failed to insert brand into Supabase."
    except Exception as e:
        err_str = str(e)
        if "PGRST205" in err_str or "Could not find the table" in err_str:
            return _sqlite_add_brand(name, handles, domains, developers, category, description, is_demo)
        if "duplicate key" in err_str or "unique constraint" in err_str:
            return None, f"Brand with name '{clean_name}' already exists."
        return None, f"Database error: {err_str}"

def delete_brand(brand_id):
    """Delete a brand by primary key from Supabase (or local SQLite)."""
    if _supabase_schema_pending:
        _sqlite_delete_brand(brand_id)
        return

    client = get_supabase_client()
    try:
        client.table("brands").delete().eq("id", brand_id).execute()
    except Exception as e:
        err_msg = str(e)
        if "PGRST205" in err_msg or "Could not find the table" in err_msg:
            _sqlite_delete_brand(brand_id)
            return
        raise SupabaseDatabaseError(f"Failed to delete brand {brand_id} from Supabase: {e}")

# -----------------------------------------------------------------------------
# Scan History CRUD Operations
# -----------------------------------------------------------------------------
def save_scan(scan_type, target_brand_id, target_brand_name, input_title, input_details, 
              risk_score, risk_category, summary_reason, indicators, recommendations,
              api_findings=None, evidence=None, ml_findings=None, profile_ml_findings=None,
              app_ml_findings=None):
    """Save an analysis scan result to Supabase PostgreSQL (or local SQLite)."""
    if _supabase_schema_pending:
        return _sqlite_save_scan(
            scan_type, target_brand_id, target_brand_name, input_title, input_details,
            risk_score, risk_category, summary_reason, indicators, recommendations,
            api_findings, evidence, ml_findings, profile_ml_findings, app_ml_findings
        )

    client = get_supabase_client()

    record = {
        "scan_type": scan_type,
        "target_brand_id": target_brand_id if target_brand_id else None,
        "target_brand_name": target_brand_name or "General",
        "input_title": input_title,
        "input_details": _ensure_dict(input_details),
        "risk_score": int(risk_score),
        "risk_category": normalize_risk_category(risk_category),
        "summary_reason": summary_reason or "",
        "indicators": _ensure_list(indicators),
        "recommendations": _ensure_list(recommendations),
        "api_findings": _ensure_dict(api_findings),
        "evidence": _ensure_dict(evidence),
        "ml_findings": _ensure_dict(ml_findings),
        "profile_ml_findings": _ensure_dict(profile_ml_findings),
        "app_ml_findings": _ensure_dict(app_ml_findings)
    }

    try:
        res = client.table("scans").insert(record).execute()
        if res.data and len(res.data) > 0:
            return res.data[0]["id"]
        raise SupabaseDatabaseError("Scan insert returned no record.")
    except Exception as e:
        err_msg = str(e)
        if "PGRST205" in err_msg or "Could not find the table" in err_msg:
            return _sqlite_save_scan(
                scan_type, target_brand_id, target_brand_name, input_title, input_details,
                risk_score, risk_category, summary_reason, indicators, recommendations,
                api_findings, evidence, ml_findings, profile_ml_findings, app_ml_findings
            )
        raise SupabaseDatabaseError(f"Failed to save scan to Supabase: {e}")

def get_recent_scans(limit=10, scan_type=None, risk_category=None, search_query=None):
    """Retrieve scans from Supabase (or local SQLite) with optional filters, search, and limit."""
    if _supabase_schema_pending:
        return _sqlite_get_recent_scans(limit, scan_type, risk_category, search_query)

    client = get_supabase_client()

    try:
        query = client.table("scans").select("*")

        if scan_type and scan_type != "all":
            query = query.eq("scan_type", scan_type)

        if risk_category and risk_category != "all":
            norm_cat = normalize_risk_category(risk_category)
            query = query.eq("risk_category", norm_cat)

        if search_query:
            clean_q = search_query.strip()
            query = query.or_(f"input_title.ilike.%{clean_q}%,target_brand_name.ilike.%{clean_q}%,summary_reason.ilike.%{clean_q}%")

        query = query.order("created_at", desc=True)

        if limit:
            query = query.limit(limit)

        res = query.execute()
        return [_format_scan_row(r) for r in (res.data or [])]
    except Exception as e:
        err_msg = str(e)
        if "PGRST205" in err_msg or "Could not find the table" in err_msg:
            return _sqlite_get_recent_scans(limit, scan_type, risk_category, search_query)
        raise SupabaseDatabaseError(f"Failed to retrieve scans from Supabase: {e}")

def get_scan_by_id(scan_id):
    """Retrieve a single scan by primary key from Supabase (or local SQLite)."""
    if _supabase_schema_pending:
        return _sqlite_get_scan_by_id(scan_id)

    client = get_supabase_client()
    try:
        res = client.table("scans").select("*").eq("id", scan_id).execute()
        if res.data and len(res.data) > 0:
            return _format_scan_row(res.data[0])
        return None
    except Exception as e:
        err_msg = str(e)
        if "PGRST205" in err_msg or "Could not find the table" in err_msg:
            return _sqlite_get_scan_by_id(scan_id)
        raise SupabaseDatabaseError(f"Failed to retrieve scan {scan_id} from Supabase: {e}")

# -----------------------------------------------------------------------------
# Dashboard Aggregate Analytics
# -----------------------------------------------------------------------------
def get_dashboard_metrics():
    """Compute aggregate analytics for dashboard KPIs and charts using Supabase records (or local SQLite)."""
    if _supabase_schema_pending:
        return _sqlite_get_dashboard_metrics()

    client = get_supabase_client()

    try:
        res_scans = client.table("scans").select("id, scan_type, risk_category, risk_score", count="exact").execute()
        all_scans = res_scans.data or []
        total_scans = res_scans.count if res_scans.count is not None else len(all_scans)

        res_brands = client.table("brands").select("id", count="exact").execute()
        total_brands = res_brands.count if res_brands.count is not None else len(res_brands.data or [])

        category_counts = {
            "HIGH RISK": 0,
            "SUSPICIOUS": 0,
            "LOW RISK": 0,
            "UNKNOWN / INSUFFICIENT DATA": 0
        }
        type_counts = {"social": 0, "link": 0, "app": 0}

        for s in all_scans:
            cat = normalize_risk_category(s.get("risk_category"))
            if cat in category_counts:
                category_counts[cat] += 1
            else:
                category_counts["UNKNOWN / INSUFFICIENT DATA"] += 1

            stype = s.get("scan_type")
            if stype in type_counts:
                type_counts[stype] += 1

        flagged_scans = category_counts["SUSPICIOUS"] + category_counts["HIGH RISK"]
        high_risk_scans = category_counts["HIGH RISK"]

        res_recent = client.table("scans").select("*").order("created_at", desc=True).limit(6).execute()
        recent_scans = [_format_scan_row(r) for r in (res_recent.data or [])]

        return {
            "total_scans": total_scans,
            "flagged_scans": flagged_scans,
            "high_risk_scans": high_risk_scans,
            "total_brands": total_brands,
            "category_counts": category_counts,
            "type_counts": type_counts,
            "recent_scans": recent_scans
        }
    except Exception as e:
        err_msg = str(e)
        if "PGRST205" in err_msg or "Could not find the table" in err_msg:
            return _sqlite_get_dashboard_metrics()
        raise SupabaseDatabaseError(f"Failed to compute dashboard metrics from Supabase: {e}")

# -----------------------------------------------------------------------------
# VirusTotal Threat Intelligence Persistent Cache (vt_cache)
# -----------------------------------------------------------------------------
def get_vt_cache(cache_key: str):
    """Retrieve cached VirusTotal threat intelligence entry from Supabase (or local SQLite)."""
    if _supabase_schema_pending:
        return _sqlite_get_vt_cache(cache_key)

    client = get_supabase_client()
    try:
        res = client.table("vt_cache").select("*").eq("cache_key", cache_key).execute()
        if res.data and len(res.data) > 0:
            row = res.data[0]
            return {
                "cache_key": row.get("cache_key"),
                "cache_type": row.get("cache_type"),
                "response_json": _ensure_dict(row.get("response_json")),
                "status": row.get("status"),
                "created_at": row.get("created_at")
            }
        return None
    except Exception as e:
        err_msg = str(e)
        if "PGRST205" in err_msg or "Could not find the table" in err_msg:
            return _sqlite_get_vt_cache(cache_key)
        logger.warning(f"Failed to query vt_cache for key {cache_key}: {e}")
        return None

def set_vt_cache(cache_key: str, cache_type: str, response_json: dict, status: str = "success"):
    """Store or update threat intelligence response in Supabase vt_cache (or local SQLite)."""
    if _supabase_schema_pending:
        return _sqlite_set_vt_cache(cache_key, cache_type, response_json, status)

    client = get_supabase_client()
    record = {
        "cache_key": cache_key,
        "cache_type": cache_type,
        "response_json": _ensure_dict(response_json),
        "status": status
    }
    try:
        client.table("vt_cache").upsert(record).execute()
        return True
    except Exception as e:
        err_msg = str(e)
        if "PGRST205" in err_msg or "Could not find the table" in err_msg:
            return _sqlite_set_vt_cache(cache_key, cache_type, response_json, status)
        logger.warning(f"Failed to save to vt_cache: {e}")
        return False
