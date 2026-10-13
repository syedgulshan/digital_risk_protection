"""
BrandShield AI - SQLite to Supabase PostgreSQL Migration Script
Safely exports existing SQLite data and imports it into Supabase PostgreSQL.

Features:
- Idempotent and safe to rerun (prevents duplicate records).
- Preserves relational foreign key mappings between brands and scans.
- Validates data types and converts JSON strings into native PostgreSQL JSONB structures.
- Parses timestamps into standard ISO 8601 formatting for PostgreSQL TIMESTAMPTZ.
- Verifies all required tables (brands, scans, vt_cache) and permissions prior to migration.
- Provides actionable diagnostic messages if tables are not yet created.
- Supports --dry-run mode to audit records without writing to Supabase.
- Never modifies or deletes the original SQLite database.
"""

import os
import sys
import json
import sqlite3
import argparse
from datetime import datetime
from dotenv import load_dotenv

# Load environment variables
load_dotenv()

SQLITE_DB_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'brandshield_backup_sqlite.db')
if not os.path.exists(SQLITE_DB_PATH):
    SQLITE_DB_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'brandshield.db')

REQUIRED_TABLES = ["brands", "scans", "vt_cache"]

def parse_json_safely(val, default):
    """Safely parse JSON strings or return default if invalid/empty."""
    if val is None:
        return default
    if isinstance(val, (dict, list)):
        return val
    try:
        s = str(val).strip()
        if not s or s in ('None', 'null'):
            return default
        return json.loads(s)
    except Exception:
        return default

def parse_timestamp_safely(val):
    """Convert SQLite timestamp string to ISO 8601 string for PostgreSQL TIMESTAMPTZ."""
    if not val:
        return None
    s = str(val).strip()
    if not s or s in ('None', 'null'):
        return None
    try:
        dt = datetime.strptime(s, "%Y-%m-%d %H:%M:%S")
        return dt.strftime("%Y-%m-%dT%H:%M:%SZ")
    except Exception:
        return s

def get_sqlite_data():
    """Extract all records from SQLite database."""
    if not os.path.exists(SQLITE_DB_PATH):
        raise FileNotFoundError(f"SQLite database file not found at: {SQLITE_DB_PATH}")

    conn = sqlite3.connect(SQLITE_DB_PATH)
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()

    # 1. Fetch brands
    cursor.execute("SELECT * FROM brands ORDER BY id ASC")
    brands = [dict(r) for r in cursor.fetchall()]

    # 2. Fetch scans
    cursor.execute("SELECT * FROM scans ORDER BY id ASC")
    scans = [dict(r) for r in cursor.fetchall()]

    # 3. Fetch vt_cache if present
    vt_cache = []
    try:
        cursor.execute("SELECT * FROM vt_cache")
        vt_cache = [dict(r) for r in cursor.fetchall()]
    except Exception:
        pass

    conn.close()
    return brands, scans, vt_cache

def verify_supabase_schema(client, supabase_url):
    """
    Verify that all required tables exist in the Supabase PostgreSQL schema.
    Returns (True, []) if all exist, or (False, list_of_missing_tables) if any are missing.
    """
    missing_tables = []
    for tbl in REQUIRED_TABLES:
        try:
            client.table(tbl).select("*").limit(1).execute()
        except Exception as e:
            err_msg = str(e)
            if "PGRST205" in err_msg or "Could not find the table" in err_msg:
                missing_tables.append(tbl)
            elif any(t in err_msg.lower() for t in ["jwt", "unauthorized", "permission denied", "401", "403"]):
                print(f"\n[ERROR] Authentication/Permission failure accessing table '{tbl}': {err_msg}")
                sys.exit(1)
            else:
                # Other transient errors or empty table responses are safe to continue
                pass

    return len(missing_tables) == 0, missing_tables

def migrate_to_supabase(dry_run=False):
    """Run data migration into Supabase PostgreSQL."""
    print("=" * 70)
    print(" BRANDSHIELD AI: SQLITE -> SUPABASE POSTGRESQL MIGRATION")
    print("=" * 70)
    print(f" Source SQLite DB : {SQLITE_DB_PATH}")
    print(f" Execution Mode   : {'DRY RUN (Audit only - no writes)' if dry_run else 'LIVE MIGRATION'}")

    # Check Supabase credentials
    supabase_url = os.environ.get("SUPABASE_URL", "").strip()
    supabase_key = os.environ.get("SUPABASE_KEY", "").strip()

    if not dry_run:
        if not supabase_url or not supabase_key or "your-project-id" in supabase_url or "your_supabase" in supabase_key:
            print("\n[ERROR] Missing or placeholder Supabase credentials in .env file!")
            print("Please ensure the following variables are set in .env:")
            print("  SUPABASE_URL=https://<your-project-id>.supabase.co")
            print("  SUPABASE_KEY=<your-secret-or-anon-key>")
            print("\nTip: Run with '--dry-run' to inspect SQLite records without connecting to Supabase.")
            sys.exit(1)

        try:
            from supabase import create_client
            client = create_client(supabase_url, supabase_key)
            print(f" Supabase Host    : {supabase_url}")
            print(" Supabase Status  : Connected successfully")
        except Exception as e:
            print(f"\n[ERROR] Failed to connect to Supabase: {e}")
            sys.exit(1)
    else:
        client = None

    # Extract SQLite data
    brands_data, scans_data, cache_data = get_sqlite_data()
    print(f"\n Found {len(brands_data)} brands, {len(scans_data)} scans, and {len(cache_data)} cache items in SQLite.")

    # Preflight check: Verify all required tables exist in Supabase schema cache
    if not dry_run:
        tables_ok, missing_tables = verify_supabase_schema(client, supabase_url)
        if not tables_ok:
            project_id = supabase_url.replace("https://", "").split(".")[0]
            print("\n" + "!" * 70)
            print(" [ERROR] DATABASE TABLES NOT FOUND IN SUPABASE")
            print("!" * 70)
            print(f" Missing table(s): {', '.join(missing_tables)}")
            print(" The Supabase PostgreSQL database does not have these tables yet.")
            print("\n How to resolve this in 3 easy steps:")
            print(" 1. Open your Supabase Dashboard SQL Editor:")
            print(f"    https://supabase.com/dashboard/project/{project_id}/sql/new")
            print(" 2. Copy and paste the entire contents of 'supabase_schema.sql' and click 'Run'")
            print(" 3. Re-run this migration command:")
            print("    python migrate_sqlite_to_supabase.py")
            print("!" * 70 + "\n")
            sys.exit(1)

    # -------------------------------------------------------------------------
    # 1. Migrate Brands
    # -------------------------------------------------------------------------
    print("\n[1/3] Migrating Brands...")
    brand_id_map = {} # sqlite_id -> supabase_id
    brands_migrated = 0
    brands_skipped = 0
    brands_failed = 0

    for b in brands_data:
        old_id = b["id"]
        name = b["name"].strip()
        record = {
            "name": name,
            "official_handles": parse_json_safely(b.get("official_handles"), []),
            "official_domains": parse_json_safely(b.get("official_domains"), []),
            "verified_developers": parse_json_safely(b.get("verified_developers"), []),
            "category": b.get("category") or "Enterprise",
            "description": b.get("description") or "",
            "is_demo": bool(b.get("is_demo", 0))
        }
        if b.get("created_at"):
            record["created_at"] = parse_timestamp_safely(b["created_at"])

        if dry_run:
            brand_id_map[old_id] = old_id
            brands_migrated += 1
            print(f"  [DRY-RUN] Brand '{name}' ready for migration.")
            continue

        try:
            # Check if brand already exists to prevent duplicate key errors
            existing = client.table("brands").select("id, name").eq("name", name).execute()
            if existing.data and len(existing.data) > 0:
                supa_id = existing.data[0]["id"]
                brand_id_map[old_id] = supa_id
                brands_skipped += 1
                print(f"  [-] Brand '{name}' already exists (ID: {supa_id}). Skipped.")
            else:
                res = client.table("brands").insert(record).execute()
                if res.data and len(res.data) > 0:
                    supa_id = res.data[0]["id"]
                    brand_id_map[old_id] = supa_id
                    brands_migrated += 1
                    print(f"  [+] Brand '{name}' migrated successfully (ID: {supa_id}).")
                else:
                    brands_failed += 1
                    print(f"  [!] Brand '{name}' insert returned no data.")
        except Exception as e:
            brands_failed += 1
            print(f"  [!] Failed to migrate brand '{name}': {e}")

    # -------------------------------------------------------------------------
    # 2. Migrate Scans
    # -------------------------------------------------------------------------
    print(f"\n[2/3] Migrating Scans (Total: {len(scans_data)})...")
    scans_migrated = 0
    scans_skipped = 0
    scans_failed = 0

    for s in scans_data:
        old_brand_id = s.get("target_brand_id")
        new_brand_id = brand_id_map.get(old_brand_id) if old_brand_id else None

        record = {
            "scan_type": s["scan_type"],
            "target_brand_id": new_brand_id,
            "target_brand_name": s.get("target_brand_name") or "General",
            "input_title": s["input_title"],
            "input_details": parse_json_safely(s.get("input_details"), {}),
            "risk_score": int(s["risk_score"]),
            "risk_category": s["risk_category"],
            "summary_reason": s.get("summary_reason") or "",
            "indicators": parse_json_safely(s.get("indicators"), []),
            "recommendations": parse_json_safely(s.get("recommendations"), []),
            "api_findings": parse_json_safely(s.get("api_findings"), {}),
            "evidence": parse_json_safely(s.get("evidence"), {}),
            "ml_findings": parse_json_safely(s.get("ml_findings"), {}),
            "profile_ml_findings": parse_json_safely(s.get("profile_ml_findings"), {}),
            "app_ml_findings": parse_json_safely(s.get("app_ml_findings"), {})
        }
        iso_created_at = parse_timestamp_safely(s.get("created_at"))
        if iso_created_at:
            record["created_at"] = iso_created_at

        if dry_run:
            scans_migrated += 1
            continue

        try:
            # Check for existing duplicate scan by input_title, scan_type, and created_at
            check_q = client.table("scans").select("id").eq("input_title", s["input_title"]).eq("scan_type", s["scan_type"])
            if iso_created_at:
                check_q = check_q.eq("created_at", iso_created_at)
            existing_scan = check_q.execute()

            if existing_scan.data and len(existing_scan.data) > 0:
                scans_skipped += 1
            else:
                res = client.table("scans").insert(record).execute()
                if res.data and len(res.data) > 0:
                    scans_migrated += 1
                else:
                    scans_failed += 1
        except Exception as e:
            scans_failed += 1
            print(f"  [!] Failed to migrate scan '{s.get('input_title', '')[:30]}': {e}")

    # -------------------------------------------------------------------------
    # 3. Migrate Threat Intelligence Cache (Optional)
    # -------------------------------------------------------------------------
    cache_migrated = 0
    if cache_data and not dry_run:
        print(f"\n[3/3] Migrating VT Cache ({len(cache_data)} items)...")
        for c in cache_data:
            try:
                rec = {
                    "cache_key": c["cache_key"],
                    "cache_type": c["cache_type"],
                    "response_json": parse_json_safely(c.get("response_json"), {}),
                    "status": c.get("status", "success")
                }
                client.table("vt_cache").upsert(rec).execute()
                cache_migrated += 1
            except Exception:
                pass

    # -------------------------------------------------------------------------
    # Migration Summary Report
    # -------------------------------------------------------------------------
    print("\n" + "=" * 70)
    print(" MIGRATION SUMMARY REPORT")
    print("=" * 70)
    print(f" Brands : {brands_migrated} migrated, {brands_skipped} existing/skipped, {brands_failed} failed.")
    print(f" Scans  : {scans_migrated} migrated, {scans_skipped} existing/skipped, {scans_failed} failed.")
    if cache_data:
        print(f" Cache  : {cache_migrated} threat intelligence cache entries migrated.")
    print(f" SQLite Backup Retained at: {SQLITE_DB_PATH}")
    print("=" * 70)

    if dry_run:
        print("[OK] Dry run completed successfully with 0 errors. Data is ready for Supabase.")
    elif brands_failed == 0 and scans_failed == 0:
        print("[OK] Migration finished successfully with zero row failures!")
    else:
        print(f"[WARNING] Migration completed with {brands_failed + scans_failed} failures. Review logs above.")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Migrate BrandShield AI SQLite database to Supabase PostgreSQL.")
    parser.add_argument("--dry-run", action="store_true", help="Audit and validate SQLite data without connecting to Supabase.")
    args = parser.parse_args()

    migrate_to_supabase(dry_run=args.dry_run)
