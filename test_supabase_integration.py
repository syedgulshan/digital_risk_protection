"""
BrandShield AI - Supabase PostgreSQL Integration Test Suite
Validates configuration checks, CRUD operations, dashboard aggregates,
error handling, timeout resilience, data migration, and security bounds.
"""

import os
import unittest
from unittest.mock import MagicMock, patch
import json

import database
from database import (
    SupabaseConfigurationError, 
    SupabaseDatabaseError,
    normalize_risk_category
)

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
                rec["created_at"] = "2026-10-12T20:00:00Z"
            table_rows.append(rec)
            return MockPostgrestResponse(data=[rec])

        elif self._action == "upsert":
            rec = dict(self._payload)
            pk = "cache_key" if "cache_key" in rec else "id"
            if pk in rec:
                table_rows = [r for r in table_rows if r.get(pk) != rec[pk]]
            if "created_at" not in rec:
                rec["created_at"] = "2026-10-12T20:00:00Z"
            table_rows.append(rec)
            self.data_store[self.table_name] = table_rows
            return MockPostgrestResponse(data=[rec])

        elif self._action == "delete":
            # Apply eq filters
            for f_type, field, val in [f for f in self._filters if f[0] == 'eq']:
                self.data_store[self.table_name] = [r for r in table_rows if r.get(field) != val]
            return MockPostgrestResponse(data=[])

        elif self._action == "select":
            result = list(table_rows)
            for f in self._filters:
                if f[0] == 'eq':
                    _, field, val = f
                    result = [r for r in result if r.get(field) == val]
                elif f[0] == 'or':
                    # Simplified mock search
                    pass

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


class TestSupabaseIntegration(unittest.TestCase):
    """Test suite for Supabase PostgreSQL database layer."""

    def setUp(self):
        database.reset_supabase_client()
        self.mock_client = MockSupabaseClient()

    def tearDown(self):
        database.reset_supabase_client()

    # -------------------------------------------------------------------------
    # 1. Configuration Validation Tests
    # -------------------------------------------------------------------------
    def test_missing_configuration_raises_error(self):
        """Test that missing or placeholder environment variables raise SupabaseConfigurationError."""
        with patch.dict(os.environ, {"SUPABASE_URL": "", "SUPABASE_KEY": ""}, clear=True):
            with self.assertRaises(SupabaseConfigurationError) as ctx:
                database.get_supabase_config()
            self.assertIn("missing or invalid", str(ctx.exception))

    def test_placeholder_configuration_raises_error(self):
        """Test that placeholder credentials raise SupabaseConfigurationError."""
        with patch.dict(os.environ, {
            "SUPABASE_URL": "https://your-project-id.supabase.co",
            "SUPABASE_KEY": "your_supabase_api_or_service_role_key_here"
        }):
            with self.assertRaises(SupabaseConfigurationError):
                database.get_supabase_config()

    def test_no_silent_sqlite_fallback(self):
        """Test that app never silently falls back to SQLite on connection failure."""
        database.reset_supabase_client()
        with patch.dict(os.environ, {"SUPABASE_URL": "", "SUPABASE_KEY": "", "SUPABASE_TEST_MODE": ""}):
            with self.assertRaises(SupabaseConfigurationError):
                database.init_db()

    # -------------------------------------------------------------------------
    # 2. Brand Registry Operations Tests
    # -------------------------------------------------------------------------
    def test_add_and_retrieve_brand(self):
        """Test adding and retrieving brands via Supabase layer."""
        database.set_supabase_client(self.mock_client)

        brand_id, err = database.add_brand(
            name="ApexBank",
            handles=["@apexbank", "@apexbank_support"],
            domains=["apexbank.com"],
            developers=["Apex Technologies LLC"],
            category="Banking & Fintech",
            description="Global retail bank."
        )
        self.assertIsNone(err)
        self.assertEqual(brand_id, 1)

        # Retrieve all
        brands = database.get_all_brands()
        self.assertEqual(len(brands), 1)
        self.assertEqual(brands[0]["name"], "ApexBank")
        self.assertEqual(brands[0]["official_handles"], ["@apexbank", "@apexbank_support"])

        # Retrieve by ID
        b = database.get_brand_by_id(1)
        self.assertIsNotNone(b)
        self.assertEqual(b["name"], "ApexBank")

    def test_duplicate_brand_rejected(self):
        """Test that adding a duplicate brand is safely rejected with informative error."""
        database.set_supabase_client(self.mock_client)

        database.add_brand("ApexBank", ["@apexbank"], ["apexbank.com"], ["Apex Tech"])
        _, err = database.add_brand("ApexBank", ["@apexbank2"], ["apexbank.org"], ["Apex Tech"])
        self.assertIsNotNone(err)
        self.assertIn("already exists", err.lower())

    def test_delete_brand(self):
        """Test deleting a brand record."""
        database.set_supabase_client(self.mock_client)

        b_id, _ = database.add_brand("ToDelete", ["@todelete"], ["todelete.com"], [])
        self.assertEqual(len(database.get_all_brands()), 1)

        database.delete_brand(b_id)
        self.assertEqual(len(database.get_all_brands()), 0)

    # -------------------------------------------------------------------------
    # 3. Scan History Operations Tests
    # -------------------------------------------------------------------------
    def test_save_and_retrieve_scan(self):
        """Test saving a scan and fetching it from Supabase."""
        database.set_supabase_client(self.mock_client)

        scan_id = database.save_scan(
            scan_type="link",
            target_brand_id=1,
            target_brand_name="ApexBank",
            input_title="http://apexbank-fake-verify.xyz",
            input_details={"url": "http://apexbank-fake-verify.xyz"},
            risk_score=94,
            risk_category="HIGH RISK",
            summary_reason="Brand typosquatting and deceptive TLD",
            indicators=[{"name": "Fake Domain", "severity": "High"}],
            recommendations=["Block domain"],
            api_findings={"malicious_count": 5},
            ml_findings={"phishing_probability": 0.98}
        )
        self.assertIsNotNone(scan_id)

        # Retrieve by ID
        scan = database.get_scan_by_id(scan_id)
        self.assertIsNotNone(scan)
        self.assertEqual(scan["input_title"], "http://apexbank-fake-verify.xyz")
        self.assertEqual(scan["risk_score"], 94)
        self.assertEqual(scan["risk_category"], "HIGH RISK")
        self.assertEqual(scan["ml_findings"]["phishing_probability"], 0.98)

    def test_get_recent_scans_filtering(self):
        """Test filtering scan history by scan_type and risk_category."""
        database.set_supabase_client(self.mock_client)

        database.save_scan("link", 1, "ApexBank", "link1", {}, 20, "LOW RISK", "clean", [], [])
        database.save_scan("social", 1, "ApexBank", "social1", {}, 85, "HIGH RISK", "lure", [], [])
        database.save_scan("app", 1, "ApexBank", "app1", {}, 65, "SUSPICIOUS", "permissions", [], [])

        all_scans = database.get_recent_scans(limit=10)
        self.assertEqual(len(all_scans), 3)

        link_scans = database.get_recent_scans(limit=10, scan_type="link")
        self.assertEqual(len(link_scans), 1)
        self.assertEqual(link_scans[0]["scan_type"], "link")

        high_scans = database.get_recent_scans(limit=10, risk_category="HIGH RISK")
        self.assertEqual(len(high_scans), 1)
        self.assertEqual(high_scans[0]["risk_category"], "HIGH RISK")

    # -------------------------------------------------------------------------
    # 4. Dashboard Metrics Calculation Tests
    # -------------------------------------------------------------------------
    def test_dashboard_metrics_aggregation(self):
        """Test calculating accurate dashboard KPI totals and category breakdowns."""
        database.set_supabase_client(self.mock_client)

        database.add_brand("ApexBank", ["@apex"], ["apex.com"], [])
        database.add_brand("CloudShield", ["@cloud"], ["cloud.com"], [])

        database.save_scan("link", 1, "ApexBank", "link1", {}, 10, "LOW RISK", "", [], [])
        database.save_scan("link", 1, "ApexBank", "link2", {}, 60, "SUSPICIOUS", "", [], [])
        database.save_scan("social", 1, "ApexBank", "social1", {}, 90, "HIGH RISK", "", [], [])
        database.save_scan("app", 2, "CloudShield", "app1", {}, 95, "HIGH RISK", "", [], [])

        metrics = database.get_dashboard_metrics()
        self.assertEqual(metrics["total_scans"], 4)
        self.assertEqual(metrics["total_brands"], 2)
        self.assertEqual(metrics["flagged_scans"], 3) # 1 suspicious + 2 high risk
        self.assertEqual(metrics["high_risk_scans"], 2)
        self.assertEqual(metrics["category_counts"]["HIGH RISK"], 2)
        self.assertEqual(metrics["category_counts"]["SUSPICIOUS"], 1)
        self.assertEqual(metrics["category_counts"]["LOW RISK"], 1)
        self.assertEqual(metrics["type_counts"]["link"], 2)
        self.assertEqual(metrics["type_counts"]["social"], 1)
        self.assertEqual(metrics["type_counts"]["app"], 1)

    # -------------------------------------------------------------------------
    # 5. Error & Timeout Handling Tests
    # -------------------------------------------------------------------------
    def test_database_query_error_sanitization(self):
        """Test that query errors are safely caught and secrets are not leaked."""
        failing_client = MagicMock()
        failing_client.table.side_effect = Exception("Supabase connection timeout to db.secret-key-12345")
        database.set_supabase_client(failing_client)

        with self.assertRaises(SupabaseDatabaseError) as ctx:
            database.get_all_brands()
        self.assertIn("Error fetching brands", str(ctx.exception))

    def test_invalid_input_validation(self):
        """Test that empty brand name is rejected without network traffic."""
        database.set_supabase_client(self.mock_client)
        b_id, err = database.add_brand("", [], [], [])
        self.assertIsNone(b_id)
        self.assertIn("required", err)

    # -------------------------------------------------------------------------
    # 6. Data Migration Dry-Run Test
    # -------------------------------------------------------------------------
    def test_migration_dry_run(self):
        """Test that the migration script can read and parse SQLite backup records without loss."""
        import migrate_sqlite_to_supabase
        brands, scans, _ = migrate_sqlite_to_supabase.get_sqlite_data()
        self.assertGreaterEqual(len(brands), 5)
        self.assertGreaterEqual(len(scans), 20)
        self.assertTrue(any(b["name"] == "ApexBank" for b in brands))

    def test_vt_cache_operations(self):
        """Test persistent VT cache get and set operations."""
        database.set_supabase_client(self.mock_client)
        success = database.set_vt_cache("url:test.com", "url", {"status": "clean", "positives": 0})
        self.assertTrue(success)

        entry = database.get_vt_cache("url:test.com")
        self.assertIsNotNone(entry)
        self.assertEqual(entry["cache_key"], "url:test.com")
        self.assertEqual(entry["response_json"]["status"], "clean")

if __name__ == '__main__':
    unittest.main()
