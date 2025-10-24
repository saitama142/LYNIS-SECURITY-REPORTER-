"""
Unit tests for lynis_reporter.storage module
"""

import pytest
import sqlite3
from datetime import datetime, timedelta
from pathlib import Path
from lynis_reporter.storage import StorageManager


class TestStorageManager:
    """Test cases for StorageManager class"""

    def test_initialize_database(self, temp_db_path):
        """Test database initialization creates tables"""
        with StorageManager(temp_db_path) as storage:
            # Check that database file was created
            assert Path(temp_db_path).exists()
            
            # Verify tables exist
            conn = sqlite3.connect(temp_db_path)
            cursor = conn.cursor()
            
            # Check scans table
            cursor.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='scans'")
            assert cursor.fetchone() is not None
            
            # Check warnings table
            cursor.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='warnings'")
            assert cursor.fetchone() is not None
            
            # Check suggestions table
            cursor.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='suggestions'")
            assert cursor.fetchone() is not None
            
            conn.close()

    def test_store_scan_basic(self, temp_db_path, sample_parsed_data):
        """Test storing a scan in the database"""
        with StorageManager(temp_db_path) as storage:
            scan_id = storage.store_scan(sample_parsed_data, is_local=True)
            
            assert scan_id is not None
            assert scan_id > 0

    def test_store_and_retrieve_scan(self, temp_db_path, sample_parsed_data):
        """Test storing and retrieving a scan"""
        with StorageManager(temp_db_path) as storage:
            scan_id = storage.store_scan(sample_parsed_data, is_local=True)
            
            # Retrieve the scan
            retrieved = storage.get_scan(scan_id)
            
            assert retrieved is not None
            assert retrieved['hostname'] == sample_parsed_data['system_info']['hostname']
            assert retrieved['hardening_index'] == sample_parsed_data['metrics']['hardening_index']
            assert retrieved['os'] == sample_parsed_data['system_info']['os']

    def test_get_latest_scan(self, temp_db_path, sample_parsed_data):
        """Test getting the most recent scan for a hostname"""
        with StorageManager(temp_db_path) as storage:
            # Store multiple scans
            scan_id_1 = storage.store_scan(sample_parsed_data, is_local=True)
            
            # Modify data for second scan
            sample_parsed_data['metrics']['hardening_index'] = 75
            scan_id_2 = storage.store_scan(sample_parsed_data, is_local=True)
            
            # Get latest
            latest = storage.get_latest_scan(sample_parsed_data['system_info']['hostname'])
            
            assert latest is not None
            assert latest['id'] == scan_id_2
            assert latest['hardening_index'] == 75

    def test_get_historical_scans(self, temp_db_path, sample_parsed_data):
        """Test retrieving historical scans"""
        with StorageManager(temp_db_path) as storage:
            hostname = sample_parsed_data['system_info']['hostname']
            
            # Store multiple scans
            for i in range(5):
                sample_parsed_data['metrics']['hardening_index'] = 60 + i
                storage.store_scan(sample_parsed_data, is_local=True)
            
            # Get history
            history = storage.get_historical_scans(hostname, limit=3)
            
            assert len(history) == 3
            # Should be in reverse chronological order
            assert history[0]['hardening_index'] == 64
            assert history[1]['hardening_index'] == 63
            assert history[2]['hardening_index'] == 62

    def test_get_warnings(self, temp_db_path, sample_parsed_data):
        """Test retrieving warnings for a scan"""
        with StorageManager(temp_db_path) as storage:
            scan_id = storage.store_scan(sample_parsed_data, is_local=True)
            
            warnings = storage.get_warnings(scan_id)
            
            assert len(warnings) == 3
            assert any(w['test_id'] == 'AUTH-9308' for w in warnings)
            assert any(w['test_id'] == 'SSH-7408' for w in warnings)

    def test_get_suggestions(self, temp_db_path, sample_parsed_data):
        """Test retrieving suggestions for a scan"""
        with StorageManager(temp_db_path) as storage:
            scan_id = storage.store_scan(sample_parsed_data, is_local=True)
            
            suggestions = storage.get_suggestions(scan_id)
            
            assert len(suggestions) == 4
            assert any(s['test_id'] == 'AUTH-9286' for s in suggestions)
            assert any(s['test_id'] == 'FILE-6310' for s in suggestions)

    def test_get_trend_data(self, temp_db_path, sample_parsed_data):
        """Test getting trend data for charts"""
        with StorageManager(temp_db_path) as storage:
            hostname = sample_parsed_data['system_info']['hostname']
            
            # Store scans over time
            for i in range(7):
                sample_parsed_data['metrics']['hardening_index'] = 60 + i
                storage.store_scan(sample_parsed_data, is_local=True)
            
            trend_data = storage.get_trend_data(hostname, days=30)
            
            assert len(trend_data) > 0
            assert 'scan_date' in trend_data[0]
            assert 'hardening_index' in trend_data[0]

    def test_compare_scans(self, temp_db_path, sample_parsed_data):
        """Test comparing two scans"""
        with StorageManager(temp_db_path) as storage:
            # Store first scan
            scan_id_1 = storage.store_scan(sample_parsed_data, is_local=True)
            
            # Modify and store second scan
            sample_parsed_data['metrics']['hardening_index'] = 75
            sample_parsed_data['warnings'].pop()  # Remove one warning
            scan_id_2 = storage.store_scan(sample_parsed_data, is_local=True)
            
            # Compare
            comparison = storage.compare_scans(scan_id_1, scan_id_2)
            
            assert comparison is not None
            assert 'scan1' in comparison
            assert 'scan2' in comparison
            assert 'score_delta' in comparison
            assert comparison['score_delta'] == 8  # 75 - 67

    def test_cleanup_old_scans(self, temp_db_path, sample_parsed_data):
        """Test cleanup of old scans based on retention period"""
        with StorageManager(temp_db_path) as storage:
            scan_id = storage.store_scan(sample_parsed_data, is_local=True)
            
            # Manually update scan date to 40 days ago
            conn = sqlite3.connect(temp_db_path)
            cursor = conn.cursor()
            old_date = (datetime.now() - timedelta(days=40)).isoformat()
            cursor.execute("UPDATE scans SET scan_date = ? WHERE id = ?", (old_date, scan_id))
            conn.commit()
            conn.close()
            
            # Store a recent scan
            recent_id = storage.store_scan(sample_parsed_data, is_local=True)
            
            # Cleanup with 30-day retention
            deleted_count = storage.cleanup_old_scans(retention_days=30)
            
            assert deleted_count > 0
            
            # Verify old scan is gone
            old_scan = storage.get_scan(scan_id)
            assert old_scan is None
            
            # Verify recent scan still exists
            recent_scan = storage.get_scan(recent_id)
            assert recent_scan is not None

    def test_get_all_hosts(self, temp_db_path, sample_parsed_data):
        """Test getting list of all unique hostnames"""
        with StorageManager(temp_db_path) as storage:
            # Store scans for multiple hosts
            sample_parsed_data['system_info']['hostname'] = 'server1'
            storage.store_scan(sample_parsed_data, is_local=True)
            
            sample_parsed_data['system_info']['hostname'] = 'server2'
            storage.store_scan(sample_parsed_data, is_local=True)
            
            sample_parsed_data['system_info']['hostname'] = 'server1'  # Duplicate
            storage.store_scan(sample_parsed_data, is_local=True)
            
            hosts = storage.get_all_hosts()
            
            assert len(hosts) == 2
            assert 'server1' in hosts
            assert 'server2' in hosts

    def test_get_fleet_summary(self, temp_db_path, sample_parsed_data):
        """Test getting fleet summary for multiple hosts"""
        with StorageManager(temp_db_path) as storage:
            # Store scans for multiple hosts
            sample_parsed_data['system_info']['hostname'] = 'web-server'
            sample_parsed_data['metrics']['hardening_index'] = 80
            storage.store_scan(sample_parsed_data, is_local=True)
            
            sample_parsed_data['system_info']['hostname'] = 'db-server'
            sample_parsed_data['metrics']['hardening_index'] = 65
            storage.store_scan(sample_parsed_data, is_local=True)
            
            fleet = storage.get_fleet_summary()
            
            assert len(fleet) == 2
            assert any(h['hostname'] == 'web-server' for h in fleet)
            assert any(h['hostname'] == 'db-server' for h in fleet)

    def test_get_common_issues(self, temp_db_path, sample_parsed_data):
        """Test getting most common warnings across fleet"""
        with StorageManager(temp_db_path) as storage:
            # Store multiple scans with common warnings
            for i in range(3):
                sample_parsed_data['system_info']['hostname'] = f'server{i}'
                storage.store_scan(sample_parsed_data, is_local=True)
            
            common = storage.get_common_issues(limit=5)
            
            assert len(common) > 0
            assert 'test_id' in common[0]
            assert 'count' in common[0]

    def test_context_manager(self, temp_db_path):
        """Test StorageManager works as context manager"""
        # Use with statement
        with StorageManager(temp_db_path) as storage:
            assert storage.conn is not None
        
        # Connection should be closed after exiting context
        # (we can't directly test this without accessing private attributes)

    def test_store_scan_with_empty_warnings(self, temp_db_path, sample_parsed_data):
        """Test storing scan with no warnings"""
        sample_parsed_data['warnings'] = []
        
        with StorageManager(temp_db_path) as storage:
            scan_id = storage.store_scan(sample_parsed_data, is_local=True)
            
            warnings = storage.get_warnings(scan_id)
            assert len(warnings) == 0

    def test_store_scan_with_empty_suggestions(self, temp_db_path, sample_parsed_data):
        """Test storing scan with no suggestions"""
        sample_parsed_data['suggestions'] = []
        
        with StorageManager(temp_db_path) as storage:
            scan_id = storage.store_scan(sample_parsed_data, is_local=True)
            
            suggestions = storage.get_suggestions(scan_id)
            assert len(suggestions) == 0

    def test_get_scan_nonexistent(self, temp_db_path):
        """Test getting non-existent scan returns None"""
        with StorageManager(temp_db_path) as storage:
            scan = storage.get_scan(99999)
            assert scan is None

    def test_get_latest_scan_no_scans(self, temp_db_path):
        """Test getting latest scan when none exist returns None"""
        with StorageManager(temp_db_path) as storage:
            latest = storage.get_latest_scan('nonexistent-host')
            assert latest is None

    def test_multiple_scans_same_host(self, temp_db_path, sample_parsed_data):
        """Test storing multiple scans for the same host"""
        with StorageManager(temp_db_path) as storage:
            hostname = sample_parsed_data['system_info']['hostname']
            
            # Store 10 scans
            for i in range(10):
                sample_parsed_data['metrics']['hardening_index'] = 50 + i
                storage.store_scan(sample_parsed_data, is_local=True)
            
            # Get all history
            history = storage.get_historical_scans(hostname, limit=100)
            
            assert len(history) == 10
            # Verify chronological order (newest first)
            assert history[0]['hardening_index'] == 59
            assert history[-1]['hardening_index'] == 50
