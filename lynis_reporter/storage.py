"""
Storage Manager for Lynis Reporter
Handles SQLite database operations for historical tracking
"""

import os
import sqlite3
import logging
import json
from typing import Dict, List, Any, Optional, Tuple
from datetime import datetime, timedelta
from pathlib import Path

logger = logging.getLogger(__name__)


class StorageManager:
    """
    Manages SQLite database for storing scan results and historical data
    """

    def __init__(self, database_path: str = "./data/lynis_reports.db"):
        """
        Initialize storage manager

        Args:
            database_path: Path to SQLite database file
        """
        self.database_path = database_path
        self.connection: Optional[sqlite3.Connection] = None
        
        # Ensure database directory exists
        db_dir = os.path.dirname(database_path)
        if db_dir and not os.path.exists(db_dir):
            os.makedirs(db_dir, exist_ok=True)
            logger.info(f"Created database directory: {db_dir}")
        
        self._initialize_database()

    def _initialize_database(self):
        """Create database schema if it doesn't exist"""
        try:
            self.connection = sqlite3.connect(self.database_path)
            self.connection.row_factory = sqlite3.Row
            cursor = self.connection.cursor()

            # Create scans table
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS scans (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    hostname TEXT NOT NULL,
                    scan_date TEXT NOT NULL,
                    hardening_index INTEGER,
                    tests_performed INTEGER,
                    tests_skipped INTEGER,
                    warnings_count INTEGER,
                    suggestions_count INTEGER,
                    os TEXT,
                    os_version TEXT,
                    kernel_version TEXT,
                    lynis_version TEXT,
                    is_local_host BOOLEAN DEFAULT 1,
                    raw_data TEXT,
                    created_at TEXT DEFAULT CURRENT_TIMESTAMP
                )
            ''')

            # Create warnings table
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS warnings (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    scan_id INTEGER NOT NULL,
                    test_id TEXT NOT NULL,
                    component TEXT,
                    message TEXT NOT NULL,
                    severity TEXT DEFAULT 'medium',
                    FOREIGN KEY (scan_id) REFERENCES scans(id) ON DELETE CASCADE
                )
            ''')

            # Create suggestions table
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS suggestions (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    scan_id INTEGER NOT NULL,
                    test_id TEXT NOT NULL,
                    component TEXT,
                    message TEXT NOT NULL,
                    priority TEXT DEFAULT 'medium',
                    FOREIGN KEY (scan_id) REFERENCES scans(id) ON DELETE CASCADE
                )
            ''')

            # Create packages table
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS packages (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    scan_id INTEGER NOT NULL,
                    package_name TEXT NOT NULL,
                    FOREIGN KEY (scan_id) REFERENCES scans(id) ON DELETE CASCADE
                )
            ''')

            # Create indices for performance
            cursor.execute('CREATE INDEX IF NOT EXISTS idx_scans_hostname ON scans(hostname)')
            cursor.execute('CREATE INDEX IF NOT EXISTS idx_scans_date ON scans(scan_date)')
            cursor.execute('CREATE INDEX IF NOT EXISTS idx_warnings_scan ON warnings(scan_id)')
            cursor.execute('CREATE INDEX IF NOT EXISTS idx_suggestions_scan ON suggestions(scan_id)')
            cursor.execute('CREATE INDEX IF NOT EXISTS idx_packages_scan ON packages(scan_id)')

            self.connection.commit()
            logger.info(f"Database initialized: {self.database_path}")

        except Exception as e:
            logger.error(f"Error initializing database: {e}")
            raise

    def store_scan(self, parsed_data: Dict[str, Any], is_local: bool = True) -> int:
        """
        Store a scan result in the database

        Args:
            parsed_data: Parsed scan data from LynisParser
            is_local: Whether this is a local scan

        Returns:
            Scan ID of the stored record
        """
        try:
            cursor = self.connection.cursor()

            system_info = parsed_data.get('system_info', {})
            metrics = parsed_data.get('metrics', {})

            # Insert scan record
            cursor.execute('''
                INSERT INTO scans (
                    hostname, scan_date, hardening_index, tests_performed,
                    tests_skipped, warnings_count, suggestions_count,
                    os, os_version, kernel_version, lynis_version,
                    is_local_host, raw_data
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ''', (
                system_info.get('hostname', 'Unknown'),
                system_info.get('report_datetime', datetime.now().isoformat()),
                metrics.get('hardening_index', 0),
                metrics.get('tests_performed', 0),
                metrics.get('tests_skipped', 0),
                len(parsed_data.get('warnings', [])),
                len(parsed_data.get('suggestions', [])),
                system_info.get('os', 'Unknown'),
                system_info.get('os_version', ''),
                system_info.get('kernel_version', ''),
                system_info.get('lynis_version', 'Unknown'),
                is_local,
                json.dumps(parsed_data.get('raw_data', {}))
            ))

            scan_id = cursor.lastrowid

            # Store warnings
            for warning in parsed_data.get('warnings', []):
                cursor.execute('''
                    INSERT INTO warnings (scan_id, test_id, component, message, severity)
                    VALUES (?, ?, ?, ?, ?)
                ''', (
                    scan_id,
                    warning.get('test_id', 'UNKNOWN'),
                    warning.get('component', ''),
                    warning.get('message', ''),
                    warning.get('severity', 'medium')
                ))

            # Store suggestions
            for suggestion in parsed_data.get('suggestions', []):
                cursor.execute('''
                    INSERT INTO suggestions (scan_id, test_id, component, message, priority)
                    VALUES (?, ?, ?, ?, ?)
                ''', (
                    scan_id,
                    suggestion.get('test_id', 'UNKNOWN'),
                    suggestion.get('component', ''),
                    suggestion.get('message', ''),
                    suggestion.get('priority', 'medium')
                ))

            # Store packages
            for package in parsed_data.get('packages', [])[:1000]:  # Limit to 1000 packages
                cursor.execute('''
                    INSERT INTO packages (scan_id, package_name)
                    VALUES (?, ?)
                ''', (scan_id, package))

            self.connection.commit()
            logger.info(f"Stored scan {scan_id} for host {system_info.get('hostname')}")
            return scan_id

        except Exception as e:
            logger.error(f"Error storing scan: {e}")
            if self.connection:
                self.connection.rollback()
            raise

    def get_scan(self, scan_id: int) -> Optional[Dict[str, Any]]:
        """
        Retrieve a scan by ID

        Args:
            scan_id: Scan ID

        Returns:
            Scan data or None if not found
        """
        try:
            cursor = self.connection.cursor()
            cursor.execute('SELECT * FROM scans WHERE id = ?', (scan_id,))
            row = cursor.fetchone()

            if not row:
                return None

            return dict(row)

        except Exception as e:
            logger.error(f"Error retrieving scan: {e}")
            return None

    def get_latest_scan(self, hostname: str) -> Optional[Dict[str, Any]]:
        """
        Get the latest scan for a hostname

        Args:
            hostname: Hostname to search for

        Returns:
            Latest scan data or None
        """
        try:
            cursor = self.connection.cursor()
            cursor.execute('''
                SELECT * FROM scans 
                WHERE hostname = ? 
                ORDER BY scan_date DESC 
                LIMIT 1
            ''', (hostname,))
            row = cursor.fetchone()

            if not row:
                return None

            return dict(row)

        except Exception as e:
            logger.error(f"Error retrieving latest scan: {e}")
            return None

    def get_historical_scans(self, hostname: str, limit: int = 10) -> List[Dict[str, Any]]:
        """
        Get historical scans for a hostname

        Args:
            hostname: Hostname to search for
            limit: Maximum number of scans to return

        Returns:
            List of scan records
        """
        try:
            cursor = self.connection.cursor()
            cursor.execute('''
                SELECT * FROM scans 
                WHERE hostname = ? 
                ORDER BY scan_date DESC 
                LIMIT ?
            ''', (hostname, limit))
            
            rows = cursor.fetchall()
            return [dict(row) for row in rows]

        except Exception as e:
            logger.error(f"Error retrieving historical scans: {e}")
            return []

    def get_warnings(self, scan_id: int) -> List[Dict[str, Any]]:
        """
        Get warnings for a scan

        Args:
            scan_id: Scan ID

        Returns:
            List of warnings
        """
        try:
            cursor = self.connection.cursor()
            cursor.execute('''
                SELECT * FROM warnings WHERE scan_id = ?
            ''', (scan_id,))
            
            rows = cursor.fetchall()
            return [dict(row) for row in rows]

        except Exception as e:
            logger.error(f"Error retrieving warnings: {e}")
            return []

    def get_suggestions(self, scan_id: int) -> List[Dict[str, Any]]:
        """
        Get suggestions for a scan

        Args:
            scan_id: Scan ID

        Returns:
            List of suggestions
        """
        try:
            cursor = self.connection.cursor()
            cursor.execute('''
                SELECT * FROM suggestions WHERE scan_id = ?
            ''', (scan_id,))
            
            rows = cursor.fetchall()
            return [dict(row) for row in rows]

        except Exception as e:
            logger.error(f"Error retrieving suggestions: {e}")
            return []

    def get_trend_data(self, hostname: str, days: int = 30) -> List[Dict[str, Any]]:
        """
        Get trend data for hardening index over time

        Args:
            hostname: Hostname to analyze
            days: Number of days to look back

        Returns:
            List of trend data points
        """
        try:
            cutoff_date = (datetime.now() - timedelta(days=days)).isoformat()
            cursor = self.connection.cursor()
            cursor.execute('''
                SELECT scan_date, hardening_index, warnings_count, suggestions_count
                FROM scans 
                WHERE hostname = ? AND scan_date >= ?
                ORDER BY scan_date ASC
            ''', (hostname, cutoff_date))
            
            rows = cursor.fetchall()
            return [dict(row) for row in rows]

        except Exception as e:
            logger.error(f"Error retrieving trend data: {e}")
            return []

    def compare_scans(self, scan_id1: int, scan_id2: int) -> Dict[str, Any]:
        """
        Compare two scans and identify differences

        Args:
            scan_id1: First scan ID (older)
            scan_id2: Second scan ID (newer)

        Returns:
            Comparison data
        """
        try:
            scan1 = self.get_scan(scan_id1)
            scan2 = self.get_scan(scan_id2)

            if not scan1 or not scan2:
                return {}

            warnings1 = set(w['test_id'] for w in self.get_warnings(scan_id1))
            warnings2 = set(w['test_id'] for w in self.get_warnings(scan_id2))

            return {
                'hardening_index_change': scan2['hardening_index'] - scan1['hardening_index'],
                'new_warnings': list(warnings2 - warnings1),
                'resolved_warnings': list(warnings1 - warnings2),
                'warnings_change': scan2['warnings_count'] - scan1['warnings_count'],
                'suggestions_change': scan2['suggestions_count'] - scan1['suggestions_count'],
            }

        except Exception as e:
            logger.error(f"Error comparing scans: {e}")
            return {}

    def cleanup_old_scans(self, retention_days: int = 30):
        """
        Remove scans older than retention period

        Args:
            retention_days: Number of days to retain
        """
        try:
            cutoff_date = (datetime.now() - timedelta(days=retention_days)).isoformat()
            cursor = self.connection.cursor()
            
            # Get count before deletion
            cursor.execute('''
                SELECT COUNT(*) FROM scans WHERE scan_date < ?
            ''', (cutoff_date,))
            count = cursor.fetchone()[0]

            if count > 0:
                # Delete old scans (CASCADE will handle related records)
                cursor.execute('''
                    DELETE FROM scans WHERE scan_date < ?
                ''', (cutoff_date,))
                
                self.connection.commit()
                logger.info(f"Cleaned up {count} scans older than {retention_days} days")
            else:
                logger.info("No old scans to clean up")

        except Exception as e:
            logger.error(f"Error cleaning up old scans: {e}")
            if self.connection:
                self.connection.rollback()

    def get_all_hosts(self) -> List[str]:
        """
        Get list of all unique hostnames in database

        Returns:
            List of hostnames
        """
        try:
            cursor = self.connection.cursor()
            cursor.execute('SELECT DISTINCT hostname FROM scans ORDER BY hostname')
            rows = cursor.fetchall()
            return [row[0] for row in rows]

        except Exception as e:
            logger.error(f"Error retrieving hosts: {e}")
            return []

    def get_fleet_summary(self) -> List[Dict[str, Any]]:
        """
        Get summary of all hosts (for fleet dashboard)

        Returns:
            List of host summaries
        """
        try:
            cursor = self.connection.cursor()
            cursor.execute('''
                SELECT 
                    hostname,
                    MAX(scan_date) as last_scan,
                    hardening_index,
                    warnings_count,
                    suggestions_count,
                    os,
                    os_version
                FROM scans
                GROUP BY hostname
                ORDER BY hardening_index ASC
            ''')
            
            rows = cursor.fetchall()
            return [dict(row) for row in rows]

        except Exception as e:
            logger.error(f"Error retrieving fleet summary: {e}")
            return []

    def get_common_issues(self, limit: int = 10) -> List[Dict[str, Any]]:
        """
        Get most common warnings across all hosts

        Args:
            limit: Maximum number of issues to return

        Returns:
            List of common issues with counts
        """
        try:
            cursor = self.connection.cursor()
            cursor.execute('''
                SELECT test_id, message, severity, COUNT(*) as occurrence_count
                FROM warnings
                WHERE scan_id IN (
                    SELECT MAX(id) FROM scans GROUP BY hostname
                )
                GROUP BY test_id, message
                ORDER BY occurrence_count DESC
                LIMIT ?
            ''', (limit,))
            
            rows = cursor.fetchall()
            return [dict(row) for row in rows]

        except Exception as e:
            logger.error(f"Error retrieving common issues: {e}")
            return []

    def close(self):
        """Close database connection"""
        if self.connection:
            self.connection.close()
            logger.debug("Database connection closed")

    def __enter__(self):
        """Context manager entry"""
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        """Context manager exit"""
        self.close()
