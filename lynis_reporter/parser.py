"""
Lynis Report Parser
Parses lynis-report.dat files from local or remote hosts
"""

import os
import re
import logging
from typing import Dict, List, Optional, Any, Tuple
from datetime import datetime
from pathlib import Path
import paramiko
from io import StringIO

logger = logging.getLogger(__name__)


class LynisParser:
    """
    Parser for lynis-report.dat files
    Handles both local file reading and remote SSH fetching
    """

    def __init__(self, input_path: str = "/var/log/lynis-report.dat", is_remote: bool = False):
        """
        Initialize parser

        Args:
            input_path: Path to lynis-report.dat file (local or remote)
            is_remote: Whether the file is on a remote host
        """
        self.input_path = input_path
        self.is_remote = is_remote
        self.raw_data: Dict[str, Any] = {}
        self.parsed_data: Dict[str, Any] = {}

    @staticmethod
    def parse_local(file_path: str) -> Dict[str, Any]:
        """
        Parse a local lynis-report.dat file

        Args:
            file_path: Path to local file

        Returns:
            Parsed data dictionary

        Raises:
            FileNotFoundError: If file doesn't exist
            PermissionError: If file can't be read
        """
        logger.info(f"Parsing local file: {file_path}")

        if not os.path.exists(file_path):
            raise FileNotFoundError(f"Lynis report file not found: {file_path}")

        if not os.access(file_path, os.R_OK):
            raise PermissionError(f"Cannot read file: {file_path}")

        parser = LynisParser(file_path)
        parser._read_local_file()
        parser._parse_data()
        return parser.parsed_data

    @staticmethod
    def parse_remote(ssh_host: str, ssh_port: int, ssh_user: str,
                     auth_method: str = 'key', ssh_key_path: Optional[str] = None,
                     ssh_password: Optional[str] = None,
                     report_path: str = "/var/log/lynis-report.dat") -> Dict[str, Any]:
        """
        Parse a remote lynis-report.dat file via SSH

        Args:
            ssh_host: Remote host address
            ssh_port: SSH port
            ssh_user: SSH username
            auth_method: 'key' or 'password'
            ssh_key_path: Path to SSH private key (for key auth)
            ssh_password: SSH password (for password auth)
            report_path: Path to report file on remote host

        Returns:
            Parsed data dictionary

        Raises:
            ConnectionError: If SSH connection fails
            FileNotFoundError: If remote file doesn't exist
        """
        logger.info(f"Parsing remote file from {ssh_user}@{ssh_host}:{report_path}")

        parser = LynisParser(report_path, is_remote=True)
        parser._read_remote_file(ssh_host, ssh_port, ssh_user, auth_method,
                                 ssh_key_path, ssh_password, report_path)
        parser._parse_data()
        return parser.parsed_data

    def _read_local_file(self):
        """Read and store raw data from local file"""
        try:
            with open(self.input_path, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read()
            self._parse_raw_content(content)
            logger.info(f"Successfully read local file: {self.input_path}")
        except Exception as e:
            logger.error(f"Error reading local file: {e}")
            raise

    def _read_remote_file(self, ssh_host: str, ssh_port: int, ssh_user: str,
                          auth_method: str, ssh_key_path: Optional[str],
                          ssh_password: Optional[str], report_path: str):
        """Read and store raw data from remote file via SSH"""
        ssh_client = None
        try:
            # Create SSH client
            ssh_client = paramiko.SSHClient()
            ssh_client.set_missing_host_key_policy(paramiko.AutoAddPolicy())

            # Connect based on authentication method
            connect_kwargs = {
                'hostname': ssh_host,
                'port': ssh_port,
                'username': ssh_user,
                'timeout': 30,
            }

            if auth_method == 'key':
                if ssh_key_path:
                    key_path = os.path.expanduser(ssh_key_path)
                    if os.path.exists(key_path):
                        connect_kwargs['key_filename'] = key_path
                    else:
                        raise FileNotFoundError(f"SSH key not found: {key_path}")
                else:
                    # Try default keys
                    logger.info("Using default SSH keys")
            elif auth_method == 'password':
                if not ssh_password:
                    raise ValueError("SSH password required for password authentication")
                connect_kwargs['password'] = ssh_password
            else:
                raise ValueError(f"Invalid auth method: {auth_method}")

            logger.info(f"Connecting to {ssh_user}@{ssh_host}:{ssh_port}")
            ssh_client.connect(**connect_kwargs)

            # Read remote file
            sftp = ssh_client.open_sftp()
            try:
                remote_file = sftp.file(report_path, 'r')
                content = remote_file.read().decode('utf-8', errors='ignore')
                remote_file.close()
                
                self._parse_raw_content(content)
                logger.info(f"Successfully read remote file from {ssh_host}")
            finally:
                sftp.close()

        except Exception as e:
            logger.error(f"Error reading remote file: {e}")
            raise ConnectionError(f"Failed to read remote file: {e}")
        finally:
            if ssh_client:
                ssh_client.close()

    def _parse_raw_content(self, content: str):
        """
        Parse raw file content into key-value pairs

        Args:
            content: Raw file content
        """
        self.raw_data = {
            'scalars': {},
            'arrays': {},
        }

        for line in content.splitlines():
            line = line.strip()
            if not line or line.startswith('#'):
                continue

            # Check if it's an array (ends with [])
            if '[]=' in line:
                key, value = line.split('[]=', 1)
                if key not in self.raw_data['arrays']:
                    self.raw_data['arrays'][key] = []
                self.raw_data['arrays'][key].append(value)
            elif '=' in line:
                # Scalar value
                key, value = line.split('=', 1)
                self.raw_data['scalars'][key] = value

    def _parse_data(self):
        """Parse raw data into structured format"""
        scalars = self.raw_data.get('scalars', {})
        arrays = self.raw_data.get('arrays', {})

        # Extract system information
        self.parsed_data = {
            'system_info': self._parse_system_info(scalars),
            'metrics': self._parse_metrics(scalars),
            'warnings': self._parse_warnings(arrays),
            'suggestions': self._parse_suggestions(arrays),
            'packages': self._parse_packages(arrays),
            'shells': self._parse_shells(arrays),
            'test_results': self._parse_test_results(scalars, arrays),
            'raw_data': self.raw_data,
        }

        logger.debug(f"Parsed data: {len(self.parsed_data['warnings'])} warnings, "
                    f"{len(self.parsed_data['suggestions'])} suggestions")

    def _parse_system_info(self, scalars: Dict[str, str]) -> Dict[str, Any]:
        """Parse system information"""
        return {
            'hostname': scalars.get('hostname', 'Unknown'),
            'os': scalars.get('os', 'Unknown'),
            'os_name': scalars.get('os_name', ''),
            'os_version': scalars.get('os_version', ''),
            'os_fullname': scalars.get('os_fullname', ''),
            'kernel_version': scalars.get('linux_version', scalars.get('kernel_version', '')),
            'lynis_version': scalars.get('lynis_version', 'Unknown'),
            'report_datetime': scalars.get('report_datetime_start', 
                                          scalars.get('report_datetime', 
                                                     datetime.now().isoformat())),
            'report_version': scalars.get('report_version', ''),
            'auditor': scalars.get('auditor', ''),
        }

    def _parse_metrics(self, scalars: Dict[str, str]) -> Dict[str, Any]:
        """Parse security metrics"""
        def safe_int(value: str, default: int = 0) -> int:
            try:
                return int(value)
            except (ValueError, TypeError):
                return default

        return {
            'hardening_index': safe_int(scalars.get('hardening_index', '0')),
            'tests_performed': safe_int(scalars.get('lynis_tests_done', '0')),
            'tests_skipped': len(scalars.get('tests_skipped', '').split('|')) if scalars.get('tests_skipped') else 0,
            'warnings_count': safe_int(scalars.get('warnings_count', '0')),
            'suggestions_count': safe_int(scalars.get('suggestions_count', '0')),
            'plugins_enabled': safe_int(scalars.get('plugins_enabled', '0')),
        }

    def _parse_warnings(self, arrays: Dict[str, List[str]]) -> List[Dict[str, str]]:
        """
        Parse warning entries
        Format: TEST-ID|MESSAGE|COMPONENT|DETAILS
        """
        warnings = []
        for warning_str in arrays.get('warning', []):
            parts = warning_str.split('|')
            if len(parts) >= 2:
                test_id = parts[0].strip()
                message = parts[1].strip()
                component = parts[2].strip() if len(parts) > 2 and parts[2].strip() != '-' else ''
                
                warnings.append({
                    'test_id': test_id,
                    'component': component,
                    'message': message,
                    'severity': self._determine_severity(test_id),
                })
            else:
                warnings.append({
                    'test_id': 'UNKNOWN',
                    'component': '',
                    'message': warning_str,
                    'severity': 'medium',
                })
        
        return warnings

    def _parse_suggestions(self, arrays: Dict[str, List[str]]) -> List[Dict[str, str]]:
        """
        Parse suggestion entries
        Format: TEST-ID|MESSAGE|COMPONENT|DETAILS
        """
        suggestions = []
        for suggestion_str in arrays.get('suggestion', []):
            parts = suggestion_str.split('|')
            if len(parts) >= 2:
                test_id = parts[0].strip()
                message = parts[1].strip()
                component = parts[2].strip() if len(parts) > 2 and parts[2].strip() != '-' else ''
                
                suggestions.append({
                    'test_id': test_id,
                    'component': component,
                    'message': message,
                    'priority': self._determine_priority(test_id),
                })
            else:
                suggestions.append({
                    'test_id': 'UNKNOWN',
                    'component': '',
                    'message': suggestion_str,
                    'priority': 'medium',
                })
        
        return suggestions

    def _parse_packages(self, arrays: Dict[str, List[str]]) -> List[str]:
        """Parse installed packages"""
        return arrays.get('installed_package', [])

    def _parse_shells(self, arrays: Dict[str, List[str]]) -> List[str]:
        """Parse available shells"""
        return arrays.get('available_shell', [])

    def _parse_test_results(self, scalars: Dict[str, str], 
                           arrays: Dict[str, List[str]]) -> Dict[str, Any]:
        """Parse test results and categories"""
        test_results = {}
        
        # Extract test-related scalars
        for key, value in scalars.items():
            if key.startswith('test_') or key.endswith('_test'):
                test_results[key] = value
        
        return {
            'details': test_results,
            'categories': self._categorize_tests(arrays),
        }

    def _categorize_tests(self, arrays: Dict[str, List[str]]) -> Dict[str, int]:
        """Categorize tests by type"""
        categories = {}
        
        # Count warnings and suggestions by category
        for warning in arrays.get('warning', []):
            test_id = warning.split('|')[0] if '|' in warning else 'UNKNOWN'
            category = self._get_test_category(test_id)
            categories[category] = categories.get(category, 0) + 1
        
        return categories

    def _get_test_category(self, test_id: str) -> str:
        """
        Determine test category from test ID
        Example: AUTH-9308 -> Authentication
        """
        category_map = {
            'AUTH': 'Authentication',
            'BOOT': 'Boot and Services',
            'KRNL': 'Kernel',
            'LOGG': 'Logging',
            'NETW': 'Networking',
            'FILE': 'File Systems',
            'PKGS': 'Packages',
            'STRG': 'Storage',
            'SSH': 'SSH',
            'HTTP': 'Web Server',
            'PHP': 'PHP',
            'SQL': 'Database',
            'MAIL': 'Mail',
            'FIRE': 'Firewall',
            'CRYP': 'Cryptography',
        }

        for prefix, category in category_map.items():
            if test_id.startswith(prefix):
                return category

        return 'Other'

    def _determine_severity(self, test_id: str) -> str:
        """
        Determine severity level based on test ID
        This is a heuristic and can be improved with actual Lynis data
        """
        critical_patterns = ['AUTH-9', 'FIRE-', 'CRYP-']
        high_patterns = ['SSH-', 'BOOT-', 'KRNL-']
        
        for pattern in critical_patterns:
            if test_id.startswith(pattern):
                return 'critical'
        
        for pattern in high_patterns:
            if test_id.startswith(pattern):
                return 'high'
        
        return 'medium'

    def _determine_priority(self, test_id: str) -> str:
        """
        Determine priority level for suggestions
        """
        high_priority = ['AUTH-', 'FIRE-', 'CRYP-', 'SSH-']
        
        for pattern in high_priority:
            if test_id.startswith(pattern):
                return 'high'
        
        return 'medium'

    def get_summary(self) -> Dict[str, Any]:
        """
        Get a summary of parsed data

        Returns:
            Summary dictionary
        """
        if not self.parsed_data:
            return {}

        return {
            'hostname': self.parsed_data['system_info']['hostname'],
            'os': self.parsed_data['system_info']['os'],
            'hardening_index': self.parsed_data['metrics']['hardening_index'],
            'warnings_count': len(self.parsed_data['warnings']),
            'suggestions_count': len(self.parsed_data['suggestions']),
            'tests_performed': self.parsed_data['metrics']['tests_performed'],
            'scan_date': self.parsed_data['system_info']['report_datetime'],
        }
