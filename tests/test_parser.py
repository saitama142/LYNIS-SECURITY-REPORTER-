"""
Unit tests for lynis_reporter.parser module
"""

import pytest
import os
from unittest.mock import Mock, patch, mock_open, MagicMock
from lynis_reporter.parser import LynisParser


class TestLynisParser:
    """Test cases for LynisParser class"""

    def test_parse_local_success(self, temp_lynis_report_file):
        """Test successful parsing of local file"""
        result = LynisParser.parse_local(temp_lynis_report_file)
        
        # Verify basic structure
        assert 'system_info' in result
        assert 'metrics' in result
        assert 'warnings' in result
        assert 'suggestions' in result
        
        # Verify system info
        assert result['system_info']['hostname'] == 'test-server'
        assert result['system_info']['os'] == 'Linux'
        assert result['system_info']['os_version'] == '22.04'
        assert result['system_info']['lynis_version'] == '3.0.9'
        
        # Verify metrics
        assert result['metrics']['hardening_index'] == 67
        assert result['metrics']['tests_performed'] == 265
        assert result['metrics']['warnings_count'] == 3
        assert result['metrics']['suggestions_count'] == 45
        
        # Verify warnings
        assert len(result['warnings']) == 3
        assert result['warnings'][0]['test_id'] == 'AUTH-9308'
        assert 'single user mode' in result['warnings'][0]['message']
        
        # Verify suggestions
        assert len(result['suggestions']) == 4

    def test_parse_local_file_not_found(self):
        """Test parsing non-existent file raises FileNotFoundError"""
        with pytest.raises(FileNotFoundError):
            LynisParser.parse_local('/nonexistent/file.dat')

    def test_parse_local_permission_denied(self, temp_lynis_report_file):
        """Test parsing file without read permission"""
        # Make file unreadable
        os.chmod(temp_lynis_report_file, 0o000)
        
        try:
            with pytest.raises(PermissionError):
                LynisParser.parse_local(temp_lynis_report_file)
        finally:
            # Restore permissions for cleanup
            os.chmod(temp_lynis_report_file, 0o644)

    def test_parse_raw_content_scalars(self):
        """Test parsing scalar key=value pairs"""
        parser = LynisParser()
        content = """hostname=test-server
os=Linux
hardening_index=67
"""
        parser._parse_raw_content(content)
        
        assert parser.raw_data['scalars']['hostname'] == 'test-server'
        assert parser.raw_data['scalars']['os'] == 'Linux'
        assert parser.raw_data['scalars']['hardening_index'] == '67'

    def test_parse_raw_content_arrays(self):
        """Test parsing array key[]= values"""
        parser = LynisParser()
        content = """warning[]=AUTH-9308|Message 1|Component|-
warning[]=SSH-7408|Message 2|SSH|-
installed_package[]=vim
installed_package[]=curl
"""
        parser._parse_raw_content(content)
        
        assert len(parser.raw_data['arrays']['warning']) == 2
        assert len(parser.raw_data['arrays']['installed_package']) == 2
        assert parser.raw_data['arrays']['warning'][0] == 'AUTH-9308|Message 1|Component|-'

    def test_parse_raw_content_ignores_comments(self):
        """Test that comments are ignored during parsing"""
        parser = LynisParser()
        content = """# This is a comment
hostname=test-server
# Another comment
os=Linux
"""
        parser._parse_raw_content(content)
        
        assert len(parser.raw_data['scalars']) == 2
        assert 'hostname' in parser.raw_data['scalars']
        assert 'os' in parser.raw_data['scalars']

    def test_parse_raw_content_ignores_empty_lines(self):
        """Test that empty lines are ignored"""
        parser = LynisParser()
        content = """hostname=test-server

os=Linux

"""
        parser._parse_raw_content(content)
        
        assert len(parser.raw_data['scalars']) == 2

    def test_determine_severity_critical(self):
        """Test severity determination for critical issues"""
        parser = LynisParser()
        
        # CRIT- prefix
        assert parser._determine_severity('CRIT-1234') == 'critical'

    def test_determine_severity_high(self):
        """Test severity determination for high severity issues"""
        parser = LynisParser()
        
        assert parser._determine_severity('AUTH-9308') == 'high'
        assert parser._determine_severity('SSH-7408') == 'high'
        assert parser._determine_severity('FIRE-4512') == 'high'

    def test_determine_severity_medium(self):
        """Test severity determination for medium severity issues"""
        parser = LynisParser()
        
        assert parser._determine_severity('KRNL-5820') == 'medium'
        assert parser._determine_severity('FILE-6310') == 'medium'

    def test_determine_severity_low_default(self):
        """Test severity defaults to low for unknown prefixes"""
        parser = LynisParser()
        
        assert parser._determine_severity('UNKNOWN-1234') == 'low'
        assert parser._determine_severity('TEST-9999') == 'low'

    def test_determine_priority_high(self):
        """Test priority determination for high priority suggestions"""
        parser = LynisParser()
        
        assert parser._determine_priority('AUTH-9286') == 'high'
        assert parser._determine_priority('SSH-7408') == 'high'

    def test_determine_priority_medium(self):
        """Test priority determination for medium priority suggestions"""
        parser = LynisParser()
        
        assert parser._determine_priority('KRNL-5820') == 'medium'
        assert parser._determine_priority('PKGS-7398') == 'medium'

    def test_parse_warnings_with_component(self):
        """Test parsing warnings with component field"""
        parser = LynisParser()
        parser.raw_data = {
            'scalars': {},
            'arrays': {
                'warning': ['SSH-7408|PermitRootLogin enabled|SSH|-']
            }
        }
        
        warnings = parser._parse_warnings(parser.raw_data['arrays'])
        
        assert len(warnings) == 1
        assert warnings[0]['test_id'] == 'SSH-7408'
        assert warnings[0]['component'] == 'SSH'
        assert 'PermitRootLogin' in warnings[0]['message']
        assert warnings[0]['severity'] == 'high'

    def test_parse_warnings_without_component(self):
        """Test parsing warnings without component (dash placeholder)"""
        parser = LynisParser()
        parser.raw_data = {
            'scalars': {},
            'arrays': {
                'warning': ['AUTH-9286|No password set|-|-']
            }
        }
        
        warnings = parser._parse_warnings(parser.raw_data['arrays'])
        
        assert len(warnings) == 1
        assert warnings[0]['component'] == ''

    def test_parse_suggestions_format(self):
        """Test parsing suggestions with proper format"""
        parser = LynisParser()
        parser.raw_data = {
            'scalars': {},
            'arrays': {
                'suggestion': [
                    'AUTH-9286|Install PAM module|-|-',
                    'FILE-6310|Change /tmp permissions|filesystem|-'
                ]
            }
        }
        
        suggestions = parser._parse_suggestions(parser.raw_data['arrays'])
        
        assert len(suggestions) == 2
        assert suggestions[0]['test_id'] == 'AUTH-9286'
        assert suggestions[0]['priority'] == 'high'
        assert suggestions[1]['component'] == 'filesystem'

    def test_parse_system_info_complete(self):
        """Test parsing complete system information"""
        parser = LynisParser()
        scalars = {
            'hostname': 'prod-server',
            'os': 'Linux',
            'os_name': 'Ubuntu',
            'os_version': '22.04',
            'os_fullname': 'Ubuntu 22.04.3 LTS',
            'linux_version': '5.15.0-84-generic',
            'lynis_version': '3.0.9',
            'report_datetime_start': '2025-10-23 22:00:00',
            'report_version': '1.0',
            'auditor': 'admin',
        }
        
        system_info = parser._parse_system_info(scalars)
        
        assert system_info['hostname'] == 'prod-server'
        assert system_info['os'] == 'Linux'
        assert system_info['os_version'] == '22.04'
        assert system_info['kernel_version'] == '5.15.0-84-generic'
        assert system_info['lynis_version'] == '3.0.9'
        assert system_info['auditor'] == 'admin'

    def test_parse_system_info_defaults(self):
        """Test parsing system info with missing fields uses defaults"""
        parser = LynisParser()
        scalars = {}
        
        system_info = parser._parse_system_info(scalars)
        
        assert system_info['hostname'] == 'Unknown'
        assert system_info['os'] == 'Unknown'
        assert system_info['lynis_version'] == 'Unknown'

    def test_parse_metrics_complete(self):
        """Test parsing complete metrics"""
        parser = LynisParser()
        scalars = {
            'hardening_index': '78',
            'lynis_tests_done': '300',
            'warnings_count': '5',
            'suggestions_count': '60',
            'plugins_enabled': '3',
        }
        
        metrics = parser._parse_metrics(scalars)
        
        assert metrics['hardening_index'] == 78
        assert metrics['tests_performed'] == 300
        assert metrics['warnings_count'] == 5
        assert metrics['suggestions_count'] == 60
        assert metrics['plugins_enabled'] == 3

    def test_parse_metrics_invalid_values(self):
        """Test parsing metrics with invalid numeric values defaults to 0"""
        parser = LynisParser()
        scalars = {
            'hardening_index': 'invalid',
            'lynis_tests_done': 'not_a_number',
        }
        
        metrics = parser._parse_metrics(scalars)
        
        assert metrics['hardening_index'] == 0
        assert metrics['tests_performed'] == 0

    def test_parse_packages(self):
        """Test parsing installed packages"""
        parser = LynisParser()
        parser.raw_data = {
            'scalars': {},
            'arrays': {
                'installed_package': ['vim', 'curl', 'nginx', 'python3']
            }
        }
        
        packages = parser._parse_packages(parser.raw_data['arrays'])
        
        assert len(packages) == 4
        assert 'vim' in packages
        assert 'nginx' in packages

    def test_parse_shells(self):
        """Test parsing available shells"""
        parser = LynisParser()
        parser.raw_data = {
            'scalars': {},
            'arrays': {
                'available_shell': ['/bin/bash', '/bin/sh', '/bin/zsh']
            }
        }
        
        shells = parser._parse_shells(parser.raw_data['arrays'])
        
        assert len(shells) == 3
        assert '/bin/bash' in shells

    def test_get_summary(self, temp_lynis_report_file):
        """Test getting summary of parsed data"""
        result = LynisParser.parse_local(temp_lynis_report_file)
        parser = LynisParser(temp_lynis_report_file)
        parser.parsed_data = result
        
        summary = parser.get_summary()
        
        assert 'hostname' in summary
        assert 'hardening_index' in summary
        assert 'warnings_count' in summary
        assert 'suggestions_count' in summary

    @patch('paramiko.SSHClient')
    def test_parse_remote_with_key(self, mock_ssh_client):
        """Test parsing remote file with SSH key authentication"""
        # Mock SSH client and SFTP
        mock_client_instance = MagicMock()
        mock_ssh_client.return_value = mock_client_instance
        
        mock_sftp = MagicMock()
        mock_client_instance.open_sftp.return_value = mock_sftp
        
        mock_file = MagicMock()
        mock_file.read.return_value = b"""hostname=remote-server
os=Linux
hardening_index=70
"""
        mock_sftp.file.return_value = mock_file
        
        # Parse remote
        result = LynisParser.parse_remote(
            ssh_host='example.com',
            ssh_port=22,
            ssh_user='admin',
            auth_method='key',
            ssh_key_path='~/.ssh/id_rsa'
        )
        
        # Verify SSH connection was attempted
        mock_client_instance.connect.assert_called_once()
        assert result['system_info']['hostname'] == 'remote-server'

    def test_parse_remote_invalid_auth_method(self):
        """Test parsing remote with invalid auth method raises error"""
        with pytest.raises(ValueError):
            LynisParser.parse_remote(
                ssh_host='example.com',
                ssh_port=22,
                ssh_user='admin',
                auth_method='invalid'
            )
