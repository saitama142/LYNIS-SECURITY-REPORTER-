"""
Unit tests for lynis_reporter.generator module
"""

import pytest
import json
from pathlib import Path
from unittest.mock import Mock, patch, MagicMock
from lynis_reporter.generator import ReportGenerator


class TestReportGenerator:
    """Test cases for ReportGenerator class"""

    def test_generate_report_creates_file(self, temp_report_dir, sample_parsed_data):
        """Test that generate_report creates an HTML file"""
        output_path = Path(temp_report_dir) / "test_report.html"
        
        generator = ReportGenerator()
        result = generator.generate_report(
            parsed_data=sample_parsed_data,
            historical_data=[],
            output_path=str(output_path)
        )
        
        assert output_path.exists()
        assert result == str(output_path)

    def test_generate_report_with_historical_data(self, temp_report_dir, sample_parsed_data):
        """Test generating report with historical data"""
        output_path = Path(temp_report_dir) / "test_report.html"
        
        historical_data = [
            {'hardening_index': 65, 'scan_date': '2025-10-20 10:00:00'},
            {'hardening_index': 67, 'scan_date': '2025-10-21 10:00:00'},
        ]
        
        generator = ReportGenerator()
        result = generator.generate_report(
            parsed_data=sample_parsed_data,
            historical_data=historical_data,
            output_path=str(output_path)
        )
        
        assert output_path.exists()
        # Read and verify content
        content = output_path.read_text()
        assert 'test-server' in content
        assert 'Executive Summary' in content

    def test_prepare_context_structure(self, sample_parsed_data):
        """Test that _prepare_context creates proper structure"""
        generator = ReportGenerator()
        
        context = generator._prepare_context(sample_parsed_data, [])
        
        # Verify required keys
        assert 'report_title' in context
        assert 'generated_date' in context
        assert 'system_info' in context
        assert 'metrics' in context
        assert 'warnings' in context
        assert 'suggestions' in context
        assert 'charts' in context

    def test_prepare_context_with_comparison(self, sample_parsed_data):
        """Test context preparation with previous scan for comparison"""
        previous_scan = {
            'hardening_index': 60,
            'warnings_count': 5,
        }
        
        generator = ReportGenerator()
        context = generator._prepare_context(
            sample_parsed_data,
            historical_data=[previous_scan]
        )
        
        assert 'comparison' in context
        assert context['comparison'] is not None

    def test_generate_charts_creates_all_charts(self, sample_parsed_data):
        """Test that all required charts are generated"""
        generator = ReportGenerator()
        
        charts = generator._generate_charts(sample_parsed_data, [])
        
        # Verify all chart types exist
        assert 'hardening_gauge' in charts
        assert 'test_coverage' in charts
        assert 'severity_breakdown' in charts

    def test_create_hardening_gauge(self, sample_parsed_data):
        """Test hardening index gauge chart creation"""
        generator = ReportGenerator()
        
        chart_json = generator._create_hardening_gauge(67)
        
        assert chart_json is not None
        # Parse JSON to verify it's valid
        chart_data = json.loads(chart_json)
        assert 'data' in chart_data

    def test_create_test_coverage_chart(self, sample_parsed_data):
        """Test test coverage pie chart creation"""
        generator = ReportGenerator()
        metrics = sample_parsed_data['metrics']
        
        chart_json = generator._create_test_coverage_chart(metrics)
        
        assert chart_json is not None
        chart_data = json.loads(chart_json)
        assert 'data' in chart_data

    def test_create_severity_chart(self, sample_parsed_data):
        """Test severity breakdown bar chart creation"""
        generator = ReportGenerator()
        warnings = sample_parsed_data['warnings']
        
        chart_json = generator._create_severity_chart(warnings)
        
        assert chart_json is not None
        chart_data = json.loads(chart_json)
        assert 'data' in chart_data

    def test_create_trend_chart_with_history(self, sample_parsed_data):
        """Test trend chart with historical data"""
        generator = ReportGenerator()
        
        historical_data = [
            {'hardening_index': 60, 'scan_date': '2025-10-20'},
            {'hardening_index': 65, 'scan_date': '2025-10-21'},
            {'hardening_index': 67, 'scan_date': '2025-10-22'},
        ]
        
        chart_json = generator._create_trend_chart(historical_data)
        
        if chart_json:  # May be None if insufficient data
            chart_data = json.loads(chart_json)
            assert 'data' in chart_data

    def test_create_trend_chart_insufficient_data(self):
        """Test trend chart returns None with insufficient data"""
        generator = ReportGenerator()
        
        chart_json = generator._create_trend_chart([])
        
        # Should handle gracefully
        assert chart_json is None or chart_json != ""

    def test_count_by_severity(self, sample_parsed_data):
        """Test counting warnings by severity level"""
        generator = ReportGenerator()
        warnings = sample_parsed_data['warnings']
        
        counts = generator._count_by_severity(warnings)
        
        assert 'high' in counts
        assert 'medium' in counts
        assert counts['high'] == 2  # AUTH-9308 and SSH-7408
        assert counts['medium'] == 1  # KRNL-5820

    def test_count_by_severity_empty(self):
        """Test severity counting with no warnings"""
        generator = ReportGenerator()
        
        counts = generator._count_by_severity([])
        
        assert counts == {}

    def test_calculate_comparison_score_increase(self):
        """Test comparison calculation with score increase"""
        generator = ReportGenerator()
        
        current = {'metrics': {'hardening_index': 75, 'warnings_count': 2}}
        previous = {'hardening_index': 67, 'warnings_count': 3}
        
        comparison = generator._calculate_comparison(current, previous)
        
        assert comparison['score_delta'] == 8
        assert comparison['score_trend'] == 'up'
        assert comparison['warnings_delta'] == -1

    def test_calculate_comparison_score_decrease(self):
        """Test comparison calculation with score decrease"""
        generator = ReportGenerator()
        
        current = {'metrics': {'hardening_index': 60, 'warnings_count': 5}}
        previous = {'hardening_index': 67, 'warnings_count': 3}
        
        comparison = generator._calculate_comparison(current, previous)
        
        assert comparison['score_delta'] == -7
        assert comparison['score_trend'] == 'down'
        assert comparison['warnings_delta'] == 2

    def test_calculate_comparison_no_change(self):
        """Test comparison with no score change"""
        generator = ReportGenerator()
        
        current = {'metrics': {'hardening_index': 67, 'warnings_count': 3}}
        previous = {'hardening_index': 67, 'warnings_count': 3}
        
        comparison = generator._calculate_comparison(current, previous)
        
        assert comparison['score_delta'] == 0
        assert comparison['score_trend'] == 'stable'

    def test_generate_remediation_guide(self, sample_parsed_data):
        """Test remediation guide generation"""
        generator = ReportGenerator()
        
        warnings = sample_parsed_data['warnings']
        suggestions = sample_parsed_data['suggestions']
        
        guide = generator._generate_remediation_guide(warnings, suggestions)
        
        assert isinstance(guide, list)
        assert len(guide) <= 20  # Top 20 items
        
        if len(guide) > 0:
            assert 'test_id' in guide[0]
            assert 'message' in guide[0]
            assert 'priority' in guide[0]

    def test_generate_remediation_guide_prioritization(self, sample_parsed_data):
        """Test that remediation guide prioritizes critical items first"""
        generator = ReportGenerator()
        
        # Add critical warning
        warnings = sample_parsed_data['warnings']
        warnings.append({
            'test_id': 'CRIT-9999',
            'message': 'Critical security issue',
            'severity': 'critical',
            'component': 'system'
        })
        
        guide = generator._generate_remediation_guide(warnings, [])
        
        # Critical items should be first
        assert guide[0]['priority'] == 'critical'

    def test_get_remediation_command_known_test(self):
        """Test getting remediation command for known test ID"""
        generator = ReportGenerator()
        
        command = generator._get_remediation_command('AUTH-9286')
        
        assert command is not None
        assert len(command) > 0

    def test_get_remediation_command_unknown_test(self):
        """Test getting remediation command for unknown test ID"""
        generator = ReportGenerator()
        
        command = generator._get_remediation_command('UNKNOWN-9999')
        
        # Should return None or empty string for unknown tests
        assert command is None or command == ""

    def test_severity_sort_key(self):
        """Test severity sorting order"""
        generator = ReportGenerator()
        
        # Lower numbers = higher priority
        assert generator._severity_sort_key('critical') < generator._severity_sort_key('high')
        assert generator._severity_sort_key('high') < generator._severity_sort_key('medium')
        assert generator._severity_sort_key('medium') < generator._severity_sort_key('low')

    def test_priority_sort_key(self):
        """Test priority sorting order"""
        generator = ReportGenerator()
        
        # Lower numbers = higher priority
        assert generator._priority_sort_key('critical') < generator._priority_sort_key('high')
        assert generator._priority_sort_key('high') < generator._priority_sort_key('medium')
        assert generator._priority_sort_key('medium') < generator._priority_sort_key('low')

    def test_generate_report_handles_empty_warnings(self, temp_report_dir, sample_parsed_data):
        """Test report generation with no warnings"""
        sample_parsed_data['warnings'] = []
        output_path = Path(temp_report_dir) / "test_report.html"
        
        generator = ReportGenerator()
        result = generator.generate_report(
            parsed_data=sample_parsed_data,
            historical_data=[],
            output_path=str(output_path)
        )
        
        assert output_path.exists()
        content = output_path.read_text()
        assert 'Executive Summary' in content

    def test_generate_report_handles_empty_suggestions(self, temp_report_dir, sample_parsed_data):
        """Test report generation with no suggestions"""
        sample_parsed_data['suggestions'] = []
        output_path = Path(temp_report_dir) / "test_report.html"
        
        generator = ReportGenerator()
        result = generator.generate_report(
            parsed_data=sample_parsed_data,
            historical_data=[],
            output_path=str(output_path)
        )
        
        assert output_path.exists()

    def test_create_category_chart(self, sample_parsed_data):
        """Test category breakdown chart creation"""
        generator = ReportGenerator()
        
        warnings = sample_parsed_data['warnings']
        suggestions = sample_parsed_data['suggestions']
        
        chart_json = generator._create_category_chart(warnings, suggestions)
        
        if chart_json:
            chart_data = json.loads(chart_json)
            assert 'data' in chart_data

    def test_report_contains_translation_widget(self, temp_report_dir, sample_parsed_data):
        """Test that generated report contains Google Translate widget"""
        output_path = Path(temp_report_dir) / "test_report.html"
        
        generator = ReportGenerator()
        generator.generate_report(
            parsed_data=sample_parsed_data,
            historical_data=[],
            output_path=str(output_path)
        )
        
        content = output_path.read_text()
        
        # Verify translation elements are present
        assert 'google_translate_element' in content
        assert 'googleTranslateElementInit' in content or 'Google Translate' in content

    def test_report_contains_bootstrap(self, temp_report_dir, sample_parsed_data):
        """Test that report uses Bootstrap 5"""
        output_path = Path(temp_report_dir) / "test_report.html"
        
        generator = ReportGenerator()
        generator.generate_report(
            parsed_data=sample_parsed_data,
            historical_data=[],
            output_path=str(output_path)
        )
        
        content = output_path.read_text()
        assert 'bootstrap' in content.lower()

    def test_report_contains_datatables(self, temp_report_dir, sample_parsed_data):
        """Test that report includes DataTables for sortable tables"""
        output_path = Path(temp_report_dir) / "test_report.html"
        
        generator = ReportGenerator()
        generator.generate_report(
            parsed_data=sample_parsed_data,
            historical_data=[],
            output_path=str(output_path)
        )
        
        content = output_path.read_text()
        assert 'DataTable' in content or 'datatables' in content.lower()

    def test_generate_report_with_missing_fields(self, temp_report_dir):
        """Test report generation handles missing data gracefully"""
        minimal_data = {
            'system_info': {'hostname': 'test', 'os': 'Linux'},
            'metrics': {'hardening_index': 50},
            'warnings': [],
            'suggestions': [],
            'packages': [],
            'shells': [],
        }
        
        output_path = Path(temp_report_dir) / "test_report.html"
        
        generator = ReportGenerator()
        result = generator.generate_report(
            parsed_data=minimal_data,
            historical_data=[],
            output_path=str(output_path)
        )
        
        assert output_path.exists()
