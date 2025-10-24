"""
Report Generator for Lynis Reporter
Generates HTML reports with Plotly visualizations
"""

import os
import logging
from typing import Dict, List, Any, Optional
from datetime import datetime
from pathlib import Path
from jinja2 import Environment, FileSystemLoader, select_autoescape
import plotly.graph_objects as go
import plotly.express as px
from plotly.subplots import make_subplots
import json

logger = logging.getLogger(__name__)


class ReportGenerator:
    """
    Generates HTML reports from parsed Lynis data
    """

    def __init__(self, template_dir: str = None, config: Any = None):
        """
        Initialize report generator

        Args:
            template_dir: Directory containing Jinja2 templates
            config: Configuration object with styling options
        """
        if template_dir is None:
            # Default to templates directory relative to this file
            base_dir = Path(__file__).parent.parent
            template_dir = str(base_dir / "templates")

        self.template_dir = template_dir
        self.config = config

        # Initialize Jinja2 environment
        self.jinja_env = Environment(
            loader=FileSystemLoader(template_dir),
            autoescape=select_autoescape(['html', 'xml'])
        )

        logger.info(f"Report generator initialized with templates from {template_dir}")

    def generate_report(self, parsed_data: Dict[str, Any],
                       historical_data: Optional[List[Dict[str, Any]]] = None,
                       output_path: str = "./report.html") -> str:
        """
        Generate complete HTML report

        Args:
            parsed_data: Parsed scan data from LynisParser
            historical_data: Historical scan data for trends
            output_path: Output file path

        Returns:
            Path to generated report
        """
        try:
            logger.info(f"Generating report: {output_path}")

            # Prepare data for template
            context = self._prepare_context(parsed_data, historical_data)

            # Generate charts
            charts = self._generate_charts(parsed_data, historical_data)
            context['charts'] = charts

            # Render template
            template = self.jinja_env.get_template('report.html')
            html_content = template.render(**context)

            # Write output
            output_dir = os.path.dirname(output_path)
            if output_dir and not os.path.exists(output_dir):
                os.makedirs(output_dir, exist_ok=True)

            with open(output_path, 'w', encoding='utf-8') as f:
                f.write(html_content)

            logger.info(f"Report generated successfully: {output_path}")
            return output_path

        except Exception as e:
            logger.error(f"Error generating report: {e}")
            raise

    def _prepare_context(self, parsed_data: Dict[str, Any],
                        historical_data: Optional[List[Dict[str, Any]]]) -> Dict[str, Any]:
        """
        Prepare template context from parsed data

        Args:
            parsed_data: Parsed scan data
            historical_data: Historical scan data

        Returns:
            Template context dictionary
        """
        system_info = parsed_data.get('system_info', {})
        metrics = parsed_data.get('metrics', {})
        warnings = parsed_data.get('warnings', [])
        suggestions = parsed_data.get('suggestions', [])

        # Calculate severity counts
        severity_counts = self._count_by_severity(warnings)
        priority_counts = self._count_by_priority(suggestions)

        # Get comparison data if historical data available
        comparison = None
        if historical_data and len(historical_data) > 1:
            comparison = self._calculate_comparison(historical_data[0], historical_data[1])

        # Get remediation guide
        remediation = self._generate_remediation_guide(warnings, suggestions)

        from lynis_reporter import __version__

        context = {
            'report_title': f"Lynis Security Report - {system_info.get('hostname', 'Unknown')}",
            'generated_date': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
            'tool_version': __version__,
            'system_info': system_info,
            'metrics': metrics,
            'warnings': sorted(warnings, key=lambda x: self._severity_sort_key(x.get('severity', 'medium'))),
            'suggestions': sorted(suggestions, key=lambda x: self._priority_sort_key(x.get('priority', 'medium'))),
            'severity_counts': severity_counts,
            'priority_counts': priority_counts,
            'comparison': comparison,
            'remediation': remediation,
            'has_history': historical_data is not None and len(historical_data) > 1,
            'config': self.config,
        }

        return context

    def _generate_charts(self, parsed_data: Dict[str, Any],
                        historical_data: Optional[List[Dict[str, Any]]]) -> Dict[str, str]:
        """
        Generate Plotly charts for the report

        Args:
            parsed_data: Parsed scan data
            historical_data: Historical scan data

        Returns:
            Dictionary of chart HTML strings
        """
        charts = {}

        metrics = parsed_data.get('metrics', {})
        warnings = parsed_data.get('warnings', [])
        suggestions = parsed_data.get('suggestions', [])

        # 1. Hardening Index Gauge
        charts['hardening_gauge'] = self._create_hardening_gauge(metrics.get('hardening_index', 0))

        # 2. Test Coverage Pie Chart
        charts['test_coverage'] = self._create_test_coverage_chart(metrics)

        # 3. Severity Distribution Bar Chart
        charts['severity_distribution'] = self._create_severity_chart(warnings)

        # 4. Historical Trend (if data available)
        if historical_data and len(historical_data) > 1:
            charts['hardening_trend'] = self._create_trend_chart(historical_data)
            charts['warnings_trend'] = self._create_warnings_trend_chart(historical_data)

        # 5. Category Breakdown
        charts['category_breakdown'] = self._create_category_chart(warnings, suggestions)

        return charts

    def _create_hardening_gauge(self, hardening_index: int) -> str:
        """Create hardening index gauge chart"""
        # Determine color based on score
        if hardening_index >= 80:
            color = "#28a745"  # green
        elif hardening_index >= 60:
            color = "#ffc107"  # yellow
        else:
            color = "#dc3545"  # red

        fig = go.Figure(go.Indicator(
            mode="gauge+number+delta",
            value=hardening_index,
            domain={'x': [0, 1], 'y': [0, 1]},
            title={'text': "Hardening Index", 'font': {'size': 24}},
            delta={'reference': 80, 'increasing': {'color': "green"}},
            gauge={
                'axis': {'range': [None, 100], 'tickwidth': 1, 'tickcolor': "darkgray"},
                'bar': {'color': color},
                'bgcolor': "white",
                'borderwidth': 2,
                'bordercolor': "gray",
                'steps': [
                    {'range': [0, 40], 'color': '#ffebee'},
                    {'range': [40, 60], 'color': '#fff3e0'},
                    {'range': [60, 80], 'color': '#fff9c4'},
                    {'range': [80, 100], 'color': '#e8f5e9'}
                ],
                'threshold': {
                    'line': {'color': "red", 'width': 4},
                    'thickness': 0.75,
                    'value': 80
                }
            }
        ))

        fig.update_layout(
            height=300,
            margin=dict(l=20, r=20, t=60, b=20),
            paper_bgcolor="rgba(0,0,0,0)",
            font={'size': 16}
        )

        return fig.to_html(full_html=False, include_plotlyjs='cdn', div_id='hardening-gauge')

    def _create_test_coverage_chart(self, metrics: Dict[str, Any]) -> str:
        """Create test coverage pie chart"""
        performed = metrics.get('tests_performed', 0)
        skipped = metrics.get('tests_skipped', 0)

        if performed == 0 and skipped == 0:
            return ""

        fig = go.Figure(data=[go.Pie(
            labels=['Tests Performed', 'Tests Skipped'],
            values=[performed, skipped],
            hole=.3,
            marker_colors=['#0066cc', '#e0e0e0']
        )])

        fig.update_layout(
            title_text="Test Coverage",
            height=300,
            margin=dict(l=20, r=20, t=60, b=20),
            showlegend=True,
            paper_bgcolor="rgba(0,0,0,0)"
        )

        return fig.to_html(full_html=False, include_plotlyjs='cdn', div_id='test-coverage')

    def _create_severity_chart(self, warnings: List[Dict[str, Any]]) -> str:
        """Create severity distribution bar chart"""
        severity_counts = self._count_by_severity(warnings)

        if not severity_counts:
            return ""

        severities = ['critical', 'high', 'medium', 'low']
        colors = {
            'critical': '#dc3545',
            'high': '#fd7e14',
            'medium': '#ffc107',
            'low': '#17a2b8'
        }

        counts = [severity_counts.get(s, 0) for s in severities]
        color_list = [colors[s] for s in severities]

        fig = go.Figure(data=[go.Bar(
            x=severities,
            y=counts,
            marker_color=color_list,
            text=counts,
            textposition='auto',
        )])

        fig.update_layout(
            title_text="Warnings by Severity",
            xaxis_title="Severity Level",
            yaxis_title="Count",
            height=300,
            margin=dict(l=40, r=20, t=60, b=40),
            paper_bgcolor="rgba(0,0,0,0)"
        )

        return fig.to_html(full_html=False, include_plotlyjs='cdn', div_id='severity-chart')

    def _create_trend_chart(self, historical_data: List[Dict[str, Any]]) -> str:
        """Create hardening index trend chart"""
        if not historical_data or len(historical_data) < 2:
            return ""

        # Sort by date
        sorted_data = sorted(historical_data, key=lambda x: x.get('scan_date', ''))

        dates = [datetime.fromisoformat(d.get('scan_date', '')).strftime('%Y-%m-%d') 
                for d in sorted_data]
        indices = [d.get('hardening_index', 0) for d in sorted_data]

        fig = go.Figure()

        fig.add_trace(go.Scatter(
            x=dates,
            y=indices,
            mode='lines+markers',
            name='Hardening Index',
            line=dict(color='#0066cc', width=3),
            marker=dict(size=8)
        ))

        # Add reference line at 80
        fig.add_hline(y=80, line_dash="dash", line_color="green",
                     annotation_text="Target (80)", annotation_position="right")

        fig.update_layout(
            title_text="Hardening Index Trend",
            xaxis_title="Scan Date",
            yaxis_title="Hardening Index",
            height=300,
            margin=dict(l=40, r=20, t=60, b=40),
            paper_bgcolor="rgba(0,0,0,0)",
            yaxis=dict(range=[0, 100])
        )

        return fig.to_html(full_html=False, include_plotlyjs='cdn', div_id='trend-chart')

    def _create_warnings_trend_chart(self, historical_data: List[Dict[str, Any]]) -> str:
        """Create warnings count trend chart"""
        if not historical_data or len(historical_data) < 2:
            return ""

        sorted_data = sorted(historical_data, key=lambda x: x.get('scan_date', ''))

        dates = [datetime.fromisoformat(d.get('scan_date', '')).strftime('%Y-%m-%d') 
                for d in sorted_data]
        warnings_counts = [d.get('warnings_count', 0) for d in sorted_data]
        suggestions_counts = [d.get('suggestions_count', 0) for d in sorted_data]

        fig = go.Figure()

        fig.add_trace(go.Scatter(
            x=dates,
            y=warnings_counts,
            mode='lines+markers',
            name='Warnings',
            line=dict(color='#dc3545', width=2),
            marker=dict(size=6)
        ))

        fig.add_trace(go.Scatter(
            x=dates,
            y=suggestions_counts,
            mode='lines+markers',
            name='Suggestions',
            line=dict(color='#ffc107', width=2),
            marker=dict(size=6)
        ))

        fig.update_layout(
            title_text="Warnings & Suggestions Trend",
            xaxis_title="Scan Date",
            yaxis_title="Count",
            height=300,
            margin=dict(l=40, r=20, t=60, b=40),
            paper_bgcolor="rgba(0,0,0,0)",
            showlegend=True
        )

        return fig.to_html(full_html=False, include_plotlyjs='cdn', div_id='warnings-trend')

    def _create_category_chart(self, warnings: List[Dict[str, Any]],
                               suggestions: List[Dict[str, Any]]) -> str:
        """Create category breakdown chart"""
        categories = {}

        for warning in warnings:
            test_id = warning.get('test_id', 'UNKNOWN')
            category = self._get_category_from_test_id(test_id)
            categories[category] = categories.get(category, 0) + 1

        if not categories:
            return ""

        sorted_categories = sorted(categories.items(), key=lambda x: x[1], reverse=True)[:10]
        labels = [c[0] for c in sorted_categories]
        values = [c[1] for c in sorted_categories]

        fig = go.Figure(data=[go.Bar(
            x=values,
            y=labels,
            orientation='h',
            marker_color='#0066cc'
        )])

        fig.update_layout(
            title_text="Top 10 Categories by Issues",
            xaxis_title="Count",
            height=400,
            margin=dict(l=150, r=20, t=60, b=40),
            paper_bgcolor="rgba(0,0,0,0)"
        )

        return fig.to_html(full_html=False, include_plotlyjs='cdn', div_id='category-chart')

    def _count_by_severity(self, warnings: List[Dict[str, Any]]) -> Dict[str, int]:
        """Count warnings by severity"""
        counts = {}
        for warning in warnings:
            severity = warning.get('severity', 'medium')
            counts[severity] = counts.get(severity, 0) + 1
        return counts

    def _count_by_priority(self, suggestions: List[Dict[str, Any]]) -> Dict[str, int]:
        """Count suggestions by priority"""
        counts = {}
        for suggestion in suggestions:
            priority = suggestion.get('priority', 'medium')
            counts[priority] = counts.get(priority, 0) + 1
        return counts

    def _calculate_comparison(self, current: Dict[str, Any],
                             previous: Dict[str, Any]) -> Dict[str, Any]:
        """Calculate comparison between two scans"""
        return {
            'hardening_delta': current.get('hardening_index', 0) - previous.get('hardening_index', 0),
            'warnings_delta': current.get('warnings_count', 0) - previous.get('warnings_count', 0),
            'suggestions_delta': current.get('suggestions_count', 0) - previous.get('suggestions_count', 0),
            'previous_date': previous.get('scan_date', ''),
        }

    def _generate_remediation_guide(self, warnings: List[Dict[str, Any]],
                                   suggestions: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Generate prioritized remediation guide"""
        items = []

        # Add critical/high warnings first
        for warning in warnings:
            severity = warning.get('severity', 'medium')
            if severity in ['critical', 'high']:
                items.append({
                    'type': 'warning',
                    'severity': severity,
                    'test_id': warning.get('test_id', ''),
                    'message': warning.get('message', ''),
                    'command': self._get_remediation_command(warning.get('test_id', '')),
                })

        # Add high priority suggestions
        for suggestion in suggestions:
            if suggestion.get('priority', 'medium') == 'high':
                items.append({
                    'type': 'suggestion',
                    'priority': 'high',
                    'test_id': suggestion.get('test_id', ''),
                    'message': suggestion.get('message', ''),
                    'command': self._get_remediation_command(suggestion.get('test_id', '')),
                })

        return items[:20]  # Limit to top 20

    def _get_remediation_command(self, test_id: str) -> str:
        """Get remediation command for a test ID (placeholder)"""
        # This is a simplified version - in production, you'd have a comprehensive mapping
        command_map = {
            'SSH-7408': 'Edit /etc/ssh/sshd_config and set PermitRootLogin no',
            'AUTH-9262': 'Set PASS_MAX_DAYS in /etc/login.defs',
            'AUTH-9286': 'Install and configure pam_cracklib or pam_pwquality',
            'FIRE-4512': 'Enable UFW: sudo ufw enable',
        }
        return command_map.get(test_id, 'Refer to Lynis documentation for remediation steps')

    def _get_category_from_test_id(self, test_id: str) -> str:
        """Get category from test ID"""
        category_map = {
            'AUTH': 'Authentication',
            'BOOT': 'Boot & Services',
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

    def _severity_sort_key(self, severity: str) -> int:
        """Get sort key for severity"""
        order = {'critical': 0, 'high': 1, 'medium': 2, 'low': 3}
        return order.get(severity, 999)

    def _priority_sort_key(self, priority: str) -> int:
        """Get sort key for priority"""
        order = {'high': 0, 'medium': 1, 'low': 2}
        return order.get(priority, 999)
