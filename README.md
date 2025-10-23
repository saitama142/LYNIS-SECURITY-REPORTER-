# 🔒 Lynis Reporter

Beautiful HTML security reports from Lynis scans. Simple. Local. Fast.

## Install

```bash
curl -sSL https://raw.githubusercontent.com/YOUR_REPO/main/install | bash
```

Or manual:
```bash
git clone https://github.com/YOUR_REPO/lynis-reporter.git
cd lynis-reporter
./install
```

## Usage

```bash
./scan              # Run scan + generate report (recommended)
./scan quick        # Quick scan (30 seconds)

./report            # Interactive menu
./report generate   # Just generate from existing scan
./report serve      # Just start web server
```

## What You Get

- **Security Score** - 0-100 hardening index
- **260+ Tests** - Comprehensive security audit
- **Interactive Charts** - Plotly visualizations
- **Prioritized Actions** - What to fix first
- **Historical Tracking** - See improvements over time
- **Dark Mode** - Easy on the eyes

## Example

```bash
$ ./scan
🔍 Running security scan...
📊 Generating report...
✅ Report ready!
🌐 http://192.168.0.32:35480/
```

Open in browser → See your security report → Fix issues → Scan again

## Features

✅ **Simple** - One command does everything  
✅ **Local** - No cloud, no data sent anywhere  
✅ **Fast** - Quick scan in 30 seconds  
✅ **Beautiful** - Modern Bootstrap UI  
✅ **Smart** - Auto-detects and fixes issues

## Requirements

- Ubuntu/Debian Linux
- Python 3.8+
- sudo access (for Lynis)

Auto-installed by the installer:
- Lynis
- Python packages (plotly, pandas, jinja2, yaml)

## License

MIT

## Credits

- **Lynis** - CISOfy (security auditing tool)
- **Bootstrap** - UI framework
- **Plotly** - Charts
