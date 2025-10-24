"""
Update Manager for Lynis Reporter
Handles version checking and updates from GitHub releases
"""

import os
import json
import time
import subprocess
import urllib.request
import urllib.error
from pathlib import Path
from typing import Optional, Dict, Any
from datetime import datetime, timedelta

from lynis_reporter import __version__


class UpdateManager:
    """Manages updates and version checking for Lynis Reporter"""
    
    GITHUB_API_URL = "https://api.github.com/repos/saitama142/LYNIS-SECURITY-REPORTER-/releases/latest"
    CACHE_DIR = Path.home() / ".cache" / "lynis-reporter"
    CACHE_FILE = CACHE_DIR / "update_check.json"
    CHECK_INTERVAL = 86400  # 24 hours in seconds
    
    def __init__(self, repo_path: Optional[str] = None):
        """
        Initialize update manager
        
        Args:
            repo_path: Path to lynis-reporter repository (auto-detected if None)
        """
        self.current_version = __version__
        self.repo_path = repo_path or self._find_repo_path()
        self.cache_data = self._load_cache()
    
    def _find_repo_path(self) -> Path:
        """Find the lynis-reporter repository path"""
        # Try to find from current script location
        current_file = Path(__file__).resolve()
        repo_path = current_file.parent.parent
        
        # Verify it's a git repo
        if (repo_path / ".git").exists():
            return repo_path
        
        # Fallback to ~/lynis-reporter
        fallback = Path.home() / "lynis-reporter"
        if fallback.exists():
            return fallback
        
        return repo_path
    
    def _load_cache(self) -> Dict[str, Any]:
        """Load cached update check data"""
        try:
            if self.CACHE_FILE.exists():
                with open(self.CACHE_FILE, 'r') as f:
                    return json.load(f)
        except Exception:
            pass
        return {}
    
    def _save_cache(self, data: Dict[str, Any]):
        """Save update check data to cache"""
        try:
            self.CACHE_DIR.mkdir(parents=True, exist_ok=True)
            with open(self.CACHE_FILE, 'w') as f:
                json.dump(data, f, indent=2)
        except Exception:
            pass  # Fail silently if can't write cache
    
    def _should_check(self) -> bool:
        """Check if enough time has passed since last check"""
        last_check = self.cache_data.get('last_check_timestamp', 0)
        return (time.time() - last_check) > self.CHECK_INTERVAL
    
    def _fetch_latest_release(self) -> Optional[Dict[str, Any]]:
        """
        Fetch latest release info from GitHub API
        
        Returns:
            Release data dict or None if failed
        """
        try:
            req = urllib.request.Request(
                self.GITHUB_API_URL,
                headers={'Accept': 'application/vnd.github.v3+json'}
            )
            
            with urllib.request.urlopen(req, timeout=5) as response:
                if response.status == 200:
                    data = json.loads(response.read().decode('utf-8'))
                    return data
        except (urllib.error.URLError, urllib.error.HTTPError, TimeoutError):
            pass  # Fail silently if no internet or API error
        except Exception:
            pass
        
        return None
    
    def check_for_updates(self, force: bool = False) -> Optional[Dict[str, Any]]:
        """
        Check if a new version is available
        
        Args:
            force: Force check even if cached result is fresh
        
        Returns:
            Dict with update info or None if no update/error
            {
                'available': bool,
                'latest_version': str,
                'current_version': str,
                'release_notes': str,
                'published_at': str,
                'html_url': str
            }
        """
        # Use cached result if fresh and not forcing
        if not force and not self._should_check():
            cached_result = self.cache_data.get('last_result')
            if cached_result:
                return cached_result
        
        # Fetch latest release from GitHub
        release_data = self._fetch_latest_release()
        
        if not release_data:
            return self.cache_data.get('last_result')  # Return cached if API fails
        
        latest_version = release_data.get('tag_name', '').lstrip('v')
        
        # Compare versions
        update_available = self._compare_versions(latest_version, self.current_version)
        
        result = {
            'available': update_available,
            'latest_version': latest_version,
            'current_version': self.current_version,
            'release_notes': release_data.get('body', ''),
            'published_at': release_data.get('published_at', ''),
            'html_url': release_data.get('html_url', ''),
            'checked_at': datetime.now().isoformat()
        }
        
        # Cache the result
        self._save_cache({
            'last_check_timestamp': time.time(),
            'last_result': result
        })
        
        return result if update_available else None
    
    def _compare_versions(self, latest: str, current: str) -> bool:
        """
        Compare version strings (semantic versioning)
        
        Args:
            latest: Latest version string (e.g., "1.2.0")
            current: Current version string (e.g., "1.1.0")
        
        Returns:
            True if latest > current
        """
        try:
            latest_parts = [int(x) for x in latest.split('.')]
            current_parts = [int(x) for x in current.split('.')]
            
            # Pad with zeros if needed
            while len(latest_parts) < 3:
                latest_parts.append(0)
            while len(current_parts) < 3:
                current_parts.append(0)
            
            return tuple(latest_parts) > tuple(current_parts)
        except (ValueError, AttributeError):
            return False
    
    def show_update_notification(self, update_info: Dict[str, Any]) -> None:
        """
        Display update notification to user
        
        Args:
            update_info: Update information dict from check_for_updates()
        """
        if not update_info or not update_info.get('available'):
            return
        
        checked_at = update_info.get('checked_at', '')
        try:
            checked_time = datetime.fromisoformat(checked_at)
            time_ago = self._humanize_time_diff(datetime.now() - checked_time)
        except:
            time_ago = "recently"
        
        print()
        print(f"ℹ️  Update available: v{update_info['current_version']} → v{update_info['latest_version']} (checked {time_ago})")
        print(f"   Run './report update' to upgrade")
        print()
    
    def _humanize_time_diff(self, delta: timedelta) -> str:
        """Convert timedelta to human-readable string"""
        seconds = int(delta.total_seconds())
        
        if seconds < 60:
            return "just now"
        elif seconds < 3600:
            minutes = seconds // 60
            return f"{minutes} minute{'s' if minutes != 1 else ''} ago"
        elif seconds < 86400:
            hours = seconds // 3600
            return f"{hours} hour{'s' if hours != 1 else ''} ago"
        else:
            days = seconds // 86400
            return f"{days} day{'s' if days != 1 else ''} ago"
    
    def perform_update(self, interactive: bool = True) -> bool:
        """
        Perform the actual update via git pull
        
        Args:
            interactive: Show prompts and confirmations
        
        Returns:
            True if update successful, False otherwise
        """
        # Check for updates first
        update_info = self.check_for_updates(force=True)
        
        if not update_info or not update_info.get('available'):
            print("✅ Already up to date!")
            print(f"   Current version: v{self.current_version}")
            return True
        
        if interactive:
            self._show_update_prompt(update_info)
            
            response = input("\nContinue? (Y/n): ").strip().lower()
            if response not in ['', 'y', 'yes']:
                print("❌ Update cancelled")
                return False
        
        print("\n📦 Updating...")
        
        # Check if repo is clean
        if not self._check_repo_clean():
            print("\n⚠️  You have local changes in the repository")
            if interactive:
                response = input("Stash changes and continue? (Y/n): ").strip().lower()
                if response not in ['', 'y', 'yes']:
                    print("❌ Update cancelled")
                    return False
                
                # Stash changes
                result = subprocess.run(
                    ['git', 'stash'],
                    cwd=self.repo_path,
                    capture_output=True,
                    text=True
                )
                if result.returncode != 0:
                    print("❌ Failed to stash changes")
                    return False
                print("  ✓ Changes stashed")
        
        # Backup database
        if not self._backup_database():
            print("⚠️  Database backup failed (continuing anyway)")
        else:
            print("  ✓ Database backed up")
        
        # Perform git pull
        result = subprocess.run(
            ['git', 'pull', 'origin', 'main'],
            cwd=self.repo_path,
            capture_output=True,
            text=True
        )
        
        if result.returncode != 0:
            print(f"❌ Git pull failed: {result.stderr}")
            return False
        
        print("  ✓ Git pull successful")
        
        # Update Python dependencies
        pip_result = subprocess.run(
            ['pip3', 'install', '-q', '-r', 'requirements.txt'],
            cwd=self.repo_path,
            capture_output=True,
            text=True
        )
        
        if pip_result.returncode == 0:
            print("  ✓ Dependencies updated")
        else:
            print("  ⚠️  Some dependencies may need manual update")
        
        # Clear cache so we don't keep showing update notification
        self._save_cache({
            'last_check_timestamp': time.time(),
            'last_result': None
        })
        
        print(f"\n✅ Updated to v{update_info['latest_version']}!")
        return True
    
    def _show_update_prompt(self, update_info: Dict[str, Any]):
        """Show interactive update prompt with changelog"""
        print()
        print("🔄 Lynis Reporter Update")
        print("━" * 60)
        print(f"Current:  v{update_info['current_version']}")
        print(f"Latest:   v{update_info['latest_version']}")
        print()
        
        # Show release notes (first 10 lines)
        notes = update_info.get('release_notes', '').strip()
        if notes:
            print("📝 What's new:")
            lines = notes.split('\n')[:10]
            for line in lines:
                if line.strip():
                    print(f"  {line}")
            if len(notes.split('\n')) > 10:
                print("  ...")
            print()
        
        print("⚠️  This will:")
        print("  ✓ Backup your database (./data/backup/)")
        print("  ✓ Preserve your config.yaml")
        print("  ✓ Update via git pull")
    
    def _check_repo_clean(self) -> bool:
        """Check if git repo has uncommitted changes"""
        result = subprocess.run(
            ['git', 'status', '--porcelain'],
            cwd=self.repo_path,
            capture_output=True,
            text=True
        )
        return result.returncode == 0 and not result.stdout.strip()
    
    def _backup_database(self) -> bool:
        """Backup the SQLite database before update"""
        try:
            db_path = self.repo_path / "data" / "lynis_reports.db"
            if not db_path.exists():
                return True  # No database to backup
            
            backup_dir = self.repo_path / "data" / "backup"
            backup_dir.mkdir(exist_ok=True)
            
            timestamp = datetime.now().strftime('%Y%m%d-%H%M%S')
            backup_path = backup_dir / f"lynis_reports-{timestamp}.db"
            
            import shutil
            shutil.copy2(db_path, backup_path)
            
            return True
        except Exception:
            return False


def check_updates_if_needed(show_notification: bool = True) -> Optional[Dict[str, Any]]:
    """
    Convenience function to check for updates
    
    Args:
        show_notification: Whether to print notification if update available
    
    Returns:
        Update info dict or None
    """
    try:
        manager = UpdateManager()
        update_info = manager.check_for_updates()
        
        if update_info and show_notification:
            manager.show_update_notification(update_info)
        
        return update_info
    except Exception:
        return None  # Fail silently
