"""
Caching functionality for scan results.
"""

import hashlib
import json
import sqlite3
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple


class ScanCache:
    """Cache for scan results to avoid re-scanning unchanged files."""

    def __init__(self, cache_dir: Optional[Path] = None, ttl_hours: int = 24):
        """
        Initialize scan cache.

        Args:
            cache_dir: Directory to store cache files (defaults to .git/.scanner-cache)
            ttl_hours: Time-to-live for cache entries in hours
        """
        if cache_dir:
            self.cache_dir = Path(cache_dir)
        else:
            # Try to find .git directory
            current = Path.cwd()
            while current != current.parent:
                git_dir = current / ".git"
                if git_dir.exists():
                    self.cache_dir = git_dir / ".scanner-cache"
                    break
                current = current.parent
            else:
                # Fallback to current directory
                self.cache_dir = Path.cwd() / ".scanner-cache"

        self.cache_dir.mkdir(exist_ok=True)
        self.db_path = self.cache_dir / "cache.db"
        self.ttl = timedelta(hours=ttl_hours)

        self._init_db()

    def _init_db(self) -> None:
        """Initialize cache database."""
        with sqlite3.connect(self.db_path) as conn:
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS file_cache (
                    file_path TEXT PRIMARY KEY,
                    file_hash TEXT NOT NULL,
                    scan_timestamp TIMESTAMP NOT NULL,
                    findings TEXT NOT NULL,
                    metadata TEXT
                )
            """
            )

            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS commit_cache (
                    commit_hash TEXT,
                    file_path TEXT,
                    findings TEXT NOT NULL,
                    scan_timestamp TIMESTAMP NOT NULL,
                    PRIMARY KEY (commit_hash, file_path)
                )
            """
            )

            conn.execute(
                """
                CREATE INDEX IF NOT EXISTS idx_scan_timestamp
                ON file_cache(scan_timestamp)
            """
            )

    def _calculate_file_hash(self, content: str) -> str:
        """Calculate hash of file content."""
        return hashlib.sha256(content.encode("utf-8")).hexdigest()

    def get_file_cache(
        self, file_path: str, content: str
    ) -> Optional[List[Dict[str, Any]]]:
        """
        Get cached findings for a file.

        Args:
            file_path: Path to the file
            content: Current file content

        Returns:
            Cached findings if valid, None otherwise
        """
        file_hash = self._calculate_file_hash(content)

        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.execute(
                """
                SELECT file_hash, scan_timestamp, findings
                FROM file_cache
                WHERE file_path = ?
                """,
                (file_path,),
            )
            row = cursor.fetchone()

            if not row:
                return None

            cached_hash, timestamp_str, findings_json = row

            # Check if file content has changed
            if cached_hash != file_hash:
                return None

            # Check if cache has expired
            scan_timestamp = datetime.fromisoformat(timestamp_str)
            if datetime.now() - scan_timestamp > self.ttl:
                return None

            return json.loads(findings_json)

    def set_file_cache(
        self,
        file_path: str,
        content: str,
        findings: List[Dict[str, Any]],
        metadata: Optional[Dict] = None,
    ) -> None:
        """
        Cache findings for a file.

        Args:
            file_path: Path to the file
            content: File content
            findings: List of findings
            metadata: Optional metadata to store
        """
        file_hash = self._calculate_file_hash(content)

        with sqlite3.connect(self.db_path) as conn:
            conn.execute(
                """
                INSERT OR REPLACE INTO file_cache
                (file_path, file_hash, scan_timestamp, findings, metadata)
                VALUES (?, ?, ?, ?, ?)
                """,
                (
                    file_path,
                    file_hash,
                    datetime.now().isoformat(),
                    json.dumps(findings),
                    json.dumps(metadata) if metadata else None,
                ),
            )

    def get_commit_cache(
        self, commit_hash: str, file_path: str
    ) -> Optional[List[Dict[str, Any]]]:
        """
        Get cached findings for a file in a specific commit.

        Args:
            commit_hash: Git commit hash
            file_path: Path to the file

        Returns:
            Cached findings if valid, None otherwise
        """
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.execute(
                """
                SELECT findings, scan_timestamp
                FROM commit_cache
                WHERE commit_hash = ? AND file_path = ?
                """,
                (commit_hash, file_path),
            )
            row = cursor.fetchone()

            if not row:
                return None

            findings_json, timestamp_str = row

            # Check if cache has expired
            scan_timestamp = datetime.fromisoformat(timestamp_str)
            if datetime.now() - scan_timestamp > self.ttl:
                return None

            return json.loads(findings_json)

    def set_commit_cache(
        self, commit_hash: str, file_path: str, findings: List[Dict[str, Any]]
    ) -> None:
        """
        Cache findings for a file in a specific commit.

        Args:
            commit_hash: Git commit hash
            file_path: Path to the file
            findings: List of findings
        """
        with sqlite3.connect(self.db_path) as conn:
            conn.execute(
                """
                INSERT OR REPLACE INTO commit_cache
                (commit_hash, file_path, findings, scan_timestamp)
                VALUES (?, ?, ?, ?)
                """,
                (
                    commit_hash,
                    file_path,
                    json.dumps(findings),
                    datetime.now().isoformat(),
                ),
            )

    def clear_expired(self) -> int:
        """
        Clear expired cache entries.

        Returns:
            Number of entries removed
        """
        cutoff = (datetime.now() - self.ttl).isoformat()

        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.execute(
                "DELETE FROM file_cache WHERE scan_timestamp < ?", (cutoff,)
            )
            file_count = cursor.rowcount

            cursor = conn.execute(
                "DELETE FROM commit_cache WHERE scan_timestamp < ?", (cutoff,)
            )
            commit_count = cursor.rowcount

        return file_count + commit_count

    def clear_all(self) -> None:
        """Clear all cache entries."""
        with sqlite3.connect(self.db_path) as conn:
            conn.execute("DELETE FROM file_cache")
            conn.execute("DELETE FROM commit_cache")

    def get_stats(self) -> Dict[str, Any]:
        """Get cache statistics."""
        with sqlite3.connect(self.db_path) as conn:
            # Count total entries
            file_count = conn.execute("SELECT COUNT(*) FROM file_cache").fetchone()[0]
            commit_count = conn.execute("SELECT COUNT(*) FROM commit_cache").fetchone()[
                0
            ]

            # Get cache size
            cache_size = self.db_path.stat().st_size if self.db_path.exists() else 0

            # Get oldest and newest entries
            oldest_file = conn.execute(
                "SELECT MIN(scan_timestamp) FROM file_cache"
            ).fetchone()[0]

            newest_file = conn.execute(
                "SELECT MAX(scan_timestamp) FROM file_cache"
            ).fetchone()[0]

        return {
            "file_entries": file_count,
            "commit_entries": commit_count,
            "total_entries": file_count + commit_count,
            "cache_size_bytes": cache_size,
            "cache_size_mb": round(cache_size / (1024 * 1024), 2),
            "oldest_entry": oldest_file,
            "newest_entry": newest_file,
            "ttl_hours": self.ttl.total_seconds() / 3600,
        }

    def export_cache(self, output_path: Path) -> None:
        """Export cache to a file for backup or analysis."""
        with sqlite3.connect(self.db_path) as conn:
            # Get all data
            file_cache = conn.execute("SELECT * FROM file_cache").fetchall()
            commit_cache = conn.execute("SELECT * FROM commit_cache").fetchall()

        export_data = {
            "export_timestamp": datetime.now().isoformat(),
            "stats": self.get_stats(),
            "file_cache": [
                {
                    "file_path": row[0],
                    "file_hash": row[1],
                    "scan_timestamp": row[2],
                    "findings": json.loads(row[3]),
                    "metadata": json.loads(row[4]) if row[4] else None,
                }
                for row in file_cache
            ],
            "commit_cache": [
                {
                    "commit_hash": row[0],
                    "file_path": row[1],
                    "findings": json.loads(row[2]),
                    "scan_timestamp": row[3],
                }
                for row in commit_cache
            ],
        }

        with open(output_path, "w", encoding="utf-8") as f:
            json.dump(export_data, f, indent=2)

    def import_cache(self, input_path: Path) -> Tuple[int, int]:
        """
        Import cache from a backup file.

        Returns:
            Tuple of (file_entries_imported, commit_entries_imported)
        """
        with open(input_path, "r", encoding="utf-8") as f:
            data = json.load(f)

        file_count = 0
        commit_count = 0

        with sqlite3.connect(self.db_path) as conn:
            # Import file cache
            for entry in data.get("file_cache", []):
                conn.execute(
                    """
                    INSERT OR REPLACE INTO file_cache
                    (file_path, file_hash, scan_timestamp, findings, metadata)
                    VALUES (?, ?, ?, ?, ?)
                    """,
                    (
                        entry["file_path"],
                        entry["file_hash"],
                        entry["scan_timestamp"],
                        json.dumps(entry["findings"]),
                        (
                            json.dumps(entry["metadata"])
                            if entry.get("metadata")
                            else None
                        ),
                    ),
                )
                file_count += 1

            # Import commit cache
            for entry in data.get("commit_cache", []):
                conn.execute(
                    """
                    INSERT OR REPLACE INTO commit_cache
                    (commit_hash, file_path, findings, scan_timestamp)
                    VALUES (?, ?, ?, ?)
                    """,
                    (
                        entry["commit_hash"],
                        entry["file_path"],
                        json.dumps(entry["findings"]),
                        entry["scan_timestamp"],
                    ),
                )
                commit_count += 1

        return file_count, commit_count
