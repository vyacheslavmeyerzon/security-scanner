"""
Tests for caching functionality.
"""

import json
import time
from datetime import timedelta
from pathlib import Path

import pytest

from security_scanner.cache import ScanCache


class TestScanCache:
    """Test cases for ScanCache class."""

    @pytest.fixture
    def temp_cache_dir(self, tmp_path):
        """Create temporary cache directory."""
        cache_dir = tmp_path / "test_cache"
        cache_dir.mkdir()
        return cache_dir

    @pytest.fixture
    def cache(self, temp_cache_dir):
        """Create ScanCache instance."""
        return ScanCache(cache_dir=temp_cache_dir, ttl_hours=1)

    @pytest.fixture
    def sample_findings(self):
        """Create sample findings."""
        return [
            {
                "type": "AWS Access Key",
                "severity": "CRITICAL",
                "file": "config.py",
                "line": 10,
                "secret": "AKIA...",
            },
            {
                "type": "API Key",
                "severity": "HIGH",
                "file": "config.py",
                "line": 20,
                "secret": "key123",
            },
        ]

    def test_cache_initialization(self, temp_cache_dir):
        """Test cache initialization."""
        cache = ScanCache(cache_dir=temp_cache_dir, ttl_hours=2)

        assert cache.cache_dir == temp_cache_dir
        assert cache.ttl == timedelta(hours=2)
        assert cache.db_path.exists()

    def test_file_cache_set_get(self, cache, sample_findings):
        """Test setting and getting file cache."""
        file_path = "test.py"
        content = "secret = 'test123'"

        # Set cache
        cache.set_file_cache(file_path, content, sample_findings)

        # Get cache with same content
        cached = cache.get_file_cache(file_path, content)
        assert cached == sample_findings

        # Get cache with different content (should return None)
        cached = cache.get_file_cache(file_path, "different content")
        assert cached is None

    def test_file_cache_expiration(self, temp_cache_dir, sample_findings):
        """Test cache expiration."""
        # Create cache with very short TTL
        cache = ScanCache(cache_dir=temp_cache_dir, ttl_hours=0.0001)  # ~0.36 seconds

        file_path = "test.py"
        content = "secret = 'test123'"

        # Set cache
        cache.set_file_cache(file_path, content, sample_findings)

        # Should get cache immediately
        cached = cache.get_file_cache(file_path, content)
        assert cached == sample_findings

        # Wait for expiration
        time.sleep(0.5)

        # Should return None after expiration
        cached = cache.get_file_cache(file_path, content)
        assert cached is None

    def test_commit_cache_set_get(self, cache, sample_findings):
        """Test setting and getting commit cache."""
        commit_hash = "abc123def456"
        file_path = "test.py"

        # Set cache
        cache.set_commit_cache(commit_hash, file_path, sample_findings)

        # Get cache
        cached = cache.get_commit_cache(commit_hash, file_path)
        assert cached == sample_findings

        # Get non-existent cache
        cached = cache.get_commit_cache("different_hash", file_path)
        assert cached is None

    def test_clear_expired(self, temp_cache_dir, sample_findings):
        """Test clearing expired entries."""
        # Create cache with short TTL
        cache = ScanCache(cache_dir=temp_cache_dir, ttl_hours=0.0001)

        # Add entries
        cache.set_file_cache("file1.py", "content1", sample_findings)
        cache.set_file_cache("file2.py", "content2", sample_findings)
        cache.set_commit_cache("hash1", "file1.py", sample_findings)

        # Wait for expiration
        time.sleep(0.5)

        # Clear expired
        removed = cache.clear_expired()
        assert removed == 3

    def test_clear_all(self, cache, sample_findings):
        """Test clearing all cache entries."""
        # Add some entries
        cache.set_file_cache("file1.py", "content1", sample_findings)
        cache.set_file_cache("file2.py", "content2", sample_findings)
        cache.set_commit_cache("hash1", "file1.py", sample_findings)

        # Clear all
        cache.clear_all()

        # Verify all cleared
        assert cache.get_file_cache("file1.py", "content1") is None
        assert cache.get_commit_cache("hash1", "file1.py") is None

        stats = cache.get_stats()
        assert stats["total_entries"] == 0

    def test_get_stats(self, cache, sample_findings):
        """Test getting cache statistics."""
        # Add entries
        cache.set_file_cache("file1.py", "content1", sample_findings)
        cache.set_file_cache("file2.py", "content2", sample_findings)
        cache.set_commit_cache("hash1", "file1.py", sample_findings)
        cache.set_commit_cache("hash2", "file2.py", sample_findings)

        stats = cache.get_stats()

        assert stats["file_entries"] == 2
        assert stats["commit_entries"] == 2
        assert stats["total_entries"] == 4
        assert stats["cache_size_bytes"] > 0
        assert stats["ttl_hours"] == 1
        assert stats["oldest_entry"] is not None
        assert stats["newest_entry"] is not None

    def test_export_import_cache(self, cache, sample_findings, tmp_path):
        """Test exporting and importing cache."""
        # Add entries
        cache.set_file_cache("file1.py", "content1", sample_findings)
        cache.set_commit_cache("hash1", "file1.py", sample_findings)

        # Export
        export_path = tmp_path / "cache_export.json"
        cache.export_cache(export_path)

        assert export_path.exists()

        # Verify export content
        with open(export_path) as f:
            data = json.load(f)

        assert len(data["file_cache"]) == 1
        assert len(data["commit_cache"]) == 1
        assert data["file_cache"][0]["file_path"] == "file1.py"

        # Clear cache
        cache.clear_all()

        # Import
        file_count, commit_count = cache.import_cache(export_path)

        assert file_count == 1
        assert commit_count == 1

        # Verify imported data
        assert cache.get_file_cache("file1.py", "content1") == sample_findings

    def test_cache_with_metadata(self, cache):
        """Test caching with metadata."""
        file_path = "test.py"
        content = "test content"
        findings = [{"type": "test", "severity": "LOW"}]
        metadata = {"scanner_version": "1.0", "patterns_count": 25}

        # Set cache with metadata
        cache.set_file_cache(file_path, content, findings, metadata)

        # Export to verify metadata is stored
        export_path = cache.cache_dir / "test_export.json"
        cache.export_cache(export_path)

        with open(export_path) as f:
            data = json.load(f)

        assert data["file_cache"][0]["metadata"] == metadata

    def test_concurrent_access(self, cache, sample_findings):
        """Test concurrent cache access."""
        import threading

        results = []

        def write_cache(file_num):
            cache.set_file_cache(
                f"file{file_num}.py", f"content{file_num}", sample_findings
            )
            results.append(file_num)

        # Create multiple threads
        threads = []
        for i in range(10):
            t = threading.Thread(target=write_cache, args=(i,))
            threads.append(t)
            t.start()

        # Wait for all threads
        for t in threads:
            t.join()

        # Verify all writes succeeded
        assert len(results) == 10

        # Verify all entries exist
        for i in range(10):
            cached = cache.get_file_cache(f"file{i}.py", f"content{i}")
            assert cached == sample_findings

    def test_invalid_cache_dir(self):
        """Test handling of invalid cache directory."""
        # Try to create cache in a file (not directory)
        with pytest.raises(Exception):
            invalid_path = Path(__file__)  # This is a file, not a directory
            ScanCache(cache_dir=invalid_path)

    def test_cache_file_hash_calculation(self, cache):
        """Test file hash calculation."""
        content1 = "test content"
        content2 = "test content"  # Same content
        content3 = "different content"

        hash1 = cache._calculate_file_hash(content1)
        hash2 = cache._calculate_file_hash(content2)
        hash3 = cache._calculate_file_hash(content3)

        # Same content should have same hash
        assert hash1 == hash2

        # Different content should have different hash
        assert hash1 != hash3

        # Hash should be consistent
        assert len(hash1) == 64  # SHA256 hex digest

    def test_cache_with_unicode_content(self, cache):
        """Test caching with unicode content."""
        file_path = "unicode.py"
        content = "# -*- coding: utf-8 -*-\n# 中文注释\napi_key = 'test123'"
        findings = [{"type": "API Key", "severity": "HIGH", "content": "中文"}]

        # Set and get cache
        cache.set_file_cache(file_path, content, findings)
        cached = cache.get_file_cache(file_path, content)

        assert cached == findings
        assert cached[0]["content"] == "中文"
