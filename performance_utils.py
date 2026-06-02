"""
Performance utilities for hex editor optimization.

This module provides caching, pooling, and optimization utilities to improve
performance across the hex editor application while maintaining functional equivalence.
"""

from functools import lru_cache, wraps
from collections import OrderedDict
import struct
from typing import Any, Callable, Optional, Tuple


class LRUCache:
    """Thread-safe LRU cache with size limit."""

    def __init__(self, maxsize=128):
        self.cache = OrderedDict()
        self.maxsize = maxsize

    def get(self, key, default=None):
        """Get item from cache, moving it to end (most recently used)."""
        if key in self.cache:
            self.cache.move_to_end(key)
            return self.cache[key]
        return default

    def put(self, key, value):
        """Add item to cache, removing oldest if at capacity."""
        if key in self.cache:
            self.cache.move_to_end(key)
        self.cache[key] = value
        if len(self.cache) > self.maxsize:
            self.cache.popitem(last=False)

    def clear(self):
        """Clear all cached items."""
        self.cache.clear()

    def invalidate(self, key):
        """Remove specific key from cache."""
        self.cache.pop(key, None)


class ByteInterpretationCache:
    """Cache for byte interpretations to avoid recomputation."""

    def __init__(self, maxsize=256):
        self.cache = LRUCache(maxsize)

    def get_interpretation(self, data: bytes, offset: int, data_type: str,
                          endianness: str) -> Optional[Any]:
        """Get cached interpretation or return None."""
        key = (bytes(data), offset, data_type, endianness)
        return self.cache.get(key)

    def cache_interpretation(self, data: bytes, offset: int, data_type: str,
                            endianness: str, value: Any):
        """Cache an interpretation result."""
        key = (bytes(data), offset, data_type, endianness)
        self.cache.put(key, value)

    def clear(self):
        """Clear all cached interpretations."""
        self.cache.clear()


# Global interpretation cache instance
_interpretation_cache = ByteInterpretationCache()


def get_interpretation_cache():
    """Get the global interpretation cache instance."""
    return _interpretation_cache


@lru_cache(maxsize=1024)
def format_hex_byte(byte_val: int) -> str:
    """Cached hex byte formatting."""
    return f"{byte_val:02X}"


@lru_cache(maxsize=256)
def format_hex_offset(offset: int, mode: str = 'h') -> str:
    """Cached offset formatting."""
    if mode == 'h':
        return f"{offset:08X}"
    elif mode == 'd':
        return f"{offset:010d}"
    else:  # octal
        return f"o{offset:08o}"


def bytes_to_hex_string(data: bytes) -> str:
    """Optimized bytes to hex string conversion using built-in hex()."""
    return data.hex().upper()


def hex_string_to_bytes(hex_str: str) -> bytes:
    """Optimized hex string to bytes conversion."""
    # Remove spaces and validate
    hex_str = hex_str.replace(" ", "").replace("\n", "")
    return bytes.fromhex(hex_str)


# Struct format cache to avoid recreating struct.Struct objects
_struct_cache = {}


def get_cached_struct(fmt: str) -> struct.Struct:
    """Get or create cached struct.Struct object."""
    if fmt not in _struct_cache:
        _struct_cache[fmt] = struct.Struct(fmt)
    return _struct_cache[fmt]


def unpack_with_cache(fmt: str, data: bytes) -> Tuple:
    """Unpack data using cached struct object."""
    return get_cached_struct(fmt).unpack(data)


def pack_with_cache(fmt: str, *values) -> bytes:
    """Pack values using cached struct object."""
    return get_cached_struct(fmt).pack(*values)


class WidgetPool:
    """Pool for reusing Qt widgets to avoid creation/destruction overhead."""

    def __init__(self, widget_factory: Callable, initial_size: int = 10):
        """
        Initialize widget pool.

        Args:
            widget_factory: Callable that creates new widget instances
            initial_size: Number of widgets to pre-create
        """
        self.widget_factory = widget_factory
        self.available = []
        self.in_use = set()

        # Pre-create initial widgets
        for _ in range(initial_size):
            self.available.append(widget_factory())

    def acquire(self):
        """Get a widget from the pool."""
        if self.available:
            widget = self.available.pop()
        else:
            widget = self.widget_factory()

        self.in_use.add(widget)
        return widget

    def release(self, widget):
        """Return a widget to the pool."""
        if widget in self.in_use:
            self.in_use.remove(widget)
            widget.hide()  # Hide but don't destroy
            self.available.append(widget)

    def release_all(self):
        """Return all in-use widgets to the pool."""
        for widget in list(self.in_use):
            self.release(widget)

    def clear(self):
        """Clear the pool, destroying all widgets."""
        for widget in self.available:
            widget.deleteLater()
        for widget in self.in_use:
            widget.deleteLater()
        self.available.clear()
        self.in_use.clear()


def debounce(wait_ms: int):
    """
    Decorator to debounce function calls (call only after wait_ms of inactivity).
    Useful for expensive operations triggered by rapid events (mouse move, etc).
    """
    def decorator(func):
        timer = None

        @wraps(func)
        def debounced(*args, **kwargs):
            nonlocal timer

            def call_func():
                nonlocal timer
                timer = None
                func(*args, **kwargs)

            # Cancel existing timer
            if timer is not None:
                timer.stop()

            # Create new timer
            from PyQt5.QtCore import QTimer
            timer = QTimer()
            timer.setSingleShot(True)
            timer.timeout.connect(call_func)
            timer.start(wait_ms)

        return debounced
    return decorator


def throttle(wait_ms: int):
    """
    Decorator to throttle function calls (allow only one call per wait_ms).
    Useful for limiting expensive operations during continuous events.
    """
    def decorator(func):
        last_call = [0]  # Use list to allow modification in closure

        @wraps(func)
        def throttled(*args, **kwargs):
            from PyQt5.QtCore import QDateTime
            current_time = QDateTime.currentMSecsSinceEpoch()

            if current_time - last_call[0] >= wait_ms:
                last_call[0] = current_time
                return func(*args, **kwargs)

        return throttled
    return decorator


class RangeSet:
    """
    Efficient storage for large sets of consecutive integers (byte offsets).
    Stores ranges instead of individual values to save memory.
    """

    def __init__(self):
        self.ranges = []  # List of (start, end) tuples (inclusive)

    def add(self, value: int):
        """Add a single value to the set."""
        self.add_range(value, value)

    def add_range(self, start: int, end: int):
        """Add a range of values (inclusive)."""
        # Find insertion point and merge with adjacent ranges
        new_ranges = []
        merged = False

        for r_start, r_end in self.ranges:
            if end < r_start - 1:
                # New range comes before this one
                if not merged:
                    new_ranges.append((start, end))
                    merged = True
                new_ranges.append((r_start, r_end))
            elif start > r_end + 1:
                # New range comes after this one
                new_ranges.append((r_start, r_end))
            else:
                # Ranges overlap or are adjacent, merge them
                start = min(start, r_start)
                end = max(end, r_end)

        if not merged:
            new_ranges.append((start, end))

        self.ranges = new_ranges

    def __contains__(self, value: int) -> bool:
        """Check if value is in the set."""
        for start, end in self.ranges:
            if start <= value <= end:
                return True
            if value < start:
                return False
        return False

    def __len__(self) -> int:
        """Get total count of values in the set."""
        return sum(end - start + 1 for start, end in self.ranges)

    def clear(self):
        """Remove all values."""
        self.ranges.clear()


# Pre-compiled regex patterns for common operations
_REGEX_CACHE = {}


def get_compiled_regex(pattern: str, flags=0):
    """Get or compile regex pattern with caching."""
    import re
    key = (pattern, flags)
    if key not in _REGEX_CACHE:
        _REGEX_CACHE[key] = re.compile(pattern, flags)
    return _REGEX_CACHE[key]
