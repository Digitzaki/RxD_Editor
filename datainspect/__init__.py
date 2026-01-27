"""
DataInspect Module
==================

This module provides data inspection functionality for the hex editor.

The DataInspector class interprets raw bytes at the cursor position into various
data types including integers, floats, characters, timestamps, GUIDs, and even
disassembly for x86 architectures.

Key Features:
-------------
- Multi-format integer display (signed/unsigned, 8/16/24/32/64-bit)
- Floating-point interpretation (float32, float64)
- Character encoding support (ANSI, UTF-8, UTF-16)
- Timestamp formats (Unix time_t, DOS date/time, Windows FILETIME, OLETIME)
- GUID parsing
- Variable-length encodings (LEB128, ULEB128)
- x86 disassembly (16-bit, 32-bit, 64-bit) via Capstone library
- Live editing: modify bytes by editing any interpreted value

Architecture:
-------------
The DataInspector class integrates with the main hex editor by:
1. Receiving cursor position updates
2. Reading bytes at that position from the file data
3. Displaying all possible interpretations in a scrollable widget
4. Allowing users to edit values, which updates the underlying bytes
5. Highlighting the relevant bytes when a field is focused

Classes:
--------
- DataInspector: Main class that manages data inspection UI and byte interpretation

License:
--------
Open Source
"""

from .data_inspector import DataInspector

__all__ = ['DataInspector']
