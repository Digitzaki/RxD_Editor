"""
Structure Analysis Module
=========================

Provides lightweight structural analysis for binary files to help with navigation.
This is NOT a full file format decoder - it provides guidance on file structure.

Features:
- Endianness detection (Little/Big Endian)
- Common value analysis (frequent 2/3/4-byte sequences)
- Text detection (ASCII + UTF-16LE combined, heavily filtered)
- Block detection (pointer table sequences, renamed from "Pointer Tables")
"""

import re
import struct
import math
from collections import Counter
from dataclasses import dataclass
from PyQt5.QtCore import QThread, pyqtSignal, Qt
from PyQt5.QtWidgets import (QWidget, QVBoxLayout, QHBoxLayout, QLabel, QPushButton,
                              QProgressBar, QTreeWidget, QTreeWidgetItem, QLineEdit,
                              QMenu)
from PyQt5.QtGui import QFont, QColor


@dataclass
class PatternResult:
    """
    Represents a detected structural pattern.

    Attributes:
        offset: Byte offset where pattern starts
        length: Length of pattern in bytes
        category: Category (e.g., "Endian", "Common Values", "Text", "Blocks")
        description: Human-readable description
        label: User-assigned label
        highlight_color: Optional color for highlighting
    """
    offset: int
    length: int
    category: str
    description: str
    label: str = ""
    highlight_color: str = None


class PatternScanner(QThread):
    """
    Structure-aware analyzer that detects file organization patterns.

    Analyzes:
    - Endianness (Little vs Big Endian)
    - Common Values (frequent 2/3/4-byte sequences with interpretation)
    - Text (clean ASCII + UTF-16LE strings, heavily filtered)
    - Blocks (pointer table sequences)

    Signals:
        progress_updated (int): Progress percentage 0-100
        scan_complete (list): List of PatternResult objects
    """
    progress_updated = pyqtSignal(int)
    scan_complete = pyqtSignal(list)
    endian_detected = pyqtSignal(str)

    def __init__(self, file_data: bytearray, forced_endian=None):
        super().__init__()
        self.file_data = file_data
        self.results = []
        self.file_size = len(file_data)
        self.min_string_length = 4  # Minimum 4 characters for text
        self.forced_endian = forced_endian
        self.analysis_endian = "LE"

    def run(self):
        """Execute structural analysis"""
        self.results = []
        self.endian_summary = ""
        total_steps = 6
        current_step = 0

        # 1. File overview
        self.detect_file_overview()
        current_step += 1
        self.progress_updated.emit(int((current_step / total_steps) * 100))

        # 2. Detect endianness
        self.detect_endianness()
        if self.endian_summary:
            self.endian_detected.emit(self.endian_summary)
        current_step += 1
        self.progress_updated.emit(int((current_step / total_steps) * 100))

        # 3. Analyze common values
        self.analyze_common_values()
        current_step += 1
        self.progress_updated.emit(int((current_step / total_steps) * 100))

        # 4. Detect clean text
        self.detect_text()
        current_step += 1
        self.progress_updated.emit(int((current_step / total_steps) * 100))

        # 5. Detect numeric/vector-like float blocks
        self.detect_float_blocks()
        current_step += 1
        self.progress_updated.emit(int((current_step / total_steps) * 100))

        # 6. Detect blocks (pointer tables)
        self.detect_blocks()
        current_step += 1
        self.progress_updated.emit(100)

        self.scan_complete.emit(self.results)

    def detect_file_overview(self):
        """Add quick anchors for extensionless files: header bytes and padding runs."""
        if self.file_size == 0:
            return

        header_len = min(32, self.file_size)
        header = bytes(self.file_data[:header_len])
        header_hex = " ".join(f"{b:02X}" for b in header[:16])
        printable = ''.join(chr(b) if 32 <= b <= 126 else '.' for b in header[:16])

        self.results.append(PatternResult(
            offset=0,
            length=header_len,
            category="File Overview",
            description=f"Header: {header_hex} | ASCII: {printable}"
        ))

        # Long aligned padding runs often separate sections in game containers.
        run_start = None
        run_value = None
        for i, byte in enumerate(self.file_data):
            if byte in (0x00, 0xFF):
                if run_start is None or byte != run_value:
                    if run_start is not None and i - run_start >= 32:
                        self._add_padding_run(run_start, i - run_start, run_value)
                    run_start = i
                    run_value = byte
            else:
                if run_start is not None and i - run_start >= 32:
                    self._add_padding_run(run_start, i - run_start, run_value)
                run_start = None
                run_value = None

        if run_start is not None and self.file_size - run_start >= 32:
            self._add_padding_run(run_start, self.file_size - run_start, run_value)

    def _add_padding_run(self, offset, length, value):
        self.results.append(PatternResult(
            offset=offset,
            length=min(length, 64),
            category="Padding / Sections",
            description=f"0x{value:02X} padding run ({length} bytes)"
        ))

    def detect_endianness(self):
        """
        Detect likely endianness using heuristics.

        Uses multiple signals:
        - Pointer alignment (do values point within file?)
        - Float plausibility (do values make sense as floats?)
        - Integer sanity (are integer values reasonable?)
        """
        if self.file_size < 100:
            return

        le_score = 0
        be_score = 0
        tests = 0

        # Sample first 10KB for analysis
        sample_size = min(10000, self.file_size - 4)
        step = max(4, sample_size // 1000)

        for offset in range(0, sample_size, step):
            if offset + 4 > self.file_size:
                break

            value_bytes = self.file_data[offset:offset+4]

            # Test as 32-bit pointer
            le_val = struct.unpack('<I', value_bytes)[0]
            be_val = struct.unpack('>I', value_bytes)[0]

            # Heuristic 1: Valid pointer (points within file)
            if 0 < le_val < self.file_size:
                le_score += 2
            if 0 < be_val < self.file_size:
                be_score += 2

            # Heuristic 2: Float plausibility
            try:
                le_float = struct.unpack('<f', value_bytes)[0]
                be_float = struct.unpack('>f', value_bytes)[0]

                if not math.isnan(le_float) and not math.isinf(le_float):
                    if -1000.0 <= le_float <= 1000.0:
                        le_score += 1

                if not math.isnan(be_float) and not math.isinf(be_float):
                    if -1000.0 <= be_float <= 1000.0:
                        be_score += 1
            except:
                pass

            # Heuristic 3: Integer sanity
            le_int = struct.unpack('<i', value_bytes)[0]
            be_int = struct.unpack('>i', value_bytes)[0]

            if -1000000 <= le_int <= 1000000:
                le_score += 0.5
            if -1000000 <= be_int <= 1000000:
                be_score += 0.5

            tests += 1

        if tests == 0:
            return

        # Determine endianness
        total_score = le_score + be_score
        if total_score > 0:
            le_confidence = le_score / total_score
            be_confidence = be_score / total_score

            if le_confidence > be_confidence:
                detected = "LE"
                confidence = le_confidence
            else:
                detected = "BE"
                confidence = be_confidence

            self.analysis_endian = self.forced_endian or detected
            label = "Little" if self.analysis_endian == "LE" else "Big"
            if self.forced_endian:
                self.endian_summary = f"{label} endian (manual)"
            else:
                self.endian_summary = f"{label} endian ({confidence*100:.0f}%)"

    def analyze_common_values(self):
        """
        Find frequently occurring aligned 2/3/4-byte raw byte patterns.

        These are aggregate patterns, but each result stores the first real
        offset plus the raw bytes so clicking can open a normal search result.
        """
        if self.file_size < 4:
            return

        for size in (2, 3, 4):
            counter = Counter()
            first_offsets = {}

            # Aligned patterns are usually more meaningful for game structures
            # than every sliding byte window.
            for offset in range(0, self.file_size - size + 1, size):
                pattern = bytes(self.file_data[offset:offset + size])
                if pattern == b'\x00' * size or pattern == b'\xFF' * size:
                    continue
                counter[pattern] += 1
                first_offsets.setdefault(pattern, offset)

            for pattern, count in counter.most_common(20):
                if count < 3:
                    continue

                offset = first_offsets[pattern]
                hex_str = " ".join(f"{b:02X}" for b in pattern)
                description = f"{hex_str}"

                if size == 4:
                    le_uint = struct.unpack('<I', pattern)[0]
                    be_uint = struct.unpack('>I', pattern)[0]
                    if self.analysis_endian == "BE":
                        primary_uint = be_uint
                        secondary_uint = le_uint
                        primary_label = "BE"
                        secondary_label = "LE"
                    else:
                        primary_uint = le_uint
                        secondary_uint = be_uint
                        primary_label = "LE"
                        secondary_label = "BE"
                    description += f" | {primary_label} uint {primary_uint} | {secondary_label} uint {secondary_uint}"
                    try:
                        le_float = struct.unpack('<f', pattern)[0]
                        be_float = struct.unpack('>f', pattern)[0]
                        float_notes = []
                        ordered_floats = (
                            ((primary_label, be_float), (secondary_label, le_float))
                            if self.analysis_endian == "BE"
                            else ((primary_label, le_float), (secondary_label, be_float))
                        )
                        for float_label, value in ordered_floats:
                            if not math.isnan(value) and not math.isinf(value) and abs(value) <= 100000.0:
                                float_notes.append(f"{float_label} float {value:.3g}")
                        if float_notes:
                            description += " | " + " | ".join(float_notes)
                    except struct.error:
                        pass

                description += f" | appears {count} times"
                result = PatternResult(
                    offset=offset,
                    length=size,
                    category=f"Common Values ({size}B)",
                    description=description
                )
                result.search_pattern = pattern
                result.match_count = count
                self.results.append(result)

    def detect_text(self):
        """
        Detect clean, human-readable text (ASCII + UTF-16LE).

        Strict filtering rules:
        - Must resemble real words, identifiers, or key/value pairs
        - Allowed: alphanumeric + limited symbols (._-:=?)
        - Excluded: garbled sequences, high-entropy junk, meaningless fragments
        - Minimum 4 characters
        - Splits intelligently at delimiters
        """
        # Detect ASCII strings
        # Pattern: allow letters, numbers, space, and limited symbols including ?
        ascii_pattern = rb'[A-Za-z0-9 ._\-:=?]{4,}'

        for match in re.finditer(ascii_pattern, bytes(self.file_data)):
            text = match.group().decode('ascii', errors='ignore')

            # Filter: must contain at least one letter
            if not re.search(r'[A-Za-z]', text):
                continue

            # Filter: skip if too much garbage
            if self._is_garbage_text(text):
                continue

            # Skip very short fragments
            if len(text.strip()) < self.min_string_length:
                continue

            # Split text at assignment operators to create separate entries
            self._split_and_add_text_entries(match.start(), text, "Text")

        # Detect UTF-16LE strings
        offset = 0
        while offset < self.file_size - 8:
            char_count = 0
            temp_offset = offset
            chars = []

            while temp_offset < self.file_size - 1:
                low = self.file_data[temp_offset]
                high = self.file_data[temp_offset + 1]

                # Check for valid UTF-16LE character
                if high == 0 and (
                    (0x41 <= low <= 0x5A) or  # A-Z
                    (0x61 <= low <= 0x7A) or  # a-z
                    (0x30 <= low <= 0x39) or  # 0-9
                    low in [0x20, 0x2E, 0x5F, 0x2D, 0x3A, 0x3D, 0x3F]  # space . _ - : = ?
                ):
                    chars.append(chr(low))
                    char_count += 1
                    temp_offset += 2
                else:
                    break

            if char_count >= self.min_string_length:
                text = ''.join(chars)

                # Apply same filtering as ASCII
                if not re.search(r'[A-Za-z]', text):
                    offset += 2
                    continue

                if self._is_garbage_text(text):
                    offset += 2
                    continue

                # Split text at assignment operators to create separate entries
                self._split_and_add_text_entries(offset, text, "Text", utf16=True)
                offset = temp_offset
            else:
                offset += 2

    def _split_and_add_text_entries(self, start_offset: int, text: str, category: str, utf16: bool = False):
        """
        Split text intelligently at delimiters and add separate entries.

        Examples:
        - "AAABAC.AD?" → "AAABAC.AD?"
        - "enum.FxPriority?=" → "enum.FxPriority?="
        - "DT=KA?=" → "DT=", "KA?="
        - "cat=1.0.dog=2.0" → "cat=", "dog="
        """
        byte_multiplier = 2 if utf16 else 1
        current_offset = start_offset

        # Split by pattern: captures key=value or key: patterns
        # Look for patterns like XX= or XX: (2 uppercase/lowercase letters followed by = or :)
        parts = re.split(r'(?<=[A-Z]{2}[=:])|(?<=[a-z]{2}[=:])', text)

        for part in parts:
            if not part or not part.strip():
                continue

            # Check if part contains letters
            if not re.search(r'[A-Za-z]', part):
                current_offset += len(part) * byte_multiplier
                continue

            # Keep key=value pairs even if short (e.g., "DT=", "KA?=")
            # Also keep longer text strings
            is_key = re.match(r'^[A-Za-z]{2,}[=:]', part)
            if not is_key and len(part.strip()) < self.min_string_length:
                current_offset += len(part) * byte_multiplier
                continue

            # Add the entry
            length = len(part) * byte_multiplier
            description = f'"{part}"'
            if utf16:
                description += " (UTF-16LE)"

            self.results.append(PatternResult(
                offset=current_offset,
                length=length,
                category=category,
                description=description
            ))

            current_offset += length

    def _is_garbage_text(self, text: str) -> bool:
        """
        Check if text is likely garbage/random data.

        Returns True if text should be filtered out.
        """
        text = text.strip()

        if len(text) < 3:
            return True

        # Calculate character diversity
        unique_chars = len(set(text))
        if unique_chars < 3:  # Too repetitive
            return True

        # Check for high entropy (random-looking)
        alpha_count = sum(1 for c in text if c.isalpha())
        if len(text) > 0 and alpha_count / len(text) < 0.3:  # Less than 30% letters
            return True

        # Check for common garbage patterns
        garbage_patterns = [
            r'^[0-9\s]+$',  # Only numbers and spaces
            r'^[\W_]+$',    # Only symbols
        ]

        for pattern in garbage_patterns:
            if re.match(pattern, text):
                return True

        return False

    def detect_blocks(self):
        """
        Detect pointer table sequences (now called "Blocks").

        Performance optimization:
        - Only highlights the FIRST pointer value in each block
        - Does NOT highlight full sequences to avoid performance issues
        """
        pointer_clusters = []

        # Scan for valid pointers in the current analysis endian. The label can be
        # toggled when the confidence guess is wrong.
        for offset in range(0, self.file_size - 8, 4):
            try:
                fmt = '>I' if self.analysis_endian == "BE" else '<I'
                ptr32 = struct.unpack(fmt, self.file_data[offset:offset+4])[0]
                if 0 < ptr32 < self.file_size:
                    pointer_clusters.append((offset, 4, ptr32, self.analysis_endian))
            except:
                continue

        # Cluster nearby pointers
        clusters = self._cluster_pointers(pointer_clusters)

        for cluster in clusters:
            if len(cluster) >= 3:
                # Only highlight the FIRST pointer for performance
                first_ptr = cluster[0]
                first_offset = first_ptr[0]
                pointer_value = first_ptr[2]
                endian = first_ptr[3] if len(first_ptr) > 3 else "LE"

                self.results.append(PatternResult(
                    offset=first_offset,
                    length=4,  # Only highlight first pointer
                    category="Blocks",
                    description=f"Block start: {len(cluster)} pointers (first → 0x{pointer_value:X})"
                ))

    def detect_float_blocks(self):
        """Detect aligned runs of plausible float32 values, useful for matrices/vectors/params."""
        if self.file_size < 24:
            return

        endian = self.analysis_endian
        fmt = ">f" if endian == "BE" else "<f"
        for _ in (0,):
            run_start = None
            run_count = 0
            nonzero_count = 0

            for offset in range(0, self.file_size - 3, 4):
                try:
                    value = struct.unpack(fmt, self.file_data[offset:offset+4])[0]
                except struct.error:
                    value = None

                plausible = (
                    value is not None and
                    not math.isnan(value) and
                    not math.isinf(value) and
                    -100000.0 <= value <= 100000.0
                )

                if plausible:
                    if run_start is None:
                        run_start = offset
                        run_count = 0
                        nonzero_count = 0
                    run_count += 1
                    if abs(value) > 0.000001:
                        nonzero_count += 1
                else:
                    if run_count >= 6 and nonzero_count >= 3:
                        self._add_float_block(run_start, run_count, endian)
                    run_start = None
                    run_count = 0
                    nonzero_count = 0

            if run_count >= 6 and nonzero_count >= 3:
                self._add_float_block(run_start, run_count, endian)

    def _add_float_block(self, offset, count, endian):
        self.results.append(PatternResult(
            offset=offset,
            length=min(count * 4, 64),
            category="Float Blocks",
            description=f"{endian} float32 run ({count} values)"
        ))

    def _cluster_pointers(self, pointers, max_gap: int = 16):
        """Group nearby pointers into clusters."""
        if not pointers:
            return []

        sorted_pointers = sorted(pointers, key=lambda x: x[0])
        clusters = [[sorted_pointers[0]]]

        for ptr in sorted_pointers[1:]:
            if ptr[0] - clusters[-1][-1][0] <= max_gap:
                clusters[-1].append(ptr)
            else:
                clusters.append([ptr])

        return [c for c in clusters if len(c) >= 3]


class PatternScanWidget(QWidget):
    """
    UI widget for structural analysis.

    Displays analysis results in a tree view organized by category:
    - Endian
    - Common Values (2B/3B/4B)
    - Text
    - Blocks

    Signals:
        result_clicked (int, int): Emitted with (offset, length) when item clicked
    """
    result_clicked = pyqtSignal(int, int)

    def __init__(self, parent=None):
        super().__init__(parent)
        self.scanner = None
        self.analysis_endian_override = None
        self.setup_ui()

    def setup_ui(self):
        """Initialize UI components"""
        layout = QVBoxLayout()
        layout.setContentsMargins(5, 5, 5, 5)

        # Header
        header_layout = QHBoxLayout()
        title = QLabel("Analyze")
        title.setFont(QFont("Arial", 11, QFont.Bold))
        header_layout.addWidget(title)

        self.scan_button = QPushButton("Analyze")
        self.scan_button.setFont(QFont("Arial", 10))
        self.scan_button.setToolTip(
            "Analyzes file structure to provide guidance.\n"
            "This is not a full file format decoder."
        )
        self.scan_button.clicked.connect(self.start_scan)
        header_layout.addWidget(self.scan_button)

        self.endian_label = QLabel("")
        self.endian_label.setFont(QFont("Arial", 9))
        self.endian_label.setStyleSheet("color: #e5c07b;")
        self.endian_label.setCursor(Qt.PointingHandCursor)
        self.endian_label.setToolTip("Click to switch analysis between Big and Little endian, then re-run.")
        self.endian_label.mousePressEvent = self.toggle_analysis_endian
        header_layout.addWidget(self.endian_label)
        header_layout.addStretch()
        layout.addLayout(header_layout)

        # Progress bar
        self.progress_bar = QProgressBar()
        self.progress_bar.setVisible(False)
        layout.addWidget(self.progress_bar)

        # Results tree
        self.tree = QTreeWidget()
        self.tree.setHeaderLabels(["Label", "Offset", "Length", "Description"])
        self.tree.setIndentation(15)
        self.tree.setColumnWidth(0, 150)
        self.tree.setColumnWidth(1, 80)
        self.tree.setColumnWidth(2, 60)
        self.tree.setColumnWidth(3, 300)
        self.tree.itemClicked.connect(self.on_item_clicked)
        self.tree.setContextMenuPolicy(Qt.CustomContextMenu)
        self.tree.customContextMenuRequested.connect(self.on_tree_context_menu)
        layout.addWidget(self.tree)

        # Label editors dictionary
        self.label_editors = {}

        # Status label
        self.status_label = QLabel("Ready to analyze")
        self.status_label.setFont(QFont("Arial", 9))
        layout.addWidget(self.status_label)

        self.setLayout(layout)

    def start_scan(self):
        """Start structural analysis"""
        if hasattr(self, 'file_data') and self.file_data:
            self.scan_button.setEnabled(False)
            self.progress_bar.setVisible(True)
            self.progress_bar.setRange(0, 100)
            self.progress_bar.setValue(0)
            self.tree.clear()
            self.endian_label.setText("")
            self.status_label.setText("Analyzing...")

            self.scanner = PatternScanner(self.file_data, self.analysis_endian_override)
            self.scanner.progress_updated.connect(self.on_scan_progress)
            self.scanner.endian_detected.connect(self.endian_label.setText)
            self.scanner.scan_complete.connect(self.on_scan_complete)
            self.scanner.start()

    def toggle_analysis_endian(self, event):
        """Let users override the confidence-based endian guess and re-run."""
        current_text = self.endian_label.text().lower()
        if self.analysis_endian_override == "BE":
            self.analysis_endian_override = "LE"
        elif self.analysis_endian_override == "LE":
            self.analysis_endian_override = "BE"
        elif "big" in current_text:
            self.analysis_endian_override = "LE"
        else:
            self.analysis_endian_override = "BE"

        label = "Big" if self.analysis_endian_override == "BE" else "Little"
        self.endian_label.setText(f"{label} endian (manual)")
        self.status_label.setText(f"Analysis endian set to {label}; re-analyzing...")
        if hasattr(self, 'file_data') and self.file_data and self.scan_button.isEnabled():
            self.start_scan()

    def on_scan_progress(self, value):
        """Update progress bar"""
        try:
            self.progress_bar.setValue(value)
        except RuntimeError:
            pass

    def on_scan_complete(self, results):
        """Display analysis results"""
        try:
            self.progress_bar.setVisible(False)
            self.scan_button.setEnabled(True)
            self.tree.clear()

            # Group by category
            categories = {}
            for result in results:
                if result.category not in categories:
                    categories[result.category] = []
                categories[result.category].append(result)

            # Display in specific order
            category_order = [
                "File Overview",
                "Common Values (2B)",
                "Common Values (3B)",
                "Common Values (4B)",
                "Text",
                "Padding / Sections",
                "Float Blocks",
                "Blocks"
            ]

            for category in category_order:
                if category in categories:
                    self._add_category(category, categories[category])

            # Add any other categories not in the order
            for category, results_list in categories.items():
                if category not in category_order:
                    self._add_category(category, results_list)

            total_results = len(results)
            self.status_label.setText(f"Analysis complete: {total_results} items found")
            self.tree.expandAll()

            # Load saved labels if parent editor exists
            if hasattr(self, 'parent_editor') and self.parent_editor:
                self.parent_editor.load_pattern_labels_to_widget()
        except RuntimeError:
            pass

    def populate_tree(self, results):
        """Populate tree with saved results (for file switching)"""
        try:
            self.tree.clear()
            self.label_editors.clear()

            categories = {}
            for result in results:
                if result.category not in categories:
                    categories[result.category] = []
                categories[result.category].append(result)

            category_order = [
                "File Overview",
                "Common Values (2B)",
                "Common Values (3B)",
                "Common Values (4B)",
                "Text",
                "Padding / Sections",
                "Float Blocks",
                "Blocks"
            ]

            for category in category_order:
                if category in categories:
                    self._add_category(category, categories[category])

            for category, results_list in categories.items():
                if category not in category_order:
                    self._add_category(category, results_list)

            total_results = len(results)
            self.status_label.setText(f"Loaded {total_results} items")
            self.tree.expandAll()
        except RuntimeError:
            pass

    def _add_category(self, category_name, results):
        """Add category and its results to tree"""
        category_item = QTreeWidgetItem(self.tree)
        category_item.setText(0, category_name)
        category_item.setFont(0, QFont("Arial", 9, QFont.Bold))
        category_item.setText(3, f"({len(results)} items)")

        for result in results:
            item = QTreeWidgetItem(category_item)

            # Label editor with color box
            label_container = QWidget()
            label_layout = QHBoxLayout()
            label_layout.setContentsMargins(0, 0, 2, 0)
            label_layout.setSpacing(4)

            color_box = QPushButton()
            color_box.setFixedSize(16, 16)
            if hasattr(result, 'highlight_color') and result.highlight_color:
                color_box.setStyleSheet(
                    f"background-color: {result.highlight_color}; border: 1px solid #555;"
                )
            else:
                color_box.setStyleSheet("background-color: transparent; border: 1px solid #555;")

            color_box.clicked.connect(
                lambda checked, r=result, cb=color_box, it=item:
                self.open_highlight_for_pattern(r, cb, it)
            )
            label_layout.addWidget(color_box)

            label_edit = QLineEdit()
            label_edit.setText(result.label)
            label_edit.setPlaceholderText("Enter label...")
            label_edit.setFrame(False)
            label_edit.setFont(QFont("Arial", 8))
            label_edit.setStyleSheet("QLineEdit { background: transparent; }")
            label_edit.returnPressed.connect(
                lambda r=result, le=label_edit: self.on_label_changed(r, le)
            )
            label_edit.editingFinished.connect(
                lambda r=result, le=label_edit: self.on_label_changed(r, le)
            )
            label_layout.addWidget(label_edit, 1)

            label_container.setLayout(label_layout)

            # Set item data
            item.setText(1, f"0x{result.offset:X}" if result.offset >= 0 else "-")
            item.setText(2, str(result.length) if result.length > 0 else "—")
            item.setText(3, result.description)

            if hasattr(result, 'highlight_color') and result.highlight_color:
                item.setBackground(3, QColor(result.highlight_color))

            item.setData(0, Qt.UserRole, result)

            self.tree.setItemWidget(item, 0, label_container)
            self.label_editors[result.offset] = label_edit

    def on_label_changed(self, result, line_edit):
        """Update label when edited"""
        new_label = line_edit.text().strip()
        result.label = new_label

    def on_item_clicked(self, item, column):
        """Handle item click - navigate to offset"""
        result = item.data(0, Qt.UserRole)
        if isinstance(result, PatternResult) and hasattr(result, "search_pattern"):
            self.open_search_results_for_pattern(result)
        elif isinstance(result, PatternResult) and result.offset >= 0:
            self.result_clicked.emit(result.offset, result.length)

    def open_search_results_for_pattern(self, result):
        """Open the main editor Search Results overlay for an aggregate pattern."""
        if not hasattr(self, 'parent_editor') or not self.parent_editor:
            return
        if self.parent_editor.current_tab_index < 0:
            return

        pattern = getattr(result, "search_pattern", None)
        if not pattern:
            return

        editor = self.parent_editor
        current_file = editor.open_files[editor.current_tab_index]
        data = bytes(current_file.file_data)

        matches = []
        offset = 0
        while offset < len(data):
            pos = data.find(pattern, offset)
            if pos == -1:
                break
            matches.append(pos)
            offset = pos + max(1, len(pattern))

        current_file.search_results = [(pos, len(pattern)) for pos in matches]
        editor.create_results_overlay()
        editor.set_search_results_title(" ".join(f"{b:02X}" for b in pattern))

        for i in reversed(range(editor.search_results_layout.count())):
            widget = editor.search_results_layout.itemAt(i).widget()
            if widget:
                widget.setParent(None)

        for pos in matches[:100]:
            editor.show_search_result(pos, pattern, data, clickable=True)
        if len(matches) > 100:
            editor.add_search_result_label(f"Showing first 100 of {len(matches):,} results")
        if not matches:
            editor.add_search_result_label("No matches found")

        if matches:
            editor.cursor_position = matches[0]
            editor.cursor_nibble = 0

        editor.display_hex(preserve_scroll=True)
        if matches:
            editor.scroll_to_offset(matches[0], center=True)
        editor.results_overlay.show()
        editor.results_overlay.raise_()

    def on_tree_context_menu(self, position):
        """Show context menu for tree items"""
        item = self.tree.itemAt(position)
        if item:
            result = item.data(0, Qt.UserRole)
            if isinstance(result, PatternResult):
                menu = QMenu()
                search_action = None
                if hasattr(result, "search_pattern"):
                    search_action = menu.addAction("Open Search Results")
                highlight_action = menu.addAction("Open Highlight Dialog")
                action = menu.exec_(self.tree.viewport().mapToGlobal(position))

                if search_action is not None and action == search_action:
                    self.open_search_results_for_pattern(result)
                elif action == highlight_action:
                    widget = self.tree.itemWidget(item, 0)
                    if widget:
                        color_box = widget.findChild(QPushButton)
                        if color_box:
                            self.open_highlight_for_pattern(result, color_box, item)

    def open_highlight_for_pattern(self, result, color_box, tree_item):
        """Open highlight dialog with pattern bytes pre-selected"""
        if hasattr(self, 'parent_editor') and self.parent_editor:
            if self.parent_editor.current_tab_index < 0:
                return

            self.parent_editor.selection_start = result.offset
            self.parent_editor.selection_end = result.offset + result.length - 1
            self.parent_editor.cursor_position = result.offset

            self.parent_editor.pattern_result_to_update = (result, color_box, tree_item)

            self.parent_editor.show_highlight_window()

    def set_file_data(self, file_data: bytearray):
        """Set file data for analysis"""
        self.file_data = file_data
        self.tree.clear()
        self.status_label.setText("Ready to analyze")
        self.scan_button.setEnabled(True)
