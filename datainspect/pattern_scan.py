"""
Pattern Scanning Module
=======================

This module provides pattern scanning functionality for detecting various structures
in binary files.

Features:
- ASCII and UTF-16LE string detection
- Pointer table identification
- Compression signature detection (zlib, gzip, LZ4, Zstandard)
- Image format signature detection (PNG, JPEG, GIF, BMP, etc.)
- libmagic file type identification
"""

import re
import struct
from dataclasses import dataclass
from PyQt5.QtCore import QThread, pyqtSignal
from PyQt5.QtWidgets import (QWidget, QVBoxLayout, QHBoxLayout, QLabel, QPushButton,
                              QProgressBar, QTreeWidget, QTreeWidgetItem, QLineEdit,
                              QMenu)
from PyQt5.QtCore import Qt
from PyQt5.QtGui import QFont, QColor

# Check for libmagic availability
try:
    import magic
    LIBMAGIC_AVAILABLE = True
except ImportError:
    LIBMAGIC_AVAILABLE = False


@dataclass
class PatternResult:
    """
    Represents a detected pattern in the file.

    Attributes:
        offset (int): Byte offset where pattern starts
        length (int): Length of pattern in bytes
        category (str): Category of pattern (e.g., "ASCII String", "Image/Media", "Pointer Table")
        description (str): Human-readable description of the pattern
        label (str): User-assigned label for this pattern
        highlight_color: Color for highlighting this pattern (optional)
    """
    offset: int
    length: int
    category: str
    description: str
    label: str = ""
    highlight_color: str = None


class PatternScanner(QThread):
    """
    Background thread for scanning files and detecting patterns.

    This class runs pattern detection algorithms in a separate thread to avoid
    blocking the UI. It detects various patterns including:
    - File signatures via libmagic
    - ASCII strings (printable 7-bit text)
    - UTF-16LE strings (Windows Unicode text)
    - Pointer tables (sequences of file offsets)
    - Compression signatures (zlib, gzip, LZ4, Zstandard, etc.)
    - Image/media signatures (PNG, JPEG, GIF, BMP, etc.)

    Signals:
        progress_updated (int): Emitted with progress percentage (0-100)
        scan_complete (list): Emitted with list of PatternResult objects when done

    Attributes:
        file_data (bytearray): Raw file bytes to scan
        results (list): List of detected PatternResult objects
        min_string_length (int): Minimum length for string detection (default 3)
    """
    progress_updated = pyqtSignal(int)
    scan_complete = pyqtSignal(list)

    def __init__(self, file_data: bytearray):
        super().__init__()
        self.file_data = file_data
        self.results = []
        self.min_string_length = 3

    def run(self):
        self.results = []
        total_steps = 6
        current_step = 0

        self.detect_libmagic_signatures()
        current_step += 1
        self.progress_updated.emit(int((current_step / total_steps) * 100))

        self.detect_ascii_strings()
        current_step += 1
        self.progress_updated.emit(int((current_step / total_steps) * 100))

        self.detect_utf16le_strings()
        current_step += 1
        self.progress_updated.emit(int((current_step / total_steps) * 100))

        self.detect_pointers()
        current_step += 1
        self.progress_updated.emit(int((current_step / total_steps) * 100))

        self.detect_compression_signatures()
        current_step += 1
        self.progress_updated.emit(int((current_step / total_steps) * 100))

        self.detect_image_signatures()
        current_step += 1
        self.progress_updated.emit(100)

        self.scan_complete.emit(self.results)

    def detect_libmagic_signatures(self):
        if not LIBMAGIC_AVAILABLE:
            self.results.append(PatternResult(
                0, 0, "libmagic",
                "N/A"
            ))
            return

        try:
            mime = magic.Magic(mime=True)
            mime_type = mime.from_buffer(bytes(self.file_data))
            detailed = magic.Magic()
            description = detailed.from_buffer(bytes(self.file_data))
            self.results.append(PatternResult(
                0, min(len(self.file_data), 512), "libmagic",
                f"MIME: {mime_type} | {description}"
            ))
        except Exception as e:
            self.results.append(PatternResult(
                0, 0, "libmagic",
                f"libmagic error: {str(e)}"
            ))

    def detect_ascii_strings(self):
        pattern = rb'[\x20-\x7E]{' + str(self.min_string_length).encode() + rb',}'
        matches = re.finditer(pattern, bytes(self.file_data))
        for match in matches:
            text = match.group().decode('ascii', errors='ignore')
            if len(text) >= self.min_string_length:
                self.results.append(PatternResult(
                    match.start(), len(text),
                    "ASCII String",
                    f'"{text[:50]}{"..." if len(text) > 50 else ""}"'
                ))

    def detect_utf16le_strings(self):
        offset = 0
        while offset < len(self.file_data) - 6:
            try:
                char_count = 0
                temp_offset = offset
                chars = []
                while temp_offset < len(self.file_data) - 1:
                    low = self.file_data[temp_offset]
                    high = self.file_data[temp_offset + 1]
                    if high == 0 and 0x20 <= low <= 0x7E:
                        chars.append(chr(low))
                        char_count += 1
                        temp_offset += 2
                    else:
                        break
                if char_count >= self.min_string_length:
                    text = ''.join(chars)
                    self.results.append(PatternResult(
                        offset, char_count * 2,
                        "UTF-16LE String",
                        f'"{text[:50]}{"..." if len(text) > 50 else ""}"'
                    ))
                    offset = temp_offset
                else:
                    offset += 2
            except:
                offset += 2

    def detect_pointers(self):
        file_size = len(self.file_data)
        pointer_clusters = []
        for offset in range(0, len(self.file_data) - 7, 4):
            try:
                ptr32 = struct.unpack('<I', self.file_data[offset:offset+4])[0]
                if 0 < ptr32 < file_size:
                    pointer_clusters.append((offset, 4, ptr32, "u32"))
                if offset + 8 <= len(self.file_data):
                    ptr64 = struct.unpack('<Q', self.file_data[offset:offset+8])[0]
                    if 0 < ptr64 < file_size:
                        pointer_clusters.append((offset, 8, ptr64, "u64"))
            except:
                continue
        clusters = self._cluster_pointers(pointer_clusters)
        for cluster in clusters:
            if len(cluster) >= 3:
                first_offset = cluster[0][0]
                last_offset = cluster[-1][0]
                length = last_offset - first_offset + cluster[-1][1]
                self.results.append(PatternResult(
                    first_offset, length,
                    "Pointer Table",
                    f"{len(cluster)} possible pointers ({cluster[0][3]})"
                ))

    def _cluster_pointers(self, pointers, max_gap: int = 16):
        """
        Group nearby pointers into clusters to identify pointer tables.

        Pointer tables are common in binary formats - sequences of file offsets
        that point to data structures. We detect them by finding groups of 3+
        valid pointers within a small range (max_gap bytes apart).
        """
        if not pointers:
            return []

        # Sort pointers by offset
        sorted_pointers = sorted(pointers, key=lambda x: x[0])

        # Start first cluster
        clusters = [[sorted_pointers[0]]]

        # Group pointers that are close together
        for ptr in sorted_pointers[1:]:
            # If this pointer is within max_gap of the last pointer in current cluster, add it
            if ptr[0] - clusters[-1][-1][0] <= max_gap:
                clusters[-1].append(ptr)
            else:
                # Too far away, start a new cluster
                clusters.append([ptr])

        # Only return clusters with at least 3 pointers (likely pointer tables)
        return [c for c in clusters if len(c) >= 3]

    def detect_compression_signatures(self):
        signatures = [
            (b'\x78\x9C', "zlib (default compression)"),
            (b'\x78\x01', "zlib (no compression)"),
            (b'\x78\xDA', "zlib (best compression)"),
            (b'\x1F\x8B', "gzip"),
            (b'\x04\x22\x4D\x18', "LZ4"),
            (b'\x28\xB5\x2F\xFD', "Zstandard"),
            (b'LZFSE', "LZFSE (Apple)"),
        ]
        for sig, desc in signatures:
            offset = 0
            while True:
                pos = self.file_data.find(sig, offset)
                if pos == -1:
                    break
                self.results.append(PatternResult(pos, len(sig), "Compression", desc))
                offset = pos + 1

    def detect_image_signatures(self):
        signatures = [
            (b'\x89PNG\r\n\x1a\n', "PNG Image"),
            (b'\xFF\xD8\xFF', "JPEG Image"),
            (b'GIF87a', "GIF Image (87a)"),
            (b'GIF89a', "GIF Image (89a)"),
            (b'BM', "Bitmap Image"),
            (b'DDS ', "DirectDraw Surface (DDS)"),
            (b'\x00\x00\x01\x00', "ICO Image"),
            (b'RIFF', "RIFF Container (WebP/WAV)"),
        ]
        for sig, desc in signatures:
            offset = 0
            while True:
                pos = self.file_data.find(sig, offset)
                if pos == -1:
                    break
                if sig == b'RIFF' and pos + 12 <= len(self.file_data):
                    riff_type = self.file_data[pos+8:pos+12]
                    if riff_type == b'WEBP':
                        desc = "WebP Image"
                    elif riff_type == b'WAVE':
                        desc = "WAV Audio"
                self.results.append(PatternResult(pos, len(sig), "Image/Media", desc))
                offset = pos + 1


class PatternScanWidget(QWidget):
    """
    UI widget for pattern scanning functionality.

    This widget provides a user interface for scanning files and displaying
    detected patterns in a tree view. Users can:
    - Trigger scans with the "Scan" button
    - View patterns organized by category
    - Click patterns to navigate to their location in hex view
    - Assign custom labels to patterns
    - Highlight patterns with custom colors

    The widget displays a hierarchical tree:
    - Top level: Categories (libmagic, Compression, Image/Media, Strings, etc.)
    - Second level: Individual patterns with offset, length, and description

    Signals:
        result_clicked (int, int): Emitted with (offset, length) when pattern is clicked

    Attributes:
        scanner (PatternScanner): Background thread performing the scan
        tree (QTreeWidget): Tree view displaying scan results
        label_editors (dict): Maps pattern offsets to label edit widgets
        parent_editor: Reference to parent HexEditorQt instance
    """
    result_clicked = pyqtSignal(int, int)

    def __init__(self, parent=None):
        super().__init__(parent)
        self.scanner = None
        self.setup_ui()

    def setup_ui(self):
        layout = QVBoxLayout()
        layout.setContentsMargins(5, 5, 5, 5)
        header_layout = QHBoxLayout()
        title = QLabel("Pattern Scan")
        title.setFont(QFont("Arial", 11, QFont.Bold))
        header_layout.addWidget(title)
        self.scan_button = QPushButton("Scan")
        self.scan_button.clicked.connect(self.start_scan)
        header_layout.addWidget(self.scan_button)
        header_layout.addStretch()
        layout.addLayout(header_layout)
        self.progress_bar = QProgressBar()
        self.progress_bar.setVisible(False)
        layout.addWidget(self.progress_bar)
        self.tree = QTreeWidget()
        self.tree.setHeaderLabels(["Label", "Offset", "Length", "Description"])
        self.tree.setIndentation(15)
        self.tree.setColumnWidth(0, 150)
        self.tree.setColumnWidth(1, 80)
        self.tree.setColumnWidth(2, 60)
        self.tree.setColumnWidth(3, 250)
        self.tree.itemClicked.connect(self.on_item_clicked)
        self.tree.setContextMenuPolicy(Qt.CustomContextMenu)
        self.tree.customContextMenuRequested.connect(self.on_tree_context_menu)
        layout.addWidget(self.tree)
        self.label_editors = {}
        self.status_label = QLabel("No scan performed")
        self.status_label.setFont(QFont("Arial", 9))
        layout.addWidget(self.status_label)
        self.setLayout(layout)

    def start_scan(self):
        if hasattr(self, 'file_data') and self.file_data:
            self.scan_button.setEnabled(False)
            self.progress_bar.setVisible(True)
            self.progress_bar.setRange(0, 100)
            self.progress_bar.setValue(0)
            self.tree.clear()
            self.status_label.setText("Scanning...")
            self.scanner = PatternScanner(self.file_data)
            self.scanner.progress_updated.connect(self.on_scan_progress)
            self.scanner.scan_complete.connect(self.on_scan_complete)
            self.scanner.start()

    def on_scan_progress(self, value):
        """Update progress bar during scan"""
        try:
            self.progress_bar.setValue(value)
        except RuntimeError:
            pass

    def on_scan_complete(self, results):
        try:
            self.progress_bar.setVisible(False)
            self.scan_button.setEnabled(True)
            self.tree.clear()
            categories = {}
            for result in results:
                if result.category not in categories:
                    categories[result.category] = []
                categories[result.category].append(result)
            category_order = ["libmagic", "Compression", "Image/Media", "ASCII String", "UTF-16LE String", "Pointer Table"]
            for category in category_order:
                if category in categories:
                    self._add_category(category, categories[category])
            for category, results_list in categories.items():
                if category not in category_order:
                    self._add_category(category, results_list)
            total_results = len(results)
            self.status_label.setText(f"Scan complete: {total_results} patterns found")
            self.tree.expandAll()

            if hasattr(self, 'parent_editor') and self.parent_editor:
                self.parent_editor.load_pattern_labels_to_widget()
        except RuntimeError:
            pass

    def populate_tree(self, results):
        """Populate tree with saved results"""
        try:
            self.tree.clear()
            self.label_editors.clear()
            categories = {}
            for result in results:
                if result.category not in categories:
                    categories[result.category] = []
                categories[result.category].append(result)
            category_order = ["libmagic", "Compression", "Image/Media", "ASCII String", "UTF-16LE String", "Pointer Table"]
            for category in category_order:
                if category in categories:
                    self._add_category(category, categories[category])
            for category, results_list in categories.items():
                if category not in category_order:
                    self._add_category(category, results_list)
            total_results = len(results)
            self.status_label.setText(f"Loaded {total_results} patterns")
            self.tree.expandAll()
        except RuntimeError:
            pass

    def _add_category(self, category_name, results):
        category_item = QTreeWidgetItem(self.tree)
        category_item.setText(0, category_name)
        category_item.setTextAlignment(0, Qt.AlignCenter)
        category_item.setText(3, f"({len(results)} items)")
        for result in results:
            item = QTreeWidgetItem(category_item)

            label_container = QWidget()
            label_layout = QHBoxLayout()
            label_layout.setContentsMargins(0, 0, 2, 0)
            label_layout.setSpacing(4)

            color_box = QPushButton()
            color_box.setFixedSize(16, 16)
            if hasattr(result, 'highlight_color') and result.highlight_color:
                color_box.setStyleSheet(f"background-color: {result.highlight_color}; border: 1px solid #555;")
            else:
                color_box.setStyleSheet("background-color: transparent; border: 1px solid #555;")
            color_box.clicked.connect(lambda checked, r=result, cb=color_box, it=item: self.open_highlight_for_pattern(r, cb, it))
            label_layout.addWidget(color_box)

            label_edit = QLineEdit()
            label_edit.setText(result.label)
            label_edit.setPlaceholderText("Enter label...")
            label_edit.setFrame(False)
            label_edit.setFont(QFont("Arial", 8))
            label_edit.setStyleSheet("QLineEdit { background: transparent; }")
            label_edit.returnPressed.connect(lambda r=result, le=label_edit: self.on_label_changed(r, le))
            label_edit.editingFinished.connect(lambda r=result, le=label_edit: self.on_label_changed(r, le))
            label_layout.addWidget(label_edit, 1)

            label_container.setLayout(label_layout)

            item.setText(1, f"0x{result.offset:X}")
            item.setText(2, str(result.length) if result.length > 0 else "—")
            item.setText(3, result.description)

            if hasattr(result, 'highlight_color') and result.highlight_color:
                item.setBackground(3, QColor(result.highlight_color))

            item.setData(0, Qt.UserRole, result)

            self.tree.setItemWidget(item, 0, label_container)
            self.label_editors[result.offset] = label_edit

    def on_label_changed(self, result, line_edit):
        new_label = line_edit.text().strip()
        result.label = new_label

    def on_item_clicked(self, item, column):
        result = item.data(0, Qt.UserRole)
        if isinstance(result, PatternResult):
            self.result_clicked.emit(result.offset, result.length)

    def on_tree_context_menu(self, position):
        item = self.tree.itemAt(position)
        if item:
            result = item.data(0, Qt.UserRole)
            if isinstance(result, PatternResult):
                menu = QMenu()
                highlight_action = menu.addAction("Open Highlight Dialog")
                action = menu.exec_(self.tree.viewport().mapToGlobal(position))

                if action == highlight_action:
                    widget = self.tree.itemWidget(item, 0)
                    if widget:
                        color_box = widget.findChild(QPushButton)
                        if color_box:
                            self.open_highlight_for_pattern(result, color_box, item)

    def open_highlight_for_pattern(self, result, color_box, tree_item):
        """Open the highlight dialog with this pattern's bytes pre-selected"""
        if hasattr(self, 'parent_editor') and self.parent_editor:
            if self.parent_editor.current_tab_index < 0:
                return

            self.parent_editor.selection_start = result.offset
            self.parent_editor.selection_end = result.offset + result.length - 1
            self.parent_editor.cursor_position = result.offset

            self.parent_editor.pattern_result_to_update = (result, color_box, tree_item)

            self.parent_editor.show_highlight_window()

    def get_color_for_category(self, category):
        category_colors = {
            "libmagic": QColor(100, 200, 100),
            "Compression": QColor(100, 150, 255),
            "Image/Media": QColor(255, 150, 100),
            "ASCII String": QColor(200, 200, 100),
            "UTF-16LE String": QColor(200, 150, 255),
            "Pointer Table": QColor(255, 100, 150),
        }
        return category_colors.get(category, QColor(150, 150, 150))

    def set_file_data(self, file_data: bytearray):
        self.file_data = file_data
        self.tree.clear()
        self.status_label.setText("Ready to scan")
        self.scan_button.setEnabled(True)
