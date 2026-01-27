"""
RxD Hex Editor - Professional Binary File Editor
=================================================

A feature-rich, professional hex editor application built with PyQt5 for viewing
and editing binary files with advanced visualization and analysis tools.

Key Features:
-------------
Core Editing:
- Multi-file tabs: Open and edit multiple files simultaneously
- Smart editing: Insert/overwrite modes, column selection, smart paste with delimiters
- Undo/Redo: Full undo/redo support with state snapshots
- Search & Replace: Hex patterns, ASCII/UTF-16 strings with regex support
- Copy/Paste formats: Hex, C array, Python bytes, Base64, and more

Analysis Tools:
- Pattern scanning: Automatic detection of strings, pointers, compression/image signatures
- Data inspector: Interpret bytes as 25+ data types (integers, floats, timestamps, GUIDs, etc.)
- Statistics: Byte frequency analysis, entropy calculation, and distribution visualizations
- Signature tracking: Mark and track important offsets with custom labels and data types
- Fields system: Define structured data fields with nested subfields and type interpretation

Visual Enhancements:
- Syntax highlighting: Color-coded display for modified/inserted bytes
- Theme system: 16+ built-in themes plus custom theme editor with gradients
- Segment boundaries: Visual column separators with customizable ranges
- Edit box overlay: Visual indicator for active editing regions
- Signature overlays: Inline value display for tracked pointers

Productivity Tools:
- Notes system: Attach searchable notes to specific byte ranges
- Version control: Built-in snapshot system with timestamps and descriptions
- Bookmarks: Quick navigation to important offsets
- File comparison: Side-by-side comparison of two files
- Debugging console: Real-time terminal output viewer

File Operations:
- Import/Export: Selected regions, multiple format support
- Large file support: Memory-mapped I/O for files over 100MB
- File metadata: Creation/modification dates, MD5/SHA256 hashing

Architecture Overview:
----------------------
Main Components:
- HexEditorQt: Main application window and core editor logic
- FileTab: Individual file tabs with file data and metadata
- FieldWidget: Structured data field management with type interpretation
- PatternScanner/PatternScanWidget: Pattern detection and display
- SignatureWidget: User-defined signature/pointer management
- DataInspector: Multi-format byte interpretation
- StatisticsWidget: Byte frequency and entropy analysis
- NotesWindow: Searchable notes management
- DebugWindow: Terminal output capture and display

Display System:
- Virtual scrolling: Efficient rendering for large files (only visible rows)
- Configurable bytes per row: 8, 16, 32, or 64 bytes
- Hex and ASCII side-by-side display with synchronized scrolling
- Custom overlays: Segment boundaries, edit boxes, signature pointers
- Dynamic highlighting: Selection, modified bytes, inserted bytes

License:
--------
Open Source

Author:
-------
Digitzaki [龍崎 明]
https://digitzaki.github.io/
"""

import sys
import os
import re
import struct
import json
import mmap
import math
from collections import Counter
from PyQt5.QtWidgets import *
from PyQt5.QtGui import *
from PyQt5.QtCore import *
from editor_themes import (THEMES, get_theme_stylesheet, get_theme_colors,
                           get_all_themes, CustomThemeEditor, load_custom_themes,
                           save_custom_themes, get_theme_categories)
from datainspect import DataInspector
from datainspect.pattern_scan import PatternScanner, PatternScanWidget, PatternResult
from datainspect.pointers import SignaturePointer, SignatureWidget, SignatureScanner, ClickableOverlay
from datainspect.statistics import StatisticsWidget
from datainspect.fields import FieldWidget

try:
    import magic
    LIBMAGIC_AVAILABLE = True
except ImportError:
    LIBMAGIC_AVAILABLE = False

try:
    import matplotlib
    matplotlib.use('Qt5Agg')
    from matplotlib.backends.backend_qt5agg import FigureCanvasQTAgg as FigureCanvas
    from matplotlib.figure import Figure
    MATPLOTLIB_AVAILABLE = True
except ImportError:
    MATPLOTLIB_AVAILABLE = False


class FileTab:
    """
    Represents a single file tab in the hex editor.

    Each opened file gets its own FileTab instance containing the file data and
    all associated metadata. This allows multiple files to be open simultaneously
    with independent edit histories, bookmarks, highlights, etc.

    Features:
    - Memory-mapped I/O for large files (>100MB)
    - Tracks modified/inserted/replaced bytes
    - Maintains pattern scan results and signature pointers
    - Stores highlights and bookmarks
    - Preserves notes attached to byte ranges

    Attributes:
        file_path (str): Absolute path to the file
        file_data (bytearray): Raw file bytes (or mmap object for large files)
        original_data (bytearray): Original unmodified file data (for comparison)
        modified (bool): Whether file has unsaved changes
        modified_bytes (set): Set of byte offsets that were modified
        inserted_bytes (set): Set of byte offsets that were inserted
        replaced_bytes (set): Set of byte offsets that were replaced
        file_handle: Open file handle (used for memory-mapping)
        mmap: Memory-mapped file object (for large files)
        use_mmap (bool): Whether this file uses memory mapping
        scan_results (list): Pattern scan results for this file
        highlights (list): Byte range highlights with colors/descriptions
        bookmarks (dict): Named bookmarks at specific offsets
        notes (list): Notes attached to byte ranges
    """
    def __init__(self, file_path, file_data=None, file_handle=None, use_mmap=False):
        self.file_path = file_path
        self.file_handle = file_handle
        self.mmap = None
        self.use_mmap = use_mmap

        if use_mmap and file_handle:
            # Memory-mapped file for large files (efficient for files >100MB)
            try:
                self.mmap = mmap.mmap(file_handle.fileno(), 0, access=mmap.ACCESS_READ)
                self.file_data = self.mmap  # Acts like bytearray but memory-mapped
                self.original_data = None  # Don't duplicate large files in memory
            except:
                # Fallback to regular loading if mmap fails
                self.file_data = bytearray(file_data)
                self.original_data = bytearray(file_data)
                self.use_mmap = False
        else:
            # Regular in-memory mode for small files
            self.file_data = bytearray(file_data)
            self.original_data = bytearray(file_data)

        self.modified = False
        self.edits = {}  # For mmap mode: {offset: byte_value} - track modifications
        self.inserted_bytes = set()
        self.modified_bytes = set()
        self.replaced_bytes = set()  # Bytes modified by replace operation (blue)
        self.byte_highlights = {}  # Per-file highlights: {offset: {color, message, underline, pattern (optional)}}
        self.pattern_highlights = []  # Pattern-based highlights that auto-search: [{pattern, color, message, underline}]
        self.pattern_highlights_dirty = False  # Flag to track if pattern highlights need reapplying
        self.snapshots = []  # Version control snapshots for this file
        self.last_snapshot_data = None  # Last snapshot data to detect changes
        self.pattern_labels = {}  # Pattern scan labels: {offset: label}
        self.pattern_scan_results = []  # Store pattern scan results per file
        self.inspector_pointers = []  # Store inspector pointers per file

    def get_byte(self, offset):
        """Get byte at offset, checking edits first if using mmap"""
        if self.use_mmap and offset in self.edits:
            return self.edits[offset]
        return self.file_data[offset]

    def set_byte(self, offset, value):
        """Set byte at offset"""
        if self.use_mmap:
            self.edits[offset] = value
            self.modified = True
        else:
            self.file_data[offset] = value

    def __del__(self):
        """Clean up mmap and file handle"""
        if self.mmap:
            self.mmap.close()
        if self.file_handle:
            self.file_handle.close()


class NotesWindow(QWidget):
    def __init__(self, parent, hex_editor):
        super().__init__()
        self.parent_window = parent
        self.hex_editor = hex_editor
        self.setup_ui()
        # Apply theme from hex editor
        self.apply_theme()

    def setup_ui(self):
        self.setWindowTitle("Notes")

        # Use size policy instead of fixed resize
        self.setMinimumSize(600, 400)

        layout = QVBoxLayout()

        # Toolbar
        toolbar = QWidget()
        toolbar_layout = QHBoxLayout()
        toolbar_layout.setContentsMargins(5, 5, 5, 5)

        toolbar_layout.addWidget(QLabel("Size:"))
        self.font_size_spin = QSpinBox()
        self.font_size_spin.setRange(6, 72)
        self.font_size_spin.setValue(10)
        self.font_size_spin.valueChanged.connect(self.change_font_size)
        toolbar_layout.addWidget(self.font_size_spin)

        self.bold_check = QCheckBox("B")
        self.bold_check.setFont(QFont("Arial", 9, QFont.Bold))
        self.bold_check.stateChanged.connect(self.apply_text_style)
        toolbar_layout.addWidget(self.bold_check)

        self.italic_check = QCheckBox("I")
        font = QFont("Arial", 9)
        font.setItalic(True)
        self.italic_check.setFont(font)
        self.italic_check.stateChanged.connect(self.apply_text_style)
        toolbar_layout.addWidget(self.italic_check)

        self.underline_check = QCheckBox("U")
        font = QFont("Arial", 9)
        font.setUnderline(True)
        self.underline_check.setFont(font)
        self.underline_check.stateChanged.connect(self.apply_text_style)
        toolbar_layout.addWidget(self.underline_check)

        color_btn = QPushButton("Color")
        color_btn.clicked.connect(self.show_text_color_picker)
        toolbar_layout.addWidget(color_btn)

        highlight_btn = QPushButton("Highlight")
        highlight_btn.clicked.connect(self.show_highlight_color_picker)
        toolbar_layout.addWidget(highlight_btn)

        table_btn = QPushButton("Table")
        table_btn.clicked.connect(self.insert_table)
        toolbar_layout.addWidget(table_btn)

        save_btn = QPushButton("Save")
        save_btn.clicked.connect(self.save_notes)
        toolbar_layout.addWidget(save_btn)

        open_btn = QPushButton("Open")
        open_btn.clicked.connect(self.open_notes)
        toolbar_layout.addWidget(open_btn)

        toolbar_layout.addStretch()
        toolbar.setLayout(toolbar_layout)
        layout.addWidget(toolbar)

        # Text editor - using QTextEdit for editing with hyperlink support
        self.text_edit = QTextEdit()
        self.text_edit.setFont(QFont("Courier", 10))
        self.text_edit.cursorPositionChanged.connect(self.update_format_from_cursor)
        layout.addWidget(self.text_edit)

        # Install event filter for key presses to detect when to create hyperlinks
        self.text_edit.installEventFilter(self)
        # Also install on viewport to catch mouse clicks on links
        self.text_edit.viewport().installEventFilter(self)

        self.setLayout(layout)

        # Track current format for new text
        self.current_char_format = QTextCharFormat()

    def apply_theme(self, dark=bool):
        # Apply theme from hex editor
        if self.hex_editor:
            self.setStyleSheet(get_theme_stylesheet(self.hex_editor.current_theme))

    def eventFilter(self, obj, event):
        # Detect when user types space or newline to create hyperlinks
        if obj == self.text_edit and event.type() == event.KeyPress:
            if event.key() in (Qt.Key_Space, Qt.Key_Return, Qt.Key_Enter):
                # Small delay to let the character be inserted first
                QTimer.singleShot(10, self.check_and_create_hyperlink)
            elif event.key() == Qt.Key_Backspace:
                # Check if we're deleting a hyperlink
                cursor = self.text_edit.textCursor()
                if cursor.position() > 0:
                    # Check character before cursor
                    cursor.movePosition(QTextCursor.Left, QTextCursor.KeepAnchor)
                    fmt = cursor.charFormat()
                    if fmt.isAnchor():
                        # Delete entire hyperlink
                        cursor.clearSelection()
                        cursor.movePosition(QTextCursor.Left)
                        cursor.select(QTextCursor.WordUnderCursor)
                        cursor.removeSelectedText()
                        return True

        # Handle mouse clicks on hyperlinks in viewport
        elif obj == self.text_edit.viewport() and event.type() == event.MouseButtonRelease:
            if event.button() == Qt.LeftButton:
                cursor = self.text_edit.cursorForPosition(event.pos())
                fmt = cursor.charFormat()
                if fmt.isAnchor():
                    anchor = fmt.anchorHref()
                    self.handle_link_click(anchor)
                    return True

        return super().eventFilter(obj, event)

    def check_and_create_hyperlink(self):
        # Look back from cursor to find hex pattern like 0x2, 0x2C, 0x002, etc.
        cursor = self.text_edit.textCursor()
        original_pos = cursor.position()

        # Get text up to cursor (look back reasonable amount)
        cursor.setPosition(max(0, original_pos - 50), QTextCursor.MoveAnchor)
        cursor.setPosition(original_pos, QTextCursor.KeepAnchor)
        text_before_cursor = cursor.selectedText()

        import re
        # Find all hex patterns in the text (0x followed by at least 1 hex digit)
        matches = list(re.finditer(r'\b0x[0-9A-Fa-f]+\b', text_before_cursor))

        if matches:
            # Get the last match (closest to cursor)
            match = matches[-1]
            hex_pattern = match.group()

            # Calculate absolute position in document
            start = max(0, original_pos - 50) + match.start()
            end = start + len(hex_pattern)

            # Select the hex pattern
            cursor.setPosition(start)
            cursor.setPosition(end, QTextCursor.KeepAnchor)

            # Create hyperlink for this pattern
            link_format = QTextCharFormat()
            link_format.setForeground(QColor(0, 0, 255))
            link_format.setFontUnderline(True)
            link_format.setAnchor(True)
            link_format.setAnchorHref(hex_pattern)
            cursor.mergeCharFormat(link_format)

    def update_format_from_cursor(self):
        # Update toolbar to reflect current cursor position formatting
        cursor = self.text_edit.textCursor()
        fmt = cursor.charFormat()

        # Block signals to prevent recursive calls
        self.font_size_spin.blockSignals(True)
        self.bold_check.blockSignals(True)
        self.italic_check.blockSignals(True)
        self.underline_check.blockSignals(True)

        # Update controls
        font_size = fmt.fontPointSize()
        if font_size > 0:
            self.font_size_spin.setValue(int(font_size))

        font = fmt.font()
        self.bold_check.setChecked(font.bold())
        self.italic_check.setChecked(font.italic())
        self.underline_check.setChecked(font.underline())

        # Store current format
        self.current_char_format = fmt

        # Unblock signals
        self.font_size_spin.blockSignals(False)
        self.bold_check.blockSignals(False)
        self.italic_check.blockSignals(False)
        self.underline_check.blockSignals(False)

    def change_font_size(self):
        cursor = self.text_edit.textCursor()
        fmt = QTextCharFormat()
        fmt.setFontPointSize(self.font_size_spin.value())

        if cursor.hasSelection():
            cursor.mergeCharFormat(fmt)
        else:
            # Apply to future typed text
            self.current_char_format.setFontPointSize(self.font_size_spin.value())
            self.text_edit.setCurrentCharFormat(self.current_char_format)

    def apply_text_style(self):
        cursor = self.text_edit.textCursor()
        fmt = QTextCharFormat()
        font = QFont("Courier", self.font_size_spin.value())
        font.setBold(self.bold_check.isChecked())
        font.setItalic(self.italic_check.isChecked())
        font.setUnderline(self.underline_check.isChecked())
        fmt.setFont(font)

        if cursor.hasSelection():
            cursor.mergeCharFormat(fmt)
        else:
            # Apply to future typed text
            self.current_char_format.setFont(font)
            self.text_edit.setCurrentCharFormat(self.current_char_format)

    def show_text_color_picker(self):
        color = QColorDialog.getColor()
        if color.isValid():
            cursor = self.text_edit.textCursor()
            fmt = QTextCharFormat()
            fmt.setForeground(color)

            if cursor.hasSelection():
                cursor.mergeCharFormat(fmt)
            else:
                # Apply to future typed text
                self.current_char_format.setForeground(color)
                self.text_edit.setCurrentCharFormat(self.current_char_format)

    def show_highlight_color_picker(self):
        color = QColorDialog.getColor()
        if color.isValid():
            cursor = self.text_edit.textCursor()
            fmt = QTextCharFormat()
            fmt.setBackground(color)

            if cursor.hasSelection():
                cursor.mergeCharFormat(fmt)
            else:
                # Apply to future typed text
                self.current_char_format.setBackground(color)
                self.text_edit.setCurrentCharFormat(self.current_char_format)

    def insert_table(self):
        dialog = QDialog(self)
        dialog.setWindowTitle("Insert Table")
        layout = QVBoxLayout()

        grid = QGridLayout()
        grid.addWidget(QLabel("Rows:"), 0, 0)
        rows_spin = QSpinBox()
        rows_spin.setRange(1, 50)
        rows_spin.setValue(3)
        grid.addWidget(rows_spin, 0, 1)

        grid.addWidget(QLabel("Columns:"), 1, 0)
        cols_spin = QSpinBox()
        cols_spin.setRange(1, 20)
        cols_spin.setValue(3)
        grid.addWidget(cols_spin, 1, 1)

        layout.addLayout(grid)

        buttons = QDialogButtonBox(QDialogButtonBox.Ok | QDialogButtonBox.Cancel)
        buttons.accepted.connect(dialog.accept)
        buttons.rejected.connect(dialog.reject)
        layout.addWidget(buttons)

        dialog.setLayout(layout)

        if dialog.exec_():
            rows = rows_spin.value()
            cols = cols_spin.value()

            # Insert real QTextTable
            cursor = self.text_edit.textCursor()

            # Create table format
            table_format = QTextTableFormat()
            table_format.setBorder(1)
            table_format.setBorderStyle(QTextFrameFormat.BorderStyle_Solid)
            table_format.setCellPadding(4)
            table_format.setCellSpacing(0)
            table_format.setAlignment(Qt.AlignLeft)

            # Insert the table
            table = cursor.insertTable(rows, cols, table_format)

            # Set column widths
            for i in range(cols):
                table.format().setColumnWidthConstraints([QTextLength(QTextLength.FixedLength, 100)])

            self.text_edit.setTextCursor(cursor)

    def handle_link_click(self, url):
        # Handle clicking on 0x<offset> links
        url_str = url.toString() if hasattr(url, 'toString') else str(url)

        # Parse hex offset - strip leading zeros
        if url_str.startswith('0x'):
            try:
                # Remove 0x prefix and parse hex (automatically handles leading zeros)
                offset = int(url_str[2:], 16)

                # Check if hex editor has a current file open
                if self.hex_editor.current_tab_index >= 0:
                    current_file = self.hex_editor.open_files[self.hex_editor.current_tab_index]

                    # Check if offset is valid
                    if 0 <= offset < len(current_file.file_data):
                        # Set cursor to that position
                        self.hex_editor.cursor_position = offset
                        self.hex_editor.cursor_nibble = 0

                        # Clear selection
                        self.hex_editor.selection_start = offset
                        self.hex_editor.selection_end = offset

                        # Refresh display and scroll to position
                        self.hex_editor.display_hex()

                        # Calculate which row the byte is on
                        row = offset // self.hex_editor.bytes_per_row

                        # Scroll to that row in hex display
                        hex_chars_per_row = self.hex_editor.bytes_per_row * 3 + 2
                        char_pos = row * hex_chars_per_row

                        hex_cursor = self.hex_editor.hex_display.textCursor()
                        hex_cursor.setPosition(char_pos)
                        self.hex_editor.hex_display.setTextCursor(hex_cursor)
                        self.hex_editor.hex_display.ensureCursorVisible()

                        # Bring hex editor window to front
                        self.parent_window.raise_()
                        self.parent_window.activateWindow()

                        QMessageBox.information(self, "Jump to Offset", f"Jumped to offset {url_str} (decimal: {offset})")
                    else:
                        QMessageBox.warning(self, "Invalid Offset", f"Offset {url_str} is out of range.\nFile size: {len(current_file.file_data)} bytes")
                else:
                    QMessageBox.warning(self, "No File Open", "Please open a file in the hex editor first.")

            except ValueError:
                QMessageBox.warning(self, "Invalid Link", f"Could not parse hex offset: {url_str}")

    def save_notes(self):
        file_path, selected_filter = QFileDialog.getSaveFileName(
            self, "Save Notes", "", "Text Files (*.txt);;Rich Text Format (*.rtf);;All Files (*)"
        )
        if file_path:
            try:
                # Save as RTF if .rtf extension or RTF filter selected
                if file_path.endswith('.rtf') or 'rtf' in selected_filter.lower():
                    # Use QTextDocumentWriter for RTF
                    writer = QTextDocumentWriter(file_path, b'richtext')
                    if writer.write(self.text_edit.document()):
                        QMessageBox.information(self, "Success", "Notes saved successfully in RTF format!")
                    else:
                        QMessageBox.critical(self, "Error", "Failed to write RTF file")
                else:
                    # Save as plain text (includes {label, offset} commands)
                    with open(file_path, 'w') as f:
                        f.write(self.text_edit.toPlainText())
                    QMessageBox.information(self, "Success", "Notes and labels saved successfully!")
            except Exception as e:
                QMessageBox.critical(self, "Error", f"Failed to save notes: {str(e)}")

    def open_notes(self):
        file_path, _ = QFileDialog.getOpenFileName(
            self, "Open Notes", "", "Text Files (*.txt);;Rich Text Format (*.rtf);;All Files (*)"
        )
        if file_path:
            try:
                if file_path.endswith('.rtf'):
                    # Load RTF with formatting using QTextDocumentWriter
                    from PyQt5.QtCore import QFile, QIODevice
                    file = QFile(file_path)
                    if file.open(QIODevice.ReadOnly):
                        data = file.readAll()
                        file.close()
                        # Create new document and load RTF data
                        doc = QTextDocument()
                        doc.setPlainText('')
                        # RTF is a text format, decode and try setHtml or use mime
                        rtf_bytes = data.data()
                        # QTextEdit doesn't directly support RTF reading, so we use setHtml for now
                        # For true RTF support, we'd need external library
                        # For now, treat as plain text if RTF parsing fails
                        try:
                            rtf_text = rtf_bytes.decode('utf-8', errors='ignore')
                            # Basic check if it's actually RTF
                            if rtf_text.startswith('{\\rtf'):
                                # RTF detected but Qt doesn't parse it natively well
                                # Strip RTF codes for basic display
                                import re
                                # Very basic RTF stripping (not perfect but workable)
                                text = re.sub(r'\\[a-z]+\d*\s?', '', rtf_text)
                                text = re.sub(r'[{}]', '', text)
                                self.text_edit.setPlainText(text)
                            else:
                                self.text_edit.setPlainText(rtf_text)
                        except:
                            self.text_edit.setPlainText(rtf_bytes.decode('latin-1', errors='ignore'))
                else:
                    # Load as plain text
                    with open(file_path, 'r') as f:
                        self.text_edit.setPlainText(f.read())

                QMessageBox.information(self, "Success", "Notes loaded successfully!")
            except Exception as e:
                QMessageBox.critical(self, "Error", f"Failed to open notes: {str(e)}")

    def closeEvent(self, event):
        """Prompt to save if there's text in the notebook and editor is closed"""
        # Only show prompt if editor is closed or not visible
        editor_closed = not self.parent_window or not self.parent_window.isVisible()

        if editor_closed and self.text_edit.toPlainText().strip():
            reply = QMessageBox.question(
                self,
                "Save Notes",
                "Would you like to save your notes before closing?",
                QMessageBox.Yes | QMessageBox.No | QMessageBox.Cancel,
                QMessageBox.Cancel
            )

            if reply == QMessageBox.Yes:
                self.save_notes()
                event.accept()
            elif reply == QMessageBox.No:
                event.accept()
            else:
                event.ignore()
        else:
            event.accept()


class SmoothScrollBar(QWidget):
    """Custom scrollbar overlay that provides smooth dragging without rendering lag"""
    valueChanged = pyqtSignal(int)

    def __init__(self, orientation=Qt.Vertical, parent=None):
        super().__init__(parent)
        self.orientation = orientation
        self._minimum = 0
        self._maximum = 100
        self._value = 0
        self._page_step = 10
        self.dragging = False
        self.drag_start_y = 0
        self.drag_start_value = 0
        self.handle_color = "#555"
        self.handle_hover_color = "#666"
        self.bg_color = "#2b2b2b"
        self.is_hovering = False
        self.setMouseTracking(True)

        # Timer for throttling value changes during drag
        self.drag_timer = QTimer(self)
        self.drag_timer.setInterval(16)  # ~60fps
        self.drag_timer.timeout.connect(self._emit_pending_value)
        self.pending_value = None

        if orientation == Qt.Vertical:
            self.setMinimumWidth(10)
            self.setMaximumWidth(10)

    def set_theme_colors(self, theme_colors):
        """Update colors based on theme dictionary"""
        self.bg_color = theme_colors.get('editor_bg', '#2b2b2b')
        self.handle_color = theme_colors.get('border', '#555')
        self.handle_hover_color = theme_colors.get('button_bg', '#666')
        self.update()

    def setRange(self, minimum, maximum):
        self._minimum = minimum
        self._maximum = maximum
        self.update()

    def setPageStep(self, step):
        self._page_step = step
        self.update()

    def setValue(self, value):
        old_value = self._value
        self._value = max(self._minimum, min(self._maximum, value))
        if old_value != self._value:
            self.update()

    def blockSignals(self, block):
        """Override to allow signal blocking like QScrollBar"""
        super().blockSignals(block)

    def maximum(self):
        """Return maximum value"""
        return self._maximum

    def value(self):
        """Return current value"""
        return self._value

    def get_handle_rect(self):
        """Calculate the handle rectangle based on current value"""
        if self._maximum <= self._minimum:
            return QRect(0, 0, self.width(), self.height())

        total_range = self._maximum - self._minimum + self._page_step
        handle_height = max(20, int(self.height() * self._page_step / total_range))
        available_height = self.height() - handle_height

        if self._maximum > self._minimum:
            position = int(available_height * (self._value - self._minimum) / (self._maximum - self._minimum))
        else:
            position = 0

        return QRect(0, position, self.width(), handle_height)

    def paintEvent(self, event):
        painter = QPainter(self)
        painter.setRenderHint(QPainter.Antialiasing)

        # Draw background
        painter.fillRect(self.rect(), QColor(self.bg_color))

        # Draw handle
        handle_rect = self.get_handle_rect()
        color = self.handle_hover_color if self.is_hovering or self.dragging else self.handle_color
        painter.setBrush(QColor(color))
        painter.setPen(Qt.NoPen)
        painter.drawRoundedRect(handle_rect, 4, 4)

    def mousePressEvent(self, event):
        if event.button() == Qt.LeftButton:
            handle_rect = self.get_handle_rect()
            if handle_rect.contains(event.pos()):
                # Start dragging the handle
                self.dragging = True
                self.drag_start_y = event.pos().y()
                self.drag_start_value = self._value
            else:
                # Clicked outside handle - jump to position
                self.jump_to_position(event.pos().y())
            self.update()

    def _emit_pending_value(self):
        """Emit the pending value change to reduce rendering load"""
        if self.pending_value is not None:
            self.valueChanged.emit(self.pending_value)
            self.pending_value = None

    def mouseMoveEvent(self, event):
        handle_rect = self.get_handle_rect()
        was_hovering = self.is_hovering
        self.is_hovering = handle_rect.contains(event.pos())

        if self.dragging:
            # Calculate new value based on drag distance
            delta_y = event.pos().y() - self.drag_start_y
            handle_height = self.get_handle_rect().height()
            available_height = self.height() - handle_height

            if available_height > 0:
                value_range = self._maximum - self._minimum
                delta_value = int(delta_y * value_range / available_height)
                new_value = self.drag_start_value + delta_value
                new_value = max(self._minimum, min(self._maximum, new_value))

                if new_value != self._value:
                    self._value = new_value
                    # Force immediate repaint for smooth visual feedback
                    self.repaint()
                    # Queue the value change signal for throttled emission
                    self.pending_value = self._value
                    if not self.drag_timer.isActive():
                        self.drag_timer.start()
        elif was_hovering != self.is_hovering:
            self.update()

    def mouseReleaseEvent(self, event):
        if event.button() == Qt.LeftButton:
            self.dragging = False
            # Stop the timer and emit any pending value immediately
            self.drag_timer.stop()
            if self.pending_value is not None:
                self.valueChanged.emit(self.pending_value)
                self.pending_value = None
            self.update()

    def jump_to_position(self, y):
        """Jump to a position when clicking outside the handle"""
        handle_height = self.get_handle_rect().height()
        available_height = self.height() - handle_height

        if available_height > 0:
            # Center the handle on the click position
            target_y = y - handle_height // 2
            target_y = max(0, min(available_height, target_y))

            value_range = self._maximum - self._minimum
            new_value = self._minimum + int(target_y * value_range / available_height)
            new_value = max(self._minimum, min(self._maximum, new_value))

            if new_value != self._value:
                self._value = new_value
                self.valueChanged.emit(self._value)
                self.update()


class HexTextEdit(QTextEdit):
    clicked = pyqtSignal(QMouseEvent)
    rightClicked = pyqtSignal(QMouseEvent)
    hovered = pyqtSignal(QMouseEvent)

    def __init__(self, parent=None):
        super().__init__(parent)
        self.setReadOnly(True)
        # Use Courier for better extended ASCII support with consistent character widths
        font = QFont("Courier", 10)
        font.setStyleHint(QFont.Monospace)
        font.setFixedPitch(True)
        self.setFont(font)
        self.setMouseTracking(True)
        # Remove default margins and padding for tight alignment
        self.document().setDocumentMargin(0)
        self.setContentsMargins(0, 0, 0, 0)
        self.setStyleSheet("QTextEdit { padding: 0px; margin: 0px; }")
        self.editor = None  # Will be set to parent HexEditorQt instance
        self.gradient_colors = None  # For gradient backgrounds
        self.background_image = None  # For image backgrounds

    def set_gradient_colors(self, colors):
        """Set gradient colors for the background"""
        self.gradient_colors = colors
        self.viewport().update()

    def set_background_image(self, image_path):
        """Set background image"""
        if image_path and os.path.isfile(image_path):
            self.background_image = image_path
        else:
            self.background_image = None
        self.viewport().update()

    def paintEvent(self, event):
        """Custom paint event to handle gradient/image backgrounds"""
        if self.gradient_colors or self.background_image:
            painter = QPainter(self.viewport())

            if self.gradient_colors:
                # Create and apply linear gradient
                gradient = QLinearGradient(0, 0, 0, self.viewport().height())
                num_colors = len(self.gradient_colors)
                for i, color in enumerate(self.gradient_colors):
                    position = i / (num_colors - 1) if num_colors > 1 else 0
                    gradient.setColorAt(position, QColor(color))

                painter.fillRect(self.viewport().rect(), gradient)

            elif self.background_image:
                # Load and draw background image
                try:
                    if os.path.isfile(self.background_image):
                        pixmap = QPixmap(self.background_image)
                        if not pixmap.isNull():
                            scaled_pixmap = pixmap.scaled(
                                self.viewport().size(),
                                Qt.KeepAspectRatioByExpanding,
                                Qt.SmoothTransformation
                            )
                            painter.drawPixmap(self.viewport().rect(), scaled_pixmap)
                        else:
                            # Image failed to load, clear the background image
                            self.background_image = None
                    else:
                        # File no longer exists, clear the background image
                        self.background_image = None
                except Exception:
                    # Any error loading the image, clear it to prevent future crashes
                    self.background_image = None

            painter.end()

        # Call parent paint event to draw text on top
        super().paintEvent(event)

    def wheelEvent(self, event):
        """Handle mouse wheel events to scroll by 4 rows at a time"""
        if self.editor is None:
            event.ignore()
            return

        # Get scroll direction from wheel delta
        delta = event.angleDelta().y()

        # Scroll by 4 rows
        rows_to_scroll = 4 if delta < 0 else -4
        self.editor.scroll_by_rows(rows_to_scroll)
        event.accept()

    def mousePressEvent(self, event):
        if event.button() == Qt.LeftButton:
            self.clicked.emit(event)
        elif event.button() == Qt.RightButton:
            self.rightClicked.emit(event)
        super().mousePressEvent(event)

    def mouseMoveEvent(self, event):
        self.hovered.emit(event)
        super().mouseMoveEvent(event)


class SmartPasteDialog(QDialog):
    """Dialog for handling paste size mismatches over selections"""

    def __init__(self, parent=None, paste_size=0, selection_size=0):
        super().__init__(parent)
        self.paste_size = paste_size
        self.selection_size = selection_size
        self.difference = paste_size - selection_size
        self.result = None  # Will be 'trim', 'pad', or 'ignore'
        self.padding_value = bytes([0x00])  # Default padding

        self.setWindowTitle("Smart Paste")
        self.setMinimumWidth(400)

        # Apply parent's theme stylesheet if available - use Light or Dark based on brightness
        if parent and hasattr(parent, 'current_theme'):
            if parent.is_dark_theme():
                base_theme_name = "Dark"
            else:
                base_theme_name = "Light"
            style = get_theme_stylesheet(base_theme_name)
            self.setStyleSheet(style)

        self.setup_ui()

    def setup_ui(self):
        layout = QVBoxLayout()
        layout.setSpacing(15)

        # Title
        title = QLabel("Paste Size Mismatch")
        title.setFont(QFont("Arial", 11, QFont.Bold))
        layout.addWidget(title)

        # Message based on difference
        if self.difference > 0:
            # Paste is larger
            message = QLabel(
                f"Paste is {abs(self.difference)} byte{'s' if abs(self.difference) > 1 else ''} longer than the selected range.\n"
                f"Paste size: {self.paste_size} bytes\n"
                f"Selection size: {self.selection_size} bytes"
            )
            message.setWordWrap(True)
            layout.addWidget(message)

            layout.addSpacing(10)

            # Options
            options_label = QLabel("Choose an option:")
            options_label.setFont(QFont("Arial", 9, QFont.Bold))
            layout.addWidget(options_label)

            self.trim_radio = QRadioButton("Trim: Remove end bytes to match selection length")
            self.trim_radio.setChecked(True)
            layout.addWidget(self.trim_radio)

            self.ignore_radio = QRadioButton("Ignore: Paste all bytes normally")
            layout.addWidget(self.ignore_radio)

        else:
            # Paste is smaller
            message = QLabel(
                f"Paste is {abs(self.difference)} byte{'s' if abs(self.difference) > 1 else ''} shorter than the selected range.\n"
                f"Paste size: {self.paste_size} bytes\n"
                f"Selection size: {self.selection_size} bytes"
            )
            message.setWordWrap(True)
            layout.addWidget(message)

            layout.addSpacing(10)

            # Checkbox for fill padding
            self.pad_checkbox = QCheckBox("Fill with padding")
            self.pad_checkbox.setChecked(False)  # Unchecked by default (ignore mode)
            self.pad_checkbox.toggled.connect(self.update_padding_controls)
            layout.addWidget(self.pad_checkbox)

            # Padding controls
            padding_container = QWidget()
            padding_layout = QVBoxLayout()
            padding_layout.setContentsMargins(20, 5, 0, 5)
            padding_layout.setSpacing(8)

            # Padding options
            padding_options_layout = QHBoxLayout()
            padding_options_layout.addWidget(QLabel("Padding:"))

            self.pad_00_radio = QRadioButton("0x00")
            self.pad_00_radio.setChecked(True)
            self.pad_00_radio.toggled.connect(self.update_custom_input)
            padding_options_layout.addWidget(self.pad_00_radio)

            self.pad_ff_radio = QRadioButton("0xFF")
            self.pad_ff_radio.toggled.connect(self.update_custom_input)
            padding_options_layout.addWidget(self.pad_ff_radio)

            self.pad_custom_radio = QRadioButton("Custom:")
            self.pad_custom_radio.toggled.connect(self.update_custom_input)
            padding_options_layout.addWidget(self.pad_custom_radio)

            self.custom_input = QLineEdit()
            self.custom_input.setPlaceholderText("00 FF or 00FF...")
            self.custom_input.setMaximumWidth(150)
            self.custom_input.setEnabled(False)
            padding_options_layout.addWidget(self.custom_input)

            padding_options_layout.addStretch()
            padding_layout.addLayout(padding_options_layout)

            help_text = QLabel("Custom pattern will loop until selection length is filled.")
            help_text.setStyleSheet("color: #888; font-size: 8pt; margin-left: 5px;")
            help_text.setWordWrap(True)
            padding_layout.addWidget(help_text)

            padding_container.setLayout(padding_layout)
            layout.addWidget(padding_container)
            self.padding_container = padding_container
            padding_container.setEnabled(False)  # Disabled by default since checkbox is unchecked

        layout.addSpacing(10)

        # OK and Cancel buttons
        button_layout = QHBoxLayout()
        button_layout.addStretch()

        ok_button = QPushButton("OK")
        ok_button.setMinimumWidth(80)
        ok_button.clicked.connect(self.accept_choice)
        button_layout.addWidget(ok_button)

        cancel_button = QPushButton("Cancel")
        cancel_button.setMinimumWidth(80)
        cancel_button.clicked.connect(self.reject)
        button_layout.addWidget(cancel_button)

        layout.addLayout(button_layout)
        self.setLayout(layout)

    def update_padding_controls(self):
        """Enable/disable padding controls based on checkbox"""
        if hasattr(self, 'padding_container'):
            enabled = self.pad_checkbox.isChecked() if hasattr(self, 'pad_checkbox') else False
            self.padding_container.setEnabled(enabled)

    def update_custom_input(self):
        """Enable/disable custom input based on selection"""
        if hasattr(self, 'custom_input'):
            self.custom_input.setEnabled(self.pad_custom_radio.isChecked())

    def accept_choice(self):
        """Process the user's choice and close the dialog"""
        if self.difference > 0:
            # Paste is larger
            if self.trim_radio.isChecked():
                self.result = 'trim'
            else:
                self.result = 'ignore'
        else:
            # Paste is smaller
            if self.pad_checkbox.isChecked():
                # Padding selected
                self.result = 'pad'

                # Determine padding value
                if self.pad_00_radio.isChecked():
                    self.padding_value = bytes([0x00])
                elif self.pad_ff_radio.isChecked():
                    self.padding_value = bytes([0xFF])
                else:
                    # Custom pattern
                    custom_text = self.custom_input.text().strip().replace(" ", "")
                    if not custom_text:
                        QMessageBox.warning(self, "Invalid Input", "Please enter a custom padding pattern.")
                        return

                    try:
                        # Parse hex pattern
                        if len(custom_text) % 2 != 0:
                            raise ValueError("Hex string must have even length")
                        self.padding_value = bytes.fromhex(custom_text)
                        if len(self.padding_value) == 0:
                            raise ValueError("Empty pattern")
                    except ValueError as e:
                        QMessageBox.warning(self, "Invalid Input", f"Invalid hex pattern: {e}")
                        return
            else:
                # Checkbox unchecked = ignore mode
                self.result = 'ignore'

        self.accept()

    def get_result(self):
        """Returns the choice and padding value if applicable"""
        return self.result, self.padding_value


class DelimiterConfigDialog(QDialog):
    """Dialog for configuring delimiter visibility"""

    def __init__(self, parent=None, current_delimiters=None):
        super().__init__(parent)
        self.setWindowTitle("Hide Delimiters Configuration")
        self.setMinimumSize(500, 400)
        self.delimiters = current_delimiters if current_delimiters else {}

        # Apply parent's theme stylesheet if available - use Light or Dark based on brightness
        if parent and hasattr(parent, 'current_theme'):
            if parent.is_dark_theme():
                base_theme_name = "Dark"
            else:
                base_theme_name = "Light"
            style = get_theme_stylesheet(base_theme_name)
            self.setStyleSheet(style)

        self.setup_ui()

    def setup_ui(self):
        layout = QVBoxLayout()

        # Title
        title = QLabel("Configure Delimiters to Hide")
        title.setFont(QFont("Arial", 11, QFont.Bold))
        layout.addWidget(title)

        # Help text
        help_text = QLabel(
            "Segment size determines pattern matching for consecutive delimiter bytes:\n"
            "• Size 1: Hides any single delimiter byte\n"
            "• Size 2: Hides \"XX XX\" patterns aligned to 2-byte boundaries\n"
            "• Size 4: Hides \"XX XX XX XX\" in columns [00-03][04-07][08-0B][0C-0F]\n"
            "• Size 8: Hides \"XX XX XX XX XX XX XX XX\" in columns [00-07][08-0F]"
        )
        help_text.setWordWrap(True)
        help_text.setStyleSheet("color: #888; font-size: 9pt; padding: 5px;")
        layout.addWidget(help_text)

        # Input section
        input_layout = QHBoxLayout()
        input_layout.addWidget(QLabel("Delimiter (hex):"))

        self.delimiter_input = QLineEdit()
        self.delimiter_input.setPlaceholderText("e.g., 00, FF, 0A")
        self.delimiter_input.returnPressed.connect(self.add_delimiter)
        input_layout.addWidget(self.delimiter_input)

        add_btn = QPushButton("Add")
        add_btn.clicked.connect(self.add_delimiter)
        input_layout.addWidget(add_btn)

        layout.addLayout(input_layout)

        # Quick-add dropdown
        quick_layout = QHBoxLayout()
        quick_layout.addWidget(QLabel("Quick add:"))

        self.quick_combo = QComboBox()
        self.quick_combo.addItems([
            "0x00 (Null)",
            "0xFF (Max byte)",
            "0x0A (Newline \\n)",
            "0x0D (Carriage return \\r)",
            "0x20 (Space)",
            "0x09 (Tab)"
        ])
        quick_layout.addWidget(self.quick_combo)

        quick_btn = QPushButton("Add Selected")
        quick_btn.clicked.connect(self.add_quick_delimiter)
        quick_layout.addWidget(quick_btn)

        quick_layout.addStretch()
        layout.addLayout(quick_layout)

        # Delimiter table
        self.table = QTableWidget()
        self.table.setColumnCount(3)
        self.table.setHorizontalHeaderLabels(["Delimiter (Hex)", "Segment Size", "Actions"])
        self.table.horizontalHeader().setStretchLastSection(False)
        self.table.horizontalHeader().setSectionResizeMode(0, QHeaderView.Stretch)
        self.table.horizontalHeader().setSectionResizeMode(1, QHeaderView.ResizeToContents)
        self.table.horizontalHeader().setSectionResizeMode(2, QHeaderView.ResizeToContents)
        self.table.setEditTriggers(QAbstractItemView.NoEditTriggers)
        layout.addWidget(self.table)

        # Buttons
        button_layout = QHBoxLayout()
        button_layout.addStretch()

        clear_btn = QPushButton("Clear All")
        clear_btn.clicked.connect(self.clear_all)
        button_layout.addWidget(clear_btn)

        cancel_btn = QPushButton("Cancel")
        cancel_btn.clicked.connect(self.reject)
        button_layout.addWidget(cancel_btn)

        ok_btn = QPushButton("OK")
        ok_btn.clicked.connect(self.accept)
        button_layout.addWidget(ok_btn)

        layout.addLayout(button_layout)

        self.setLayout(layout)

        # Populate table with existing delimiters
        self.refresh_table()

    def add_delimiter(self):
        """Add a delimiter from the input field"""
        text = self.delimiter_input.text().strip().upper()
        if not text:
            return

        # Remove "0x" prefix if present
        if text.startswith("0X"):
            text = text[2:]

        # Validate hex
        try:
            value = int(text, 16)
            if 0 <= value <= 255:
                if value not in self.delimiters:
                    self.delimiters[value] = 4  # Default segment size is 4
                    self.refresh_table()
                self.delimiter_input.clear()
            else:
                QMessageBox.warning(self, "Invalid Value", "Value must be between 0x00 and 0xFF")
        except ValueError:
            QMessageBox.warning(self, "Invalid Input", "Please enter a valid hexadecimal value")

    def add_quick_delimiter(self):
        """Add a delimiter from the quick-add dropdown"""
        text = self.quick_combo.currentText()
        hex_part = text.split()[0]  # Get "0x00" part
        value = int(hex_part, 16)

        if value not in self.delimiters:
            self.delimiters[value] = 4  # Default segment size is 4
            self.refresh_table()

    def remove_delimiter(self, value):
        """Remove a delimiter"""
        if value in self.delimiters:
            del self.delimiters[value]
            self.refresh_table()

    def clear_all(self):
        """Clear all delimiters"""
        self.delimiters.clear()
        self.refresh_table()

    def update_padding(self, value, new_padding):
        """Update padding for a delimiter"""
        if value in self.delimiters:
            self.delimiters[value] = new_padding

    def refresh_table(self):
        """Refresh the table with current delimiters"""
        self.table.setRowCount(len(self.delimiters))

        for row, value in enumerate(sorted(self.delimiters.keys())):
            # Delimiter value
            item = QTableWidgetItem(f"0x{value:02X}")
            item.setFont(QFont("Courier", 10))
            self.table.setItem(row, 0, item)

            # Segment size combo box (only 1, 2, 4, 8)
            size_combo = QComboBox()
            size_combo.addItems(["1", "2", "4", "8"])
            current_size = self.delimiters[value]
            if str(current_size) in ["1", "2", "4", "8"]:
                size_combo.setCurrentText(str(current_size))
            else:
                size_combo.setCurrentText("4")  # Default to 4
            size_combo.currentTextChanged.connect(lambda text, v=value: self.update_padding(v, int(text)))
            self.table.setCellWidget(row, 1, size_combo)

            # Remove button
            remove_btn = QPushButton("Remove")
            remove_btn.clicked.connect(lambda checked, v=value: self.remove_delimiter(v))
            self.table.setCellWidget(row, 2, remove_btn)

    def get_delimiters(self):
        """Get the configured delimiters"""
        return self.delimiters


class SegmentOverlay(QWidget):
    """Overlay widget that draws vertical segment lines over the hex display"""
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setAttribute(Qt.WA_TransparentForMouseEvents)
        self.setAttribute(Qt.WA_TranslucentBackground)
        self.segment_size = 0
        self.line_color = QColor("#555555")
        self.char_width = 10
        self.leading_spaces = 2
        self.spacing_multiplier = 1.0  # Double spacing for 1440p+ monitors
        self.padding_offset = 4  # Left padding from hex_display stylesheet

        # Install event filter on parent to catch resize events
        if parent:
            parent.installEventFilter(self)

    def eventFilter(self, obj, event):
        """Catch parent resize events and update geometry"""
        if event.type() == event.Resize and obj == self.parent():
            self.setGeometry(0, 0, self.parent().width(), self.parent().height())
        return super().eventFilter(obj, event)

    def set_segment_size(self, size):
        """Set the segment size (0 = no lines, 1, 2, 4, 8)"""
        self.segment_size = size
        self.raise_()
        self.update()

    def set_line_color(self, color):
        """Set the color for segment lines"""
        self.line_color = QColor(color)
        self.raise_()
        self.update()

    def set_char_width(self, width):
        """Set the character width for positioning"""
        self.char_width = width
        self.raise_()
        self.update()

    def set_leading_spaces(self, spaces):
        """Set the leading spaces for positioning"""
        self.leading_spaces = spaces
        self.raise_()
        self.update()

    def set_spacing_multiplier(self, multiplier):
        """Set the spacing multiplier (2.0 for 1440p+, 1.0 for lower)"""
        self.spacing_multiplier = multiplier
        self.raise_()
        self.update()

    def paintEvent(self, event):
        """Draw vertical segment lines"""
        if self.segment_size == 0:
            return

        painter = QPainter(self)
        painter.setRenderHint(QPainter.Antialiasing, False)

        # Use a bold grey line
        pen = QPen(self.line_color)
        pen.setWidth(2)
        painter.setPen(pen)

        # Calculate positions for segment lines
        # Each hex byte takes 3 characters: "XX "
        bytes_per_char = 3

        # Draw lines at segment boundaries
        for segment in range(1, 16 // self.segment_size):
            # Position after N segments
            byte_pos = segment * self.segment_size
            # Calculate x position: padding + leading spaces + (byte_pos * 3 chars per byte)
            # Use round() instead of int() for better precision on high-DPI displays
            base_x = self.padding_offset + self.leading_spaces * self.char_width + byte_pos * bytes_per_char * self.char_width
            # Add extra spacing for 1440p+ monitors
            extra_spacing = -4.0
            x = round(base_x + extra_spacing)

            # Debug output
            if segment == 1:  # Only print for first line to avoid spam
                print(f"Segment line debug: segment_size={self.segment_size}, segment={segment}, byte_pos={byte_pos}")
                print(f"  char_width={self.char_width}, leading_spaces={self.leading_spaces}")
                print(f"  base_x={base_x}, extra_spacing={extra_spacing}, final_x={x}")
                print(f"  overlay width={self.width()}, spacing_multiplier={self.spacing_multiplier}")

            # Draw line from top to bottom
            painter.drawLine(x, 0, x, self.height())



class EditBoxOverlay(QWidget):
    """Overlay widget to draw an edit box around highlighted bytes during typing"""
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setAttribute(Qt.WA_TransparentForMouseEvents)
        self.setAttribute(Qt.WA_TranslucentBackground)
        self.setStyleSheet("background: transparent;")
        self.edit_box_rect = None  # QRect for the edit box
        self.theme_colors = {}
        self.visible_box = False

    def set_edit_box(self, rect):
        """Set the rectangle for the edit box"""
        self.edit_box_rect = rect
        self.visible_box = rect is not None
        self.update()

    def clear_edit_box(self):
        """Clear the edit box"""
        self.edit_box_rect = None
        self.visible_box = False
        self.update()

    def set_theme_colors(self, colors):
        """Set theme colors for drawing"""
        self.theme_colors = colors

    def paintEvent(self, event):
        """Draw the edit box"""
        if not self.visible_box or self.edit_box_rect is None:
            return

        painter = QPainter(self)
        painter.setRenderHint(QPainter.Antialiasing)

        # Get border color from theme
        border_color = QColor(self.theme_colors.get('button_bg', '#0e639c'))
        border_color.setAlpha(255)

        # Draw thick border around edit box
        pen = QPen(border_color, 3, Qt.SolidLine)
        painter.setPen(pen)
        painter.setBrush(Qt.NoBrush)
        painter.drawRect(self.edit_box_rect)

        # Draw semi-transparent fill
        fill_color = QColor(self.theme_colors.get('selection_bg', '#264f78'))
        fill_color.setAlpha(30)
        painter.fillRect(self.edit_box_rect, fill_color)


class BoundaryOverlay(QWidget):
    """Overlay widget to draw vertical lines at column boundaries"""
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setAttribute(Qt.WA_TransparentForMouseEvents)
        self.setAttribute(Qt.WA_TranslucentBackground)
        self.setStyleSheet("background: transparent;")
        self.boundary_enabled = False
        self.boundary_start_col = 0
        self.boundary_end_col = 15
        self.theme_colors = {}
        self.char_width = 10
        self.padding_offset = 0
        self.leading_spaces = 0
        self.bytes_per_row = 16

    def set_boundaries(self, enabled, start_col, end_col):
        """Set boundary columns"""
        self.boundary_enabled = enabled
        self.boundary_start_col = start_col
        self.boundary_end_col = end_col
        self.update()

    def set_display_params(self, char_width, padding_offset, leading_spaces, bytes_per_row):
        """Set display parameters for calculating line positions"""
        self.char_width = char_width
        self.padding_offset = padding_offset
        self.leading_spaces = leading_spaces
        self.bytes_per_row = bytes_per_row
        self.update()

    def set_theme_colors(self, colors):
        """Set theme colors for drawing"""
        self.theme_colors = colors
        self.update()

    def paintEvent(self, event):
        """Draw boundary lines"""
        if not self.boundary_enabled:
            return

        painter = QPainter(self)
        painter.setRenderHint(QPainter.Antialiasing)

        # Use same color as edit box border
        border_color = QColor(self.theme_colors.get('button_bg', '#0e639c'))
        border_color.setAlpha(255)

        pen = QPen(border_color, 3, Qt.SolidLine)
        painter.setPen(pen)

        # Calculate x positions for boundary lines
        # Each hex byte takes 3 characters: "XX "
        bytes_per_char = 3

        # Draw line at start boundary (left side of start column) only if not at column 0
        if self.boundary_start_col > 0:
            base_x = self.padding_offset + self.leading_spaces * self.char_width + self.boundary_start_col * bytes_per_char * self.char_width
            x = round(base_x - 4.0)  # Adjust spacing
            painter.drawLine(x, 0, x, self.height())

        # Draw line at end boundary (right side of end column) only if not at column 0x0F (15)
        if self.boundary_end_col < 15:
            base_x = self.padding_offset + self.leading_spaces * self.char_width + (self.boundary_end_col + 1) * bytes_per_char * self.char_width
            x = round(base_x - 4.0)  # Adjust spacing
            painter.drawLine(x, 0, x, self.height())


class GradientWidget(QWidget):
    """Custom widget that supports gradient backgrounds"""
    def __init__(self, parent=None):
        super().__init__(parent)
        self.gradient_colors = None
        self.background_image = None

    def set_gradient_colors(self, colors):
        """Set gradient colors for the background"""
        self.gradient_colors = colors
        self.update()

    def set_background_image(self, image_path):
        """Set background image"""
        if image_path and os.path.isfile(image_path):
            self.background_image = image_path
        else:
            self.background_image = None
        self.update()

    def paintEvent(self, event):
        """Custom paint event to handle gradient/image backgrounds"""
        super().paintEvent(event)

        if self.gradient_colors or self.background_image:
            painter = QPainter(self)

            if self.gradient_colors:
                # Create and apply linear gradient
                gradient = QLinearGradient(0, 0, 0, self.height())
                num_colors = len(self.gradient_colors)
                for i, color in enumerate(self.gradient_colors):
                    position = i / (num_colors - 1) if num_colors > 1 else 0
                    gradient.setColorAt(position, QColor(color))

                painter.fillRect(self.rect(), gradient)

            elif self.background_image:
                # Load and draw background image
                try:
                    if os.path.isfile(self.background_image):
                        pixmap = QPixmap(self.background_image)
                        if not pixmap.isNull():
                            scaled_pixmap = pixmap.scaled(
                                self.size(),
                                Qt.KeepAspectRatioByExpanding,
                                Qt.SmoothTransformation
                            )
                            painter.drawPixmap(self.rect(), scaled_pixmap)
                        else:
                            self.background_image = None
                    else:
                        self.background_image = None
                except Exception:
                    self.background_image = None

            painter.end()


class DebugOutputRedirector:
    def __init__(self, text_widget):
        self.text_widget = text_widget
        self.buffer = []

    def write(self, text):
        if text and text.strip():
            self.buffer.append(text)
            QMetaObject.invokeMethod(
                self.text_widget,
                "append",
                Qt.QueuedConnection,
                Q_ARG(str, text.rstrip())
            )

    def flush(self):
        pass


class DebugWindow(QDialog):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setWindowTitle("Debugging Console")
        self.setMinimumSize(800, 600)
        self.parent_editor = parent

        layout = QVBoxLayout()
        layout.setContentsMargins(10, 10, 10, 10)
        layout.setSpacing(10)

        title_label = QLabel("Terminal Output")
        title_label.setFont(QFont("Arial", 12, QFont.Bold))
        title_label.setAlignment(Qt.AlignCenter)
        layout.addWidget(title_label)

        self.output_text = QTextEdit()
        self.output_text.setReadOnly(True)
        self.output_text.setFont(QFont("Courier", 9))
        layout.addWidget(self.output_text)

        button_layout = QHBoxLayout()

        copy_button = QPushButton("Copy All")
        copy_button.clicked.connect(self.copy_all)
        button_layout.addWidget(copy_button)

        clear_button = QPushButton("Clear")
        clear_button.clicked.connect(self.clear_output)
        button_layout.addWidget(clear_button)

        button_layout.addStretch()

        close_button = QPushButton("Close")
        close_button.clicked.connect(self.close)
        button_layout.addWidget(close_button)

        layout.addLayout(button_layout)
        self.setLayout(layout)

        if parent and hasattr(parent, 'current_theme'):
            self.setStyleSheet(get_theme_stylesheet(parent.current_theme))

    def copy_all(self):
        clipboard = QApplication.clipboard()
        clipboard.setText(self.output_text.toPlainText())

    def clear_output(self):
        self.output_text.clear()

    def append_text(self, text):
        self.output_text.append(text.rstrip())
        scrollbar = self.output_text.verticalScrollBar()
        scrollbar.setValue(scrollbar.maximum())


class HexEditorQt(QMainWindow):
    """
    Main hex editor application window.

    This is the primary class that orchestrates the entire hex editor application.
    It manages the UI, file operations, editing functionality, and coordinates
    between all sub-components.

    Core Features:
    --------------
    File Management:
    - Multi-file tabs with independent state
    - Memory-mapped I/O for large files (>100MB)
    - Save/Save As/Export functionality
    - Recent files tracking
    - File comparison tool

    Editing:
    - Hex and ASCII editing modes
    - Insert/Overwrite modes
    - Undo/Redo with state snapshots
    - Copy/Paste with multiple formats (hex, C array, etc.)
    - Column selection mode
    - Smart paste with delimiter configuration
    - Find & Replace (hex patterns, ASCII, UTF-16, regex)

    Visualization:
    - Hex + ASCII side-by-side display
    - Configurable bytes per row (8, 16, 32, 64)
    - Virtual scrolling for large files
    - Syntax highlighting for modified/inserted bytes
    - Customizable themes with gradient backgrounds
    - Signature pointer overlays

    Analysis Tools:
    - Pattern scanner (strings, pointers, file signatures)
    - Data inspector (interpret bytes as various types)
    - Statistics (byte frequency, entropy)
    - Byte distribution visualization
    - Signature tracking with custom data types

    UI Components:
    - Tab widget for multiple files
    - Hex display (HexTextEdit)
    - Right panel with tabs: Pattern Scan, Signatures, Data Inspector, Statistics
    - Status bar with offset/size info
    - Menubar with File/Edit/View/Tools/Help
    - Toolbar with common actions

    Architecture:
    -------------
    The class follows a coordinator pattern where:
    - HexEditorQt manages overall state and UI
    - FileTab instances store per-file data
    - Specialized widgets (PatternScanWidget, SignatureWidget, DataInspector,
      StatisticsWidget) handle specific features
    - HexTextEdit renders the hex display with virtual scrolling

    Key Methods:
    - open_file(): Load a file into a new tab
    - display_hex(): Render hex+ASCII display (virtual scrolling for large files)
    - save_file(): Write changes back to disk
    - handle_key_press(): Process keyboard input for editing
    - update_data_inspector(): Refresh data inspector at cursor
    - scroll_to_offset(): Navigate to specific byte offset

    Attributes:
        open_files (list[FileTab]): List of open file tabs
        current_tab_index (int): Index of currently active tab
        cursor_position (int): Current cursor byte offset
        cursor_nibble (int): Which nibble of byte is selected (0 or 1)
        selection_start (int): Start offset of selection
        selection_end (int): End offset of selection
        undo_stack (list): Stack of previous file states
        redo_stack (list): Stack of undone file states
        bytes_per_row (int): Number of bytes per row (default 16)
        endian_mode (str): 'little' or 'big' endian for multi-byte values
        current_theme (str): Name of active color theme
        hex_display (HexTextEdit): Main hex display widget
        pattern_scan_widget (PatternScanWidget): Pattern scanning panel
        signature_widget (SignatureWidget): Signature pointer panel
        data_inspector (DataInspector): Data interpretation panel
        statistics_widget (StatisticsWidget): Statistics panel
    """
    def __init__(self):
        super().__init__()
        self.open_files = []
        self.current_tab_index = -1
        self.cursor_position = None
        self.cursor_nibble = 0
        self.selection_start = None
        self.selection_end = None
        self.column_selection_mode = False  # Track if we're in column selection mode
        self.column_sel_start_row = None  # Starting row for column selection
        self.column_sel_start_col = None  # Starting column for column selection
        self.column_sel_end_row = None    # Ending row for column selection
        self.column_sel_end_col = None    # Ending column for column selection
        self.clipboard = None
        self.clipboard_grid_rows = None  # Number of rows if clipboard data is from column selection
        self.clipboard_grid_cols = None  # Number of columns if clipboard data is from column selection
        self.endian_mode = 'little'
        self.integral_basis = 'dec'  # 'hex', 'dec', or 'oct'
        self.undo_stack = []
        self.redo_stack = []

        # Version control snapshot timer (shared across all files)
        self.snapshot_timer = QTimer(self)
        self.snapshot_timer.setSingleShot(True)
        self.snapshot_timer.timeout.connect(self.create_snapshot)
        self.current_theme = self.load_theme_preference()
        self.notes_window = None
        self.debug_window = None
        self.debug_redirector = None
        self.original_stdout = sys.stdout
        self.original_stderr = sys.stderr
        self.bytes_per_row = 16
        self.offset_mode = 'h'  # 'h' for hex, 'd' for decimal, 'o' for octal
        self._last_inspector_pos = None
        self.auxiliary_windows = []  # Track all open auxiliary windows
        self.ignore_file_size_warnings = False  # Flag to suppress file size change warnings
        self.pattern_result_to_update = None  # Track pattern result for color box update
        self.hidden_delimiters = {}  # Dict of byte values to padding: {byte_value: padding}

        # Chunked rendering for large files
        self.max_initial_rows = 200  # Only render 200 rows initially
        self.rendered_start_byte = 0  # Track what's currently rendered
        self.rendered_end_byte = 0
        self.current_top_row = 0  # Track the logical top row being viewed

        # Scroll debounce timer to prevent lag during scrolling
        self.scroll_timer = QTimer(self)
        self.scroll_timer.setSingleShot(True)
        self.scroll_timer.timeout.connect(self.on_scroll_stopped)
        self.pending_scroll_position = None

        # Flag to prevent feedback loop during nav scrollbar dragging
        self.in_nav_scroll = False

        # Signature pointer overlays
        self.signature_overlays = []  # List of QLabel widgets for signature value overlays
        self.screen_change_connected = False  # Track if we've connected the screen change signal

        # Extended ASCII display option (128-255)
        self.show_extended_ascii = True  # Always show extended ASCII (128-255)

        # Edit box feature
        self.edit_box_active = False
        self.edit_box_start = None
        self.edit_box_end = None
        self.edit_box_start_row = None
        self.edit_box_start_col = None
        self.edit_box_end_row = None
        self.edit_box_end_col = None

        # Segment boundaries feature
        self.boundary_enabled = False
        self.boundary_start_col = 0
        self.boundary_end_col = 15

        # Segment separator (0 = none, 1, 2, 4, 8 = draw lines between segments)
        self.segment_size = 0

        # Load all saved settings (theme, segment size, etc.)
        self.load_settings()

        self.setup_ui()
        self.apply_theme()

    def is_high_res_screen(self):
        """Check if the current screen is 1440p or higher."""
        screen = self.screen()
        if screen:
            screen_geometry = screen.availableGeometry()
            screen_height = screen_geometry.height()
            screen_width = screen_geometry.width()
            print(f"Monitor Detection - Screen: {screen.name()}, Resolution: {screen_width}x{screen_height}")
            return screen_height >= 1400
        print("Monitor Detection - No screen detected, defaulting to low-res")
        return False  # Default to low res if no screen detected

    def get_hex_column_width(self):
        """Calculate appropriate hex column width based on screen resolution."""
        # ONLY use the screen that THIS window is currently on
        screen = self.screen()
        if screen:
            screen_geometry = screen.availableGeometry()
            screen_height = screen_geometry.height()

            # Debug output
            print(f"Window is on screen: {screen.name()}, height: {screen_height}")

            # Use screen HEIGHT to determine resolution
            # 1440p = 1440 height, 1080p = 1080 height
            if screen_height >= 1400:
                print("Using 615px width for 1440p+")
                return 615
            elif screen_height <= 1100:
                print("Using 415px width for 1080p")
                return 415
            else:
                # Linear interpolation between 1100 and 1400
                ratio = (screen_height - 1100) / (1400 - 1100)
                width = int(415 + (200 * ratio))
                print(f"Using {width}px width for intermediate resolution")
                return width
        print("No screen detected, using default 615px width")
        return 615  # Default fallback

    def on_screen_changed(self, screen):
        """Handle window moving to a different screen."""
        print(f"Screen changed to: {screen.name() if screen else 'None'}")

        # Recalculate hex column width for the new screen
        new_width = self.get_hex_column_width()

        # Calculate spacing multiplier based on screen resolution
        spacing_mult = 1.0
        if screen:
            screen_height = screen.availableGeometry().height()
            if screen_height >= 1400:
                spacing_mult = 2.0
                print(f"Setting spacing_mult to 2.0 for 1440p+ screen (height={screen_height})")
            else:
                print(f"Setting spacing_mult to 1.0 for lower res screen (height={screen_height})")

        # Update segment overlays with new font metrics and spacing
        if hasattr(self, 'segment_overlay') and hasattr(self, 'hex_display'):
            font_metrics = QFontMetrics(self.hex_display.font())
            char_width = font_metrics.horizontalAdvance('0')
            self.segment_overlay.set_char_width(char_width)
            self.segment_overlay.set_spacing_multiplier(spacing_mult)
            self.segment_overlay.update()
            print(f"Updated segment_overlay: char_width={char_width}, spacing_mult={spacing_mult}")

        if hasattr(self, 'header_segment_overlay') and hasattr(self, 'hex_header'):
            header_font_metrics = QFontMetrics(self.hex_header.font())
            header_char_width = header_font_metrics.horizontalAdvance('0')
            self.header_segment_overlay.set_char_width(header_char_width)
            self.header_segment_overlay.set_spacing_multiplier(spacing_mult)
            self.header_segment_overlay.update()
            print(f"Updated header_segment_overlay: char_width={header_char_width}, spacing_mult={spacing_mult}")

        # Update boundary overlay with current display parameters
        if hasattr(self, 'boundary_overlay') and hasattr(self, 'hex_display'):
            font_metrics = QFontMetrics(self.hex_display.font())
            char_width = font_metrics.horizontalAdvance('0')
            # Use same padding as SegmentOverlay (4) for alignment
            padding_offset = 4
            leading_spaces = 2
            self.boundary_overlay.set_display_params(char_width, padding_offset, leading_spaces, self.bytes_per_row)
            self.boundary_overlay.set_boundaries(self.boundary_enabled, self.boundary_start_col, self.boundary_end_col)
            self.boundary_overlay.update()

        # Update if the width changed
        if new_width != self.hex_column_width:
            self.hex_column_width = new_width
            print(f"Updating hex column width to: {new_width}px")

            # Update the hex header and display widths
            self.hex_header.setMinimumWidth(self.hex_column_width)
            self.hex_header.setMaximumWidth(self.hex_column_width)
            self.hex_display.setMinimumWidth(self.hex_column_width)
            self.hex_display.setMaximumWidth(self.hex_column_width)

            # Update overlay geometries
            if hasattr(self, 'segment_overlay'):
                self.segment_overlay.setGeometry(0, 0, self.hex_column_width, self.hex_display.height())
            if hasattr(self, 'header_segment_overlay'):
                self.header_segment_overlay.setGeometry(0, 0, self.hex_column_width, self.hex_header.height())
            if hasattr(self, 'edit_box_overlay'):
                self.edit_box_overlay.setGeometry(0, 0, self.hex_column_width, self.hex_display.height())
            if hasattr(self, 'boundary_overlay'):
                self.boundary_overlay.setGeometry(0, 0, self.hex_column_width, self.hex_display.height())

            # Update search results overlay if it exists
            if hasattr(self, 'results_overlay') and self.results_overlay is not None:
                overlay_height = 200
                x_start = 130
                y_position = self.hex_ascii_container.height() - overlay_height
                # Calculate width within hex_ascii_container
                overlay_width = self.hex_ascii_container.width() - x_start
                self.results_overlay.setGeometry(x_start, y_position, overlay_width, overlay_height)

        # Recalculate window width for the new screen
        if screen and not self.isMaximized():
            screen_geometry = screen.availableGeometry()
            screen_height = screen_geometry.height()

            # Default is 1200, increase by 400 for 1440p+
            new_window_width = 1200
            if screen_height >= 1400:
                new_window_width = 1600

            # Only resize if width changed
            if self.width() != new_window_width:
                print(f"Updating window width to: {new_window_width}px")
                self.resize(new_window_width, self.height())

    def build_hex_header(self):
        """Build hex header string"""
        # Define byte labels for each mode
        byte_labels = {
            'h': [f"{i:02X}" for i in range(16)],
            'd': [f"{i:02d}" for i in range(16)],
            'o': [f"{i:02o}" for i in range(16)]
        }

        labels = byte_labels.get(self.offset_mode, byte_labels['h'])
        header = "  "  # Leading spaces to align with data

        for i, label in enumerate(labels):
            header += label + " "

        return header.rstrip()

    def setup_ui(self):
        self.setWindowTitle("RxD Hex Editor")

        # Calculate hex column width based on screen resolution
        self.hex_column_width = self.get_hex_column_width()

        # Set default size but allow resizing
        # Detect screen resolution and adjust width based on monitor
        self.update_window_size_for_screen()
        self.setMinimumSize(500, 200)  # Minimum usable size

        # Enable drag and drop
        self.setAcceptDrops(True)

        self.create_menus()

        central_widget = GradientWidget()
        self.setCentralWidget(central_widget)
        self.central_widget = central_widget  # Store reference for gradient application
        main_layout = QVBoxLayout()
        main_layout.setContentsMargins(0, 0, 0, 0)
        main_layout.setSpacing(0)

        # Tab widget for files
        self.tab_widget = QTabWidget()
        self.tab_widget.setTabsClosable(True)
        self.tab_widget.tabCloseRequested.connect(self.close_tab)
        self.tab_widget.currentChanged.connect(self.on_tab_changed)
        # Set file tab font
        tab_font = QFont("Arial", 10)
        self.tab_widget.setFont(tab_font)

        # Add scroll buttons to the left side of tab bar
        tab_scroll_widget = QWidget()
        tab_scroll_layout = QHBoxLayout()
        tab_scroll_layout.setContentsMargins(0, 0, 5, 0)
        tab_scroll_layout.setSpacing(2)

        self.tab_scroll_left_btn = QPushButton("<")
        self.tab_scroll_left_btn.setMinimumWidth(40)
        self.tab_scroll_left_btn.setMaximumWidth(40)
        self.tab_scroll_left_btn.setMaximumHeight(42)
        self.tab_scroll_left_btn.clicked.connect(self.scroll_tabs_left)
        tab_scroll_layout.addWidget(self.tab_scroll_left_btn)

        self.tab_scroll_right_btn = QPushButton(">")
        self.tab_scroll_right_btn.setMinimumWidth(40)
        self.tab_scroll_right_btn.setMaximumWidth(40)
        self.tab_scroll_right_btn.setMaximumHeight(42)
        self.tab_scroll_right_btn.clicked.connect(self.scroll_tabs_right)
        tab_scroll_layout.addWidget(self.tab_scroll_right_btn)

        tab_scroll_widget.setLayout(tab_scroll_layout)
        self.tab_widget.setCornerWidget(tab_scroll_widget, Qt.TopLeftCorner)

        # Remove any spacing/margins from tab widget
        self.tab_widget.setContentsMargins(0, 0, 0, 0)

        main_layout.addWidget(self.tab_widget, stretch=0)

        # Main content splitter
        content_splitter = QSplitter(Qt.Horizontal)
        content_splitter.setChildrenCollapsible(False)
        content_splitter.setHandleWidth(0)  # Hide splitter handle since overlay has its own resize handle
        content_splitter.setStyleSheet("QSplitter::handle { background: transparent; width: 0px; }")  # Completely hide handle
        self.content_splitter = content_splitter  # Store reference to prevent resizing

        # Left side: Hex display
        hex_widget = QWidget()
        hex_main_layout = QVBoxLayout()
        hex_main_layout.setContentsMargins(0, 0, 0, 0)
        hex_main_layout.setSpacing(0)

        # Get theme colors for borders and grid lines
        theme_colors = get_theme_colors(self.current_theme)
        grid_line_color = theme_colors.get('grid_line', theme_colors['border'])

        # Header row - wrap in widget with top and bottom border
        header_widget = QWidget()
        header_widget.setStyleSheet(f"border-top: 2px solid {grid_line_color}; border-bottom: 1px solid {grid_line_color}; padding-top: 4px;")
        header_widget.setSizePolicy(QSizePolicy.Fixed, QSizePolicy.Preferred)
        header_layout = QHBoxLayout()
        header_layout.setContentsMargins(0, 0, 0, 0)
        header_layout.setSpacing(0)

        # Offset header (clickable to cycle modes)
        self.offset_header = QLabel("Offset (h)")
        self.offset_header.setFont(QFont("Courier", 9, QFont.Bold))
        self.offset_header.setMinimumWidth(130)
        self.offset_header.setMaximumWidth(130)
        self.offset_header.setAlignment(Qt.AlignCenter)
        self.offset_header.setStyleSheet(f"border-right: 2px solid {grid_line_color}; border-bottom: 1px solid {grid_line_color}; cursor: pointer; padding: 4px 2px; margin: 0px;")
        self.offset_header.mousePressEvent = self.cycle_offset_mode
        self.offset_header.setSizePolicy(QSizePolicy.Fixed, QSizePolicy.Preferred)
        self.offset_header.setContentsMargins(0, 0, 0, 0)
        header_layout.addWidget(self.offset_header)

        # Create a combined container for hex and ASCII headers
        hex_ascii_header_combined = QWidget()
        hex_ascii_header_combined_layout = QHBoxLayout()
        hex_ascii_header_combined_layout.setContentsMargins(0, 0, 0, 0)
        hex_ascii_header_combined_layout.setSpacing(0)
        hex_ascii_header_combined.setSizePolicy(QSizePolicy.Fixed, QSizePolicy.Preferred)

        # Hex column header (00 01 02 ... 0F)
        self.hex_header = QLabel(self.build_hex_header())
        self.hex_header.setFont(QFont("Courier", 9))
        self.hex_header.setMinimumWidth(self.hex_column_width)
        self.hex_header.setMaximumWidth(self.hex_column_width)
        self.hex_header.setAlignment(Qt.AlignLeft | Qt.AlignVCenter)
        self.hex_header.setStyleSheet(f"border-right: 1px solid {grid_line_color}; border-bottom: 1px solid {grid_line_color}; padding: 4px 0px 4px 4px; margin: 0px;")
        self.hex_header.setSizePolicy(QSizePolicy.Fixed, QSizePolicy.Preferred)
        self.hex_header.setContentsMargins(0, 0, 0, 0)
        hex_ascii_header_combined_layout.addWidget(self.hex_header)

        # Create segment overlay for hex header
        self.header_segment_overlay = SegmentOverlay(self.hex_header)
        self.header_segment_overlay.setGeometry(0, 0, self.hex_column_width, self.hex_header.height())
        self.header_segment_overlay.set_segment_size(self.segment_size)
        # Calculate character width from font
        header_font_metrics = QFontMetrics(self.hex_header.font())
        header_char_width = header_font_metrics.horizontalAdvance('0')
        self.header_segment_overlay.set_char_width(header_char_width)
        # Set spacing multiplier based on screen resolution
        spacing_mult = 1.0
        screen = self.screen()
        if screen:
            screen_height = screen.availableGeometry().height()
            if screen_height >= 1400:
                spacing_mult = 2.0
        self.header_segment_overlay.set_spacing_multiplier(spacing_mult)
        self.header_segment_overlay.show()

        # ASCII header fixed next to hex
        self.ascii_header = QLabel("Decoded Text")
        self.ascii_header.setFont(QFont("Courier", 9))
        self.ascii_header.setMinimumWidth(250)
        self.ascii_header.setMaximumWidth(250)
        self.ascii_header.setAlignment(Qt.AlignLeft)
        self.ascii_header.setStyleSheet(f"border-left: 2px solid {grid_line_color}; border-right: 1px solid {grid_line_color}; border-bottom: 1px solid {grid_line_color}; padding: 4px 0px 4px 4px; margin: 0px;")
        self.ascii_header.setSizePolicy(QSizePolicy.Fixed, QSizePolicy.Fixed)
        self.ascii_header.setContentsMargins(2, 0, 2, 0)
        hex_ascii_header_combined_layout.addWidget(self.ascii_header)

        hex_ascii_header_combined.setLayout(hex_ascii_header_combined_layout)
        header_layout.addWidget(hex_ascii_header_combined)

        header_widget.setLayout(header_layout)
        self.hex_header_widget = header_widget  # Store reference for positioning
        hex_main_layout.addWidget(header_widget)

        # Data display row - wrap in a container widget for overlay positioning
        self.hex_ascii_container = QWidget()
        self.hex_ascii_container.setSizePolicy(QSizePolicy.Fixed, QSizePolicy.Expanding)
        hex_layout = QHBoxLayout()
        hex_layout.setContentsMargins(0, 0, 0, 0)
        hex_layout.setSpacing(0)

        # Offset column
        self.offset_display = HexTextEdit()
        self.offset_display.editor = self  # Set reference to parent editor
        self.offset_display.setFixedWidth(130)  # Match header width exactly
        self.offset_display.setVerticalScrollBarPolicy(Qt.ScrollBarAlwaysOff)
        self.offset_display.setStyleSheet(f"border-right: 2px solid {grid_line_color}; padding: 2px;")
        self.offset_display.setAlignment(Qt.AlignCenter)
        self.offset_display.setSizePolicy(QSizePolicy.Fixed, QSizePolicy.Expanding)
        self.offset_display.clicked.connect(self.on_offset_click)
        hex_layout.addWidget(self.offset_display)

        # Hex column
        self.hex_display = HexTextEdit()
        self.hex_display.editor = self  # Set reference to parent editor
        self.hex_display.setVerticalScrollBarPolicy(Qt.ScrollBarAlwaysOff)
        self.hex_display.setLineWrapMode(QTextEdit.NoWrap)
        self.hex_display.setMinimumWidth(self.hex_column_width)
        self.hex_display.setMaximumWidth(self.hex_column_width)
        self.hex_display.clicked.connect(self.on_hex_click)
        self.hex_display.rightClicked.connect(self.on_hex_right_click)
        self.hex_display.hovered.connect(self.on_hex_hover)
        self.hex_display.setFocusPolicy(Qt.StrongFocus)
        self.hex_display.setStyleSheet(f"border-right: 1px solid {grid_line_color}; padding: 2px 0px 2px 4px;")
        self.hex_display.setSizePolicy(QSizePolicy.Fixed, QSizePolicy.Expanding)
        self.hex_display.setTextInteractionFlags(Qt.NoTextInteraction)  # Disable native text selection
        self.hex_display.verticalScrollBar().valueChanged.connect(self.on_scroll)
        hex_layout.addWidget(self.hex_display)

        # Create segment overlay for hex display
        self.segment_overlay = SegmentOverlay(self.hex_display)
        self.segment_overlay.setGeometry(0, 0, self.hex_column_width, self.hex_display.height())
        self.segment_overlay.set_segment_size(self.segment_size)
        # Calculate character width from font
        font_metrics = QFontMetrics(self.hex_display.font())
        char_width = font_metrics.horizontalAdvance('0')
        self.segment_overlay.set_char_width(char_width)
        # Set spacing multiplier based on screen resolution
        spacing_mult = 1.0
        screen = self.screen()
        if screen:
            screen_height = screen.availableGeometry().height()
            if screen_height >= 1400:
                spacing_mult = 2.0
        self.segment_overlay.set_spacing_multiplier(spacing_mult)
        self.segment_overlay.show()

        # Create edit box overlay
        self.edit_box_overlay = EditBoxOverlay(self.hex_display)
        self.edit_box_overlay.setGeometry(0, 0, self.hex_column_width, self.hex_display.height())
        self.edit_box_overlay.set_theme_colors(theme_colors)
        self.edit_box_overlay.show()

        # Create boundary overlay
        self.boundary_overlay = BoundaryOverlay(self.hex_display)
        self.boundary_overlay.setGeometry(0, 0, self.hex_column_width, self.hex_display.height())
        self.boundary_overlay.set_theme_colors(theme_colors)
        # Initialize display parameters (use same padding as SegmentOverlay: 4)
        font_metrics = QFontMetrics(self.hex_display.font())
        char_width = font_metrics.horizontalAdvance('0')
        self.boundary_overlay.set_display_params(char_width, 4, 2, self.bytes_per_row)
        self.boundary_overlay.set_boundaries(self.boundary_enabled, self.boundary_start_col, self.boundary_end_col)
        self.boundary_overlay.show()

        # ASCII column - fixed next to hex
        self.ascii_display = HexTextEdit()
        self.ascii_display.editor = self  # Set reference to parent editor
        self.ascii_display.hovered.connect(self.on_ascii_hover)
        self.ascii_display.setMinimumWidth(250)
        self.ascii_display.setMaximumWidth(250)
        self.ascii_display.setLineWrapMode(QTextEdit.NoWrap)
        self.ascii_display.setVerticalScrollBarPolicy(Qt.ScrollBarAlwaysOff)
        self.ascii_display.clicked.connect(self.on_ascii_click)
        self.ascii_display.setTextInteractionFlags(Qt.NoTextInteraction)  # Disable native text selection
        self.ascii_display.rightClicked.connect(self.on_ascii_right_click)
        self.ascii_display.setStyleSheet(f"border-left: 2px solid {grid_line_color}; border-right: 1px solid {grid_line_color}; padding: 2px 4px;")
        self.ascii_display.setSizePolicy(QSizePolicy.Fixed, QSizePolicy.Expanding)
        self.ascii_display.setAlignment(Qt.AlignCenter)
        hex_layout.addWidget(self.ascii_display)

        # Add spacer to push everything to the left (scrollbar will be positioned separately)
        hex_layout.addStretch()

        self.hex_ascii_container.setLayout(hex_layout)
        hex_main_layout.addWidget(self.hex_ascii_container)
        hex_widget.setLayout(hex_main_layout)
        # Allow hex widget to stretch with window
        content_splitter.addWidget(hex_widget)

        # Sync scrolling
        self.hex_display.verticalScrollBar().valueChanged.connect(self.on_hex_scroll)

        # Right side: Tabbed panels with scrollbar (will be positioned as overlay)
        self.inspector_widget = QWidget()
        self.inspector_width = 390  # Initial width for overlay
        self.inspector_widget.setMinimumWidth(self.inspector_width)
        self.inspector_widget.setSizePolicy(QSizePolicy.Preferred, QSizePolicy.Expanding)
        self.inspector_widget.setObjectName("inspector_widget")
        # Ensure the widget only captures events within its bounds
        self.inspector_widget.setAttribute(Qt.WA_NoMousePropagation, False)
        # Add shadow effect for overlay appearance (no xOffset to avoid extending beyond widget bounds)
        shadow = QGraphicsDropShadowEffect()
        shadow.setBlurRadius(15)
        shadow.setXOffset(0)  # No offset to prevent interactive area extending beyond widget
        shadow.setYOffset(2)
        shadow.setColor(QColor(0, 0, 0, 140))
        self.inspector_widget.setGraphicsEffect(shadow)

        # Main horizontal layout: tabbed content with resize handle
        inspector_main_layout = QHBoxLayout()
        inspector_main_layout.setContentsMargins(0, 0, 0, 0)
        inspector_main_layout.setSpacing(0)

        # Add resize handle on the left edge
        self.inspector_resize_handle = QWidget()
        self.inspector_resize_handle.setFixedWidth(2)  # Thin resize handle
        self.inspector_resize_handle.setCursor(Qt.SizeHorCursor)
        # Style will be set after theme is loaded
        theme_colors = get_theme_colors(self.current_theme)
        self.inspector_resize_handle.setStyleSheet(f"background-color: {theme_colors['border']};")
        self.inspector_resize_handle.mousePressEvent = self.start_inspector_resize
        self.inspector_resize_handle.mouseMoveEvent = self.resize_inspector
        self.inspector_resize_handle.mouseReleaseEvent = self.end_inspector_resize
        inspector_main_layout.addWidget(self.inspector_resize_handle)

        # Content container
        inspector_content_widget = QWidget()
        inspector_content_layout = QHBoxLayout()
        inspector_content_layout.setContentsMargins(0, 0, 0, 0)
        inspector_content_layout.setSpacing(1)

        # Create tab widget for different panels
        self.right_panel_tabs = QTabWidget()
        self.right_panel_tabs.setTabPosition(QTabWidget.North)
        self.right_panel_tabs.setUsesScrollButtons(True)
        # Set tab font size
        tab_font = QFont("Arial", 10)
        self.right_panel_tabs.setFont(tab_font)
        # Style scroll buttons to match theme
        self.update_tab_scroll_buttons_style()
        # Update arrow text when tabs change
        self.right_panel_tabs.currentChanged.connect(lambda: self._update_arrow_button_text())

        # Data Inspector Tab (original inspector)
        data_inspector_widget = QWidget()
        inspector_layout = QVBoxLayout()
        inspector_layout.setContentsMargins(2, 0, 2, 0)

        # Inspector title with navigation buttons
        inspector_title_widget = QWidget()
        inspector_title_layout = QHBoxLayout()
        inspector_title_layout.setContentsMargins(10, 15, 10, 10)

        inspector_title = QLabel("Data Inspector")
        inspector_title.setFont(QFont("Arial", 9, QFont.Bold))
        inspector_title.setAlignment(Qt.AlignCenter)
        inspector_title_layout.addWidget(inspector_title)

        # Navigation buttons
        first_btn = QPushButton("|◄")
        first_btn.setMinimumWidth(40)
        first_btn.setMaximumWidth(50)
        first_btn.setToolTip("Jump to start of file")
        first_btn.clicked.connect(self.first_byte)
        inspector_title_layout.addWidget(first_btn)

        prev_btn = QPushButton("◄")
        prev_btn.setMinimumWidth(40)
        prev_btn.setMaximumWidth(50)
        prev_btn.setToolTip("Previous byte")
        prev_btn.clicked.connect(self.prev_byte)
        inspector_title_layout.addWidget(prev_btn)

        next_btn = QPushButton("►")
        next_btn.setMinimumWidth(40)
        next_btn.setMaximumWidth(50)
        next_btn.setToolTip("Next byte")
        next_btn.clicked.connect(self.next_byte)
        inspector_title_layout.addWidget(next_btn)

        last_btn = QPushButton("►|")
        last_btn.setMinimumWidth(40)
        last_btn.setMaximumWidth(50)
        last_btn.setToolTip("Jump to end of file")
        last_btn.clicked.connect(self.last_byte)
        inspector_title_layout.addWidget(last_btn)

        inspector_title_widget.setLayout(inspector_title_layout)
        inspector_layout.addWidget(inspector_title_widget)

        # Inspector content scroll area
        self.inspector_scroll = QScrollArea()
        self.inspector_scroll.setWidgetResizable(True)
        self.inspector_scroll.setVerticalScrollBarPolicy(Qt.ScrollBarAsNeeded)
        self.inspector_content = QWidget()
        self.inspector_content_layout = QVBoxLayout()
        self.inspector_content_layout.setAlignment(Qt.AlignTop)
        self.inspector_content.setLayout(self.inspector_content_layout)
        self.inspector_scroll.setWidget(self.inspector_content)
        inspector_layout.addWidget(self.inspector_scroll, 1)  # Stretch factor to expand and fill space

        # Initialize DataInspector module
        self.data_inspector = DataInspector(self)

        # Endian button
        self.endian_btn = QPushButton("Byte Order: Little Endian")
        self.endian_btn.setMinimumHeight(35)
        self.endian_btn.setFont(QFont("Arial", 9))
        self.endian_btn.clicked.connect(self.toggle_endian)
        inspector_layout.addWidget(self.endian_btn)

        # Number basis selection (for integrals)
        basis_label = QLabel("Integral Display Basis:")
        basis_label.setFont(QFont("Arial", 9, QFont.Bold))
        basis_label.setMinimumHeight(20)
        basis_label.setAlignment(Qt.AlignCenter)
        inspector_layout.addWidget(basis_label)

        basis_container = QWidget()
        basis_layout = QHBoxLayout()
        basis_layout.setContentsMargins(10, 5, 10, 5)
        basis_layout.setSpacing(15)

        self.hex_basis_check = QCheckBox("Hex")
        self.hex_basis_check.setMinimumHeight(30)
        self.hex_basis_check.setFont(QFont("Arial", 9))
        self.hex_basis_check.setChecked(False)
        self.hex_basis_check.stateChanged.connect(lambda: self.on_basis_changed('hex'))
        basis_layout.addWidget(self.hex_basis_check)

        self.dec_basis_check = QCheckBox("Dec")
        self.dec_basis_check.setMinimumHeight(30)
        self.dec_basis_check.setFont(QFont("Arial", 9))
        self.dec_basis_check.setChecked(True)
        self.dec_basis_check.stateChanged.connect(lambda: self.on_basis_changed('dec'))
        basis_layout.addWidget(self.dec_basis_check)

        self.oct_basis_check = QCheckBox("Oct")
        self.oct_basis_check.setMinimumHeight(30)
        self.oct_basis_check.setFont(QFont("Arial", 9))
        self.oct_basis_check.setChecked(False)
        self.oct_basis_check.stateChanged.connect(lambda: self.on_basis_changed('oct'))
        basis_layout.addWidget(self.oct_basis_check)

        basis_container.setLayout(basis_layout)
        inspector_layout.addWidget(basis_container)

        data_inspector_widget.setLayout(inspector_layout)
        self.right_panel_tabs.addTab(data_inspector_widget, "Inspector")

        # Pattern Scan Tab
        self.pattern_scan_widget = PatternScanWidget()
        self.pattern_scan_widget.parent_editor = self
        self.pattern_scan_widget.result_clicked.connect(self.on_pattern_result_clicked)
        self.right_panel_tabs.addTab(self.pattern_scan_widget, "Pattern Scan")

        # Signature Tab
        self.signature_widget = SignatureWidget()
        self.signature_widget.parent_editor = self
        self.signature_widget.pointer_added.connect(self.on_signature_pointer_added)
        self.right_panel_tabs.addTab(self.signature_widget, "Pointers")

        # Fields Tab
        self.fields_widget = FieldWidget()
        self.fields_widget.parent_editor = self
        self.fields_widget.field_segment_clicked.connect(self.on_field_segment_clicked)
        self.right_panel_tabs.addTab(self.fields_widget, "Fields")

        # Statistics Tab
        self.statistics_widget = StatisticsWidget()
        self.statistics_widget.parent_editor = self
        self.right_panel_tabs.addTab(self.statistics_widget, "Statistics")

        inspector_content_layout.addWidget(self.right_panel_tabs)
        inspector_content_widget.setLayout(inspector_content_layout)
        inspector_main_layout.addWidget(inspector_content_widget)

        self.inspector_widget.setLayout(inspector_main_layout)

        # Add placeholder widget to maintain spacing in layout
        self.inspector_placeholder = QWidget()
        self.inspector_placeholder.setFixedWidth(0)  # Minimal width to avoid affecting layout
        self.inspector_placeholder.setObjectName("inspector_placeholder")
        self.inspector_placeholder.setAttribute(Qt.WA_TransparentForMouseEvents, True)  # Don't capture mouse events
        content_splitter.addWidget(self.inspector_placeholder)

        # Set initial sizes and stretch factors
        content_splitter.setSizes([1170, 0])
        content_splitter.setStretchFactor(0, 1)
        content_splitter.setStretchFactor(1, 0)  # Placeholder doesn't stretch
        # Disable splitter interaction completely
        for i in range(content_splitter.count()):
            handle = content_splitter.handle(i)
            if handle:
                handle.setEnabled(False)
                handle.setAttribute(Qt.WA_TransparentForMouseEvents, True)

        main_layout.addWidget(content_splitter, stretch=1)

        # Status bar
        self.status_label = QLabel("Ready")
        self.status_label.setFont(QFont("Courier", 9))
        self.statusBar().addWidget(self.status_label, 1)

        central_widget.setLayout(main_layout)

        # Set up inspector widget as overlay (absolute positioning)
        self.inspector_widget.setParent(central_widget)
        self.inspector_widget.raise_()  # Bring to front

        # Create navigation scrollbar as a separate overlay widget (positioned next to inspector)
        self.hex_nav_scrollbar = SmoothScrollBar(Qt.Vertical, central_widget)
        theme_colors = get_theme_colors(self.current_theme)
        self.hex_nav_scrollbar.set_theme_colors(theme_colors)
        self.hex_nav_scrollbar.setFixedWidth(12)
        self.hex_nav_scrollbar.raise_()

        # Position will be set in resizeEvent
        self.position_inspector_overlay()

        # Key event filters
        self.hex_display.installEventFilter(self)
        self.ascii_display.installEventFilter(self)

        # Connect navigation scrollbar to hex display scrollbar (bidirectional sync)
        self.hex_nav_scrollbar.valueChanged.connect(self.on_nav_scroll)
        self.hex_display.verticalScrollBar().rangeChanged.connect(self.update_nav_scrollbar_range)

    def position_inspector_overlay(self):
        """Position the inspector widget and scrollbar as overlays on the right side."""
        if not hasattr(self, 'inspector_widget'):
            return

        # Get the central widget size
        central_widget = self.centralWidget()
        if not central_widget:
            return

        widget_height = central_widget.height()
        total_width = central_widget.width()

        # Reserve space for scrollbar
        scrollbar_width = 12 if hasattr(self, 'hex_nav_scrollbar') else 0
        available_width = total_width - scrollbar_width

        # Calculate actual inspector width (constrained by available space)
        actual_inspector_width = min(self.inspector_width, available_width)

        # Position scrollbar first (always stays visible on the left of inspector)
        if hasattr(self, 'hex_nav_scrollbar'):
            scrollbar_x = max(0, total_width - scrollbar_width - actual_inspector_width)
            self.hex_nav_scrollbar.setGeometry(scrollbar_x, 0, scrollbar_width, widget_height)
            self.hex_nav_scrollbar.raise_()

        # Position inspector on the right side, after scrollbar
        inspector_x = max(0, total_width - actual_inspector_width)

        self.inspector_widget.setGeometry(inspector_x, 0, actual_inspector_width, widget_height)
        self.inspector_widget.raise_()

    def start_inspector_resize(self, event):
        """Start resizing the inspector widget."""
        self.resizing_inspector = True
        self.resize_start_x = event.globalPos().x()
        self.resize_start_width = self.inspector_width

    def resize_inspector(self, event):
        """Resize the inspector widget as the user drags."""
        if not hasattr(self, 'resizing_inspector') or not self.resizing_inspector:
            return

        # Calculate new width based on mouse movement (dragging left decreases width)
        delta_x = self.resize_start_x - event.globalPos().x()
        new_width = self.resize_start_width + delta_x

        # Get central widget to calculate max width constraint
        central_widget = self.centralWidget()
        if central_widget:
            # Leave space for scrollbar (12px) plus margin (10px)
            scrollbar_width = 12
            margin = 10
            max_width_limit = central_widget.width() - scrollbar_width - margin
        else:
            max_width_limit = 1200

        # Constrain width between min and max
        min_width = 5
        max_width = max(min_width, max_width_limit)  # Ensure max is at least min
        new_width = max(min_width, min(max_width, new_width))

        # Update inspector width
        self.inspector_width = new_width
        # Note: Don't use setFixedWidth here, let position_inspector_overlay handle actual width

        # Reposition the inspector overlay
        self.position_inspector_overlay()

        # Update search results overlay if it exists
        if hasattr(self, 'results_overlay') and self.results_overlay is not None and self.results_overlay.isVisible():
            overlay_height = 200
            x_start = 130
            y_position = self.hex_ascii_container.height() - overlay_height
            # Available width is just the space within hex_ascii_container
            # Don't subtract inspector_width as it's in a different coordinate space
            overlay_width = self.hex_ascii_container.width() - x_start
            self.results_overlay.setGeometry(x_start, y_position, overlay_width, overlay_height)

    def end_inspector_resize(self, event):
        """End resizing the inspector widget."""
        self.resizing_inspector = False

    def update_window_size_for_screen(self):
        """Update window size based on current screen resolution."""
        # Use the screen that THIS window is currently on
        screen = self.screen()
        if screen:
            screen_geometry = screen.availableGeometry()
            screen_height = screen_geometry.height()

            # Default is 1200, increase by 400 for 1440p+
            optimal_width = 1200
            if screen_height >= 1400:
                optimal_width = 1600

            # Set initial width (height will be set by Qt defaults)
            self.resize(optimal_width, 840)

    def create_menus(self):
        menubar = self.menuBar()

        # File menu
        file_menu = menubar.addMenu("File")

        open_action = QAction("Open", self)
        open_action.triggered.connect(self.open_file)
        file_menu.addAction(open_action)

        file_menu.addSeparator()

        close_action = QAction("Close", self)
        close_action.triggered.connect(self.close_file)
        file_menu.addAction(close_action)

        close_all_action = QAction("Close All", self)
        close_all_action.triggered.connect(self.close_all_files)
        file_menu.addAction(close_all_action)

        file_menu.addSeparator()

        save_action = QAction("Save", self)
        save_action.setShortcut("Ctrl+S")
        save_action.triggered.connect(self.save_file)
        file_menu.addAction(save_action)

        save_all_action = QAction("Save All", self)
        save_all_action.setShortcut("Ctrl+Shift+S")
        save_all_action.triggered.connect(self.save_all_files)
        file_menu.addAction(save_all_action)

        file_menu.addSeparator()

        exit_action = QAction("Exit", self)
        exit_action.triggered.connect(self.close)
        file_menu.addAction(exit_action)

        # Edit menu
        edit_menu = menubar.addMenu("Edit")

        undo_action = QAction("Undo", self)
        undo_action.setShortcut("Ctrl+Z")
        undo_action.triggered.connect(self.undo)
        edit_menu.addAction(undo_action)

        redo_action = QAction("Redo", self)
        redo_action.setShortcut("Ctrl+Y")
        redo_action.triggered.connect(self.redo)
        edit_menu.addAction(redo_action)

        edit_menu.addSeparator()

        copy_action = QAction("Copy", self)
        copy_action.setShortcut("Ctrl+C")
        copy_action.triggered.connect(self.copy)
        edit_menu.addAction(copy_action)

        cut_action = QAction("Cut", self)
        cut_action.setShortcut("Ctrl+X")
        cut_action.triggered.connect(self.cut)
        edit_menu.addAction(cut_action)

        paste_write_action = QAction("Paste Write", self)
        paste_write_action.setShortcut("Ctrl+B")
        paste_write_action.triggered.connect(self.paste_write)
        edit_menu.addAction(paste_write_action)

        paste_insert_action = QAction("Paste Insert", self)
        paste_insert_action.setShortcut("Ctrl+V")
        paste_insert_action.triggered.connect(self.paste_insert)
        edit_menu.addAction(paste_insert_action)

        edit_menu.addSeparator()

        fill_selection_action = QAction("Fill Selection", self)
        fill_selection_action.setShortcut("Ctrl+L")
        fill_selection_action.triggered.connect(self.show_fill_selection_dialog)
        edit_menu.addAction(fill_selection_action)

        # View menu
        view_menu = menubar.addMenu("View")

        search_action = QAction("Search", self)
        search_action.setShortcut("Ctrl+F")
        search_action.triggered.connect(self.show_search_window)
        view_menu.addAction(search_action)

        replace_action = QAction("Replace", self)
        replace_action.setShortcut("Ctrl+R")
        replace_action.triggered.connect(self.show_replace_window)
        view_menu.addAction(replace_action)

        goto_action = QAction("Go to...", self)
        goto_action.setShortcut("Ctrl+G")
        goto_action.triggered.connect(self.show_goto_window)
        view_menu.addAction(goto_action)

        view_menu.addSeparator()

        hide_delimiters_action = QAction("Hide Delimiters...", self)
        hide_delimiters_action.triggered.connect(self.show_delimiter_config)
        view_menu.addAction(hide_delimiters_action)
        view_menu.addSeparator()

        segments_action = QAction("Segments...", self)
        segments_action.triggered.connect(self.show_segments_config)
        view_menu.addAction(segments_action)

        # Tools menu
        tools_menu = menubar.addMenu("Tools")

        highlight_action = QAction("Highlight", self)
        highlight_action.setShortcut("Ctrl+H")
        highlight_action.triggered.connect(self.show_highlight_window)
        tools_menu.addAction(highlight_action)

        tools_menu.addSeparator()

        notes_action = QAction("Show Notes", self)
        notes_action.triggered.connect(self.toggle_notes)
        tools_menu.addAction(notes_action)

        tools_menu.addSeparator()

        calc_action = QAction("Calculator", self)
        calc_action.triggered.connect(self.show_calculator_window)
        tools_menu.addAction(calc_action)

        color_action = QAction("Color Picker", self)
        color_action.triggered.connect(self.show_color_picker_window)
        tools_menu.addAction(color_action)

        compare_action = QAction("Compare Data", self)
        compare_action.triggered.connect(self.show_compare_window)
        tools_menu.addAction(compare_action)

        # Options menu
        options_menu = menubar.addMenu("Options")

        version_control_action = QAction("Version Control", self)
        version_control_action.triggered.connect(self.show_version_control)
        options_menu.addAction(version_control_action)

        options_menu.addSeparator()

        themes_action = QAction("Themes", self)
        themes_action.triggered.connect(self.show_theme_selector)
        options_menu.addAction(themes_action)

        options_menu.addSeparator()

        save_json_action = QAction("Save JSON...", self)
        save_json_action.triggered.connect(self.save_json)
        options_menu.addAction(save_json_action)

        load_json_action = QAction("Load JSON...", self)
        load_json_action.triggered.connect(self.load_json)
        options_menu.addAction(load_json_action)

        clear_action = QAction("Clear", self)
        clear_action.triggered.connect(self.clear_all)
        options_menu.addAction(clear_action)

        options_menu.addSeparator()

        debug_action = QAction("Debugging", self)
        debug_action.triggered.connect(self.show_debug_window)
        options_menu.addAction(debug_action)

        about_action = QAction("About", self)
        about_action.triggered.connect(self.show_about_dialog)
        options_menu.addAction(about_action)

    def eventFilter(self, obj, event):
        if event.type() == QEvent.KeyPress:
            if obj == self.hex_display:
                return self.on_hex_key_press(event)
            elif obj == self.ascii_display:
                return self.on_ascii_key_press(event)
        return super().eventFilter(obj, event)

    def on_hex_key_press(self, event):
        if self.current_tab_index < 0:
            return False

        key = event.key()
        modifiers = event.modifiers()

        # Arrow keys
        if key in (Qt.Key_Left, Qt.Key_Right, Qt.Key_Up, Qt.Key_Down):
            self.handle_arrow_keys(key)
            return True

        # Hex input
        if self.cursor_position is not None:
            text = event.text()
            if text and text in '0123456789ABCDEFabcdef':
                self.handle_hex_input(text.upper())
                return True

        return False

    def on_ascii_key_press(self, event):
        if self.current_tab_index < 0 or self.cursor_position is None:
            return False

        text = event.text()
        if text and len(text) == 1 and 32 <= ord(text) <= 126:
            self.handle_ascii_input(text)
            return True

        return False

    def handle_arrow_keys(self, key):
        if self.cursor_position is None:
            return

        if key == Qt.Key_Left:
            if self.cursor_nibble == 1:
                self.cursor_nibble = 0
            elif self.cursor_position > 0:
                self.cursor_position -= 1
                self.cursor_nibble = 1
        elif key == Qt.Key_Right:
            if self.cursor_nibble == 0:
                self.cursor_nibble = 1
            else:
                current_file = self.open_files[self.current_tab_index]
                if self.cursor_position < len(current_file.file_data) - 1:
                    self.cursor_position += 1
                    self.cursor_nibble = 0
        elif key == Qt.Key_Up:
            if self.cursor_position >= self.bytes_per_row:
                self.cursor_position -= self.bytes_per_row
        elif key == Qt.Key_Down:
            current_file = self.open_files[self.current_tab_index]
            if self.cursor_position + self.bytes_per_row < len(current_file.file_data):
                self.cursor_position += self.bytes_per_row

        self.update_cursor_highlight()
        self.data_inspector.update()

    def handle_hex_input(self, char):
        current_file = self.open_files[self.current_tab_index]
        if self.cursor_position >= len(current_file.file_data):
            return

        self.save_undo_state()

        old_value = current_file.file_data[self.cursor_position]
        nibble_value = int(char, 16)

        if self.cursor_nibble == 0:
            new_value = (nibble_value << 4) | (old_value & 0x0F)
        else:
            new_value = (old_value & 0xF0) | nibble_value

        current_file.file_data[self.cursor_position] = new_value
        current_file.modified = True
        current_file.modified_bytes.add(self.cursor_position)
        current_file.pattern_highlights_dirty = True  # Mark pattern highlights for reapplication

        # Move cursor
        if self.cursor_nibble == 0:
            self.cursor_nibble = 1
        else:
            self.cursor_nibble = 0
            if self.cursor_position < len(current_file.file_data) - 1:
                self.cursor_position += 1

        self.display_hex()
        self.update_cursor_highlight()
        self.data_inspector.update()

    def handle_ascii_input(self, char):
        current_file = self.open_files[self.current_tab_index]
        if self.cursor_position >= len(current_file.file_data):
            return

        self.save_undo_state()

        current_file.file_data[self.cursor_position] = ord(char)
        current_file.modified = True
        current_file.modified_bytes.add(self.cursor_position)
        current_file.pattern_highlights_dirty = True  # Mark pattern highlights for reapplication

        if self.cursor_position < len(current_file.file_data) - 1:
            self.cursor_position += 1

        self.display_hex()
        self.update_cursor_highlight()
        self.data_inspector.update()

    def open_file(self):
        file_path, _ = QFileDialog.getOpenFileName(
            self, "Open File", "", "All Files (*)"
        )
        if file_path:
            try:
                # Check file size first
                file_size = os.path.getsize(file_path)
                mmap_threshold = 10 * 1024 * 1024  # 10 MB - use mmap for files larger than this

                use_mmap = file_size > mmap_threshold

                if use_mmap:
                    # Use memory-mapped file for large files
                    file_handle = open(file_path, 'r+b' if os.access(file_path, os.W_OK) else 'rb')
                    file_tab = FileTab(file_path, file_handle=file_handle, use_mmap=True)
                else:
                    # Load small files entirely into memory
                    with open(file_path, 'rb') as f:
                        file_data = f.read()
                    file_tab = FileTab(file_path, file_data)

                self.open_files.append(file_tab)

                tab_name = os.path.basename(file_path)
                tab_widget = QWidget()
                self.tab_widget.addTab(tab_widget, tab_name)
                self.tab_widget.setCurrentIndex(len(self.open_files) - 1)

                # Reset rendered range for new file
                self.rendered_start_byte = 0
                self.rendered_end_byte = 0

                # Note: Don't call set_file_data to avoid clearing data
                # The on_tab_changed event will be triggered automatically
                # when we set the current index above, which will handle
                # setting up the widgets for this new empty file

                self.display_hex()

            except Exception as e:
                QMessageBox.critical(self, "Error", f"Failed to open file: {str(e)}")

    def close_tab(self, index):
        if 0 <= index < len(self.open_files):
            file_tab = self.open_files[index]
            if file_tab.modified:
                # Play beep for unsaved changes warning
                QApplication.beep()
                reply = QMessageBox.question(
                    self, "Unsaved Changes",
                    f"File {os.path.basename(file_tab.file_path)} has unsaved changes. Close anyway?",
                    QMessageBox.Yes | QMessageBox.No
                )
                if reply == QMessageBox.No:
                    return

            self.open_files.pop(index)
            self.tab_widget.removeTab(index)

            # Update reference file dropdown after closing a tab
            if hasattr(self, 'signature_widget') and hasattr(self.signature_widget, '_update_ref_file_combo'):
                self.signature_widget._update_ref_file_combo()

            if len(self.open_files) == 0:
                self.current_tab_index = -1
                self.clear_display()

    def close_file(self):
        if self.current_tab_index >= 0:
            self.close_tab(self.current_tab_index)

    def close_all_files(self):
        while len(self.open_files) > 0:
            self.close_tab(0)

    def update_tab_title(self, tab_index=None):
        """Update the tab title to show * if file has unsaved edits"""
        if tab_index is None:
            tab_index = self.current_tab_index

        if tab_index < 0 or tab_index >= len(self.open_files):
            return

        current_file = self.open_files[tab_index]
        tab_name = os.path.basename(current_file.file_path)

        # Add * if file has been modified
        if current_file.modified:
            tab_name += " *"

        self.tab_widget.setTabText(tab_index, tab_name)

        # Update reference file dropdown to reflect the tab name change
        if hasattr(self, 'signature_widget') and hasattr(self.signature_widget, '_update_ref_file_combo'):
            self.signature_widget._update_ref_file_combo()

    def on_tab_changed(self, index):
        # Save pattern scan results and pointers from the previous tab
        if self.current_tab_index >= 0 and self.current_tab_index < len(self.open_files):
            prev_file = self.open_files[self.current_tab_index]
            # Save pattern scan results (if any exist in the tree)
            prev_file.pattern_scan_results = []
            root = self.pattern_scan_widget.tree.invisibleRootItem()
            for i in range(root.childCount()):
                category_item = root.child(i)
                for j in range(category_item.childCount()):
                    result_item = category_item.child(j)
                    result = result_item.data(0, Qt.UserRole)
                    if result:
                        prev_file.pattern_scan_results.append(result)
            # Save inspector pointers
            prev_file.inspector_pointers = list(self.signature_widget.pointers)

        # Clear overlays from previous tab first
        if hasattr(self, 'signature_overlays'):
            for overlay in self.signature_overlays:
                try:
                    # Disconnect signals before deleting to prevent crashes
                    overlay.value_changed.disconnect()
                    overlay.editingFinished.disconnect()
                    overlay.returnPressed.disconnect()
                    overlay.deleteLater()
                except (RuntimeError, TypeError):
                    # Widget already deleted or signals already disconnected
                    pass
            self.signature_overlays.clear()

        self.current_tab_index = index
        if index >= 0:
            self.cursor_position = 0
            self.cursor_nibble = 0
            self.selection_start = None
            self.selection_end = None
            # Reset rendered range for new tab
            self.rendered_start_byte = 0
            self.rendered_end_byte = 0
            self.current_top_row = 0
            current_file = self.open_files[index]

            # Set file data for widgets (this only updates the file_data reference)
            self.pattern_scan_widget.file_data = current_file.file_data
            self.statistics_widget.set_file_data(current_file.file_data)

            # Restore pattern scan results for this file
            self.pattern_scan_widget.tree.clear()
            if current_file.pattern_scan_results:
                self.pattern_scan_widget.populate_tree(current_file.pattern_scan_results)
            else:
                self.pattern_scan_widget.status_label.setText("Ready to scan")
            self.pattern_scan_widget.scan_button.setEnabled(True)

            # Restore inspector pointers for this file
            self.signature_widget.pointers = list(current_file.inspector_pointers)
            self.signature_widget.rebuild_tree()

            # Update reference file dropdown to reflect current open files
            if hasattr(self.signature_widget, '_update_ref_file_combo'):
                self.signature_widget._update_ref_file_combo()

            self.display_hex()
        else:
            self.clear_display()

    def shift_pattern_labels(self, current_file, start_pos, shift_amount):
        """Shift pattern labels after a position by shift_amount (positive for insert, negative for cut)"""
        old_labels = dict(current_file.pattern_labels)
        current_file.pattern_labels.clear()

        for offset, label in old_labels.items():
            if shift_amount < 0:  # Cut operation
                end_pos = start_pos + abs(shift_amount) - 1
                if offset < start_pos:
                    # Before cut range - keep same position
                    current_file.pattern_labels[offset] = label
                elif offset > end_pos:
                    # After cut range - shift backward
                    new_offset = offset + shift_amount
                    if new_offset >= 0:
                        current_file.pattern_labels[new_offset] = label
                # Labels within cut range are removed
            else:  # Insert operation
                if offset < start_pos:
                    # Before insert position - keep same position
                    current_file.pattern_labels[offset] = label
                else:
                    # At or after insert position - shift forward
                    current_file.pattern_labels[offset + shift_amount] = label

    def shift_signature_pointers(self, start_pos, shift_amount):
        """Shift signature pointers after a position by shift_amount (positive for insert, negative for cut)"""
        if not hasattr(self, 'signature_widget') or not self.signature_widget.pointers:
            return

        pointers_to_remove = []
        pointers_to_update = []

        for pointer in self.signature_widget.pointers:
            if shift_amount < 0:  # Cut operation
                end_pos = start_pos + abs(shift_amount) - 1
                pointer_end = pointer.offset + pointer.length - 1

                # Check if pointer is completely before the cut range
                if pointer_end < start_pos:
                    # Keep same position
                    continue
                # Check if pointer is completely after the cut range
                elif pointer.offset > end_pos:
                    # Shift backward
                    new_offset = pointer.offset + shift_amount
                    if new_offset >= 0:
                        pointers_to_update.append((pointer, new_offset))
                else:
                    # Pointer overlaps with cut range - remove it
                    pointers_to_remove.append(pointer)
            else:  # Insert operation
                if pointer.offset < start_pos:
                    # Before insert position - keep same position
                    continue
                else:
                    # At or after insert position - shift forward
                    pointers_to_update.append((pointer, pointer.offset + shift_amount))

        # Remove pointers that were in the cut range
        for pointer in pointers_to_remove:
            self.signature_widget.pointers.remove(pointer)

        # Update pointer offsets
        for pointer, new_offset in pointers_to_update:
            pointer.offset = new_offset

        # Rebuild the signature widget tree to reflect changes
        if pointers_to_remove or pointers_to_update:
            self.signature_widget.rebuild_tree()

    def shift_non_pattern_highlights(self, current_file, start_pos, shift_amount):
        """Shift non-pattern highlights after a position by shift_amount (positive for insert, negative for cut)"""
        # Only shift non-pattern highlights (manual selection highlights)
        old_highlights = {offset: info for offset, info in current_file.byte_highlights.items() if "pattern" not in info}

        # Remove all non-pattern highlights
        current_file.byte_highlights = {offset: info for offset, info in current_file.byte_highlights.items() if "pattern" in info}

        # Re-add shifted highlights
        for offset, info in old_highlights.items():
            if shift_amount < 0:  # Cut operation
                end_pos = start_pos + abs(shift_amount) - 1
                if offset < start_pos:
                    # Before cut range - keep same position
                    current_file.byte_highlights[offset] = info
                elif offset > end_pos:
                    # After cut range - shift backward
                    current_file.byte_highlights[offset + shift_amount] = info
                # Highlights within cut range are removed (not re-added)
            else:  # Insert operation
                if offset < start_pos:
                    # Before insertion - keep same position
                    current_file.byte_highlights[offset] = info
                else:
                    # At or after insertion - shift forward
                    current_file.byte_highlights[offset + shift_amount] = info

    def reapply_pattern_highlights(self, current_file):
        """Dynamically reapply pattern-based highlights by searching for patterns"""
        # Only reapply if dirty flag is set or if this is the first time
        if not current_file.pattern_highlights_dirty and current_file.pattern_highlights:
            # Check if we have any pattern highlights in byte_highlights
            has_pattern_highlights = any("pattern" in info for info in current_file.byte_highlights.values())
            if has_pattern_highlights:
                return  # Already applied and not dirty, skip

        if not current_file.pattern_highlights:
            return

        # Clear all pattern-based highlights first
        current_file.byte_highlights = {
            offset: info for offset, info in current_file.byte_highlights.items()
            if "pattern" not in info
        }

        # Reapply each pattern highlight
        file_data = current_file.file_data
        for pattern_info in current_file.pattern_highlights:
            pattern = pattern_info["pattern"]
            color = pattern_info["color"]
            message = pattern_info["message"]
            underline = pattern_info["underline"]

            pos = 0
            while pos <= len(file_data) - len(pattern):
                if bytes(file_data[pos:pos+len(pattern)]) == pattern:
                    for i in range(len(pattern)):
                        current_file.byte_highlights[pos + i] = {
                            "color": color,
                            "message": message,
                            "underline": underline,
                            "pattern": bytes(pattern)
                        }
                    pos += len(pattern)
                else:
                    pos += 1

        # Mark as clean after reapplying
        current_file.pattern_highlights_dirty = False

    def display_hex(self, preserve_scroll=False):
        if self.current_tab_index < 0 or not self.open_files:
            return

        current_file = self.open_files[self.current_tab_index]

        # Reapply pattern-based highlights dynamically
        self.reapply_pattern_highlights(current_file)

        file_data = current_file.file_data

        # Save scroll position if preserving
        hex_scroll_pos = self.hex_display.verticalScrollBar().value() if preserve_scroll else 0
        offset_scroll_pos = self.offset_display.verticalScrollBar().value() if preserve_scroll else 0
        ascii_scroll_pos = self.ascii_display.verticalScrollBar().value() if preserve_scroll else 0

        self.offset_display.clear()
        self.hex_display.clear()
        self.ascii_display.clear()

        offset_lines = []
        hex_lines = []
        ascii_lines = []

        # Calculate how many rows to render
        total_rows = (len(file_data) + self.bytes_per_row - 1) // self.bytes_per_row

        # Use existing rendered range if available and valid, otherwise calculate new range
        if (self.rendered_start_byte < len(file_data) and
            self.rendered_end_byte > 0 and
            total_rows > self.max_initial_rows):
            # Keep existing range (might be extended by scroll handler)
            start_byte = self.rendered_start_byte
            end_byte = self.rendered_end_byte
        elif total_rows > self.max_initial_rows and self.cursor_position is not None:
            # Cursor is set and file is large, render around cursor position
            cursor_row = self.cursor_position // self.bytes_per_row
            # Render a window around the cursor
            context_rows = self.max_initial_rows // 2
            start_row = max(0, cursor_row - context_rows)
            end_row = min(total_rows, start_row + self.max_initial_rows)
            # Adjust start if we're near the end
            if end_row == total_rows:
                start_row = max(0, end_row - self.max_initial_rows)

            start_byte = start_row * self.bytes_per_row
            end_byte = min(len(file_data), end_row * self.bytes_per_row)
        else:
            # Default: render from start
            start_byte = 0
            end_byte = min(len(file_data), self.max_initial_rows * self.bytes_per_row)

        # Store what range is being rendered
        self.rendered_start_byte = start_byte
        self.rendered_end_byte = end_byte

        for i in range(start_byte, end_byte, self.bytes_per_row):
            row_data = file_data[i:i + self.bytes_per_row]

            # Check if any bytes in this row have changes (modified, inserted, or replaced)
            row_has_changes = False
            for j in range(len(row_data)):
                byte_index = i + j
                if (byte_index in current_file.modified_bytes or
                    byte_index in current_file.inserted_bytes or
                    byte_index in current_file.replaced_bytes):
                    row_has_changes = True
                    break

            # Offset - centered without prefix, bold if row has changes
            if self.offset_mode == 'h':
                offset_line = f"{i:08X}"
            elif self.offset_mode == 'd':
                offset_line = f"{i:010d}"
            else:  # octal
                offset_line = f"o{i:08o}"

            # Store if this row has changes for later formatting
            if row_has_changes:
                offset_line += " ●"  # Temporary marker for bold formatting
            offset_lines.append(offset_line)

            # Hex - build plain text row with leading spaces for alignment
            hex_row = "  "  # Add 2 leading spaces to align with header
            for j, byte in enumerate(row_data):
                hex_row += f"{byte:02X} "

            # Pad with spaces if row is incomplete
            if len(row_data) < self.bytes_per_row:
                hex_row += "   " * (self.bytes_per_row - len(row_data))

            hex_lines.append(hex_row.rstrip())

            # ASCII - build plain text row
            ascii_row = ""
            for j, byte in enumerate(row_data):
                # Show extended ASCII (160-255) always enabled
                # Control characters (0x00-0x1F, 0x7F-0x9F) displayed as dots
                if 32 <= byte <= 126:
                    char = chr(byte)
                elif 160 <= byte <= 255:
                    char = chr(byte)
                else:
                    char = '.'
                ascii_row += char

            # Pad with spaces if row is incomplete
            if len(row_data) < self.bytes_per_row:
                ascii_row += " " * (self.bytes_per_row - len(row_data))

            ascii_lines.append(ascii_row)

        # Add padding rows at the end to allow scrolling the last row to the top
        # Calculate how many rows are visible in the hex display
        visible_rows = max(20, self.hex_display.height() // 18)  # Approximate line height of 18px
        padding_rows = visible_rows - 1  # Leave space for visible_rows minus the actual last row

        for _ in range(padding_rows):
            offset_lines.append("")
            hex_lines.append("")
            ascii_lines.append("")

        # Find lines with markers before setting text
        lines_to_bold = []
        for line_num, line in enumerate(offset_lines):
            if " ●" in line:
                lines_to_bold.append(line_num)

        # Remove markers from offset text and join
        offset_text_clean = '\n'.join(line.replace(" ●", "") for line in offset_lines)
        hex_text = '\n'.join(hex_lines)
        ascii_text = '\n'.join(ascii_lines)

        self.offset_display.setPlainText(offset_text_clean)
        self.hex_display.setPlainText(hex_text)
        self.ascii_display.setPlainText(ascii_text)

        # Apply color formatting to marked lines without changing size
        highlight_format = QTextCharFormat()
        highlight_format.setForeground(QColor("#FF6B6B"))
        highlight_format.setFontWeight(QFont.Normal)

        for target_line in lines_to_bold:
            offset_cursor = self.offset_display.textCursor()
            offset_cursor.movePosition(QTextCursor.Start)

            # Move to target line
            for _ in range(target_line):
                offset_cursor.movePosition(QTextCursor.NextBlock)

            # Select entire line
            offset_cursor.movePosition(QTextCursor.StartOfBlock)
            offset_cursor.movePosition(QTextCursor.EndOfBlock, QTextCursor.KeepAnchor)

            # Apply color highlight
            offset_cursor.mergeCharFormat(highlight_format)

        # Center align all offset text after applying bold
        cursor = self.offset_display.textCursor()
        cursor.select(QTextCursor.Document)
        fmt = QTextBlockFormat()
        fmt.setAlignment(Qt.AlignCenter)
        cursor.mergeBlockFormat(fmt)

        # Apply formatting after setting plain text
        self.apply_hex_formatting(current_file)

        # Restore scroll position if preserving
        if preserve_scroll:
            self.hex_display.verticalScrollBar().setValue(hex_scroll_pos)
            self.offset_display.verticalScrollBar().setValue(offset_scroll_pos)
            self.ascii_display.verticalScrollBar().setValue(ascii_scroll_pos)

        self.update_cursor_highlight()
        self.update_edit_box_overlay()  # Update edit box if active
        self.data_inspector.update()
        self.update_status()
        self.update_tab_title()

        # Update navigation scrollbar to represent full file
        self.update_nav_scrollbar_range(0, 0)

        # Update signature pointer overlays
        self.update_signature_overlays()

        # Update fields tree
        if hasattr(self, 'fields_widget'):
            self.fields_widget.rebuild_tree()

    def scroll_to_offset(self, offset, center=True):
        """Scroll the hex display to show the given offset, using proper QTextEdit scrolling"""
        if self.current_tab_index < 0 or not self.open_files:
            return

        current_file = self.open_files[self.current_tab_index]
        if offset >= len(current_file.file_data):
            return

        # Calculate which line the offset is on
        target_row = offset // self.bytes_per_row

        # Check if target row is outside the currently rendered window
        file_data = current_file.file_data
        total_rows = (len(file_data) + self.bytes_per_row - 1) // self.bytes_per_row

        # For large files, check if we need to re-render
        if total_rows > self.max_initial_rows:
            rendered_start_row = self.rendered_start_byte // self.bytes_per_row
            rendered_end_row = self.rendered_end_byte // self.bytes_per_row

            # If target is outside rendered window, re-render centered on target
            if target_row < rendered_start_row or target_row >= rendered_end_row:
                self.current_top_row = target_row
                self.render_at_row(target_row, center=center)
                # After render_at_row, the scrollbar is already positioned correctly
                return

        # Target row is within rendered window, scroll to it
        # Calculate row position within the rendered document
        rendered_start_row = self.rendered_start_byte // self.bytes_per_row
        row_in_document = target_row - rendered_start_row

        # Move a QTextCursor to that line in the document
        cursor = QTextCursor(self.hex_display.document())
        cursor.movePosition(QTextCursor.Start)
        cursor.movePosition(QTextCursor.Down, QTextCursor.MoveAnchor, row_in_document)

        # Set the cursor (this doesn't change selection, just position)
        self.hex_display.setTextCursor(cursor)

        # Ensure the cursor line is visible, centered if requested
        if center:
            # Center the line in the viewport
            viewport_height = self.hex_display.viewport().height()
            cursor_rect = self.hex_display.cursorRect(cursor)
            target_y = (viewport_height // 2) - (cursor_rect.height() // 2)
            scrollbar = self.hex_display.verticalScrollBar()
            new_value = scrollbar.value() + cursor_rect.top() - target_y
            scrollbar.setValue(new_value)

            # Update current_top_row based on actual scroll position
            line_height = self.hex_display.fontMetrics().height()
            if line_height > 0:
                self.current_top_row = rendered_start_row + (scrollbar.value() // line_height)
        else:
            self.hex_display.ensureCursorVisible()

            # Update current_top_row based on actual scroll position
            line_height = self.hex_display.fontMetrics().height()
            scrollbar = self.hex_display.verticalScrollBar()
            rendered_start_row = self.rendered_start_byte // self.bytes_per_row
            if line_height > 0:
                self.current_top_row = rendered_start_row + (scrollbar.value() // line_height)

        # Update navigation scrollbar to reflect new position
        self.update_nav_scrollbar_position()

    def apply_hex_formatting(self, current_file):
        """Apply colors and cursor highlighting to the hex and ASCII displays - optimized"""
        # Clear all existing formatting first
        hex_cursor = self.hex_display.textCursor()
        hex_cursor.select(QTextCursor.Document)
        hex_cursor.setCharFormat(QTextCharFormat())
        hex_cursor.clearSelection()

        ascii_cursor = self.ascii_display.textCursor()
        ascii_cursor.select(QTextCursor.Document)
        ascii_cursor.setCharFormat(QTextCharFormat())
        ascii_cursor.clearSelection()

        # Apply delimiter grey-out first (if any delimiters are configured)
        if self.hidden_delimiters:
            # Get theme foreground color and make it paler
            theme_colors = get_theme_colors(self.current_theme)
            foreground_color = QColor(theme_colors['editor_fg'])
            background_color = QColor(theme_colors['editor_bg'])

            # Blend foreground with background to create a paler color (30% foreground, 70% background)
            pale_color = QColor(
                int(foreground_color.red() * 0.3 + background_color.red() * 0.7),
                int(foreground_color.green() * 0.3 + background_color.green() * 0.7),
                int(foreground_color.blue() * 0.3 + background_color.blue() * 0.7)
            )

            delimiter_format = QTextCharFormat()
            delimiter_format.setForeground(pale_color)

            # Track byte ranges to hide: list of (start_idx, end_idx)
            ranges_to_hide = []

            # Find delimiter patterns for each delimiter type
            for delimiter_value, padding in self.hidden_delimiters.items():
                byte_index = self.rendered_start_byte

                while byte_index < min(self.rendered_end_byte, len(current_file.file_data)):
                    byte_value = current_file.file_data[byte_index]

                    if byte_value == delimiter_value:
                        # Check if we have 'padding' consecutive delimiter bytes
                        seq_start = byte_index
                        seq_count = 0

                        # Count consecutive delimiter bytes
                        while (seq_start + seq_count < len(current_file.file_data) and
                               current_file.file_data[seq_start + seq_count] == delimiter_value and
                               seq_count < padding):
                            seq_count += 1

                        # Check if we have exactly 'padding' consecutive bytes
                        if seq_count == padding:
                            # For padding > 1, check alignment within row
                            if padding > 1:
                                pos_in_row = byte_index % self.bytes_per_row

                                # Check if aligned to segment boundary
                                if pos_in_row % padding == 0:
                                    # Check that sequence doesn't span row boundary
                                    end_pos_in_row = (byte_index + padding - 1) % self.bytes_per_row
                                    if end_pos_in_row >= pos_in_row:  # Same row
                                        ranges_to_hide.append((byte_index, byte_index + padding))
                                        byte_index += padding
                                        continue
                            else:
                                # Padding 1: hide any single delimiter
                                ranges_to_hide.append((byte_index, byte_index + 1))

                    byte_index += 1

            # Apply grey-out to all bytes in marked ranges
            for start_idx, end_idx in ranges_to_hide:
                for idx in range(start_idx, end_idx):
                    # Skip if outside rendered range
                    if idx < self.rendered_start_byte or idx >= min(self.rendered_end_byte, len(current_file.file_data)):
                        continue

                    # Calculate display positions
                    row_num = (idx - self.rendered_start_byte) // self.bytes_per_row
                    j = idx % self.bytes_per_row
                    hex_chars_per_row = self.bytes_per_row * 3 + 2
                    hex_pos = row_num * hex_chars_per_row + 2 + (j * 3)
                    ascii_chars_per_row = self.bytes_per_row + 1
                    ascii_pos = row_num * ascii_chars_per_row + j

                    # Apply grey color to hex display
                    hex_cursor.setPosition(hex_pos)
                    hex_cursor.movePosition(QTextCursor.Right, QTextCursor.KeepAnchor, 2)
                    hex_cursor.mergeCharFormat(delimiter_format)

                    # Apply grey color to ASCII display
                    ascii_cursor.setPosition(ascii_pos)
                    ascii_cursor.movePosition(QTextCursor.Right, QTextCursor.KeepAnchor, 1)
                    ascii_cursor.mergeCharFormat(delimiter_format)

        # Format for cursor
        cursor_format = QTextCharFormat()
        if self.is_dark_theme():
            cursor_format.setBackground(QColor(64, 64, 64))
        else:
            cursor_format.setBackground(QColor(200, 220, 255))
        cursor_format.setProperty(QTextFormat.OutlinePen, QPen(QColor(0, 255, 0), 2))

        # Format for modified bytes (red)
        modified_format = QTextCharFormat()
        modified_format.setForeground(QColor(255, 0, 0))

        # Format for inserted bytes (green)
        inserted_format = QTextCharFormat()
        inserted_format.setForeground(QColor(0, 255, 0))

        # Format for replaced bytes (blue)
        replaced_format = QTextCharFormat()
        replaced_format.setForeground(QColor(33, 150, 243))

        # Format for selection
        selection_format = QTextCharFormat()
        if self.is_dark_theme():
            selection_format.setBackground(QColor(100, 100, 150))
        else:
            selection_format.setBackground(QColor(173, 216, 230))

        # Helper function to calculate positions (relative to rendered window)
        def get_positions(byte_index):
            # Calculate row relative to the rendered window, not absolute file position
            if byte_index < self.rendered_start_byte or byte_index >= self.rendered_end_byte:
                return None, None  # Byte is outside rendered range
            row_num = (byte_index - self.rendered_start_byte) // self.bytes_per_row
            j = byte_index % self.bytes_per_row
            hex_chars_per_row = self.bytes_per_row * 3 + 2
            hex_pos = row_num * hex_chars_per_row + 2 + (j * 3)
            ascii_chars_per_row = self.bytes_per_row + 1
            ascii_pos = row_num * ascii_chars_per_row + j
            return hex_pos, ascii_pos

        # Collect all bytes that need formatting
        bytes_to_format = set()

        # Add highlighted bytes
        bytes_to_format.update(current_file.byte_highlights.keys())

        # Don't add signature pointer bytes to formatting (overlays handle display)
        # for pointer in self.signature_widget.pointers:
        #     bytes_to_format.update(range(pointer.offset, pointer.offset + pointer.length))

        # Add modified bytes
        bytes_to_format.update(current_file.modified_bytes)
        bytes_to_format.update(current_file.inserted_bytes)
        bytes_to_format.update(current_file.replaced_bytes)

        # Add cursor position
        if self.cursor_position is not None:
            bytes_to_format.add(self.cursor_position)

        # Add selection range
        if self.selection_start is not None and self.selection_end is not None:
            sel_start = min(self.selection_start, self.selection_end)
            sel_end = max(self.selection_start, self.selection_end)

            # Handle column selection mode differently
            if self.column_selection_mode and self.column_sel_start_row is not None:
                # Only highlight bytes in the column range
                min_row = min(self.column_sel_start_row, self.column_sel_end_row)
                max_row = max(self.column_sel_start_row, self.column_sel_end_row)
                min_col = min(self.column_sel_start_col, self.column_sel_end_col)
                max_col = max(self.column_sel_start_col, self.column_sel_end_col)

                for row in range(min_row, max_row + 1):
                    for col in range(min_col, max_col + 1):
                        byte_index = row * self.bytes_per_row + col
                        if byte_index < len(current_file.file_data):
                            bytes_to_format.add(byte_index)
            else:
                # Normal linear selection
                bytes_to_format.update(range(sel_start, sel_end + 1))

        # Only format bytes that need it
        for byte_index in bytes_to_format:
            if byte_index >= len(current_file.file_data):
                continue

            hex_pos, ascii_pos = get_positions(byte_index)
            # Skip if byte is outside rendered range
            if hex_pos is None or ascii_pos is None:
                continue

            is_cursor = (self.cursor_position is not None and byte_index == self.cursor_position)

            # Apply user highlights first (lowest priority)
            if byte_index in current_file.byte_highlights:
                highlight_info = current_file.byte_highlights[byte_index]
                highlight_color = QColor(highlight_info["color"])
                highlight_color.setAlpha(80)

                user_highlight_format = QTextCharFormat()
                if highlight_info.get("underline", False):
                    user_highlight_format.setUnderlineStyle(QTextCharFormat.WaveUnderline)
                    user_highlight_format.setUnderlineColor(highlight_color)
                    user_highlight_format.setFontUnderline(True)
                else:
                    user_highlight_format.setBackground(highlight_color)

                hex_cursor.setPosition(hex_pos)
                hex_cursor.movePosition(QTextCursor.Right, QTextCursor.KeepAnchor, 2)
                hex_cursor.mergeCharFormat(user_highlight_format)

                ascii_cursor.setPosition(ascii_pos)
                ascii_cursor.movePosition(QTextCursor.Right, QTextCursor.KeepAnchor, 1)
                ascii_cursor.mergeCharFormat(user_highlight_format)

            # Signature pointer formatting removed - overlays handle display

            # Apply color for modified bytes
            if byte_index in current_file.modified_bytes:
                hex_cursor.setPosition(hex_pos)
                hex_cursor.movePosition(QTextCursor.Right, QTextCursor.KeepAnchor, 2)
                hex_cursor.mergeCharFormat(modified_format)

                ascii_cursor.setPosition(ascii_pos)
                ascii_cursor.movePosition(QTextCursor.Right, QTextCursor.KeepAnchor, 1)
                ascii_cursor.mergeCharFormat(modified_format)

            # Apply color for inserted bytes
            elif byte_index in current_file.inserted_bytes:
                hex_cursor.setPosition(hex_pos)
                hex_cursor.movePosition(QTextCursor.Right, QTextCursor.KeepAnchor, 2)
                hex_cursor.mergeCharFormat(inserted_format)

                ascii_cursor.setPosition(ascii_pos)
                ascii_cursor.movePosition(QTextCursor.Right, QTextCursor.KeepAnchor, 1)
                ascii_cursor.mergeCharFormat(inserted_format)

            # Apply color for replaced bytes
            elif byte_index in current_file.replaced_bytes:
                hex_cursor.setPosition(hex_pos)
                hex_cursor.movePosition(QTextCursor.Right, QTextCursor.KeepAnchor, 2)
                hex_cursor.mergeCharFormat(replaced_format)

                ascii_cursor.setPosition(ascii_pos)
                ascii_cursor.movePosition(QTextCursor.Right, QTextCursor.KeepAnchor, 1)
                ascii_cursor.mergeCharFormat(replaced_format)

            # Apply selection highlighting
            if self.selection_start is not None and self.selection_end is not None:
                # Check if this byte should be highlighted based on selection mode
                should_highlight = False

                if self.column_selection_mode and self.column_sel_start_row is not None:
                    # Column selection - check if byte is in the selected column range
                    min_row = min(self.column_sel_start_row, self.column_sel_end_row)
                    max_row = max(self.column_sel_start_row, self.column_sel_end_row)
                    min_col = min(self.column_sel_start_col, self.column_sel_end_col)
                    max_col = max(self.column_sel_start_col, self.column_sel_end_col)

                    byte_row = byte_index // self.bytes_per_row
                    byte_col = byte_index % self.bytes_per_row

                    if min_row <= byte_row <= max_row and min_col <= byte_col <= max_col:
                        should_highlight = True
                else:
                    # Normal linear selection
                    sel_start = min(self.selection_start, self.selection_end)
                    sel_end = max(self.selection_start, self.selection_end)
                    if sel_start <= byte_index <= sel_end:
                        should_highlight = True

                if should_highlight:
                    hex_cursor.setPosition(hex_pos)
                    hex_cursor.movePosition(QTextCursor.Right, QTextCursor.KeepAnchor, 2)
                    hex_cursor.mergeCharFormat(selection_format)

                    ascii_cursor.setPosition(ascii_pos)
                    ascii_cursor.movePosition(QTextCursor.Right, QTextCursor.KeepAnchor, 1)
                    ascii_cursor.mergeCharFormat(selection_format)

            # Apply cursor highlighting on top (highest priority)
            if is_cursor:
                hex_cursor.setPosition(hex_pos)
                hex_cursor.movePosition(QTextCursor.Right, QTextCursor.KeepAnchor, 2)
                hex_cursor.mergeCharFormat(cursor_format)

                bold_format = QTextCharFormat()
                bold_format.setFontWeight(QFont.Bold)
                if self.cursor_nibble == 0:
                    hex_cursor.setPosition(hex_pos)
                    hex_cursor.movePosition(QTextCursor.Right, QTextCursor.KeepAnchor, 1)
                    hex_cursor.mergeCharFormat(bold_format)
                else:
                    hex_cursor.setPosition(hex_pos + 1)
                    hex_cursor.movePosition(QTextCursor.Right, QTextCursor.KeepAnchor, 1)
                    hex_cursor.mergeCharFormat(bold_format)

                ascii_cursor.setPosition(ascii_pos)
                ascii_cursor.movePosition(QTextCursor.Right, QTextCursor.KeepAnchor, 1)
                ascii_cursor.mergeCharFormat(cursor_format)

    def clear_display(self):
        self.offset_display.clear()
        self.hex_display.clear()
        self.ascii_display.clear()
        self.data_inspector.clear()
        # Clear pattern scan widget
        self.pattern_scan_widget.tree.clear()
        self.pattern_scan_widget.label_editors.clear()
        self.pattern_scan_widget.status_label.setText("Ready to scan")
        # Clear signature widget
        self.signature_widget.pointers.clear()
        self.signature_widget.rebuild_tree()

    def scroll_by_rows(self, num_rows):
        """Scroll the display by a specific number of rows (positive = down, negative = up)"""
        if self.current_tab_index < 0:
            return

        current_file = self.open_files[self.current_tab_index]
        file_data = current_file.file_data
        total_rows = (len(file_data) + self.bytes_per_row - 1) // self.bytes_per_row

        # Update the logical top row
        self.current_top_row = max(0, min(total_rows - 1, self.current_top_row + num_rows))

        # Check if we need to re-render (if we're outside the current window)
        rendered_start_row = self.rendered_start_byte // self.bytes_per_row
        rendered_end_row = self.rendered_end_byte // self.bytes_per_row

        # If scrolling outside the rendered window, trigger re-render
        if (self.current_top_row < rendered_start_row or
            self.current_top_row >= rendered_end_row or
            total_rows <= self.max_initial_rows):

            # For small files, just scroll the viewport
            if total_rows <= self.max_initial_rows:
                line_height = self.hex_display.fontMetrics().height()
                scrollbar = self.hex_display.verticalScrollBar()
                new_value = self.current_top_row * line_height
                scrollbar.setValue(new_value)
            else:
                # For large files, re-render around the new position
                self.render_at_row(self.current_top_row)
        else:
            # Just scroll within the current window
            line_height = self.hex_display.fontMetrics().height()
            scrollbar = self.hex_display.verticalScrollBar()

            # Calculate the scrollbar value for the desired row within the rendered window
            row_in_window = self.current_top_row - rendered_start_row
            new_value = row_in_window * line_height
            scrollbar.setValue(new_value)

        # Update navigation scrollbar to reflect new position
        self.update_nav_scrollbar_position()

    def render_at_row(self, target_row, center=False):
        """Re-render the display with target row visible"""
        if self.current_tab_index < 0:
            return

        current_file = self.open_files[self.current_tab_index]
        file_data = current_file.file_data
        total_rows = (len(file_data) + self.bytes_per_row - 1) // self.bytes_per_row

        # Calculate new render window centered on target row
        window_size = self.max_initial_rows
        half_window = window_size // 2

        new_start_row = max(0, target_row - half_window)
        new_end_row = min(total_rows, new_start_row + window_size)

        # Adjust if we're near the end
        if new_end_row == total_rows:
            new_start_row = max(0, new_end_row - window_size)

        new_start_byte = new_start_row * self.bytes_per_row
        new_end_byte = min(len(file_data), new_end_row * self.bytes_per_row)

        # Update rendered range
        self.rendered_start_byte = new_start_byte
        self.rendered_end_byte = new_end_byte

        # Re-render
        self.display_hex(preserve_scroll=False)

        # Set scrollbar position
        line_height = self.hex_display.fontMetrics().height()
        scrollbar = self.hex_display.verticalScrollBar()
        row_in_window = target_row - new_start_row

        if center:
            # Center the target row in the viewport
            viewport_height = self.hex_display.viewport().height()
            visible_rows = viewport_height // line_height if line_height > 0 else 0
            # Calculate offset to center the row
            center_offset = (visible_rows // 2) * line_height
            target_position = row_in_window * line_height
            scrollbar.setValue(max(0, target_position - center_offset))
            # Update current_top_row based on actual scroll position
            if line_height > 0:
                self.current_top_row = new_start_row + (scrollbar.value() // line_height)
        else:
            # Position target row at the top
            scrollbar.setValue(row_in_window * line_height)
            self.current_top_row = target_row

        # Update navigation scrollbar to reflect new position
        self.update_nav_scrollbar_position()

    def on_scroll(self, value):
        """Handle scroll events with minimal debouncing for responsiveness"""
        # Store the scroll position and restart the timer
        self.pending_scroll_position = value
        self.scroll_timer.start(50)  # Wait 50ms after scroll stops for immediate response

        # Update overlay positions immediately during scroll for smooth tracking
        if hasattr(self, 'signature_overlays'):
            scroll_value = value
            font_metrics = self.hex_display.fontMetrics()
            line_height = font_metrics.height()

            for overlay in self.signature_overlays:
                try:
                    # Get the pointer associated with this overlay
                    pointer = overlay.pointer
                    row_in_rendered = (pointer.offset - self.rendered_start_byte) // self.bytes_per_row

                    # Update Y position based on scroll
                    y_pos = 2 + row_in_rendered * line_height - scroll_value

                    # Move the overlay to new position
                    overlay.move(overlay.x(), int(y_pos))
                except:
                    pass

    def on_scroll_stopped(self):
        """Called when scrolling has stopped - update the display window"""
        if self.current_tab_index < 0 or self.pending_scroll_position is None:
            return

        current_file = self.open_files[self.current_tab_index]
        file_data = current_file.file_data
        total_rows = (len(file_data) + self.bytes_per_row - 1) // self.bytes_per_row

        # Only do dynamic loading for large files
        if total_rows <= self.max_initial_rows:
            # Update current_top_row for small files
            line_height = self.hex_display.fontMetrics().height()
            if line_height > 0:
                self.current_top_row = self.pending_scroll_position // line_height
            self.pending_scroll_position = None
            # Update overlays after scrolling stops
            self.update_signature_overlays()
            return

        scrollbar = self.hex_display.verticalScrollBar()

        # Calculate which row is currently at the top of the viewport
        line_height = self.hex_display.fontMetrics().height()
        rendered_start_row = self.rendered_start_byte // self.bytes_per_row

        if line_height > 0:
            row_in_window = self.pending_scroll_position // line_height
            self.current_top_row = rendered_start_row + row_in_window

        max_scroll = scrollbar.maximum()
        if max_scroll == 0:
            self.pending_scroll_position = None
            return

        # Define sliding window: keep max_initial_rows around current position
        window_size = self.max_initial_rows
        half_window = window_size // 2

        # Calculate new render window
        new_start_row = max(0, self.current_top_row - half_window)
        new_end_row = min(total_rows, new_start_row + window_size)

        # Adjust if we're near the end
        if new_end_row == total_rows:
            new_start_row = max(0, new_end_row - window_size)

        new_start_byte = new_start_row * self.bytes_per_row
        new_end_byte = min(len(file_data), new_end_row * self.bytes_per_row)

        # Only re-render if window changed significantly (more than 20% of window)
        threshold_rows = window_size // 5
        current_start_row = self.rendered_start_byte // self.bytes_per_row
        current_end_row = self.rendered_end_byte // self.bytes_per_row

        if (abs(new_start_row - current_start_row) > threshold_rows or
            abs(new_end_row - current_end_row) > threshold_rows):

            self.rendered_start_byte = new_start_byte
            self.rendered_end_byte = new_end_byte

            # Re-render with new window
            self.display_hex(preserve_scroll=False)

            # Restore position to show current_top_row at the top
            row_in_window = self.current_top_row - new_start_row
            scrollbar.setValue(row_in_window * line_height)

        self.pending_scroll_position = None

        # Update overlays after scrolling stops
        self.update_signature_overlays()

        # Update navigation scrollbar to reflect current position
        self.update_nav_scrollbar_position()

    def on_hex_click(self, event):
        if self.current_tab_index < 0:
            return

        current_file = self.open_files[self.current_tab_index]

        cursor = self.hex_display.cursorForPosition(event.pos())
        line = cursor.blockNumber()

        # Get column position from current block only (not entire document)
        block = cursor.block()
        col = cursor.position() - block.position()

        # Account for 2 leading spaces, then each byte is "XX " (3 chars)
        if col > 1:
            byte_in_row = (col - 2) // 3
        else:
            byte_in_row = 0

        # Clamp to valid range
        if byte_in_row < 0:
            byte_in_row = 0
        elif byte_in_row >= self.bytes_per_row:
            byte_in_row = self.bytes_per_row - 1

        # Calculate byte index based on rendered range
        start_row = self.rendered_start_byte // self.bytes_per_row
        absolute_row = start_row + line
        byte_index = absolute_row * self.bytes_per_row + byte_in_row

        if byte_index < len(current_file.file_data):
            # Check if boundaries are enabled and click is outside boundary columns
            if self.boundary_enabled:
                clicked_col = byte_in_row
                if clicked_col < self.boundary_start_col:
                    # Snap to start boundary
                    byte_in_row = self.boundary_start_col
                    byte_index = absolute_row * self.bytes_per_row + byte_in_row
                    print(f"Click on column {clicked_col} snapped to start boundary {self.boundary_start_col}")
                elif clicked_col > self.boundary_end_col:
                    # Snap to end boundary
                    byte_in_row = self.boundary_end_col
                    byte_index = absolute_row * self.bytes_per_row + byte_in_row
                    print(f"Click on column {clicked_col} snapped to end boundary {self.boundary_end_col}")

            # Check if edit box is active and byte is outside the edit box range
            if self.edit_box_active and (byte_index < self.edit_box_start or byte_index > self.edit_box_end):
                # Deactivate edit box when clicking outside the range
                self.edit_box_active = False
                if hasattr(self, 'edit_box_overlay'):
                    self.edit_box_overlay.clear_edit_box()
                print(f"Edit box deactivated - clicked byte {byte_index} outside range [{self.edit_box_start}, {self.edit_box_end}]")

            self.cursor_position = byte_index
            # Always start at the first nibble (high nibble) of the byte
            self.cursor_nibble = 0

            # Check if Ctrl is held for column selection
            if event.modifiers() & Qt.ControlModifier:
                # Start column selection mode
                self.column_selection_mode = True
                self.column_sel_start_row = absolute_row
                self.column_sel_start_col = byte_in_row
                self.column_sel_end_row = absolute_row
                self.column_sel_end_col = byte_in_row
                print(f"Column selection started: row={absolute_row}, col={byte_in_row}")
            else:
                # Normal selection mode
                self.column_selection_mode = False
                self.column_sel_start_row = None
                self.column_sel_start_col = None
                self.column_sel_end_row = None
                self.column_sel_end_col = None

            # Start selection on click
            self.selection_start = byte_index
            self.selection_end = byte_index

            print(f"Hex click: line={line}, col={col}, byte_in_row={byte_in_row}, byte_index={byte_index}")
            # Just update cursor/selection highlighting, don't redraw everything
            self.update_cursor_highlight()
            self.data_inspector.update()
            self.update_status()
            self.setFocus()  # Make sure main window has focus for keyboard events

    def on_ascii_click(self, event):
        if self.current_tab_index < 0:
            return

        current_file = self.open_files[self.current_tab_index]

        cursor = self.ascii_display.cursorForPosition(event.pos())
        line = cursor.blockNumber()

        # Get column position from current block only (not entire document)
        block = cursor.block()
        col = cursor.position() - block.position()

        # Clamp to valid range
        if col < 0:
            col = 0
        elif col >= self.bytes_per_row:
            col = self.bytes_per_row - 1

        # Calculate byte index based on rendered range
        start_row = self.rendered_start_byte // self.bytes_per_row
        absolute_row = start_row + line
        byte_index = absolute_row * self.bytes_per_row + col

        if byte_index < len(current_file.file_data):
            # Check if boundaries are enabled and click is outside boundary columns
            if self.boundary_enabled:
                if col < self.boundary_start_col:
                    # Snap to start boundary
                    col = self.boundary_start_col
                    byte_index = absolute_row * self.bytes_per_row + col
                    print(f"ASCII click on column snapped to start boundary {self.boundary_start_col}")
                elif col > self.boundary_end_col:
                    # Snap to end boundary
                    col = self.boundary_end_col
                    byte_index = absolute_row * self.bytes_per_row + col
                    print(f"ASCII click on column snapped to end boundary {self.boundary_end_col}")

            self.cursor_position = byte_index
            self.cursor_nibble = 0

            # Check if Ctrl is held for column selection
            if event.modifiers() & Qt.ControlModifier:
                # Start column selection mode
                self.column_selection_mode = True
                self.column_sel_start_row = absolute_row
                self.column_sel_start_col = col
                self.column_sel_end_row = absolute_row
                self.column_sel_end_col = col
                print(f"Column selection started: row={absolute_row}, col={col}")
            else:
                # Normal selection mode
                self.column_selection_mode = False
                self.column_sel_start_row = None
                self.column_sel_start_col = None
                self.column_sel_end_row = None
                self.column_sel_end_col = None

            # Start selection on click
            self.selection_start = byte_index
            self.selection_end = byte_index

            print(f"ASCII click: line={line}, col={col}, byte_index={byte_index}, cursor_pos={self.cursor_position}")
            # Just update cursor/selection highlighting, don't redraw everything
            self.update_cursor_highlight()
            self.data_inspector.update()
            self.update_status()
            self.setFocus()  # Make sure main window has focus for keyboard events

    def on_hex_hover(self, event):
        """Show tooltip for highlighted bytes and handle drag selection"""
        if self.current_tab_index < 0:
            return

        current_file = self.open_files[self.current_tab_index]
        cursor = self.hex_display.cursorForPosition(event.pos())
        line = cursor.blockNumber()

        # Get column position from current block only (not entire document)
        block = cursor.block()
        col = cursor.position() - block.position()

        # Account for 2 leading spaces
        byte_col = (col - 2) // 3 if col > 1 else 0
        if byte_col >= 0 and byte_col < self.bytes_per_row:
            # Calculate byte index based on rendered range
            start_row = self.rendered_start_byte // self.bytes_per_row
            absolute_row = start_row + line
            byte_index = absolute_row * self.bytes_per_row + byte_col

            # Handle drag selection - check if left mouse button is pressed
            if event.buttons() & Qt.LeftButton:
                if self.selection_start is not None and byte_index < len(current_file.file_data):
                    if self.column_selection_mode:
                        # Update column selection end position
                        self.column_sel_end_row = absolute_row
                        self.column_sel_end_col = byte_col

                        # Rebuild selection_start and selection_end based on column range
                        min_row = min(self.column_sel_start_row, self.column_sel_end_row)
                        max_row = max(self.column_sel_start_row, self.column_sel_end_row)
                        min_col = min(self.column_sel_start_col, self.column_sel_end_col)
                        max_col = max(self.column_sel_start_col, self.column_sel_end_col)

                        # Set selection bounds to encompass the column range
                        self.selection_start = min_row * self.bytes_per_row + min_col
                        self.selection_end = max_row * self.bytes_per_row + max_col
                        print(f"Column drag: rows {min_row}-{max_row}, cols {min_col}-{max_col}")
                    else:
                        # Normal linear selection
                        self.selection_end = byte_index

                    self.cursor_position = byte_index
                    self.display_hex(preserve_scroll=True)
                    self.update_status()

            # Show tooltip for highlighted bytes
            if byte_index in current_file.byte_highlights and byte_index < len(current_file.file_data):
                message = current_file.byte_highlights[byte_index].get("message", "")
                if message:
                    QToolTip.showText(event.globalPos(), message, self.hex_display)
                else:
                    QToolTip.hideText()
            else:
                QToolTip.hideText()

    def on_ascii_hover(self, event):
        """Show tooltip for highlighted bytes in ASCII view and handle drag selection"""
        if self.current_tab_index < 0:
            return

        current_file = self.open_files[self.current_tab_index]
        cursor = self.ascii_display.cursorForPosition(event.pos())
        line = cursor.blockNumber()

        # Get column position from current block only (not entire document)
        block = cursor.block()
        col = cursor.position() - block.position()

        if col >= 0 and col < self.bytes_per_row:
            # Calculate byte index based on rendered range
            start_row = self.rendered_start_byte // self.bytes_per_row
            absolute_row = start_row + line
            byte_index = absolute_row * self.bytes_per_row + col

            # Handle drag selection - check if left mouse button is pressed
            if event.buttons() & Qt.LeftButton:
                if self.selection_start is not None and byte_index < len(current_file.file_data):
                    if self.column_selection_mode:
                        # Update column selection end position
                        self.column_sel_end_row = absolute_row
                        self.column_sel_end_col = col

                        # Rebuild selection_start and selection_end based on column range
                        min_row = min(self.column_sel_start_row, self.column_sel_end_row)
                        max_row = max(self.column_sel_start_row, self.column_sel_end_row)
                        min_col = min(self.column_sel_start_col, self.column_sel_end_col)
                        max_col = max(self.column_sel_start_col, self.column_sel_end_col)

                        # Set selection bounds to encompass the column range
                        self.selection_start = min_row * self.bytes_per_row + min_col
                        self.selection_end = max_row * self.bytes_per_row + max_col
                        print(f"Column drag: rows {min_row}-{max_row}, cols {min_col}-{max_col}")
                    else:
                        # Normal linear selection
                        self.selection_end = byte_index

                    self.cursor_position = byte_index
                    self.display_hex(preserve_scroll=True)
                    self.update_status()

            # Show tooltip for highlighted bytes
            if byte_index in current_file.byte_highlights and byte_index < len(current_file.file_data):
                message = current_file.byte_highlights[byte_index].get("message", "")
                if message:
                    QToolTip.showText(event.globalPos(), message, self.ascii_display)
                else:
                    QToolTip.hideText()
            else:
                QToolTip.hideText()

    def on_hex_right_click(self, event):
        menu = QMenu(self)

        # Segment 1: Highlight-related
        highlight_action = menu.addAction("Highlight")
        highlight_action.triggered.connect(self.show_highlight_window)

        copy_offset_action = menu.addAction("Copy Offset")
        def copy_offset():
            if self.cursor_position is not None:
                offset_str = f"0x{self.cursor_position:X}"
                clipboard = QApplication.clipboard()
                clipboard.setText(offset_str)
                QMessageBox.information(self, "Copy Offset", f"Copied {offset_str} to clipboard")
        copy_offset_action.triggered.connect(copy_offset)

        menu.addSeparator()

        # Segment 2: Standard clipboard actions
        copy_action = menu.addAction("Copy")
        cut_action = menu.addAction("Cut")
        paste_write_action = menu.addAction("Paste (Write)")
        paste_insert_action = menu.addAction("Paste (Insert)")

        copy_action.triggered.connect(self.copy)
        cut_action.triggered.connect(self.cut)
        paste_write_action.triggered.connect(self.paste_write)
        paste_insert_action.triggered.connect(self.paste_insert)

        menu.addSeparator()

        # Segment 3: Fields actions
        if self.selection_start is not None and self.selection_end is not None:
            add_field_action = menu.addAction("Add Field")
            add_field_action.triggered.connect(self.add_field_from_selection)

            copy_subfield_action = menu.addAction("Copy Subfield")
            copy_subfield_action.triggered.connect(self.copy_subfield_from_selection)

        menu.exec_(event.globalPos())

    def on_ascii_right_click(self, event):
        self.on_hex_right_click(event)

    def on_offset_click(self, event):
        """Handle clicks on offset column - jump to the first byte of that row"""
        if self.current_tab_index < 0:
            return

        cursor = self.offset_display.cursorForPosition(event.pos())
        line_num = cursor.blockNumber()

        # Calculate the byte offset for the first byte in this row based on rendered range
        start_row = self.rendered_start_byte // self.bytes_per_row
        byte_offset = (start_row + line_num) * self.bytes_per_row

        # Only navigate if the offset is valid
        if byte_offset < len(self.open_files[self.current_tab_index].file_data):
            self.cursor_position = byte_offset
            self.cursor_nibble = 0
            self.selection_start = None
            self.selection_end = None
            self.display_hex(preserve_scroll=True)
            self.scroll_to_offset(byte_offset, center=True)

    def update_cursor_highlight(self):
        """Update only the cursor and selection highlighting without redrawing text"""
        if self.current_tab_index < 0:
            return

        # Check if edit box should be deactivated due to cursor moving outside range
        if self.edit_box_active and self.cursor_position is not None:
            if self.cursor_position < self.edit_box_start or self.cursor_position > self.edit_box_end:
                # Cursor moved outside edit box range, deactivate it
                self.edit_box_active = False
                if hasattr(self, 'edit_box_overlay'):
                    self.edit_box_overlay.clear_edit_box()
                print(f"Edit box deactivated - cursor moved to {self.cursor_position} outside range [{self.edit_box_start}, {self.edit_box_end}]")

        current_file = self.open_files[self.current_tab_index]
        self.apply_hex_formatting(current_file)

    def on_hex_scroll(self, value):
        self.offset_display.verticalScrollBar().setValue(value)
        self.ascii_display.verticalScrollBar().setValue(value)
        # Don't sync nav scrollbar if we're in the middle of handling a nav scroll event
        # (prevents feedback loop that causes scrollbar to jump)
        if not self.in_nav_scroll:
            # Sync navigation scrollbar (block signals to prevent loop)
            self.hex_nav_scrollbar.blockSignals(True)
            self.hex_nav_scrollbar.setValue(value)
            self.hex_nav_scrollbar.blockSignals(False)

    def on_nav_scroll(self, value):
        """Handle navigation scrollbar changes - represents full file, not just rendered portion"""
        if self.current_tab_index < 0:
            return

        # Set flag to prevent feedback loop
        self.in_nav_scroll = True
        try:
            current_file = self.open_files[self.current_tab_index]
            file_data = current_file.file_data
            total_rows = (len(file_data) + self.bytes_per_row - 1) // self.bytes_per_row

            if total_rows == 0:
                return

            # Calculate which row should be at top based on scrollbar position
            max_scroll = self.hex_nav_scrollbar.maximum()
            if max_scroll > 0:
                target_row = int((value / max_scroll) * total_rows)
                target_row = max(0, min(total_rows - 1, target_row))

                # Use the row-based scrolling system
                if target_row != self.current_top_row:
                    self.current_top_row = target_row

                    # Check if we need to re-render
                    if total_rows > self.max_initial_rows:
                        rendered_start_row = self.rendered_start_byte // self.bytes_per_row
                        rendered_end_row = self.rendered_end_byte // self.bytes_per_row

                        if target_row < rendered_start_row or target_row >= rendered_end_row:
                            self.render_at_row(target_row, center=False)
                        else:
                            # Scroll within current window
                            line_height = self.hex_display.fontMetrics().height()
                            scrollbar = self.hex_display.verticalScrollBar()
                            row_in_window = target_row - rendered_start_row
                            scrollbar.setValue(row_in_window * line_height)
                    else:
                        # Small file, just scroll the viewport
                        line_height = self.hex_display.fontMetrics().height()
                        scrollbar = self.hex_display.verticalScrollBar()
                        scrollbar.setValue(target_row * line_height)
        finally:
            # Always clear flag, even if exception occurs
            self.in_nav_scroll = False

    def update_nav_scrollbar_range(self, min_val, max_val):
        """Update navigation scrollbar to represent the full file"""
        if self.current_tab_index < 0:
            return

        current_file = self.open_files[self.current_tab_index]
        file_data = current_file.file_data
        total_rows = (len(file_data) + self.bytes_per_row - 1) // self.bytes_per_row

        self.hex_nav_scrollbar.blockSignals(True)
        # Set range to represent full file (0 to total_rows in pixel units)
        # Use a large range for smooth scrolling
        total_pixels = total_rows * 100  # Arbitrary multiplier for smooth scrolling
        self.hex_nav_scrollbar.setRange(0, total_pixels)

        # Set page step based on visible rows
        viewport_height = self.hex_display.viewport().height()
        line_height = self.hex_display.fontMetrics().height()
        visible_rows = viewport_height // line_height if line_height > 0 else 20
        page_step = (visible_rows / total_rows * total_pixels) if total_rows > 0 else 100
        self.hex_nav_scrollbar.setPageStep(int(page_step))
        self.hex_nav_scrollbar.blockSignals(False)

        # Update scrollbar position to reflect current_top_row
        self.update_nav_scrollbar_position()

    def update_nav_scrollbar_position(self):
        """Update the navigation scrollbar position to reflect current_top_row"""
        if self.current_tab_index < 0:
            return

        current_file = self.open_files[self.current_tab_index]
        file_data = current_file.file_data
        total_rows = (len(file_data) + self.bytes_per_row - 1) // self.bytes_per_row

        if total_rows == 0:
            return

        # Calculate scrollbar position based on current_top_row
        max_scroll = self.hex_nav_scrollbar.maximum()
        if max_scroll > 0 and total_rows > 0:
            ratio = self.current_top_row / total_rows
            new_value = int(ratio * max_scroll)

            self.hex_nav_scrollbar.blockSignals(True)
            self.hex_nav_scrollbar.setValue(new_value)
            self.hex_nav_scrollbar.blockSignals(False)

    # NOTE: update_data_inspector, clear_inspector, and update_bytes_from_inspector
    # have been moved to the datainspect.DataInspector class.
    # Use self.data_inspector.update(), self.data_inspector.clear(), and
    # self.data_inspector.update_bytes_from_editor() instead.

    def update_status(self):
        if self.current_tab_index < 0:
            self.status_label.setText("Ready")
            return

        current_file = self.open_files[self.current_tab_index]
        file_size = len(current_file.file_data)

        # Determine byte status at cursor position
        byte_status = ""
        if self.cursor_position is not None:
            if self.cursor_position in current_file.inserted_bytes:
                byte_status = " [Inserted]"
            elif self.cursor_position in current_file.replaced_bytes:
                byte_status = " [Replaced]"
            elif self.cursor_position in current_file.modified_bytes:
                byte_status = " [Modified]"
            else:
                byte_status = " [Original]"

        status = f"File: {os.path.basename(current_file.file_path)} | Size: {file_size} bytes"
        if self.cursor_position is not None:
            status += f" | Offset: 0x{self.cursor_position:X}"
        status += byte_status

        # Add current view info
        total_rows = (file_size + self.bytes_per_row - 1) // self.bytes_per_row
        if total_rows > self.max_initial_rows:
            # Calculate which rows are currently being displayed based on rendered range
            start_row = (self.rendered_start_byte // self.bytes_per_row) + 1
            end_row = min((self.rendered_end_byte + self.bytes_per_row - 1) // self.bytes_per_row, total_rows)
            status += f" | [Viewing rows {start_row:,}-{end_row:,} of {total_rows:,}]"

        self.status_label.setText(status)

    def on_pattern_result_clicked(self, offset, length):
        if self.current_tab_index < 0:
            return
        current_file = self.open_files[self.current_tab_index]
        if 0 <= offset < len(current_file.file_data):
            self.cursor_position = offset
            self.cursor_nibble = 0
            if length > 0:
                end_offset = min(offset + length - 1, len(current_file.file_data) - 1)
                self.selection_start = offset
                self.selection_end = end_offset
            else:
                self.selection_start = offset
                self.selection_end = offset
            self.display_hex()
            self.scroll_to_offset(offset, center=True)

    def on_signature_pointer_added(self, pointer):
        """Called when a signature pointer is added - refresh display to show overlay"""
        if self.current_tab_index >= 0:
            self.display_hex(preserve_scroll=True)

    def on_field_segment_clicked(self, start, end):
        """Called when a field segment is clicked - jump to and highlight that byte range"""
        if self.current_tab_index >= 0:
            self.highlight_bytes(start, end - start + 1)
            self.scroll_to_offset(start, center=True)

    def add_field_from_selection(self):
        """Add a new field from the current selection"""
        if self.selection_start is None or self.selection_end is None or self.current_tab_index < 0:
            return

        start = min(self.selection_start, self.selection_end)
        end = max(self.selection_start, self.selection_end) + 1

        print(f"DEBUG: Creating field from selection")
        print(f"  selection_start = {self.selection_start} (0x{self.selection_start:X})")
        print(f"  selection_end = {self.selection_end} (0x{self.selection_end:X})")
        print(f"  start = {start} (0x{start:X})")
        print(f"  end = {end} (0x{end:X}) [exclusive]")
        print(f"  This represents bytes 0x{start:X} through 0x{end-1:X} (inclusive)")

        from PyQt5.QtWidgets import QInputDialog
        label, ok = QInputDialog.getText(self, "Add Field", "Enter field label:", text=f"Field_{len(self.fields_widget.fields) + 1}")

        if ok and label:
            self.fields_widget.add_field(label, start, end, self.current_tab_index)
            self.right_panel_tabs.setCurrentWidget(self.fields_widget)

    def copy_subfield_from_selection(self):
        """Copy the current selection as a subfield segment"""
        if self.selection_start is None or self.selection_end is None or self.current_tab_index < 0:
            return

        start = min(self.selection_start, self.selection_end)
        end = max(self.selection_start, self.selection_end) + 1

        self.fields_widget.copy_segment(start, end, self.current_tab_index)
        self.right_panel_tabs.setCurrentWidget(self.fields_widget)

    def update_signature_overlays(self):
        """Update signature pointer overlay widgets positioned over hex display"""
        # Clear existing overlays
        for overlay in self.signature_overlays:
            try:
                # Disconnect signals before deleting to prevent crashes
                overlay.value_changed.disconnect()
                overlay.editingFinished.disconnect()
                overlay.returnPressed.disconnect()
                overlay.deleteLater()
            except (RuntimeError, TypeError):
                # Widget already deleted or signals already disconnected
                pass
        self.signature_overlays.clear()

        if self.current_tab_index < 0:
            return

        current_file = self.open_files[self.current_tab_index]

        # Get theme colors
        theme_colors = get_theme_colors(self.current_theme)

        # Get font metrics for positioning
        font_metrics = self.hex_display.fontMetrics()
        char_width = font_metrics.horizontalAdvance("0")
        line_height = font_metrics.height()

        # Calculate scroll offset
        scroll_value = self.hex_display.verticalScrollBar().value()

        # Iterate through all signature pointers
        for pointer in self.signature_widget.pointers:
            # Check if pointer is in rendered range
            if pointer.offset < self.rendered_start_byte or pointer.offset >= self.rendered_end_byte:
                continue

            # Calculate start row and column within rendered window
            row_in_rendered = (pointer.offset - self.rendered_start_byte) // self.bytes_per_row
            col = pointer.offset % self.bytes_per_row

            # Skip if pointer starts outside rendered window
            if row_in_rendered < 0:
                continue

            # Recalculate pointer value from current file data to reflect any changes
            # Skip recalculation for string types with custom values
            if pointer.offset + pointer.length <= len(current_file.file_data):
                if pointer.data_type.lower() == "string" and pointer.custom_value:
                    # Keep custom value, don't recalculate
                    pass
                else:
                    pointer.value = self.signature_widget.interpret_value(
                        current_file.file_data, pointer.offset, pointer.length, pointer.data_type,
                        self.signature_widget.string_display_mode, pointer
                    )

            # Calculate X position at START of pointer: 4px left padding + 2 spaces + col * 3 characters (XX + space)
            x_pos = 4 + (2 + col * 3) * char_width

            # Calculate Y position: account for scroll and 2px top padding
            y_pos = 2 + row_in_rendered * line_height - scroll_value

            # Create editable overlay
            overlay = ClickableOverlay(pointer, self.hex_display)
            overlay.value_changed.connect(self.on_overlay_value_changed)
            overlay.offset_jump.connect(self.on_offset_jump)
            overlay.clicked.connect(self.on_overlay_clicked)

            # Show interpreted value instead of raw hex bytes
            # For string types: show custom value if set
            if pointer.data_type.lower() == "string" and pointer.custom_value:
                value_str = pointer.custom_value
            # For offset types: always show the offset value (clickable to jump)
            elif pointer.data_type.lower().startswith("offset") or pointer.data_type.lower() in ["string (offset)", "string (ref.)"]:
                value_str = str(pointer.value)
            else:
                value_str = str(pointer.value)

            overlay.setText(value_str)
            overlay.setFont(QFont("Courier", 10))

            # Make N/A values read-only
            if str(pointer.value) == "N/A":
                overlay.setReadOnly(True)
            else:
                overlay.setReadOnly(False)

            # Use theme colors - background with button border
            # For gradient themes, use menubar_bg as fallback since background may not exist
            bg_color = theme_colors.get('background', theme_colors.get('menubar_bg', '#1a1a1a'))
            button_color = theme_colors.get('button_bg', '#3e3e42')
            fg_color = theme_colors.get('foreground', '#d4d4d4')

            overlay.setStyleSheet(f"""
                QLineEdit {{
                    background-color: {bg_color};
                    border: 2px solid {button_color};
                    padding: 0px;
                    margin: 0px;
                    color: {fg_color};
                }}
            """)

            # Calculate width based on hex bytes coverage
            # Boxes should NOT grow larger than the number of bytes they represent
            hex_coverage_width = (pointer.length * 3 - 1) * char_width
            overlay_width = hex_coverage_width

            overlay.setGeometry(int(x_pos), int(y_pos), int(overlay_width), line_height)

            # Set tooltip showing hex bytes and full value (for long values)
            hex_bytes = current_file.file_data[pointer.offset:pointer.offset + pointer.length]
            hex_str = " ".join(f"{b:02X}" for b in hex_bytes)
            tooltip_text = f"Hex: {hex_str}\nOffset: 0x{pointer.offset:X}"
            if pointer.label:
                tooltip_text = f"Label: {pointer.label}\n{tooltip_text}"
            # Add full value to tooltip if it's long
            if len(value_str) > 10:
                tooltip_text += f"\nValue: {value_str}"
            overlay.setToolTip(tooltip_text)

            # Check if overlays should be hidden
            if self.signature_widget.hide_overlay_values:
                overlay.hide()
            else:
                overlay.show()

            self.signature_overlays.append(overlay)

    def on_offset_jump(self, offset):
        """Jump to the specified offset when an offset pointer is double-clicked"""
        if self.current_tab_index < 0:
            return

        current_file = self.open_files[self.current_tab_index]

        # Validate offset is within file bounds
        if 0 <= offset < len(current_file.file_data):
            self.cursor_position = offset
            self.cursor_nibble = 0
            self.selection_start = offset
            self.selection_end = offset
            self.display_hex()
            self.scroll_to_offset(offset, center=True)

    def on_overlay_clicked(self, pointer):
        """Locate and highlight pointer in the pointer table when overlay is clicked"""
        if not self.signature_widget:
            return

        # For Segment type, highlight the segment of bytes indicated by the value
        if pointer.data_type.lower() == "segment":
            if self.current_tab_index >= 0:
                current_file = self.open_files[self.current_tab_index]

                # Parse the segment value from the pointer's interpreted value
                # Format is "0xSTART-0xEND: VALUE"
                if isinstance(pointer.value, str) and ":" in pointer.value:
                    try:
                        # Extract the numeric value from the formatted string
                        value_str = pointer.value.split(":")[-1].strip()
                        segment_length = int(value_str)

                        # Use segment_start from pointer
                        segment_start = pointer.segment_start if hasattr(pointer, 'segment_start') else pointer.offset
                        segment_end = min(segment_start + segment_length - 1, len(current_file.file_data) - 1)

                        if segment_end >= segment_start and segment_length > 0:
                            self.selection_start = segment_start
                            self.selection_end = segment_end
                            self.scroll_to_offset(segment_start, center=True)
                            self.display_hex(preserve_scroll=True)

                            # Show info in status bar
                            self.status_label.setText(
                                f"Segment: 0x{segment_start:X} - 0x{segment_end:X} ({segment_length} bytes)"
                            )
                    except (ValueError, AttributeError):
                        pass

        # Find the pointer in the tree and select it
        self.signature_widget.locate_pointer_in_tree(pointer)

    def on_overlay_value_changed(self, pointer, new_value):
        """Handle inline editing of pointer value"""
        if self.current_tab_index < 0:
            return

        current_file = self.open_files[self.current_tab_index]
        file_data = current_file.file_data

        if new_value:
            try:
                # For string types, store custom value and don't modify bytes
                if pointer.data_type.lower() == "string":
                    # Check if value actually changed
                    current_display = pointer.custom_value if pointer.custom_value else str(pointer.value)
                    if new_value == current_display:
                        return

                    # Store the custom value
                    pointer.custom_value = new_value

                    # Update tree display
                    self.signature_widget.rebuild_tree()

                    # Refresh display to update the overlay
                    self.display_hex(preserve_scroll=True)
                    return

                # For offset types and string offset/ref types, update the label instead of modifying bytes
                dtype_lower = pointer.data_type.lower()
                if dtype_lower.startswith("offset") or dtype_lower in ["string (offset)", "string (ref.)"]:
                    # Check if value actually changed
                    current_display = pointer.label if (pointer.label and not pointer.label.startswith("Selection_")) else str(pointer.value)
                    if new_value == current_display or new_value == str(pointer.value):
                        return

                    # Update the label to the custom string
                    pointer.label = new_value

                    # Update tree display
                    self.signature_widget.rebuild_tree()

                    # Refresh display to update the overlay
                    self.display_hex(preserve_scroll=True)
                    return

                # For segment types, update the bytes (the value determines the segment length)
                if pointer.data_type.lower() == "segment":
                    # If the value contains ":", extract just the number part
                    if ":" in new_value:
                        new_value = new_value.split(":")[-1].strip()

                    # Convert value to bytes and update
                    new_bytes = self.signature_widget.value_to_bytes(new_value, pointer.data_type, pointer.length, pointer)
                    if new_bytes:
                        for i, byte in enumerate(new_bytes):
                            if pointer.offset + i < len(file_data):
                                file_data[pointer.offset + i] = byte

                        # Re-interpret the value
                        pointer.value = self.signature_widget.interpret_value(
                            file_data, pointer.offset, pointer.length, pointer.data_type,
                            self.signature_widget.string_display_mode, pointer
                        )

                        # Mark as modified and update UI
                        current_file.modified = True
                        self.update_tab_title()
                        self.signature_widget.rebuild_tree()
                        self.display_hex(preserve_scroll=True)
                    return

                # Check if value actually changed by comparing with current value
                current_value = str(pointer.value)
                if new_value == current_value:
                    # No change, just refresh without marking as modified
                    return

                # Convert new value to bytes using the signature widget's method
                new_bytes = self.signature_widget.value_to_bytes(new_value, pointer.data_type, pointer.length, pointer)
                if new_bytes:
                    # Save undo state
                    self.save_undo_state()

                    # Update file data
                    for i, byte in enumerate(new_bytes):
                        if pointer.offset + i < len(file_data):
                            file_data[pointer.offset + i] = byte
                            current_file.modified_bytes.add(pointer.offset + i)

                    # Mark file as modified
                    current_file.modified = True

                    # Recalculate pointer value
                    pointer.value = self.signature_widget.interpret_value(
                        file_data, pointer.offset, pointer.length, pointer.data_type,
                        self.signature_widget.string_display_mode, pointer
                    )

                    # Update tree display
                    self.signature_widget.rebuild_tree()

                    # Update tab title
                    tab_text = os.path.basename(current_file.file_path) + " *"
                    self.tab_widget.setTabText(self.current_tab_index, tab_text)

                    # Refresh display
                    self.display_hex(preserve_scroll=True)
                else:
                    QMessageBox.warning(self, "Invalid Value", "The value you entered is invalid for this data type.")
                    # Restore original value
                    self.display_hex(preserve_scroll=True)
            except Exception as e:
                QMessageBox.warning(self, "Error", f"Failed to update value: {str(e)}")
                # Restore original value
                self.display_hex(preserve_scroll=True)

    def save_pattern_labels_to_current_file(self):
        if self.current_tab_index < 0:
            return
        current_file = self.open_files[self.current_tab_index]
        current_file.pattern_labels.clear()

        # Extract labels from pattern scan widget tree
        root = self.pattern_scan_widget.tree.invisibleRootItem()
        for i in range(root.childCount()):
            category_item = root.child(i)
            for j in range(category_item.childCount()):
                item = category_item.child(j)
                result = item.data(0, Qt.UserRole)
                if isinstance(result, PatternResult) and result.label:
                    current_file.pattern_labels[result.offset] = result.label

    def load_pattern_labels_to_widget(self):
        if self.current_tab_index < 0:
            return
        current_file = self.open_files[self.current_tab_index]

        # Apply saved labels to pattern scan results
        root = self.pattern_scan_widget.tree.invisibleRootItem()
        for i in range(root.childCount()):
            category_item = root.child(i)
            for j in range(category_item.childCount()):
                item = category_item.child(j)
                result = item.data(0, Qt.UserRole)
                if isinstance(result, PatternResult):
                    if result.offset in current_file.pattern_labels:
                        result.label = current_file.pattern_labels[result.offset]
                        # Update the label editor widget
                        if result.offset in self.pattern_scan_widget.label_editors:
                            self.pattern_scan_widget.label_editors[result.offset].setText(result.label)

    def first_byte(self):
        """Jump to the first byte of the file"""
        if self.cursor_position is not None and self.current_tab_index >= 0:
            self.cursor_position = 0
            self.cursor_nibble = 0
            self.display_hex(preserve_scroll=True)
            self.scroll_to_offset(0)
            self.data_inspector.update()

    def last_byte(self):
        """Jump to the last byte of the file"""
        if self.cursor_position is not None and self.current_tab_index >= 0:
            current_file = self.open_files[self.current_tab_index]
            if len(current_file.file_data) > 0:
                self.cursor_position = len(current_file.file_data) - 1
                self.cursor_nibble = 0
                self.display_hex(preserve_scroll=True)
                self.scroll_to_offset(self.cursor_position)
                self.data_inspector.update()

    def prev_byte(self):
        if self.cursor_position is not None and self.cursor_position > 0:
            self.cursor_position -= 1
            self.cursor_nibble = 0
            self.display_hex(preserve_scroll=True)
            self.scroll_to_offset(self.cursor_position)
            self.data_inspector.update()

    def next_byte(self):
        if self.cursor_position is not None and self.current_tab_index >= 0:
            current_file = self.open_files[self.current_tab_index]
            if self.cursor_position < len(current_file.file_data) - 1:
                self.cursor_position += 1
                self.cursor_nibble = 0
                self.display_hex(preserve_scroll=True)
                self.scroll_to_offset(self.cursor_position)
                self.data_inspector.update()

    def scroll_tabs_left(self):
        """Scroll the tab bar to the left"""
        tab_bar = self.tab_widget.tabBar()
        if tab_bar:
            # Get the current scroll position and scroll left
            scroll_buttons = tab_bar.findChildren(QToolButton)
            for button in scroll_buttons:
                if 'Left' in button.objectName() or button.arrowType() == Qt.LeftArrow:
                    button.click()
                    break

    def scroll_tabs_right(self):
        """Scroll the tab bar to the right"""
        tab_bar = self.tab_widget.tabBar()
        if tab_bar:
            # Get the current scroll position and scroll right
            scroll_buttons = tab_bar.findChildren(QToolButton)
            for button in scroll_buttons:
                if 'Right' in button.objectName() or button.arrowType() == Qt.RightArrow:
                    button.click()
                    break

    def toggle_endian(self):
        self.endian_mode = 'big' if self.endian_mode == 'little' else 'little'
        self.endian_btn.setText(
            f"Byte Order: {'Little' if self.endian_mode == 'little' else 'Big'} Endian"
        )
        self.data_inspector.update()

    def format_integral(self, value, num_digits=None, signed=False):
        """Format an integral value based on current basis setting."""
        if self.integral_basis == 'hex':
            if signed and value < 0:
                # For signed negative values, convert to unsigned representation
                if num_digits == 2:
                    value = value & 0xFF
                elif num_digits == 4:
                    value = value & 0xFFFF
                elif num_digits == 6:
                    value = value & 0xFFFFFF
                elif num_digits == 8:
                    value = value & 0xFFFFFFFF
                elif num_digits == 16:
                    value = value & 0xFFFFFFFFFFFFFFFF
            if num_digits:
                return f"0x{value:0{num_digits}X}"
            else:
                return f"0x{value:X}"
        elif self.integral_basis == 'oct':
            return f"0o{value:o}"
        else:  # dec
            return str(value)

    def on_basis_changed(self, basis_type):
        """Handle basis checkbox changes - ensure only one is selected at a time."""
        # Block signals to prevent recursive calls
        self.hex_basis_check.blockSignals(True)
        self.dec_basis_check.blockSignals(True)
        self.oct_basis_check.blockSignals(True)

        # Uncheck all
        self.hex_basis_check.setChecked(False)
        self.dec_basis_check.setChecked(False)
        self.oct_basis_check.setChecked(False)

        # Check the selected one and set basis
        if basis_type == 'hex':
            self.hex_basis_check.setChecked(True)
            self.integral_basis = 'hex'
        elif basis_type == 'oct':
            self.oct_basis_check.setChecked(True)
            self.integral_basis = 'oct'
        else:  # dec
            self.dec_basis_check.setChecked(True)
            self.integral_basis = 'dec'

        # Restore signals
        self.hex_basis_check.blockSignals(False)
        self.dec_basis_check.blockSignals(False)
        self.oct_basis_check.blockSignals(False)

        self.data_inspector.update()

    def highlight_bytes(self, start_pos, byte_count):
        """Highlight a range of bytes in the hex and ASCII displays"""
        print(f"DEBUG highlight_bytes: start_pos={start_pos} (0x{start_pos:X}), byte_count={byte_count}")
        print(f"  Will highlight bytes 0x{start_pos:X} through 0x{start_pos + byte_count - 1:X}")

        if self.current_tab_index < 0 or not self.open_files:
            return

        current_file = self.open_files[self.current_tab_index]
        file_data = current_file.file_data

        if start_pos < 0 or start_pos >= len(file_data):
            return

        # Clear all existing formatting first
        hex_cursor = self.hex_display.textCursor()
        hex_cursor.select(QTextCursor.Document)
        hex_cursor.setCharFormat(QTextCharFormat())
        hex_cursor.clearSelection()

        ascii_cursor = self.ascii_display.textCursor()
        ascii_cursor.select(QTextCursor.Document)
        ascii_cursor.setCharFormat(QTextCharFormat())
        ascii_cursor.clearSelection()

        # Apply formatting
        self.apply_hex_formatting(current_file)

        # Highlight format for inspector selection (blue)
        highlight_format = QTextCharFormat()
        highlight_format.setBackground(QColor(50, 100, 200))

        # Highlight the range
        for i in range(byte_count):
            byte_index = start_pos + i
            if byte_index >= len(file_data):
                break

            row_num = byte_index // self.bytes_per_row
            col_num = byte_index % self.bytes_per_row

            # Highlight in hex display (only the 2 hex digits, not the trailing space)
            hex_chars_per_row = self.bytes_per_row * 3 + 2
            hex_pos = row_num * hex_chars_per_row + 2 + (col_num * 3)

            hex_cursor = self.hex_display.textCursor()
            hex_cursor.setPosition(hex_pos)
            hex_cursor.setPosition(hex_pos + 2, QTextCursor.KeepAnchor)
            hex_cursor.setCharFormat(highlight_format)

            # Highlight in ASCII display
            ascii_chars_per_row = self.bytes_per_row
            ascii_pos = row_num * ascii_chars_per_row + col_num

            ascii_cursor = self.ascii_display.textCursor()
            ascii_cursor.setPosition(ascii_pos)
            ascii_cursor.setPosition(ascii_pos + 1, QTextCursor.KeepAnchor)
            ascii_cursor.setCharFormat(highlight_format)

    def cycle_offset_mode(self, event):
        """Cycle through hex -> decimal -> octal offset modes"""
        modes = ['h', 'd', 'o']
        labels = {'h': 'Offset (h)', 'd': 'Offset (d)', 'o': 'Offset (o)'}

        current_index = modes.index(self.offset_mode)
        next_index = (current_index + 1) % len(modes)
        self.offset_mode = modes[next_index]

        self.offset_header.setText(labels[self.offset_mode])
        self.hex_header.setText(self.build_hex_header())
        self.display_hex()

    def save_undo_state(self):
        if self.current_tab_index < 0:
            return

        current_file = self.open_files[self.current_tab_index]
        state = {
            'data': bytearray(current_file.file_data),
            'modified_bytes': set(current_file.modified_bytes),
            'inserted_bytes': set(current_file.inserted_bytes),
            'replaced_bytes': set(current_file.replaced_bytes),
            'byte_highlights': dict(current_file.byte_highlights),
            'pattern_highlights': list(current_file.pattern_highlights)
        }
        self.undo_stack.append(state)
        self.redo_stack.clear()

        # Limit undo stack size
        if len(self.undo_stack) > 100:
            self.undo_stack.pop(0)

        # Schedule snapshot creation after edit
        self.schedule_snapshot()

    def undo(self):
        if not self.undo_stack or self.current_tab_index < 0:
            return

        current_file = self.open_files[self.current_tab_index]

        # Save current state to redo stack
        current_state = {
            'data': bytearray(current_file.file_data),
            'modified_bytes': set(current_file.modified_bytes),
            'inserted_bytes': set(current_file.inserted_bytes),
            'replaced_bytes': set(current_file.replaced_bytes),
            'byte_highlights': dict(current_file.byte_highlights),
            'pattern_highlights': list(current_file.pattern_highlights)
        }
        self.redo_stack.append(current_state)

        # Restore previous state
        state = self.undo_stack.pop()
        current_file.file_data = state['data']
        current_file.modified_bytes = state['modified_bytes']
        current_file.inserted_bytes = state['inserted_bytes']
        current_file.replaced_bytes = state.get('replaced_bytes', set())
        current_file.byte_highlights = state.get('byte_highlights', {})
        current_file.pattern_highlights = state.get('pattern_highlights', [])
        current_file.modified = len(state['modified_bytes']) > 0 or len(state['inserted_bytes']) > 0 or len(current_file.replaced_bytes) > 0
        current_file.pattern_highlights_dirty = True  # Mark pattern highlights for reapplication after undo

        self.display_hex()

    def redo(self):
        if not self.redo_stack or self.current_tab_index < 0:
            return

        current_file = self.open_files[self.current_tab_index]

        # Save current state to undo stack
        current_state = {
            'data': bytearray(current_file.file_data),
            'modified_bytes': set(current_file.modified_bytes),
            'inserted_bytes': set(current_file.inserted_bytes),
            'replaced_bytes': set(current_file.replaced_bytes),
            'byte_highlights': dict(current_file.byte_highlights),
            'pattern_highlights': list(current_file.pattern_highlights)
        }
        self.undo_stack.append(current_state)

        # Restore redo state
        state = self.redo_stack.pop()
        current_file.file_data = state['data']
        current_file.modified_bytes = state['modified_bytes']
        current_file.inserted_bytes = state['inserted_bytes']
        current_file.replaced_bytes = state.get('replaced_bytes', set())
        current_file.byte_highlights = state.get('byte_highlights', {})
        current_file.pattern_highlights = state.get('pattern_highlights', [])
        current_file.modified = len(state['modified_bytes']) > 0 or len(state['inserted_bytes']) > 0 or len(current_file.replaced_bytes) > 0
        current_file.pattern_highlights_dirty = True  # Mark pattern highlights for reapplication after redo

        self.display_hex()

    def show_file_size_warning(self, parent, num_bytes, is_increase):
        """Show file size change warning with checkbox to ignore future warnings"""
        if self.ignore_file_size_warnings:
            return True

        # Play beep for file size change warning
        QApplication.beep()

        action = "increase" if is_increase else "decrease"
        dialog = QDialog(parent)
        dialog.setWindowTitle("Warning: File Size Change")
        dialog.setMinimumSize(350, 150)

        layout = QVBoxLayout()

        # Warning message
        message = QLabel(
            f"This action will {action} file size by {num_bytes} byte(s).\n\n"
            f"{'Inserting' if is_increase else 'Removing'} bytes may corrupt structured file formats.\n\n"
            "Continue?"
        )
        message.setWordWrap(True)
        layout.addWidget(message)

        # Checkbox to ignore future warnings
        ignore_checkbox = QCheckBox("Don't show this warning again")
        layout.addWidget(ignore_checkbox)

        # Buttons
        button_box = QDialogButtonBox(QDialogButtonBox.Yes | QDialogButtonBox.No)
        button_box.button(QDialogButtonBox.No).setDefault(True)

        def on_accept():
            if ignore_checkbox.isChecked():
                self.ignore_file_size_warnings = True
            dialog.accept()

        button_box.accepted.connect(on_accept)
        button_box.rejected.connect(dialog.reject)
        layout.addWidget(button_box)

        dialog.setLayout(layout)
        return dialog.exec_() == QDialog.Accepted

    def copy(self):
        if self.current_tab_index < 0:
            return

        if self.selection_start is not None and self.selection_end is not None:
            current_file = self.open_files[self.current_tab_index]

            # Handle column selection mode differently
            if self.column_selection_mode and self.column_sel_start_row is not None:
                # Column-based copy - collect bytes from selected columns across rows
                min_row = min(self.column_sel_start_row, self.column_sel_end_row)
                max_row = max(self.column_sel_start_row, self.column_sel_end_row)
                min_col = min(self.column_sel_start_col, self.column_sel_end_col)
                max_col = max(self.column_sel_start_col, self.column_sel_end_col)

                # Collect bytes column by column within each row
                copied_bytes = bytearray()
                for row in range(min_row, max_row + 1):
                    for col in range(min_col, max_col + 1):
                        pos = row * self.bytes_per_row + col
                        if pos < len(current_file.file_data):
                            copied_bytes.append(current_file.file_data[pos])

                self.clipboard = bytes(copied_bytes)
                # Store grid dimensions for structured pasting
                self.clipboard_grid_rows = max_row - min_row + 1
                self.clipboard_grid_cols = max_col - min_col + 1
            else:
                # Normal linear selection
                start = min(self.selection_start, self.selection_end)
                end = max(self.selection_start, self.selection_end)
                self.clipboard = bytes(current_file.file_data[start:end + 1])
                # Clear grid dimensions for linear selection
                self.clipboard_grid_rows = None
                self.clipboard_grid_cols = None
        elif self.cursor_position is not None:
            current_file = self.open_files[self.current_tab_index]
            self.clipboard = bytes([current_file.file_data[self.cursor_position]])
            # Clear grid dimensions for single byte copy
            self.clipboard_grid_rows = None
            self.clipboard_grid_cols = None

        # Also copy to system clipboard as both hex string and raw bytes
        if self.clipboard:
            system_clipboard = QApplication.clipboard()
            # Copy as hex string for easy viewing/pasting
            hex_string = ' '.join(f'{b:02X}' for b in self.clipboard)
            system_clipboard.setText(hex_string)

    def cut(self):
        if self.current_tab_index < 0:
            return

        if self.selection_start is not None and self.selection_end is not None:
            current_file = self.open_files[self.current_tab_index]

            # Handle column selection mode differently
            if self.column_selection_mode and self.column_sel_start_row is not None:
                # Column-based cut
                min_row = min(self.column_sel_start_row, self.column_sel_end_row)
                max_row = max(self.column_sel_start_row, self.column_sel_end_row)
                min_col = min(self.column_sel_start_col, self.column_sel_end_col)
                max_col = max(self.column_sel_start_col, self.column_sel_end_col)

                num_rows = max_row - min_row + 1
                num_cols = max_col - min_col + 1
                num_bytes = num_rows * num_cols

                # Warning prompt before cutting (reduces file size)
                if not self.show_file_size_warning(self, num_bytes, is_increase=False):
                    return

                # Copy to clipboard first (using column selection logic)
                copied_bytes = bytearray()
                for row in range(min_row, max_row + 1):
                    for col in range(min_col, max_col + 1):
                        pos = row * self.bytes_per_row + col
                        if pos < len(current_file.file_data):
                            copied_bytes.append(current_file.file_data[pos])
                self.clipboard = bytes(copied_bytes)
                # Store grid dimensions for structured pasting
                self.clipboard_grid_rows = num_rows
                self.clipboard_grid_cols = num_cols

                # Remove bytes from bottom to top, right to left to maintain position integrity
                self.save_undo_state()
                positions_to_remove = []
                for row in range(min_row, max_row + 1):
                    for col in range(min_col, max_col + 1):
                        pos = row * self.bytes_per_row + col
                        if pos < len(current_file.file_data):
                            positions_to_remove.append(pos)

                # Sort in reverse order to delete from end to beginning
                positions_to_remove.sort(reverse=True)

                # Track cumulative shift for each deletion
                for idx, pos in enumerate(positions_to_remove):
                    # Calculate how many positions were already removed before this one
                    shift_amount = idx

                    # Shift markers after this position
                    old_modified = set(current_file.modified_bytes)
                    old_inserted = set(current_file.inserted_bytes)
                    old_replaced = set(current_file.replaced_bytes)

                    current_file.modified_bytes.clear()
                    current_file.inserted_bytes.clear()
                    current_file.replaced_bytes.clear()

                    for p in old_modified:
                        if p < pos:
                            current_file.modified_bytes.add(p)
                        elif p > pos:
                            current_file.modified_bytes.add(p - 1)

                    for p in old_inserted:
                        if p < pos:
                            current_file.inserted_bytes.add(p)
                        elif p > pos:
                            current_file.inserted_bytes.add(p - 1)

                    for p in old_replaced:
                        if p < pos:
                            current_file.replaced_bytes.add(p)
                        elif p > pos:
                            current_file.replaced_bytes.add(p - 1)

                    # Shift highlights and labels
                    self.shift_non_pattern_highlights(current_file, pos, -1)
                    self.shift_pattern_labels(current_file, pos, -1)
                    self.shift_signature_pointers(pos, -1)

                    # Adjust fields
                    if hasattr(self, 'fields_widget'):
                        self.fields_widget.adjust_for_delete(pos, 1, self.current_tab_index)

                    # Delete the byte
                    del current_file.file_data[pos]

                current_file.modified = True
                current_file.pattern_highlights_dirty = True
                self.selection_start = None
                self.selection_end = None
                self.column_selection_mode = False
                self.cursor_position = min_row * self.bytes_per_row + min_col
                self.display_hex(preserve_scroll=True)
                self.scroll_to_offset(self.cursor_position)
            else:
                # Normal linear selection
                start = min(self.selection_start, self.selection_end)
                end = max(self.selection_start, self.selection_end)
                num_bytes = end - start + 1

                # Warning prompt before cutting (reduces file size)
                if not self.show_file_size_warning(self, num_bytes, is_increase=False):
                    return

                # Copy to clipboard first
                self.clipboard = bytes(current_file.file_data[start:end + 1])
                # Clear grid dimensions for linear selection
                self.clipboard_grid_rows = None
                self.clipboard_grid_cols = None

                # Then remove the bytes
                self.save_undo_state()

                # Shift all markers: remove markers in the cut range and shift markers after
                old_modified = set(current_file.modified_bytes)
                old_inserted = set(current_file.inserted_bytes)
                old_replaced = set(current_file.replaced_bytes)

                current_file.modified_bytes.clear()
                current_file.inserted_bytes.clear()
                current_file.replaced_bytes.clear()

                for pos in old_modified:
                    if pos < start:
                        current_file.modified_bytes.add(pos)
                    elif pos > end:
                        current_file.modified_bytes.add(pos - num_bytes)
                    # Positions within [start, end] are removed

                for pos in old_inserted:
                    if pos < start:
                        current_file.inserted_bytes.add(pos)
                    elif pos > end:
                        current_file.inserted_bytes.add(pos - num_bytes)
                    # Positions within [start, end] are removed

                for pos in old_replaced:
                    if pos < start:
                        current_file.replaced_bytes.add(pos)
                    elif pos > end:
                        current_file.replaced_bytes.add(pos - num_bytes)
                    # Positions within [start, end] are removed

                # Shift non-pattern highlights
                self.shift_non_pattern_highlights(current_file, start, -num_bytes)

                # Shift pattern labels
                self.shift_pattern_labels(current_file, start, -num_bytes)

                # Shift signature pointers
                self.shift_signature_pointers(start, -num_bytes)

                # Adjust fields
                if hasattr(self, 'fields_widget'):
                    self.fields_widget.adjust_for_delete(start, num_bytes, self.current_tab_index)

                del current_file.file_data[start:end + 1]
                current_file.modified = True
                current_file.pattern_highlights_dirty = True  # Mark pattern highlights for reapplication

                self.selection_start = None
                self.selection_end = None
                self.cursor_position = start
                self.display_hex(preserve_scroll=True)
                self.scroll_to_offset(self.cursor_position)
        elif self.cursor_position is not None:
            # Single byte cut
            if not self.show_file_size_warning(self, 1, is_increase=False):
                return

            current_file = self.open_files[self.current_tab_index]
            self.clipboard = bytes([current_file.file_data[self.cursor_position]])
            # Clear grid dimensions for single byte cut
            self.clipboard_grid_rows = None
            self.clipboard_grid_cols = None

            self.save_undo_state()

            # Shift all markers: remove marker at cursor position and shift markers after
            old_modified = set(current_file.modified_bytes)
            old_inserted = set(current_file.inserted_bytes)
            old_replaced = set(current_file.replaced_bytes)

            current_file.modified_bytes.clear()
            current_file.inserted_bytes.clear()
            current_file.replaced_bytes.clear()

            for pos in old_modified:
                if pos < self.cursor_position:
                    current_file.modified_bytes.add(pos)
                elif pos > self.cursor_position:
                    current_file.modified_bytes.add(pos - 1)
                # Position at cursor is removed

            for pos in old_inserted:
                if pos < self.cursor_position:
                    current_file.inserted_bytes.add(pos)
                elif pos > self.cursor_position:
                    current_file.inserted_bytes.add(pos - 1)
                # Position at cursor is removed

            for pos in old_replaced:
                if pos < self.cursor_position:
                    current_file.replaced_bytes.add(pos)
                elif pos > self.cursor_position:
                    current_file.replaced_bytes.add(pos - 1)
                # Position at cursor is removed

            # Shift non-pattern highlights
            self.shift_non_pattern_highlights(current_file, self.cursor_position, -1)

            # Shift pattern labels
            self.shift_pattern_labels(current_file, self.cursor_position, -1)

            # Shift signature pointers
            self.shift_signature_pointers(self.cursor_position, -1)

            # Adjust fields
            if hasattr(self, 'fields_widget'):
                self.fields_widget.adjust_for_delete(self.cursor_position, 1, self.current_tab_index)

            del current_file.file_data[self.cursor_position]
            current_file.modified = True
            current_file.pattern_highlights_dirty = True  # Mark pattern highlights for reapplication
            self.display_hex(preserve_scroll=True)
            self.scroll_to_offset(self.cursor_position)

        # Also copy to system clipboard as hex string
        if self.clipboard:
            system_clipboard = QApplication.clipboard()
            hex_string = ' '.join(f'{b:02X}' for b in self.clipboard)
            system_clipboard.setText(hex_string)

    def get_paste_data(self):
        """Get paste data from system clipboard or internal clipboard.
        Supports hex strings (with or without spaces) and regular text."""

        # Try system clipboard first
        system_clipboard = QApplication.clipboard()
        clipboard_text = system_clipboard.text().strip()

        if clipboard_text:
            # Try to parse as hex data first
            # Remove common separators
            hex_clean = clipboard_text.replace(' ', '').replace(':', '').replace('-', '').replace(',', '')

            # Check if it looks like hex (all chars are 0-9, A-F, a-f)
            if all(c in '0123456789ABCDEFabcdef' for c in hex_clean):
                # Must be even number of characters for valid hex
                if len(hex_clean) % 2 == 0:
                    try:
                        # Parse as hex bytes
                        return bytes.fromhex(hex_clean)
                    except ValueError:
                        pass  # Not valid hex, fall through to text interpretation

            # Not hex data, treat as regular text - convert to UTF-8 bytes
            try:
                return clipboard_text.encode('utf-8')
            except Exception:
                pass  # Encoding failed, fall through to internal clipboard

        # Fall back to internal clipboard
        return self.clipboard

    def paste_write(self):
        if self.current_tab_index < 0 or self.cursor_position is None:
            return

        # Deactivate edit box for paste operations
        if self.edit_box_active:
            self.edit_box_active = False
            if hasattr(self, 'edit_box_overlay'):
                self.edit_box_overlay.clear_edit_box()

        # Try to get data from system clipboard first, then fall back to internal clipboard
        paste_data = self.get_paste_data()
        if not paste_data:
            return

        current_file = self.open_files[self.current_tab_index]

        # Check if pasting over a selection
        if self.selection_start is not None and self.selection_end is not None:
            sel_start = min(self.selection_start, self.selection_end)
            sel_end = max(self.selection_start, self.selection_end)

            # Handle column selection mode differently
            if self.column_selection_mode and self.column_sel_start_row is not None:
                # Column-based paste
                min_row = min(self.column_sel_start_row, self.column_sel_end_row)
                max_row = max(self.column_sel_start_row, self.column_sel_end_row)
                min_col = min(self.column_sel_start_col, self.column_sel_end_col)
                max_col = max(self.column_sel_start_col, self.column_sel_end_col)

                num_rows = max_row - min_row + 1
                num_cols = max_col - min_col + 1
                selection_size = num_rows * num_cols
                paste_size = len(paste_data)

                # Show Smart Paste Dialog if sizes differ
                smart_paste_choice = None
                if paste_size != selection_size:
                    dialog = SmartPasteDialog(self, paste_size, selection_size)
                    if dialog.exec_() != QDialog.Accepted:
                        return  # User cancelled

                    choice, padding_value = dialog.get_result()
                    smart_paste_choice = choice

                    if choice == 'trim':
                        # Trim paste data to match selection size
                        # If clipboard has grid structure, maintain it during trim
                        if self.clipboard_grid_rows is not None and self.clipboard_grid_cols is not None:
                            # Structure-aware trim: extract the portion that fits
                            src_rows = self.clipboard_grid_rows
                            src_cols = self.clipboard_grid_cols
                            tgt_rows = num_rows
                            tgt_cols = num_cols

                            trimmed_data = bytearray()
                            data_idx = 0

                            for src_row in range(min(src_rows, tgt_rows)):
                                for src_col in range(min(src_cols, tgt_cols)):
                                    if data_idx < len(paste_data):
                                        trimmed_data.append(paste_data[data_idx])
                                    data_idx += 1
                                # Skip remaining columns in this row if src_cols > tgt_cols
                                if src_cols > tgt_cols:
                                    data_idx += (src_cols - tgt_cols)

                            paste_data = bytes(trimmed_data)
                            # Update grid metadata to match trimmed dimensions
                            self.clipboard_grid_rows = min(src_rows, tgt_rows)
                            self.clipboard_grid_cols = min(src_cols, tgt_cols)
                        else:
                            # Linear trim (no structure)
                            paste_data = paste_data[:selection_size]
                    elif choice == 'pad':
                        # Check if clipboard has grid structure metadata
                        if self.clipboard_grid_rows is not None and self.clipboard_grid_cols is not None:
                            # Structure-aware padding: maintain row/column layout
                            src_rows = self.clipboard_grid_rows
                            src_cols = self.clipboard_grid_cols
                            tgt_rows = num_rows
                            tgt_cols = num_cols

                            padded_data = bytearray()
                            data_idx = 0

                            for tgt_row in range(tgt_rows):
                                for tgt_col in range(tgt_cols):
                                    if tgt_row < src_rows and tgt_col < src_cols:
                                        # Data from source
                                        if data_idx < len(paste_data):
                                            padded_data.append(paste_data[data_idx])
                                            data_idx += 1
                                        else:
                                            # Source data exhausted (shouldn't happen)
                                            padded_data.extend(padding_value[:1])
                                    else:
                                        # Padding region
                                        padded_data.extend(padding_value[:1])

                            paste_data = bytes(padded_data)
                        else:
                            # Linear padding (no structure metadata)
                            bytes_needed = selection_size - paste_size
                            padding = bytearray()
                            while len(padding) < bytes_needed:
                                padding.extend(padding_value)
                            padding = padding[:bytes_needed]
                            paste_data = paste_data + bytes(padding)

                self.save_undo_state()

                # Paste data column-wise (row by row within the column range)
                # If ignore was chosen and data has grid structure, maintain that structure
                if smart_paste_choice == 'ignore' and self.clipboard_grid_rows is not None and self.clipboard_grid_cols is not None:
                    # Use source grid dimensions, not selection dimensions
                    src_rows = self.clipboard_grid_rows
                    src_cols = self.clipboard_grid_cols
                    data_index = 0

                    for src_row in range(src_rows):
                        for src_col in range(src_cols):
                            if data_index < len(paste_data):
                                # Map to target position starting at min_row, min_col
                                tgt_row = min_row + src_row
                                tgt_col = min_col + src_col
                                pos = tgt_row * self.bytes_per_row + tgt_col
                                if pos < len(current_file.file_data):
                                    current_file.file_data[pos] = paste_data[data_index]
                                    if pos not in current_file.inserted_bytes:
                                        current_file.modified_bytes.add(pos)
                                data_index += 1
                elif smart_paste_choice == 'ignore':
                    # Ignore chosen but no grid metadata - paste linearly starting at selection start
                    # Only paste the actual data without filling the entire selection
                    data_index = 0
                    row = min_row
                    col = min_col

                    while data_index < len(paste_data):
                        pos = row * self.bytes_per_row + col
                        if pos < len(current_file.file_data):
                            current_file.file_data[pos] = paste_data[data_index]
                            if pos not in current_file.inserted_bytes:
                                current_file.modified_bytes.add(pos)
                        data_index += 1

                        # Move to next position (linear, not confined to selection box)
                        col += 1
                        if col >= self.bytes_per_row:
                            # Wrap to next row
                            col = 0
                            row += 1
                else:
                    # Standard pasting with trim/pad: paste within the selection box
                    # If clipboard has grid structure after trim/pad, use it
                    if self.clipboard_grid_rows is not None and self.clipboard_grid_cols is not None:
                        # Structure-aware pasting
                        src_rows = self.clipboard_grid_rows
                        src_cols = self.clipboard_grid_cols
                        data_index = 0

                        for src_row in range(src_rows):
                            for src_col in range(src_cols):
                                if data_index < len(paste_data):
                                    # Map to target position
                                    tgt_row = min_row + src_row
                                    tgt_col = min_col + src_col
                                    pos = tgt_row * self.bytes_per_row + tgt_col
                                    if pos < len(current_file.file_data):
                                        current_file.file_data[pos] = paste_data[data_index]
                                        if pos not in current_file.inserted_bytes:
                                            current_file.modified_bytes.add(pos)
                                    data_index += 1
                    else:
                        # Linear pasting within selection box
                        data_index = 0
                        row = min_row
                        col = min_col

                        while data_index < len(paste_data):
                            pos = row * self.bytes_per_row + col
                            if pos < len(current_file.file_data):
                                current_file.file_data[pos] = paste_data[data_index]
                                if pos not in current_file.inserted_bytes:
                                    current_file.modified_bytes.add(pos)
                            data_index += 1

                            # Move to next position within selection box
                            col += 1
                            if col > max_col:
                                # Move to next row
                                col = min_col
                                row += 1

                paste_position = sel_start
            else:
                # Normal linear selection - paste without smart paste dialog
                # Check if clipboard has grid structure to preserve it
                paste_position = sel_start

                self.save_undo_state()

                if self.clipboard_grid_rows is not None and self.clipboard_grid_cols is not None:
                    # Preserve grid structure during paste
                    src_rows = self.clipboard_grid_rows
                    src_cols = self.clipboard_grid_cols
                    start_row = paste_position // self.bytes_per_row
                    start_col = paste_position % self.bytes_per_row
                    data_index = 0

                    for src_row in range(src_rows):
                        for src_col in range(src_cols):
                            if data_index < len(paste_data):
                                # Map to target position
                                tgt_row = start_row + src_row
                                tgt_col = start_col + src_col
                                pos = tgt_row * self.bytes_per_row + tgt_col
                                if pos < len(current_file.file_data):
                                    current_file.file_data[pos] = paste_data[data_index]
                                    if pos not in current_file.inserted_bytes:
                                        current_file.modified_bytes.add(pos)
                                data_index += 1
                else:
                    # Linear paste (no grid structure)
                    for i, byte in enumerate(paste_data):
                        pos = paste_position + i
                        if pos < len(current_file.file_data):
                            current_file.file_data[pos] = byte
                            if pos not in current_file.inserted_bytes:
                                current_file.modified_bytes.add(pos)
        else:
            # No selection, paste at cursor
            paste_position = self.cursor_position

            self.save_undo_state()

            if self.clipboard_grid_rows is not None and self.clipboard_grid_cols is not None:
                # Preserve grid structure during paste
                src_rows = self.clipboard_grid_rows
                src_cols = self.clipboard_grid_cols
                start_row = paste_position // self.bytes_per_row
                start_col = paste_position % self.bytes_per_row
                data_index = 0

                for src_row in range(src_rows):
                    for src_col in range(src_cols):
                        if data_index < len(paste_data):
                            # Map to target position
                            tgt_row = start_row + src_row
                            tgt_col = start_col + src_col
                            pos = tgt_row * self.bytes_per_row + tgt_col
                            if pos < len(current_file.file_data):
                                current_file.file_data[pos] = paste_data[data_index]
                                if pos not in current_file.inserted_bytes:
                                    current_file.modified_bytes.add(pos)
                            data_index += 1
            else:
                # Linear paste (no grid structure)
                for i, byte in enumerate(paste_data):
                    pos = paste_position + i
                    if pos < len(current_file.file_data):
                        current_file.file_data[pos] = byte
                        if pos not in current_file.inserted_bytes:
                            current_file.modified_bytes.add(pos)

        current_file.modified = True
        current_file.pattern_highlights_dirty = True  # Mark pattern highlights for reapplication
        self.display_hex(preserve_scroll=True)
        self.scroll_to_offset(paste_position)

    def paste_insert(self):
        if self.current_tab_index < 0 or self.cursor_position is None:
            return

        # Deactivate edit box for paste operations
        if self.edit_box_active:
            self.edit_box_active = False
            if hasattr(self, 'edit_box_overlay'):
                self.edit_box_overlay.clear_edit_box()

        # Try to get data from system clipboard first, then fall back to internal clipboard
        paste_data = self.get_paste_data()
        if not paste_data:
            return

        current_file = self.open_files[self.current_tab_index]

        # Initialize smart paste choice
        smart_paste_choice = None

        # Check if pasting over a selection
        insert_position = self.cursor_position
        if self.selection_start is not None and self.selection_end is not None:
            sel_start = min(self.selection_start, self.selection_end)
            sel_end = max(self.selection_start, self.selection_end)

            # Handle column selection mode differently
            if self.column_selection_mode and self.column_sel_start_row is not None:
                # Column-based paste - calculate selection size based on column dimensions
                min_row = min(self.column_sel_start_row, self.column_sel_end_row)
                max_row = max(self.column_sel_start_row, self.column_sel_end_row)
                min_col = min(self.column_sel_start_col, self.column_sel_end_col)
                max_col = max(self.column_sel_start_col, self.column_sel_end_col)

                num_rows = max_row - min_row + 1
                num_cols = max_col - min_col + 1
                selection_size = num_rows * num_cols
            else:
                # Normal linear selection - no smart paste dialog, just replace selection
                selection_size = sel_end - sel_start + 1

            # For column selections, show smart paste dialog if sizes differ
            if self.column_selection_mode and self.column_sel_start_row is not None:
                paste_size = len(paste_data)

                # Show Smart Paste Dialog if sizes differ
                smart_paste_choice = None
                if paste_size != selection_size:
                    dialog = SmartPasteDialog(self, paste_size, selection_size)
                    if dialog.exec_() != QDialog.Accepted:
                        return  # User cancelled

                    choice, padding_value = dialog.get_result()
                    smart_paste_choice = choice

                    if choice == 'trim':
                        # Trim paste data to match selection size
                        # If clipboard has grid structure, maintain it during trim
                        if self.clipboard_grid_rows is not None and self.clipboard_grid_cols is not None:
                            # Structure-aware trim: extract the portion that fits
                            src_rows = self.clipboard_grid_rows
                            src_cols = self.clipboard_grid_cols
                            tgt_rows = num_rows
                            tgt_cols = num_cols

                            trimmed_data = bytearray()
                            data_idx = 0

                            for src_row in range(min(src_rows, tgt_rows)):
                                for src_col in range(min(src_cols, tgt_cols)):
                                    if data_idx < len(paste_data):
                                        trimmed_data.append(paste_data[data_idx])
                                    data_idx += 1
                                # Skip remaining columns in this row if src_cols > tgt_cols
                                if src_cols > tgt_cols:
                                    data_idx += (src_cols - tgt_cols)

                            paste_data = bytes(trimmed_data)
                            # Update grid metadata to match trimmed dimensions
                            self.clipboard_grid_rows = min(src_rows, tgt_rows)
                            self.clipboard_grid_cols = min(src_cols, tgt_cols)
                        else:
                            # Linear trim (no structure)
                            paste_data = paste_data[:selection_size]
                    elif choice == 'pad':
                        # Check if clipboard has grid structure metadata
                        if self.clipboard_grid_rows is not None and self.clipboard_grid_cols is not None:
                            # Structure-aware padding: maintain row/column layout
                            src_rows = self.clipboard_grid_rows
                            src_cols = self.clipboard_grid_cols
                            tgt_rows = num_rows
                            tgt_cols = num_cols

                            padded_data = bytearray()
                            data_idx = 0

                            for tgt_row in range(tgt_rows):
                                for tgt_col in range(tgt_cols):
                                    if tgt_row < src_rows and tgt_col < src_cols:
                                        # Data from source
                                        if data_idx < len(paste_data):
                                            padded_data.append(paste_data[data_idx])
                                            data_idx += 1
                                        else:
                                            # Source data exhausted (shouldn't happen)
                                            padded_data.extend(padding_value[:1])
                                    else:
                                        # Padding region
                                        padded_data.extend(padding_value[:1])

                            paste_data = bytes(padded_data)
                        else:
                            # Linear padding (no structure metadata)
                            bytes_needed = selection_size - paste_size
                            padding = bytearray()
                            while len(padding) < bytes_needed:
                                padding.extend(padding_value)
                            padding = padding[:bytes_needed]
                            paste_data = paste_data + bytes(padding)
                    # If 'ignore' is chosen, keep original paste_data size

            # Use selection start as insert position
            insert_position = sel_start

            # For both linear and column selections, we delete the selected bytes
            selection_bytes_to_delete = selection_size
        else:
            selection_bytes_to_delete = 0

        # Calculate net file size change: bytes_to_insert - bytes_to_delete
        num_bytes = len(paste_data)
        net_size_change = num_bytes - selection_bytes_to_delete

        # Warning prompt (only if file size will change)
        if net_size_change > 0:
            if not self.show_file_size_warning(self, net_size_change, is_increase=True):
                return
        elif net_size_change < 0:
            if not self.show_file_size_warning(self, -net_size_change, is_increase=False):
                return

        self.save_undo_state()

        # Handle column selection specially - process row by row to maintain shape
        # Skip row-by-row processing if 'ignore' chosen without grid metadata
        if (self.selection_start is not None and self.selection_end is not None and
            self.column_selection_mode and self.column_sel_start_row is not None and
            not (smart_paste_choice == 'ignore' and
                 (self.clipboard_grid_rows is None or self.clipboard_grid_cols is None))):

            min_row = min(self.column_sel_start_row, self.column_sel_end_row)
            max_row = max(self.column_sel_start_row, self.column_sel_end_row)
            min_col = min(self.column_sel_start_col, self.column_sel_end_col)
            max_col = max(self.column_sel_start_col, self.column_sel_end_col)

            num_rows = max_row - min_row + 1
            num_cols = max_col - min_col + 1

            # Determine source dimensions for insertion
            # If 'ignore' was chosen and clipboard has grid metadata, use source dimensions
            use_source_grid = (smart_paste_choice == 'ignore' and
                             self.clipboard_grid_rows is not None and
                             self.clipboard_grid_cols is not None)

            if use_source_grid:
                src_rows = self.clipboard_grid_rows
                src_cols = self.clipboard_grid_cols
            else:
                # For trim/pad operations with grid structure, use the updated clipboard dimensions
                if self.clipboard_grid_rows is not None and self.clipboard_grid_cols is not None:
                    src_rows = self.clipboard_grid_rows
                    src_cols = self.clipboard_grid_cols
                else:
                    # No grid structure, use selection dimensions
                    src_rows = num_rows
                    src_cols = num_cols

            # Process row by row to maintain the column structure
            data_index = 0
            cumulative_offset = 0  # Track cumulative position changes

            for row_idx in range(src_rows):
                target_row = min_row + row_idx

                # For this row, delete the column selection bytes (only if within selection)
                row_positions = []
                if target_row <= max_row:
                    for col in range(min_col, max_col + 1):
                        pos = target_row * self.bytes_per_row + col + cumulative_offset
                        if pos < len(current_file.file_data):
                            row_positions.append(pos)

                first_row_pos = (target_row * self.bytes_per_row + min_col + cumulative_offset
                               if target_row <= max_row and row_positions
                               else target_row * self.bytes_per_row + min_col + cumulative_offset)

                # Delete this row's column bytes (from end to start) only if within selection
                delete_count = 0
                if target_row <= max_row and row_positions:
                    for pos in sorted(row_positions, reverse=True):
                        current_file.file_data.pop(pos)
                        current_file.modified_bytes.discard(pos)
                        current_file.inserted_bytes.discard(pos)
                        current_file.replaced_bytes.discard(pos)
                    delete_count = len(row_positions)

                # Extract the bytes for this row from paste_data using source columns
                row_paste_data = []
                for _ in range(src_cols):
                    if data_index < len(paste_data):
                        row_paste_data.append(paste_data[data_index])
                        data_index += 1
                    else:
                        break

                # Insert the new bytes for this row
                for i, byte in enumerate(row_paste_data):
                    current_file.file_data.insert(first_row_pos + i, byte)
                    current_file.inserted_bytes.add(first_row_pos + i)

                # Update cumulative offset
                cumulative_offset += len(row_paste_data) - delete_count

            # Rebuild all tracking sets after the complex operation
            # This is simpler than trying to track all the shifts
            current_file.pattern_highlights_dirty = True

        # If there's a normal linear selection (not column), delete it first before inserting
        elif (self.selection_start is not None and self.selection_end is not None):
            sel_start = min(self.selection_start, self.selection_end)
            sel_end = max(self.selection_start, self.selection_end)

            # Delete selected bytes (from end to start to maintain positions)
            for pos in range(sel_end, sel_start - 1, -1):
                if pos < len(current_file.file_data):
                    current_file.file_data.pop(pos)
                    # Remove from tracking sets
                    current_file.modified_bytes.discard(pos)
                    current_file.inserted_bytes.discard(pos)
                    current_file.replaced_bytes.discard(pos)

            # Shift all markers after the deleted range
            delete_count = sel_end - sel_start + 1
            old_modified = set(current_file.modified_bytes)
            old_inserted = set(current_file.inserted_bytes)
            old_replaced = set(current_file.replaced_bytes)

            current_file.modified_bytes.clear()
            current_file.inserted_bytes.clear()
            current_file.replaced_bytes.clear()

            for pos in old_modified:
                if pos > sel_end:
                    current_file.modified_bytes.add(pos - delete_count)
                elif pos < sel_start:
                    current_file.modified_bytes.add(pos)

            for pos in old_inserted:
                if pos > sel_end:
                    current_file.inserted_bytes.add(pos - delete_count)
                elif pos < sel_start:
                    current_file.inserted_bytes.add(pos)

            for pos in old_replaced:
                if pos > sel_end:
                    current_file.replaced_bytes.add(pos - delete_count)
                elif pos < sel_start:
                    current_file.replaced_bytes.add(pos)

            # Shift non-pattern highlights
            self.shift_non_pattern_highlights(current_file, sel_end + 1, -delete_count)

            # Shift pattern labels
            self.shift_pattern_labels(current_file, sel_end + 1, -delete_count)

            # Shift signature pointers
            self.shift_signature_pointers(sel_end + 1, -delete_count)

            # Adjust fields
            if hasattr(self, 'fields_widget'):
                self.fields_widget.adjust_for_delete(sel_start, delete_count, self.current_tab_index)

            # When inserting, we need to shift all existing markers that come after the insertion point
            insert_count = len(paste_data)
            old_modified = set(current_file.modified_bytes)
            old_inserted = set(current_file.inserted_bytes)
            old_replaced = set(current_file.replaced_bytes)

            # Clear and rebuild the sets with shifted positions
            current_file.modified_bytes.clear()
            current_file.inserted_bytes.clear()
            current_file.replaced_bytes.clear()

            for pos in old_modified:
                if pos >= insert_position:
                    current_file.modified_bytes.add(pos + insert_count)
                else:
                    current_file.modified_bytes.add(pos)

            for pos in old_inserted:
                if pos >= insert_position:
                    current_file.inserted_bytes.add(pos + insert_count)
                else:
                    current_file.inserted_bytes.add(pos)

            for pos in old_replaced:
                if pos >= insert_position:
                    current_file.replaced_bytes.add(pos + insert_count)
                else:
                    current_file.replaced_bytes.add(pos)

            # Shift non-pattern highlights
            self.shift_non_pattern_highlights(current_file, insert_position, insert_count)

            # Shift pattern labels
            self.shift_pattern_labels(current_file, insert_position, insert_count)

            # Shift signature pointers
            self.shift_signature_pointers(insert_position, insert_count)

            # Adjust fields
            if hasattr(self, 'fields_widget'):
                self.fields_widget.adjust_for_insert(insert_position, insert_count, self.current_tab_index)

            # Insert bytes
            for i, byte in enumerate(paste_data):
                pos = insert_position + i
                current_file.file_data.insert(pos, byte)
                current_file.inserted_bytes.add(pos)
        else:
            # No selection, just insert at cursor
            insert_count = len(paste_data)
            old_modified = set(current_file.modified_bytes)
            old_inserted = set(current_file.inserted_bytes)
            old_replaced = set(current_file.replaced_bytes)

            # Clear and rebuild the sets with shifted positions
            current_file.modified_bytes.clear()
            current_file.inserted_bytes.clear()
            current_file.replaced_bytes.clear()

            for pos in old_modified:
                if pos >= insert_position:
                    current_file.modified_bytes.add(pos + insert_count)
                else:
                    current_file.modified_bytes.add(pos)

            for pos in old_inserted:
                if pos >= insert_position:
                    current_file.inserted_bytes.add(pos + insert_count)
                else:
                    current_file.inserted_bytes.add(pos)

            for pos in old_replaced:
                if pos >= insert_position:
                    current_file.replaced_bytes.add(pos + insert_count)
                else:
                    current_file.replaced_bytes.add(pos)

            # Shift non-pattern highlights
            self.shift_non_pattern_highlights(current_file, insert_position, insert_count)

            # Shift pattern labels
            self.shift_pattern_labels(current_file, insert_position, insert_count)

            # Shift signature pointers
            self.shift_signature_pointers(insert_position, insert_count)

            # Adjust fields
            if hasattr(self, 'fields_widget'):
                self.fields_widget.adjust_for_insert(insert_position, insert_count, self.current_tab_index)

            # Insert bytes
            for i, byte in enumerate(paste_data):
                pos = insert_position + i
                current_file.file_data.insert(pos, byte)
                current_file.inserted_bytes.add(pos)

        current_file.modified = True
        current_file.pattern_highlights_dirty = True  # Mark pattern highlights for reapplication
        self.display_hex(preserve_scroll=True)
        self.scroll_to_offset(insert_position)

    def show_fill_selection_dialog(self):
        if self.current_tab_index < 0:
            return

        if self.selection_start is None or self.selection_end is None:
            QMessageBox.warning(self, "No Selection", "Please select a range of bytes to fill.")
            return

        dialog = QDialog(self)
        dialog.setWindowTitle("Fill Selection")
        dialog.setMinimumSize(450, 300)

        layout = QVBoxLayout()

        # Pattern input section
        pattern_group = QWidget()
        pattern_layout = QVBoxLayout()
        pattern_layout.addWidget(QLabel("Fill pattern (hex values):"))

        pattern_input = QLineEdit()
        pattern_input.setFont(QFont("Courier", 10))
        pattern_layout.addWidget(pattern_input)

        help_label = QLabel("Enter hex bytes separated by spaces. Pattern will repeat to fill selection.")
        help_label.setStyleSheet("color: #666; font-size: 9pt;")
        pattern_layout.addWidget(help_label)

        pattern_group.setLayout(pattern_layout)
        layout.addWidget(pattern_group)

        # Random bytes option
        layout.addSpacing(10)
        random_checkbox = QCheckBox("Use random bytes instead")
        layout.addWidget(random_checkbox)

        # Random range
        random_group = QWidget()
        random_layout = QHBoxLayout()
        random_layout.addWidget(QLabel("Random byte range (decimal):"))

        range_min = QSpinBox()
        range_min.setMinimum(0)
        range_min.setMaximum(255)
        range_min.setValue(0)
        random_layout.addWidget(range_min)

        random_layout.addWidget(QLabel("-"))

        range_max = QSpinBox()
        range_max.setMinimum(0)
        range_max.setMaximum(255)
        range_max.setValue(255)
        random_layout.addWidget(range_max)

        random_group.setLayout(random_layout)
        random_group.setEnabled(False)
        layout.addWidget(random_group)

        # Column range selection
        layout.addSpacing(10)
        col_range_group = QWidget()
        col_range_layout = QHBoxLayout()
        col_range_layout.addWidget(QLabel("Column range (hex, inclusive 00-0F):"))

        col_start_input = QLineEdit()
        col_start_input.setPlaceholderText("00")
        col_start_input.setMaxLength(2)
        col_start_input.setFixedWidth(40)
        col_range_layout.addWidget(col_start_input)

        col_range_layout.addWidget(QLabel("-"))

        col_end_input = QLineEdit()
        col_end_input.setPlaceholderText("0F")
        col_end_input.setMaxLength(2)
        col_end_input.setFixedWidth(40)
        col_range_layout.addWidget(col_end_input)

        col_range_group.setLayout(col_range_layout)
        layout.addWidget(col_range_group)

        # Enable/disable controls based on random checkbox
        def on_random_toggled(checked):
            pattern_input.setEnabled(not checked)
            random_group.setEnabled(checked)

        random_checkbox.toggled.connect(on_random_toggled)

        # Preset buttons
        layout.addSpacing(10)
        preset_label = QLabel("Preset deletion methods:")
        layout.addWidget(preset_label)

        preset_layout = QHBoxLayout()
        zerobytes_btn = QPushButton("Zerobytes")
        dod_btn = QPushButton("DoD Sanitizing")
        preset_layout.addWidget(zerobytes_btn)
        preset_layout.addWidget(dod_btn)
        preset_layout.addStretch()
        layout.addWidget(QWidget())
        layout.itemAt(layout.count() - 1).widget().setLayout(preset_layout)

        # Preset button actions
        def set_zerobytes():
            pattern_input.setText("00")
            random_checkbox.setChecked(False)

        zerobytes_btn.clicked.connect(set_zerobytes)
        dod_btn.clicked.connect(set_zerobytes)  # DoD uses zeros for simplicity

        layout.addStretch()

        # Buttons
        button_layout = QHBoxLayout()
        ok_button = QPushButton("OK")
        cancel_button = QPushButton("Cancel")
        button_layout.addStretch()
        button_layout.addWidget(ok_button)
        button_layout.addWidget(cancel_button)
        layout.addLayout(button_layout)

        dialog.setLayout(layout)

        def on_ok():
            try:
                start = min(self.selection_start, self.selection_end)
                end = max(self.selection_start, self.selection_end)
                length = end - start + 1

                current_file = self.open_files[self.current_tab_index]

                self.save_undo_state()

                # Parse column range
                col_start_text = col_start_input.text().strip()
                col_end_text = col_end_input.text().strip()
                try:
                    col_start = int(col_start_text, 16) if col_start_text else 0
                    col_end = int(col_end_text, 16) if col_end_text else 15
                    if not (0 <= col_start <= col_end <= 15):
                        raise ValueError()
                except:
                    QMessageBox.warning(dialog, "Invalid Column Range",
                                        "Please enter valid hex columns (00-0F).")
                    return

                import random

                if random_checkbox.isChecked():
                    min_val = range_min.value()
                    max_val = range_max.value()
                    if min_val > max_val:
                        min_val, max_val = max_val, min_val

                    for offset in range(length):
                        row = (start + offset) // 16
                        col = (start + offset) % 16
                        if col_start <= col <= col_end:
                            current_file.file_data[start + offset] = random.randint(min_val, max_val)
                            current_file.modified_bytes.add(start + offset)
                else:
                    # Parse hex pattern
                    pattern_text = pattern_input.text().strip()
                    if not pattern_text:
                        QMessageBox.warning(dialog, "Invalid Pattern", "Please enter a hex pattern.")
                        return

                    pattern_parts = pattern_text.replace(',', ' ').split()
                    pattern_bytes = []
                    for part in pattern_parts:
                        try:
                            byte_val = int(part, 16)
                            if 0 <= byte_val <= 255:
                                pattern_bytes.append(byte_val)
                            else:
                                raise ValueError()
                        except:
                            QMessageBox.warning(dialog, "Invalid Pattern",
                                                f"Invalid hex value: {part}\nPlease use hex values 00-FF.")
                            return

                    if not pattern_bytes:
                        QMessageBox.warning(dialog, "Invalid Pattern", "Please enter at least one hex byte.")
                        return

                    for offset in range(length):
                        row = (start + offset) // 16
                        col = (start + offset) % 16
                        if col_start <= col <= col_end:
                            current_file.file_data[start + offset] = pattern_bytes[offset % len(pattern_bytes)]
                            current_file.modified_bytes.add(start + offset)

                current_file.modified = True
                current_file.pattern_highlights_dirty = True  # Mark pattern highlights for reapplication
                # Update tab title
                tab_text = os.path.basename(current_file.file_path) + " *"
                self.tab_widget.setTabText(self.current_tab_index, tab_text)

                self.display_hex(preserve_scroll=True)
                dialog.accept()
            except Exception as e:
                QMessageBox.critical(dialog, "Error", f"Failed to fill selection: {str(e)}")

        def on_cancel():
            dialog.reject()

        ok_button.clicked.connect(on_ok)
        cancel_button.clicked.connect(on_cancel)

        dialog.exec()

    def show_highlight_window(self):
        if self.current_tab_index < 0:
            return

        dialog = QDialog(self)
        dialog.setWindowTitle("Highlight Bytes")
        dialog.setMinimumSize(400, 400)

        layout = QVBoxLayout()

        current_file = self.open_files[self.current_tab_index]

        # If selection exists, use it; otherwise use byte at cursor
        has_selection = self.selection_start is not None and self.selection_end is not None
        if has_selection:
            start = min(self.selection_start, self.selection_end)
            end = max(self.selection_start, self.selection_end)
            # Always read bytes in their file order (not reversed)
            selected_bytes = bytes(current_file.file_data[start:end+1])
        elif self.cursor_position is not None and self.cursor_position < len(current_file.file_data):
            # Use byte at cursor position
            start = self.cursor_position
            end = self.cursor_position
            selected_bytes = bytes([current_file.file_data[self.cursor_position]])
            has_selection = True  # Treat cursor position as a single-byte selection
        else:
            start = None
            end = None
            selected_bytes = b''

        # Mode toggle buttons (Search vs Selection)
        mode_frame = QWidget()
        mode_layout = QHBoxLayout()
        mode_layout.addWidget(QLabel("Mode:"))

        search_mode_btn = QPushButton("Search")
        selection_mode_btn = QPushButton("Selection")

        # Track current mode
        current_mode = ["search" if not has_selection else "selection"]

        # Get theme colors for styling
        theme_colors = get_theme_colors(self.current_theme)
        # For Matrix theme, use dark text on bright buttons for better readability
        button_text_color = "#000000" if self.current_theme == "Matrix" else theme_colors['foreground']

        def set_search_mode():
            current_mode[0] = "search"
            search_mode_btn.setStyleSheet(f"background-color: {theme_colors['button_bg']}; color: {button_text_color}; font-weight: bold;")
            selection_mode_btn.setStyleSheet(f"background-color: {theme_colors['editor_bg']}; color: {theme_colors['foreground']};")
            bytes_input_frame.setVisible(True)
            selection_info_frame.setVisible(False)

        def set_selection_mode():
            current_mode[0] = "selection"
            selection_mode_btn.setStyleSheet(f"background-color: {theme_colors['button_bg']}; color: {button_text_color}; font-weight: bold;")
            search_mode_btn.setStyleSheet(f"background-color: {theme_colors['editor_bg']}; color: {theme_colors['foreground']};")
            bytes_input_frame.setVisible(False)
            selection_info_frame.setVisible(True)

        search_mode_btn.clicked.connect(set_search_mode)
        selection_mode_btn.clicked.connect(set_selection_mode)

        mode_layout.addWidget(search_mode_btn)
        mode_layout.addWidget(selection_mode_btn)
        mode_layout.addStretch()
        mode_frame.setLayout(mode_layout)
        layout.addWidget(mode_frame)

        # Selection info display
        selection_info_frame = QWidget()
        selection_info_layout = QVBoxLayout()
        if has_selection:
            selection_info_layout.addWidget(QLabel(f"Selected: {len(selected_bytes)} byte(s)"))
            byte_preview = ' '.join(f'{b:02X}' for b in selected_bytes[:16])
            if len(selected_bytes) > 16:
                byte_preview += "..."
            selection_info_layout.addWidget(QLabel(f"Bytes: {byte_preview}"))
        else:
            selection_info_layout.addWidget(QLabel("No selection. Switch to Search mode to enter bytes manually."))
        selection_info_frame.setLayout(selection_info_layout)
        layout.addWidget(selection_info_frame)

        # Manual byte input (for search mode)
        bytes_input_frame = QWidget()
        bytes_input_layout = QVBoxLayout()
        bytes_input_layout.addWidget(QLabel("Bytes (hex, space-separated, e.g., '48 65 6C 6C 6F'):"))
        bytes_input = QLineEdit()
        bytes_input.setPlaceholderText("Enter hex bytes...")
        bytes_input_layout.addWidget(bytes_input)
        bytes_input_frame.setLayout(bytes_input_layout)
        layout.addWidget(bytes_input_frame)

        # Set initial mode
        if has_selection:
            set_selection_mode()
        else:
            set_search_mode()

        # Color selection
        highlight_frame = QWidget()
        highlight_layout = QHBoxLayout()
        highlight_layout.addWidget(QLabel("Highlight Color:"))

        selected_color = ["#FFFF00"]  # Use list for mutability
        color_btn = QPushButton("Choose Color")
        color_btn.setStyleSheet(f"background-color: {selected_color[0]}; color: black;")

        color_preview = QLabel("    ")
        color_preview.setStyleSheet(f"background-color: {selected_color[0]}; border: 1px solid black;")
        color_preview.setMinimumWidth(30)

        def choose_color():
            color = QColorDialog.getColor()
            if color.isValid():
                selected_color[0] = color.name()
                color_btn.setStyleSheet(f"background-color: {selected_color[0]}; color: black;")
                color_preview.setStyleSheet(f"background-color: {selected_color[0]}; border: 1px solid black;")

        color_btn.clicked.connect(choose_color)
        highlight_layout.addWidget(color_btn)
        highlight_layout.addWidget(color_preview)
        highlight_frame.setLayout(highlight_layout)
        layout.addWidget(highlight_frame)

        # Find all checkbox
        find_all_check = QCheckBox("Find All (highlight all matching byte sequences)")
        layout.addWidget(find_all_check)

        # Underline checkbox
        underline_check = QCheckBox("Underline (use colored underline instead of background)")
        layout.addWidget(underline_check)

        # Message text
        message_frame = QWidget()
        message_layout = QVBoxLayout()
        message_layout.addWidget(QLabel("Message (optional):"))
        message_layout.addWidget(QLabel("Hover over highlighted bytes to see this message"))
        message_text = QTextEdit()
        message_text.setMaximumHeight(60)
        message_layout.addWidget(message_text)
        message_frame.setLayout(message_layout)
        layout.addWidget(message_frame)

        # Buttons
        button_frame = QWidget()
        button_layout = QHBoxLayout()

        ok_btn = QPushButton("OK")
        ok_btn.setStyleSheet(f"background-color: {theme_colors['button_bg']}; color: {button_text_color};")
        cancel_btn = QPushButton("Cancel")
        cancel_btn.setStyleSheet(f"background-color: {theme_colors['button_disabled']}; color: {theme_colors['foreground']};")

        def apply_highlight():
            color = selected_color[0]
            message = message_text.toPlainText().strip()
            use_underline = underline_check.isChecked()

            # Determine target bytes based on mode
            if current_mode[0] == "selection":
                target_bytes = selected_bytes
                if not target_bytes:
                    QMessageBox.warning(dialog, "Error", "No bytes selected")
                    return
            else:  # search mode
                try:
                    hex_parts = bytes_input.text().strip().replace('0x', '').split()
                    target_bytes = bytes([int(h, 16) for h in hex_parts if h])
                    if not target_bytes:
                        QMessageBox.warning(dialog, "Error", "Please enter valid hex bytes")
                        return
                except ValueError:
                    QMessageBox.warning(dialog, "Error", "Invalid hex format. Use space-separated hex values (e.g., '48 65 6C 6C 6F')")
                    return

            if find_all_check.isChecked():
                # Find all matching sequences - store as pattern highlight
                pattern = target_bytes
                if not pattern:
                    QMessageBox.warning(dialog, "Error", "No bytes specified for highlighting")
                    return

                # Add to pattern highlights for dynamic tracking
                current_file.pattern_highlights.append({
                    "pattern": bytes(pattern),
                    "color": color,
                    "message": message,
                    "underline": use_underline
                })

                # Apply highlights to current file data
                file_data = current_file.file_data
                pos = 0
                found_count = 0
                while pos <= len(file_data) - len(pattern):
                    if bytes(file_data[pos:pos+len(pattern)]) == pattern:
                        for i in range(len(pattern)):
                            current_file.byte_highlights[pos + i] = {
                                "color": color,
                                "message": message,
                                "underline": use_underline,
                                "pattern": bytes(pattern)  # Mark as pattern-based
                            }
                        pos += len(pattern)
                        found_count += 1
                    else:
                        pos += 1

                # Pattern has been applied, so not dirty
                current_file.pattern_highlights_dirty = False

                if found_count == 0:
                    QMessageBox.information(dialog, "Not Found", "No matching byte sequences found")
                    return
            else:
                # Find and highlight first match starting from selection start or cursor position
                pattern = target_bytes
                if not pattern:
                    QMessageBox.warning(dialog, "Error", "No bytes specified for highlighting")
                    return

                file_data = current_file.file_data
                # If in selection mode, start from the beginning of the selection
                if current_mode[0] == "selection" and has_selection:
                    # Use the start of the selection (min of selection_start and selection_end)
                    start_pos = start
                else:
                    # Start search from cursor position (for search mode)
                    start_pos = self.cursor_position if self.cursor_position is not None else 0

                pos = start_pos
                found = False
                while pos <= len(file_data) - len(pattern):
                    if bytes(file_data[pos:pos+len(pattern)]) == pattern:
                        for i in range(len(pattern)):
                            current_file.byte_highlights[pos + i] = {
                                "color": color,
                                "message": message,
                                "underline": use_underline
                            }
                        found = True
                        break
                    pos += 1

                if not found:
                    QMessageBox.information(dialog, "Not Found", f"No matching byte sequence found from position 0x{start_pos:X}")
                    return

            self.display_hex(preserve_scroll=True)

            # Update pattern result color box and description if this was triggered from pattern scan
            if hasattr(self, 'pattern_result_to_update') and self.pattern_result_to_update:
                result, color_box, tree_item = self.pattern_result_to_update
                result.highlight_color = color
                color_box.setStyleSheet(f"background-color: {color}; border: 1px solid #555;")

                # Update description background
                tree_item.setBackground(3, QColor(color))

                self.pattern_result_to_update = None

            dialog.accept()

        def on_dialog_close():
            # Clear pattern result reference when dialog closes
            if hasattr(self, 'pattern_result_to_update'):
                self.pattern_result_to_update = None

        ok_btn.clicked.connect(apply_highlight)
        cancel_btn.clicked.connect(lambda: (on_dialog_close(), dialog.reject()))

        button_layout.addWidget(ok_btn)
        button_layout.addWidget(cancel_btn)
        button_frame.setLayout(button_layout)
        layout.addWidget(button_frame)

        dialog.setLayout(layout)
        dialog.finished.connect(on_dialog_close)
        dialog.show()

    def show_search_window(self):
        dialog = QDialog(self)
        dialog.setWindowTitle("Search")
        dialog.setMinimumSize(400, 180)

        layout = QVBoxLayout()

        # Search pattern
        pattern_layout = QHBoxLayout()
        pattern_layout.addWidget(QLabel("Search for:"))
        self.search_pattern_edit = QLineEdit()
        pattern_layout.addWidget(self.search_pattern_edit)
        layout.addLayout(pattern_layout)

        # Search type button (Hex/Text toggle)
        type_layout = QHBoxLayout()
        type_layout.addWidget(QLabel("Search type:"))
        self.search_type_btn = QPushButton("Hex")
        self.search_type_btn.setFont(QFont("Arial", 9, QFont.Bold))
        self.search_type_btn.setCheckable(True)
        self.search_type_btn.setChecked(True)
        self.search_type_btn.setMaximumWidth(100)
        self.search_type_btn.clicked.connect(self.toggle_search_type)
        type_layout.addWidget(self.search_type_btn)
        type_layout.addStretch()
        layout.addLayout(type_layout)

        # Search direction options
        options_group = QGroupBox("Search Direction")
        options_layout = QHBoxLayout()

        self.search_forward_radio = QRadioButton("Forward")
        self.search_forward_radio.setChecked(True)
        options_layout.addWidget(self.search_forward_radio)

        self.search_backward_radio = QRadioButton("Backward")
        options_layout.addWidget(self.search_backward_radio)

        self.search_findall_radio = QRadioButton("Find All")
        options_layout.addWidget(self.search_findall_radio)

        options_group.setLayout(options_layout)
        layout.addWidget(options_group)

        # Buttons
        button_layout = QHBoxLayout()
        button_layout.addStretch()

        search_btn = QPushButton("Search")
        search_btn.clicked.connect(lambda: self.perform_search(dialog))
        button_layout.addWidget(search_btn)

        close_btn = QPushButton("Close")
        close_btn.clicked.connect(dialog.close)
        button_layout.addWidget(close_btn)

        layout.addLayout(button_layout)

        dialog.setLayout(layout)
        dialog.show()

    def create_results_overlay(self):
        # Create results overlay widget at bottom between hex and ASCII displays
        if not hasattr(self, 'results_overlay') or self.results_overlay is None:
            # Parent to hex_ascii_container so it can span between hex and ASCII
            self.results_overlay = QWidget(self.hex_ascii_container)
            self.results_overlay.setObjectName("results_overlay")

            # Position at bottom, starting after offset column
            overlay_height = 200
            x_start = 130  # After offset column
            y_position = self.hex_ascii_container.height() - overlay_height

            # Calculate width within hex_ascii_container (don't subtract inspector as it's in different coordinate space)
            overlay_width = self.hex_ascii_container.width() - x_start

            self.results_overlay.setGeometry(x_start, y_position, overlay_width, overlay_height)

            overlay_layout = QVBoxLayout()
            overlay_layout.setContentsMargins(10, 8, 10, 5)
            overlay_layout.setSpacing(4)

            # Title row with close button
            title_row = QHBoxLayout()
            title_label = QLabel("Search Results")
            title_label.setFont(QFont("Arial", 10, QFont.Bold))
            title_row.addWidget(title_label)
            title_row.addStretch()

            close_btn = QPushButton("✕")
            close_btn.setMaximumWidth(25)
            close_btn.setMaximumHeight(25)
            close_btn.clicked.connect(lambda: self.results_overlay.hide())
            title_row.addWidget(close_btn)

            overlay_layout.addLayout(title_row)

            # Results display area (scrollable)
            self.search_results_scroll = QScrollArea()
            self.search_results_scroll.setWidgetResizable(True)

            self.search_results_widget = QWidget()
            self.search_results_layout = QVBoxLayout()
            self.search_results_layout.setAlignment(Qt.AlignTop)
            self.search_results_layout.setContentsMargins(0, 0, 0, 0)
            self.search_results_layout.setSpacing(2)
            self.search_results_widget.setLayout(self.search_results_layout)
            self.search_results_scroll.setWidget(self.search_results_widget)

            overlay_layout.addWidget(self.search_results_scroll)

            self.results_overlay.setLayout(overlay_layout)

            # Style the overlay with semi-transparent background
            if self.is_dark_theme():
                self.results_overlay.setStyleSheet("""
                    #results_overlay {
                        background-color: rgba(43, 43, 43, 240);
                        border: 2px solid #555;
                        border-radius: 4px;
                    }
                """)
            else:
                self.results_overlay.setStyleSheet("""
                    #results_overlay {
                        background-color: rgba(232, 232, 232, 240);
                        border: 2px solid #aaa;
                        border-radius: 4px;
                    }
                """)

            self.results_overlay.hide()
            self.results_overlay.raise_()  # Ensure it's on top

            # Helper function to update overlay position
            def update_overlay_position():
                if hasattr(self, 'results_overlay') and self.results_overlay is not None:
                    overlay_height = 200
                    x_start = 130  # After offset column
                    y_position = self.hex_ascii_container.height() - overlay_height

                    # Calculate width within hex_ascii_container
                    overlay_width = self.hex_ascii_container.width() - x_start

                    self.results_overlay.setGeometry(x_start, y_position, overlay_width, overlay_height)
                    self.results_overlay.raise_()

            # Connect resize event to reposition overlay (Y position only, width doesn't change on resize)
            original_resize = self.hex_ascii_container.resizeEvent
            def new_resize(event):
                update_overlay_position()
                if original_resize:
                    original_resize(event)
            self.hex_ascii_container.resizeEvent = new_resize

    def toggle_search_type(self):
        if self.search_type_btn.isChecked():
            self.search_type_btn.setText("Hex")
        else:
            self.search_type_btn.setText("Text")

    def perform_search(self, dialog=None):
        if self.current_tab_index < 0:
            return

        pattern_text = self.search_pattern_edit.text()
        if not pattern_text:
            return

        current_file = self.open_files[self.current_tab_index]
        is_hex = self.search_type_btn.isChecked()

        # Convert pattern to bytes
        if is_hex:
            try:
                pattern = bytes.fromhex(pattern_text.replace(" ", ""))
            except ValueError:
                QMessageBox.critical(self, "Error", "Invalid hex pattern")
                return
        else:
            pattern = pattern_text.encode()

        # Create results overlay if it doesn't exist
        self.create_results_overlay()

        # Clear previous results
        for i in reversed(range(self.search_results_layout.count())):
            self.search_results_layout.itemAt(i).widget().setParent(None)

        data = bytes(current_file.file_data)

        if self.search_forward_radio.isChecked():
            # Search forward from current position
            start_pos = self.cursor_position + 1 if self.cursor_position is not None else 0
            pos = data.find(pattern, start_pos)
            if pos != -1:
                self.show_search_result(pos, pattern, data)
                self.cursor_position = pos
                self.cursor_nibble = 0
                self.display_hex()
                # Scroll to result
                row = pos // self.bytes_per_row
                self.hex_display.verticalScrollBar().setValue(row)
            else:
                self.add_search_result_label("No match found")

        elif self.search_backward_radio.isChecked():
            # Search backward from current position
            end_pos = self.cursor_position if self.cursor_position is not None else len(data)
            pos = data.rfind(pattern, 0, end_pos)
            if pos != -1:
                self.show_search_result(pos, pattern, data)
                self.cursor_position = pos
                self.cursor_nibble = 0
                self.display_hex()
                # Scroll to result
                row = pos // self.bytes_per_row
                self.hex_display.verticalScrollBar().setValue(row)
            else:
                self.add_search_result_label("No match found")

        else:  # Find All
            # Find all occurrences
            matches = []
            offset = 0
            while True:
                pos = data.find(pattern, offset)
                if pos == -1:
                    break
                matches.append(pos)
                # Skip past the entire pattern to avoid overlapping matches
                offset = pos + len(pattern)

            if matches:
                for pos in matches:
                    self.show_search_result(pos, pattern, data, clickable=True)
            else:
                self.add_search_result_label("No matches found")

        # Show results overlay
        self.results_overlay.show()
        self.results_overlay.raise_()

    def show_search_result(self, pos, pattern, data, clickable=False):
        # Show context: 4 bytes before and after
        context_before = 4
        context_after = 4

        start = max(0, pos - context_before)
        end = min(len(data), pos + len(pattern) + context_after)

        result_widget = QWidget()
        result_layout = QHBoxLayout()
        result_layout.setContentsMargins(5, 2, 5, 2)

        # Build the hex display with blue colored matched bytes
        hex_parts = []
        for i in range(start, end):
            if i >= pos and i < pos + len(pattern):
                # Searched bytes in blue
                hex_parts.append(f"<span style='color: #2196F3; font-weight: bold;'>{data[i]:02X}</span>")
            else:
                hex_parts.append(f"{data[i]:02X}")

        hex_str = " ".join(hex_parts)

        result_label = QLabel(f"Result: {hex_str} | Offset: 0x{pos:X}")
        result_label.setFont(QFont("Courier", 8))
        result_label.setTextFormat(Qt.RichText)

        if clickable:
            result_label.mousePressEvent = lambda event, p=pos: self.goto_search_result(p)
            result_label.setCursor(Qt.PointingHandCursor)
            result_label.setStyleSheet("text-decoration: underline;")

        result_layout.addWidget(result_label)
        result_widget.setLayout(result_layout)
        self.search_results_layout.addWidget(result_widget)

    def add_search_result_label(self, text):
        label = QLabel(text)
        label.setFont(QFont("Arial", 7))
        self.search_results_layout.addWidget(label)

    def goto_search_result(self, pos):
        self.cursor_position = pos
        self.cursor_nibble = 0
        # Update display first
        self.display_hex(preserve_scroll=True)
        # Then scroll to result using proper QTextEdit scrolling, centered
        self.scroll_to_offset(pos, center=True)
        self.data_inspector.update()

    def show_replace_window(self):
        dialog = QDialog(self)
        dialog.setWindowTitle("Replace")
        dialog.setMinimumSize(400, 220)

        layout = QVBoxLayout()

        # Search pattern
        search_layout = QHBoxLayout()
        search_layout.addWidget(QLabel("Find:"))
        self.replace_find_edit = QLineEdit()
        search_layout.addWidget(self.replace_find_edit)
        layout.addLayout(search_layout)

        # Replace pattern
        replace_layout = QHBoxLayout()
        replace_layout.addWidget(QLabel("Replace:"))
        self.replace_with_edit = QLineEdit()
        replace_layout.addWidget(self.replace_with_edit)
        layout.addLayout(replace_layout)

        # Search type button (Hex/Text toggle)
        type_layout = QHBoxLayout()
        type_layout.addWidget(QLabel("Search type:"))
        self.replace_type_btn = QPushButton("Hex")
        self.replace_type_btn.setFont(QFont("Arial", 9, QFont.Bold))
        self.replace_type_btn.setCheckable(True)
        self.replace_type_btn.setChecked(True)
        self.replace_type_btn.setMaximumWidth(100)

        def toggle_replace_type():
            if self.replace_type_btn.isChecked():
                self.replace_type_btn.setText("Hex")
            else:
                self.replace_type_btn.setText("Text")

        self.replace_type_btn.clicked.connect(toggle_replace_type)
        type_layout.addWidget(self.replace_type_btn)
        type_layout.addStretch()
        layout.addLayout(type_layout)

        # Search direction options
        options_group = QGroupBox("Replace")
        options_layout = QHBoxLayout()

        self.replace_forward_radio = QRadioButton("All Forward")
        self.replace_forward_radio.setChecked(True)
        options_layout.addWidget(self.replace_forward_radio)

        self.replace_backward_radio = QRadioButton("All Backward")
        options_layout.addWidget(self.replace_backward_radio)

        self.replace_all_radio = QRadioButton("All")
        options_layout.addWidget(self.replace_all_radio)

        options_group.setLayout(options_layout)
        layout.addWidget(options_group)

        # Buttons
        button_layout = QHBoxLayout()
        button_layout.addStretch()

        replace_btn = QPushButton("Replace")
        replace_btn.clicked.connect(lambda: self.perform_replace(dialog))
        button_layout.addWidget(replace_btn)

        close_btn = QPushButton("Close")
        close_btn.clicked.connect(dialog.close)
        button_layout.addWidget(close_btn)

        layout.addLayout(button_layout)

        dialog.setLayout(layout)
        dialog.show()

    def perform_replace(self, dialog):
        if self.current_tab_index < 0:
            return

        # Get search and replace patterns
        find_text = self.replace_find_edit.text()
        replace_text = self.replace_with_edit.text()

        if not find_text:
            QMessageBox.warning(dialog, "Error", "Please enter search pattern")
            return

        # Parse patterns based on search type
        is_hex = self.replace_type_btn.isChecked()

        try:
            if is_hex:
                # Parse hex patterns
                find_pattern = bytes.fromhex(find_text.replace(' ', '').replace('0x', ''))
                replace_pattern = bytes.fromhex(replace_text.replace(' ', '').replace('0x', ''))
            else:
                # Use text patterns (decoded)
                find_pattern = find_text.encode('utf-8')
                replace_pattern = replace_text.encode('utf-8')
        except ValueError as e:
            QMessageBox.warning(dialog, "Error", f"Invalid pattern format: {str(e)}")
            return

        current_file = self.open_files[self.current_tab_index]
        data = bytearray(current_file.file_data)

        # Determine search range based on radio selection
        if self.replace_forward_radio.isChecked():
            # Replace all from cursor/selection forward
            start_pos = self.cursor_position if self.cursor_position is not None else 0
            if self.selection_start is not None:
                start_pos = min(self.selection_start, self.selection_end)
            search_start = start_pos
            search_end = len(data)
        elif self.replace_backward_radio.isChecked():
            # Replace all from start to cursor/selection
            end_pos = self.cursor_position if self.cursor_position is not None else len(data)
            if self.selection_start is not None:
                end_pos = min(self.selection_start, self.selection_end)
            search_start = 0
            search_end = end_pos
        else:  # All
            search_start = 0
            search_end = len(data)

        # Find all occurrences in range
        matches = []
        offset = search_start
        while offset < search_end:
            pos = data.find(find_pattern, offset, search_end)
            if pos == -1:
                break
            matches.append(pos)
            offset = pos + len(find_pattern)

        if not matches:
            QMessageBox.information(dialog, "Replace", "No matches found")
            return

        # Confirm replacement and check for size changes
        if len(find_pattern) != len(replace_pattern):
            # File size will change - use the helper with checkbox
            size_diff = abs((len(replace_pattern) - len(find_pattern)) * len(matches))
            is_increase = len(replace_pattern) > len(find_pattern)
            if not self.show_file_size_warning(dialog, size_diff, is_increase):
                return
        else:
            # No size change, just confirm replacement
            reply = QMessageBox.question(
                dialog,
                "Confirm Replace",
                f"Replace {len(matches)} occurrence(s)?",
                QMessageBox.Yes | QMessageBox.No,
                QMessageBox.No
            )
            if reply != QMessageBox.Yes:
                return

        # Perform replacement
        self.save_undo_state()

        # Replace from end to start to maintain correct positions
        # and track how we need to shift existing markers
        size_diff = len(replace_pattern) - len(find_pattern)

        # Process replacements from end to start
        for match_idx in range(len(matches) - 1, -1, -1):
            pos = matches[match_idx]

            # If size changes, shift all existing markers that are after this position
            if size_diff != 0:
                old_modified = set(current_file.modified_bytes)
                old_inserted = set(current_file.inserted_bytes)
                old_replaced = set(current_file.replaced_bytes)

                current_file.modified_bytes.clear()
                current_file.inserted_bytes.clear()
                current_file.replaced_bytes.clear()

                # Shift markers after the current replacement position
                for p in old_modified:
                    if p >= pos + len(find_pattern):
                        current_file.modified_bytes.add(p + size_diff)
                    elif p < pos:
                        current_file.modified_bytes.add(p)

                for p in old_inserted:
                    if p >= pos + len(find_pattern):
                        current_file.inserted_bytes.add(p + size_diff)
                    elif p < pos:
                        current_file.inserted_bytes.add(p)

                for p in old_replaced:
                    if p >= pos + len(find_pattern):
                        current_file.replaced_bytes.add(p + size_diff)
                    elif p < pos:
                        current_file.replaced_bytes.add(p)

            # Remove old bytes
            del data[pos:pos + len(find_pattern)]
            # Insert new bytes and mark as replaced (blue)
            for i, byte_val in enumerate(replace_pattern):
                data.insert(pos + i, byte_val)
                current_file.replaced_bytes.add(pos + i)

        current_file.file_data = data
        current_file.modified = True
        self.display_hex(preserve_scroll=True)

        QMessageBox.information(dialog, "Replace Complete", f"Replaced {len(matches)} occurrence(s)")
        dialog.close()

    def show_goto_window(self):
        dialog = QDialog(self)
        dialog.setWindowTitle("Go To Offset")
        dialog.setMinimumSize(280, 140)

        layout = QVBoxLayout()

        offset_layout = QHBoxLayout()
        offset_layout.addWidget(QLabel("Offset:"))
        offset_edit = QLineEdit()
        offset_layout.addWidget(offset_edit)
        layout.addLayout(offset_layout)

        buttons = QDialogButtonBox(QDialogButtonBox.Ok | QDialogButtonBox.Cancel)

        def goto_offset():
            try:
                offset_text = offset_edit.text()
                # Always parse as hex by default (users expect hex offsets in a hex editor)
                if offset_text.startswith('0x') or offset_text.startswith('0X'):
                    offset = int(offset_text, 16)
                else:
                    # Parse as hex even without 0x prefix
                    offset = int(offset_text, 16)

                if self.current_tab_index >= 0:
                    current_file = self.open_files[self.current_tab_index]
                    if 0 <= offset < len(current_file.file_data):
                        self.cursor_position = offset
                        self.cursor_nibble = 0

                        # Scroll to the offset (handles re-rendering if needed)
                        self.scroll_to_offset(offset, center=True)

                        # Refresh display to show cursor at new position
                        self.display_hex(preserve_scroll=True)

                        self.update_cursor_highlight()
                        self.data_inspector.update()
                        dialog.accept()
                    else:
                        QMessageBox.critical(dialog, "Error", "Offset out of range")
            except ValueError:
                QMessageBox.critical(dialog, "Error", "Invalid offset format")

        buttons.accepted.connect(goto_offset)
        buttons.rejected.connect(dialog.reject)
        layout.addWidget(buttons)

        dialog.setLayout(layout)
        dialog.show()

    def show_delimiter_config(self):
        """Show the delimiter configuration dialog"""
        dialog = DelimiterConfigDialog(self, self.hidden_delimiters.copy())

        if dialog.exec_() == QDialog.Accepted:
            self.hidden_delimiters = dialog.get_delimiters()
            # Refresh display to show updated delimiter highlighting
            self.display_hex(preserve_scroll=True)

    def show_segments_config(self):
        """Show the segment configuration dialog"""
        dialog = QDialog(self)
        dialog.setWindowTitle("Segment Configuration")
        dialog.setModal(True)
        dialog.resize(350, 200)

        layout = QVBoxLayout()

        # Title
        title = QLabel("Column Segment Separators")
        title.setFont(QFont("Arial", 11, QFont.Bold))
        layout.addWidget(title)

        # Help text
        help_text = QLabel(
            "Draw thin vertical lines between hex column segments.\n"
            "Select segment size or 'None' to disable."
        )
        help_text.setWordWrap(True)
        help_text.setStyleSheet("color: #888; font-size: 9pt; padding: 5px;")
        layout.addWidget(help_text)

        # Segment size selection
        segment_layout = QHBoxLayout()
        segment_layout.addWidget(QLabel("Segment Size:"))

        segment_combo = QComboBox()
        segment_combo.addItems(["None", "1", "2", "4", "8"])
        if self.segment_size == 0:
            segment_combo.setCurrentText("None")
        else:
            segment_combo.setCurrentText(str(self.segment_size))
        segment_layout.addWidget(segment_combo)
        segment_layout.addStretch()

        layout.addLayout(segment_layout)

        
        # Add boundaries button
        layout.addSpacing(10)
        separator2 = QFrame()
        separator2.setFrameShape(QFrame.HLine)
        separator2.setFrameShadow(QFrame.Sunken)
        layout.addWidget(separator2)

        boundaries_label = QLabel("Column Boundaries")
        boundaries_label.setFont(QFont("Arial", 10, QFont.Bold))
        layout.addWidget(boundaries_label)

        boundaries_help = QLabel("Set column-based editing constraints")
        boundaries_help.setStyleSheet("color: #888; font-size: 9pt; padding: 5px;")
        layout.addWidget(boundaries_help)

        boundaries_button = QPushButton("Configure Boundaries...")
        boundaries_button.setMinimumWidth(200)
        boundaries_button.clicked.connect(lambda: [dialog.accept(), self.show_boundaries_config()])
        layout.addWidget(boundaries_button)

        layout.addStretch()

        # Buttons
        buttons = QDialogButtonBox(QDialogButtonBox.Ok | QDialogButtonBox.Cancel)

        def apply_segments():
            text = segment_combo.currentText()
            if text == "None":
                self.segment_size = 0
            else:
                self.segment_size = int(text)
            # Update segment overlays
            if hasattr(self, 'segment_overlay'):
                self.segment_overlay.set_segment_size(self.segment_size)
            if hasattr(self, 'header_segment_overlay'):
                self.header_segment_overlay.set_segment_size(self.segment_size)
            self.display_hex(preserve_scroll=True)
            # Save segment size preference
            self.save_settings()
            dialog.accept()

        buttons.accepted.connect(apply_segments)
        buttons.rejected.connect(dialog.reject)
        layout.addWidget(buttons)

        dialog.setLayout(layout)
        dialog.exec_()


    def show_boundaries_config(self):
        """Show the column boundaries configuration dialog"""
        dialog = QDialog(self)
        dialog.setWindowTitle("Column Boundaries Configuration")
        dialog.setModal(True)
        dialog.resize(400, 250)

        layout = QVBoxLayout()

        # Title
        title = QLabel("Column Editing Boundaries")
        title.setFont(QFont("Arial", 11, QFont.Bold))
        layout.addWidget(title)

        # Help text
        help_text = QLabel(
            "Restrict editing to specific column ranges.\n"
            "When enabled, cursor will wrap at column boundaries.\n"
            f"Columns range from 0x00 to {self.bytes_per_row - 1:02X} (0-{self.bytes_per_row - 1})."
        )
        help_text.setWordWrap(True)
        help_text.setStyleSheet("color: #888; font-size: 9pt; padding: 5px;")
        layout.addWidget(help_text)

        # Enable checkbox
        enable_check = QCheckBox("Enable Column Boundaries")
        enable_check.setChecked(self.boundary_enabled)
        layout.addWidget(enable_check)

        # Start column selection
        start_layout = QHBoxLayout()
        start_label = QLabel("Start Column (hex):")
        start_label.setMinimumWidth(150)
        start_layout.addWidget(start_label)
        start_spin = QSpinBox()
        start_spin.setRange(0, self.bytes_per_row - 1)
        start_spin.setValue(self.boundary_start_col)
        start_spin.setDisplayIntegerBase(16)
        start_spin.setPrefix("0x")
        start_spin.setMinimumWidth(100)
        start_spin.setMinimumHeight(30)
        start_layout.addWidget(start_spin)
        start_layout.addStretch()
        layout.addLayout(start_layout)

        # End column selection
        end_layout = QHBoxLayout()
        end_label = QLabel("End Column (hex):")
        end_label.setMinimumWidth(150)
        end_layout.addWidget(end_label)
        end_spin = QSpinBox()
        end_spin.setRange(0, self.bytes_per_row - 1)
        end_spin.setValue(self.boundary_end_col)
        end_spin.setDisplayIntegerBase(16)
        end_spin.setPrefix("0x")
        end_spin.setMinimumWidth(100)
        end_spin.setMinimumHeight(30)
        end_layout.addWidget(end_spin)
        end_layout.addStretch()
        layout.addLayout(end_layout)

        # Example label
        example_text = QLabel()
        def update_example():
            if enable_check.isChecked():
                example_text.setText(f"Example: Editing restricted to columns 0x{start_spin.value():02X} through 0x{end_spin.value():02X}")
            else:
                example_text.setText("Boundaries disabled - all columns available")
        update_example()
        example_text.setStyleSheet("color: #888; font-style: italic; padding: 10px;")
        layout.addWidget(example_text)

        # Update example when values change
        enable_check.stateChanged.connect(update_example)
        start_spin.valueChanged.connect(update_example)
        end_spin.valueChanged.connect(update_example)

        layout.addStretch()

        # Buttons
        buttons = QDialogButtonBox(QDialogButtonBox.Ok | QDialogButtonBox.Cancel)
        # Make buttons larger
        for button in buttons.buttons():
            button.setMinimumHeight(35)
            button.setMinimumWidth(80)

        def apply_boundaries():
            self.boundary_enabled = enable_check.isChecked()
            self.boundary_start_col = start_spin.value()
            self.boundary_end_col = end_spin.value()

            # Validate that start <= end
            if self.boundary_start_col > self.boundary_end_col:
                QMessageBox.warning(dialog, "Invalid Range",
                                  "Start column must be less than or equal to end column.")
                return

            # Update boundary overlay
            if hasattr(self, 'boundary_overlay'):
                self.boundary_overlay.set_boundaries(self.boundary_enabled, self.boundary_start_col, self.boundary_end_col)
                self.boundary_overlay.setGeometry(0, 0, self.hex_column_width, self.hex_display.height())

            self.display_hex(preserve_scroll=True)
            self.save_settings()
            dialog.accept()

        buttons.accepted.connect(apply_boundaries)
        buttons.rejected.connect(dialog.reject)
        layout.addWidget(buttons)

        dialog.setLayout(layout)
        dialog.exec_()

    def _serialize_subfields(self, subfields):
        """Helper function to recursively serialize subfields for JSON export"""
        serialized = []
        for subfield in subfields:
            subfield_dict = {
                "name": subfield.name,
                "start": subfield.start,
                "end": subfield.end,
                "data_type": subfield.data_type,
                "endian": subfield.endian,
                "subfields": self._serialize_subfields(subfield.subfields) if subfield.subfields else []
            }
            serialized.append(subfield_dict)
        return serialized

    def _deserialize_subfields(self, subfields_data):
        """Helper function to recursively deserialize subfields from JSON"""
        from datainspect.fields import Subfield
        subfields = []
        for subfield_data in subfields_data:
            subfield = Subfield(
                subfield_data["name"],
                subfield_data["start"],
                subfield_data["end"],
                subfield_data["data_type"],
                subfield_data["endian"]
            )
            subfield.subfields = self._deserialize_subfields(subfield_data.get("subfields", []))
            subfields.append(subfield)
        return subfields

    def save_json(self):
        if self.current_tab_index < 0:
            QMessageBox.warning(self, "No File", "Please open a file first")
            return

        current_file = self.open_files[self.current_tab_index]

        # Check if there's anything to save
        has_highlights = current_file.byte_highlights or current_file.pattern_highlights
        has_pointers = hasattr(self, 'signature_widget') and self.signature_widget.pointers
        has_pattern_labels = current_file.pattern_labels
        has_delimiters = bool(self.hidden_delimiters)
        has_fields = hasattr(self, 'fields_widget') and self.fields_widget.fields

        if not has_highlights and not has_pointers and not has_pattern_labels and not has_delimiters and not has_fields:
            QMessageBox.information(self, "No Data", "No highlights, pointers, pattern labels, hidden delimiters, or fields to save")
            return

        # Show dialog with checkboxes to select what to save
        dialog = QDialog(self)
        dialog.setWindowTitle("Select Data to Save")
        dialog.setMinimumWidth(300)

        layout = QVBoxLayout()
        layout.setSpacing(10)

        info_label = QLabel("Select which data to include in the JSON file:")
        info_label.setWordWrap(True)
        layout.addWidget(info_label)

        layout.addSpacing(5)

        # Create checkboxes for each data type
        checkboxes = {}

        if has_highlights:
            cb = QCheckBox("Highlights")
            cb.setChecked(True)
            checkboxes['highlights'] = cb
            layout.addWidget(cb)

        if has_pointers:
            cb = QCheckBox("Pointers")
            cb.setChecked(True)
            checkboxes['pointers'] = cb
            layout.addWidget(cb)

        if has_pattern_labels:
            cb = QCheckBox("Pattern Labels")
            cb.setChecked(True)
            checkboxes['pattern_labels'] = cb
            layout.addWidget(cb)

        if has_delimiters:
            cb = QCheckBox("Hidden Delimiters")
            cb.setChecked(True)
            checkboxes['delimiters'] = cb
            layout.addWidget(cb)

        if has_fields:
            cb = QCheckBox("Fields")
            cb.setChecked(True)
            checkboxes['fields'] = cb
            layout.addWidget(cb)

        layout.addSpacing(10)

        # OK and Cancel buttons
        button_layout = QHBoxLayout()
        button_layout.addStretch()

        ok_button = QPushButton("OK")
        ok_button.clicked.connect(dialog.accept)
        button_layout.addWidget(ok_button)

        cancel_button = QPushButton("Cancel")
        cancel_button.clicked.connect(dialog.reject)
        button_layout.addWidget(cancel_button)

        layout.addLayout(button_layout)
        dialog.setLayout(layout)

        if dialog.exec_() != QDialog.Accepted:
            return

        # Check if at least one checkbox is selected
        selected = {key: cb.isChecked() for key, cb in checkboxes.items()}
        if not any(selected.values()):
            QMessageBox.warning(self, "No Selection", "Please select at least one data type to save")
            return

        file_path, _ = QFileDialog.getSaveFileName(
            self, "Save JSON", "", "JSON Files (*.json);;All Files (*)"
        )

        if file_path:
            try:
                highlights_data = {
                    "file": os.path.basename(current_file.file_path)
                }

                # Add highlights section if selected
                if selected.get('highlights', False):
                    # Convert highlights to JSON-serializable format
                    # Separate pattern-based from manual highlights
                    manual_highlights = {offset: info for offset, info in current_file.byte_highlights.items() if "pattern" not in info}

                    highlights_data["highlights"] = {
                        str(offset): {
                            "color": info["color"],
                            "message": info.get("message", ""),
                            "underline": info.get("underline", False)
                        }
                        for offset, info in manual_highlights.items()
                    }
                    highlights_data["pattern_highlights"] = [
                        {
                            "pattern": list(p["pattern"]),  # Convert bytes to list for JSON
                            "color": p["color"],
                            "message": p["message"],
                            "underline": p["underline"]
                        }
                        for p in current_file.pattern_highlights
                    ]

                # Add pointers section if selected
                pointers_data = []
                if selected.get('pointers', False) and hasattr(self, 'signature_widget') and self.signature_widget.pointers:
                    # Group pointers by category to detect selection vs search
                    pointer_groups = {}
                    for pointer in self.signature_widget.pointers:
                        category = pointer.category
                        if category not in pointer_groups:
                            pointer_groups[category] = []
                        pointer_groups[category].append(pointer)

                    # Build pointer data
                    for category, pointers in pointer_groups.items():
                        if category == "Custom":
                            # Selection-based pointers
                            for pointer in pointers:
                                pointers_data.append({
                                    "mode": "selection",
                                    "offset_start": pointer.offset,
                                    "offset_end": pointer.offset + pointer.length - 1,
                                    "length": pointer.length,
                                    "type": pointer.data_type
                                })
                        else:
                            # Search-based pointers - save once per category with hex pattern
                            first_pointer = pointers[0]
                            pointers_data.append({
                                "mode": "search",
                                "hex_pattern": category,
                                "length": first_pointer.length,
                                "type": first_pointer.data_type
                            })

                    highlights_data["pointers"] = pointers_data

                # Add pattern scan labels section if selected
                if selected.get('pattern_labels', False):
                    pattern_labels_data = []
                    if hasattr(self, 'pattern_scan_widget') and self.pattern_scan_widget:
                        root = self.pattern_scan_widget.tree.invisibleRootItem()
                        for i in range(root.childCount()):
                            category_item = root.child(i)
                            category_name = category_item.text(0)
                            for j in range(category_item.childCount()):
                                item = category_item.child(j)
                                result = item.data(0, Qt.UserRole)
                                if isinstance(result, PatternResult):
                                    # Check if this result has a label or color
                                    has_label = result.label and result.label.strip()
                                    has_color = hasattr(result, 'highlight_color') and result.highlight_color

                                    if has_label or has_color:
                                        pattern_labels_data.append({
                                            "category": category_name,
                                            "offset": result.offset,
                                            "length": result.length,
                                            "description": result.description,
                                            "label": result.label if has_label else "",
                                            "color": result.highlight_color if has_color else ""
                                        })

                    highlights_data["pattern_scan_labels"] = pattern_labels_data

                # Add hidden delimiter options if selected
                if selected.get('delimiters', False) and self.hidden_delimiters:
                    highlights_data["hidden_delimiters"] = self.hidden_delimiters

                # Add fields section if selected
                if selected.get('fields', False) and hasattr(self, 'fields_widget') and self.fields_widget.fields:
                    fields_data = []
                    for field in self.fields_widget.fields:
                        field_dict = {
                            "label": field.label,
                            "start": field.start,
                            "end": field.end,
                            "tab_index": field.tab_index,
                            "subfields": self._serialize_subfields(field.subfields)
                        }
                        fields_data.append(field_dict)
                    highlights_data["fields"] = fields_data

                with open(file_path, 'w') as f:
                    json.dump(highlights_data, f, indent=2)

                QMessageBox.information(self, "Success", f"Data saved to {os.path.basename(file_path)}")
            except Exception as e:
                QMessageBox.critical(self, "Error", f"Failed to save data: {str(e)}")

    def load_json(self):
        if self.current_tab_index < 0:
            QMessageBox.warning(self, "No File", "Please open a file first")
            return

        file_path, _ = QFileDialog.getOpenFileName(
            self, "Load JSON", "", "JSON Files (*.json);;All Files (*)"
        )

        if file_path:
            try:
                with open(file_path, 'r') as f:
                    json_data = json.load(f)

                current_file = self.open_files[self.current_tab_index]

                # Load manual highlights from JSON
                loaded_count = 0
                for offset_str, info in json_data.get("highlights", {}).items():
                    offset = int(offset_str)
                    if offset < len(current_file.file_data):
                        current_file.byte_highlights[offset] = {
                            "color": info["color"],
                            "message": info.get("message", ""),
                            "underline": info.get("underline", False)
                        }
                        loaded_count += 1

                # Load pattern highlights
                pattern_count = 0
                for pattern_info in json_data.get("pattern_highlights", []):
                    pattern_bytes = bytes(pattern_info["pattern"])
                    current_file.pattern_highlights.append({
                        "pattern": pattern_bytes,
                        "color": pattern_info["color"],
                        "message": pattern_info["message"],
                        "underline": pattern_info["underline"]
                    })
                    pattern_count += 1

                # Mark pattern highlights as dirty so they get applied
                if pattern_count > 0:
                    current_file.pattern_highlights_dirty = True

                # Check for items that require rescanning
                pattern_labels_data = json_data.get("pattern_scan_labels", [])
                search_pointers_data = [p for p in json_data.get("pointers", []) if p.get("mode") == "search"]

                needs_rescan = len(pattern_labels_data) > 0 or len(search_pointers_data) > 0

                # Show warning prompt if rescanning is needed
                if needs_rescan:
                    warning_msg = "This JSON file contains items that require rescanning:\n\n"

                    if pattern_labels_data:
                        warning_msg += f"• {len(pattern_labels_data)} Pattern Scan label(s) with colors\n"

                    if search_pointers_data:
                        warning_msg += f"• {len(search_pointers_data)} Pointer Search group(s)\n"

                    warning_msg += "\nRescanning will take some time. Do you want to proceed?"

                    reply = QMessageBox.question(
                        self,
                        "Rescan Required",
                        warning_msg,
                        QMessageBox.Yes | QMessageBox.No,
                        QMessageBox.No
                    )

                    if reply == QMessageBox.No:
                        # User cancelled, don't load these items
                        pattern_labels_data = []
                        search_pointers_data = []

                # Load pointers
                pointer_count = 0

                # First load selection-based pointers (direct load)
                for pointer_info in json_data.get("pointers", []):
                    mode = pointer_info.get("mode")
                    length = pointer_info.get("length")
                    data_type = pointer_info.get("type")

                    if mode == "selection":
                        # Selection-based pointer - add directly
                        offset_start = pointer_info.get("offset_start")
                        if offset_start < len(current_file.file_data):
                            pointer = SignaturePointer(
                                offset_start,
                                length,
                                data_type,
                                f"Selection_{offset_start:X}",
                                category="Custom"
                            )
                            # Calculate value
                            pointer.value = self.signature_widget.interpret_value(
                                current_file.file_data,
                                pointer.offset,
                                pointer.length,
                                pointer.data_type,
                                self.signature_widget.string_display_mode,
                                pointer
                            )
                            self.signature_widget.pointers.append(pointer)
                            self.signature_widget.pointer_added.emit(pointer)
                            pointer_count += 1

                # Rebuild pointer tree for selection pointers
                if pointer_count > 0:
                    self.signature_widget.rebuild_tree()

                # Now handle search-based pointers (rescan one at a time)
                if search_pointers_data:
                    self.load_search_pointers_sequentially(search_pointers_data, current_file)

                # Handle pattern scan labels (rescan required)
                if pattern_labels_data:
                    self.load_pattern_scan_labels(pattern_labels_data, current_file)

                # Load hidden delimiter options
                if "hidden_delimiters" in json_data:
                    # Convert string keys back to integers
                    self.hidden_delimiters = {int(k): v for k, v in json_data["hidden_delimiters"].items()}

                # Load fields
                fields_count = 0
                if "fields" in json_data and hasattr(self, 'fields_widget'):
                    self.fields_widget.fields.clear()
                    for field_data in json_data["fields"]:
                        from datainspect.fields import Field
                        field = Field(
                            field_data["label"],
                            field_data["start"],
                            field_data["end"],
                            field_data["tab_index"]
                        )
                        field.subfields = self._deserialize_subfields(field_data.get("subfields", []))
                        self.fields_widget.fields.append(field)
                        fields_count += 1
                    self.fields_widget.rebuild_tree()

                self.display_hex()

                # Build success message
                msg_parts = []
                if loaded_count > 0:
                    msg_parts.append(f"{loaded_count} manual highlight(s)")
                if pattern_count > 0:
                    msg_parts.append(f"{pattern_count} pattern highlight(s)")
                if pointer_count > 0:
                    msg_parts.append(f"{pointer_count} selection pointer(s)")
                if fields_count > 0:
                    msg_parts.append(f"{fields_count} field(s)")

                msg = "Loaded: " + ", ".join(msg_parts) if msg_parts else "No data loaded"

                if search_pointers_data:
                    msg += f"\n\nLoading {len(search_pointers_data)} pointer search group(s)..."

                if pattern_labels_data:
                    msg += f"\n\nLoading {len(pattern_labels_data)} pattern scan label(s)..."

                QMessageBox.information(self, "Success", msg)
            except Exception as e:
                QMessageBox.critical(self, "Error", f"Failed to load JSON: {str(e)}")

    def load_search_pointers_sequentially(self, search_pointers_data, current_file):
        """Load search-based pointers one at a time by rescanning"""
        if not search_pointers_data:
            return

        # Create a progress dialog
        progress = QProgressDialog("Loading pointer searches...", "Cancel", 0, len(search_pointers_data), self)
        progress.setWindowTitle("Loading Pointers")
        progress.setWindowModality(Qt.WindowModal)
        progress.setMinimumDuration(0)

        total_loaded = 0

        for idx, pointer_info in enumerate(search_pointers_data):
            if progress.wasCanceled():
                break

            hex_pattern = pointer_info.get("hex_pattern", "")
            length = pointer_info.get("length")
            data_type = pointer_info.get("type")

            progress.setLabelText(f"Loading pointer search {idx + 1}/{len(search_pointers_data)}...\nPattern: {hex_pattern}")
            progress.setValue(idx)

            # Use the pointer panel's search functionality
            if hasattr(self, 'signature_widget'):
                # Parse hex pattern
                hex_bytes = bytes.fromhex(hex_pattern.replace(" ", ""))

                # Search for pattern in file
                matches = []
                for i in range(len(current_file.file_data) - len(hex_bytes) + 1):
                    if current_file.file_data[i:i+len(hex_bytes)] == hex_bytes:
                        matches.append(i)

                # Create pointers for all matches
                for match_offset in matches:
                    # The pointer points to bytes AFTER the search pattern
                    value_offset = match_offset + len(hex_bytes)
                    if value_offset + length > len(current_file.file_data):
                        continue  # Skip if value extends beyond file
                    pointer = SignaturePointer(
                        value_offset,
                        length,
                        data_type,
                        f"Search_{hex_pattern}",
                        category=hex_pattern
                    )
                    # Calculate value
                    pointer.value = self.signature_widget.interpret_value(
                        current_file.file_data,
                        pointer.offset,
                        pointer.length,
                        pointer.data_type,
                        self.signature_widget.string_display_mode,
                        pointer
                    )
                    self.signature_widget.pointers.append(pointer)
                    total_loaded += 1

            QApplication.processEvents()  # Keep UI responsive

        progress.setValue(len(search_pointers_data))

        # Rebuild pointer tree
        if total_loaded > 0:
            self.signature_widget.rebuild_tree()
            self.display_hex()

        QMessageBox.information(self, "Pointers Loaded", f"Loaded {total_loaded} pointer(s) from {len(search_pointers_data)} search group(s)")

    def load_pattern_scan_labels(self, pattern_labels_data, current_file):
        """Load pattern scan labels by rescanning and reapplying labels/colors"""
        if not pattern_labels_data or not hasattr(self, 'pattern_scan_widget'):
            return

        # First, trigger a pattern scan
        QMessageBox.information(
            self,
            "Pattern Scan Required",
            f"Rescanning file to load {len(pattern_labels_data)} pattern label(s).\n\n"
            "This may take a moment..."
        )

        # Store the labels temporarily
        self.pending_pattern_labels = pattern_labels_data

        # Start the scan
        self.pattern_scan_widget.file_data = current_file.file_data
        self.pattern_scan_widget.start_scan()

        # Connect to scan completion to apply labels
        self.pattern_scan_widget.scanner.scan_complete.connect(
            lambda results: self.apply_loaded_pattern_labels(results)
        )

    def apply_loaded_pattern_labels(self, results):
        """Apply loaded pattern labels after scan completes"""
        if not hasattr(self, 'pending_pattern_labels'):
            return

        pattern_labels_data = self.pending_pattern_labels
        delattr(self, 'pending_pattern_labels')

        applied_count = 0

        # Match loaded labels to scan results by offset, length, category, and description
        for label_info in pattern_labels_data:
            target_offset = label_info.get("offset")
            target_length = label_info.get("length")
            target_category = label_info.get("category")
            target_description = label_info.get("description")
            label_text = label_info.get("label", "")
            label_color = label_info.get("color", "")

            # Find matching result in the tree
            root = self.pattern_scan_widget.tree.invisibleRootItem()
            for i in range(root.childCount()):
                category_item = root.child(i)
                category_name = category_item.text(0)

                if category_name == target_category:
                    for j in range(category_item.childCount()):
                        item = category_item.child(j)
                        result = item.data(0, Qt.UserRole)

                        if isinstance(result, PatternResult):
                            if (result.offset == target_offset and
                                result.length == target_length and
                                result.description == target_description):

                                # Apply label
                                if label_text:
                                    result.label = label_text
                                    if result.offset in self.pattern_scan_widget.label_editors:
                                        self.pattern_scan_widget.label_editors[result.offset].setText(label_text)

                                # Apply color
                                if label_color:
                                    result.highlight_color = label_color
                                    # Update color box
                                    widget = self.pattern_scan_widget.tree.itemWidget(item, 0)
                                    if widget:
                                        color_box = widget.findChild(QPushButton)
                                        if color_box:
                                            color_box.setStyleSheet(f"background-color: {label_color}; border: 1px solid #555;")
                                    # Update description background
                                    item.setBackground(3, QColor(label_color))

                                applied_count += 1
                                break

        # Save labels to current file
        if self.current_tab_index >= 0:
            self.save_pattern_labels_to_current_file()

        QMessageBox.information(
            self,
            "Pattern Labels Loaded",
            f"Applied {applied_count} pattern label(s) and color(s)"
        )

    def clear_all(self):
        """Clear all highlights, pattern labels, pointers, and hidden delimiters"""
        if self.current_tab_index < 0:
            return

        current_file = self.open_files[self.current_tab_index]

        has_highlights = current_file.byte_highlights or current_file.pattern_highlights
        has_labels = current_file.pattern_labels
        has_pointers = hasattr(self, 'signature_widget') and self.signature_widget.pointers
        has_delimiters = bool(self.hidden_delimiters)

        if not has_highlights and not has_labels and not has_pointers and not has_delimiters:
            QMessageBox.information(self, "Nothing to Clear", "No highlights, pattern labels, pointers, or hidden delimiters to clear")
            return

        reply = QMessageBox.question(
            self, "Clear All",
            "Are you sure you want to clear all highlights, pattern labels, pointers, and hidden delimiters?",
            QMessageBox.Yes | QMessageBox.No
        )

        if reply == QMessageBox.Yes:
            # Clear highlights
            current_file.byte_highlights.clear()
            current_file.pattern_highlights.clear()

            # Clear pattern labels
            current_file.pattern_labels.clear()

            # Clear pattern scan labels in the widget
            if hasattr(self, 'pattern_scan_widget') and self.pattern_scan_widget:
                root = self.pattern_scan_widget.tree.invisibleRootItem()
                for i in range(root.childCount()):
                    category_item = root.child(i)
                    for j in range(category_item.childCount()):
                        item = category_item.child(j)
                        result = item.data(0, Qt.UserRole)
                        if isinstance(result, PatternResult):
                            result.label = ""
                            # Clear the label editor widget
                            if result.offset in self.pattern_scan_widget.label_editors:
                                self.pattern_scan_widget.label_editors[result.offset].setText("")

            # Clear pointers
            if hasattr(self, 'signature_widget') and self.signature_widget:
                self.signature_widget.pointers.clear()
                self.signature_widget.rebuild_tree()

            # Clear hidden delimiters
            self.hidden_delimiters.clear()

            self.display_hex()
            QMessageBox.information(self, "Success", "All highlights, pattern labels, pointers, and hidden delimiters cleared")

    def show_calculator_window(self):
        dialog = QDialog(self, Qt.Window)
        dialog.setWindowTitle("Hex Calculator")
        dialog.setMinimumSize(550, 650)
        dialog.setModal(False)

        # Apply theme stylesheet - use Light or Dark theme based on current theme brightness
        if self.is_dark_theme():
            base_theme_name = "Dark"
        else:
            base_theme_name = "Light"
        style = get_theme_stylesheet(base_theme_name)
        dialog.setStyleSheet(style)

        self.auxiliary_windows.append(dialog)

        main_layout = QVBoxLayout()
        main_layout.setSpacing(10)
        main_layout.setContentsMargins(10, 10, 10, 10)

        # Input section at top
        input_label = QLabel("Input:")
        input_label.setFont(QFont("Arial", 10, QFont.Bold))
        main_layout.addWidget(input_label)

        input_edit = QLineEdit()
        input_edit.setFont(QFont("Courier", 11))
        input_edit.setPlaceholderText("Enter hex or number...")
        input_edit.setMinimumHeight(35)
        input_edit.setContextMenuPolicy(Qt.DefaultContextMenu)
        input_edit.setToolTip("Enter values here - supports hex (0xAB, AB CD), integers, and floats")
        main_layout.addWidget(input_edit)

        # Data Inspector section
        inspector_label = QLabel("Data Inspector:")
        inspector_label.setFont(QFont("Arial", 10, QFont.Bold))
        inspector_label.setContentsMargins(0, 10, 0, 0)
        main_layout.addWidget(inspector_label)

        # Scroll area for inspector content
        inspector_scroll = QScrollArea()
        inspector_scroll.setWidgetResizable(True)
        inspector_scroll.setVerticalScrollBarPolicy(Qt.ScrollBarAsNeeded)
        inspector_content = QWidget()
        inspector_content_layout = QVBoxLayout()
        inspector_content_layout.setAlignment(Qt.AlignTop)
        inspector_content_layout.setSpacing(2)
        inspector_content.setLayout(inspector_content_layout)
        inspector_scroll.setWidget(inspector_content)
        main_layout.addWidget(inspector_scroll)

        # State variables
        current_endianness = ['little']
        current_basis = ['dec']

        # Inspector data fields (label: value)
        inspector_fields = {}

        def add_inspector_row(label_text):
            # Get base theme colors (Light or Dark based on current theme brightness)
            theme_colors = get_theme_colors(base_theme_name)
            inspector_bg = theme_colors.get('inspector_bg', theme_colors.get('background', '#1a1a1a'))
            menubar_bg = theme_colors.get('menubar_bg', theme_colors.get('background', '#1a1a1a'))
            border_color = theme_colors.get('border', '#3a3a3a')
            foreground = theme_colors.get('foreground', '#ffffff')

            widget = QWidget()
            widget.setStyleSheet(f"background-color: {inspector_bg}; border: 1px solid {border_color}; border-radius: 3px;")
            label_color = foreground
            value_bg = menubar_bg
            value_border = border_color
            value_color = foreground

            layout = QHBoxLayout()
            layout.setContentsMargins(6, 3, 6, 3)

            label = QLabel(label_text)
            label.setMinimumWidth(90)
            label.setFont(QFont("Arial", 8))
            label.setStyleSheet(f"color: {label_color}; border: none;")
            layout.addWidget(label)

            value_edit = QLineEdit()
            value_edit.setFont(QFont("Courier", 8))
            value_edit.setStyleSheet(f"border: 1px solid {value_border}; background-color: {value_bg}; color: {value_color}; padding: 2px;")
            value_edit.setContextMenuPolicy(Qt.DefaultContextMenu)
            value_edit.setToolTip("Edit to change value")

            layout.addWidget(value_edit, 1)

            widget.setLayout(layout)
            inspector_content_layout.addWidget(widget)
            inspector_fields[label_text] = value_edit
            return value_edit

        # Create all inspector fields
        add_inspector_row("Int8:")
        add_inspector_row("UInt8:")
        add_inspector_row("Int16:")
        add_inspector_row("UInt16:")
        add_inspector_row("Int32:")
        add_inspector_row("UInt32:")
        add_inspector_row("Int64:")
        add_inspector_row("UInt64:")
        add_inspector_row("LEB128:")
        add_inspector_row("ULEB128:")
        add_inspector_row("Float32:")
        add_inspector_row("Float64:")

        # Endianness toggle button
        theme_colors = get_theme_colors(self.current_theme)
        endian_btn = QPushButton("Byte Order: Little Endian")
        endian_btn.setMinimumHeight(35)
        endian_btn.setFont(QFont("Arial", 9, QFont.Bold))
        endian_btn.setStyleSheet(f"background-color: {theme_colors['button_bg']}; color: {theme_colors.get('button_text', 'white')};")
        main_layout.addWidget(endian_btn)

        # Integral display basis options
        basis_label = QLabel("Integral Display Basis:")
        basis_label.setFont(QFont("Arial", 9, QFont.Bold))
        basis_label.setAlignment(Qt.AlignCenter)
        basis_label.setMinimumHeight(20)
        main_layout.addWidget(basis_label)

        basis_container = QWidget()
        basis_layout = QHBoxLayout()
        basis_layout.setContentsMargins(10, 5, 10, 5)
        basis_layout.setSpacing(15)

        hex_basis_radio = QRadioButton("Hex")
        hex_basis_radio.setMinimumHeight(30)
        hex_basis_radio.setFont(QFont("Arial", 9))
        basis_layout.addWidget(hex_basis_radio)

        dec_basis_radio = QRadioButton("Dec")
        dec_basis_radio.setMinimumHeight(30)
        dec_basis_radio.setFont(QFont("Arial", 9))
        dec_basis_radio.setChecked(True)
        basis_layout.addWidget(dec_basis_radio)

        oct_basis_radio = QRadioButton("Oct")
        oct_basis_radio.setMinimumHeight(30)
        oct_basis_radio.setFont(QFont("Arial", 9))
        basis_layout.addWidget(oct_basis_radio)

        basis_container.setLayout(basis_layout)
        main_layout.addWidget(basis_container)

        dialog.setLayout(main_layout)

        # Helper functions
        def format_integral(value, width, signed=False):
            if current_basis[0] == 'hex':
                if signed and value < 0:
                    mask = (1 << (width * 4)) - 1
                    value = value & mask
                return f"0x{value:0{width}X}"
            elif current_basis[0] == 'oct':
                if signed and value < 0:
                    bits = width * 4
                    mask = (1 << bits) - 1
                    value = value & mask
                return f"0o{value:o}"
            else:
                return str(value)

        def read_leb128(data_bytes, signed=True):
            result = 0
            shift = 0
            size = 0
            for b in data_bytes:
                size += 1
                result |= (b & 0x7f) << shift
                shift += 7
                if (b & 0x80) == 0:
                    break
            if signed and size > 0 and (result & (1 << (shift - 1))):
                result -= (1 << shift)
            return result, size

        updating = [False]

        def update_inspector():
            if updating[0]:
                return

            updating[0] = True

            value_str = input_edit.text().strip().upper()

            # Clear all fields
            for field in inspector_fields.values():
                field.clear()

            if not value_str:
                updating[0] = False
                return

            try:
                # Detect input type
                is_hex_string = False
                hex_value_str = value_str
                is_float = '.' in value_str

                if value_str.startswith('0X'):
                    hex_value_str = value_str[2:]
                    is_hex_string = True
                elif ' ' in value_str:
                    if all(c in '0123456789ABCDEF ' for c in value_str):
                        is_hex_string = True
                elif all(c in '0123456789ABCDEF' for c in value_str):
                    if not is_float and any(c in 'ABCDEF' for c in value_str):
                        is_hex_string = True

                if is_hex_string:
                    hex_clean = hex_value_str.replace(' ', '')
                    if len(hex_clean) % 2 != 0:
                        hex_clean = '0' + hex_clean

                    hex_bytes = bytes.fromhex(hex_clean)
                    endian = '<' if current_endianness[0] == 'little' else '>'

                    # Populate integer fields
                    if len(hex_bytes) >= 1:
                        int8_val = struct.unpack('b', hex_bytes[:1])[0]
                        uint8_val = hex_bytes[0]
                        inspector_fields["Int8:"].setText(format_integral(int8_val, 2, signed=True))
                        inspector_fields["UInt8:"].setText(format_integral(uint8_val, 2))

                    if len(hex_bytes) >= 2:
                        int16_val = struct.unpack(f'{endian}h', hex_bytes[:2])[0]
                        uint16_val = struct.unpack(f'{endian}H', hex_bytes[:2])[0]
                        inspector_fields["Int16:"].setText(format_integral(int16_val, 4, signed=True))
                        inspector_fields["UInt16:"].setText(format_integral(uint16_val, 4))

                    if len(hex_bytes) >= 4:
                        int32_val = struct.unpack(f'{endian}i', hex_bytes[:4])[0]
                        uint32_val = struct.unpack(f'{endian}I', hex_bytes[:4])[0]
                        inspector_fields["Int32:"].setText(format_integral(int32_val, 8, signed=True))
                        inspector_fields["UInt32:"].setText(format_integral(uint32_val, 8))

                        float32_val = struct.unpack(f'{endian}f', hex_bytes[:4])[0]
                        inspector_fields["Float32:"].setText(f"{float32_val:.6f}")

                    if len(hex_bytes) >= 8:
                        int64_val = struct.unpack(f'{endian}q', hex_bytes[:8])[0]
                        uint64_val = struct.unpack(f'{endian}Q', hex_bytes[:8])[0]
                        inspector_fields["Int64:"].setText(format_integral(int64_val, 16, signed=True))
                        inspector_fields["UInt64:"].setText(format_integral(uint64_val, 16))

                        float64_val = struct.unpack(f'{endian}d', hex_bytes[:8])[0]
                        inspector_fields["Float64:"].setText(f"{float64_val:.15f}")

                    # LEB128
                    if len(hex_bytes) > 0:
                        try:
                            leb_val, leb_size = read_leb128(hex_bytes, signed=True)
                            inspector_fields["LEB128:"].setText(str(leb_val))
                        except:
                            inspector_fields["LEB128:"].setText("Invalid")

                        try:
                            uleb_val, uleb_size = read_leb128(hex_bytes, signed=False)
                            inspector_fields["ULEB128:"].setText(str(uleb_val))
                        except:
                            inspector_fields["ULEB128:"].setText("Invalid")

                elif is_float:
                    float_value = float(value_str)
                    endian = '<' if current_endianness[0] == 'little' else '>'

                    # Float32
                    float32_bytes = struct.pack(f'{endian}f', float_value)
                    float32_hex = ' '.join(f"{b:02X}" for b in float32_bytes)
                    inspector_fields["Float32:"].setText(float32_hex)

                    # Float64
                    float64_bytes = struct.pack(f'{endian}d', float_value)
                    float64_hex = ' '.join(f"{b:02X}" for b in float64_bytes)
                    inspector_fields["Float64:"].setText(float64_hex)

                else:
                    int_value = int(value_str)
                    endian = '<' if current_endianness[0] == 'little' else '>'

                    # Pack to different sizes and show hex
                    try:
                        int8_bytes = struct.pack('b', int_value)
                        inspector_fields["Int8:"].setText(' '.join(f"{b:02X}" for b in int8_bytes))
                    except:
                        inspector_fields["Int8:"].setText("Overflow")

                    try:
                        uint8_bytes = struct.pack('B', int_value)
                        inspector_fields["UInt8:"].setText(' '.join(f"{b:02X}" for b in uint8_bytes))
                    except:
                        inspector_fields["UInt8:"].setText("Overflow")

                    try:
                        int16_bytes = struct.pack(f'{endian}h', int_value)
                        inspector_fields["Int16:"].setText(' '.join(f"{b:02X}" for b in int16_bytes))
                    except:
                        inspector_fields["Int16:"].setText("Overflow")

                    try:
                        uint16_bytes = struct.pack(f'{endian}H', int_value)
                        inspector_fields["UInt16:"].setText(' '.join(f"{b:02X}" for b in uint16_bytes))
                    except:
                        inspector_fields["UInt16:"].setText("Overflow")

                    try:
                        int32_bytes = struct.pack(f'{endian}i', int_value)
                        inspector_fields["Int32:"].setText(' '.join(f"{b:02X}" for b in int32_bytes))
                    except:
                        inspector_fields["Int32:"].setText("Overflow")

                    try:
                        uint32_bytes = struct.pack(f'{endian}I', int_value)
                        inspector_fields["UInt32:"].setText(' '.join(f"{b:02X}" for b in uint32_bytes))
                    except:
                        inspector_fields["UInt32:"].setText("Overflow")

                    try:
                        int64_bytes = struct.pack(f'{endian}q', int_value)
                        inspector_fields["Int64:"].setText(' '.join(f"{b:02X}" for b in int64_bytes))
                    except:
                        inspector_fields["Int64:"].setText("Overflow")

                    try:
                        uint64_bytes = struct.pack(f'{endian}Q', int_value)
                        inspector_fields["UInt64:"].setText(' '.join(f"{b:02X}" for b in uint64_bytes))
                    except:
                        inspector_fields["UInt64:"].setText("Overflow")

                    # LEB128 encoding
                    try:
                        leb_bytes = []
                        val = int_value
                        while True:
                            byte = val & 0x7f
                            val >>= 7
                            if (val == 0 and (byte & 0x40) == 0) or (val == -1 and (byte & 0x40) != 0):
                                leb_bytes.append(byte)
                                break
                            leb_bytes.append(byte | 0x80)
                        inspector_fields["LEB128:"].setText(' '.join(f"{b:02X}" for b in leb_bytes))
                    except:
                        inspector_fields["LEB128:"].setText("Error")

                    # ULEB128 encoding
                    try:
                        uleb_bytes = []
                        val = int_value if int_value >= 0 else 0
                        while True:
                            byte = val & 0x7f
                            val >>= 7
                            if val == 0:
                                uleb_bytes.append(byte)
                                break
                            uleb_bytes.append(byte | 0x80)
                        inspector_fields["ULEB128:"].setText(' '.join(f"{b:02X}" for b in uleb_bytes))
                    except:
                        inspector_fields["ULEB128:"].setText("Error")

            except (ValueError, OverflowError, struct.error):
                pass

            updating[0] = False

        def toggle_endian():
            if current_endianness[0] == 'little':
                current_endianness[0] = 'big'
                endian_btn.setText("Byte Order: Big Endian")
            else:
                current_endianness[0] = 'little'
                endian_btn.setText("Byte Order: Little Endian")
            update_inspector()

        def on_basis_changed():
            if hex_basis_radio.isChecked():
                current_basis[0] = 'hex'
            elif dec_basis_radio.isChecked():
                current_basis[0] = 'dec'
            elif oct_basis_radio.isChecked():
                current_basis[0] = 'oct'
            update_inspector()

        def on_field_edited(field_name):
            """Handle when a data inspector field is edited"""
            if updating[0]:
                return

            field = inspector_fields[field_name]
            value_str = field.text().strip()

            if not value_str:
                return

            try:
                endian = '<' if current_endianness[0] == 'little' else '>'

                # Parse the value and convert to hex bytes
                if field_name == "Int8:":
                    val = int(value_str, 0)
                    data = struct.pack('b', val)
                elif field_name == "UInt8:":
                    val = int(value_str, 0)
                    data = struct.pack('B', val)
                elif field_name == "Int16:":
                    val = int(value_str, 0)
                    data = struct.pack(f'{endian}h', val)
                elif field_name == "UInt16:":
                    val = int(value_str, 0)
                    data = struct.pack(f'{endian}H', val)
                elif field_name == "Int32:":
                    val = int(value_str, 0)
                    data = struct.pack(f'{endian}i', val)
                elif field_name == "UInt32:":
                    val = int(value_str, 0)
                    data = struct.pack(f'{endian}I', val)
                elif field_name == "Int64:":
                    val = int(value_str, 0)
                    data = struct.pack(f'{endian}q', val)
                elif field_name == "UInt64:":
                    val = int(value_str, 0)
                    data = struct.pack(f'{endian}Q', val)
                elif field_name == "Float32:":
                    # Check if it's hex bytes or float value
                    if ' ' in value_str or all(c in '0123456789ABCDEFabcdef' for c in value_str.replace(' ', '')):
                        # It's hex bytes
                        hex_clean = value_str.replace(' ', '')
                        data = bytes.fromhex(hex_clean)
                    else:
                        val = float(value_str)
                        data = struct.pack(f'{endian}f', val)
                elif field_name == "Float64:":
                    # Check if it's hex bytes or float value
                    if ' ' in value_str or all(c in '0123456789ABCDEFabcdef' for c in value_str.replace(' ', '')):
                        # It's hex bytes
                        hex_clean = value_str.replace(' ', '')
                        data = bytes.fromhex(hex_clean)
                    else:
                        val = float(value_str)
                        data = struct.pack(f'{endian}d', val)
                else:
                    return

                # Update input with hex representation
                hex_str = ' '.join(f'{b:02X}' for b in data)
                input_edit.setText(hex_str)

            except:
                # Ignore invalid input
                pass

        # Connect signals
        input_edit.textChanged.connect(update_inspector)
        endian_btn.clicked.connect(toggle_endian)
        hex_basis_radio.toggled.connect(on_basis_changed)
        dec_basis_radio.toggled.connect(on_basis_changed)
        oct_basis_radio.toggled.connect(on_basis_changed)

        # Connect each field to the editor handler
        for field_name, field_widget in inspector_fields.items():
            field_widget.editingFinished.connect(lambda fn=field_name: on_field_edited(fn))

        dialog.show()

    def show_color_picker_window(self):
        dialog = QDialog(self, Qt.Window)
        dialog.setWindowTitle("Color Picker")
        dialog.resize(500, 650)
        dialog.setMinimumSize(450, 600)
        dialog.setModal(False)

        # Track this window
        self.auxiliary_windows.append(dialog)

        # Apply theme stylesheet - use Light or Dark theme based on current theme brightness
        if self.is_dark_theme():
            base_theme_name = "Dark"
        else:
            base_theme_name = "Light"
        style = get_theme_stylesheet(base_theme_name)
        dialog.setStyleSheet(style)

        # Get base theme colors for additional styling
        theme = get_theme_colors(base_theme_name)

        # Apply additional theme styling specific to color picker
        additional_style = dialog.styleSheet() + f"""
            QSlider::groove:horizontal {{
                background: {theme.get('menubar_bg', theme['editor_bg'])};
                height: 8px;
                border-radius: 4px;
            }}
            QSlider::handle:horizontal {{
                background: {theme['button_bg']};
                width: 18px;
                margin: -5px 0;
                border-radius: 9px;
            }}
            QSlider::handle:horizontal:hover {{
                background: {theme['button_hover']};
            }}
            QCheckBox {{
                color: {theme['foreground']};
                spacing: 8px;
            }}
            QCheckBox::indicator {{
                width: 18px;
                height: 18px;
                border: 2px solid {theme['border']};
                border-radius: 3px;
                background: {theme.get('menubar_bg', theme['editor_bg'])};
            }}
            QCheckBox::indicator:checked {{
                background: {theme['button_bg']};
                border-color: {theme['button_bg']};
            }}
        """
        dialog.setStyleSheet(additional_style)

        layout = QVBoxLayout()
        layout.setSpacing(12)
        layout.setContentsMargins(20, 20, 20, 20)

        # Title
        title = QLabel("Color Picker")
        title.setFont(QFont("Arial", 14, QFont.Bold))
        title.setAlignment(Qt.AlignCenter)
        layout.addWidget(title)

        # Color preview circle - centered
        preview_frame = QWidget()
        preview_frame_layout = QHBoxLayout()
        preview_frame_layout.setAlignment(Qt.AlignCenter)
        preview_canvas = QLabel()
        preview_canvas.setFixedSize(140, 140)
        preview_canvas.setStyleSheet(f"background-color: #000000; border: 3px solid {theme['border']}; border-radius: 70px;")
        preview_frame_layout.addWidget(preview_canvas)
        preview_frame.setLayout(preview_frame_layout)
        layout.addWidget(preview_frame)

        # State variables
        state = {
            'alpha_assist_mode': 'None',  # 'None', '0.0', '1.0', or 'RGBA'
        }

        # Alpha button row
        options_row = QHBoxLayout()

        alpha_assist_btn = QPushButton("Alpha: None")
        alpha_assist_btn.setMaximumWidth(160)
        options_row.addWidget(alpha_assist_btn)

        options_row.addStretch()
        layout.addLayout(options_row)

        # Sliders container
        slider_frame = QWidget()
        slider_layout = QVBoxLayout()
        slider_layout.setSpacing(10)

        # R slider
        r_layout = QHBoxLayout()
        r_label = QLabel("R")
        r_label.setFont(QFont("Arial", 10, QFont.Bold))
        r_label.setMinimumWidth(20)
        r_layout.addWidget(r_label)
        r_slider = QSlider(Qt.Horizontal)
        r_slider.setRange(0, 255)
        r_slider.setValue(0)
        r_layout.addWidget(r_slider, 1)
        r_value = QLabel("0")
        r_value.setFont(QFont("Courier", 10))
        r_value.setMinimumWidth(40)
        r_value.setAlignment(Qt.AlignRight)
        r_layout.addWidget(r_value)
        slider_layout.addLayout(r_layout)

        # G slider
        g_layout = QHBoxLayout()
        g_label = QLabel("G")
        g_label.setFont(QFont("Arial", 10, QFont.Bold))
        g_label.setMinimumWidth(20)
        g_layout.addWidget(g_label)
        g_slider = QSlider(Qt.Horizontal)
        g_slider.setRange(0, 255)
        g_slider.setValue(0)
        g_layout.addWidget(g_slider, 1)
        g_value = QLabel("0")
        g_value.setFont(QFont("Courier", 10))
        g_value.setMinimumWidth(40)
        g_value.setAlignment(Qt.AlignRight)
        g_layout.addWidget(g_value)
        slider_layout.addLayout(g_layout)

        # B slider
        b_layout = QHBoxLayout()
        b_label = QLabel("B")
        b_label.setFont(QFont("Arial", 10, QFont.Bold))
        b_label.setMinimumWidth(20)
        b_layout.addWidget(b_label)
        b_slider = QSlider(Qt.Horizontal)
        b_slider.setRange(0, 255)
        b_slider.setValue(0)
        b_layout.addWidget(b_slider, 1)
        b_value = QLabel("0")
        b_value.setFont(QFont("Courier", 10))
        b_value.setMinimumWidth(40)
        b_value.setAlignment(Qt.AlignRight)
        b_layout.addWidget(b_value)
        slider_layout.addLayout(b_layout)

        # A slider (initially hidden)
        a_layout = QHBoxLayout()
        a_label = QLabel("A")
        a_label.setFont(QFont("Arial", 10, QFont.Bold))
        a_label.setMinimumWidth(20)
        a_layout.addWidget(a_label)
        a_slider = QSlider(Qt.Horizontal)
        a_slider.setRange(0, 255)
        a_slider.setValue(255)
        a_layout.addWidget(a_slider, 1)
        a_value = QLabel("255")
        a_value.setFont(QFont("Courier", 10))
        a_value.setMinimumWidth(40)
        a_value.setAlignment(Qt.AlignRight)
        a_layout.addWidget(a_value)

        # Create container widget for alpha slider
        a_widget = QWidget()
        a_widget.setLayout(a_layout)
        a_widget.setVisible(False)
        slider_layout.addWidget(a_widget)

        slider_frame.setLayout(slider_layout)
        layout.addWidget(slider_frame)

        # Output display (always visible)
        output_frame = QFrame()
        output_frame.setStyleSheet(f"""
            QFrame {{
                background-color: {theme['editor_bg']};
                border: 2px solid {theme['border']};
                border-radius: 5px;
                padding: 10px;
            }}
        """)
        output_layout = QVBoxLayout()

        decimal_label = QLabel("")
        decimal_label.setFont(QFont("Courier", 10))
        decimal_label.setWordWrap(True)
        output_layout.addWidget(decimal_label)

        hex_label = QLabel("")
        hex_label.setFont(QFont("Courier", 10))
        hex_label.setWordWrap(True)
        output_layout.addWidget(hex_label)

        output_frame.setLayout(output_layout)
        layout.addWidget(output_frame)

        # Copy options
        copy_row = QHBoxLayout()
        copy_raw_btn = QPushButton("Copy Raw Bytes")
        copy_hex_btn = QPushButton("Copy Hex String")
        copy_rgb_btn = QPushButton("Copy RGB/RGBA")

        copy_row.addWidget(copy_raw_btn)
        copy_row.addWidget(copy_hex_btn)
        copy_row.addWidget(copy_rgb_btn)
        layout.addLayout(copy_row)

        def update_color():
            r = r_slider.value()
            g = g_slider.value()
            b = b_slider.value()

            # Auto-calculate alpha for 0.0 and 1.0 modes
            if state['alpha_assist_mode'] in ['0.0', '1.0']:
                avg_brightness = (r + g + b) / 3.0
                if state['alpha_assist_mode'] == '0.0':
                    a_slider.setValue(max(0, min(255, int(100 - avg_brightness))))
                else:  # 1.0
                    a_slider.setValue(max(0, min(255, int(avg_brightness))))

            a = a_slider.value()

            is_rgba_mode = state['alpha_assist_mode'] == 'RGBA'
            has_alpha = state['alpha_assist_mode'] in ['0.0', '1.0', 'RGBA']

            # Update value labels
            r_value.setText(str(r))
            g_value.setText(str(g))
            b_value.setText(str(b))
            a_value.setText(str(a))

            # Update preview with transparency support
            if has_alpha:
                # Use rgba() format for transparency
                preview_canvas.setStyleSheet(f"background-color: rgba({r}, {g}, {b}, {a/255.0:.2f}); border: 3px solid {theme['border']}; border-radius: 70px;")
            else:
                hex_color = f"#{r:02X}{g:02X}{b:02X}"
                preview_canvas.setStyleSheet(f"background-color: {hex_color}; border: 3px solid {theme['border']}; border-radius: 70px;")

            # Always update translate output with decimal values (0.00-1.00)
            r_decimal = r / 255.0
            g_decimal = g / 255.0
            b_decimal = b / 255.0
            a_decimal = a / 255.0

            if is_rgba_mode:
                decimal_label.setText(f"R: {r_decimal:.2f}  G: {g_decimal:.2f}  B: {b_decimal:.2f}  A: {a_decimal:.2f}")
                hex_label.setText(f"Hex: #{r:02X}{g:02X}{b:02X}{a:02X}")
            else:
                decimal_label.setText(f"R: {r_decimal:.2f}  G: {g_decimal:.2f}  B: {b_decimal:.2f}")
                hex_label.setText(f"Hex: #{r:02X}{g:02X}{b:02X}")

        def cycle_alpha_assist():
            """Cycle between None, 0.0, 1.0, and RGBA modes"""
            if state['alpha_assist_mode'] == 'None':
                state['alpha_assist_mode'] = '0.0'
                alpha_assist_btn.setText("Alpha: 0.0")
            elif state['alpha_assist_mode'] == '0.0':
                state['alpha_assist_mode'] = '1.0'
                alpha_assist_btn.setText("Alpha: 1.0")
            elif state['alpha_assist_mode'] == '1.0':
                state['alpha_assist_mode'] = 'RGBA'
                alpha_assist_btn.setText("Alpha: RGBA")
                # Show alpha slider in RGBA mode
                a_widget.setVisible(True)
                update_color()
                return
            else:  # RGBA mode
                state['alpha_assist_mode'] = 'None'
                alpha_assist_btn.setText("Alpha: None")

            # Hide alpha slider in None, 0.0 and 1.0 modes
            a_widget.setVisible(False)

            # Handle alpha based on mode
            if state['alpha_assist_mode'] == 'None':
                # None mode: Disable alpha (fully opaque)
                a_slider.setValue(255)
            else:
                # Compute alpha based on RGB brightness
                r = r_slider.value()
                g = g_slider.value()
                b = b_slider.value()

                # Average brightness (0-255)
                avg_brightness = (r + g + b) / 3.0

                if state['alpha_assist_mode'] == '0.0':
                    # 0.0 mode: 255 - average (brighter colors = more transparent)
                    alpha = max(0, min(255, int(255 - avg_brightness)))
                else:  # 1.0
                    # 1.0 mode: 0 + average (brighter colors = more opaque)
                    alpha = max(0, min(255, int(avg_brightness)))

                a_slider.setValue(alpha)

            update_color()

        def copy_raw():
            r = r_slider.value()
            g = g_slider.value()
            b = b_slider.value()
            a = a_slider.value()

            is_rgba_mode = state['alpha_assist_mode'] == 'RGBA'

            if is_rgba_mode:
                data = bytes([r, g, b, a])
            else:
                data = bytes([r, g, b])

            # Copy as hex representation
            hex_str = ' '.join(f'{b:02X}' for b in data)
            QApplication.clipboard().setText(hex_str)

        def copy_hex():
            r = r_slider.value()
            g = g_slider.value()
            b = b_slider.value()
            a = a_slider.value()

            is_rgba_mode = state['alpha_assist_mode'] == 'RGBA'

            if is_rgba_mode:
                hex_str = f"#{r:02X}{g:02X}{b:02X}{a:02X}"
            else:
                hex_str = f"#{r:02X}{g:02X}{b:02X}"

            QApplication.clipboard().setText(hex_str)

        def copy_rgb():
            r = r_slider.value()
            g = g_slider.value()
            b = b_slider.value()
            a = a_slider.value()

            is_rgba_mode = state['alpha_assist_mode'] == 'RGBA'

            if is_rgba_mode:
                rgb_str = f"rgba({r}, {g}, {b}, {a/255.0:.2f})"
            else:
                rgb_str = f"rgb({r}, {g}, {b})"

            QApplication.clipboard().setText(rgb_str)

        # Connect signals
        alpha_assist_btn.clicked.connect(cycle_alpha_assist)
        r_slider.valueChanged.connect(update_color)
        g_slider.valueChanged.connect(update_color)
        b_slider.valueChanged.connect(update_color)
        a_slider.valueChanged.connect(update_color)
        copy_raw_btn.clicked.connect(copy_raw)
        copy_hex_btn.clicked.connect(copy_hex)
        copy_rgb_btn.clicked.connect(copy_rgb)

        update_color()

        dialog.setLayout(layout)
        dialog.show()

    def show_compare_window(self):
        dialog = QDialog(self)
        dialog.setModal(False)  # Allow multiple windows
        self.auxiliary_windows.append(dialog)  # Track this window
        dialog.setWindowTitle("Compare Files")
        dialog.setMinimumSize(1400, 900)
        dialog.resize(1400, 900)

        # Apply theme stylesheet - use Light or Dark theme based on current theme brightness
        if self.is_dark_theme():
            base_theme_name = "Dark"
        else:
            base_theme_name = "Light"
        style = get_theme_stylesheet(base_theme_name)
        dialog.setStyleSheet(style)

        layout = QVBoxLayout()
        layout.setContentsMargins(10, 10, 10, 10)

        # File selection area
        file_select_layout = QHBoxLayout()
        file_select_layout.setSpacing(5)

        # File 1
        file1_layout = QVBoxLayout()
        file1_label = QLabel("File 1 (Editable):")
        file1_label.setFont(QFont("Arial", 9, QFont.Bold))
        file1_layout.addWidget(file1_label)

        file1_path_layout = QHBoxLayout()
        file1_edit = QLineEdit()
        file1_edit.setMaximumHeight(26)
        file1_btn = QPushButton("Browse...")
        file1_btn.setMaximumHeight(26)
        file1_btn.setFont(QFont("Arial", 9))

        # Default to current file if available
        if self.current_tab_index >= 0:
            current_file = self.open_files[self.current_tab_index]
            file1_edit.setText(current_file.file_path)

        def browse_file1():
            path, _ = QFileDialog.getOpenFileName(dialog, "Select File 1")
            if path:
                file1_edit.setText(path)

        file1_btn.clicked.connect(browse_file1)
        file1_path_layout.addWidget(file1_edit)
        file1_path_layout.addWidget(file1_btn)
        file1_layout.addLayout(file1_path_layout)
        file_select_layout.addLayout(file1_layout)

        # File 2
        file2_layout = QVBoxLayout()
        file2_label = QLabel("File 2 (Read-Only Reference):")
        file2_label.setFont(QFont("Arial", 9, QFont.Bold))
        file2_layout.addWidget(file2_label)

        file2_path_layout = QHBoxLayout()
        file2_edit = QLineEdit()
        file2_edit.setMaximumHeight(26)
        file2_btn = QPushButton("Browse...")
        file2_btn.setMaximumHeight(26)
        file2_btn.setFont(QFont("Arial", 9))

        # Default to next file if available
        if len(self.open_files) > 1:
            next_index = (self.current_tab_index + 1) % len(self.open_files)
            next_file = self.open_files[next_index]
            file2_edit.setText(next_file.file_path)

        def browse_file2():
            path, _ = QFileDialog.getOpenFileName(dialog, "Select File 2")
            if path:
                file2_edit.setText(path)

        file2_btn.clicked.connect(browse_file2)
        file2_path_layout.addWidget(file2_edit)
        file2_path_layout.addWidget(file2_btn)
        file2_layout.addLayout(file2_path_layout)
        file_select_layout.addLayout(file2_layout)

        layout.addLayout(file_select_layout)

        # Compare button and toggle
        controls_layout = QHBoxLayout()
        controls_layout.setSpacing(5)
        compare_btn = QPushButton("Compare")
        compare_btn.setFixedHeight(26)
        compare_btn.setFont(QFont("Arial", 9))
        controls_layout.addWidget(compare_btn)

        refresh_btn = QPushButton("Refresh")
        refresh_btn.setFixedHeight(26)
        refresh_btn.setFont(QFont("Arial", 9))
        refresh_btn.setToolTip("Refresh comparison with current editor changes")
        controls_layout.addWidget(refresh_btn)

        toggle_highlight_share_btn = QPushButton("Toggle Highlights")
        toggle_highlight_share_btn.setFixedHeight(30)
        toggle_highlight_share_btn.setFont(QFont("Arial", 8))
        controls_layout.addWidget(toggle_highlight_share_btn)

        controls_layout.addStretch()
        layout.addLayout(controls_layout)

        # Comparison display area
        compare_splitter = QSplitter(Qt.Horizontal)

        # File 1 display (editable)
        file1_container = QWidget()
        file1_container_layout = QVBoxLayout()
        file1_container_layout.setContentsMargins(0, 0, 0, 0)

        file1_header_layout = QHBoxLayout()
        file1_header_layout.setContentsMargins(0, 0, 0, 0)
        file1_display_label = QLabel("File 1 - Editable")
        file1_display_label.setFont(QFont("Arial", 9, QFont.Bold))
        file1_header_layout.addWidget(file1_display_label)
        file1_container_layout.addLayout(file1_header_layout)

        # Headers for File 1
        file1_headers = QHBoxLayout()
        file1_headers.setContentsMargins(0, 2, 0, 2)
        file1_offset_header = QLabel("Offset")
        file1_offset_header.setFont(QFont("Courier", 8, QFont.Bold))
        file1_offset_header.setMinimumWidth(100)
        file1_offset_header.setMaximumWidth(100)
        file1_offset_header.setAlignment(Qt.AlignCenter)
        file1_headers.addWidget(file1_offset_header)

        file1_hex_header = QLabel("Hex Bytes")
        file1_hex_header.setFont(QFont("Courier", 8, QFont.Bold))
        file1_hex_header.setAlignment(Qt.AlignCenter)
        file1_headers.addWidget(file1_hex_header)

        file1_text_header = QLabel("Decoded Text")
        file1_text_header.setFont(QFont("Courier", 8, QFont.Bold))
        file1_text_header.setMinimumWidth(150)
        file1_text_header.setMaximumWidth(150)
        file1_text_header.setAlignment(Qt.AlignCenter)
        file1_headers.addWidget(file1_text_header)

        file1_container_layout.addLayout(file1_headers)

        file1_display = HexTextEdit()
        file1_display.setFont(QFont("Courier", 10))
        file1_display.setReadOnly(True)
        file1_display.setMinimumHeight(500)
        file1_container_layout.addWidget(file1_display, 1)

        file1_container.setLayout(file1_container_layout)
        compare_splitter.addWidget(file1_container)

        # File 2 display (read-only)
        file2_container = QWidget()
        file2_container_layout = QVBoxLayout()
        file2_container_layout.setContentsMargins(0, 0, 0, 0)

        file2_header_layout = QHBoxLayout()
        file2_header_layout.setContentsMargins(0, 0, 0, 0)
        file2_display_label = QLabel("File 2 - Read-Only Reference")
        file2_display_label.setFont(QFont("Arial", 9, QFont.Bold))
        file2_header_layout.addWidget(file2_display_label)
        file2_container_layout.addLayout(file2_header_layout)

        # Headers for File 2
        file2_headers = QHBoxLayout()
        file2_headers.setContentsMargins(0, 2, 0, 2)
        file2_offset_header = QLabel("Offset")
        file2_offset_header.setFont(QFont("Courier", 8, QFont.Bold))
        file2_offset_header.setMinimumWidth(100)
        file2_offset_header.setMaximumWidth(100)
        file2_offset_header.setAlignment(Qt.AlignCenter)
        file2_headers.addWidget(file2_offset_header)

        file2_hex_header = QLabel("Hex Bytes")
        file2_hex_header.setFont(QFont("Courier", 8, QFont.Bold))
        file2_hex_header.setAlignment(Qt.AlignCenter)
        file2_headers.addWidget(file2_hex_header)

        file2_text_header = QLabel("Decoded Text")
        file2_text_header.setFont(QFont("Courier", 8, QFont.Bold))
        file2_text_header.setMinimumWidth(150)
        file2_text_header.setMaximumWidth(150)
        file2_text_header.setAlignment(Qt.AlignCenter)
        file2_headers.addWidget(file2_text_header)

        file2_container_layout.addLayout(file2_headers)

        file2_display = HexTextEdit()
        file2_display.setFont(QFont("Courier", 10))
        file2_display.setReadOnly(True)
        file2_display.setTextInteractionFlags(Qt.TextSelectableByMouse | Qt.TextSelectableByKeyboard)
        file2_display.setMinimumHeight(500)
        file2_container_layout.addWidget(file2_display, 1)

        file2_container.setLayout(file2_container_layout)
        compare_splitter.addWidget(file2_container)

        layout.addWidget(compare_splitter, 1)

        # Scroll sync: file2 follows file1, but file2 can scroll independently
        syncing = [False]

        def sync_file1_to_file2(value):
            if not syncing[0]:
                syncing[0] = True
                file2_display.verticalScrollBar().setValue(value)
                syncing[0] = False

        file1_display.verticalScrollBar().valueChanged.connect(sync_file1_to_file2)

        # Store data for comparison
        file1_original_data = None
        file2_data = None
        file1_current_data = None
        file1_snapshot_data = None
        current_style_swapped = False
        comp_cursor_position = None
        comp_cursor_nibble = 0

        def format_comparison_view(data, differences_set, show_red_diff, original_data_for_edit_check=None, reference_data=None, cursor_pos=None, cursor_nibble=0, user_highlights=None, original_differences_set=None):
            html = '<pre style="font-family: Courier; line-height: 1.4;">'

            bytes_per_row = 16
            for row_start in range(0, len(data), bytes_per_row):
                row_end = min(row_start + bytes_per_row, len(data))
                row_data = data[row_start:row_end]

                # Offset
                offset_str = f"0x{row_start:08X}"
                html += f'<span style="color: #888;">{offset_str}</span>  '

                # Hex bytes
                for i, byte in enumerate(row_data):
                    offset = row_start + i
                    hex_str = f"{byte:02X}"

                    color = None
                    bg_color = None
                    is_cursor = (cursor_pos is not None and offset == cursor_pos)

                    # Check for user highlights first
                    if user_highlights and offset in user_highlights:
                        highlight_info = user_highlights[offset]
                        if highlight_info.get("underline", False):
                            # Use underline - keep as text decoration later
                            pass
                        else:
                            # Use background color with 25% opacity
                            hex_color = highlight_info["color"].lstrip('#')
                            r, g, b = int(hex_color[0:2], 16), int(hex_color[2:4], 16), int(hex_color[4:6], 16)
                            bg_color = f'rgba({r}, {g}, {b}, 0.25)'

                    if original_data_for_edit_check and reference_data and original_differences_set is not None:
                        # Check if this byte was edited INSIDE Compare Data (after snapshot)
                        if offset < len(original_data_for_edit_check) and byte != original_data_for_edit_check[offset]:
                            # Byte was edited inside Compare Data
                            if offset < len(reference_data) and byte == reference_data[offset]:
                                # Edited to match File 2 - green
                                color = '#00AA00'
                            elif offset in original_differences_set:
                                # Was different at snapshot (including pre-existing edits) - keep red
                                color = '#FF0000'
                            else:
                                # Was matching at snapshot, edited to differ - show as blue (new edit)
                                color = '#0066FF'
                        elif offset in differences_set and show_red_diff:
                            # Not edited in Compare Data, but different - show as red
                            color = '#FF0000'
                    elif offset in differences_set and show_red_diff:
                        color = '#FF0000'

                    # Format the byte with highlighting and per-nibble bold
                    if is_cursor:
                        # Highlight entire byte, make specific nibble bold
                        first_nibble = hex_str[0]
                        second_nibble = hex_str[1]

                        # Use cursor background color matching main editor theme
                        cursor_bg = '#404040' if self.is_dark_theme() else '#C8DCFF'
                        if color:
                            # Keep color but add background highlight
                            if cursor_nibble == 0:
                                html += f'<span style="color: {color}; background-color: {cursor_bg};"><b>{first_nibble}</b>{second_nibble}</span> '
                            else:
                                html += f'<span style="color: {color}; background-color: {cursor_bg};">{first_nibble}<b>{second_nibble}</b></span> '
                        else:
                            # No color, just highlight and bold
                            if cursor_nibble == 0:
                                html += f'<span style="background-color: {cursor_bg};"><b>{first_nibble}</b>{second_nibble}</span> '
                            else:
                                html += f'<span style="background-color: {cursor_bg};">{first_nibble}<b>{second_nibble}</b></span> '
                    elif bg_color:
                        # User highlight background
                        if color:
                            html += f'<span style="color: {color}; background-color: {bg_color}; font-weight: bold;">{hex_str}</span> '
                        else:
                            html += f'<span style="background-color: {bg_color};">{hex_str}</span> '
                    elif color:
                        html += f'<span style="color: {color}; font-weight: bold;">{hex_str}</span> '
                    else:
                        html += f'{hex_str} '

                # Padding for incomplete rows
                padding = bytes_per_row - len(row_data)
                html += '   ' * padding

                # Decoded text
                html += ' | '
                for i, byte in enumerate(row_data):
                    offset = row_start + i
                    # Control characters (0x00-0x1F, 0x7F-0x9F) shown as dots
                    char = chr(byte) if (32 <= byte <= 126) or (160 <= byte <= 255) else '.'

                    color = None
                    bg_color = None
                    is_cursor = (cursor_pos is not None and offset == cursor_pos)

                    # Check for user highlights first
                    if user_highlights and offset in user_highlights:
                        highlight_info = user_highlights[offset]
                        if highlight_info.get("underline", False):
                            # Use underline - keep as text decoration later
                            pass
                        else:
                            # Use background color with 25% opacity
                            hex_color = highlight_info["color"].lstrip('#')
                            r, g, b = int(hex_color[0:2], 16), int(hex_color[2:4], 16), int(hex_color[4:6], 16)
                            bg_color = f'rgba({r}, {g}, {b}, 0.25)'

                    if original_data_for_edit_check and reference_data and original_differences_set is not None:
                        # Check if this byte was edited INSIDE Compare Data (after snapshot)
                        if offset < len(original_data_for_edit_check) and byte != original_data_for_edit_check[offset]:
                            # Byte was edited inside Compare Data
                            if offset < len(reference_data) and byte == reference_data[offset]:
                                # Edited to match File 2 - green
                                color = '#00AA00'
                            elif offset in original_differences_set:
                                # Was different at snapshot (including pre-existing edits) - keep red
                                color = '#FF0000'
                            else:
                                # Was matching at snapshot, edited to differ - show as blue (new edit)
                                color = '#0066FF'
                        elif offset in differences_set and show_red_diff:
                            # Not edited in Compare Data, but different - show as red
                            color = '#FF0000'
                    elif offset in differences_set and show_red_diff:
                        color = '#FF0000'

                    # Format the character
                    if is_cursor:
                        # Highlight and bold the character at cursor position
                        cursor_bg = '#404040' if self.is_dark_theme() else '#C8DCFF'
                        if color:
                            html += f'<span style="color: {color}; background-color: {cursor_bg}; font-weight: bold;">{char}</span>'
                        else:
                            html += f'<span style="background-color: {cursor_bg}; font-weight: bold;">{char}</span>'
                    elif bg_color:
                        # User highlight background
                        if color:
                            html += f'<span style="color: {color}; background-color: {bg_color}; font-weight: bold;">{char}</span>'
                        else:
                            html += f'<span style="background-color: {bg_color};">{char}</span>'
                    elif color:
                        html += f'<span style="color: {color}; font-weight: bold;">{char}</span>'
                    else:
                        html += char

                html += '\n'

            html += '</pre>'
            return html

        def update_comparison_display():
            if file1_current_data is None or file2_data is None:
                return

            # Save scroll positions independently
            file1_scrollbar = file1_display.verticalScrollBar()
            file2_scrollbar = file2_display.verticalScrollBar()
            file1_scroll_pos = file1_scrollbar.value()
            file2_scroll_pos = file2_scrollbar.value()

            # Find differences between current and original
            differences = set()
            original_differences = set()
            max_len = max(len(file1_current_data), len(file2_data))

            for i in range(max_len):
                byte1 = file1_current_data[i] if i < len(file1_current_data) else None
                byte2 = file2_data[i] if i < len(file2_data) else None

                if byte1 != byte2:
                    differences.add(i)

            # Track differences at the time Compare Data was opened (snapshot)
            max_len_snap = max(len(file1_snapshot_data), len(file2_data))
            for i in range(max_len_snap):
                snap_byte1 = file1_snapshot_data[i] if i < len(file1_snapshot_data) else None
                byte2 = file2_data[i] if i < len(file2_data) else None

                if snap_byte1 != byte2:
                    original_differences.add(i)

            # Determine which highlights to use
            file1_highlights = None
            file2_highlights = None

            if highlight_share_enabled[0]:
                # Get highlights from main editor files
                file1_path = file1_edit.text()
                file2_path = file2_edit.text()

                # Find file tabs that match the paths and get their individual highlights
                for file_tab in self.open_files:
                    if file_tab.file_path == file1_path:
                        file1_highlights = file_tab.byte_highlights
                    if file_tab.file_path == file2_path:
                        file2_highlights = file_tab.byte_highlights

            # Display both files with red differences on both sides and cursor highlighting
            file1_html = format_comparison_view(file1_current_data, differences, True, file1_snapshot_data, file2_data, comp_cursor_position, comp_cursor_nibble, file1_highlights, original_differences)
            file2_html = format_comparison_view(file2_data, differences, True, cursor_pos=comp_cursor_position, cursor_nibble=comp_cursor_nibble, user_highlights=file2_highlights)

            file1_display.setHtml(file1_html)
            file2_display.setHtml(file2_html)

            # Restore scroll positions independently
            file1_scrollbar.setValue(file1_scroll_pos)
            file2_scrollbar.setValue(file2_scroll_pos)

        def compare_files():
            nonlocal file1_original_data, file2_data, file1_current_data, file1_snapshot_data, comp_cursor_position, comp_cursor_nibble

            path1 = file1_edit.text()
            path2 = file2_edit.text()

            if not path1 or not path2:
                QMessageBox.critical(dialog, "Error", "Please select both files")
                return

            try:
                # Check if file1 is open in editor and use its current data
                file1_tab = None
                for file_tab in self.open_files:
                    if file_tab.file_path == path1:
                        file1_tab = file_tab
                        break

                if file1_tab:
                    # Use the current editor data (includes all edits, cuts, inserts)
                    file1_current_data = bytearray(file1_tab.file_data)
                    file1_original_data = bytearray(file1_tab.original_data)
                    file1_snapshot_data = bytearray(file1_tab.file_data)
                else:
                    # File not open in editor, read from disk
                    with open(path1, 'rb') as f1:
                        file1_original_data = bytearray(f1.read())
                        file1_current_data = bytearray(file1_original_data)
                        file1_snapshot_data = bytearray(file1_original_data)

                # Check if file2 is open in editor and use its current data
                file2_tab = None
                for file_tab in self.open_files:
                    if file_tab.file_path == path2:
                        file2_tab = file_tab
                        break

                if file2_tab:
                    # Use the current editor data (includes all edits, cuts, inserts)
                    file2_data = bytearray(file2_tab.file_data)
                else:
                    # File not open in editor, read from disk
                    with open(path2, 'rb') as f2:
                        file2_data = bytearray(f2.read())

                comp_cursor_position = 0
                comp_cursor_nibble = 0
                update_comparison_display()

            except Exception as e:
                QMessageBox.critical(dialog, "Error", f"Failed to compare: {str(e)}")

        # State for highlight sharing
        highlight_share_enabled = [False]

        def toggle_highlight_share():
            if file1_original_data is None or file2_data is None:
                return

            highlight_share_enabled[0] = not highlight_share_enabled[0]

            # Update button text
            if highlight_share_enabled[0]:
                toggle_highlight_share_btn.setText("Toggle Highlight Share (ON)")
            else:
                toggle_highlight_share_btn.setText("Toggle Highlight Share (OFF)")

            update_comparison_display()

        def handle_file1_click(event):
            nonlocal comp_cursor_position, comp_cursor_nibble
            if file1_current_data is None:
                return

            cursor = file1_display.cursorForPosition(event.pos())
            text = file1_display.toPlainText()
            pos = cursor.position()

            lines = text[:pos].split('\n')
            if not lines:
                return

            current_line = lines[-1]

            # Parse offset
            try:
                line_full = text.split('\n')[len(lines) - 1] if len(lines) <= len(text.split('\n')) else ""
                if '|' in line_full:
                    offset_part = line_full.split('|')[0].strip().split()[0]
                    row_offset = int(offset_part, 16)

                    # Find column
                    col_in_line = len(current_line)
                    hex_start_col = 12

                    if col_in_line >= hex_start_col:
                        hex_col = col_in_line - hex_start_col
                        byte_col = hex_col // 3
                        nibble_col = (hex_col % 3)

                        comp_cursor_position = row_offset + byte_col
                        comp_cursor_nibble = 0 if nibble_col == 0 else 1

                        if comp_cursor_position >= len(file1_current_data):
                            comp_cursor_position = len(file1_current_data) - 1

                        # Update display to show bold cursor
                        update_comparison_display()
            except:
                pass

        def handle_file1_key(event):
            nonlocal comp_cursor_position, comp_cursor_nibble
            if file1_current_data is None or comp_cursor_position is None:
                return

            key = event.key()

            # Handle hex input
            if Qt.Key_0 <= key <= Qt.Key_9 or Qt.Key_A <= key <= Qt.Key_F:
                char = event.text().upper()
                if char in '0123456789ABCDEF':
                    if comp_cursor_position >= len(file1_current_data):
                        return

                    old_value = file1_current_data[comp_cursor_position]
                    nibble_value = int(char, 16)

                    if comp_cursor_nibble == 0:
                        new_value = (nibble_value << 4) | (old_value & 0x0F)
                    else:
                        new_value = (old_value & 0xF0) | nibble_value

                    # Save the position of the byte we're editing before moving cursor
                    edited_position = comp_cursor_position
                    file1_current_data[edited_position] = new_value

                    # Move cursor
                    if comp_cursor_nibble == 0:
                        comp_cursor_nibble = 1
                    else:
                        comp_cursor_nibble = 0
                        if comp_cursor_position < len(file1_current_data) - 1:
                            comp_cursor_position += 1

                    update_comparison_display()

                    # Update main editor if this is the current file
                    if self.current_tab_index >= 0:
                        current_file = self.open_files[self.current_tab_index]
                        if current_file.file_path == file1_edit.text():
                            current_file.file_data = bytearray(file1_current_data)
                            current_file.modified = True
                            # Mark the edited byte as replaced (red) if it differs from original
                            if edited_position not in current_file.inserted_bytes:
                                if edited_position < len(current_file.original_data):
                                    if new_value != current_file.original_data[edited_position]:
                                        # Byte was changed from original - mark as replaced (red)
                                        current_file.replaced_bytes.add(edited_position)
                                        current_file.modified_bytes.discard(edited_position)
                                    else:
                                        # Byte matches original - remove all markings
                                        current_file.replaced_bytes.discard(edited_position)
                                        current_file.modified_bytes.discard(edited_position)
                            self.display_hex()

        def handle_file2_click(event):
            nonlocal comp_cursor_position, comp_cursor_nibble
            if file2_data is None:
                return

            cursor = file2_display.cursorForPosition(event.pos())
            text = file2_display.toPlainText()
            pos = cursor.position()

            lines = text[:pos].split('\n')
            if not lines:
                return

            current_line = lines[-1]

            # Parse offset
            try:
                line_full = text.split('\n')[len(lines) - 1] if len(lines) <= len(text.split('\n')) else ""
                if '|' not in line_full:
                    return

                offset_part = line_full.split('|')[0].strip().split()[0]
                row_offset = int(offset_part, 16)

                # Find column - need to get the actual character at cursor position
                col_in_line = len(current_line)
                hex_start_col = 12
                hex_end_col = 12 + (16 * 3) - 1  # 16 bytes * 3 chars per byte - 1

                # Check if we're in the hex area
                if col_in_line < hex_start_col or col_in_line > hex_end_col:
                    return

                hex_col = col_in_line - hex_start_col
                byte_col = hex_col // 3
                nibble_col = (hex_col % 3)

                # Check bounds
                if byte_col >= 16:
                    return

                # Get the character at the click position
                if pos < len(text):
                    clicked_char = text[pos]
                    # If clicking on a space (nibble_col == 2), select that byte's second nibble
                    if clicked_char == ' ':
                        # Space after a byte - select this byte's second nibble
                        nibble_col = 1
                    elif clicked_char not in '0123456789ABCDEFabcdef':
                        # Not a hex character or space, ignore
                        return

                comp_cursor_position = row_offset + byte_col
                # Match file1 behavior: nibble 0 stays 0, nibble 1 or 2 becomes 1
                comp_cursor_nibble = 0 if nibble_col == 0 else 1

                # Check if position is valid
                if comp_cursor_position >= len(file2_data):
                    comp_cursor_position = len(file2_data) - 1

                # Scroll file1 to match the clicked line in file2
                # Get file2's current scroll position
                file2_scroll = file2_display.verticalScrollBar().value()

                # Temporarily disable sync to prevent recursion
                syncing[0] = True
                file1_display.verticalScrollBar().setValue(file2_scroll)
                syncing[0] = False

                update_comparison_display()
            except:
                pass

        file1_display.clicked.connect(handle_file1_click)
        file2_display.clicked.connect(handle_file2_click)
        dialog.keyPressEvent = handle_file1_key

        compare_btn.clicked.connect(compare_files)
        refresh_btn.clicked.connect(compare_files)
        toggle_highlight_share_btn.clicked.connect(toggle_highlight_share)

        # Auto-compare if both files are already set
        if file1_edit.text() and file2_edit.text():
            compare_files()

        dialog.setLayout(layout)
        dialog.exec_()

    def save_file(self):
        if self.current_tab_index < 0:
            return

        current_file = self.open_files[self.current_tab_index]
        original_path = current_file.file_path
        backup_path = original_path + ".bak"

        try:
            # Create backup of original file
            import shutil
            shutil.copy2(original_path, backup_path)

            # Overwrite original file with modified data
            with open(original_path, 'wb') as f:
                f.write(current_file.file_data)

            current_file.modified = False
            current_file.modified_bytes.clear()
            current_file.inserted_bytes.clear()
            current_file.replaced_bytes.clear()
            self.display_hex()

            QMessageBox.information(self, "Success", f"File saved successfully!\nBackup created: {os.path.basename(backup_path)}")

        except Exception as e:
            QMessageBox.critical(self, "Error", f"Failed to save: {str(e)}")

    def save_all_files(self):
        if len(self.open_files) == 0:
            return

        import shutil
        saved_count = 0
        failed_files = []

        for file_tab in self.open_files:
            if not file_tab.modified:
                continue

            original_path = file_tab.file_path
            backup_path = original_path + ".bak"

            try:
                # Create backup of original file
                shutil.copy2(original_path, backup_path)

                # Overwrite original file with modified data
                with open(original_path, 'wb') as f:
                    f.write(file_tab.file_data)

                file_tab.modified = False
                file_tab.modified_bytes.clear()
                file_tab.inserted_bytes.clear()
                saved_count += 1

            except Exception as e:
                failed_files.append(f"{os.path.basename(original_path)}: {str(e)}")

        # Refresh display
        self.display_hex()

        # Show result message
        if failed_files:
            error_msg = f"Saved {saved_count} file(s).\n\nFailed to save:\n" + "\n".join(failed_files)
            QMessageBox.warning(self, "Save All - Partial Success", error_msg)
        elif saved_count > 0:
            QMessageBox.information(self, "Success", f"All {saved_count} file(s) saved successfully!\nBackups created for each file.")
        else:
            QMessageBox.information(self, "Info", "No files needed saving.")

    def showEvent(self, event):
        """Handle window show event to detect correct screen on startup."""
        super().showEvent(event)

        # Connect to screen change events (windowHandle is now available)
        if not self.screen_change_connected and self.windowHandle():
            self.windowHandle().screenChanged.connect(self.on_screen_changed)
            self.screen_change_connected = True

        # Recalculate hex column width now that we know which screen we're on
        new_width = self.get_hex_column_width()

        if new_width != self.hex_column_width:
            self.hex_column_width = new_width
            print(f"On show: Updating hex column width to: {new_width}px")

            # Update the hex header and display widths
            self.hex_header.setMinimumWidth(self.hex_column_width)
            self.hex_header.setMaximumWidth(self.hex_column_width)
            self.hex_display.setMinimumWidth(self.hex_column_width)
            self.hex_display.setMaximumWidth(self.hex_column_width)

            # Update overlay geometries
            if hasattr(self, 'segment_overlay'):
                self.segment_overlay.setGeometry(0, 0, self.hex_column_width, self.hex_display.height())
            if hasattr(self, 'header_segment_overlay'):
                self.header_segment_overlay.setGeometry(0, 0, self.hex_column_width, self.hex_header.height())
            if hasattr(self, 'edit_box_overlay'):
                self.edit_box_overlay.setGeometry(0, 0, self.hex_column_width, self.hex_display.height())
            if hasattr(self, 'boundary_overlay'):
                self.boundary_overlay.setGeometry(0, 0, self.hex_column_width, self.hex_display.height())

    def resizeEvent(self, event):
        super().resizeEvent(event)

        # Update inspector overlay position
        self.position_inspector_overlay()

        # Update overlay geometries for hex display
        if hasattr(self, 'segment_overlay') and hasattr(self, 'hex_display'):
            self.segment_overlay.setGeometry(0, 0, self.hex_column_width, self.hex_display.height())
        if hasattr(self, 'header_segment_overlay') and hasattr(self, 'hex_header'):
            self.header_segment_overlay.setGeometry(0, 0, self.hex_column_width, self.hex_header.height())
        if hasattr(self, 'edit_box_overlay') and hasattr(self, 'hex_display'):
            self.edit_box_overlay.setGeometry(0, 0, self.hex_column_width, self.hex_display.height())
        if hasattr(self, 'boundary_overlay') and hasattr(self, 'hex_display'):
            self.boundary_overlay.setGeometry(0, 0, self.hex_column_width, self.hex_display.height())

        # Update search overlay position when window resizes (overlay spans hex and ASCII at bottom)
        if hasattr(self, 'results_overlay') and self.results_overlay is not None and self.results_overlay.isVisible():
            overlay_height = 200
            x_start = 130  # After offset column
            # Calculate width dynamically based on hex_ascii_container width
            overlay_width = self.hex_ascii_container.width() - x_start
            y_position = self.hex_ascii_container.height() - overlay_height
            self.results_overlay.setGeometry(x_start, y_position, overlay_width, overlay_height)
            self.results_overlay.raise_()

        # Update signature pointer overlays when window resizes
        if hasattr(self, 'signature_overlays') and self.signature_overlays:
            self.update_signature_overlays()

    def toggle_notes(self):
        if self.notes_window is None:
            self.notes_window = NotesWindow(self, self)
            self.notes_window.show()
        else:
            if self.notes_window.isVisible():
                self.notes_window.hide()
            else:
                self.notes_window.show()
                # Update theme when showing
                self.notes_window.apply_theme(self.is_dark_theme())


    def show_theme_selector(self):
        """Show theme selection dialog"""
        dialog = QDialog(self)
        dialog.setWindowTitle("Select Theme")
        dialog.setMinimumSize(400, 500)

        # Apply theme stylesheet - use Light or Dark theme based on current theme brightness
        # This ensures light gradient themes get a light dialog, dark themes get a dark dialog
        if self.is_dark_theme():
            base_theme_name = "Dark"
        else:
            base_theme_name = "Light"
        style = get_theme_stylesheet(base_theme_name)
        dialog.setStyleSheet(style)

        layout = QVBoxLayout()

        # Info label
        info_label = QLabel("Choose a theme:")
        layout.addWidget(info_label)

        # List widget for themes
        theme_list = QListWidget()
        theme_list.setSelectionMode(QListWidget.SingleSelection)

        # Add built-in themes organized by category
        all_themes = get_all_themes()
        custom_themes = load_custom_themes()
        theme_categories = get_theme_categories()

        # Get base theme colors for category backgrounds (Light or Dark based on current theme)
        base_theme_colors = get_theme_colors(base_theme_name)
        category_bg_color = base_theme_colors.get('selection_bg', base_theme_colors.get('editor_bg', '#3e3e42'))
        category_fg_color = base_theme_colors.get('foreground', '#d4d4d4')

        # Add built-in themes by category
        for category in ["Dark", "Light", "Gradient"]:
            if category in theme_categories:
                # Add category separator
                separator_item = QListWidgetItem(category)
                separator_item.setFlags(Qt.NoItemFlags)
                separator_item.setBackground(QColor(category_bg_color))
                separator_item.setForeground(QColor(category_fg_color))
                theme_list.addItem(separator_item)

                # Add themes in this category
                category_themes = theme_categories[category]
                for theme_name in sorted(category_themes.keys()):
                    item = QListWidgetItem(f"  {theme_name}")
                    item.setData(Qt.UserRole, theme_name)  # Store actual theme name
                    theme_list.addItem(item)
                    if theme_name == self.current_theme:
                        theme_list.setCurrentItem(item)

        # Add separator if there are custom themes
        if custom_themes:
            separator_item = QListWidgetItem("--- Custom Themes ---")
            separator_item.setFlags(Qt.NoItemFlags)
            separator_item.setBackground(QColor(category_bg_color))
            separator_item.setForeground(QColor(category_fg_color))
            theme_list.addItem(separator_item)

            # Add custom themes
            for theme_name in sorted(custom_themes.keys()):
                item = QListWidgetItem(f"  {theme_name} (Custom)")
                item.setData(Qt.UserRole, theme_name)  # Store actual theme name
                theme_list.addItem(item)
                if theme_name == self.current_theme:
                    theme_list.setCurrentItem(item)

        layout.addWidget(theme_list)

        # Custom theme buttons
        custom_button_layout = QHBoxLayout()

        create_custom_button = QPushButton("Create Custom Theme")

        def create_custom_theme():
            self.show_custom_theme_editor()
            # Refresh the theme list
            dialog.close()
            self.show_theme_selector()

        create_custom_button.clicked.connect(create_custom_theme)
        custom_button_layout.addWidget(create_custom_button)

        edit_custom_button = QPushButton("Edit Selected")

        def edit_selected_theme():
            current_item = theme_list.currentItem()
            if current_item:
                theme_name = current_item.data(Qt.UserRole)
                if not theme_name:
                    theme_name = current_item.text()

                # Only allow editing custom themes
                if theme_name in custom_themes:
                    self.show_custom_theme_editor(theme_name)
                    dialog.close()
                    self.show_theme_selector()
                else:
                    QMessageBox.information(dialog, "Info",
                        "You can only edit custom themes. To create a new theme based on this one, "
                        "use 'Create Custom Theme' and select this theme as the base.")

        edit_custom_button.clicked.connect(edit_selected_theme)
        custom_button_layout.addWidget(edit_custom_button)
        custom_button_layout.addStretch()

        layout.addLayout(custom_button_layout)

        # Buttons
        button_layout = QHBoxLayout()

        apply_button = QPushButton("Apply")

        def apply_theme():
            current_item = theme_list.currentItem()
            if current_item and current_item.flags() != Qt.NoItemFlags:
                # Get the actual theme name
                theme_name = current_item.data(Qt.UserRole)
                if not theme_name:
                    theme_name = current_item.text()

                self.current_theme = theme_name
                self.apply_theme()
                self.save_settings()
                dialog.accept()

        apply_button.clicked.connect(apply_theme)
        theme_list.itemDoubleClicked.connect(apply_theme)

        cancel_button = QPushButton("Cancel")
        cancel_button.clicked.connect(dialog.reject)

        button_layout.addWidget(apply_button)
        button_layout.addStretch()
        button_layout.addWidget(cancel_button)

        layout.addLayout(button_layout)
        dialog.setLayout(layout)

        # Apply current theme to dialog
        dialog.setStyleSheet(get_theme_stylesheet(self.current_theme))

        dialog.show()

    def show_custom_theme_editor(self, theme_name=None):
        """Show custom theme editor dialog"""
        editor = CustomThemeEditor(self, theme_name)

        # Connect live preview to apply theme in real-time
        def preview_theme(theme):
            # Temporarily apply theme for preview
            temp_theme_name = "__preview__"

            # Get all themes (includes built-in and custom)
            all_themes = get_all_themes()
            all_themes[temp_theme_name] = theme

            self.current_theme = temp_theme_name
            self.apply_theme()

        editor.themeChanged.connect(preview_theme)

        if editor.exec_() == QDialog.Accepted:
            # User clicked Apply - save and apply the theme
            custom_theme = editor.get_theme()
            theme_name = custom_theme.get("name", "Custom Theme")

            # Load and update custom themes
            custom_themes = load_custom_themes()
            custom_themes[theme_name] = custom_theme
            save_custom_themes(custom_themes)

            # Apply the new theme
            self.current_theme = theme_name
            self.apply_theme()
            self.save_settings()

    def show_debug_window(self):
        """Show debugging console window"""
        if self.debug_window is None:
            self.debug_window = DebugWindow(self)

            # Setup output redirection if not already done
            if self.debug_redirector is None:
                self.debug_redirector = DebugOutputRedirector(self.debug_window.output_text)
                sys.stdout = self.debug_redirector
                sys.stderr = self.debug_redirector

        self.debug_window.show()
        self.debug_window.raise_()
        self.debug_window.activateWindow()

    def show_about_dialog(self):
        """Show About dialog with application information"""
        dialog = QDialog(self)
        dialog.setWindowTitle("About")
        dialog.setMinimumSize(500, 400)
        dialog.setMaximumSize(500, 400)

        # Apply current theme to dialog
        dialog.setStyleSheet(get_theme_stylesheet(self.current_theme))

        main_layout = QVBoxLayout()
        main_layout.setContentsMargins(20, 20, 20, 20)
        main_layout.setSpacing(15)

        # Title
        title_label = QLabel("RxD Hex Editor")
        title_font = QFont("Arial", 18, QFont.Bold)
        title_label.setFont(title_font)
        title_label.setAlignment(Qt.AlignCenter)
        main_layout.addWidget(title_label)

        # Tagline
        tagline_label = QLabel("Byte Editing, Visualized")
        tagline_font = QFont("Arial", 9)
        tagline_label.setFont(tagline_font)
        tagline_label.setAlignment(Qt.AlignCenter)
        if self.is_dark_theme():
            tagline_label.setStyleSheet("color: #999;")
        else:
            tagline_label.setStyleSheet("color: #666;")
        main_layout.addWidget(tagline_label)

        main_layout.addSpacing(10)

        # Developer section
        dev_frame = QWidget()
        dev_layout = QVBoxLayout()
        dev_layout.setContentsMargins(20, 10, 20, 10)
        dev_layout.setSpacing(5)

        dev_label = QLabel("Main Developer: Akira Ryuzaki")
        dev_font = QFont("Arial", 9)
        dev_label.setFont(dev_font)
        dev_label.setAlignment(Qt.AlignCenter)
        dev_layout.addWidget(dev_label)

        dev_jp_label = QLabel("アキラ・リュウザキ")
        dev_jp_font = QFont("Arial", 9)
        dev_jp_label.setFont(dev_jp_font)
        dev_jp_label.setAlignment(Qt.AlignCenter)
        if self.is_dark_theme():
            dev_jp_label.setStyleSheet("color: #bbb;")
        else:
            dev_jp_label.setStyleSheet("color: #777;")
        dev_layout.addWidget(dev_jp_label)

        dev_frame.setLayout(dev_layout)
        if self.is_dark_theme():
            dev_frame.setStyleSheet("QWidget { background-color: #2d2d2d; border: 1px solid #444; border-radius: 5px; }")
        else:
            dev_frame.setStyleSheet("QWidget { background-color: #f5f5f5; border: 1px solid #ccc; border-radius: 5px; }")
        main_layout.addWidget(dev_frame)

        main_layout.addSpacing(10)

        # Version section
        version_label = QLabel("Version: 1.0.0.0 (Initial Build)")
        version_font = QFont("Arial", 9)
        version_label.setFont(version_font)
        version_label.setAlignment(Qt.AlignCenter)
        if self.is_dark_theme():
            version_label.setStyleSheet("color: #bbb;")
        else:
            version_label.setStyleSheet("color: #666;")
        main_layout.addWidget(version_label)

        # Copyright
        copyright_label = QLabel("Open-Source Project on GitHub")
        copyright_font = QFont("Arial", 9)
        copyright_label.setFont(copyright_font)
        copyright_label.setAlignment(Qt.AlignCenter)
        if self.is_dark_theme():
            copyright_label.setStyleSheet("color: #bbb;")
        else:
            copyright_label.setStyleSheet("color: #666;")
        main_layout.addWidget(copyright_label)

        main_layout.addSpacing(5)

        # Link
        link_label = QLabel('<a href="https://digitzaki.github.io/">https://digitzaki.github.io/</a>')
        link_label.setOpenExternalLinks(True)
        link_label.setAlignment(Qt.AlignCenter)
        link_font = QFont("Arial", 9)
        link_label.setFont(link_font)
        if self.is_dark_theme():
            link_label.setStyleSheet("color: #4a9eff;")
        else:
            link_label.setStyleSheet("color: #0066cc;")
        main_layout.addWidget(link_label)

        main_layout.addStretch()

        # Close button
        button_layout = QHBoxLayout()
        button_layout.addStretch()
        close_button = QPushButton("Close")
        close_button.setMinimumWidth(80)
        close_button.clicked.connect(dialog.accept)
        button_layout.addWidget(close_button)
        button_layout.addStretch()
        main_layout.addLayout(button_layout)

        dialog.setLayout(main_layout)
        dialog.exec()

    def is_dark_theme(self):
        """Check if current theme is dark"""
        theme_colors = get_theme_colors(self.current_theme)
        # For gradient themes, use menubar_bg instead of background
        bg_color = theme_colors.get('background') or theme_colors.get('menubar_bg', '#1e1e1e')
        # Convert hex to int for comparison
        bg_hex = bg_color.lstrip('#')
        bg_rgb = int(bg_hex[:2], 16), int(bg_hex[2:4], 16), int(bg_hex[4:6], 16)
        brightness = (bg_rgb[0] + bg_rgb[1] + bg_rgb[2]) / 3
        return brightness < 128

    def load_theme_preference(self):
        """Load saved theme preference from settings file"""
        settings_file = os.path.join(os.path.expanduser("~"), ".hex_editor_settings.json")
        try:
            if os.path.exists(settings_file):
                with open(settings_file, 'r') as f:
                    settings = json.load(f)
                    theme = settings.get('theme', 'Dark')
                    # Validate theme exists (check both built-in and custom themes)
                    all_themes = get_all_themes()
                    if theme in all_themes:
                        return theme
        except Exception as e:
            print(f"Error loading theme preference: {e}")
        return "Dark"

    def load_settings(self):
        """Load all saved settings from settings file"""
        settings_file = os.path.join(os.path.expanduser("~"), ".hex_editor_settings.json")
        try:
            if os.path.exists(settings_file):
                with open(settings_file, 'r') as f:
                    settings = json.load(f)

                    # Load theme
                    theme = settings.get('theme', 'Dark')
                    all_themes = get_all_themes()
                    if theme in all_themes:
                        self.current_theme = theme

                    # Load segment size
                    segment_size = settings.get('segment_size', 0)
                    if segment_size in [0, 1, 2, 4, 8]:
                        self.segment_size = segment_size

                    # Load boundary settings
                    self.boundary_enabled = settings.get('boundary_enabled', False)
                    self.boundary_start_col = settings.get('boundary_start_col', 0)
                    self.boundary_end_col = settings.get('boundary_end_col', 15)
        except Exception as e:
            print(f"Error loading settings: {e}")

    def save_theme_preference(self):
        """Save current theme preference to settings file"""
        settings_file = os.path.join(os.path.expanduser("~"), ".hex_editor_settings.json")
        try:
            settings = {}
            # Load existing settings if file exists
            if os.path.exists(settings_file):
                with open(settings_file, 'r') as f:
                    settings = json.load(f)

            # Update theme
            settings['theme'] = self.current_theme

            # Save settings
            with open(settings_file, 'w') as f:
                json.dump(settings, f, indent=2)
        except Exception as e:
            print(f"Error saving theme preference: {e}")

    def save_settings(self):
        """Save all settings to settings file"""
        settings_file = os.path.join(os.path.expanduser("~"), ".hex_editor_settings.json")
        try:
            settings = {}
            # Load existing settings if file exists
            if os.path.exists(settings_file):
                with open(settings_file, 'r') as f:
                    settings = json.load(f)

            # Update settings
            settings['theme'] = self.current_theme
            settings['segment_size'] = self.segment_size
            settings['boundary_enabled'] = self.boundary_enabled
            settings['boundary_start_col'] = self.boundary_start_col
            settings['boundary_end_col'] = self.boundary_end_col

            # Save settings
            with open(settings_file, 'w') as f:
                json.dump(settings, f, indent=2)
        except Exception as e:
            print(f"Error saving settings: {e}")

    def apply_theme(self):
        style = get_theme_stylesheet(self.current_theme)
        self.setStyleSheet(style)

        # Get theme colors for custom widgets
        theme_colors = get_theme_colors(self.current_theme)

        # Apply gradient or image backgrounds to the entire editor (central widget)
        if hasattr(self, 'central_widget'):
            if theme_colors.get('gradient', False):
                gradient_colors = theme_colors.get('gradient_colors', [])
                self.central_widget.set_gradient_colors(gradient_colors)
                # Also apply gradient to hex display for editor background
                if hasattr(self, 'hex_display'):
                    self.hex_display.set_gradient_colors(gradient_colors)
            else:
                self.central_widget.set_gradient_colors(None)
                # Clear hex display gradient
                if hasattr(self, 'hex_display'):
                    self.hex_display.set_gradient_colors(None)

        # Get grid line color (with fallback to border for backward compatibility)
        grid_line_color = theme_colors.get('grid_line', theme_colors['border'])

        # Check if we have a gradient theme
        has_gradient = theme_colors.get('gradient', False)

        # For gradient themes, don't set background colors - let the gradient show through
        semi_transparent_bg = ""
        if not has_gradient:
            # Only set backgrounds for non-gradient themes
            editor_bg = theme_colors.get('editor_bg', '#1a1a1a')
            if editor_bg != 'transparent':
                semi_transparent_bg = editor_bg

        # Update segment overlay theme
        if hasattr(self, 'segment_overlay'):
            self.segment_overlay.set_line_color(grid_line_color)
        if hasattr(self, 'header_segment_overlay'):
            self.header_segment_overlay.set_line_color(grid_line_color)

        # Update hex editor borders and backgrounds with themed colors
        if hasattr(self, 'hex_header_widget'):
            bg_style = f"background-color: {semi_transparent_bg}; " if semi_transparent_bg else ""
            self.hex_header_widget.setStyleSheet(f"{bg_style}border-top: 2px solid {grid_line_color}; border-bottom: 1px solid {grid_line_color}; padding-top: 4px;")
        if hasattr(self, 'offset_header'):
            bg_style = f"background-color: {semi_transparent_bg}; " if semi_transparent_bg else ""
            self.offset_header.setStyleSheet(f"{bg_style}border-right: 2px solid {grid_line_color}; border-bottom: 1px solid {grid_line_color}; cursor: pointer; padding: 4px 2px; margin: 0px;")
        if hasattr(self, 'hex_header'):
            bg_style = f"background-color: {semi_transparent_bg}; " if semi_transparent_bg else ""
            self.hex_header.setStyleSheet(f"{bg_style}border-right: 1px solid {grid_line_color}; border-bottom: 1px solid {grid_line_color}; padding: 4px 0px 4px 4px; margin: 0px;")
        if hasattr(self, 'ascii_header'):
            bg_style = f"background-color: {semi_transparent_bg}; " if semi_transparent_bg else ""
            self.ascii_header.setStyleSheet(f"{bg_style}border-left: 2px solid {grid_line_color}; border-right: 1px solid {grid_line_color}; border-bottom: 1px solid {grid_line_color}; padding: 4px 0px 4px 4px; margin: 0px;")
        if hasattr(self, 'offset_display'):
            bg_style = f"background-color: {semi_transparent_bg}; " if semi_transparent_bg else ""
            self.offset_display.setStyleSheet(f"{bg_style}border-right: 2px solid {grid_line_color}; padding: 2px;")
        if hasattr(self, 'hex_display'):
            bg_style = f"background-color: {semi_transparent_bg}; " if semi_transparent_bg else ""
            self.hex_display.setStyleSheet(f"{bg_style}border-right: 1px solid {grid_line_color}; padding: 2px 0px 2px 4px;")
        if hasattr(self, 'ascii_display'):
            bg_style = f"background-color: {semi_transparent_bg}; " if semi_transparent_bg else ""
            self.ascii_display.setStyleSheet(f"{bg_style}border-left: 2px solid {grid_line_color}; border-right: 1px solid {grid_line_color}; padding: 2px 4px;")

        # Update custom scrollbar theme
        if hasattr(self, 'hex_nav_scrollbar'):
            self.hex_nav_scrollbar.set_theme_colors(theme_colors)

        # Update inspector resize handle theme
        if hasattr(self, 'inspector_resize_handle'):
            self.inspector_resize_handle.setStyleSheet(f"background-color: {theme_colors['border']};")

        # Update inspector widget background to use inspector_bg (so images don't go over it)
        if hasattr(self, 'inspector_widget'):
            # Use inspector_bg if available, otherwise fall back to background
            inspector_bg = theme_colors.get('inspector_bg', theme_colors.get('background', '#1a1a1a'))
            self.inspector_widget.setStyleSheet(f"QWidget#inspector_widget {{ background-color: {inspector_bg}; }}")

        # Update endian button theme
        if hasattr(self, 'endian_btn'):
            # For Matrix theme, use dark text on bright buttons for better readability
            button_text_color = "#000000" if self.current_theme == "Matrix" else theme_colors['foreground']
            self.endian_btn.setStyleSheet(f"""
                QPushButton {{
                    background-color: {theme_colors['button_bg']};
                    color: {button_text_color};
                    border: none;
                    border-radius: 4px;
                    padding: 8px;
                    font-weight: bold;
                }}
                QPushButton:hover {{
                    background-color: {theme_colors['button_hover']};
                    color: {button_text_color};
                }}
            """)

        # Update notes window theme if it exists
        if self.notes_window is not None:
            self.notes_window.apply_theme(self.is_dark_theme())

        # Update tab scroll buttons theme
        if hasattr(self, 'right_panel_tabs'):
            self.update_tab_scroll_buttons_style()

        # Refresh display to update byte selection and data inspector colors
        if self.current_tab_index >= 0:
            self.display_hex(preserve_scroll=True)

        # Update pointer overlay colors
        self.update_signature_overlays()

    def update_tab_scroll_buttons_style(self):
        """Update tab scroll button styling to match current theme"""
        theme_colors = get_theme_colors(self.current_theme)

        # Use editor background or menubar background for buttons - ensure opaque
        bg_color = theme_colors.get('editor_bg', '#252526')
        if bg_color == 'transparent':
            bg_color = theme_colors.get('menubar_bg', '#2d2d30')

        # Use solid background color to prevent tabs from showing through
        scroller_bg = theme_colors.get('background', '#1e1e1e')

        # Ensure hover and pressed colors are fully opaque
        hover_color = theme_colors.get('button_hover', '#3e3e42')
        # Use button_bg for pressed state to ensure it's fully opaque
        pressed_color = theme_colors.get('button_bg', '#0e639c')
        foreground_color = theme_colors.get('foreground', '#d4d4d4')

        # Style with triangular arrow symbols ◀ ▶
        self.right_panel_tabs.setStyleSheet(f"""
            QTabBar::scroller {{
                width: 60px;
                background-color: {scroller_bg};
                border: none;
            }}
            QTabBar QToolButton {{
                background-color: {bg_color};
                border: 1px solid {theme_colors.get('border', '#3e3e42')};
                border-radius: 2px;
                margin: 1px;
                padding: 2px;
                min-width: 26px;
                max-width: 26px;
                min-height: 24px;
                color: {foreground_color};
                font-size: 14px;
                font-weight: normal;
                font-family: Arial, sans-serif;
            }}
            QTabBar QToolButton:hover {{
                background-color: {hover_color};
            }}
            QTabBar QToolButton:pressed {{
                background-color: {pressed_color};
                border: 1px solid {pressed_color};
            }}
            QTabBar QToolButton::left-arrow {{
                image: none;
            }}
            QTabBar QToolButton::right-arrow {{
                image: none;
            }}
        """)

        # Set arrow button text using a delayed call to ensure buttons exist
        from PyQt5.QtCore import QTimer
        QTimer.singleShot(10, self._update_arrow_button_text)

    def _update_arrow_button_text(self):
        """Update the arrow button text to show < and > symbols"""
        if not hasattr(self, 'right_panel_tabs'):
            return

        try:
            # Find all QToolButton children in the tab bar
            tab_bar = self.right_panel_tabs.tabBar()
            if tab_bar:
                for button in tab_bar.findChildren(QToolButton):
                    # Check arrow type and set text with Unicode triangular arrows
                    if button.arrowType() == Qt.LeftArrow:
                        button.setText("◀")  # U+25C0 Black Left-Pointing Triangle
                        button.setToolButtonStyle(Qt.ToolButtonTextOnly)
                    elif button.arrowType() == Qt.RightArrow:
                        button.setText("▶")  # U+25B6 Black Right-Pointing Triangle
                        button.setToolButtonStyle(Qt.ToolButtonTextOnly)
        except Exception:
            pass

    def update_edit_box_overlay(self):
        """Update the edit box overlay visualization"""
        if not hasattr(self, 'edit_box_overlay'):
            return

        if not self.edit_box_active or self.edit_box_start is None:
            self.edit_box_overlay.clear_edit_box()
            return

        # Calculate the visual rectangle for the edit box
        try:
            font_metrics = QFontMetrics(self.hex_display.font())
            char_width = font_metrics.horizontalAdvance('0')
            line_height = font_metrics.height()

            # Calculate starting position
            start_row = self.edit_box_start // self.bytes_per_row
            start_col = self.edit_box_start % self.bytes_per_row
            end_row = self.edit_box_end // self.bytes_per_row
            end_col = self.edit_box_end % self.bytes_per_row

            # Calculate relative row positions (accounting for rendered start)
            rendered_start_row = self.rendered_start_byte // self.bytes_per_row
            rendered_end_byte = self.rendered_start_byte + (self.visible_rows * self.bytes_per_row)
            rendered_end_row = rendered_end_byte // self.bytes_per_row

            # Check if edit box is visible in current viewport
            if end_row < rendered_start_row or start_row > rendered_end_row:
                # Edit box is not visible, hide it
                self.edit_box_overlay.clear_edit_box()
                return

            visual_start_row = start_row - rendered_start_row
            visual_end_row = end_row - rendered_start_row

            # Clamp to visible area
            if visual_start_row < 0:
                visual_start_row = 0
            if visual_end_row >= self.visible_rows:
                visual_end_row = self.visible_rows - 1

            # Hex display has 2 leading spaces (see display_hex line 5447)
            # Each hex byte is 2 characters + 1 space (3 chars total)
            leading_spaces = 2
            x_start = (leading_spaces + start_col * 3) * char_width
            # End should be 2 chars for the byte (not including trailing space)
            x_end = (leading_spaces + end_col * 3 + 2.75) * char_width
            y_start = visual_start_row * line_height
            # Add slight padding to ensure full coverage without bleeding
            y_end = (visual_end_row + 1) * line_height + 2.25

            rect = QRect(int(x_start), int(y_start), int(x_end - x_start), int(y_end - y_start))
            self.edit_box_overlay.set_edit_box(rect)
        except Exception as e:
            print(f"Error updating edit box overlay: {e}")

    def keyPressEvent(self, event):
        print(f"keyPressEvent: cursor_pos={self.cursor_position}, tab={self.current_tab_index}, key={event.key()}, text={event.text()}")

        if self.cursor_position is None or self.current_tab_index < 0:
            super().keyPressEvent(event)
            return

        current_file = self.open_files[self.current_tab_index]
        key = event.key()
        modifiers = event.modifiers()
        text = event.text().upper()

        # Ignore modifier-only keys (Ctrl, Shift, Alt, Meta) and Enter/Return
        # These should not trigger hex input
        if key in (Qt.Key_Control, Qt.Key_Shift, Qt.Key_Alt, Qt.Key_Meta,
                   Qt.Key_Return, Qt.Key_Enter, Qt.Key_CapsLock, Qt.Key_Tab,
                   Qt.Key_Escape, Qt.Key_Backspace, Qt.Key_Delete):
            # Let these be handled by their specific handlers below
            pass        # Handle hex digit input (0-9, A-F) only if it's a valid single character
        # and no modifiers are pressed (except Shift for letters)
        elif text in '0123456789ABCDEF' and len(text) == 1:
            # Typing detection: Check if we're typing (not paste) and have a highlight
            is_manual_typing = not (modifiers & Qt.ControlModifier)  # Not Ctrl+V or other paste

            # If manual typing and we have a highlight but no edit box yet
            # Only process if it's a REAL selection (start != end), not just a single click
            if is_manual_typing and self.selection_start is not None and self.selection_end is not None:
                if not self.edit_box_active and self.selection_start != self.selection_end:
                    sel_start = min(self.selection_start, self.selection_end)
                    sel_end = max(self.selection_start, self.selection_end)

                    # ONLY activate edit box for column selections (Ctrl+Click+Drag)
                    # For regular drag selections, just move cursor to start
                    if self.column_selection_mode:
                        # Column selection - activate edit box
                        self.edit_box_active = True
                        self.edit_box_start = sel_start
                        self.edit_box_end = sel_end

                        # Calculate row and column boundaries
                        self.edit_box_start_row = sel_start // self.bytes_per_row
                        self.edit_box_start_col = sel_start % self.bytes_per_row
                        self.edit_box_end_row = sel_end // self.bytes_per_row
                        self.edit_box_end_col = sel_end % self.bytes_per_row

                        # Move cursor to start of highlight
                        self.cursor_position = sel_start
                        self.cursor_nibble = 0

                        # Update edit box visual
                        self.update_edit_box_overlay()

                        print(f"Edit box activated for column selection: {sel_start} to {sel_end}")
                    else:
                        # Regular drag selection - move cursor to start, no edit box
                        # Clear selection so cursor can advance normally
                        self.cursor_position = sel_start
                        self.cursor_nibble = 0
                        self.selection_start = None
                        self.selection_end = None
                        print(f"Regular drag selection: moved cursor to start {sel_start}, clearing highlight")
                elif self.selection_start == self.selection_end:
                    # Single click selection - clear it so it doesn't show highlight
                    self.selection_start = None
                    self.selection_end = None
                    print(f"Single click: clearing highlight")

            # Check if we're within edit box boundaries (if edit box is active)
            if self.edit_box_active:
                if self.cursor_position < self.edit_box_start or self.cursor_position > self.edit_box_end:
                    print(f"Cursor {self.cursor_position} outside edit box [{self.edit_box_start}, {self.edit_box_end}], ignoring input")
                    return

            # Check boundary constraints (if enabled)
            if self.boundary_enabled:
                current_col = self.cursor_position % self.bytes_per_row
                if current_col < self.boundary_start_col or current_col > self.boundary_end_col:
                    print(f"Cursor at col {current_col} outside boundaries [{self.boundary_start_col}, {self.boundary_end_col}], ignoring input")
                    return

            print(f"Editing byte at {self.cursor_position}: nibble={self.cursor_nibble}")
            if self.cursor_position < len(current_file.file_data):
                # Save for undo on first nibble of each byte
                if self.cursor_nibble == 0:
                    self.save_undo_state()

                current_byte = current_file.file_data[self.cursor_position]
                hex_str = f"{current_byte:02X}"

                # Modify the appropriate nibble
                if self.cursor_nibble == 0:
                    new_hex = text + hex_str[1]
                else:
                    new_hex = hex_str[0] + text

                new_byte = int(new_hex, 16)
                current_file.file_data[self.cursor_position] = new_byte

                # Mark as modified only if the byte differs from the original
                if self.cursor_position not in current_file.inserted_bytes:
                    if self.cursor_position < len(current_file.original_data):
                        if new_byte != current_file.original_data[self.cursor_position]:
                            current_file.modified_bytes.add(self.cursor_position)
                        else:
                            # Byte matches original, remove from modified set if present
                            current_file.modified_bytes.discard(self.cursor_position)

                # Check if any bytes are actually modified
                current_file.modified = len(current_file.modified_bytes) > 0 or len(current_file.inserted_bytes) > 0

                # Update tab title
                tab_text = os.path.basename(current_file.file_path)
                if current_file.modified:
                    tab_text += " *"
                self.tab_widget.setTabText(self.current_tab_index, tab_text)

                # Schedule snapshot after edit
                self.schedule_snapshot()

                # Move cursor with wrapping logic for edit box
                if self.cursor_nibble == 0:
                    self.cursor_nibble = 1
                else:
                    self.cursor_nibble = 0

                    # Check if we just finished editing the last byte of the edit box
                    if self.edit_box_active and self.cursor_position == self.edit_box_end:
                        # Deactivate edit box after completing the last byte
                        self.edit_box_active = False
                        if hasattr(self, 'edit_box_overlay'):
                            self.edit_box_overlay.clear_edit_box()
                        print(f"Edit box deactivated after completing last byte at {self.cursor_position}")
                        # Clear selection
                        self.selection_start = None
                        self.selection_end = None
                    elif self.cursor_position < len(current_file.file_data) - 1:
                        next_pos = self.cursor_position + 1

                        # Handle wrapping within edit box
                        if self.edit_box_active:
                            # Check if we're at the end of a row within the edit box
                            current_row = self.cursor_position // self.bytes_per_row
                            current_col = self.cursor_position % self.bytes_per_row

                            # If at the end column of the edit box, wrap to start column of next row
                            if current_col == self.edit_box_end_col and current_row < self.edit_box_end_row:
                                next_pos = (current_row + 1) * self.bytes_per_row + self.edit_box_start_col
                            # If we would go past the edit box end, wrap back to start
                            elif next_pos > self.edit_box_end:
                                next_pos = self.edit_box_start
                                print(f"Edit box: wrapped from end {self.edit_box_end} to start {self.edit_box_start}")

                        # Handle wrapping within boundaries
                        elif self.boundary_enabled:
                            current_col = self.cursor_position % self.bytes_per_row
                            current_row = self.cursor_position // self.bytes_per_row

                            # Check if we're at the end column of the boundary
                            if current_col == self.boundary_end_col:
                                # Wrap to start column of next row
                                next_pos = (current_row + 1) * self.bytes_per_row + self.boundary_start_col
                                print(f"Boundary wrap: at end col {self.boundary_end_col}, wrapping to next row pos {next_pos}")

                        self.cursor_position = next_pos

                self.display_hex(preserve_scroll=True)
                self.scroll_to_offset(self.cursor_position)
                self.update_status()

        # Handle arrow keys
        elif key == Qt.Key_Left:
            old_pos = self.cursor_position
            if self.cursor_nibble == 1:
                self.cursor_nibble = 0
            elif self.cursor_position > 0:
                new_pos = self.cursor_position - 1
                # Check edit box boundaries
                if self.edit_box_active and new_pos < self.edit_box_start:
                    print(f"Left arrow blocked by edit box boundary")
                    new_pos = self.cursor_position
                # Check boundary constraints (wrap to end of previous row if needed)
                elif self.boundary_enabled:
                    new_col = new_pos % self.bytes_per_row
                    if new_col < self.boundary_start_col:
                        # Wrap to end column of previous row
                        new_row = (new_pos // self.bytes_per_row) - 1
                        if new_row >= 0:
                            new_pos = new_row * self.bytes_per_row + self.boundary_end_col
                        else:
                            new_pos = self.cursor_position  # Stay at current position
                self.cursor_position = new_pos
                self.cursor_nibble = 1
            print(f"Left arrow: {old_pos} -> {self.cursor_position}, nibble={self.cursor_nibble}")
            self.display_hex(preserve_scroll=True)
            self.scroll_to_offset(self.cursor_position)
            self.update_status()

        elif key == Qt.Key_Right:
            old_pos = self.cursor_position
            if self.cursor_nibble == 0:
                self.cursor_nibble = 1
            elif self.cursor_position < len(current_file.file_data) - 1:
                new_pos = self.cursor_position + 1
                # Check edit box boundaries
                if self.edit_box_active and new_pos > self.edit_box_end:
                    print(f"Right arrow blocked by edit box boundary")
                    new_pos = self.cursor_position
                # Check boundary constraints (wrap to start of next row if needed)
                elif self.boundary_enabled:
                    new_col = new_pos % self.bytes_per_row
                    if new_col > self.boundary_end_col:
                        # Wrap to start column of next row
                        new_row = (new_pos // self.bytes_per_row) + 1
                        if new_row * self.bytes_per_row + self.boundary_start_col < len(current_file.file_data):
                            new_pos = new_row * self.bytes_per_row + self.boundary_start_col
                        else:
                            new_pos = self.cursor_position  # Stay at current position
                self.cursor_position = new_pos
                self.cursor_nibble = 0
            print(f"Right arrow: {old_pos} -> {self.cursor_position}, nibble={self.cursor_nibble}")
            self.display_hex(preserve_scroll=True)
            self.scroll_to_offset(self.cursor_position)
            self.update_status()

        elif key == Qt.Key_Up:
            old_pos = self.cursor_position
            if self.cursor_position >= self.bytes_per_row:
                new_pos = self.cursor_position - self.bytes_per_row
                # Check edit box boundaries
                if self.edit_box_active and new_pos < self.edit_box_start:
                    print(f"Up arrow blocked by edit box boundary")
                    new_pos = self.cursor_position
                # Check boundary constraints (keep within column range)
                elif self.boundary_enabled:
                    new_col = new_pos % self.bytes_per_row
                    if new_col < self.boundary_start_col or new_col > self.boundary_end_col:
                        print(f"Up arrow would move outside column boundaries, staying in place")
                        new_pos = self.cursor_position
                self.cursor_position = new_pos
            print(f"Up arrow: {old_pos} -> {self.cursor_position}")
            self.display_hex(preserve_scroll=True)
            self.scroll_to_offset(self.cursor_position)
            self.update_status()

        elif key == Qt.Key_Down:
            old_pos = self.cursor_position
            if self.cursor_position + self.bytes_per_row < len(current_file.file_data):
                new_pos = self.cursor_position + self.bytes_per_row
                # Check edit box boundaries
                if self.edit_box_active and new_pos > self.edit_box_end:
                    print(f"Down arrow blocked by edit box boundary")
                    new_pos = self.cursor_position
                # Check boundary constraints (keep within column range)
                elif self.boundary_enabled:
                    new_col = new_pos % self.bytes_per_row
                    if new_col < self.boundary_start_col or new_col > self.boundary_end_col:
                        print(f"Down arrow would move outside column boundaries, staying in place")
                        new_pos = self.cursor_position
                self.cursor_position = new_pos
            print(f"Down arrow: {old_pos} -> {self.cursor_position}")
            self.display_hex(preserve_scroll=True)
            self.scroll_to_offset(self.cursor_position)
            self.update_status()

        # Enter/Return keys are ignored (no action)
        elif key in (Qt.Key_Return, Qt.Key_Enter):
            pass  # Do nothing

        else:
            super().keyPressEvent(event)

    def dragEnterEvent(self, event):
        if event.mimeData().hasUrls():
            event.acceptProposedAction()

    def dropEvent(self, event):
        files = [url.toLocalFile() for url in event.mimeData().urls()]
        for file_path in files:
            if os.path.isfile(file_path):
                try:
                    # Check file size first
                    file_size = os.path.getsize(file_path)
                    max_size = 100 * 1024 * 1024  # 100 MB limit

                    if file_size > max_size:
                        reply = QMessageBox.question(
                            self,
                            "Large File Warning",
                            f"This file is {file_size / (1024 * 1024):.1f} MB. "
                            f"Loading files larger than {max_size / (1024 * 1024):.0f} MB may cause performance issues.\n\n"
                            "Do you want to continue?",
                            QMessageBox.Yes | QMessageBox.No,
                            QMessageBox.No
                        )
                        if reply == QMessageBox.No:
                            continue

                    with open(file_path, 'rb') as f:
                        file_data = f.read()

                    file_tab = FileTab(file_path, file_data)
                    self.open_files.append(file_tab)

                    tab_name = os.path.basename(file_path)
                    tab_widget = QWidget()
                    self.tab_widget.addTab(tab_widget, tab_name)
                    self.tab_widget.setCurrentIndex(len(self.open_files) - 1)

                    self.display_hex()

                except Exception as e:
                    QMessageBox.critical(self, "Error", f"Failed to open file {file_path}: {str(e)}")

    def schedule_snapshot(self):
        """Schedule a snapshot creation after user stops editing (debounce)"""
        if self.current_tab_index < 0:
            return
        self.snapshot_timer.stop()
        is_started = self.snapshot_timer.start(3000)  # 3 seconds after last edit
        self.status_label.setText(f"Edit detected - snapshot scheduled (timer active: {self.snapshot_timer.isActive()})")


    def create_snapshot(self):
        """Create a snapshot of the current file state"""
        if self.current_tab_index < 0:
            return

        current_file = self.open_files[self.current_tab_index]
        current_data = bytes(current_file.file_data)

        # Only create snapshot if data has changed
        if current_file.last_snapshot_data == current_data:
            return

        # Calculate bytes changed from last snapshot
        bytes_changed = 0
        if current_file.last_snapshot_data is not None:
            bytes_changed = sum(1 for a, b in zip(current_file.last_snapshot_data, current_data) if a != b)
            bytes_changed += abs(len(current_data) - len(current_file.last_snapshot_data))
        else:
            bytes_changed = len(current_data)

        snapshot = {
            'timestamp': QDateTime.currentDateTime(),
            'data': bytearray(current_data),
            'modified_bytes': set(current_file.modified_bytes),
            'inserted_bytes': set(current_file.inserted_bytes),
            'replaced_bytes': set(current_file.replaced_bytes),
            'bytes_changed': bytes_changed
        }

        current_file.snapshots.append(snapshot)
        current_file.last_snapshot_data = current_data

        # Limit to 50 snapshots per file
        if len(current_file.snapshots) > 50:
            current_file.snapshots.pop(0)

    def show_version_control(self):
        """Show the version control window with snapshots"""
        if self.current_tab_index < 0:
            QMessageBox.information(self, "Version Control", "No file is currently open.")
            return

        current_file = self.open_files[self.current_tab_index]

        dialog = QDialog(self)
        dialog.setWindowTitle("Version Control")
        dialog.setMinimumSize(500, 400)

        # Apply current theme to dialog
        dialog.setStyleSheet(get_theme_stylesheet(self.current_theme))

        layout = QVBoxLayout()

        # Info label
        info_label = QLabel("File snapshots are automatically saved as you edit:")
        layout.addWidget(info_label)

        # List widget for snapshots
        snapshot_list = QListWidget()
        snapshot_list.setSelectionMode(QListWidget.SingleSelection)

        if not current_file.snapshots:
            item = QListWidgetItem("No snapshots available yet")
            item.setFlags(Qt.NoItemFlags)
            snapshot_list.addItem(item)
        else:
            # Add snapshots in reverse order (newest first)
            for i, snapshot in enumerate(reversed(current_file.snapshots)):
                timestamp = snapshot['timestamp'].toString("yyyy-MM-dd hh:mm:ss")
                bytes_changed = snapshot['bytes_changed']
                text = f"{timestamp}: {bytes_changed} Bytes Changed"
                item = QListWidgetItem(text)
                item.setData(Qt.UserRole, len(current_file.snapshots) - 1 - i)  # Store actual index
                snapshot_list.addItem(item)

        layout.addWidget(snapshot_list)

        # Buttons
        button_layout = QHBoxLayout()

        load_button = QPushButton("Load Snapshot")
        load_button.setEnabled(len(current_file.snapshots) > 0)

        def load_snapshot():
            current_item = snapshot_list.currentItem()
            if not current_item:
                return

            snapshot_index = current_item.data(Qt.UserRole)
            if snapshot_index is None:
                return

            # Confirm with user
            reply = QMessageBox.question(
                dialog,
                "Confirm Load",
                "Loading this snapshot will replace the current file state. Continue?",
                QMessageBox.Yes | QMessageBox.No,
                QMessageBox.No
            )

            if reply == QMessageBox.Yes:
                snapshot = current_file.snapshots[snapshot_index]

                # Save current state to undo stack before loading snapshot
                self.save_undo_state()

                # Restore snapshot data
                current_file.file_data = bytearray(snapshot['data'])
                current_file.modified_bytes = set(snapshot['modified_bytes'])
                current_file.inserted_bytes = set(snapshot['inserted_bytes'])
                current_file.replaced_bytes = set(snapshot['replaced_bytes'])
                current_file.modified = len(snapshot['modified_bytes']) > 0 or len(snapshot['inserted_bytes']) > 0 or len(current_file.replaced_bytes) > 0

                # Update last_snapshot_data to the loaded snapshot so future edits are tracked correctly
                current_file.last_snapshot_data = bytes(snapshot['data'])

                self.display_hex()
                dialog.accept()
                QMessageBox.information(self, "Snapshot Loaded", "The snapshot has been loaded successfully.")

        load_button.clicked.connect(load_snapshot)
        snapshot_list.itemDoubleClicked.connect(load_snapshot)

        close_button = QPushButton("Close")
        close_button.clicked.connect(dialog.reject)

        button_layout.addWidget(load_button)
        button_layout.addStretch()
        button_layout.addWidget(close_button)

        layout.addLayout(button_layout)
        dialog.setLayout(layout)

        # Apply theme
        if self.is_dark_theme():
            dialog.setStyleSheet("""
                QDialog, QWidget {
                    background-color: #1e1e1e;
                    color: #d4d4d4;
                }
                QListWidget {
                    background-color: #252526;
                    color: #d4d4d4;
                    border: 1px solid #3e3e42;
                }
                QPushButton {
                    background-color: #0e639c;
                    color: white;
                    border: none;
                    padding: 5px 15px;
                    border-radius: 2px;
                }
                QPushButton:hover {
                    background-color: #1177bb;
                }
                QPushButton:disabled {
                    background-color: #3e3e42;
                    color: #666;
                }
            """)

        dialog.show()

    def moveEvent(self, event):
        """Handle window move events to detect screen changes"""
        super().moveEvent(event)

        # Get the screen the window is currently on
        current_screen = self.screen()

        # Store the screen for comparison
        if not hasattr(self, '_last_screen'):
            self._last_screen = current_screen
        elif self._last_screen != current_screen:
            # Screen changed, refresh display and update window size
            self._last_screen = current_screen
            self.on_screen_changed(current_screen)
            self.update_window_size_for_screen()
            if self.current_tab_index >= 0:
                self.display_hex()

    def closeEvent(self, event):
        """Close all auxiliary windows when main window closes"""
        # Check for unsaved files
        unsaved_files = [f for f in self.open_files if f.modified]

        if unsaved_files:
            file_names = [os.path.basename(f.file_path) for f in unsaved_files]
            file_list = "\n".join(file_names)

            # Play beep for unsaved changes warning
            QApplication.beep()
            reply = QMessageBox.question(
                self,
                "Unsaved Changes",
                f"You have {len(unsaved_files)} unsaved file(s):\n\n{file_list}\n\nAre you sure you want to exit?",
                QMessageBox.Yes | QMessageBox.No,
                QMessageBox.No
            )

            if reply == QMessageBox.No:
                event.ignore()
                return

        # Save all settings
        self.save_settings()

        # Close all auxiliary windows except notebook
        for window in self.auxiliary_windows:
            if window and window.isVisible():
                window.close()

        # Close debug window if open
        if self.debug_window:
            self.debug_window.close()

        # Restore stdout/stderr
        if self.debug_redirector:
            sys.stdout = self.original_stdout
            sys.stderr = self.original_stderr

        # Close notebook window separately so it can be excluded if needed
        # The notebook window is not in auxiliary_windows list, so it stays open
        event.accept()


def main():
    # Enable DPI scaling for proper handling across different monitors
    QApplication.setAttribute(Qt.AA_DisableHighDpiScaling, True)
    QApplication.setAttribute(Qt.AA_UseHighDpiPixmaps, True)

    app = QApplication(sys.argv)
    app.setStyle('Fusion')

    window = HexEditorQt()
    window.show()

    sys.exit(app.exec_())


if __name__ == "__main__":
    main()
