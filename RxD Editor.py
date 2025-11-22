import sys
import os
import re
import struct
import json
from PyQt5.QtWidgets import *
from PyQt5.QtGui import *
from PyQt5.QtCore import *
from editor_themes import THEMES, get_theme_stylesheet, get_theme_colors


class FileTab:
    def __init__(self, file_path, file_data):
        self.file_path = file_path
        self.file_data = bytearray(file_data)
        self.original_data = bytearray(file_data)
        self.modified = False
        self.inserted_bytes = set()
        self.modified_bytes = set()
        self.replaced_bytes = set()  # Bytes modified by replace operation (blue)
        self.byte_highlights = {}  # Per-file highlights: {offset: {color, message, underline, pattern (optional)}}
        self.pattern_highlights = []  # Pattern-based highlights that auto-search: [{pattern, color, message, underline}]
        self.snapshots = []  # Version control snapshots for this file
        self.last_snapshot_data = None  # Last snapshot data to detect changes


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
        self.bold_check.setFont(QFont("Arial", 10, QFont.Bold))
        self.bold_check.stateChanged.connect(self.apply_text_style)
        toolbar_layout.addWidget(self.bold_check)

        self.italic_check = QCheckBox("I")
        font = QFont("Arial", 10)
        font.setItalic(True)
        self.italic_check.setFont(font)
        self.italic_check.stateChanged.connect(self.apply_text_style)
        toolbar_layout.addWidget(self.italic_check)

        self.underline_check = QCheckBox("U")
        font = QFont("Arial", 10)
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

    def apply_theme(self):
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
            self, "Save Notes", "", "Rich Text Format (*.rtf);;Text Files (*.txt);;All Files (*)"
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
                    # Save as plain text
                    with open(file_path, 'w') as f:
                        f.write(self.text_edit.toPlainText())
                    QMessageBox.information(self, "Success", "Notes saved successfully!")
            except Exception as e:
                QMessageBox.critical(self, "Error", f"Failed to save notes: {str(e)}")

    def open_notes(self):
        file_path, _ = QFileDialog.getOpenFileName(
            self, "Open Notes", "", "Rich Text Format (*.rtf);;Text Files (*.txt);;All Files (*)"
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


class HexTextEdit(QTextEdit):
    clicked = pyqtSignal(QMouseEvent)
    rightClicked = pyqtSignal(QMouseEvent)
    hovered = pyqtSignal(QMouseEvent)

    def __init__(self, parent=None):
        super().__init__(parent)
        self.setReadOnly(True)
        self.setFont(QFont("Courier", 10))
        self.setMouseTracking(True)
        # Remove default margins and padding for tight alignment
        self.document().setDocumentMargin(0)
        self.setContentsMargins(0, 0, 0, 0)
        self.setStyleSheet("QTextEdit { padding: 0px; margin: 0px; }")

    def mousePressEvent(self, event):
        if event.button() == Qt.LeftButton:
            self.clicked.emit(event)
        elif event.button() == Qt.RightButton:
            self.rightClicked.emit(event)
        super().mousePressEvent(event)

    def mouseMoveEvent(self, event):
        self.hovered.emit(event)
        super().mouseMoveEvent(event)


class HexEditorQt(QMainWindow):
    def __init__(self):
        super().__init__()
        self.open_files = []
        self.current_tab_index = -1
        self.cursor_position = None
        self.cursor_nibble = 0
        self.selection_start = None
        self.selection_end = None
        self.clipboard = None
        self.endian_mode = 'little'
        self.hex_basis = False
        self.undo_stack = []
        self.redo_stack = []

        # Version control snapshot timer (shared across all files)
        self.snapshot_timer = QTimer(self)
        self.snapshot_timer.setSingleShot(True)
        self.snapshot_timer.timeout.connect(self.create_snapshot)
        self.current_theme = self.load_theme_preference()
        self.notes_window = None
        self.bytes_per_row = 16
        self.offset_mode = 'h'  # 'h' for hex, 'd' for decimal, 'o' for octal
        self._last_inspector_pos = None
        self.auxiliary_windows = []  # Track all open auxiliary windows
        self.ignore_file_size_warnings = False  # Flag to suppress file size change warnings

        # Chunked rendering for large files
        self.max_initial_rows = 200  # Only render 200 rows initially
        self.rendered_start_byte = 0  # Track what's currently rendered
        self.rendered_end_byte = 0

        self.setup_ui()
        self.apply_theme()

    def setup_ui(self):
        self.setWindowTitle("RxD Hex Editor")

        # Set default size but allow resizing (10% thinner than before)
        self.resize(1474, 840)
        self.setMinimumSize(1340, 800)  # Minimum usable size

        # Enable drag and drop
        self.setAcceptDrops(True)

        self.create_menus()

        central_widget = QWidget()
        self.setCentralWidget(central_widget)
        main_layout = QVBoxLayout()
        main_layout.setContentsMargins(0, 0, 0, 0)

        # Tab widget for files
        self.tab_widget = QTabWidget()
        self.tab_widget.setTabsClosable(True)
        self.tab_widget.tabCloseRequested.connect(self.close_tab)
        self.tab_widget.currentChanged.connect(self.on_tab_changed)
        main_layout.addWidget(self.tab_widget, stretch=0)

        # Main content splitter
        content_splitter = QSplitter(Qt.Horizontal)
        content_splitter.setChildrenCollapsible(False)

        # Left side: Hex display
        hex_widget = QWidget()
        hex_main_layout = QVBoxLayout()
        hex_main_layout.setContentsMargins(0, 0, 0, 0)
        hex_main_layout.setSpacing(0)

        # Header row - wrap in widget with bottom border
        header_widget = QWidget()
        header_widget.setStyleSheet("border-bottom: 1px solid #555;")
        header_layout = QHBoxLayout()
        header_layout.setContentsMargins(0, 0, 0, 0)
        header_layout.setSpacing(0)

        # Offset header (clickable to cycle modes)
        self.offset_header = QLabel("Offset (h)")
        self.offset_header.setFont(QFont("Courier", 9, QFont.Bold))
        self.offset_header.setMinimumWidth(130)
        self.offset_header.setMaximumWidth(130)
        self.offset_header.setAlignment(Qt.AlignCenter)
        self.offset_header.setStyleSheet("border-right: 1px solid #555; border-bottom: none; cursor: pointer; padding: 4px 2px; margin: 0px;")
        self.offset_header.mousePressEvent = self.cycle_offset_mode
        self.offset_header.setSizePolicy(QSizePolicy.Fixed, QSizePolicy.Preferred)
        self.offset_header.setContentsMargins(0, 0, 0, 0)
        header_layout.addWidget(self.offset_header)

        # Hex column header (00 01 02 ... 0F)
        self.hex_header = QLabel("  00 01 02 03 04 05 06 07 08 09 0A 0B 0C 0D 0E 0F")
        self.hex_header.setFont(QFont("Courier", 10))
        self.hex_header.setMinimumWidth(485)
        self.hex_header.setAlignment(Qt.AlignLeft | Qt.AlignVCenter)
        self.hex_header.setStyleSheet("border-right: 1px solid #555; border-bottom: none; padding: 4px 0px 4px 4px; margin: 0px;")
        self.hex_header.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Preferred)
        self.hex_header.setContentsMargins(0, 0, 0, 0)
        header_layout.addWidget(self.hex_header)

        # ASCII header
        self.ascii_header = QLabel("Decoded Text")
        self.ascii_header.setFont(QFont("Courier", 10))
        self.ascii_header.setMinimumWidth(256)
        self.ascii_header.setAlignment(Qt.AlignLeft)
        self.ascii_header.setStyleSheet("border-right: 1px solid #555; border-bottom: none; padding: 4px 0px 4px 4px; margin: 0px;")
        self.ascii_header.setSizePolicy(QSizePolicy.Fixed, QSizePolicy.Fixed)
        self.ascii_header.setContentsMargins(2, 0, 2, 0)
        header_layout.addWidget(self.ascii_header)

        header_widget.setLayout(header_layout)
        hex_main_layout.addWidget(header_widget)

        # Data display row - wrap in a container widget for overlay positioning
        self.hex_ascii_container = QWidget()
        hex_layout = QHBoxLayout()
        hex_layout.setContentsMargins(0, 0, 0, 0)
        hex_layout.setSpacing(0)

        # Offset column
        self.offset_display = HexTextEdit()
        self.offset_display.setFixedWidth(130)  # Match header width exactly
        self.offset_display.setVerticalScrollBarPolicy(Qt.ScrollBarAlwaysOff)
        self.offset_display.setStyleSheet("border-right: 1px solid #555; padding: 2px;")
        self.offset_display.setAlignment(Qt.AlignCenter)
        self.offset_display.setSizePolicy(QSizePolicy.Fixed, QSizePolicy.Expanding)
        self.offset_display.clicked.connect(self.on_offset_click)
        hex_layout.addWidget(self.offset_display)

        # Hex column
        self.hex_display = HexTextEdit()
        self.hex_display.setVerticalScrollBarPolicy(Qt.ScrollBarAlwaysOff)
        self.hex_display.setLineWrapMode(QTextEdit.NoWrap)
        self.hex_display.setMinimumWidth(485)
        self.hex_display.clicked.connect(self.on_hex_click)
        self.hex_display.rightClicked.connect(self.on_hex_right_click)
        self.hex_display.hovered.connect(self.on_hex_hover)
        self.hex_display.setFocusPolicy(Qt.StrongFocus)
        self.hex_display.setStyleSheet("border-right: 1px solid #555; padding: 2px 0px 2px 4px;")
        self.hex_display.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Expanding)
        self.hex_display.setTextInteractionFlags(Qt.NoTextInteraction)  # Disable native text selection
        self.hex_display.verticalScrollBar().valueChanged.connect(self.on_scroll)
        hex_layout.addWidget(self.hex_display)

        # ASCII column - right next to hex
        self.ascii_display = HexTextEdit()
        self.ascii_display.hovered.connect(self.on_ascii_hover)
        self.ascii_display.setMinimumWidth(250)
        self.ascii_display.setMaximumWidth(400)
        self.ascii_display.setLineWrapMode(QTextEdit.NoWrap)
        self.ascii_display.setVerticalScrollBarPolicy(Qt.ScrollBarAlwaysOff)
        self.ascii_display.clicked.connect(self.on_ascii_click)
        self.ascii_display.setTextInteractionFlags(Qt.NoTextInteraction)  # Disable native text selection
        self.ascii_display.rightClicked.connect(self.on_ascii_right_click)
        self.ascii_display.setStyleSheet("border-right: 1px solid #555; padding: 2px 0px;")
        self.ascii_display.setSizePolicy(QSizePolicy.Fixed, QSizePolicy.Expanding)
        self.ascii_display.setAlignment(Qt.AlignCenter)
        hex_layout.addWidget(self.ascii_display)

        self.hex_ascii_container.setLayout(hex_layout)
        hex_main_layout.addWidget(self.hex_ascii_container)
        hex_widget.setLayout(hex_main_layout)
        # Allow hex widget to stretch with window
        hex_widget.setMinimumWidth(600)
        content_splitter.addWidget(hex_widget)

        # Sync scrolling
        self.hex_display.verticalScrollBar().valueChanged.connect(self.on_hex_scroll)

        # Right side: Data Inspector with scrollbar
        self.inspector_widget = QWidget()
        self.inspector_widget.setMinimumWidth(320)
        self.inspector_widget.setMaximumWidth(450)
        self.inspector_widget.setObjectName("inspector_widget")
        self.inspector_widget.setSizePolicy(QSizePolicy.Preferred, QSizePolicy.Expanding)

        # Main horizontal layout: scrollbar on left, inspector content on right
        inspector_main_layout = QHBoxLayout()
        inspector_main_layout.setContentsMargins(0, 0, 0, 0)
        inspector_main_layout.setSpacing(0)

        # Add vertical scrollbar for hex view navigation
        self.hex_nav_scrollbar = QScrollBar(Qt.Vertical)
        self.hex_nav_scrollbar.setMinimumWidth(16)
        self.hex_nav_scrollbar.setMaximumWidth(16)
        inspector_main_layout.addWidget(self.hex_nav_scrollbar)

        # Inspector content container
        inspector_content_widget = QWidget()
        inspector_layout = QVBoxLayout()
        inspector_layout.setContentsMargins(5, 0, 5, 0)

        # Inspector title
        inspector_title_widget = QWidget()
        inspector_title_layout = QHBoxLayout()
        inspector_title_layout.setContentsMargins(10, 5, 10, 5)

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

        # Inspector content scroll area (hide its scrollbar)
        self.inspector_scroll = QScrollArea()
        self.inspector_scroll.setWidgetResizable(True)
        self.inspector_scroll.setVerticalScrollBarPolicy(Qt.ScrollBarAlwaysOff)
        self.inspector_content = QWidget()
        self.inspector_content_layout = QVBoxLayout()
        self.inspector_content_layout.setAlignment(Qt.AlignTop)
        self.inspector_content.setLayout(self.inspector_content_layout)
        self.inspector_scroll.setWidget(self.inspector_content)
        inspector_layout.addWidget(self.inspector_scroll)

        # Endian button
        self.endian_btn = QPushButton("Byte Order: Little Endian")
        self.endian_btn.setMinimumHeight(35)
        self.endian_btn.setFont(QFont("Arial", 9))
        self.endian_btn.setStyleSheet("""
            QPushButton {
                background-color: #3b82f6;
                color: white;
                border: none;
                border-radius: 4px;
                padding: 8px;
                font-weight: bold;
            }
            QPushButton:hover {
                background-color: #2563eb;
            }
            QPushButton:pressed {
                background-color: #1d4ed8;
            }
        """)
        self.endian_btn.clicked.connect(self.toggle_endian)
        inspector_layout.addWidget(self.endian_btn)

        # Hex basis checkbox
        self.hex_basis_check = QCheckBox("Hexadecimal basis (for integrals)")
        self.hex_basis_check.setMinimumHeight(35)
        self.hex_basis_check.setFont(QFont("Arial", 9))
        self.hex_basis_check.stateChanged.connect(self.toggle_hex_basis)
        inspector_layout.addWidget(self.hex_basis_check)

        # Set the layout to the content widget and add it to main layout
        inspector_content_widget.setLayout(inspector_layout)
        inspector_main_layout.addWidget(inspector_content_widget)

        self.inspector_widget.setLayout(inspector_main_layout)
        content_splitter.addWidget(self.inspector_widget)

        # Set initial sizes and stretch factors
        content_splitter.setSizes([780, 390])  # Initial proportions
        content_splitter.setStretchFactor(0, 3)  # Hex view gets more stretch
        content_splitter.setStretchFactor(1, 1)  # Inspector gets less stretch

        main_layout.addWidget(content_splitter, stretch=1)

        # Status bar
        self.status_label = QLabel("Ready")
        self.status_label.setFont(QFont("Courier", 9))
        self.statusBar().addWidget(self.status_label, 1)

        central_widget.setLayout(main_layout)

        # Key event filters
        self.hex_display.installEventFilter(self)
        self.ascii_display.installEventFilter(self)

        # Connect navigation scrollbar to hex display scrollbar (bidirectional sync)
        self.hex_nav_scrollbar.valueChanged.connect(self.on_nav_scroll)
        self.hex_display.verticalScrollBar().rangeChanged.connect(self.update_nav_scrollbar_range)

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

        # Search menu
        search_menu = menubar.addMenu("Search")

        search_action = QAction("Search", self)
        search_action.setShortcut("Ctrl+F")
        search_action.triggered.connect(self.show_search_window)
        search_menu.addAction(search_action)

        replace_action = QAction("Replace", self)
        replace_action.setShortcut("Ctrl+R")
        replace_action.triggered.connect(self.show_replace_window)
        search_menu.addAction(replace_action)

        goto_action = QAction("Go to...", self)
        goto_action.setShortcut("Ctrl+G")
        goto_action.triggered.connect(self.show_goto_window)
        search_menu.addAction(goto_action)

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

        save_highlights_action = QAction("Save Highlights...", self)
        save_highlights_action.triggered.connect(self.save_highlights)
        options_menu.addAction(save_highlights_action)

        load_highlights_action = QAction("Load Highlights...", self)
        load_highlights_action.triggered.connect(self.load_highlights)
        options_menu.addAction(load_highlights_action)

        clear_highlights_action = QAction("Clear All Highlights", self)
        clear_highlights_action.triggered.connect(self.clear_all_highlights)
        options_menu.addAction(clear_highlights_action)

        options_menu.addSeparator()

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
        self.update_data_inspector()

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

        # Move cursor
        if self.cursor_nibble == 0:
            self.cursor_nibble = 1
        else:
            self.cursor_nibble = 0
            if self.cursor_position < len(current_file.file_data) - 1:
                self.cursor_position += 1

        self.display_hex()
        self.update_cursor_highlight()
        self.update_data_inspector()

    def handle_ascii_input(self, char):
        current_file = self.open_files[self.current_tab_index]
        if self.cursor_position >= len(current_file.file_data):
            return

        self.save_undo_state()

        current_file.file_data[self.cursor_position] = ord(char)
        current_file.modified = True
        current_file.modified_bytes.add(self.cursor_position)

        if self.cursor_position < len(current_file.file_data) - 1:
            self.cursor_position += 1

        self.display_hex()
        self.update_cursor_highlight()
        self.update_data_inspector()

    def open_file(self):
        file_path, _ = QFileDialog.getOpenFileName(
            self, "Open File", "", "All Files (*)"
        )
        if file_path:
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
                        return

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

                self.display_hex()

            except Exception as e:
                QMessageBox.critical(self, "Error", f"Failed to open file: {str(e)}")

    def close_tab(self, index):
        if 0 <= index < len(self.open_files):
            file_tab = self.open_files[index]
            if file_tab.modified:
                reply = QMessageBox.question(
                    self, "Unsaved Changes",
                    f"File {os.path.basename(file_tab.file_path)} has unsaved changes. Close anyway?",
                    QMessageBox.Yes | QMessageBox.No
                )
                if reply == QMessageBox.No:
                    return

            self.open_files.pop(index)
            self.tab_widget.removeTab(index)

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

    def on_tab_changed(self, index):
        self.current_tab_index = index
        if index >= 0:
            self.cursor_position = 0
            self.cursor_nibble = 0
            self.selection_start = None
            self.selection_end = None
            # Reset rendered range for new tab
            self.rendered_start_byte = 0
            self.rendered_end_byte = 0
            self.display_hex()
        else:
            self.clear_display()

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
                char = chr(byte) if 32 <= byte <= 126 else '.'
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
        self.update_data_inspector()
        self.update_status()
        self.update_tab_title()

    def scroll_to_offset(self, offset, center=True):
        """Scroll the hex display to show the given offset, using proper QTextEdit scrolling"""
        if self.current_tab_index < 0 or not self.open_files:
            return

        current_file = self.open_files[self.current_tab_index]
        if offset >= len(current_file.file_data):
            return

        # Calculate which line the offset is on
        row = offset // self.bytes_per_row

        # Move a QTextCursor to that line
        cursor = QTextCursor(self.hex_display.document())
        cursor.movePosition(QTextCursor.Start)
        cursor.movePosition(QTextCursor.Down, QTextCursor.MoveAnchor, row)

        # Set the cursor (this doesn't change selection, just position)
        self.hex_display.setTextCursor(cursor)

        # Ensure the cursor line is visible, centered if requested
        if center:
            # Center the line in the viewport
            viewport_height = self.hex_display.viewport().height()
            cursor_rect = self.hex_display.cursorRect(cursor)
            target_y = (viewport_height // 2) - (cursor_rect.height() // 2)
            scrollbar = self.hex_display.verticalScrollBar()
            scrollbar.setValue(scrollbar.value() + cursor_rect.top() - target_y)
        else:
            self.hex_display.ensureCursorVisible()

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

        # Helper function to calculate positions
        def get_positions(byte_index):
            row_num = byte_index // self.bytes_per_row
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
            bytes_to_format.update(range(sel_start, sel_end + 1))

        # Only format bytes that need it
        for byte_index in bytes_to_format:
            if byte_index >= len(current_file.file_data):
                continue

            hex_pos, ascii_pos = get_positions(byte_index)
            is_cursor = (self.cursor_position is not None and byte_index == self.cursor_position)

            # Apply user highlights first (lowest priority)
            if byte_index in current_file.byte_highlights:
                highlight_info = current_file.byte_highlights[byte_index]
                highlight_color = QColor(highlight_info["color"])
                highlight_color.setAlpha(64)

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
                sel_start = min(self.selection_start, self.selection_end)
                sel_end = max(self.selection_start, self.selection_end)
                if sel_start <= byte_index <= sel_end:
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
        self.clear_inspector()

    def on_scroll(self, value):
        """Handle scroll events to load more data dynamically"""
        if self.current_tab_index < 0:
            return

        current_file = self.open_files[self.current_tab_index]
        file_data = current_file.file_data
        total_rows = (len(file_data) + self.bytes_per_row - 1) // self.bytes_per_row

        # Only do dynamic loading for large files
        if total_rows <= self.max_initial_rows:
            return

        scrollbar = self.hex_display.verticalScrollBar()
        max_scroll = scrollbar.maximum()

        # Check if we're near the bottom (within 10% of max scroll)
        if max_scroll > 0 and value > max_scroll * 0.9:
            # Check if there's more data to load
            if self.rendered_end_byte < len(file_data):
                # Load another chunk of rows
                rows_to_add = 100
                new_end_byte = min(len(file_data), self.rendered_end_byte + rows_to_add * self.bytes_per_row)

                # Extend the rendered range
                self.rendered_end_byte = new_end_byte

                # Re-render with extended range
                old_scroll_pos = scrollbar.value()
                self.display_hex(preserve_scroll=False)
                # Restore scroll position
                scrollbar.setValue(old_scroll_pos)

    def on_hex_click(self, event):
        if self.current_tab_index < 0:
            return

        current_file = self.open_files[self.current_tab_index]

        # Get plain text to calculate accurate position
        cursor = self.hex_display.cursorForPosition(event.pos())
        line = cursor.blockNumber()

        # Get the plain text line
        plain_text = self.hex_display.toPlainText()
        lines = plain_text.split('\n')

        if line < len(lines):
            line_text = lines[line]

            # Calculate position in the plain text line
            chars_before_line = sum(len(lines[i]) + 1 for i in range(line))
            cursor_pos = cursor.position()
            col = cursor_pos - chars_before_line

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

            byte_index = line * self.bytes_per_row + byte_in_row

            if byte_index < len(current_file.file_data):
                self.cursor_position = byte_index
                # Always start at the first nibble (high nibble) of the byte
                self.cursor_nibble = 0

                # Start selection on click
                self.selection_start = byte_index
                self.selection_end = byte_index

                print(f"Hex click: line={line}, col={col}, byte_in_row={byte_in_row}, byte_index={byte_index}")
                self.display_hex(preserve_scroll=True)
                self.setFocus()  # Make sure main window has focus for keyboard events

    def on_ascii_click(self, event):
        if self.current_tab_index < 0:
            return

        current_file = self.open_files[self.current_tab_index]

        # Use the plain text to get accurate position
        plain_text = self.ascii_display.toPlainText()
        lines = plain_text.split('\n')

        cursor = self.ascii_display.cursorForPosition(event.pos())
        line = cursor.blockNumber()

        if line < len(lines):
            # Get column by calculating position in plain text
            chars_before = sum(len(lines[i]) + 1 for i in range(line))  # +1 for newline
            cursor_pos = cursor.position()
            col = cursor_pos - chars_before

            # Clamp to valid range
            if col < 0:
                col = 0
            elif col >= self.bytes_per_row:
                col = self.bytes_per_row - 1

            byte_index = line * self.bytes_per_row + col

            if byte_index < len(current_file.file_data):
                self.cursor_position = byte_index
                self.cursor_nibble = 0

                # Start selection on click
                self.selection_start = byte_index
                self.selection_end = byte_index

                print(f"ASCII click: line={line}, col={col}, byte_index={byte_index}, cursor_pos={self.cursor_position}")
                self.display_hex(preserve_scroll=True)
                # Scroll to show the selected byte
                self.scroll_to_offset(byte_index)
                self.setFocus()  # Make sure main window has focus for keyboard events

    def on_hex_hover(self, event):
        """Show tooltip for highlighted bytes and handle drag selection"""
        if self.current_tab_index < 0:
            return

        current_file = self.open_files[self.current_tab_index]
        plain_text = self.hex_display.toPlainText()
        lines = plain_text.split('\n')

        cursor = self.hex_display.cursorForPosition(event.pos())
        line = cursor.blockNumber()

        if line < len(lines):
            chars_before = sum(len(lines[i]) + 1 for i in range(line))
            cursor_pos = cursor.position()
            col = cursor_pos - chars_before

            # Account for 2 leading spaces
            byte_col = (col - 2) // 3 if col > 1 else 0
            if byte_col >= 0 and byte_col < self.bytes_per_row:
                byte_index = line * self.bytes_per_row + byte_col

                # Handle drag selection - check if left mouse button is pressed
                if event.buttons() & Qt.LeftButton:
                    if self.selection_start is not None and byte_index < len(current_file.file_data):
                        self.selection_end = byte_index
                        self.display_hex(preserve_scroll=True)

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
        plain_text = self.ascii_display.toPlainText()
        lines = plain_text.split('\n')

        cursor = self.ascii_display.cursorForPosition(event.pos())
        line = cursor.blockNumber()

        if line < len(lines):
            chars_before = sum(len(lines[i]) + 1 for i in range(line))
            cursor_pos = cursor.position()
            col = cursor_pos - chars_before

            if col >= 0 and col < self.bytes_per_row:
                byte_index = line * self.bytes_per_row + col

                # Handle drag selection - check if left mouse button is pressed
                if event.buttons() & Qt.LeftButton:
                    if self.selection_start is not None and byte_index < len(current_file.file_data):
                        self.selection_end = byte_index
                        self.display_hex(preserve_scroll=True)

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

        menu.exec_(event.globalPos())

    def on_ascii_right_click(self, event):
        self.on_hex_right_click(event)

    def on_offset_click(self, event):
        """Handle clicks on offset column - jump to the first byte of that row"""
        if self.current_tab_index < 0:
            return

        cursor = self.offset_display.cursorForPosition(event.pos())
        line_num = cursor.blockNumber()

        # Calculate the byte offset for the first byte in this row
        byte_offset = line_num * self.bytes_per_row

        # Only navigate if the offset is valid
        if byte_offset < len(self.open_files[self.current_tab_index].file_data):
            self.cursor_position = byte_offset
            self.cursor_nibble = 0
            self.selection_start = None
            self.selection_end = None
            self.display_hex(preserve_scroll=True)
            self.scroll_to_offset(byte_offset, center=True)

    def update_cursor_highlight(self):
        # The cursor box is drawn in display_hex, so nothing to do here
        # This method is kept for compatibility with code that calls it
        pass

    def on_hex_scroll(self, value):
        self.offset_display.verticalScrollBar().setValue(value)
        self.ascii_display.verticalScrollBar().setValue(value)
        # Sync navigation scrollbar (block signals to prevent loop)
        self.hex_nav_scrollbar.blockSignals(True)
        self.hex_nav_scrollbar.setValue(value)
        self.hex_nav_scrollbar.blockSignals(False)

    def on_nav_scroll(self, value):
        """Handle navigation scrollbar changes and sync to hex display"""
        self.hex_display.verticalScrollBar().setValue(value)

    def update_nav_scrollbar_range(self, min_val, max_val):
        """Update navigation scrollbar range to match hex display scrollbar"""
        self.hex_nav_scrollbar.blockSignals(True)
        self.hex_nav_scrollbar.setRange(min_val, max_val)
        self.hex_nav_scrollbar.setPageStep(self.hex_display.verticalScrollBar().pageStep())
        self.hex_nav_scrollbar.blockSignals(False)

    def update_data_inspector(self):
        # Clear existing inspector widgets
        for i in reversed(range(self.inspector_content_layout.count())):
            self.inspector_content_layout.itemAt(i).widget().setParent(None)

        if self.current_tab_index < 0 or self.cursor_position is None:
            return

        current_file = self.open_files[self.current_tab_index]
        pos = self.cursor_position

        if pos >= len(current_file.file_data):
            return

        data = current_file.file_data

        # Helper to read bytes
        def read_bytes(offset, count):
            if offset + count <= len(data):
                return bytes(data[offset:offset + count])
            return None

        # Display format
        def add_inspector_row(label, value, byte_size=1, data_offset=0, data_type=None):
            widget = QWidget()
            if self.is_dark_theme():
                widget.setStyleSheet("background-color: #252525; border: 1px solid #3a3a3a; border-radius: 3px; margin: 1px;")
                label_color = "#b0b0b0"
                value_bg = "#2d2d2d"
                value_border = "#4a4a4a"
                value_color = "#ffffff"
            else:
                widget.setStyleSheet("background-color: #f5f5f5; border: 1px solid #c0c0c0; border-radius: 3px; margin: 1px;")
                label_color = "#5a5a5a"
                value_bg = "#ffffff"
                value_border = "#b0b0b0"
                value_color = "#2c3e50"

            layout = QHBoxLayout()
            layout.setContentsMargins(8, 4, 8, 4)

            label_widget = QLabel(label)
            label_widget.setMinimumWidth(80)
            label_widget.setFont(QFont("Arial", 8))
            label_widget.setStyleSheet(f"color: {label_color}; border: none;")
            layout.addWidget(label_widget)

            # Make all values editable
            value_edit = QLineEdit(str(value))
            value_edit.setFont(QFont("Courier", 8))

            # Special handling for Double field - make it scrollable
            if label == "Double:":
                value_edit.setMinimumWidth(240)
            else:
                value_edit.setMaximumWidth(240)

            value_edit.setStyleSheet(f"border: 1px solid {value_border}; background-color: {value_bg}; color: {value_color}; padding: 2px;")

            # Store metadata for highlighting and editing
            value_edit.setProperty('byte_size', byte_size)
            value_edit.setProperty('data_offset', data_offset)
            value_edit.setProperty('data_type', data_type)

            # Connect focus event to highlight bytes
            def on_focus(event):
                # Use cursor_position directly, not the captured pos variable
                if self.cursor_position is not None:
                    self.highlight_bytes(self.cursor_position + data_offset, byte_size)
                QLineEdit.focusInEvent(value_edit, event)
            value_edit.focusInEvent = on_focus

            # Connect editing finished event to update bytes
            if data_type and data_type != 'offset':
                def on_edit_finished():
                    # Use cursor_position directly, not the captured pos variable
                    if self.cursor_position is not None:
                        self.update_bytes_from_inspector(value_edit, self.cursor_position + data_offset, data_type)
                value_edit.editingFinished.connect(on_edit_finished)

            layout.addWidget(value_edit)
            layout.addStretch()
            widget.setLayout(layout)
            self.inspector_content_layout.addWidget(widget)

        # Offset
        offset_str = f"0x{pos:X}" if self.offset_mode == 'h' else str(pos)
        add_inspector_row("Offset:", offset_str, byte_size=0, data_offset=0, data_type='offset')

        # Byte (hex only)
        byte_val = data[pos]
        if self.hex_basis:
            add_inspector_row("Byte (hex):", f"0x{byte_val:02X}", byte_size=1, data_offset=0, data_type='byte_hex')

        # Int8
        int8_val = struct.unpack('b', bytes([byte_val]))[0]
        add_inspector_row("Int8:", str(int8_val) if not self.hex_basis else f"0x{int8_val & 0xFF:02X}", byte_size=1, data_offset=0, data_type='int8')

        # UInt8
        add_inspector_row("UInt8:", str(byte_val) if not self.hex_basis else f"0x{byte_val:02X}", byte_size=1, data_offset=0, data_type='uint8')

        # Int16
        bytes_16 = read_bytes(pos, 2)
        if bytes_16:
            fmt = '<h' if self.endian_mode == 'little' else '>h'
            int16_val = struct.unpack(fmt, bytes_16)[0]
            add_inspector_row("Int16:", str(int16_val) if not self.hex_basis else f"0x{int16_val & 0xFFFF:04X}", byte_size=2, data_offset=0, data_type='int16')

        # UInt16
        if bytes_16:
            fmt = '<H' if self.endian_mode == 'little' else '>H'
            uint16_val = struct.unpack(fmt, bytes_16)[0]
            add_inspector_row("UInt16:", str(uint16_val) if not self.hex_basis else f"0x{uint16_val:04X}", byte_size=2, data_offset=0, data_type='uint16')

        # Int32
        bytes_32 = read_bytes(pos, 4)
        if bytes_32:
            fmt = '<i' if self.endian_mode == 'little' else '>i'
            int32_val = struct.unpack(fmt, bytes_32)[0]
            add_inspector_row("Int32:", str(int32_val) if not self.hex_basis else f"0x{int32_val & 0xFFFFFFFF:08X}", byte_size=4, data_offset=0, data_type='int32')

        # UInt32
        if bytes_32:
            fmt = '<I' if self.endian_mode == 'little' else '>I'
            uint32_val = struct.unpack(fmt, bytes_32)[0]
            add_inspector_row("UInt32:", str(uint32_val) if not self.hex_basis else f"0x{uint32_val:08X}", byte_size=4, data_offset=0, data_type='uint32')

        # Int64
        bytes_64 = read_bytes(pos, 8)
        if bytes_64:
            fmt = '<q' if self.endian_mode == 'little' else '>q'
            int64_val = struct.unpack(fmt, bytes_64)[0]
            add_inspector_row("Int64:", str(int64_val) if not self.hex_basis else f"0x{int64_val & 0xFFFFFFFFFFFFFFFF:016X}", byte_size=8, data_offset=0, data_type='int64')

        # UInt64
        if bytes_64:
            fmt = '<Q' if self.endian_mode == 'little' else '>Q'
            uint64_val = struct.unpack(fmt, bytes_64)[0]
            add_inspector_row("UInt64:", str(uint64_val) if not self.hex_basis else f"0x{uint64_val:016X}", byte_size=8, data_offset=0, data_type='uint64')

        # Int24
        bytes_24 = read_bytes(pos, 3)
        if bytes_24:
            # Manual 24-bit signed int parsing
            if self.endian_mode == 'little':
                int24_val = bytes_24[0] | (bytes_24[1] << 8) | (bytes_24[2] << 16)
            else:
                int24_val = (bytes_24[0] << 16) | (bytes_24[1] << 8) | bytes_24[2]
            if int24_val & 0x800000:
                int24_val -= 0x1000000
            add_inspector_row("Int24:", str(int24_val) if not self.hex_basis else f"0x{int24_val & 0xFFFFFF:06X}", byte_size=3, data_offset=0, data_type='int24')

        # UInt24
        if bytes_24:
            if self.endian_mode == 'little':
                uint24_val = bytes_24[0] | (bytes_24[1] << 8) | (bytes_24[2] << 16)
            else:
                uint24_val = (bytes_24[0] << 16) | (bytes_24[1] << 8) | bytes_24[2]
            add_inspector_row("UInt24:", str(uint24_val) if not self.hex_basis else f"0x{uint24_val:06X}", byte_size=3, data_offset=0, data_type='uint24')

        # LEB128 (signed)
        leb_bytes = read_bytes(pos, min(10, len(data) - pos))
        if leb_bytes:
            try:
                result = 0
                shift = 0
                leb_size = 0
                for b in leb_bytes:
                    leb_size += 1
                    result |= (b & 0x7f) << shift
                    shift += 7
                    if (b & 0x80) == 0:
                        break
                if result & (1 << (shift - 1)):
                    result -= (1 << shift)
                add_inspector_row("LEB128:", str(result), byte_size=leb_size, data_offset=0, data_type='leb128')
            except:
                add_inspector_row("LEB128:", "Invalid", byte_size=1, data_offset=0, data_type=None)

        # ULEB128 (unsigned)
        if leb_bytes:
            try:
                result = 0
                shift = 0
                uleb_size = 0
                for b in leb_bytes:
                    uleb_size += 1
                    result |= (b & 0x7f) << shift
                    shift += 7
                    if (b & 0x80) == 0:
                        break
                add_inspector_row("ULEB128:", str(result), byte_size=uleb_size, data_offset=0, data_type='uleb128')
            except:
                add_inspector_row("ULEB128:", "Invalid", byte_size=1, data_offset=0, data_type=None)

        # AnsiChar / char8_t
        ansi_char = chr(byte_val) if 32 <= byte_val <= 126 else f"\\x{byte_val:02x}"
        add_inspector_row("AnsiChar / char8_t:", ansi_char, byte_size=1, data_offset=0, data_type='ansichar')

        # WideChar / char16_t
        if bytes_16:
            fmt = '<H' if self.endian_mode == 'little' else '>H'
            wide_val = struct.unpack(fmt, bytes_16)[0]
            try:
                wide_char = chr(wide_val) if wide_val < 0xD800 or wide_val > 0xDFFF else f"\\u{wide_val:04x}"
            except:
                wide_char = f"\\u{wide_val:04x}"
            add_inspector_row("WideChar / char16_t:", wide_char, byte_size=2, data_offset=0, data_type='widechar')

        # UTF-8 code point
        utf8_bytes = read_bytes(pos, min(4, len(data) - pos))
        if utf8_bytes:
            try:
                utf8_size = 1
                if utf8_bytes[0] < 0x80:
                    utf8_size = 1
                elif (utf8_bytes[0] & 0xE0) == 0xC0:
                    utf8_size = 2
                elif (utf8_bytes[0] & 0xF0) == 0xE0:
                    utf8_size = 3
                elif (utf8_bytes[0] & 0xF8) == 0xF0:
                    utf8_size = 4
                utf8_str = bytes(utf8_bytes[:utf8_size]).decode('utf-8')
                add_inspector_row("UTF-8 code point:", utf8_str, byte_size=utf8_size, data_offset=0, data_type='utf8')
            except:
                add_inspector_row("UTF-8 code point:", "Invalid", byte_size=1, data_offset=0, data_type=None)

        # Single (float32) - same as Float
        if bytes_32:
            fmt = '<f' if self.endian_mode == 'little' else '>f'
            float_val = struct.unpack(fmt, bytes_32)[0]
            add_inspector_row("Single (float32):", f"{float_val:.6f}", byte_size=4, data_offset=0, data_type='float')

        # Double (float64)
        if bytes_64:
            fmt = '<d' if self.endian_mode == 'little' else '>d'
            double_val = struct.unpack(fmt, bytes_64)[0]
            add_inspector_row("Double (float64):", f"{double_val:.15f}", byte_size=8, data_offset=0, data_type='double')

        # OLETIME (OLE Automation date - 8 bytes double)
        if bytes_64:
            fmt = '<d' if self.endian_mode == 'little' else '>d'
            ole_val = struct.unpack(fmt, bytes_64)[0]
            try:
                from datetime import datetime, timedelta
                base_date = datetime(1899, 12, 30)
                result_date = base_date + timedelta(days=ole_val)
                add_inspector_row("OLETIME:", result_date.strftime("%Y-%m-%d %H:%M:%S"), byte_size=8, data_offset=0, data_type='oletime')
            except:
                add_inspector_row("OLETIME:", "Invalid", byte_size=8, data_offset=0, data_type=None)

        # FILETIME (Windows FILETIME - 8 bytes)
        if bytes_64:
            fmt = '<Q' if self.endian_mode == 'little' else '>Q'
            filetime_val = struct.unpack(fmt, bytes_64)[0]
            try:
                from datetime import datetime, timedelta
                if filetime_val > 0:
                    base_date = datetime(1601, 1, 1)
                    result_date = base_date + timedelta(microseconds=filetime_val / 10)
                    add_inspector_row("FILETIME:", result_date.strftime("%Y-%m-%d %H:%M:%S"), byte_size=8, data_offset=0, data_type='filetime')
                else:
                    add_inspector_row("FILETIME:", "Invalid", byte_size=8, data_offset=0, data_type=None)
            except:
                add_inspector_row("FILETIME:", "Invalid", byte_size=8, data_offset=0, data_type=None)

        # DOS date (2 bytes)
        if bytes_16:
            fmt = '<H' if self.endian_mode == 'little' else '>H'
            dos_date = struct.unpack(fmt, bytes_16)[0]
            try:
                day = dos_date & 0x1F
                month = (dos_date >> 5) & 0x0F
                year = ((dos_date >> 9) & 0x7F) + 1980
                if 1 <= day <= 31 and 1 <= month <= 12:
                    add_inspector_row("DOS date:", f"{year:04d}-{month:02d}-{day:02d}", byte_size=2, data_offset=0, data_type='dos_date')
                else:
                    add_inspector_row("DOS date:", "Invalid", byte_size=2, data_offset=0, data_type=None)
            except:
                add_inspector_row("DOS date:", "Invalid", byte_size=2, data_offset=0, data_type=None)

        # DOS time (2 bytes)
        if bytes_16:
            fmt = '<H' if self.endian_mode == 'little' else '>H'
            dos_time = struct.unpack(fmt, bytes_16)[0]
            try:
                seconds = (dos_time & 0x1F) * 2
                minutes = (dos_time >> 5) & 0x3F
                hours = (dos_time >> 11) & 0x1F
                if hours < 24 and minutes < 60 and seconds < 60:
                    add_inspector_row("DOS time:", f"{hours:02d}:{minutes:02d}:{seconds:02d}", byte_size=2, data_offset=0, data_type='dos_time')
                else:
                    add_inspector_row("DOS time:", "Invalid", byte_size=2, data_offset=0, data_type=None)
            except:
                add_inspector_row("DOS time:", "Invalid", byte_size=2, data_offset=0, data_type=None)

        # DOS time & date (4 bytes)
        bytes_dos = read_bytes(pos, 4)
        if bytes_dos:
            fmt = '<HH' if self.endian_mode == 'little' else '>HH'
            dos_time, dos_date = struct.unpack(fmt, bytes_dos)
            try:
                seconds = (dos_time & 0x1F) * 2
                minutes = (dos_time >> 5) & 0x3F
                hours = (dos_time >> 11) & 0x1F
                day = dos_date & 0x1F
                month = (dos_date >> 5) & 0x0F
                year = ((dos_date >> 9) & 0x7F) + 1980
                if hours < 24 and minutes < 60 and seconds < 60 and 1 <= day <= 31 and 1 <= month <= 12:
                    add_inspector_row("DOS time & date:", f"{year:04d}-{month:02d}-{day:02d} {hours:02d}:{minutes:02d}:{seconds:02d}", byte_size=4, data_offset=0, data_type='dos_datetime')
                else:
                    add_inspector_row("DOS time & date:", "Invalid", byte_size=4, data_offset=0, data_type=None)
            except:
                add_inspector_row("DOS time & date:", "Invalid", byte_size=4, data_offset=0, data_type=None)

        # time_t (32 bit)
        if bytes_32:
            fmt = '<i' if self.endian_mode == 'little' else '>i'
            time_t_32 = struct.unpack(fmt, bytes_32)[0]
            try:
                from datetime import datetime
                if time_t_32 >= 0:
                    result_date = datetime.utcfromtimestamp(time_t_32)
                    add_inspector_row("time_t (32 bit):", result_date.strftime("%Y-%m-%d %H:%M:%S UTC"), byte_size=4, data_offset=0, data_type='time_t_32')
                else:
                    add_inspector_row("time_t (32 bit):", "Invalid", byte_size=4, data_offset=0, data_type=None)
            except:
                add_inspector_row("time_t (32 bit):", "Invalid", byte_size=4, data_offset=0, data_type=None)

        # time_t (64 bit)
        if bytes_64:
            fmt = '<q' if self.endian_mode == 'little' else '>q'
            time_t_64 = struct.unpack(fmt, bytes_64)[0]
            try:
                from datetime import datetime
                if time_t_64 >= 0:
                    result_date = datetime.utcfromtimestamp(time_t_64)
                    add_inspector_row("time_t (64 bit):", result_date.strftime("%Y-%m-%d %H:%M:%S UTC"), byte_size=8, data_offset=0, data_type='time_t_64')
                else:
                    add_inspector_row("time_t (64 bit):", "Invalid", byte_size=8, data_offset=0, data_type=None)
            except:
                add_inspector_row("time_t (64 bit):", "Invalid", byte_size=8, data_offset=0, data_type=None)

        # GUID (16 bytes)
        bytes_guid = read_bytes(pos, 16)
        if bytes_guid:
            try:
                if self.endian_mode == 'little':
                    guid_fmt = '<IHH8s'
                    d1, d2, d3, d4 = struct.unpack(guid_fmt, bytes_guid)
                    guid_str = f"{d1:08X}-{d2:04X}-{d3:04X}-{d4[0]:02X}{d4[1]:02X}-{d4[2]:02X}{d4[3]:02X}{d4[4]:02X}{d4[5]:02X}{d4[6]:02X}{d4[7]:02X}"
                else:
                    guid_fmt = '>IHH8s'
                    d1, d2, d3, d4 = struct.unpack(guid_fmt, bytes_guid)
                    guid_str = f"{d1:08X}-{d2:04X}-{d3:04X}-{d4[0]:02X}{d4[1]:02X}-{d4[2]:02X}{d4[3]:02X}{d4[4]:02X}{d4[5]:02X}{d4[6]:02X}{d4[7]:02X}"
                add_inspector_row("GUID:", guid_str, byte_size=16, data_offset=0, data_type='guid')
            except:
                add_inspector_row("GUID:", "Invalid", byte_size=16, data_offset=0, data_type=None)

        # Disassembly (x86-16, x86-32, x86-64)
        disasm_bytes = read_bytes(pos, min(15, len(data) - pos))
        if disasm_bytes:
            try:
                from capstone import Cs, CS_ARCH_X86, CS_MODE_16, CS_MODE_32, CS_MODE_64

                # x86-16
                try:
                    md16 = Cs(CS_ARCH_X86, CS_MODE_16)
                    instructions = list(md16.disasm(disasm_bytes, pos))
                    if instructions:
                        instr = instructions[0]
                        disasm_text = f"{instr.mnemonic} {instr.op_str}"
                        add_inspector_row("Disassembly (x86-16):", disasm_text, byte_size=instr.size, data_offset=0, data_type=None)
                    else:
                        add_inspector_row("Disassembly (x86-16):", "Invalid instruction", byte_size=1, data_offset=0, data_type=None)
                except:
                    add_inspector_row("Disassembly (x86-16):", "Error", byte_size=1, data_offset=0, data_type=None)

                # x86-32
                try:
                    md32 = Cs(CS_ARCH_X86, CS_MODE_32)
                    instructions = list(md32.disasm(disasm_bytes, pos))
                    if instructions:
                        instr = instructions[0]
                        disasm_text = f"{instr.mnemonic} {instr.op_str}"
                        add_inspector_row("Disassembly (x86-32):", disasm_text, byte_size=instr.size, data_offset=0, data_type=None)
                    else:
                        add_inspector_row("Disassembly (x86-32):", "Invalid instruction", byte_size=1, data_offset=0, data_type=None)
                except:
                    add_inspector_row("Disassembly (x86-32):", "Error", byte_size=1, data_offset=0, data_type=None)

                # x86-64
                try:
                    md64 = Cs(CS_ARCH_X86, CS_MODE_64)
                    instructions = list(md64.disasm(disasm_bytes, pos))
                    if instructions:
                        instr = instructions[0]
                        disasm_text = f"{instr.mnemonic} {instr.op_str}"
                        add_inspector_row("Disassembly (x86-64):", disasm_text, byte_size=instr.size, data_offset=0, data_type=None)
                    else:
                        add_inspector_row("Disassembly (x86-64):", "Invalid instruction", byte_size=1, data_offset=0, data_type=None)
                except:
                    add_inspector_row("Disassembly (x86-64):", "Error", byte_size=1, data_offset=0, data_type=None)
            except ImportError:
                # Capstone not available
                add_inspector_row("Disassembly (x86-16):", "[capstone library not installed]", byte_size=1, data_offset=0, data_type=None)
                add_inspector_row("Disassembly (x86-32):", "[capstone library not installed]", byte_size=1, data_offset=0, data_type=None)
                add_inspector_row("Disassembly (x86-64):", "[capstone library not installed]", byte_size=1, data_offset=0, data_type=None)

    def clear_inspector(self):
        for i in reversed(range(self.inspector_content_layout.count())):
            self.inspector_content_layout.itemAt(i).widget().setParent(None)

    def update_bytes_from_inspector(self, line_edit, position, data_type):
        """Update file bytes based on inspector field edit"""
        if self.current_tab_index < 0:
            return

        current_file = self.open_files[self.current_tab_index]
        file_data = current_file.file_data

        try:
            text = line_edit.text().strip()

            # Parse hex values
            is_hex = text.startswith('0x') or text.startswith('0X')
            if is_hex:
                text = text[2:]

            # Convert based on data type
            if data_type == 'byte_hex':
                value = int(text, 16)
                if 0 <= value <= 0xFF:
                    file_data[position] = value
                else:
                    raise ValueError("Byte value out of range")

            elif data_type == 'int8':
                if is_hex:
                    value = int(text, 16)
                    if value > 127:
                        value = value - 256
                else:
                    value = int(text)
                if -128 <= value <= 127:
                    file_data[position] = value & 0xFF
                else:
                    raise ValueError("Int8 value out of range")

            elif data_type == 'uint8':
                value = int(text, 16) if is_hex else int(text)
                if 0 <= value <= 255:
                    file_data[position] = value
                else:
                    raise ValueError("UInt8 value out of range")

            elif data_type == 'int16':
                value = int(text, 16) if is_hex else int(text)
                if -32768 <= value <= 32767:
                    fmt = '<h' if self.endian_mode == 'little' else '>h'
                    bytes_val = struct.pack(fmt, value)
                    for i, b in enumerate(bytes_val):
                        if position + i < len(file_data):
                            file_data[position + i] = b
                else:
                    raise ValueError("Int16 value out of range")

            elif data_type == 'uint16':
                value = int(text, 16) if is_hex else int(text)
                if 0 <= value <= 65535:
                    fmt = '<H' if self.endian_mode == 'little' else '>H'
                    bytes_val = struct.pack(fmt, value)
                    for i, b in enumerate(bytes_val):
                        if position + i < len(file_data):
                            file_data[position + i] = b
                else:
                    raise ValueError("UInt16 value out of range")

            elif data_type == 'int32':
                value = int(text, 16) if is_hex else int(text)
                if -2147483648 <= value <= 2147483647:
                    fmt = '<i' if self.endian_mode == 'little' else '>i'
                    bytes_val = struct.pack(fmt, value)
                    for i, b in enumerate(bytes_val):
                        if position + i < len(file_data):
                            file_data[position + i] = b
                else:
                    raise ValueError("Int32 value out of range")

            elif data_type == 'uint32':
                value = int(text, 16) if is_hex else int(text)
                if 0 <= value <= 4294967295:
                    fmt = '<I' if self.endian_mode == 'little' else '>I'
                    bytes_val = struct.pack(fmt, value)
                    for i, b in enumerate(bytes_val):
                        if position + i < len(file_data):
                            file_data[position + i] = b
                else:
                    raise ValueError("UInt32 value out of range")

            elif data_type == 'int64':
                value = int(text, 16) if is_hex else int(text)
                if -9223372036854775808 <= value <= 9223372036854775807:
                    fmt = '<q' if self.endian_mode == 'little' else '>q'
                    bytes_val = struct.pack(fmt, value)
                    for i, b in enumerate(bytes_val):
                        if position + i < len(file_data):
                            file_data[position + i] = b
                else:
                    raise ValueError("Int64 value out of range")

            elif data_type == 'uint64':
                value = int(text, 16) if is_hex else int(text)
                if 0 <= value <= 18446744073709551615:
                    fmt = '<Q' if self.endian_mode == 'little' else '>Q'
                    bytes_val = struct.pack(fmt, value)
                    for i, b in enumerate(bytes_val):
                        if position + i < len(file_data):
                            file_data[position + i] = b
                else:
                    raise ValueError("UInt64 value out of range")

            elif data_type == 'float':
                value = float(text)
                fmt = '<f' if self.endian_mode == 'little' else '>f'
                bytes_val = struct.pack(fmt, value)
                for i, b in enumerate(bytes_val):
                    if position + i < len(file_data):
                        file_data[position + i] = b

            elif data_type == 'double':
                value = float(text)
                fmt = '<d' if self.endian_mode == 'little' else '>d'
                bytes_val = struct.pack(fmt, value)
                for i, b in enumerate(bytes_val):
                    if position + i < len(file_data):
                        file_data[position + i] = b

            elif data_type == 'int24':
                value = int(text, 16) if is_hex else int(text)
                if -8388608 <= value <= 8388607:
                    if value < 0:
                        value = value + 0x1000000
                    if self.endian_mode == 'little':
                        bytes_val = bytes([value & 0xFF, (value >> 8) & 0xFF, (value >> 16) & 0xFF])
                    else:
                        bytes_val = bytes([(value >> 16) & 0xFF, (value >> 8) & 0xFF, value & 0xFF])
                    for i, b in enumerate(bytes_val):
                        if position + i < len(file_data):
                            file_data[position + i] = b
                else:
                    raise ValueError("Int24 value out of range")

            elif data_type == 'uint24':
                value = int(text, 16) if is_hex else int(text)
                if 0 <= value <= 16777215:
                    if self.endian_mode == 'little':
                        bytes_val = bytes([value & 0xFF, (value >> 8) & 0xFF, (value >> 16) & 0xFF])
                    else:
                        bytes_val = bytes([(value >> 16) & 0xFF, (value >> 8) & 0xFF, value & 0xFF])
                    for i, b in enumerate(bytes_val):
                        if position + i < len(file_data):
                            file_data[position + i] = b
                else:
                    raise ValueError("UInt24 value out of range")

            elif data_type == 'ansichar':
                if len(text) == 1:
                    file_data[position] = ord(text)
                elif text.startswith('\\x') and len(text) == 4:
                    file_data[position] = int(text[2:], 16)
                else:
                    raise ValueError("Invalid AnsiChar format")

            elif data_type == 'widechar':
                if len(text) == 1:
                    value = ord(text)
                elif text.startswith('\\u') and len(text) == 6:
                    value = int(text[2:], 16)
                else:
                    raise ValueError("Invalid WideChar format")
                fmt = '<H' if self.endian_mode == 'little' else '>H'
                bytes_val = struct.pack(fmt, value)
                for i, b in enumerate(bytes_val):
                    if position + i < len(file_data):
                        file_data[position + i] = b

            elif data_type == 'utf8':
                bytes_val = text.encode('utf-8')
                for i, b in enumerate(bytes_val):
                    if position + i < len(file_data):
                        file_data[position + i] = b

            elif data_type == 'guid':
                # Parse GUID format: XXXXXXXX-XXXX-XXXX-XXXX-XXXXXXXXXXXX
                guid_parts = text.replace('{', '').replace('}', '').split('-')
                if len(guid_parts) == 5:
                    d1 = int(guid_parts[0], 16)
                    d2 = int(guid_parts[1], 16)
                    d3 = int(guid_parts[2], 16)
                    d4_1 = int(guid_parts[3], 16)
                    d4_2 = int(guid_parts[4], 16)

                    if self.endian_mode == 'little':
                        bytes_val = struct.pack('<IHH', d1, d2, d3)
                    else:
                        bytes_val = struct.pack('>IHH', d1, d2, d3)

                    bytes_val += struct.pack('>HQ', d4_1, d4_2)[0:8]

                    for i, b in enumerate(bytes_val[:16]):
                        if position + i < len(file_data):
                            file_data[position + i] = b
                else:
                    raise ValueError("Invalid GUID format")

            # Mark as modified and update displays
            self.save_undo_state()
            current_file.modified = True

            # Mark the modified bytes
            byte_count = 1 if data_type in ['byte_hex', 'int8', 'uint8', 'ansichar'] else \
                         2 if data_type in ['int16', 'uint16', 'widechar', 'dos_date', 'dos_time'] else \
                         3 if data_type in ['int24', 'uint24'] else \
                         4 if data_type in ['int32', 'uint32', 'float', 'dos_datetime', 'time_t_32'] else \
                         8 if data_type in ['int64', 'uint64', 'double', 'oletime', 'filetime', 'time_t_64'] else \
                         16 if data_type in ['guid'] else 1

            for i in range(byte_count):
                if position + i < len(file_data):
                    current_file.modified_bytes.add(position + i)

            # Update tab title
            tab_text = os.path.basename(current_file.file_path) + " *"
            self.tab_widget.setTabText(self.current_tab_index, tab_text)

            self.display_hex()
            self.update_data_inspector()

        except (ValueError, struct.error) as e:
            # Reset to original value on error
            print(f"Invalid input: {e}")
            self.update_data_inspector()

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

        # Add truncation warning if applicable
        total_rows = (file_size + self.bytes_per_row - 1) // self.bytes_per_row
        if total_rows > self.max_initial_rows:
            status += f" | [Viewing first {self.max_initial_rows:,} rows of {total_rows:,}]"

        self.status_label.setText(status)

    def first_byte(self):
        """Jump to the first byte of the file"""
        if self.cursor_position is not None and self.current_tab_index >= 0:
            self.cursor_position = 0
            self.cursor_nibble = 0
            self.display_hex(preserve_scroll=True)
            self.scroll_to_offset(0)
            self.update_data_inspector()

    def last_byte(self):
        """Jump to the last byte of the file"""
        if self.cursor_position is not None and self.current_tab_index >= 0:
            current_file = self.open_files[self.current_tab_index]
            if len(current_file.file_data) > 0:
                self.cursor_position = len(current_file.file_data) - 1
                self.cursor_nibble = 0
                self.display_hex(preserve_scroll=True)
                self.scroll_to_offset(self.cursor_position)
                self.update_data_inspector()

    def prev_byte(self):
        if self.cursor_position is not None and self.cursor_position > 0:
            self.cursor_position -= 1
            self.cursor_nibble = 0
            self.display_hex(preserve_scroll=True)
            self.scroll_to_offset(self.cursor_position)
            self.update_data_inspector()

    def next_byte(self):
        if self.cursor_position is not None and self.current_tab_index >= 0:
            current_file = self.open_files[self.current_tab_index]
            if self.cursor_position < len(current_file.file_data) - 1:
                self.cursor_position += 1
                self.cursor_nibble = 0
                self.display_hex(preserve_scroll=True)
                self.scroll_to_offset(self.cursor_position)
                self.update_data_inspector()

    def toggle_endian(self):
        self.endian_mode = 'big' if self.endian_mode == 'little' else 'little'
        self.endian_btn.setText(
            f"Byte Order: {'Little' if self.endian_mode == 'little' else 'Big'} Endian"
        )
        self.update_data_inspector()

    def toggle_hex_basis(self):
        self.hex_basis = self.hex_basis_check.isChecked()
        self.update_data_inspector()

    def highlight_bytes(self, start_pos, byte_count):
        """Highlight a range of bytes in the hex and ASCII displays"""
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
        hex_labels = {'h': '  00 01 02 03 04 05 06 07 08 09 0A 0B 0C 0D 0E 0F',
                      'd': '  00 01 02 03 04 05 06 07 08 09 10 11 12 13 14 15',
                      'o': '  00 01 02 03 04 05 06 07 10 11 12 13 14 15 16 17'}

        current_index = modes.index(self.offset_mode)
        next_index = (current_index + 1) % len(modes)
        self.offset_mode = modes[next_index]

        self.offset_header.setText(labels[self.offset_mode])
        self.hex_header.setText(hex_labels[self.offset_mode])
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

        self.display_hex()

    def show_file_size_warning(self, parent, num_bytes, is_increase):
        """Show file size change warning with checkbox to ignore future warnings"""
        if self.ignore_file_size_warnings:
            return True

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
            start = min(self.selection_start, self.selection_end)
            end = max(self.selection_start, self.selection_end)
            self.clipboard = bytes(current_file.file_data[start:end + 1])
            QMessageBox.information(self, "Copy", f"Copied {len(self.clipboard)} bytes")
        elif self.cursor_position is not None:
            current_file = self.open_files[self.current_tab_index]
            self.clipboard = bytes([current_file.file_data[self.cursor_position]])
            QMessageBox.information(self, "Copy", "Copied 1 byte")

    def cut(self):
        if self.current_tab_index < 0:
            return

        if self.selection_start is not None and self.selection_end is not None:
            # Calculate the number of bytes to cut
            start = min(self.selection_start, self.selection_end)
            end = max(self.selection_start, self.selection_end)
            num_bytes = end - start + 1

            # Warning prompt before cutting (reduces file size)
            if not self.show_file_size_warning(self, num_bytes, is_increase=False):
                return

            # Copy to clipboard first
            current_file = self.open_files[self.current_tab_index]
            self.clipboard = bytes(current_file.file_data[start:end + 1])
            QMessageBox.information(self, "Cut", f"Cut {len(self.clipboard)} bytes")

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

            del current_file.file_data[start:end + 1]
            current_file.modified = True

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
            QMessageBox.information(self, "Cut", "Cut 1 byte")

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

            del current_file.file_data[self.cursor_position]
            current_file.modified = True
            self.display_hex(preserve_scroll=True)
            self.scroll_to_offset(self.cursor_position)

    def paste_write(self):
        if self.current_tab_index < 0 or not self.clipboard or self.cursor_position is None:
            return

        self.save_undo_state()
        current_file = self.open_files[self.current_tab_index]

        for i, byte in enumerate(self.clipboard):
            pos = self.cursor_position + i
            if pos < len(current_file.file_data):
                current_file.file_data[pos] = byte
                # Mark as modified only if not in inserted_bytes
                if pos not in current_file.inserted_bytes:
                    current_file.modified_bytes.add(pos)

        current_file.modified = True
        self.display_hex(preserve_scroll=True)
        self.scroll_to_offset(self.cursor_position)

    def paste_insert(self):
        if self.current_tab_index < 0 or not self.clipboard or self.cursor_position is None:
            return

        # Warning prompt before inserting (increases file size)
        num_bytes = len(self.clipboard)
        if not self.show_file_size_warning(self, num_bytes, is_increase=True):
            return

        self.save_undo_state()
        current_file = self.open_files[self.current_tab_index]

        # When inserting, we need to shift all existing markers that come after the insertion point
        insert_count = len(self.clipboard)
        old_modified = set(current_file.modified_bytes)
        old_inserted = set(current_file.inserted_bytes)
        old_replaced = set(current_file.replaced_bytes)

        # Clear and rebuild the sets with shifted positions
        current_file.modified_bytes.clear()
        current_file.inserted_bytes.clear()
        current_file.replaced_bytes.clear()

        for pos in old_modified:
            if pos >= self.cursor_position:
                current_file.modified_bytes.add(pos + insert_count)
            else:
                current_file.modified_bytes.add(pos)

        for pos in old_inserted:
            if pos >= self.cursor_position:
                current_file.inserted_bytes.add(pos + insert_count)
            else:
                current_file.inserted_bytes.add(pos)

        for pos in old_replaced:
            if pos >= self.cursor_position:
                current_file.replaced_bytes.add(pos + insert_count)
            else:
                current_file.replaced_bytes.add(pos)

        # Shift non-pattern highlights
        self.shift_non_pattern_highlights(current_file, self.cursor_position, insert_count)

        # Insert bytes
        for i, byte in enumerate(self.clipboard):
            pos = self.cursor_position + i
            current_file.file_data.insert(pos, byte)
            current_file.inserted_bytes.add(pos)

        current_file.modified = True
        self.display_hex(preserve_scroll=True)
        self.scroll_to_offset(self.cursor_position)

    def show_fill_selection_dialog(self):
        if self.current_tab_index < 0:
            return

        if self.selection_start is None or self.selection_end is None:
            QMessageBox.warning(self, "No Selection", "Please select a range of bytes to fill.")
            return

        dialog = QDialog(self)
        dialog.setWindowTitle("Fill Selection")
        dialog.setMinimumSize(450, 250)

        layout = QVBoxLayout()

        # Pattern input section
        pattern_group = QWidget()
        pattern_layout = QVBoxLayout()
        pattern_layout.addWidget(QLabel("Fill pattern (hex values):"))

        pattern_input = QLineEdit()
        pattern_input.setPlaceholderText("e.g., 00 or 31 32 33")
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
        random_layout.addWidget(QLabel("Range (decimal):"))

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
        layout.itemAt(layout.count()-1).widget().setLayout(preset_layout)

        # Preset button actions
        def set_zerobytes():
            pattern_input.setText("00")
            random_checkbox.setChecked(False)

        zerobytes_btn.clicked.connect(set_zerobytes)
        dod_btn.clicked.connect(set_zerobytes)  # DoD also uses zeros for simplicity

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

                if random_checkbox.isChecked():
                    # Fill with random bytes
                    import random
                    min_val = range_min.value()
                    max_val = range_max.value()
                    if min_val > max_val:
                        min_val, max_val = max_val, min_val

                    for i in range(length):
                        current_file.file_data[start + i] = random.randint(min_val, max_val)
                        current_file.modified_bytes.add(start + i)
                else:
                    # Fill with pattern
                    pattern_text = pattern_input.text().strip()
                    if not pattern_text:
                        QMessageBox.warning(dialog, "Invalid Pattern", "Please enter a hex pattern.")
                        return

                    # Parse hex pattern
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

                    # Fill selection with pattern (repeat as needed)
                    for i in range(length):
                        current_file.file_data[start + i] = pattern_bytes[i % len(pattern_bytes)]
                        current_file.modified_bytes.add(start + i)

                current_file.modified = True

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

        def set_search_mode():
            current_mode[0] = "search"
            search_mode_btn.setStyleSheet("background-color: #3498db; color: white; font-weight: bold;")
            selection_mode_btn.setStyleSheet("")
            bytes_input_frame.setVisible(True)
            selection_info_frame.setVisible(False)

        def set_selection_mode():
            current_mode[0] = "selection"
            selection_mode_btn.setStyleSheet("background-color: #3498db; color: white; font-weight: bold;")
            search_mode_btn.setStyleSheet("")
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
        ok_btn.setStyleSheet("background-color: #27ae60; color: white;")
        cancel_btn = QPushButton("Cancel")
        cancel_btn.setStyleSheet("background-color: #95a5a6; color: white;")

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
            dialog.accept()

        ok_btn.clicked.connect(apply_highlight)
        cancel_btn.clicked.connect(dialog.reject)

        button_layout.addWidget(ok_btn)
        button_layout.addWidget(cancel_btn)
        button_frame.setLayout(button_layout)
        layout.addWidget(button_frame)

        dialog.setLayout(layout)
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
        self.search_type_btn.setFont(QFont("Arial", 10, QFont.Bold))
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

            # Position at bottom, starting after offset column (130px), spanning hex (505px) + ASCII (165px) = 670px width
            # Height of 160px at the bottom
            # Reduce width slightly to prevent cut-off by Data Inspector
            overlay_height = 160
            x_start = 130  # After offset column
            overlay_width = 640  # Slightly less than 650 to avoid cut-off
            y_position = self.hex_ascii_container.height() - overlay_height
            self.results_overlay.setGeometry(x_start, y_position, overlay_width, overlay_height)

            overlay_layout = QVBoxLayout()
            overlay_layout.setContentsMargins(10, 5, 10, 5)
            overlay_layout.setSpacing(2)

            # Title row with close button
            title_row = QHBoxLayout()
            title_label = QLabel("Search Results")
            title_label.setFont(QFont("Arial", 9, QFont.Bold))
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

            # Connect resize event to reposition overlay at bottom spanning hex and ASCII
            original_resize = self.hex_ascii_container.resizeEvent
            def new_resize(event):
                if hasattr(self, 'results_overlay') and self.results_overlay is not None:
                    overlay_height = 160
                    x_start = 130  # After offset column
                    overlay_width = 640  # Slightly less than 650 to avoid cut-off
                    y_position = self.hex_ascii_container.height() - overlay_height
                    self.results_overlay.setGeometry(x_start, y_position, overlay_width, overlay_height)
                    self.results_overlay.raise_()
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
        result_label.setFont(QFont("Courier", 7))
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
        self.update_data_inspector()

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
        self.replace_type_btn.setFont(QFont("Arial", 10, QFont.Bold))
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

                        # Reset rendered range to recalculate around new cursor position
                        self.rendered_start_byte = 0
                        self.rendered_end_byte = 0

                        self.display_hex(preserve_scroll=True)  # Refresh display to show cursor at new position

                        # Scroll to the offset using proper QTextEdit scrolling, centered
                        self.scroll_to_offset(offset, center=True)

                        self.update_cursor_highlight()
                        self.update_data_inspector()
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

    def save_highlights(self):
        if self.current_tab_index < 0:
            QMessageBox.warning(self, "No File", "Please open a file first")
            return

        current_file = self.open_files[self.current_tab_index]

        if not current_file.byte_highlights and not current_file.pattern_highlights:
            QMessageBox.information(self, "No Highlights", "No highlights to save")
            return

        file_path, _ = QFileDialog.getSaveFileName(
            self, "Save Highlights", "", "JSON Files (*.json);;All Files (*)"
        )

        if file_path:
            try:
                # Convert highlights to JSON-serializable format
                # Separate pattern-based from manual highlights
                manual_highlights = {offset: info for offset, info in current_file.byte_highlights.items() if "pattern" not in info}

                highlights_data = {
                    "file": os.path.basename(current_file.file_path),
                    "highlights": {
                        str(offset): {
                            "color": info["color"],
                            "message": info.get("message", ""),
                            "underline": info.get("underline", False)
                        }
                        for offset, info in manual_highlights.items()
                    },
                    "pattern_highlights": [
                        {
                            "pattern": list(p["pattern"]),  # Convert bytes to list for JSON
                            "color": p["color"],
                            "message": p["message"],
                            "underline": p["underline"]
                        }
                        for p in current_file.pattern_highlights
                    ]
                }

                with open(file_path, 'w') as f:
                    json.dump(highlights_data, f, indent=2)

                QMessageBox.information(self, "Success", f"Highlights saved to {os.path.basename(file_path)}")
            except Exception as e:
                QMessageBox.critical(self, "Error", f"Failed to save highlights: {str(e)}")

    def load_highlights(self):
        if self.current_tab_index < 0:
            QMessageBox.warning(self, "No File", "Please open a file first")
            return

        file_path, _ = QFileDialog.getOpenFileName(
            self, "Load Highlights", "", "JSON Files (*.json);;All Files (*)"
        )

        if file_path:
            try:
                with open(file_path, 'r') as f:
                    highlights_data = json.load(f)

                current_file = self.open_files[self.current_tab_index]

                # Load manual highlights from JSON
                loaded_count = 0
                for offset_str, info in highlights_data.get("highlights", {}).items():
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
                for pattern_info in highlights_data.get("pattern_highlights", []):
                    pattern_bytes = bytes(pattern_info["pattern"])
                    current_file.pattern_highlights.append({
                        "pattern": pattern_bytes,
                        "color": pattern_info["color"],
                        "message": pattern_info["message"],
                        "underline": pattern_info["underline"]
                    })
                    pattern_count += 1

                self.display_hex()
                msg = f"Loaded {loaded_count} manual highlight(s)"
                if pattern_count > 0:
                    msg += f" and {pattern_count} pattern highlight(s)"
                QMessageBox.information(self, "Success", msg)
            except Exception as e:
                QMessageBox.critical(self, "Error", f"Failed to load highlights: {str(e)}")

    def clear_all_highlights(self):
        if self.current_tab_index < 0:
            return

        current_file = self.open_files[self.current_tab_index]

        if not current_file.byte_highlights and not current_file.pattern_highlights:
            QMessageBox.information(self, "No Highlights", "No highlights to clear")
            return

        reply = QMessageBox.question(
            self, "Clear Highlights",
            "Are you sure you want to clear all highlights?",
            QMessageBox.Yes | QMessageBox.No
        )

        if reply == QMessageBox.Yes:
            current_file.byte_highlights.clear()
            current_file.pattern_highlights.clear()
            self.display_hex()
            QMessageBox.information(self, "Success", "All highlights cleared")

    def show_calculator_window(self):
        dialog = QDialog(self, Qt.Window)  # Make it a separate window
        dialog.setWindowTitle("Hex Calculator")
        dialog.setFixedSize(340, 300)  # Increased to show all fields properly
        dialog.setModal(False)  # Allow multiple windows

        # Track this window
        self.auxiliary_windows.append(dialog)

        layout = QVBoxLayout()
        layout.setSpacing(3)  # Tight spacing
        layout.setContentsMargins(8, 8, 8, 8)  # Reduce margins

        # Input
        tk_label = QLabel("Enter a Value / Hex:")
        tk_label.setFont(QFont("Arial", 9, QFont.Bold))
        layout.addWidget(tk_label)

        input_edit = QLineEdit()
        input_edit.setFont(QFont("Courier", 10))
        input_edit.setAlignment(Qt.AlignCenter)
        layout.addWidget(input_edit)

        # Type label
        type_label = QLabel("")
        type_label.setFont(QFont("Arial", 8))
        type_label.setStyleSheet("font-style: italic; color: #3498db;")
        layout.addWidget(type_label)

        # Byte length and Endianness (compact layout)
        byte_frame = QWidget()
        byte_layout = QHBoxLayout()
        byte_layout.setSpacing(10)
        byte_layout.addWidget(QLabel("Byte Length:"))
        byte_combo = QComboBox()
        byte_combo.addItems(['4', '8'])
        byte_combo.setMaximumWidth(60)
        byte_layout.addWidget(byte_combo)

        byte_layout.addSpacing(15)
        byte_layout.addWidget(QLabel("Byte Order:"))
        endian_combo = QComboBox()
        endian_combo.addItems(['Little', 'Big'])
        endian_combo.setMaximumWidth(80)
        byte_layout.addWidget(endian_combo)
        byte_layout.addStretch()
        byte_frame.setLayout(byte_layout)
        layout.addWidget(byte_frame)

        # Track current endianness
        current_endianness = ["little"]

        # Results
        result_frame = QWidget()
        result_layout = QVBoxLayout()

        little_label = QLabel("Little Endian:")
        little_label.setFont(QFont("Arial", 10, QFont.Bold))
        result_layout.addWidget(little_label)
        little_edit = QLineEdit()
        little_edit.setFont(QFont("Courier", 10))
        little_edit.setReadOnly(True)
        little_edit.setAlignment(Qt.AlignCenter)
        result_layout.addWidget(little_edit)

        big_label = QLabel("Big Endian:")
        big_label.setFont(QFont("Arial", 10, QFont.Bold))
        result_layout.addWidget(big_label)
        big_edit = QLineEdit()
        big_edit.setFont(QFont("Courier", 10))
        big_edit.setReadOnly(True)
        big_edit.setAlignment(Qt.AlignCenter)
        result_layout.addWidget(big_edit)

        result_frame.setLayout(result_layout)
        layout.addWidget(result_frame)

        updating = [False]  # Use list to allow modification in nested function

        def update_hex_values():
            if updating[0]:  # Prevent recursion
                return

            updating[0] = True

            value_str = input_edit.text().strip().upper()
            if not value_str:
                type_label.setText("")
                little_label.setText("Little Endian:")
                big_label.setText("Big Endian:")
                little_edit.clear()
                big_edit.clear()
                updating[0] = False
                return

            try:
                # Check if it's a hex string (like "DEADBEEF" or "0xDEADBEEF" or "30 00")
                is_hex_string = False
                hex_value_str = value_str
                if value_str.startswith('0X'):
                    hex_value_str = value_str[2:]
                    is_hex_string = True
                elif ' ' in value_str:
                    # If there's a space, treat as hex (e.g., "30 00")
                    if all(c in '0123456789ABCDEF ' for c in value_str):
                        is_hex_string = True
                elif all(c in '0123456789ABCDEF' for c in value_str):
                    # No space - only treat as hex if it contains A-F
                    if '.' not in value_str and any(c in 'ABCDEF' for c in value_str):
                        is_hex_string = True

                if is_hex_string:
                    # Hex input detected - show Integer and Float conversions
                    type_label.setText("Hex Detected")

                    # Remove spaces from hex string
                    hex_clean = hex_value_str.replace(' ', '')

                    if len(hex_clean) % 2 != 0:
                        hex_clean = '0' + hex_clean

                    hex_bytes = bytes.fromhex(hex_clean)

                    # Change labels to Integer and Float
                    little_label.setText("Integer:")
                    big_label.setText("Float:")

                    # Calculate Integer value using selected endianness
                    try:
                        int_value = int.from_bytes(hex_bytes, byteorder=current_endianness[0], signed=False)
                        little_edit.setText(str(int_value))
                    except:
                        little_edit.setText("N/A")

                    # Calculate Float value using selected endianness
                    try:
                        if len(hex_bytes) == 4:
                            endian_format = '<f' if current_endianness[0] == 'little' else '>f'
                            float_value = struct.unpack(endian_format, hex_bytes)[0]
                            big_edit.setText(str(float_value))
                        elif len(hex_bytes) == 8:
                            endian_format = '<d' if current_endianness[0] == 'little' else '>d'
                            float_value = struct.unpack(endian_format, hex_bytes)[0]
                            big_edit.setText(str(float_value))
                        else:
                            big_edit.setText("N/A")
                    except:
                        big_edit.setText("N/A")

                else:
                    # Decimal input - show hex conversions
                    little_label.setText("Little Endian:")
                    big_label.setText("Big Endian:")

                    is_float = '.' in value_str

                    if is_float:
                        value = float(value_str)
                        type_label.setText("Float Detected")

                        # Only update combo if needed
                        if byte_combo.count() != 2 or byte_combo.itemText(0) != 'Single':
                            byte_combo.blockSignals(True)
                            byte_combo.clear()
                            byte_combo.addItems(['Single', 'Double'])
                            byte_combo.blockSignals(False)

                        precision = byte_combo.currentText()

                        if precision == 'Single':
                            little_bytes = struct.pack('<f', value)
                            big_bytes = struct.pack('>f', value)
                        else:
                            little_bytes = struct.pack('<d', value)
                            big_bytes = struct.pack('>d', value)

                        little_hex = ' '.join(f"{b:02X}" for b in little_bytes)
                        big_hex = ' '.join(f"{b:02X}" for b in big_bytes)
                    else:
                        value = int(value_str)
                        type_label.setText("Integer Detected")

                        # Only update combo if needed
                        if byte_combo.count() != 8 or byte_combo.itemText(0) != '1':
                            byte_combo.blockSignals(True)
                            byte_combo.clear()
                            byte_combo.addItems(['1', '2', '3', '4', '5', '6', '7', '8'])
                            byte_combo.setCurrentText('4')
                            byte_combo.blockSignals(False)

                        byte_length = int(byte_combo.currentText())

                        little_bytes = value.to_bytes(byte_length, byteorder='little', signed=True if value < 0 else False)
                        big_bytes = value.to_bytes(byte_length, byteorder='big', signed=True if value < 0 else False)

                        little_hex = ' '.join(f"{b:02X}" for b in little_bytes)
                        big_hex = ' '.join(f"{b:02X}" for b in big_bytes)

                    little_edit.setText(little_hex)
                    big_edit.setText(big_hex)

            except (ValueError, OverflowError):
                type_label.setText("Invalid Input")
                little_edit.clear()
                big_edit.clear()

            updating[0] = False

        def endian_changed(text):
            current_endianness[0] = 'little' if text == 'Little' else 'big'
            update_hex_values()

        input_edit.textChanged.connect(update_hex_values)
        byte_combo.currentTextChanged.connect(update_hex_values)
        endian_combo.currentTextChanged.connect(endian_changed)

        dialog.setLayout(layout)
        dialog.show()  # Use show() instead of exec_() to allow multiple windows

    def show_color_picker_window(self):
        dialog = QDialog(self, Qt.Window)  # Make it a separate window
        dialog.setWindowTitle("RGB Color Picker")
        dialog.resize(400, 480)
        dialog.setMinimumSize(300, 400)
        dialog.setModal(False)  # Allow multiple windows

        # Track this window
        self.auxiliary_windows.append(dialog)

        layout = QVBoxLayout()

        # Title
        title = QLabel("RGB Color Picker")
        title.setFont(QFont("Arial", 12, QFont.Bold))
        title.setAlignment(Qt.AlignCenter)
        layout.addWidget(title)

        # Mode toggle
        mode_btn = QPushButton("Switch to Decimal")
        mode_btn.setStyleSheet("background-color: #3498db; color: white;")
        layout.addWidget(mode_btn)

        disclaimer = QLabel("")
        disclaimer.setStyleSheet("font-style: italic; color: #e74c3c;")
        disclaimer.setAlignment(Qt.AlignCenter)
        layout.addWidget(disclaimer)

        # Color preview circle - centered
        preview_frame = QWidget()
        preview_frame_layout = QHBoxLayout()
        preview_frame_layout.setAlignment(Qt.AlignCenter)
        preview_canvas = QLabel()
        preview_canvas.setFixedSize(120, 120)
        preview_canvas.setStyleSheet("background-color: black; border: 2px solid #34495e; border-radius: 60px;")
        preview_canvas.setAlignment(Qt.AlignCenter)
        preview_frame_layout.addWidget(preview_canvas)
        preview_frame.setLayout(preview_frame_layout)
        layout.addWidget(preview_frame)

        # Hex values display
        hex_frame = QFrame()
        hex_frame.setStyleSheet("background-color: #ecf0f1; border: 2px solid #bdc3c7;")
        hex_layout = QVBoxLayout()

        values_title = QLabel("Hex Values:")
        values_title.setFont(QFont("Arial", 10, QFont.Bold))
        values_title.setStyleSheet("color: #000000;")
        hex_layout.addWidget(values_title)

        # RGB hex values
        rgb_hex_layout = QHBoxLayout()
        r_label = QLabel("R:")
        r_label.setStyleSheet("color: #000000;")
        rgb_hex_layout.addWidget(r_label)

        r_hex_label = QLabel("00")
        r_hex_label.setFont(QFont("Courier", 12))
        r_hex_label.setStyleSheet("color: #e74c3c;")
        rgb_hex_layout.addWidget(r_hex_label)

        g_label = QLabel("G:")
        g_label.setStyleSheet("color: #000000;")
        rgb_hex_layout.addWidget(g_label)

        g_hex_label = QLabel("00")
        g_hex_label.setFont(QFont("Courier", 12))
        g_hex_label.setStyleSheet("color: #27ae60;")
        rgb_hex_layout.addWidget(g_hex_label)

        b_label = QLabel("B:")
        b_label.setStyleSheet("color: #000000;")
        rgb_hex_layout.addWidget(b_label)

        b_hex_label = QLabel("00")
        b_hex_label.setFont(QFont("Courier", 12))
        b_hex_label.setStyleSheet("color: #3498db;")
        rgb_hex_layout.addWidget(b_hex_label)

        hex_layout.addLayout(rgb_hex_layout)

        # Full hex
        full_hex_layout = QHBoxLayout()
        full_hex_lbl = QLabel("Full Hex:")
        full_hex_lbl.setStyleSheet("color: #000000;")
        full_hex_layout.addWidget(full_hex_lbl)
        full_hex_label = QLabel("#000000")
        full_hex_label.setFont(QFont("Courier", 12))
        full_hex_label.setStyleSheet("color: #000000;")
        full_hex_layout.addWidget(full_hex_label)
        hex_layout.addLayout(full_hex_layout)

        # Shorthand
        short_layout = QHBoxLayout()
        short_lbl = QLabel("Shorthand:")
        short_lbl.setStyleSheet("color: #000000;")
        short_layout.addWidget(short_lbl)
        shorthand_label = QLabel("N/A")
        shorthand_label.setFont(QFont("Courier", 12))
        shorthand_label.setStyleSheet("color: #000000;")
        short_layout.addWidget(shorthand_label)
        hex_layout.addLayout(short_layout)

        hex_frame.setLayout(hex_layout)
        layout.addWidget(hex_frame)

        # Sliders
        mode = ["Hex"]  # Use list to allow modification in nested function

        slider_frame = QWidget()
        slider_layout = QVBoxLayout()

        # R slider
        r_layout = QHBoxLayout()
        r_label = QLabel("R")
        r_label.setFont(QFont("Arial", 10, QFont.Bold))
        r_label.setStyleSheet("color: #e74c3c;")
        r_layout.addWidget(r_label)
        r_slider = QSlider(Qt.Horizontal)
        r_slider.setRange(0, 255)
        r_slider.setValue(0)
        r_layout.addWidget(r_slider)
        r_value = QLabel("0")
        r_value.setFont(QFont("Courier", 10))
        r_layout.addWidget(r_value)
        slider_layout.addLayout(r_layout)

        # G slider
        g_layout = QHBoxLayout()
        g_label = QLabel("G")
        g_label.setFont(QFont("Arial", 10, QFont.Bold))
        g_label.setStyleSheet("color: #27ae60;")
        g_layout.addWidget(g_label)
        g_slider = QSlider(Qt.Horizontal)
        g_slider.setRange(0, 255)
        g_slider.setValue(0)
        g_layout.addWidget(g_slider)
        g_value = QLabel("0")
        g_value.setFont(QFont("Courier", 10))
        g_layout.addWidget(g_value)
        slider_layout.addLayout(g_layout)

        # B slider
        b_layout = QHBoxLayout()
        b_label = QLabel("B")
        b_label.setFont(QFont("Arial", 10, QFont.Bold))
        b_label.setStyleSheet("color: #3498db;")
        b_layout.addWidget(b_label)
        b_slider = QSlider(Qt.Horizontal)
        b_slider.setRange(0, 255)
        b_slider.setValue(0)
        b_layout.addWidget(b_slider)
        b_value = QLabel("0")
        b_value.setFont(QFont("Courier", 10))
        b_layout.addWidget(b_value)
        slider_layout.addLayout(b_layout)

        slider_frame.setLayout(slider_layout)
        layout.addWidget(slider_frame)

        def update_color():
            if mode[0] == "Hex":
                r = r_slider.value()
                g = g_slider.value()
                b = b_slider.value()

                r_hex_label.setText(f"{r:02X}")
                g_hex_label.setText(f"{g:02X}")
                b_hex_label.setText(f"{b:02X}")

                r_value.setText(str(r))
                g_value.setText(str(g))
                b_value.setText(str(b))
            else:  # Decimal (0.00-1.00)
                # Use full precision: slider 0-100 maps to 0.00-1.00
                r_dec = r_slider.value() / 100.0
                g_dec = g_slider.value() / 100.0
                b_dec = b_slider.value() / 100.0

                # Convert decimal to RGB for display (preserve exact color)
                r = round(r_dec * 255)
                g = round(g_dec * 255)
                b = round(b_dec * 255)

                r_hex_label.setText(f"{r_dec:.2f}")
                g_hex_label.setText(f"{g_dec:.2f}")
                b_hex_label.setText(f"{b_dec:.2f}")

                r_value.setText(f"{r_dec:.2f}")
                g_value.setText(f"{g_dec:.2f}")
                b_value.setText(f"{b_dec:.2f}")

            hex_color = f"#{r:02X}{g:02X}{b:02X}"
            preview_canvas.setStyleSheet(f"background-color: {hex_color}; border: 2px solid #34495e; border-radius: 75px;")
            full_hex_label.setText(hex_color)

            # Shorthand
            r_hex = f"{r:02X}"
            g_hex = f"{g:02X}"
            b_hex = f"{b:02X}"

            if r_hex[0] == r_hex[1] and g_hex[0] == g_hex[1] and b_hex[0] == b_hex[1]:
                shorthand = f"#{r_hex[0]}{g_hex[0]}{b_hex[0]}"
                shorthand_label.setText(shorthand)
            else:
                shorthand_label.setText("N/A")

        def toggle_mode():
            if mode[0] == "Hex":
                mode[0] = "Decimal"
                mode_btn.setText("Switch to Hex")
                disclaimer.setText("Lower decimal values may induce transparency")
                values_title.setText("Decimal Values (0.00 - 1.00):")

                # Convert current values (0-255 to 0-100 for 0.00-1.00 range)
                current_r = r_slider.value()
                current_g = g_slider.value()
                current_b = b_slider.value()

                # Change slider ranges to 0-100 (representing 0.00-1.00)
                r_slider.setRange(0, 100)
                g_slider.setRange(0, 100)
                b_slider.setRange(0, 100)

                # Convert RGB (0-255) to decimal slider (0-100)
                # This preserves the color exactly
                r_slider.setValue(round((current_r / 255.0) * 100))
                g_slider.setValue(round((current_g / 255.0) * 100))
                b_slider.setValue(round((current_b / 255.0) * 100))
            else:
                mode[0] = "Hex"
                mode_btn.setText("Switch to Decimal")
                disclaimer.setText("")
                values_title.setText("Hex Values:")

                # Convert current values back (0-100 to 0-255)
                current_r_dec = r_slider.value() / 100.0
                current_g_dec = g_slider.value() / 100.0
                current_b_dec = b_slider.value() / 100.0

                r_slider.setRange(0, 255)
                g_slider.setRange(0, 255)
                b_slider.setRange(0, 255)

                # Convert decimal (0.00-1.00) back to RGB (0-255)
                # This preserves the color exactly
                r_slider.setValue(round(current_r_dec * 255))
                g_slider.setValue(round(current_g_dec * 255))
                b_slider.setValue(round(current_b_dec * 255))

            update_color()

        mode_btn.clicked.connect(toggle_mode)
        r_slider.valueChanged.connect(update_color)
        g_slider.valueChanged.connect(update_color)
        b_slider.valueChanged.connect(update_color)

        update_color()

        dialog.setLayout(layout)
        dialog.show()  # Use show() instead of exec_() to allow multiple windows

    def show_compare_window(self):
        dialog = QDialog(self)
        dialog.setModal(False)  # Allow multiple windows
        self.auxiliary_windows.append(dialog)  # Track this window
        dialog.setWindowTitle("Compare Files")
        dialog.setMinimumSize(1400, 900)
        dialog.resize(1400, 900)

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
                    char = chr(byte) if 32 <= byte <= 126 else '.'

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
                            # Mark the edited byte as modified (red) if it's not an inserted byte
                            if edited_position not in current_file.inserted_bytes:
                                if edited_position < len(current_file.original_data):
                                    if new_value != current_file.original_data[edited_position]:
                                        current_file.modified_bytes.add(edited_position)
                                    else:
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

    def resizeEvent(self, event):
        super().resizeEvent(event)
        # Update search overlay position when window resizes (overlay spans hex and ASCII at bottom)
        if hasattr(self, 'results_overlay') and self.results_overlay is not None and self.results_overlay.isVisible():
            overlay_height = 160
            x_start = 130  # After offset column
            overlay_width = 640  # Slightly less than 650 to avoid cut-off
            y_position = self.hex_ascii_container.height() - overlay_height
            self.results_overlay.setGeometry(x_start, y_position, overlay_width, overlay_height)
            self.results_overlay.raise_()

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

        layout = QVBoxLayout()

        # Info label
        info_label = QLabel("Choose a theme:")
        layout.addWidget(info_label)

        # List widget for themes
        theme_list = QListWidget()
        theme_list.setSelectionMode(QListWidget.SingleSelection)

        # Add themes
        for theme_name in sorted(THEMES.keys()):
            item = QListWidgetItem(theme_name)
            theme_list.addItem(item)
            if theme_name == self.current_theme:
                theme_list.setCurrentItem(item)

        layout.addWidget(theme_list)

        # Buttons
        button_layout = QHBoxLayout()

        apply_button = QPushButton("Apply")

        def apply_theme():
            current_item = theme_list.currentItem()
            if current_item:
                self.current_theme = current_item.text()
                self.apply_theme()
                self.save_theme_preference()
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
        tagline_font = QFont("Arial", 10)
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
        dev_font = QFont("Arial", 10)
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
        # Convert hex to int for comparison
        bg_hex = theme_colors['background'].lstrip('#')
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
                    # Validate theme exists
                    if theme in THEMES:
                        return theme
        except Exception as e:
            print(f"Error loading theme preference: {e}")
        return "Dark"

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

    def apply_theme(self):
        style = get_theme_stylesheet(self.current_theme)
        self.setStyleSheet(style)

        # Update notes window theme if it exists
        if self.notes_window is not None:
            self.notes_window.apply_theme(self.is_dark_theme())

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
            pass
        # Handle hex digit input (0-9, A-F) only if it's a valid single character
        # and no modifiers are pressed (except Shift for letters)
        elif text in '0123456789ABCDEF' and len(text) == 1:
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

                # Move cursor
                if self.cursor_nibble == 0:
                    self.cursor_nibble = 1
                else:
                    self.cursor_nibble = 0
                    if self.cursor_position < len(current_file.file_data) - 1:
                        self.cursor_position += 1

                self.display_hex(preserve_scroll=True)
                self.scroll_to_offset(self.cursor_position)
                self.update_status()

        # Handle arrow keys
        elif key == Qt.Key_Left:
            old_pos = self.cursor_position
            if self.cursor_nibble == 1:
                self.cursor_nibble = 0
            elif self.cursor_position > 0:
                self.cursor_position -= 1
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
                self.cursor_position += 1
                self.cursor_nibble = 0
            print(f"Right arrow: {old_pos} -> {self.cursor_position}, nibble={self.cursor_nibble}")
            self.display_hex(preserve_scroll=True)
            self.scroll_to_offset(self.cursor_position)
            self.update_status()

        elif key == Qt.Key_Up:
            old_pos = self.cursor_position
            if self.cursor_position >= self.bytes_per_row:
                self.cursor_position -= self.bytes_per_row
            print(f"Up arrow: {old_pos} -> {self.cursor_position}")
            self.display_hex(preserve_scroll=True)
            self.scroll_to_offset(self.cursor_position)
            self.update_status()

        elif key == Qt.Key_Down:
            old_pos = self.cursor_position
            if self.cursor_position + self.bytes_per_row < len(current_file.file_data):
                self.cursor_position += self.bytes_per_row
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
            # Screen changed, refresh display
            self._last_screen = current_screen
            if self.current_tab_index >= 0:
                self.display_hex()

    def closeEvent(self, event):
        """Close all auxiliary windows when main window closes"""
        # Check for unsaved files
        unsaved_files = [f for f in self.open_files if f.modified]

        if unsaved_files:
            file_names = [os.path.basename(f.file_path) for f in unsaved_files]
            file_list = "\n".join(file_names)

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

        # Save theme preference
        self.save_theme_preference()

        # Close all auxiliary windows except notebook
        for window in self.auxiliary_windows:
            if window and window.isVisible():
                window.close()

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
