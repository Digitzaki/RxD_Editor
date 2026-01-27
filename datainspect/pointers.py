"""
Signature Pointers Module
=========================

This module provides signature pointer functionality for marking and interpreting
specific byte locations in binary files.

Features:
- User-defined signature pointers with data type interpretation
- Bulk pattern scanning to find multiple occurrences
- Clickable overlays showing interpreted values
- Category-based organization
- Segment type for highlighting byte ranges
"""

import struct
from PyQt5.QtCore import QThread, pyqtSignal, Qt, QRect, QTimer
from PyQt5.QtWidgets import (QWidget, QVBoxLayout, QHBoxLayout, QLabel, QPushButton,
                              QProgressBar, QTreeWidget, QTreeWidgetItem, QLineEdit,
                              QComboBox, QCheckBox, QMenu, QInputDialog)
from PyQt5.QtGui import QFont, QPainter, QPen, QColor


class SignaturePointer:
    """
    Represents a user-defined pointer or signature marker in the file.

    Signature pointers allow users to mark important locations in the file and
    interpret the bytes at those locations as specific data types. They appear
    as overlays on the hex display showing the interpreted value.

    Use cases:
    - Marking structure fields (e.g., "file size at offset 0x10")
    - Tracking file offsets/pointers within the file
    - Labeling important data values
    - Organizing related pointers by category

    Attributes:
        offset (int): Byte offset where pointer starts
        length (int): Number of bytes this pointer spans
        data_type (str): Type interpretation (e.g., "int8", "uint16", "float32", "string", "segment")
        label (str): User-assigned label describing this pointer
        value: Interpreted value at this offset (computed dynamically)
        category (str): Category for organizing pointers (default "Custom")
        custom_value: User-entered value for string types
        pattern (bytes): Search pattern that found this pointer (for grouping)
        segment_start (int): For segment type, where the segment starts
        value_type (str): For segment type, whether to interpret as signed or unsigned (e.g., "int", "uint")
        endianness (str): For segment type, the endianness ("LE" or "BE")
        reference_tab_index (int): For String (Ref.) type, index of the tab to use as reference
    """
    def __init__(self, offset: int, length: int, data_type: str, label: str = "", category: str = "Custom", pattern: bytes = None, segment_start: int = None, value_type: str = None, endianness: str = None, reference_tab_index: int = None):
        self.offset = offset
        self.length = length
        self.data_type = data_type
        self.label = label
        self.value = None
        self.category = category
        self.custom_value = None
        self.pattern = pattern
        self.segment_start = segment_start if segment_start is not None else offset
        self.value_type = value_type
        self.endianness = endianness if endianness else "LE"
        self.reference_tab_index = reference_tab_index


class ClickableOverlay(QLineEdit):
    """
    Editable overlay widget for signature pointer values.

    This widget appears as a text overlay on top of the hex display, positioned
    directly over the bytes of a signature pointer. It displays the interpreted
    value and allows editing.

    Features:
    - Click offset-type pointers to jump to that location
    - Edit non-offset values to modify underlying bytes
    - Expand when focused for better editing experience
    - Forward mouse events to hex display when not editing

    Signals:
        value_changed (object, str): Emitted with (pointer, new_value) when edited
        offset_jump (int): Emitted with offset when offset-type pointer is clicked
        clicked (object): Emitted with pointer when overlay is clicked

    Attributes:
        pointer (SignaturePointer): The signature pointer this overlay represents
        hex_display_parent: Reference to parent hex display widget
        is_offset_type (bool): True if this is an offset/pointer type (clickable)
        is_editing (bool): True when user is actively editing the value
    """
    value_changed = pyqtSignal(object, str)
    offset_jump = pyqtSignal(int)
    clicked = pyqtSignal(object)

    def __init__(self, pointer, parent=None):
        super().__init__(parent)
        self.pointer = pointer
        self.hex_display_parent = parent
        dtype_lower = pointer.data_type.lower()
        self.is_offset_type = dtype_lower.startswith("offset") or dtype_lower == "segment" or dtype_lower == "string (offset)" or dtype_lower == "string (ref.)"
        self.is_editing = False
        self.original_geometry = None
        self.original_text = ""

        if self.is_offset_type:
            self.setCursor(Qt.PointingHandCursor)
        else:
            self.setCursor(Qt.IBeamCursor)

        self.setReadOnly(False)
        self.setFrame(False)
        self.setAlignment(Qt.AlignCenter)

        self.editingFinished.connect(self._on_editing_finished)
        self.returnPressed.connect(self._on_editing_finished)
        self.textChanged.connect(self._on_text_changed)

    def focusInEvent(self, event):
        super().focusInEvent(event)
        self.is_editing = True
        self.original_text = self.text()
        self.original_geometry = self.geometry()
        self._expand_for_editing()

    def focusOutEvent(self, event):
        super().focusOutEvent(event)
        self.is_editing = False
        if self.original_geometry:
            self.setGeometry(self.original_geometry)

    def _expand_for_editing(self):
        if self.original_geometry:
            metrics = self.fontMetrics()
            text_width = metrics.horizontalAdvance(self.text()) + 16
            if text_width > self.original_geometry.width():
                width_diff = text_width - self.original_geometry.width()
                new_x = self.original_geometry.x() - (width_diff // 2)

                self.setGeometry(
                    new_x,
                    self.original_geometry.y(),
                    text_width,
                    self.original_geometry.height()
                )
                self.raise_()

    def _on_text_changed(self, text):
        if self.is_editing:
            self._expand_for_editing()

    def mousePressEvent(self, event):
        if event.button() == Qt.LeftButton and not self.is_editing:
            self.clicked.emit(self.pointer)
            # For segment types, accept the event to prevent text selection
            if self.pointer.data_type.lower() == "segment":
                event.accept()
                return
        super().mousePressEvent(event)

    def _on_editing_finished(self):
        try:
            new_value = self.text()
            self.value_changed.emit(self.pointer, new_value)
            self.clearFocus()
        except RuntimeError:
            pass

    def mouseDoubleClickEvent(self, event):
        if self.is_offset_type and event.button() == Qt.LeftButton:
            dtype_lower = self.pointer.data_type.lower()

            # For segment types, emit clicked to highlight the segment
            if dtype_lower == "segment":
                self.clicked.emit(self.pointer)
                event.accept()
                return

            # For String (Offset) and String (Ref.), don't jump - just show the string
            if dtype_lower == "string (offset)" or dtype_lower == "string (ref.)":
                event.accept()
                return

            # For offset types, try to jump to the offset
            try:
                value_str = str(self.pointer.value).strip()
                offset = int(value_str, 16)
                self.offset_jump.emit(offset)
                event.accept()
                return
            except (ValueError, AttributeError):
                pass

        super().mouseDoubleClickEvent(event)

    def wheelEvent(self, event):
        if self.hex_display_parent and hasattr(self.hex_display_parent, 'wheelEvent'):
            self.hex_display_parent.wheelEvent(event)
        else:
            super().wheelEvent(event)


class SignatureScanner(QThread):
    """Thread for scanning file for signature patterns"""
    progress_updated = pyqtSignal(int, int)
    scan_complete = pyqtSignal(list)

    def __init__(self, file_data: bytearray, hex_bytes: bytes, length: int, data_type: str, category_name: str, value_type: str = None, endianness: str = None, reference_tab_index: int = None):
        super().__init__()
        self.file_data = file_data
        self.hex_bytes = hex_bytes
        self.length = length
        self.data_type = data_type
        self.category_name = category_name
        self.value_type = value_type
        self.endianness = endianness if endianness else "LE"
        self.reference_tab_index = reference_tab_index

    def run(self):
        file_size = len(self.file_data)
        bytes_per_row = 16
        total_rows = (file_size + bytes_per_row - 1) // bytes_per_row
        rows_per_chunk = 50

        offset = 0
        found_count = 0
        current_row = 0
        all_pointers = []

        while offset < file_size:
            chunk_start = offset
            chunk_end = min(chunk_start + (rows_per_chunk * bytes_per_row), file_size)

            search_offset = chunk_start
            while search_offset < chunk_end:
                search_offset = self.file_data.find(self.hex_bytes, search_offset, chunk_end)
                if search_offset == -1:
                    break

                value_offset = search_offset + len(self.hex_bytes)
                if value_offset + self.length <= file_size:
                    # For segment type, segment_start is where the pattern was found
                    segment_start = search_offset if self.data_type.lower() == "segment" else value_offset
                    pointer = SignaturePointer(
                        value_offset,
                        self.length,
                        self.data_type,
                        f"Result_{found_count + 1}",
                        category=self.category_name,
                        pattern=self.hex_bytes,
                        segment_start=segment_start,
                        value_type=self.value_type,
                        endianness=self.endianness,
                        reference_tab_index=self.reference_tab_index
                    )
                    all_pointers.append(pointer)
                    found_count += 1

                search_offset += 1

            offset = chunk_end
            current_row = offset // bytes_per_row
            self.progress_updated.emit(current_row, total_rows)
            self.msleep(10)

        self.progress_updated.emit(total_rows, total_rows)
        self.scan_complete.emit(all_pointers)


class SignatureWidget(QWidget):
    """
    Widget for managing user-defined signature pointers.

    This widget provides UI for:
    - Adding signature pointers at selected bytes
    - Bulk scanning for patterns and creating pointers
    - Organizing pointers by category
    - Editing pointer labels and types
    - Toggling overlay visibility
    - Exporting/importing pointer definitions

    Signature pointers overlay the hex display to show interpreted values of
    specific byte sequences. They're useful for reverse engineering file formats,
    tracking important offsets, and documenting binary structures.

    Workflow:
    1. User selects bytes in hex editor
    2. User clicks "Add Current Selection" or uses scan feature
    3. Pointer is created with chosen data type and label
    4. Overlay appears on hex display showing interpreted value
    5. Clicking offset-type overlays jumps to that location

    Signals:
        pointer_added (object): Emitted with SignaturePointer when new pointer added

    Attributes:
        pointers (list): List of SignaturePointer objects
        parent_editor: Reference to parent HexEditorQt instance
        hide_overlay_values (bool): Toggle overlay visibility
        label_editors (dict): Maps pointer offsets to label edit widgets
        string_display_mode (str): How to display string values ('ascii', 'utf8', 'utf16le')
    """
    pointer_added = pyqtSignal(object)

    def __init__(self, parent=None):
        super().__init__(parent)
        self.pointers = []
        self.parent_editor = None
        self.hide_overlay_values = False
        self.label_editors = {}
        self.setup_ui()

    def get_valid_types_for_length(self, length):
        types = ["Hex"]

        if length >= 1:
            types.extend(["int8", "uint8"])
        if length >= 2:
            types.extend(["int16", "uint16", "Offset"])
        if length >= 3:
            types.extend(["int24", "uint24"])
        if length >= 4:
            types.extend(["int32", "uint32", "float32", "Segment", "String (Offset)", "String (Ref.)"])
        if length >= 8:
            types.extend(["int64", "uint64", "float64"])
        if length >= 1:
            types.append("String")

        return types

    def needs_endianness(self, base_type):
        return base_type.lower() in ["int16", "uint16", "int24", "uint24", "int32", "uint32", "int64", "uint64", "float32", "float64"]

    def get_full_type_name(self, base_type, endianness):
        if self.needs_endianness(base_type):
            return f"{base_type} {endianness}"
        return base_type

    def get_length_for_type(self, data_type):
        dtype_lower = data_type.lower()
        base_type = dtype_lower.split()[0]

        type_lengths = {
            "int8": 1, "uint8": 1,
            "int16": 2, "uint16": 2, "offset": 2,
            "int24": 3, "uint24": 3,
            "int32": 4, "uint32": 4, "float32": 4, "segment": 4,
            "int64": 8, "uint64": 8, "float64": 8,
            "hex": 1, "string": 1
        }

        return type_lengths.get(base_type, 4)

    def setup_ui(self):
        layout = QVBoxLayout()
        layout.setContentsMargins(5, 5, 5, 5)

        header_layout = QHBoxLayout()
        title = QLabel("Pointers")
        title.setFont(QFont("Arial", 11, QFont.Bold))
        header_layout.addWidget(title)
        header_layout.addStretch()
        layout.addLayout(header_layout)

        mode_group = QWidget()
        mode_layout = QHBoxLayout()
        mode_layout.setContentsMargins(0, 5, 0, 5)

        mode_label = QLabel("Mode:")
        mode_label.setFont(QFont("Arial", 8))
        mode_layout.addWidget(mode_label)

        self.mode_combo = QComboBox()
        self.mode_combo.addItems(["Selection", "Search"])
        self.mode_combo.currentTextChanged.connect(self.on_mode_changed)
        mode_layout.addWidget(self.mode_combo)

        mode_layout.addSpacing(15)

        self.sel_type_label = QLabel("Type:")
        self.sel_type_label.setFont(QFont("Arial", 8))
        mode_layout.addWidget(self.sel_type_label)

        self.selection_type_combo = QComboBox()
        self.selection_type_combo.setFont(QFont("Arial", 8))
        self.selection_type_combo.addItems(self.get_valid_types_for_length(16))
        self.selection_type_combo.setCurrentText("int32")
        self.selection_type_combo.currentTextChanged.connect(self.on_selection_type_changed)
        mode_layout.addWidget(self.selection_type_combo)

        self.sel_endian_button = QPushButton("LE")
        self.sel_endian_button.setFont(QFont("Arial", 8))
        self.sel_endian_button.setMinimumWidth(35)
        self.sel_endian_button.setMaximumHeight(25)
        self.sel_endian_button.clicked.connect(self.toggle_selection_endianness)
        mode_layout.addWidget(self.sel_endian_button)

        self.sel_endian = "LE"

        self.sel_value_label = QLabel("Value:")
        self.sel_value_label.setFont(QFont("Arial", 8))
        self.sel_value_label.setVisible(False)
        mode_layout.addWidget(self.sel_value_label)

        self.sel_value_combo = QComboBox()
        self.sel_value_combo.setFont(QFont("Arial", 8))
        self.sel_value_combo.addItems(["int", "uint"])
        self.sel_value_combo.setCurrentText("uint")
        self.sel_value_combo.setVisible(False)
        mode_layout.addWidget(self.sel_value_combo)

        self.hex_label = QLabel("Hex Pattern:")
        self.hex_label.setFont(QFont("Arial", 8))
        self.hex_label.setVisible(False)
        mode_layout.addWidget(self.hex_label)

        self.hex_input = QLineEdit()
        self.hex_input.setPlaceholderText("e.g., 48 65 6C 6C 6F")
        self.hex_input.setFont(QFont("Courier", 9))
        self.hex_input.setVisible(False)
        mode_layout.addWidget(self.hex_input)

        mode_layout.addStretch()

        mode_group.setLayout(mode_layout)
        layout.addWidget(mode_group)

        self.sel_ref_widget = QWidget()
        sel_ref_layout = QHBoxLayout()
        sel_ref_layout.setContentsMargins(0, 0, 0, 5)

        self.sel_ref_label = QLabel("Ref Tab:")
        self.sel_ref_label.setFont(QFont("Arial", 8))
        sel_ref_layout.addWidget(self.sel_ref_label)

        self.sel_ref_combo = QComboBox()
        self.sel_ref_combo.setFont(QFont("Arial", 8))
        sel_ref_layout.addWidget(self.sel_ref_combo)

        sel_ref_layout.addStretch()

        self.sel_ref_widget.setLayout(sel_ref_layout)
        self.sel_ref_widget.setVisible(False)
        layout.addWidget(self.sel_ref_widget)

        self.search_widget = QWidget()
        search_layout = QHBoxLayout()
        search_layout.setContentsMargins(0, 0, 0, 5)

        type_label = QLabel("Type:")
        type_label.setFont(QFont("Arial", 8))
        search_layout.addWidget(type_label)

        self.type_combo = QComboBox()
        self.type_combo.setFont(QFont("Arial", 8))
        self.type_combo.addItems(self.get_valid_types_for_length(16))
        self.type_combo.setCurrentText("int32")
        self.type_combo.currentTextChanged.connect(self.on_search_type_changed)
        search_layout.addWidget(self.type_combo)

        self.search_endian_button = QPushButton("LE")
        self.search_endian_button.setFont(QFont("Arial", 8))
        self.search_endian_button.setMinimumWidth(35)
        self.search_endian_button.setMaximumHeight(25)
        self.search_endian_button.clicked.connect(self.toggle_search_endianness)
        search_layout.addWidget(self.search_endian_button)

        self.search_endian = "LE"

        self.search_length_label = QLabel("Length:")
        self.search_length_label.setFont(QFont("Arial", 8))
        self.search_length_label.setVisible(False)
        search_layout.addWidget(self.search_length_label)

        self.search_length_input = QLineEdit()
        self.search_length_input.setPlaceholderText("bytes")
        self.search_length_input.setFont(QFont("Arial", 8))
        self.search_length_input.setMaximumWidth(50)
        self.search_length_input.setText("2")
        self.search_length_input.setVisible(False)
        search_layout.addWidget(self.search_length_input)

        self.search_value_label = QLabel("Value:")
        self.search_value_label.setFont(QFont("Arial", 8))
        self.search_value_label.setVisible(False)
        search_layout.addWidget(self.search_value_label)

        self.search_value_combo = QComboBox()
        self.search_value_combo.setFont(QFont("Arial", 8))
        self.search_value_combo.addItems(["int", "uint"])
        self.search_value_combo.setCurrentText("uint")
        self.search_value_combo.setVisible(False)
        search_layout.addWidget(self.search_value_combo)

        self.search_ref_label = QLabel("Ref Tab:")
        self.search_ref_label.setFont(QFont("Arial", 8))
        self.search_ref_label.setVisible(False)
        search_layout.addWidget(self.search_ref_label)

        self.search_ref_combo = QComboBox()
        self.search_ref_combo.setFont(QFont("Arial", 8))
        self.search_ref_combo.setVisible(False)
        search_layout.addWidget(self.search_ref_combo)

        search_layout.addStretch()

        self.search_widget.setLayout(search_layout)
        self.search_widget.setVisible(False)
        layout.addWidget(self.search_widget)

        self.add_pointer_button = QPushButton("Add Pointer")
        self.add_pointer_button.clicked.connect(self.add_pointer)
        self.add_pointer_button.setFont(QFont("Arial", 9, QFont.Bold))
        layout.addWidget(self.add_pointer_button)

        self.progress_bar = QProgressBar()
        self.progress_bar.setVisible(False)
        layout.addWidget(self.progress_bar)

        list_header_layout = QHBoxLayout()
        list_header_layout.setContentsMargins(0, 5, 0, 0)

        self.list_label = QLabel("Active Pointers: 0")
        self.list_label.setFont(QFont("Arial", 9))
        list_header_layout.addWidget(self.list_label)

        self.hide_values_checkbox = QCheckBox("Hide Values")
        self.hide_values_checkbox.setFont(QFont("Arial", 8))
        self.hide_values_checkbox.setStyleSheet("""
            QCheckBox {
                color: white;
                spacing: 5px;
            }
            QCheckBox::indicator {
                width: 13px;
                height: 13px;
                border: 1px solid #666;
                background-color: #2b2b2b;
                border-radius: 2px;
            }
            QCheckBox::indicator:checked {
                background-color: #4a9eff;
                border: 1px solid #4a9eff;
            }
        """)
        self.hide_values_checkbox.stateChanged.connect(self.on_hide_values_changed)
        list_header_layout.addWidget(self.hide_values_checkbox)

        self.string_display_mode = "ascii"

        list_header_layout.addStretch()
        layout.addLayout(list_header_layout)

        self.pointer_tree = QTreeWidget()
        self.pointer_tree.setHeaderLabels(["Label", "Offset", "Type", "Value"])
        self.pointer_tree.setIndentation(15)
        self.pointer_tree.setColumnWidth(0, 80)
        self.pointer_tree.setColumnWidth(1, 70)
        self.pointer_tree.setColumnWidth(2, 80)
        self.pointer_tree.setColumnWidth(3, 100)
        self.pointer_tree.itemClicked.connect(self.on_pointer_clicked)
        self.pointer_tree.setContextMenuPolicy(Qt.CustomContextMenu)
        self.pointer_tree.customContextMenuRequested.connect(self.on_pointer_context_menu)
        layout.addWidget(self.pointer_tree)

        self.status_label = QLabel("Ready")
        self.status_label.setFont(QFont("Arial", 9))
        layout.addWidget(self.status_label)

        self.setLayout(layout)

    def on_mode_changed(self, mode):
        is_search = mode == "Search"

        self.sel_type_label.setVisible(not is_search)
        self.selection_type_combo.setVisible(not is_search)
        self.sel_endian_button.setVisible(not is_search)
        self.hex_label.setVisible(is_search)
        self.hex_input.setVisible(is_search)
        self.sel_ref_widget.setVisible(False)
        self.sel_value_label.setVisible(False)
        self.sel_value_combo.setVisible(False)

        self.search_widget.setVisible(is_search)

        if is_search:
            self.on_search_type_changed(self.type_combo.currentText())
        else:
            self.on_selection_type_changed(self.selection_type_combo.currentText())

    def add_pointer(self):
        if not self.parent_editor or self.parent_editor.current_tab_index < 0:
            self.status_label.setText("No file open")
            return

        current_file = self.parent_editor.open_files[self.parent_editor.current_tab_index]
        file_data = current_file.file_data

        mode = self.mode_combo.currentText()
        new_pointers = []

        if mode == "Selection":
            if self.parent_editor.selection_start is None or self.parent_editor.selection_end is None:
                self.status_label.setText("No bytes selected")
                return

            base_type = self.selection_type_combo.currentText()
            data_type = self.get_full_type_name(base_type, self.sel_endian)

            if self.parent_editor.column_selection_mode and self.parent_editor.column_sel_start_row is not None:
                min_row = min(self.parent_editor.column_sel_start_row, self.parent_editor.column_sel_end_row)
                max_row = max(self.parent_editor.column_sel_start_row, self.parent_editor.column_sel_end_row)
                min_col = min(self.parent_editor.column_sel_start_col, self.parent_editor.column_sel_end_col)
                max_col = max(self.parent_editor.column_sel_start_col, self.parent_editor.column_sel_end_col)

                sel_start = min_row * self.parent_editor.bytes_per_row + min_col
                num_rows = max_row - min_row + 1
                num_cols = max_col - min_col + 1
                selection_length = num_rows * num_cols
            else:
                sel_start = min(self.parent_editor.selection_start, self.parent_editor.selection_end)
                sel_end = max(self.parent_editor.selection_start, self.parent_editor.selection_end)
                selection_length = sel_end - sel_start + 1

            length = selection_length

            pattern_bytes = bytes(file_data[sel_start:sel_start + length]) if sel_start + length <= len(file_data) else b''

            value_type = None
            segment_start = sel_start
            endianness = self.sel_endian
            reference_tab_index = None

            if base_type.lower() == "segment":
                value_type = self.sel_value_combo.currentText()

            # Get selected reference tab if String (Ref.) type
            if base_type.lower() == "string (ref.)":
                if self.sel_ref_combo.count() == 0:
                    self.status_label.setText("No reference tabs available")
                    return
                reference_tab_index = self.sel_ref_combo.currentData()
                if reference_tab_index is None:
                    self.status_label.setText("Please select a reference tab")
                    return

            pointer = SignaturePointer(sel_start, length, data_type, f"Selection_{sel_start:X}", category="Custom", pattern=pattern_bytes, segment_start=segment_start, value_type=value_type, endianness=endianness, reference_tab_index=reference_tab_index)
            new_pointers.append(pointer)

        else:
            hex_pattern = self.hex_input.text().strip()
            if not hex_pattern:
                self.status_label.setText("Enter a hex pattern")
                return

            try:
                hex_bytes = bytes.fromhex(hex_pattern.replace(" ", ""))
            except ValueError:
                self.status_label.setText("Invalid hex pattern")
                return

            base_type = self.type_combo.currentText()
            data_type = self.get_full_type_name(base_type, self.search_endian)

            if base_type.lower() in ["offset", "string", "string (offset)", "string (ref.)", "hex", "segment"]:
                try:
                    length = int(self.search_length_input.text())
                    if length <= 0:
                        self.status_label.setText("Length must be positive")
                        return
                except ValueError:
                    self.status_label.setText("Invalid length")
                    return
            else:
                length = self.get_length_for_type(data_type)

            category_name = hex_pattern

            value_type = None
            endianness = self.search_endian
            reference_tab_index = None

            if base_type.lower() == "segment":
                value_type = self.search_value_combo.currentText()

            # Get selected reference tab if String (Ref.) type
            if base_type.lower() == "string (ref.)":
                if self.search_ref_combo.count() == 0:
                    self.status_label.setText("No reference tabs available")
                    return
                reference_tab_index = self.search_ref_combo.currentData()
                if reference_tab_index is None:
                    self.status_label.setText("Please select a reference tab")
                    return

            self.add_pointer_button.setEnabled(False)
            self.progress_bar.setVisible(True)
            self.progress_bar.setValue(0)
            self.status_label.setText("Searching...")

            self.scanning_tab_index = self.parent_editor.current_tab_index

            self.scanner = SignatureScanner(file_data, hex_bytes, length, data_type, category_name, value_type, endianness, reference_tab_index)
            self.scanner.progress_updated.connect(self.on_scan_progress)
            self.scanner.scan_complete.connect(self.on_scan_complete)

            self.scanner.start()
            return

        for pointer in new_pointers:
            pointer.value = self.interpret_value(file_data, pointer.offset, pointer.length, pointer.data_type, self.string_display_mode, pointer)

            self.pointers.append(pointer)

            self.pointer_added.emit(pointer)

        self.rebuild_tree()

        if len(new_pointers) == 1:
            self.status_label.setText(f"Pointer added at 0x{new_pointers[0].offset:X}")
            pointer = new_pointers[0]
            self.parent_editor.scroll_to_offset(pointer.offset, center=True)
            self.parent_editor.selection_start = pointer.offset
            self.parent_editor.selection_end = pointer.offset + pointer.length - 1
            self.parent_editor.display_hex(preserve_scroll=True)
        else:
            self.status_label.setText(f"{len(new_pointers)} pointers added")
            if new_pointers:
                pointer = new_pointers[0]
                self.parent_editor.scroll_to_offset(pointer.offset, center=True)
                self.parent_editor.selection_start = pointer.offset
                self.parent_editor.selection_end = pointer.offset + pointer.length - 1
                self.parent_editor.display_hex(preserve_scroll=True)

    def on_scan_progress(self, current_row, total_rows):
        try:
            if not hasattr(self, 'scanning_tab_index') or self.parent_editor.current_tab_index != self.scanning_tab_index:
                return

            percentage = int((current_row / total_rows) * 100) if total_rows > 0 else 0
            self.progress_bar.setValue(percentage)
            self.progress_bar.setFormat(f"Scanning: {current_row:,} / {total_rows:,} rows ({percentage}%)")
        except RuntimeError:
            pass

    def on_scan_complete(self, all_pointers):
        try:
            if not all_pointers:
                if hasattr(self, 'scanning_tab_index') and self.parent_editor.current_tab_index == self.scanning_tab_index:
                    self.progress_bar.setVisible(False)
                    self.add_pointer_button.setEnabled(True)
                    self.status_label.setText("Pattern not found")
                return

            if hasattr(self, 'scanning_tab_index') and self.parent_editor.current_tab_index == self.scanning_tab_index:
                self.status_label.setText(f"Scan complete, loading pointers...")
                self.progress_bar.setValue(0)
                self.progress_bar.setFormat(f"Loading: 0 / {len(all_pointers):,} pointers")

            self.pending_pointers = all_pointers
            self.total_pointers_found = len(all_pointers)
            self.pointers_loaded = 0

            self.process_pending_pointers()
        except RuntimeError:
            pass

    def process_pending_pointers(self):
        if not self.pending_pointers:
            return

        if not hasattr(self, 'scanning_tab_index'):
            return

        if self.scanning_tab_index < 0 or self.scanning_tab_index >= len(self.parent_editor.open_files):
            return

        scan_file = self.parent_editor.open_files[self.scanning_tab_index]
        file_data = scan_file.file_data

        batch_size = 5
        process_count = min(batch_size, len(self.pending_pointers))

        for _ in range(process_count):
            if not self.pending_pointers:
                break

            pointer = self.pending_pointers.pop(0)
            pointer.value = self.interpret_value(file_data, pointer.offset, pointer.length, pointer.data_type, self.string_display_mode, pointer)
            self.pointers.append(pointer)
            self.pointer_added.emit(pointer)
            self.pointers_loaded += 1

        try:
            on_same_tab = self.parent_editor.current_tab_index == self.scanning_tab_index
            if on_same_tab:
                self.progress_bar.setValue(int((self.pointers_loaded / self.total_pointers_found) * 100))
                self.progress_bar.setFormat(f"Loading: {self.pointers_loaded:,} / {self.total_pointers_found:,} pointers")
        except RuntimeError:
            return

        if self.pending_pointers:
            QTimer.singleShot(10, self.process_pending_pointers)
        else:
            self.rebuild_tree()

            try:
                if on_same_tab:
                    self.progress_bar.setVisible(False)
                    self.add_pointer_button.setEnabled(True)
                    self.status_label.setText(f"{self.pointers_loaded:,} pointers loaded")

                    if self.pointers:
                        self.parent_editor.scroll_to_offset(self.pointers[0].offset, center=True)
            except RuntimeError:
                pass

    def interpret_value(self, data, offset, length, data_type, string_mode="ascii", pointer=None):
        """This method is quite long - see full implementation in original file"""
        if offset + length > len(data):
            return "N/A"

        value_bytes = bytes(data[offset:offset+length])

        try:
            dtype_lower = data_type.lower()

            if not (dtype_lower == "hex" or dtype_lower == "string" or dtype_lower.startswith("offset")):
                expected_lengths = {
                    "int8": 1, "uint8": 1,
                    "int16 le": 2, "uint16 le": 2, "int16 be": 2, "uint16 be": 2,
                    "int24 le": 3, "uint24 le": 3, "int24 be": 3, "uint24 be": 3,
                    "int32 le": 4, "uint32 le": 4, "int32 be": 4, "uint32 be": 4,
                    "int64 le": 8, "uint64 le": 8, "int64 be": 8, "uint64 be": 8,
                    "float32 le": 4, "float32 be": 4,
                    "float64 le": 8, "float64 be": 8,
                }
                expected_length = expected_lengths.get(dtype_lower)
                if expected_length is not None and length != expected_length:
                    return "N/A"

            if dtype_lower == "hex":
                return " ".join(f"{b:02X}" for b in value_bytes)
            elif dtype_lower == "int8":
                return struct.unpack('b', value_bytes[:1])[0]
            elif dtype_lower == "uint8":
                return struct.unpack('B', value_bytes[:1])[0]
            elif dtype_lower == "int16 le":
                return struct.unpack('<h', value_bytes[:2])[0]
            elif dtype_lower == "uint16 le":
                return struct.unpack('<H', value_bytes[:2])[0]
            elif dtype_lower == "int16 be":
                return struct.unpack('>h', value_bytes[:2])[0]
            elif dtype_lower == "uint16 be":
                return struct.unpack('>H', value_bytes[:2])[0]
            elif dtype_lower == "int24 le":
                extended = value_bytes[:3] + (b'\xff' if value_bytes[2] & 0x80 else b'\x00')
                return struct.unpack('<i', extended)[0] >> 8
            elif dtype_lower == "uint24 le":
                extended = value_bytes[:3] + b'\x00'
                return struct.unpack('<I', extended)[0]
            elif dtype_lower == "int24 be":
                extended = (b'\xff' if value_bytes[0] & 0x80 else b'\x00') + value_bytes[:3]
                return struct.unpack('>i', extended)[0] >> 8
            elif dtype_lower == "uint24 be":
                extended = b'\x00' + value_bytes[:3]
                return struct.unpack('>I', extended)[0]
            elif dtype_lower == "int32 le":
                return struct.unpack('<i', value_bytes[:4])[0]
            elif dtype_lower == "uint32 le":
                return struct.unpack('<I', value_bytes[:4])[0]
            elif dtype_lower == "int32 be":
                return struct.unpack('>i', value_bytes[:4])[0]
            elif dtype_lower == "uint32 be":
                return struct.unpack('>I', value_bytes[:4])[0]
            elif dtype_lower == "int64 le":
                return struct.unpack('<q', value_bytes[:8])[0]
            elif dtype_lower == "uint64 le":
                return struct.unpack('<Q', value_bytes[:8])[0]
            elif dtype_lower == "int64 be":
                return struct.unpack('>q', value_bytes[:8])[0]
            elif dtype_lower == "uint64 be":
                return struct.unpack('>Q', value_bytes[:8])[0]
            elif dtype_lower == "float32 le":
                val = struct.unpack('<f', value_bytes[:4])[0]
                return f"{val:.3f}"
            elif dtype_lower == "float32 be":
                val = struct.unpack('>f', value_bytes[:4])[0]
                return f"{val:.3f}"
            elif dtype_lower == "float64 le":
                val = struct.unpack('<d', value_bytes[:8])[0]
                return f"{val:.3f}"
            elif dtype_lower == "float64 be":
                val = struct.unpack('>d', value_bytes[:8])[0]
                return f"{val:.3f}"
            elif dtype_lower == "offset":
                hex_str = ''.join(f'{b:02X}' for b in value_bytes)
                return format(int(hex_str, 16), 'X')
            elif dtype_lower == "segment":
                # Segment type: interpret based on value_type (int/uint) and endianness
                value_type = pointer.value_type if (pointer and hasattr(pointer, 'value_type') and pointer.value_type) else "uint"
                endianness = pointer.endianness if (pointer and hasattr(pointer, 'endianness') and pointer.endianness) else "LE"
                is_signed = value_type.lower() == "int"
                is_little = endianness == "LE"

                segment_value = 0
                try:
                    if length == 1:
                        segment_value = struct.unpack('b' if is_signed else 'B', value_bytes[:1])[0]
                    elif length == 2:
                        fmt = ('<h' if is_little else '>h') if is_signed else ('<H' if is_little else '>H')
                        segment_value = struct.unpack(fmt, value_bytes[:2])[0]
                    elif length == 4:
                        fmt = ('<i' if is_little else '>i') if is_signed else ('<I' if is_little else '>I')
                        segment_value = struct.unpack(fmt, value_bytes[:4])[0]
                    elif length == 8:
                        fmt = ('<q' if is_little else '>q') if is_signed else ('<Q' if is_little else '>Q')
                        segment_value = struct.unpack(fmt, value_bytes[:8])[0]
                    else:
                        return "N/A"
                except (struct.error, IndexError):
                    return "N/A"

                # Calculate segment range
                segment_start = pointer.segment_start if (pointer and hasattr(pointer, 'segment_start')) else offset
                segment_end = segment_start + segment_value - 1 if segment_value > 0 else segment_start

                # Return formatted string: start-end: value
                return f"0x{segment_start:X}-0x{segment_end:X}: {segment_value}"
            elif dtype_lower == "string":
                # String: always display ASCII from the bytes at this location
                try:
                    decoded = value_bytes.decode('latin-1', errors='ignore')
                    result = ""
                    for char in decoded:
                        char_code = ord(char)
                        if (32 <= char_code <= 126) or (160 <= char_code <= 255):
                            result += char
                        else:
                            result += "."
                    return result if result else "N/A"
                except:
                    return "N/A"
            elif dtype_lower == "string (offset)":
                # String (Offset): read bytes as offset, then extract string from that offset
                try:
                    hex_str = ''.join(f'{b:02X}' for b in value_bytes)
                    target_offset = int(hex_str, 16)

                    if target_offset >= len(data):
                        return "N/A"

                    max_len = min(100, len(data) - target_offset)
                    string_bytes = data[target_offset:target_offset + max_len]

                    null_pos = -1
                    for i, b in enumerate(string_bytes):
                        if b == 0x00:
                            null_pos = i
                            break

                    if null_pos > 0:
                        string_bytes = string_bytes[:null_pos]

                    result = ""
                    for byte in string_bytes:
                        if (32 <= byte <= 126) or (160 <= byte <= 255):
                            result += chr(byte)
                        else:
                            result += "."

                    return result if result else "N/A"
                except:
                    return "N/A"
            elif dtype_lower == "string (ref.)":
                # String (Ref.): read bytes as offset, extract string from reference tab at that offset
                try:
                    hex_str = ''.join(f'{b:02X}' for b in value_bytes)
                    target_offset = int(hex_str, 16)

                    # Get the reference tab data from the pointer
                    if not (pointer and hasattr(pointer, 'reference_tab_index')):
                        return "N/A"

                    ref_tab_index = pointer.reference_tab_index
                    if ref_tab_index is None:
                        return "N/A"

                    # Check if parent editor exists and has the reference tab
                    if not self.parent_editor or ref_tab_index < 0 or ref_tab_index >= len(self.parent_editor.open_files):
                        return "N/A"

                    ref_data = self.parent_editor.open_files[ref_tab_index].file_data

                    if target_offset >= len(ref_data):
                        return "N/A"

                    # Search backwards from target_offset to find the start of the string
                    string_start = target_offset
                    while string_start > 0:
                        prev_byte = ref_data[string_start - 1]
                        # Stop if we hit a null byte or non-printable character
                        if prev_byte == 0x00 or not ((32 <= prev_byte <= 126) or (160 <= prev_byte <= 255)):
                            break
                        string_start -= 1

                    # Extract string from start to null terminator or max length
                    max_len = min(100, len(ref_data) - string_start)
                    string_bytes = ref_data[string_start:string_start + max_len]

                    null_pos = -1
                    for i, b in enumerate(string_bytes):
                        if b == 0x00:
                            null_pos = i
                            break

                    if null_pos > 0:
                        string_bytes = string_bytes[:null_pos]

                    result = ""
                    for byte in string_bytes:
                        if (32 <= byte <= 126) or (160 <= byte <= 255):
                            result += chr(byte)
                        else:
                            result += "."

                    return result if result else "N/A"
                except:
                    return "N/A"
            else:
                return "N/A"
        except (struct.error, IndexError, ValueError) as e:
            return "N/A"

    def on_pointer_label_changed(self, pointer, line_edit):
        new_label = line_edit.text().strip()
        pointer.label = new_label

    def rebuild_tree(self):
        self.pointer_tree.clear()
        self.label_editors.clear()

        categories = {}
        for pointer in self.pointers:
            if pointer.category not in categories:
                categories[pointer.category] = []
            categories[pointer.category].append(pointer)

        for category_name, pointers_list in categories.items():
            category_item = QTreeWidgetItem(self.pointer_tree)
            category_item.setText(0, category_name)
            category_item.setTextAlignment(0, Qt.AlignCenter)
            category_item.setText(1, f"({len(pointers_list)} items)")
            category_item.setExpanded(True)

            for pointer in pointers_list:
                self.add_pointer_to_category(pointer, category_item)

        self.update_pointer_count()

    def update_pointer_count(self):
        count = len(self.pointers)
        self.list_label.setText(f"Active Pointers: {count}")

    def locate_pointer_in_tree(self, pointer):
        root = self.pointer_tree.invisibleRootItem()
        for i in range(root.childCount()):
            category_item = root.child(i)
            for j in range(category_item.childCount()):
                item = category_item.child(j)
                item_pointer = item.data(0, Qt.UserRole)
                if item_pointer is pointer:
                    category_item.setExpanded(True)
                    self.pointer_tree.setCurrentItem(item)
                    self.pointer_tree.scrollToItem(item)
                    return

    def toggle_selection_endianness(self):
        if self.sel_endian == "LE":
            self.sel_endian = "BE"
            self.sel_endian_button.setText("BE")
        else:
            self.sel_endian = "LE"
            self.sel_endian_button.setText("LE")

    def toggle_search_endianness(self):
        if self.search_endian == "LE":
            self.search_endian = "BE"
            self.search_endian_button.setText("BE")
        else:
            self.search_endian = "LE"
            self.search_endian_button.setText("LE")

    def on_selection_type_changed(self, type_text):
        type_lower = type_text.lower()
        is_segment = type_lower == "segment"
        is_string_ref = type_lower == "string (ref.)"

        self.sel_endian_button.setVisible(self.needs_endianness(type_text) or is_segment)

        self.sel_value_label.setVisible(is_segment)
        self.sel_value_combo.setVisible(is_segment)

        self.sel_ref_widget.setVisible(is_string_ref)
        if is_string_ref:
            self.update_ref_combos()

    def on_search_type_changed(self, type_text):
        type_lower = type_text.lower()
        needs_length = type_lower in ["offset", "string", "string (offset)", "string (ref.)", "hex", "segment"]
        is_segment = type_lower == "segment"
        is_string_ref = type_lower == "string (ref.)"

        self.search_length_label.setVisible(needs_length)
        self.search_length_input.setVisible(needs_length)

        self.search_value_label.setVisible(is_segment)
        self.search_value_combo.setVisible(is_segment)

        self.search_ref_label.setVisible(is_string_ref)
        self.search_ref_combo.setVisible(is_string_ref)
        if is_string_ref:
            self.update_ref_combos()

        if needs_length:
            if type_lower in ["offset", "segment", "string (offset)", "string (ref.)"]:
                self.search_length_input.setPlaceholderText("bytes")
                if not self.search_length_input.text():
                    self.search_length_input.setText("4")
            else:
                self.search_length_input.setPlaceholderText("bytes")
                if not self.search_length_input.text():
                    self.search_length_input.setText("1")

        self.search_endian_button.setVisible((not needs_length and self.needs_endianness(type_text)) or is_segment)

    def on_hide_values_changed(self, state):
        self.hide_overlay_values = (state == Qt.Checked)

        if self.parent_editor and hasattr(self.parent_editor, 'signature_overlays'):
            for overlay in self.parent_editor.signature_overlays:
                overlay.setVisible(not self.hide_overlay_values)

    def update_ref_combos(self):
        """Update the reference tab combo boxes with available tabs"""
        if not self.parent_editor or not self.parent_editor.open_files:
            return

        import os

        # Clear both combos
        self.sel_ref_combo.clear()
        self.search_ref_combo.clear()

        # Add all open tabs except the current one
        for i, file_tab in enumerate(self.parent_editor.open_files):
            if i != self.parent_editor.current_tab_index:
                tab_name = os.path.basename(file_tab.file_path)
                self.sel_ref_combo.addItem(f"{i}: {tab_name}", i)
                self.search_ref_combo.addItem(f"{i}: {tab_name}", i)

    def add_pointer_to_category(self, pointer, category_item):
        item = QTreeWidgetItem(category_item)

        label_edit = QLineEdit()
        label_edit.setText(pointer.label if pointer.label else "")
        label_edit.setPlaceholderText("Enter label...")
        label_edit.setFrame(False)
        label_edit.setFont(QFont("Arial", 8))
        label_edit.setStyleSheet("QLineEdit { background: transparent; }")
        label_edit.returnPressed.connect(lambda p=pointer, le=label_edit: self.on_pointer_label_changed(p, le))
        label_edit.editingFinished.connect(lambda p=pointer, le=label_edit: self.on_pointer_label_changed(p, le))

        pointer_id = (pointer.offset, pointer.length)
        self.label_editors[pointer_id] = label_edit

        item.setText(1, f"0x{pointer.offset:X}")
        item.setText(2, pointer.data_type)

        if pointer.data_type.lower() == "string" and pointer.custom_value:
            item.setText(3, pointer.custom_value)
        elif pointer.data_type.lower().startswith("offset"):
            if self.parent_editor and self.parent_editor.current_tab_index >= 0:
                current_file = self.parent_editor.open_files[self.parent_editor.current_tab_index]
                hex_bytes = current_file.file_data[pointer.offset:pointer.offset + pointer.length]
                hex_str = " ".join(f"{b:02x}" for b in hex_bytes)
                value_str = f"{hex_str}: ({pointer.value})"
                item.setText(3, value_str)
            else:
                item.setText(3, str(pointer.value))
        else:
            item.setText(3, str(pointer.value))

        item.setData(0, Qt.UserRole, pointer)
        self.pointer_tree.setItemWidget(item, 0, label_edit)

    def on_pointer_clicked(self, item, column):
        pointer = item.data(0, Qt.UserRole)
        if isinstance(pointer, SignaturePointer) and self.parent_editor:
            self.parent_editor.scroll_to_offset(pointer.offset, center=True)
            self.parent_editor.selection_start = pointer.offset
            self.parent_editor.selection_end = pointer.offset + pointer.length - 1
            self.parent_editor.display_hex(preserve_scroll=True)

    def on_pointer_context_menu(self, position):
        item = self.pointer_tree.itemAt(position)
        if item:
            pointer = item.data(0, Qt.UserRole)
            if isinstance(pointer, SignaturePointer):
                menu = QMenu()
                edit_action = menu.addAction("Edit Value")
                delete_action = menu.addAction("Delete Pointer")
                action = menu.exec_(self.pointer_tree.viewport().mapToGlobal(position))

                if action == edit_action:
                    self.edit_pointer_value(pointer, item)
                elif action == delete_action:
                    self.delete_pointer(pointer, item)

    def edit_pointer_value(self, pointer, item):
        if not self.parent_editor or self.parent_editor.current_tab_index < 0:
            return

        current_file = self.parent_editor.open_files[self.parent_editor.current_tab_index]
        file_data = current_file.file_data

        new_value, ok = QInputDialog.getText(
            self,
            "Edit Value",
            f"Enter new value for {pointer.label} ({pointer.data_type}):",
            text=str(pointer.value)
        )

        if ok and new_value:
            try:
                new_bytes = self.value_to_bytes(new_value, pointer.data_type, pointer.length, pointer)
                if new_bytes:
                    for i, byte in enumerate(new_bytes):
                        if pointer.offset + i < len(file_data):
                            file_data[pointer.offset + i] = byte

                    pointer.value = self.interpret_value(file_data, pointer.offset, pointer.length, pointer.data_type, self.string_display_mode, pointer)

                    self.rebuild_tree()

                    self.parent_editor.display_hex(preserve_scroll=True)
                    self.status_label.setText(f"Updated value at 0x{pointer.offset:X}")
                else:
                    self.status_label.setText("Invalid value for type")
            except Exception as e:
                self.status_label.setText(f"Error: {str(e)}")

    def value_to_bytes(self, value_str, data_type, length, pointer=None):
        """Convert string value to bytes - see full implementation in original file"""
        if value_str == "N/A":
            return None

        dtype_lower = data_type.lower()

        try:
            if dtype_lower == "hex":
                hex_clean = value_str.replace(" ", "")
                return bytes.fromhex(hex_clean)[:length]
            elif dtype_lower == "int8":
                return struct.pack('b', int(value_str))
            elif dtype_lower == "uint8":
                return struct.pack('B', int(value_str))
            elif dtype_lower == "int16 le":
                return struct.pack('<h', int(value_str))
            elif dtype_lower == "uint16 le":
                return struct.pack('<H', int(value_str))
            elif dtype_lower == "int16 be":
                return struct.pack('>h', int(value_str))
            elif dtype_lower == "uint16 be":
                return struct.pack('>H', int(value_str))
            elif dtype_lower == "int32 le":
                return struct.pack('<i', int(value_str))
            elif dtype_lower == "uint32 le":
                return struct.pack('<I', int(value_str))
            elif dtype_lower == "int32 be":
                return struct.pack('>i', int(value_str))
            elif dtype_lower == "uint32 be":
                return struct.pack('>I', int(value_str))
            elif dtype_lower == "int64 le":
                return struct.pack('<q', int(value_str))
            elif dtype_lower == "uint64 le":
                return struct.pack('<Q', int(value_str))
            elif dtype_lower == "int64 be":
                return struct.unpack('>q', int(value_str))
            elif dtype_lower == "uint64 be":
                return struct.pack('>Q', int(value_str))
            elif dtype_lower == "float32 le":
                return struct.pack('<f', float(value_str))
            elif dtype_lower == "float32 be":
                return struct.pack('>f', float(value_str))
            elif dtype_lower == "float64 le":
                return struct.pack('<d', float(value_str))
            elif dtype_lower == "float64 be":
                return struct.pack('>d', float(value_str))
            elif dtype_lower == "offset":
                hex_str = value_str.strip().upper()

                if len(hex_str) % 2 != 0:
                    hex_str = '0' + hex_str

                result_bytes = bytes.fromhex(hex_str)

                if len(result_bytes) < length:
                    result_bytes += b'\x00' * (length - len(result_bytes))

                return result_bytes[:length]
            elif dtype_lower == "segment":
                # Segment type: pack based on value_type (int/uint), endianness, and length
                value_type = pointer.value_type if (pointer and hasattr(pointer, 'value_type') and pointer.value_type) else "uint"
                endianness = pointer.endianness if (pointer and hasattr(pointer, 'endianness') and pointer.endianness) else "LE"
                is_signed = value_type.lower() == "int"
                is_little = endianness == "LE"
                int_val = int(value_str)

                if length == 1:
                    return struct.pack('b' if is_signed else 'B', int_val)
                elif length == 2:
                    fmt = ('<h' if is_little else '>h') if is_signed else ('<H' if is_little else '>H')
                    return struct.pack(fmt, int_val)
                elif length == 4:
                    fmt = ('<i' if is_little else '>i') if is_signed else ('<I' if is_little else '>I')
                    return struct.pack(fmt, int_val)
                elif length == 8:
                    fmt = ('<q' if is_little else '>q') if is_signed else ('<Q' if is_little else '>Q')
                    return struct.pack(fmt, int_val)
                else:
                    return None
            elif dtype_lower == "string":
                encoded = value_str.encode('utf-8')
                if len(encoded) < length:
                    encoded += b'\x00' * (length - len(encoded))
                return encoded[:length]
            else:
                return None
        except (ValueError, struct.error, OverflowError):
            return None

    def delete_pointer(self, pointer, item):
        if pointer in self.pointers:
            self.pointers.remove(pointer)
        self.status_label.setText(f"Deleted pointer at 0x{pointer.offset:X}")

        self.rebuild_tree()

        if self.parent_editor:
            self.parent_editor.display_hex(preserve_scroll=True)

    def set_file_data(self, file_data: bytearray):
        self.pointers.clear()
        self.pointer_tree.clear()
        self.update_pointer_count()
        self.status_label.setText("Ready")
