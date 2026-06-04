"""
Data Inspector Module
======================

This module provides the DataInspector class which interprets raw bytes at a given
position into multiple data type representations.

The DataInspector supports a wide range of data types and formats:
- Integers: int8, uint8, int16, uint16, int24, uint24, int32, uint32, int64, uint64
- Variable-length integers: LEB128 (signed), ULEB128 (unsigned)
- Floating-point: float32, float64
- Characters: AnsiChar, WideChar (UTF-16), UTF-8 code points
- Timestamps: DOS date/time, Windows FILETIME, Unix time_t, OLETIME
- GUIDs: 128-bit globally unique identifiers
- Disassembly: x86-16, x86-32, x86-64 (requires Capstone library)

Each data type can be edited in-place, and changes are written back to the file data.
"""

import ctypes
import math
import struct
import sys
from PyQt5.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QLabel, QLineEdit, QTabWidget,
    QPushButton, QColorDialog, QComboBox, QMessageBox
)
from PyQt5.QtGui import QFont, QColor
from PyQt5.QtCore import Qt, QTimer
from editor_themes import get_theme_colors, get_theme_surface_colors


class _InspectorExpressionParser:
    """Small safe parser for inspector math: +, -, *, /, ^, %, parentheses."""

    def __init__(self, text, default_float=False):
        self.text = text
        self.default_float = default_float
        self.index = 0

    def parse(self):
        value = self.parse_expression()
        if self.index != len(self.text):
            raise ValueError(f"Unexpected token: {self.text[self.index:]}")
        if not math.isfinite(float(value)):
            raise ValueError("Expression result is not finite")
        return value

    def peek(self):
        return self.text[self.index] if self.index < len(self.text) else ''

    def consume(self, char):
        if self.peek() == char:
            self.index += 1
            return True
        return False

    def parse_expression(self):
        value = self.parse_term()
        while True:
            if self.consume('+'):
                value += self.parse_term()
            elif self.consume('-'):
                value -= self.parse_term()
            else:
                return value

    def parse_term(self):
        value = self.parse_power()
        while True:
            if self.consume('*'):
                value *= self.parse_power()
            elif self.consume('/'):
                divisor = self.parse_power()
                if divisor == 0:
                    raise ValueError("Cannot divide by zero")
                value /= divisor
            elif self.starts_implicit_factor():
                value *= self.parse_power()
            else:
                return value

    def parse_power(self):
        value = self.parse_unary()
        if self.consume('^'):
            value = value ** self.parse_power()
        return value

    def parse_unary(self):
        if self.consume('+'):
            return self.parse_unary()
        if self.consume('-'):
            return -self.parse_unary()
        return self.parse_postfix()

    def parse_postfix(self):
        value = self.parse_primary()
        while self.consume('%'):
            value /= 100.0
        return value

    def parse_primary(self):
        if self.consume('('):
            value = self.parse_expression()
            if not self.consume(')'):
                raise ValueError("Missing closing parenthesis")
            return value
        return self.parse_number()

    def starts_implicit_factor(self):
        char = self.peek()
        return char == '(' or char.isdigit() or char == '.'

    def parse_number(self):
        start = self.index
        if self.text.startswith(('0x', '0X'), self.index):
            self.index += 2
            while self.peek() and self.peek() in '0123456789abcdefABCDEF':
                self.index += 1
            if self.index == start + 2:
                raise ValueError("Invalid hex number")
            return int(self.text[start:self.index], 16)

        has_dot = False
        while self.peek() and (self.peek().isdigit() or self.peek() == '.'):
            if self.peek() == '.':
                if has_dot:
                    raise ValueError("Invalid number")
                has_dot = True
            self.index += 1

        if self.peek() and self.peek() in 'eE':
            has_dot = True
            self.index += 1
            if self.peek() in '+-':
                self.index += 1
            exponent_start = self.index
            while self.peek() and self.peek().isdigit():
                self.index += 1
            if self.index == exponent_start:
                raise ValueError("Invalid exponent")

        if self.index == start:
            raise ValueError("Expected number")

        token = self.text[start:self.index]
        if self.default_float or has_dot:
            return float(token)
        return int(token, 10)


class DataInspector:
    """
    Data Inspector for Hex Editor

    This class provides comprehensive data interpretation at the cursor position.
    It displays bytes interpreted as various data types and allows editing values
    to modify the underlying bytes.

    Attributes:
        editor: Reference to the parent HexEditorQt instance
        inspector_content_layout: QVBoxLayout containing all inspector field widgets

    Supported Data Types:
        - Byte (hex): Single byte in hexadecimal
        - Integers: Signed and unsigned in various sizes (8, 16, 24, 32, 64 bits)
        - LEB128/ULEB128: Variable-length integer encodings
        - Characters: ANSI (8-bit), Wide (16-bit), UTF-8
        - Floats: Single (32-bit), Double (64-bit)
        - Timestamps: DOS date/time, FILETIME, OLETIME, Unix time_t
        - GUID: 128-bit globally unique identifier
        - Disassembly: x86 machine code (16/32/64-bit)
    """

    def __init__(self, editor):
        """
        Initialize the DataInspector.

        Args:
            editor: Parent HexEditorQt instance that contains:
                - inspector_content_layout: Layout to add inspector widgets to
                - cursor_position: Current cursor position in file
                - open_files: List of open file tabs
                - current_tab_index: Currently active tab index
                - endian_mode: 'little' or 'big' endian for multi-byte values
                - offset_mode: 'h' for hex, 'd' for decimal offset display
                - integral_basis: 'hex', 'dec', 'oct', 'bin' for integer display
        """
        self.editor = editor
        self.inspector_content_layout = editor.inspector_content_layout
        self.current_subtab_index = 0
        self.vector_component_type = "Float32"
        self.quaternion_component_type = "Float32"
        self.bounding_box_component_type = "Float32"
        self._committing_editor_value = False
        self._updating_inspector = False
        self._pending_deferred_update = False
        self._restore_scroll_after_update = None
        self._warning_boxes = []

    def _disable_combo_wheel(self, combo):
        def wheel_event(event):
            event.ignore()
            parent = combo.parentWidget()
            if parent:
                parent.wheelEvent(event)
        combo.wheelEvent = wheel_event

    def _style_colors(self):
        theme = get_theme_colors(getattr(self.editor, "current_theme", "Dark"))
        def translucent(color, alpha):
            qcolor = QColor(color)
            if not qcolor.isValid():
                qcolor = QColor("#1f1f1f")
            return f"rgba({qcolor.red()}, {qcolor.green()}, {qcolor.blue()}, {alpha})"

        is_layered_theme = bool(
            theme.get('gradient')
            or theme.get('app_bg_image')
            or theme.get('hex_bytes_bg_image')
            or theme.get('offset_ascii_bg_image')
        )
        surfaces = get_theme_surface_colors(theme)
        base_row_bg = surfaces.get('surface', theme.get('inspector_bg', theme.get('background', '#1f1f1f')))
        base_value_bg = surfaces.get('control', theme.get('editor_bg', base_row_bg))
        row_bg = translucent(base_row_bg, 70) if is_layered_theme else base_row_bg
        value_bg = translucent(base_row_bg, 55) if is_layered_theme else base_value_bg
        value = theme.get('editor_fg', theme.get('foreground', '#ffffff'))
        border = theme.get('border', theme.get('button_bg', '#555555'))
        label = theme.get('foreground', value)
        selection_bg = theme.get('selection_bg', theme.get('button_bg', border))
        selection_fg = theme.get('selection_fg', value)
        return {
            'row_bg': row_bg,
            'row_border': border,
            'label': label,
            'value_bg': value_bg,
            'value_border': border,
            'value': value,
            'selection_bg': selection_bg,
            'selection_fg': selection_fg,
            'button_bg': theme.get('button_bg', value_bg),
            'button_hover': theme.get('button_hover', selection_bg),
        }

    def _make_row_widget(self):
        colors = self._style_colors()
        widget = QWidget()
        widget.setStyleSheet(
            f"background-color: {colors['row_bg']}; border: 1px solid {colors['row_border']}; "
            "border-radius: 3px; margin: 1px;"
        )
        layout = QHBoxLayout()
        layout.setContentsMargins(8, 4, 8, 4)
        widget.setLayout(layout)
        return widget, layout, colors

    def _make_value_edit(self, value, colors, width=70):
        edit = QLineEdit(str(value))
        edit.setFont(QFont("Courier", 8))
        edit.setMinimumWidth(width)
        edit.setStyleSheet(
            f"border: 1px solid {colors['value_border']}; background-color: {colors['value_bg']}; "
            f"color: {colors['value']}; padding: 2px; selection-background-color: {colors['selection_bg']}; "
            f"selection-color: {colors['selection_fg']};"
        )
        return edit

    def _style_combo(self, combo, colors):
        combo.setStyleSheet(
            f"QComboBox {{ background-color: {colors['value_bg']}; color: {colors['value']}; "
            f"border: 1px solid {colors['value_border']}; padding: 1px 4px; }}"
            f"QComboBox::drop-down {{ border-left: 1px solid {colors['value_border']}; width: 16px; }}"
            f"QComboBox QAbstractItemView {{ background-color: {colors['value_bg']}; color: {colors['value']}; "
            f"selection-background-color: {colors['selection_bg']}; selection-color: {colors['selection_fg']}; }}"
        )

    def _attach_highlight(self, widget, byte_size, data_offset=0):
        def on_focus(event):
            if self.editor.cursor_position is not None:
                self.editor.highlight_bytes(self.editor.cursor_position + data_offset, byte_size)
            widget.__class__.focusInEvent(widget, event)
        widget.focusInEvent = on_focus

    def _read_bytes(self, data, offset, count):
        if offset + count <= len(data):
            return bytes(data[offset:offset + count])
        return None

    def _commit_bytes(self, position, bytes_val, defer_refresh=False):
        if self.editor.current_tab_index < 0:
            return
        current_file = self.editor.open_files[self.editor.current_tab_index]
        file_data = current_file.file_data
        if position < 0 or position + len(bytes_val) > len(file_data):
            return

        self.editor.save_undo_state()
        for i, byte in enumerate(bytes_val):
            file_data[position + i] = byte
            current_file.modified_bytes.add(position + i)
        current_file.modified = True

        import os
        tab_text = os.path.basename(current_file.file_path) + " *"
        self.editor.tab_widget.setTabText(self.editor.current_tab_index, tab_text)
        if defer_refresh:
            self.editor.display_hex(preserve_scroll=True, update_side_panels=False)
        else:
            self.editor.display_hex(preserve_scroll=True)
        self._schedule_update()

    def _apply_dialog_titlebar(self, dialog):
        if sys.platform != "win32":
            return
        try:
            dark = self.editor.system_uses_dark_titlebar() if hasattr(self.editor, "system_uses_dark_titlebar") else self.editor.is_dark_theme()
            dark_enabled = ctypes.c_int(1 if dark else 0)
            hwnd = int(dialog.winId())
            for attribute in (20, 19):
                result = ctypes.windll.dwmapi.DwmSetWindowAttribute(
                    ctypes.c_void_p(hwnd),
                    ctypes.c_uint(attribute),
                    ctypes.byref(dark_enabled),
                    ctypes.sizeof(dark_enabled)
                )
                if result == 0:
                    break
        except Exception:
            pass

    def _show_warning(self, title, text):
        box = QMessageBox(self.editor)
        box.setIcon(QMessageBox.Warning)
        box.setWindowTitle(title)
        box.setText(text)
        box.setStandardButtons(QMessageBox.Ok)
        colors = self._style_colors()
        box.setFont(QFont("Courier", 8))
        box.setStyleSheet(
            f"QMessageBox {{ background-color: {colors['row_bg']}; color: {colors['value']}; }}"
            f"QMessageBox QLabel {{ background-color: transparent; color: {colors['value']}; border: none; }}"
            f"QMessageBox QWidget {{ background-color: {colors['row_bg']}; color: {colors['value']}; }}"
            f"QPushButton {{ background-color: {colors['value_bg']}; color: {colors['value']}; "
            f"border: 1px solid {colors['value_border']}; padding: 3px 12px; min-width: 54px; }}"
        )
        QTimer.singleShot(0, lambda: self._apply_dialog_titlebar(box))
        self._warning_boxes.append(box)
        box.finished.connect(lambda _=None, b=box: self._warning_boxes.remove(b) if b in self._warning_boxes else None)
        box.open()

    def _parse_numeric_literal(self, text, default_float=False):
        text = text.strip()
        if default_float or any(ch in text.lower() for ch in ('.', 'e')):
            return float(text)
        return int(text, 0)

    def _evaluate_simple_math_expression(self, text, default_float=False):
        text = text.strip().replace(" ", "")
        if not text:
            return None
        if not any(char in text for char in "+-*/^()%"):
            return None

        parser = _InspectorExpressionParser(text, default_float)
        return parser.parse()

    def _resolve_numeric_text(self, text, data_type):
        default_float = data_type in ('half', 'float', 'double')
        result = self._evaluate_simple_math_expression(text, default_float)
        if result is None:
            return text.strip()
        if default_float:
            result = float(result)
            if not math.isfinite(result):
                raise ValueError("Float expression result is not finite")
            return str(result)
        result = round(result)
        if data_type == 'byte_hex':
            return f"{result:X}"
        return str(result)

    def _parse_float_editor_text(self, text, data_type):
        """Accept normal float text or inspector math and return a finite float."""
        resolved = self._resolve_numeric_text(text, data_type)
        value = float(resolved)
        if not math.isfinite(value):
            label = {
                'half': "Float16",
                'float': "Float32",
                'double': "Float64",
            }.get(data_type, "Float")
            raise ValueError(f"{label} value must be finite")
        return value

    def _float_pack_info(self, data_type):
        if data_type == 'half':
            return 'e', 2, "{:.6f}", "Float16"
        if data_type == 'float':
            return 'f', 4, "{:.6f}", "Float32"
        if data_type == 'double':
            return 'd', 8, "{:.15f}", "Float64"
        raise ValueError("Unsupported float type")

    def _set_line_edit_text_safely(self, line_edit, text):
        old_state = line_edit.blockSignals(True)
        line_edit.setText(text)
        line_edit.setProperty('original_text', text)
        line_edit.blockSignals(old_state)

    def _format_float_display(self, value, decimals):
        """Format inspector floats without exposing NaN/Inf or negative tiny zero."""
        if not math.isfinite(value):
            value = 0.0
        if abs(value) < (0.5 * (10 ** -decimals)):
            value = 0.0
        return f"{value:.{decimals}f}"

    def update(self):
        """
        Update the data inspector display with interpretations at current cursor position.

        This method:
        1. Clears existing inspector widgets
        2. Reads bytes at the cursor position
        3. Interprets bytes as various data types
        4. Creates editable fields for each interpretation
        5. Connects signals for editing and highlighting
        """
        if self._updating_inspector:
            self._schedule_update()
            return

        self._updating_inspector = True
        try:
            self._update_impl()
        finally:
            self._updating_inspector = False

    def _schedule_update(self):
        if self._pending_deferred_update:
            return
        if hasattr(self.editor, 'inspector_scroll'):
            self._restore_scroll_after_update = (
                self.editor.inspector_scroll.horizontalScrollBar().value(),
                self.editor.inspector_scroll.verticalScrollBar().value()
            )
        self._pending_deferred_update = True

        def run_update():
            self._pending_deferred_update = False
            self.update()

        QTimer.singleShot(0, run_update)

    def _restore_inspector_scroll(self, h_value, v_value):
        if not hasattr(self.editor, 'inspector_scroll'):
            return
        self.editor.inspector_scroll.horizontalScrollBar().setValue(h_value)
        self.editor.inspector_scroll.verticalScrollBar().setValue(v_value)

    def _update_impl(self):
        # Clear existing inspector widgets
        for i in reversed(range(self.inspector_content_layout.count())):
            widget = self.inspector_content_layout.itemAt(i).widget()
            if widget:
                widget.setParent(None)

        # Validate state
        if self.editor.current_tab_index < 0 or self.editor.cursor_position is None:
            return

        current_file = self.editor.open_files[self.editor.current_tab_index]
        pos = self.editor.cursor_position

        if pos >= len(current_file.file_data):
            return

        data = current_file.file_data

        tabs = QTabWidget()
        tabs.setFont(QFont("Courier", 8))
        colors = self._style_colors()
        tabs.setStyleSheet(
            f"QTabWidget::pane {{ border: 1px solid {colors['row_border']}; background-color: {colors['row_bg']}; }}"
            f"QTabBar::tab {{ background-color: {colors['row_bg']}; color: {colors['label']}; "
            f"padding: 3px 8px; border: 1px solid {colors['row_border']}; }}"
            f"QTabBar::tab:selected {{ color: {colors['value']}; border-bottom: 2px solid {colors['selection_bg']}; }}"
        )

        numeric_tab = QWidget()
        numeric_layout = QVBoxLayout()
        numeric_layout.setAlignment(Qt.AlignTop)
        numeric_layout.setContentsMargins(0, 0, 0, 0)
        numeric_tab.setLayout(numeric_layout)

        colors_tab = QWidget()
        colors_layout = QVBoxLayout()
        colors_layout.setAlignment(Qt.AlignTop)
        colors_layout.setContentsMargins(0, 0, 0, 0)
        colors_tab.setLayout(colors_layout)

        vectors_tab = QWidget()
        vectors_layout = QVBoxLayout()
        vectors_layout.setAlignment(Qt.AlignTop)
        vectors_layout.setContentsMargins(0, 0, 0, 0)
        vectors_tab.setLayout(vectors_layout)

        tabs.addTab(numeric_tab, "Numeric")
        tabs.addTab(colors_tab, "Colors")
        tabs.addTab(vectors_tab, "Vectors")
        tabs.setCurrentIndex(min(self.current_subtab_index, tabs.count() - 1))
        tabs.currentChanged.connect(lambda index: setattr(self, 'current_subtab_index', index))
        self.inspector_content_layout.addWidget(tabs)
        if self._restore_scroll_after_update is not None and hasattr(self.editor, 'inspector_scroll'):
            h_value, v_value = self._restore_scroll_after_update
            QTimer.singleShot(0, lambda: self._restore_inspector_scroll(h_value, v_value))
            self._restore_scroll_after_update = None

        # Helper function to safely read bytes from file data
        def read_bytes(offset, count):
            """Read count bytes starting at offset, or None if out of bounds."""
            if offset + count <= len(data):
                return bytes(data[offset:offset + count])
            return None

        # Helper function to add an inspector row (label + editable value)
        def add_inspector_row(label, value, byte_size=1, data_offset=0, data_type=None):
            """
            Add a row to the inspector showing a label and editable value.

            Args:
                label: Display name for this data type (e.g., "Int32:")
                value: Interpreted value to display
                byte_size: Number of bytes this interpretation uses
                data_offset: Offset from cursor position where these bytes start
                data_type: Type identifier for editing (e.g., 'int32', 'float', 'guid')
            """
            widget, layout, row_colors = self._make_row_widget()

            # Create label widget
            label_widget = QLabel(label)
            label_widget.setMinimumWidth(80)
            label_widget.setFont(QFont("Arial", 8))
            label_widget.setStyleSheet(f"color: {row_colors['label']}; border: none; background: transparent;")
            layout.addWidget(label_widget)

            # Create editable value field
            value_edit = self._make_value_edit(value, row_colors, width=150)
            value_edit.setMinimumWidth(150)

            # Store metadata for highlighting and editing
            value_edit.setProperty('byte_size', byte_size)
            value_edit.setProperty('data_offset', data_offset)
            value_edit.setProperty('data_type', data_type)
            value_edit.setProperty('original_text', str(value))

            # Connect focus event to highlight the relevant bytes in hex display
            def on_focus(event):
                if self.editor.cursor_position is not None:
                    self.editor.highlight_bytes(self.editor.cursor_position + data_offset, byte_size)
                QLineEdit.focusInEvent(value_edit, event)
            value_edit.focusInEvent = on_focus

            # Connect editing finished event to update bytes (except for read-only offset field)
            if data_type and data_type != 'offset':
                def on_edit_finished():
                    if self.editor.cursor_position is not None:
                        self.update_bytes_from_editor(
                            value_edit,
                            self.editor.cursor_position + data_offset,
                            data_type
                        )
                value_edit.editingFinished.connect(on_edit_finished)

            layout.addWidget(value_edit, 1)  # Stretch factor to expand horizontally
            numeric_layout.addWidget(widget)

        # --- Begin Data Type Interpretations ---

        # Offset (current cursor position)
        offset_str = f"0x{pos:X}" if self.editor.offset_mode == 'h' else str(pos)
        add_inspector_row("Offset:", offset_str, byte_size=0, data_offset=0, data_type='offset')

        # Single byte value (always shown in hex)
        byte_val = data[pos]
        if self.editor.integral_basis == 'hex':
            add_inspector_row("Byte (hex):", f"0x{byte_val:02X}", byte_size=1, data_offset=0, data_type='byte_hex')

        # Int8 (signed 8-bit integer)
        int8_val = struct.unpack('b', bytes([byte_val]))[0]
        add_inspector_row("Int8:", self.editor.format_integral(int8_val, 2, signed=True), byte_size=1, data_offset=0, data_type='int8')

        # UInt8 (unsigned 8-bit integer)
        add_inspector_row("UInt8:", self.editor.format_integral(byte_val, 2), byte_size=1, data_offset=0, data_type='uint8')

        # Int16 (signed 16-bit integer)
        bytes_16 = read_bytes(pos, 2)
        if bytes_16:
            fmt = '<h' if self.editor.endian_mode == 'little' else '>h'
            int16_val = struct.unpack(fmt, bytes_16)[0]
            add_inspector_row("Int16:", self.editor.format_integral(int16_val, 4, signed=True), byte_size=2, data_offset=0, data_type='int16')

        # UInt16 (unsigned 16-bit integer)
        if bytes_16:
            fmt = '<H' if self.editor.endian_mode == 'little' else '>H'
            uint16_val = struct.unpack(fmt, bytes_16)[0]
            add_inspector_row("UInt16:", self.editor.format_integral(uint16_val, 4), byte_size=2, data_offset=0, data_type='uint16')

        # Int32 (signed 32-bit integer)
        bytes_32 = read_bytes(pos, 4)
        if bytes_32:
            fmt = '<i' if self.editor.endian_mode == 'little' else '>i'
            int32_val = struct.unpack(fmt, bytes_32)[0]
            add_inspector_row("Int32:", self.editor.format_integral(int32_val, 8, signed=True), byte_size=4, data_offset=0, data_type='int32')

        # UInt32 (unsigned 32-bit integer)
        if bytes_32:
            fmt = '<I' if self.editor.endian_mode == 'little' else '>I'
            uint32_val = struct.unpack(fmt, bytes_32)[0]
            add_inspector_row("UInt32:", self.editor.format_integral(uint32_val, 8), byte_size=4, data_offset=0, data_type='uint32')

        # Int64 (signed 64-bit integer)
        bytes_64 = read_bytes(pos, 8)
        if bytes_64:
            fmt = '<q' if self.editor.endian_mode == 'little' else '>q'
            int64_val = struct.unpack(fmt, bytes_64)[0]
            add_inspector_row("Int64:", self.editor.format_integral(int64_val, 16, signed=True), byte_size=8, data_offset=0, data_type='int64')

        # UInt64 (unsigned 64-bit integer)
        if bytes_64:
            fmt = '<Q' if self.editor.endian_mode == 'little' else '>Q'
            uint64_val = struct.unpack(fmt, bytes_64)[0]
            add_inspector_row("UInt64:", self.editor.format_integral(uint64_val, 16), byte_size=8, data_offset=0, data_type='uint64')

        # Int24 (signed 24-bit integer - manual parsing)
        bytes_24 = read_bytes(pos, 3)
        if bytes_24:
            # Reconstruct 24-bit value based on endianness
            if self.editor.endian_mode == 'little':
                int24_val = bytes_24[0] | (bytes_24[1] << 8) | (bytes_24[2] << 16)
            else:
                int24_val = (bytes_24[0] << 16) | (bytes_24[1] << 8) | bytes_24[2]
            # Apply sign bit extension
            if int24_val & 0x800000:
                int24_val -= 0x1000000
            add_inspector_row("Int24:", self.editor.format_integral(int24_val, 6, signed=True), byte_size=3, data_offset=0, data_type='int24')

        # UInt24 (unsigned 24-bit integer)
        if bytes_24:
            if self.editor.endian_mode == 'little':
                uint24_val = bytes_24[0] | (bytes_24[1] << 8) | (bytes_24[2] << 16)
            else:
                uint24_val = (bytes_24[0] << 16) | (bytes_24[1] << 8) | bytes_24[2]
            add_inspector_row("UInt24:", self.editor.format_integral(uint24_val, 6), byte_size=3, data_offset=0, data_type='uint24')

        # LEB128 (signed variable-length integer)
        leb_bytes = read_bytes(pos, min(10, len(data) - pos))
        if leb_bytes:
            try:
                result = 0
                shift = 0
                leb_size = 0
                # Decode LEB128: each byte has 7 bits of data + continuation bit
                for b in leb_bytes:
                    leb_size += 1
                    result |= (b & 0x7f) << shift
                    shift += 7
                    if (b & 0x80) == 0:  # No continuation bit, done
                        break
                # Apply sign extension
                if result & (1 << (shift - 1)):
                    result -= (1 << shift)
                add_inspector_row("LEB128:", str(result), byte_size=leb_size, data_offset=0, data_type='leb128')
            except:
                add_inspector_row("LEB128:", "Invalid", byte_size=1, data_offset=0, data_type=None)

        # ULEB128 (unsigned variable-length integer)
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

        # AnsiChar / char8_t (single byte character)
        # Control characters shown as hex escape sequences
        ansi_char = chr(byte_val) if (32 <= byte_val <= 126) or (160 <= byte_val <= 255) else f"\\x{byte_val:02x}"
        add_inspector_row("AnsiChar / char8_t:", ansi_char, byte_size=1, data_offset=0, data_type='ansichar')

        # WideChar / char16_t (UTF-16 character)
        if bytes_16:
            fmt = '<H' if self.editor.endian_mode == 'little' else '>H'
            wide_val = struct.unpack(fmt, bytes_16)[0]
            try:
                # Avoid surrogate pairs
                wide_char = chr(wide_val) if wide_val < 0xD800 or wide_val > 0xDFFF else f"\\u{wide_val:04x}"
            except:
                wide_char = f"\\u{wide_val:04x}"
            add_inspector_row("WideChar / char16_t:", wide_char, byte_size=2, data_offset=0, data_type='widechar')

        # UTF-8 code point (variable length 1-4 bytes)
        utf8_bytes = read_bytes(pos, min(4, len(data) - pos))
        if utf8_bytes:
            try:
                # Determine UTF-8 sequence length from first byte
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

        # Half (float16) - IEEE 754 half precision floating point
        if bytes_16:
            fmt = '<e' if self.editor.endian_mode == 'little' else '>e'
            half_val = struct.unpack(fmt, bytes_16)[0]
            add_inspector_row("Half (float16):", self._format_float_display(half_val, 6), byte_size=2, data_offset=0, data_type='half')

        # Single (float32) - IEEE 754 single precision floating point
        if bytes_32:
            fmt = '<f' if self.editor.endian_mode == 'little' else '>f'
            float_val = struct.unpack(fmt, bytes_32)[0]
            add_inspector_row("Single (float32):", self._format_float_display(float_val, 6), byte_size=4, data_offset=0, data_type='float')

        # Double (float64) - IEEE 754 double precision floating point
        if bytes_64:
            fmt = '<d' if self.editor.endian_mode == 'little' else '>d'
            double_val = struct.unpack(fmt, bytes_64)[0]
            add_inspector_row("Double (float64):", self._format_float_display(double_val, 15), byte_size=8, data_offset=0, data_type='double')

        # OLETIME (OLE Automation date - days since 1899-12-30 as double)
        if bytes_64:
            fmt = '<d' if self.editor.endian_mode == 'little' else '>d'
            ole_val = struct.unpack(fmt, bytes_64)[0]
            try:
                from datetime import datetime, timedelta
                base_date = datetime(1899, 12, 30)
                result_date = base_date + timedelta(days=ole_val)
                add_inspector_row("OLETIME:", result_date.strftime("%Y-%m-%d %H:%M:%S"), byte_size=8, data_offset=0, data_type='oletime')
            except:
                add_inspector_row("OLETIME:", "Invalid", byte_size=8, data_offset=0, data_type=None)

        # FILETIME (Windows FILETIME - 100-nanosecond intervals since 1601-01-01)
        if bytes_64:
            fmt = '<Q' if self.editor.endian_mode == 'little' else '>Q'
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

        # DOS date (2 bytes - packed date format used by MS-DOS)
        if bytes_16:
            fmt = '<H' if self.editor.endian_mode == 'little' else '>H'
            dos_date = struct.unpack(fmt, bytes_16)[0]
            try:
                # Extract day (5 bits), month (4 bits), year (7 bits + 1980)
                day = dos_date & 0x1F
                month = (dos_date >> 5) & 0x0F
                year = ((dos_date >> 9) & 0x7F) + 1980
                if 1 <= day <= 31 and 1 <= month <= 12:
                    add_inspector_row("DOS date:", f"{year:04d}-{month:02d}-{day:02d}", byte_size=2, data_offset=0, data_type='dos_date')
                else:
                    add_inspector_row("DOS date:", "Invalid", byte_size=2, data_offset=0, data_type=None)
            except:
                add_inspector_row("DOS date:", "Invalid", byte_size=2, data_offset=0, data_type=None)

        # DOS time (2 bytes - packed time format used by MS-DOS)
        if bytes_16:
            fmt = '<H' if self.editor.endian_mode == 'little' else '>H'
            dos_time = struct.unpack(fmt, bytes_16)[0]
            try:
                # Extract seconds/2 (5 bits), minutes (6 bits), hours (5 bits)
                seconds = (dos_time & 0x1F) * 2
                minutes = (dos_time >> 5) & 0x3F
                hours = (dos_time >> 11) & 0x1F
                if hours < 24 and minutes < 60 and seconds < 60:
                    add_inspector_row("DOS time:", f"{hours:02d}:{minutes:02d}:{seconds:02d}", byte_size=2, data_offset=0, data_type='dos_time')
                else:
                    add_inspector_row("DOS time:", "Invalid", byte_size=2, data_offset=0, data_type=None)
            except:
                add_inspector_row("DOS time:", "Invalid", byte_size=2, data_offset=0, data_type=None)

        # DOS time & date (4 bytes - combined DOS time and date)
        bytes_dos = read_bytes(pos, 4)
        if bytes_dos:
            fmt = '<HH' if self.editor.endian_mode == 'little' else '>HH'
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

        # time_t (32 bit) - Unix timestamp (seconds since 1970-01-01)
        if bytes_32:
            fmt = '<i' if self.editor.endian_mode == 'little' else '>i'
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

        # time_t (64 bit) - Unix timestamp (seconds since 1970-01-01)
        if bytes_64:
            fmt = '<q' if self.editor.endian_mode == 'little' else '>q'
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

        # GUID (16 bytes) - Globally Unique Identifier
        bytes_guid = read_bytes(pos, 16)
        if bytes_guid:
            try:
                # Parse GUID structure: 4-byte, 2-byte, 2-byte, 8-byte
                if self.editor.endian_mode == 'little':
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

        # Disassembly (x86-16, x86-32, x86-64) - requires Capstone library
        disasm_bytes = read_bytes(pos, min(15, len(data) - pos))
        if disasm_bytes:
            try:
                from capstone import Cs, CS_ARCH_X86, CS_MODE_16, CS_MODE_32, CS_MODE_64

                # x86-16 disassembly
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

                # x86-32 disassembly
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

                # x86-64 disassembly
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
                # Capstone library not available
                add_inspector_row("Disassembly (x86-16):", "[capstone library not installed]", byte_size=1, data_offset=0, data_type=None)
                add_inspector_row("Disassembly (x86-32):", "[capstone library not installed]", byte_size=1, data_offset=0, data_type=None)
                add_inspector_row("Disassembly (x86-64):", "[capstone library not installed]", byte_size=1, data_offset=0, data_type=None)

        self._populate_color_tab(colors_layout, data, pos)
        self._populate_vector_tab(vectors_layout, data, pos)
        numeric_layout.addStretch()
        colors_layout.addStretch()
        vectors_layout.addStretch()

    def _preview_style(self, color):
        return (
            "QPushButton {"
            f"background-color: {color.name(QColor.HexRgb)};"
            "border: 1px solid #888; border-radius: 2px; min-width: 22px; max-width: 22px;"
            "min-height: 18px; max-height: 18px; padding: 0px;"
            "}"
        )

    def _components_to_qcolor(self, components, fmt_name):
        if fmt_name == "HSV":
            h_byte, s, v = components
            hue = int(round((h_byte / 255.0) * 359)) if h_byte else 0
            return QColor.fromHsv(hue, s, v)

        mapping = {
            "RGB24": ("R", "G", "B"),
            "RGBA32": ("R", "G", "B", "A"),
            "BGR24": ("B", "G", "R"),
            "BGRA32": ("B", "G", "R", "A"),
            "ARGB32": ("A", "R", "G", "B"),
            "ABGR32": ("A", "B", "G", "R"),
        }[fmt_name]
        values = dict(zip(mapping, components))
        return QColor(values.get("R", 0), values.get("G", 0), values.get("B", 0), values.get("A", 255))

    def _qcolor_to_components(self, color, fmt_name):
        if fmt_name == "HSV":
            hue = color.hue()
            if hue < 0:
                hue = 0
            return [int(round((hue / 359.0) * 255)), color.saturation(), color.value()]

        source = {"R": color.red(), "G": color.green(), "B": color.blue(), "A": color.alpha()}
        mapping = {
            "RGB24": ("R", "G", "B"),
            "RGBA32": ("R", "G", "B", "A"),
            "BGR24": ("B", "G", "R"),
            "BGRA32": ("B", "G", "R", "A"),
            "ARGB32": ("A", "R", "G", "B"),
            "ABGR32": ("A", "B", "G", "R"),
        }[fmt_name]
        return [source[name] for name in mapping]

    def _color_component_labels(self, fmt_name):
        return {
            "RGB24": ("R", "G", "B"),
            "RGBA32": ("R", "G", "B", "A"),
            "BGR24": ("B", "G", "R"),
            "BGRA32": ("B", "G", "R", "A"),
            "ARGB32": ("A", "R", "G", "B"),
            "ABGR32": ("A", "B", "G", "R"),
            "HSV": ("H", "S", "V"),
        }[fmt_name]

    def _populate_color_tab(self, layout, data, pos):
        formats = [
            ("RGB24", 3), ("RGBA32", 4), ("BGR24", 3), ("BGRA32", 4),
            ("ARGB32", 4), ("ABGR32", 4), ("HSV", 3)
        ]
        for fmt_name, byte_count in formats:
            raw = self._read_bytes(data, pos, byte_count)
            if not raw:
                self._add_disabled_row(layout, f"{fmt_name}:", f"Need {byte_count} bytes")
                continue
            self._add_color_row(layout, fmt_name, list(raw), byte_count)

    def _add_color_row(self, layout, fmt_name, components, byte_count):
        widget, row, colors = self._make_row_widget()
        outer = QVBoxLayout()
        outer.setContentsMargins(0, 0, 0, 0)
        outer.setSpacing(3)
        row.addLayout(outer, 1)

        top_row = QHBoxLayout()
        top_row.setContentsMargins(0, 0, 0, 0)
        top_row.setSpacing(5)
        outer.addLayout(top_row)

        label = QLabel(f"{fmt_name}:")
        label.setMinimumWidth(62)
        label.setFont(QFont("Arial", 8))
        label.setStyleSheet(f"color: {colors['label']}; border: none;")
        top_row.addWidget(label)

        color = self._components_to_qcolor(components, fmt_name)
        preview = QPushButton()
        preview.setToolTip("Pick color")
        preview.setStyleSheet(self._preview_style(color))
        preview.setFocusPolicy(Qt.StrongFocus)
        self._attach_highlight(preview, byte_count, 0)
        top_row.addWidget(preview)

        code_text = color.name(QColor.HexRgb)
        if color.alpha() != 255 and fmt_name != "HSV":
            code_text = f"{code_text}{color.alpha():02X}"
        code_edit = self._make_value_edit(code_text.upper(), colors, width=76)
        self._attach_highlight(code_edit, byte_count, 0)
        top_row.addWidget(code_edit, 1)

        component_edits = []
        components_row = QHBoxLayout()
        components_row.setContentsMargins(62, 0, 0, 0)
        components_row.setSpacing(4)
        outer.addLayout(components_row)
        for label_text, value in zip(self._color_component_labels(fmt_name), components):
            component_label = QLabel(label_text)
            component_label.setFont(QFont("Arial", 8))
            component_label.setStyleSheet(f"color: {colors['label']}; border: none;")
            components_row.addWidget(component_label)
            shown_value = int(round((value / 255.0) * 359)) if fmt_name == "HSV" and label_text == "H" else value
            edit = self._make_value_edit(shown_value, colors, width=38)
            edit.setProperty('original_text', str(shown_value))
            self._attach_highlight(edit, 1, len(component_edits))
            components_row.addWidget(edit, 1)
            component_edits.append((label_text, edit))
        components_row.addStretch(1)

        def refresh_preview_from_components():
            try:
                values = []
                for label_text, edit in component_edits:
                    value = int(self._resolve_numeric_text(edit.text().strip(), 'uint8'))
                    if fmt_name == "HSV" and label_text == "H":
                        value = int(round((max(0, min(359, value)) / 359.0) * 255))
                    values.append(max(0, min(255, value)))
                new_color = self._components_to_qcolor(values, fmt_name)
                preview.setStyleSheet(self._preview_style(new_color))
                color_code = new_color.name(QColor.HexRgb)
                if new_color.alpha() != 255 and fmt_name != "HSV":
                    color_code = f"{color_code}{new_color.alpha():02X}"
                code_edit.setText(color_code.upper())
                return values
            except Exception:
                return None

        def commit_components():
            values = refresh_preview_from_components()
            if values is not None:
                self._commit_bytes(self.editor.cursor_position, bytes(values[:byte_count]), defer_refresh=True)
            else:
                for _, edit in component_edits:
                    edit.setText(edit.property('original_text') or "")
                self._schedule_update()

        for _, edit in component_edits:
            edit.textEdited.connect(lambda _: refresh_preview_from_components())
        for _, edit in component_edits:
            edit.editingFinished.connect(commit_components)

        def commit_code():
            text = code_edit.text().strip().lstrip('#')
            try:
                if any(op in text for op in "+-*/%"):
                    code_edit.setText(code_text.upper())
                    return
                if len(text) not in (6, 8):
                    raise ValueError
                picked = QColor(f"#{text[:6]}")
                if not picked.isValid():
                    raise ValueError
                if len(text) == 8:
                    picked.setAlpha(int(text[6:8], 16))
                values = self._qcolor_to_components(picked, fmt_name)
                self._commit_bytes(self.editor.cursor_position, bytes(values[:byte_count]), defer_refresh=True)
            except Exception:
                code_edit.setText(code_text.upper())
                self._schedule_update()

        code_edit.editingFinished.connect(commit_code)

        def pick_color():
            if self.editor.cursor_position is not None:
                self.editor.highlight_bytes(self.editor.cursor_position, byte_count)
            dialog = QColorDialog(color, preview)
            dialog.setWindowTitle(f"Select {fmt_name} Color")
            dialog.setOption(QColorDialog.DontUseNativeDialog, True)
            dialog.setOption(QColorDialog.ShowAlphaChannel, byte_count == 4)
            dialog.setMinimumSize(560, 430)
            dialog.resize(560, 430)
            dialog.setFont(QFont("Courier", 8))
            dialog.setStyleSheet(
                f"QColorDialog, QColorDialog QWidget {{ background-color: {colors['row_bg']}; color: {colors['value']}; font: 8pt 'Courier'; }}"
                f"QColorDialog QFrame, QColorDialog QGroupBox {{ background-color: {colors['row_bg']}; border: 1px solid {colors['row_border']}; }}"
                f"QColorDialog QAbstractSpinBox {{ font: 8pt 'Courier'; }}"
                f"QLabel {{ color: {colors['value']}; border: none; }}"
                f"QLineEdit, QSpinBox {{ background-color: {colors['value_bg']}; color: {colors['value']}; "
                f"border: 1px solid {colors['value_border']}; padding: 1px; min-height: 18px; }}"
                f"QColorDialog QPushButton {{ background-color: {colors['value_bg']}; color: {colors['value']}; "
                f"border: 1px solid {colors['value_border']}; padding: 2px 10px; min-height: 20px; min-width: 74px; "
                "font: 8pt 'Courier'; }}"
                f"QColorDialog QPushButton:hover {{ border-color: {colors['label']}; }}"
            )
            dialog.currentColorChanged.connect(lambda live_color: preview.setStyleSheet(self._preview_style(live_color)))
            QTimer.singleShot(0, lambda: self._apply_dialog_titlebar(dialog))
            if dialog.exec_() == QColorDialog.Accepted:
                values = self._qcolor_to_components(dialog.selectedColor(), fmt_name)
                self._commit_bytes(self.editor.cursor_position, bytes(values[:byte_count]), defer_refresh=True)
            else:
                preview.setStyleSheet(self._preview_style(color))

        preview.clicked.connect(pick_color)
        layout.addWidget(widget)

    def _vector_formats(self):
        return {
            "Int8": ("b", 1), "UInt8": ("B", 1), "Int16": ("h", 2), "UInt16": ("H", 2),
            "Int32": ("i", 4), "UInt32": ("I", 4), "Float32": ("f", 4), "Float64": ("d", 8),
        }

    def _populate_vector_tab(self, layout, data, pos):
        self._add_component_type_selector(layout, "Vectors:", "vector_component_type")
        for vector_name, count in (("Vector2", 2), ("Vector3", 3), ("Vector4", 4)):
            self._add_vector_row(layout, data, pos, vector_name, count, component_type=self.vector_component_type)

        self._add_component_type_selector(layout, "Quaternion:", "quaternion_component_type")
        self._add_vector_row(
            layout,
            data,
            pos,
            "Quaternion",
            4,
            axes=("X", "Y", "Z", "W"),
            show_length=True,
            component_type=self.quaternion_component_type
        )

        self._add_component_type_selector(layout, "Bounding Box:", "bounding_box_component_type")
        self._add_vector_row(
            layout,
            data,
            pos,
            "Bounding Box",
            6,
            axes=("Min X", "Min Y", "Min Z", "Max X", "Max Y", "Max Z"),
            component_type=self.bounding_box_component_type
        )

    def _add_component_type_selector(self, layout, label_text, attr_name):
        widget, row, colors = self._make_row_widget()
        label = QLabel(label_text)
        label.setMinimumWidth(86)
        label.setFont(QFont("Arial", 8))
        label.setStyleSheet(f"color: {colors['label']}; border: none;")
        row.addWidget(label)
        combo = QComboBox()
        combo.setFont(QFont("Courier", 8))
        combo.setMaximumHeight(22)
        combo.setFocusPolicy(Qt.ClickFocus)
        self._disable_combo_wheel(combo)
        self._style_combo(combo, colors)
        combo.addItems(list(self._vector_formats().keys()))
        combo.setCurrentText(getattr(self, attr_name, "Float32"))
        combo.currentTextChanged.connect(lambda text, name=attr_name: self._set_component_type(name, text))
        row.addWidget(combo, 1)
        layout.addWidget(widget)

    def _set_component_type(self, attr_name, text):
        if text not in self._vector_formats():
            return
        setattr(self, attr_name, text)
        self._schedule_update()

    def _add_vector_row(self, layout, data, pos, vector_name, component_count, axes=None, show_length=False, component_type=None):
        vector_formats = self._vector_formats()
        component_type = component_type or self.vector_component_type
        if component_type not in vector_formats:
            component_type = "Float32"
        fmt_char, component_size = vector_formats[component_type]
        total_size = component_size * component_count
        raw = self._read_bytes(data, pos, total_size)
        if not raw:
            self._add_disabled_row(layout, f"{vector_name}:", f"Need {total_size} bytes")
            return

        endian = '<' if self.editor.endian_mode == 'little' else '>'
        fmt = endian + (fmt_char * component_count)
        try:
            values = list(struct.unpack(fmt, raw))
        except struct.error:
            self._add_disabled_row(layout, f"{vector_name}:", "Invalid")
            return

        widget, row, colors = self._make_row_widget()
        group = QVBoxLayout()
        group.setContentsMargins(0, 0, 0, 0)
        group.setSpacing(3)
        row.addLayout(group, 1)

        header = QLabel(f"[{vector_name}]")
        header.setFont(QFont("Arial", 8, QFont.Bold))
        header.setStyleSheet(f"color: {colors['value']}; border: none;")
        group.addWidget(header)

        axis_names = axes or ("X", "Y", "Z", "W")[:component_count]
        for index, axis in enumerate(axis_names):
            component_row = QHBoxLayout()
            component_row.setContentsMargins(8, 0, 0, 0)
            component_row.setSpacing(5)
            group.addLayout(component_row)

            axis_label = QLabel(axis)
            axis_label.setMinimumWidth(42 if " " in axis else 18)
            axis_label.setFont(QFont("Arial", 8))
            axis_label.setStyleSheet(f"color: {colors['label']}; border: none;")
            component_row.addWidget(axis_label)
            value = f"{values[index]:.6g}" if fmt_char in ("f", "d") else str(values[index])
            edit = self._make_value_edit(value, colors, width=58)
            edit.setProperty('byte_size', component_size)
            edit.setProperty('data_offset', index * component_size)
            edit.setProperty('original_text', value)

            self._attach_highlight(edit, component_size, index * component_size)

            def commit_component(edit_widget=edit, data_offset=index * component_size):
                try:
                    value_text = edit_widget.text().strip()
                    value_type = 'float' if fmt_char == 'f' else 'double' if fmt_char == 'd' else 'int64'
                    resolved_text = self._resolve_numeric_text(value_text, value_type)
                    value = float(resolved_text) if fmt_char in ("f", "d") else int(resolved_text, 0)
                    bytes_val = struct.pack(endian + fmt_char, value)
                    self._commit_bytes(self.editor.cursor_position + data_offset, bytes_val, defer_refresh=True)
                except Exception:
                    edit_widget.setText(edit_widget.property('original_text') or "")
                    self._schedule_update()

            edit.editingFinished.connect(commit_component)
            component_row.addWidget(edit, 1)

        if show_length and all(isinstance(value, (int, float)) for value in values):
            length = math.sqrt(sum(float(value) * float(value) for value in values))
            length_row = QHBoxLayout()
            length_row.setContentsMargins(8, 0, 0, 0)
            length_row.setSpacing(5)
            group.addLayout(length_row)
            length_label = QLabel("Length")
            length_label.setMinimumWidth(42)
            length_label.setFont(QFont("Arial", 8))
            length_label.setStyleSheet(f"color: {colors['label']}; border: none;")
            length_row.addWidget(length_label)
            length_value = QLabel(f"{length:.6g}")
            length_value.setFont(QFont("Courier", 8))
            length_value.setStyleSheet(f"color: {colors['value']}; border: none;")
            length_row.addWidget(length_value, 1)

        layout.addWidget(widget)

    def _add_disabled_row(self, layout, label_text, message):
        widget, row, colors = self._make_row_widget()
        widget.setEnabled(False)
        label = QLabel(label_text)
        label.setMinimumWidth(72)
        label.setFont(QFont("Arial", 8))
        label.setStyleSheet(f"color: {colors['label']}; border: none;")
        row.addWidget(label)
        value = QLabel(message)
        value.setFont(QFont("Courier", 8))
        value.setStyleSheet(f"color: {colors['label']}; border: none;")
        row.addWidget(value, 1)
        layout.addWidget(widget)

    def clear(self):
        """
        Clear all inspector widgets.

        This removes all data type interpretation widgets from the inspector panel.
        """
        for i in reversed(range(self.inspector_content_layout.count())):
            widget = self.inspector_content_layout.itemAt(i).widget()
            if widget:
                widget.setParent(None)

    def update_bytes_from_editor(self, line_edit, position, data_type):
        """
        Update file bytes based on user editing an inspector field.

        This method:
        1. Parses the edited value from the line edit widget
        2. Converts it to bytes based on data_type
        3. Writes those bytes to the file data
        4. Marks bytes as modified
        5. Refreshes the display

        Args:
            line_edit: QLineEdit widget containing the edited value
            position: Byte offset in file where value should be written
            data_type: Type identifier (e.g., 'int32', 'float', 'guid') for parsing
        """
        if self.editor.current_tab_index < 0:
            return
        if self._committing_editor_value:
            return

        current_file = self.editor.open_files[self.editor.current_tab_index]
        file_data = current_file.file_data

        self._committing_editor_value = True
        try:
            text = line_edit.text().strip()
            numeric_types = {
                'byte_hex', 'int8', 'uint8', 'int16', 'uint16', 'int24', 'uint24',
                'int32', 'uint32', 'int64', 'uint64', 'half', 'float', 'double'
            }
            if data_type in numeric_types:
                text = self._resolve_numeric_text(text, data_type)

            # Detect and handle hex prefix (0x or 0X)
            is_hex = text.startswith('0x') or text.startswith('0X')
            if is_hex:
                text = text[2:]

            # --- Convert based on data type ---

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
                    fmt = '<h' if self.editor.endian_mode == 'little' else '>h'
                    bytes_val = struct.pack(fmt, value)
                    for i, b in enumerate(bytes_val):
                        if position + i < len(file_data):
                            file_data[position + i] = b
                else:
                    raise ValueError("Int16 value out of range")

            elif data_type == 'uint16':
                value = int(text, 16) if is_hex else int(text)
                if 0 <= value <= 65535:
                    fmt = '<H' if self.editor.endian_mode == 'little' else '>H'
                    bytes_val = struct.pack(fmt, value)
                    for i, b in enumerate(bytes_val):
                        if position + i < len(file_data):
                            file_data[position + i] = b
                else:
                    raise ValueError("UInt16 value out of range")

            elif data_type == 'int32':
                value = int(text, 16) if is_hex else int(text)
                if -2147483648 <= value <= 2147483647:
                    fmt = '<i' if self.editor.endian_mode == 'little' else '>i'
                    bytes_val = struct.pack(fmt, value)
                    for i, b in enumerate(bytes_val):
                        if position + i < len(file_data):
                            file_data[position + i] = b
                else:
                    raise ValueError("Int32 value out of range")

            elif data_type == 'uint32':
                value = int(text, 16) if is_hex else int(text)
                if 0 <= value <= 4294967295:
                    fmt = '<I' if self.editor.endian_mode == 'little' else '>I'
                    bytes_val = struct.pack(fmt, value)
                    for i, b in enumerate(bytes_val):
                        if position + i < len(file_data):
                            file_data[position + i] = b
                else:
                    raise ValueError("UInt32 value out of range")

            elif data_type == 'int64':
                value = int(text, 16) if is_hex else int(text)
                if -9223372036854775808 <= value <= 9223372036854775807:
                    fmt = '<q' if self.editor.endian_mode == 'little' else '>q'
                    bytes_val = struct.pack(fmt, value)
                    for i, b in enumerate(bytes_val):
                        if position + i < len(file_data):
                            file_data[position + i] = b
                else:
                    raise ValueError("Int64 value out of range")

            elif data_type == 'uint64':
                value = int(text, 16) if is_hex else int(text)
                if 0 <= value <= 18446744073709551615:
                    fmt = '<Q' if self.editor.endian_mode == 'little' else '>Q'
                    bytes_val = struct.pack(fmt, value)
                    for i, b in enumerate(bytes_val):
                        if position + i < len(file_data):
                            file_data[position + i] = b
                else:
                    raise ValueError("UInt64 value out of range")

            elif data_type == 'float':
                value = self._parse_float_editor_text(text, data_type)
                fmt = '<f' if self.editor.endian_mode == 'little' else '>f'
                bytes_val = struct.pack(fmt, value)
                formatted_value = self._format_float_display(struct.unpack(fmt, bytes_val)[0], 6)
                if bytes(file_data[position:position + len(bytes_val)]) == bytes_val:
                    self._set_line_edit_text_safely(line_edit, formatted_value)
                    return
                for i, b in enumerate(bytes_val):
                    if position + i < len(file_data):
                        file_data[position + i] = b
                self._set_line_edit_text_safely(line_edit, formatted_value)

            elif data_type == 'half':
                value = self._parse_float_editor_text(text, data_type)
                fmt = '<e' if self.editor.endian_mode == 'little' else '>e'
                bytes_val = struct.pack(fmt, value)
                formatted_value = self._format_float_display(struct.unpack(fmt, bytes_val)[0], 6)
                if bytes(file_data[position:position + len(bytes_val)]) == bytes_val:
                    self._set_line_edit_text_safely(line_edit, formatted_value)
                    return
                for i, b in enumerate(bytes_val):
                    if position + i < len(file_data):
                        file_data[position + i] = b
                self._set_line_edit_text_safely(line_edit, formatted_value)

            elif data_type == 'double':
                value = self._parse_float_editor_text(text, data_type)
                fmt = '<d' if self.editor.endian_mode == 'little' else '>d'
                bytes_val = struct.pack(fmt, value)
                formatted_value = self._format_float_display(struct.unpack(fmt, bytes_val)[0], 15)
                if bytes(file_data[position:position + len(bytes_val)]) == bytes_val:
                    self._set_line_edit_text_safely(line_edit, formatted_value)
                    return
                for i, b in enumerate(bytes_val):
                    if position + i < len(file_data):
                        file_data[position + i] = b
                self._set_line_edit_text_safely(line_edit, formatted_value)

            elif data_type == 'int24':
                value = int(text, 16) if is_hex else int(text)
                if -8388608 <= value <= 8388607:
                    if value < 0:
                        value = value + 0x1000000
                    if self.editor.endian_mode == 'little':
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
                    if self.editor.endian_mode == 'little':
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
                fmt = '<H' if self.editor.endian_mode == 'little' else '>H'
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

                    if self.editor.endian_mode == 'little':
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
            self.editor.save_undo_state()
            current_file.modified = True

            # Calculate byte count based on data type
            byte_count = 1 if data_type in ['byte_hex', 'int8', 'uint8', 'ansichar'] else \
                         2 if data_type in ['int16', 'uint16', 'half', 'widechar', 'dos_date', 'dos_time'] else \
                         3 if data_type in ['int24', 'uint24'] else \
                         4 if data_type in ['int32', 'uint32', 'float', 'dos_datetime', 'time_t_32'] else \
                         8 if data_type in ['int64', 'uint64', 'double', 'oletime', 'filetime', 'time_t_64'] else \
                         16 if data_type in ['guid'] else 1

            # Mark modified bytes
            for i in range(byte_count):
                if position + i < len(file_data):
                    current_file.modified_bytes.add(position + i)

            # Update tab title to show modification
            import os
            tab_text = os.path.basename(current_file.file_path) + " *"
            self.editor.tab_widget.setTabText(self.editor.current_tab_index, tab_text)

            # Refresh display
            self.editor.display_hex(preserve_scroll=True)
            self.update()

        except Exception as e:
            # Reset to original value on error
            print(f"Invalid input: {e}")
            self._set_line_edit_text_safely(line_edit, line_edit.property('original_text') or "")
            QTimer.singleShot(0, lambda message=str(e): self._show_warning("Invalid Inspector Value", message))
            self._schedule_update()
        finally:
            self._committing_editor_value = False
