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

import struct
from PyQt5.QtWidgets import QWidget, QVBoxLayout, QHBoxLayout, QLabel, QLineEdit
from PyQt5.QtGui import QFont
from PyQt5.QtCore import Qt


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
            widget = QWidget()

            # Apply theme-appropriate styling
            if self.editor.is_dark_theme():
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

            # Create label widget
            label_widget = QLabel(label)
            label_widget.setMinimumWidth(80)
            label_widget.setFont(QFont("Arial", 8))
            label_widget.setStyleSheet(f"color: {label_color}; border: none;")
            layout.addWidget(label_widget)

            # Create editable value field
            value_edit = QLineEdit(str(value))
            value_edit.setFont(QFont("Courier", 8))
            value_edit.setMinimumWidth(150)
            value_edit.setStyleSheet(
                f"border: 1px solid {value_border}; background-color: {value_bg}; "
                f"color: {value_color}; padding: 2px;"
            )

            # Store metadata for highlighting and editing
            value_edit.setProperty('byte_size', byte_size)
            value_edit.setProperty('data_offset', data_offset)
            value_edit.setProperty('data_type', data_type)

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
            widget.setLayout(layout)
            self.inspector_content_layout.addWidget(widget)

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

        # Single (float32) - IEEE 754 single precision floating point
        if bytes_32:
            fmt = '<f' if self.editor.endian_mode == 'little' else '>f'
            float_val = struct.unpack(fmt, bytes_32)[0]
            add_inspector_row("Single (float32):", f"{float_val:.6f}", byte_size=4, data_offset=0, data_type='float')

        # Double (float64) - IEEE 754 double precision floating point
        if bytes_64:
            fmt = '<d' if self.editor.endian_mode == 'little' else '>d'
            double_val = struct.unpack(fmt, bytes_64)[0]
            add_inspector_row("Double (float64):", f"{double_val:.15f}", byte_size=8, data_offset=0, data_type='double')

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

        current_file = self.editor.open_files[self.editor.current_tab_index]
        file_data = current_file.file_data

        try:
            text = line_edit.text().strip()

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
                value = float(text)
                fmt = '<f' if self.editor.endian_mode == 'little' else '>f'
                bytes_val = struct.pack(fmt, value)
                for i, b in enumerate(bytes_val):
                    if position + i < len(file_data):
                        file_data[position + i] = b

            elif data_type == 'double':
                value = float(text)
                fmt = '<d' if self.editor.endian_mode == 'little' else '>d'
                bytes_val = struct.pack(fmt, value)
                for i, b in enumerate(bytes_val):
                    if position + i < len(file_data):
                        file_data[position + i] = b

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
                         2 if data_type in ['int16', 'uint16', 'widechar', 'dos_date', 'dos_time'] else \
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
            self.editor.display_hex()
            self.update()

        except (ValueError, struct.error) as e:
            # Reset to original value on error
            print(f"Invalid input: {e}")
            self.update()
