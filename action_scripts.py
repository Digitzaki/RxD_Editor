import json
import json
import os
import sys
import ctypes
import math
import random
import re
import struct
from copy import deepcopy

from PyQt5.QtCore import QObject, QEvent, Qt, QTimer, pyqtSignal
from PyQt5.QtGui import QFont, QKeySequence, QColor
from PyQt5.QtWidgets import (
    QAction, QComboBox, QDialog, QDialogButtonBox, QFormLayout, QHBoxLayout,
    QLabel, QLineEdit, QListWidget, QListWidgetItem, QMessageBox, QPushButton,
    QFileDialog, QMenu, QInputDialog,
    QTextEdit, QVBoxLayout, QWidget, QApplication
)
from editor_themes import get_theme_colors, get_theme_surface_colors
from rxd_paths import migrated_storage_path

from datainspect.pointers import SignaturePointer


SCRIPT_STORAGE = migrated_storage_path(
    "action_scripts.json",
    [os.path.join(os.path.dirname(os.path.abspath(__file__)), "action_scripts.json")]
)


def safe_export_filename(name, extension=".json"):
    cleaned = re.sub(r"[^A-Za-z0-9._ -]+", "_", str(name or "export")).strip().strip(".")
    if not cleaned:
        cleaned = "export"
    if not cleaned.lower().endswith(extension):
        cleaned += extension
    return cleaned


def apply_native_titlebar_theme(window, dark=None):
    if sys.platform != "win32" or window is None:
        return
    try:
        if dark is None:
            parent = window.parent()
            dark = parent.system_uses_dark_titlebar() if hasattr(parent, "system_uses_dark_titlebar") else False
        enabled = ctypes.c_int(1 if dark else 0)
        for attribute in (20, 19):
            result = ctypes.windll.dwmapi.DwmSetWindowAttribute(
                ctypes.c_void_p(int(window.winId())),
                ctypes.c_uint(attribute),
                ctypes.byref(enabled),
                ctypes.sizeof(enabled)
            )
            if result == 0:
                break
    except Exception:
        pass


def script_dialog_stylesheet(parent):
    theme = get_theme_colors(getattr(parent, "current_theme", "Dark"))
    surfaces = get_theme_surface_colors(theme)
    surface_bg = surfaces["surface"]
    control_bg = surfaces["control"]
    control_fg = surfaces["control_text"]
    text_fg = surfaces["text"]
    return f"""
        QDialog {{
            background-color: {surface_bg};
            color: {text_fg};
            font-family: Arial;
            font-size: 9pt;
        }}
        QDialog QLabel {{
            color: {text_fg};
            font-size: 9pt;
        }}
        QDialog QLineEdit,
        QDialog QTextEdit,
        QDialog QListWidget,
        QDialog QComboBox {{
            background-color: {control_bg};
            color: {control_fg};
            border: 1px solid {theme.get('border', '#555555')};
            padding: 2px 4px;
            min-height: 18px;
            font-size: 8pt;
        }}
        QDialog QComboBox::drop-down {{
            width: 16px;
        }}
        QDialog QListWidget::item {{
            padding: 2px 4px;
            min-height: 16px;
        }}
        QDialog QListWidget::item:selected {{
            background-color: {theme.get('selection_bg', theme.get('button_bg', '#990000'))};
            color: {theme.get('selection_fg', theme.get('foreground', '#ffffff'))};
        }}
        QDialog QPushButton {{
            background-color: {theme.get('button_bg', '#990000')};
            color: {theme.get('button_text', theme.get('foreground', '#ffffff'))};
            border: none;
            border-radius: 3px;
            padding: 3px 10px;
            min-height: 20px;
            min-width: 58px;
            font-size: 9pt;
        }}
        QDialog QPushButton:hover {{
            background-color: {theme.get('button_hover', '#b00000')};
        }}
        QMenu {{
            background-color: {surface_bg};
            color: {text_fg};
            border: 1px solid {theme.get('border', '#555555')};
            font-size: 8pt;
        }}
        QMenu::item {{
            padding: 3px 18px 3px 8px;
        }}
        QMenu::item:selected {{
            background-color: {theme.get('selection_bg', theme.get('button_bg', '#990000'))};
            color: {theme.get('selection_fg', theme.get('foreground', '#ffffff'))};
        }}
        QDialog QDialogButtonBox QPushButton {{
            min-width: 64px;
        }}
        QMessageBox {{
            background-color: {surface_bg};
            color: {text_fg};
            font-family: Arial;
            font-size: 9pt;
        }}
        QMessageBox QLabel {{
            color: {text_fg};
            font-size: 9pt;
        }}
        QMessageBox QPushButton {{
            background-color: {theme.get('button_bg', '#990000')};
            color: {theme.get('button_text', theme.get('foreground', '#ffffff'))};
            border: none;
            border-radius: 3px;
            padding: 3px 14px;
            min-height: 20px;
            min-width: 56px;
            font-size: 9pt;
        }}
        QMessageBox QPushButton:hover {{
            background-color: {theme.get('button_hover', '#b00000')};
        }}
    """


def compact_layout(layout):
    if layout is None:
        return
    left, top, right, bottom = layout.getContentsMargins()
    layout.setContentsMargins(min(left, 8), min(top, 8), min(right, 8), min(bottom, 8))
    if layout.spacing() < 0 or layout.spacing() > 6:
        layout.setSpacing(5)
    for i in range(layout.count()):
        item = layout.itemAt(i)
        if item and item.layout():
            compact_layout(item.layout())


class ScriptBaseDialog(QDialog):
    def showEvent(self, event):
        super().showEvent(event)
        parent = self.parent()
        root = parent
        while root is not None and not hasattr(root, "current_theme"):
            root = root.parent() if hasattr(root, "parent") else None
        theme_parent = root or parent
        self.setFont(QFont("Arial", 9))
        compact_layout(self.layout())
        if not self.property("scriptDialogStyled"):
            self.setStyleSheet(script_dialog_stylesheet(theme_parent))
            self.setProperty("scriptDialogStyled", True)
        dark = theme_parent.system_uses_dark_titlebar() if hasattr(theme_parent, "system_uses_dark_titlebar") else None
        QTimer.singleShot(0, lambda: apply_native_titlebar_theme(self, dark))


ACTION_SPECS = {
    "go_offset": ("Navigation", "Go to offset", [("offset", "Offset", "0x0")]),
    "select_range": ("Navigation", "Select range", [("start", "Start", "0x0"), ("length", "Length", "1")]),
    "write_bytes": ("Editing", "Write bytes", [("offset", "Offset", "cursor"), ("bytes", "Hex bytes", "00")]),
    "insert_bytes": ("Editing", "Insert bytes", [("offset", "Offset", "cursor"), ("bytes", "Hex bytes", "00")]),
    "delete_bytes": ("Editing", "Delete bytes", [("offset", "Offset", "cursor"), ("length", "Length", "1")]),
    "fill_selection": ("Editing", "Fill selection", [("bytes", "Hex bytes/pattern", "00")]),
    "replace_byte_pattern": ("Editing", "Replace byte pattern", [("find", "Find hex", ""), ("replace", "Replace hex", "")]),
    "search_hex": ("Search", "Search for hex pattern", [("pattern", "Hex pattern", ""), ("direction", "Direction", "All")]),
    "search_text": ("Search", "Search for text/string", [("text", "Text", ""), ("encoding", "Encoding", "utf-8"), ("direction", "Direction", "All")]),
    "search_data": ("Search", "Search data value/range", [("type", "Type", "Float32"), ("mode", "Mode", "Value"), ("value", "Value", ""), ("min", "Min", ""), ("max", "Max", ""), ("direction", "Direction", "All")]),
    "search_color": ("Search", "Search color", [("format", "Format", "RGBA32"), ("mode", "Mode", "Value"), ("values", "Values", "R=255,G=255,B=255,A="), ("direction", "Direction", "All")]),
    "search_vector": ("Search", "Search vector", [("shape", "Shape", "Vector3"), ("type", "Type", "Float32"), ("endian", "Endian", "LE"), ("mode", "Mode", "Value"), ("values", "Values", "X=0,Y=0,Z=0"), ("direction", "Direction", "All")]),
    "replace_hex": ("Replace", "Replace hex", [("find", "Find hex", ""), ("replace", "Replace hex", ""), ("direction", "Direction", "All")]),
    "replace_text": ("Replace", "Replace text/string", [("find", "Find text", ""), ("replace", "Replace text", ""), ("encoding", "Encoding", "utf-8"), ("direction", "Direction", "All")]),
    "replace_data": ("Replace", "Replace data value/range", [("type", "Type", "Float32"), ("mode", "Find Mode", "Value"), ("value", "Find Value", ""), ("min", "Find Min", ""), ("max", "Find Max", ""), ("replace_mode", "Replace Mode", "Fixed"), ("replace_value", "Replace Value", ""), ("replace_min", "Random Min", ""), ("replace_max", "Random Max", ""), ("direction", "Direction", "All")]),
    "replace_color": ("Replace", "Replace color", [("format", "Format", "RGBA32"), ("mode", "Find Mode", "Value"), ("values", "Find Values", "R=255,G=255,B=255,A="), ("replace_mode", "Replace Mode", "Fixed"), ("replace_values", "Replace Values", "R=,G=,B=,A="), ("direction", "Direction", "All")]),
    "replace_vector": ("Replace", "Replace vector", [("shape", "Shape", "Vector3"), ("type", "Type", "Float32"), ("endian", "Endian", "LE"), ("mode", "Find Mode", "Value"), ("values", "Find Values", "X=0,Y=0,Z=0"), ("replace_mode", "Replace Mode", "Fixed"), ("replace_values", "Replace Values", "X=,Y=,Z="), ("direction", "Direction", "All")]),
    "jump_next_result": ("Search", "Jump to next result", []),
    "jump_previous_result": ("Search", "Jump to previous result", []),
    "inspector_math": ("Data Inspector", "Apply inspector math", [
        ("target", "Target", "Numeric"),
        ("type", "Type", "Float32"),
        ("expression", "Expression", "value+1"),
    ]),
    "inspector_set_color": ("Data Inspector", "Set color", [("format", "Format", "RGBA32"), ("values", "Values", "R=255,G=255,B=255,A=255")]),
    "add_delimiter": ("Organization", "Add delimiter value", [("value", "Byte value", "00"), ("padding", "Padding", "1")]),
    "remove_delimiter": ("Organization", "Remove delimiter value", [("value", "Byte value", "00")]),
    "toggle_delimiter_visibility": ("Organization", "Toggle delimiter visibility", []),
    "delimit_selection": ("Organization", "Delimit selection", [("value", "Byte value", "00"), ("padding", "Padding", "1")]),
    "create_highlight": ("Highlights", "Create highlight", [("start", "Start", "cursor"), ("length", "Length", "1"), ("color", "Color", "#ff0000"), ("message", "Message", "")]),
    "highlight_selected_range": ("Highlights", "Highlight selected range", [("color", "Color", "#ff0000"), ("message", "Message", "")]),
    "highlight_byte_pattern": ("Highlights", "Highlight byte pattern", [("pattern", "Hex pattern", ""), ("color", "Color", "#ff0000"), ("message", "Message", "")]),
    "toggle_highlight_visibility": ("Highlights", "Toggle highlight visibility", []),
    "remove_highlight": ("Highlights", "Remove highlight", [("start", "Start", "selection"), ("length", "Length", "selection")]),
    "create_pointer_box": ("Pointer Boxes", "Create pointer box", [("offset", "Offset", "cursor"), ("length", "Length", "4"), ("type", "Type", "uint32"), ("label", "Label", "Script Pointer")]),
    "delete_pointer_box": ("Pointer Boxes", "Delete pointer box", [("label", "Label contains", "")]),
    "jump_pointer_box": ("Pointer Boxes", "Jump through pointer box", [("label", "Label contains", "")]),
}


def default_script():
    return {"name": "New Script", "description": "", "hotkey": "", "actions": []}


MODIFIER_KEYS = {
    Qt.Key_Control, Qt.Key_Shift, Qt.Key_Alt, Qt.Key_Meta,
    Qt.Key_AltGr, Qt.Key_CapsLock, Qt.Key_NumLock, Qt.Key_ScrollLock
}


def hotkey_from_event(event):
    key = event.key()
    if key in MODIFIER_KEYS or key == Qt.Key_unknown:
        return ""

    parts = []
    modifiers = event.modifiers()
    if modifiers & Qt.ControlModifier:
        parts.append("Ctrl")
    if modifiers & Qt.AltModifier:
        parts.append("Alt")
    if modifiers & Qt.ShiftModifier:
        parts.append("Shift")
    if modifiers & Qt.MetaModifier:
        parts.append("Meta")

    keypad = bool(modifiers & Qt.KeypadModifier)
    if keypad and Qt.Key_0 <= key <= Qt.Key_9:
        key_name = f"NumPad{key - Qt.Key_0}"
    elif Qt.Key_0 <= key <= Qt.Key_9:
        key_name = str(key - Qt.Key_0)
    elif Qt.Key_A <= key <= Qt.Key_Z:
        key_name = chr(ord('A') + key - Qt.Key_A)
    elif Qt.Key_F1 <= key <= Qt.Key_F24:
        key_name = f"F{key - Qt.Key_F1 + 1}"
    elif key == Qt.Key_Space:
        key_name = "Space"
    else:
        key_name = QKeySequence(key).toString(QKeySequence.NativeText)
        if not key_name:
            return ""

    parts.append(key_name)
    return "+".join(parts)


def normalize_hotkey(text):
    return "+".join(part.strip() for part in str(text).split("+") if part.strip())


class HotkeyCaptureEdit(QLineEdit):
    def __init__(self, hotkey="", parent=None):
        super().__init__(parent)
        self.setReadOnly(True)
        self.setPlaceholderText("Click, then press shortcut")
        self.setText(normalize_hotkey(hotkey))
        self.setFont(QFont("Courier", 8))

    def keyPressEvent(self, event):
        if event.key() in (Qt.Key_Backspace, Qt.Key_Delete, Qt.Key_Escape):
            self.clear()
            event.accept()
            return
        hotkey = hotkey_from_event(event)
        if hotkey:
            self.setText(hotkey)
            event.accept()
            return
        super().keyPressEvent(event)


class ActionHotkeyFilter(QObject):
    def __init__(self, manager):
        super().__init__(manager.editor)
        self.manager = manager

    def eventFilter(self, obj, event):
        if event.type() != QEvent.KeyPress or event.isAutoRepeat():
            return False
        if QApplication.activeModalWidget() is not None:
            return False
        active = QApplication.activeWindow()
        if active is not self.manager.editor:
            return False

        focus = QApplication.focusWidget()
        if focus and isinstance(focus, (QLineEdit, QTextEdit, QComboBox)) and focus.__class__.__name__ != "HexTextEdit":
            return False

        hotkey = hotkey_from_event(event)
        if not hotkey:
            return False
        index = self.manager.hotkey_map.get(hotkey)
        if index is None:
            return False
        self.manager.run_script(index)
        event.accept()
        return True


class ActionScriptManager:
    def __init__(self, editor):
        self.editor = editor
        self.scripts = []
        self.hotkey_map = {}
        self.hotkey_filter = ActionHotkeyFilter(self)
        QApplication.instance().installEventFilter(self.hotkey_filter)
        self.load()

    def load(self):
        try:
            with open(SCRIPT_STORAGE, "r", encoding="utf-8") as f:
                data = json.load(f)
            self.scripts = data if isinstance(data, list) else []
        except Exception:
            self.scripts = []

    def save(self):
        with open(SCRIPT_STORAGE, "w", encoding="utf-8") as f:
            json.dump(self.scripts, f, indent=2)

    def export_to_file(self, path, index=None):
        if index is None:
            if len(self.scripts) != 1:
                raise ValueError("Choose one script to export")
            script = self.scripts[0]
        else:
            if index < 0 or index >= len(self.scripts):
                raise ValueError("No script selected")
            script = self.scripts[index]
        with open(path, "w", encoding="utf-8") as f:
            json.dump({"script": script}, f, indent=2)

    def import_from_file(self, path):
        with open(path, "r", encoding="utf-8") as f:
            data = json.load(f)
        if isinstance(data, dict) and "script" in data:
            script = data["script"]
        elif isinstance(data, dict) and "scripts" in data:
            scripts = data["scripts"]
            if not isinstance(scripts, list) or len(scripts) != 1:
                raise ValueError("Import one script at a time")
            script = scripts[0]
        elif isinstance(data, list):
            if len(data) != 1:
                raise ValueError("Import one script at a time")
            script = data[0]
        else:
            script = data
        if not isinstance(script, dict):
            raise ValueError("Script file must contain one script object")

        imported = deepcopy(default_script())
        imported.update(script)
        imported["actions"] = script.get("actions", []) if isinstance(script.get("actions", []), list) else []
        if not imported.get("name"):
            imported["name"] = "Imported Script"
        if (imported.get("hotkey") and hasattr(self.editor, "find_hotkey_conflict") and
                self.editor.find_hotkey_conflict(imported.get("hotkey"), ignore_script_name=imported.get("name"))):
            imported["hotkey"] = ""
        self.scripts.append(imported)
        self.save()
        self.install_shortcuts()
        return imported.get("name", "Imported Script")

    def install_shortcuts(self):
        self.hotkey_map = {}
        for index, script in enumerate(self.scripts):
            hotkey = normalize_hotkey(script.get("hotkey", ""))
            if not hotkey:
                continue
            self.hotkey_map[hotkey] = index

    def run_script(self, index):
        if index < 0 or index >= len(self.scripts):
            return
        runner = ActionScriptRunner(self.editor)
        runner.run(self.scripts[index])


class ActionScriptRunner:
    NUMERIC_FORMATS = {
        "Byte": ("B", 1, 0, 255, False),
        "ByteHex": ("B", 1, 0, 255, False),
        "Int8": ("b", 1, -128, 127, False),
        "UInt8": ("B", 1, 0, 255, False),
        "Int16": ("h", 2, -32768, 32767, False),
        "UInt16": ("H", 2, 0, 65535, False),
        "Int32": ("i", 4, -2147483648, 2147483647, False),
        "UInt32": ("I", 4, 0, 4294967295, False),
        "Int64": ("q", 8, -9223372036854775808, 9223372036854775807, False),
        "UInt64": ("Q", 8, 0, 18446744073709551615, False),
        "Float16": ("e", 2, None, None, True),
        "HalfFloat": ("e", 2, None, None, True),
        "Float32": ("f", 4, None, None, True),
        "Float64": ("d", 8, None, None, True),
    }
    COLOR_FORMATS = {
        "RGB24": ("R", "G", "B"),
        "RGBA32": ("R", "G", "B", "A"),
        "BGR24": ("B", "G", "R"),
        "BGRA32": ("B", "G", "R", "A"),
        "ARGB32": ("A", "R", "G", "B"),
        "ABGR32": ("A", "B", "G", "R"),
        "HSV": ("H", "S", "V"),
    }
    VECTOR_FORMATS = {
        "Int8": ("b", 1, -128, 127, False),
        "UInt8": ("B", 1, 0, 255, False),
        "Int16": ("h", 2, -32768, 32767, False),
        "UInt16": ("H", 2, 0, 65535, False),
        "Int32": ("i", 4, -2147483648, 2147483647, False),
        "UInt32": ("I", 4, 0, 4294967295, False),
        "Float16": ("e", 2, None, None, True),
        "Float32": ("f", 4, None, None, True),
        "Float64": ("d", 8, None, None, True),
    }
    VECTOR_COMPONENTS = {
        "Vector2": ("X", "Y"),
        "Vector3": ("X", "Y", "Z"),
        "Vector4": ("X", "Y", "Z", "W"),
        "Quaternion": ("X", "Y", "Z", "W"),
        "BoundingBox": ("Min X", "Min Y", "Min Z", "Max X", "Max Y", "Max Z"),
        "Bounding Box": ("Min X", "Min Y", "Min Z", "Max X", "Max Y", "Max Z"),
    }

    def __init__(self, editor):
        self.editor = editor
        self.highlight_visible = True
        self.defer_refresh = False
        self.refresh_requested = False

    def error(self, message):
        box = QMessageBox(self.editor)
        box.setIcon(QMessageBox.Warning)
        box.setWindowTitle("Action Script Error")
        box.setText(message)
        box.setStandardButtons(QMessageBox.Ok)
        box.setFont(QFont("Arial", 9))
        box.setStyleSheet(script_dialog_stylesheet(self.editor))
        dark = self.editor.system_uses_dark_titlebar() if hasattr(self.editor, "system_uses_dark_titlebar") else None
        QTimer.singleShot(0, lambda: apply_native_titlebar_theme(box, dark))
        box.exec_()

    def current_file(self):
        if self.editor.current_tab_index < 0:
            raise ValueError("No file is open")
        return self.editor.open_files[self.editor.current_tab_index]

    def parse_offset(self, text):
        if text in (None, "", "cursor"):
            if self.editor.cursor_position is None:
                raise ValueError("No cursor position")
            return self.editor.cursor_position
        return int(str(text).strip(), 0)

    def parse_length(self, text):
        if text == "selection":
            if self.editor.selection_start is None or self.editor.selection_end is None:
                raise ValueError("No selection")
            return abs(self.editor.selection_end - self.editor.selection_start) + 1
        value = int(str(text).strip(), 0)
        if value < 0:
            raise ValueError("Length cannot be negative")
        return value

    def parse_byte_value(self, text):
        text = str(text).strip()
        if text.lower().startswith("0x"):
            value = int(text, 16)
        elif any(c in text for c in "abcdefABCDEF"):
            value = int(text, 16)
        else:
            value = int(text, 10)
        if not 0 <= value <= 255:
            raise ValueError("Byte value out of range")
        return value

    def parse_hex(self, text):
        cleaned = str(text).replace("0x", "").replace("0X", "").replace(",", " ").replace("_", "")
        cleaned = "".join(cleaned.split())
        if not cleaned or len(cleaned) % 2:
            raise ValueError("Invalid hex bytes")
        return bytes.fromhex(cleaned)

    def endian_prefix(self):
        return "<" if getattr(self.editor, "endian_mode", "little") == "little" else ">"

    def normalize_name(self, text):
        return re.sub(r"[^a-z0-9]", "", str(text or "").lower())

    def choose_key(self, value, choices, label):
        normalized = self.normalize_name(value)
        for choice in choices:
            if self.normalize_name(choice) == normalized:
                return choice
        raise ValueError(f"Unknown {label}: {value}")

    def current_offset(self):
        if self.editor.cursor_position is None:
            raise ValueError("No cursor position")
        return self.editor.cursor_position

    def read_struct_value(self, data, offset, fmt_char, size, is_float):
        if offset < 0 or offset + size > len(data):
            raise ValueError("Not enough bytes for inspector value")
        if size == 1:
            return struct.unpack(fmt_char, bytes(data[offset:offset + size]))[0]
        return struct.unpack(self.endian_prefix() + fmt_char, bytes(data[offset:offset + size]))[0]

    def pack_struct_value(self, value, fmt_char, size, min_value=None, max_value=None, is_float=False):
        if is_float:
            value = float(value)
            if not math.isfinite(value):
                raise ValueError("Inspector math result is not finite")
        else:
            value = round(float(value))
            if min_value is not None and value < min_value:
                value = min_value
            if max_value is not None and value > max_value:
                value = max_value
            value = int(value)
        if size == 1:
            return struct.pack(fmt_char, value)
        return struct.pack(self.endian_prefix() + fmt_char, value)

    def evaluate_inspector_expression(self, expression, current_value, is_float=False):
        expr = str(expression or "").strip()
        if not expr:
            raise ValueError("Expression is empty")

        if expr[0] in "+-*/^%":
            expr = f"value{expr}"

        value_text = repr(float(current_value)) if is_float else str(int(round(float(current_value))))

        def percent_repl(match):
            number = match.group(1)
            return f"(value*({number})/100)"

        expr = re.sub(r"(?i)\b(current|value)\b", "value", expr)
        expr = re.sub(r"([+-])\s*(\d+(?:\.\d+)?)%", lambda m: f"{m.group(1)}(value*{m.group(2)}/100)", expr)
        expr = re.sub(r"(?<![A-Za-z0-9_.])(\d+(?:\.\d+)?)%", percent_repl, expr)
        expr = expr.replace("value", value_text)

        inspector = getattr(self.editor, "data_inspector", None)
        if inspector and hasattr(inspector, "_evaluate_simple_math_expression"):
            result = inspector._evaluate_simple_math_expression(expr, default_float=is_float)
        else:
            raise ValueError("Data inspector math parser is unavailable")
        if result is None:
            result = float(expr) if is_float else int(expr, 0)
        return result

    def commit_bytes(self, offset, data):
        inspector = getattr(self.editor, "data_inspector", None)
        if inspector and hasattr(inspector, "_commit_bytes"):
            inspector._commit_bytes(offset, data, defer_refresh=True)
            return
        current = self.current_file()
        self.editor.save_undo_state()
        current.file_data[offset:offset + len(data)] = data
        current.modified_bytes.update(range(offset, offset + len(data)))
        current.modified = True
        self.refresh()

    def validate_range(self, offset, length, allow_end=False):
        file_len = len(self.current_file().file_data)
        max_end = file_len if allow_end else file_len - 1
        if offset < 0 or offset > max_end:
            raise ValueError("Offset out of range")
        if length < 0 or offset + length > file_len:
            raise ValueError("Range out of file bounds")

    def find_matches(self, data, pattern, start=0, end=None, overlap=False):
        if not pattern:
            raise ValueError("Search pattern is empty")
        if end is None:
            end = len(data)
        matches = []
        start = max(0, start)
        end = min(len(data), end)
        while True:
            pos = data.find(pattern, start, end)
            if pos < 0:
                break
            matches.append(pos)
            start = pos + (1 if overlap else len(pattern))
        return matches

    def search_matches_for_direction(self, data, pattern, direction):
        direction = str(direction or "All").strip().lower()
        cursor = self.editor.cursor_position
        if direction in ("forward", "next"):
            start = (cursor + 1) if cursor is not None else 0
            pos = data.find(pattern, start)
            return [] if pos < 0 else [pos]
        if direction in ("backward", "previous", "prev"):
            end = cursor if cursor is not None else len(data)
            pos = data.rfind(pattern, 0, end)
            return [] if pos < 0 else [pos]
        return self.find_matches(data, pattern)

    def range_for_direction(self, data_len, direction):
        direction = str(direction or "All").strip().lower()
        cursor = self.editor.cursor_position
        if direction in ("forward", "next"):
            return (cursor if cursor is not None else 0), data_len
        if direction in ("backward", "previous", "prev"):
            return 0, (cursor if cursor is not None else data_len)
        return 0, data_len

    def parse_component_text(self, labels, text, range_mode=False, is_float=False):
        values = {self.normalize_name(label): None for label in labels}
        label_lookup = {self.normalize_name(label): label for label in labels}
        raw = str(text or "").strip()
        if not raw:
            return [None for _ in labels]
        parts = [part.strip() for part in re.split(r"[;,]", raw) if part.strip()]
        positional = 0
        for part in parts:
            if "=" in part:
                key, value_text = part.split("=", 1)
                label_key = self.normalize_name(key)
                if label_key not in label_lookup:
                    raise ValueError(f"Unknown component: {key}")
            else:
                if positional >= len(labels):
                    raise ValueError("Too many component values")
                label_key = self.normalize_name(labels[positional])
                value_text = part
                positional += 1
            value_text = value_text.strip()
            if value_text == "":
                values[label_key] = None
                continue
            if range_mode:
                match = re.match(r"^\s*([-+]?(?:0x[0-9a-fA-F]+|\d+(?:\.\d+)?))\s*(?:-|\.\.)\s*([-+]?(?:0x[0-9a-fA-F]+|\d+(?:\.\d+)?))\s*$", value_text)
                if not match:
                    raise ValueError(f"Invalid range for {label_lookup[label_key]}")
                a_text, b_text = match.groups()
                a = float(a_text) if is_float else int(a_text, 0)
                b = float(b_text) if is_float else int(b_text, 0)
                values[label_key] = (min(a, b), max(a, b))
            else:
                values[label_key] = float(value_text) if is_float else int(value_text, 0)
        return [values[self.normalize_name(label)] for label in labels]

    def component_values_match(self, values, criteria, range_mode):
        for value, criterion in zip(values, criteria):
            if criterion is None:
                continue
            if range_mode:
                if not (criterion[0] <= value <= criterion[1]):
                    return False
            elif value != criterion:
                return False
        return True

    def numeric_type_info(self, type_name):
        fmt_name = self.choose_key(type_name, self.NUMERIC_FORMATS.keys(), "numeric type")
        fmt_char, size, min_value, max_value, is_float = self.NUMERIC_FORMATS[fmt_name]
        fmt = fmt_char if size == 1 else self.endian_prefix() + fmt_char
        return fmt_name, fmt, fmt_char, size, min_value, max_value, is_float

    def find_data_matches(self, data, s):
        _name, fmt, _fmt_char, size, _min_value, _max_value, is_float = self.numeric_type_info(s.get("type", "Float32"))
        range_mode = self.normalize_name(s.get("mode", "Value")) == "range"
        if range_mode:
            if str(s.get("min", "")).strip() == "" or str(s.get("max", "")).strip() == "":
                raise ValueError("Data range needs min and max")
            mn = float(s.get("min")) if is_float else int(str(s.get("min")), 0)
            mx = float(s.get("max")) if is_float else int(str(s.get("max")), 0)
            criteria = (min(mn, mx), max(mn, mx))
        else:
            if str(s.get("value", "")).strip() == "":
                raise ValueError("Data search needs a value")
            criteria = float(s.get("value")) if is_float else int(str(s.get("value")), 0)
        start, end = self.range_for_direction(len(data), s.get("direction", "All"))
        matches = []
        for pos in range(start, max(start, end - size + 1)):
            try:
                value = struct.unpack(fmt, data[pos:pos + size])[0]
            except Exception:
                continue
            if (range_mode and criteria[0] <= value <= criteria[1]) or (not range_mode and value == criteria):
                matches.append(pos)
        return matches, size

    def find_color_matches(self, data, s):
        fmt_name = self.choose_key(s.get("format", "RGBA32"), self.COLOR_FORMATS.keys(), "color format")
        labels = self.COLOR_FORMATS[fmt_name]
        size = len(labels)
        range_mode = self.normalize_name(s.get("mode", "Value")) == "range"
        criteria = self.parse_component_text(labels, s.get("values", ""), range_mode=range_mode, is_float=False)
        start, end = self.range_for_direction(len(data), s.get("direction", "All"))
        matches = []
        for pos in range(start, max(start, end - size + 1)):
            values = list(data[pos:pos + size])
            if self.component_values_match(values, criteria, range_mode):
                matches.append(pos)
        return matches, size, fmt_name, labels

    def find_vector_matches(self, data, s):
        shape = self.choose_key(s.get("shape", "Vector3"), self.VECTOR_COMPONENTS.keys(), "vector shape")
        component_type = self.choose_key(s.get("type", "Float32"), self.VECTOR_FORMATS.keys(), "vector component type")
        endian = ">" if self.normalize_name(s.get("endian", "LE")) in ("be", "big", "bigendian") else "<"
        fmt_char, component_size, _min_value, _max_value, is_float = self.VECTOR_FORMATS[component_type]
        fmt = fmt_char if component_size == 1 else endian + fmt_char
        labels = self.VECTOR_COMPONENTS[shape]
        size = component_size * len(labels)
        range_mode = self.normalize_name(s.get("mode", "Value")) == "range"
        criteria = self.parse_component_text(labels, s.get("values", ""), range_mode=range_mode, is_float=is_float)
        start, end = self.range_for_direction(len(data), s.get("direction", "All"))
        matches = []
        for pos in range(start, max(start, end - size + 1)):
            try:
                values = [
                    struct.unpack(fmt, data[pos + i * component_size:pos + (i + 1) * component_size])[0]
                    for i in range(len(labels))
                ]
            except Exception:
                continue
            if self.component_values_match(values, criteria, range_mode):
                matches.append(pos)
        return matches, size, shape, component_type, labels, fmt, component_size, is_float

    def replace_fixed_or_random(self, old_values, labels, spec_text, random_mode, is_float=False, clamp_byte=False):
        parsed = self.parse_component_text(labels, spec_text, range_mode=random_mode, is_float=is_float)
        out = list(old_values)
        for i, criterion in enumerate(parsed):
            if criterion is None:
                continue
            if random_mode:
                value = random.uniform(criterion[0], criterion[1]) if is_float else random.randint(int(criterion[0]), int(criterion[1]))
            else:
                value = criterion
            if clamp_byte:
                value = max(0, min(255, int(round(float(value)))))
            elif not is_float:
                value = int(round(float(value)))
            out[i] = value
        return out

    def run(self, script):
        self.defer_refresh = True
        self.refresh_requested = False
        try:
            for action in script.get("actions", []):
                self.run_action(action.get("type"), action.get("settings", {}))
                QApplication.processEvents()
        except Exception as e:
            self.error(str(e))
        finally:
            self.defer_refresh = False
            if self.refresh_requested:
                self.refresh()

    def run_action(self, action_type, settings):
        method = getattr(self, f"act_{action_type}", None)
        if not method:
            raise ValueError(f"Unsupported action: {action_type}")
        method(settings)

    def refresh(self):
        if self.defer_refresh:
            self.refresh_requested = True
            return
        self.editor.display_hex(preserve_scroll=True)
        self.editor.data_inspector.update()

    def act_go_offset(self, s):
        offset = self.parse_offset(s.get("offset"))
        self.validate_range(offset, 0)
        self.editor.cursor_position = offset
        self.editor.cursor_nibble = 0
        self.editor.scroll_to_offset(offset, center=True)
        self.refresh()

    def act_select_range(self, s):
        start = self.parse_offset(s.get("start"))
        length = self.parse_length(s.get("length"))
        self.validate_range(start, length)
        self.editor.selection_start = start
        self.editor.selection_end = start + length - 1
        self.editor.cursor_position = start
        self.refresh()

    def act_write_bytes(self, s):
        data = self.parse_hex(s.get("bytes", ""))
        offset = self.parse_offset(s.get("offset"))
        self.validate_range(offset, len(data))
        current = self.current_file()
        self.editor.save_undo_state()
        current.file_data[offset:offset + len(data)] = data
        current.modified_bytes.update(range(offset, offset + len(data)))
        current.modified = True
        self.refresh()

    def act_insert_bytes(self, s):
        data = self.parse_hex(s.get("bytes", ""))
        offset = self.parse_offset(s.get("offset"))
        self.validate_range(offset, 0, allow_end=True)
        current = self.current_file()
        self.editor.save_undo_state()
        current.file_data[offset:offset] = data
        current.inserted_bytes.update(range(offset, offset + len(data)))
        current.modified = True
        self.refresh()

    def act_delete_bytes(self, s):
        offset = self.parse_offset(s.get("offset"))
        length = self.parse_length(s.get("length"))
        self.validate_range(offset, length)
        current = self.current_file()
        self.editor.save_undo_state()
        del current.file_data[offset:offset + length]
        current.modified = True
        self.editor.cursor_position = min(offset, max(0, len(current.file_data) - 1))
        self.refresh()

    def act_fill_selection(self, s):
        if self.editor.selection_start is None or self.editor.selection_end is None:
            raise ValueError("No selection")
        pattern = self.parse_hex(s.get("bytes", ""))
        if not pattern:
            raise ValueError("Fill pattern is empty")
        start = min(self.editor.selection_start, self.editor.selection_end)
        end = max(self.editor.selection_start, self.editor.selection_end)
        current = self.current_file()
        self.editor.save_undo_state()
        length = end - start + 1
        repeats = (pattern * ((length + len(pattern) - 1) // len(pattern)))[:length]
        current.file_data[start:end + 1] = repeats
        current.modified_bytes.update(range(start, end + 1))
        current.modified = True
        self.refresh()

    def act_replace_byte_pattern(self, s):
        find = self.parse_hex(s.get("find", ""))
        replace = self.parse_hex(s.get("replace", ""))
        if not find:
            raise ValueError("Find pattern is empty")
        current = self.current_file()
        data = current.file_data
        self.editor.save_undo_state()
        pos = 0
        count = 0
        while True:
            pos = data.find(find, pos)
            if pos < 0:
                break
            original_end = pos + len(find)
            data[pos:original_end] = replace
            current.modified_bytes.update(range(pos, pos + len(replace)))
            count += 1
            pos += max(1, len(replace))
        if count == 0:
            raise ValueError("Pattern not found")
        current.modified = True
        self.refresh()

    def set_search_results(self, matches, size, title="Search", pattern=None):
        current = self.current_file()
        results = [(pos, size) for pos in matches]
        current.search_results = results
        if hasattr(self.editor, "publish_search_results"):
            self.editor.publish_search_results(title, results, pattern=pattern)
            return
        if matches:
            self.editor.cursor_position = matches[0]
            self.editor.cursor_nibble = 0
            self.editor.scroll_to_offset(matches[0], center=True)
        self.refresh()

    def act_search_hex(self, s):
        pattern = self.parse_hex(s.get("pattern", ""))
        data = bytes(self.current_file().file_data)
        matches = self.search_matches_for_direction(data, pattern, s.get("direction", "All"))
        title = " ".join(f"{b:02X}" for b in pattern)
        self.set_search_results(matches, len(pattern), title=title, pattern=pattern)

    def act_search_text(self, s):
        encoding = s.get("encoding") or "utf-8"
        pattern = str(s.get("text", "")).encode(encoding)
        if not pattern:
            raise ValueError("Search text is empty")
        data = bytes(self.current_file().file_data)
        matches = self.search_matches_for_direction(data, pattern, s.get("direction", "All"))
        self.set_search_results(matches, len(pattern), title=str(s.get("text", "")), pattern=pattern)

    def act_search_data(self, s):
        data = bytes(self.current_file().file_data)
        matches, size = self.find_data_matches(data, s)
        title = f"{s.get('type', 'Data')} {s.get('value') or str(s.get('min', '')) + '-' + str(s.get('max', ''))}"
        self.set_search_results(matches, size, title=title.strip(), pattern=None)

    def act_search_color(self, s):
        data = bytes(self.current_file().file_data)
        matches, size, fmt_name, _labels = self.find_color_matches(data, s)
        self.set_search_results(matches, size, title=f"{fmt_name} {s.get('values', '')}".strip(), pattern=None)

    def act_search_vector(self, s):
        data = bytes(self.current_file().file_data)
        matches, size, shape, component_type, _labels, _fmt, _component_size, _is_float = self.find_vector_matches(data, s)
        self.set_search_results(matches, size, title=f"{shape} {component_type} {s.get('values', '')}".strip(), pattern=None)

    def replace_at_matches(self, matches, size, build_replacement):
        if not matches:
            raise ValueError("No matches found")
        current = self.current_file()
        data = bytearray(current.file_data)
        self.editor.save_undo_state()
        for pos in sorted(matches, reverse=True):
            old = bytes(data[pos:pos + size])
            replacement = build_replacement(pos, old)
            data[pos:pos + size] = replacement
            current.replaced_bytes.update(range(pos, pos + len(replacement)))
        current.file_data = data
        current.modified = True
        current.pattern_highlights_dirty = True
        self.refresh()

    def act_replace_hex(self, s):
        find = self.parse_hex(s.get("find", ""))
        replace = self.parse_hex(s.get("replace", ""))
        data = bytes(self.current_file().file_data)
        matches = self.search_matches_for_direction(data, find, s.get("direction", "All"))
        self.replace_at_matches(matches, len(find), lambda _pos, _old: replace)

    def act_replace_text(self, s):
        encoding = s.get("encoding") or "utf-8"
        find = str(s.get("find", "")).encode(encoding)
        replace = str(s.get("replace", "")).encode(encoding)
        if not find:
            raise ValueError("Replace text find value is empty")
        data = bytes(self.current_file().file_data)
        matches = self.search_matches_for_direction(data, find, s.get("direction", "All"))
        self.replace_at_matches(matches, len(find), lambda _pos, _old: replace)

    def act_replace_data(self, s):
        current = self.current_file()
        data = bytes(current.file_data)
        matches, size = self.find_data_matches(data, s)
        _name, fmt, fmt_char, _size, min_value, max_value, is_float = self.numeric_type_info(s.get("type", "Float32"))
        random_mode = self.normalize_name(s.get("replace_mode", "Fixed")) in ("random", "rand")
        if random_mode:
            if str(s.get("replace_min", "")).strip() == "" or str(s.get("replace_max", "")).strip() == "":
                raise ValueError("Random data replacement needs min and max")
            mn = float(s.get("replace_min")) if is_float else int(str(s.get("replace_min")), 0)
            mx = float(s.get("replace_max")) if is_float else int(str(s.get("replace_max")), 0)
        else:
            if str(s.get("replace_value", "")).strip() == "":
                raise ValueError("Data replacement needs a value")
            fixed_value = float(s.get("replace_value")) if is_float else int(str(s.get("replace_value")), 0)

        def build(_pos, _old):
            value = random.uniform(min(mn, mx), max(mn, mx)) if random_mode and is_float else (
                random.randint(min(int(mn), int(mx)), max(int(mn), int(mx))) if random_mode else fixed_value
            )
            if is_float:
                return struct.pack(fmt, float(value))
            value = int(round(float(value)))
            if min_value is not None:
                value = max(min_value, value)
            if max_value is not None:
                value = min(max_value, value)
            if size == 1:
                return struct.pack(fmt_char, value)
            return struct.pack(fmt, value)

        self.replace_at_matches(matches, size, build)

    def act_replace_color(self, s):
        data = bytes(self.current_file().file_data)
        matches, size, _fmt_name, labels = self.find_color_matches(data, s)
        random_mode = self.normalize_name(s.get("replace_mode", "Fixed")) in ("random", "rand")

        def build(_pos, old):
            values = self.replace_fixed_or_random(list(old), labels, s.get("replace_values", ""), random_mode, is_float=False, clamp_byte=True)
            return bytes(values)

        self.replace_at_matches(matches, size, build)

    def act_replace_vector(self, s):
        data = bytes(self.current_file().file_data)
        matches, size, _shape, _component_type, labels, fmt, component_size, is_float = self.find_vector_matches(data, s)
        random_mode = self.normalize_name(s.get("replace_mode", "Fixed")) in ("random", "rand")

        def build(_pos, old):
            old_values = [
                struct.unpack(fmt, old[i * component_size:(i + 1) * component_size])[0]
                for i in range(len(labels))
            ]
            values = self.replace_fixed_or_random(old_values, labels, s.get("replace_values", ""), random_mode, is_float=is_float)
            out = bytearray()
            for value in values:
                out.extend(struct.pack(fmt, float(value) if is_float else int(round(float(value)))))
            return bytes(out)

        self.replace_at_matches(matches, size, build)

    def jump_result(self, forward=True):
        results = self.current_file().search_results
        if not results:
            raise ValueError("No search results")
        cursor = self.editor.cursor_position or 0
        offsets = sorted(pos for pos, _ in results)
        if forward:
            target = next((pos for pos in offsets if pos > cursor), offsets[0])
        else:
            target = next((pos for pos in reversed(offsets) if pos < cursor), offsets[-1])
        self.editor.cursor_position = target
        self.editor.cursor_nibble = 0
        self.editor.scroll_to_offset(target, center=True)
        self.refresh()

    def act_jump_next_result(self, s):
        self.jump_result(True)

    def act_jump_previous_result(self, s):
        self.jump_result(False)

    def act_inspector_math(self, s):
        target = self.choose_key(s.get("target", "Numeric"), ("Numeric", "Color", "Vector"), "inspector target")
        if target == "Numeric":
            self.apply_numeric_inspector_math(s)
        elif target == "Color":
            self.apply_color_inspector_math(s)
        else:
            self.apply_vector_inspector_math(s)

    def apply_numeric_inspector_math(self, s):
        fmt_name = self.choose_key(s.get("type", s.get("format", "Float32")), self.NUMERIC_FORMATS.keys(), "numeric format")
        fmt_char, size, min_value, max_value, is_float = self.NUMERIC_FORMATS[fmt_name]
        offset = self.current_offset()
        current = self.current_file()
        value = self.read_struct_value(current.file_data, offset, fmt_char, size, is_float)
        result = self.evaluate_inspector_expression(s.get("expression", ""), value, is_float=is_float)
        self.commit_bytes(offset, self.pack_struct_value(result, fmt_char, size, min_value, max_value, is_float))

    def apply_color_inspector_math(self, s):
        fmt_name = self.choose_key(s.get("type", s.get("format", "RGB24")), self.COLOR_FORMATS.keys(), "color format")
        labels = self.COLOR_FORMATS[fmt_name]
        offset = self.current_offset()
        current = self.current_file()
        if offset + len(labels) > len(current.file_data):
            raise ValueError("Not enough bytes for color value")
        values = list(bytes(current.file_data[offset:offset + len(labels)]))
        values = [
            max(0, min(255, int(round(float(self.evaluate_inspector_expression(s.get("expression", ""), value, is_float=False))))))
            for value in values
        ]
        self.commit_bytes(offset, bytes(values))

    def apply_vector_inspector_math(self, s):
        vector_name = self.choose_key(s.get("shape", "Vector3"), self.VECTOR_COMPONENTS.keys(), "vector format")
        component_type = self.choose_key(s.get("type", s.get("component_type", "Float32")), self.VECTOR_FORMATS.keys(), "vector component type")
        fmt_char, size, min_value, max_value, is_float = self.VECTOR_FORMATS[component_type]
        labels = self.VECTOR_COMPONENTS[vector_name]
        offset = self.current_offset()
        current = self.current_file()
        out = bytearray()
        for index, _label in enumerate(labels):
            component_offset = offset + index * size
            value = self.read_struct_value(current.file_data, component_offset, fmt_char, size, is_float)
            result = self.evaluate_inspector_expression(s.get("expression", ""), value, is_float=is_float)
            out.extend(self.pack_struct_value(result, fmt_char, size, min_value, max_value, is_float))
        self.commit_bytes(offset, bytes(out))

    def act_inspector_set_color(self, s):
        fmt_name = self.choose_key(s.get("format", "RGBA32"), self.COLOR_FORMATS.keys(), "color format")
        labels = self.COLOR_FORMATS[fmt_name]
        current = self.current_file()
        offset = self.current_offset()
        if offset + len(labels) > len(current.file_data):
            raise ValueError("Not enough bytes for color value")
        old_values = list(bytes(current.file_data[offset:offset + len(labels)]))
        values = self.replace_fixed_or_random(old_values, labels, s.get("values", ""), False, is_float=False, clamp_byte=True)
        self.commit_bytes(offset, bytes(values))

    def act_add_delimiter(self, s):
        self.editor.hidden_delimiters[self.parse_byte_value(s.get("value"))] = max(1, self.parse_length(s.get("padding", "1")))
        self.refresh()

    def act_remove_delimiter(self, s):
        self.editor.hidden_delimiters.pop(self.parse_byte_value(s.get("value")), None)
        self.refresh()

    def act_toggle_delimiter_visibility(self, s):
        self.editor.hidden_delimiters = {} if self.editor.hidden_delimiters else {0: 1}
        self.refresh()

    def act_delimit_selection(self, s):
        self.act_add_delimiter(s)

    def add_highlight_range(self, start, length, color, message="", underline=False, pattern=None, refresh=True):
        self.validate_range(start, length)
        current = self.current_file()
        for pos in range(start, start + length):
            current.byte_highlights[pos] = {"color": color, "message": message, "underline": underline}
            if pattern is not None:
                current.byte_highlights[pos]["pattern"] = pattern
        if refresh:
            self.refresh()

    def act_create_highlight(self, s):
        self.add_highlight_range(self.parse_offset(s.get("start")), self.parse_length(s.get("length")), s.get("color", "#ff0000"), s.get("message", ""))

    def act_highlight_selected_range(self, s):
        if self.editor.selection_start is None or self.editor.selection_end is None:
            raise ValueError("No selection")
        start = min(self.editor.selection_start, self.editor.selection_end)
        length = abs(self.editor.selection_end - self.editor.selection_start) + 1
        self.add_highlight_range(start, length, s.get("color", "#ff0000"), s.get("message", ""))

    def act_highlight_byte_pattern(self, s):
        pattern = self.parse_hex(s.get("pattern", ""))
        current = self.current_file()
        data = bytes(current.file_data)
        matches = self.find_matches(data, pattern, overlap=True)
        if not matches:
            raise ValueError("Highlight pattern not found")
        color = s.get("color", "#ff0000")
        message = s.get("message", "")
        pattern_text = pattern.hex()
        for pos in matches:
            self.validate_range(pos, len(pattern))
            for byte_pos in range(pos, pos + len(pattern)):
                current.byte_highlights[byte_pos] = {"color": color, "message": message, "underline": False, "pattern": pattern_text}
        self.refresh()

    def act_toggle_highlight_visibility(self, s):
        current = self.current_file()
        if current.byte_highlights:
            current._script_hidden_highlights = current.byte_highlights
            current.byte_highlights = {}
        elif hasattr(current, "_script_hidden_highlights"):
            current.byte_highlights = current._script_hidden_highlights
        self.refresh()

    def act_remove_highlight(self, s):
        current = self.current_file()
        if s.get("start") == "selection":
            if self.editor.selection_start is None or self.editor.selection_end is None:
                raise ValueError("No selection")
            start = min(self.editor.selection_start, self.editor.selection_end)
            length = abs(self.editor.selection_end - self.editor.selection_start) + 1
        else:
            start = self.parse_offset(s.get("start"))
            length = self.parse_length(s.get("length"))
        for pos in range(start, start + length):
            current.byte_highlights.pop(pos, None)
        self.refresh()

    def act_create_pointer_box(self, s):
        offset = self.parse_offset(s.get("offset"))
        length = self.parse_length(s.get("length"))
        self.validate_range(offset, length)
        pointer = SignaturePointer(offset, length, s.get("type", "uint32"), s.get("label", "Script Pointer"), "Custom")
        self.editor.signature_widget.pointers.append(pointer)
        self.editor.signature_widget.update_pointer_list()
        self.editor.update_signature_overlays()

    def act_delete_pointer_box(self, s):
        text = str(s.get("label", ""))
        self.editor.signature_widget.pointers = [p for p in self.editor.signature_widget.pointers if text not in getattr(p, "label", "")]
        self.editor.signature_widget.update_pointer_list()
        self.editor.update_signature_overlays()

    def act_jump_pointer_box(self, s):
        text = str(s.get("label", ""))
        for pointer in self.editor.signature_widget.pointers:
            if text in getattr(pointer, "label", ""):
                self.act_go_offset({"offset": str(pointer.offset)})
                return
        raise ValueError("Pointer box not found")


class CategorizedActionButton(QPushButton):
    actionChanged = pyqtSignal(str)

    def __init__(self, action_type="go_offset", parent=None):
        super().__init__(parent)
        self.action_type = action_type
        self.setFont(QFont("Arial", 8))
        self.setMinimumHeight(22)
        self.clicked.connect(self.show_action_menu)
        self.update_text()

    def update_text(self):
        category, label, _fields = ACTION_SPECS.get(self.action_type, ("Action", self.action_type, []))
        self.setText(f"{category}: {label}  ▾")

    def set_action_type(self, action_type):
        if action_type not in ACTION_SPECS:
            return
        if self.action_type == action_type:
            self.update_text()
            return
        self.action_type = action_type
        self.update_text()
        self.actionChanged.emit(action_type)

    def currentData(self):
        return self.action_type

    def show_action_menu(self):
        menu = QMenu(self)
        categories = {}
        for key, spec in ACTION_SPECS.items():
            categories.setdefault(spec[0], []).append((spec[1], key))

        for category in sorted(categories.keys()):
            submenu = menu.addMenu(category)
            submenu.setFont(QFont("Arial", 8))
            for label, key in sorted(categories[category], key=lambda item: item[0].lower()):
                action = submenu.addAction(label)
                action.setData(key)

        chosen = menu.exec_(self.mapToGlobal(self.rect().bottomLeft()))
        if chosen and chosen.data():
            self.set_action_type(chosen.data())


class ActionSettingsDialog(ScriptBaseDialog):
    def __init__(self, action=None, parent=None):
        super().__init__(parent)
        self.setWindowTitle("Action Settings")
        self.action = deepcopy(action) if action else {"type": "go_offset", "settings": {}}
        self.edits = {}

        layout = QVBoxLayout(self)
        form = QFormLayout()
        self.type_combo = CategorizedActionButton(self.action.get("type", "go_offset"))
        self.type_combo.actionChanged.connect(lambda _action_type: self.rebuild_form())
        form.addRow("Action:", self.type_combo)
        layout.addLayout(form)

        self.settings_widget = QWidget()
        self.settings_layout = QFormLayout(self.settings_widget)
        layout.addWidget(self.settings_widget)

        buttons = QDialogButtonBox(QDialogButtonBox.Ok | QDialogButtonBox.Cancel)
        buttons.setFont(QFont("Arial", 9))
        buttons.accepted.connect(self.accept)
        buttons.rejected.connect(self.reject)
        layout.addWidget(buttons)
        self.rebuild_form()

    def rebuild_form(self):
        while self.settings_layout.rowCount():
            self.settings_layout.removeRow(0)
        self.edits = {}
        action_type = self.type_combo.currentData()
        current_settings = self.action.get("settings", {}) if self.action.get("type") == action_type else {}
        for key, label, default in ACTION_SPECS[action_type][2]:
            if key == "direction":
                edit = QComboBox()
                edit.addItems(["All", "Forward", "Backward"])
                value = str(current_settings.get(key, default))
                index = edit.findText(value, Qt.MatchFixedString)
                if index >= 0:
                    edit.setCurrentIndex(index)
                edit.setFont(QFont("Arial", 8))
            elif key == "mode":
                edit = QComboBox()
                edit.addItems(["Value", "Range"])
                value = str(current_settings.get(key, default))
                index = edit.findText(value, Qt.MatchFixedString)
                if index >= 0:
                    edit.setCurrentIndex(index)
                edit.setFont(QFont("Arial", 8))
            elif key == "replace_mode":
                edit = QComboBox()
                edit.addItems(["Fixed", "Random"])
                value = str(current_settings.get(key, default))
                index = edit.findText(value, Qt.MatchFixedString)
                if index >= 0:
                    edit.setCurrentIndex(index)
                edit.setFont(QFont("Arial", 8))
            elif key == "endian":
                edit = QComboBox()
                edit.addItems(["LE", "BE"])
                value = str(current_settings.get(key, default))
                index = edit.findText(value, Qt.MatchFixedString)
                if index >= 0:
                    edit.setCurrentIndex(index)
                edit.setFont(QFont("Arial", 8))
            elif key == "encoding":
                edit = QComboBox()
                edit.addItems(["utf-8", "ascii", "latin-1", "utf-16-le", "utf-16-be", "utf-32-le", "utf-32-be", "cp1252"])
                value = str(current_settings.get(key, default))
                index = edit.findText(value, Qt.MatchFixedString)
                if index >= 0:
                    edit.setCurrentIndex(index)
                edit.setFont(QFont("Arial", 8))
            elif action_type == "inspector_math" and key == "target":
                edit = QComboBox()
                edit.addItems(["Numeric", "Color", "Vector"])
                value = str(current_settings.get(key, default))
                index = edit.findText(value, Qt.MatchFixedString)
                if index >= 0:
                    edit.setCurrentIndex(index)
                edit.setFont(QFont("Arial", 8))
            elif key == "format":
                edit = QComboBox()
                edit.addItems(["RGB24", "RGBA32", "BGR24", "BGRA32", "ARGB32", "ABGR32", "HSV"])
                value = str(current_settings.get(key, default))
                index = edit.findText(value, Qt.MatchFixedString)
                if index >= 0:
                    edit.setCurrentIndex(index)
                edit.setFont(QFont("Arial", 8))
            elif key == "shape":
                edit = QComboBox()
                edit.addItems(["Vector2", "Vector3", "Vector4", "Quaternion", "BoundingBox"])
                value = str(current_settings.get(key, default))
                index = edit.findText(value, Qt.MatchFixedString)
                if index >= 0:
                    edit.setCurrentIndex(index)
                edit.setFont(QFont("Arial", 8))
            elif key == "type" and action_type in (
                "inspector_math", "search_data", "search_vector", "replace_data", "replace_vector"
            ):
                edit = QComboBox()
                if action_type == "inspector_math":
                    edit.addItems([
                        "Float32", "Float64", "Float16", "Int8", "UInt8", "Int16", "UInt16", "Int32", "UInt32", "Int64", "UInt64",
                        "RGB24", "RGBA32", "BGR24", "BGRA32", "ARGB32", "ABGR32", "HSV",
                    ])
                elif action_type in ("search_vector", "replace_vector"):
                    edit.addItems(["Float32", "Float64", "Float16", "Int8", "UInt8", "Int16", "UInt16", "Int32", "UInt32"])
                else:
                    edit.addItems(["Float32", "Float64", "Float16", "Int8", "UInt8", "Int16", "UInt16", "Int32", "UInt32", "Int64", "UInt64"])
                value = str(current_settings.get(key, default))
                index = edit.findText(value, Qt.MatchFixedString)
                if index >= 0:
                    edit.setCurrentIndex(index)
                edit.setFont(QFont("Arial", 8))
            else:
                edit = QLineEdit(str(current_settings.get(key, default)))
                edit.setFont(QFont("Courier", 8))
            self.edits[key] = edit
            self.settings_layout.addRow(label + ":", edit)

    def get_action(self):
        action_type = self.type_combo.currentData()
        return {
            "type": action_type,
            "settings": {
                key: (edit.currentText() if isinstance(edit, QComboBox) else edit.text())
                for key, edit in self.edits.items()
            }
        }


class ScriptEditorDialog(ScriptBaseDialog):
    def __init__(self, script=None, parent=None):
        super().__init__(parent)
        self.setWindowTitle("Action Script")
        self.resize(560, 520)
        self.script = deepcopy(script) if script else default_script()
        self.ignore_script_index = None

        layout = QVBoxLayout(self)
        form = QFormLayout()
        self.name_edit = QLineEdit(self.script.get("name", "New Script"))
        self.desc_edit = QLineEdit(self.script.get("description", ""))
        self.hotkey_edit = HotkeyCaptureEdit(self.script.get("hotkey", ""))
        self.hotkey_edit.setToolTip("Click here, then press the shortcut keys together")
        form.addRow("Name:", self.name_edit)
        form.addRow("Description:", self.desc_edit)
        form.addRow("Hotkey:", self.hotkey_edit)
        layout.addLayout(form)

        self.actions_list = QListWidget()
        self.actions_list.setFont(QFont("Arial", 8))
        layout.addWidget(self.actions_list, 1)

        btn_row = QHBoxLayout()
        for text, slot in (
            ("Add", self.add_action), ("Edit", self.edit_action), ("Remove", self.remove_action),
            ("Up", self.move_up), ("Down", self.move_down)
        ):
            btn = QPushButton(text)
            btn.setFont(QFont("Arial", 9))
            btn.clicked.connect(slot)
            btn_row.addWidget(btn)
        layout.addLayout(btn_row)

        buttons = QDialogButtonBox(QDialogButtonBox.Ok | QDialogButtonBox.Cancel)
        buttons.setFont(QFont("Arial", 9))
        buttons.accepted.connect(self.accept)
        buttons.rejected.connect(self.reject)
        layout.addWidget(buttons)
        self.refresh_actions()

    def _editor_root(self):
        widget = self.parent()
        while widget is not None:
            if hasattr(widget, "find_hotkey_conflict"):
                return widget
            if hasattr(widget, "manager") and hasattr(widget.manager, "editor"):
                return widget.manager.editor
            widget = widget.parent() if hasattr(widget, "parent") else None
        return None

    def accept(self):
        hotkey = normalize_hotkey(self.hotkey_edit.text())
        editor = self._editor_root()
        if hotkey and editor and hasattr(editor, "find_hotkey_conflict"):
            current_name = self.name_edit.text().strip() or self.script.get("name", "Unnamed Script")
            conflict = editor.find_hotkey_conflict(
                hotkey,
                ignore_script_name=current_name,
                ignore_script_index=self.ignore_script_index
            )
            if conflict:
                msg = QMessageBox(self)
                msg.setIcon(QMessageBox.Warning)
                msg.setWindowTitle("Hotkey Conflict")
                msg.setText(f"This hotkey conflicts with {conflict}.")
                msg.setInformativeText("Choose a different shortcut before saving this script.")
                msg.setStandardButtons(QMessageBox.Ok)
                msg.setStyleSheet(script_dialog_stylesheet(editor))
                QTimer.singleShot(0, lambda: apply_native_titlebar_theme(msg, editor.system_uses_dark_titlebar() if hasattr(editor, "system_uses_dark_titlebar") else None))
                msg.exec_()
                self.hotkey_edit.clear()
                return
        super().accept()

    def refresh_actions(self):
        self.actions_list.clear()
        for action in self.script.get("actions", []):
            spec = ACTION_SPECS.get(action.get("type"), ("", action.get("type", "Unknown"), []))
            self.actions_list.addItem(QListWidgetItem(spec[1]))

    def current_index(self):
        return self.actions_list.currentRow()

    def add_action(self):
        dialog = ActionSettingsDialog(parent=self)
        if dialog.exec_() == QDialog.Accepted:
            self.script.setdefault("actions", []).append(dialog.get_action())
            self.refresh_actions()

    def edit_action(self):
        index = self.current_index()
        if index < 0:
            return
        dialog = ActionSettingsDialog(self.script["actions"][index], self)
        if dialog.exec_() == QDialog.Accepted:
            self.script["actions"][index] = dialog.get_action()
            self.refresh_actions()
            self.actions_list.setCurrentRow(index)

    def remove_action(self):
        index = self.current_index()
        if index >= 0:
            del self.script["actions"][index]
            self.refresh_actions()

    def move_up(self):
        index = self.current_index()
        if index > 0:
            actions = self.script["actions"]
            actions[index - 1], actions[index] = actions[index], actions[index - 1]
            self.refresh_actions()
            self.actions_list.setCurrentRow(index - 1)

    def move_down(self):
        index = self.current_index()
        actions = self.script["actions"]
        if 0 <= index < len(actions) - 1:
            actions[index + 1], actions[index] = actions[index], actions[index + 1]
            self.refresh_actions()
            self.actions_list.setCurrentRow(index + 1)

    def get_script(self):
        self.script["name"] = self.name_edit.text().strip() or "Unnamed Script"
        self.script["description"] = self.desc_edit.text().strip()
        self.script["hotkey"] = normalize_hotkey(self.hotkey_edit.text())
        return self.script


class ScriptManagerDialog(ScriptBaseDialog):
    def __init__(self, manager, parent=None):
        super().__init__(parent)
        self.manager = manager
        self.setWindowTitle("Action Scripts")
        self.resize(620, 420)

        layout = QHBoxLayout(self)
        self.list_widget = QListWidget()
        self.list_widget.setFont(QFont("Arial", 8))
        layout.addWidget(self.list_widget, 1)

        side = QVBoxLayout()
        for text, slot in (
            ("Create", self.create_script), ("Edit", self.edit_script), ("Run", self.run_script),
            ("Duplicate", self.duplicate_script), ("Rename", self.rename_script), ("Delete", self.delete_script),
            ("Import...", self.import_scripts), ("Export...", self.export_scripts)
        ):
            btn = QPushButton(text)
            btn.setFont(QFont("Arial", 9))
            btn.clicked.connect(slot)
            side.addWidget(btn)
        side.addStretch()
        close_btn = QPushButton("Close")
        close_btn.setFont(QFont("Arial", 9))
        close_btn.clicked.connect(self.accept)
        side.addWidget(close_btn)
        layout.addLayout(side)
        self.refresh()

    def refresh(self):
        self.list_widget.clear()
        for script in self.manager.scripts:
            hotkey = f" [{script.get('hotkey')}]" if script.get("hotkey") else ""
            self.list_widget.addItem(f"{script.get('name', 'Unnamed')}{hotkey}")

    def current_index(self):
        return self.list_widget.currentRow()

    def save_refresh(self):
        self.manager.save()
        self.manager.install_shortcuts()
        if hasattr(self.manager.editor, "rebuild_scripts_menu"):
            self.manager.editor.rebuild_scripts_menu()
        self.refresh()

    def create_script(self):
        dialog = ScriptEditorDialog(parent=self)
        if dialog.exec_() == QDialog.Accepted:
            self.manager.scripts.append(dialog.get_script())
            self.save_refresh()

    def edit_script(self):
        index = self.current_index()
        if index < 0:
            return
        dialog = ScriptEditorDialog(self.manager.scripts[index], self)
        dialog.ignore_script_index = index
        if dialog.exec_() == QDialog.Accepted:
            self.manager.scripts[index] = dialog.get_script()
            self.save_refresh()

    def run_script(self):
        index = self.current_index()
        if index >= 0:
            self.manager.run_script(index)

    def duplicate_script(self):
        index = self.current_index()
        if index < 0:
            return
        script = deepcopy(self.manager.scripts[index])
        script["name"] = script.get("name", "Script") + " Copy"
        script["hotkey"] = ""
        self.manager.scripts.insert(index + 1, script)
        self.save_refresh()

    def rename_script(self):
        self.edit_script()

    def delete_script(self):
        index = self.current_index()
        if index >= 0:
            del self.manager.scripts[index]
            self.save_refresh()

    def import_scripts(self):
        path, _ = QFileDialog.getOpenFileName(self, "Import Action Scripts", "", "JSON Files (*.json);;All Files (*)")
        if not path:
            return
        try:
            name = self.manager.import_from_file(path)
            self.save_refresh()
            QMessageBox.information(self, "Import Complete", f"Imported script '{name}'.")
        except Exception as exc:
            QMessageBox.warning(self, "Import Failed", str(exc))

    def export_scripts(self):
        index = self.current_index()
        if index < 0:
            QMessageBox.warning(self, "No Script Selected", "Select one script to export.")
            return
        script_name = self.manager.scripts[index].get("name", "Action Script")
        path, _ = QFileDialog.getSaveFileName(self, "Export Action Script", safe_export_filename(script_name), "JSON Files (*.json);;All Files (*)")
        if not path:
            return
        try:
            self.manager.export_to_file(path, index)
            QMessageBox.information(self, "Export Complete", f"Exported script '{script_name}'.")
        except Exception as exc:
            QMessageBox.warning(self, "Export Failed", str(exc))
