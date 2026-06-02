import struct
from PyQt5.QtWidgets import (QWidget, QVBoxLayout, QTreeWidget, QTreeWidgetItem,
                             QPushButton, QLabel, QLineEdit, QComboBox, QHBoxLayout,
                             QMenu, QAction, QInputDialog, QAbstractItemView, QCheckBox)
from PyQt5.QtCore import Qt, pyqtSignal
from PyQt5.QtGui import QFont, QColor


class Field:
    def __init__(self, label, start, end, tab_index):
        self.label = label
        self.start = start
        self.end = end
        self.tab_index = tab_index
        self.subfields = []

    def adjust_for_insert(self, insert_pos, insert_len):
        if insert_pos <= self.start:
            self.start += insert_len
            self.end += insert_len
        elif insert_pos < self.end:
            self.end += insert_len

        for subfield in self.subfields:
            subfield.adjust_for_insert(insert_pos, insert_len)

    def adjust_for_delete(self, delete_pos, delete_len):
        if delete_pos + delete_len <= self.start:
            self.start -= delete_len
            self.end -= delete_len
        elif delete_pos < self.end:
            if delete_pos <= self.start:
                overlap = min(self.start + delete_len, delete_pos + delete_len) - self.start
                self.start -= min(delete_pos, self.start)
                self.end -= delete_len
            else:
                self.end -= min(delete_len, self.end - delete_pos)

        for subfield in self.subfields:
            subfield.adjust_for_delete(delete_pos, delete_len)


class Subfield:
    def __init__(self, name, start, end, data_type, endian):
        self.name = name
        self.start = start
        self.end = end
        self.data_type = data_type
        self.endian = endian
        self.subfields = []
        self.overlay_pointer = False

    def adjust_for_insert(self, insert_pos, insert_len):
        if insert_pos <= self.start:
            self.start += insert_len
            self.end += insert_len
        elif insert_pos < self.end:
            self.end += insert_len

        for subfield in self.subfields:
            subfield.adjust_for_insert(insert_pos, insert_len)

    def adjust_for_delete(self, delete_pos, delete_len):
        if delete_pos + delete_len <= self.start:
            self.start -= delete_len
            self.end -= delete_len
        elif delete_pos < self.end:
            if delete_pos <= self.start:
                overlap = min(self.start + delete_len, delete_pos + delete_len) - self.start
                self.start -= min(delete_pos, self.start)
                self.end -= delete_len
            else:
                self.end -= min(delete_len, self.end - delete_pos)

        for subfield in self.subfields:
            subfield.adjust_for_delete(delete_pos, delete_len)


class FieldTreeWidget(QTreeWidget):
    def __init__(self, parent=None):
        super().__init__(parent)

    def dropEvent(self, event):
        dragged_item = self.currentItem()
        if not dragged_item:
            event.ignore()
            return

        owner = self.parent()
        if owner and hasattr(owner, "handle_tree_drop"):
            if owner.handle_tree_drop(dragged_item, self.itemAt(event.pos()), self.dropIndicatorPosition()):
                event.accept()
                return

        event.ignore()


class FieldWidget(QWidget):
    field_segment_clicked = pyqtSignal(int, int)

    def __init__(self, parent=None):
        super().__init__(parent)
        self.fields = []
        self.parent_editor = None
        self.clipboard_segment = None
        self.clipboard_subfield = None
        self.setup_ui()

    def setup_ui(self):
        layout = QVBoxLayout()
        layout.setContentsMargins(10, 10, 10, 10)
        layout.setSpacing(5)

        title = QLabel("Fields")
        title.setFont(QFont("Arial", 11, QFont.Bold))
        title.setAlignment(Qt.AlignCenter)
        layout.addWidget(title)

        self.tree = FieldTreeWidget(self)
        self.tree.setHeaderLabels(["Field / Subfield"])
        self.tree.setFont(QFont("Arial", 9))
        self.tree.setContextMenuPolicy(Qt.CustomContextMenu)
        self.tree.customContextMenuRequested.connect(self.show_context_menu)
        self.tree.itemClicked.connect(self.on_item_clicked)
        self.tree.setColumnWidth(0, 250)
        self.tree.setDragDropMode(QTreeWidget.InternalMove)
        self.tree.setSelectionMode(QTreeWidget.SingleSelection)
        layout.addWidget(self.tree)

        self.status_label = QLabel("Ready")
        self.status_label.setFont(QFont("Arial", 9))
        layout.addWidget(self.status_label)

        self.setLayout(layout)

    def show_context_menu(self, position):
        item = self.tree.itemAt(position)
        menu = QMenu()

        if item and item.data(0, Qt.UserRole) == "field":
            paste_action = QAction("Paste Subfield", self)
            paste_action.triggered.connect(lambda: self.paste_subfield(item))
            paste_action.setEnabled(self.clipboard_segment is not None or self.clipboard_subfield is not None)
            menu.addAction(paste_action)

            rename_action = QAction("Rename Field", self)
            rename_action.triggered.connect(lambda: self.rename_field(item))
            menu.addAction(rename_action)

            delete_action = QAction("Delete Field", self)
            delete_action.triggered.connect(lambda: self.delete_field(item))
            menu.addAction(delete_action)

        elif item and item.data(0, Qt.UserRole) == "subfield":
            copy_action = QAction("Copy Subfield", self)
            copy_action.triggered.connect(lambda: self.copy_subfield(item))
            menu.addAction(copy_action)

            paste_action = QAction("Paste Nested Subfield", self)
            paste_action.triggered.connect(lambda: self.paste_nested_subfield(item))
            paste_action.setEnabled(self.clipboard_segment is not None or self.clipboard_subfield is not None)
            menu.addAction(paste_action)

            delete_action = QAction("Delete Subfield", self)
            delete_action.triggered.connect(lambda: self.delete_subfield(item))
            menu.addAction(delete_action)

            rename_action = QAction("Rename Subfield", self)
            rename_action.triggered.connect(lambda: self.rename_subfield(item))
            menu.addAction(rename_action)

        if menu.actions():
            menu.exec_(self.tree.viewport().mapToGlobal(position))

    def rename_field(self, item):
        field = item.data(0, Qt.UserRole + 1)
        if field:
            text, ok = QInputDialog.getText(self, "Rename Field", "Enter new label:", text=field.label)
            if ok and text:
                field.label = text
                self.rebuild_tree()

    def rename_subfield(self, item):
        subfield = item.data(0, Qt.UserRole + 1)
        if subfield:
            text, ok = QInputDialog.getText(self, "Rename Subfield", "Enter new name:", text=subfield.name)
            if ok and text:
                subfield.name = text
                self.rebuild_tree()

    def delete_field(self, item):
        field = item.data(0, Qt.UserRole + 1)
        if field and field in self.fields:
            self.fields.remove(field)
            self.rebuild_tree()
            self.status_label.setText("Field deleted")
            if self.parent_editor:
                self.parent_editor.display_hex()

    def delete_subfield(self, item):
        subfield = item.data(0, Qt.UserRole + 1)
        parent_list = self.find_subfield_parent_list(subfield)
        if subfield and parent_list and subfield in parent_list:
            parent_list.remove(subfield)
            self.rebuild_tree()
            self.status_label.setText("Subfield deleted")
            if self.parent_editor:
                self.parent_editor.display_hex()

    def copy_subfield(self, item):
        subfield = item.data(0, Qt.UserRole + 1)
        if subfield:
            self.clipboard_subfield = self.clone_subfield(subfield)
            self.clipboard_segment = None
            self.status_label.setText(f"Copied subfield '{subfield.name}'")

    def paste_subfield(self, field_item):
        if (not self.clipboard_segment and not self.clipboard_subfield) or not self.parent_editor:
            return

        field = field_item.data(0, Qt.UserRole + 1)
        if not field:
            return

        subfield = self.build_subfield_from_clipboard(f"Subfield_{len(field.subfields) + 1}")
        if not subfield:
            return
        field.subfields.append(subfield)

        self.rebuild_tree()
        self.status_label.setText(f"Subfield pasted into '{field.label}'")

        if self.parent_editor:
            self.parent_editor.display_hex()

    def paste_nested_subfield(self, subfield_item):
        if (not self.clipboard_segment and not self.clipboard_subfield) or not self.parent_editor:
            return

        parent_subfield = subfield_item.data(0, Qt.UserRole + 1)
        if not parent_subfield:
            return

        nested_subfield = self.build_subfield_from_clipboard(f"Nested_{len(parent_subfield.subfields) + 1}")
        if not nested_subfield:
            return
        parent_subfield.subfields.append(nested_subfield)

        self.rebuild_tree()
        self.status_label.setText(f"Nested subfield pasted into '{parent_subfield.name}'")

        if self.parent_editor:
            self.parent_editor.display_hex()

    def build_subfield_from_clipboard(self, fallback_name):
        if self.clipboard_subfield:
            clone = self.clone_subfield(self.clipboard_subfield)
            if not clone.name:
                clone.name = fallback_name
            return clone

        if not self.clipboard_segment or not self.parent_editor:
            return None

        start, end, tab_index = self.clipboard_segment
        if tab_index != self.parent_editor.current_tab_index:
            self.status_label.setText("Cannot paste from different file")
            return None

        return Subfield(fallback_name, start, end, "Hex", "LE")

    def clone_subfield(self, subfield):
        clone = Subfield(subfield.name, subfield.start, subfield.end, subfield.data_type, subfield.endian)
        clone.overlay_pointer = getattr(subfield, "overlay_pointer", False)
        clone.subfields = [self.clone_subfield(child) for child in subfield.subfields]
        return clone

    def add_field(self, label, start, end, tab_index):
        print(f"DEBUG add_field called: label={label}, start={start} (0x{start:X}), end={end} (0x{end:X})")
        field = Field(label, start, end, tab_index)
        print(f"DEBUG field created: field.start={field.start}, field.end={field.end}")

        if self.parent_editor and hasattr(self.parent_editor, 'signature_widget'):
            pointer_count = 0
            for pointer in self.parent_editor.signature_widget.pointers:
                if (pointer.offset >= start and
                    pointer.offset + pointer.length <= end):
                    endian = "LE"
                    if hasattr(pointer, 'endianness'):
                        endian = pointer.endianness

                    data_type = pointer.data_type
                    base_type = data_type.lower().split()[0] if ' ' in data_type else data_type.lower()

                    print(f"DEBUG: Creating subfield from pointer")
                    print(f"  pointer.data_type: {data_type}")
                    print(f"  base_type: {base_type}")
                    print(f"  pointer.endianness: {getattr(pointer, 'endianness', 'NOT SET')}")
                    print(f"  endian: {endian}")

                    subfield = Subfield(
                        pointer.label or f"Pointer_{pointer.offset:X}",
                        pointer.offset,
                        pointer.offset + pointer.length,
                        base_type,
                        endian
                    )
                    print(f"  created subfield.data_type: {subfield.data_type}")
                    print(f"  created subfield.endian: {subfield.endian}")
                    field.subfields.append(subfield)
                    pointer_count += 1

            if pointer_count > 0:
                self.status_label.setText(f"Field '{label}' added with {pointer_count} auto-generated subfields")
            else:
                self.status_label.setText(f"Field '{label}' added")
        else:
            self.status_label.setText(f"Field '{label}' added")

        self.fields.append(field)
        self.rebuild_tree()
        if self.parent_editor:
            self.parent_editor.display_hex()

    def copy_segment(self, start, end, tab_index):
        self.clipboard_segment = (start, end, tab_index)
        self.clipboard_subfield = None
        self.status_label.setText(f"Copied segment 0x{start:X}-0x{end:X}; right-click a field to paste")

    def save_expansion_state(self, item, expanded_items):
        obj = item.data(0, Qt.UserRole + 1)
        if obj and item.isExpanded():
            expanded_items.add(id(obj))
        for i in range(item.childCount()):
            child = item.child(i)
            self.save_expansion_state(child, expanded_items)

    def find_subfield_parent_list(self, subfield, subfields=None):
        if subfields is None:
            for field in self.fields:
                found = self.find_subfield_parent_list(subfield, field.subfields)
                if found is not None:
                    return found
            return None

        if subfield in subfields:
            return subfields

        for child in subfields:
            found = self.find_subfield_parent_list(subfield, child.subfields)
            if found is not None:
                return found
        return None

    def is_descendant_subfield(self, possible_parent, possible_child):
        if possible_parent is possible_child:
            return True
        for child in possible_parent.subfields:
            if self.is_descendant_subfield(child, possible_child):
                return True
        return False

    def normalize_drop_target(self, target_item):
        while target_item and target_item.data(0, Qt.UserRole) not in ("field", "subfield"):
            target_item = target_item.parent()
        return target_item

    def handle_tree_drop(self, dragged_item, target_item, drop_indicator):
        dragged_type = dragged_item.data(0, Qt.UserRole)
        if dragged_type not in ("field", "subfield"):
            return False

        target_item = self.normalize_drop_target(target_item)
        target_type = target_item.data(0, Qt.UserRole) if target_item else None

        if dragged_type == "field":
            field = dragged_item.data(0, Qt.UserRole + 1)
            if field not in self.fields:
                return False

            old_index = self.fields.index(field)
            insert_index = len(self.fields)
            if target_type == "field":
                target_field = target_item.data(0, Qt.UserRole + 1)
                if target_field in self.fields:
                    insert_index = self.fields.index(target_field)
                    if drop_indicator == QAbstractItemView.BelowItem:
                        insert_index += 1
            if old_index < insert_index:
                insert_index -= 1
            self.fields.remove(field)
            self.fields.insert(insert_index, field)
            self.rebuild_tree(preserve_expansion=True)
            self.status_label.setText(f"Moved field '{field.label}'")
            return True

        subfield = dragged_item.data(0, Qt.UserRole + 1)
        source_list = self.find_subfield_parent_list(subfield)
        if source_list is None:
            return False

        if target_type == "subfield":
            target_subfield = target_item.data(0, Qt.UserRole + 1)
            if self.is_descendant_subfield(subfield, target_subfield):
                self.status_label.setText("Cannot move a subfield into itself")
                return False
            if drop_indicator == QAbstractItemView.OnItem:
                destination_list = target_subfield.subfields
                insert_index = len(destination_list)
            else:
                destination_list = self.find_subfield_parent_list(target_subfield)
                if destination_list is None:
                    return False
                insert_index = destination_list.index(target_subfield)
                if drop_indicator == QAbstractItemView.BelowItem:
                    insert_index += 1
        elif target_type == "field":
            target_field = target_item.data(0, Qt.UserRole + 1)
            destination_list = target_field.subfields
            insert_index = 0 if drop_indicator == QAbstractItemView.AboveItem else len(destination_list)
        else:
            return False

        if destination_list is source_list:
            old_index = source_list.index(subfield)
            if old_index < insert_index:
                insert_index -= 1
        source_list.remove(subfield)
        if insert_index > len(destination_list):
            insert_index = len(destination_list)
        destination_list.insert(insert_index, subfield)
        self.rebuild_tree(preserve_expansion=True)
        self.status_label.setText(f"Moved subfield '{subfield.name}'")
        if self.parent_editor:
            self.parent_editor.display_hex(preserve_scroll=True)
        return True

    def rebuild_tree(self, preserve_expansion=False):
        expanded_items = set()

        if preserve_expansion:
            root = self.tree.invisibleRootItem()
            for i in range(root.childCount()):
                self.save_expansion_state(root.child(i), expanded_items)

        self.tree.clear()

        # Debug: Print all field ranges BEFORE building UI
        for i, field in enumerate(self.fields):
            byte_count = field.end - field.start
            print(f"DEBUG rebuild_tree: Field {i} '{field.label}': start={field.start} (0x{field.start:X}), end={field.end} (0x{field.end:X}), byte_count={byte_count}")

        if not self.parent_editor or self.parent_editor.current_tab_index < 0:
            return

        current_tab = self.parent_editor.current_tab_index
        current_file = self.parent_editor.open_files[current_tab]
        file_data = current_file.file_data

        for field in self.fields:
            if field.tab_index != current_tab:
                continue

            field_item = QTreeWidgetItem(self.tree)
            field_item.setData(0, Qt.UserRole, "field")
            field_item.setData(0, Qt.UserRole + 1, field)

            field_widget = QWidget()
            field_layout = QHBoxLayout()
            field_layout.setContentsMargins(5, 5, 5, 5)
            field_layout.setSpacing(10)

            field_label = QLabel(field.label)
            field_label.setFont(QFont("Arial", 9, QFont.Bold))
            field_layout.addWidget(field_label)

            field_segment_edit = QLineEdit(f"0x{field.start:X}-0x{field.end-1:X}")
            field_segment_edit.setFont(QFont("Courier", 9))
            field_segment_edit.setMaximumWidth(150)
            field_segment_edit.setStyleSheet("QLineEdit { color: #4A9EFF; text-decoration: underline; font-weight: bold; }")
            field_segment_edit.setCursor(Qt.PointingHandCursor)
            field_segment_edit.editingFinished.connect(lambda f=field, se=field_segment_edit: self.on_field_segment_edited(f, se))
            field_segment_edit.mousePressEvent = lambda event, s=field.start, e=field.end-1: (
                self.field_segment_clicked.emit(s, e) if event.button() == Qt.LeftButton else None
            )
            field_layout.addWidget(field_segment_edit)
            field_layout.addStretch()
            field_widget.setLayout(field_layout)

            self.tree.setItemWidget(field_item, 0, field_widget)

            if preserve_expansion:
                field_item.setExpanded(id(field) in expanded_items)
            else:
                field_item.setExpanded(True)

            for subfield in field.subfields:
                self.add_subfield_to_tree(subfield, field_item, file_data, expanded_items, preserve_expansion)

    def add_subfield_to_tree(self, subfield, parent_item, file_data, expanded_items, preserve_expansion):
        subfield_item = QTreeWidgetItem(parent_item)
        subfield_item.setData(0, Qt.UserRole, "subfield")
        subfield_item.setData(0, Qt.UserRole + 1, subfield)

        subfield_item.setText(0, f"  {subfield.name}")
        subfield_item.setFont(0, QFont("Arial", 8))

        if preserve_expansion:
            subfield_item.setExpanded(id(subfield) in expanded_items)
        else:
            subfield_item.setExpanded(True)

        length = subfield.end - subfield.start

        segment_item = QTreeWidgetItem(subfield_item)
        segment_item.setText(0, "")
        segment_item.setFlags(segment_item.flags() & ~Qt.ItemIsDragEnabled)
        segment_widget = QWidget()
        segment_layout = QHBoxLayout()
        segment_layout.setContentsMargins(0, 2, 0, 2)
        segment_layout.setSpacing(5)

        segment_label = QLabel("Offset:")
        segment_label.setFont(QFont("Arial", 8))
        segment_layout.addWidget(segment_label)

        segment_edit = QLineEdit(f"0x{subfield.start:X}-0x{subfield.end-1:X}")
        segment_edit.setFont(QFont("Courier", 8))
        segment_edit.setMaximumWidth(150)
        segment_edit.setStyleSheet("QLineEdit { color: #4A9EFF; text-decoration: underline; }")
        segment_edit.setCursor(Qt.PointingHandCursor)
        segment_edit.editingFinished.connect(lambda sf=subfield, se=segment_edit: self.on_segment_edited(sf, se))
        segment_edit.mousePressEvent = lambda event, s=subfield.start, e=subfield.end-1: (
            self.field_segment_clicked.emit(s, e) if event.button() == Qt.LeftButton else None
        )
        segment_layout.addWidget(segment_edit)
        segment_layout.addStretch()
        segment_widget.setLayout(segment_layout)
        self.tree.setItemWidget(segment_item, 0, segment_widget)

        type_item = QTreeWidgetItem(subfield_item)
        type_item.setText(0, "")
        type_item.setFlags(type_item.flags() & ~Qt.ItemIsDragEnabled)
        type_widget = QWidget()
        type_layout = QHBoxLayout()
        type_layout.setContentsMargins(0, 2, 0, 2)
        type_layout.setSpacing(5)

        type_label = QLabel("Type:")
        type_label.setFont(QFont("Arial", 8))
        type_layout.addWidget(type_label)

        type_combo = QComboBox()
        type_combo.setFont(QFont("Arial", 8))
        type_combo.setMinimumWidth(80)
        type_combo.setMaximumWidth(80)
        types = self.get_valid_types_for_length(length)
        type_combo.addItems(types)

        print(f"DEBUG: Displaying subfield")
        print(f"  subfield.data_type: {subfield.data_type}")
        print(f"  length: {length}")
        print(f"  available types: {types}")

        base_type = subfield.data_type.split()[0] if ' ' in subfield.data_type else subfield.data_type
        current_endian = subfield.data_type.split()[1] if ' ' in subfield.data_type and len(subfield.data_type.split()) > 1 else subfield.endian

        print(f"  base_type: {base_type}")
        print(f"  current_endian: {current_endian}")
        print(f"  base_type in types: {base_type in types}")

        if base_type in types:
            type_combo.setCurrentText(base_type)
        type_combo.currentTextChanged.connect(lambda t, sf=subfield: self.on_type_changed(sf, t))
        type_layout.addWidget(type_combo)

        if self.needs_endianness(base_type):
            endian_btn = QPushButton(current_endian)
            endian_btn.setFont(QFont("Arial", 9))
            endian_btn.setMinimumWidth(50)
            endian_btn.setMaximumWidth(60)
            endian_btn.setMinimumHeight(25)
            endian_btn.clicked.connect(lambda checked, sf=subfield: self.toggle_endian(sf))
            type_layout.addWidget(endian_btn)

        overlay_check = QCheckBox("Overlay")
        overlay_check.setFont(QFont("Arial", 8))
        overlay_check.setToolTip("Show this subfield as an editable pointer overlay in the hex view")
        overlay_check.setChecked(getattr(subfield, "overlay_pointer", False))
        overlay_check.stateChanged.connect(lambda state, sf=subfield: self.on_overlay_changed(sf, state))
        type_layout.addWidget(overlay_check)

        type_layout.addStretch()
        type_widget.setLayout(type_layout)
        self.tree.setItemWidget(type_item, 0, type_widget)

        value_item = QTreeWidgetItem(subfield_item)
        value_item.setText(0, "")
        value_item.setFlags(value_item.flags() & ~Qt.ItemIsDragEnabled)
        value_widget = QWidget()
        value_layout = QHBoxLayout()
        value_layout.setContentsMargins(0, 2, 0, 2)
        value_layout.setSpacing(5)

        value_label = QLabel("Value:")
        value_label.setFont(QFont("Arial", 8))
        value_layout.addWidget(value_label)

        value = self.interpret_value(file_data, subfield)
        value_edit = QLineEdit(str(value))
        value_edit.setFont(QFont("Courier", 8))
        value_edit.editingFinished.connect(lambda sf=subfield, ve=value_edit: self.on_value_edited(sf, ve))
        value_layout.addWidget(value_edit)
        value_layout.addStretch()
        value_widget.setLayout(value_layout)
        self.tree.setItemWidget(value_item, 0, value_widget)

        for nested_subfield in subfield.subfields:
            self.add_subfield_to_tree(nested_subfield, subfield_item, file_data, expanded_items, preserve_expansion)

    def on_item_clicked(self, item, column):
        item_type = item.data(0, Qt.UserRole)

        if item_type == "field":
            field = item.data(0, Qt.UserRole + 1)
            if field and self.parent_editor:
                print(f"DEBUG: Highlighting field")
                print(f"  field.start = {field.start} (0x{field.start:X})")
                print(f"  field.end = {field.end} (0x{field.end:X})")
                print(f"  byte_count = {field.end - field.start}")
                print(f"  Will highlight bytes 0x{field.start:X} through 0x{field.start + (field.end - field.start) - 1:X}")
                self.parent_editor.highlight_bytes(field.start, field.end - field.start)
                self.parent_editor.scroll_to_offset(field.start, center=True)

        elif item_type == "subfield":
            subfield = item.data(0, Qt.UserRole + 1)
            if subfield and self.parent_editor:
                self.parent_editor.highlight_bytes(subfield.start, subfield.end - subfield.start)
                self.parent_editor.scroll_to_offset(subfield.start, center=True)

    def on_type_changed(self, subfield, new_type):
        subfield.data_type = new_type
        if not self.needs_endianness(new_type):
            subfield.endian = "LE"

        if self.parent_editor and hasattr(self.parent_editor, 'signature_widget'):
            for pointer in self.parent_editor.signature_widget.pointers:
                if pointer.offset == subfield.start and pointer.length == (subfield.end - subfield.start):
                    pointer.data_type = new_type
                    if not self.needs_endianness(new_type):
                        pointer.endianness = "LE"
                    break
            self.parent_editor.signature_widget.rebuild_tree()

        self.rebuild_tree(preserve_expansion=True)
        if self.parent_editor:
            self.parent_editor.display_hex()

    def on_overlay_changed(self, subfield, state):
        subfield.overlay_pointer = (state == Qt.Checked)
        if self.parent_editor:
            self.parent_editor.display_hex(preserve_scroll=True)
        self.status_label.setText(
            f"Overlay {'enabled' if subfield.overlay_pointer else 'disabled'} for '{subfield.name}'"
        )

    def toggle_endian(self, subfield):
        subfield.endian = "BE" if subfield.endian == "LE" else "LE"

        if self.parent_editor and hasattr(self.parent_editor, 'signature_widget'):
            for pointer in self.parent_editor.signature_widget.pointers:
                if pointer.offset == subfield.start and pointer.length == (subfield.end - subfield.start):
                    pointer.endianness = subfield.endian
                    break
            self.parent_editor.signature_widget.rebuild_tree()

        self.rebuild_tree(preserve_expansion=True)
        if self.parent_editor:
            self.parent_editor.display_hex()

    def on_value_edited(self, subfield, value_edit):
        if not self.parent_editor or self.parent_editor.current_tab_index < 0:
            return

        current_file = self.parent_editor.open_files[self.parent_editor.current_tab_index]
        file_data = current_file.file_data

        try:
            text = value_edit.text().strip()
            length = subfield.end - subfield.start

            bytes_val = self.value_to_bytes(text, subfield.data_type, subfield.endian, length)

            if bytes_val:
                self.parent_editor.save_undo_state()
                for i, b in enumerate(bytes_val):
                    if subfield.start + i < len(file_data):
                        file_data[subfield.start + i] = b
                        current_file.modified_bytes.add(subfield.start + i)

                current_file.modified = True

                import os
                tab_text = os.path.basename(current_file.file_path) + " *"
                self.parent_editor.tab_widget.setTabText(self.parent_editor.current_tab_index, tab_text)

                self.parent_editor.display_hex()
                self.rebuild_tree(preserve_expansion=True)
                self.status_label.setText("Value updated")

        except Exception as e:
            self.status_label.setText(f"Error: {e}")
            self.rebuild_tree(preserve_expansion=True)

    def on_field_segment_edited(self, field, segment_edit):
        try:
            text = segment_edit.text().strip()
            parts = text.split('-')
            if len(parts) != 2:
                self.status_label.setText("Invalid format. Use: 0xSTART-0xEND")
                return

            start_str = parts[0].strip().replace('0x', '').replace('0X', '')
            end_str = parts[1].strip().replace('0x', '').replace('0X', '')

            new_start = int(start_str, 16)
            new_end_inclusive = int(end_str, 16)

            if new_start > new_end_inclusive:
                self.status_label.setText("Start must be less than or equal to end")
                return

            if not self.parent_editor or self.parent_editor.current_tab_index < 0:
                return

            current_file = self.parent_editor.open_files[self.parent_editor.current_tab_index]
            if new_end_inclusive >= len(current_file.file_data):
                self.status_label.setText("End offset exceeds file size")
                return

            field.start = new_start
            field.end = new_end_inclusive + 1
            self.rebuild_tree(preserve_expansion=True)
            self.status_label.setText("Field segment updated")

            if self.parent_editor:
                self.parent_editor.display_hex()

        except ValueError:
            self.status_label.setText("Invalid hex format")
            self.rebuild_tree(preserve_expansion=True)
        except Exception as e:
            self.status_label.setText(f"Error: {e}")
            self.rebuild_tree(preserve_expansion=True)

    def on_segment_edited(self, subfield, segment_edit):
        try:
            text = segment_edit.text().strip()
            parts = text.split('-')
            if len(parts) != 2:
                self.status_label.setText("Invalid format. Use: 0xSTART-0xEND")
                return

            start_str = parts[0].strip().replace('0x', '').replace('0X', '')
            end_str = parts[1].strip().replace('0x', '').replace('0X', '')

            new_start = int(start_str, 16)
            new_end_inclusive = int(end_str, 16)

            if new_start > new_end_inclusive:
                self.status_label.setText("Start must be less than or equal to end")
                return

            if not self.parent_editor or self.parent_editor.current_tab_index < 0:
                return

            current_file = self.parent_editor.open_files[self.parent_editor.current_tab_index]
            if new_end_inclusive >= len(current_file.file_data):
                self.status_label.setText("End offset exceeds file size")
                return

            subfield.start = new_start
            subfield.end = new_end_inclusive + 1
            self.rebuild_tree(preserve_expansion=True)
            self.status_label.setText("Segment updated")

            if self.parent_editor:
                self.parent_editor.display_hex()

        except ValueError:
            self.status_label.setText("Invalid hex format")
            self.rebuild_tree(preserve_expansion=True)
        except Exception as e:
            self.status_label.setText(f"Error: {e}")
            self.rebuild_tree(preserve_expansion=True)

    def interpret_value(self, data, subfield):
        offset = subfield.start
        length = subfield.end - subfield.start
        data_type = subfield.data_type
        endian = subfield.endian

        print(f"DEBUG INTERPRET: data_type = '{data_type}', endian = '{endian}', offset = {offset}, length = {length}")

        if offset + length > len(data):
            return "N/A"

        value_bytes = bytes(data[offset:offset+length])

        try:
            dtype_lower = data_type.lower()
            print(f"DEBUG INTERPRET: dtype_lower = '{dtype_lower}'")

            if dtype_lower == "hex":
                return " ".join(f"{b:02X}" for b in value_bytes)
            elif dtype_lower == "int8":
                return struct.unpack('b', value_bytes[:1])[0]
            elif dtype_lower == "uint8":
                return struct.unpack('B', value_bytes[:1])[0]
            elif dtype_lower == "int16":
                fmt = '<h' if endian == "LE" else '>h'
                return struct.unpack(fmt, value_bytes[:2])[0]
            elif dtype_lower == "uint16":
                fmt = '<H' if endian == "LE" else '>H'
                return struct.unpack(fmt, value_bytes[:2])[0]
            elif dtype_lower == "int24":
                if endian == "LE":
                    extended = value_bytes[:3] + (b'\xff' if value_bytes[2] & 0x80 else b'\x00')
                    return struct.unpack('<i', extended)[0]
                else:
                    extended = (b'\xff' if value_bytes[0] & 0x80 else b'\x00') + value_bytes[:3]
                    return struct.unpack('>i', extended)[0]
            elif dtype_lower == "uint24":
                if endian == "LE":
                    extended = value_bytes[:3] + b'\x00'
                    return struct.unpack('<I', extended)[0]
                else:
                    extended = b'\x00' + value_bytes[:3]
                    return struct.unpack('>I', extended)[0]
            elif dtype_lower == "int32":
                fmt = '<i' if endian == "LE" else '>i'
                result = struct.unpack(fmt, value_bytes[:4])[0]
                print(f"DEBUG INTERPRET: int32 matched! fmt = '{fmt}', result = {result}")
                return result
            elif dtype_lower == "uint32":
                fmt = '<I' if endian == "LE" else '>I'
                return struct.unpack(fmt, value_bytes[:4])[0]
            elif dtype_lower == "int64":
                fmt = '<q' if endian == "LE" else '>q'
                return struct.unpack(fmt, value_bytes[:8])[0]
            elif dtype_lower == "uint64":
                fmt = '<Q' if endian == "LE" else '>Q'
                return struct.unpack(fmt, value_bytes[:8])[0]
            elif dtype_lower == "float32":
                fmt = '<f' if endian == "LE" else '>f'
                return struct.unpack(fmt, value_bytes[:4])[0]
            elif dtype_lower == "float64":
                fmt = '<d' if endian == "LE" else '>d'
                return struct.unpack(fmt, value_bytes[:8])[0]
            elif dtype_lower == "string":
                try:
                    return value_bytes.decode('utf-8', errors='replace')
                except:
                    return value_bytes.decode('latin-1', errors='replace')
            else:
                print(f"DEBUG INTERPRET: No match found, falling back to hex. dtype_lower = '{dtype_lower}'")
                return " ".join(f"{b:02X}" for b in value_bytes)

        except Exception as e:
            return f"Error: {e}"

    def value_to_bytes(self, text, data_type, endian, length):
        dtype_lower = data_type.lower()

        is_hex = text.startswith('0x') or text.startswith('0X')
        if is_hex:
            text = text[2:]

        try:
            if dtype_lower == "hex":
                hex_str = text.replace(" ", "")
                return bytes.fromhex(hex_str)[:length]
            elif dtype_lower == "int8":
                value = int(text, 16) if is_hex else int(text)
                if -128 <= value <= 127:
                    return struct.pack('b', value)
            elif dtype_lower == "uint8":
                value = int(text, 16) if is_hex else int(text)
                if 0 <= value <= 255:
                    return struct.pack('B', value)
            elif dtype_lower == "int16":
                value = int(text, 16) if is_hex else int(text)
                fmt = '<h' if endian == "LE" else '>h'
                return struct.pack(fmt, value)
            elif dtype_lower == "uint16":
                value = int(text, 16) if is_hex else int(text)
                fmt = '<H' if endian == "LE" else '>H'
                return struct.pack(fmt, value)
            elif dtype_lower == "int24":
                value = int(text, 16) if is_hex else int(text)
                if value < 0:
                    value = value + 0x1000000
                if endian == "LE":
                    return bytes([value & 0xFF, (value >> 8) & 0xFF, (value >> 16) & 0xFF])
                else:
                    return bytes([(value >> 16) & 0xFF, (value >> 8) & 0xFF, value & 0xFF])
            elif dtype_lower == "uint24":
                value = int(text, 16) if is_hex else int(text)
                if endian == "LE":
                    return bytes([value & 0xFF, (value >> 8) & 0xFF, (value >> 16) & 0xFF])
                else:
                    return bytes([(value >> 16) & 0xFF, (value >> 8) & 0xFF, value & 0xFF])
            elif dtype_lower == "int32":
                value = int(text, 16) if is_hex else int(text)
                fmt = '<i' if endian == "LE" else '>i'
                return struct.pack(fmt, value)
            elif dtype_lower == "uint32":
                value = int(text, 16) if is_hex else int(text)
                fmt = '<I' if endian == "LE" else '>I'
                return struct.pack(fmt, value)
            elif dtype_lower == "int64":
                value = int(text, 16) if is_hex else int(text)
                fmt = '<q' if endian == "LE" else '>q'
                return struct.pack(fmt, value)
            elif dtype_lower == "uint64":
                value = int(text, 16) if is_hex else int(text)
                fmt = '<Q' if endian == "LE" else '>Q'
                return struct.pack(fmt, value)
            elif dtype_lower == "float32":
                value = float(text)
                fmt = '<f' if endian == "LE" else '>f'
                return struct.pack(fmt, value)
            elif dtype_lower == "float64":
                value = float(text)
                fmt = '<d' if endian == "LE" else '>d'
                return struct.pack(fmt, value)
            elif dtype_lower == "string":
                return text.encode('utf-8')[:length]
            else:
                return None

        except Exception as e:
            raise ValueError(f"Invalid value for {data_type}: {e}")

    def get_valid_types_for_length(self, length):
        types = ["Hex"]

        if length >= 1:
            types.extend(["int8", "uint8", "String"])
        if length >= 2:
            types.extend(["int16", "uint16"])
        if length >= 3:
            types.extend(["int24", "uint24"])
        if length >= 4:
            types.extend(["int32", "uint32", "float32"])
        if length >= 8:
            types.extend(["int64", "uint64", "float64"])

        return types

    def needs_endianness(self, data_type):
        return data_type.lower() in ["int16", "uint16", "int24", "uint24", "int32", "uint32", "int64", "uint64", "float32", "float64"]

    def adjust_for_insert(self, insert_pos, insert_len, tab_index):
        for field in self.fields:
            if field.tab_index == tab_index:
                field.adjust_for_insert(insert_pos, insert_len)

    def adjust_for_delete(self, delete_pos, delete_len, tab_index):
        for field in self.fields:
            if field.tab_index == tab_index:
                field.adjust_for_delete(delete_pos, delete_len)

    def get_overlay_pointers(self, tab_index):
        from datainspect.pointers import SignaturePointer

        pointers = []

        def collect(subfields):
            for subfield in subfields:
                if getattr(subfield, "overlay_pointer", False):
                    pointer_type = subfield.data_type
                    if self.needs_endianness(pointer_type):
                        pointer_type = f"{pointer_type} {subfield.endian}"
                    pointer = SignaturePointer(
                        subfield.start,
                        subfield.end - subfield.start,
                        pointer_type,
                        subfield.name,
                        category="Fields",
                        endianness=subfield.endian
                    )
                    pointer.field_subfield = subfield
                    pointers.append(pointer)
                collect(subfield.subfields)

        for field in self.fields:
            if field.tab_index == tab_index:
                collect(field.subfields)

        return pointers
