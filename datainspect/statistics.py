"""
Statistics Module
=================

This module provides file statistics and visualization functionality.

Features:
- Byte distribution throughout file
- ASCII character frequency
- High/Low nibble distribution
- Overall entropy analysis
- Magic numbers/pointers visualization
- Interactive graphs with matplotlib
"""

import math
from collections import Counter
from PyQt5.QtCore import Qt, QEvent
from PyQt5.QtWidgets import (QWidget, QVBoxLayout, QHBoxLayout, QLabel, QPushButton,
                              QScrollArea, QComboBox, QListWidget, QListWidgetItem)
from PyQt5.QtGui import QFont, QColor

# Check for matplotlib availability
try:
    import matplotlib
    matplotlib.use('Qt5Agg')
    from matplotlib.backends.backend_qt5agg import FigureCanvasQTAgg as FigureCanvas
    from matplotlib.figure import Figure
    MATPLOTLIB_AVAILABLE = True
except ImportError:
    MATPLOTLIB_AVAILABLE = False


class StatisticsWidget(QWidget):
    """Widget for displaying file statistics with multiple graph types"""

    def __init__(self, parent=None):
        super().__init__(parent)
        self.file_data = None
        self.current_graph_index = 0
        self.parent_editor = None
        self.graph_types = [
            "Byte Distribution",
            "ASCII Character Frequency",
            "High/Low Nibble Distribution",
            "Overall Entropy",
            "Magic Numbers / Pointers"
        ]
        self.setup_ui()

    def setup_ui(self):
        layout = QVBoxLayout()
        layout.setContentsMargins(5, 5, 5, 5)

        title = QLabel("File Statistics")
        title.setFont(QFont("Arial", 11, QFont.Bold))
        layout.addWidget(title)

        if MATPLOTLIB_AVAILABLE:
            self.figure = Figure(figsize=(5, 4), dpi=100, facecolor='#2d2d30')
            self.canvas = FigureCanvas(self.figure)
            self.canvas.setMinimumHeight(250)
            layout.addWidget(self.canvas)

            self.hover_info_label = QLabel("")
            self.hover_info_label.setAlignment(Qt.AlignCenter)
            self.hover_info_label.setFont(QFont("Arial", 9))
            self.hover_info_label.setMinimumHeight(20)
            self.hover_info_label.setStyleSheet("color: #e5c07b; padding: 5px;")
            layout.addWidget(self.hover_info_label)

            self.pointer_controls_widget = QWidget()
            pointer_controls_layout = QVBoxLayout()
            pointer_controls_layout.setContentsMargins(0, 5, 0, 5)

            filter_layout = QHBoxLayout()
            filter_label = QLabel("Filter:")
            filter_label.setFont(QFont("Arial", 9))
            filter_layout.addWidget(filter_label)

            self.pointer_filter_combo = QComboBox()
            self.pointer_filter_combo.setFont(QFont("Arial", 9))
            self.pointer_filter_combo.currentTextChanged.connect(self.on_pointer_filter_changed)
            filter_layout.addWidget(self.pointer_filter_combo)
            filter_layout.addStretch()
            pointer_controls_layout.addLayout(filter_layout)

            self.pointer_list = QListWidget()
            self.pointer_list.setFont(QFont("Courier", 8))
            self.pointer_list.setMaximumHeight(150)
            self.pointer_list.itemClicked.connect(self.on_pointer_list_clicked)
            self.pointer_list.itemEntered.connect(self.on_pointer_list_hovered)
            self.pointer_list.setMouseTracking(True)
            pointer_controls_layout.addWidget(self.pointer_list)

            self.pointer_controls_widget.setLayout(pointer_controls_layout)
            self.pointer_controls_widget.hide()
            layout.addWidget(self.pointer_controls_widget)

            nav_layout = QHBoxLayout()
            self.prev_graph_btn = QPushButton("◄")
            self.prev_graph_btn.clicked.connect(self.prev_graph)
            nav_layout.addWidget(self.prev_graph_btn)

            self.graph_label = QLabel(self.graph_types[0])
            self.graph_label.setAlignment(Qt.AlignCenter)
            self.graph_label.setFont(QFont("Arial", 9, QFont.Bold))
            nav_layout.addWidget(self.graph_label)

            self.next_graph_btn = QPushButton("►")
            self.next_graph_btn.clicked.connect(self.next_graph)
            nav_layout.addWidget(self.next_graph_btn)

            layout.addLayout(nav_layout)
        else:
            info_label = QLabel("Matplotlib not available. Install matplotlib for graph visualization.")
            info_label.setWordWrap(True)
            layout.addWidget(info_label)

        info_scroll = QScrollArea()
        info_scroll.setWidgetResizable(True)
        info_scroll.setMinimumHeight(200)

        self.info_widget = QWidget()
        self.info_layout = QVBoxLayout()
        self.info_layout.setAlignment(Qt.AlignTop)
        self.info_widget.setLayout(self.info_layout)
        info_scroll.setWidget(self.info_widget)

        layout.addWidget(info_scroll)

        self.setLayout(layout)

        self.installEventFilter(self)

    def eventFilter(self, obj, event):
        if event.type() == QEvent.KeyPress:
            if event.key() == Qt.Key_Left:
                self.prev_graph()
                return True
            elif event.key() == Qt.Key_Right:
                self.next_graph()
                return True
        return super().eventFilter(obj, event)

    def set_file_data(self, data):
        self.file_data = data
        self.update_statistics()

    def prev_graph(self):
        if not MATPLOTLIB_AVAILABLE or not self.file_data:
            return
        self.current_graph_index = (self.current_graph_index - 1) % len(self.graph_types)
        self.update_statistics()

    def next_graph(self):
        if not MATPLOTLIB_AVAILABLE or not self.file_data:
            return
        self.current_graph_index = (self.current_graph_index + 1) % len(self.graph_types)
        self.update_statistics()

    def update_statistics(self):
        if not self.file_data:
            self.clear_info()
            return

        if MATPLOTLIB_AVAILABLE:
            self.graph_label.setText(self.graph_types[self.current_graph_index])
            self.hover_info_label.setText("")
            self.figure.clear()
            ax = self.figure.add_subplot(111)

            if self.current_graph_index == 4:
                self.pointer_controls_widget.show()
            else:
                self.pointer_controls_widget.hide()

            if self.current_graph_index == 0:
                self.plot_byte_distribution_throughout_file(ax)
            elif self.current_graph_index == 1:
                self.plot_ascii_character_frequency(ax)
            elif self.current_graph_index == 2:
                self.plot_nibble_distribution(ax)
            elif self.current_graph_index == 3:
                self.plot_overall_entropy(ax)
            elif self.current_graph_index == 4:
                self.plot_magic_numbers_pointers(ax)

            self.canvas.draw()

        self.update_info()

    def plot_nibble_distribution(self, ax):
        high_nibbles = Counter()
        low_nibbles = Counter()

        for byte in self.file_data:
            high_nibbles[byte >> 4] += 1
            low_nibbles[byte & 0x0F] += 1

        x = range(16)
        high_freq = [high_nibbles.get(i, 0) for i in x]
        low_freq = [low_nibbles.get(i, 0) for i in x]

        width = 0.35
        x_pos = [i - width/2 for i in x]
        x_pos2 = [i + width/2 for i in x]

        ax.bar(x_pos, high_freq, width, label='High Nibble', color='#c678dd')
        ax.bar(x_pos2, low_freq, width, label='Low Nibble', color='#56b6c2')
        ax.set_xlabel('Nibble Value', color='#abb2bf')
        ax.set_ylabel('Frequency', color='#abb2bf')
        ax.set_title('High/Low Nibble Distribution', color='#abb2bf')
        ax.set_xticks(x)
        ax.legend()
        ax.set_facecolor('#21252b')
        ax.tick_params(colors='#abb2bf')
        for spine in ax.spines.values():
            spine.set_color('#3e4451')

    def plot_byte_distribution_throughout_file(self, ax):
        max_byte = 256

        max_samples = 10000
        if len(self.file_data) > max_samples:
            step = len(self.file_data) // max_samples
            sampled_positions = range(0, len(self.file_data), step)
            sampled_data = [(pos, self.file_data[pos]) for pos in sampled_positions if self.file_data[pos] < max_byte]
        else:
            sampled_data = [(i, byte) for i, byte in enumerate(self.file_data) if byte < max_byte]

        if sampled_data:
            positions, byte_values = zip(*sampled_data)

            scatter = ax.scatter(positions, byte_values, s=1, c='#61afef', alpha=0.5, picker=True)
            ax.set_xlabel('File Position', color='#abb2bf')
            ax.set_ylabel('Byte Value', color='#abb2bf')

            ax.set_title('Byte Distribution', color='#abb2bf')
            ax.set_ylim(-5, 260)
            ax.set_yticks([0, 64, 128, 192, 255])
            ax.set_facecolor('#21252b')
            ax.tick_params(colors='#abb2bf')
            for spine in ax.spines.values():
                spine.set_color('#3e4451')

            def on_hover(event):
                if event.inaxes == ax:
                    if event.xdata is not None and event.ydata is not None:
                        x_range = ax.get_xlim()[1] - ax.get_xlim()[0]
                        y_range = ax.get_ylim()[1] - ax.get_ylim()[0]

                        distances = []
                        for i, (px, py) in enumerate(zip(positions, byte_values)):
                            norm_dx = (px - event.xdata) / x_range
                            norm_dy = (py - event.ydata) / y_range
                            dist = norm_dx**2 + norm_dy**2
                            distances.append((dist, i))

                        distances.sort()
                        if distances and distances[0][0] < 0.001:
                            closest_idx = distances[0][1]
                            pos = positions[closest_idx]
                            byte_val = byte_values[closest_idx]

                            control_chars = {
                                0: 'NUL', 1: 'SOH', 2: 'STX', 3: 'ETX', 4: 'EOT', 5: 'ENQ', 6: 'ACK', 7: 'BEL',
                                8: 'BS', 9: 'TAB', 10: 'LF', 11: 'VT', 12: 'FF', 13: 'CR', 14: 'SO', 15: 'SI',
                                16: 'DLE', 17: 'DC1', 18: 'DC2', 19: 'DC3', 20: 'DC4', 21: 'NAK', 22: 'SYN', 23: 'ETB',
                                24: 'CAN', 25: 'EM', 26: 'SUB', 27: 'ESC', 28: 'FS', 29: 'GS', 30: 'RS', 31: 'US',
                                127: 'DEL'
                            }

                            if 32 <= byte_val <= 126:
                                char_display = f"'{chr(byte_val)}'"
                            elif byte_val in control_chars:
                                char_display = control_chars[byte_val]
                            elif 160 <= byte_val <= 255:
                                char_display = f"'{chr(byte_val)}'"
                            else:
                                char_display = f"\\x{byte_val:02x}"

                            label_text = f"Position: 0x{pos:x} ({pos})  •  Byte: {byte_val} (0x{byte_val:02x}) {char_display}"
                            self.hover_info_label.setText(label_text)
                            return

                    self.hover_info_label.setText("")

            self.canvas.mpl_connect('motion_notify_event', on_hover)

            def on_pick(event):
                if event.mouseevent.inaxes == ax and hasattr(self, 'parent_editor') and self.parent_editor:
                    if len(event.ind) > 0:
                        idx = event.ind[0]
                        clicked_position = positions[idx]

                        self.parent_editor.cursor_position = clicked_position
                        self.parent_editor.cursor_nibble = 0
                        self.parent_editor.scroll_to_offset(clicked_position)
                        self.parent_editor.display_hex(preserve_scroll=True)
                        self.parent_editor.data_inspector.update()

            self.canvas.mpl_connect('pick_event', on_pick)

    def plot_ascii_character_frequency(self, ax):
        max_char = 256

        char_counts = [0] * max_char
        for byte in self.file_data:
            if byte < max_char:
                char_counts[byte] += 1

        chars = list(range(max_char))
        counts = char_counts

        if chars:
            def get_char_label(char_code):
                control_chars = {
                    0: 'NUL', 1: 'SOH', 2: 'STX', 3: 'ETX', 4: 'EOT', 5: 'ENQ', 6: 'ACK', 7: 'BEL',
                    8: 'BS', 9: 'TAB', 10: 'LF', 11: 'VT', 12: 'FF', 13: 'CR', 14: 'SO', 15: 'SI',
                    16: 'DLE', 17: 'DC1', 18: 'DC2', 19: 'DC3', 20: 'DC4', 21: 'NAK', 22: 'SYN', 23: 'ETB',
                    24: 'CAN', 25: 'EM', 26: 'SUB', 27: 'ESC', 28: 'FS', 29: 'GS', 30: 'RS', 31: 'US',
                    127: 'DEL'
                }

                if 32 <= char_code <= 126:
                    return f"'{chr(char_code)}' (Byte {char_code})"
                elif char_code in control_chars:
                    return f'{control_chars[char_code]} (Byte {char_code})'
                elif 160 <= char_code <= 255:
                    return f"'{chr(char_code)}' (Byte {char_code})"
                else:
                    return f'\\x{char_code:02x} (Byte {char_code})'

            x = range(len(chars))
            bars = ax.bar(x, counts, color='#98c379', edgecolor='#98c379', linewidth=1)

            ax.set_xlabel('Byte Characters', color='#abb2bf')
            ax.set_ylabel('Frequency', color='#abb2bf')
            ax.set_title('Byte Character Frequency (0-255) - Hover for details', color='#abb2bf')
            ax.set_xticks([])
            ax.set_facecolor('#21252b')
            ax.tick_params(colors='#abb2bf')
            for spine in ax.spines.values():
                spine.set_color('#3e4451')

            self.hover_bar_index = None

            def on_hover(event):
                if event.inaxes == ax and event.xdata is not None:
                    bar_index = int(round(event.xdata))

                    if 0 <= bar_index < len(bars):
                        if self.hover_bar_index != bar_index:
                            for b in bars:
                                b.set_color('#98c379')
                                b.set_edgecolor('#98c379')
                                b.set_linewidth(1)

                            bars[bar_index].set_color('#61afef')
                            bars[bar_index].set_edgecolor('#61afef')
                            bars[bar_index].set_linewidth(2)

                            char_code = chars[bar_index]
                            count = counts[bar_index]
                            label = get_char_label(char_code)
                            self.hover_info_label.setText(f"{label}  •  Count: {count}")

                            self.hover_bar_index = bar_index
                            self.canvas.draw_idle()
                        return

                if self.hover_bar_index is not None:
                    for b in bars:
                        b.set_color('#98c379')
                        b.set_edgecolor('#98c379')
                        b.set_linewidth(1)
                    self.hover_info_label.setText("")
                    self.hover_bar_index = None
                    self.canvas.draw_idle()

            self.canvas.mpl_connect('motion_notify_event', on_hover)

    def plot_overall_entropy(self, ax):
        overall_entropy = self.calculate_entropy(self.file_data)

        block_sizes = [256, 1024, 4096]
        block_entropies = {}

        for block_size in block_sizes:
            entropies = []
            for i in range(0, len(self.file_data), block_size):
                block = self.file_data[i:i+block_size]
                if block:
                    entropies.append(self.calculate_entropy(block))
            if entropies:
                block_entropies[block_size] = {
                    'mean': sum(entropies) / len(entropies),
                    'min': min(entropies),
                    'max': max(entropies)
                }

        categories = ['Overall', '256-byte\nblocks', '1KB\nblocks', '4KB\nblocks']
        values = [overall_entropy]
        colors = ['#e06c75']

        for block_size in block_sizes:
            if block_size in block_entropies:
                values.append(block_entropies[block_size]['mean'])
                colors.append('#61afef')

        categories = categories[:len(values)]

        x = range(len(values))
        bars = ax.bar(x, values, color=colors, edgecolor=colors, linewidth=2)

        ax.set_ylabel('Entropy (bits)', color='#abb2bf')
        ax.set_title('Entropy Analysis', color='#abb2bf')
        ax.set_xticks(x)
        ax.set_xticklabels(categories, color='#abb2bf')
        ax.set_ylim(0, 8)
        ax.axhline(y=7, color='#98c379', linestyle='--', linewidth=1, alpha=0.5, label='High entropy (≥7 bits)')
        ax.legend()
        ax.set_facecolor('#21252b')
        ax.tick_params(colors='#abb2bf')
        for spine in ax.spines.values():
            spine.set_color('#3e4451')

        for i, (bar, value) in enumerate(zip(bars, values)):
            height = bar.get_height()
            ax.text(bar.get_x() + bar.get_width()/2., height,
                   f'{value:.2f}',
                   ha='center', va='bottom', color='#abb2bf', fontsize=9)

    def plot_magic_numbers_pointers(self, ax):
        pointers = []
        if self.parent_editor and hasattr(self.parent_editor, 'signature_widget'):
            pointers = self.parent_editor.signature_widget.pointers

        self.current_pointers = pointers
        self.current_pointer_filter = None

        if not pointers:
            ax.text(0.5, 0.5, 'No pointers defined\n\nAdd pointers in the Pointers tab to visualize them here',
                   ha='center', va='center', transform=ax.transAxes,
                   color='#abb2bf', fontsize=11, style='italic')
            ax.set_facecolor('#21252b')
            ax.set_title('Magic Numbers / Pointers Distribution', color='#abb2bf')
            ax.set_xticks([])
            ax.set_yticks([])
            for spine in ax.spines.values():
                spine.set_color('#3e4451')

            self.pointer_list.clear()
            self.pointer_filter_combo.clear()
            return

        pattern_groups = {}
        selection_pointers = []

        for pointer in pointers:
            is_selection = (hasattr(pointer, 'category') and pointer.category == "Custom" and
                          hasattr(pointer, 'label') and pointer.label.startswith("Selection_"))

            if is_selection:
                selection_pointers.append(pointer)
            else:
                pattern = pointer.pattern if hasattr(pointer, 'pattern') and pointer.pattern else b''
                if isinstance(pattern, (bytes, bytearray)) and len(pattern) > 0:
                    pattern_key = ' '.join(f'{b:02X}' for b in pattern)
                else:
                    pattern_key = f"Unknown ({pointer.category if hasattr(pointer, 'category') else 'Custom'})"

                if pattern_key not in pattern_groups:
                    pattern_groups[pattern_key] = []
                pattern_groups[pattern_key].append(pointer)

        if selection_pointers:
            pattern_groups["Selection"] = selection_pointers

        self.pattern_groups = pattern_groups

        color_palette = ['#e06c75', '#61afef', '#98c379', '#e5c07b', '#c678dd', '#56b6c2', '#d19a66']
        pattern_colors = {}
        for i, pattern_key in enumerate(pattern_groups.keys()):
            pattern_colors[pattern_key] = color_palette[i % len(color_palette)]

        self.pattern_colors = pattern_colors

        current_filter = self.pointer_filter_combo.currentText() if self.pointer_filter_combo.count() > 0 else "All"

        self.pointer_filter_combo.blockSignals(True)
        self.pointer_filter_combo.clear()
        self.pointer_filter_combo.addItem("All")

        if "Selection" in pattern_groups:
            self.pointer_filter_combo.addItem("Selection")

        other_patterns = sorted([k for k in pattern_groups.keys() if k != "Selection"])
        for pattern_key in other_patterns:
            self.pointer_filter_combo.addItem(pattern_key)

        filter_index = self.pointer_filter_combo.findText(current_filter)
        if filter_index >= 0:
            self.pointer_filter_combo.setCurrentIndex(filter_index)
        else:
            self.pointer_filter_combo.setCurrentIndex(0)

        self.pointer_filter_combo.blockSignals(False)

        current_filter = self.pointer_filter_combo.currentText()
        if current_filter == "All":
            pointers_to_show = pointers
        else:
            pointers_to_show = pattern_groups.get(current_filter, [])

        file_length = len(self.file_data)

        for pattern_key, group_pointers in pattern_groups.items():
            if current_filter != "All" and pattern_key != current_filter:
                continue

            positions = []
            byte_values = []

            for pointer in group_pointers:
                pos = pointer.offset if hasattr(pointer, 'offset') else 0

                if 0 <= pos < file_length:
                    byte_val = self.file_data[pos]
                    positions.append(pos)
                    byte_values.append(byte_val)

            if positions:
                ax.scatter(positions, byte_values, s=1, c=pattern_colors[pattern_key],
                          alpha=0.5, picker=True)

        ax.set_xlabel('File Position', color='#abb2bf')
        ax.set_ylabel('Byte Value', color='#abb2bf')
        ax.set_title('Magic Numbers / Pointers Distribution', color='#abb2bf')
        ax.set_ylim(-5, 260)
        ax.set_yticks([0, 64, 128, 192, 255])
        ax.set_facecolor('#21252b')
        ax.tick_params(colors='#abb2bf')
        for spine in ax.spines.values():
            spine.set_color('#3e4451')

        self.pointer_list.clear()
        for pointer in pointers_to_show:
            pos = pointer.offset if hasattr(pointer, 'offset') else 0
            label = pointer.label if hasattr(pointer, 'label') and pointer.label else 'Unknown'
            byte_val = self.file_data[pos] if 0 <= pos < file_length else 0

            pattern = pointer.pattern if hasattr(pointer, 'pattern') else ''
            if isinstance(pattern, (bytes, bytearray)):
                pattern_str = ' '.join(f'{b:02X}' for b in pattern[:4])
                pattern_key = ' '.join(f'{b:02X}' for b in pattern)
                if len(pattern) > 4:
                    pattern_str += '...'
            else:
                pattern_str = str(pattern)[:12]
                pattern_key = str(pattern)

            list_text = f"[{label}] 0x{pos:06X} | {pattern_str}"
            item = QListWidgetItem(list_text)
            item.setData(Qt.UserRole, pointer)

            if pattern_key in self.pattern_colors:
                item.setForeground(QColor(self.pattern_colors[pattern_key]))

            self.pointer_list.addItem(item)

    def calculate_entropy(self, data):
        if not data:
            return 0
        byte_counts = Counter(data)
        entropy = 0
        data_len = len(data)
        for count in byte_counts.values():
            probability = count / data_len
            if probability > 0:
                entropy -= probability * math.log2(probability)
        return entropy

    def on_pointer_filter_changed(self, filter_text):
        self.update_statistics()

    def on_pointer_list_clicked(self, item):
        pointer = item.data(Qt.UserRole)
        if pointer and self.parent_editor:
            pos = pointer.offset if hasattr(pointer, 'offset') else 0

            self.parent_editor.cursor_position = pos
            self.parent_editor.cursor_nibble = 0
            self.parent_editor.scroll_to_offset(pos)
            self.parent_editor.display_hex(preserve_scroll=True)
            self.parent_editor.data_inspector.update()

    def on_pointer_list_hovered(self, item):
        pointer = item.data(Qt.UserRole)
        if pointer and self.file_data:
            pos = pointer.offset if hasattr(pointer, 'offset') else 0
            label = pointer.label if hasattr(pointer, 'label') and pointer.label else 'Unknown'
            byte_val = self.file_data[pos] if 0 <= pos < len(self.file_data) else 0

            pattern = pointer.pattern if hasattr(pointer, 'pattern') else ''
            if isinstance(pattern, (bytes, bytearray)):
                pattern_str = ' '.join(f'{b:02X}' for b in pattern[:8])
                if len(pattern) > 8:
                    pattern_str += '...'
            else:
                pattern_str = str(pattern)[:20]

            label_text = f"{label} @ 0x{pos:X}  •  Pattern: {pattern_str}  •  Byte: 0x{byte_val:02X}"
            self.hover_info_label.setText(label_text)

    def update_plots(self):
        self.update_statistics()

    def update_info(self):
        self.clear_info()

        if not self.file_data:
            return

        byte_counts = Counter(self.file_data)
        total_bytes = len(self.file_data)

        self.add_info_item("File Size", f"{total_bytes:,} bytes")

        most_common = byte_counts.most_common(5)
        self.add_info_section("Most Common Bytes:")
        for byte_val, count in most_common:
            percentage = (count / total_bytes) * 100
            self.add_info_item(f"  0x{byte_val:02X}", f"{count:,} ({percentage:.2f}%)")

        null_count = byte_counts.get(0, 0)
        null_percentage = (null_count / total_bytes) * 100
        self.add_info_item("Null Bytes (0x00)", f"{null_count:,} ({null_percentage:.2f}%)")

        printable_count = sum(count for byte_val, count in byte_counts.items()
                             if (32 <= byte_val <= 126) or (160 <= byte_val <= 255))
        non_printable_count = total_bytes - printable_count
        printable_percentage = (printable_count / total_bytes) * 100
        self.add_info_item("Printable Bytes", f"{printable_count:,} ({printable_percentage:.2f}%)")
        self.add_info_item("Non-Printable Bytes", f"{non_printable_count:,} ({100-printable_percentage:.2f}%)")

        high_nibbles = Counter(byte >> 4 for byte in self.file_data)
        low_nibbles = Counter(byte & 0x0F for byte in self.file_data)
        self.add_info_section("Nibble Distribution:")
        self.add_info_item("  Most common high nibble", f"0x{high_nibbles.most_common(1)[0][0]:X}")
        self.add_info_item("  Most common low nibble", f"0x{low_nibbles.most_common(1)[0][0]:X}")

        entropy = self.calculate_entropy(self.file_data)
        self.add_info_item("Overall Entropy", f"{entropy:.4f} bits")

        self.detect_repeated_sequences()

    def detect_repeated_sequences(self):
        if len(self.file_data) < 4:
            return

        self.add_info_section("Repeated Sequences:")

        sequences = Counter()
        for i in range(len(self.file_data) - 3):
            seq = bytes(self.file_data[i:i+4])
            if seq != b'\x00\x00\x00\x00':
                sequences[seq] += 1

        most_repeated = [(seq, count) for seq, count in sequences.most_common(3) if count > 1]

        if most_repeated:
            for seq, count in most_repeated:
                hex_str = ' '.join(f'{b:02X}' for b in seq)
                self.add_info_item(f"  {hex_str}", f"appears {count} times")
        else:
            self.add_info_item("  No significant patterns", "detected")

    def add_info_section(self, title):
        label = QLabel(title)
        label.setFont(QFont("Arial", 9, QFont.Bold))
        label.setStyleSheet("margin-top: 10px;")
        self.info_layout.addWidget(label)

    def add_info_item(self, label_text, value_text):
        item_layout = QHBoxLayout()

        label = QLabel(label_text + ":")
        label.setFont(QFont("Arial", 9))
        label.setMinimumWidth(180)
        item_layout.addWidget(label)

        value = QLabel(value_text)
        value.setFont(QFont("Courier", 9))
        item_layout.addWidget(value)

        item_layout.addStretch()
        self.info_layout.addLayout(item_layout)

    def clear_info(self):
        while self.info_layout.count():
            item = self.info_layout.takeAt(0)
            if item.widget():
                item.widget().deleteLater()
            elif item.layout():
                while item.layout().count():
                    subitem = item.layout().takeAt(0)
                    if subitem.widget():
                        subitem.widget().deleteLater()
