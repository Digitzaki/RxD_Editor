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
import time
import struct
from collections import Counter
from PyQt5.QtCore import Qt, QEvent, QTimer
from PyQt5.QtWidgets import (QWidget, QVBoxLayout, QHBoxLayout, QLabel, QPushButton,
                              QScrollArea, QComboBox, QListWidget, QListWidgetItem,
                              QLineEdit)
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


COMPACT_FONT = QFont("Arial", 8)


class StatisticsWidget(QWidget):
    """Widget for displaying file statistics with multiple graph types"""

    def __init__(self, parent=None):
        super().__init__(parent)
        self.file_data = None
        self._stats_dirty = False
        self._byte_counts = None
        self._cached_total_bytes = 0
        self.byte_filter_min = 0
        self.byte_filter_max = 255
        self.analysis_matches = []
        self.analysis_match_size = 1
        self.value_filter_active = False
        self.current_graph_index = 0
        self.parent_editor = None
        self.graph_types = [
            "Byte Distribution",
            "ASCII Frequency",
            "Nibble Dist.",
            "Overall Entropy",
            "Pointer Frequency"
        ]
        self._hover_timer = QTimer()
        self._hover_timer.setSingleShot(True)
        self._hover_timer.setInterval(50)
        self._pending_hover_event = None
        self.setup_ui()

    def setup_ui(self):
        layout = QVBoxLayout()
        layout.setContentsMargins(5, 5, 5, 5)

        title_row = QHBoxLayout()
        title = QLabel("File Statistics")
        title.setFont(QFont("Arial", 11, QFont.Bold))
        title_row.addWidget(title)
        title_row.addStretch()

        if MATPLOTLIB_AVAILABLE:
            title_row.addWidget(QLabel("Filter:"))
            self.filter_mode_btn = QPushButton("Byte")
            self.filter_mode_btn.setFont(QFont("Arial", 9, QFont.Bold))
            self.filter_mode_btn.setCheckable(True)
            self.filter_mode_btn.setMinimumWidth(70)
            self.filter_mode_btn.setMaximumWidth(82)
            self.filter_mode_btn.clicked.connect(self.toggle_filter_mode)
            title_row.addWidget(self.filter_mode_btn)
        layout.addLayout(title_row)

        if MATPLOTLIB_AVAILABLE:
            self.analysis_controls_widget = QWidget()
            analysis_layout = QVBoxLayout()
            analysis_layout.setContentsMargins(0, 0, 0, 0)
            analysis_layout.setSpacing(2)

            byte_filter_layout = QHBoxLayout()
            byte_filter_layout.setSpacing(3)
            byte_label = QLabel("Byte:")
            byte_label.setFont(COMPACT_FONT)
            byte_filter_layout.addWidget(byte_label)
            self.byte_min_edit = QLineEdit("00")
            self.byte_min_edit.setFont(COMPACT_FONT)
            self.byte_min_edit.setMaximumWidth(34)
            self.byte_min_edit.setToolTip("Minimum byte value, hex or decimal")
            byte_filter_layout.addWidget(self.byte_min_edit)
            byte_filter_layout.addWidget(QLabel("-"))
            self.byte_max_edit = QLineEdit("FF")
            self.byte_max_edit.setFont(COMPACT_FONT)
            self.byte_max_edit.setMaximumWidth(34)
            self.byte_max_edit.setToolTip("Maximum byte value, hex or decimal")
            byte_filter_layout.addWidget(self.byte_max_edit)
            apply_filter_btn = QPushButton("Apply")
            apply_filter_btn.setFont(COMPACT_FONT)
            apply_filter_btn.setMinimumWidth(68)
            apply_filter_btn.setMaximumWidth(72)
            apply_filter_btn.clicked.connect(self.apply_byte_filter)
            byte_filter_layout.addWidget(apply_filter_btn)
            reset_filter_btn = QPushButton("Reset")
            reset_filter_btn.setFont(COMPACT_FONT)
            reset_filter_btn.setMinimumWidth(68)
            reset_filter_btn.setMaximumWidth(72)
            reset_filter_btn.clicked.connect(self.reset_byte_filter)
            byte_filter_layout.addWidget(reset_filter_btn)
            byte_filter_layout.addStretch()
            self.byte_filter_widget = QWidget()
            self.byte_filter_widget.setLayout(byte_filter_layout)
            analysis_layout.addWidget(self.byte_filter_widget)

            scan_layout = QHBoxLayout()
            scan_layout.setSpacing(3)
            self.scan_type_combo = QComboBox()
            self.scan_type_combo.setFont(COMPACT_FONT)
            self.scan_type_combo.addItems([
                "Float32 BE", "Float32 LE", "Float64 BE", "Float64 LE",
                "UInt16 BE", "UInt16 LE", "Int16 BE", "Int16 LE",
                "UInt32 BE", "UInt32 LE", "Int32 BE", "Int32 LE",
                "UInt64 BE", "UInt64 LE", "Int64 BE", "Int64 LE"
            ])
            self.scan_type_combo.setMaximumWidth(78)
            scan_layout.addWidget(self.scan_type_combo)
            self.scan_min_edit = QLineEdit("0.0")
            self.scan_min_edit.setFont(COMPACT_FONT)
            self.scan_min_edit.setMaximumWidth(45)
            scan_layout.addWidget(self.scan_min_edit)
            scan_layout.addWidget(QLabel("-"))
            self.scan_max_edit = QLineEdit("1.0")
            self.scan_max_edit.setFont(COMPACT_FONT)
            self.scan_max_edit.setMaximumWidth(45)
            scan_layout.addWidget(self.scan_max_edit)
            scan_btn = QPushButton("Find")
            scan_btn.setFont(COMPACT_FONT)
            scan_btn.setMinimumWidth(52)
            scan_btn.setMaximumWidth(62)
            scan_btn.clicked.connect(self.run_value_scan)
            scan_layout.addWidget(scan_btn)
            clear_scan_btn = QPushButton("Clear")
            clear_scan_btn.setFont(COMPACT_FONT)
            clear_scan_btn.setMinimumWidth(58)
            clear_scan_btn.setMaximumWidth(70)
            clear_scan_btn.clicked.connect(self.clear_analysis_matches)
            scan_layout.addWidget(clear_scan_btn)
            scan_layout.addStretch()
            self.value_filter_widget = QWidget()
            self.value_filter_widget.setLayout(scan_layout)
            self.value_filter_widget.hide()
            analysis_layout.addWidget(self.value_filter_widget)

            self.analysis_controls_widget.setLayout(analysis_layout)
            layout.addWidget(self.analysis_controls_widget)

            self.figure = Figure(figsize=(5, 4), dpi=100, facecolor='#2d2d30')
            self.canvas = FigureCanvas(self.figure)
            self.canvas.setMinimumHeight(230)
            layout.addWidget(self.canvas)

            self.hover_info_label = QLabel("")
            self.hover_info_label.setAlignment(Qt.AlignCenter)
            self.hover_info_label.setFont(QFont("Arial", 9))
            self.hover_info_label.setMinimumHeight(20)
            self.hover_info_label.setStyleSheet("color: #e5c07b; padding: 5px;")
            layout.addWidget(self.hover_info_label)

            self.pointer_controls_widget = QWidget()
            pointer_controls_layout = QVBoxLayout()
            pointer_controls_layout.setContentsMargins(0, 2, 0, 2)

            filter_layout = QHBoxLayout()
            filter_label = QLabel("Filter:")
            filter_label.setFont(COMPACT_FONT)
            filter_layout.addWidget(filter_label)

            self.pointer_filter_combo = QComboBox()
            self.pointer_filter_combo.setFont(COMPACT_FONT)
            self.pointer_filter_combo.setMaximumHeight(22)
            self.pointer_filter_combo.currentTextChanged.connect(self.on_pointer_filter_changed)
            filter_layout.addWidget(self.pointer_filter_combo)
            filter_layout.addStretch()
            pointer_controls_layout.addLayout(filter_layout)

            self.pointer_list = QListWidget()
            self.pointer_list.setFont(QFont("Courier", 8))
            self.pointer_list.setMaximumHeight(100)
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

    def set_file_data(self, data, defer_update=False):
        self.file_data = data
        self._stats_dirty = True
        self._byte_counts = None
        self._cached_total_bytes = len(data) if data else 0
        if defer_update:
            self.clear_info()
            if data:
                self.add_info_item("File Size", f"{len(data):,} bytes")
                self.add_info_item("Statistics", "Open this tab to calculate")
            if MATPLOTLIB_AVAILABLE:
                self.figure.clear()
                self.graph_label.setText(self.graph_types[self.current_graph_index])
                self.hover_info_label.setText("")
                self.canvas.draw_idle()
            return
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

        self._stats_dirty = False

        if MATPLOTLIB_AVAILABLE:
            try:
                self._hover_timer.timeout.disconnect()
            except TypeError:
                pass
            self.graph_label.setText(self.graph_types[self.current_graph_index])
            self.hover_info_label.setText("")
            self.figure.clear()
            ax = self.figure.add_subplot(111)
            self.figure.subplots_adjust(left=0.14, right=0.96, top=0.86, bottom=0.22)

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

            try:
                self.figure.tight_layout(pad=0.7)
            except Exception:
                pass
            self.canvas.draw()

        self.update_info()

    def using_value_filter(self):
        return self.value_filter_active

    def iter_filtered_positions(self):
        if not self.file_data:
            return
        data_len = len(self.file_data)
        if self.using_value_filter():
            seen = set()
            for start in self.analysis_matches:
                end = min(start + self.analysis_match_size, data_len)
                for pos in range(start, end):
                    if pos not in seen:
                        seen.add(pos)
                        yield pos
            return
        for pos, byte in enumerate(self.file_data):
            if self.byte_filter_min <= byte <= self.byte_filter_max:
                yield pos

    def get_filtered_byte_counts(self):
        counts = Counter()
        for pos in self.iter_filtered_positions():
            counts[self.file_data[pos]] += 1
        return counts

    def get_filtered_bytes(self, max_bytes=None):
        result = bytearray()
        for pos in self.iter_filtered_positions():
            result.append(self.file_data[pos])
            if max_bytes is not None and len(result) >= max_bytes:
                break
        return bytes(result)

    def graph_filter_label(self):
        if self.using_value_filter():
            return f"Value matches ({len(self.analysis_matches):,})"
        return f"0x{self.byte_filter_min:02X}-0x{self.byte_filter_max:02X}"

    def plot_nibble_distribution(self, ax):
        high_nibbles = Counter()
        low_nibbles = Counter()

        for byte, count in self.get_filtered_byte_counts().items():
            high_nibbles[byte >> 4] += count
            low_nibbles[byte & 0x0F] += count

        x = range(16)
        high_freq = [high_nibbles.get(i, 0) for i in x]
        low_freq = [low_nibbles.get(i, 0) for i in x]

        width = 0.35
        x_pos = [i - width/2 for i in x]
        x_pos2 = [i + width/2 for i in x]

        ax.bar(x_pos, high_freq, width, label='High Nibble', color='#c678dd')
        ax.bar(x_pos2, low_freq, width, label='Low Nibble', color='#56b6c2')
        ax.set_xlabel('Nibble', color='#abb2bf', fontsize=8)
        ax.set_ylabel('Freq.', color='#abb2bf', fontsize=8)
        ax.set_title(f'Nibble Dist. ({self.graph_filter_label()})', color='#abb2bf', fontsize=10)
        ax.set_xticks(x)
        ax.set_xticklabels([f"{i:X}" for i in x], fontsize=7)
        ax.legend(fontsize=7, loc='upper right')
        ax.set_facecolor('#21252b')
        ax.tick_params(colors='#abb2bf', labelsize=8, pad=1)
        for spine in ax.spines.values():
            spine.set_color('#3e4451')

    def plot_byte_distribution_throughout_file(self, ax):
        max_byte = 256

        filtered_positions = list(self.iter_filtered_positions())
        max_samples = 10000
        if len(filtered_positions) > max_samples:
            step = max(1, len(filtered_positions) // max_samples)
            filtered_positions = filtered_positions[::step]
        sampled_data = [
            (pos, self.file_data[pos])
            for pos in filtered_positions
            if self.file_data[pos] < max_byte
        ]

        if sampled_data:
            positions, byte_values = zip(*sampled_data)

            scatter = ax.scatter(positions, byte_values, s=1, c='#61afef', alpha=0.5, picker=True)
            ax.set_xlabel('Offset', color='#abb2bf', fontsize=8)
            ax.set_ylabel('Byte', color='#abb2bf', fontsize=8)

            ax.set_title(f'Byte Dist. ({self.graph_filter_label()})', color='#abb2bf', fontsize=10)
            ax.set_ylim(-5, 260)
            ax.set_yticks([0, 64, 128, 192, 255])
            ax.set_facecolor('#21252b')
            ax.tick_params(colors='#abb2bf', labelsize=8)
            for spine in ax.spines.values():
                spine.set_color('#3e4451')

            def process_hover():
                if self._pending_hover_event is None:
                    return
                event = self._pending_hover_event
                self._pending_hover_event = None

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

            self._hover_timer.timeout.connect(process_hover)

            def on_hover(event):
                self._pending_hover_event = event
                self._hover_timer.start()

            self.canvas.mpl_connect('motion_notify_event', on_hover)

            def on_pick(event):
                if event.mouseevent.inaxes == ax and hasattr(self, 'parent_editor') and self.parent_editor:
                    if len(event.ind) > 0:
                        idx = event.ind[0]
                        clicked_position = positions[idx]
                        clicked_byte = byte_values[idx]
                        if not self.using_value_filter():
                            self.search_byte_value(clicked_byte, clicked_position)

            self.canvas.mpl_connect('pick_event', on_pick)
        else:
            ax.text(0.5, 0.5, 'No bytes in selected range',
                   ha='center', va='center', transform=ax.transAxes,
                   color='#abb2bf', fontsize=11, style='italic')
            ax.set_facecolor('#21252b')
            ax.set_title(f'Byte Dist. ({self.graph_filter_label()})', color='#abb2bf', fontsize=10)
            ax.set_xticks([])
            ax.set_yticks([])
            for spine in ax.spines.values():
                spine.set_color('#3e4451')

    def plot_ascii_character_frequency(self, ax):
        max_char = 256

        char_counts = [0] * max_char
        for byte, count in self.get_filtered_byte_counts().items():
            if byte < max_char:
                char_counts[byte] = count

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

            ax.set_xlabel('Bytes', color='#abb2bf', fontsize=8)
            ax.set_ylabel('Freq.', color='#abb2bf', fontsize=8)
            ax.set_title(f'Byte Frequency ({self.graph_filter_label()})', color='#abb2bf', fontsize=10)
            ax.set_xticks([])
            ax.set_facecolor('#21252b')
            ax.tick_params(colors='#abb2bf', labelsize=8)
            for spine in ax.spines.values():
                spine.set_color('#3e4451')

            self.hover_bar_index = None

            def process_ascii_hover():
                if self._pending_hover_event is None:
                    return
                event = self._pending_hover_event
                self._pending_hover_event = None

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

            self._hover_timer.timeout.connect(process_ascii_hover)

            def on_hover(event):
                self._pending_hover_event = event
                self._hover_timer.start()

            self.canvas.mpl_connect('motion_notify_event', on_hover)

    def plot_overall_entropy(self, ax):
        entropy_data = self.get_filtered_bytes()
        if not entropy_data:
            ax.text(0.5, 0.5, 'No bytes in current filter',
                   ha='center', va='center', transform=ax.transAxes,
                   color='#abb2bf', fontsize=9, style='italic')
            ax.set_facecolor('#21252b')
            ax.set_title('Entropy Analysis', color='#abb2bf', fontsize=10)
            ax.set_xticks([])
            ax.set_yticks([])
            return

        overall_entropy = self.calculate_entropy(entropy_data)

        block_sizes = [256, 1024, 4096]
        block_entropies = {}

        for block_size in block_sizes:
            entropies = []
            for i in range(0, len(entropy_data), block_size):
                block = entropy_data[i:i+block_size]
                if block:
                    entropies.append(self.calculate_entropy(block))
            if entropies:
                block_entropies[block_size] = {
                    'mean': sum(entropies) / len(entropies),
                    'min': min(entropies),
                    'max': max(entropies)
                }

        categories = ['Overall', '256B', '1KB', '4KB']
        values = [overall_entropy]
        colors = ['#e06c75']

        for block_size in block_sizes:
            if block_size in block_entropies:
                values.append(block_entropies[block_size]['mean'])
                colors.append('#61afef')

        categories = categories[:len(values)]

        x = range(len(values))
        bars = ax.bar(x, values, color=colors, edgecolor=colors, linewidth=2)

        ax.set_ylabel('Entropy', color='#abb2bf', fontsize=8)
        ax.set_title(f'Entropy ({self.graph_filter_label()})', color='#abb2bf', fontsize=10)
        ax.set_xticks(x)
        ax.set_xticklabels(categories, color='#abb2bf', fontsize=8)
        ax.set_ylim(0, 8)
        ax.axhline(y=7, color='#98c379', linestyle='--', linewidth=1, alpha=0.5, label='High entropy (≥7 bits)')
        ax.legend(fontsize=7, loc='lower right')
        ax.set_facecolor('#21252b')
        ax.tick_params(colors='#abb2bf', labelsize=8, pad=1)
        for spine in ax.spines.values():
            spine.set_color('#3e4451')

        for i, (bar, value) in enumerate(zip(bars, values)):
            height = bar.get_height()
            ax.text(bar.get_x() + bar.get_width()/2., height,
                   f'{value:.2f}',
                   ha='center', va='bottom', color='#abb2bf', fontsize=8)

    def plot_magic_numbers_pointers(self, ax):
        pointers = []
        if self.parent_editor and hasattr(self.parent_editor, 'signature_widget'):
            pointers = self.parent_editor.signature_widget.pointers

        self.current_pointers = pointers
        self.current_pointer_filter = None

        if not pointers:
            ax.text(0.5, 0.5, 'No pointers defined',
                   ha='center', va='center', transform=ax.transAxes,
                   color='#abb2bf', fontsize=9, style='italic')
            ax.set_facecolor('#21252b')
            ax.set_title('Pointer Frequency', color='#abb2bf', fontsize=10)
            ax.set_xticks([])
            ax.set_yticks([])
            for spine in ax.spines.values():
                spine.set_color('#3e4451')

            self.pointer_list.clear()
            self.pointer_filter_combo.clear()
            self.pointer_controls_widget.hide()
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
                    if self.using_value_filter():
                        in_value_filter = any(start <= pos < start + self.analysis_match_size for start in self.analysis_matches)
                        if not in_value_filter:
                            continue
                    elif not (self.byte_filter_min <= byte_val <= self.byte_filter_max):
                        continue
                    positions.append(pos)
                    byte_values.append(byte_val)

            if positions:
                ax.scatter(positions, byte_values, s=1, c=pattern_colors[pattern_key],
                          alpha=0.5, picker=True)

        ax.set_xlabel('Offset', color='#abb2bf', fontsize=8)
        ax.set_ylabel('Byte', color='#abb2bf', fontsize=8)
        ax.set_title(f'Pointers ({self.graph_filter_label()})', color='#abb2bf', fontsize=10)
        ax.set_ylim(-5, 260)
        ax.set_yticks([0, 64, 128, 192, 255])
        ax.set_facecolor('#21252b')
        ax.tick_params(colors='#abb2bf', labelsize=8)
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
        if data is self.file_data:
            byte_counts = self.get_byte_counts()
        else:
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

    def parse_byte_filter_value(self, text):
        text = text.strip()
        if not text:
            raise ValueError("empty byte value")
        if text.lower().startswith("0x"):
            value = int(text, 16)
        elif any(c in "abcdefABCDEF" for c in text):
            value = int(text, 16)
        else:
            value = int(text, 10)
        if not 0 <= value <= 255:
            raise ValueError("byte value out of range")
        return value

    def apply_byte_filter(self):
        try:
            min_val = self.parse_byte_filter_value(self.byte_min_edit.text())
            max_val = self.parse_byte_filter_value(self.byte_max_edit.text())
            if min_val > max_val:
                min_val, max_val = max_val, min_val
            self.byte_filter_min = min_val
            self.byte_filter_max = max_val
            self.update_statistics()
        except ValueError as e:
            self.hover_info_label.setText(f"Invalid byte range: {e}")

    def reset_byte_filter(self):
        self.byte_filter_min = 0
        self.byte_filter_max = 255
        self.byte_min_edit.setText("00")
        self.byte_max_edit.setText("FF")
        self.update_statistics()

    def toggle_filter_mode(self):
        value_mode = self.filter_mode_btn.isChecked()
        self.filter_mode_btn.setText("Value" if value_mode else "Byte")
        self.byte_filter_widget.setVisible(not value_mode)
        self.value_filter_widget.setVisible(value_mode)

    def clear_analysis_matches(self):
        self.analysis_matches = []
        self.analysis_match_size = 1
        self.value_filter_active = False
        if self.parent_editor and self.parent_editor.current_tab_index >= 0:
            current_file = self.parent_editor.open_files[self.parent_editor.current_tab_index]
            current_file.search_results = []
            self.parent_editor.display_hex(preserve_scroll=True)
        self.update_statistics()

    def apply_matches_to_editor(self, matches, size, jump_to=None):
        if not self.parent_editor or self.parent_editor.current_tab_index < 0:
            return

        current_file = self.parent_editor.open_files[self.parent_editor.current_tab_index]
        current_file.search_results = [(pos, size) for pos in matches]

        if jump_to is None and matches:
            jump_to = matches[0]

        if jump_to is not None:
            self.parent_editor.cursor_position = jump_to
            self.parent_editor.cursor_nibble = 0
            self.parent_editor.scroll_to_offset(jump_to, center=True)

        self.parent_editor.display_hex(preserve_scroll=True)
        self.parent_editor.data_inspector.update()

    def populate_editor_search_results(self, matches, size, title, pattern=None, dtype=None):
        if not self.parent_editor or self.parent_editor.current_tab_index < 0:
            return

        editor = self.parent_editor
        current_file = editor.open_files[editor.current_tab_index]
        data = bytes(current_file.file_data)

        editor.create_results_overlay()
        editor.set_search_results_title(title)
        for i in reversed(range(editor.search_results_layout.count())):
            widget = editor.search_results_layout.itemAt(i).widget()
            if widget:
                widget.setParent(None)

        current_file.search_results = [(pos, size) for pos in matches]
        for pos in matches[:100]:
            if dtype:
                editor.show_datatype_search_result(pos, dtype, data, clickable=True)
            else:
                editor.show_search_result(pos, pattern or data[pos:pos + size], data, clickable=True)
        if not matches:
            editor.add_search_result_label("No matches found")
        if len(matches) > 100:
            editor.add_search_result_label(f"Showing first 100 of {len(matches):,} results")

        editor.results_overlay.show()
        editor.results_overlay.raise_()

    def search_byte_value(self, byte_value, clicked_position=None):
        matches = [i for i, byte in enumerate(self.file_data) if byte == byte_value]
        self.analysis_matches = matches
        self.analysis_match_size = 1

        rows = [
            {"offset": pos, "text": f"0x{pos:08X}  byte 0x{byte_value:02X}"}
            for pos in matches
        ]
        self.populate_editor_search_results(matches, 1, f"0x{byte_value:02X}", pattern=bytes([byte_value]))
        self.apply_matches_to_editor(matches, 1, jump_to=clicked_position)

    def get_scan_format(self, scan_type):
        mapping = {
            "Float32 BE": (">f", 4, float),
            "Float32 LE": ("<f", 4, float),
            "Float64 BE": (">d", 8, float),
            "Float64 LE": ("<d", 8, float),
            "UInt16 BE": (">H", 2, int),
            "UInt16 LE": ("<H", 2, int),
            "Int16 BE": (">h", 2, int),
            "Int16 LE": ("<h", 2, int),
            "UInt32 BE": (">I", 4, int),
            "UInt32 LE": ("<I", 4, int),
            "Int32 BE": (">i", 4, int),
            "Int32 LE": ("<i", 4, int),
            "UInt64 BE": (">Q", 8, int),
            "UInt64 LE": ("<Q", 8, int),
            "Int64 BE": (">q", 8, int),
            "Int64 LE": ("<q", 8, int),
        }
        return mapping.get(scan_type)

    def run_value_scan(self):
        if not self.file_data:
            return

        scan_type = self.scan_type_combo.currentText()
        scan_info = self.get_scan_format(scan_type)
        if not scan_info:
            self.hover_info_label.setText("Unsupported scan type")
            return

        fmt, size, caster = scan_info
        try:
            min_val = caster(self.scan_min_edit.text().strip())
            max_val = caster(self.scan_max_edit.text().strip())
        except ValueError:
            self.hover_info_label.setText("Invalid scan range")
            return

        if min_val > max_val:
            min_val, max_val = max_val, min_val

        matches = []
        rows = []
        data_len = len(self.file_data)
        for pos in range(0, data_len - size + 1):
            try:
                raw = bytes(self.file_data[pos:pos + size])
                value = struct.unpack(fmt, raw)[0]
            except struct.error:
                continue
            if isinstance(value, float) and (math.isnan(value) or math.isinf(value)):
                continue
            if min_val <= value <= max_val:
                matches.append(pos)
                if len(rows) < 100:
                    hex_bytes = " ".join(f"{b:02X}" for b in raw)
                    rows.append({
                        "offset": pos,
                        "text": f"0x{pos:08X}  {scan_type}={value:g}  {hex_bytes}"
                    })

        self.analysis_matches = matches
        self.analysis_match_size = size
        self.value_filter_active = True
        self.hover_info_label.setText(f"Value filter: {len(matches):,} matches")
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

        byte_counts = self.get_byte_counts()
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

        high_nibbles = Counter()
        low_nibbles = Counter()
        for byte, count in byte_counts.items():
            high_nibbles[byte >> 4] += count
            low_nibbles[byte & 0x0F] += count
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
        max_windows = 250000
        step = max(1, (len(self.file_data) - 3) // max_windows)

        for i in range(0, len(self.file_data) - 3, step):
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

        if step > 1:
            self.add_info_item("  Note", f"sampled every {step:,} bytes for speed")

    def get_byte_counts(self):
        total_bytes = len(self.file_data) if self.file_data else 0
        if self._byte_counts is None or self._cached_total_bytes != total_bytes:
            self._byte_counts = Counter(self.file_data)
            self._cached_total_bytes = total_bytes
        return self._byte_counts

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
