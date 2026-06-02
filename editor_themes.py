"""
Hex Editor Themes
Defines color schemes for the hex editor application
"""

import json
import os
import sys
import ctypes
from pathlib import Path
from rxd_paths import migrated_storage_path

try:
    from PyQt5.QtWidgets import (QDialog, QVBoxLayout, QHBoxLayout, QGridLayout, QLabel,
                                 QPushButton, QLineEdit, QScrollArea, QWidget,
                                 QColorDialog, QFrame, QMessageBox, QComboBox,
                                 QFileDialog, QCheckBox, QSlider, QGroupBox,
                                 QSizePolicy)
    from PyQt5.QtCore import Qt, pyqtSignal, QTimer
    from PyQt5.QtGui import QColor, QPalette, QLinearGradient, QBrush
    PYQT_AVAILABLE = True
except ImportError:
    PYQT_AVAILABLE = False

THEMES = {
    "Dark": {
        "Dark": {
            "name": "Dark",
            "background": "#1e1e1e",
            "inspector_bg": "#1e1e1e",
            "foreground": "#d4d4d4",
            "editor_bg": "#252526",
            "editor_fg": "#d4d4d4",
            "selection_bg": "#264f78",
            "border": "#3e3e42",
            "grid_line": "#888888",
            "menubar_bg": "#2d2d30",
            "menubar_selected": "#3e3e42",
            "button_bg": "#0e639c",
            "button_hover": "#1177bb",
            "button_disabled": "#3e3e42",
            "modified_byte": "#ff6b6b",
            "inserted_byte": "#51cf66",
            "replaced_byte": "#74c0fc"
        },
        "Monotone Dark": {
            "name": "Monotone Dark",
            "background": "#000000",
            "inspector_bg": "#000000",
            "foreground": "#ffffff",
            "editor_bg": "#0a0a0a",
            "editor_fg": "#ffffff",
            "selection_bg": "#404040",
            "border": "#505050",
            "grid_line": "#606060",
            "menubar_bg": "#050505",
            "menubar_selected": "#202020",
            "button_bg": "#c0c0c0",
            "button_hover": "#a0a0a0",
            "button_disabled": "#404040",
            "modified_byte": "#ff5050",
            "inserted_byte": "#50ff50",
            "replaced_byte": "#5050ff"
        },
        "Dracula": {
            "name": "Dracula",
            "background": "#282a36",
            "inspector_bg": "#282a36",
            "foreground": "#f8f8f2",
            "editor_bg": "#21222c",
            "editor_fg": "#f8f8f2",
            "selection_bg": "#44475a",
            "border": "#44475a",
            "grid_line": "#6272a4",
            "menubar_bg": "#21222c",
            "menubar_selected": "#44475a",
            "button_bg": "#bd93f9",
            "button_hover": "#cfa8ff",
            "button_disabled": "#44475a",
            "modified_byte": "#ff79c6",
            "inserted_byte": "#50fa7b",
            "replaced_byte": "#8be9fd"
        },
        "Solarized Dark": {
            "name": "Solarized Dark",
            "background": "#002b36",
            "inspector_bg": "#002b36",
            "foreground": "#93a1a1",
            "editor_bg": "#073642",
            "editor_fg": "#eee8d5",
            "selection_bg": "#586e75",
            "border": "#073642",
            "grid_line": "#839496",
            "menubar_bg": "#073642",
            "menubar_selected": "#586e75",
            "button_bg": "#268bd2",
            "button_hover": "#2aa198",
            "button_disabled": "#073642",
            "modified_byte": "#dc322f",
            "inserted_byte": "#859900",
            "replaced_byte": "#268bd2"
        },
        "Matrix": {
            "name": "Matrix",
            "background": "#0d0208",
            "inspector_bg": "#0d0208",
            "foreground": "#00ff41",
            "editor_bg": "#0a0a0a",
            "editor_fg": "#6b8e6b",
            "selection_bg": "#003b00",
            "border": "#00ff41",
            "grid_line": "#1f850d",
            "menubar_bg": "#0a0a0a",
            "menubar_selected": "#1a1a1a",
            "button_bg": "#00ff41",
            "button_hover": "#39ff14",
            "button_disabled": "#1a1a1a",
            "button_text": "#000000",
            "modified_byte": "#39ff14",
            "inserted_byte": "#00ff41",
            "replaced_byte": "#00d9ff"
        },
        "Halloween": {
            "name": "Halloween",
            "background": "#1a0033",
            "inspector_bg": "#1a0033",
            "foreground": "#ff6600",
            "editor_bg": "#2d0052",
            "editor_fg": "#ffaa00",
            "selection_bg": "#4d0080",
            "border": "#6600cc",
            "grid_line": "#8000ff",
            "menubar_bg": "#2d0052",
            "menubar_selected": "#4d0080",
            "button_bg": "#ff6600",
            "button_hover": "#ff8833",
            "button_disabled": "#4d0080",
            "modified_byte": "#ff0066",
            "inserted_byte": "#00ff66",
            "replaced_byte": "#00ccff"
        },
        "Jolly": {
            "name": "Jolly",
            "background": "#0d2818",
            "inspector_bg": "#0d2818",
            "foreground": "#ff2e2e",
            "editor_bg": "#0a1f14",
            "editor_fg": "#ffeded",
            "selection_bg": "#1a4d2e",
            "border": "#2d5a3d",
            "grid_line": "#2d8a4d",
            "menubar_bg": "#0a1f14",
            "menubar_selected": "#1a4d2e",
            "button_bg": "#ff2e2e",
            "button_hover": "#ff5252",
            "button_disabled": "#1a4d2e",
            "modified_byte": "#ff2e2e",
            "inserted_byte": "#2eff2e",
            "replaced_byte": "#ffd700"
        },
        "Cyberpunk": {
            "name": "Cyberpunk",
            "background": "#0a0e27",
            "inspector_bg": "#0a0e27",
            "foreground": "#ff2a6d",
            "editor_bg": "#05080f",
            "editor_fg": "#d1f7ff",
            "selection_bg": "#1a1d4a",
            "border": "#05d9e8",
            "grid_line": "#3a3d7a",
            "menubar_bg": "#05080f",
            "menubar_selected": "#1a1d4a",
            "button_bg": "#ff2a6d",
            "button_hover": "#ff5c8d",
            "button_disabled": "#1a1d4a",
            "button_text": "#0a0e27",
            "modified_byte": "#ff2a6d",
            "inserted_byte": "#01cdfe",
            "replaced_byte": "#fffb96"
        },
        "Ocean Night": {
            "name": "Ocean Night",
            "background": "#0a192f",
            "inspector_bg": "#0a192f",
            "foreground": "#8892b0",
            "editor_bg": "#112240",
            "editor_fg": "#ccd6f6",
            "selection_bg": "#233554",
            "border": "#1d3a5f",
            "grid_line": "#3d6a9f",
            "menubar_bg": "#112240",
            "menubar_selected": "#233554",
            "button_bg": "#64ffda",
            "button_hover": "#80ffe6",
            "button_disabled": "#233554",
            "modified_byte": "#f07178",
            "inserted_byte": "#c3e88d",
            "replaced_byte": "#82aaff"
        },
        "Sunset": {
            "name": "Sunset",
            "background": "#1a0b2e",
            "inspector_bg": "#1a0b2e",
            "foreground": "#ff6c95",
            "editor_bg": "#16213e",
            "editor_fg": "#ffcce1",
            "selection_bg": "#3e2c5c",
            "border": "#533483",
            "grid_line": "#6e4c9c",
            "menubar_bg": "#16213e",
            "menubar_selected": "#3e2c5c",
            "button_bg": "#ff6c95",
            "button_hover": "#ff8fab",
            "button_disabled": "#3e2c5c",
            "modified_byte": "#ff6c95",
            "inserted_byte": "#7dd3fc",
            "replaced_byte": "#fbbf24"
        },
        "Tokyo Night": {
            "name": "Tokyo Night",
            "background": "#1a1b26",
            "inspector_bg": "#1a1b26",
            "foreground": "#a9b1d6",
            "editor_bg": "#24283b",
            "editor_fg": "#c0caf5",
            "selection_bg": "#364a82",
            "border": "#414868",
            "grid_line": "#6168a8",
            "menubar_bg": "#1f2335",
            "menubar_selected": "#292e42",
            "button_bg": "#7aa2f7",
            "button_hover": "#89b4fa",
            "button_disabled": "#414868",
            "modified_byte": "#f7768e",
            "inserted_byte": "#9ece6a",
            "replaced_byte": "#7dcfff"
        },
        "Retrobox Dark": {
            "name": "Retrobox Dark",
            "background": "#282828",
            "inspector_bg": "#282828",
            "foreground": "#ebdbb2",
            "editor_bg": "#1d2021",
            "editor_fg": "#ebdbb2",
            "selection_bg": "#504945",
            "border": "#3c3836",
            "grid_line": "#665c54",
            "menubar_bg": "#1d2021",
            "menubar_selected": "#3c3836",
            "button_bg": "#689d6a",
            "button_hover": "#8ec07c",
            "button_disabled": "#504945",
            "modified_byte": "#fb4934",
            "inserted_byte": "#b8bb26",
            "replaced_byte": "#83a598"
        },
        "Blood Moon": {
            "name": "Blood Moon",
            "background": "#000000",
            "inspector_bg": "#000000",
            "foreground": "#ff4444",
            "editor_bg": "#0a0000",
            "editor_fg": "#ff6666",
            "selection_bg": "#330000",
            "border": "#550000",
            "grid_line": "#770000",
            "menubar_bg": "#0a0000",
            "menubar_selected": "#220000",
            "button_bg": "#880000",
            "button_hover": "#bb0000",
            "button_disabled": "#440000",
            "modified_byte": "#ff0000",
            "inserted_byte": "#ff4444",
            "replaced_byte": "#ff8888"
        },
        "Crimson": {
            "name": "Crimson",
            "background": "#1e0811",
            "inspector_bg": "#1e0811",
            "foreground": "#ffb3c1",
            "editor_bg": "#2d0e1a",
            "editor_fg": "#ffd4df",
            "selection_bg": "#4a1525",
            "border": "#6b1f36",
            "grid_line": "#8d2947",
            "menubar_bg": "#2d0e1a",
            "menubar_selected": "#4a1525",
            "button_bg": "#dc143c",
            "button_hover": "#ff1744",
            "button_disabled": "#4a1525",
            "modified_byte": "#ff1744",
            "inserted_byte": "#00e676",
            "replaced_byte": "#ff80ab"
        }
    },
    "Light": {
        "Light": {
            "name": "Light",
            "background": "#ffffff",
            "inspector_bg": "#ffffff",
            "foreground": "#000000",
            "editor_bg": "#f5f5f5",
            "editor_fg": "#000000",
            "selection_bg": "#add6ff",
            "border": "#cccccc",
            "grid_line": "#999999",
            "menubar_bg": "#f0f0f0",
            "menubar_selected": "#e0e0e0",
            "button_bg": "#0078d4",
            "button_hover": "#106ebe",
            "button_disabled": "#cccccc",
            "modified_byte": "#d63031",
            "inserted_byte": "#00b894",
            "replaced_byte": "#0984e3"
        },
        "Pastel Pink": {
            "name": "Pastel Pink",
            "background": "#fef0f5",
            "inspector_bg": "#fef0f5",
            "foreground": "#4a4a4a",
            "editor_bg": "#fff5f9",
            "editor_fg": "#3d3d3d",
            "selection_bg": "#ffc9e0",
            "border": "#ffc9e0",
            "grid_line": "#ff99c8",
            "menubar_bg": "#fff0f7",
            "menubar_selected": "#ffe4f0",
            "button_bg": "#ff99c8",
            "button_hover": "#ffb3d7",
            "button_disabled": "#ffd9eb",
            "modified_byte": "#ff6b9d",
            "inserted_byte": "#69db7c",
            "replaced_byte": "#74c0fc"
        },
        "Pastel Lavender": {
            "name": "Pastel Lavender",
            "background": "#f3f0ff",
            "inspector_bg": "#f3f0ff",
            "foreground": "#3d3755",
            "editor_bg": "#f8f5ff",
            "editor_fg": "#3d3755",
            "selection_bg": "#d0bfff",
            "border": "#d0bfff",
            "grid_line": "#b197fc",
            "menubar_bg": "#ebe4ff",
            "menubar_selected": "#dfd2ff",
            "button_bg": "#b197fc",
            "button_hover": "#c5acff",
            "button_disabled": "#e5dbff",
            "modified_byte": "#ff6b9d",
            "inserted_byte": "#69db7c",
            "replaced_byte": "#9775fa"
        },
        "Pastel Mint": {
            "name": "Pastel Mint",
            "background": "#e6fcf5",
            "inspector_bg": "#e6fcf5",
            "foreground": "#0d3d2e",
            "editor_bg": "#f0fdf7",
            "editor_fg": "#0d3d2e",
            "selection_bg": "#96f2d7",
            "border": "#96f2d7",
            "grid_line": "#63e6be",
            "menubar_bg": "#d3f9ef",
            "menubar_selected": "#b8f5e6",
            "button_bg": "#63e6be",
            "button_hover": "#7efdd4",
            "button_disabled": "#c3fae8",
            "modified_byte": "#ff6b9d",
            "inserted_byte": "#20c997",
            "replaced_byte": "#74c0fc"
        },
        "Retrobox Light": {
            "name": "Retrobox Light",
            "background": "#fbf1c7",
            "inspector_bg": "#fbf1c7",
            "foreground": "#3c3836",
            "editor_bg": "#f9f5d7",
            "editor_fg": "#282828",
            "selection_bg": "#d5c4a1",
            "border": "#bdae93",
            "grid_line": "#a89984",
            "menubar_bg": "#f2e5bc",
            "menubar_selected": "#ebdbb2",
            "button_bg": "#689d6a",
            "button_hover": "#8ec07c",
            "button_disabled": "#d5c4a1",
            "modified_byte": "#cc241d",
            "inserted_byte": "#98971a",
            "replaced_byte": "#458588"
        },
        "Monotone Light": {
            "name": "Monotone Light",
            "background": "#ffffff",
            "inspector_bg": "#ffffff",
            "foreground": "#000000",
            "editor_bg": "#fafafa",
            "editor_fg": "#000000",
            "selection_bg": "#d0d0d0",
            "border": "#c0c0c0",
            "grid_line": "#a0a0a0",
            "menubar_bg": "#f5f5f5",
            "menubar_selected": "#e0e0e0",
            "button_bg": "#404040",
            "button_hover": "#606060",
            "button_disabled": "#d0d0d0",
            "modified_byte": "#ff4040",
            "inserted_byte": "#40b040",
            "replaced_byte": "#4080ff"
        },
        "Solarized Light": {
            "name": "Solarized Light",
            "background": "#fdf6e3",
            "inspector_bg": "#fdf6e3",
            "foreground": "#657b83",
            "editor_bg": "#eee8d5",
            "editor_fg": "#586e75",
            "selection_bg": "#93a1a1",
            "border": "#93a1a1",
            "grid_line": "#93a1a1",
            "menubar_bg": "#eee8d5",
            "menubar_selected": "#d6d0c0",
            "button_bg": "#268bd2",
            "button_hover": "#2aa198",
            "button_disabled": "#93a1a1",
            "modified_byte": "#dc322f",
            "inserted_byte": "#859900",
            "replaced_byte": "#268bd2"
        }
    },
    "Gradient": {
        "Sunset Gradient": {
            "name": "Sunset Gradient",
            "gradient": True,
            "gradient_colors": ["#1a1210", "#221814", "#2a1e18", "#32241c", "#3a2a20"],
            "foreground": "#f5e6d3",
            "editor_bg": "transparent",
            "editor_fg": "#f5e6d3",
            "selection_bg": "#66402860",
            "border": "#8b6b45",
            "grid_line": "#66402880",
            "menubar_bg": "#1a1008",
            "menubar_selected": "#2a1810",
            "button_bg": "#664028",
            "button_hover": "#7a5030",
            "button_disabled": "#3d2418",
            "modified_byte": "#ff8866",
            "inserted_byte": "#88dd88",
            "replaced_byte": "#88ccff"
        },
        "Ocean Gradient": {
            "name": "Ocean Gradient",
            "gradient": True,
            "gradient_colors": ["#0a1218", "#12181e", "#1a1e24", "#22242a", "#2a2a30"],
            "foreground": "#d4dfe8",
            "editor_bg": "transparent",
            "editor_fg": "#d4dfe8",
            "selection_bg": "#37425360",
            "border": "#5a6d80",
            "grid_line": "#37425380",
            "menubar_bg": "#08121a",
            "menubar_selected": "#0d1b2a",
            "button_bg": "#374253",
            "button_hover": "#455060",
            "button_disabled": "#1b2838",
            "modified_byte": "#ff8899",
            "inserted_byte": "#88dd88",
            "replaced_byte": "#88ccff"
        },
        "Forest Gradient": {
            "name": "Forest Gradient",
            "gradient": True,
            "gradient_colors": ["#121816", "#18201c", "#1e2622", "#242c28", "#2a322e"],
            "foreground": "#d8e8d8",
            "editor_bg": "transparent",
            "editor_fg": "#d8e8d8",
            "selection_bg": "#3e513b60",
            "border": "#5a7050",
            "grid_line": "#3e513b80",
            "menubar_bg": "#121812",
            "menubar_selected": "#1a2420",
            "button_bg": "#3e513b",
            "button_hover": "#4a6044",
            "button_disabled": "#263329",
            "modified_byte": "#ff8899",
            "inserted_byte": "#99ee99",
            "replaced_byte": "#88ddff"
        },
        "Midnight Gradient": {
            "name": "Midnight Gradient",
            "gradient": True,
            "gradient_colors": ["#12121e", "#1a1a26", "#22222e", "#2a2a36", "#32323e"],
            "foreground": "#e0e0f0",
            "editor_bg": "transparent",
            "editor_fg": "#e0e0f0",
            "selection_bg": "#38385a60",
            "border": "#5a5a80",
            "grid_line": "#38385a80",
            "menubar_bg": "#12121e",
            "menubar_selected": "#1a1a2e",
            "button_bg": "#38385a",
            "button_hover": "#424268",
            "button_disabled": "#24243d",
            "modified_byte": "#ff99aa",
            "inserted_byte": "#99ee99",
            "replaced_byte": "#99ccff"
        },
        "Lavender Gradient": {
            "name": "Lavender Gradient",
            "gradient": True,
            "gradient_colors": ["#1a1821", "#221e29", "#2a2431", "#322a39", "#3a3041"],
            "foreground": "#e8e5f2",
            "editor_bg": "transparent",
            "editor_fg": "#e8e5f2",
            "selection_bg": "#544f7860",
            "border": "#7a7599",
            "grid_line": "#544f7880",
            "menubar_bg": "#1a1820",
            "menubar_selected": "#2a2533",
            "button_bg": "#544f78",
            "button_hover": "#625d8f",
            "button_disabled": "#38334a",
            "modified_byte": "#ff99bb",
            "inserted_byte": "#99ee99",
            "replaced_byte": "#99ccff"
        },
        "Rose Gradient": {
            "name": "Rose Gradient",
            "gradient": True,
            "gradient_colors": ["#1d181a", "#251e20", "#2d2426", "#352a2c", "#3d3032"],
            "foreground": "#f0e5ea",
            "editor_bg": "transparent",
            "editor_fg": "#f0e5ea",
            "selection_bg": "#5d4e5860",
            "border": "#8a7080",
            "grid_line": "#5d4e5880",
            "menubar_bg": "#1d181c",
            "menubar_selected": "#2d2428",
            "button_bg": "#5d4e58",
            "button_hover": "#6d5c68",
            "button_disabled": "#3d3238",
            "modified_byte": "#ff8899",
            "inserted_byte": "#99dd99",
            "replaced_byte": "#99bbff"
        },
        "Sage Gradient": {
            "name": "Sage Gradient",
            "gradient": True,
            "gradient_colors": ["#18201c", "#202824", "#283028", "#30382c", "#384030"],
            "foreground": "#e5ebe8",
            "editor_bg": "transparent",
            "editor_fg": "#e5ebe8",
            "selection_bg": "#4f5a5260",
            "border": "#708070",
            "grid_line": "#4f5a5280",
            "menubar_bg": "#18201c",
            "menubar_selected": "#252a28",
            "button_bg": "#4f5a52",
            "button_hover": "#5d6a60",
            "button_disabled": "#333a36",
            "modified_byte": "#ff8899",
            "inserted_byte": "#99ee99",
            "replaced_byte": "#88ddff"
        },
        "Blush Gradient": {
            "name": "Blush Gradient",
            "gradient": True,
            "gradient_colors": ["#1d1a1c", "#252022", "#2d2628", "#352c2e", "#3d3234"],
            "foreground": "#f0e8ea",
            "editor_bg": "transparent",
            "editor_fg": "#f0e8ea",
            "selection_bg": "#5d565860",
            "border": "#8a7880",
            "grid_line": "#5d565880",
            "menubar_bg": "#1d1a1c",
            "menubar_selected": "#2d2628",
            "button_bg": "#5d5658",
            "button_hover": "#6d6668",
            "button_disabled": "#3d3638",
            "modified_byte": "#ff8899",
            "inserted_byte": "#99dd99",
            "replaced_byte": "#99bbff"
        },
        "Copper Gradient": {
            "name": "Copper Gradient",
            "gradient": True,
            "gradient_colors": ["#1a1410", "#221a14", "#2a2018", "#32261c", "#3a2c20"],
            "foreground": "#f0e8dc",
            "editor_bg": "transparent",
            "editor_fg": "#f0e8dc",
            "selection_bg": "#5a4a3c60",
            "border": "#8a7860",
            "grid_line": "#5a4a3c80",
            "menubar_bg": "#1a1410",
            "menubar_selected": "#2a2018",
            "button_bg": "#5a4a3c",
            "button_hover": "#6a5848",
            "button_disabled": "#3a2e24",
            "modified_byte": "#ff8866",
            "inserted_byte": "#99dd99",
            "replaced_byte": "#88ccff"
        },
        "Steel Gradient": {
            "name": "Steel Gradient",
            "gradient": True,
            "gradient_colors": ["#14181c", "#1c2024", "#24282c", "#2c3034", "#34383c"],
            "foreground": "#e0e8ec",
            "editor_bg": "transparent",
            "editor_fg": "#e0e8ec",
            "selection_bg": "#48545860",
            "border": "#6a7880",
            "grid_line": "#48545880",
            "menubar_bg": "#14181c",
            "menubar_selected": "#1e2428",
            "button_bg": "#485458",
            "button_hover": "#566468",
            "button_disabled": "#2c3438",
            "modified_byte": "#ff8899",
            "inserted_byte": "#99ee99",
            "replaced_byte": "#88ccff"
        },
        "Sand Gradient": {
            "name": "Sand Gradient",
            "gradient": True,
            "gradient_colors": ["#1a1814", "#22201c", "#2a2824", "#32302c", "#3a3834"],
            "foreground": "#ebe8e0",
            "editor_bg": "transparent",
            "editor_fg": "#ebe8e0",
            "selection_bg": "#5a585060",
            "border": "#8a8870",
            "grid_line": "#5a585080",
            "menubar_bg": "#1a1814",
            "menubar_selected": "#2a2820",
            "button_bg": "#5a5850",
            "button_hover": "#6a6860",
            "button_disabled": "#3a3830",
            "modified_byte": "#ff8866",
            "inserted_byte": "#99dd99",
            "replaced_byte": "#88ccff"
        },
        "Teal Gradient": {
            "name": "Teal Gradient",
            "gradient": True,
            "gradient_colors": ["#121a1c", "#1a2224", "#222a2c", "#2a3234", "#323a3c"],
            "foreground": "#d8e8ea",
            "editor_bg": "transparent",
            "editor_fg": "#d8e8ea",
            "selection_bg": "#3e505860",
            "border": "#5a7880",
            "grid_line": "#3e505880",
            "menubar_bg": "#12181a",
            "menubar_selected": "#1a2628",
            "button_bg": "#3e5058",
            "button_hover": "#4a5e68",
            "button_disabled": "#263438",
            "modified_byte": "#ff8899",
            "inserted_byte": "#99ee99",
            "replaced_byte": "#88ffff"
        },
        "Pastel Sky Gradient": {
            "name": "Pastel Sky Gradient",
            "gradient": True,
            "gradient_colors": ["#e8f4f8", "#dcedf5", "#d0e6f2", "#c4dfef", "#b8d8ec"],
            "inspector_bg": "#e8f4f8",
            "foreground": "#2a4a5c",
            "editor_bg": "transparent",
            "editor_fg": "#2a4a5c",
            "selection_bg": "#7aa0c860",
            "border": "#6a90b8",
            "grid_line": "#7aa0c880",
            "menubar_bg": "#dcedf5",
            "menubar_selected": "#c4dfef",
            "button_bg": "#5a8fc0",
            "button_hover": "#4a7fb0",
            "button_disabled": "#9abcd8",
            "modified_byte": "#d9534f",
            "inserted_byte": "#5cb85c",
            "replaced_byte": "#5bc0de"
        },
        "Peach Cream Gradient": {
            "name": "Peach Cream Gradient",
            "gradient": True,
            "gradient_colors": ["#fff5f0", "#ffebe0", "#ffe1d0", "#ffd7c0", "#ffcdb0"],
            "inspector_bg": "#fff5f0",
            "foreground": "#5c3a2a",
            "editor_bg": "transparent",
            "editor_fg": "#5c3a2a",
            "selection_bg": "#c89a7060",
            "border": "#b88a60",
            "grid_line": "#c89a7080",
            "menubar_bg": "#ffebe0",
            "menubar_selected": "#ffd7c0",
            "button_bg": "#d88a50",
            "button_hover": "#c87a40",
            "button_disabled": "#e8ba90",
            "modified_byte": "#d9534f",
            "inserted_byte": "#5cb85c",
            "replaced_byte": "#5bc0de"
        },
        "Mint Breeze Gradient": {
            "name": "Mint Breeze Gradient",
            "gradient": True,
            "gradient_colors": ["#f0fff8", "#e0fef0", "#d0fde8", "#c0fce0", "#b0fbd8"],
            "inspector_bg": "#f0fff8",
            "foreground": "#2a5c3a",
            "editor_bg": "transparent",
            "editor_fg": "#2a5c3a",
            "selection_bg": "#70c89060",
            "border": "#60b880",
            "grid_line": "#70c89080",
            "menubar_bg": "#e0fef0",
            "menubar_selected": "#c0fce0",
            "button_bg": "#50d880",
            "button_hover": "#40c870",
            "button_disabled": "#90e8b0",
            "modified_byte": "#d9534f",
            "inserted_byte": "#5cb85c",
            "replaced_byte": "#5bc0de"
        },
        "Lavender Dawn Gradient": {
            "name": "Lavender Dawn Gradient",
            "gradient": True,
            "gradient_colors": ["#f8f0ff", "#f0e0ff", "#e8d0ff", "#e0c0ff", "#d8b0ff"],
            "inspector_bg": "#f8f0ff",
            "foreground": "#4a2a5c",
            "editor_bg": "transparent",
            "editor_fg": "#4a2a5c",
            "selection_bg": "#a870c860",
            "border": "#9860b8",
            "grid_line": "#a870c880",
            "menubar_bg": "#f0e0ff",
            "menubar_selected": "#e0c0ff",
            "button_bg": "#9050d8",
            "button_hover": "#8040c8",
            "button_disabled": "#c090e8",
            "modified_byte": "#d9534f",
            "inserted_byte": "#5cb85c",
            "replaced_byte": "#5bc0de"
        },
        "Sunrise Gradient": {
            "name": "Sunrise Gradient",
            "gradient": True,
            "gradient_colors": ["#fff8f0", "#fff0e0", "#ffe8d0", "#ffdfc0", "#ffd6b0"],
            "inspector_bg": "#fff8f0",
            "foreground": "#5c3a1a",
            "editor_bg": "transparent",
            "editor_fg": "#5c3a1a",
            "selection_bg": "#c8a87060",
            "border": "#b89860",
            "grid_line": "#c8a87080",
            "menubar_bg": "#fff0e0",
            "menubar_selected": "#ffdfc0",
            "button_bg": "#d89050",
            "button_hover": "#c88040",
            "button_disabled": "#e8c090",
            "modified_byte": "#d9534f",
            "inserted_byte": "#5cb85c",
            "replaced_byte": "#5bc0de"
        },
        "Blossom Gradient": {
            "name": "Blossom Gradient",
            "gradient": True,
            "gradient_colors": ["#fff0f8", "#ffe0f0", "#ffd0e8", "#ffc0e0", "#ffb0d8"],
            "inspector_bg": "#fff0f8",
            "foreground": "#5c2a4a",
            "editor_bg": "transparent",
            "editor_fg": "#5c2a4a",
            "selection_bg": "#c870a860",
            "border": "#b86098",
            "grid_line": "#c870a880",
            "menubar_bg": "#ffe0f0",
            "menubar_selected": "#ffc0e0",
            "button_bg": "#d85090",
            "button_hover": "#c84080",
            "button_disabled": "#e890c0",
            "modified_byte": "#d9534f",
            "inserted_byte": "#5cb85c",
            "replaced_byte": "#5bc0de"
        }
    }
}


# Custom themes configuration file
CUSTOM_THEMES_FILE = Path(migrated_storage_path(
    "custom_themes.json",
    [Path.home() / ".hex_editor_custom_themes.json"]
))


def load_custom_themes():
    """Load custom themes from file"""
    if CUSTOM_THEMES_FILE.exists():
        try:
            with open(CUSTOM_THEMES_FILE, 'r') as f:
                return json.load(f)
        except Exception:
            return {}
    return {}


def save_custom_themes(custom_themes):
    """Save custom themes to file"""
    try:
        with open(CUSTOM_THEMES_FILE, 'w') as f:
            json.dump(custom_themes, f, indent=2)
        return True
    except Exception:
            return False


def with_theme_defaults(theme):
    """Return a copy with newer theme fields filled for older/custom themes."""
    normalized = dict(theme or {})
    normalized.setdefault("byte_hover", normalized.get("selection_bg", normalized.get("button_bg", "#404040")))
    return normalized


def _solid_theme_value(value):
    if value is None:
        return ""
    value = str(value).strip()
    if not value or value.lower() == "transparent":
        return ""
    return value


def get_theme_surface_colors(theme_or_name):
    """Return solid surface colors for dialogs and controls, even for gradient themes."""
    theme = resolve_theme(theme_or_name) if isinstance(theme_or_name, str) else with_theme_defaults(theme_or_name)
    gradient_base = ""
    gradient_colors = theme.get("gradient_colors") or []
    if gradient_colors:
        gradient_base = _solid_theme_value(gradient_colors[0])

    surface = (
        _solid_theme_value(theme.get("inspector_bg")) or
        _solid_theme_value(theme.get("background")) or
        _solid_theme_value(theme.get("menubar_bg")) or
        gradient_base or
        "#1f1f1f"
    )
    control = (
        _solid_theme_value(theme.get("editor_bg")) or
        _solid_theme_value(theme.get("inspector_bg")) or
        _solid_theme_value(theme.get("menubar_bg")) or
        surface
    )
    return {
        "surface": surface,
        "control": control,
        "text": theme.get("foreground", theme.get("editor_fg", "#ffffff")),
        "control_text": theme.get("editor_fg", theme.get("foreground", "#ffffff")),
    }


def get_builtin_themes_flat():
    """Get built-in themes flattened without custom themes."""
    themes = {}
    for category, category_themes in THEMES.items():
        for name, theme in category_themes.items():
            themes[name] = with_theme_defaults(theme)
    return themes


def resolve_theme(theme_name):
    """Resolve built-in/custom theme ids without letting duplicate names shadow built-ins."""
    theme_name = theme_name or "Dark"
    builtins = get_builtin_themes_flat()
    custom_themes = load_custom_themes()

    if isinstance(theme_name, str) and theme_name.startswith("custom:"):
        custom_name = theme_name.split(":", 1)[1]
        return with_theme_defaults(custom_themes.get(custom_name, builtins["Dark"]))
    if isinstance(theme_name, str) and theme_name.startswith("builtin:"):
        builtin_name = theme_name.split(":", 1)[1]
        return with_theme_defaults(builtins.get(builtin_name, builtins["Dark"]))

    if theme_name in builtins:
        return with_theme_defaults(builtins[theme_name])
    if theme_name in custom_themes:
        return with_theme_defaults(custom_themes[theme_name])
    return with_theme_defaults(builtins["Dark"])


def get_all_themes():
    """Get all themes including custom ones, flattened from categories"""
    all_themes = get_builtin_themes_flat()

    custom_themes = load_custom_themes()
    for name, theme in custom_themes.items():
        if name not in all_themes:
            all_themes[name] = with_theme_defaults(theme)

    return all_themes


def get_theme_categories():
    """Get themes organized by category"""
    categories = {}

    # Add built-in categories
    for category, themes in THEMES.items():
        categories[category] = themes

    # Add custom themes as a separate category
    custom_themes = load_custom_themes()
    if custom_themes:
        categories["Custom"] = custom_themes

    return categories


def get_theme_stylesheet(theme_name):
    """Generate Qt stylesheet for a given theme"""
    theme = resolve_theme(theme_name)
    surfaces = get_theme_surface_colors(theme)
    dialog_bg = surfaces["surface"]
    control_bg = surfaces["control"]
    dialog_fg = surfaces["text"]
    control_fg = surfaces["control_text"]

    # Handle full-editor visual backgrounds (gradient or app background image)
    if theme.get("gradient", False) or theme.get("app_bg_image", ""):
        return f"""
            QMainWindow, QWidget {{
                background-color: transparent;
                color: {theme['foreground']};
            }}
            QDialog, QMessageBox {{
                background-color: {dialog_bg};
                color: {dialog_fg};
            }}
            QDialog QWidget, QMessageBox QWidget {{
                background-color: {dialog_bg};
                color: {dialog_fg};
            }}
            QTextEdit {{
                background-color: transparent;
                color: {theme['editor_fg']};
                border: none;
                selection-background-color: {theme['selection_bg']};
            }}
            QMenuBar {{
                background-color: {theme['menubar_bg']};
                color: {theme['foreground']};
                border-bottom: 1px solid {theme['border']};
            }}
            QMenuBar::item:selected {{
                background-color: {theme['menubar_selected']};
            }}
            QMenu {{
                background-color: {theme['menubar_bg']};
                color: {theme['foreground']};
                border: 1px solid {theme['border']};
            }}
            QMenu::item:selected {{
                background-color: {theme['menubar_selected']};
            }}
            QTabWidget::pane {{
                border: none;
            }}
            QTabBar::tab {{
                background-color: {theme['menubar_bg']};
                color: {theme['foreground']};
                padding: 8px 16px;
                border: none;
                border-bottom: 2px solid transparent;
            }}
            QTabBar::tab:selected {{
                border-bottom: 2px solid {theme['button_bg']};
            }}
            QLabel {{
                color: {theme['foreground']};
            }}
            QPushButton {{
                background-color: {theme['button_bg']};
                color: {theme.get('button_text', 'white')};
                border: none;
                padding: 6px 16px;
                border-radius: 3px;
            }}
            QPushButton:hover {{
                background-color: {theme['button_hover']};
            }}
            QPushButton:disabled {{
                background-color: {theme['button_disabled']};
                color: #666;
            }}
            QDialog QTextEdit, QDialog QPlainTextEdit, QDialog QListWidget,
            QDialog QTreeWidget, QDialog QTableWidget, QMessageBox QLabel {{
                background-color: {control_bg};
                color: {control_fg};
                border: 1px solid {theme['border']};
                selection-background-color: {theme['selection_bg']};
            }}
            QLineEdit, QSpinBox, QComboBox, QTextEdit#notes {{
                background-color: {control_bg};
                color: {control_fg};
                border: 1px solid {theme['border']};
                padding: 4px;
            }}
            QComboBox::drop-down {{
                border: none;
                background-color: {theme['button_bg']};
                width: 20px;
            }}
            QComboBox::down-arrow {{
                image: none;
                border-left: 4px solid transparent;
                border-right: 4px solid transparent;
                border-top: 6px solid {theme['foreground']};
                width: 0px;
                height: 0px;
                margin-right: 6px;
            }}
            QComboBox QAbstractItemView {{
                background-color: {control_bg};
                color: {control_fg};
                border: 1px solid {theme['border']};
                selection-background-color: {theme['button_bg']};
                selection-color: {theme.get('button_text', 'white')};
            }}
            QScrollBar:vertical, QScrollBar:horizontal {{
                background-color: {theme['menubar_bg']};
                border: none;
            }}
            QScrollBar::handle:vertical, QScrollBar::handle:horizontal {{
                background-color: {theme['border']};
                border-radius: 4px;
            }}
            QScrollBar::handle:vertical:hover, QScrollBar::handle:horizontal:hover {{
                background-color: {theme['button_bg']};
            }}
            QStatusBar {{
                background-color: {theme['menubar_bg']};
                color: {theme['foreground']};
                border-top: 1px solid {theme['border']};
            }}
            QStatusBar QLabel {{
                color: {theme['foreground']};
            }}
        """

    # Standard theme stylesheet
    return f"""
        QMainWindow, QWidget {{
            background-color: {theme['background']};
            color: {theme['foreground']};
        }}
        QTextEdit {{
            background-color: {theme['editor_bg']};
            color: {theme['editor_fg']};
            border: none;
            selection-background-color: {theme['selection_bg']};
        }}
        QMenuBar {{
            background-color: {theme['menubar_bg']};
            color: {theme['foreground']};
            border-bottom: 1px solid {theme['border']};
        }}
        QMenuBar::item:selected {{
            background-color: {theme['menubar_selected']};
        }}
        QMenu {{
            background-color: {theme['menubar_bg']};
            color: {theme['foreground']};
            border: 1px solid {theme['border']};
        }}
        QMenu::item:selected {{
            background-color: {theme['menubar_selected']};
        }}
        QTabWidget::pane {{
            border: none;
        }}
        QTabBar::tab {{
            background-color: {theme['editor_bg']};
            color: {theme['foreground']};
            padding: 8px 16px;
            border: none;
            border-bottom: 2px solid transparent;
        }}
        QTabBar::tab:selected {{
            border-bottom: 2px solid {theme['button_bg']};
        }}
        QLabel {{
            color: {theme['foreground']};
        }}
        QPushButton {{
            background-color: {theme['button_bg']};
            color: {theme.get('button_text', 'white')};
            border: none;
            padding: 6px 16px;
            border-radius: 3px;
        }}
        QPushButton:hover {{
            background-color: {theme['button_hover']};
        }}
        QPushButton:disabled {{
            background-color: {theme['button_disabled']};
            color: #666;
        }}
        QLineEdit, QSpinBox, QComboBox, QTextEdit#notes {{
            background-color: {theme['editor_bg']};
            color: {theme['editor_fg']};
            border: 1px solid {theme['border']};
            padding: 4px;
        }}
        QScrollBar:vertical, QScrollBar:horizontal {{
            background-color: {theme['editor_bg']};
            border: none;
        }}
        QScrollBar::handle:vertical, QScrollBar::handle:horizontal {{
            background-color: {theme['border']};
            border-radius: 4px;
        }}
        QScrollBar::handle:vertical:hover, QScrollBar::handle:horizontal:hover {{
            background-color: {theme['button_bg']};
        }}
        QStatusBar {{
            background-color: {theme['background']};
            color: {theme['foreground']};
            border-top: 1px solid {theme['border']};
        }}
        QStatusBar QLabel {{
            color: {theme['foreground']};
        }}
    """


def get_theme_colors(theme_name):
    """Get color values for a theme"""
    return resolve_theme(theme_name)


def get_image_background_style(image_path, tint_color, tint_opacity, fit_mode='fill'):
    """
    Generate CSS style for image background with optional tinting.

    Args:
        image_path: Path to the background image file
        tint_color: Hex color for tinting (e.g., '#000000')
        tint_opacity: Opacity of the tint overlay (0.0 to 1.0)

    Returns:
        CSS style string for background with image and tint overlay
    """
    if not image_path:
        return ""

    # Convert file path to an encoded file URL so spaces/special chars still load as a pixmap.
    from urllib.parse import quote
    url_path = quote(os.path.abspath(image_path).replace('\\', '/'), safe='/:')
    bg_size = {
        'fit': 'contain',
        'stretch': '100% 100%',
        'fill': 'cover'
    }.get((fit_mode or 'fill').lower(), 'cover')

    if tint_opacity > 0:
        # Parse hex color to RGB
        tint_color = tint_color.lstrip('#')
        r = int(tint_color[0:2], 16)
        g = int(tint_color[2:4], 16)
        b = int(tint_color[4:6], 16)

        # Create a style with both image and color overlay
        return f"""
            background-image:
                linear-gradient(rgba({r}, {g}, {b}, {tint_opacity}), rgba({r}, {g}, {b}, {tint_opacity})),
                url("file:///{url_path}");
            background-size: {bg_size};
            background-position: center;
            background-repeat: no-repeat;
        """
    else:
        # Just the image without tint
        return f"""
            background-image: url("file:///{url_path}");
            background-size: {bg_size};
            background-position: center;
            background-repeat: no-repeat;
        """


def get_theme_image_backgrounds(theme_name):
    """
    Get image background information for a theme.

    Returns:
        dict with keys:
            - hex_bytes_style: CSS style for hex bytes area background
            - offset_ascii_style: CSS style for offset/ASCII/surrounding area background
            - inspector_style: CSS style for data inspector background
    """
    theme = resolve_theme(theme_name)

    return {
        'app_style': get_image_background_style(
            theme.get('app_bg_image', ''),
            theme.get('app_bg_tint_color', '#000000'),
            theme.get('app_bg_tint_opacity', 0),
            theme.get('app_bg_fit', 'fill')
        ),
        'hex_bytes_style': get_image_background_style(
            theme.get('hex_bytes_bg_image', ''),
            theme.get('hex_bytes_tint_color', '#000000'),
            theme.get('hex_bytes_tint_opacity', 0),
            theme.get('hex_bytes_fit', 'fill')
        ),
        'offset_ascii_style': get_image_background_style(
            theme.get('offset_ascii_bg_image', ''),
            theme.get('offset_ascii_tint_color', '#000000'),
            theme.get('offset_ascii_tint_opacity', 0),
            theme.get('offset_ascii_fit', 'fill')
        )
    }


# Theme parameter labels for user-friendly display
THEME_PARAM_LABELS = {
    "background": "Main Background",
    "foreground": "Main Text Color",
    "inspector_bg": "Inspector Background",
    "editor_bg": "Editor Background",
    "editor_fg": "Editor Text Color",
    "selection_bg": "Selection Background",
    "byte_hover": "Byte Hover",
    "border": "Border Color",
    "grid_line": "Grid/Separator Lines",
    "menubar_bg": "Menu Bar Background",
    "menubar_selected": "Menu Bar Selected",
    "button_bg": "Button Background",
    "button_hover": "Button Hover",
    "button_disabled": "Button Disabled",
    "modified_byte": "Modified Byte Highlight",
    "inserted_byte": "Inserted Byte Highlight",
    "replaced_byte": "Replaced Byte Highlight"
}


if PYQT_AVAILABLE:
    IMAGE_FILTER = "Images (*.png *.jpg *.jpeg *.bmp *.gif *.webp);;All Files (*)"
    IMAGE_EXTENSIONS = {'.png', '.jpg', '.jpeg', '.bmp', '.gif', '.webp'}


    def apply_native_titlebar_theme(window, dark=True):
        """Apply Windows native dark/light titlebar flag for standalone theme dialogs."""
        if sys.platform != "win32" or window is None:
            return
        try:
            dark_enabled = ctypes.c_int(1 if dark else 0)
            hwnd = int(window.winId())
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


    class ColorButton(QPushButton):
        """A button that displays and allows selecting a color"""
        colorChanged = pyqtSignal(str)

        def __init__(self, color="#000000", parent=None):
            super().__init__(parent)
            self.color = color
            self.setObjectName("themeColorButton")
            self.setFixedSize(14, 14)
            self.clicked.connect(self.choose_color)
            self.update_color()

        def update_color(self):
            """Update button style to show current color"""
            self.setStyleSheet(f"""
                QPushButton#themeColorButton {{
                    background-color: {self.color};
                    border: 1px solid #999;
                    border-radius: 3px;
                    min-width: 14px;
                    max-width: 14px;
                    min-height: 14px;
                    max-height: 14px;
                    padding: 0px;
                }}
                QPushButton#themeColorButton:hover {{
                    border: 1px solid #fff;
                }}
            """)

        def choose_color(self):
            """Open color picker dialog"""
            owner = self.window()
            parent_editor = getattr(owner, "parent_editor", None)
            if parent_editor and hasattr(parent_editor, "get_theme_color_dialog"):
                dialog = parent_editor.get_theme_color_dialog(QColor(self.color), self)
            else:
                dialog = QColorDialog(QColor(self.color), self)
                dialog.setOption(QColorDialog.DontUseNativeDialog, False)
            dialog.setWindowTitle("Select Color")
            dark = True
            if parent_editor and hasattr(parent_editor, "system_uses_dark_titlebar"):
                dark = parent_editor.system_uses_dark_titlebar()
            QTimer.singleShot(0, lambda: apply_native_titlebar_theme(dialog, dark))
            if dialog.exec_() == QDialog.Accepted:
                color = dialog.selectedColor()
                self.color = color.name()
                self.update_color()
                self.colorChanged.emit(self.color)

        def set_color(self, color):
            """Set color programmatically"""
            self.color = color
            self.update_color()


    class CustomThemeEditor(QDialog):
        """Dialog for creating and editing custom themes with live preview and gradient support"""
        themeChanged = pyqtSignal(dict)

        def __init__(self, parent=None, base_theme=None):
            super().__init__(parent)
            self.setWindowTitle("Custom Theme Editor")
            self.setMinimumSize(640, 500)
            self.resize(700, 540)
            self.parent_editor = parent
            self.setFont(parent.font() if parent and hasattr(parent, 'font') else self.font())
            self.setAcceptDrops(True)
            self._loading_theme = False
            self.original_custom_name = base_theme.split(":", 1)[1] if isinstance(base_theme, str) and base_theme.startswith("custom:") else None
            self._temporary_live_storage = self.original_custom_name is None
            self._live_storage_name = self.original_custom_name or "__RxD Live Preview__"

            # Apply parent's theme stylesheet if available - use Light or Dark based on brightness
            if parent and hasattr(parent, 'current_theme'):
                if parent.is_dark_theme():
                    base_theme_name = "Dark"
                else:
                    base_theme_name = "Light"
                style = get_theme_stylesheet(base_theme_name)
                self.setStyleSheet(style + self.compact_editor_stylesheet(get_theme_colors(base_theme_name)))

            # Start with a base theme or Dark theme
            if base_theme:
                self.current_theme = resolve_theme(base_theme).copy()
            else:
                self.current_theme = THEMES["Dark"]["Dark"].copy()

            # Ensure inspector_bg exists (default to background if missing)
            if 'inspector_bg' not in self.current_theme:
                self.current_theme['inspector_bg'] = self.current_theme.get('background', '#1e1e1e')

            self.color_buttons = {}
            self.gradient_enabled = False
            self.gradient_colors = []
            self.background_row = None

            # Image background properties
            self.app_bg_image_path = self.current_theme.get('app_bg_image', '')
            self.app_bg_tint_color = self.current_theme.get('app_bg_tint_color', '#000000')
            self.app_bg_tint_opacity = self.current_theme.get('app_bg_tint_opacity', 0)
            self.app_bg_fit = self.current_theme.get('app_bg_fit', 'fill')
            self.app_bg_gif_quality = self.current_theme.get('app_bg_gif_quality', 'optimized')

            self.hex_bytes_image_path = self.current_theme.get('hex_bytes_bg_image', '')
            self.hex_bytes_tint_color = self.current_theme.get('hex_bytes_tint_color', '#000000')
            self.hex_bytes_tint_opacity = self.current_theme.get('hex_bytes_tint_opacity', 0)
            self.hex_bytes_fit = self.current_theme.get('hex_bytes_fit', 'fill')
            self.hex_bytes_gif_quality = self.current_theme.get('hex_bytes_gif_quality', 'optimized')

            self.offset_ascii_image_path = self.current_theme.get('offset_ascii_bg_image', '')
            self.offset_ascii_tint_color = self.current_theme.get('offset_ascii_tint_color', '#000000')
            self.offset_ascii_tint_opacity = self.current_theme.get('offset_ascii_tint_opacity', 0)
            self.offset_ascii_fit = self.current_theme.get('offset_ascii_fit', 'fill')
            self.offset_ascii_gif_quality = self.current_theme.get('offset_ascii_gif_quality', 'optimized')

            self.setup_ui()

        def showEvent(self, event):
            super().showEvent(event)
            if self.parent_editor and hasattr(self.parent_editor, "system_uses_dark_titlebar"):
                dark = self.parent_editor.system_uses_dark_titlebar()
            elif self.parent_editor and hasattr(self.parent_editor, "is_dark_theme"):
                dark = self.parent_editor.is_dark_theme()
            else:
                dark = True
            apply_native_titlebar_theme(self, dark)
            QTimer.singleShot(0, self.apply_theme_live)

        def compact_editor_stylesheet(self, theme):
            surfaces = get_theme_surface_colors(theme)
            button_text = theme.get('button_text', theme.get('foreground', '#ffffff'))
            dialog_bg = surfaces["surface"]
            panel_bg = surfaces["control"]
            fg = surfaces["text"]
            editor_fg = surfaces["control_text"]
            border = theme.get('border', '#555555')
            return f"""
                QDialog {{
                    background-color: {dialog_bg};
                    color: {fg};
                    font-family: Arial;
                    font-size: 9pt;
                }}
                QWidget {{
                    background-color: {dialog_bg};
                    color: {fg};
                }}
                QLabel {{
                    background-color: transparent;
                    color: {fg};
                    font-size: 9pt;
                }}
                QPushButton {{
                    padding: 3px 8px;
                    min-height: 20px;
                    font-size: 9pt;
                }}
                QPushButton#themeColorButton {{
                    min-width: 14px;
                    max-width: 14px;
                    min-height: 14px;
                    max-height: 14px;
                    padding: 0px;
                }}
                QLineEdit, QComboBox {{
                    background-color: {panel_bg};
                    color: {editor_fg};
                    border: 1px solid {border};
                    padding: 2px 4px;
                    min-height: 20px;
                    font-size: 9pt;
                }}
                QComboBox QAbstractItemView {{
                    background-color: {panel_bg};
                    color: {editor_fg};
                    border: 1px solid {border};
                }}
                QSlider::groove:horizontal {{
                    height: 4px;
                }}
                QSlider::handle:horizontal {{
                    width: 10px;
                    margin: -4px 0px;
                }}
                QWidget#themePanel {{
                    background-color: {panel_bg};
                }}
            """

        def setup_ui(self):
            """Setup the user interface"""
            main_layout = QVBoxLayout()
            main_layout.setSpacing(5)
            main_layout.setContentsMargins(8, 8, 8, 8)

            # Header section - compact
            header_layout = QHBoxLayout()
            header_layout.addWidget(QLabel("Theme Name:"))
            self.theme_name_input = QLineEdit()
            self.theme_name_input.setPlaceholderText("Enter custom theme name")
            self.theme_name_input.setText(self.current_theme.get("name", "Custom Theme"))
            self.theme_name_input.setMinimumWidth(150)
            # Connect to update theme name in real-time
            self.theme_name_input.textChanged.connect(self.on_theme_name_changed)
            header_layout.addWidget(self.theme_name_input)

            header_layout.addSpacing(20)
            header_layout.addWidget(QLabel("Start from:"))
            self.base_theme_combo = QComboBox()
            all_theme_names = sorted(get_all_themes().keys())
            self.base_theme_combo.addItems(all_theme_names)
            if self.current_theme.get("name") in all_theme_names:
                self.base_theme_combo.setCurrentText(self.current_theme.get("name"))
            self.base_theme_combo.currentTextChanged.connect(self.load_base_theme)
            self.base_theme_combo.setMinimumWidth(120)
            header_layout.addWidget(self.base_theme_combo)
            header_layout.addStretch()
            main_layout.addLayout(header_layout)

            # Main content area with side-by-side layout
            content_layout = QHBoxLayout()
            content_layout.setSpacing(8)

            # LEFT PANEL - Background Options
            left_panel = QWidget()
            left_panel.setObjectName("themePanel")
            left_layout = QVBoxLayout(left_panel)
            left_layout.setContentsMargins(0, 0, 0, 0)
            left_layout.setSpacing(5)

            # Main background type selection - compact
            bg_type_layout = QHBoxLayout()
            bg_type_layout.addWidget(QLabel("Background:"))
            self.main_bg_combo = QComboBox()
            self.main_bg_combo.addItems(["Color", "Gradient", "Image"])

            # Determine current type
            if self.current_theme.get("gradient", False):
                self.main_bg_combo.setCurrentText("Gradient")
            elif self.app_bg_image_path:
                self.main_bg_combo.setCurrentText("Image")
            else:
                self.main_bg_combo.setCurrentText("Color")

            self.main_bg_combo.currentTextChanged.connect(self.on_main_bg_type_changed)
            bg_type_layout.addWidget(self.main_bg_combo)
            left_layout.addLayout(bg_type_layout)

            # Gradient colors section
            self.gradient_widget = QWidget()
            gradient_layout = QVBoxLayout(self.gradient_widget)
            gradient_layout.setContentsMargins(0, 3, 0, 3)
            gradient_layout.setSpacing(4)

            self.gradient_colors_layout = QHBoxLayout()
            self.gradient_color_buttons = []

            default_gradient = ["#ff6b35", "#ff8c42", "#ffa94d", "#ffc75f", "#f9c74f"]
            for i in range(5):
                initial_color = default_gradient[i]
                color_btn = ColorButton(initial_color)
                color_btn.colorChanged.connect(lambda c, idx=i: self.update_gradient_color(idx, c))
                self.gradient_color_buttons.append(color_btn)
                self.gradient_colors_layout.addWidget(color_btn)

            gradient_layout.addLayout(self.gradient_colors_layout)
            left_layout.addWidget(self.gradient_widget)

            # Whole-editor background image section
            self.app_image_widget = QWidget()
            app_image_layout = QVBoxLayout(self.app_image_widget)
            app_image_layout.setContentsMargins(0, 3, 0, 3)
            app_image_layout.setSpacing(4)

            app_btn_layout = QHBoxLayout()
            app_bg_browse_btn = QPushButton("Editor Background...")
            app_bg_browse_btn.clicked.connect(self.browse_app_bg_image)
            app_btn_layout.addWidget(app_bg_browse_btn)
            app_bg_clear_btn = QPushButton("Clear")
            app_bg_clear_btn.clicked.connect(self.clear_app_bg_image)
            app_btn_layout.addWidget(app_bg_clear_btn)
            app_image_layout.addLayout(app_btn_layout)

            self.app_bg_image_label = QLabel(os.path.basename(self.app_bg_image_path) if self.app_bg_image_path else "No editor background image")
            self.app_bg_image_label.setStyleSheet("padding: 2px; font-size: 8pt; color: #888;")
            self.app_bg_image_label.setWordWrap(True)
            self.app_bg_image_label.setMaximumHeight(30)
            app_image_layout.addWidget(self.app_bg_image_label)

            app_tint_layout = QHBoxLayout()
            app_tint_layout.addWidget(QLabel("Tint:"))
            self.app_bg_tint_btn = ColorButton(self.app_bg_tint_color)
            self.app_bg_tint_btn.colorChanged.connect(self.on_app_bg_tint_changed)
            app_tint_layout.addWidget(self.app_bg_tint_btn)
            app_tint_layout.addWidget(QLabel("Opacity:"))
            self.app_bg_opacity_slider = QSlider(Qt.Horizontal)
            self.app_bg_opacity_slider.setRange(0, 100)
            self.app_bg_opacity_slider.setValue(int(self.app_bg_tint_opacity * 100))
            self.app_bg_opacity_slider.valueChanged.connect(self.on_app_bg_opacity_changed)
            app_tint_layout.addWidget(self.app_bg_opacity_slider, 1)
            self.app_bg_opacity_label = QLabel(f"{int(self.app_bg_tint_opacity * 100)}%")
            self.app_bg_opacity_label.setMinimumWidth(30)
            app_tint_layout.addWidget(self.app_bg_opacity_label)
            app_image_layout.addLayout(app_tint_layout)
            app_fit_layout = QHBoxLayout()
            app_fit_layout.addWidget(QLabel("Size:"))
            self.app_bg_fit_combo = QComboBox()
            self.app_bg_fit_combo.addItems(["Fill", "Fit", "Stretch"])
            self.app_bg_fit_combo.setCurrentText(self.app_bg_fit.capitalize())
            self.app_bg_fit_combo.currentTextChanged.connect(lambda text: self.on_fit_mode_changed('app_bg_fit', text))
            app_fit_layout.addWidget(self.app_bg_fit_combo)
            app_fit_layout.addWidget(QLabel("Quality:"))
            self.app_bg_gif_quality_combo = QComboBox()
            self.app_bg_gif_quality_combo.addItems(["Optimized", "Smooth", "Full"])
            self.app_bg_gif_quality_combo.setCurrentText(self.app_bg_gif_quality.capitalize())
            self.app_bg_gif_quality_combo.currentTextChanged.connect(lambda text: self.on_gif_quality_changed('app_bg_gif_quality', text))
            app_fit_layout.addWidget(self.app_bg_gif_quality_combo)
            app_fit_layout.addStretch()
            app_image_layout.addLayout(app_fit_layout)
            left_layout.addWidget(self.app_image_widget)

            # Hex display image section - always visible
            hex_image_label = QLabel("Hex Display Image:")
            hex_image_label.setStyleSheet("font-weight: bold; font-size: 9pt; margin-top: 3px;")
            left_layout.addWidget(hex_image_label)
            self.image_widget = QWidget()
            image_layout = QVBoxLayout(self.image_widget)
            image_layout.setContentsMargins(0, 3, 0, 3)
            image_layout.setSpacing(4)

            img_btn_layout = QHBoxLayout()
            hex_bytes_browse_btn = QPushButton("Select Image...")
            hex_bytes_browse_btn.clicked.connect(self.browse_hex_bytes_image)
            img_btn_layout.addWidget(hex_bytes_browse_btn)
            hex_bytes_clear_btn = QPushButton("Clear")
            hex_bytes_clear_btn.clicked.connect(self.clear_hex_bytes_image)
            img_btn_layout.addWidget(hex_bytes_clear_btn)
            image_layout.addLayout(img_btn_layout)

            self.hex_bytes_image_label = QLabel("No image selected")
            self.hex_bytes_image_label.setStyleSheet("padding: 4px; border: 1px solid #555; font-size: 10px;")
            self.hex_bytes_image_label.setWordWrap(True)
            self.hex_bytes_image_label.setMaximumHeight(35)
            image_layout.addWidget(self.hex_bytes_image_label)

            tint_layout = QHBoxLayout()
            tint_layout.addWidget(QLabel("Tint:"))
            self.hex_bytes_tint_btn = ColorButton(self.hex_bytes_tint_color)
            self.hex_bytes_tint_btn.colorChanged.connect(self.on_hex_bytes_tint_changed)
            tint_layout.addWidget(self.hex_bytes_tint_btn)
            tint_layout.addWidget(QLabel("Opacity:"))
            self.hex_bytes_opacity_slider = QSlider(Qt.Horizontal)
            self.hex_bytes_opacity_slider.setRange(0, 100)
            self.hex_bytes_opacity_slider.setValue(int(self.hex_bytes_tint_opacity * 100))
            self.hex_bytes_opacity_slider.valueChanged.connect(self.on_hex_bytes_opacity_changed)
            tint_layout.addWidget(self.hex_bytes_opacity_slider, 1)
            self.hex_bytes_opacity_label = QLabel(f"{int(self.hex_bytes_tint_opacity * 100)}%")
            self.hex_bytes_opacity_label.setMinimumWidth(35)
            tint_layout.addWidget(self.hex_bytes_opacity_label)
            image_layout.addLayout(tint_layout)
            hex_fit_layout = QHBoxLayout()
            hex_fit_layout.addWidget(QLabel("Size:"))
            self.hex_bytes_fit_combo = QComboBox()
            self.hex_bytes_fit_combo.addItems(["Fill", "Fit", "Stretch"])
            self.hex_bytes_fit_combo.setCurrentText(self.hex_bytes_fit.capitalize())
            self.hex_bytes_fit_combo.currentTextChanged.connect(lambda text: self.on_fit_mode_changed('hex_bytes_fit', text))
            hex_fit_layout.addWidget(self.hex_bytes_fit_combo)
            hex_fit_layout.addWidget(QLabel("Quality:"))
            self.hex_bytes_gif_quality_combo = QComboBox()
            self.hex_bytes_gif_quality_combo.addItems(["Optimized", "Smooth", "Full"])
            self.hex_bytes_gif_quality_combo.setCurrentText(self.hex_bytes_gif_quality.capitalize())
            self.hex_bytes_gif_quality_combo.currentTextChanged.connect(lambda text: self.on_gif_quality_changed('hex_bytes_gif_quality', text))
            hex_fit_layout.addWidget(self.hex_bytes_gif_quality_combo)
            hex_fit_layout.addStretch()
            image_layout.addLayout(hex_fit_layout)

            left_layout.addWidget(self.image_widget)

            # Additional overlay images - compact collapsible sections
            overlay_label = QLabel("Additional Overlays:")
            overlay_label.setStyleSheet("font-weight: bold; font-size: 9pt; margin-top: 3px;")
            left_layout.addWidget(overlay_label)

            # Offset/ASCII compact section
            offset_btn_layout = QHBoxLayout()
            offset_browse_btn = QPushButton("Offset/ASCII Image...")
            offset_browse_btn.clicked.connect(self.browse_offset_ascii_image)
            offset_btn_layout.addWidget(offset_browse_btn)
            offset_clear_btn = QPushButton("×")
            offset_clear_btn.setMaximumWidth(30)
            offset_clear_btn.clicked.connect(self.clear_offset_ascii_image)
            offset_btn_layout.addWidget(offset_clear_btn)
            left_layout.addLayout(offset_btn_layout)

            self.offset_ascii_image_label = QLabel("No image")
            self.offset_ascii_image_label.setStyleSheet("padding: 2px; font-size: 9px; color: #888;")
            left_layout.addWidget(self.offset_ascii_image_label)

            offset_tint_layout = QHBoxLayout()
            self.offset_ascii_tint_btn = ColorButton(self.offset_ascii_tint_color)
            self.offset_ascii_tint_btn.colorChanged.connect(self.on_offset_ascii_tint_changed)
            offset_tint_layout.addWidget(self.offset_ascii_tint_btn)
            self.offset_ascii_opacity_slider = QSlider(Qt.Horizontal)
            self.offset_ascii_opacity_slider.setRange(0, 100)
            self.offset_ascii_opacity_slider.setValue(int(self.offset_ascii_tint_opacity * 100))
            self.offset_ascii_opacity_slider.valueChanged.connect(self.on_offset_ascii_opacity_changed)
            offset_tint_layout.addWidget(self.offset_ascii_opacity_slider, 1)
            self.offset_ascii_opacity_label = QLabel(f"{int(self.offset_ascii_tint_opacity * 100)}%")
            self.offset_ascii_opacity_label.setMinimumWidth(30)
            offset_tint_layout.addWidget(self.offset_ascii_opacity_label)
            left_layout.addLayout(offset_tint_layout)
            offset_fit_layout = QHBoxLayout()
            offset_fit_layout.addWidget(QLabel("Size:"))
            self.offset_ascii_fit_combo = QComboBox()
            self.offset_ascii_fit_combo.addItems(["Fill", "Fit", "Stretch"])
            self.offset_ascii_fit_combo.setCurrentText(self.offset_ascii_fit.capitalize())
            self.offset_ascii_fit_combo.currentTextChanged.connect(lambda text: self.on_fit_mode_changed('offset_ascii_fit', text))
            offset_fit_layout.addWidget(self.offset_ascii_fit_combo)
            offset_fit_layout.addWidget(QLabel("Quality:"))
            self.offset_ascii_gif_quality_combo = QComboBox()
            self.offset_ascii_gif_quality_combo.addItems(["Optimized", "Smooth", "Full"])
            self.offset_ascii_gif_quality_combo.setCurrentText(self.offset_ascii_gif_quality.capitalize())
            self.offset_ascii_gif_quality_combo.currentTextChanged.connect(lambda text: self.on_gif_quality_changed('offset_ascii_gif_quality', text))
            offset_fit_layout.addWidget(self.offset_ascii_gif_quality_combo)
            offset_fit_layout.addStretch()
            left_layout.addLayout(offset_fit_layout)

            self.offset_drop_widgets = [offset_browse_btn, offset_clear_btn, self.offset_ascii_image_label, self.offset_ascii_tint_btn, self.offset_ascii_opacity_slider]

            left_layout.addStretch()

            # Update visibility
            self.update_bg_widgets_visibility()

            left_panel.setMinimumWidth(230)
            content_layout.addWidget(left_panel)

            # RIGHT PANEL - Color Configuration (no scrolling needed!)
            right_panel = QWidget()
            right_panel.setObjectName("themePanel")
            right_layout = QVBoxLayout(right_panel)
            right_layout.setContentsMargins(0, 0, 0, 0)
            right_layout.setSpacing(4)

            colors_label = QLabel("Theme Colors")
            colors_label.setStyleSheet("font-weight: bold; font-size: 10pt;")
            right_layout.addWidget(colors_label)

            # Create color grid - 2 columns for efficient space use
            colors_grid = QWidget()
            colors_grid.setObjectName("themePanel")
            colors_grid.setSizePolicy(QSizePolicy.Preferred, QSizePolicy.Maximum)
            grid_layout = QGridLayout(colors_grid)
            grid_layout.setHorizontalSpacing(10)
            grid_layout.setVerticalSpacing(3)
            grid_layout.setContentsMargins(0, 6, 0, 0)

            # Create color pickers in compact grid
            for index, (param, label) in enumerate(THEME_PARAM_LABELS.items()):
                row_widget = QWidget()
                param_layout = QHBoxLayout(row_widget)
                param_layout.setContentsMargins(0, 0, 0, 0)
                param_layout.setSpacing(4)

                # Label
                param_label = QLabel(label + ":")
                param_label.setMinimumWidth(104)
                param_layout.addWidget(param_label)

                # Color button
                color_button = ColorButton(self.current_theme.get(param, "#000000"))
                color_button.colorChanged.connect(lambda c, p=param: self.on_color_changed(p, c))
                self.color_buttons[param] = color_button
                param_layout.addWidget(color_button)

                # Color hex value display
                color_value = QLineEdit(self.current_theme.get(param, "#000000"))
                color_value.setFixedWidth(66)
                color_value.setReadOnly(True)
                color_value.setStyleSheet("background: #2d2d30; color: #d4d4d4; border: 1px solid #555; font-size: 8pt; padding: 1px 3px;")
                self.color_buttons[param].color_value_label = color_value
                param_layout.addWidget(color_value)

                param_layout.addStretch()
                grid_layout.addWidget(row_widget, index // 2, index % 2)

                # Store reference to background row
                if param == "background":
                    self.background_row = row_widget

            right_layout.addWidget(colors_grid, 0, Qt.AlignTop)
            right_layout.addStretch()

            content_layout.addWidget(right_panel, 1, Qt.AlignTop)
            main_layout.addLayout(content_layout)

            # Bottom buttons - compact
            button_layout = QHBoxLayout()
            button_layout.setSpacing(8)

            save_button = QPushButton("Save Theme")
            save_button.clicked.connect(self.save_theme)
            button_layout.addWidget(save_button)

            button_layout.addStretch()

            close_button = QPushButton("Close")
            close_button.clicked.connect(self.accept)
            button_layout.addWidget(close_button)

            main_layout.addLayout(button_layout)

            self.setLayout(main_layout)

            # Load gradient colors if theme has them, otherwise keep defaults
            if self.current_theme.get("gradient", False):
                gradient_colors = self.current_theme.get("gradient_colors", [])
                if gradient_colors:
                    for i in range(min(len(gradient_colors), len(self.gradient_color_buttons))):
                        self.gradient_color_buttons[i].set_color(gradient_colors[i])

            # Hide main background color row if gradient is active
            if self.current_theme.get("gradient", False):
                if self.background_row:
                    self.background_row.setVisible(False)

            # Disable inspector_bg button if it's set to transparent
            if self.current_theme.get("inspector_bg", "") == "transparent":
                if "inspector_bg" in self.color_buttons:
                    self.color_buttons["inspector_bg"].setEnabled(False)

            self.apply_theme_live()

        def on_main_bg_type_changed(self, bg_type):
            """Handle main background type change"""
            if bg_type == "Color":
                self.current_theme["gradient"] = False
                if "gradient_colors" in self.current_theme:
                    del self.current_theme["gradient_colors"]
                if self.current_theme.get("editor_bg") == "transparent":
                    self.current_theme["editor_bg"] = self.current_theme.get("background", "#1e1e1e")

            elif bg_type == "Gradient":
                self.current_theme["gradient"] = True
                self.current_theme["editor_bg"] = "transparent"
                gradient_colors = [btn.color for btn in self.gradient_color_buttons]
                self.current_theme["gradient_colors"] = gradient_colors

            elif bg_type == "Image":
                self.current_theme["gradient"] = False
                if "gradient_colors" in self.current_theme:
                    del self.current_theme["gradient_colors"]

            self.update_bg_widgets_visibility()
            self.apply_theme_live()

        def update_bg_widgets_visibility(self):
            """Update visibility of background widgets based on selection"""
            bg_type = self.main_bg_combo.currentText()

            self.gradient_widget.setVisible(bg_type == "Gradient")
            self.app_image_widget.setVisible(bg_type == "Image")
            self.image_widget.setVisible(True)

            # Show/hide main background color row
            if self.background_row:
                self.background_row.setVisible(bg_type == "Color")

        def apply_theme_live(self):
            """Apply theme changes to parent editor in real-time"""
            theme_name = self.current_theme.get("name", "Custom Theme")
            preview_theme_id = f"custom:{self._live_storage_name}" if self._live_storage_name else None
            if self._live_storage_name:
                custom_themes = load_custom_themes()
                custom_themes[self._live_storage_name] = self.current_theme
                save_custom_themes(custom_themes)

            self.setStyleSheet(
                get_theme_stylesheet(preview_theme_id or theme_name) +
                self.compact_editor_stylesheet(get_theme_colors(preview_theme_id or theme_name))
            )
            self.style().unpolish(self)
            self.style().polish(self)
            self.update()

            if self.parent_editor and hasattr(self.parent_editor, 'apply_theme'):
                # Update parent's current theme and apply
                if preview_theme_id:
                    self.parent_editor.current_theme = preview_theme_id
                    self.parent_editor.apply_theme()

        def update_gradient_color(self, index, color):
            """Update a gradient color"""
            gradient_colors = [btn.color for btn in self.gradient_color_buttons]
            self.current_theme["gradient_colors"] = gradient_colors
            self.apply_theme_live()

        def load_base_theme(self, theme_name):
            """Load a base theme to start customizing from"""
            all_themes = get_all_themes()
            if theme_name in all_themes:
                self.current_theme = all_themes[theme_name].copy()
                self.current_theme["name"] = self.theme_name_input.text() or "Custom Theme"

                # Ensure inspector_bg exists (default to background if missing)
                if 'inspector_bg' not in self.current_theme:
                    self.current_theme['inspector_bg'] = self.current_theme.get('background', '#1e1e1e')

                # Load image properties
                self.app_bg_image_path = self.current_theme.get('app_bg_image', '')
                self.app_bg_tint_color = self.current_theme.get('app_bg_tint_color', '#000000')
                self.app_bg_tint_opacity = self.current_theme.get('app_bg_tint_opacity', 0)
                self.app_bg_fit = self.current_theme.get('app_bg_fit', 'fill')
                self.app_bg_gif_quality = self.current_theme.get('app_bg_gif_quality', 'optimized')

                self.hex_bytes_image_path = self.current_theme.get('hex_bytes_bg_image', '')
                self.hex_bytes_tint_color = self.current_theme.get('hex_bytes_tint_color', '#000000')
                self.hex_bytes_tint_opacity = self.current_theme.get('hex_bytes_tint_opacity', 0)
                self.hex_bytes_fit = self.current_theme.get('hex_bytes_fit', 'fill')
                self.hex_bytes_gif_quality = self.current_theme.get('hex_bytes_gif_quality', 'optimized')

                self.offset_ascii_image_path = self.current_theme.get('offset_ascii_bg_image', '')
                self.offset_ascii_tint_color = self.current_theme.get('offset_ascii_tint_color', '#000000')
                self.offset_ascii_tint_opacity = self.current_theme.get('offset_ascii_tint_opacity', 0)
                self.offset_ascii_fit = self.current_theme.get('offset_ascii_fit', 'fill')
                self.offset_ascii_gif_quality = self.current_theme.get('offset_ascii_gif_quality', 'optimized')

                # Update image UI elements
                self.app_bg_image_label.setText(os.path.basename(self.app_bg_image_path) if self.app_bg_image_path else "No editor background image")
                self.app_bg_tint_btn.set_color(self.app_bg_tint_color)
                self.app_bg_opacity_slider.setValue(int(self.app_bg_tint_opacity * 100))
                self.app_bg_opacity_label.setText(f"{int(self.app_bg_tint_opacity * 100)}%")
                self.app_bg_fit_combo.setCurrentText(self.app_bg_fit.capitalize())
                self.app_bg_gif_quality_combo.setCurrentText(self.app_bg_gif_quality.capitalize())

                self.hex_bytes_image_label.setText(self.hex_bytes_image_path or "No image selected")
                self.hex_bytes_tint_btn.set_color(self.hex_bytes_tint_color)
                self.hex_bytes_opacity_slider.setValue(int(self.hex_bytes_tint_opacity * 100))
                self.hex_bytes_opacity_label.setText(f"{int(self.hex_bytes_tint_opacity * 100)}%")
                self.hex_bytes_fit_combo.setCurrentText(self.hex_bytes_fit.capitalize())
                self.hex_bytes_gif_quality_combo.setCurrentText(self.hex_bytes_gif_quality.capitalize())

                self.offset_ascii_image_label.setText(self.offset_ascii_image_path or "No image selected")
                self.offset_ascii_tint_btn.set_color(self.offset_ascii_tint_color)
                self.offset_ascii_opacity_slider.setValue(int(self.offset_ascii_tint_opacity * 100))
                self.offset_ascii_opacity_label.setText(f"{int(self.offset_ascii_tint_opacity * 100)}%")
                self.offset_ascii_fit_combo.setCurrentText(self.offset_ascii_fit.capitalize())
                self.offset_ascii_gif_quality_combo.setCurrentText(self.offset_ascii_gif_quality.capitalize())

                # Update all color buttons
                for param, button in self.color_buttons.items():
                    color = self.current_theme.get(param, "#000000")
                    if color != "transparent":
                        button.set_color(color)
                        if hasattr(button, 'color_value_label'):
                            button.color_value_label.setText(color)

                # Determine and set background type
                is_gradient = self.current_theme.get("gradient", False)
                if is_gradient:
                    self.main_bg_combo.setCurrentText("Gradient")
                elif self.app_bg_image_path:
                    self.main_bg_combo.setCurrentText("Image")
                else:
                    self.main_bg_combo.setCurrentText("Color")

                # Update gradient colors if present, otherwise use defaults
                default_gradient = ["#ff6b35", "#ff8c42", "#ffa94d", "#ffc75f", "#f9c74f"]
                if is_gradient:
                    gradient_colors = self.current_theme.get("gradient_colors", default_gradient)
                else:
                    gradient_colors = default_gradient

                for i in range(min(len(gradient_colors), len(self.gradient_color_buttons))):
                    self.gradient_color_buttons[i].set_color(gradient_colors[i])

                # Update visibility
                self.update_bg_widgets_visibility()
                self.apply_theme_live()

        def on_theme_name_changed(self, text):
            """Handle theme name change in real-time"""
            self.current_theme["name"] = text or "Custom Theme"

        def is_image_file(self, file_path):
            return os.path.splitext(file_path)[1].lower() in IMAGE_EXTENSIONS

        def dragEnterEvent(self, event):
            if event.mimeData().hasUrls():
                for url in event.mimeData().urls():
                    if url.isLocalFile() and self.is_image_file(url.toLocalFile()):
                        event.acceptProposedAction()
                        return
            event.ignore()

        def dragMoveEvent(self, event):
            self.dragEnterEvent(event)

        def dropEvent(self, event):
            for url in event.mimeData().urls():
                if url.isLocalFile():
                    file_path = url.toLocalFile()
                    if self.is_image_file(file_path):
                        self.set_dropped_image(file_path, self.drop_target_for_pos(event.pos()))
                        event.acceptProposedAction()
                        return
            event.ignore()

        def widget_matches_drop_list(self, widget, widgets):
            while widget is not None and widget is not self:
                if widget in widgets:
                    return True
                widget = widget.parent()
            return False

        def drop_target_for_pos(self, pos):
            widget = self.childAt(pos)
            if widget is not None:
                if self.widget_matches_drop_list(widget, getattr(self, 'offset_drop_widgets', [])):
                    return 'offset'
            if self.app_image_widget.isVisible() and self.app_image_widget.geometry().contains(self.app_image_widget.parent().mapFrom(self, pos)):
                return 'app'
            if self.image_widget.geometry().contains(self.image_widget.parent().mapFrom(self, pos)):
                return 'hex'
            return 'hex'

        def set_dropped_image(self, file_path, target):
            if target == 'app':
                self.app_bg_image_path = file_path
                self.app_bg_image_label.setText(os.path.basename(file_path))
                self.current_theme['app_bg_image'] = file_path
            elif target == 'offset':
                self.offset_ascii_image_path = file_path
                self.offset_ascii_image_label.setText(os.path.basename(file_path))
                self.current_theme['offset_ascii_bg_image'] = file_path
            else:
                self.hex_bytes_image_path = file_path
                self.hex_bytes_image_label.setText(os.path.basename(file_path))
                self.current_theme['hex_bytes_bg_image'] = file_path
            self.apply_theme_live()

        def browse_app_bg_image(self):
            """Browse for whole-editor background image"""
            file_path, _ = QFileDialog.getOpenFileName(
                self, "Select Editor Background Image", "",
                IMAGE_FILTER
            )
            if file_path:
                if not os.path.exists(file_path):
                    QMessageBox.warning(self, "Image Error", "That image path does not exist.")
                    return
                self.app_bg_image_path = file_path
                self.app_bg_image_label.setText(os.path.basename(file_path))
                self.current_theme['app_bg_image'] = file_path
                self.apply_theme_live()

        def clear_app_bg_image(self):
            """Clear whole-editor background image"""
            self.app_bg_image_path = ""
            self.app_bg_image_label.setText("No editor background image")
            if 'app_bg_image' in self.current_theme:
                del self.current_theme['app_bg_image']
            self.apply_theme_live()

        def on_app_bg_tint_changed(self, color):
            """Handle whole-editor background tint color change"""
            self.app_bg_tint_color = color
            self.current_theme['app_bg_tint_color'] = color
            self.apply_theme_live()

        def on_app_bg_opacity_changed(self, value):
            """Handle whole-editor background tint opacity change"""
            self.app_bg_tint_opacity = value / 100.0
            self.app_bg_opacity_label.setText(f"{value}%")
            self.current_theme['app_bg_tint_opacity'] = self.app_bg_tint_opacity
            self.apply_theme_live()

        def on_fit_mode_changed(self, key, text):
            """Handle image sizing mode changes."""
            self.current_theme[key] = text.lower()
            self.apply_theme_live()

        def on_gif_quality_changed(self, key, text):
            """Handle animated GIF playback quality changes."""
            self.current_theme[key] = text.lower()
            self.apply_theme_live()

        def on_color_changed(self, param, color):
            """Handle color change for a parameter"""
            self.current_theme[param] = color
            if hasattr(self.color_buttons[param], 'color_value_label'):
                self.color_buttons[param].color_value_label.setText(color)

            self.apply_theme_live()
            self.themeChanged.emit(self.current_theme)

        def browse_hex_bytes_image(self):
            """Browse for hex bytes background image"""
            file_path, _ = QFileDialog.getOpenFileName(
                self, "Select Hex Bytes Background Image", "",
                IMAGE_FILTER
            )
            if file_path:
                self.hex_bytes_image_path = file_path
                # Show just filename
                self.hex_bytes_image_label.setText(os.path.basename(file_path))
                self.current_theme['hex_bytes_bg_image'] = file_path
                self.apply_theme_live()

        def clear_hex_bytes_image(self):
            """Clear hex bytes background image"""
            self.hex_bytes_image_path = ""
            self.hex_bytes_image_label.setText("No image selected")
            if 'hex_bytes_bg_image' in self.current_theme:
                del self.current_theme['hex_bytes_bg_image']
            self.apply_theme_live()

        def on_hex_bytes_tint_changed(self, color):
            """Handle hex bytes tint color change"""
            self.hex_bytes_tint_color = color
            self.current_theme['hex_bytes_tint_color'] = color
            self.apply_theme_live()

        def on_hex_bytes_opacity_changed(self, value):
            """Handle hex bytes tint opacity change"""
            self.hex_bytes_tint_opacity = value / 100.0
            self.hex_bytes_opacity_label.setText(f"{value}%")
            self.current_theme['hex_bytes_tint_opacity'] = self.hex_bytes_tint_opacity
            self.apply_theme_live()

        def browse_offset_ascii_image(self):
            """Browse for offset/ASCII background image"""
            file_path, _ = QFileDialog.getOpenFileName(
                self, "Select Offset/ASCII Background Image", "",
                IMAGE_FILTER
            )
            if file_path:
                self.offset_ascii_image_path = file_path
                self.offset_ascii_image_label.setText(os.path.basename(file_path))
                self.current_theme['offset_ascii_bg_image'] = file_path
                self.apply_theme_live()

        def clear_offset_ascii_image(self):
            """Clear offset/ASCII background image"""
            self.offset_ascii_image_path = ""
            self.offset_ascii_image_label.setText("No image")
            if 'offset_ascii_bg_image' in self.current_theme:
                del self.current_theme['offset_ascii_bg_image']
            self.apply_theme_live()

        def on_offset_ascii_tint_changed(self, color):
            """Handle offset/ASCII tint color change"""
            self.offset_ascii_tint_color = color
            self.current_theme['offset_ascii_tint_color'] = color
            self.apply_theme_live()

        def on_offset_ascii_opacity_changed(self, value):
            """Handle offset/ASCII tint opacity change"""
            self.offset_ascii_tint_opacity = value / 100.0
            self.offset_ascii_opacity_label.setText(f"{value}%")
            self.current_theme['offset_ascii_tint_opacity'] = self.offset_ascii_tint_opacity
            self.apply_theme_live()

        def save_theme(self):
            """Save the current theme to custom themes file"""
            theme_name = self.theme_name_input.text().strip()
            if not theme_name:
                QMessageBox.warning(self, "Invalid Name", "Please enter a theme name.")
                return

            # Check if trying to overwrite a built-in theme
            all_builtin = get_all_themes()
            builtin_names = [name for cat in THEMES.values() for name in cat.keys()]
            if theme_name in builtin_names:
                QMessageBox.warning(self, "Invalid Name",
                                  f"Cannot use name '{theme_name}' - it's a built-in theme.")
                return

            self.current_theme["name"] = theme_name

            # Load existing custom themes
            custom_themes = load_custom_themes()
            if self.original_custom_name and self.original_custom_name != theme_name:
                custom_themes.pop(self.original_custom_name, None)
            if self._temporary_live_storage:
                custom_themes.pop(self._live_storage_name, None)
            custom_themes[theme_name] = self.current_theme

            # Save to file
            if save_custom_themes(custom_themes):
                self.original_custom_name = theme_name
                self._temporary_live_storage = False
                self._live_storage_name = theme_name
                QMessageBox.information(self, "Success", f"Theme '{theme_name}' saved successfully!")
            else:
                QMessageBox.warning(self, "Error", "Failed to save theme.")

        def delete_theme(self):
            """Delete the current custom theme"""
            theme_name = self.theme_name_input.text().strip()
            theme_key = self.original_custom_name or theme_name
            if not theme_name:
                QMessageBox.warning(self, "Invalid Name", "Please enter a theme name.")
                return

            custom_themes = load_custom_themes()

            if theme_key in custom_themes:
                theme_name = theme_key
            elif theme_name in custom_themes:
                theme_key = theme_name
            else:
                theme_key = theme_name

            # Only block built-ins when there is no same-named custom theme to delete.
            builtin_names = [name for cat in THEMES.values() for name in cat.keys()]
            if theme_key in builtin_names and theme_key not in custom_themes:
                QMessageBox.warning(self, "Cannot Delete",
                                  "Cannot delete built-in themes.")
                return

            if theme_key not in custom_themes:
                QMessageBox.warning(self, "Not Found",
                                  f"Custom theme '{theme_key}' not found.")
                return

            # Confirm deletion
            reply = QMessageBox.question(self, "Confirm Delete",
                                        f"Are you sure you want to delete theme '{theme_key}'?",
                                        QMessageBox.Yes | QMessageBox.No)

            if reply == QMessageBox.Yes:
                del custom_themes[theme_key]
                if save_custom_themes(custom_themes):
                    QMessageBox.information(self, "Success",
                                          f"Theme '{theme_key}' deleted successfully!")
                    self.reject()
                else:
                    QMessageBox.warning(self, "Error", "Failed to delete theme.")

        def get_theme(self):
            """Get the current theme configuration"""
            theme_name = self.theme_name_input.text().strip() or self.current_theme.get("name", "Custom Theme")
            self.current_theme["name"] = theme_name
            return self.current_theme
