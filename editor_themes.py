"""
Hex Editor Themes
Defines color schemes for the hex editor application
"""

import json
import os
from pathlib import Path

try:
    from PyQt5.QtWidgets import (QDialog, QVBoxLayout, QHBoxLayout, QLabel,
                                 QPushButton, QLineEdit, QScrollArea, QWidget,
                                 QColorDialog, QFrame, QMessageBox, QComboBox,
                                 QFileDialog, QCheckBox)
    from PyQt5.QtCore import Qt, pyqtSignal
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
            "gradient_colors": ["#000000", "#11090b", "#200b10", "#27060D", "#240207"],
            "foreground": "#f0e5ea",
            "editor_bg": "transparent",
            "editor_fg": "#f0e5ea",
            "selection_bg": "#5d4e5860",
            "border": "#992b4f",
            "grid_line": "#6b314880",
            "menubar_bg": "#1d181c",
            "menubar_selected": "#2d2428",
            "button_bg": "#5d4e58",
            "button_hover": "#6d5c68",
            "button_disabled": "#3d3238",
            "modified_byte": "#ff8899",
            "inserted_byte": "#99dd99",
            "replaced_byte": "#99bbff"
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
CUSTOM_THEMES_FILE = Path.home() / ".hex_editor_custom_themes.json"


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


def get_all_themes():
    """Get all themes including custom ones, flattened from categories"""
    all_themes = {}

    # Flatten built-in categorized themes
    for category, themes in THEMES.items():
        all_themes.update(themes)

    # Add custom themes
    custom_themes = load_custom_themes()
    all_themes.update(custom_themes)

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
    all_themes = get_all_themes()

    if theme_name not in all_themes:
        theme_name = "Dark"

    theme = all_themes[theme_name]

    # Handle gradient themes
    if theme.get("gradient", False):
        return f"""
            QMainWindow, QWidget {{
                background-color: transparent;
                color: {theme['foreground']};
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
            QLineEdit, QSpinBox, QComboBox, QTextEdit#notes {{
                background-color: {theme['menubar_bg']};
                color: {theme['foreground']};
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
                background-color: {theme['menubar_bg']};
                color: {theme['foreground']};
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
    all_themes = get_all_themes()
    if theme_name not in all_themes:
        theme_name = "Dark"
    return all_themes[theme_name]


# Theme parameter labels for user-friendly display
THEME_PARAM_LABELS = {
    "background": "Main Background",
    "foreground": "Main Text Color",
    "inspector_bg": "Inspector Background",
    "editor_bg": "Editor Background",
    "editor_fg": "Editor Text Color",
    "selection_bg": "Selection Background",
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
    class ColorButton(QPushButton):
        """A button that displays and allows selecting a color"""
        colorChanged = pyqtSignal(str)

        def __init__(self, color="#000000", parent=None):
            super().__init__(parent)
            self.color = color
            self.setFixedSize(40, 30)
            self.clicked.connect(self.choose_color)
            self.update_color()

        def update_color(self):
            """Update button style to show current color"""
            self.setStyleSheet(f"""
                QPushButton {{
                    background-color: {self.color};
                    border: 2px solid #999;
                    border-radius: 3px;
                }}
                QPushButton:hover {{
                    border: 2px solid #fff;
                }}
            """)

        def choose_color(self):
            """Open color picker dialog"""
            color = QColorDialog.getColor(QColor(self.color), self, "Choose Color")
            if color.isValid():
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
            self.setMinimumSize(700, 700)

            # Apply parent's theme stylesheet if available - use Light or Dark based on brightness
            if parent and hasattr(parent, 'current_theme'):
                if parent.is_dark_theme():
                    base_theme_name = "Dark"
                else:
                    base_theme_name = "Light"
                style = get_theme_stylesheet(base_theme_name)
                self.setStyleSheet(style)

            # Start with a base theme or Dark theme
            if base_theme and base_theme in get_all_themes():
                self.current_theme = get_all_themes()[base_theme].copy()
            else:
                self.current_theme = THEMES["Dark"]["Dark"].copy()

            # Ensure inspector_bg exists (default to background if missing)
            if 'inspector_bg' not in self.current_theme:
                self.current_theme['inspector_bg'] = self.current_theme.get('background', '#1e1e1e')

            self.color_buttons = {}
            self.gradient_enabled = False
            self.gradient_colors = []
            self.background_row = None  # Track background color row widget
            self.setup_ui()

        def setup_ui(self):
            """Setup the user interface"""
            layout = QVBoxLayout()
            layout.setSpacing(10)

            # Theme name section
            name_layout = QHBoxLayout()
            name_layout.addWidget(QLabel("Theme Name:"))
            self.theme_name_input = QLineEdit()
            self.theme_name_input.setPlaceholderText("Enter custom theme name")
            self.theme_name_input.setText(self.current_theme.get("name", "Custom Theme"))
            name_layout.addWidget(self.theme_name_input)
            layout.addLayout(name_layout)

            # Base theme selection
            base_layout = QHBoxLayout()
            base_layout.addWidget(QLabel("Start from:"))
            self.base_theme_combo = QComboBox()
            all_theme_names = sorted(get_all_themes().keys())
            self.base_theme_combo.addItems(all_theme_names)
            self.base_theme_combo.currentTextChanged.connect(self.load_base_theme)
            base_layout.addWidget(self.base_theme_combo)
            base_layout.addStretch()
            layout.addLayout(base_layout)

            # Gradient/Image support section
            gradient_layout = QHBoxLayout()
            self.gradient_checkbox = QCheckBox("Use Gradient Background")
            self.gradient_checkbox.setChecked(self.current_theme.get("gradient", False))
            self.gradient_checkbox.stateChanged.connect(self.toggle_gradient)
            gradient_layout.addWidget(self.gradient_checkbox)
            gradient_layout.addStretch()
            layout.addLayout(gradient_layout)

            # Inspector gradient option
            inspector_gradient_layout = QHBoxLayout()
            self.inspector_gradient_checkbox = QCheckBox("Use Gradient for Inspector Background")
            # Check if inspector_bg is transparent (uses gradient)
            self.inspector_gradient_checkbox.setChecked(
                self.current_theme.get("inspector_bg", "") == "transparent"
            )
            self.inspector_gradient_checkbox.stateChanged.connect(self.toggle_inspector_gradient)
            inspector_gradient_layout.addWidget(self.inspector_gradient_checkbox)
            inspector_gradient_layout.addStretch()
            layout.addLayout(inspector_gradient_layout)

            # Gradient colors section (initially hidden)
            self.gradient_widget = QWidget()
            gradient_colors_layout = QVBoxLayout(self.gradient_widget)
            gradient_colors_layout.addWidget(QLabel("Gradient Colors (top to bottom):"))

            self.gradient_colors_layout = QHBoxLayout()
            self.gradient_color_buttons = []

            # Default gradient colors (sunset palette)
            default_gradient = ["#ff6b35", "#ff8c42", "#ffa94d", "#ffc75f", "#f9c74f"]

            # Create 5 gradient color pickers with defaults
            for i in range(5):
                initial_color = default_gradient[i]
                color_btn = ColorButton(initial_color)
                color_btn.colorChanged.connect(lambda c, idx=i: self.update_gradient_color(idx, c))
                self.gradient_color_buttons.append(color_btn)
                self.gradient_colors_layout.addWidget(color_btn)

            gradient_colors_layout.addLayout(self.gradient_colors_layout)
            self.gradient_widget.setVisible(self.current_theme.get("gradient", False))
            layout.addWidget(self.gradient_widget)

            # Separator
            separator = QFrame()
            separator.setFrameShape(QFrame.HLine)
            separator.setFrameShadow(QFrame.Sunken)
            layout.addWidget(separator)

            # Scrollable area for color parameters
            scroll = QScrollArea()
            scroll.setWidgetResizable(True)
            scroll.setHorizontalScrollBarPolicy(Qt.ScrollBarAlwaysOff)

            scroll_widget = QWidget()
            scroll_layout = QVBoxLayout(scroll_widget)
            scroll_layout.setSpacing(8)

            # Create color pickers for each theme parameter
            for param, label in THEME_PARAM_LABELS.items():
                # Create a container widget for this row
                row_widget = QWidget()
                param_layout = QHBoxLayout(row_widget)
                param_layout.setContentsMargins(0, 0, 0, 0)

                # Label
                param_label = QLabel(label + ":")
                param_label.setMinimumWidth(180)
                param_layout.addWidget(param_label)

                # Color button
                color_button = ColorButton(self.current_theme.get(param, "#000000"))
                color_button.colorChanged.connect(lambda c, p=param: self.on_color_changed(p, c))
                self.color_buttons[param] = color_button
                param_layout.addWidget(color_button)

                # Color hex value display
                color_value = QLineEdit(self.current_theme.get(param, "#000000"))
                color_value.setMaximumWidth(80)
                color_value.setReadOnly(True)
                color_value.setStyleSheet("background: #2d2d30; color: #d4d4d4; border: 1px solid #555;")
                self.color_buttons[param].color_value_label = color_value
                param_layout.addWidget(color_value)

                param_layout.addStretch()
                scroll_layout.addWidget(row_widget)

                # Store reference to background row
                if param == "background":
                    self.background_row = row_widget

            scroll_layout.addStretch()
            scroll.setWidget(scroll_widget)
            layout.addWidget(scroll)

            # Preview section
            preview_label = QLabel("Live Preview:")
            preview_label.setStyleSheet("font-weight: bold; margin-top: 10px;")
            layout.addWidget(preview_label)

            self.preview_widget = QWidget()
            self.preview_widget.setMinimumHeight(80)
            self.preview_layout = QVBoxLayout(self.preview_widget)

            preview_text = QLabel("This is a preview of your custom theme")
            preview_text.setAlignment(Qt.AlignCenter)
            self.preview_layout.addWidget(preview_text)

            preview_button = QPushButton("Sample Button")
            self.preview_layout.addWidget(preview_button)

            layout.addWidget(self.preview_widget)

            # Buttons
            button_layout = QHBoxLayout()

            save_button = QPushButton("Save Theme")
            save_button.clicked.connect(self.save_theme)
            button_layout.addWidget(save_button)

            delete_button = QPushButton("Delete Theme")
            delete_button.clicked.connect(self.delete_theme)
            button_layout.addWidget(delete_button)

            button_layout.addStretch()

            cancel_button = QPushButton("Cancel")
            cancel_button.clicked.connect(self.reject)
            button_layout.addWidget(cancel_button)

            apply_button = QPushButton("Apply")
            apply_button.clicked.connect(self.apply_theme)
            button_layout.addWidget(apply_button)

            layout.addLayout(button_layout)

            self.setLayout(layout)

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

            self.update_preview()

        def toggle_gradient(self, state):
            """Toggle gradient background mode"""
            self.gradient_enabled = state == Qt.Checked
            self.gradient_widget.setVisible(self.gradient_enabled)
            self.current_theme["gradient"] = self.gradient_enabled

            if self.gradient_enabled:
                # Set editor background to transparent
                self.current_theme["editor_bg"] = "transparent"
                if "editor_bg" in self.color_buttons:
                    self.color_buttons["editor_bg"].setEnabled(False)

                # Hide the main background color row since gradient will be used instead
                if self.background_row:
                    self.background_row.setVisible(False)

                # Get gradient colors
                gradient_colors = [btn.color for btn in self.gradient_color_buttons]
                self.current_theme["gradient_colors"] = gradient_colors
            else:
                if "editor_bg" in self.color_buttons:
                    self.color_buttons["editor_bg"].setEnabled(True)

                # Show the main background color row again
                if self.background_row:
                    self.background_row.setVisible(True)

                if "gradient_colors" in self.current_theme:
                    del self.current_theme["gradient_colors"]
                # Restore editor_bg to a solid color if it was transparent
                if self.current_theme.get("editor_bg") == "transparent":
                    self.current_theme["editor_bg"] = self.current_theme.get("background", "#1e1e1e")

            self.update_preview()

        def toggle_inspector_gradient(self, state):
            """Toggle gradient for inspector background"""
            use_gradient = state == Qt.Checked

            if use_gradient:
                # Set inspector background to transparent to use gradient
                self.current_theme["inspector_bg"] = "transparent"
                if "inspector_bg" in self.color_buttons:
                    self.color_buttons["inspector_bg"].setEnabled(False)
            else:
                # Restore inspector background to a solid color
                if "inspector_bg" in self.color_buttons:
                    self.color_buttons["inspector_bg"].setEnabled(True)
                # Use current background or a default
                if self.current_theme.get("inspector_bg") == "transparent":
                    self.current_theme["inspector_bg"] = self.current_theme.get("background", "#1e1e1e")

            self.update_preview()

        def update_gradient_color(self, index, color):
            """Update a gradient color"""
            gradient_colors = [btn.color for btn in self.gradient_color_buttons]
            self.current_theme["gradient_colors"] = gradient_colors
            self.update_preview()

        def load_base_theme(self, theme_name):
            """Load a base theme to start customizing from"""
            all_themes = get_all_themes()
            if theme_name in all_themes:
                self.current_theme = all_themes[theme_name].copy()
                self.current_theme["name"] = self.theme_name_input.text() or "Custom Theme"

                # Ensure inspector_bg exists (default to background if missing)
                if 'inspector_bg' not in self.current_theme:
                    self.current_theme['inspector_bg'] = self.current_theme.get('background', '#1e1e1e')

                # Update all color buttons
                for param, button in self.color_buttons.items():
                    color = self.current_theme.get(param, "#000000")
                    if color != "transparent":
                        button.set_color(color)
                        if hasattr(button, 'color_value_label'):
                            button.color_value_label.setText(color)

                # Update gradient checkbox
                is_gradient = self.current_theme.get("gradient", False)
                self.gradient_checkbox.setChecked(is_gradient)
                self.gradient_widget.setVisible(is_gradient)

                # Update inspector gradient checkbox
                inspector_uses_gradient = self.current_theme.get("inspector_bg", "") == "transparent"
                self.inspector_gradient_checkbox.setChecked(inspector_uses_gradient)
                if "inspector_bg" in self.color_buttons:
                    self.color_buttons["inspector_bg"].setEnabled(not inspector_uses_gradient)

                # Update gradient colors if present, otherwise use defaults
                default_gradient = ["#ff6b35", "#ff8c42", "#ffa94d", "#ffc75f", "#f9c74f"]
                if is_gradient:
                    gradient_colors = self.current_theme.get("gradient_colors", default_gradient)
                else:
                    gradient_colors = default_gradient

                for i in range(min(len(gradient_colors), len(self.gradient_color_buttons))):
                    self.gradient_color_buttons[i].set_color(gradient_colors[i])

                # Hide or show main background color row based on gradient status
                if self.background_row:
                    has_gradient = self.current_theme.get("gradient", False)
                    self.background_row.setVisible(not has_gradient)

                self.update_preview()

        def on_color_changed(self, param, color):
            """Handle color change for a parameter"""
            self.current_theme[param] = color
            if hasattr(self.color_buttons[param], 'color_value_label'):
                self.color_buttons[param].color_value_label.setText(color)

            self.update_preview()
            self.themeChanged.emit(self.current_theme)

        def update_preview(self):
            """Update the preview widget with current theme colors"""
            theme = self.current_theme

            if theme.get("gradient", False):
                # Show gradient preview
                bg_color = theme.get('menubar_bg', '#1e1e1e')
            else:
                bg_color = theme.get('background', '#1e1e1e')

            self.preview_widget.setStyleSheet(f"""
                QWidget {{
                    background-color: {bg_color};
                    color: {theme.get('foreground', '#d4d4d4')};
                    border: 2px solid {theme.get('border', '#3e3e42')};
                    border-radius: 5px;
                }}
                QLabel {{
                    color: {theme.get('foreground', '#d4d4d4')};
                    border: none;
                }}
                QPushButton {{
                    background-color: {theme.get('button_bg', '#0e639c')};
                    color: {theme.get('button_text', 'white')};
                    border: none;
                    padding: 6px 16px;
                    border-radius: 3px;
                }}
                QPushButton:hover {{
                    background-color: {theme.get('button_hover', '#1177bb')};
                }}
            """)

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
            custom_themes[theme_name] = self.current_theme

            # Save to file
            if save_custom_themes(custom_themes):
                QMessageBox.information(self, "Success", f"Theme '{theme_name}' saved successfully!")
            else:
                QMessageBox.warning(self, "Error", "Failed to save theme.")

        def delete_theme(self):
            """Delete the current custom theme"""
            theme_name = self.theme_name_input.text().strip()
            if not theme_name:
                QMessageBox.warning(self, "Invalid Name", "Please enter a theme name.")
                return

            # Check if it's a built-in theme
            builtin_names = [name for cat in THEMES.values() for name in cat.keys()]
            if theme_name in builtin_names:
                QMessageBox.warning(self, "Cannot Delete",
                                  "Cannot delete built-in themes.")
                return

            # Load custom themes
            custom_themes = load_custom_themes()

            if theme_name not in custom_themes:
                QMessageBox.warning(self, "Not Found",
                                  f"Custom theme '{theme_name}' not found.")
                return

            # Confirm deletion
            reply = QMessageBox.question(self, "Confirm Delete",
                                        f"Are you sure you want to delete theme '{theme_name}'?",
                                        QMessageBox.Yes | QMessageBox.No)

            if reply == QMessageBox.Yes:
                del custom_themes[theme_name]
                if save_custom_themes(custom_themes):
                    QMessageBox.information(self, "Success",
                                          f"Theme '{theme_name}' deleted successfully!")
                    self.reject()
                else:
                    QMessageBox.warning(self, "Error", "Failed to delete theme.")

        def apply_theme(self):
            """Apply the current theme"""
            self.current_theme["name"] = self.theme_name_input.text().strip() or "Custom Theme"
            self.accept()

        def get_theme(self):
            """Get the current theme configuration"""
            return self.current_theme
