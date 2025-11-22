"""
Hex Editor Themes
Defines color schemes for the hex editor application
"""

THEMES = {
    "Dark": {
        "name": "Dark",
        "background": "#1e1e1e",
        "foreground": "#d4d4d4",
        "editor_bg": "#252526",
        "editor_fg": "#d4d4d4",
        "selection_bg": "#264f78",
        "border": "#3e3e42",
        "menubar_bg": "#2d2d30",
        "menubar_selected": "#3e3e42",
        "button_bg": "#0e639c",
        "button_hover": "#1177bb",
        "button_disabled": "#3e3e42",
        "modified_byte": "#ff6b6b",
        "inserted_byte": "#51cf66",
        "replaced_byte": "#74c0fc"
    },
    "Light": {
        "name": "Light",
        "background": "#ffffff",
        "foreground": "#000000",
        "editor_bg": "#f5f5f5",
        "editor_fg": "#000000",
        "selection_bg": "#add6ff",
        "border": "#cccccc",
        "menubar_bg": "#f0f0f0",
        "menubar_selected": "#e0e0e0",
        "button_bg": "#0078d4",
        "button_hover": "#106ebe",
        "button_disabled": "#cccccc",
        "modified_byte": "#d63031",
        "inserted_byte": "#00b894",
        "replaced_byte": "#0984e3"
    },
    "Nord": {
        "name": "Nord",
        "background": "#2e3440",
        "foreground": "#d8dee9",
        "editor_bg": "#3b4252",
        "editor_fg": "#eceff4",
        "selection_bg": "#5e81ac",
        "border": "#4c566a",
        "menubar_bg": "#3b4252",
        "menubar_selected": "#434c5e",
        "button_bg": "#5e81ac",
        "button_hover": "#81a1c1",
        "button_disabled": "#4c566a",
        "modified_byte": "#bf616a",
        "inserted_byte": "#a3be8c",
        "replaced_byte": "#88c0d0"
    },
    "Dracula": {
        "name": "Dracula",
        "background": "#282a36",
        "foreground": "#f8f8f2",
        "editor_bg": "#21222c",
        "editor_fg": "#f8f8f2",
        "selection_bg": "#44475a",
        "border": "#44475a",
        "menubar_bg": "#21222c",
        "menubar_selected": "#44475a",
        "button_bg": "#bd93f9",
        "button_hover": "#cfa8ff",
        "button_disabled": "#44475a",
        "modified_byte": "#ff79c6",
        "inserted_byte": "#50fa7b",
        "replaced_byte": "#8be9fd"
    },
    "Monokai": {
        "name": "Monokai",
        "background": "#272822",
        "foreground": "#f8f8f2",
        "editor_bg": "#1e1f1c",
        "editor_fg": "#f8f8f2",
        "selection_bg": "#49483e",
        "border": "#3e3d32",
        "menubar_bg": "#1e1f1c",
        "menubar_selected": "#49483e",
        "button_bg": "#66d9ef",
        "button_hover": "#7ee2f7",
        "button_disabled": "#3e3d32",
        "modified_byte": "#f92672",
        "inserted_byte": "#a6e22e",
        "replaced_byte": "#66d9ef"
    },
    "Pastel Pink": {
        "name": "Pastel Pink",
        "background": "#fef0f5",
        "foreground": "#4a4a4a",
        "editor_bg": "#fff5f9",
        "editor_fg": "#3d3d3d",
        "selection_bg": "#ffc9e0",
        "border": "#ffc9e0",
        "menubar_bg": "#fff0f7",
        "menubar_selected": "#ffe4f0",
        "button_bg": "#ff99c8",
        "button_hover": "#ffb3d7",
        "button_disabled": "#ffd9eb",
        "modified_byte": "#ff6b9d",
        "inserted_byte": "#69db7c",
        "replaced_byte": "#74c0fc"
    },
    "Pastel Blue": {
        "name": "Pastel Blue",
        "background": "#e7f5ff",
        "foreground": "#1e3a5f",
        "editor_bg": "#f0f7ff",
        "editor_fg": "#1e3a5f",
        "selection_bg": "#a5d8ff",
        "border": "#a5d8ff",
        "menubar_bg": "#dbeeff",
        "menubar_selected": "#bfddff",
        "button_bg": "#74c0fc",
        "button_hover": "#91d2ff",
        "button_disabled": "#d0ebff",
        "modified_byte": "#ff6b6b",
        "inserted_byte": "#51cf66",
        "replaced_byte": "#4c6ef5"
    },
    "Pastel Lavender": {
        "name": "Pastel Lavender",
        "background": "#f3f0ff",
        "foreground": "#3d3755",
        "editor_bg": "#f8f5ff",
        "editor_fg": "#3d3755",
        "selection_bg": "#d0bfff",
        "border": "#d0bfff",
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
        "foreground": "#0d3d2e",
        "editor_bg": "#f0fdf7",
        "editor_fg": "#0d3d2e",
        "selection_bg": "#96f2d7",
        "border": "#96f2d7",
        "menubar_bg": "#d3f9ef",
        "menubar_selected": "#b8f5e6",
        "button_bg": "#63e6be",
        "button_hover": "#7efdd4",
        "button_disabled": "#c3fae8",
        "modified_byte": "#ff6b9d",
        "inserted_byte": "#20c997",
        "replaced_byte": "#74c0fc"
    },
    "Solarized Dark": {
        "name": "Solarized Dark",
        "background": "#002b36",
        "foreground": "#93a1a1",
        "editor_bg": "#073642",
        "editor_fg": "#eee8d5",
        "selection_bg": "#586e75",
        "border": "#073642",
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
        "foreground": "#00ff41",
        "editor_bg": "#0a0a0a",
        "editor_fg": "#00ff41",
        "selection_bg": "#003b00",
        "border": "#00ff41",
        "menubar_bg": "#0a0a0a",
        "menubar_selected": "#1a1a1a",
        "button_bg": "#00ff41",
        "button_hover": "#39ff14",
        "button_disabled": "#1a1a1a",
        "modified_byte": "#39ff14",
        "inserted_byte": "#00ff41",
        "replaced_byte": "#00d9ff"
    },
    "Halloween": {
        "name": "Halloween",
        "background": "#1a0033",
        "foreground": "#ff6600",
        "editor_bg": "#2d0052",
        "editor_fg": "#ffaa00",
        "selection_bg": "#4d0080",
        "border": "#6600cc",
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
        "foreground": "#ff2e2e",
        "editor_bg": "#0a1f14",
        "editor_fg": "#ffeded",
        "selection_bg": "#1a4d2e",
        "border": "#2d5a3d",
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
        "foreground": "#ff2a6d",
        "editor_bg": "#05080f",
        "editor_fg": "#d1f7ff",
        "selection_bg": "#1a1d4a",
        "border": "#05d9e8",
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
        "foreground": "#8892b0",
        "editor_bg": "#112240",
        "editor_fg": "#ccd6f6",
        "selection_bg": "#233554",
        "border": "#1d3a5f",
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
        "foreground": "#ff6c95",
        "editor_bg": "#16213e",
        "editor_fg": "#ffcce1",
        "selection_bg": "#3e2c5c",
        "border": "#533483",
        "menubar_bg": "#16213e",
        "menubar_selected": "#3e2c5c",
        "button_bg": "#ff6c95",
        "button_hover": "#ff8fab",
        "button_disabled": "#3e2c5c",
        "modified_byte": "#ff6c95",
        "inserted_byte": "#7dd3fc",
        "replaced_byte": "#fbbf24"
    }
}


def get_theme_stylesheet(theme_name):
    """Generate Qt stylesheet for a given theme"""
    if theme_name not in THEMES:
        theme_name = "Dark"

    theme = THEMES[theme_name]

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
            color: white;
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
    """


def get_theme_colors(theme_name):
    """Get color values for a theme"""
    if theme_name not in THEMES:
        theme_name = "Dark"
    return THEMES[theme_name]
