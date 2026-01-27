# RxD Hex Editor

A modern, professional hex editor designed for clear, efficient binary file modification and analysis. RxD Editor delivers all the essential features of traditional hex editors while introducing enhanced visuals, advanced analysis tools, integrated version control, and workflow-improving productivity features.

## ✨ Features

### Core Editing
- **Multi-file tabs** - Open and edit multiple files simultaneously with independent state
- **Smart editing modes** - Insert/overwrite modes with visual indicators
- **Column selection** - Select and edit rectangular regions of bytes
- **Advanced copy/paste** - Multiple formats: Hex, C array, Python bytes, Base64, binary
- **Smart paste** - Configurable delimiter handling for pasting hex strings
- **Full undo/redo** - Complete state snapshots with unlimited history
- **Search & Replace** - Hex patterns, ASCII strings, UTF-16, regex support
- **Byte operations** - Delete, insert, fill, XOR operations

### Analysis Tools
- **Pattern Scanner** - Automatic detection of:
  - ASCII and UTF-16 strings
  - File signatures (PNG, JPEG, ZIP, ELF, PE, etc.)
  - Pointer patterns with validation
  - Compression signatures
- **Data Inspector** - Interpret bytes as 25+ data types:
  - Integers (int8-int64, signed/unsigned)
  - Floats (float32, float64)
  - Timestamps (Unix, Windows FILETIME, DOS)
  - GUIDs, IPv4/IPv6 addresses
  - RGB colors with visual preview
- **Fields System** - Define structured data layouts:
  - Create named fields spanning byte ranges
  - Add nested subfields with type interpretation
  - Auto-generate subfields from pointers
  - Drag-and-drop reordering (subfields locked to parent)
  - Edit values directly with type conversion
- **Statistics & Visualization**:
  - Byte frequency analysis
  - Entropy calculation
  - Byte distribution graphs
  - Histogram visualization
- **Signature Tracking** - Mark important offsets:
  - Custom labels and data types
  - Inline value display overlays
  - Endianness selection
  - Pointer validation

### Visual Enhancements
- **Syntax highlighting** - Color-coded modified/inserted bytes
- **Theme system** - 16+ built-in themes:
  - Dark themes: Dark, Matrix, Nord, Dracula, Monokai, Cyberpunk
  - Light themes: Light, Solarized, GitHub, High Contrast
  - Specialty: Hacker Green, Synthwave, Ocean, Forest, Sunset, Lavender
- **Custom theme editor** - Create themes with:
  - Custom colors for all UI elements
  - Gradient backgrounds (linear, radial, conical)
  - Background image support
  - Save/load custom themes
- **Segment boundaries** - Visual column separators with adjustable ranges
- **Edit box overlay** - Highlight active editing regions
- **Signature overlays** - Inline display of pointer values
- **Configurable display** - 8, 16, 32, or 64 bytes per row

### Productivity Tools
- **Notes System** - Attach notes to byte ranges:
  - Rich text formatting
  - Color-coded categories
  - Search and filter notes
  - Quick navigation
- **Version Control** - Built-in snapshot system:
  - Automatic snapshots on edits
  - Manual snapshots with descriptions
  - Browse and restore previous versions
  - Compare snapshots
- **Bookmarks** - Quick navigation to important offsets
- **File Comparison** - Side-by-side file diff view
- **Debugging Console** - Real-time terminal output viewer:
  - Copy and clear functionality
  - Auto-scrolling
  - Theme-styled interface
- **Relative Offset Display** - Show offsets relative to selection or cursor
- **Hidden Delimiters** - Hide specific byte values as spacing

### File Operations
- **Large file support** - Memory-mapped I/O for files over 100MB
- **Import/Export** - Export selected regions to new files
- **Multiple file formats** - Import from hex strings, C arrays, Python bytes
- **File metadata** - View creation/modification dates, calculate MD5/SHA256 hashes
- **Recent files** - Quick access to recently opened files
- **Auto-save** - Configurable auto-save with snapshots

## 🚀 What's New in This Release

This release introduces major enhancements:

- **Fields system** - Structure your data with nested fields and type interpretation
- **Enhanced pointer system** - Auto-generate subfields from pointers in fields
- **Debugging console** - Monitor and copy terminal output
- **Improved drag-and-drop** - Subfields stay within their parent fields
- **Theme improvements** - Enhanced custom theme editor
- **Stability improvements** - Bug fixes and performance optimizations

## 📦 Installation

### Option 1: From Releases (Recommended)
Follow the ["Releases"](https://github.com/Digitzaki/RxD_Editor/releases) tab for pre-built packages.

### Option 2: From Source
Use Git:
```bash
git clone https://github.com/Digitzaki/RxD_Editor.git
cd RxD_Editor
```

Or download the raw code and install dependencies:

```bash
pip install PyQt5 python-magic matplotlib
```

Then run:
```bash
python hex_editor_qt_full.py
```

### Requirements
- Python 3.7+
- PyQt5
- python-magic (optional, for file type detection)
- matplotlib (optional, for statistics graphs)

## 🛠 Development

Contributions, feature requests, and issue reports are welcome!
Feel free to open a pull request or start a discussion.

### Project Structure
```
RxD_Editor/
├── hex_editor_qt_full.py    # Main editor application
├── editor_themes.py          # Theme system and custom theme editor
└── datainspect/              # Analysis modules
    ├── data_inspector.py     # Multi-type data interpretation
    ├── pattern_scan.py       # Pattern detection scanner
    ├── pointers.py           # Signature/pointer tracking
    ├── statistics.py         # Statistics and visualization
    └── fields.py             # Structured field system
```

## 📝 License

Open Source

## 👤 Author

**Digitzaki [龍崎 明]**
- Website: https://digitzaki.github.io/

---

*Byte Editing, Visualized*
