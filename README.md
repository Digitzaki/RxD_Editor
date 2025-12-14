# RxD Hex Editor

A professional hex editor with advanced features for binary file analysis and editing.

## Interface Overview

### Menu Bar

**File Menu**
- Open, Close, Close All - Manage files in tabs
- Save, Save All - Save modifications
- Exit

**Edit Menu**
- Undo/Redo - Full undo/redo support
- Copy, Cut, Paste Write, Paste Insert - Advanced clipboard operations
- Fill Selection - Fill selected bytes with a pattern

**View Menu**
- Search, Replace, Go to - Navigation and search tools
- Hide Delimiters - Configure bytes to hide with padding
- Segments - Configure visual byte grouping separators

**Tools Menu**
- Highlight - Create custom byte pattern highlights
- Show Notes - Open persistent notes panel
- Calculator - Built-in programmer's calculator
- Color Picker - RGB/Hex color picker tool
- Compare Data - Compare bytes between files or regions

**Options Menu**
- Version Control - Manage file snapshots and restore points
- Themes - Select from built-in themes or create custom ones
- Save/Load JSON - Export/import highlights and annotations
- Clear - Remove all highlights and annotations

### Main Display

**Three-Column Layout:**
- **Offset Column** (left) - Byte positions (click header to cycle: hex/decimal/octal)
- **Hex Column** (center) - Hexadecimal byte values with editing support
- **Decoded Text** (right) - ASCII representation with extended character support

**Features:**
- Click any byte to position cursor
- Type hex digits to edit bytes directly
- Right-click for context menu
- Multi-file tabs for working with multiple files
- Column selection mode for rectangular selections

### Right Panel Tabs

**Inspector Tab**
- View selected bytes as different data types
- Signed/unsigned integers (8, 16, 32, 64-bit)
- Floating point (float, double)
- Text encodings (ASCII, UTF-8, UTF-16)
- Binary representation
- Toggle byte order (little/big endian)
- Choose integral display basis (hex/dec/oct)
- Navigation buttons (first, prev, next, last byte)

**Pattern Scan Tab**
- Automatic pattern detection in files
- Identifies ASCII strings, UTF-16LE strings
- Detects pointer tables and possible file offsets
- Finds compression signatures (zlib, gzip, LZ4, etc.)
- Discovers image format headers
- Uses libmagic for MIME type detection
- Click results to jump to location

**Pointers Tab**
- Manage custom data signatures and pointers
- Define data structures with types and labels
- Visual overlays show pointer target values
- Organize with categories
- Save/load pointer definitions

**Statistics Tab**
- Real-time file statistics
- Byte frequency analysis
- Byte distribution histogram
- Entropy calculation
- Magic number detection
- Visual charts (requires matplotlib)

### Status Bar

Shows current file state:
- Cursor position and selected byte range
- File size and modification status
- Ready state indicator

## Key Features

**Multi-Tab Editing** - Work with multiple files simultaneously

**Version Control** - Create snapshots and restore to previous states

**Custom Themes** - 25+ built-in themes (dark, light, gradient) plus custom theme editor

**Advanced Selection** - Standard and column selection modes for precise byte operations

**Pattern Highlighting** - Define and colorize byte patterns with labels and categories

**Notes System** - Persistent notes that save with your workflow

**Delimiter Hiding** - Hide repeated delimiters (like null bytes) with padding indicators

**Segment Separators** - Visual grouping of bytes (1, 2, 4, or 8 byte segments)

**Memory Mapped Files** - Efficient handling of large files (10MB+)

**Smart Resolution Detection** - Automatically adjusts UI based on screen resolution (1080p/1440p+)

## Keyboard Shortcuts

- **Ctrl+S** - Save file
- **Ctrl+Shift+S** - Save all files
- **Ctrl+Z** - Undo
- **Ctrl+Y** - Redo
- **Ctrl+C** - Copy selection
- **Ctrl+X** - Cut selection
- **Ctrl+V** - Paste insert
- **Ctrl+B** - Paste write (overwrite)
- **Ctrl+F** - Search
- **Ctrl+R** - Replace
- **Ctrl+G** - Go to offset
- **Ctrl+H** - Highlight dialog
- **Ctrl+L** - Fill selection
- **Arrow Keys** - Navigate bytes

## Quick Start

1. **Open a file** - File → Open or drag and drop
2. **Navigate** - Click bytes or use arrow keys
3. **Edit** - Type hex digits directly or use ASCII column
4. **Inspect** - Right panel Inspector shows selected bytes as different data types
5. **Scan** - Use Pattern Scan tab to analyze file structure
6. **Highlight** - Mark important bytes with custom colors and labels (Ctrl+H)
7. **Save** - Ctrl+S to save changes
