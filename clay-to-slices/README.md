# CLY to STL Converter

A web-based converter for FreeForm Workspace (.cly) files to STL format for 3D printing.

## Features

- **Web Interface**: Simple drag-and-drop interface
- **Multiple Formats**: Convert to ASCII or Binary STL
- **Large File Support**: Handles files up to 100MB
- **Real-time Progress**: Visual feedback during conversion
- **Comprehensive Logging**: Detailed logs for reverse engineering

## Quick Start

### Windows
1. **Setup (one-time):**
   ```batch
   setup.bat
   ```

2. **Run the application:**
   ```batch
   run.bat
   ```

### Linux/Mac
1. **Setup (one-time):**
   ```bash
   chmod +x setup.sh
   ./setup.sh
   ```

2. **Run the application:**
   ```bash
   chmod +x run.sh
   ./run.sh
   ```

3. **Open your browser to:** `http://localhost:5000`

## Manual Setup

If you prefer manual setup:

1. **Create virtual environment:**
   ```bash
   python -m venv venv
   ```

2. **Activate virtual environment:**
   - Windows: `venv\Scripts\activate`
   - Linux/Mac: `source venv/bin/activate`

3. **Install dependencies:**
   ```bash
   pip install -r requirements.txt
   ```

4. **Run the application:**
   ```bash
   python app.py
   ```

## Virtual Environment

This project uses a Python virtual environment to isolate dependencies:

- **Virtual Environment**: `venv/`
- **Dependencies**: Listed in `requirements.txt`
- **Development Dependencies**: Listed in `requirements-dev.txt`

## Logging

The application creates detailed logs in `cly_converter.log` that include:

- File header parsing
- Binary data structure analysis
- ASCII marker detection
- Potential vertex/face data identification
- Hex dumps of binary sections
- Conversion progress

This logging will help with reverse engineering the exact .cly format.

## File Format Support

- **Input**: FreeForm Workspace (.cly) files
- **Output**: STL files (ASCII or Binary)

## Current Status

This is a **prototype with comprehensive logging**. The current implementation:

✅ **Complete:**
- Web interface with drag-and-drop
- File upload handling
- STL export (ASCII and Binary)
- Progress feedback
- Error handling
- **Detailed logging for reverse engineering**
- **Virtual environment setup**

⚠️ **Needs Enhancement:**
- The binary parsing is currently a placeholder (creates a simple cube)
- To make it production-ready, we need to reverse-engineer the exact .cly binary format

## Development

The app uses:
- **Flask**: Web framework
- **NumPy**: Numerical computations
- **Struct**: Binary data parsing
- **Logging**: Comprehensive debugging

## Project Structure

## License

MIT License 