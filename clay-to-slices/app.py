from flask import Flask, render_template, request, send_file, jsonify
import os
import struct
import numpy as np
import tempfile
from werkzeug.utils import secure_filename
import logging
import binascii
import io
from config import Config

app = Flask(__name__)
app.config.from_object(Config)

# Ensure directories exist
os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)
os.makedirs(app.config['OUTPUT_FOLDER'], exist_ok=True)

# Configure detailed logging for reverse engineering
logging.basicConfig(
    level=getattr(logging, app.config['LOG_LEVEL']),
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler(app.config['LOG_FILE']),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

class CLYParser:
    def __init__(self, file_path):
        self.file_path = file_path
        self.vertices = []
        self.faces = []
        self.metadata = {}
        self.binary_data = []
        self.structure_analysis = {}
        
    def hex_dump(self, data, length=64):
        """Create a hex dump for debugging"""
        hex_str = binascii.hexlify(data[:length]).decode('ascii')
        return ' '.join(hex_str[i:i+2] for i in range(0, len(hex_str), 2))
    
    def analyze_binary_structure(self, data, offset, length=100):
        """Analyze binary data structure for reverse engineering"""
        logger.info(f"=== Binary Structure Analysis at offset {offset} ===")
        
        # Look for patterns
        logger.info(f"First {length} bytes as hex: {self.hex_dump(data[offset:offset+length])}")
        
        # Try to find ASCII strings
        ascii_chars = []
        for i in range(min(length, len(data) - offset)):
            byte = data[offset + i]
            if 32 <= byte <= 126:  # Printable ASCII
                ascii_chars.append(chr(byte))
            else:
                ascii_chars.append('.')
        
        logger.info(f"ASCII representation: {''.join(ascii_chars)}")
        
        # Look for potential float values (4 bytes)
        if len(data) - offset >= 16:
            logger.info("Potential 4-byte values (as floats):")
            for i in range(0, min(16, len(data) - offset), 4):
                if i + 4 <= len(data) - offset:
                    try:
                        float_val = struct.unpack('<f', data[offset+i:offset+i+4])[0]
                        logger.info(f"  Offset {offset+i}: {float_val}")
                    except:
                        pass
        
        # Look for potential integer values
        if len(data) - offset >= 8:
            logger.info("Potential 4-byte values (as integers):")
            for i in range(0, min(16, len(data) - offset), 4):
                if i + 4 <= len(data) - offset:
                    try:
                        int_val = struct.unpack('<I', data[offset+i:offset+i+4])[0]
                        logger.info(f"  Offset {offset+i}: {int_val}")
                    except:
                        pass
    
    def parse_header(self):
        """Parse the ASCII header of the .cly file"""
        logger.info("=== Parsing CLY Header ===")
        
        with open(self.file_path, 'rb') as f:
            header_lines = []
            line_count = 0
            
            while True:
                line = f.readline().decode('utf-8', errors='ignore').strip()
                header_lines.append(line)
                line_count += 1
                
                logger.info(f"Header line {line_count}: {line}")
                
                if line == 'endHeader':
                    break
                if line_count > 100:  # Safety check
                    logger.warning("Header parsing stopped - too many lines")
                    break
            
            # Parse metadata
            for line in header_lines:
                if line.startswith('units'):
                    self.metadata['units'] = line.split()[1]
                    logger.info(f"Units: {self.metadata['units']}")
                elif line.startswith('modelDimensions'):
                    parts = line.split()
                    self.metadata['dimensions'] = [float(parts[1]), float(parts[2]), float(parts[3])]
                    logger.info(f"Model dimensions: {self.metadata['dimensions']}")
                elif line.startswith('numVoxels'):
                    self.metadata['numVoxels'] = int(line.split()[1])
                    logger.info(f"Number of voxels: {self.metadata['numVoxels']}")
                elif line.startswith('numTris'):
                    self.metadata['numTris'] = int(line.split()[1])
                    logger.info(f"Number of triangles: {self.metadata['numTris']}")
                elif line.startswith('bitmap'):
                    parts = line.split()
                    self.metadata['bitmap'] = [int(parts[1]), int(parts[2])]
                    logger.info(f"Bitmap info: {self.metadata['bitmap']}")
                elif line.startswith('fileVersion'):
                    self.metadata['fileVersion'] = int(line.split()[1])
                    logger.info(f"File version: {self.metadata['fileVersion']}")
            
            start_pos = f.tell()
            logger.info(f"Header ends at position: {start_pos}")
            return start_pos
    
    def parse_binary_data(self, start_pos):
        """Parse the binary mesh data with detailed logging"""
        logger.info("=== Parsing Binary Data ===")
        
        with open(self.file_path, 'rb') as f:
            f.seek(start_pos)
            
            # Read first chunk for analysis
            chunk_size = 1024
            first_chunk = f.read(chunk_size)
            logger.info(f"First {chunk_size} bytes of binary data:")
            self.analyze_binary_structure(first_chunk, 0, chunk_size)
            
            # Look for known markers
            f.seek(start_pos)
            data = f.read()
            
            # Search for ASCII markers in binary data
            logger.info("=== Searching for ASCII markers ===")
            ascii_markers = []
            for i in range(len(data) - 10):
                chunk = data[i:i+10]
                try:
                    text = chunk.decode('ascii', errors='ignore')
                    if text.isprintable() and len(text.strip()) > 3:
                        ascii_markers.append((i, text.strip()))
                except:
                    pass
            
            # Log found markers
            for offset, marker in ascii_markers[:20]:  # Limit to first 20
                logger.info(f"ASCII marker at offset {offset}: '{marker}'")
            
            # Analyze structure around known markers
            if ascii_markers:
                logger.info("=== Analyzing structure around markers ===")
                for offset, marker in ascii_markers[:5]:
                    if offset + 100 < len(data):
                        logger.info(f"Structure around '{marker}' at offset {offset}:")
                        self.analyze_binary_structure(data, offset, 100)
            
            # Try to find potential vertex data
            logger.info("=== Looking for potential vertex data ===")
            # Look for sequences of 12 bytes (3 floats for x,y,z)
            potential_vertices = []
            for i in range(0, min(len(data), 1000), 12):
                if i + 12 <= len(data):
                    try:
                        x, y, z = struct.unpack('<fff', data[i:i+12])
                        # Check if values are reasonable (not NaN, not too large)
                        if all(-10000 < val < 10000 for val in [x, y, z]) and \
                           not any(np.isnan(val) for val in [x, y, z]):
                            potential_vertices.append((i, x, y, z))
                    except:
                        pass
            
            logger.info(f"Found {len(potential_vertices)} potential vertex candidates")
            for i, (offset, x, y, z) in enumerate(potential_vertices[:10]):
                logger.info(f"  Vertex {i}: offset {offset}, pos ({x:.3f}, {y:.3f}, {z:.3f})")
            
            # For now, create a placeholder mesh based on metadata
            self.create_placeholder_mesh()
    
    def create_placeholder_mesh(self):
        """Create a placeholder mesh based on metadata"""
        logger.info("=== Creating Placeholder Mesh ===")
        
        # Use metadata to create a reasonable placeholder
        if 'dimensions' in self.metadata:
            dims = self.metadata['dimensions']
            logger.info(f"Creating placeholder mesh with dimensions: {dims}")
            
            # Create a simple box with the given dimensions
            x, y, z = dims[0], dims[1], dims[2]
            
            vertices = np.array([
                [0, 0, 0], [x, 0, 0], [x, y, 0], [0, y, 0],
                [0, 0, z], [x, 0, z], [x, y, z], [0, y, z]
            ])
            
            faces = np.array([
                [0, 1, 2], [0, 2, 3],  # bottom
                [4, 5, 6], [4, 6, 7],  # top
                [0, 1, 5], [0, 5, 4],  # front
                [2, 3, 7], [2, 7, 6],  # back
                [1, 2, 6], [1, 6, 5],  # right
                [0, 3, 7], [0, 7, 4]   # left
            ])
            
            self.vertices = vertices
            self.faces = faces
            
            logger.info(f"Created placeholder mesh with {len(vertices)} vertices and {len(faces)} faces")
        else:
            # Fallback to unit cube
            logger.warning("No dimensions found, creating unit cube")
            vertices = np.array([
                [0, 0, 0], [1, 0, 0], [1, 1, 0], [0, 1, 0],
                [0, 0, 1], [1, 0, 1], [1, 1, 1], [0, 1, 1]
            ])
            
            faces = np.array([
                [0, 1, 2], [0, 2, 3],  # bottom
                [4, 5, 6], [4, 6, 7],  # top
                [0, 1, 5], [0, 5, 4],  # front
                [2, 3, 7], [2, 7, 6],  # back
                [1, 2, 6], [1, 6, 5],  # right
                [0, 3, 7], [0, 7, 4]   # left
            ])
            
            self.vertices = vertices
            self.faces = faces
    
    def parse(self):
        """Parse the entire .cly file with comprehensive logging"""
        logger.info("=== Starting CLY File Parsing ===")
        logger.info(f"File: {self.file_path}")
        logger.info(f"File size: {os.path.getsize(self.file_path)} bytes")
        
        try:
            start_pos = self.parse_header()
            self.parse_binary_data(start_pos)
            
            logger.info("=== Parsing Summary ===")
            logger.info(f"Metadata: {self.metadata}")
            logger.info(f"Vertices: {len(self.vertices)}")
            logger.info(f"Faces: {len(self.faces)}")
            
            return True
        except Exception as e:
            logger.error(f"Error parsing .cly file: {e}", exc_info=True)
            return False
    
    def export_stl(self, output_path, ascii_format=True):
        """Export to STL format with logging"""
        logger.info(f"=== Exporting to STL ===")
        logger.info(f"Output path: {output_path}")
        logger.info(f"Format: {'ASCII' if ascii_format else 'Binary'}")
        
        if ascii_format:
            with open(output_path, 'w') as f:
                f.write("solid mesh\n")
                for i, face in enumerate(self.faces):
                    # Calculate normal
                    v1, v2, v3 = self.vertices[face]
                    normal = np.cross(v2 - v1, v3 - v1)
                    normal = normal / np.linalg.norm(normal)
                    
                    f.write(f"  facet normal {normal[0]:.6f} {normal[1]:.6f} {normal[2]:.6f}\n")
                    f.write("    outer loop\n")
                    for vertex_idx in face:
                        v = self.vertices[vertex_idx]
                        f.write(f"      vertex {v[0]:.6f} {v[1]:.6f} {v[2]:.6f}\n")
                    f.write("    endloop\n")
                    f.write("  endfacet\n")
                f.write("endsolid mesh\n")
        else:
            # Binary STL
            with open(output_path, 'wb') as f:
                # Write header (80 bytes)
                f.write(b'\x00' * 80)
                
                # Write number of triangles
                f.write(struct.pack('<I', len(self.faces)))
                
                # Write each triangle
                for i, face in enumerate(self.faces):
                    # Calculate normal
                    v1, v2, v3 = self.vertices[face]
                    normal = np.cross(v2 - v1, v3 - v1)
                    normal = normal / np.linalg.norm(normal)
                    
                    # Write normal
                    f.write(struct.pack('<3f', normal[0], normal[1], normal[2]))
                    
                    # Write vertices
                    for vertex_idx in face:
                        v = self.vertices[vertex_idx]
                        f.write(struct.pack('<3f', v[0], v[1], v[2]))
                    
                    # Write attribute byte count (0)
                    f.write(struct.pack('<H', 0))
        
        logger.info(f"STL export completed: {len(self.faces)} faces written")

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/upload', methods=['POST'])
def upload_file():
    logger.info("=== File Upload Request ===")
    
    if 'file' not in request.files:
        logger.error("No file in request")
        return jsonify({'error': 'No file uploaded'}), 400
    
    file = request.files['file']
    if file.filename == '':
        logger.error("No filename provided")
        return jsonify({'error': 'No file selected'}), 400
    
    logger.info(f"Uploaded file: {file.filename}")
    logger.info(f"File size: {len(file.read())} bytes")
    file.seek(0)  # Reset file pointer
    
    if not file.filename.lower().endswith('.cly'):
        logger.error(f"Invalid file type: {file.filename}")
        return jsonify({'error': 'Please upload a .cly file'}), 400
    
    try:
        # Save uploaded file
        filename = secure_filename(file.filename)
        file_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
        file.save(file_path)
        
        logger.info(f"File saved to: {file_path}")
        
        # Parse the .cly file
        parser = CLYParser(file_path)
        if not parser.parse():
            logger.error("Failed to parse .cly file")
            return jsonify({'error': 'Failed to parse .cly file'}), 400
        
        # Export to STL
        output_filename = filename.replace('.cly', '.stl')
        output_path = os.path.join(app.config['OUTPUT_FOLDER'], output_filename)
        
        format_type = request.form.get('format', 'ascii')
        ascii_format = format_type == 'ascii'
        
        logger.info(f"Converting to STL format: {format_type}")
        parser.export_stl(output_path, ascii_format)
        
        logger.info(f"Conversion completed: {output_path}")
        
        # Return the converted file
        return send_file(
            output_path,
            as_attachment=True,
            download_name=output_filename,
            mimetype='application/octet-stream'
        )
        
    except Exception as e:
        logger.error(f"Error processing file: {e}", exc_info=True)
        return jsonify({'error': f'Error processing file: {str(e)}'}), 500
    
    finally:
        # Clean up uploaded file
        if os.path.exists(file_path):
            os.remove(file_path)
            logger.info(f"Cleaned up uploaded file: {file_path}")

if __name__ == '__main__':
    logger.info("=== Starting CLY to STL Converter ===")
    app.run(
        debug=app.config['DEBUG'],
        host=app.config['HOST'],
        port=app.config['PORT']
    ) 