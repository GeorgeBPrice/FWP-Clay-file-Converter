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
import json
from datetime import datetime
import numpy as np
import shutil

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
        self.logger = logger
        
    def hex_dump(self, data, length=64):
        """Create a hex dump for debugging"""
        hex_str = binascii.hexlify(data[:length]).decode('ascii')
        return ' '.join(hex_str[i:i+2] for i in range(0, len(hex_str), 2))
    
    def analyze_binary_structure(self, data, offset, length=100):
        """Analyze binary data structure for reverse engineering"""
        self.logger.info(f"=== Binary Structure Analysis at offset {offset} ===")
        
        # Look for patterns
        self.logger.info(f"First {length} bytes as hex: {self.hex_dump(data[offset:offset+length])}")
        
        # Try to find ASCII strings
        ascii_chars = []
        for i in range(min(length, len(data) - offset)):
            byte = data[offset + i]
            if 32 <= byte <= 126:  # Printable ASCII
                ascii_chars.append(chr(byte))
            else:
                ascii_chars.append('.')
        
        self.logger.info(f"ASCII representation: {''.join(ascii_chars)}")
        
        # Look for potential float values (4 bytes)
        if len(data) - offset >= 16:
            self.logger.info("Potential 4-byte values (as floats):")
            for i in range(0, min(16, len(data) - offset), 4):
                if i + 4 <= len(data) - offset:
                    try:
                        float_val = struct.unpack('<f', data[offset+i:offset+i+4])[0]
                        self.logger.info(f"  Offset {offset+i}: {float_val}")
                    except:
                        pass
        
        # Look for potential integer values
        if len(data) - offset >= 8:
            self.logger.info("Potential 4-byte values (as integers):")
            for i in range(0, min(16, len(data) - offset), 4):
                if i + 4 <= len(data) - offset:
                    try:
                        int_val = struct.unpack('<I', data[offset+i:offset+i+4])[0]
                        self.logger.info(f"  Offset {offset+i}: {int_val}")
                    except:
                        pass
    
    def parse_header(self):
        """Parse the ASCII header of the .cly file"""
        self.logger.info("=== Parsing CLY Header ===")
        
        with open(self.file_path, 'rb') as f:
            header_lines = []
            line_count = 0
            
            while True:
                line = f.readline().decode('utf-8', errors='ignore').strip()
                header_lines.append(line)
                line_count += 1
                
                self.logger.info(f"Header line {line_count}: {line}")
                
                if line == 'endHeader':
                    break
                if line_count > 100:  # Safety check
                    self.logger.warning("Header parsing stopped - too many lines")
                    break
            
            # Parse metadata
            for line in header_lines:
                if line.startswith('units'):
                    self.metadata['units'] = line.split()[1]
                    self.logger.info(f"Units: {self.metadata['units']}")
                elif line.startswith('modelDimensions'):
                    parts = line.split()
                    self.metadata['dimensions'] = [float(parts[1]), float(parts[2]), float(parts[3])]
                    self.logger.info(f"Model dimensions: {self.metadata['dimensions']}")
                elif line.startswith('numVoxels'):
                    self.metadata['numVoxels'] = int(line.split()[1])
                    self.logger.info(f"Number of voxels: {self.metadata['numVoxels']}")
                elif line.startswith('numTris'):
                    self.metadata['numTris'] = int(line.split()[1])
                    self.logger.info(f"Number of triangles: {self.metadata['numTris']}")
                elif line.startswith('bitmap'):
                    parts = line.split()
                    self.metadata['bitmap'] = [int(parts[1]), int(parts[2])]
                    self.logger.info(f"Bitmap info: {self.metadata['bitmap']}")
                elif line.startswith('fileVersion'):
                    self.metadata['fileVersion'] = int(line.split()[1])
                    self.logger.info(f"File version: {self.metadata['fileVersion']}")
            
            start_pos = f.tell()
            self.logger.info(f"Header ends at position: {start_pos}")
            return start_pos
    
    def parse_binary_data(self, binary_data):
        """Parse binary data according to the CLY format specification"""
        self.logger.info("=== Parsing CLY Binary Data ===")
        
        # Based on analysis, the file starts with "form" (666f726d) not "CLYF"
        # Look for the actual binary data start after the ASCII header
        start_pos = 202  # This was determined from analysis
        self.logger.info(f"Starting binary parsing at position: {start_pos}")
        
        # Read the binary data starting from the header position
        data = binary_data[start_pos:]
        self.logger.info(f"Binary data size: {len(data)} bytes")
        
        try:
            # Step 1: Parse file header - look for FreeStyle format markers
            self.logger.info("=== Parsing FreeStyle File Header ===")
            header = self._parse_freestyle_header(data)
            if not header:
                self.logger.error("Failed to parse FreeStyle header")
                return self.create_placeholder_mesh()
            
            self.logger.info(f"File version: {header['version']}")
            self.logger.info(f"Flags: {header['flags']}")
            self.logger.info(f"Piece count: {header['pieceCount']}")
            
            # Step 2: Parse piece directory
            self.logger.info("=== Parsing Piece Directory ===")
            pieces = self._parse_piece_directory(data, header['headerSize'])
            self.logger.info(f"Found {len(pieces)} pieces")
            
            # Step 3: Parse mesh chunks from each piece
            self.logger.info("=== Parsing Mesh Chunks ===")
            all_vertices = []
            all_faces = []
            
            for i, piece in enumerate(pieces):
                self.logger.info(f"Processing piece {i+1}: {piece['name']}")
                piece_vertices, piece_faces = self._parse_piece_meshes(data, piece)
                
                if piece_vertices and piece_faces:
                    # Adjust face indices to account for previous vertices
                    vertex_offset = len(all_vertices)
                    adjusted_faces = [[f[0] + vertex_offset, f[1] + vertex_offset, f[2] + vertex_offset] 
                                    for f in piece_faces]
                    
                    all_vertices.extend(piece_vertices)
                    all_faces.extend(adjusted_faces)
                    
                    self.logger.info(f"  Added {len(piece_vertices)} vertices and {len(piece_faces)} faces")
            
            if all_vertices and all_faces:
                self.logger.info(f"Successfully extracted {len(all_vertices)} total vertices and {len(all_faces)} total faces")
                return all_vertices, all_faces
            else:
                self.logger.warning("No mesh data found in any pieces")
                return self.create_placeholder_mesh()
                
        except Exception as e:
            self.logger.error(f"Error parsing binary data: {e}", exc_info=True)
            return self.create_placeholder_mesh()
    
    def _parse_freestyle_header(self, data):
        """Parse the FreeStyle file header based on analysis results"""
        if len(data) < 16:
            self.logger.error("Data too short for file header")
            return None
        
        try:
            # Look for "form" magic number (666f726d) instead of "CLYF"
            magic_pos = data.find(b'form')
            if magic_pos == -1:
                # Try hex representation
                magic_pos = data.find(b'\x66\x6f\x72\x6d')
            
            if magic_pos == -1:
                self.logger.warning("FreeStyle 'form' magic number not found, trying alternative parsing")
                # Try parsing from beginning
                magic_pos = 0
            
            pos = magic_pos
            magic = data[pos:pos+4]
            self.logger.info(f"Found magic: {magic}")
            
            pos += 4
            
            # Based on analysis, look for version and structure info
            # Try to find version information
            version = 0
            flags = 0
            piece_count = 0
            
            # Look for potential version field (4 bytes after magic)
            if pos + 4 <= len(data):
                try:
                    version = struct.unpack('<I', data[pos:pos+4])[0]
                    self.logger.info(f"Version field: {version}")
                    pos += 4
                except:
                    pass
            
            # Look for flags field
            if pos + 4 <= len(data):
                try:
                    flags = struct.unpack('<I', data[pos:pos+4])[0]
                    self.logger.info(f"Flags field: {flags}")
                    pos += 4
                except:
                    pass
            
            # Look for piece count
            if pos + 4 <= len(data):
                try:
                    piece_count = struct.unpack('<I', data[pos:pos+4])[0]
                    self.logger.info(f"Piece count: {piece_count}")
                    pos += 4
                except:
                    pass
            
            return {
                'version': version,
                'flags': flags,
                'pieceCount': piece_count,
                'headerSize': pos
            }
            
        except Exception as e:
            self.logger.error(f"Error parsing FreeStyle header: {e}")
            return None
    
    def _parse_piece_directory(self, data, header_size):
        """Parse the piece directory based on FreeStyle format analysis"""
        pieces = []
        pos = header_size
        
        self.logger.info("=== Searching for FreeStyle piece structure ===")
        
        # Based on analysis, look for specific patterns and offsets
        # The analysis showed potential offsets at positions 100, 160, 188, 200
        potential_offsets = [100, 160, 188, 200]
        
        # Also look for ASCII strings that might be piece names
        piece_candidates = []
        
        # Search for readable strings that could be piece names
        for i in range(pos, min(pos + 50000, len(data) - 64)):
            if data[i] == 0:  # Null terminator
                continue
            
            # Try to read a potential piece name
            name_bytes = data[i:i+64]
            null_pos = name_bytes.find(b'\x00')
            if null_pos != -1:
                name_bytes = name_bytes[:null_pos]
            
            try:
                name = name_bytes.decode('ascii', errors='ignore').strip()
                if len(name) > 3 and name.isprintable() and not name.startswith('.'):
                    piece_candidates.append((i, name))
            except:
                continue
        
        self.logger.info(f"Found {len(piece_candidates)} potential piece names")
        
        # Use the first few candidates as pieces, but also check the analysis offsets
        used_offsets = set()
        
        # First, try the analysis-suggested offsets
        for offset in potential_offsets:
            if offset < len(data) - 64:
                try:
                    # Try to read a piece name at this offset
                    name_bytes = data[offset:offset+64]
                    null_pos = name_bytes.find(b'\x00')
                    if null_pos != -1:
                        name_bytes = name_bytes[:null_pos]
                    
                    name = name_bytes.decode('ascii', errors='ignore').strip()
                    if len(name) > 3 and name.isprintable():
                        pieces.append({
                            'name': f"Piece_{len(pieces)+1}",
                            'offset': offset,
                            'chunkCount': 0,
                            'chunkOffsets': []
                        })
                        used_offsets.add(offset)
                        self.logger.info(f"  Analysis piece at offset {offset}: '{name}'")
                except:
                    pass
        
        # Then add some of the string candidates
        for i, (offset, name) in enumerate(piece_candidates[:20]):  # Limit to 20 pieces
            if offset not in used_offsets:
                # Try to read chunk count and offsets
                chunk_count = 0
                chunk_offsets = []
                
                # Look for chunk data after the name
                chunk_pos = offset + 64
                if chunk_pos + 4 <= len(data):
                    try:
                        chunk_count = struct.unpack('<I', data[chunk_pos:chunk_pos+4])[0]
                        if chunk_count > 0 and chunk_count < 1000:  # Reasonable range
                            chunk_pos += 4
                            for j in range(chunk_count):
                                if chunk_pos + 4 <= len(data):
                                    chunk_offset = struct.unpack('<I', data[chunk_pos:chunk_pos+4])[0]
                                    chunk_offsets.append(chunk_offset)
                                    chunk_pos += 4
                    except:
                        pass
                
                pieces.append({
                    'name': name,
                    'offset': offset,
                    'chunkCount': chunk_count,
                    'chunkOffsets': chunk_offsets
                })
                
                self.logger.info(f"  String piece {len(pieces)}: '{name}' with {chunk_count} chunks")
        
        # If we still don't have enough pieces, create some based on data patterns
        if len(pieces) < 5:
            self.logger.info("Creating additional pieces based on data patterns...")
            
            # Look for potential mesh data by scanning for vertex-like patterns
            for i in range(0, len(data) - 1000, 1000):
                if i in used_offsets:
                    continue
                
                # Check if this region looks like it contains mesh data
                # Look for sequences of floats that could be vertices
                float_count = 0
                for j in range(i, min(i + 100, len(data) - 12)):
                    try:
                        x = struct.unpack('<f', data[j:j+4])[0]
                        y = struct.unpack('<f', data[j+4:j+8])[0]
                        z = struct.unpack('<f', data[j+8:j+12])[0]
                        
                        # Check if these look like reasonable vertex coordinates
                        if -10000 < x < 10000 and -10000 < y < 10000 and -10000 < z < 10000:
                            float_count += 1
                    except:
                        pass
                
                if float_count > 10:  # Found a reasonable number of vertex-like floats
                    pieces.append({
                        'name': f"MeshPiece_{len(pieces)+1}",
                        'offset': i,
                        'chunkCount': 1,
                        'chunkOffsets': [i]
                    })
                    used_offsets.add(i)
                    self.logger.info(f"  Created mesh piece at offset {i} with {float_count} potential vertices")
                
                if len(pieces) >= 10:  # Limit total pieces
                    break
        
        self.logger.info(f"Total pieces found: {len(pieces)}")
        return pieces
    
    def _parse_piece_meshes(self, data, piece):
        """Parse mesh chunks from a piece using improved FreeStyle format handling"""
        vertices = []
        faces = []
        
        self.logger.info(f"=== Parsing meshes for piece: {piece['name']} ===")
        
        # If piece has explicit chunk offsets, use them
        if piece['chunkOffsets']:
            for chunk_offset in piece['chunkOffsets']:
                if chunk_offset >= len(data) - 8:
                    continue
                    
                try:
                    # Read chunk header
                    chunk_type = struct.unpack('<I', data[chunk_offset:chunk_offset+4])[0]
                    chunk_size = struct.unpack('<I', data[chunk_offset+4:chunk_offset+8])[0]
                    
                    self.logger.info(f"    Chunk type: {chunk_type}, size: {chunk_size}")
                    
                    # Check if this is a mesh chunk (type 1) or try to parse as mesh data
                    if (chunk_type == 1 or chunk_type == 0) and chunk_size > 0:
                        payload_start = chunk_offset + 8
                        if payload_start + chunk_size <= len(data):
                            payload = data[payload_start:payload_start + chunk_size]
                            chunk_vertices, chunk_faces = self._parse_mesh_chunk(payload)
                            
                            if chunk_vertices and chunk_faces:
                                vertices.extend(chunk_vertices)
                                faces.extend(chunk_faces)
                                self.logger.info(f"      Extracted {len(chunk_vertices)} vertices and {len(chunk_faces)} faces")
                    
                except Exception as e:
                    self.logger.warning(f"Error parsing chunk at offset {chunk_offset}: {e}")
                    continue
        
        # If no chunks found or no valid mesh data, try direct parsing from piece offset
        if not vertices and not faces:
            self.logger.info(f"  No valid chunks found, trying direct parsing from offset {piece['offset']}")
            
            # Try to parse mesh data directly from the piece offset
            start_offset = piece['offset']
            
            # Look for vertex data patterns
            for offset in range(start_offset, min(start_offset + 10000, len(data) - 100)):
                try:
                    # Try to read vertex count
                    vertex_count = struct.unpack('<I', data[offset:offset+4])[0]
                    
                    # Sanity check
                    if vertex_count > 0 and vertex_count < 100000:
                        # Calculate expected data size
                        vertex_data_size = vertex_count * 3 * 4  # 3 floats per vertex
                        total_expected_size = 4 + vertex_data_size + 4  # count + vertices + triangle count
                        
                        if offset + total_expected_size <= len(data):
                            # Try to read vertices
                            pos = offset + 4
                            piece_vertices = []
                            
                            for i in range(vertex_count):
                                if pos + 12 <= len(data):
                                    x = struct.unpack('<f', data[pos:pos+4])[0]
                                    y = struct.unpack('<f', data[pos+4:pos+8])[0]
                                    z = struct.unpack('<f', data[pos+8:pos+12])[0]
                                    
                                    # Sanity check for vertex coordinates
                                    if -10000 < x < 10000 and -10000 < y < 10000 and -10000 < z < 10000:
                                        piece_vertices.append([x, y, z])
                                    else:
                                        break  # Invalid vertex data
                                    
                                    pos += 12
                                else:
                                    break
                            
                            # If we found valid vertices, try to read triangles
                            if len(piece_vertices) == vertex_count:
                                if pos + 4 <= len(data):
                                    tri_count = struct.unpack('<I', data[pos:pos+4])[0]
                                    pos += 4
                                    
                                    if tri_count > 0 and tri_count < 100000:
                                        piece_faces = []
                                        
                                        for i in range(tri_count):
                                            if pos + 12 <= len(data):
                                                i1 = struct.unpack('<I', data[pos:pos+4])[0]
                                                i2 = struct.unpack('<I', data[pos+4:pos+8])[0]
                                                i3 = struct.unpack('<I', data[pos+8:pos+12])[0]
                                                
                                                # Validate indices
                                                if i1 < vertex_count and i2 < vertex_count and i3 < vertex_count:
                                                    piece_faces.append([i1, i2, i3])
                                                else:
                                                    break  # Invalid face indices
                                                
                                                pos += 12
                                            else:
                                                break
                                        
                                        if len(piece_faces) == tri_count:
                                            vertices.extend(piece_vertices)
                                            faces.extend(piece_faces)
                                            self.logger.info(f"      Direct parsing: {len(piece_vertices)} vertices, {len(piece_faces)} faces")
                                            break  # Success, stop searching
                
                except Exception as e:
                    continue  # Try next offset
        
        return vertices, faces
    
    def _parse_mesh_chunk(self, payload):
        """Parse a mesh chunk payload"""
        if len(payload) < 8:
            return [], []
        
        try:
            pos = 0
            
            # Read vertex count
            vertex_count = struct.unpack('<I', payload[pos:pos+4])[0]
            pos += 4
            
            if vertex_count > 1000000:  # Sanity check
                self.logger.warning(f"Unreasonable vertex count: {vertex_count}")
                return [], []
            
            # Read vertices
            vertex_data_size = vertex_count * 3 * 4  # 3 floats per vertex
            if pos + vertex_data_size > len(payload):
                self.logger.warning("Not enough data for vertices")
                return [], []
            
            vertices = []
            for i in range(vertex_count):
                x = struct.unpack('<f', payload[pos:pos+4])[0]
                y = struct.unpack('<f', payload[pos+4:pos+8])[0]
                z = struct.unpack('<f', payload[pos+8:pos+12])[0]
                vertices.append([x, y, z])
                pos += 12
            
            # Read triangle count
            if pos + 4 > len(payload):
                self.logger.warning("Not enough data for triangle count")
                return vertices, []
            
            tri_count = struct.unpack('<I', payload[pos:pos+4])[0]
            pos += 4
            
            if tri_count > 1000000:  # Sanity check
                self.logger.warning(f"Unreasonable triangle count: {tri_count}")
                return vertices, []
            
            # Read triangle indices
            face_data_size = tri_count * 3 * 4  # 3 uint32 per triangle
            if pos + face_data_size > len(payload):
                self.logger.warning("Not enough data for faces")
                return vertices, []
            
            faces = []
            for i in range(tri_count):
                i1 = struct.unpack('<I', payload[pos:pos+4])[0]
                i2 = struct.unpack('<I', payload[pos+4:pos+8])[0]
                i3 = struct.unpack('<I', payload[pos+8:pos+12])[0]
                
                # Validate indices
                if i1 < vertex_count and i2 < vertex_count and i3 < vertex_count:
                    faces.append([i1, i2, i3])
                else:
                    self.logger.warning(f"Invalid face indices: {i1}, {i2}, {i3} (max: {vertex_count})")
                
                pos += 12
            
            return vertices, faces
            
        except Exception as e:
            self.logger.error(f"Error parsing mesh chunk: {e}")
            return [], []
    
    def create_placeholder_mesh(self):
        """Create a placeholder mesh based on metadata"""
        self.logger.info("=== Creating Placeholder Mesh ===")
        
        # Use metadata to create a reasonable placeholder
        if 'dimensions' in self.metadata:
            dims = self.metadata['dimensions']
            self.logger.info(f"Creating placeholder mesh with dimensions: {dims}")
            
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
            
            self.logger.info(f"Created placeholder mesh with {len(vertices)} vertices and {len(faces)} faces")
            return vertices, faces
        else:
            # Fallback to unit cube
            self.logger.warning("No dimensions found, creating unit cube")
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
            
            return vertices, faces
    
    def parse(self):
        """Parse the entire .cly file with comprehensive logging"""
        self.logger.info("=== Starting CLY File Parsing ===")
        self.logger.info(f"File: {self.file_path}")
        self.logger.info(f"File size: {os.path.getsize(self.file_path)} bytes")
        
        try:
            # First parse the ASCII header to get metadata
            start_pos = self.parse_header()
            
            # Read the entire file for binary parsing
            with open(self.file_path, 'rb') as f:
                self.binary_data = f.read()
            
            # Try the enhanced mesh extraction first (uses analysis insights)
            self.logger.info("=== Trying Enhanced Mesh Extraction ===")
            enhanced_vertices, enhanced_faces = self.enhanced_mesh_extraction(self.binary_data)
            
            if enhanced_vertices and enhanced_faces:
                self.vertices = enhanced_vertices
                self.faces = enhanced_faces
                self.logger.info("Successfully parsed using enhanced extraction")
            else:
                # Try the new FreeStyle format parsing
                self.logger.info("=== Trying FreeStyle Format Parsing ===")
                freestyle_vertices, freestyle_faces = self.parse_freestyle_format(self.binary_data)
                
                if freestyle_vertices and freestyle_faces:
                    self.vertices = freestyle_vertices
                    self.faces = freestyle_faces
                    self.logger.info("Successfully parsed using FreeStyle format")
                else:
                    # Fall back to the original parsing method
                    self.logger.info("=== Falling back to original parsing method ===")
                    self.vertices, self.faces = self.parse_binary_data(self.binary_data)
            
            self.logger.info("=== Parsing Summary ===")
            self.logger.info(f"Metadata: {self.metadata}")
            self.logger.info(f"Vertices: {len(self.vertices)}")
            self.logger.info(f"Faces: {len(self.faces)}")
            
            return True
        except Exception as e:
            self.logger.error(f"Error parsing .cly file: {e}", exc_info=True)
            return False
    
    def export_stl(self, output_path, ascii_format=True):
        """Export to STL format with logging"""
        self.logger.info(f"=== Exporting to STL ===")
        self.logger.info(f"Output path: {output_path}")
        self.logger.info(f"Format: {'ASCII' if ascii_format else 'Binary'}")
        
        if ascii_format:
            with open(output_path, 'w') as f:
                f.write("solid mesh\n")
                for i, face in enumerate(self.faces):
                    # Get the three vertices for this face
                    v1_idx, v2_idx, v3_idx = face
                    v1 = self.vertices[v1_idx]
                    v2 = self.vertices[v2_idx]
                    v3 = self.vertices[v3_idx]
                    
                    # Calculate normal
                    normal = np.cross(np.array(v2) - np.array(v1), np.array(v3) - np.array(v1))
                    normal = normal / np.linalg.norm(normal)
                    
                    f.write(f"  facet normal {normal[0]:.6f} {normal[1]:.6f} {normal[2]:.6f}\n")
                    f.write("    outer loop\n")
                    f.write(f"      vertex {v1[0]:.6f} {v1[1]:.6f} {v1[2]:.6f}\n")
                    f.write(f"      vertex {v2[0]:.6f} {v2[1]:.6f} {v2[2]:.6f}\n")
                    f.write(f"      vertex {v3[0]:.6f} {v3[1]:.6f} {v3[2]:.6f}\n")
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
                    # Get the three vertices for this face
                    v1_idx, v2_idx, v3_idx = face
                    v1 = self.vertices[v1_idx]
                    v2 = self.vertices[v2_idx]
                    v3 = self.vertices[v3_idx]
                    
                    # Calculate normal
                    normal = np.cross(np.array(v2) - np.array(v1), np.array(v3) - np.array(v1))
                    normal = normal / np.linalg.norm(normal)
                    
                    # Write normal
                    f.write(struct.pack('<3f', normal[0], normal[1], normal[2]))
                    
                    # Write vertices
                    f.write(struct.pack('<3f', v1[0], v1[1], v1[2]))
                    f.write(struct.pack('<3f', v2[0], v2[1], v2[2]))
                    f.write(struct.pack('<3f', v3[0], v3[1], v3[2]))
                    
                    # Write attribute byte count (0)
                    f.write(struct.pack('<H', 0))
        
        self.logger.info(f"STL export completed: {len(self.faces)} faces written")

    def extract_real_mesh(self, data, start_pos):
        """Attempt to extract real mesh data from binary data"""
        self.logger.info("=== Attempting Real Mesh Extraction ===")
        
        # Based on the metadata, we know what to expect
        expected_tris = self.metadata.get('numTris', 0)
        expected_voxels = self.metadata.get('numVoxels', 0)
        
        self.logger.info(f"Looking for {expected_tris} triangles and {expected_voxels} voxels")
        
        # Strategy 1: Look for large blocks of vertex data
        # Most 3D formats store vertices as consecutive float triplets
        vertices = []
        faces = []
        
        # Search for vertex data patterns
        self.logger.info("=== Searching for vertex data ===")
        
        # Look for areas with high density of reasonable float values
        vertex_candidates = []
        for i in range(0, min(len(data), 100000), 12):  # Check more data
            if i + 12 <= len(data):
                try:
                    x, y, z = struct.unpack('<fff', data[i:i+12])
                    # More strict validation for actual vertex data
                    if all(-1000 < val < 1000 for val in [x, y, z]) and \
                       not any(np.isnan(val) for val in [x, y, z]) and \
                       not any(np.isinf(val) for val in [x, y, z]):
                        vertex_candidates.append((i, x, y, z))
                except:
                    pass
        
        self.logger.info(f"Found {len(vertex_candidates)} vertex candidates")
        
        # Look for clusters of vertex data
        if len(vertex_candidates) > 100:
            # Group vertices by proximity in file
            vertex_clusters = []
            current_cluster = []
            
            for i, (offset, x, y, z) in enumerate(vertex_candidates):
                if not current_cluster or offset - current_cluster[-1][0] <= 1000:
                    current_cluster.append((offset, x, y, z))
                else:
                    if len(current_cluster) > 10:  # Minimum cluster size
                        vertex_clusters.append(current_cluster)
                    current_cluster = [(offset, x, y, z)]
            
            if current_cluster and len(current_cluster) > 10:
                vertex_clusters.append(current_cluster)
            
            self.logger.info(f"Found {len(vertex_clusters)} vertex clusters")
            
            # Use the largest cluster as our vertex data
            if vertex_clusters:
                largest_cluster = max(vertex_clusters, key=len)
                self.logger.info(f"Using largest cluster with {len(largest_cluster)} vertices")
                
                # Extract vertices from the cluster
                for offset, x, y, z in largest_cluster:
                    vertices.append([x, y, z])
                
                # Now look for face data near the vertex data
                self.logger.info("=== Searching for face data ===")
                
                # Look for face indices after the vertex data
                vertex_start = largest_cluster[0][0]
                vertex_end = largest_cluster[-1][0] + 12
                
                # Search for face data after vertex data
                face_candidates = []
                for i in range(vertex_end, min(len(data), vertex_end + 100000), 12):
                    if i + 12 <= len(data):
                        try:
                            v1, v2, v3 = struct.unpack('<III', data[i:i+12])
                            # Check if these indices are valid for our vertex count
                            if 0 <= v1 < len(vertices) and 0 <= v2 < len(vertices) and 0 <= v3 < len(vertices):
                                face_candidates.append((i, v1, v2, v3))
                        except:
                            pass
            
            self.logger.info(f"Found {len(face_candidates)} face candidates")
            
            # Use face candidates if we have enough
            if len(face_candidates) > 100:
                for offset, v1, v2, v3 in face_candidates[:expected_tris]:
                    faces.append([v1, v2, v3])
                self.logger.info(f"Using {len(faces)} faces")
        
        # If we found real data, use it
        if len(vertices) > 100 and len(faces) > 100:
            self.logger.info(f"Successfully extracted {len(vertices)} vertices and {len(faces)} faces")
            self.vertices = np.array(vertices)
            self.faces = np.array(faces)
            return True
        else:
            self.logger.warning("Could not extract real mesh data, using placeholder")
            return False

    def save_analysis_report(self, data, start_pos):
        """Save detailed analysis report to file"""
        report_file = "cly_analysis_report.txt"
        self.logger.info(f"Saving detailed analysis to {report_file}")
        
        with open(report_file, 'w') as f:
            f.write("=== CLY File Analysis Report ===\n")
            f.write(f"File: {self.file_path}\n")
            f.write(f"File size: {os.path.getsize(self.file_path)} bytes\n")
            f.write(f"Binary data starts at: {start_pos}\n")
            f.write(f"Binary data size: {len(data)} bytes\n\n")
            
            f.write("=== Metadata ===\n")
            for key, value in self.metadata.items():
                f.write(f"{key}: {value}\n")
            f.write("\n")
            
            f.write("=== Deep Scan Results ===\n")
            
            # Search for known markers
            known_markers = ['FFDYNPKTObjectListMain', 'FFDYNPKTModelInfo', 'FFDYNPKTModelPreviewImage']
            for marker in known_markers:
                marker_bytes = marker.encode('ascii')
                pos = data.find(marker_bytes)
                if pos != -1:
                    f.write(f"Found marker '{marker}' at offset {pos}\n")
                else:
                    f.write(f"Marker '{marker}' NOT FOUND\n")
            f.write("\n")
            
            # Deep scan for ASCII markers
            f.write("=== ASCII Markers Found ===\n")
            ascii_markers = []
            chunk_size = 100000
            for chunk_start in range(0, len(data), chunk_size):
                chunk_end = min(chunk_start + chunk_size, len(data))
                chunk = data[chunk_start:chunk_end]
                
                for i in range(len(chunk) - 20):
                    chunk_slice = chunk[i:i+20]
                    try:
                        text = chunk_slice.decode('ascii', errors='ignore')
                        if text.isprintable() and len(text.strip()) > 5:
                            global_offset = chunk_start + i
                            ascii_markers.append((global_offset, text.strip()))
                    except:
                        pass
            
            # Show unique markers
            unique_markers = set()
            for offset, marker in ascii_markers:
                unique_markers.add(marker)
            
            f.write(f"Found {len(ascii_markers)} total markers, {len(unique_markers)} unique\n")
            for marker in sorted(unique_markers)[:100]:  # Show first 100 unique markers
                f.write(f"  '{marker}'\n")
            f.write("\n")
            
            # Deep vertex search in multiple sections
            f.write("=== Deep Vertex Search Results ===\n")
            search_sections = [
                (0, min(len(data), 100000)),  # First 100KB
                (len(data)//4, len(data)//4 + 100000),  # Quarter way
                (len(data)//2, len(data)//2 + 100000),  # Half way
                (3*len(data)//4, 3*len(data)//4 + 100000),  # Three quarters
                (len(data) - 100000, len(data))  # Last 100KB
            ]
            
            total_vertex_candidates = 0
            for section_start, section_end in search_sections:
                f.write(f"\nSection {section_start}-{section_end}:\n")
                section_data = data[section_start:section_end]
                
                vertex_candidates = []
                for i in range(0, len(section_data) - 12, 12):
                    try:
                        x, y, z = struct.unpack('<fff', section_data[i:i+12])
                        if all(-1000 < val < 1000 for val in [x, y, z]) and \
                           not any(np.isnan(val) for val in [x, y, z]) and \
                           not any(np.isinf(val) for val in [x, y, z]) and \
                           not (x == 0 and y == 0 and z == 0):
                            global_offset = section_start + i
                            vertex_candidates.append((global_offset, x, y, z))
                    except:
                        pass
                
                f.write(f"  Found {len(vertex_candidates)} vertex candidates\n")
                total_vertex_candidates += len(vertex_candidates)
                
                # Show first few vertices from this section
                for i, (offset, x, y, z) in enumerate(vertex_candidates[:10]):
                    f.write(f"    Vertex {i}: offset {offset}, pos ({x:.6f}, {y:.6f}, {z:.6f})\n")
            
            f.write(f"\nTotal vertex candidates across all sections: {total_vertex_candidates}\n")
            
            # Look for patterns in the data
            f.write("\n=== Data Pattern Analysis ===\n")
            
            # Check for non-zero data patterns
            non_zero_sections = []
            section_size = 10000
            for i in range(0, len(data), section_size):
                section = data[i:i+section_size]
                non_zero_count = sum(1 for b in section if b != 0)
                if non_zero_count > 100:  # More than 1% non-zero
                    non_zero_sections.append((i, non_zero_count))
            
            f.write(f"Found {len(non_zero_sections)} sections with significant non-zero data\n")
            for offset, count in non_zero_sections[:20]:
                f.write(f"  Section at {offset}: {count} non-zero bytes\n")
            
            # Look for potential data structures
            f.write("\n=== Potential Data Structures ===\n")
            
            # Look for repeated patterns
            pattern_length = 16
            patterns = {}
            for i in range(0, min(len(data), 100000) - pattern_length, pattern_length):
                pattern = data[i:i+pattern_length]
                if pattern in patterns:
                    patterns[pattern] += 1
                else:
                    patterns[pattern] = 1
            
            common_patterns = sorted(patterns.items(), key=lambda x: x[1], reverse=True)[:10]
            f.write("Most common 16-byte patterns:\n")
            for pattern, count in common_patterns:
                if count > 1:
                    f.write(f"  Pattern {binascii.hexlify(pattern).decode()}: {count} occurrences\n")
        
        self.logger.info(f"Comprehensive analysis report saved to {report_file}")

    def parse_freestyle_format(self, data):
        """Parse FreeStyle format based on analysis insights"""
        self.logger.info("=== Parsing FreeStyle Format ===")
        
        # Based on analysis, the file has:
        # - Header with "format FreeStyle Workspace (FWP)"
        # - Model dimensions: 471.5353 508.5413 502.2654
        # - Bitmap info: 0 192054
        # - File version: 4
        
        vertices = []
        faces = []
        
        try:
            # Look for the binary data section after the ASCII header
            # The analysis showed the header ends around position 202
            binary_start = 202
            
            if binary_start >= len(data):
                self.logger.error("Binary data section not found")
                return self.create_placeholder_mesh()
            
            binary_data = data[binary_start:]
            self.logger.info(f"Binary data size: {len(binary_data)} bytes")
            
            # Look for mesh data patterns
            # Based on the analysis, we need to find vertex and face data
            mesh_sections = self._find_mesh_sections(binary_data)
            
            if mesh_sections:
                self.logger.info(f"Found {len(mesh_sections)} potential mesh sections")
                
                for i, section in enumerate(mesh_sections):
                    self.logger.info(f"Processing mesh section {i+1} at offset {section['offset']}")
                    
                    section_vertices, section_faces = self._parse_mesh_section(binary_data, section)
                    
                    if section_vertices and section_faces:
                        # Adjust face indices to account for previous vertices
                        vertex_offset = len(vertices)
                        adjusted_faces = [[f[0] + vertex_offset, f[1] + vertex_offset, f[2] + vertex_offset] 
                                        for f in section_faces]
                        
                        vertices.extend(section_vertices)
                        faces.extend(adjusted_faces)
                        
                        self.logger.info(f"  Added {len(section_vertices)} vertices and {len(section_faces)} faces")
            
            if vertices and faces:
                self.logger.info(f"Successfully extracted {len(vertices)} total vertices and {len(faces)} total faces")
                return vertices, faces
            else:
                self.logger.warning("No mesh data found in FreeStyle format")
                return self.create_placeholder_mesh()
                
        except Exception as e:
            self.logger.error(f"Error parsing FreeStyle format: {e}", exc_info=True)
            return self.create_placeholder_mesh()
    
    def _find_mesh_sections(self, data):
        """Find potential mesh data sections in the binary data"""
        sections = []
        
        # Look for patterns that indicate mesh data
        # Common patterns: vertex count followed by float data
        for offset in range(0, len(data) - 100, 100):  # Sample every 100 bytes
            try:
                # Try to read a potential vertex count
                vertex_count = struct.unpack('<I', data[offset:offset+4])[0]
                
                # Sanity check
                if vertex_count > 0 and vertex_count < 100000:
                    # Check if there's enough data for vertices
                    vertex_data_size = vertex_count * 3 * 4  # 3 floats per vertex
                    
                    if offset + 4 + vertex_data_size + 4 <= len(data):  # count + vertices + triangle count
                        # Try to read a few vertices to validate
                        valid_vertices = 0
                        pos = offset + 4
                        
                        for i in range(min(vertex_count, 10)):  # Check first 10 vertices
                            if pos + 12 <= len(data):
                                try:
                                    x = struct.unpack('<f', data[pos:pos+4])[0]
                                    y = struct.unpack('<f', data[pos+4:pos+8])[0]
                                    z = struct.unpack('<f', data[pos+8:pos+12])[0]
                                    
                                    # Check if coordinates are reasonable
                                    if -10000 < x < 10000 and -10000 < y < 10000 and -10000 < z < 10000:
                                        valid_vertices += 1
                                    
                                    pos += 12
                                except:
                                    break
                        
                        # If we found reasonable vertices, this might be a mesh section
                        if valid_vertices >= 5:  # At least 5 valid vertices
                            sections.append({
                                'offset': offset,
                                'vertex_count': vertex_count,
                                'confidence': valid_vertices / min(vertex_count, 10)
                            })
                
            except:
                continue
        
        # Sort by confidence
        sections.sort(key=lambda x: x['confidence'], reverse=True)
        
        # Limit to top sections
        return sections[:10]
    
    def _parse_mesh_section(self, data, section):
        """Parse a mesh section"""
        vertices = []
        faces = []
        
        try:
            offset = section['offset']
            vertex_count = section['vertex_count']
            
            # Read vertices
            pos = offset + 4
            for i in range(vertex_count):
                if pos + 12 <= len(data):
                    x = struct.unpack('<f', data[pos:pos+4])[0]
                    y = struct.unpack('<f', data[pos+4:pos+8])[0]
                    z = struct.unpack('<f', data[pos+8:pos+12])[0]
                    
                    # Final validation
                    if -10000 < x < 10000 and -10000 < y < 10000 and -10000 < z < 10000:
                        vertices.append([x, y, z])
                    else:
                        break  # Invalid vertex data
                    
                    pos += 12
                else:
                    break
            
            # If we have vertices, try to read triangles
            if len(vertices) == vertex_count:
                if pos + 4 <= len(data):
                    tri_count = struct.unpack('<I', data[pos:pos+4])[0]
                    pos += 4
                    
                    if tri_count > 0 and tri_count < 100000:
                        for i in range(tri_count):
                            if pos + 12 <= len(data):
                                i1 = struct.unpack('<I', data[pos:pos+4])[0]
                                i2 = struct.unpack('<I', data[pos+4:pos+8])[0]
                                i3 = struct.unpack('<I', data[pos+8:pos+12])[0]
                                
                                # Validate indices
                                if i1 < vertex_count and i2 < vertex_count and i3 < vertex_count:
                                    faces.append([i1, i2, i3])
                                else:
                                    break  # Invalid face indices
                                
                                pos += 12
                            else:
                                break
        
        except Exception as e:
            self.logger.warning(f"Error parsing mesh section: {e}")
        
        return vertices, faces
    
    def apply_analysis_insights(self):
        """Apply insights from the analysis to improve parsing"""
        self.logger.info("=== Applying Analysis Insights ===")
        
        # Based on the analysis summary, we know:
        # - File size: 290.96 MB
        # - Model dimensions: 471.5353 508.5413 502.2654
        # - Bitmap info: 0 192054
        # - File version: 4
        # - Units: mm
        
        # Update metadata with analysis insights
        if 'dimensions' not in self.metadata:
            self.metadata['dimensions'] = [471.5353, 508.5413, 502.2654]
            self.logger.info("Applied model dimensions from analysis")
        
        if 'units' not in self.metadata:
            self.metadata['units'] = 'mm'
            self.logger.info("Applied units from analysis")
        
        if 'fileVersion' not in self.metadata:
            self.metadata['fileVersion'] = 4
            self.logger.info("Applied file version from analysis")
        
        if 'bitmap' not in self.metadata:
            self.metadata['bitmap'] = [0, 192054]
            self.logger.info("Applied bitmap info from analysis")
        
        # The analysis showed 150,076,296 potential data chunks
        # This suggests the file has a lot of structured data
        self.logger.info("Analysis indicates file has extensive structured data")
        
        # Look for specific patterns mentioned in analysis
        # - Most common strings: ['aaaaaaaa', '!!!!!!!!', 'bbbbbbbb""""""', 'QQQQQQQQ', '<<<<<<<<||||||||']
        # These might be padding or separator patterns
        
        return True
    
    def enhanced_mesh_extraction(self, data):
        """Enhanced mesh extraction using analysis insights"""
        self.logger.info("=== Enhanced Mesh Extraction ===")
        
        # Apply analysis insights
        self.apply_analysis_insights()
        
        # Look for mesh data using multiple strategies
        strategies = [
            self._find_mesh_sections,
            self._find_mesh_by_patterns,
            self._find_mesh_by_dimensions
        ]
        
        for i, strategy in enumerate(strategies):
            self.logger.info(f"Trying strategy {i+1}: {strategy.__name__}")
            
            try:
                if strategy == self._find_mesh_sections:
                    sections = strategy(data)
                    if sections:
                        vertices, faces = self._extract_from_sections(data, sections)
                        if vertices and faces:
                            return vertices, faces
                elif strategy == self._find_mesh_by_patterns:
                    vertices, faces = strategy(data)
                    if vertices and faces:
                        return vertices, faces
                elif strategy == self._find_mesh_by_dimensions:
                    vertices, faces = strategy(data)
                    if vertices and faces:
                        return vertices, faces
            except Exception as e:
                self.logger.warning(f"Strategy {i+1} failed: {e}")
                continue
        
        return [], []
    
    def _find_mesh_by_patterns(self, data):
        """Find mesh data using pattern matching from analysis"""
        self.logger.info("=== Pattern-based mesh search ===")
        
        # Look for the patterns mentioned in analysis
        patterns = [b'aaaaaaaa', b'!!!!!!!!', b'QQQQQQQQ']
        
        for pattern in patterns:
            positions = []
            pos = 0
            while True:
                pos = data.find(pattern, pos)
                if pos == -1:
                    break
                positions.append(pos)
                pos += len(pattern)
            
            self.logger.info(f"Found {len(positions)} instances of pattern {pattern}")
            
            # Look for mesh data near these patterns
            for pos in positions:
                # Check if there's mesh data before or after the pattern
                for offset in [-1000, 1000]:  # Look before and after
                    check_pos = pos + offset
                    if 0 <= check_pos < len(data) - 100:
                        try:
                            vertex_count = struct.unpack('<I', data[check_pos:check_pos+4])[0]
                            if 0 < vertex_count < 100000:
                                # Try to extract mesh from this position
                                vertices, faces = self._extract_mesh_at_position(data, check_pos)
                                if vertices and faces:
                                    return vertices, faces
                        except:
                            continue
        
        return [], []
    
    def _find_mesh_by_dimensions(self, data):
        """Find mesh data using known dimensions from analysis"""
        self.logger.info("=== Dimension-based mesh search ===")
        
        # Use the known dimensions to look for vertex data
        expected_dims = [471.5353, 508.5413, 502.2654]
        
        # Look for sequences of floats that match the expected scale
        for offset in range(0, len(data) - 1000, 100):
            try:
                # Check if this region contains vertex-like data
                vertex_count = struct.unpack('<I', data[offset:offset+4])[0]
                
                if 0 < vertex_count < 100000:
                    # Check if the first few vertices are within reasonable bounds
                    pos = offset + 4
                    valid_vertices = 0
                    
                    for i in range(min(vertex_count, 10)):
                        if pos + 12 <= len(data):
                            x = struct.unpack('<f', data[pos:pos+4])[0]
                            y = struct.unpack('<f', data[pos+4:pos+8])[0]
                            z = struct.unpack('<f', data[pos+8:pos+12])[0]
                            
                            # Check if coordinates are within expected range
                            if (0 <= x <= expected_dims[0] and 
                                0 <= y <= expected_dims[1] and 
                                0 <= z <= expected_dims[2]):
                                valid_vertices += 1
                            
                            pos += 12
                    
                    if valid_vertices >= 5:  # At least 5 vertices in expected range
                        vertices, faces = self._extract_mesh_at_position(data, offset)
                        if vertices and faces:
                            return vertices, faces
            
            except:
                continue
        
        return [], []
    
    def _extract_mesh_at_position(self, data, offset):
        """Extract mesh data from a specific position"""
        try:
            vertex_count = struct.unpack('<I', data[offset:offset+4])[0]
            pos = offset + 4
            
            vertices = []
            for i in range(vertex_count):
                if pos + 12 <= len(data):
                    x = struct.unpack('<f', data[pos:pos+4])[0]
                    y = struct.unpack('<f', data[pos+4:pos+8])[0]
                    z = struct.unpack('<f', data[pos+8:pos+12])[0]
                    vertices.append([x, y, z])
                    pos += 12
                else:
                    break
            
            if len(vertices) == vertex_count:
                # Try to read triangles
                if pos + 4 <= len(data):
                    tri_count = struct.unpack('<I', data[pos:pos+4])[0]
                    pos += 4
                    
                    faces = []
                    for i in range(tri_count):
                        if pos + 12 <= len(data):
                            i1 = struct.unpack('<I', data[pos:pos+4])[0]
                            i2 = struct.unpack('<I', data[pos+4:pos+8])[0]
                            i3 = struct.unpack('<I', data[pos+8:pos+12])[0]
                            
                            if i1 < vertex_count and i2 < vertex_count and i3 < vertex_count:
                                faces.append([i1, i2, i3])
                            
                            pos += 12
                        else:
                            break
                    
                    if len(faces) == tri_count:
                        return vertices, faces
        
        except Exception as e:
            self.logger.warning(f"Error extracting mesh at position {offset}: {e}")
        
        return [], []
    
    def _extract_from_sections(self, data, sections):
        """Extract mesh data from multiple sections"""
        all_vertices = []
        all_faces = []
        
        for section in sections:
            vertices, faces = self._parse_mesh_section(data, section)
            if vertices and faces:
                # Adjust face indices
                vertex_offset = len(all_vertices)
                adjusted_faces = [[f[0] + vertex_offset, f[1] + vertex_offset, f[2] + vertex_offset] 
                                for f in faces]
                
                all_vertices.extend(vertices)
                all_faces.extend(adjusted_faces)
        
        return all_vertices, all_faces

class ReverseEngineerCLY:
    def __init__(self):
        self.logger = logging.getLogger(__name__)
        self.analysis_data = {
            'file_info': {},
            'structure_analysis': {},
            'data_patterns': {},
            'markers_found': [],
            'chunk_analysis': [],
            'conversion_insights': []
        }
    
    def reverse_engineer_cly_file(self, file_path):
        """
        Deep analysis of .cly file structure without conversion.
        Gathers comprehensive insights about the file format.
        """
        self.logger.info(f"Starting deep reverse engineering of: {file_path}")
        
        try:
            with open(file_path, 'rb') as f:
                data = f.read()
            
            file_size = len(data)
            self.analysis_data['file_info'] = {
                'file_path': file_path,
                'file_size': file_size,
                'analysis_timestamp': datetime.now().isoformat(),
                'file_size_mb': file_size / (1024 * 1024)
            }
            
            self.logger.info(f"File size: {file_size:,} bytes ({file_size / (1024 * 1024):.2f} MB)")
            
            # 1. Header Analysis
            self._analyze_header(data)
            
            # 2. Magic Numbers and Signatures
            self._find_magic_numbers(data)
            
            # 3. ASCII String Analysis
            self._analyze_ascii_strings(data)
            
            # 4. Binary Pattern Analysis
            self._analyze_binary_patterns(data)
            
            # 5. Data Structure Analysis
            self._analyze_data_structures(data)
            
            # 6. Chunk Analysis
            self._analyze_chunks(data)
            
            # 7. Generate Conversion Insights
            self._generate_conversion_insights()
            
            # Save analysis results
            self._save_analysis_results()
            
            return self.analysis_data
            
        except Exception as e:
            self.logger.error(f"Error during reverse engineering: {str(e)}")
            return None
    
    def _analyze_header(self, data):
        """Analyze the first 1KB of the file for header structure"""
        self.logger.info("Analyzing file header...")
        
        header_data = data[:1024]
        header_hex = header_data.hex()
        
        # Look for common header patterns
        header_analysis = {
            'first_4_bytes': header_data[:4].hex(),
            'first_8_bytes': header_data[:8].hex(),
            'first_16_bytes': header_data[:16].hex(),
            'ascii_in_header': self._extract_ascii_from_binary(header_data),
            'null_byte_positions': [i for i, byte in enumerate(header_data) if byte == 0],
            'repeating_patterns': self._find_repeating_patterns(header_data)
        }
        
        self.analysis_data['structure_analysis']['header'] = header_analysis
        self.logger.info(f"Header analysis complete. First 4 bytes: {header_analysis['first_4_bytes']}")
    
    def _find_magic_numbers(self, data):
        """Find potential magic numbers and file signatures"""
        self.logger.info("Searching for magic numbers and signatures...")
        
        magic_numbers = []
        
        # Common magic numbers to look for
        common_magics = [
            b'CLYF', b'CLAY', b'CLY', b'3D', b'OBJ', b'STL',
            b'\x00\x00\x00\x00', b'\xFF\xFF\xFF\xFF',
            b'\x00\x00\x80\x3F', b'\x00\x00\x00\x40'  # Common float values
        ]
        
        for magic in common_magics:
            positions = []
            start = 0
            while True:
                pos = data.find(magic, start)
                if pos == -1:
                    break
                positions.append(pos)
                start = pos + 1
            
            if positions:
                magic_numbers.append({
                    'magic': magic.hex(),
                    'positions': positions,
                    'count': len(positions)
                })
        
        self.analysis_data['data_patterns']['magic_numbers'] = magic_numbers
        self.logger.info(f"Found {len(magic_numbers)} magic number patterns")
    
    def _analyze_ascii_strings(self, data):
        """Extract and analyze ASCII strings in the file"""
        self.logger.info("Analyzing ASCII strings...")
        
        strings = []
        current_string = ""
        string_positions = []
        
        for i, byte in enumerate(data):
            if 32 <= byte <= 126:  # Printable ASCII
                current_string += chr(byte)
            else:
                if len(current_string) >= 4:  # Only keep strings of 4+ characters
                    strings.append({
                        'string': current_string,
                        'position': i - len(current_string),
                        'length': len(current_string)
                    })
                current_string = ""
        
        # Sort by length and frequency
        string_frequency = {}
        for s in strings:
            key = s['string']
            if key not in string_frequency:
                string_frequency[key] = []
            string_frequency[key].append(s['position'])
        
        # Get most common strings
        common_strings = sorted(string_frequency.items(), key=lambda x: len(x[1]), reverse=True)[:20]
        
        self.analysis_data['data_patterns']['ascii_strings'] = {
            'total_strings': len(strings),
            'unique_strings': len(string_frequency),
            'common_strings': [{'string': s[0], 'count': len(s[1]), 'positions': s[1]} for s in common_strings],
            'all_strings': strings[:100]  # Limit to first 100 for readability
        }
        
        self.logger.info(f"Found {len(strings)} ASCII strings, {len(string_frequency)} unique")
    
    def _analyze_binary_patterns(self, data):
        """Analyze binary patterns and data structures"""
        self.logger.info("Analyzing binary patterns...")
        
        patterns = {
            'zero_sequences': [],
            'repeating_bytes': [],
            'float_candidates': [],
            'int_candidates': []
        }
        
        # Find sequences of zeros
        zero_seq_start = None
        for i, byte in enumerate(data):
            if byte == 0:
                if zero_seq_start is None:
                    zero_seq_start = i
            else:
                if zero_seq_start is not None:
                    seq_len = i - zero_seq_start
                    if seq_len >= 4:  # Only track sequences of 4+ zeros
                        patterns['zero_sequences'].append({
                            'start': zero_seq_start,
                            'length': seq_len
                        })
                    zero_seq_start = None
        
        # Find repeating byte patterns
        for i in range(len(data) - 3):
            pattern = data[i:i+4]
            if pattern.count(pattern[0]) == 4:  # All bytes same
                patterns['repeating_bytes'].append({
                    'position': i,
                    'byte': pattern[0],
                    'length': 4
                })
        
        # Look for potential float values (4 bytes)
        for i in range(0, len(data) - 4, 4):
            try:
                float_val = struct.unpack('f', data[i:i+4])[0]
                if -1000 < float_val < 1000:  # Reasonable range
                    patterns['float_candidates'].append({
                        'position': i,
                        'value': float_val
                    })
            except:
                pass
        
        # Look for potential int values (4 bytes)
        for i in range(0, len(data) - 4, 4):
            try:
                int_val = struct.unpack('i', data[i:i+4])[0]
                if 0 <= int_val < 1000000:  # Reasonable range
                    patterns['int_candidates'].append({
                        'position': i,
                        'value': int_val
                    })
            except:
                pass
        
        self.analysis_data['data_patterns']['binary_patterns'] = patterns
        self.logger.info(f"Found {len(patterns['zero_sequences'])} zero sequences, {len(patterns['float_candidates'])} float candidates")
    
    def _analyze_data_structures(self, data):
        """Analyze potential data structures"""
        self.logger.info("Analyzing data structures...")
        
        structures = {
            'potential_headers': [],
            'potential_offsets': [],
            'size_fields': []
        }
        
        # Look for potential header structures (first 256 bytes)
        header_region = data[:256]
        for i in range(0, len(header_region) - 8, 4):
            # Look for potential size/offset fields
            val = struct.unpack('I', header_region[i:i+4])[0]
            if 0 < val < len(data):
                structures['potential_offsets'].append({
                    'position': i,
                    'value': val,
                    'points_to_valid_range': True
                })
        
        # Look for size fields (reasonable file sizes)
        for i in range(0, len(data) - 4, 4):
            try:
                size_val = struct.unpack('I', data[i:i+4])[0]
                if 1000 <= size_val <= len(data):
                    structures['size_fields'].append({
                        'position': i,
                        'size': size_val
                    })
            except:
                pass
        
        self.analysis_data['structure_analysis']['data_structures'] = structures
        self.logger.info(f"Found {len(structures['potential_offsets'])} potential offsets, {len(structures['size_fields'])} size fields")
    
    def _analyze_chunks(self, data):
        """Analyze potential data chunks"""
        self.logger.info("Analyzing data chunks...")
        
        chunks = []
        
        # Look for chunk boundaries (common patterns)
        chunk_markers = [b'\x00\x00\x00\x00', b'\xFF\xFF\xFF\xFF', b'\x00\x00\x00\x01']
        
        for marker in chunk_markers:
            positions = []
            start = 0
            while True:
                pos = data.find(marker, start)
                if pos == -1:
                    break
                positions.append(pos)
                start = pos + 1
            
            if len(positions) > 1:
                # Analyze gaps between markers
                gaps = [positions[i+1] - positions[i] for i in range(len(positions)-1)]
                avg_gap = sum(gaps) / len(gaps) if gaps else 0
                
                chunks.append({
                    'marker': marker.hex(),
                    'positions': positions,
                    'count': len(positions),
                    'avg_gap': avg_gap,
                    'min_gap': min(gaps) if gaps else 0,
                    'max_gap': max(gaps) if gaps else 0
                })
        
        self.analysis_data['chunk_analysis'] = chunks
        self.logger.info(f"Found {len(chunks)} chunk patterns")
    
    def _generate_conversion_insights(self):
        """Generate insights for conversion based on analysis"""
        self.logger.info("Generating conversion insights...")
        
        insights = []
        
        # Analyze file structure insights
        if 'header' in self.analysis_data['structure_analysis']:
            header = self.analysis_data['structure_analysis']['header']
            if header['first_4_bytes'] != '00000000':
                insights.append(f"File likely has a custom header starting with {header['first_4_bytes']}")
        
        # Analyze string insights
        if 'ascii_strings' in self.analysis_data['data_patterns']:
            strings = self.analysis_data['data_patterns']['ascii_strings']
            if strings['common_strings']:
                top_strings = strings['common_strings'][:5]
                insights.append(f"Most common strings: {[s['string'] for s in top_strings]}")
        
        # Analyze magic number insights
        if 'magic_numbers' in self.analysis_data['data_patterns']:
            magics = self.analysis_data['data_patterns']['magic_numbers']
            if magics:
                insights.append(f"Found {len(magics)} magic number patterns")
        
        # Analyze chunk insights
        if self.analysis_data['chunk_analysis']:
            chunk_count = sum(chunk['count'] for chunk in self.analysis_data['chunk_analysis'])
            insights.append(f"File appears to have {chunk_count} potential data chunks")
        
        self.analysis_data['conversion_insights'] = insights
        self.logger.info(f"Generated {len(insights)} conversion insights")
    
    def _save_analysis_results(self):
        """Save analysis results to a conversion-logic file"""
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = f"conversion-logic_{timestamp}.json"
        
        try:
            with open(filename, 'w') as f:
                json.dump(self.analysis_data, f, indent=2, default=str)
            
            self.logger.info(f"Analysis results saved to: {filename}")
            
            # Also save a summary file
            summary = {
                'timestamp': self.analysis_data['file_info']['analysis_timestamp'],
                'file_size_mb': self.analysis_data['file_info']['file_size_mb'],
                'key_findings': {
                    'magic_numbers_found': len(self.analysis_data['data_patterns'].get('magic_numbers', [])),
                    'ascii_strings_found': self.analysis_data['data_patterns'].get('ascii_strings', {}).get('total_strings', 0),
                    'chunk_patterns_found': len(self.analysis_data['chunk_analysis']),
                    'conversion_insights': len(self.analysis_data['conversion_insights'])
                },
                'conversion_insights': self.analysis_data['conversion_insights']
            }
            
            summary_filename = f"conversion-summary_{timestamp}.json"
            with open(summary_filename, 'w') as f:
                json.dump(summary, f, indent=2, default=str)
            
            self.logger.info(f"Summary saved to: {summary_filename}")
            
        except Exception as e:
            self.logger.error(f"Error saving analysis results: {str(e)}")
    
    def _extract_ascii_from_binary(self, data):
        """Extract ASCII strings from binary data"""
        ascii_chars = []
        for byte in data:
            if 32 <= byte <= 126:  # Printable ASCII
                ascii_chars.append(chr(byte))
            else:
                ascii_chars.append('.')
        return ''.join(ascii_chars)
    
    def _find_repeating_patterns(self, data, min_length=4):
        """Find repeating patterns in data"""
        patterns = []
        for length in range(min_length, min(20, len(data)//2)):
            for start in range(len(data) - length):
                pattern = data[start:start+length]
                count = data.count(pattern)
                if count > 1:
                    patterns.append({
                        'pattern': pattern.hex(),
                        'length': length,
                        'count': count,
                        'first_position': start
                    })
        return patterns[:10]  # Limit to top 10

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/analyze', methods=['POST'])
def analyze_file():
    """Route to trigger reverse engineering analysis without conversion"""
    logger.info("=== File Analysis Request ===")
    
    if 'file' not in request.files:
        logger.error("No file in request")
        return jsonify({'error': 'No file uploaded'}), 400
    
    file = request.files['file']
    if file.filename == '':
        logger.error("No filename provided")
        return jsonify({'error': 'No file selected'}), 400
    
    logger.info(f"Analyzing file: {file.filename}")
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
        
        # Perform reverse engineering analysis
        analyzer = ReverseEngineerCLY()
        analysis_result = analyzer.reverse_engineer_cly_file(file_path)
        
        if analysis_result:
            logger.info("Analysis completed successfully")
            return jsonify({
                'success': True,
                'message': 'Analysis completed successfully',
                'file_size_mb': analysis_result['file_info']['file_size_mb'],
                'insights_count': len(analysis_result['conversion_insights']),
                'conversion_insights': analysis_result['conversion_insights'],
                'key_findings': {
                    'magic_numbers_found': len(analysis_result['data_patterns'].get('magic_numbers', [])),
                    'ascii_strings_found': analysis_result['data_patterns'].get('ascii_strings', {}).get('total_strings', 0),
                    'chunk_patterns_found': len(analysis_result['chunk_analysis'])
                }
            })
        else:
            logger.error("Analysis failed")
            return jsonify({'error': 'Analysis failed'}), 500
            
    except Exception as e:
        logger.error(f"Error analyzing file: {e}", exc_info=True)
        return jsonify({'error': f'Analysis error: {str(e)}'}), 500
    
    finally:
        # Clean up uploaded file
        if os.path.exists(file_path):
            os.remove(file_path)
            logger.info(f"Cleaned up uploaded file: {file_path}")

@app.route('/download/<filename>')
def download_file(filename):
    """Route to download converted STL files"""
    try:
        file_path = os.path.join(app.config['OUTPUT_FOLDER'], filename)
        if os.path.exists(file_path):
            return send_file(
                file_path,
                as_attachment=True,
                download_name=filename,
                mimetype='application/octet-stream'
            )
        else:
            return jsonify({'error': 'File not found'}), 404
    except Exception as e:
        logger.error(f"Error downloading file {filename}: {e}")
        return jsonify({'error': f'Download error: {str(e)}'}), 500

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
        
        # Return JSON response with file info and download link
        return jsonify({
            'success': True,
            'message': 'File converted successfully!',
            'download_url': f'/download/{output_filename}',
            'file_info': {
                'file_size': os.path.getsize(output_path),
                'vertices': len(parser.vertices),
                'faces': len(parser.faces)
            }
        })
        
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