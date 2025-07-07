#!/usr/bin/env python3
"""
Simple test script for the CLY to STL converter
"""

import os
import tempfile
import numpy as np
from app import CLYParser

def create_test_cly_file():
    """Create a simple test .cly file for testing"""
    test_content = """format FreeStyle Workspace (FWP)
version FreeForm Modeling/135/Tue Dec 29 10:12:32 2009/V10.0
units mm 
modelDimensions 10.0 10.0 10.0
bitmap 0 1000 
fileVersion 4
coarseTerm -1
endHeader

FFDYNPKTObjectListMain
FFDYNPKTModelInfo
numVoxels 1000
numTris 100
"""
    
    with tempfile.NamedTemporaryFile(mode='w', suffix='.cly', delete=False) as f:
        f.write(test_content)
        return f.name

def test_parser():
    """Test the CLY parser"""
    print("Testing CLY Parser...")
    
    # Create test file
    test_file = create_test_cly_file()
    print(f"Created test file: {test_file}")
    
    try:
        # Parse the file
        parser = CLYParser(test_file)
        success = parser.parse()
        
        if success:
            print("✅ Parser test passed!")
            print(f"Metadata: {parser.metadata}")
            print(f"Vertices: {len(parser.vertices)}")
            print(f"Faces: {len(parser.faces)}")
        else:
            print("❌ Parser test failed!")
            
    except Exception as e:
        print(f"❌ Parser test failed with exception: {e}")
    
    finally:
        # Clean up
        if os.path.exists(test_file):
            os.remove(test_file)

if __name__ == '__main__':
    test_parser() 