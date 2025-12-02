"""
Improved BMP Parser with fixes and enhancements
"""

from Constants import *
from utils import bytes_to_int
from Errors import *

class BMPParser:
    """Parse BMP files manually with improved features"""
    
    def __init__(self, file_bytes):
        self.file_bytes = file_bytes
        self.width = 0
        self.height = 0
        self.bit_depth = 0
        self.compression = 0
        self.pixel_data_offset = 0
        self.channels = 0
        self.row_padding = 0  # MISSING: Row padding calculation
        self.pixel_data = None
        self.is_top_down = False  # MISSING: Handle negative height
        
        self.parse()
    
    def parse(self):
        """Parse BMP structure with improved validation"""
        # 1. Check minimum file size
        if len(self.file_bytes) < 54:
            raise ImageCorruptedError("File too small to be a valid BMP")
        
        # 2. Check signature
        if self.file_bytes[:2] != BMP_SIGNATURE:  # Use constant
            raise ImageCorruptedError("Invalid BMP signature")
        
        # 3. Parse basic headers
        file_size = bytes_to_int(self.file_bytes, 2, 4, 'little')
        self.pixel_data_offset = bytes_to_int(self.file_bytes, 10, 4, 'little')
        
        dib_header_size = bytes_to_int(self.file_bytes, 14, 4, 'little')
        
        self.width = bytes_to_int(self.file_bytes, 18, 4, 'little')
        self.height = bytes_to_int(self.file_bytes, 22, 4, 'little')
        
        # FIX: Handle negative height (top-down BMP)
        if self.height < 0:
            self.height = abs(self.height)
            self.is_top_down = True
        
        # 4. Check color planes (must be 1)
        planes = bytes_to_int(self.file_bytes, 26, 2, 'little')
        if planes != 1:
            raise ImageCorruptedError(f"Invalid BMP: planes = {planes} (must be 1)")
        
        self.bit_depth = bytes_to_int(self.file_bytes, 28, 2, 'little')
        self.compression = bytes_to_int(self.file_bytes, 30, 4, 'little')
        
        # 5. Determine channels based on bit depth
        if self.bit_depth == 24:
            self.channels = 3  # BGR
        elif self.bit_depth == 32:
            self.channels = 4  # BGRA
        elif self.bit_depth == 8:
            self.channels = 1  # Grayscale with palette
        else:
            raise ImageCorruptedError(f"Unsupported bit depth: {self.bit_depth}")
        
        # 6. Validate against supported bit depths
        if self.bit_depth not in SUPPORTED_BIT_DEPTHS:
            raise ImageFormatError(
                f"{self.bit_depth}-bit", 
                f"Unsupported bit depth: {self.bit_depth}"
            )
        
        # 7. Check compression
        if self.compression != 0:
            raise CompressionDetectedError("BMP uses compression - only uncompressed BMP supported")
        
        # NEW: Calculate row padding
        self._calculate_row_padding()
    
    def _calculate_row_padding(self):
        """Calculate row padding (BMP rows must be multiple of 4 bytes)"""
        if self.bit_depth == 8:
            bytes_per_pixel = 1
        elif self.bit_depth == 24:
            bytes_per_pixel = 3
        elif self.bit_depth == 32:
            bytes_per_pixel = 4
        else:
            return
        
        row_size = self.width * bytes_per_pixel
        self.row_padding = (4 - (row_size % 4)) % 4
    
    def get_pixel_data(self):
        """Extract pixel data with proper padding handling"""
        if self.pixel_data is not None:
            return self.pixel_data
        
        # Calculate row size WITH padding
        bytes_per_pixel = self.bit_depth // 8
        if bytes_per_pixel == 0:  # 8-bit
            bytes_per_pixel = 1
        
        row_size_with_padding = self.width * bytes_per_pixel + self.row_padding
        
        pixel_data = bytearray()
        
        # FIX: Handle both top-down and bottom-up BMPs
        for y in range(self.height):
            if self.is_top_down:
                # Top-down: rows in normal order (0 = top row)
                row_index = y
            else:
                # Bottom-up: rows in reverse order (0 = bottom row)
                row_index = self.height - 1 - y
            
            row_offset = self.pixel_data_offset + row_index * row_size_with_padding
            
            for x in range(self.width):
                pixel_offset = row_offset + x * bytes_per_pixel
                
                # Read pixel components
                for c in range(self.channels):
                    byte_pos = pixel_offset + c
                    if byte_pos < len(self.file_bytes):
                        pixel_data.append(self.file_bytes[byte_pos])
                    else:
                        # Pad with 0 if file is truncated
                        pixel_data.append(0)
        
        self.pixel_data = bytes(pixel_data)
        return self.pixel_data
    
    def get_dimensions(self):
        """Return (width, height, channels)"""
        return (self.width, self.height, self.channels)
    
    def has_alpha(self):
        """Check if image has alpha channel"""
        return self.bit_depth == 32
    
    def is_compressed(self):
        """Check if BMP uses compression"""
        return self.compression != 0
    
    # NEW METHODS ADDED:
    
    def get_capacity_bits(self, use_alpha=True):
        """
        Calculate steganography capacity in bits
        """
        if self.bit_depth == 8:
            # 8-bit: we'll convert to 24-bit for steganography
            usable_channels = 3
        elif self.bit_depth == 24:
            usable_channels = 3
        elif self.bit_depth == 32:
            usable_channels = 4 if (use_alpha and self.has_alpha()) else 3
        else:
            return 0
        
        total_pixels = self.width * self.height
        available_bits = total_pixels * usable_channels
        
        # Subtract header bits
        available_bits -= HEADER_SIZE_BITS
        
        return max(0, available_bits)
    
    def get_capacity_bytes(self, use_alpha=True):
        """Get capacity in bytes"""
        bits = self.get_capacity_bits(use_alpha)
        return bits // 8
    
    def get_image_info(self):
        """Get comprehensive image information"""
        capacity_bits = self.get_capacity_bits()
        
        return {
            'width': self.width,
            'height': self.height,
            'bit_depth': self.bit_depth,
            'channels': self.channels,
            'has_alpha': self.has_alpha(),
            'is_compressed': self.is_compressed(),
            'pixel_data_offset': self.pixel_data_offset,
            'row_padding': self.row_padding,
            'is_top_down': self.is_top_down,
            'capacity_bits': capacity_bits,
            'capacity_bytes': capacity_bits // 8
        }
    
    def reconstruct_bmp(self, modified_pixel_data):
        """
        Reconstruct BMP with modified pixel data
        Returns: complete BMP file bytes
        """
        # Keep original headers
        header = self.file_bytes[:self.pixel_data_offset]
        
        # Calculate sizes
        bytes_per_pixel = self.bit_depth // 8
        if bytes_per_pixel == 0:  # 8-bit
            bytes_per_pixel = 1
        
        row_size_with_padding = self.width * bytes_per_pixel + self.row_padding
        
        new_pixel_data = bytearray()
        src_index = 0
        
        for y in range(self.height):
            row_data = bytearray()
            
            for x in range(self.width):
                for c in range(self.channels):
                    if src_index < len(modified_pixel_data):
                        row_data.append(modified_pixel_data[src_index])
                        src_index += 1
                    else:
                        row_data.append(0)  # Pad if needed
            
            # Add row padding
            while len(row_data) < row_size_with_padding:
                row_data.append(0)
            
            new_pixel_data.extend(row_data)
        
        # FIX: Reorder rows for bottom-up BMP
        if not self.is_top_down:
            # Split into rows and reverse order
            rows = []
            for i in range(0, len(new_pixel_data), row_size_with_padding):
                rows.append(new_pixel_data[i:i + row_size_with_padding])
            rows.reverse()
            
            # Flatten back
            new_pixel_data = bytearray()
            for row in rows:
                new_pixel_data.extend(row)
        
        # Combine header and pixel data
        reconstructed = header + bytes(new_pixel_data)
        
        # Update file size in header
        file_size_bytes = int_to_bytes(len(reconstructed), 4, 'little')
        reconstructed = reconstructed[:2] + file_size_bytes + reconstructed[6:]
        
        return bytes(reconstructed)
    
    def print_info(self):
        """Print image information"""
        info = self.get_image_info()
        
        print("=" * 50)
        print("BMP Image Information")
        print("=" * 50)
        print(f"Dimensions: {info['width']} x {info['height']}")
        print(f"Bit depth: {info['bit_depth']}-bit")
        print(f"Channels: {info['channels']}")
        print(f"Alpha channel: {'Yes' if info['has_alpha'] else 'No'}")
        print(f"Compression: {'Yes' if info['is_compressed'] else 'No'}")
        print(f"Row padding: {info['row_padding']} bytes")
        print(f"Orientation: {'Top-down' if info['is_top_down'] else 'Bottom-up'}")
        print("-" * 50)
        print(f"Steganography capacity: {info['capacity_bytes']:,} bytes")
        print(f"                      : {info['capacity_bits']:,} bits")
        print("=" * 50)


# Helper function to create parser from file
def create_bmp_parser(filename):
    """
    Create BMPParser from file with error handling
    """
    from utils import read_file_bytes
    
    try:
        file_bytes = read_file_bytes(filename)
        return BMPParser(file_bytes)
    except Exception as e:
        raise FileReadError(filename, str(e))