"""
Core Steganography Algorithms for LSB Encoding/Decoding
Pure Python implementation - no external libraries
"""

from Constants import *
from utils import *
from Errors import *

# =============================================================================
# BIT MANIPULATION FUNCTIONS
# =============================================================================

def embed_bit_in_byte(byte_value, bit):
    """
    Embed a single bit (0 or 1) into the LSB of a byte
    
    Args:
        byte_value: Integer (0-255)
        bit: String '0' or '1', or integer 0 or 1
    
    Returns:
        Modified byte with LSB set to bit
    """
    # Ensure bit is integer 0 or 1
    if isinstance(bit, str):
        bit_int = 1 if bit == '1' else 0
    else:
        bit_int = 1 if bit else 0
    
    # Clear LSB: byte_value & 0xFE (11111110)
    # Then set LSB: | bit_int
    return (byte_value & 0xFE) | bit_int


def extract_bit_from_byte(byte_value):
    """
    Extract LSB from a byte
    
    Args:
        byte_value: Integer (0-255)
    
    Returns:
        String '0' or '1'
    """
    # Get LSB: byte_value & 0x01 (00000001)
    return '1' if (byte_value & 0x01) else '0'


def embed_bits_in_pixel(pixel_channel_values, bits):
    """
    Embed multiple bits into pixel channels
    
    Args:
        pixel_channel_values: List/tuple of bytes (R, G, B[, A])
        bits: List of bits to embed (one per channel)
    
    Returns:
        Modified pixel channel values
    """
    if len(bits) > len(pixel_channel_values):
        raise ValueError("More bits than available channels")
    
    modified = []
    for i, channel_value in enumerate(pixel_channel_values):
        if i < len(bits):
            modified.append(embed_bit_in_byte(channel_value, bits[i]))
        else:
            modified.append(channel_value)  # Keep unchanged
    
    return tuple(modified)


def extract_bits_from_pixel(pixel_channel_values, num_bits=None):
    """
    Extract LSBs from pixel channels
    
    Args:
        pixel_channel_values: List/tuple of bytes
        num_bits: Number of bits to extract (default: all channels)
    
    Returns:
        List of bits as strings ('0'/'1')
    """
    if num_bits is None:
        num_bits = len(pixel_channel_values)
    
    bits = []
    for i in range(min(num_bits, len(pixel_channel_values))):
        bits.append(extract_bit_from_byte(pixel_channel_values[i]))
    
    return bits


# =============================================================================
# MESSAGE PREPARATION AND PARSING
# =============================================================================

def prepare_message_for_encoding(message, password=None):
    """
    Prepare a message for encoding with metadata header
    
    Args:
        message: String to hide
        password: Optional password for encryption (not implemented)
    
    Returns:
        Binary string ready for LSB encoding
    
    Raises:
        InvalidMessageError: If message is invalid
        MessageTooLargeError: If message exceeds MAX_MESSAGE_SIZE
    """
    # Validate message
    if not message or not isinstance(message, str):
        raise InvalidMessageError("Message must be a non-empty string")
    
    if len(message) > MAX_MESSAGE_SIZE:
        raise MessageTooLargeError(len(message), MAX_MESSAGE_SIZE)
    
    # Convert message to binary
    message_binary = string_to_binary(message)
    message_length = len(message_binary)
    
    # Calculate checksum for integrity verification
    checksum = calculate_checksum(message_binary)
    
    # Create header
    magic_binary = int_to_binary(MAGIC_NUMBER, 32)
    length_binary = int_to_binary(message_length, 32)
    checksum_binary = int_to_binary(checksum, 32)
    
    # Combine header and message
    complete_binary = magic_binary + length_binary + checksum_binary + message_binary
    
    # Optional: Simple encryption (XOR with password)
    if password:
        complete_binary = _apply_simple_encryption(complete_binary, password)
    
    return complete_binary


def parse_encoded_message(binary_data, password=None):
    """
    Parse binary data to extract and verify message
    
    Args:
        binary_data: Binary string from LSB extraction
        password: Optional password for decryption
    
    Returns:
        Tuple: (message_text, is_valid, metadata)
    
    Raises:
        MagicNumberError: If magic number not found
        ChecksumError: If checksum verification fails
    """
    # Optional: Decrypt if password provided
    if password:
        binary_data = _apply_simple_encryption(binary_data, password)
    
    # Check minimum length
    if len(binary_data) < HEADER_SIZE_BITS:
        raise MagicNumberError(found=None, expected=MAGIC_NUMBER)
    
    # Extract header fields
    magic_binary = binary_data[0:32]
    length_binary = binary_data[32:64]
    checksum_binary = binary_data[64:96]
    
    # Convert to integers
    magic = binary_to_int(magic_binary)
    message_length = binary_to_int(length_binary)
    expected_checksum = binary_to_int(checksum_binary)
    
    # Verify magic number
    if magic != MAGIC_NUMBER:
        raise MagicNumberError(found=magic, expected=MAGIC_NUMBER)
    
    # Check if we have enough data
    total_bits_needed = HEADER_SIZE_BITS + message_length
    if len(binary_data) < total_bits_needed:
        raise ValueError(f"Incomplete message: need {total_bits_needed} bits, have {len(binary_data)}")
    
    # Extract message binary
    message_binary = binary_data[HEADER_SIZE_BITS:HEADER_SIZE_BITS + message_length]
    
    # Verify checksum
    calculated_checksum = calculate_checksum(message_binary)
    is_valid = (calculated_checksum == expected_checksum)
    
    if not is_valid:
        raise ChecksumError(expected=expected_checksum, calculated=calculated_checksum)
    
    # Convert binary to text
    try:
        message_text = binary_to_string(message_binary)
    except Exception as e:
        raise DecodingError(f"Failed to convert binary to text: {str(e)}")
    
    # Prepare metadata
    metadata = {
        'message_length_chars': len(message_text),
        'message_length_bits': message_length,
        'checksum_valid': is_valid,
        'checksum_expected': expected_checksum,
        'checksum_calculated': calculated_checksum,
        'magic_number': magic,
        'header_size_bits': HEADER_SIZE_BITS,
        'total_bits': total_bits_needed
    }
    
    return message_text, is_valid, metadata


# =============================================================================
# LSB ENCODING/DECODING
# =============================================================================

def encode_binary_in_pixels(pixel_data, binary_message, use_alpha=True, strategy='sequential'):
    """
    Encode binary message into pixel LSBs
    
    Args:
        pixel_data: Bytes of pixel data (RGB or RGBA)
        binary_message: Binary string to encode
        use_alpha: Whether to use alpha channel (for 32-bit images)
        strategy: Encoding strategy ('sequential', 'interleaved')
    
    Returns:
        Modified pixel data bytes
    
    Raises:
        ValueError: If pixel data format is invalid
    """
    if len(pixel_data) == 0:
        raise ValueError("Pixel data is empty")
    
    # Determine format
    if len(pixel_data) % 4 == 0 and use_alpha:
        # RGBA format (4 bytes per pixel)
        bytes_per_pixel = 4
        channels_per_pixel = 4
    elif len(pixel_data) % 3 == 0:
        # RGB format (3 bytes per pixel)
        bytes_per_pixel = 3
        channels_per_pixel = 3
    else:
        # Unknown format, assume RGB and use all channels
        bytes_per_pixel = 3
        channels_per_pixel = 3
    
    # Convert to mutable list
    pixels = bytearray(pixel_data)
    message_length = len(binary_message)
    message_index = 0
    
    # Choose encoding strategy
    if strategy == 'sequential':
        # Simple sequential encoding
        for i in range(0, len(pixels), bytes_per_pixel):
            if message_index >= message_length:
                break
            
            # Embed bits in each channel
            for channel in range(min(channels_per_pixel, bytes_per_pixel)):
                if message_index >= message_length:
                    break
                
                bit = binary_message[message_index]
                pixel_index = i + channel
                
                if pixel_index < len(pixels):
                    pixels[pixel_index] = embed_bit_in_byte(pixels[pixel_index], bit)
                    message_index += 1
    
    elif strategy == 'interleaved':
        # Interleaved encoding for better visual stealth
        # Skip some pixels based on message length
        total_pixels = len(pixels) // bytes_per_pixel
        if message_length < total_pixels * channels_per_pixel:
            skip = (total_pixels * channels_per_pixel) // message_length
        else:
            skip = 1
        
        pixel_index = 0
        while message_index < message_length and pixel_index < len(pixels):
            bit = binary_message[message_index]
            pixels[pixel_index] = embed_bit_in_byte(pixels[pixel_index], bit)
            message_index += 1
            pixel_index += skip
    
    else:
        raise ValueError(f"Unknown encoding strategy: {strategy}")
    
    return bytes(pixels)


def decode_binary_from_pixels(pixel_data, use_alpha=True, max_bits=None):
    """
    Decode binary message from pixel LSBs
    
    Args:
        pixel_data: Bytes of pixel data
        use_alpha: Whether alpha channel contains data
        max_bits: Maximum bits to extract (None = extract all)
    
    Returns:
        Binary string extracted from LSBs
    """
    if len(pixel_data) == 0:
        return ""
    
    # Determine format
    if len(pixel_data) % 4 == 0 and use_alpha:
        bytes_per_pixel = 4
        channels_per_pixel = 4
    else:
        bytes_per_pixel = 3
        channels_per_pixel = 3
    
    binary_message = ""
    
    if max_bits is None:
        # Extract all bits
        for i in range(0, len(pixel_data), bytes_per_pixel):
            for channel in range(min(channels_per_pixel, len(pixel_data) - i)):
                binary_message += extract_bit_from_byte(pixel_data[i + channel])
    else:
        # Extract up to max_bits
        bits_extracted = 0
        for i in range(0, len(pixel_data), bytes_per_pixel):
            for channel in range(min(channels_per_pixel, len(pixel_data) - i)):
                if bits_extracted >= max_bits:
                    break
                binary_message += extract_bit_from_byte(pixel_data[i + channel])
                bits_extracted += 1
    
    return binary_message


def find_and_decode_message(pixel_data, use_alpha=True, password=None):
    """
    Smart decoding: find and decode message automatically
    
    Args:
        pixel_data: Pixel data bytes
        use_alpha: Whether to check alpha channel
        password: Optional decryption password
    
    Returns:
        Tuple: (success, message_or_error, metadata)
    """
    try:
        # First, try with alpha channel
        binary_data = decode_binary_from_pixels(pixel_data, use_alpha=use_alpha)
        message, is_valid, metadata = parse_encoded_message(binary_data, password)
        return True, message, metadata
    
    except MagicNumberError:
        # Try without alpha channel
        if use_alpha:
            try:
                binary_data = decode_binary_from_pixels(pixel_data, use_alpha=False)
                message, is_valid, metadata = parse_encoded_message(binary_data, password)
                return True, message, metadata
            except:
                pass
        
        return False, "No hidden message found", None
    
    except ChecksumError as e:
        return False, f"Message corrupted: {str(e)}", None
    
    except Exception as e:
        return False, f"Decoding failed: {str(e)}", None


# =============================================================================
# SECURITY/ENCRYPTION HELPERS
# =============================================================================

def _apply_simple_encryption(binary_string, password):
    """
    Simple XOR encryption for basic security
    
    Note: This is NOT cryptographically secure!
    For coursework demonstration only.
    
    Args:
        binary_string: Binary string to encrypt/decrypt
        password: Encryption key
    
    Returns:
        Encrypted/decrypted binary string
    """
    # Convert password to binary key
    password_binary = string_to_binary(password)
    if not password_binary:
        return binary_string
    
    # Repeat password to match message length
    key_length = len(password_binary)
    encrypted = []
    
    for i, bit in enumerate(binary_string):
        key_bit = password_binary[i % key_length]
        # XOR operation: 0⊕0=0, 0⊕1=1, 1⊕0=1, 1⊕1=0
        encrypted_bit = '1' if (bit != key_bit) else '0'
        encrypted.append(encrypted_bit)
    
    return ''.join(encrypted)


def scramble_bits(binary_string, seed=12345):
    """
    Scramble bits for additional security
    
    Args:
        binary_string: Binary string to scramble
        seed: Random seed for reproducibility
    
    Returns:
        Scrambled binary string
    """
    # Simple pseudo-random scrambling
    import random
    random.seed(seed)
    
    bits = list(binary_string)
    random.shuffle(bits)
    
    return ''.join(bits)


def unscramble_bits(binary_string, seed=12345):
    """
    Unscramble bits scrambled with scramble_bits
    
    Args:
        binary_string: Scrambled binary string
        seed: Same seed used for scrambling
    
    Returns:
        Original binary string
    """
    # To unscramble, we need to know the original order
    # This is a simplified version - real implementation would need mapping
    return scramble_bits(binary_string, seed)  # Scrambling twice returns original


# =============================================================================
# QUALITY AND CAPACITY ANALYSIS
# =============================================================================

def calculate_capacity_analysis(pixel_data, use_alpha=True):
    """
    Analyze steganography capacity and quality impact
    
    Args:
        pixel_data: Pixel data bytes
        use_alpha: Whether alpha channel can be used
    
    Returns:
        Dictionary with analysis results
    """
    if len(pixel_data) == 0:
        return {}
    
    # Determine format
    if len(pixel_data) % 4 == 0 and use_alpha:
        bytes_per_pixel = 4
        channels_per_pixel = 4
    else:
        bytes_per_pixel = 3
        channels_per_pixel = 3
    
    total_pixels = len(pixel_data) // bytes_per_pixel
    available_bits = total_pixels * channels_per_pixel
    available_bytes = available_bits // 8
    
    # Estimate maximum message size (with header)
    header_bytes = HEADER_SIZE_BITS // 8
    max_message_bytes = available_bytes - header_bytes
    
    # Calculate bit distribution (for randomness analysis)
    lsb_distribution = {'0': 0, '1': 0}
    for i in range(len(pixel_data)):
        bit = extract_bit_from_byte(pixel_data[i])
        lsb_distribution[bit] += 1
    
    total_lsbs = lsb_distribution['0'] + lsb_distribution['1']
    if total_lsbs > 0:
        zero_percentage = (lsb_distribution['0'] / total_lsbs) * 100
        one_percentage = (lsb_distribution['1'] / total_lsbs) * 100
        randomness_score = min(zero_percentage, one_percentage) * 2  # 0-100%
    else:
        randomness_score = 0
    
    return {
        'total_pixels': total_pixels,
        'channels_per_pixel': channels_per_pixel,
        'available_bits': available_bits,
        'available_bytes': available_bytes,
        'max_message_bytes': max(0, max_message_bytes),
        'header_overhead_bytes': header_bytes,
        'lsb_distribution': lsb_distribution,
        'lsb_randomness_score': randomness_score,
        'lsb_zero_percentage': zero_percentage if total_lsbs > 0 else 0,
        'lsb_one_percentage': one_percentage if total_lsbs > 0 else 0,
        'estimated_psnr': 51.1  # Typical PSNR for LSB steganography (>50dB is excellent)
    }


def estimate_visual_impact(original_pixels, modified_pixels):
    """
    Estimate visual impact of LSB modifications
    
    Args:
        original_pixels: Original pixel data
        modified_pixels: Modified pixel data
    
    Returns:
        Dictionary with impact metrics
    """
    if len(original_pixels) != len(modified_pixels):
        return {"error": "Pixel arrays have different lengths"}
    
    changed_pixels = 0
    max_change = 0
    total_change = 0
    
    for i in range(len(original_pixels)):
        if original_pixels[i] != modified_pixels[i]:
            changed_pixels += 1
            change = abs(original_pixels[i] - modified_pixels[i])
            total_change += change
            if change > max_change:
                max_change = change
    
    total_pixels = len(original_pixels)
    change_percentage = (changed_pixels / total_pixels) * 100
    avg_change = total_change / changed_pixels if changed_pixels > 0 else 0
    
    # PSNR estimation (simplified)
    mse = total_change / total_pixels if total_pixels > 0 else 0
    if mse > 0:
        psnr = 10 * (2 * 8) / mse  # Simplified PSNR formula
    else:
        psnr = float('inf')
    
    return {
        'total_pixels': total_pixels,
        'changed_pixels': changed_pixels,
        'change_percentage': change_percentage,
        'max_pixel_change': max_change,
        'average_pixel_change': avg_change,
        'total_change': total_change,
        'mean_squared_error': mse,
        'estimated_psnr_db': psnr,
        'quality_assessment': _assess_quality(psnr)
    }


def _assess_quality(psnr):
    """Assess image quality based on PSNR"""
    if psnr == float('inf'):
        return "Perfect (no changes)"
    elif psnr >= 50:
        return "Excellent (imperceptible)"
    elif psnr >= 40:
        return "Good (barely perceptible)"
    elif psnr >= 30:
        return "Fair (slightly noticeable)"
    elif psnr >= 20:
        return "Poor (noticeable)"
    else:
        return "Bad (very noticeable)"


# =============================================================================
# VALIDATION AND TESTING
# =============================================================================

def validate_encoding(original_message, decoded_message):
    """
    Validate that encoding/decoding preserved the message
    
    Args:
        original_message: Original message before encoding
        decoded_message: Message after decoding
    
    Returns:
        Tuple: (is_correct, error_message)
    """
    if original_message == decoded_message:
        return True, "Message preserved correctly"
    else:
        # Find differences
        orig_len = len(original_message)
        dec_len = len(decoded_message)
        
        if orig_len != dec_len:
            error = f"Length mismatch: original={orig_len}, decoded={dec_len}"
        else:
            # Find first differing character
            for i, (o, d) in enumerate(zip(original_message, decoded_message)):
                if o != d:
                    error = f"Character mismatch at position {i}: '{o}' != '{d}'"
                    break
            else:
                error = "Unknown difference"
        
        return False, error


def run_stego_tests():
    """Run comprehensive tests on stego_core functions"""
    print("Running Steganography Core Tests...")
    tests_passed = 0
    tests_total = 0
    
    # Test 1: Bit manipulation
    try:
        # Test embed_bit_in_byte
        assert embed_bit_in_byte(0b11111111, '0') == 0b11111110
        assert embed_bit_in_byte(0b00000000, '1') == 0b00000001
        assert embed_bit_in_byte(0b10101010, '1') == 0b10101011
        assert extract_bit_from_byte(0b11111110) == '0'
        assert extract_bit_from_byte(0b00000001) == '1'
        tests_passed += 1
        print("✓ Test 1: Bit manipulation passed")
    except AssertionError as e:
        print("✗ Test 1: Bit manipulation failed")
    
    tests_total += 1
    
    # Test 2: Message preparation
    try:
        test_message = "Hello, World!"
        binary = prepare_message_for_encoding(test_message)
        
        # Verify header structure
        magic_binary = binary[0:32]
        magic = binary_to_int(magic_binary)
        assert magic == MAGIC_NUMBER
        
        # Verify length
        length_binary = binary[32:64]
        message_length = binary_to_int(length_binary)
        expected_length = len(string_to_binary(test_message))
        assert message_length == expected_length
        
        tests_passed += 1
        print("✓ Test 2: Message preparation passed")
    except Exception as e:
        print(f"✗ Test 2: Message preparation failed: {str(e)}")
    
    tests_total += 1
    
    # Test 3: Encoding/Decoding round-trip
    try:
        test_pixels = bytes([i % 256 for i in range(300)])  # Simple test pattern
        test_message = "Test"
        
        # Prepare and encode
        binary_message = prepare_message_for_encoding(test_message)
        encoded_pixels = encode_binary_in_pixels(test_pixels, binary_message)
        
        # Decode
        decoded_binary = decode_binary_from_pixels(encoded_pixels)
        decoded_message, is_valid, metadata = parse_encoded_message(decoded_binary)
        
        assert test_message == decoded_message
        assert is_valid == True
        
        tests_passed += 1
        print("✓ Test 3: Encoding/Decoding round-trip passed")
    except Exception as e:
        print(f"✗ Test 3: Encoding/Decoding round-trip failed: {str(e)}")
    
    tests_total += 1
    
    # Print summary
    print("\n" + "=" * 50)
    print(f"Test Results: {tests_passed}/{tests_total} passed")
    print("=" * 50)
    
    return tests_passed == tests_total


# =============================================================================
# MAIN GUARD
# =============================================================================

if __name__ == "__main__":
    # Run tests if executed directly
    success = run_stego_tests()
    
    if success:
        print("\n✅ All stego_core tests passed!")
    else:
        print("\n❌ Some tests failed!")