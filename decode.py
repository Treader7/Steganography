"""
Main Decoding Module for BMP Steganography
Extracts hidden messages from BMP files with robust error handling
"""

from Constants import *
from utils import *
from Errors import *
from BMP_parser import BMPParser

# =============================================================================
# DECODING WORKFLOW
# =============================================================================

class SteganographyDecoder:
    """
    Main decoder class for BMP steganography
    Handles complete decoding workflow with smart detection
    """
    
    def __init__(self, verbose=False):
        """
        Initialize decoder
        
        Args:
            verbose: Whether to print progress information
        """
        self.verbose = verbose
        self.progress_callback = None
    
    def _log(self, message):
        """Log message if verbose mode is enabled"""
        if self.verbose:
            print(f"[DECODER] {message}")
    
    def _update_progress(self, stage, percentage, message=""):
        """Update progress if callback is set"""
        if self.progress_callback:
            self.progress_callback(stage, percentage, message)
    
    def decode_message(self, input_bmp, use_alpha=True, password=None):
        """
        Decode hidden message from BMP file
        
        Args:
            input_bmp: Path to BMP file with hidden message
            use_alpha: Whether to check alpha channel for data
            password: Optional password for decryption
        
        Returns:
            Tuple: (success, message_or_error, metadata)
        """
        try:
            self._log(f"Starting decoding: {input_bmp}")
            self._update_progress("initializing", 10, "Initializing decoder")
            
            # =============================================================
            # STAGE 1: VALIDATION AND PREPARATION
            # =============================================================
            self._update_progress("validation", 20, "Validating BMP file")
            
            # Check file exists and is readable
            if get_file_size(input_bmp) == 0:
                raise FileReadError(input_bmp, "File is empty or doesn't exist")
            
            # Read and parse BMP
            self._log("Reading and parsing BMP file...")
            bmp_data = read_file_bytes(input_bmp)
            parser = BMPParser(bmp_data)
            
            # Get image info
            image_info = parser.get_image_info()
            self._log_image_info(image_info)
            
            # Adjust use_alpha based on actual image
            if use_alpha and not image_info['has_alpha']:
                self._log("Image doesn't have alpha channel, using RGB only")
                use_alpha = False
            
            # =============================================================
            # STAGE 2: EXTRACT PIXEL DATA
            # =============================================================
            self._update_progress("pixel_extraction", 40, "Extracting pixel data")
            
            self._log("Extracting pixel data...")
            pixel_data, has_alpha, is_grayscale = parser.get_pixel_array()
            
            self._log(f"Pixel data size: {len(pixel_data):,} bytes")
            self._log(f"Image is grayscale: {is_grayscale}")
            
            # =============================================================
            # STAGE 3: EXTRACT BINARY DATA
            # =============================================================
            self._update_progress("binary_extraction", 60, "Extracting binary data")
            
            from stego_core import decode_binary_from_pixels
            self._log("Extracting binary data from LSBs...")
            
            # Try with specified alpha setting first
            binary_data = decode_binary_from_pixels(pixel_data, use_alpha=use_alpha)
            
            # =============================================================
            # STAGE 4: PARSE AND VALIDATE MESSAGE
            # =============================================================
            self._update_progress("parsing", 80, "Parsing and validating message")
            
            from stego_core import parse_encoded_message, find_and_decode_message
            
            self._log("Parsing encoded message...")
            
            # Try to parse with current settings
            try:
                message, is_valid, metadata = parse_encoded_message(binary_data, password)
                self._log(f"✅ Message found and validated!")
                
            except MagicNumberError:
                # Magic number not found - try different settings
                self._log("Magic number not found, trying alternative settings...")
                
                if use_alpha:
                    # Try without alpha channel
                    self._log("Trying without alpha channel...")
                    binary_data = decode_binary_from_pixels(pixel_data, use_alpha=False)
                    
                    try:
                        message, is_valid, metadata = parse_encoded_message(binary_data, password)
                        self._log(f"✅ Message found (without alpha channel)!")
                        use_alpha = False  # Update flag
                    except:
                        # Try the smart finder
                        self._log("Using smart message detection...")
                        success, message, metadata = find_and_decode_message(
                            pixel_data, use_alpha=True, password=password
                        )
                        
                        if not success:
                            raise MagicNumberError(found=None, expected=MAGIC_NUMBER)
                else:
                    # Already tried without alpha, so no message
                    raise MagicNumberError(found=None, expected=MAGIC_NUMBER)
            
            except ChecksumError as e:
                self._log(f"⚠️  Checksum error: {e}")
                raise  # Re-raise for caller to handle
            
            # =============================================================
            # STAGE 5: ANALYZE AND PREPARE RESULTS
            # =============================================================
            self._update_progress("analysis", 90, "Analyzing results")
            
            # Calculate extraction statistics
            extraction_stats = self._calculate_extraction_stats(
                pixel_data, binary_data, metadata
            )
            
            # Combine metadata
            full_metadata = {
                **metadata,
                **extraction_stats,
                'input_file': input_bmp,
                'image_width': image_info['width'],
                'image_height': image_info['height'],
                'bit_depth': image_info['bit_depth'],
                'has_alpha': has_alpha,
                'used_alpha_for_decoding': use_alpha,
                'is_grayscale': is_grayscale,
                'password_protected': password is not None,
                'checksum_valid': metadata.get('checksum_valid', False)
            }
            
            self._update_progress("complete", 100, "Decoding complete")
            
            # Log success
            self._log_decoding_success(message, full_metadata)
            
            return True, message, full_metadata
            
        except SteganographyError:
            # Re-raise our custom errors
            raise
        except Exception as e:
            # Wrap unexpected errors
            raise DecodingError(f"Decoding failed: {str(e)}")
    
    def _log_image_info(self, info):
        """Log image information"""
        self._log(f"Image: {info['width']} x {info['height']} pixels")
        self._log(f"Bit depth: {info['bit_depth']}-bit")
        self._log(f"Channels: {info['channels']}")
        self._log(f"Alpha: {'Yes' if info['has_alpha'] else 'No'}")
        self._log(f"Capacity: {info['capacity_bytes']:,} bytes")
    
    def _calculate_extraction_stats(self, pixel_data, binary_data, metadata):
        """Calculate extraction statistics"""
        total_bits_extracted = len(binary_data)
        message_bits = metadata.get('message_length_bits', 0)
        header_bits = metadata.get('header_size_bits', HEADER_SIZE_BITS)
        
        # Calculate efficiency
        total_pixel_bits = len(pixel_data) * 8  # Each byte has 8 LSBs
        if total_pixel_bits > 0:
            extraction_efficiency = (total_bits_extracted / total_pixel_bits) * 100
        else:
            extraction_efficiency = 0
        
        # Message density (how much of extracted data is actual message)
        if total_bits_extracted > 0:
            message_density = (message_bits / total_bits_extracted) * 100
        else:
            message_density = 0
        
        return {
            'total_bits_extracted': total_bits_extracted,
            'total_bytes_extracted': total_bits_extracted // 8,
            'extraction_efficiency_percent': extraction_efficiency,
            'message_density_percent': message_density,
            'overhead_bits': header_bits,
            'overhead_percent': (header_bits / total_bits_extracted * 100) if total_bits_extracted > 0 else 0
        }
    
    def _log_decoding_success(self, message, metadata):
        """Log successful decoding information"""
        if not self.verbose:
            return
        
        msg_preview = message[:50] + "..." if len(message) > 50 else message
        
        self._log("=" * 60)
        self._log("DECODING SUCCESSFUL")
        self._log("=" * 60)
        self._log(f"Message preview: {msg_preview}")
        self._log(f"Message length: {len(message):,} characters")
        self._log(f"Binary length: {metadata.get('message_length_bits', 0):,} bits")
        self._log(f"Checksum: {'VALID' if metadata.get('checksum_valid') else 'INVALID'}")
        self._log(f"Used alpha channel: {metadata.get('used_alpha_for_decoding', False)}")
        self._log(f"Password protected: {metadata.get('password_protected', False)}")
        self._log("=" * 60)
    
    def decode_to_file(self, input_bmp, output_file, use_alpha=True, password=None):
        """
        Decode message and save to text file
        
        Args:
            input_bmp: Path to BMP file with hidden message
            output_file: Path to save decoded message
            use_alpha: Whether to check alpha channel for data
            password: Optional password for decryption
        
        Returns:
            Tuple: (success, metadata_or_error)
        """
        try:
            self._log(f"Decoding to file: {input_bmp} -> {output_file}")
            
            # Decode message
            success, message, metadata = self.decode_message(
                input_bmp, use_alpha, password
            )
            
            if not success:
                return False, "Failed to decode message"
            
            # Save to file
            self._log(f"Saving message to: {output_file}")
            
            with open(output_file, 'w', encoding='utf-8') as f:
                f.write(message)
            
            self._log(f"✅ Message saved successfully")
            
            return True, metadata
            
        except Exception as e:
            raise DecodingError(f"Failed to decode to file: {str(e)}")
    
    def scan_file(self, input_bmp):
        """
        Scan file for hidden messages without extracting
        
        Args:
            input_bmp: Path to BMP file to scan
        
        Returns:
            Dictionary with scan results
        """
        try:
            self._log(f"Scanning file: {input_bmp}")
            
            # Read and parse BMP
            bmp_data = read_file_bytes(input_bmp)
            parser = BMPParser(bmp_data)
            
            # Get image info
            image_info = parser.get_image_info()
            pixel_data, has_alpha, is_grayscale = parser.get_pixel_array()
            
            from stego_core import calculate_capacity_analysis
            capacity_info = calculate_capacity_analysis(pixel_data, use_alpha=has_alpha)
            
            # Check for magic number in LSBs
            from stego_core import decode_binary_from_pixels
            
            # Try with alpha
            binary_with_alpha = decode_binary_from_pixels(pixel_data, use_alpha=True)
            has_magic_alpha = self._check_for_magic_number(binary_with_alpha)
            
            # Try without alpha
            binary_without_alpha = decode_binary_from_pixels(pixel_data, use_alpha=False)
            has_magic_no_alpha = self._check_for_magic_number(binary_without_alpha)
            
            # Analyze LSB randomness
            lsb_randomness = capacity_info.get('lsb_randomness_score', 0)
            is_suspicious = lsb_randomness > 70  # High randomness suggests hidden data
            
            scan_results = {
                'file_exists': True,
                'is_valid_bmp': True,
                'image_info': image_info,
                'capacity_info': capacity_info,
                'detected_magic_with_alpha': has_magic_alpha,
                'detected_magic_without_alpha': has_magic_no_alpha,
                'lsb_randomness_score': lsb_randomness,
                'is_suspicious': is_suspicious,
                'suspicion_level': self._get_suspicion_level(lsb_randomness, has_magic_alpha or has_magic_no_alpha),
                'recommendation': self._get_scan_recommendation(has_magic_alpha, has_magic_no_alpha, is_suspicious)
            }
            
            return scan_results
            
        except SteganographyError as e:
            return {
                'file_exists': True,
                'is_valid_bmp': False,
                'error': str(e)
            }
        except Exception as e:
            return {
                'file_exists': False,
                'error': str(e)
            }
    
    def _check_for_magic_number(self, binary_data):
        """Check if binary data contains our magic number"""
        if len(binary_data) < 32:
            return False
        
        try:
            magic_binary = binary_data[0:32]
            magic = binary_to_int(magic_binary)
            return magic == MAGIC_NUMBER
        except:
            return False
    
    def _get_suspicion_level(self, randomness_score, has_magic):
        """Determine suspicion level based on analysis"""
        if has_magic:
            return "HIGH - Contains hidden data (magic number found)"
        elif randomness_score > 80:
            return "MEDIUM - High LSB randomness (likely contains hidden data)"
        elif randomness_score > 60:
            return "LOW - Moderate LSB randomness (might contain hidden data)"
        else:
            return "NONE - No evidence of hidden data"
    
    def _get_scan_recommendation(self, has_magic_alpha, has_magic_no_alpha, is_suspicious):
        """Get recommendation based on scan results"""
        if has_magic_alpha or has_magic_no_alpha:
            return "This image contains hidden data. Use decode function to extract."
        elif is_suspicious:
            return "Image shows signs of hidden data. Try decoding with different settings."
        else:
            return "No hidden data detected. Image appears normal."
    
    def get_decoding_summary(self, metadata):
        """
        Get user-friendly decoding summary
        
        Args:
            metadata: Metadata dictionary from decode_message
        
        Returns:
            Formatted summary string
        """
        summary = []
        summary.append("=" * 60)
        summary.append("DECODING RESULTS")
        summary.append("=" * 60)
        
        if 'input_file' in metadata:
            summary.append(f"Input file: {metadata['input_file']}")
        
        if 'message_length_chars' in metadata:
            summary.append(f"Message length: {metadata['message_length_chars']:,} characters")
        
        if 'message_length_bits' in metadata:
            summary.append(f"Binary length: {metadata['message_length_bits']:,} bits")
        
        if 'checksum_valid' in metadata:
            summary.append(f"Checksum: {'VALID ✅' if metadata['checksum_valid'] else 'INVALID ❌'}")
        
        if 'used_alpha_for_decoding' in metadata:
            summary.append(f"Alpha channel used: {'Yes' if metadata['used_alpha_for_decoding'] else 'No'}")
        
        if 'password_protected' in metadata:
            summary.append(f"Password protected: {'Yes' if metadata['password_protected'] else 'No'}")
        
        if 'extraction_efficiency_percent' in metadata:
            summary.append(f"Extraction efficiency: {metadata['extraction_efficiency_percent']:.1f}%")
        
        if 'message_density_percent' in metadata:
            summary.append(f"Message density: {metadata['message_density_percent']:.1f}%")
        
        summary.append("=" * 60)
        
        return "\n".join(summary)


# =============================================================================
# SIMPLIFIED DECODING FUNCTIONS (for easy use)
# =============================================================================

def decode_message_simple(input_bmp, use_alpha=True, password=None, verbose=True):
    """
    Simple one-function decoding interface
    
    Args:
        input_bmp: Path to BMP file with hidden message
        use_alpha: Whether to check alpha channel for data
        password: Optional password for decryption
        verbose: Print progress information
    
    Returns:
        Tuple: (success, message_or_error, metadata)
    """
    decoder = SteganographyDecoder(verbose=verbose)
    
    try:
        success, message, metadata = decoder.decode_message(
            input_bmp, use_alpha, password
        )
        
        if verbose:
            print(decoder.get_decoding_summary(metadata))
        
        return success, message, metadata
        
    except SteganographyError as e:
        if verbose:
            print(f"\n❌ DECODING FAILED: {e}")
        return False, str(e), None
    
    except Exception as e:
        if verbose:
            print(f"\n❌ UNEXPECTED ERROR: {str(e)}")
        return False, f"Unexpected error: {str(e)}", None


def decode_to_file_simple(input_bmp, output_file, use_alpha=True, password=None, verbose=True):
    """
    Simple interface for decoding to file
    
    Args:
        input_bmp: Path to BMP file with hidden message
        output_file: Path to save decoded message
        use_alpha: Whether to check alpha channel for data
        password: Optional password for decryption
        verbose: Print progress information
    
    Returns:
        Tuple: (success, metadata_or_error)
    """
    decoder = SteganographyDecoder(verbose=verbose)
    
    try:
        success, metadata = decoder.decode_to_file(
            input_bmp, output_file, use_alpha, password
        )
        
        if verbose:
            print(f"\n✅ Message saved to: {output_file}")
            print(decoder.get_decoding_summary(metadata))
        
        return success, metadata
        
    except SteganographyError as e:
        if verbose:
            print(f"\n❌ DECODING FAILED: {e}")
        return False, str(e)
    
    except Exception as e:
        if verbose:
            print(f"\n❌ UNEXPECTED ERROR: {str(e)}")
        return False, f"Unexpected error: {str(e)}"


def scan_file_simple(input_bmp, verbose=True):
    """
    Simple interface for scanning files
    
    Args:
        input_bmp: Path to BMP file to scan
        verbose: Print results
    
    Returns:
        Dictionary with scan results
    """
    decoder = SteganographyDecoder(verbose=verbose)
    
    try:
        results = decoder.scan_file(input_bmp)
        
        if verbose:
            print("\n" + "=" * 60)
            print("FILE SCAN RESULTS")
            print("=" * 60)
            
            if not results.get('file_exists', False):
                print(f"❌ File not found: {input_bmp}")
            elif not results.get('is_valid_bmp', False):
                print(f"❌ Invalid BMP file: {results.get('error', 'Unknown error')}")
            else:
                info = results['image_info']
                print(f"Image: {info['width']}x{info['height']} {info['bit_depth']}-bit")
                print(f"Alpha channel: {'Yes' if info['has_alpha'] else 'No'}")
                
                cap = results['capacity_info']
                print(f"Capacity: {cap['available_bytes']:,} bytes")
                print(f"LSB randomness: {cap['lsb_randomness_score']:.1f}%")
                
                print(f"\nMagic number detection:")
                print(f"  With alpha: {'FOUND ✅' if results['detected_magic_with_alpha'] else 'Not found'}")
                print(f"  Without alpha: {'FOUND ✅' if results['detected_magic_without_alpha'] else 'Not found'}")
                
                print(f"\nSuspicion level: {results['suspicion_level']}")
                print(f"Recommendation: {results['recommendation']}")
            
            print("=" * 60)
        
        return results
        
    except Exception as e:
        if verbose:
            print(f"\n❌ SCAN FAILED: {str(e)}")
        
        return {
            'file_exists': False,
            'error': str(e)
        }


# =============================================================================
# BATCH DECODING
# =============================================================================

def batch_decode(file_list, use_alpha=True, password=None):
    """
    Decode multiple BMP files
    
    Args:
        file_list: List of BMP file paths
        use_alpha: Whether to check alpha channel
        password: Optional password for decryption
    
    Returns:
        List of (success, message, metadata) tuples
    """
    results = []
    total = len(file_list)
    
    print(f"Starting batch decoding of {total} files")
    print("=" * 60)
    
    for i, input_bmp in enumerate(file_list, 1):
        print(f"\nDecoding file {i}/{total}:")
        print(f"  File: {input_bmp}")
        
        try:
            success, message, metadata = decode_message_simple(
                input_bmp, use_alpha, password, verbose=False
            )
            
            if success:
                msg_preview = message[:30] + "..." if len(message) > 30 else message
                print(f"  ✅ Success: {msg_preview}")
                results.append((True, message, metadata))
            else:
                print(f"  ❌ Failed: {message}")
                results.append((False, message, None))
                
        except Exception as e:
            print(f"  ❌ Error: {str(e)}")
            results.append((False, str(e), None))
    
    print("\n" + "=" * 60)
    
    # Summary
    success_count = sum(1 for success, _, _ in results if success)
    print(f"Batch complete: {success_count}/{total} successful")
    
    return results


# =============================================================================
# RECOVERY FUNCTIONS
# =============================================================================

def brute_force_decode(input_bmp, password_list=None, use_alpha_options=None):
    """
    Try decoding with different settings (for recovery)
    
    Args:
        input_bmp: Path to BMP file
        password_list: List of passwords to try
        use_alpha_options: List of use_alpha settings to try
    
    Returns:
        List of (settings, success, message) tuples
    """
    if password_list is None:
        password_list = [None, "password", "secret", "123456", ""]
    
    if use_alpha_options is None:
        use_alpha_options = [True, False]
    
    results = []
    
    print("Starting brute force decoding...")
    print(f"Trying {len(password_list)} passwords × {len(use_alpha_options)} settings")
    print("=" * 60)
    
    for password in password_list:
        for use_alpha in use_alpha_options:
            settings = {
                'password': password,
                'use_alpha': use_alpha
            }
            
            print(f"Trying: alpha={use_alpha}, password='{password}'")
            
            try:
                success, message, metadata = decode_message_simple(
                    input_bmp, use_alpha, password, verbose=False
                )
                
                if success:
                    print(f"  ✅ SUCCESS!")
                    results.append((settings, True, message, metadata))
                    # Found it, but continue to see if others work
                else:
                    results.append((settings, False, message, None))
                    
            except Exception as e:
                results.append((settings, False, str(e), None))
    
    print("\n" + "=" * 60)
    
    # Filter successful results
    successful = [(s, m, md) for s, success, m, md in results if success]
    
    if successful:
        print(f"Found {len(successful)} successful decoding(s):")
        for i, (settings, message, metadata) in enumerate(successful, 1):
            print(f"\n{i}. Settings: alpha={settings['use_alpha']}, password='{settings['password']}'")
            print(f"   Message preview: {message[:50]}...")
    else:
        print("No successful decodings found")
    
    return results


# =============================================================================
# TEST FUNCTIONS
# =============================================================================

def test_decoder():
    """Test decoder functionality"""
    print("Testing Steganography Decoder...")
    
    try:
        # First, we need an encoded image to test with
        # Create a test image and encode a message
        from bmp_parser import create_test_bmp
        from encoder import encode_message_simple
        
        # Create test BMP
        test_bmp = create_test_bmp(width=50, height=50, bit_depth=24)
        test_input = "test_decode_input.bmp"
        test_output = "test_decode_output.bmp"
        
        # Save test BMP
        write_file_bytes(test_input, test_bmp)
        
        # Encode a test message
        test_message = "This is a secret test message for decoding!"
        
        print(f"\nEncoding test message: '{test_message}'")
        encode_success, encode_details = encode_message_simple(
            test_input, test_message, test_output, use_alpha=False, verbose=False
        )
        
        if not encode_success:
            print("❌ Failed to create test encoded image")
            return False
        
        # Now test decoding
        print(f"\nDecoding from: {test_output}")
        decoder = SteganographyDecoder(verbose=True)
        
        decode_success, decoded_message, metadata = decoder.decode_message(
            test_output, use_alpha=False
        )
        
        if decode_success and decoded_message == test_message:
            print("\n✅ Decoding test passed!")
            print(f"Original: '{test_message}'")
            print(f"Decoded:  '{decoded_message}'")
            
            # Test scan function
            print("\nTesting scan function...")
            scan_results = decoder.scan_file(test_output)
            
            if scan_results.get('detected_magic_without_alpha', False):
                print("✅ Scan correctly detected hidden data")
            else:
                print("⚠️  Scan did not detect hidden data")
            
            # Clean up test files
            import os
            if os.path.exists(test_input):
                os.remove(test_input)
            if os.path.exists(test_output):
                os.remove(test_output)
            
            return True
        else:
            print("\n❌ Decoding test failed")
            print(f"Original: '{test_message}'")
            print(f"Decoded:  '{decoded_message}'")
            return False
            
    except Exception as e:
        print(f"\n❌ Test failed with error: {str(e)}")
        import traceback
        traceback.print_exc()
        return False


# =============================================================================
# COMMAND LINE INTERFACE
# =============================================================================

def decode_from_command_line():
    """Command line interface for decoding"""
    import sys
    import argparse
    
    parser = argparse.ArgumentParser(description='Decode hidden message from BMP file')
    parser.add_argument('input', help='Input BMP file with hidden message')
    parser.add_argument('-o', '--output', help='Output text file (optional)')
    parser.add_argument('-a', '--alpha', action='store_true', help='Use alpha channel (32-bit only)')
    parser.add_argument('-p', '--password', help='Password for decryption')
    parser.add_argument('-s', '--scan', action='store_true', help='Scan file without decoding')
    parser.add_argument('-b', '--brute', action='store_true', help='Brute force with common passwords')
    parser.add_argument('-q', '--quiet', action='store_true', help='Quiet mode (minimal output)')
    parser.add_argument('-v', '--verbose', action='store_true', help='Verbose mode')
    
    args = parser.parse_args()
    
    # Determine verbose level
    verbose = args.verbose
    if args.quiet:
        verbose = False
    
    # Create decoder
    decoder = SteganographyDecoder(verbose=verbose)
    
    try:
        if args.scan:
            # Scan mode
            results = decoder.scan_file(args.input)
            
            if verbose:
                print("\n" + decoder.get_decoding_summary(results))
            
            # Exit with appropriate code
            if results.get('detected_magic_with_alpha', False) or \
               results.get('detected_magic_without_alpha', False):
                sys.exit(0)  # Success: found hidden data
            else:
                sys.exit(2)  # Special exit code: no hidden data found
                
        elif args.brute:
            # Brute force mode
            results = brute_force_decode(args.input)
            sys.exit(0 if any(success for _, success, _, _ in results) else 1)
            
        elif args.output:
            # Decode to file
            success, metadata = decoder.decode_to_file(
                args.input, args.output, args.alpha, args.password
            )
            
            if success:
                if verbose:
                    print(decoder.get_decoding_summary(metadata))
                print(f"\n✅ Message saved to: {args.output}")
                sys.exit(0)
            else:
                print(f"\n❌ Failed to decode: {metadata}")
                sys.exit(1)
                
        else:
            # Decode to console
            success, message, metadata = decoder.decode_message(
                args.input, args.alpha, args.password
            )
            
            if success:
                if verbose:
                    print(decoder.get_decoding_summary(metadata))
                    print("\n" + "=" * 60)
                    print("DECODED MESSAGE:")
                    print("=" * 60)
                
                print(message)
                
                if verbose:
                    print("=" * 60)
                
                sys.exit(0)
            else:
                print(f"\n❌ Failed to decode: {message}")
                sys.exit(1)
                
    except SteganographyError as e:
        print(f"\n❌ ERROR: {e}")
        sys.exit(1)
    except Exception as e:
        print(f"\n❌ UNEXPECTED ERROR: {str(e)}")
        sys.exit(1)


# =============================================================================
# MAIN GUARD
# =============================================================================

if __name__ == "__main__":
    # If run directly, run tests or command line interface
    print("=" * 60)
    print("STEGANOGRAPHY DECODER")
    print("=" * 60)
    
    # Check if we should run tests or command line interface
    import sys
    
    if len(sys.argv) > 1:
        # Run command line interface
        decode_from_command_line()
    else:
        # Run tests
        if test_decoder():
            print("\n✅ All decoder tests passed!")
        else:
            print("\n❌ Decoder tests failed!")