"""
Main Encoding Module for BMP Steganography
Handles complete encoding workflow with user-friendly interface
"""

from Constants import *
from utils import *
from Errors import *
from BMP_parser import BMPParser

# =============================================================================
# ENCODING WORKFLOW
# =============================================================================

class SteganographyEncoder:
    """
    Main encoder class for BMP steganography
    Handles complete encoding workflow with error handling
    """
    
    def __init__(self, verbose=False):
        """
        Initialize encoder
        
        Args:
            verbose: Whether to print progress information
        """
        self.verbose = verbose
        self.progress_callback = None
    
    def _log(self, message):
        """Log message if verbose mode is enabled"""
        if self.verbose:
            print(f"[ENCODER] {message}")
    
    def _update_progress(self, stage, percentage, message=""):
        """Update progress if callback is set"""
        if self.progress_callback:
            self.progress_callback(stage, percentage, message)
    
    def encode_file(self, input_bmp, message_file, output_bmp, use_alpha=True, password=None):
        """
        Encode message from file into BMP
        
        Args:
            input_bmp: Path to input BMP file
            message_file: Path to text file containing message
            output_bmp: Path for output BMP file
            use_alpha: Whether to use alpha channel (32-bit only)
            password: Optional password for encryption
        
        Returns:
            Tuple: (success, details_or_error)
        """
        try:
            # Read message from file
            self._log(f"Reading message from: {message_file}")
            self._update_progress("reading_message", 10, "Reading message file")
            
            with open(message_file, 'r', encoding='utf-8') as f:
                message = f.read()
            
            if not message:
                raise InvalidMessageError("Message file is empty")
            
            self._log(f"Message length: {len(message)} characters")
            
            # Encode message
            return self.encode_message(input_bmp, message, output_bmp, use_alpha, password)
            
        except FileNotFoundError:
            raise FileReadError(message_file, "Message file not found")
        except Exception as e:
            raise EncodingError(f"Failed to encode from file: {str(e)}")
    
    def encode_message(self, input_bmp, message, output_bmp, use_alpha=True, password=None):
        """
        Encode text message into BMP
        
        Args:
            input_bmp: Path to input BMP file
            message: Text message to hide
            output_bmp: Path for output BMP file
            use_alpha: Whether to use alpha channel (32-bit only)
            password: Optional password for encryption
        
        Returns:
            Tuple: (success, details)
        """
        try:
            self._log(f"Starting encoding: {input_bmp} -> {output_bmp}")
            self._log(f"Message length: {len(message)} characters")
            
            # =============================================================
            # STAGE 1: VALIDATION AND PREPARATION
            # =============================================================
            self._update_progress("validation", 20, "Validating inputs")
            
            # Validate output path
            self._validate_output_path(output_bmp)
            
            # Read and validate BMP
            self._log("Reading and validating BMP file...")
            bmp_data = read_file_bytes(input_bmp)
            parser = BMPParser(bmp_data)
            
            # Get image info
            image_info = parser.get_image_info()
            self._log_image_info(image_info)
            
            # =============================================================
            # STAGE 2: MESSAGE PREPARATION
            # =============================================================
            self._update_progress("message_prep", 40, "Preparing message")
            
            from stego_core import prepare_message_for_encoding
            
            try:
                binary_message = prepare_message_for_encoding(message, password)
            except MessageTooLargeError as e:
                # Calculate actual capacity
                capacity_bytes = parser.get_capacity_bytes(use_alpha)
                raise InsufficientCapacityError(
                    required=len(message),
                    available=capacity_bytes
                )
            
            message_bits = len(binary_message)
            self._log(f"Binary message size: {message_bits} bits ({message_bits//8} bytes)")
            
            # =============================================================
            # STAGE 3: CAPACITY CHECK
            # =============================================================
            self._update_progress("capacity_check", 50, "Checking capacity")
            
            capacity_bits = parser.get_capacity_bits(use_alpha)
            capacity_bytes = capacity_bits // 8
            
            if message_bits > capacity_bits:
                self._log(f"❌ INSUFFICIENT CAPACITY")
                self._log(f"   Required: {message_bits} bits ({message_bits//8} bytes)")
                self._log(f"   Available: {capacity_bits} bits ({capacity_bytes} bytes)")
                self._log(f"   Shortfall: {message_bits - capacity_bits} bits")
                
                raise InsufficientCapacityError(
                    required=message_bits // 8,
                    available=capacity_bytes
                )
            
            # Calculate usage percentage
            usage_percent = (message_bits / capacity_bits) * 100
            self._log(f"✅ Capacity check passed: {usage_percent:.1f}% of capacity used")
            
            # =============================================================
            # STAGE 4: EXTRACT AND MODIFY PIXELS
            # =============================================================
            self._update_progress("pixel_extraction", 60, "Extracting pixels")
            
            self._log("Extracting pixel data...")
            pixel_data, has_alpha, is_grayscale = parser.get_pixel_array()
            
            # Adjust use_alpha based on actual image
            if use_alpha and not has_alpha:
                self._log("Warning: Image doesn't have alpha channel, using RGB only")
                use_alpha = False
            
            self._update_progress("encoding", 70, "Encoding message into pixels")
            
            from stego_core import encode_binary_in_pixels
            self._log("Encoding message into pixels...")
            
            encoded_pixels = encode_binary_in_pixels(
                pixel_data, 
                binary_message, 
                use_alpha=use_alpha,
                strategy='sequential'
            )
            
            # =============================================================
            # STAGE 5: ANALYZE CHANGES
            # =============================================================
            self._update_progress("analysis", 80, "Analyzing changes")
            
            from stego_core import estimate_visual_impact
            impact = estimate_visual_impact(pixel_data, encoded_pixels)
            
            self._log("✓ Encoding complete")
            self._log(f"  Pixels changed: {impact['changed_pixels']:,} ({impact['change_percentage']:.4f}%)")
            self._log(f"  Estimated quality: {impact['quality_assessment']}")
            
            # =============================================================
            # STAGE 6: RECONSTRUCT AND SAVE BMP
            # =============================================================
            self._update_progress("reconstruction", 90, "Reconstructing BMP")
            
            self._log("Reconstructing BMP file...")
            new_bmp_data = parser.reconstruct_bmp(encoded_pixels, has_alpha, is_grayscale)
            
            self._log(f"Saving to: {output_bmp}")
            write_file_bytes(output_bmp, new_bmp_data)
            
            # =============================================================
            # STAGE 7: VERIFICATION
            # =============================================================
            self._update_progress("verification", 95, "Verifying encoding")
            
            # Quick verification by checking file was written
            output_size = get_file_size(output_bmp)
            if output_size == 0:
                raise FileWriteError(output_bmp, "Output file is empty")
            
            self._log(f"Output file size: {output_size:,} bytes")
            
            # Optional: Verify encoding by decoding (slower but thorough)
            if self.verbose:
                verify_success = self._verify_encoding(output_bmp, message, password)
                if verify_success:
                    self._log("✅ Verification passed: Message can be decoded correctly")
                else:
                    self._log("⚠️  Verification warning: Could not verify decoding")
            
            self._update_progress("complete", 100, "Encoding complete")
            
            # =============================================================
            # PREPARE RESULTS
            # =============================================================
            result_details = {
                'success': True,
                'input_file': input_bmp,
                'output_file': output_bmp,
                'message_length': len(message),
                'message_bits': message_bits,
                'image_width': image_info['width'],
                'image_height': image_info['height'],
                'bit_depth': image_info['bit_depth'],
                'has_alpha': has_alpha,
                'used_alpha': use_alpha and has_alpha,
                'is_grayscale': is_grayscale,
                'capacity_bits': capacity_bits,
                'capacity_bytes': capacity_bytes,
                'usage_percent': usage_percent,
                'changed_pixels': impact['changed_pixels'],
                'change_percentage': impact['change_percentage'],
                'estimated_psnr': impact['estimated_psnr_db'],
                'quality_assessment': impact['quality_assessment'],
                'output_size': output_size,
                'password_protected': password is not None
            }
            
            return True, result_details
            
        except SteganographyError:
            # Re-raise our custom errors
            raise
        except Exception as e:
            # Wrap unexpected errors
            raise EncodingError(f"Encoding failed: {str(e)}")
    
    def _validate_output_path(self, output_path):
        """Validate output file path"""
        import os
        
        # Check if output directory exists and is writable
        output_dir = os.path.dirname(output_path)
        if output_dir and not os.path.exists(output_dir):
            try:
                os.makedirs(output_dir)
                self._log(f"Created output directory: {output_dir}")
            except:
                raise FileWriteError(output_path, "Cannot create output directory")
        
        # Check if we can write to directory
        if output_dir and not os.access(output_dir, os.W_OK):
            raise FileWriteError(output_path, "No write permission for output directory")
        
        # Check if file exists and warn
        if os.path.exists(output_path):
            self._log(f"Warning: Output file exists and will be overwritten: {output_path}")
    
    def _log_image_info(self, info):
        """Log image information"""
        self._log(f"Image: {info['width']} x {info['height']} pixels")
        self._log(f"Bit depth: {info['bit_depth']}-bit")
        self._log(f"Channels: {info['channels']}")
        self._log(f"Alpha: {'Yes' if info['has_alpha'] else 'No'}")
        self._log(f"Capacity: {info['capacity_bytes']:,} bytes")
    
    def _verify_encoding(self, encoded_bmp, original_message, password=None):
        """
        Verify encoding by decoding and comparing
        
        Note: This is optional and can be slow for large images
        """
        try:
            from decoder import decode_message_from_bmp
            
            success, decoded_message, metadata = decode_message_from_bmp(
                encoded_bmp, 
                use_alpha=True,
                password=password
            )
            
            if success and decoded_message == original_message:
                return True
            else:
                return False
                
        except:
            return False  # Verification failed, but encoding might still be OK
    
    def get_encoding_summary(self, result_details):
        """
        Get user-friendly encoding summary
        
        Args:
            result_details: Details dictionary from encode_message
        
        Returns:
            Formatted summary string
        """
        if not result_details.get('success', False):
            return "Encoding failed"
        
        summary = []
        summary.append("=" * 60)
        summary.append("ENCODING SUCCESSFUL")
        summary.append("=" * 60)
        summary.append(f"Input: {result_details['input_file']}")
        summary.append(f"Output: {result_details['output_file']}")
        summary.append(f"Message: {result_details['message_length']} characters")
        summary.append(f"Image: {result_details['image_width']}x{result_details['image_height']} "
                      f"{result_details['bit_depth']}-bit")
        summary.append(f"Alpha channel used: {'Yes' if result_details['used_alpha'] else 'No'}")
        summary.append(f"Grayscale: {'Yes' if result_details['is_grayscale'] else 'No'}")
        summary.append("-" * 60)
        summary.append(f"Capacity used: {result_details['usage_percent']:.1f}%")
        summary.append(f"  Available: {result_details['capacity_bytes']:,} bytes")
        summary.append(f"  Used: {result_details['message_bits']//8:,} bytes")
        summary.append(f"Pixels modified: {result_details['changed_pixels']:,} "
                      f"({result_details['change_percentage']:.4f}%)")
        summary.append(f"Estimated quality: {result_details['quality_assessment']} "
                      f"(PSNR: {result_details['estimated_psnr']:.1f} dB)")
        summary.append(f"Password protected: {'Yes' if result_details['password_protected'] else 'No'}")
        summary.append("=" * 60)
        
        return "\n".join(summary)


# =============================================================================
# SIMPLIFIED ENCODING FUNCTIONS (for easy use)
# =============================================================================

def encode_message_simple(input_bmp, message, output_bmp, use_alpha=True, verbose=True):
    """
    Simple one-function encoding interface
    
    Args:
        input_bmp: Path to input BMP file
        message: Text message to hide
        output_bmp: Path for output BMP file
        use_alpha: Whether to use alpha channel
        verbose: Print progress information
    
    Returns:
        Tuple: (success, details_or_error_message)
    """
    encoder = SteganographyEncoder(verbose=verbose)
    
    try:
        success, details = encoder.encode_message(
            input_bmp, message, output_bmp, use_alpha
        )
        
        if verbose:
            print(encoder.get_encoding_summary(details))
        
        return success, details
        
    except SteganographyError as e:
        if verbose:
            print(f"\n❌ ENCODING FAILED: {e}")
        return False, str(e)
    
    except Exception as e:
        if verbose:
            print(f"\n❌ UNEXPECTED ERROR: {str(e)}")
        return False, f"Unexpected error: {str(e)}"


def encode_file_simple(input_bmp, message_file, output_bmp, use_alpha=True, verbose=True):
    """
    Simple interface for encoding from file
    
    Args:
        input_bmp: Path to input BMP file
        message_file: Path to text file with message
        output_bmp: Path for output BMP file
        use_alpha: Whether to use alpha channel
        verbose: Print progress information
    
    Returns:
        Tuple: (success, details_or_error_message)
    """
    encoder = SteganographyEncoder(verbose=verbose)
    
    try:
        success, details = encoder.encode_file(
            input_bmp, message_file, output_bmp, use_alpha
        )
        
        if verbose:
            print(encoder.get_encoding_summary(details))
        
        return success, details
        
    except SteganographyError as e:
        if verbose:
            print(f"\n❌ ENCODING FAILED: {e}")
        return False, str(e)
    
    except Exception as e:
        if verbose:
            print(f"\n❌ UNEXPECTED ERROR: {str(e)}")
        return False, f"Unexpected error: {str(e)}"


# =============================================================================
# PROGRESS TRACKING UTILITIES
# =============================================================================

class ProgressTracker:
    """Track and display encoding progress"""
    
    def __init__(self, total_stages=7):
        self.total_stages = total_stages
        self.current_stage = 0
        self.stage_names = [
            "Initializing",
            "Reading BMP",
            "Preparing message",
            "Checking capacity",
            "Encoding pixels",
            "Analyzing changes",
            "Saving file",
            "Verifying",
            "Complete"
        ]
    
    def update(self, stage, percentage, message=""):
        """Update progress display"""
        stage_name = self.stage_names[min(stage, len(self.stage_names)-1)]
        
        # Simple text progress
        bar_length = 40
        filled = int(bar_length * percentage / 100.0)
        bar = '█' * filled + '░' * (bar_length - filled)
        
        if message:
            print(f"\r{bar} {percentage:5.1f}% | {stage_name:20s} | {message}", end='', flush=True)
        else:
            print(f"\r{bar} {percentage:5.1f}% | {stage_name:20s}", end='', flush=True)
        
        if percentage >= 100:
            print()  # New line when complete


# =============================================================================
# BATCH ENCODING
# =============================================================================

def batch_encode(messages, input_bmp_template, output_bmp_template, use_alpha=True):
    """
    Encode multiple messages into multiple BMPs
    
    Args:
        messages: List of messages to encode
        input_bmp_template: Template for input BMP paths (use {index})
        output_bmp_template: Template for output BMP paths (use {index})
        use_alpha: Whether to use alpha channel
    
    Returns:
        List of (success, details) tuples
    """
    results = []
    total = len(messages)
    
    print(f"Starting batch encoding of {total} messages")
    print("=" * 60)
    
    for i, message in enumerate(messages, 1):
        print(f"\nEncoding message {i}/{total}:")
        print(f"  Length: {len(message)} characters")
        
        # Generate file paths
        input_bmp = input_bmp_template.format(index=i)
        output_bmp = output_bmp_template.format(index=i)
        
        try:
            success, details = encode_message_simple(
                input_bmp, message, output_bmp, use_alpha, verbose=False
            )
            
            if success:
                print(f"  ✅ Success: {output_bmp}")
                results.append((True, details))
            else:
                print(f"  ❌ Failed: {details}")
                results.append((False, details))
                
        except Exception as e:
            print(f"  ❌ Error: {str(e)}")
            results.append((False, str(e)))
    
    print("\n" + "=" * 60)
    
    # Summary
    success_count = sum(1 for success, _ in results if success)
    print(f"Batch complete: {success_count}/{total} successful")
    
    return results


# =============================================================================
# TEST FUNCTIONS
# =============================================================================

def test_encoder():
    """Test encoder functionality"""
    print("Testing Steganography Encoder...")
    
    try:
        # Create a test BMP
        from bmp_parser import create_test_bmp
        
        test_bmp = create_test_bmp(width=50, height=50, bit_depth=24)
        test_input = "test_input.bmp"
        test_output = "test_output.bmp"
        
        # Save test BMP
        write_file_bytes(test_input, test_bmp)
        
        # Test message
        test_message = "This is a test message for steganography!"
        
        # Create encoder
        encoder = SteganographyEncoder(verbose=True)
        
        # Encode
        print(f"\nEncoding test message: '{test_message}'")
        success, details = encoder.encode_message(
            test_input, test_message, test_output, use_alpha=False
        )
        
        if success:
            print("\n✅ Encoding test passed!")
            print(f"Output file: {test_output}")
            print(f"File size: {get_file_size(test_output):,} bytes")
            
            # Clean up test files
            import os
            if os.path.exists(test_input):
                os.remove(test_input)
            if os.path.exists(test_output):
                os.remove(test_output)
            
            return True
        else:
            print("\n❌ Encoding test failed")
            return False
            
    except Exception as e:
        print(f"\n❌ Test failed with error: {str(e)}")
        return False


# =============================================================================
# COMMAND LINE INTERFACE
# =============================================================================

def encode_from_command_line():
    """Command line interface for encoding"""
    import sys
    import argparse
    
    parser = argparse.ArgumentParser(description='Encode message into BMP using steganography')
    parser.add_argument('input', help='Input BMP file')
    parser.add_argument('output', help='Output BMP file')
    parser.add_argument('-m', '--message', help='Message to hide (use -f for file)')
    parser.add_argument('-f', '--file', help='Text file containing message')
    parser.add_argument('-a', '--alpha', action='store_true', help='Use alpha channel (32-bit only)')
    parser.add_argument('-p', '--password', help='Password for encryption')
    parser.add_argument('-q', '--quiet', action='store_true', help='Quiet mode (minimal output)')
    parser.add_argument('-v', '--verbose', action='store_true', help='Verbose mode')
    
    args = parser.parse_args()
    
    # Determine verbose level
    verbose = args.verbose
    if args.quiet:
        verbose = False
    
    # Check message source
    if args.message and args.file:
        print("Error: Specify either --message or --file, not both")
        sys.exit(1)
    
    if not args.message and not args.file:
        print("Error: Specify message with --message or --file")
        sys.exit(1)
    
    # Create encoder
    encoder = SteganographyEncoder(verbose=verbose)
    
    try:
        if args.message:
            # Encode from command line message
            success, details = encoder.encode_message(
                args.input,
                args.message,
                args.output,
                use_alpha=args.alpha,
                password=args.password
            )
        else:
            # Encode from file
            success, details = encoder.encode_file(
                args.input,
                args.file,
                args.output,
                use_alpha=args.alpha,
                password=args.password
            )
        
        if success:
            print("\n" + encoder.get_encoding_summary(details))
            sys.exit(0)
        else:
            print(f"\n❌ Encoding failed: {details}")
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
    # If run directly, run tests
    print("=" * 60)
    print("STEGANOGRAPHY ENCODER")
    print("=" * 60)
    
    # Check if we should run tests or command line interface
    import sys
    
    if len(sys.argv) > 1:
        # Run command line interface
        encode_from_command_line()
    else:
        # Run tests
        if test_encoder():
            print("\n✅ All encoder tests passed!")
        else:
            print("\n❌ Encoder tests failed!")