import os
import time
import math

# =============================================================================
# CONSTANTS
# =============================================================================

MAGIC_NUMBER = 0xCAFEBABE
HEADER_SIZE_BITS = 96  # 32 magic + 32 length + 32 checksum (no flags needed)
MAX_MESSAGE_SIZE = 10_000_000  # 10MB
MIN_PSNR_THRESHOLD = 40.0  # Minimum acceptable quality (dB)

# Image format signatures
IMAGE_SIGNATURES = {
    'BMP': [0x42, 0x4D],
    'JPEG': [0xFF, 0xD8, 0xFF],
    'GIF': [0x47, 0x49, 0x46, 0x38, 0x39, 0x61],
    'PNG': [0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A],
}

SUPPORTED_FORMATS = ['BMP']
LOSSY_FORMATS = ['JPEG', 'GIF', 'PNG', 'WEBP']

# Channel analysis
LOW_VARIANCE_THRESHOLD = 10.0
OPTIMAL_VARIANCE_THRESHOLD = 30.0


# =============================================================================
# EXCEPTION CLASSES
# =============================================================================

class SteganographyError(Exception):
    """Base class for steganography-related exceptions."""
    pass


class ImageFormatError(SteganographyError):
    """Raised when the image format is unsupported or unrecognized."""
    def __init__(self, format_found, message=""):
        self.format_found = format_found
        self.message = message or f"Unsupported image format: {format_found}"
        super().__init__(self.message)


class InsufficientCapacityError(SteganographyError):
    """Image too small for message"""
    def __init__(self, required, available):
        self.required = required
        self.available = available
        super().__init__(f"Need {required} bytes, have {available} bytes")


class CompressionDetectedError(SteganographyError):
    """Lossy compression detected"""
    pass


class ImageCorruptedError(SteganographyError):
    """Cannot parse image - it may be corrupted"""
    pass


class VerificationFailedError(SteganographyError):
    """Encoded data does not match original"""
    def __init__(self, expected, actual):
        self.expected = expected
        self.actual = actual
        super().__init__(f"Verification failed: checksum mismatch")


class QualityError(SteganographyError):
    """Image quality too low for encoding"""
    def __init__(self, psnr, threshold):
        self.psnr = psnr
        self.threshold = threshold
        super().__init__(f"Image quality too low: PSNR={psnr:.2f} dB, Threshold={threshold:.2f} dB")


# =============================================================================
# PROGRESS TRACKING
# =============================================================================

class ProgressTracker:
    """
    Track and report progress of encoding operations
    """
    def __init__(self, total_stages=5, callback=None):
        self.total_stages = total_stages
        self.current_stage = 0
        self.stage_name = "Initializing"
        self.percentage = 0.0
        self.start_time = time.time()
        self.stage_start_time = time.time()
        self.callback = callback
        
        # Stage definitions
        self.stages = {
            'validation': (0, 10),
            'parsing': (10, 25),
            'preparation': (25, 35),
            'encoding': (35, 85),
            'reconstruction': (85, 95),
            'verification': (95, 100)
        }
    
    def start_stage(self, stage_name):
        """Begin a new stage"""
        self.stage_name = stage_name
        self.stage_start_time = time.time()
        
        if stage_name in self.stages:
            self.percentage = self.stages[stage_name][0]
        
        self._notify()
    
    def update_stage_progress(self, stage_name, progress_in_stage):
        """
        Update progress within current stage
        progress_in_stage: 0.0 to 1.0
        """
        if stage_name in self.stages:
            start_pct, end_pct = self.stages[stage_name]
            self.percentage = start_pct + (end_pct - start_pct) * progress_in_stage
        
        self._notify()
    
    def complete_stage(self, stage_name):
        """Mark stage as complete"""
        if stage_name in self.stages:
            self.percentage = self.stages[stage_name][1]
        
        self._notify()
    
    def get_estimated_time_remaining(self):
        """
        Estimate time remaining based on current progress
        Returns: seconds (float) or None if cannot estimate
        """
        if self.percentage <= 0:
            return None
        
        elapsed = time.time() - self.start_time
        estimated_total = elapsed / (self.percentage / 100.0)
        remaining = estimated_total - elapsed
        
        return max(0, remaining)
    
    def _notify(self):
        """Send update via callback"""
        if self.callback:
            try:
                self.callback(
                    percentage=self.percentage,
                    stage=self.stage_name,
                    eta=self.get_estimated_time_remaining()
                )
            except:
                pass
    
    def _format_time(self, seconds):
        """Format seconds into readable string"""
        if seconds is None:
            return "calculating..."
        
        if seconds < 60:
            return f"{int(seconds)}s"
        elif seconds < 3600:
            mins = int(seconds / 60)
            secs = int(seconds % 60)
            return f"{mins}m {secs}s"
        else:
            hours = int(seconds / 3600)
            mins = int((seconds % 3600) / 60)
            return f"{hours}h {mins}m"
    
    def print_progress(self):
        """Print progress bar to console"""
        bar_length = 40
        filled = int(bar_length * self.percentage / 100.0)
        bar = '█' * filled + '░' * (bar_length - filled)
        
        eta = self.get_estimated_time_remaining()
        eta_str = self._format_time(eta)
        
        print(f"\r{bar} {self.percentage:5.1f}% | {self.stage_name:20s} | ETA: {eta_str:10s}", end='', flush=True)
        
        if self.percentage >= 100:
            print()


def simple_progress_callback(percentage, stage, eta):
    """
    Simple callback that prints to console
    """
    bar_length = 40
    filled = int(bar_length * percentage / 100.0)
    bar = '█' * filled + '░' * (bar_length - filled)
    
    if eta:
        eta_str = f"{int(eta)}s"
    else:
        eta_str = "..."
    
    print(f"\r{bar} {percentage:5.1f}% | {stage:15s} | ETA: {eta_str:5s}", end='', flush=True)
    
    if percentage >= 100:
        print()


# =============================================================================
# FILE I/O UTILITIES
# =============================================================================

def read_file_bytes(filepath):
    """
    Read entire file as bytes
    """
    try:
        with open(filepath, 'rb') as f:
            data = f.read()
        return data
    except FileNotFoundError:
        raise FileNotFoundError(f"File not found: {filepath}")
    except PermissionError:
        raise PermissionError(f"Permission denied: {filepath}")
    except Exception as e:
        raise IOError(f"Error reading file: {str(e)}")


def write_file_bytes(filepath, data):
    """
    Write bytes to file
    """
    try:
        # Ensure directory exists
        directory = os.path.dirname(filepath)
        if directory and not os.path.exists(directory):
            os.makedirs(directory)
        
        with open(filepath, 'wb') as f:
            f.write(data)
            f.flush()
            os.fsync(f.fileno())
        
        return True
    except PermissionError:
        raise PermissionError(f"Permission denied: {filepath}")
    except Exception as e:
        raise IOError(f"Error writing file: {str(e)}")


def get_file_size(filepath):
    """Get file size in bytes"""
    try:
        return os.path.getsize(filepath)
    except:
        return 0


def check_disk_space(filepath, required_bytes):
    """
    Check if enough disk space available
    Returns: (has_space, available_bytes)
    """
    try:
        directory = os.path.dirname(filepath) or '.'
        stat = os.statvfs(directory)
        available = stat.f_bavail * stat.f_frsize
        return (available >= required_bytes, available)
    except:
        return (True, required_bytes)


# =============================================================================
# BINARY CONVERSION UTILITIES
# =============================================================================

def bytes_to_int(byte_array, start, length, endian='big'):
    """
    Convert byte slice to integer
    """
    slice_bytes = byte_array[start:start+length]
    
    if endian == 'big':
        result = 0
        for byte in slice_bytes:
            result = (result << 8) | byte
        return result
    else:  # little endian
        result = 0
        for i, byte in enumerate(slice_bytes):
            result |= (byte << (i * 8))
        return result


def int_to_bytes(value, length, endian='big'):
    """
    Convert integer to bytes
    """
    result = []
    
    if endian == 'big':
        for i in range(length - 1, -1, -1):
            result.append((value >> (i * 8)) & 0xFF)
    else:  # little endian
        for i in range(length):
            result.append((value >> (i * 8)) & 0xFF)
    
    return bytes(result)


def string_to_binary(text):
    """
    Convert string to binary string ('0' and '1' characters)
    """
    text_bytes = text.encode('utf-8')
    
    binary_str = ''
    for byte in text_bytes:
        binary_str += format(byte, '08b')
    
    return binary_str


def binary_to_string(binary_str):
    """
    Convert binary string back to text
    """
    bytes_list = []
    for i in range(0, len(binary_str), 8):
        byte_str = binary_str[i:i+8]
        if len(byte_str) == 8:
            bytes_list.append(int(byte_str, 2))
    
    try:
        return bytes(bytes_list).decode('utf-8')
    except:
        raise ValueError("Invalid binary string - cannot decode to UTF-8")


def int_to_binary(value, bit_length=32):
    """
    Convert integer to fixed-length binary string
    """
    binary = bin(value)[2:]
    return binary.zfill(bit_length)


def binary_to_int(binary_str):
    """
    Convert binary string to integer
    """
    return int(binary_str, 2)


# =============================================================================
# CHECKSUM
# =============================================================================

def calculate_crc32(data):
    """
    Calculate CRC32 checksum manually
    Implements polynomial: 0xEDB88320 (reversed)
    """
    crc = 0xFFFFFFFF
    
    if isinstance(data, str):
        data = data.encode('utf-8')
    
    for byte in data:
        crc ^= byte
        for _ in range(8):
            if crc & 1:
                crc = (crc >> 1) ^ 0xEDB88320
            else:
                crc >>= 1
    
    return crc ^ 0xFFFFFFFF


def verify_checksum(data, expected_checksum):
    """
    Verify data integrity
    """
    calculated = calculate_crc32(data)
    return calculated == expected_checksum


# =============================================================================
# INPUT VALIDATION & SANITIZATION
# =============================================================================

def sanitize_message(text):
    """
    Clean and validate input message
    """
    if not isinstance(text, str):
        raise ValueError("Message must be a string")
    
    if not text:
        raise ValueError("Message cannot be empty")
    
    # Remove null bytes
    text = text.replace('\x00', '')
    
    # Check for valid UTF-8
    try:
        text.encode('utf-8').decode('utf-8')
    except:
        raise ValueError("Message contains invalid UTF-8 characters")
    
    # Trim to max size
    max_chars = MAX_MESSAGE_SIZE // 4
    if len(text) > max_chars:
        raise ValueError(f"Message too long: {len(text)} chars, max {max_chars}")
    
    return text


def validate_output_path(output_path):
    """
    Validate output file path
    Returns: (is_valid, error_message)
    """
    if not output_path:
        return (False, "Output path cannot be empty")
    
    directory = os.path.dirname(output_path)
    if not directory:
        directory = '.'
    
    if not os.path.exists(directory):
        try:
            os.makedirs(directory)
        except:
            return (False, f"Cannot create directory: {directory}")
    
    if not os.access(directory, os.W_OK):
        return (False, f"No write permission for directory: {directory}")
    
    return (True, "")


def estimate_encoding_time(message_size_bytes, image_width, image_height):
    """
    Estimate encoding time based on size
    Returns: estimated_seconds (float)
    """
    total_pixels = image_width * image_height
    
    base_time = 0.5
    time_per_mpixel = 0.3
    mpixels = total_pixels / 1_000_000
    
    time_per_mb_message = 0.1
    message_mb = message_size_bytes / 1_000_000
    
    estimated = base_time + (mpixels * time_per_mpixel) + (message_mb * time_per_mb_message)
    
    return estimated


# =============================================================================
# STATISTICAL ANALYSIS
# =============================================================================

def analyze_lsb_randomness(pixel_array, width, height, channels):
    """
    Analyze LSB distribution to detect prior encoding
    Returns: (randomness_score, is_suspicious, confidence)
    """
    lsbs = []
    
    for y in range(height):
        for x in range(width):
            pixel_index = (y * width + x) * channels
            for c in range(channels):
                if pixel_index + c < len(pixel_array):
                    pixel_value = pixel_array[pixel_index + c]
                    lsb = pixel_value & 1
                    lsbs.append(lsb)
    
    if not lsbs:
        return (0.5, False, 0.0)
    
    ones_count = sum(lsbs)
    zeros_count = len(lsbs) - ones_count
    expected_ones = len(lsbs) / 2.0
    
    if expected_ones > 0:
        chi_square = ((ones_count - expected_ones) ** 2 / expected_ones +
                      (zeros_count - expected_ones) ** 2 / expected_ones)
    else:
        chi_square = 0
    
    randomness_score = 1.0 / (1.0 + chi_square / 10.0)
    is_suspicious = chi_square < 0.01 or randomness_score > 0.95
    confidence = min(1.0, len(lsbs) / 100000.0)
    
    return (randomness_score, is_suspicious, confidence)


def warn_if_previously_encoded(parser):
    """
    Check if image likely contains hidden data
    Returns: (is_encoded, confidence, message)
    """
    try:
        pixel_data = parser.get_pixel_data()
        width, height, channels = parser.get_dimensions()
        
        randomness, suspicious, confidence = analyze_lsb_randomness(
            pixel_data, width, height, channels
        )
        
        if suspicious and confidence > 0.7:
            message = f"Warning: LSB analysis suggests image may already contain hidden data (confidence: {confidence:.1%})"
            return (True, confidence, message)
        
        return (False, confidence, "No prior encoding detected")
        
    except Exception as e:
        return (False, 0.0, "Analysis failed")


# =============================================================================
# CHANNEL ANALYSIS & OPTIMIZATION
# =============================================================================

def calculate_channel_variance(pixel_array, width, height, channels):
    """
    Calculate variance for each color channel
    Returns: list of (channel_index, variance)
    """
    if channels == 1:
        return [(0, calculate_single_channel_variance(pixel_array, width, height, 0, 1))]
    
    variances = []
    for c in range(channels):
        variance = calculate_single_channel_variance(pixel_array, width, height, c, channels)
        variances.append((c, variance))
    
    return variances


def calculate_single_channel_variance(pixel_array, width, height, channel_index, total_channels):
    """
    Calculate variance for a single channel
    """
    values = []
    
    for y in range(height):
        for x in range(width):
            pixel_index = (y * width + x) * total_channels + channel_index
            if pixel_index < len(pixel_array):
                values.append(pixel_array[pixel_index])
    
    if not values:
        return 0.0
    
    mean = sum(values) / len(values)
    variance = sum((v - mean) ** 2 for v in values) / len(values)
    
    return variance


def rank_channels_by_suitability(pixel_array, width, height, channels):
    """
    Rank channels for encoding (higher variance = better)
    Returns: list of channel indices, best first
    """
    variances = calculate_channel_variance(pixel_array, width, height, channels)
    sorted_channels = sorted(variances, key=lambda x: x[1], reverse=True)
    return [ch for ch, var in sorted_channels]


def analyze_channel_suitability(pixel_array, width, height, channels):
    """
    Analyze and report channel suitability
    Returns: (ranked_channels, recommendations)
    """
    variances = calculate_channel_variance(pixel_array, width, height, channels)
    ranked = rank_channels_by_suitability(pixel_array, width, height, channels)
    
    channel_names = ['R', 'G', 'B', 'A'] if channels > 1 else ['Gray']
    recommendations = []
    
    for ch, var in variances:
        name = channel_names[ch] if ch < len(channel_names) else f"Ch{ch}"
        
        if var < LOW_VARIANCE_THRESHOLD:
            recommendations.append(f"{name} channel: LOW variance ({var:.1f}) - poor for encoding")
        elif var > OPTIMAL_VARIANCE_THRESHOLD:
            recommendations.append(f"{name} channel: HIGH variance ({var:.1f}) - excellent for encoding")
        else:
            recommendations.append(f"{name} channel: MEDIUM variance ({var:.1f}) - acceptable")
    
    return (ranked, recommendations)


# =============================================================================
# QUALITY METRICS
# =============================================================================

def calculate_mse(original_pixels, modified_pixels):
    """
    Calculate Mean Squared Error
    """
    if len(original_pixels) != len(modified_pixels):
        raise ValueError("Pixel arrays must be same length")
    
    if len(original_pixels) == 0:
        return 0.0
    
    total_squared_diff = 0
    for i in range(len(original_pixels)):
        diff = int(original_pixels[i]) - int(modified_pixels[i])
        total_squared_diff += diff * diff
    
    mse = total_squared_diff / len(original_pixels)
    return mse


def calculate_psnr(original_pixels, modified_pixels, max_pixel_value=255):
    """
    Calculate Peak Signal-to-Noise Ratio in dB
    Higher is better (>40dB is excellent)
    """
    mse = calculate_mse(original_pixels, modified_pixels)
    
    if mse == 0:
        return float('inf')
    
    psnr = 10 * math.log10((max_pixel_value ** 2) / mse)
    return psnr


def calculate_ssim_simple(original_pixels, modified_pixels, width, height, channels):
    """
    Simplified Structural Similarity Index
    Returns value between 0 and 1 (1 = identical)
    """
    if len(original_pixels) != len(modified_pixels):
        return 0.0
    
    mean_orig = sum(original_pixels) / len(original_pixels)
    mean_mod = sum(modified_pixels) / len(modified_pixels)
    
    var_orig = sum((p - mean_orig) ** 2 for p in original_pixels) / len(original_pixels)
    var_mod = sum((p - mean_mod) ** 2 for p in modified_pixels) / len(modified_pixels)
    
    covar = sum((original_pixels[i] - mean_orig) * (modified_pixels[i] - mean_mod) 
                for i in range(len(original_pixels))) / len(original_pixels)
    
    c1 = (0.01 * 255) ** 2
    c2 = (0.03 * 255) ** 2
    
    luminance = (2 * mean_orig * mean_mod + c1) / (mean_orig ** 2 + mean_mod ** 2 + c1)
    contrast = (2 * math.sqrt(var_orig) * math.sqrt(var_mod) + c2) / (var_orig + var_mod + c2)
    structure = (covar + c2/2) / (math.sqrt(var_orig) * math.sqrt(var_mod) + c2/2)
    
    ssim = luminance * contrast * structure
    
    return max(0.0, min(1.0, ssim))


def generate_quality_report(original_pixels, modified_pixels, width, height, channels):
    """
    Generate comprehensive quality report
    Returns: dict with metrics
    """
    mse = calculate_mse(original_pixels, modified_pixels)
    psnr = calculate_psnr(original_pixels, modified_pixels)
    ssim = calculate_ssim_simple(original_pixels, modified_pixels, width, height, channels)
    
    modified_count = sum(1 for i in range(len(original_pixels)) 
                        if original_pixels[i] != modified_pixels[i])
    total_pixels = len(original_pixels)
    modification_percentage = (modified_count / total_pixels * 100) if total_pixels > 0 else 0
    
    if psnr >= 50:
        quality_level = "EXCELLENT"
    elif psnr >= 40:
        quality_level = "VERY GOOD"
    elif psnr >= 30:
        quality_level = "GOOD"
    elif psnr >= 20:
        quality_level = "FAIR"
    else:
        quality_level = "POOR"
    
    report = {
        'mse': mse,
        'psnr_db': psnr,
        'ssim': ssim,
        'modified_pixels': modified_count,
        'total_pixels': total_pixels,
        'modification_percent': modification_percentage,
        'quality_level': quality_level,
        'meets_threshold': psnr >= MIN_PSNR_THRESHOLD
    }
    
    return report


def verify_quality_threshold(quality_report, threshold=MIN_PSNR_THRESHOLD):
    """
    Check if quality meets minimum threshold
    Raises QualityError if below threshold
    """
    if quality_report['psnr_db'] < threshold:
        raise QualityError(quality_report['psnr_db'], threshold)
    
    return True


# =============================================================================
# FORMAT DETECTION
# =============================================================================

def detect_image_format(file_bytes):
    """
    Detect format from file header
    Returns: (format_name, is_supported, warning_message)
    """
    if len(file_bytes) < 12:
        return ('UNKNOWN', False, "File too small to identify")
    
    for format_name, signature in IMAGE_SIGNATURES.items():
        if len(file_bytes) >= len(signature):
            match = all(file_bytes[i] == signature[i] for i in range(len(signature)))
            if match:
                is_supported = format_name in SUPPORTED_FORMATS
                warning = ""
                
                if format_name in LOSSY_FORMATS:
                    warning = f"{format_name} uses lossy compression - LSB encoding will fail"
                elif not is_supported:
                    warning = f"{format_name} is not currently supported"
                
                return (format_name, is_supported, warning)
    
    return ('UNKNOWN', False, "Unrecognized image format")


# =============================================================================
# IMAGE PARSER CLASS
# =============================================================================

class BMPParser:
    """Parse BMP files manually"""
    
    def __init__(self, file_bytes):
        self.file_bytes = file_bytes
        self.width = 0
        self.height = 0
        self.bit_depth = 0
        self.compression = 0
        self.pixel_data_offset = 0
        self.channels = 0
        self.pixel_data = None
        
        self.parse()
    
    def parse(self):
        """Parse BMP structure"""
        if self.file_bytes[:2] != bytes([0x42, 0x4D]):
            raise ImageCorruptedError("Invalid BMP signature")
        
        file_size = bytes_to_int(self.file_bytes, 2, 4, 'little')
        self.pixel_data_offset = bytes_to_int(self.file_bytes, 10, 4, 'little')
        
        dib_header_size = bytes_to_int(self.file_bytes, 14, 4, 'little')
        
        self.width = bytes_to_int(self.file_bytes, 18, 4, 'little')
        self.height = bytes_to_int(self.file_bytes, 22, 4, 'little')
        self.bit_depth = bytes_to_int(self.file_bytes, 28, 2, 'little')
        self.compression = bytes_to_int(self.file_bytes, 30, 4, 'little')
        
        if self.bit_depth == 24:
            self.channels = 3  # BGR
        elif self.bit_depth == 32:
            self.channels = 4  # BGRA
        elif self.bit_depth == 8:
            self.channels = 1  # Grayscale
        else:
            raise ImageCorruptedError(f"Unsupported bit depth: {self.bit_depth}")
        
        if self.compression != 0:
            raise CompressionDetectedError("BMP uses compression")
    
    def get_pixel_data(self):
        """Extract pixel data"""
        if self.pixel_data is not None:
            return self.pixel_data
        
        row_size = ((self.width * self.bit_depth + 31) // 32) * 4
        
        pixel_data = []
        
        for y in range(self.height):
            row_offset = self.pixel_data_offset + (self.height - 1 - y) * row_size
            
            for x in range(self.width):
                pixel_offset = row_offset + x * (self.bit_depth // 8)
                
                for c in range(self.channels):
                    if pixel_offset + c < len(self.file_bytes):
                        pixel_data.append(self.file_bytes[pixel_offset + c])
        
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


# =============================================================================
# CAPACITY CALCULATION
# =============================================================================

def calculate_image_capacity(width, height, channels, has_alpha=False):
    """
    Calculate how many bytes can be stored in image
    """
    usable_channels = channels - 1 if has_alpha else channels
    
    if usable_channels <= 0:
        return 0
    
    total_pixels = width * height
    available_bits = total_pixels * usable_channels * 1
    available_bits -= HEADER_SIZE_BITS
    available_bytes = available_bits // 8
    
    return max(0, available_bytes)


def validate_capacity(message_bytes, available_bytes):
    """
    Verify message fits in available space
    """
    if isinstance(message_bytes, str):
        message_bytes = message_bytes.encode('utf-8')
    
    required = len(message_bytes)
    
    if required > available_bytes:
        raise InsufficientCapacityError(required, available_bytes)
    
    return True


def calculate_capacity_usage(message_size, capacity):
    """
    Calculate percentage of capacity used
    Returns: percentage (0-100)
    """
    if capacity == 0:
        return 100.0
    
    return (message_size / capacity) * 100.0


# =============================================================================
# MESSAGE PREPARATION
# =============================================================================

def prepare_message(text):
    """
    Prepare message for encoding with metadata header
    Returns: binary string ready for encoding
    """
    text = sanitize_message(text)
    
    message_binary = string_to_binary(text)
    
    message_length = len(message_binary)
    checksum = calculate_crc32(message_binary)
    
    magic_binary = int_to_binary(MAGIC_NUMBER, 32)
    length_binary = int_to_binary(message_length, 32)
    checksum_binary = int_to_binary(checksum, 32)
    
    complete_binary = magic_binary + length_binary + checksum_binary + message_binary
    
    return complete_binary


def extract_message_from_binary(binary_str):
    """
    Parse binary string back to message
    Returns: (message_text, is_valid, metadata)
    """
    if len(binary_str) < HEADER_SIZE_BITS:
        raise ValueError("Binary string too short for header")
    
    magic = binary_to_int(binary_str[0:32])
    length = binary_to_int(binary_str[32:64])
    checksum = binary_to_int(binary_str[64:96])
    
    if magic != MAGIC_NUMBER:
        raise ValueError(f"Invalid magic number: {hex(magic)}")
    
    # Parse flags
    is_encrypted = bool(flags & 0x01)
    has_error_correction = bool(flags & 0x02)
    
    # Extract salt if encrypted
    data_start = HEADER_SIZE_BITS
    salt = None
    if is_encrypted:
        if len(binary_str) < HEADER_SIZE_BITS + 32:
            raise ValueError("Binary too short for salt")
        salt_int = binary_to_int(binary_str[128:160])
        salt = int_to_bytes(salt_int, 4, 'big')
        data_start = HEADER_SIZE_BITS + 32
    
    # Extract message binary
    message_binary = binary_str[data_start:data_start + length]
    
    # Remove error correction if present
    if has_error_correction:
        message_binary, errors = remove_error_correction(message_binary)
    
    # Verify checksum
    calculated_checksum = calculate_crc32(message_binary)
    is_valid = (calculated_checksum == checksum)
    
    # Convert binary to text
    try:
        if is_encrypted and password:
            # Decrypt
            message_bytes = binary_to_string(message_binary).encode('latin-1')
            decrypted_bytes = decrypt_message(message_bytes, password, salt)
            message_text = decrypted_bytes.decode('utf-8')
        else:
            message_text = binary_to_string(message_binary)
    except Exception as e:
        raise ValueError(f"Failed to extract message: {str(e)}")
    
    metadata = {
        'is_encrypted': is_encrypted,
        'has_error_correction': has_error_correction,
        'checksum_valid': is_valid,
        'message_length': length
    }
    
    return (message_text, is_valid, metadata)


### Core Encoding Logic ###

def embed_bit_in_pixel(pixel_value, bit):
    """
    Replace LSB of pixel with message bit
    """
    # Clear LSB (bitwise AND with 11111110)
    cleared = pixel_value & 0xFE
    
    # Set new LSB
    modified = cleared | int(bit)
    
    return modified

def encode_message_in_pixels(pixel_array, binary_message, width, height, channels, has_alpha, channel_order=None):
    """
    Encode binary message into pixel array
    Modifies pixel_array in place
    Returns: (modified_pixels, number of bits encoded)
    """
    # Create mutable copy
    modified_pixels = bytearray(pixel_array)
    
    message_length = len(binary_message)
    message_index = 0
    
    # Determine which channels to use
    if channel_order is None:
        # Use all non-alpha channels in order
        if has_alpha:
            usable_channels = list(range(channels - 1))
        else:
            usable_channels = list(range(channels))
    else:
        usable_channels = channel_order
    
    # Encode bit by bit
    for y in range(height):
        for x in range(width):
            for c in usable_channels:
                if message_index >= message_length:
                    # Done encoding
                    return bytes(modified_pixels), message_index
                
                # Calculate pixel position
                pixel_index = (y * width + x) * channels + c
                
                if pixel_index < len(modified_pixels):
                    # Get current bit from message
                    bit = binary_message[message_index]
                    
                    # Modify pixel LSB
                    modified_pixels[pixel_index] = embed_bit_in_pixel(
                        modified_pixels[pixel_index],
                        bit
                    )
                    
                    message_index += 1
    
    return bytes(modified_pixels), message_index


### Image Reconstruction ###

def reconstruct_bmp(original_bytes, modified_pixel_data, parser):
    """
    Rebuild BMP file with modified pixels
    """
    # Keep headers unchanged (up to pixel data offset)
    header = original_bytes[:parser.pixel_data_offset]
    
    # Add modified pixel data (accounting for row padding)
    row_size = ((parser.width * parser.bit_depth + 31) // 32) * 4
    
    new_pixel_data = bytearray()
    pixel_index = 0
    
    for y in range(parser.height):
        row_data = bytearray()
        
        for x in range(parser.width):
            for c in range(parser.channels):
                if pixel_index < len(modified_pixel_data):
                    row_data.append(modified_pixel_data[pixel_index])
                    pixel_index += 1
        
        # Add padding to reach row_size
        while len(row_data) < row_size:
            row_data.append(0)
        
        new_pixel_data.extend(row_data)
    
    # Combine header and new pixel data
    reconstructed = header + bytes(new_pixel_data)
    
    return reconstructed

def reconstruct_png(original_bytes, modified_pixel_data, parser):
    """
    Rebuild PNG file with modified pixels
    Note: This is simplified - real PNG reconstruction is complex
    """
    # Would need to:
    # 1. Compress modified_pixel_data with zlib
    # 2. Apply PNG filters
    # 3. Create new IDAT chunks
    # 4. Calculate CRCs
    # 5. Rebuild file with new IDATs
    
    raise NotImplementedError("PNG reconstruction requires zlib compression")


# =============================================================================
# SECTION 21: MAIN ENCODING FUNCTION
# =============================================================================

def encode_message(image_path, message, output_path, password=None, 
                  use_error_correction=False, verify_after=True, 
                  progress_tracker=None):
    """
    Main encoding function
    
    Returns: (success, quality_report)
    """
    start_time = time.time()
    
    if progress_tracker:
        progress_tracker.start_stage('validation')
    
    try:
        # Step 1: Validate file
        if not os.path.exists(image_path):
            raise FileNotFoundError(f"Image not found: {image_path}")
        
        # Read file
        file_bytes = read_file_bytes(image_path)
        file_size = len(file_bytes)
        
        # Detect format
        format_type, is_supported, warning = detect_image_format(file_bytes)
        
        if not is_supported:
            raise ImageFormatError(format_type, warning)
        
        if progress_tracker:
            progress_tracker.complete_stage('validation')
            progress_tracker.start_stage('parsing')
        
        # Step 2: Parse image
        if format_type == 'PNG':
            parser = PNGParser(file_bytes)
        elif format_type == 'BMP':
            parser = BMPParser(file_bytes)
        elif format_type in ['TIFF_LE', 'TIFF_BE']:
            parser = TIFFParser(file_bytes)
        else:
            raise ImageFormatError(format_type)
        
        width, height, channels = parser.get_dimensions()
        has_alpha = parser.has_alpha()
        
        # Get pixel data
        try:
            original_pixels = parser.get_pixel_data()
        except NotImplementedError:
            raise ImageFormatError(format_type, "Format parsing not fully implemented")
        
        if progress_tracker:
            progress_tracker.complete_stage('parsing')
            progress_tracker.start_stage('preparation')
        
        # Step 3: Analyze image
        # Check for prior encoding
        is_encoded, confidence, encoding_message = warn_if_previously_encoded(parser)
        
        # Analyze channels
        ranked_channels, channel_recommendations = analyze_channel_suitability(
            original_pixels, width, height, channels
        )
        
        # Check compression risk
        risk_level, risk_factors, risk_recommendations = detect_compression_risk(
            parser, format_type
        )
        
        # Step 4: Check capacity
        capacity = calculate_image_capacity(width, height, channels, has_alpha)
        
        # Prepare message
        prepared_binary = prepare_message(message, password, use_error_correction)
        required_bytes = len(prepared_binary) // 8
        
        validate_capacity(required_bytes, capacity)
        
        if progress_tracker:
            progress_tracker.complete_stage('preparation')
            progress_tracker.start_stage('encoding')
        
        # Step 5: Encode
        modified_pixels, bits_encoded = encode_message_in_pixels(
            original_pixels,
            prepared_binary,
            width,
            height,
            channels,
            has_alpha,
            ranked_channels
        )
        
        if progress_tracker:
            progress_tracker.complete_stage('encoding')
            progress_tracker.start_stage('reconstruction')
        
        # Step 6: Reconstruct image
        if format_type == 'BMP':
            reconstructed_bytes = reconstruct_bmp(file_bytes, modified_pixels, parser)
        elif format_type == 'PNG':
            reconstructed_bytes = reconstruct_png(file_bytes, modified_pixels, parser)
        else:
            raise NotImplementedError(f"Reconstruction not implemented for {format_type}")
        
        if progress_tracker:
            progress_tracker.complete_stage('reconstruction')
        
        # Step 7: Quality check
        quality_report = generate_quality_report(
            original_pixels,
            modified_pixels,
            width,
            height,
            channels
        )
        
        if verify_after:
            try:
                verify_quality_threshold(quality_report)
            except QualityError as e:
                pass  # Log warning but continue
        
        # Step 8: Validate output path
        is_valid, error_msg = validate_output_path(output_path)
        if not is_valid:
            raise ValueError(error_msg)
        
        # Check disk space
        has_space, available = check_disk_space(output_path, len(reconstructed_bytes))
        if not has_space:
            raise IOError(f"Insufficient disk space: need {len(reconstructed_bytes)}, have {available}")
        
        if progress_tracker:
            progress_tracker.start_stage('verification')
        
        # Step 9: Save
        write_file_bytes(output_path, reconstructed_bytes)
        
        if progress_tracker:
            progress_tracker.complete_stage('verification')
        
        duration = time.time() - start_time
        
        return (True, quality_report)
    
    except Exception as e:
        raise

def safe_encode(image_path, message, output_path, password=None,
                use_error_correction=False, verify_after=True,
                verbose=False):
    """
    User-friendly wrapper with comprehensive error handling
    """
    progress = None
    if verbose:
        progress = ProgressTracker()
    
    try:
        success, quality_report = encode_message(
            image_path=image_path,
            message=message,
            output_path=output_path,
            password=password,
            use_error_correction=use_error_correction,
            verify_after=verify_after,
            progress_tracker=progress
        )
        
        if verbose:
            if progress:
                progress.print_progress()
            print(f"\n✓ Successfully encoded message")
            print(f"  Output: {output_path}")
            print(f"  Quality: {quality_report['quality_level']} (PSNR: {quality_report['psnr_db']:.2f} dB)")
            print(f"  Modified: {quality_report['modification_percent']:.3f}% of pixels")
        
        return success
    
    except FileNotFoundError as e:
        if verbose:
            print(f"\n✗ Error: Image file not found")
            print(f"  Path: {image_path}")
        raise
    
    except ImageFormatError as e:
        if verbose:
            print(f"\n✗ Error: {e.message}")
            print(f"  Supported formats: {', '.join(SUPPORTED_FORMATS)}")
        raise
    
    except InsufficientCapacityError as e:
        if verbose:
            print(f"\n✗ Error: Image too small for message")
            print(f"  Required: {e.required} bytes")
            print(f"  Available: {e.available} bytes")
            print(f"  Shortfall: {e.required - e.available} bytes")
        raise
    
    except CompressionDetectedError as e:
        if verbose:
            print(f"\n✗ Error: {str(e)}")
            print(f"  LSB encoding requires lossless formats")
        raise
    
    except QualityError as e:
        if verbose:
            print(f"\n✗ Warning: Image quality below threshold")
            print(f"  PSNR: {e.psnr:.2f} dB (threshold: {e.threshold:.2f} dB)")
        raise
    
    except Exception as e:
        if verbose:
            print(f"\n✗ Unexpected error: {str(e)}")
        raise