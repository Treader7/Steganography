### Steganography Exception classes ###
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