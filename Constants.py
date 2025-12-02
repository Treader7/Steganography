### Constants ###
BMP_SIGNATURE = [0x42, 0x4D] # to identify bmp files this also spells 'BM' in ASCII
BMP_HEADER_SIZE = 54 # BMP header size in bytes and to know when the header ends and pixel data starts
Supportted_bit_depth = [24, 32] # supported bit depths for BMP files RGB and RGBA

MAGIC_NUMBER = 0xAAFF7799 # to identify valid messages this is a signature completly random
Header_size_bits = 96 # size of the header in bits to know where the header ends and message starts
max_message_size = 1000000  # 1 MB max message size to prevent excessive memory usage
