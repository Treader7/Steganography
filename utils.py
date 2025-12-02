from Constants import*


### File Operations ###
def read_file_bytes(filename):
    try:
        with open(filename, 'rb') as f:
            return f.read()
    except FileNotFoundError:
        raise FileNotFoundError(f"File not found: {filename}")
    except PermissionError:
        raise PermissionError(f"Permission denied: {filename}")
    except Exception as e:
        raise IOError(f"Error reading {filename}: {str(e)}")
    

def write_file_bytes(filename, data):
    try:
        with open(filename,'wb') as f:
            f.write(data)
        return True
    except PermissionError:
        raise PermissionError(f"Permission denied{filename}")
    except Exception as e:
        raise IOError(f"Error writing {filename}:{str(e)}")
    

def get_file_size(filename):
    try:
        with open(filename, 'rb') as f:
            f.seek(0,2)
            return f.tell()
    except:
        return 0



###Binary/Integer Conversions###
def bytes_to_int(byte_array, start, length, endian='little'):
    if start + length > len(byte_array):
        raise ValueError("Requested beyond array length")
    
    result=0

    if endian=='little':
        for i in range(length):
            result |=byte_array[start+i]<<(i * 8)
    else:
        for i in range(length):
            result = (result<<8)|byte_array[start+i]

    return result

def int_to_bytes(value,length,endian='little'):
    if value<0:
        raise ValueError("cannot convert negative integer to bytes")
    
    max_value=(1<<(length*8))-1

    if value>max_value:
        raise ValueError(f"Value{value} too large for {length} bytes")
    
    result=bytearray()

    if endian == 'little':
        for i in range(length):
            result.append((value>>(i*8)) & 0xFF)
    else:
        for i in range (length-1,-1,-1):
            result.append((value>>(i*8))& 0xFF)
    return bytes(result)



### Text/Binary Conversions
def string_to_binary(text):
    if not isinstance(text, str):
        raise TypeError("Input must be a string")
    
    if not text:
        return""
    
    text_bytes=text.encode('utf-8')

    binary_str=''
    for byte in text_bytes:
        binary_str+=format(byte,'08b')
    
    return binary_str

def binary_to_string(binary_str, str):
    if not isinstance(binary_str, str):
        raise TypeError("Input must be a string")
    
    if not binary_str:
        return""
    
    if len(binary_str) % 8 != 0:
        binary_str=binary_str[:-(len(binary_str)%8)]

    if not binary_str:
        return""
    
    bytes_list=[]
    for i in range (0, len(binary_str), 8):
        chunk=binary_str[i:i+8]
        if len(chunk) !=8:
            break

        byte_value=int(chunk, 2)
        bytes_list.append(byte_value)

        text_bytes=bytes(bytes_list)
    try:
        return text_bytes.decode('utf-8')
    except UnicodeDecodeError:
        return text_bytes.decode('latin-1', errors='ignore')
    


### Checksums (Data Integrity) ###

def calculate_checksum(data):
    if isinstance(data, str):
        data=data.encode('utf-8')
    elif not isinstance(data,(bytes, bytearray)):
        raise TypeError("Data must be string or bytes")
    checksum=0
    
    for byte in data:
        checksum=(checksum+byte) & 0xFFFFFFFF
    return checksum

def verify_checksum(data, expected_checksum):
    calculated= calculate_checksum(data)
    return calculated == expected_checksum



### Binary String Utilities ###
def int_to_binary(value, bit_length=32):
    if value<0:
        raise ValueError("Cannot convert negative intger to binary")
    max_value=(1<<bit_length)-1
    if value>max_value:
        raise ValueError(f"Value {value} too large for{bit_length} bits")
    
    binary=bin(value[2:])
    return binary.zfill(bit_length)

def binary_to_int(binary_str):
    if not binary_str:
        return 0
    for char in binary_str:
        if char not in '01':
            raise ValueError(f"Invalid binary character:'{char}'")
    return int(binary_str,2)



### Validatiion Function ###
def valdiate_bmp_format(bmp_data):
    if len(bmp_data)<54:
        return False, "File too small to be a valid BMP"
    if bmp_data[0:2]!=BMP_SIGNATURE:
        return False, "Not a BMP file(invalid signature)"
    
    try:
        bit_depth=bytes_to_int(bmp_data, 28, 2, "little")
        if bit_depth not in Supportted_bit_depth:
            return False, f"Unsupported bit depth: {bit_depth}"
    except:
        return False,"Cannot read bit depth"
    return True, "Valid BMP format"
def validate_message_length(message, max_size=max_message_size):
    if not message:
        return False,f"Message too long: {len(message)} chars, max{max_size}"
    return True, "Message Length Valid"



### Capacity Calculations ###
def calculate_bmp_capacity(width, height, bit_depth, use_alpha=True):
    if bit_depth==24:
        channels=3
    elif bit_depth==32:
        channels=4 if use_alpha else 3
    else:
        raise ValueError(f"Unsupported bit depth: {bit_depth}")
    
    total_pixels=width*height
    available_bits=total_pixels*channels
    available_bits-=Header_size_bits

    return max(0, available_bits)
def calculate_capacity_precentage(message_size_bits, total_capacity_bits, ):
    if total_capacity_bits==0:
        return 100.0
    precentage=(message_size_bits/total_capacity_bits)*100.0
    return min(100.0, precentage)