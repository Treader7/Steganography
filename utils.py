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

def calculate_chceksum(data)