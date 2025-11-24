
def decode_message(image):
    """
    Decodes a message from the least significant bits of the image pixels.

    Parameters:
    image (list of list of tuples): 2D array representing the image where each pixel is a tuple (R, G, B).

    Returns:
    str: The decoded message.
    """
    binary_message = ''
    
    for i in range(len(image)):
        for j in range(len(image[i])):
            pixel = image[i][j]
            for k in range(3):  # For R, G, B channels
                binary_message += str(pixel[k] & 1)

    # Split binary message into bytes
    bytes_list = [binary_message[i:i+8] for i in range(0, len(binary_message), 8)]
    
    message = ''
    for byte in bytes_list:
        char = chr(int(byte, 2))
        if char == '\x00':  # Null character signifies end of message
            break
        message += char

    return message