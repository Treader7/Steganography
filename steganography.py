def encode_message(image, message):
    """
    Encodes a message into the least significant bits of the image pixels.

    Parameters:
    image (list of list of tuples): 2D array representing the image where each pixel is a tuple (R, G, B).
    message (str): The message to encode into the image.

    Returns:
    list of list of tuples: The modified image with the encoded message.
    """
    import itertools

    # Convert message to binary
    binary_message = ''.join(format(ord(char), '08b') for char in message)
    binary_message += '00000000'  # Null character to signify end of message

    message_index = 0
    message_length = len(binary_message)

    for i in range(len(image)):
        for j in range(len(image[i])):
            if message_index < message_length:
                pixel = list(image[i][j])
                for k in range(3):  # For R, G, B channels
                    if message_index < message_length:
                        # Modify the least significant bit
                        pixel[k] = (pixel[k] & ~1) | int(binary_message[message_index])
                        message_index += 1
                image[i][j] = tuple(pixel)
            else:
                return image  # Message fully encoded

    return image  # Return modified image even if message wasn't fully encoded


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