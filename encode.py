def encode_message(image, message):

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

