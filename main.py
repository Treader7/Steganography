from steganography import encode_message, decode_message
def main():
    # Example image: 4x4 pixels, each pixel is (R, G, B)
    image = [
        [(255, 255, 255), (255, 255, 255), (255, 255, 255), (255, 255, 255)],
        [(255, 255, 255), (255, 255, 255), (255, 255, 255), (255, 255, 255)],
        [(255, 255, 255), (255, 255, 255), (255, 255, 255), (255, 255, 255)],
        [(255, 255, 255), (255, 255, 255), (255, 255, 255), (255, 255, 255)]
    ]

    message = "Hi"
    print("Original Message:", message)

    # Encode the message into the image
    encoded_image = encode_message(image, message)
    print("Message encoded into image.")

    # Decode the message from the image
    decoded_message = decode_message(encoded_image)
    print("Decoded Message:", decoded_message)