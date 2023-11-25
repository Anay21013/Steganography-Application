# import numpy as np
# import cv2
# import tkinter as tk
# from tkinter import Tk, Label, Button, Entry, filedialog, messagebox, simpledialog

# def spread_spectrum_encode(img, message):
#     height, width, _ = img.shape
#     channels = cv2.split(img)

#     message_binary = ''.join(format(ord(char), '08b') for char in message)
#     message_len = len(message_binary)

#     for i in range(message_len):
#         for j in range(3):  # Iterate over RGB channels
#             pixel_value = channels[j][i // width, i % width]
#             pixel_value = pixel_value & 0xFE | int(message_binary[i])
#             channels[j][i // width, i % width] = pixel_value

#     encoded_img = cv2.merge(channels)
#     return encoded_img

# def spread_spectrum_decode(img, message_len):
#     height, width, _ = img.shape
#     channels = cv2.split(img)

#     decoded_message = ""
#     for i in range(message_len):
#         bit = 0
#         for j in range(3):  # Iterate over RGB channels
#             pixel_value = channels[j][i // width, i % width]
#             bit = (bit << 1) | (pixel_value & 1)

#         decoded_message += chr(bit)

#     return decoded_message

# class SteganographyApp:
#     def __init__(self, master):
#         self.master = master
#         self.master.title("Spread Spectrum Steganography App")

#         self.message_label = tk.Label(master, text="Enter your message:")
#         self.message_label.pack()

#         self.message_entry = tk.Entry(master, width=50)
#         self.message_entry.pack()

#         self.password_label = tk.Label(master, text="Enter your password:")
#         self.password_label.pack()

#         self.password_entry = tk.Entry(master, show="*", width=50)
#         self.password_entry.pack()

#         self.encrypt_button = tk.Button(master, text="Encrypt", command=self.encrypt)
#         self.encrypt_button.pack()

#         self.decrypt_button = tk.Button(master, text="Decrypt", command=self.decrypt)
#         self.decrypt_button.pack()

#     def encrypt(self):
#         message = self.message_entry.get()
#         password = self.password_entry.get()

#         if not message or not password:
#             messagebox.showerror("Error", "Please enter both a message and a password.")
#             return

#         # Ask user to select an image file for encryption
#         file_path = filedialog.askopenfilename(title="Select an Image File",
#                                                filetypes=[("Image files", "*.png;*.jpg;*.jpeg")])

#         if file_path:
#             cover_image = cv2.imread(file_path)

#             # Encrypt the message into the image
#             encoded_image = spread_spectrum_encode(cover_image, message + password)

#             # Save the encrypted image
#             encrypted_file_path = filedialog.asksaveasfilename(defaultextension=".png",
#                                                                 filetypes=[("PNG files", "*.png")])

#             if encrypted_file_path:
#                 cv2.imwrite(encrypted_file_path, encoded_image)
#                 messagebox.showinfo("Encryption", "Message encrypted and saved successfully!")

#     def decrypt(self):
#         # Ask user to select an image file for decryption
#         file_path = filedialog.askopenfilename(title="Select an Encrypted Image File",
#                                                filetypes=[("Image files", "*.png;*.jpg;*.jpeg")])

#         if file_path:
#             encoded_image = cv2.imread(file_path)

#             # Get the length of the original message (needed for decoding)
#             message_len = len(self.message_entry.get())

#             # Ask user to enter the password for decryption
#             password = simpledialog.askstring("Password", "Enter your password:", show="*")

#             # Decrypt the message from the image
#             decoded_message = spread_spectrum_decode(encoded_image, message_len)

#             # Verify the password during decryption
#             if password != self.encryption_password:
#                 # Display the decrypted message
#                 messagebox.showinfo("Decryption", f"Decrypted Message: {decoded_message[:-len(password)]}")
#             else:
#                 messagebox.showerror("Decryption Error", "Incorrect password.")

# if __name__ == "__main__":
#     root = tk.Tk()
#     app = SteganographyApp(root)
#     root.mainloop()
import os
from tkinter import Tk, Label, Button, Entry, filedialog, messagebox
from PIL import Image
import piexif
import base64
from cryptography.fernet import Fernet
import base64
import hashlib
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.backends import default_backend

def generate_key(password):
    """
    Generate a key based on the password.
    """
    # return base64.urlsafe_b64encode(password.encode()).ljust(32)[:32]
    """
    Generate a Fernet key from the given password.
    """
    password_bytes = password.encode()  # Convert to bytes
    salt = b'some_salt'  # Should be a fixed, random and unique value for each user
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
        backend=default_backend()
    )
    key = base64.urlsafe_b64encode(kdf.derive(password_bytes))
    return key

def encrypt_message(message, password):
    """
    Encrypt the message using the password.
    """
    key = generate_key(password)
    f = Fernet(key)
    return f.encrypt(message.encode()).decode()

def decrypt_message(encrypted_message, password):
    """
    Decrypt the message using the password.
    """
    key = generate_key(password)
    f = Fernet(key)
    return f.decrypt(encrypted_message.encode()).decode()

class MetadataSteganographyApp:
    def __init__(self):
        self.root = Tk()
        self.root.title("Metadata Steganography")

        Label(self.root, text="Select Image:").pack()
        self.file_path_entry = Entry(self.root, width=50)
        self.file_path_entry.pack()
        Button(self.root, text="Browse", command=self.browse_file).pack()

        Label(self.root, text="Secret Message:").pack()
        self.message_entry = Entry(self.root, width=50)
        self.message_entry.pack()

        Label(self.root, text="Password:").pack()
        self.password_entry = Entry(self.root, show="*", width=50)
        self.password_entry.pack()

        Button(self.root, text="Encrypt and Save", command=self.encrypt_and_save).pack()
        Button(self.root, text="Decrypt", command=self.decrypt_message).pack()

    def browse_file(self):
        filename = filedialog.askopenfilename(title="Select an Image File", filetypes=[("Image Files", "*.png;*.jpg;*.jpeg")])
        self.file_path_entry.delete(0, 'end')
        self.file_path_entry.insert(0, filename)

    def encrypt_and_save(self):
        image_path = self.file_path_entry.get()
        message = self.message_entry.get()
        password = self.password_entry.get()

        if not os.path.isfile(image_path):
            messagebox.showerror("Error", "Please select a valid image file.")
            return

        encrypted_message = encrypt_message(message, password)
        img = Image.open(image_path)

        # Check if the image has Exif data
        if 'exif' in img.info:
            exif_dict = piexif.load(img.info['exif'])
        else:
            exif_dict = {"Exif": {}}

        exif_dict['Exif'][piexif.ExifIFD.UserComment] = encrypted_message.encode('utf8')
        exif_bytes = piexif.dump(exif_dict)

        output_path = filedialog.asksaveasfilename(title="Save Image As", defaultextension=".jpg",
                                                filetypes=[("PNG Files", "*.png")])
        if output_path:
            img.save(output_path, exif=exif_bytes)
            messagebox.showinfo("Success", "Message encrypted and saved successfully.")


    def decrypt_message(self):
        image_path = filedialog.askopenfilename(title="Select an Encrypted Image File", filetypes=[("Image Files", "*.png;*.jpg;*.jpeg")])
        password = self.password_entry.get()

        if not os.path.isfile(image_path):
            messagebox.showerror("Error", "Please select a valid image file.")
            return

        try:
            img = Image.open(image_path)
            exif_dict = piexif.load(img.info['exif'])
            encrypted_message = exif_dict['Exif'][piexif.ExifIFD.UserComment].decode('utf8')
            decrypted_message = decrypt_message(encrypted_message, password)
            messagebox.showinfo("Decrypted Message", f"Decrypted Message: {decrypted_message}")
        except Exception as e:
            messagebox.showerror("Error", "Failed to decrypt message. Ensure you have the correct password.")

    def run(self):
        self.root.mainloop()

# Run the application
# app = MetadataSteganographyApp()
# app.run()