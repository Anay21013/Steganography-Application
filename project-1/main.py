# import cv2
# import os
# from tkinter import Tk, Label, Button, Entry, filedialog, messagebox

# def encrypt_message():
#     filename = filedialog.askopenfilename(title="Select an Image File", filetypes=[("Image Files", "*.png;*.jpg;*.jpeg")])
#     img = cv2.imread(filename)

#     if img is None:
#         messagebox.showerror("Error", "Invalid image file.")
#         return

#     msg = entry_message.get()
#     password = entry_password.get()

#     d = {}
#     c = {}

#     for i in range(255):
#         d[chr(i)] = i
#         c[i] = chr(i)

#     m = 0
#     n = 0
#     z = 0

#     for i in range(len(msg)):
#         img[n, m, z] = d[msg[i]]
#         n = n + 1
#         m = m + 1
#         z = (z + 1) % 3

#     output_filename = filedialog.asksaveasfilename(title="Save Encrypted Image As", defaultextension=".png",
#                                                      filetypes=[("PNG Files", "*.png")])

#     cv2.imwrite(output_filename, img)
#     messagebox.showinfo("Success", "Message encrypted and saved successfully.")

# def decrypt_message():
#     filename = filedialog.askopenfilename(title="Select an Encrypted Image File", filetypes=[("Image Files", "*.png")])
#     img = cv2.imread(filename)

#     if img is None:
#         messagebox.showerror("Error", "Invalid image file.")
#         return

#     password = entry_password.get()

#     d = {}
#     c = {}

#     for i in range(255):
#         d[chr(i)] = i
#         c[i] = chr(i)

#     message = ""
#     n = 0
#     m = 0
#     z = 0

#     for i in range(len(img)):
#         pixel_value = img[n, m, z]

#         if pixel_value == 255:
#             message += " "  # Handle the case where the pixel value is 255
#         else:
#             message += c[pixel_value]
#         n = n + 1
#         m = m + 1
#         z = (z + 1) % 3

#     messagebox.showinfo("Decrypted Message", f"Decrypted Message: {message}")

# # GUI Setup
# root = Tk()
# root.title("LSB Steganography")

# label_message = Label(root, text="Enter your secret message:")
# label_message.pack()

# entry_message = Entry(root, width=50)
# entry_message.pack()

# label_password = Label(root, text="Enter a passcode:")
# label_password.pack()

# entry_password = Entry(root, show="*", width=50)
# entry_password.pack()

# btn_encrypt = Button(root, text="Encrypt Message", command=encrypt_message)
# btn_encrypt.pack()

# btn_decrypt = Button(root, text="Decrypt Message", command=decrypt_message)
# btn_decrypt.pack()

# root.mainloop()
import os
import cv2
from tkinter import Tk, Label, Button, Entry, filedialog, messagebox, simpledialog

class LSBSteganographyApp:
    def __init__(self):
        self.root = Tk()
        self.root.title("LSB Steganography")

        self.label_message = Label(self.root, text="Enter your secret message:")
        self.label_message.pack()

        self.entry_message = Entry(self.root, width=50)
        self.entry_message.pack()

        self.label_password = Label(self.root, text="Enter a passcode:")
        self.label_password.pack()

        self.entry_password = Entry(self.root, show="*", width=50)
        self.entry_password.pack()

        self.btn_encrypt = Button(self.root, text="Encrypt Message", command=self.encrypt_message)
        self.btn_encrypt.pack()

        self.btn_decrypt = Button(self.root, text="Decrypt Message", command=self.decrypt_message)
        self.btn_decrypt.pack()

        self.encryption_password = None  # Variable to store the encryption password

    def encrypt_message(self):
        filename = filedialog.askopenfilename(title="Select an Image File", filetypes=[("Image Files", "*.png;*.jpg;*.jpeg")])
        img = cv2.imread(filename)

        if img is None:
            messagebox.showerror("Error", "Invalid image file.")
            return

        msg = self.entry_message.get()
        password = self.entry_password.get()

        self.encryption_password = password  # Store the password for decryption

        d = {}
        c = {}

        for i in range(255):
            d[chr(i)] = i
            c[i] = chr(i)

        m = 0
        n = 0
        z = 0

        for i in range(len(msg)):
            img[n, m, z] = d[msg[i]]
            n = n + 1
            m = m + 1
            z = (z + 1) % 3

        output_filename = filedialog.asksaveasfilename(title="Save Encrypted Image As", defaultextension=".png",
                                                         filetypes=[("PNG Files", "*.png")])

        cv2.imwrite(output_filename, img)
        messagebox.showinfo("Success", "Message encrypted and saved successfully.")

    def decrypt_message(self):
        filename = filedialog.askopenfilename(title="Select an Encrypted Image File", filetypes=[("Image Files", "*.png")])
        img = cv2.imread(filename)

        if img is None:
            messagebox.showerror("Error", "Invalid image file.")
            return

        password = simpledialog.askstring("Password", "Enter the decryption password:", show='*')

        if password != self.encryption_password:
            messagebox.showerror("Error", "Incorrect password. Please try again.")
            return

        d = {}
        c = {}

        for i in range(255):
            d[chr(i)] = i
            c[i] = chr(i)

        message = ""
        n = 0
        m = 0
        z = 0

        for i in range(len(img)):
            pixel_value = img[n, m, z]

            if pixel_value == 255:
                message += " "  # Handle the case where the pixel value is 255
            else:
                message += c[pixel_value]
            n = n + 1
            m = m + 1
            z = (z + 1) % 3

        messagebox.showinfo("Decrypted Message", f"Decrypted Message: {message}")

    def run(self):
        self.root.mainloop()

# Instantiate the application and run it
# app = LSBSteganographyApp()
# app.run()
