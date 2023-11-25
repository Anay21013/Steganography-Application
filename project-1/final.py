import tkinter as tk
from tkinter import Button

# Import the LSB Steganography App and Metadata Steganography App from main1.py and main2.py
from main import LSBSteganographyApp
from main2 import MetadataSteganographyApp

class CombinedSteganographyApp:
    def __init__(self):
        self.root = tk.Tk()
        self.root.title("Combined Steganography App")
        self.root.geometry("600x400")
        # Create buttons for LSB and Metadata Steganography
        self.btn_lsb_steganography = Button(self.root, text="LSB Steganography", command=self.launch_lsb_app)
        self.btn_lsb_steganography.pack()

        self.btn_metadata_steganography = Button(self.root, text="Metadata Steganography", command=self.launch_metadata_app)
        self.btn_metadata_steganography.pack()

    def launch_lsb_app(self):
        # Launch the LSB Steganography App from main1.py
        lsb_app = LSBSteganographyApp()
        lsb_app.run()

    def launch_metadata_app(self):
        # Launch the Metadata Steganography App from main2.py
        metadata_app = MetadataSteganographyApp()
        metadata_app.run()

    def run(self):
        self.root.mainloop()

if __name__ == "__main__":
    # Instantiate the CombinedSteganographyApp and run it
    combined_app = CombinedSteganographyApp()
    combined_app.run()
