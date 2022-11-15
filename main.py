# Creating a python program to Encode and decode message text using Tkinter

# Import the module for GUI
import tkinter as tk

# Initialising the font type and size
FONT = ("timesnewroman", 25, "bold")

class CaesarCipherGUI:

    def __init__(self, master):

        # Title for the window
        master.title("Caesar Cipher GUI")

        # String type for plaintext and ciphertext
        self.plaintext = tk.StringVar(master, value="")
        self.Ciphertext = tk.StringVar(master, value="")

        # Integer value for the key
        self.key = tk.IntVar(master)

        # Plaintext GUI and controls
        self.plain_label = tk.Label(master, text="Plaintext", fg="green", font=FONT).grid(row=0, column=0)
        self.plain_entry = tk.Entry(master, textvariable=self.plaintext, width=40, font=FONT)
        self.plain_entry.grid(row=0, column=1, padx=20)

        # Button constructs a button
        self.encrypt_button = tk.Button(master, text="Encrypt", command=lambda: self.encrypt_callback(),
                                        font=FONT).grid(row=0, column=2)
        self.decrypt_button = tk.Button(master, text="Decrypt", command=lambda: self.decrypt_callback(),
                                        font=FONT).grid(row=2, column=2)

        # Key controls
        self.key_label = tk.Label(master, text="Key", font=FONT).grid(row=1, column=0)
        self.key_entry = tk.Entry(master, textvariable=self.key, width=10, font=FONT).grid(row=1, column=1, sticky=tk.W,
                                                                                           padx=20)

        # Ciphertext controls
        self.cipher_label = tk.Label(master, text="Ciphertext", fg="red", font=FONT).grid(row=2, column=0)
        self.cipher_entry = tk.Entry(master, textvariable=self.Ciphertext, width=40, font=FONT)
        self.cipher_entry.grid(row=2, column=1, padx=20)

    # Defination of key function
    def get_key(self):
        try:
            key_val = self.key.get()
            return key_val
        except tk.TclError:
            pass

    # Encryption method
    def encrypt_callback(self):
        key = self.get_key()
        ciphertext = encrypt(self.plain_entry.get(), key)
        self.cipher_entry.delete(0, tk.END)
        self.cipher_entry.insert(0, ciphertext)

    # Decryption method
    def decrypt_callback(self):
        key = self.get_key()
        plaintext = decrypt(self.cipher_entry.get(), key)
        self.plain_entry.delete(0, tk.END)
        self.plain_entry.insert(0, plaintext)


# Encryption formula of Caeser cipher
def encrypt(plaintext, key):
    ciphertext = ""
    for char in plaintext.upper():
        if char.isalpha():
            ciphertext += chr((ord(char) + key - 65) % 26 + 65)
        else:
            ciphertext += char
    return ciphertext


# Decryption formula of Caser cipher
def decrypt(ciphertext, key):
    plaintext = ""
    for char in ciphertext.upper():
        if char.isalpha():
            plaintext += chr((ord(char) - key - 65) % 26 + 65)
        else:
            plaintext += char
    return plaintext


# Run the program
if __name__ == "__main__":
    root = tk.Tk()
    caesar = CaesarCipherGUI(root)
    root.mainloop()
