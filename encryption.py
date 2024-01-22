from cryptography.fernet import Fernet
from tkinter import *
from tkinter import filedialog
from tkinter import messagebox
from PIL import Image

root = Tk()
root.title("Image Encryption")
root.geometry("300x200")


def select_image():
    file_path = filedialog.askopenfilename(title="Select an image file",
                                           filetypes=[("Image files", "*.jpg;*.jpeg;*.png")])
    if file_path:
        image = Image.open(file_path)

        key = Fernet.generate_key()

        fernet = Fernet(key)

        with open(file_path, 'rb') as file:
            image_data = file.read()
        encrypted_data = fernet.encrypt(image_data)

        encrypted_file_path = file_path + '.encrypted'
        with open(encrypted_file_path, 'wb') as encrypted_file:
            encrypted_file.write(encrypted_data)

        message = 'Image encrypted successfully.\n\nEncryption key:\n{}\n\nEncrypted image saved at:\n{}'.format(
            key.decode(), encrypted_file_path)
        print(key.decode())
        messagebox.showinfo('Success!', message)


def decrypt_image():
    file_path = filedialog.askopenfilename(title="Select an encrypted image file",
                                           filetypes=[("Encrypted image files", "*.encrypted")])
    if file_path:
        key = simpledialog.askstring("Enter the encryption key", "Please enter the encryption key:")

        fernet = Fernet(key.encode())

        with open(file_path, 'rb') as file:
            encrypted_data = file.read()

        decrypted_data = fernet.decrypt(encrypted_data)
        decrypted_file_path = file_path[:-10]
        with open(decrypted_file_path, 'wb') as decrypted_file:
            decrypted_file.write(decrypted_data)

        message = 'Image decrypted successfully.\n\nDecrypted image saved at:\n{}'.format(decrypted_file_path)

        messagebox.showinfo('Success!', message)


encrypt_button = Button(root, text="Encrypt an image", command=select_image)
encrypt_button.pack(pady=10)

decrypt_button = Button(root, text="Decrypt an image", command=decrypt_image)
decrypt_button.pack(pady=10)

root.mainloop()