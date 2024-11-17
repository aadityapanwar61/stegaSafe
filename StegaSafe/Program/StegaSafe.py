from kivymd.app import MDApp
from kivymd.uix.boxlayout import MDBoxLayout
from kivymd.uix.button import MDRaisedButton, MDFlatButton
from kivymd.uix.textfield import MDTextField
from kivymd.uix.toolbar import MDTopAppBar as MDToolbar
from kivymd.uix.dialog import MDDialog
from kivy.uix.image import Image
from tkinter import filedialog
from stegano import lsb
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
import base64
import hashlib
import os
import tkinter as tk

# Initialize Tkinter without creating a window
root = tk.Tk()
root.withdraw()


class SteganographyApp(MDApp):
    def build(self):
        self.theme_cls.primary_palette = "Blue"
        self.theme_cls.theme_style = "Light"

        # Generate a random encryption key for the session
        fixed_passphrase = "YourSecurePassphrase123!"  # Replace this with a strong, secure passphrase.
        
        # Derive a fixed 256-bit encryption key from the passphrase
        self.encryption_key = hashlib.sha256(fixed_passphrase.encode()).digest()

        # Root layout
        main_layout = MDBoxLayout(orientation="vertical", spacing=10, padding=10)

        # Toolbar
        toolbar = MDToolbar(title="StegaSafe")
        toolbar.right_action_items = [["information-outline", lambda x: self.show_info_dialog()]]
        main_layout.add_widget(toolbar)

        # Load Image Button
        load_button = MDRaisedButton(text="Load Image", pos_hint={"center_x": 0.5}, on_release=self.load_image)

        # Image Display
        self.image_display = Image(size_hint=(1, 0.4), allow_stretch=True)
        self.image_path = False

        # Text Field for Message Input
        self.message_input = MDTextField(
            hint_text="Enter your message",
            helper_text="This message will be encoded into the image",
            helper_text_mode="on_focus",
            size_hint_x=0.9,
            pos_hint={"center_x": 0.5},
        )

        # Buttons for Encoding and Decoding
        self.encode_button = MDRaisedButton(
            text="Encode Message", pos_hint={"center_x": 0.5}, on_release=self.encode_message
        )
        self.decode_button = MDRaisedButton(
            text="Decode Message", pos_hint={"center_x": 0.5}, on_release=self.decode_message
        )

        # Add widgets to layout
        main_layout.add_widget(load_button)
        main_layout.add_widget(self.image_display)
        main_layout.add_widget(self.message_input)
        main_layout.add_widget(self.encode_button)
        main_layout.add_widget(self.decode_button)

        return main_layout

    def show_info_dialog(self):
        info_dialog = MDDialog(
            title="About StegaSafe",
            text="This app allows you to securely hide messages within images.",
            buttons=[MDFlatButton(text="CLOSE", on_release=lambda x: info_dialog.dismiss())],
        )
        info_dialog.open()

    def load_image(self, instance):
        self.image_path = filedialog.askopenfilename()
        if self.image_path:
            if not self.image_path.lower().endswith((".png", ".jpg", ".jpeg")):
                self.show_dialog("Invalid File", "Please select a valid image file (PNG or JPG).")
                self.image_path = False
                return

            self.image_display.source = self.image_path
            self.image_display.reload()
            self.show_dialog("Image Loaded", f"Loaded: {self.image_path.split('/')[-1]}")
        else:
            self.show_dialog("No Image Selected", "You did not select an image.")

    def encode_message(self, instance):
        if not self.image_path:
            self.show_dialog("No Image", "Please load an image first.")
            return

        if not self.image_path.lower().endswith((".png", ".jpg", ".jpeg")):
            self.show_dialog("Invalid File", "The loaded file is not a valid image. Please load a PNG or JPG file.")
            return

        message = self.message_input.text
        if not message:
            self.show_dialog("No Message", "Please enter a message to encode.")
            return

        # Encrypt the message
        encrypted_message = self.encrypt_message(message)

        # Tkinter file dialog for save location
        save_path = filedialog.asksaveasfilename(defaultextension=".png", filetypes=[("PNG files", "*.png")])
        if not save_path:
            self.show_dialog("Encoding Canceled", "Encoding canceled.")
            return

        try:
            encoded_image = lsb.hide(self.image_path, encrypted_message)
            encoded_image.save(save_path)
            self.show_dialog("Message Encoded", f"Message encoded and saved to {save_path}")
            self.clear_fields()  # Clear fields after encoding
        except Exception as e:
            self.show_dialog("Error", f"Error: {e}")

    def decode_message(self, instance):
        if not self.image_path:
            self.show_dialog("No Image", "Please load an image first.")
            return

        if not self.image_path.lower().endswith((".png", ".jpg", ".jpeg")):
            self.show_dialog("Invalid File", "The loaded file is not a valid image. Please load a PNG or JPG file.")
            return

        try:
            encrypted_message = lsb.reveal(self.image_path)
            if encrypted_message:
                # Decrypt the message
                hidden_message = self.decrypt_message(encrypted_message)
                self.show_dialog("Decoded Message", f"Decoded message: {hidden_message}")
                self.clear_fields()  # Clear fields after decoding
            else:
                self.show_dialog("No Hidden Message", "No hidden message found.")
        except Exception as e:
            self.show_dialog("Error", f"Error: {e}")

    def encrypt_message(self, message):
        # Encrypt the message with a fixed key
        cipher = AES.new(self.encryption_key, AES.MODE_CBC)
        ct_bytes = cipher.encrypt(pad(message.encode(), AES.block_size))
        iv = base64.b64encode(cipher.iv).decode("utf-8")
        ct = base64.b64encode(ct_bytes).decode("utf-8")
        return f"{iv}{ct}"

    def decrypt_message(self, encrypted_message):
        # Decrypt the message with the fixed key
        iv = base64.b64decode(encrypted_message[:24])  # Extract IV
        ct = base64.b64decode(encrypted_message[24:])
        cipher = AES.new(self.encryption_key, AES.MODE_CBC, iv)
        message = unpad(cipher.decrypt(ct), AES.block_size).decode("utf-8")
        return message

    def clear_fields(self):
        # Clear the image and message input
        self.image_display.source = ""
        self.message_input.text = ""

    def show_dialog(self, title, text):
        dialog = MDDialog(
            title=title,
            text=text,
            buttons=[MDFlatButton(text="CLOSE", on_release=lambda x: dialog.dismiss())],
        )
        dialog.open()


if __name__ == "__main__":
    SteganographyApp().run()
