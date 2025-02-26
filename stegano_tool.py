import tkinter as tk
from tkinter import ttk, filedialog, messagebox
from PIL import Image, ImageTk
import cv2
import numpy as np
import hashlib
import logging

class SteganoApp(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("Secure Steganography Suite v2.0")
        self.geometry("900x700")
        self.configure(bg="#f0f0f0")
        
        # Initialize variables
        self.encode_image_path = None
        self.decode_image_path = None
        self.max_message_length = 0
        self.processing = False

        # Configure style
        self.style = ttk.Style()
        self.style.theme_use("clam")
        self._configure_styles()
        
        # Setup logging
        logging.basicConfig(filename='stegano_errors.log', level=logging.ERROR)
        
        # Create UI components
        self.create_widgets()
        self.create_status_bar()

    def _configure_styles(self):
        self.style.configure("TNotebook.Tab", font=('Helvetica', 12, 'bold'), padding=[15, 5])
        self.style.configure("Status.TLabel", background="#e0e0e0", relief=tk.SUNKEN)
        self.style.map("TButton",
                      foreground=[('active', 'white'), ('!disabled', 'black')],
                      background=[('active', '#45a049'), ('!disabled', '#4CAF50')])

    def create_widgets(self):
        # Notebook for tabs
        self.notebook = ttk.Notebook(self)
        self.encoder_tab = ttk.Frame(self.notebook)
        self.decoder_tab = ttk.Frame(self.notebook)
        
        # Add tabs
        self.notebook.add(self.encoder_tab, text="📤 Encode")
        self.notebook.add(self.decoder_tab, text="📥 Decode")
        self.notebook.pack(expand=1, fill="both", padx=10, pady=10)
        
        # Create tab contents
        self.create_encoder_ui()
        self.create_decoder_ui()

    def create_encoder_ui(self):
        frame = ttk.Frame(self.encoder_tab)
        frame.pack(pady=20, padx=20, fill="both", expand=True)
        
        # Image Preview
        self.img_preview = ttk.Label(frame, text="No image selected", style='Preview.TLabel')
        self.img_preview.pack(pady=10)
        
        ttk.Button(frame, text="📁 Select Image", command=self.load_encode_image).pack(pady=5)
        
        # Message Input
        ttk.Label(frame, text="🔒 Secret Message:").pack(pady=5)
        self.msg_entry = ttk.Entry(frame, width=60)
        self.msg_entry.pack()
        self.msg_entry.bind("<KeyRelease>", self.update_message_counter)
        
        # Message Counter
        self.message_counter = ttk.Label(frame, text="0/0 characters")
        self.message_counter.pack()
        
        # Key Input
        ttk.Label(frame, text="🔑 Encryption Key:").pack(pady=5)
        self.key_entry = ttk.Entry(frame, show="•", width=60)
        self.key_entry.pack()
        
        ttk.Button(frame, text="🛡️ Encode & Save", command=self.encode).pack(pady=15)

    def create_decoder_ui(self):
        frame = ttk.Frame(self.decoder_tab)
        frame.pack(pady=20, padx=20, fill="both", expand=True)
        
        # Image Preview
        self.decoded_preview = ttk.Label(frame, text="No image selected", style='Preview.TLabel')
        self.decoded_preview.pack(pady=10)
        
        ttk.Button(frame, text="📁 Select Image", command=self.load_decode_image).pack(pady=5)
        
        # Key Input
        ttk.Label(frame, text="🔑 Decryption Key:").pack(pady=5)
        self.dec_key_entry = ttk.Entry(frame, show="•", width=60)
        self.dec_key_entry.pack()
        
        ttk.Button(frame, text="🔍 Decode Message", command=self.decode).pack(pady=15)
        
        # Result Display
        self.result_text = tk.Text(frame, height=8, width=60, state="disabled", wrap=tk.WORD)
        self.result_text.pack(pady=10)

    def create_status_bar(self):
        self.status = ttk.Label(self, text="Ready", style="Status.TLabel", anchor=tk.W)
        self.status.pack(side=tk.BOTTOM, fill=tk.X)

    def load_encode_image(self):
        self.encode_image_path = filedialog.askopenfilename(
            filetypes=[("Image Files", "*.png;*.jpg;*.jpeg")]
        )
        if self.encode_image_path:
            try:
                img = Image.open(self.encode_image_path)
                img.thumbnail((400, 400))
                photo = ImageTk.PhotoImage(img)
                self.img_preview.config(image=photo, text="")
                self.img_preview.image = photo
                
                # Calculate max message capacity
                img_cv = cv2.imread(self.encode_image_path)
                self.max_message_length = img_cv.size // 8 - 16  # 16 chars for hash
                self.message_counter.config(text=f"0/{self.max_message_length} characters")
                
                self.status.config(text=f"Loaded: {self.encode_image_path}")
            except Exception as e:
                self.status.config(text="Error loading image")
                messagebox.showerror("Error", f"Failed to load image: {str(e)}")
                logging.error(f"Image load error: {str(e)}")

    def load_decode_image(self):
        self.decode_image_path = filedialog.askopenfilename(
            filetypes=[("Image Files", "*.png;*.jpg;*.jpeg")]
        )
        if self.decode_image_path:
            try:
                img = Image.open(self.decode_image_path)
                img.thumbnail((400, 400))
                photo = ImageTk.PhotoImage(img)
                self.decoded_preview.config(image=photo, text="")
                self.decoded_preview.image = photo
                self.status.config(text=f"Loaded: {self.decode_image_path}")
            except Exception as e:
                self.status.config(text="Error loading image")
                messagebox.showerror("Error", f"Failed to load image: {str(e)}")
                logging.error(f"Image load error: {str(e)}")

    def update_message_counter(self, event=None):
        current_length = len(self.msg_entry.get())
        self.message_counter.config(
            text=f"{current_length}/{self.max_message_length} characters",
            foreground="red" if current_length > self.max_message_length else "black"
        )

    def generate_key_hash(self, key):
        return hashlib.sha256(key.encode()).hexdigest()[:16]

    def encode(self):
        if self.processing:
            return
            
        key = self.key_entry.get()
        message = self.msg_entry.get()
        
        if not all([key, message, self.encode_image_path]):
            messagebox.showwarning("Warning", "Please complete all fields")
            return

        try:
            self.processing = True
            self.status.config(text="Encoding...")
            
            key_hash = self.generate_key_hash(key)
            full_message = key_hash + message + "@@@"
            
            img = cv2.imread(self.encode_image_path)
            if img is None:
                raise ValueError("Invalid image file")
                
            flat_img = img.copy().flatten()
            bin_message = ''.join(format(ord(c), '08b') for c in full_message)
            
            if len(bin_message) > len(flat_img):
                raise ValueError("Message exceeds image capacity")
                
            # Safe bitwise operation using 0xFE mask
            for i in range(len(bin_message)):
                flat_img[i] = (flat_img[i] & 0xFE) | int(bin_message[i])
                
            encoded_img = flat_img.reshape(img.shape)
            save_path = filedialog.asksaveasfilename(
                defaultextension=".png",
                filetypes=[("PNG Files", "*.png")]
            )
            
            if save_path:
                cv2.imwrite(save_path, encoded_img)
                messagebox.showinfo("Success", "Message encoded successfully!")
                self.status.config(text="Encoding complete")
                
        except Exception as e:
            self.status.config(text="Encoding failed")
            messagebox.showerror("Error", f"Encoding failed: {str(e)}")
            logging.error(f"Encoding error: {str(e)}")
        finally:
            self.processing = False

    def decode(self):
        if self.processing:
            return
            
        key = self.dec_key_entry.get()
        if not all([key, self.decode_image_path]):
            messagebox.showwarning("Warning", "Please complete all fields")
            return

        try:
            self.processing = True
            self.status.config(text="Decoding...")
            
            key_hash = self.generate_key_hash(key)
            img = cv2.imread(self.decode_image_path)
            
            if img is None:
                raise ValueError("Invalid image file")
                
            flat_img = img.flatten()
            bits = [str(flat_img[i] & 1) for i in range(len(flat_img))]
            chars = [chr(int(''.join(bits[i:i+8]), 2)) for i in range(0, len(bits), 8)]
            decoded_message = ''.join(chars)
            
            if key_hash not in decoded_message:
                raise ValueError("Invalid key or no hidden message")
                
            final_message = decoded_message.split('@@@')[0].replace(key_hash, '')
            
            self.result_text.config(state="normal")
            self.result_text.delete(1.0, tk.END)
            self.result_text.insert(tk.END, final_message)
            self.result_text.config(state="disabled")
            self.status.config(text="Decoding complete")
            
        except Exception as e:
            self.status.config(text="Decoding failed")
            messagebox.showerror("Error", f"Decoding failed: {str(e)}")
            logging.error(f"Decoding error: {str(e)}")
        finally:
            self.processing = False

if __name__ == "__main__":
    app = SteganoApp()
    app.mainloop()