import tkinter as tk
from tkinter import messagebox, simpledialog, scrolledtext
import json
import base64
import os
import secrets
import string
import hashlib
from cryptography.fernet import Fernet, InvalidToken
import pyperclip # For easy clipboard operations (install with: pip install pyperclip)

# --- Configuration ---
DATA_FILE = "passwords.dat" # File to store encrypted passwords
MASTER_PASSWORD_HASH_FILE = "master_hash.dat" # File to store master password hash
SALT_SIZE = 16 # Size of the salt for master password hashing

# --- Security Functions ---

def generate_key_from_master(master_password, salt):
    """
    Derives a cryptographic key from the master password using PBKDF2.
    """
    kdf = hashlib.pbkdf2_hmac(
        'sha256',
        master_password.encode('utf-8'),
        salt,
        100000 # Number of iterations, higher is more secure but slower
    )
    return base64.urlsafe_b64encode(kdf)

def load_master_password_hash_and_salt():
    """
    Loads the master password hash and salt from a file.
    Returns (hashed_password, salt) or (None, None) if file not found.
    """
    if os.path.exists(MASTER_PASSWORD_HASH_FILE):
        try:
            with open(MASTER_PASSWORD_HASH_FILE, 'rb') as f:
                data = f.read()
                if len(data) >= SALT_SIZE:
                    salt = data[:SALT_SIZE]
                    hashed_password = data[SALT_SIZE:]
                    return hashed_password, salt
                else:
                    print("Warning: Master password hash file corrupted (salt too short).")
                    return None, None
        except Exception as e:
            print(f"Error loading master password hash: {e}")
            return None, None
    return None, None

def save_master_password_hash_and_salt(hashed_password, salt):
    """
    Saves the master password hash and salt to a file.
    """
    try:
        with open(MASTER_PASSWORD_HASH_FILE, 'wb') as f:
            f.write(salt + hashed_password)
    except Exception as e:
        messagebox.showerror("Error", f"Failed to save master password hash: {e}")

def hash_master_password(master_password, salt=None):
    """
    Hashes the master password with a salt. Generates a new salt if not provided.
    Returns (hashed_password, salt).
    """
    if salt is None:
        salt = os.urandom(SALT_SIZE) # Generate a random salt
    
    hashed_password = hashlib.pbkdf2_hmac(
        'sha256',
        master_password.encode('utf-8'),
        salt,
        100000 # Number of iterations
    )
    return hashed_password, salt

# --- Password Manager Core Logic ---

class PasswordManager:
    def __init__(self):
        self.fernet_key = None
        self.passwords = {} # Dictionary to store password entries: {service: {"username": "", "password": ""}}
        self.is_authenticated = False

    def authenticate_master_password(self):
        """
        Handles master password setup or login.
        """
        hashed_master_password, salt = load_master_password_hash_and_salt()

        if hashed_master_password is None:
            # First run: Set up new master password
            while True:
                new_master_pw = simpledialog.askstring("Setup Master Password", "Enter a new master password:", show='*')
                if not new_master_pw:
                    messagebox.showerror("Error", "Master password cannot be empty.")
                    return False
                confirm_master_pw = simpledialog.askstring("Confirm Master Password", "Confirm your new master password:", show='*')
                if new_master_pw == confirm_master_pw:
                    hashed_pw, new_salt = hash_master_password(new_master_pw)
                    save_master_password_hash_and_salt(hashed_pw, new_salt)
                    self.fernet_key = generate_key_from_master(new_master_pw, new_salt)
                    self.is_authenticated = True
                    messagebox.showinfo("Success", "Master password set successfully!")
                    self.load_passwords() # Load any existing (but unreadable) data if present
                    return True
                else:
                    messagebox.showerror("Error", "Passwords do not match. Please try again.")
        else:
            # Subsequent runs: Authenticate with existing master password
            for _ in range(3): # Allow 3 attempts
                entered_master_pw = simpledialog.askstring("Enter Master Password", "Enter your master password to unlock:", show='*')
                if not entered_master_pw:
                    messagebox.showerror("Error", "Master password cannot be empty. Exiting.")
                    return False

                entered_hashed_pw, _ = hash_master_password(entered_master_pw, salt)
                if entered_hashed_pw == hashed_master_password:
                    self.fernet_key = generate_key_from_master(entered_master_pw, salt)
                    self.is_authenticated = True
                    messagebox.showinfo("Success", "Authenticated successfully!")
                    self.load_passwords()
                    return True
                else:
                    messagebox.showwarning("Authentication Failed", "Incorrect master password. Please try again.")
            messagebox.showerror("Authentication Failed", "Too many incorrect attempts. Exiting.")
            return False

    def encrypt_data(self, data):
        """Encrypts data using the Fernet key."""
        if not self.fernet_key:
            raise ValueError("Encryption key not set. Authenticate first.")
        f = Fernet(self.fernet_key)
        return f.encrypt(data.encode('utf-8'))

    def decrypt_data(self, encrypted_data):
        """Decrypts data using the Fernet key."""
        if not self.fernet_key:
            raise ValueError("Encryption key not set. Authenticate first.")
        f = Fernet(self.fernet_key)
        try:
            return f.decrypt(encrypted_data).decode('utf-8')
        except InvalidToken:
            raise ValueError("Invalid master password or corrupted data.")

    def load_passwords(self):
        """Loads and decrypts passwords from the data file."""
        if not self.is_authenticated:
            return
        
        if os.path.exists(DATA_FILE):
            try:
                with open(DATA_FILE, 'rb') as f:
                    encrypted_data = f.read()
                decrypted_json = self.decrypt_data(encrypted_data)
                self.passwords = json.loads(decrypted_json)
                messagebox.showinfo("Load Success", "Passwords loaded successfully.")
            except FileNotFoundError:
                self.passwords = {}
            except ValueError as e:
                messagebox.showerror("Decryption Error", f"Could not decrypt passwords. Data might be corrupted or master password is wrong. Error: {e}")
                self.passwords = {} # Clear potentially corrupted data
            except json.JSONDecodeError:
                messagebox.showerror("Data Error", "Password data file is corrupted (invalid JSON).")
                self.passwords = {}
            except Exception as e:
                messagebox.showerror("Error", f"An unexpected error occurred while loading passwords: {e}")
                self.passwords = {}
        else:
            self.passwords = {}

    def save_passwords(self):
        """Encrypts and saves passwords to the data file."""
        if not self.is_authenticated:
            messagebox.showwarning("Not Authenticated", "Cannot save passwords without authentication.")
            return

        try:
            json_data = json.dumps(self.passwords, indent=4)
            encrypted_data = self.encrypt_data(json_data)
            with open(DATA_FILE, 'wb') as f:
                f.write(encrypted_data)
            messagebox.showinfo("Save Success", "Passwords saved successfully.")
        except Exception as e:
            messagebox.showerror("Save Error", f"Failed to save passwords: {e}")

    def add_password(self, service, username, password):
        """Adds a new password entry."""
        if not service or not username or not password:
            messagebox.showwarning("Input Error", "All fields (Service, Username, Password) must be filled.")
            return False
        
        if service in self.passwords:
            if not messagebox.askyesno("Overwrite?", f"Service '{service}' already exists. Overwrite?"):
                return False

        self.passwords[service] = {"username": username, "password": password}
        self.save_passwords()
        return True

    def get_password(self, service):
        """Retrieves a password entry."""
        return self.passwords.get(service)

    def delete_password(self, service):
        """Deletes a password entry."""
        if service in self.passwords:
            if messagebox.askyesno("Confirm Delete", f"Are you sure you want to delete the entry for '{service}'?"):
                del self.passwords[service]
                self.save_passwords()
                messagebox.showinfo("Deleted", f"Entry for '{service}' deleted.")
                return True
        else:
            messagebox.showwarning("Not Found", f"No entry found for '{service}'.")
            return False
        return False

    def generate_strong_password(self, length=16, use_uppercase=True, use_lowercase=True, use_digits=True, use_symbols=True):
        """
        Generates a strong random password based on specified criteria.
        """
        characters = ""
        if use_lowercase:
            characters += string.ascii_lowercase
        if use_uppercase:
            characters += string.ascii_uppercase
        if use_digits:
            characters += string.digits
        if use_symbols:
            characters += string.punctuation

        if not characters:
            messagebox.showwarning("Generation Error", "Please select at least one character type for password generation.")
            return ""

        password = ''.join(secrets.choice(characters) for _ in range(length))
        return password

# --- GUI Application ---

class PasswordManagerApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Secure Password Manager")
        self.root.geometry("800x600")
        self.root.resizable(True, True) # Allow resizing

        self.pm = PasswordManager()

        # Center the window on the screen
        self.root.update_idletasks()
        width = self.root.winfo_width()
        height = self.root.winfo_height()
        x = (self.root.winfo_screenwidth() // 2) - (width // 2)
        y = (self.root.winfo_screenheight() // 2) - (height // 2)
        self.root.geometry(f'{width}x{height}+{x}+{y}')

        # Apply a modern look (basic styling)
        self.root.tk_setPalette(background='#f0f0f0', foreground='#333333',
                                activeBackground='#e0e0e0', activeForeground='#000000')

        # Authentication check on startup
        if not self.pm.authenticate_master_password():
            self.root.destroy() # Close the app if authentication fails
            return

        self.create_widgets()
        self.update_password_list()

    def create_widgets(self):
        # Frame for input fields
        input_frame = tk.Frame(self.root, padx=10, pady=10, bd=2, relief="groove")
        input_frame.pack(pady=10, padx=10, fill="x")

        tk.Label(input_frame, text="Service/Website:", anchor="w").grid(row=0, column=0, sticky="w", pady=2)
        self.service_entry = tk.Entry(input_frame, width=50)
        self.service_entry.grid(row=0, column=1, sticky="ew", padx=5, pady=2)

        tk.Label(input_frame, text="Username/Email:", anchor="w").grid(row=1, column=0, sticky="w", pady=2)
        self.username_entry = tk.Entry(input_frame, width=50)
        self.username_entry.grid(row=1, column=1, sticky="ew", padx=5, pady=2)

        tk.Label(input_frame, text="Password:", anchor="w").grid(row=2, column=0, sticky="w", pady=2)
        self.password_entry = tk.Entry(input_frame, width=50, show="*") # Password hidden by default
        self.password_entry.grid(row=2, column=1, sticky="ew", padx=5, pady=2)

        # Buttons for actions
        button_frame = tk.Frame(self.root, padx=10, pady=5)
        button_frame.pack(pady=5, padx=10, fill="x")

        tk.Button(button_frame, text="Add/Update Password", command=self.add_update_password, bg="#4CAF50", fg="white", relief="raised", bd=3, padx=10, pady=5).pack(side="left", padx=5)
        tk.Button(button_frame, text="Generate Password", command=self.open_password_generator, bg="#2196F3", fg="white", relief="raised", bd=3, padx=10, pady=5).pack(side="left", padx=5)
        tk.Button(button_frame, text="Copy Password", command=self.copy_selected_password, bg="#FFC107", fg="black", relief="raised", bd=3, padx=10, pady=5).pack(side="left", padx=5)
        tk.Button(button_frame, text="Delete Selected", command=self.delete_selected_password, bg="#F44336", fg="white", relief="raised", bd=3, padx=10, pady=5).pack(side="left", padx=5)
        
        self.show_hide_button = tk.Button(button_frame, text="Show Passwords", command=self.toggle_password_visibility, bg="#9E9E9E", fg="white", relief="raised", bd=3, padx=10, pady=5)
        self.show_hide_button.pack(side="left", padx=5)

        # Search functionality
        search_frame = tk.Frame(self.root, padx=10, pady=5)
        search_frame.pack(pady=5, padx=10, fill="x")

        tk.Label(search_frame, text="Search:", anchor="w").pack(side="left")
        self.search_entry = tk.Entry(search_frame, width=40)
        self.search_entry.pack(side="left", padx=5, fill="x", expand=True)
        self.search_entry.bind("<KeyRelease>", self.filter_password_list)

        # Password list display
        list_frame = tk.Frame(self.root, padx=10, pady=10, bd=2, relief="sunken")
        list_frame.pack(pady=10, padx=10, fill="both", expand=True)

        self.password_list = scrolledtext.ScrolledText(list_frame, wrap=tk.WORD, height=15, font=("Consolas", 10), state="disabled")
        self.password_list.pack(fill="both", expand=True)
        # Bind double-click to load selected entry
        self.password_list.bind("<Double-Button-1>", self.load_selected_entry_to_fields)


    def add_update_password(self):
        """Adds or updates a password entry based on input fields."""
        service = self.service_entry.get().strip()
        username = self.username_entry.get().strip()
        password = self.password_entry.get().strip()

        if self.pm.add_password(service, username, password):
            self.clear_fields()
            self.update_password_list()

    def update_password_list(self, filter_text=""):
        """Refreshes the displayed list of passwords."""
        self.password_list.config(state="normal")
        self.password_list.delete(1.0, tk.END)
        
        if not self.pm.is_authenticated:
            self.password_list.insert(tk.END, "Please authenticate to view passwords.\n")
            self.password_list.config(state="disabled")
            return

        if not self.pm.passwords:
            self.password_list.insert(tk.END, "No passwords stored yet. Add one!\n")
        else:
            sorted_services = sorted(self.pm.passwords.keys())
            for service in sorted_services:
                if filter_text.lower() in service.lower(): # Filter by service name
                    entry = self.pm.passwords[service]
                    username = entry.get("username", "N/A")
                    password_display = entry.get("password", "N/A")
                    
                    # Hide password if toggle is off
                    if self.password_entry.cget("show") == "*":
                        password_display = "*" * len(password_display) if password_display != "N/A" else "N/A"

                    self.password_list.insert(tk.END, f"Service: {service}\n")
                    self.password_list.insert(tk.END, f"  User: {username}\n")
                    self.password_list.insert(tk.END, f"  Pass: {password_display}\n")
                    self.password_list.insert(tk.END, "-" * 50 + "\n")
        
        self.password_list.config(state="disabled")

    def filter_password_list(self, event=None):
        """Filters the password list based on search entry content."""
        filter_text = self.search_entry.get().strip()
        self.update_password_list(filter_text)

    def load_selected_entry_to_fields(self, event=None):
        """Loads the selected entry from the listbox into the input fields."""
        try:
            # Get the line number of the clicked text
            index = self.password_list.index(tk.CURRENT)
            line_num = int(float(index))
            
            # Find the start of the entry block (Service: ...)
            start_line = line_num
            while start_line > 1:
                line_content = self.password_list.get(f"{start_line}.0", f"{start_line}.end").strip()
                if line_content.startswith("Service:"):
                    break
                start_line -= 1
            
            # Extract service name from the identified line
            service_line = self.password_list.get(f"{start_line}.0", f"{start_line}.end").strip()
            if service_line.startswith("Service:"):
                service = service_line.replace("Service:", "").strip()
                
                entry = self.pm.get_password(service)
                if entry:
                    self.service_entry.delete(0, tk.END)
                    self.service_entry.insert(0, service)
                    self.username_entry.delete(0, tk.END)
                    self.username_entry.insert(0, entry["username"])
                    self.password_entry.delete(0, tk.END)
                    self.password_entry.insert(0, entry["password"])
                else:
                    messagebox.showwarning("Error", "Could not retrieve selected entry details.")
            else:
                messagebox.showwarning("Selection Error", "Please double-click on a 'Service:' line to load an entry.")

        except Exception as e:
            # This can happen if the user clicks on an empty area or separator
            # messagebox.showwarning("Selection Error", f"Could not load entry. Please select a valid entry. {e}")
            pass # Silently ignore clicks on non-entry lines for better UX

    def copy_selected_password(self):
        """Copies the password of the currently loaded entry to the clipboard."""
        service = self.service_entry.get().strip()
        if not service:
            messagebox.showwarning("No Entry Selected", "Please load an entry into the fields first or select one from the list.")
            return

        entry = self.pm.get_password(service)
        if entry:
            password = entry["password"]
            try:
                pyperclip.copy(password)
                messagebox.showinfo("Copied", f"Password for '{service}' copied to clipboard. It will be cleared in 10 seconds.")
                # Clear clipboard after a delay for security
                self.root.after(10000, self.clear_clipboard) 
            except pyperclip.PyperclipException:
                messagebox.showerror("Clipboard Error", "Failed to copy to clipboard. Pyperclip might not be configured correctly for your system.")
        else:
            messagebox.showwarning("Not Found", f"No entry found for '{service}'.")

    def clear_clipboard(self):
        """Clears the clipboard."""
        try:
            pyperclip.copy("")
            # messagebox.showinfo("Clipboard Cleared", "Clipboard has been cleared for security.")
        except pyperclip.PyperclipException:
            # print("Warning: Could not clear clipboard.")
            pass # Silently fail if clipboard can't be cleared

    def delete_selected_password(self):
        """Deletes the currently loaded entry."""
        service = self.service_entry.get().strip()
        if not service:
            messagebox.showwarning("No Entry Selected", "Please load an entry into the fields first.")
            return
        
        if self.pm.delete_password(service):
            self.clear_fields()
            self.update_password_list()

    def clear_fields(self):
        """Clears all input fields."""
        self.service_entry.delete(0, tk.END)
        self.username_entry.delete(0, tk.END)
        self.password_entry.delete(0, tk.END)

    def toggle_password_visibility(self):
        """Toggles the visibility of passwords in the entry field and list."""
        current_show_char = self.password_entry.cget("show")
        if current_show_char == "*":
            self.password_entry.config(show="")
            self.show_hide_button.config(text="Hide Passwords")
        else:
            self.password_entry.config(show="*")
            self.show_hide_button.config(text="Show Passwords")
        self.update_password_list(self.search_entry.get().strip()) # Refresh list to reflect visibility change

    def open_password_generator(self):
        """Opens a new window for password generation."""
        generator_window = tk.Toplevel(self.root)
        generator_window.title("Password Generator")
        generator_window.geometry("400x300")
        generator_window.transient(self.root) # Make it appear on top of the main window
        generator_window.grab_set() # Make it modal

        # Length
        tk.Label(generator_window, text="Password Length:").pack(pady=5)
        self.length_scale = tk.Scale(generator_window, from_=8, to=32, orient=tk.HORIZONTAL, length=200)
        self.length_scale.set(16) # Default length
        self.length_scale.pack(pady=5)

        # Character types
        self.use_uppercase = tk.BooleanVar(value=True)
        tk.Checkbutton(generator_window, text="Include Uppercase (A-Z)", variable=self.use_uppercase).pack(anchor="w")
        self.use_lowercase = tk.BooleanVar(value=True)
        tk.Checkbutton(generator_window, text="Include Lowercase (a-z)", variable=self.use_lowercase).pack(anchor="w")
        self.use_digits = tk.BooleanVar(value=True)
        tk.Checkbutton(generator_window, text="Include Digits (0-9)", variable=self.use_digits).pack(anchor="w")
        self.use_symbols = tk.BooleanVar(value=True)
        tk.Checkbutton(generator_window, text="Include Symbols (!@#$%)", variable=self.use_symbols).pack(anchor="w")

        # Generated password display
        self.generated_password_entry = tk.Entry(generator_window, width=40, state="readonly")
        self.generated_password_entry.pack(pady=10)

        # Generate and Copy buttons
        gen_button_frame = tk.Frame(generator_window)
        gen_button_frame.pack(pady=5)
        tk.Button(gen_button_frame, text="Generate", command=self.generate_and_display_password).pack(side="left", padx=5)
        tk.Button(gen_button_frame, text="Copy to Main Field", command=self.copy_generated_to_main).pack(side="left", padx=5)
        
        # Initial generation
        self.generate_and_display_password()

    def generate_and_display_password(self):
        """Generates a password and displays it in the generator window."""
        length = self.length_scale.get()
        password = self.pm.generate_strong_password(
            length=length,
            use_uppercase=self.use_uppercase.get(),
            use_lowercase=self.use_lowercase.get(),
            use_digits=self.use_digits.get(),
            use_symbols=self.use_symbols.get()
        )
        self.generated_password_entry.config(state="normal")
        self.generated_password_entry.delete(0, tk.END)
        self.generated_password_entry.insert(0, password)
        self.generated_password_entry.config(state="readonly")

    def copy_generated_to_main(self):
        """Copies the generated password to the main password entry field."""
        generated_pw = self.generated_password_entry.get()
        if generated_pw:
            self.password_entry.delete(0, tk.END)
            self.password_entry.insert(0, generated_pw)
            messagebox.showinfo("Copied", "Generated password copied to main password field.")
        else:
            messagebox.showwarning("No Password", "No password generated yet.")

if __name__ == "__main__":
    # Ensure pyperclip is installed
    try:
        import pyperclip
    except ImportError:
        messagebox.showerror("Missing Dependency", "The 'pyperclip' library is not installed. "
                                                 "Please install it using 'pip install pyperclip' "
                                                 "and restart the application.")
        sys.exit(1)

    root = tk.Tk()
    app = PasswordManagerApp(root)
    if app.is_authenticated: # Only start mainloop if authentication was successful
        root.mainloop()

