import bcrypt
import os

USER_DATA_FILE = "user.txt"

def hash_password(plain_text_password):
    password_bytes = plain_text_password.encode('utf-8')
    salt = bcrypt.gensalt()
    hashed = bcrypt.hashpw(password_bytes, salt)
    return hashed.decode('utf-8')

def verify_password(plain_text_password, hashed_password):
    password_bytes = plain_text_password.encode('utf-8')
    hash_bytes = hashed_password.encode('utf-8')
    return bcrypt.checkpw(password_bytes, hash_bytes)

def register_user(username, password):
    if user_exists(username):
        return False
    hashed = hash_password(password)
    with open(USER_DATA_FILE, 'a') as f:
        f.write(f"{username}:{hashed}\n")
    return True

def user_exists(username):
    if not os.path.exists(USER_DATA_FILE):
        return False

    with open(USER_DATA_FILE, "r") as f:
        for line in f:
            if ":" not in line:
                continue
            stored_username = line.strip().split(":", 1)[0]
            if stored_username == username:
                return True

    return False

def login_user(username, password):
    if not os.path.exists(USER_DATA_FILE):
        return False

    with open(USER_DATA_FILE, "r") as f:
        for line in f:
            if ":" not in line:
                continue
            stored_username, stored_hash = line.strip().split(":", 1)
            if stored_username == username:
                return verify_password(password, stored_hash)

    return False

def validate_username(username):
    if len(username) < 3 or len(username) > 20:
        return False, "Username must be between 3 and 20 characters."
    if not username.isalnum():
        return False, "Username must only contain letters and numbers."
    return True, ""

def validate_password(password):
    if len(password) < 6 or len(password) > 50:
        return False, "Password must be between 6 and 50 characters."
    if not any(c.islower() for c in password):
        return False, "Password must include a lowercase letter."
    if not any(c.isupper() for c in password):
        return False, "Password must include an uppercase letter."
    if not any(c.isdigit() for c in password):
        return False, "Password must include a number."
    return True, ""

def display_menu():
    """Displays the main menu options."""
    print("\n" + "="*50)
    print(" MULTI-DOMAIN INTELLIGENCE PLATFORM")
    print(" Secure Authentication System")
    print("="*50)
    print("\n[1] Register a new user")
    print("[2] Login")
    print("[3] Exit")
    print("-"*50)

def main():
    """Main program loop."""
    print("\nWelcome to the Week 7 Authentication System!")
    while True:
        display_menu()
        choice = input("\nPlease select an option (1-3): ").strip()

        if choice == '1':
            # Registration flow
            print("\n--- USER REGISTRATION ---")
            username = input("Enter a username: ").strip()

            # Validate username
            is_valid, error_msg = validate_username(username)
            if not is_valid:
                print(f"Error: {error_msg}")
                continue

            password = input("Enter a password: ").strip()
            # Validate password
            is_valid, error_msg = validate_password(password)
            if not is_valid:
                print(f"Error: {error_msg}")
                continue

            # Confirm password
            password_confirm = input("Confirm password: ").strip()
            if password != password_confirm:
                print("Error: Passwords do not match.")
                continue

            # Register the user
            if register_user(username, password):
                print("Registration successful.")
            else:
                print("Registration failed: user may already exist.")
            input("\nPress Enter to return to main menu...")

        elif choice == '2':
            # Login flow
            print("\n--- USER LOGIN ---")
            username = input("Enter your username: ").strip()
            password = input("Enter your password: ").strip()

            # Attempt login
            if login_user(username, password):
                print("\nYou are now logged in.")
                print("(In a real application, you would now access the dashboard.)")
            else:
                print("Login failed: invalid username or password.")
            input("\nPress Enter to return to main menu...")

        elif choice == '3':
            # Exit
            print("\nThank you for using the authentication system.")
            print("Exiting...")
            break

        else:
            print("\nError: Invalid option. Please select 1, 2, or 3.")

if __name__ == "__main__":
    main()




