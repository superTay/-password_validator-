
# Importing datetime library for log-decorator

import datetime
from functools import wraps
import json

# Custom exception classes
class PasswordWeakError(Exception):
    """Raised when the password does not meet security requirements."""
    pass

class UserAlreadyExistsError(Exception):
    """Raised when trying to register a username that already exists."""
    pass

class UserNotFoundError(Exception):
    """Raised when the username does not exist during sign in."""
    pass

class IncorrectPasswordError(Exception):
    """Raised when password check fails."""
    pass

class PasswordValidator:
    """
    A utility class for validating the strength and security of user passwords.

    This class provides a static method to verify that a given password meets 
    specific security criteria, such as minimum length, inclusion of uppercase 
    letters, digits, and special characters. If the password does not satisfy 
    these requirements, a detailed exception is raised describing the unmet criteria.

    Usage:
        PasswordValidator.validate(password)

    Where:
        password (str): The password string to be validated.

    Raises:
        PasswordWeakError: If the password fails one or more security checks,
                           containing a message detailing the issues.
    """
    @staticmethod
    def validate(password: str):
        errors = []

        if len(password) < 8:
            errors.append("La contraseña debe tener al menos 8 caracteres.")
        if not any(c.isupper() for c in password):
            errors.append("La contraseña debe tener al menos una letra mayúscula.")
        if not any(c.isdigit() for c in password):
            errors.append("La contraseña debe tener al menos un número.")
        if not any(c in "_#*@" for c in password):
            errors.append("La contraseña debe contener al menos uno de estos caracteres especiales: _ # * @")

        if errors:
            raise PasswordWeakError("\n".join(errors))

class User:
    """
    Represents a system user with a username and password.

    This class encapsulates the basic attributes of a user and provides 
    a simple interface to access user information. Password validation 
    is expected to be handled externally before instantiation.

    Attributes:
        username (str): The unique identifier for the user.
        password (str): The user's password stored as a string.

    Methods:
        __str__: Returns a string representation of the user, displaying the username.
    """
    def __init__(self, username: str, password: str):
        self.username = username
        self.password = password

    def __str__(self):
        return f"User(username={self.username})"



# log - decorator function

def log_call(func):
   @wraps(func)
   def wrapper(*args, **kwargs):
       print(f"Function name: {func.__name__}")# Function name
       fecha = datetime.datetime.now()
       print(f"[{fecha.strftime('%Y-%m-%d %H:%M:%S')}] Called function: {func.__name__}")
       print(f"Arguments: args={args}, kwargs={kwargs}")

       result = func(*args, **kwargs)  # Execute the original function
        
       print(f"Result: {result}\n")  # Log the returned result
       return result  # Return the result to maintain functionality

   return wrapper


# Function to user sign in
@log_call
def sign_in():
    """
    Prompts the user to enter their username and password.

    Returns:
        tuple[str, str]: A tuple containing the entered username and password.
        """
    username_input = input("Enter your username: ")
    password_input = input("Enter your password: ")
    return username_input, password_input

# Check If a user_list exists, and If it does, load it from json. 

def load_users_from_json():
    """
    Check If the file exists
    """

    try:

        with open ("users.json", "r") as file:
           user_list = json.load(file)
           return user_list
        
    except FileNotFoundError:
       return []
  
    except json.JSONDecodeError:
       print("⚠️ The file users.json exists but does not contain valid data")
       return []


# Saving users

def save_users_to_json(user_list):

    """Open user list in writing mode. 
    Then we save the user list (json.dump)
    """
    # file opening
    with open ("users.json","w") as file:
   # file saving with same structure
      json.dump(user_list,file, indent=4)


# Function to check if the user exists
@log_call
def check_user_exists(username, user_list):
    """
    Checks if a given username exists in the provided user list.

    Args:
        username (str): The username to check.
        user_list (list): List of user dictionaries with 'username' and 'password' keys.

    Returns:
        bool: True if the username exists, False otherwise.
        """
    for user in user_list:
        if user["username"] == username:
            return True
    return False

# Adding new user:

def add_new_user(username, password):
   # 1. Load the current list of users from the file (or empty list if it doesn't exist)
   user_list = load_users_from_json()

   # 2. Check if the user already exists to avoid duplicates
   if check_user_exists(username, user_list):
       print(f"❌ The user '{username}' already exists.")
       return False  # Indicate that it was not added

   # 3. If it doesn't exist, add the new user (dictionary) to the list
   user_list.append({"username": username, "password": password})

   # 4. Save the updated list of users to the JSON file
   save_users_to_json(user_list)

   print(f"✅ User '{username}' added successfully.")
   return True  # Indicate success


# Function to user sign up
@log_call 
def sign_up(user_list):
    """
    Handles user registration.
    Asks the user to choose a unique username, then prompts for a strong password
    until it meets all security requirements. Adds the new user to the user_list.

    Returns:
        tuple[str, str]: The username and password of the newly created account.
        """
     # Ask for a valid username

    while True:
        username_input = input("Choose a username: ").strip()
        
        # Check if username already exists in the user list
        if check_user_exists(username_input, user_list):
            print ("❌ That username is already taken. Please choose another.")
            continue  # Go back to the start of the loop and ask again
        
        # If we reach here, the username is available — break the loop
        break

    # Now that we have a valid username, ask for password
    while True:
        try:
            password_input = input("Choose a password: ").strip()
            password_validation(password_input)  # Esta función lanza excepción si es débil
            # Si no lanza excepción, contraseña es válida
            print("✅ Account created successfully!")
            return username_input, password_input
        except PasswordWeakError as e:
            print(e)
            print("Please try again with a stronger password.")
            
# Function that checks whether the entered password is valid
# based on a set of security requirements.

@log_call
def password_validation(password):
    """
    Validates a password against security requirements.

    The password must meet the following criteria:
      - Minimum length of 8 characters.
      - At least one uppercase letter.
      - At least one number.
      - At least one special character from the set: _ # *

    Args:
        password (str): The password string to validate.

    Returns:
        tuple[bool, str]:
            - bool: True if the password meets all requirements, False otherwise.
            - str: "Password is correct." if valid, or a concatenated string of error messages if invalid.
            """
    
    errors = []

    # Requirement 1: Minimum length of 8 characters
    if len(password) < 8:
        errors.append (" ❌ The password must be at least 8 characters long.")

    # Flags to track presence of different character types
    has_uppercase = False   # At least one uppercase letter
    has_number = False      # At least one digit
    special_characters = "_#*@"  # Allowed special characters
    has_special = False     # At least one of the allowed special characters

    # Check each character in the password
    for char in password:
        if char.isupper():          # Requirement 2: Uppercase letter
            has_uppercase = True
        if char.isdigit():          # Requirement 3: Number
            has_number = True
        if char in special_characters:  # Requirement 4: Special character
            has_special = True

    # Validate uppercase letter requirement
    if not has_uppercase:
        errors.append(" ❌ The password must contain at least one uppercase letter.")

    # Validate number requirement
    if not has_number:
        errors.append(" ❌ The password must contain at least one number.")

    # Validate special character requirement
    if not has_special:
        errors.append(" ❌ The password must contain at least one of these characters: _ # *")

    # Return results: False with error messages if criteria not met, else True with success message
    
    if errors:
            raise PasswordWeakError("\n".join(errors))
    


# Example of usage

def main():
    # Loading the user list
    user_list = load_users_from_json()

    print("Welcome!\n")
    # MENU LOOP: ask once until valid choice, then process sign in or sign up
    while True:
        try:
            choice = input("Do you want to [1] Sign in or [2] Sign up? Enter 1 or 2: ").strip()
            if choice not in ["1", "2"]:
                print("❌ Invalid option. Please enter 1 for Sign in or 2 for Sign up.")
                continue

            if choice == "1":
                # Sign in flow: nested loops for username and password input
                while True:
                    username_input = input("Enter your username: ")
                    if not check_user_exists(username_input, user_list):
                        print("❌ User not found. Please try again or sign up first.")
                        continue  # Repeat username input

                    # Username exists, now ask repeatedly for password until correct
                    while True:
                        password_input = input("Enter your password: ")
                        for user in user_list:
                            if user["username"] == username_input and user["password"] == password_input:
                                print("✅ Login successful!")
                                break  # Exit password for-loop
                        else:
                            print("❌ Incorrect password. Please try again.")
                            continue  # Repeat password input
                        break  # Correct password, exit password loop
                    break  # Username and password correct, exit sign-in loop

            elif choice == "2":
                # Sign up flow with its own validations and loops
                new_user, new_password = sign_up(user_list)
                #  Add the new user to the in-memory list
                user_list.append({"username": new_user, "password": new_password})
                # Save the updated user list to the JSON file for persistence
                save_users_to_json(user_list)
                print(f"✅ User '{new_user}' successfully registered and saved.")

            break  # Exit main menu loop on successful sign in or sign up

        except KeyboardInterrupt:
            print("\nProcess interrupted by user. Exiting gracefully.")
            break
        except Exception as e:
            print(f"An unexpected error occurred: {e}")

main()


