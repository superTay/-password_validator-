
# Importing datetime library for log-decorator

import datetime
from functools import wraps

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

# List of users
user_list = [
    {"username": "user1", "password": "pass1234"},
    {"username": "user2", "password": "pass5678"},
]

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

# Function to user sign up
@log_call 
def sign_up():
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
            print("❌ That username is already taken. Please choose another.")
            continue  # Go back to the start of the loop and ask again
        
        # If we reach here, the username is available — break the loop
        break

    # Now that we have a valid username, ask for password
    while True:
        password_input = input("Choose a password: ").strip()
        is_valid, message = password_validation(password_input)
        if is_valid:
            # Save the new user into the list
            user_list.append({"username": username_input, "password": password_input})
            print("✅ Account created successfully!")
            return username_input, password_input  # Return the new credentials
        else:
            # Show all password rule errors and ask again
            print(message)
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
        errors.append(" ❌ The password must be at least 8 characters long.")

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
        return False, "\n".join(errors)
    else:
        return True, "Password is correct."


# Example of usage

def main():
    print("Welcome!\n")
    # Ask the user if he wants sign in or sign up and managin errors
    # MENU: Ask once
    while True:
        choice = input("Do you want to [1] Sign in or [2] Sign up? Enter 1 or 2: ").strip()
        if choice in ["1", "2"]:
            break
        else:
            print("❌ Invalid option. Please enter 1 for Sign in or 2 for Sign up.")

    # ROUTING based on choice

    if choice == "1":
        # SIGN IN FLOW
        username_input, password_input = sign_in()
        # Check if the username exists before entering the loop
        if not check_user_exists(username_input, user_list):
            print("❌ User not found. Please sign up first.")
        else:
        # Password retry loop
            while True:
                password_input = input("Enter your password: ")
                for user in user_list:
                    if user["username"] == username_input and user["password"] == password_input:
                        print("✅ Login successful!")
                        break  # Exit for loop
                else:
                # Only runs if no break occurred in the for loop
                    print("❌ Incorrect password. Please try again.")
                    continue  # Retry password

                break  # If login was successful, exit while loop
                             

    elif choice == "2":
        # SIGN UP FLOW
        new_user, new_password = sign_up()

if __name__ == "__main__":
    main()



