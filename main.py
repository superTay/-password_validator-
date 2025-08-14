
# List of users
user_list = [
    {"username": "user1", "password": "pass1234"},
    {"username": "user2", "password": "pass5678"},
]

# Function to prompt the user for input
def get_user_input():
    username_input = input("Enter your username: ")
    password_input = input("Enter your password: ")
    return username_input, password_input

# Function to check if the user exists

def check_user_exists(username, user_list):
    for user in user_list:
        if user["username"] == username:
            return True
    return False

# Function that checks whether the entered password is valid
# based on a set of security requirements.
def password_validation(password):
    errors = []

    # Requirement 1: Minimum length of 8 characters
    if len(password) < 8:
        errors.append(" ❌ The password must be at least 8 characters long.")

    # Flags to track presence of different character types
    has_uppercase = False   # At least one uppercase letter
    has_number = False      # At least one digit
    special_characters = "_#*"  # Allowed special characters
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
# Ask the user if he wants sign in or sign up

choice = input("Do you want to [1] Sign in or [2] Sign up? Enter 1 or 2: ")

# Managing errors

while True:
    choice = input("Do you want to [1] Sign in or [2] Sign up? Enter 1 or 2: ").strip()
    if choice in ["1", "2"]:
        break
    else:
        print("❌ Invalid option. Please enter 1 for Sign in or 2 for Sign up.")


if choice == "1":
    # SIGN IN
    username_input, password_input = get_user_input()
    
    if check_user_exists(username_input, user_list):
        for user in user_list:
            if user["username"] == username_input and user["password"] == password_input:
                print("✅ Login successful!")
                break
        else:
            print("❌ Incorrect password.")
    else:
        print("❌ User not found. Please sign up first.")

elif choice == "2":
    # SIGN UP
    username_input = input("Choose a username: ")
    
    if check_user_exists(username_input, user_list):
        print("❌ That username is already taken. Please choose another.")
    else:
        password_input = input("Choose a password: ")
        while True:
            is_valid, message = password_validation(password_input)
            if is_valid:
                user_list.append({"username": username_input, "password": password_input})
                print("✅ Account created successfully!")
                break
            else:
                print(message)
                password_input = input("Please enter a valid password: ")
else:
    print("❌ Invalid option. Please restart the program.")



