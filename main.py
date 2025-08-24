
# Importing datetime library for log-decorator

import datetime
from functools import wraps
import json

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
    @log_call
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


class UserManager:
    """
    Manages a collection of User objects, including user registration,
    authentication, and persistence to a JSON file.

    This class handles loading users from a file, saving updates, checking
    existence of usernames, signing up new users with password validation,
    and signing in existing users with credential verification.

    Attributes:
        file_path (str): The path to the JSON file storing user data.
        users (list[User]): The list of User objects currently managed.

    Methods:
        load_users() -> list[User]:
            Loads and returns a list of User objects from the JSON file.
            Returns an empty list if the file does not exist.

        save_users() -> None:
            Saves the current list of User objects to the JSON file,
            serializing them to dictionaries.

        user_exists(username: str) -> bool:
            Checks if a user with the given username exists in the managed list.
            Returns True if the username is found, False otherwise.

        sign_up(username: str, password: str) -> None:
            Registers a new user with the specified username and password.
            Validates that the username is unique and the password meets security requirements.
            Raises UserAlreadyExistsError or PasswordWeakError on failure.

        sign_in(username: str, password: str) -> User:
            Authenticates a user by username and password.
            Returns the corresponding User object on success.
            Raises UserNotFoundError or IncorrectPasswordError if authentication fails.
            
            """
    def __init__(self, file_path="users.json"):
        self.file_path = file_path
        self.users = self.load_users()

    def load_users(self):
        try:
            with open(self.file_path, "r") as f:
                users_data = json.load(f)
            return [User(u["username"], u["password"]) for u in users_data]
        except FileNotFoundError:
            return []

    def save_users(self):
        users_data = [{"username": u.username, "password": u.password} for u in self.users]
        with open(self.file_path, "w") as f:
            json.dump(users_data, f, indent=4)


    @log_call
    def user_exists(self, username: str) -> bool:
        return any(u.username == username for u in self.users)

    @log_call
    def sign_up(self, username: str, password: str):
        if self.user_exists(username):
            raise UserAlreadyExistsError(f"The user '{username}' already exists.")

        PasswordValidator.validate(password)  # Validar antes de crear

        new_user = User(username, password)
        self.users.append(new_user)
        self.save_users()

    @log_call
    def sign_in(self, username: str, password: str):
        for user in self.users:
            if user.username == username:
                if user.password == password:
                    return user
                else:
                    raise IncorrectPasswordError("Incorrect Password.")
        raise UserNotFoundError("User Not Found.")

# Example of usage

def main():
    user_manager = UserManager()

    while True:
        choice = input("Enter 1 to Sign Up, 2 to Sign In, 0 to Exit: ")
        if choice == "1":
         while True:
            username = input("Username: ")
            password = input("Password: ")
            try:
                user_manager.sign_up(username, password)
                print("User registered successfully.")
                break
            except Exception as e:
                print(f"Error: {e}")
                retry = input("Try again? (y/n): ").lower()
                if retry != 'y':
                        break
        elif choice == "2":
            username = input("Username: ")
            password = input("Password: ")
            try:
                user = user_manager.sign_in(username, password)
                print(f"Welcome back, {user.username}!")
            except Exception as e:
                print(f"Error: {e}")
        elif choice == "0":
            print("Goodbye!")
            break
        else:
            print("Invalid option. Try again.")

if __name__ == "__main__":
    main()

