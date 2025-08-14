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


