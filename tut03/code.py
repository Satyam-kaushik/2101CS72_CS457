def is_valid_password(password, criteria):
    if len(password) < 8:
        print(f"Password '{password}' is Invalid. Less than 8 characters.")
        return False

    if "uppercase" in criteria and not any(c.isupper() for c in password):
        print(f"Password '{password}' is Invalid. Missing Uppercase letters.")
        return False
    if "lowercase" in criteria and not any(c.islower() for c in password):
        print(f"Password '{password}' is Invalid. Missing Lowercase letters.")
        return False
    if "numbers" in criteria and not any(c.isdigit() for c in password):
        print(f"Password '{password}' is Invalid. Missing Numbers.")
        return False
    if "special_chars" in criteria:
        allowed_specials = {"!", "@", "#"}
        special_count = sum(1 for c in password if c in allowed_specials)
        if special_count == 0:
            print(f"Password '{password}' is Invalid. Missing Special characters.")
            return False
        if any(c not in allowed_specials and not c.isalnum() for c in password):
            print(f"Password '{password}' is Invalid. Contains unallowed special characters.")
            return False

    print(f"Password '{password}' is Valid.")
    return True

# Get user-selected criteria
criteria_options = {
    "1": "uppercase",
    "2": "lowercase",
    "3": "numbers",
    "4": "special_chars"
}

print("Select criteria by entering numbers separated by commas:")
print("1: Uppercase Letters (A-Z)")
print("2: Lowercase Letters (a-z)")
print("3: Numbers (0-9)")
print("4: Special Characters (!, @, #) [Only these 3 allowed]")

selected_criteria = input("Enter selected criteria: ").strip()
while not selected_criteria:
    selected_criteria = input("Please enter at least one criterion: ").strip()

selected_criteria = selected_criteria.split(",")
selected_criteria = [criteria_options[c.strip()] for c in selected_criteria if c.strip() in criteria_options]

#  Get password input from user
password_list = []
while True:
    try:
        n = int(input("Enter number of passwords: ").strip())
        if n > 0:
            break
        else:
            print("Please enter a positive number.")
    except ValueError:
        print("Invalid input. Please enter a valid number.")

for _ in range(n):
    password_list.append(input("Enter password: ").strip())

# Step 3: Define validation function


# Step 4: Validate passwords
for pwd in password_list:
    is_valid_password(pwd, selected_criteria)
