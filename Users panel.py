import ast
import hashlib
import getpass
# calling your database or making one
try:
    with open("Users.txt", 'r', encoding='utf-8') as f1:
        content = f1.read()
        Users = ast.literal_eval(content)
except:
    Users = {}
try:
    with open("Admin.txt", 'r', encoding='utf-8') as f2:
        content1 = f2.read()
        Admin = ast.literal_eval(content1)
except:
    Admin = {}
try:
    with open("Root.txt", 'r', encoding='utf-8') as f3:
        content1 = f3.read()
        Root = ast.literal_eval(content1)
    if not Root:
        print("There no data about Root, and must be at least one root")
        root_user = input("Please Enter your name >> ")
        root_password = getpass.getpass("Please Enter a password>> ")
        encoded_root_password = hashlib.sha256(
            root_password.encode('utf-8')).hexdigest()
        Root = {root_user: encoded_root_password}
        print(f"Welcome Root {root_user}")
        print(
            f"Now you have created Root User, You can use it to log in")
        Continue_Checking = "Elmasrey"
        while Continue_Checking.lower() not in ["y", "n"]:
            print("Do you want to Continue (y-n)")
            Continue_Checking = input(">> ")
        if Continue_Checking == "n":
            with open("Root.txt", 'w', encoding='utf-8') as f6:
                f6.write(str(Root))
            exit()
except:
    print("Welcome in our small program")
    root_user = input("Please Enter your name>> ")
    root_password = root_password = getpass.getpass(
        "Please Enter a password>> ")
    encoded_root_password = hashlib.sha256(
        root_password.encode('utf-8')).hexdigest()
    Root = {root_user: encoded_root_password}
    print(f"Welcome Root {root_user}")
    print(
        f"Now you have created Root User, You can use it to log in")
    Continue_Checking = "Elmasrey"
    while Continue_Checking.lower() not in ["y", "n"]:
        print("Do you want to Continue (y-n)")
        Continue_Checking = input(">> ")
    if Continue_Checking == "n":
        with open("Root.txt", 'w', encoding='utf-8') as f6:
            f6.write(str(Root))
        exit()

# main body


def main():
    counter = 1
    print("Please Log in\n")
    user_name = input("Please Enter The username>> ")
    while True:
        if Users.get(user_name) == None and Admin.get(user_name) == None and Root.get(user_name) == None:
            print("Wrong username, try again")
            user_name = input("Please Enter The username>> ")
            counter += 1
            if counter == 4:
                print("You are out of trying, Please Try again later")
                break
        else:
            password = getpass.getpass("Please Enter The password>> ")
            encoded_password = encoded_text(password)
            while Users.get(user_name) != encoded_password and Admin.get(user_name) != encoded_password and Root.get(user_name) != encoded_password:
                print("Wrong password, try again")
                password = getpass.getpass("Please Enter The password>> ")
                encoded_password = encoded_text(password)
                counter += 1
                if counter == 4:
                    print("You are out of trying, Please Try again later")
                    break
            if Root.get(user_name) == encoded_password:
                print(f"Welcome Root {user_name}, Have a nice day")
                edit_choice = 0
                while edit_choice not in ["1", "2", "3", "4"]:
                    print("Please choose from the following:-\n\
                    1)Edit in Users\n\
                    2)Edit is Admins\n\
                    3)Edit in Roots\n\
                    4)Exit")
                    edit_choice = input(">> ")
                if edit_choice == "1":
                    edit_in_Users_function()
                elif edit_choice == "2":
                    edit_in_Admins_function()
                elif edit_choice == "3":
                    edit_in_Roots_function()
                else:
                    print("Thank you, see you later")
                break
            elif Admin.get(user_name) == encoded_password:
                print(f"Welcome Administrator {user_name}, Have a nice day")
                edit_choice = 0
                while edit_choice not in ["1", "2", "3"]:
                    print("Please choose from the following:-\n\
                    1)Edit in Users\n\
                    2)Change Your password\n\
                    3)Exit")
                    edit_choice = input(">> ")
                if edit_choice == "1":
                    edit_in_Users_function()
                elif edit_choice == "2":
                    New_pass_for_Admin = getpass.getpass(
                        "Please Enter Your New password>> ")
                    Admin[user_name] = encoded_text(New_pass_for_Admin)
                    print(f"You have changed Your password Successfully")
                else:
                    print("Thank you, see you later")
                break
            elif Users.get(user_name) == encoded_password:
                print(f"Welcome {user_name}, Have a nice day")
                edit_choice = 0
                while edit_choice not in ["y", "n"]:
                    print("If you want to change Your password please Enter (y-n)")
                    edit_choice = input(">> ")
                if edit_choice == "y":
                    New_pass_for_User = getpass.getpass(
                        "Please Enter Your New password>> ")
                    Users[user_name] = encoded_text(New_pass_for_User)
                    print(f"You have changed Your password Successfully")
                else:
                    print("Thank you, see you later")
                break
            else:
                break
    with open("Users.txt", 'w', encoding='utf-8') as f4:
        f4.write(str(Users))

    with open("Admin.txt", 'w', encoding='utf-8') as f5:
        f5.write(str(Admin))

    with open("Root.txt", 'w', encoding='utf-8') as f6:
        f6.write(str(Root))

# Functions


def encoded_text(text):
    text = text.encode('utf-8')
    new_hash = hashlib.new("sha256")  # type
    new_hash.update(text)
    hash_text = new_hash.hexdigest()
    return hash_text


def edit_in_Users_function():
    edit_choice1 = 0
    while edit_choice1 not in ["1", "2", "3", "4", "5"]:
        print("Please choose from the following:-\n\
        1)Add User\n\
        2)Change password for user\n\
        3)Remove User\n\
        4)Showing all Users\n\
        5)Exit")
        edit_choice1 = input(">> ")
    if edit_choice1 == "1":
        added_username_name = input("Please Enter the name of New user>> ")
        added_username_password = getpass.getpass(
            "Please Enter the password of New user>> ")
        Users[added_username_name] = encoded_text(added_username_password)
        print(
            f"You have added new user ==> {added_username_name}")
    elif edit_choice1 == "2":
        changed_username_name = input("Please Enter the name of the user>> ")
        if Users.get(changed_username_name) == None:
            print("This user doesn't exisit please try again later")
        else:
            changed_username_password = getpass.getpass(
                "Please Enter the new password of The user>> ")
            Users[changed_username_name] = encoded_text(
                changed_username_password)
            print(
                f"You have change the password for {changed_username_name} Successfully")
    elif edit_choice1 == "3":
        removed_username_name = input(
            "Please Enter the name of the user that you want to remove>> ")
        try:
            Users.pop(removed_username_name)
            print(f"You have removed {removed_username_name}")
        except:
            print("This user doesn't exisit please try again later")
    elif edit_choice1 == "4":
        Showing(Users)
    else:
        print("Thank you, see you later")


def edit_in_Admins_function():
    edit_choice1 = 0
    while edit_choice1 not in ["1", "2", "3", "4", "5"]:
        print("Please choose from the following:-\n\
        1)Add Admin\n\
        2)Change password for Admin\n\
        3)Remove Admin\n\
        4)Showing all Admin Users\n\
        5)Exit")
        edit_choice1 = input(">> ")
    if edit_choice1 == "1":
        added_Admin_name = input(
            "Please Enter the name of New Admin>> ")
        added_Admin_password = getpass.getpass(
            "Please Enter the password of New Admin>> ")
        Admin[added_Admin_name] = encoded_text(added_Admin_password)
        print(
            f"You have added new Admin ==> {added_Admin_name}")
    elif edit_choice1 == "2":
        changed_Admin_name = input(
            "Please Enter the name of The Admin>> ")
        if Admin.get(changed_Admin_name) == None:
            print("This Admin doesn't exisit please try again later")
        else:
            changed_Admin_password = getpass.getpass(
                "Please Enter the New password of The Admin>> ")
            Admin[changed_Admin_name] = encoded_text(changed_Admin_password)
            print(
                f"You have change the password for {changed_Admin_name} Successfully")
    elif edit_choice1 == "3":
        removed_Admin_name = input(
            "Please Enter the name of the Admin that you want to remove>> ")
        try:
            Admin.pop(removed_Admin_name)
            print(f"You have removed {removed_Admin_name}")
        except:
            print("This Admin doesn't exisit please try again later")
    elif edit_choice1 == "4":
        Showing(Admin)
    else:
        print("Thank you, see you later")


def edit_in_Roots_function():
    edit_choice1 = 0
    while edit_choice1 not in ["1", "2", "3", "4", "5"]:
        print("Please choose from the following:-\n\
        1)Add Root\n\
        2)Change password for Root\n\
        3)Remove Root\n\
        4)Showing all Root Users\n\
        5)Exit")
        edit_choice1 = input(">> ")
    if edit_choice1 == "1":
        added_Root_name = input(
            "Please Enter the name of New Root>> ")
        added_Root_password = getpass.getpass(
            "Please Enter the password of New Root>> ")
        Root[added_Root_name] = encoded_text(added_Root_password)
        print(
            f"You have added new Root ==> {added_Root_name}")
    elif edit_choice1 == "2":
        changed_Root_name = input(
            "Please Enter the name of The Root>> ")
        if Root.get(changed_Root_name) == None:
            print("This Root doesn't exisit please try again later")
        else:
            changed_Root_password = getpass.getpass(
                "Please Enter the New password of The Root>> ")
            Root[changed_Root_name] = encoded_text(changed_Root_password)
            print(
                f"You have change the password for {changed_Root_name} Successfully")
    elif edit_choice1 == "3":
        removed_Root_name = input(
            "Please Enter the name of the Root that you want to remove>> ")
        try:
            Root.pop(removed_Root_name)
            print(f"You have removed {removed_Root_name}")
        except:
            print("This Root doesn't exisit please try again later")
    elif edit_choice1 == "4":
        Showing(Root)

    else:
        print("Thank you, see you later")


def Showing(Dictionary):
    if len(Dictionary.keys()) == 0:
        print("#"*28)
        print("#"+" "*26+"#")
        print("# There no-one here"+" "*8+"#")
        print("# Please add some"+" "*10+"#")
        print("#"+" "*26+"#")
        print("#"*28)
    else:
        counter = 1
        print("#"*28)
        print("#"+" "*26+"#")
        length = len(Dictionary.keys())
        length1 = 15 - len(str(length))
        print(f"# There are {length}"+" "*length1+"#")
        print("#"+" "*26+"#")
        for i in Dictionary.keys():
            length = 22 - len(i)
            print(f"# {counter}. {i}"+" "*length+"#")
            counter += 1
        print("#"+" "*26+"#")
        print("#"*28)


if __name__ == '__main__':
    main()
