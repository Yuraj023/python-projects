# def happy_birthday(name):
#     print(f"happy birthday {name}")

# happy_birthday("yuraj")
# happy_birthday("anchal")
# happy_birthday("vikash")

def add(x,y):
    z=x+y
    return z

def sub(x,y):
    z=x-y
    return z

def multi(x,y):
    z=x*y
    return z

def divide(x,y):
    if y==0:
        return " by zero is not allowed "
    z=x/y
    return z

while True:
    print("1. addition")
    print("2.subtraction")
    print("3. multipilication")
    print("4. division")
    print("5. exit")

    choice = int(input("enter your choice: "))

    if choice == 5:
        print("shutdown the calculator")
        break

    a = int(input("enter the first number: "))
    b = int(input("enter the second number: "))
    if choice == 1:
        print(" addition", add(a,b))

    elif choice == 2:
        print("substraction",sub(a,b))

    elif choice == 3:
        print("mutliplication",multi(a,b))

    elif choice == 4:
        print(" division",divide(a,b))

    else:
        print("invalid input")
        continue


