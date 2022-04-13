"""MODULE THAT CONTAINS FUNCTIONS FOR PROVIDING USER AUTHENTICATION"""

#function used to check that the password introduced is not empty ------------------------------------------------------
def isEmptyFunction(lenghtOfPass, label):
    if lenghtOfPass=="":
        label.config(text="The lenght must be a number")
    elif " " in lenghtOfPass:
        label.config(text="The lenght cannot contain whitespaces")

#function used to check that the lenght of the password is a number ---------------------------------------------------
def isNotEmptyFunction(lenghOfPass, isOkay, label):
    isChar=[]
    for char in lenghOfPass:
        isChar.append(char.isalpha())

    for i in isChar:
        isOkay=True 
        if(i==True):
            label.config(text="The lenght must be a number") 
            isOkay=False
            break    
    return isOkay

#function used to check that the introduced password has at least one upper letter --------------------------------------
def checkUpperLetter(txt, upper):
    for c in txt.get():
        if c.isupper()==True:
            upper = True
            break
    return upper

#function used to check that the introduced password has at least one number --------------------------------------------
def checkNumber(txt, hasNum):
    for num in txt.get():
        if num.isdigit()==True:
            hasNum = True
            break
    return hasNum
