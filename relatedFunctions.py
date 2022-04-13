"""MODULE USED FOR DEFINING AUXILIARY FUNCTIONS THAT WE WILL NEED IN THE PROGRAM"""

#function used to combine functions (useful to run multiple commands when pressing the button) ---------------------------
def combinedFunction(*funcs):
    def inner_function(*args, **kwargs):
        for f in funcs:
            f(*args, **kwargs)
    return inner_function





