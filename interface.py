"""MODULE USED TO DEFINE THE INTERFACE """

#IMPORTS ---------------------------------------------------------------------------------------------------------------
from ctypes import set_last_error
import sqlite3
from sqlite3.dbapi2 import adapt
from tkinter import *
from tkinter import simpledialog
from functools import partial
from Crypto.Random import *
from Crypto.Random import get_random_bytes
import queries, saveData, hmac_calc, base64
import cryptography, relatedFunctions, authentication

#Create PopUp --------------------------------------------------------------------------------------------------------------
def popUp(text):
    answer = simpledialog.askstring(text,text)
    if(len(answer)<1):
        answer=None
        
    return answer

#Initialize window ----------------------------------------------------------------------------------------------------------
window = Tk()
window.update()
window.title("Password Manager")

#create screen --------------------------------------------------------------------------------------------------------------
def welcomeScreen():
    window.geometry('500x175')
    window.configure(bg='#333333')

    lbl = Label(window, text="Welcome to KVault. ", font=("Arial", 21),bg='#333333',fg="#5dc1b9")
    lbl.config(anchor=CENTER)
    lbl.pack()

    lbl = Label(window, text="To start, please, select one option: ", font=("Arial", 15),bg='#333333',fg="white")
    lbl.config(anchor=CENTER)
    lbl.pack()

    btn = Button(window, text="Create a Master Password", command= createMasterScreen, activebackground="#9D9D9D")
    btn.pack(pady=5)

    btn = Button(window, text="Suggest a Master Password", command= suggestMasterScreen, activebackground="#9D9D9D")
    btn.pack(pady=5)

# function to create the first window where we are asked for the master password ---------------------------------------------
def createMasterScreen():
    for widget in window.winfo_children():
        widget.destroy()

    window.geometry('500x175')
    window.configure(bg='#333333')

    lbl2 = Label(window, text="", font=("Arial", 15),bg='#333333',fg="red")
    lbl2.config(anchor=CENTER)
    lbl2.pack()

    lbl = Label(window, text="Choose a Master Password", font=("Arial", 15),bg='#333333',fg="white")
    lbl.config(anchor=CENTER)
    lbl.pack()

    txt = Entry(window, width=20, show="*")
    txt.pack()
    txt.focus()

    lbl1 = Label(window, text="Re-enter password", font=("Arial", 15),bg='#333333',fg="white")
    lbl1.config(anchor=CENTER)
    lbl1.pack()

    txt1 = Entry(window, width=30, show="*")
    txt1.pack()

    # function that is used to save the password into the database ---------------------------------------------------------
    def savePassword():
        #user validation stuff
        upper, hasNum = False, False
        #check for upper letter
        upper = authentication.checkUpperLetter(txt, upper)
        #check for numbers
        hasNum = authentication.checkNumber(txt, hasNum)

        if len(txt.get())==0 or len(txt1.get())==0:
            lbl2.config(text="Password cannot be empty", font=("Arial", 15),fg="red")
        
        elif len(txt.get())<=6 or len(txt1.get())<=6:
            lbl2.config(text="Password must contain at least 7 characters", font=("Arial", 15),fg="red")
        
        elif upper==False:
            lbl2.config(text="Password must contain at least 1 UPPERCASE letter", font=("Arial", 15),fg="red")
        
        elif hasNum==False:
            lbl2.config(text="Password must contain at least 1 number", font=("Arial", 15),fg="red")

        elif txt.get() == txt1.get():
            hashedPassword = cryptography.hashPassword(txt.get().encode('utf-8'),0)
            queries.insertpassword(hashedPassword)
            cryptography.hmacAndSign(0)
            managerScreen()

        else:
            lbl2.config(text="Passwords do not match", font=("Arial", 15), fg="red")

    btn = Button(window, text="Save", command=savePassword, activebackground="#9D9D9D")
    btn.pack(pady=5)

# function that is used to creater the screen that suggest a master password --------------------------------------------
def suggestMasterScreen():
    for widget in window.winfo_children():
        widget.destroy()

    window.geometry('500x175')
    window.configure(bg='#333333')

    lbl2 = Label(window, text="", font=("Arial", 15),bg='#333333',fg="red")
    lbl2.config(anchor=CENTER)
    lbl2.pack()

    lbl = Label(window, text="Introduce the lenght desired for your password", font=("Arial", 15),bg='#333333',fg="white")
    lbl.config(anchor=CENTER)
    lbl.pack()

    lbl3 = Label(window, text="", font=("Arial", 15), bg='#333333', fg="red")
    lbl.config(anchor=CENTER)
    lbl3.pack()

    lengthofpass = Entry(window, width=20)
    lengthofpass.pack()
    lengthofpass.focus()

    #function that is used to create the screen where the suggested password is displayed -------------------------------
    def suggestMasterScreen1():
        isEmpty=False
        isOkay=False
        
        if(" " in lengthofpass.get() or lengthofpass.get()==""):
            isEmpty=True
            authentication.isEmptyFunction(lengthofpass.get(), lbl3)

        elif(not isEmpty):
            isOkay = authentication.isNotEmptyFunction(lengthofpass.get(), isOkay, lbl3)
               
        if(int(lengthofpass.get())<=6):
            isOkay=False
            lbl3.config(text="Password must contain at least 7 characters")
            
        if(isOkay):
            length = lengthofpass.get()
            for widget in window.winfo_children():
                widget.destroy()

            lbl1 = Label(window, text="The suggested password is: ", font=("Arial", 15),bg='#333333',fg="white")
            lbl1.config(anchor=CENTER)
            lbl1.pack()
            password = cryptography.password_gen(int(length))
            window.clipboard_clear()
            window.clipboard_append(password)

            lbl2 = Label(window, text=password, font=("Arial", 15),bg='#333333',fg="#5dc1b9")
            lbl2.config(anchor=CENTER)
            lbl2.pack()

            lbl1 = Label(window, text="Please, remeber it", font=("Arial", 15),bg='#333333',fg="orange")
            lbl1.config(anchor=CENTER)
            lbl1.pack()

            lbl4 = Label(window, text="Otherwise, you will not be able to access the application", font=("Arial", 15),bg='#333333',fg="orange")
            lbl4.config(anchor=CENTER)
            lbl4.pack()

            #function used to save the suggested password in the database ---------------------------------------------------
            def saveSuggestedPassword():
                hashedPassword = cryptography.hashPassword(password.encode('utf-8'),0)
                queries.insertpassword(hashedPassword)
                cryptography.hmacAndSign(0)
                managerScreen()

            btn = Button(window, text="Save", command=saveSuggestedPassword, activebackground="#9D9D9D")
            btn.pack(pady=5)

    btn = Button(window, text="Save", command= suggestMasterScreen1, activebackground="#9D9D9D")
    btn.pack(pady=5)

# function used to login once we have the password into the database ------------------------------------------------------
def loginScreen():
    for widget in window.winfo_children():
        widget.destroy()

    window.geometry('500x125')
    window.configure(bg='#333333')

    lbl = Label(window, text="Enter  Master Password", font=("Arial", 15), pady=10,bg='#333333',fg="white")
    lbl.config(anchor=CENTER)
    lbl.pack()

    txt = Entry(window, width=30, show="*")
    txt.pack()
    txt.focus()

    lbl1 = Label(window,bg="#333333")
    lbl1.config(anchor=CENTER)
    lbl1.pack(side=TOP)

    #function used to get the master password from the databsase ------------------------------------------------------
    def getMasterPassword():
        checkHashedPassword = cryptography.hashPassword(txt.get().encode('utf-8'),1)
        return queries.getPassword(checkHashedPassword)

    #function used to check if the password is the same as the one in the db ------------------------------------------
    def checkPassword():
        password = getMasterPassword()

        #if the password is good, we can compare the HMACS checking for attacks
        if password:
            keyHmac = base64.decodebytes(queries.getHMACKey().encode("ascii"))
            hmac1 = hmac_calc.computeHMAC(keyHmac)
            hmac2 = queries.getHMAC()

            #if they are the same, all good
            if hmac1 == hmac2:
                managerScreen()

            #otherwise, recover the data from the backup
            else:
                print("ERROR, THE HASHES ARE NOT THE SAME.\n AN ATTACK MAY HAPPENED.\n BACKUP IN PROGRES...")
                saveData.recoverBackup()
                print("BACKUP COMPLETED")

        if len(txt.get())==0:
            txt.delete(0,"end")
            lbl1.config(text="Passwords cant be empty", font=("Arial", 15), fg="red")
        else:
            txt.delete(0, 'end')
            lbl1.config(text="Wrong Password", font=("Arial", 15),fg="red")

    btn = Button(window, text="Submit", activebackground='#9D9D9D', font=("Arial", 11), command=checkPassword)
    btn.pack(pady=5)

#function used to show the content of the application ------------------------------------------------------------------
def managerScreen():
    "Import the module of the cursors so that we avoid the circular import error"
    from queries import cursor, cursor1,cursor3
    for widget in window.winfo_children():
        widget.destroy()

    #function used to add an entry to the application -------------------------------------------------------------------
    def addEntry():
        text1= "Website"
        text2 = "Username"
        text3 = "Password"
        website = popUp(text1) 
        username = popUp(text2)
        password = popUp(text3)
        
        #check if the entry already exists
        for i in range(0,len(array)):  
            #obtain the decrypted user
            dUser = cryptography.decryptUser(array, array1, array3, i)
            dUser=str(dUser).replace("b","").replace("'","")

            #obtain the decrypted password
            dPass= cryptography.decryptPassword(array, array1, array3, i)
            dPass=str(dPass).replace("b","").replace("'","")

            #do not allow to introduce two equal entries
            if(website==array[i][1] and dUser==username and dPass==password):
                username=None

        #encrypt data and store the data into the backup file
        cryptography.encryptData(website, username, password)
        #compute the hash and sign it
        cryptography.hmacAndSign(1)
        managerScreen()

    #styling the managerscreen 
    window.geometry('830x550')
    window.resizable(height=None, width=None)
    lbl = Label(window, text="Password Manager", font=("Arial", 21),bg="#333333",fg="white")
    lbl.grid(column=1)

    btn = Button(window, text="Add new password", font=("Arial", 11), command=addEntry, activebackground='#9D9D9D')
    btn.grid(column=1, pady=10)

    lbl = Label(window, text="Website", font=("Arial", 21),bg="#333333",fg="white")
    lbl.config(anchor=CENTER)
    lbl.grid(row=2, column=0, padx=40)
    lbl = Label(window, text="Username", font=("Arial", 21),bg="#333333",fg="white")
    lbl.grid(row=2, column=1, padx=40)
    lbl = Label(window, text="Password", font=("Arial", 21),bg="#333333",fg="white")
    lbl.grid(row=2, column=2, padx=40)

    #adding functionalities to the delete and show button
    cursor.execute('SELECT * FROM vault')
    cursor1.execute('SELECT * FROM key')
    cursor3.execute('SELECT * FROM nonce')
    
    if (cursor.fetchall() != None):
        i = 0
        passHide = [StringVar()]

        while True:
            #save data from tables into arrays
            cursor.execute('SELECT * FROM vault')
            cursor1.execute('SELECT * FROM key')
            cursor3.execute('SELECT * FROM nonce')
            array = cursor.fetchall()
            array1 = cursor1.fetchall()
            array3 = cursor3.fetchall()
            
            if (len(array) == 0) or (len(array1) == 0) or (len(array3)==0):
                break
                
            decryptedUser = StringVar()
            #obtain the decrypted user
            decryptedU = cryptography.decryptUser(array, array1, array3, i)
            #set the stringVariable as the decrypted user
            decryptedUser.set(decryptedU)

            #set the value of the webpage entry
            lbl1 = Label(window, text=(array[i][1]), font=("Arial", 15),bg="#333333",fg="white")
            lbl1.grid(column=0, row=(i+3))

            #hide the password entry
            passHide[i].set("*******")
            
            #assign to the user entry the decryptedUser
            lbl2 = Entry(window, textvariable=decryptedUser, font=("Arial", 15), state="readonly", readonlybackground="#333333", justify=CENTER ,bd=0,fg="white")
            lbl2.grid(column=1, row=(i+3))

            #assign to the password entry the hidden value
            lbl3 = Entry(window, textvariable=passHide[i], font=("Arial", 15),state="readonly", readonlybackground="#333333",justify=CENTER,bd=0,fg="white")
            lbl3.grid(column=2, row=(i+3))

            #delete button, when pressed we delete the entry and at the same time remove the corresponding values from the tables
            #first remove the entries and the key
            all_commands = relatedFunctions.combinedFunction(partial(queries.removeEntry, array[i][0]), partial(queries.removeKey, array1[i][0]))
            #now remove also the nonce
            all_commands = relatedFunctions.combinedFunction(all_commands, partial(queries.removeNonce, array3[i][0]))
            #vcompute, sign and verify the hash
            all_commands = relatedFunctions.combinedFunction(all_commands, cryptography.hmacAndSign(1))
            btn = Button(window, text="Delete", font=("Arial", 11), command= all_commands,  activebackground='#9D9D9D')
            btn.grid(column=3, row=(i+3), pady=10, padx=10)

            #show function will be executed when pressed the show button to show the password. Decrypts and show the password-------
            def show():
                cursor.execute('SELECT * FROM vault')
                array=cursor.fetchall()
                for r in range(0,len(array)):
                    #decrypt the password and assign it to the hidden variable
                    decryptedPassword = cryptography.decryptPassword(array, array1, array3, r)
                    passHide[r].set(decryptedPassword)

            #hide function that hides again the password in * format ------------------------------------------
            def hide():
                cursor.execute('SELECT * FROM vault')
                array=cursor.fetchall()
                for r in range(0,len(array)):
                    passHide[r].set("*******")

            #show button
            btnshow = Button(window, text="Show", font=("Arial", 11), command= show,  activebackground='#9D9D9D')
            btnshow.grid(column=3, row=1, pady=10, padx=10)

            #hide button
            btnshow1 = Button(window, text="Hide", font=("Arial", 11), command= hide,  activebackground='#9D9D9D')
            btnshow1.grid(column=4, row=1, pady=10, padx=10)

            i = i +1
            passHide.append(StringVar())

            #checking errors
            cursor.execute('SELECT * FROM vault')
            if (len(cursor.fetchall()) <= i):
                break

            cursor1.execute('SELECT * FROM key')
            if (len(cursor1.fetchall()) <= i):
                break

            cursor3.execute('SELECT * FROM nonce')
            if (len(cursor3.fetchall()) <= i):
                break

            