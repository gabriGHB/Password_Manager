"""MAIN MODULE USED TO MAKE THE APPLICATION RUN"""

#IMPORTS -------------------------------------------------------------------------------------------
from interface import loginScreen, welcomeScreen, window
from queries import cursor


#-------------------------------------------- MAIN -------------------------------------------------
cursor.execute('SELECT * FROM masterpassword')
if (cursor.fetchall()):
    loginScreen()
else:
    welcomeScreen()
window.mainloop()  
