"""MODULE USED FOR LOAD DATA INTO BAKCUP"""

#IMPORTS -------------------------------------------------------------------------------------------------
from sqlite3 import *
from interface import *

#function that loads data from the original db into the backup -------------------------------------------
def saveBackup():
    bck = sqlite3.connect("backup.db")
    db = sqlite3.connect("password_manager.db")
    with bck:
        db.backup(bck)

#function that loads the backup into the original db in case of attack -----------------------------------
def recoverBackup():
    bck = sqlite3.connect("backup.db")
    db = sqlite3.connect("password_manager.db")
    with db:
        bck.backup(db)