"""MODULE USED TO DEFINE THE DB AND THE FUNCTIONS RELATED TO IT"""

#IMPORTS ----------------------------------------------------------------------------------------------
import sqlite3
import interface

#CREATE THE DB AND CONNECT THE CURSORS ---------------------------------------------------------------
with sqlite3.connect('password_manager.db') as db:
    cursor = db.cursor()
    cursor1 = db.cursor()
    cursor2 = db.cursor()
    cursor3 = db.cursor()
    cursorAll = db.cursor()

#CREATE THE TABLES ------------------------------------------------------------------------------------
cursor.execute("""
CREATE TABLE IF NOT EXISTS masterpassword(
id INTEGER PRIMARY KEY,
password TEXT NOT NULL);
""")

cursor.execute("""
CREATE TABLE IF NOT EXISTS vault(
id INTEGER PRIMARY KEY,
website TEXT NOT NULL,
username TEXT NOT NULL,
password TEXT NOT NULL);
""")

cursor.execute("""
CREATE TABLE IF NOT EXISTS salt(
    id INTEGER PRIMARY KEY,
    salt TEXT NOT NULL);
""")

cursor.execute("""
CREATE TABLE IF NOT EXISTS key(
    id INTEGER PRIMARY KEY,
    key TEXT NOT NULL,
    nonceKey TEXT NOT NULL);
""")

cursor.execute("""
CREATE TABLE IF NOT EXISTS nonce(
    id INTEGER PRIMARY KEY,
    nonceUser TEXT NOT NULL,
    noncePass TEXT NOT NULL);
""")

cursor.execute("""
CREATE TABLE IF NOT EXISTS hmac(
    id INTEGER PRIMARY KEY,
    hmac_v TEXT NOT NULL);
""")


cursor.execute("""
CREATE TABLE IF NOT EXISTS hmacKey(
    id INTEGER PRIMARY KEY,
    hmac_key TEXT NOT NULL);
""")

#function used to insert the salt in the db ---------------------------------------------------------
def insertSalt(salt):
    insert_salt = """INSERT INTO salt(salt)
    VALUES(?) """
    cursor.execute(insert_salt, [(salt)])
    db.commit()

#function used to get the salt from the db ---------------------------------------------------------
def getSalt():
    cursor.execute('SELECT * FROM salt WHERE id = 1')
    salt = cursor.fetchall()
    salt = salt[0][1]
    return salt

#function used to insert the hashed password in the db ----------------------------------------------
def insertpassword(hashedPassword):
    insert_password = """INSERT INTO masterpassword(password)
    VALUES(?) """
    cursor.execute(insert_password, [(hashedPassword)])
    db.commit()

#functions used to get the hashed password from the db ------------------------------------------------
def getPassword(checkHashedPassword):
        cursor.execute('SELECT * FROM masterpassword WHERE id = 1 AND password = ?', [(checkHashedPassword)])
        return cursor.fetchall()

def getPasswordSimple():
    cursor.execute('SELECT * FROM masterpassword WHERE id = 1')
    return cursor.fetchall()


#function used to insert the key in the db ---------------------------------------------------------
def insertkey(key, nonceKey):
        insert_key = """INSERT INTO key(key, nonceKey)
        VALUES(?,?) """
        cursor.execute(insert_key, (key, nonceKey))
        db.commit()


#function used to get the key from the db ---------------------------------------------------------
def getKey(input):
    cursor.execute('SELECT * FROM key WHERE id = ?', (input,))
    return cursor.fetchall()


#function used to insert the data encrypted in the db ----------------------------------------------
def insertFields(website, encryptedUser, encryptedPass):
        insert_fields = """INSERT INTO vault(website, username, password) 
        VALUES(?, ?, ?) """
        cursor.execute(insert_fields, (website, encryptedUser, encryptedPass))
        db.commit()

#function used to insert the encryption tags in the db ---------------------------------------------
def insertTag(tagUser, tagPass):
        insert_tags = """INSERT INTO tag(tagUser, tagPass) 
        VALUES(?, ?) """
        cursor.execute(insert_tags, (tagUser, tagPass))
        db.commit()

#function used to insert the encryption nonces in the db -------------------------------------------
def insertNonce(nonceUser, noncePass):
        insert_nonces = """INSERT INTO nonce(nonceUser, noncePass) 
        VALUES(?, ?) """
        cursor.execute(insert_nonces, (nonceUser, noncePass))
        db.commit()

#function used to remove an entry from the db -------------------------------------------------------
def removeEntry(input):
    cursor.execute("DELETE FROM vault WHERE id = ?", (input,))
    db.commit()
    interface.managerScreen()

#function used to remove nonces from the db ---------------------------------------------------------
def removeNonce(input):
    cursor.execute("DELETE FROM nonce WHERE id = ?", (input,))
    db.commit()
    interface.managerScreen()

#function used to remove the key fromthe db ---------------------------------------------------------
def removeKey(input):
    cursor.execute("DELETE FROM key WHERE id = ?", (input,))
    db.commit()
    interface.managerScreen()

#function used to get an entry from the db ---------------------------------------------------------
def getEntry(input):
    cursor.execute('SELECT * FROM vault WHERE id = ?', (input,))
    return cursor.fetchall()

#function used to get the tag from the db -----------------------------------------------------------
def getTag(input):
    cursor2.execute('SELECT * FROM tag WHERE id=?', (input,))
    return cursor2.fetchall()

#function used to get the nonces from the db ---------------------------------------------------------
def getNonce(input):
    cursor3.execute('SELECT * FROM nonce WHERE id=?', (input,))
    return cursor3.fetchall()

#function used to get all from the key table ---------------------------------------------------------
def getAllKeys():
    cursorAll.execute('SELECT * FROM key')
    return cursorAll.fetchall()

#function used to get all from the masterpassword table ---------------------------------------------
def getAllMasters():
    cursorAll.execute('SELECT * FROM masterpassword')
    return cursorAll.fetchall()

#function used to get all from the nonce table ---------------------------------------------------------
def getAllNonces():
    cursorAll.execute('SELECT * FROM nonce')
    return cursorAll.fetchall()

#function used to get all from the salt table ---------------------------------------------------------
def getAllSalts():
    cursorAll.execute('SELECT * FROM salt')
    return cursorAll.fetchall()

#function used to get all from the vault table ---------------------------------------------------------
def getAllVaults():
    cursorAll.execute('SELECT * FROM vault')
    return cursorAll.fetchall()

#function used to get all from the key table ---------------------------------------------------------
def getAll():
    return getAllKeys() + getAllMasters() + getAllNonces() + getAllSalts() + getAllVaults()

#function used to insert the initial hmac in the db --------------------------------------------------
def insertHMAC(hmac):
    insert_hmac = """INSERT INTO hmac(hmac_v)
    VALUES(?) """
    cursor.execute(insert_hmac, [(hmac)])
    db.commit()

#function used to update the hmac value in the table --------------------------------------------------
def updateHMAC(hmac):
    update = """UPDATE hmac
                SET hmac_v = ? """
    cursor.execute(update, [(hmac)])
    db.commit()

#function used to get the hmac value from the table --------------------------------------------------
def getHMAC():
    cursor.execute('SELECT * FROM hmac WHERE id = 1')
    hmac = cursor.fetchall()
    hmac = hmac[0][1]
    return hmac

#function used to insert the HMAC key into the DB ---------------------------------------------------
def insertHMACkey(key):
    insert_key = """INSERT INTO hmacKey(hmac_key)
    VALUES(?) """
    cursor.execute(insert_key, [(key)])
    db.commit()

#function used to get the HMAC key from the DB --------------------------------------------------------
def getHMACKey():
    cursor.execute('SELECT * FROM hmacKey WHERE id = 1')
    hmac_key = cursor.fetchall()
    hmac_key = hmac_key[0][1]
    return hmac_key