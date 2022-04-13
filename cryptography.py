"""MODULE for includign all  the cryptographyc functions"""

#IMPORTS ----------------------------------------------------------------------------------------------
from ctypes import set_last_error
from Crypto.Hash import SHA512
from Crypto.Hash import SHA256
from tkinter import *
from Crypto.Random import *
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad
from Crypto.Util.Padding import unpad
from Crypto.Protocol.KDF import scrypt
from Crypto.Protocol.KDF import bcrypt
import string
import secrets
import queries
import base64
import signatures, hmac_calc


#function that generates a random password of a given lenght (used to suggest password) ---------------
def password_gen(password_length):
    characters = string.ascii_letters + string.digits
    secure_password = ''.join(secrets.choice(characters) for i in range(password_length))
    return secure_password

#function that performs AES symmetric encryption -------------------------------------------------------
def symmetricEncryption(key,data):
    cipher=AES.new(key, AES.MODE_CTR)
    nonce=cipher.nonce
    encryptedKey= cipher.encrypt(pad(data, AES.block_size))

    return encryptedKey,nonce


#function that performs AES symmentric decryption ------------------------------------------------------
def symmetricDecryption(key, data, nonce):
    cipher = AES.new(key, AES.MODE_CTR, nonce=nonce)

    try: 
        decryptdeKey = unpad(cipher.decrypt(data), AES.block_size)
        return decryptdeKey
    except  ValueError:
        print("FATAL ERROR DECRIPTION")
       

#function used to encrypt the password, the username and store the data in the db encoded --------------
def encryptData(website, username, password ):
     #obtain the key
    salt = get_random_bytes(32)
    pass1 = get_random_bytes(32)
    key = scrypt(pass1, salt, 32, N = 2**16, r = 8, p = 1)
    #encrypt the user and the password 
    encryptedPass,  noncePass = symmetricEncryption(key, password.encode("utf-8"))
    encryptedUser,  nonceUser = symmetricEncryption(key, username.encode("utf-8"))
    #encrypt the key used for encryption using the hashed hash
    keyEncrypted, nonceKey = encryptEncryptionKey(key)
    #insert the enccrypted and encoded key in the db
    queries.insertkey(encode64(keyEncrypted), encode64(nonceKey))
    #inser the encrypted and encoded vales in the database
    queries.insertFields(website, encode64(encryptedUser), encode64(encryptedPass))
    #insert the encoded nonces in the tables
    queries.insertNonce(encode64(nonceUser), encode64(noncePass))

#function used to get the user from the db and decrypt it ---------------------------------------------- 
def decryptUser(array, array1, array3, i):
    #get the data
    encryptedUser = decode64(queries.getEntry(array[i][0])[0][2]) 
    nonceUser = decode64(queries.getNonce(array3[i][0])[0][1])
    encryptedkey = decode64(queries.getKey(array1[i][0])[0][1])
    encryptedNonce = decode64(queries.getKey(array1[i][0])[0][2])
    hash = decode64(queries.getPasswordSimple()[0][1])
    hashOfHash = SHA512.new(hash)
    hashOfHash = hashOfHash.hexdigest()
    hash_bytes =decode64(hashOfHash)[0:32]
    #decrypt the key
    decryptedKey = symmetricDecryption(hash_bytes, encryptedkey, encryptedNonce )
    #decrypt the user
    decryptedUser = symmetricDecryption(decryptedKey, encryptedUser, nonceUser)
    return decryptedUser

#function used to decrypt the password -----------------------------------------------------------------
def decryptPassword(array, array1, array3, r):
    #get the data
    encryptedPassword =  decode64(queries.getEntry(array[r][0])[0][3])
    noncePassword =  decode64(queries.getNonce(array3[r][0])[0][2])
    encryptedKey = decode64(queries.getKey(array1[r][0])[0][1])
    encryptedNonce =  decode64(queries.getKey(array1[r][0])[0][2])
    hash = decode64(queries.getPasswordSimple()[0][1])
    hashOfHash = SHA512.new(hash)
    hashOfHash = hashOfHash.hexdigest()
    hash_bytes =decode64(hashOfHash)[0:32]
    #decrypt the key
    decryptedKey = symmetricDecryption(hash_bytes, encryptedKey, encryptedNonce)
    #decrypt the password
    decryptedPassword = symmetricDecryption(decryptedKey, encryptedPassword, noncePassword)
    return decryptedPassword


#function used to encrypt the encryption key and store it in the db -----------------------------------
def encryptEncryptionKey(key):
    #first obtain the hash from the db
    hash = decode64(queries.getPasswordSimple()[0][1])
    #hash it again and get the first 32 bytes. This will be the encryption key
    hashOfHash = SHA512.new(hash)
    hashOfHash = hashOfHash.hexdigest()
    hash_bytes =decode64(hashOfHash)[0:32]
    #encrypt the key
    keyEncrypted, nonceKey =symmetricEncryption(hash_bytes, key)
    return keyEncrypted, nonceKey


#function used to hash the the master passsword --------------------------------------------------------
#we use a counter to control whether to generate a salt or not. If it is the first time the salt will
#be generated. If not, it will be obtained from the db
def hashPassword(input,cnt):
    if(cnt==0):
        salt = get_random_bytes(10)
        salt=base64.b64encode(salt)
        salt=str(salt).replace("b","").replace("'","")
        queries.insertSalt(salt)
    salt = queries.getSalt()
    salt = salt.encode("utf-8")
    salt = SHA256.new(salt)
    salt= salt.hexdigest()
    salt= decode64(salt)[0:16]
    b64pwd =  base64.b64encode(SHA256.new(input).digest())
    hash1 = bcrypt(b64pwd, 13, salt)
    hash1 = hash1.hex()
    return hash1
    
#function used to encode the data using base64 ---------------------------------------------------------
def encode64(data):
    data = base64.b64encode(data)
    data= data.decode("UTF-8")
    return data
    
#function used to decode the data ----------------------------------------------------------------------
def decode64(data):
    return base64.decodebytes(data.encode("ascii"))

#function used to perform the hmac, sign and verify it -----------------------------------------------
def hmacAndSign(cond):
    if cond == 0:
        keyHMAC = hmac_calc.computeSaveKeyHMAC()
        hmac = hmac_calc.computeHMAC(keyHMAC)
        signature = signatures.signHMAC(hmac)
        signatures.verifyHMAC(signature, hmac, 0)
    else:
        keyHMAC = base64.decodebytes(queries.getHMACKey().encode("ascii"))
        hmac = hmac_calc.computeHMAC(keyHMAC)
        signature = signatures.signHMAC(hmac)
        signatures.verifyHMAC(signature, hmac, 1)
