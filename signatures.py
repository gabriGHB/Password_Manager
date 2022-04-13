""""MODUULE USED FOR SIGNING THE HMAC"""

#IMPORTS -------------------------------------------------------------------------------------------------
from Crypto.Signature import pkcs1_15
from Crypto.Hash import SHA256
from Crypto.PublicKey import RSA
import queries
import saveData

#Ffunction used to sign the HMAC using the private key ------------------------------------------------
def signHMAC(hmac):
    f = open("./PKI/keyVault_private.pem", "rb")
    key = RSA.import_key(f.read())
    h = SHA256.new(hmac.encode("utf-8"))
    signature = pkcs1_15.new(key).sign(h)
    return signature

#function used to virify the signature of the HMAC using the public key -------------------------------
def verifyHMAC(signature, hmac, cond):
    f = open("./PKI/keyVault_public.pem", "rb")
    key = RSA.import_key(f.read())
    h = SHA256.new(hmac.encode("utf-8"))
    try:
        pkcs1_15.new(key).verify(h, signature)
        #if cond = 0, it is the first time we access the app so we perform insert
        if cond == 0:
            queries.insertHMAC(hmac)
        #otherwise, it is when we are updating values, so we perform update
        else:
            queries.updateHMAC(hmac)
        saveData.saveBackup()
    except (ValueError, TypeError):
        print("ERROR, THE SIGNATURE IS NOT VALID.\n AN ATTACK MAY HAPPENED.\n BACKUP IN PROGRES...")
        saveData.recoverBackup()
        print("BACKUP COMPLETED")