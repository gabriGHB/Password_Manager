"""MODULE USED FOR COMPUTING THE HMAC OF THE DB"""

#IMPORTS --------------------------------------------------------------------------------------
from sqlite3 import *
from interface import *
from Crypto.Hash import HMAC, SHA256
from queries import *
import base64

#function used to compute a string concatenating all the data from the db ----------------------
def computeStringDB():
    allData = queries.getAll()
    data = ""
    for i in allData:
        for j in i:
            data += str(j)
    return data

#function used to compute the HMAC key used to hash the previous string -----------------------
def computeSaveKeyHMAC():
    key = get_random_bytes(32)
    queries.insertHMACkey(base64.b64encode(key).decode("UTF-8"))
    return key

#function used to compute the HMAC of the previous string -------------------------------------
def computeHMAC(key):
    data = computeStringDB()
    data = data.encode("utf-8")
    h = HMAC.new(key, digestmod=SHA256)
    h.update(data)
    return h.hexdigest()
 




