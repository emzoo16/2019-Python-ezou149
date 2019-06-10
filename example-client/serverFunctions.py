import urllib.request
import json
import base64
import nacl.encoding
import nacl.signing
import nacl.pwhash
import nacl.secret
import nacl.utils
import time
import database
import server

    
"""----------------------------------------------------------------------------------
                                POST METHODS
-----------------------------------------------------------------------------------"""
"""
Checks if the server is online and the users authentication. Returns an ok message
"""
def ping (pubkey_hex_str, signing_key, headers):
    url = "http://cs302.kiwi.land/api/ping"

    signature_bytes = bytes(pubkey_hex_str, encoding='utf-8')
    signed = signing_key.sign(signature_bytes, encoder=nacl.encoding.HexEncoder)
    signature_hex_str = signed.signature.decode('utf-8')

    if pubkey_hex_str == None :
         payload = {}
    else:
        payload = {
            "pubkey": pubkey_hex_str,
            "signature": signature_hex_str
        }
    #Convert the python dictionary into a JSON object.
    json_bytes = json.dumps(payload).encode('utf-8')

    try:
        req = urllib.request.Request(url, data=json_bytes, headers=headers)
        response = urllib.request.urlopen(req)
        data = response.read() # read the received bytes
        encoding = response.info().get_content_charset('utf-8') #load encoding if possible (default to utf-8)
        response.close()
    except urllib.error.HTTPError as error:
        print(error.read())
        exit()

    JSON_object = json.loads(data.decode(encoding))

"""
Associates a new public key with your account.
"""
def add_pubkey(pubkey_hex_str, signing_key, username, headers):
    url = "http://cs302.kiwi.land/api/add_pubkey"

    signature_bytes = bytes(pubkey_hex_str + username, encoding='utf-8')
    signed = signing_key.sign(signature_bytes, encoder=nacl.encoding.HexEncoder)
    signature_hex_str = signed.signature.decode('utf-8')

    payload = {
    "pubkey": pubkey_hex_str,
    "username": username,
    "signature": signature_hex_str
    }
    #Convert the python dictionary into a JSON object.
    json_bytes = json.dumps(payload).encode('utf-8')
    try:
        req = urllib.request.Request(url, data=json_bytes, headers=headers)
        response = urllib.request.urlopen(req)
        data = response.read() # read the received bytes
        encoding = response.info().get_content_charset('utf-8') #load encoding if possible (default to utf-8)
        response.close()
    except urllib.error.HTTPError as error:
        print(error.read())
        exit()

    JSON_object = json.loads(data.decode(encoding))
    certificate = JSON_object["loginserver_record"]
    return certificate

"""
Adds private data of user ie the list of private keys, blocked users/messages/words, friends and 
favourite messages.
"""
def add_privatedata(privatedata, headers, signing_key, password):
    url = "http://cs302.kiwi.land/api/add_privatedata"
    certificate = get_loginserver_record(headers)
    time_str = str(time.time())

    privatedata_encrypted = encrypt_privatedata(privatedata,password)
    privatedata_encrypted_str = privatedata_encrypted.decode('utf-8')
    signature_bytes = bytes(privatedata_encrypted_str + certificate + time_str, encoding='utf-8')
    signed = signing_key.sign(signature_bytes, encoder=nacl.encoding.HexEncoder)
    signature_hex_str = signed.signature.decode('utf-8')

    payload = {
    "privatedata": privatedata_encrypted_str,
    "loginserver_record": certificate,
    "client_saved_at": time_str,
    "signature": signature_hex_str
    }

    json_bytes = json.dumps(payload).encode('utf-8')

    try:
        req = urllib.request.Request(url, data=json_bytes, headers= headers)
        response = urllib.request.urlopen(req)
        data = response.read() # read the received bytes
        encoding = response.info().get_content_charset('utf-8') #load encoding if possible (default to utf-8)
        response.close()
    except urllib.error.HTTPError as error:
        print(error.read())
        exit()
    JSON_object = json.loads(data.decode(encoding))


"""
Informs server about connection for a user. ie public key,status (online,offline)
"""
def report(pubkey_hex_str, headers, status):
    url = "http://cs302.kiwi.land/api/report"
    server.get_lan_ip()

    payload = {
    "connection_address": server.get_lan_ip() + ":8080",
    "connection_location": 2,
    "incoming_pubkey": pubkey_hex_str,
    "status": status
    }
    json_bytes = json.dumps(payload).encode('utf-8')

    try:
        req = urllib.request.Request(url,data = json_bytes, headers=headers)
        response = urllib.request.urlopen(req)
        data = response.read() # read the received bytes
        encoding = response.info().get_content_charset('utf-8') #load encoding if possible (default to utf-8)
        response.close()
    except urllib.error.HTTPError as error:
        print(error.read())
        exit()
    JSON_object = json.loads(data.decode(encoding))
   

"""----------------------------------------------------------------------------------
                                  GET METHODS
-----------------------------------------------------------------------------------"""    
"""
Load the current login record for this use in creating point to point messages
"""
def get_loginserver_record(headers):
    url = "http://cs302.kiwi.land/api/get_loginserver_record"
    try:
        req = urllib.request.Request(url,data = None,headers=headers)
        response = urllib.request.urlopen(req)
        data = response.read() # read the received bytes
        encoding = response.info().get_content_charset('utf-8') #load encoding if possible (default to utf-8)
        response.close()
    except urllib.error.HTTPError as error:
        print(error.read())
        exit()
    JSON_object = json.loads(data.decode(encoding))
    certificate = JSON_object["loginserver_record"]
    return certificate

"""
Returns public key of the login server. Used to validate loginserver_records in broadcasts
and privatemessages.
"""
def loginserver_pubkey():
    url = "http://cs302.kiwi.land/api/loginserver_pubkey"
    try:
        req = urllib.request.Request(url)
        response = urllib.request.urlopen(req)
        data = response.read() # read the received bytes
        encoding = response.info().get_content_charset('utf-8') #load encoding if possible (default to utf-8)
        response.close()
    except urllib.error.HTTPError as error:
        print(error.read())
        exit()
    JSON_object = json.loads(data.decode(encoding))
    pubkey = JSON_object["pubkey"]
    return pubkey

"""
Returns a new api key for the purposes of authentication.
"""
def load_new_apikey():
    url = "http://cs302.kiwi.land/api/load_new_apikey"
    try:
        req = urllib.request.Request(url)
        response = urllib.request.urlopen(req)
        data = response.read() # read the received bytes
        encoding = response.info().get_content_charset('utf-8') #load encoding if possible (default to utf-8)
        response.close()
    except urllib.error.HTTPError as error:
        print(error.read())
        exit()
    JSON_object = json.loads(data.decode(encoding))
    return JSON_object

"""
List all users who have done a report in the last 5 minutes.
Returns list of users along with basic info about those users.
"""
def list_users(headers):
    url = "http://cs302.kiwi.land/api/list_users"
    try:
        req = urllib.request.Request(url, data=None, headers=headers)
        response = urllib.request.urlopen(req)
        data = response.read() # read the received bytes
        encoding = response.info().get_content_charset('utf-8') #load encoding if possible (default to utf-8)
        response.close()
    except urllib.error.HTTPError as error:
        print(error.read())
        exit()
    JSON_object = json.loads(data.decode(encoding))
    update_database_users(JSON_object)
    return JSON_object

"""
Loads the login server record for a given pubkey.
"""
def check_pubkey(string, headers):
    url = "http://cs302.kiwi.land/api/check_pubkey?pubkey="+string
    try:
        req = urllib.request.Request(url, data=None, headers=headers)
        response = urllib.request.urlopen(req)
        data = response.read() # read the received bytes
        encoding = response.info().get_content_charset('utf-8') #load encoding if possible (default to utf-8)
        response.close()
    except urllib.error.HTTPError as error:
        print(error.read())
        exit()
    JSON_object = json.loads(data.decode(encoding))
    return JSON_object

"""
Used to get the encrypted private data for a user.
"""
def get_privatedata(headers,signing_key):
    url = "http://cs302.kiwi.land/api/get_privatedata"

    try:
        req = urllib.request.Request(url, data=None, headers=headers)
        response = urllib.request.urlopen(req)
        data = response.read() # read the received bytes
        encoding = response.info().get_content_charset('utf-8') #load encoding if possible (default to utf-8)
        response.close()
    except urllib.error.HTTPError as error:
        print(error.read())
        exit()

    JSON_object = json.loads(data.decode(encoding))
    privatedata_encrypted = JSON_object["privatedata"]
    privatedata_str = decrypt_privatedata(privatedata_encrypted,"1234",signing_key)
    return JSON_object

"""----------------------------------------------------------------------------------
                                  OTHER METHODS
-----------------------------------------------------------------------------------"""   

def encrypt_privatedata(privatedata, password):
    print("calling secret box encrypt")
    secret_box = create_secret_box(password)
    privatedata_JSON = json.dumps(privatedata).encode('utf-8')
    nonce = nacl.utils.random(nacl.secret.SecretBox.NONCE_SIZE)
    encrypted = secret_box.encrypt(privatedata_JSON, nonce)
    base64_encryption = base64.b64encode(encrypted)

    return base64_encryption

def decrypt_privatedata(encrypted_privatedata,password,signing_key):

    privatedata = base64.b64decode(encrypted_privatedata)
    secret_box = create_secret_box(password)
    privatedata_str = secret_box.decrypt(privatedata)
    return privatedata_str


def create_secret_box(password):
    key_password = bytes(password, 'utf-8')

    salt = key_password
    for i in range(15):
        salt = salt + key_password

    while len(salt)>16:
        salt = salt[:-1]

    symmetric_key = nacl.pwhash.argon2i.kdf(32, key_password, salt, opslimit=8, 
    memlimit=536870912, encoder=nacl.encoding.RawEncoder)

    #key = nacl.utils.random(nacl.secret.SecretBox.KEY_SIZE)
    box = nacl.secret.SecretBox(symmetric_key)
    return box

def update_database_users(dict):
    for user in dict["users"]:
        username = user["username"] 
        pubkey = user["incoming_pubkey"]
        ip_address = user["connection_address"]
        database.update_user_list(username,pubkey,ip_address)






