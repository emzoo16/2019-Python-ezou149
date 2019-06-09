import urllib.request
import json
import base64
import nacl.encoding
import nacl.signing
import time

username = "ezou149"
password = "emzoo16_844010534"

pubkey_hex_str =  "cccfdbb8faa9221965fee9fc1b1c4313f269a0238e37934bbbf7fdff157051bc"
#create HTTP BASIC authorization header
credentials = ('%s:%s' % (username, password))
b64_credentials = base64.b64encode(credentials.encode('ascii'))

headers = {
    'Authorization': 'Basic %s' % b64_credentials.decode('ascii'),
    'Content-Type' : 'application/json; charset=utf-8',
}

"""----------------------------------------------------------------------------------
                                POST METHODS
-----------------------------------------------------------------------------------"""
"""
Checks if the server is online and the users authentication. Returns an ok message
"""
def ping ():
    url = "http://cs302.kiwi.land/api/ping"

    signature_bytes = bytes(pubkey_hex_str, encoding='utf-8')
    signed = signing_key.sign(signature_bytes, encoder=nacl.encoding.HexEncoder)
    signature_hex_str = signed.signature.decode('utf-8')

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
    print(JSON_object)

"""
Associates a new public key with your account.
"""
def add_pubkey():
    signature_bytes = bytes(pubkey_hex_str + username, encoding='utf-8')
    signed = signing_key.sign(message_bytes, encoder=nacl.encoding.HexEncoder)
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
    print(JSON_object)

"""
Broadcast between users (public message)
"""
def broadcast(message):
    url = "http://cs302.kiwi.land/api/rx_broadcast"
    certificate = get_loginserver_record()
    time_str = str(time.time())

    message_bytes = bytes(certificate + message + time, encoding='utf-8')
    signed = signing_key.sign(message_bytes, encoder=nacl.encoding.HexEncoder)
    signature_hex_str = signed.signature.decode('utf-8')

    payload = {
    "loginserver_record": certificate,  
    "message": message,  
    "sender_created_at" : time_str,  
    "signature" : signature_hex_str
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
    print(JSON_object)

"""
Adds private data of user ie the list of private keys, blocked users/messages/words, friends and 
favourite messages.
"""
def add_privatedata(privatedata):
    url = "http://cs302.kiwi.land/api/add_privatedata"
    certificate = get_loginserver_record()
    time_str = str(time.time())

    signature_bytes = bytes(privatedata + certificate + time, encoding='utf-8')
    signed = signing_key.sign(signature_bytes, encoder=nacl.encoding.HexEncoder)
    signature_hex_str = signed.signature.decode('utf-8')

    payload = {
    "privatedata": privatedata,
    "pubkey": certificate,
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
    print(JSON_object)

"""
Informs server about connection for a user. ie public key,status (online,offline)
"""
def report():
    url = "http://cs302.kiwi.land/api/rx_broadcast"

    payload = {
    "connection_address": "127.0.0.1:8000",
    "connection_location": 2,
    "incoming_pubkey": pubkey_hex_str
    }
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
    print(JSON_object)

"""----------------------------------------------------------------------------------
                                  GET METHODS
-----------------------------------------------------------------------------------"""    
"""
Load the current login record for this use in creating point to point messages
"""
def get_loginserver_record():
    url = "http://cs302.kiwi.land/api/get_loginserver_record"
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
    certificate = JSON_object["loginserver_record"]
    return certificate

"""
Returns public key of the login server. Used to validate loginserver_records in broadcasts
and privatemessages.
"""
def loginserver_pubkey():
    url = "http://cs302.kiwi.land/api/rx_loginserver_pubkey"
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
    print(JSON_object)
    return JSON_object

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
        print(JSON_object)
        return JSON_object

"""
List all users who have done a report in the last 5 minutes.
Returns list of users along with basic info about those users.
"""
def list_users():
    url = "http://cs302.kiwi.land/api/list_users"
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
        print(JSON_object)
        return JSON_object

"""
Loads the login server record for a given pubkey.
"""
def check_pubkey():
    url = "http://cs302.kiwi.land/api/check_pubkey?pubkey"+string
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
    print(JSON_object)
    return JSON_object

"""
Used to get the encrypted private data for a user.
"""
def get_privatedata():
    url = "http://cs302.kiwi.land/api/get_privatedata"
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
    print(JSON_object)
    return JSON_object

    





