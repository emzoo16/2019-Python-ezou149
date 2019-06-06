import urllib.request
import json
import base64
import nacl.encoding
import nacl.signing
import nacl.pwhash
import nacl.secret
import nacl.utils
import nacl.utils
from nacl.public import PrivateKey, SealedBox
import time
import serverFunctions
import database

username = "ezou149"
password = "emzoo16_844010534"

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
Broadcast between users (public message)
"""
def broadcast(message, signing_key, headers):
    availableIPs = ping_all_online()
    certificate = serverFunctions.get_loginserver_record(headers)
    time_str = str(time.time())

    for ip in availableIPs:
        url = "http://"+ ip + "/api/rx_broadcast"

        message_bytes = bytes(certificate + message + time_str, encoding='utf-8')
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
Used for sending secret messages between users.
"""
def privatemessage(message, signing_key, headers, target_ip, target_user):
    time_str = str(time.time())
    database.add_message(target_user, username, message, time_str)
    
    url = "http://"+ target_ip + "/api/rx_privatemessage"
    certificate = serverFunctions.get_loginserver_record(headers)
    target_pubkey_str = serverFunctions.loginserver_pubkey()
    target_pubkey = nacl.signing.VerifyKey(target_pubkey_str, encoder=nacl.encoding.HexEncoder) 
    target_pubkey_curve = target_pubkey.to_curve25519_public_key()

    sealed_box = nacl.public.SealedBox(target_pubkey_curve)
    encrypted = sealed_box.encrypt(bytes(message,encoding='utf-8'), encoder=nacl.encoding.HexEncoder)
    encrypted_str = encrypted.decode('utf-8')

    message_bytes = bytes(certificate + target_pubkey_str + "admin" + encrypted_str 
    + time_str, encoding='utf-8')
    signed = signing_key.sign(message_bytes, encoder=nacl.encoding.HexEncoder)
    signature_hex_str = signed.signature.decode('utf-8')

    payload = {
    "loginserver_record": certificate, 
    "target_pubkey": target_pubkey_str, 
    "target_username": "admin", 
    "encrypted_message": encrypted_str,
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
Checks if another client is alive.
"""
def ping_check(target_ip_address):
    url = "http://" + target_ip_address + "/api/ping_check"
    time_str = str(time.time())

    payload = {
    "my_time": time_str,
    "my_active_usernames": [username],
    "connection_address": "172.23.1.134:8080",
    "connection_location": 2
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
    return JSON_object


def ping_all_online():
    availableIPs = []
    userIPs = getUserIPs()
    for ip in userIPs:
        return_data = ping_check(ip)
        if return_data["response"] == 'ok':
            availableIPs.append(ip)
    return availableIPs
    

"""
Transmit private group messages between users.
"""
def groupmessage():
    url = "http://cs302.kiwi.land/api/rx_groupmessage"

    {
    "loginserver_record": " ......... ", 
    "groupkey_hash": " .......... ", 
    "group_message": " ...... ", 
    "sender_created_at" : "1556931977.0179243", 
    "signature" : " ............"
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
Transmit private group messages between users.
"""
def groupinvite():
    url = "http://cs302.kiwi.land/api/rx_groupinvite"

    {
    "loginserver_record": " ......... ", 
    "groupkey_hash": " .......... ", 
    "target_pubkey": " .......... ", 
    "target_username": " .......... ", 
    "encrypted_groupkey": " ...... ", 
    "sender_created_at" : "1556931977.0179243", 
    "signature" : " ............"
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

"""----------------------------------------------------------------------------------
                                  GET METHODS
-----------------------------------------------------------------------------------"""    

"""
Checks messages for the user since a give timestamp.
"""
def checkmessages():
    url = "http://cs302.kiwi.land/api/checkmessages?since=" + "1559347200.0000000"

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
    return JSON_object;


def getUserIPs():
    userIPs = []
    online_users = serverFunctions.list_users(headers)
    users = online_users["users"]

    for user in users:
        userString = user["connection_address"] 
        userIPs.append(userString)

    return userIPs
