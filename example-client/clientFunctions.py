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
import server
import socket
import os

if os.name != "nt":
    import fcntl
    import struct
    

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
    #availableIPs = ping_all_online()

    certificate = serverFunctions.get_loginserver_record(headers)
    time_str = str(time.time())
    message_bytes = bytes(certificate + message + time_str, encoding='utf-8')
    signed = signing_key.sign(message_bytes, encoder=nacl.encoding.HexEncoder)
    signature_hex_str = signed.signature.decode('utf-8')

    payload = {
    "loginserver_record": certificate,  
    "message": message,  
    "sender_created_at" : time_str,  
    "signature" : signature_hex_str
    }

    print("all ips")
    for ip in getUserIPs():
        print(ip)
    json_bytes = json.dumps(payload).encode('utf-8')
   
    for ip in getUserIPs():
        print("broadcasting: " + ip)
        url = "http://" + ip +"/api/rx_broadcast"
        try:
            req = urllib.request.Request(url, data=json_bytes, headers= headers)
            response = urllib.request.urlopen(req,timeout=2)
            data = response.read() # read the received bytes
            encoding = response.info().get_content_charset('utf-8') #load encoding if possible (default to utf-8)
            response.close()
            JSON_object = json.loads(data.decode(encoding))
            print(JSON_object)
        except urllib.error.HTTPError as error:
            print(error.read())
        except urllib.error.URLError as error:
            print("response : URL error here")
        except ConnectionResetError as error:
            print("connection reset error")
        except OSError as error:
            print("socket connection reset error")
        except socket.timeout as error:
            print("timed out")
        
            #return 'error'
        #JSON_object = json.loads(data.decode(encoding))

def privatemessage(message, signing_key, headers, target_username):
    time_str = str(time.time())
    target_ip = get_ip_from_username(target_username,headers)
    target_pubkey_str = get_pubkey_from_username(target_username,headers)
    
    database.add_message(server.get_currentusername(), target_username, message, time_str)
    
    url = "http://"+ target_ip +"/api/rx_privatemessage"
    certificate = serverFunctions.get_loginserver_record(headers)

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
    "target_username": target_username, 
    "encrypted_message": encrypted_str,
    "sender_created_at" : time_str, 
    "signature" : signature_hex_str
    }

    json_bytes = json.dumps(payload).encode('utf-8')

    try:
        req = urllib.request.Request(url, data=json_bytes, headers= headers)
        response = urllib.request.urlopen(req, timeout=2)
        data = response.read() # read the received bytes
        encoding = response.info().get_content_charset('utf-8') #load encoding if possible (default to utf-8)
        response.close()
    except urllib.error.HTTPError as error:
        print(error.read())
    except ConnectionResetError:
        print("connection reset error")
    except OSError as error:
        print("socket connection reset error")
    except socket.timeout as error:
        print("timed out")
    JSON_object = json.loads(data.decode(encoding))
    print(JSON_object)

"""
Checks if another client is alive.
"""
def ping_check(target_ip_address):
    print("ping checking: " + target_ip_address)
    url = "http://"+ target_ip_address+ "/api/ping_check"
    time_str = str(time.time())

    payload = {
    "my_time": time_str,
    "my_active_usernames": username,
    "connection_address": "172.23.1.134:8080",
    "connection_location": 2
    }

    json_bytes = json.dumps(payload).encode('utf-8')
    try:
        req = urllib.request.Request(url, data=json_bytes, headers= headers)
        response = urllib.request.urlopen(req,timeout=2)
        data = response.read() # read the received bytes
        encoding = response.info().get_content_charset('utf-8') #load encoding if possible (default to utf-8)
        response.close()
        JSON_object = json.loads(data.decode(encoding))
        print(JSON_object)
        return JSON_object
    except urllib.error.HTTPError as error:
        print(error.read())
        return {"response : error here"}
    except urllib.error.URLError as error:
        print("response : URL error here")
        return {"response : URL error here"}
    except ConnectionResetError as error:
        print("connection reset error")
    except OSError as error:
        print("socket connection reset error")
    except socket.timeout as error:
        print("timed out")
   

def ping_all_online(headers):
    availableIPs = []
    userIPs = getUserIPs()
    for ip in userIPs:
        return_data = ping_check(ip)
        if(return_data != "error here"):
            availableIPs.append(ip)
            print("this ip is okay: " + ip )
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
    except ConnectionResetError:
        print("connection reset error")
    except OSError as error:
        print("socket connection reset error")
    except socket.timeout as error:
        print("timed out")
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

def get_ip_from_username(target_username,headers):
    online_users = serverFunctions.list_users(headers)
    users = online_users["users"]
    
    for user in users:
        current_user = user["username"] 
        if(current_user == target_username ):
            info = user["connection_address"]
            print("\n" + str(user["connection_address"]))
            return info

def get_pubkey_from_username(target_username,headers):
    online_users = serverFunctions.list_users(headers)
    users = online_users["users"]
    
    for user in users:
        current_user = user["username"] 
        if(current_user == target_username ):
            info = user["incoming_pubkey"]
            print("\n"+str(user["incoming_pubkey"]))
            return info

def get_onlineusernames(headers):
    #ping_check all users online and get IPs that are successful
    availableIPs = ping_all_online(headers)
    print(len(availableIPs))
    online_users = serverFunctions.list_users(headers)

    formattedUsers = []
    users = online_users["users"]
    print(len(users))

    #For all the users that are online, loop through the users that are online and check if their
    #ip address available
    for user in users:
        #for ip in availableIPs:
            #if user["connection_address"] == ip:
        userString = user["username"]
        formattedUsers.append(userString)

    return formattedUsers

