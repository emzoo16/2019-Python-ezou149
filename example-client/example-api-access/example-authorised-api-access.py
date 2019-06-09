import urllib.request
import json
import base64
import nacl.encoding
import nacl.signing
import time

#url = "http://cs302.kiwi.land/api/add_pubkey"

hex_key = b'e278c1106318479da40b17ea4376710e11eb16c3e2a7854b2de9287ae4ed9a08'
signing_key = nacl.signing.SigningKey(hex_key, encoder=nacl.encoding.HexEncoder)

pubkey_hex = signing_key.verify_key.encode(encoder=nacl.encoding.HexEncoder)
pubkey_hex_str = pubkey_hex.decode('utf-8')

#STUDENT TO UPDATE THESE...
username = "ezou149"
password = "emzoo16_844010534"

# Generate a new random signing key(private key).
signing_key = nacl.signing.SigningKey.generate()
url = "http://cs302.kiwi.land/api/ping"

message_bytes = bytes(pubkey_hex_str, encoding='utf-8')
signed = signing_key.sign(message_bytes, encoder=nacl.encoding.HexEncoder)
signature_hex_str = signed.signature.decode('utf-8')

#create HTTP BASIC authorization header
credentials = ('%s:%s' % (username, password))
b64_credentials = base64.b64encode(credentials.encode('ascii'))

headers = {
    'Authorization': 'Basic %s' % b64_credentials.decode('ascii'),
    'Content-Type' : 'application/json; charset=utf-8',
}
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

print("get_loginserver_record")
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
print(JSON_object)
certificate = JSON_object["loginserver_record"]

time = str(time.time())
signature_bytes = bytes(certificate + "Yay" + time, encoding='utf-8')
signature = signing_key.sign(signature_bytes, encoder=nacl.encoding.HexEncoder)
signature_hex_str = signature.signature.decode('utf-8')

url = "http://cs302.kiwi.land/api/rx_broadcast"
#create HTTP BASIC authorization header
credentials = ('%s:%s' % (username, password))
b64_credentials = base64.b64encode(credentials.encode('ascii'))


headers = {
    'Authorization': 'Basic %s' % b64_credentials.decode('ascii'),
    'Content-Type' : 'application/json; charset=utf-8',
}

payload = {
    "loginserver_record": certificate,  
    "message": "Yay again",  
    "sender_created_at" : time,  
    "signature" : signature_hex_str
}

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


