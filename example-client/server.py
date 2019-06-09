import cherrypy
import urllib.request
import json
import base64
import nacl.encoding
import nacl.signing
import time
import serverFunctions
import clientFunctions
import os
import sched
import database
from jinja2 import Environment, FileSystemLoader
from nacl.public import PrivateKey, SealedBox


startHTML = "<html><head><title>CS302 example</title><link rel='stylesheet' href='/static/style.css' /></head><body>"

hex_key = b'e278c1106318479da40b17ea4376710e11eb16c3e2a7854b2de9287ae4ed9a08'
signing_key = nacl.signing.SigningKey(hex_key, encoder=nacl.encoding.HexEncoder)

pubkey_hex = signing_key.verify_key.encode(encoder=nacl.encoding.HexEncoder)
pubkey_hex_str = pubkey_hex.decode('utf-8')

CUR_DIR = os.path.dirname(os.path.abspath(__file__))
env=Environment(loader=FileSystemLoader(CUR_DIR), trim_blocks=True)

username = "ezou149"
password = "emzoo16_844010534"

connection_location = 1
#create HTTP BASIC authorization header
credentials = ('%s:%s' % (username, password))
b64_credentials = base64.b64encode(credentials.encode('ascii'))

headers = {
    'Authorization': 'Basic %s' % b64_credentials.decode('ascii'),
    'Content-Type' : 'application/json; charset=utf-8',
}

s = sched.scheduler(time.time, time.sleep)

class MainApp(object):

	#CherryPy Configuration
    _cp_config = {'tools.encode.on': True, 
                  'tools.encode.encoding': 'utf-8',
                  'tools.sessions.on' : 'True',
                 }       

	# If they try somewhere we don't know, catch it here and send them to the right place.
    @cherrypy.expose
    def default(self, *args, **kwargs):
        """The default page, given when we don't recognise where the request is for."""
        Page = startHTML + "I don't know where you're trying to go, so have a 404 Error."
        cherrypy.response.status = 404
        return Page

    # PAGES (which return HTML that can be viewed in browser)
    @cherrypy.expose
    def index(self): 
        database.initialise_database()
        template = env.get_template('signin.html')
        return template.render()
       
    @cherrypy.expose
    def login(self, bad_attempt = "0"):
        template = env.get_template('signin.html')
        return template.render(error = bad_attempt)

    @cherrypy.expose
    def dashboard(self):
        serverFunctions.ping(pubkey_hex_str, signing_key, headers)
        serverFunctions.report(pubkey_hex_str,headers,"online")
        template = env.get_template('dashboard.html')
        broadcasts = database.get_all_broadcasts()
        return template.render(onlineusers = getUsers(), username = username, 
        recentbroadcasts = broadcasts)
    """
    @cherrypy.expose
    def privateMessage(self):
        onlineusers_database = database.get_message_usernames(username)
        past_messages_database = database.get_messages_from(username,"jzhe142")
        template = env.get_template('privatemessage.html')
        return template.render(onlineusers = onlineusers_database, pastmessages = past_messages_database)
    
    @cherrypy.expose
    def changeMessagePage(self, sender_username):
        print(sender_username)
        onlineusers_database = database.get_message_usernames(username)
        past_messages_database = database.get_messages_from(username,sender_username)
        template = env.get_template('privatemessage.html')
        return template.render(onlineusers = onlineusers_database, pastmessages = past_messages_database)
"""
    @cherrypy.expose
    def check_broadcast(self, message):
        serverFunctions.ping(pubkey_hex_str,signing_key, headers)
        clientFunctions.broadcast(message, signing_key, headers)
        raise cherrypy.HTTPRedirect('/dashboard')
    
    """
    @cherrypy.expose
    def check_privatemessage(self, message):
        serverFunctions.ping(pubkey_hex_str,signing_key, headers)
        clientFunctions.privatemessage(message, signing_key, headers, pubkey_hex_str)
        raise cherrypy.HTTPRedirect('/privatemessage.html')"""

    # LOGGING IN AND OUT
    @cherrypy.expose
    def signin(self, username_given=None, password_given=None):
        """Check their name and password and send them either to the main page, or back to the main login screen."""
        error = authoriseUserLogin(username_given, password_given)
        if error == 0:
            cherrypy.session['username'] = username
            raise cherrypy.HTTPRedirect('/dashboard')
        else:
           raise cherrypy.HTTPRedirect('/login?bad_attempt=1')

    @cherrypy.expose
    def signout(self):
        """Logs the current user out, expires their session"""
        username = cherrypy.session.get('username')
        serverFunctions.report(pubkey_hex_str,headers,"offline")
        if username == None:
            pass
        else:
            cherrypy.lib.sessions.expire()
        raise cherrypy.HTTPRedirect('/')

###
### Functions only after here
###
def authoriseUserLogin(username_given = None, password_given = None):
    print("Log on attempt from {0}:{1}".format(username, password))
    if (username.lower() == username_given) and (password.lower() == password_given):
        #Generate a public key
        serverFunctions.ping(pubkey_hex_str, signing_key, headers)
        #clientFunctions.ping_all_online()
        serverFunctions.report(pubkey_hex_str,headers,"online")
        serverFunctions.get_loginserver_record(headers)
        #serverFunctions.add_privatedata("Hello",headers,signing_key, "1234")
        #serverFunctions.get_privatedata(headers,signing_key)
        print("Success")
        return 0
    else:
        print("Failure")
        return 1

def getUsers():
    formattedUsers = []
    online_users = serverFunctions.list_users(headers)
    users = online_users["users"]

    for user in users:
        userString = user["username"] + " : " + user["status"] 
        formattedUsers.append(userString)
    return formattedUsers

class ApiApp(object):

    @cherrypy.expose
    @cherrypy.tools.json_out()
    @cherrypy.tools.json_in()
    def rx_broadcast(self):
        message = cherrypy.request.json["message"] 
        time = cherrypy.request.json["sender_created_at"]
        certificate = cherrypy.request.json["loginserver_record"]
        broadcast_username = certificate[0:7]
        database.add_broadcast(broadcast_username,message,time)
    
        return {'response': 'ok'}
        
    @cherrypy.expose
    @cherrypy.tools.json_out()
    @cherrypy.tools.json_in()
    def rx_privatemessage(self):
        print("privatemessage api called")
        target_username = cherrypy.request.json["target_username"]
        target_pubkey = cherrypy.request.json["target_pubkey"]

        if(username == target_username and pubkey_hex_str == target_pubkey):
            certificate = cherrypy.request.json["loginserver_record"]
            sender_username = certificate[0:7]

            private_key_curve = target_pubkey.to_curve25519_private_key()
            unseal_box = SealedBox(private_key_curve)

            message_encrypted = cherrypy.request.json["encrypted_message"]
            message_decrypted = unseal_box.decrypt(message_encrypted)
            message = message_decrypted.decode('utf-8')

            database.add_message(username,sender_username,message,time)
            return {'response': 'not decrypted'}

        return {'response': 'ok'}   

    @cherrypy.expose
    @cherrypy.tools.json_out()
    @cherrypy.tools.json_in()
    def ping_check(self):
        time_str = str(time.time())
        #Store recieved information in a list?
        return_body = { "response": "ok",
                        "my_time": time_str,
                        "my_active_usernames": username}
        return return_body
