#!/usr/bin/python3
""" main.py

    COMPSYS302 - Software Design - Example Client Webapp
    Current Author/Maintainer: Hammond Pearce (hammond.pearce@auckland.ac.nz)
    Last Edited: March 2019

    This program uses the CherryPy web server (from www.cherrypy.org).
"""
# Requires:  CherryPy 18.0.1  (www.cherrypy.org)
#            Python  (We use 3.5.x +)

import os

import cherrypy

import server

import urllib.request

import os
import socket

if os.name != "nt":
    import fcntl
    import struct

def get_interface_ip(ifname):
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    return socket.inet_ntoa(fcntl.ioctl(s.fileno(), 0x8915, struct.pack('256s',
                            ifname[:15]))[20:24])

def get_lan_ip():
    ip = socket.gethostbyname(socket.gethostname())
    if ip.startswith("127.") and os.name != "nt":
        interfaces = [
            "eth0",
            "eth1",
            "eth2",
            "wlan0",
            "wlan1",
            "wifi0",
            "ath0",
            "ath1",
            "ppp0",
            ]
        for ifname in interfaces:
            try:
                ip = get_interface_ip(ifname)
                break
            except IOError:
                pass
    print(ip)
    return ip
get_lan_ip()

# The address we listen for connections on
LISTEN_IP = "172.23.1.134"
LISTEN_PORT = 8080

def runMainApp():
    #set up the config
    conf = {
        '/': {
            'tools.staticdir.root': os.getcwd(),
            'tools.encode.on': True, 
            'tools.encode.encoding': 'utf-8',
            'tools.sessions.on': True,
            'tools.sessions.timeout': 60 * 1, #timeout is in minutes, * 60 to get hours

            # The default session backend is in RAM. Other options are 'file',
            # 'postgres', 'memcached'. For example, uncomment:
            # 'tools.sessions.storage_type': 'file',
            # 'tools.sessions.storage_path': '/tmp/mysessions',
        },

        #configuration for the static assets directory
        '/static': { 
            'tools.staticdir.on': True,
            'tools.staticdir.dir': 'static',
        },

        '/css': { 
            'tools.staticdir.on': True,
            'tools.staticdir.dir': 'static',
        },
        
        #once a favicon is set up, the following code could be used to select it for cherrypy
        #'/favicon.ico': {
        #    'tools.staticfile.on': True,
        #    'tools.staticfile.filename': os.getcwd() + '/static/favicon.ico',
        #},
    }

    cherrypy.site = {
        'base_path': os.getcwd()
    }

    # Create an instance of MainApp and tell Cherrypy to send all requests under / to it. (ie all of them)
    cherrypy.tree.mount(server.MainApp(), "/", conf)
    cherrypy.tree.mount(server.ApiApp(), "/api/", conf)

    # Tell cherrypy where to listen, and to turn autoreload on
    cherrypy.config.update({'server.socket_host': LISTEN_IP,
                            'server.socket_port': LISTEN_PORT,
                            'engine.autoreload.on': True,
                           })

    #cherrypy.tools.auth = cherrypy.Tool('before_handler', auth.check_auth, 99)

    print("========================================")
    print("             Hammond Pearce")
    print("         University of Auckland")
    print("   COMPSYS302 - Example client web app")
    print("========================================")                       
    
    # Start the web server
    cherrypy.engine.start()

    # And stop doing anything else. Let the web server take over.
    cherrypy.engine.block()
 
#Run the function to start everything
if __name__ == '__main__':
    runMainApp()