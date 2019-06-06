import sqlite3

"""
Users table(username,password)
Message table(sender,reciever, message, time)
Broadcast table(sender,message, time)
"""

def initialise_database():
    print("initialised")
    conn = sqlite3.connect("database.db")
    c = conn.cursor()

    c.execute("""CREATE TABLE IF NOT EXISTS users(username TEXT PRIMARY KEY NOT NULL, 
    password TEXT NOT NULL)""")
    c.execute("""CREATE TABLE IF NOT EXISTS broadcasts(sender TEXT NOT NULL, 
    message TEXT NOT NULL, time TEXT NOT NULL)""")
    c.execute("""CREATE TABLE IF NOT EXISTS messages(reciever TEXT NOT NULL, sender TEXT NOT NULL, 
    message TEXT NOT NULL, time TEXT NOT NULL)""")
    c.close()


def add_broadcast(new_sender, new_message, new_time):
    conn = sqlite3.connect("database.db")
    c = conn.cursor()
    c.execute("insert into broadcasts (sender,message,time) values ('" + new_sender +"','" 
    + new_message + "','" + new_time + "')")
    conn.commit()
    c.close()

def get_all_broadcasts():
    conn = sqlite3.connect("database.db")
    c = conn.cursor()
    return_broadcasts = []
    c.execute( """select b.sender, b.message
                  from broadcasts b 
                  order by time desc""")
    broadcasts = c.fetchall()
    c.close()
    for broadcast in broadcasts:
        return_broadcasts.append("Sender:" + str(broadcast[0]) + "Message: "+ str(broadcast[1]))
    print("return_broadcasts: " + str(return_broadcasts))
    return return_broadcasts

def add_message(new_reciever, new_sender, new_message, new_time):
    conn = sqlite3.connect("database.db")
    c = conn.cursor()
    c.execute("insert into messages(reciever, sender,message,time) values ('" + new_reciever + "','" + 
    new_sender +"','" + new_message + "','" + new_time + "')")
    conn.commit()
    c.close()

def get_message_usernames(username):
    conn = sqlite3.connect("database.db")
    c = conn.cursor()
    return_usernames = []
    c.execute( """select distinct m.sender
                  from messages m
                  where m.sender <> '"""+ username + """'""")
    usernames = c.fetchall()
    c.close()
    for username in usernames:
        print("username for message" + username[0])
        return_usernames.append(str(username[0]))
    return return_usernames

def get_messages_from(signin_username, sender_username):
    conn = sqlite3.connect("database.db")
    c = conn.cursor()
    return_messages = []
    c.execute("""select distinct m.message, m.time, m.sender
                 from messages m
                 where (m.sender = ? and m.reciever = ?)
                 or (m.sender = ? and m.reciever = ?)
                 order by time asc""",
                 (sender_username,signin_username,signin_username,sender_username))
    messages = c.fetchall()
    c.close()
    for message in messages:
        print(message[0] + " " + message[2])
        return_messages.append(str(message[0] + " " + message[2]))
    return return_messages
