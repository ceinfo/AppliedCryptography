#!/usr/bin/python

import sqlite3
import datetime
import time
import os
import sys
import base64
import ast
import traceback

from flask import Flask
from flask import request
from flask import render_template
from flask import url_for, redirect
from werkzeug.serving import run_simple

from Crypto.PublicKey import RSA
from Crypto.Signature import PKCS1_PSS
## Commented out for upgrade to new pkcs
#from Crypto.Signature import PKCS1_v1_5
#from Crypto.Cipher import PKCS1_OAEP
from Crypto.Cipher import AES
from Crypto.Hash import SHA256
from Crypto import Random

from sqlalchemy import create_engine, Column, String, Integer, Unicode, MetaData, Table, or_
from sqlalchemy.orm import mapper, create_session
from bcrypt import hashpw, gensalt

from OpenSSL import SSL
context = SSL.Context(SSL.SSLv23_METHOD)
loggedin = False
user = ""

"""
### use below for 2.7.11+
import ssl 
context = ssl.SSLContext(ssl.PROTOCOL_TLSv1_2)
context.load_cert_chain("crypto.com.crt", "crypto.com.key")
"""
cer = "./crypto.com.crt"
key = "./crypto.com.key"
dbname = "ceng_extract.db"
engine = create_engine("sqlite:///" + dbname, echo=False)
session = create_session(bind=engine, autocommit=False, autoflush=True)
table = None
metadata = MetaData(bind=engine)
user_fields = ["user", "password"]
message_fields = ["to", "user", "entry", "ds", "datets"]
KEY_LENGTH = 1024
KEYDIR = "keystore"
KEYDIR_PRIVATE = os.path.join(".", KEYDIR, "privatekeys")
KEYDIR_PUBLIC = os.path.join(".", KEYDIR, "publickeys")
KEYDIR_CRYPTO = os.path.join(".", KEYDIR, "serverkeys")
CRYPTO_PUBLIC_KEY = "crypto_publickey"
CRYPTO_PRIVATE_KEY = "crypto_privatekey"
cer = os.path.join(".", KEYDIR, "crypto.com.crt")
key = os.path.join(".", KEYDIR, "crypto.com.key")
random_gen = Random.new().read

# Append the web_db_fields to the master table list.
USERS = "users"
MESSAGE = "message"
userColumns = user_fields
messageColumns = message_fields

class Users(object):
  pass
class Message(object):
  pass

BS = 32
pad = lambda s: s+ (BS - len(s) % BS) *chr(BS-len(s) %BS)
unpad = lambda s: s[:-ord(s[len(s)-1:])]

app = Flask(__name__)
app.debug = True


@app.route("/")
@app.route("/welcome")
def welcome():
  str = render_template("login.html")
  return str


@app.route("/logout", methods=["GET", "POST"])
def logout():
  global user
  global loggedIn
  user = ""
  loggedIn = False
  return redirect(url_for("welcome"))


@app.route("/validate_login", methods=["GET", "POST"])
def validate_login():
  user = request.form["user"]
  password = request.form["password"]
  str = validatepass(user, password)
  return str 


# This allows a new entry to be added to the site.
@app.route("/add_entry", methods=["GET", "POST"])
def add_entry():
  if not user:
    return redirect(url_for("logout"))

  str = render_template("add_entry.html", user=user)
  return str


# This allows the entry to be current and previous entries to be displayed.
@app.route("/insert_entry", methods=["GET", "POST"])
def insert_entry():
  entry = request.form["entry"]
  to = request.form["to"]
  user = request.form["user"]
  try:
    encrypt = request.form["encrypt"]
  except:
    encrypt = ""
  ds = request.form["ds"]

  # The encrypted entry 
  cipher = entry
  if encrypt:
    (ds, cipher) = encrypt_msg(entry, user, to)
    
  datadict = {}
  datadict[user] = {"to":to, "user":user, "entry":cipher, 
                    "ds":ds, "datets": time.strftime("%c")}
  database_insert(datadict[user], MESSAGE)

  outstr = "<B>Entry: </B><BR>" + str(cipher)
  outstr += "<BR><BR><B>DS: </B><BR>" + str(ds) + "<HR><BR>"

  (records, decryptdict) = database_query_entry(user)
  outstr += render_template("view_entry.html", entry=entry, user=user, records=records, dict=decryptdict)
  return outstr


@app.route("/view_entries")
def view_entries():
  if not user:
    return redirect(url_for("logout"))
  outstr = ""
  (records, decryptdict) = database_query_entry(user)
  outstr += render_template("view_entry.html", user=user, records=records, dict=decryptdict)
  return outstr


@app.route("/view_entries_decrypted")
def view_entries_decrypted():
  if not user:
    return redirect(url_for("logout"))
  outstr = ""
  (records, decryptdict) = database_query_entry(user, True)
  outstr += render_template("view_entry_decrypted.html", user=user, records=records, dict=decryptdict)
  return outstr


############################################################
# LOCAL FUNCTIONS
############################################################
def testtime():
  print "Some timing tests"


"""
  validatepass:  Validate the user and password 
  in the sqlite database.
"""
def validatepass(iuser, plain):
  global loggedin
  global user
  str = ""
  hashed = ""
  plain = plain.encode("utf-8")
  r = (session.query(Users).filter_by(user=iuser).first())
  if r and r.password:
    hashed = (r.password).encode("utf-8")

  # Check for valid user and passwords
  if len(hashed) and hashpw(plain, hashed) == hashed:
    str = "Directing to logged in <BR>"
    loggedin = True
    user = iuser
    return redirect(url_for("add_entry"))
  else:
    str = "Invalid data,  goodbye!<BR>"
  return str


"""
  database_query_entry():  queries the message/entry table. 
  iuser:  searches for the user that entered the record.
"""
def database_query_entry(iuser, requester_decrypt=False):
  decryptdict = {}
  outstr = ""
  r = (session.query(Message).filter(or_(Message.user==iuser,Message.to==iuser))
       .order_by(Message.Id.desc()).all())

  for rec in r:
    try:
      (dsig, dmsg) = decrypt_msg(ast.literal_eval(rec.entry.decode()), rec.user, rec.ds.decode(), user)
      if requester_decrypt:
        (dsig, dmsg) = decrypt_encrypt_msg_for_requester(dmsg, dsig, user)

    except:
      dsig = dmsg = "ERROR:  Cannot decode message."
      #traceback.print_exc()

    decryptdict[rec.Id] = {"msg": dmsg,  "ds": dsig}
  return (r, decryptdict)


"""
  hashp():  hashes for the user password
"""
def hashp(plain):
  hashed = hashpw(plain, gensalt())
  return hashed


"""
  create_test_users():  Creates test users for inital testing
  Flushes the current table and only creates these entries. 
"""
def create_test_users():
  try:  
    session.query(Users).delete()
    session.commit()
  except:
    pass

  #Create the datadictionary
  datadict = {}
  datadict["1"] = {"user":"one", "password":hashp("1pass")}
  datadict["2"] = {"user":"two", "password":hashp("2pass")}
  datadict["3"] = {"user":"three", "password":hashp("3pass")}

  for key, value in datadict.iteritems():
    database_insert(datadict[key], USERS)


"""
  database_create(): Helps to create a sqlite database.
    Called at initial program startup and adds userCol
    columns.
"""
def database_create():
  t = Table( "users", metadata, Column("Id", Integer, primary_key=True),
      *(Column(userCol, Unicode(3000, convert_unicode=False)) for userCol in userColumns))
  b = Table( "message", metadata, Column("Id", Integer, primary_key=True),
      *(Column(messageCol, Unicode(3000, convert_unicode=False)) for messageCol in messageColumns))
  metadata.create_all()
  mapper(Users, t)
  mapper(Message, b)


"""
  database_insert(): This function accepts a dictionary element
    and inserts into the sqlite database.

  Arguments:
    insert_record - a dictionary record with file properties.
"""
def database_insert(insert_record, table_name):
  table_model = ""
  if table_name == USERS:
    table_model = Users()
  else:
    table_model = Message()

  # Print all elements from the record.
  for key, value in insert_record.iteritems():
    newvalue = str(value)
    setattr(table_model, str(key), newvalue)

  session.add(table_model)
  session.commit()


"""
  Function creates signs entry with server pk,  then 
  encrypts entry for storage into database.
"""
def encrypt_msg(entry, user, to):
  server_publickey = get_server_keys("public")

  pk = get_user_keys("private", user, 0)
  msg = entry
  hash = SHA256.new(msg)
  signer = PKCS1_PSS.new(pk)
  signature = signer.sign(hash)
  signature = base64.b64encode(signature)

  shared_key = get_user_keys("private", user, BS)
  raw = pad(msg)
  iv = Random.new().read(AES.block_size)
  aes = AES.new(shared_key, AES.MODE_CBC, iv)
  cipher = base64.b64encode(iv + aes.encrypt(raw))
  cipher = server_publickey.encrypt(cipher, BS)

  ##decrypt_msg(cipher, user, signature, user)
  return (signature, cipher)
  


"""
  Function is used when the view page is requested. 
  This encrypts takes the decrypted database message 
  and encrypts with the requester's public key and a 
  digital signature with the server's private key.
"""
def encrypt_msg_for_requester(entry, user):
  server_privatekey = get_server_keys("private")
  user_publickey = get_user_keys("public", user, 0)

  msg = entry
  hash = SHA256.new(msg)
  signer = PKCS1_PSS.new(server_privatekey)
  signature = signer.sign(hash)
  signature = base64.b64encode(signature)
  
  msg = base64.b64encode(msg)
  cipher = user_publickey.encrypt(msg, BS)
  return (signature, cipher)



"""
  This is used for the test decryption page to validate 
  testing.  This reverses the requester encryption.
"""
def decrypt_encrypt_msg_for_requester(msg, ds, user):
  try:
    server_publickey = get_server_keys("public")
    user_privatekey = get_user_keys("private", user, 0)
    
    # decrypt the msg
    decrypt_msg = user_privatekey.decrypt(msg)
    decrypt_msg = base64.b64decode(decrypt_msg)

    # compare to the digital signature  
    hash = SHA256.new(decrypt_msg)
    verifier = PKCS1_PSS.new(server_publickey)
    ds = base64.b64decode(ds)

    if verifier.verify(hash, ds):
      ds = base64.b64encode(ds)
    else:
      ds = decrypt_msg = "ERROR:  Invalid Signature, msg cannot be verified!"
  except: 
      ds = decrypt_msg = "ERROR:  Cannot decode message."
      #traceback.print_exc()

  return (ds, decrypt_msg)



"""
  decrypt_msg():  Allows users to decrypt and 
  verify the validity of message.  
"""
def decrypt_msg(cipher, user, signature, req_user):
  server_privatekey = get_server_keys("private")
  rsa_decrypt = server_privatekey.decrypt(cipher)

  try:
    rsa_decrypt = base64.b64decode(rsa_decrypt)
    shared_key = get_user_keys("private", user, BS)
    iv = rsa_decrypt[:AES.block_size]
    aes = AES.new(shared_key, AES.MODE_CBC, iv)
    msg = unpad(aes.decrypt(rsa_decrypt[AES.block_size:])).decode()
  except:
    # Occurs when shared_key corrupted. 
    ds = "ERROR:  Cannot decode message."
    return (ds, ds)

  if verify_signature(user, msg, signature):
    (ds, msg) = encrypt_msg_for_requester(msg, req_user)
    return (ds, msg)
  else: 
    ds = "ERROR: Invalid signature,  msg will not be returned."
    return (ds, ds)



"""
  verify_signature():  This function allows verification of 
  a msg into a hash with a stored database hash value for 
  msg authentication.
"""
def verify_signature(user, msg, db_signature):
  pk = get_user_keys("public", user, 0)
  hash = SHA256.new(msg)
  verifier = PKCS1_PSS.new(pk)
  db_signature = base64.b64decode(db_signature)

  if verifier.verify(hash, db_signature):
    return True
  return False


"""
  get_server_keys():  Gets either the public/private key
  for this crypto.com system.  
  User passes in "private" or "public" for keytype value
  to retrive.
"""
def get_server_keys(keytype):
  if keytype == "private":
    server_pk = os.path.join(KEYDIR_CRYPTO, CRYPTO_PRIVATE_KEY)
  else:
    server_pk = os.path.join(KEYDIR_CRYPTO, CRYPTO_PUBLIC_KEY)

  key = open(server_pk, "r").read()
  server_publickey = RSA.importKey(key)
  return server_publickey
  

"""
  get_user_keys():  Get the specific user's symmetric shared 
  key.
"""
def get_user_keys(keytype, user, bytelim):
  if keytype == "private":
    keyname = os.path.join(KEYDIR_PRIVATE, user + "_privatekey")
  else:
    keyname = os.path.join(KEYDIR_PUBLIC, user + "_publickey")

  # Return if only want a portion of key
  if bytelim:
    key = open(keyname, "r").read(bytelim)
    return key

  keypair = open(keyname, "r").read()
  pk = RSA.importKey(keypair)
  return pk


"""
  writefile():  Helper function to write text to a file.
"""
def writefile(fname, text):
  f = open(fname, "wb")
  f.write(text)
  f.close()


"""
  generate_keys():  Helper function to create some private/public
  key pairs.
"""
def generate_keys():
  for keydir in [KEYDIR, KEYDIR_PRIVATE, KEYDIR_PUBLIC]:
    if not os.path.exists(keydir):
      os.mkdir(keydir)
  for x in ["one", "two", "three"]:
    rsa_pair = RSA.generate(KEY_LENGTH,random_gen)
    """
    sk = rsa_pair.exportKey("PEM")
    pk = rsa_pair.publickey().exportKey("PEM")
    """

    sk = rsa_pair.exportKey("DER")
    pk = rsa_pair.publickey().exportKey("DER")
    writefile(KEYDIR_PRIVATE + "/" + x + "_privatekey", sk)
    writefile(KEYDIR_PUBLIC + "/" + x + "_publickey", pk)
  

############################################################
#  MAIN
############################################################
if __name__ == "__main__":
  database_create()
  #generate_keys()
  #create_test_users()
  context = (cer, key)
  run_simple("127.0.0.1", 5001, app, ssl_context=context)

