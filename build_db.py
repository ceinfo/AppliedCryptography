#!/usr/bin/python

"""
Catherine Eng
  Applied Cryptography - build our database and seeds inital users 
  and used for our Send Message Service.
"""

import time
import whois
import urllib2
import socket
import requests
import json
import geocoder
import simplekml
import sqlite3
import os

from urlparse import urlparse
##from pprint import pprint
##from scapy.all import *
from sqlalchemy import create_engine, Column, String, Integer, Unicode, MetaData, Table
from sqlalchemy.orm import mapper, create_session
from bcrypt import hashpw, gensalt


PRINT_DELIM = "-" * 50
dbname = "ceng_extract.db"
if os.path.exists(dbname):
  os.remove(dbname)
engine = create_engine("sqlite:///" + dbname, echo=False)
table = None
metadata = MetaData(bind=engine)


# Setting up the database in the next few lines.
datadict = {}
users_fields = ["user", "password"]

# Append the web_db_fields to the master table list.
usersColumns = users_fields

class Users(object):
  pass


"""
  database_insert(): This function accepts a dictionary element
    and inserts into the sqlite database.

  Arguments:
    insert_record - a dictionary record with file properties.
"""
def database_insert(insert_record):
  session = create_session(bind=engine, autocommit=False, autoflush=True)
  w = Users()

  # Print all elements from the record.
  for key, value in insert_record.iteritems():
    newvalue = str(value)
    setattr(w, str(key), newvalue)

  session.add(w)
  session.commit()



"""
  database_report(): Queries the database for all records inserted.
    Summarizes the # of records, # of images and # of pdfs.
    Writes a report to the REPORT_FILE filename.

  Arguments:
    report_text - contains output from querying the database.
"""
def database_report():
  report_text = "\n  " + PRINT_DELIM
  report_text += "\n    Database Record Listing "
  report_text += "\n  " + PRINT_DELIM
  add_usersColumns = ["Id"] + usersColumns
  session = create_session(bind=engine, autocommit=False, autoflush=True)

  # Print all elements from the record.
  for r in session.query(Users):
    ##field_str = "\n  " + str(r.Id) + "_" + "Record: " + r.domain
    field_str = "\n  " + str(r.Id) + "_" + str(r.user) + ":" + str(r.password)
    for field in add_usersColumns:
      value = getattr(r, field)
      if (value):
        field_str += "\n\t" + field + "=" + str(value)
      """
      else:
         field_str += "\n\tNone found for " + field
      """
    report_text += field_str

  report_text += "\n  " + PRINT_DELIM
  report_text += "\n    Database Program Summary "
  report_text += "\n  " + PRINT_DELIM
  report_text += "\n   # Total Records Found:  %d" % (session.query(Users).count())
  
  return report_text


"""
  database_create(): Helps to create a sqlite database.
    Called at initial program startup and adds usersCol
    columns.
"""
def database_create():
  t = Table( "users", metadata, Column("Id", Integer, primary_key=True),
      *(Column(usersCol, Unicode(3000, convert_unicode=False)) for usersCol in usersColumns))
  metadata.create_all()
  mapper(Users, t)
  usersColumns_str = str(sorted(usersColumns))


def hashp(plain):
  hashed = hashpw(plain, gensalt())
  return hashed

###############################################################
#  Starting main 
###############################################################

#Create our database
database_create()

#Create the datadictionary
datadict["1"] = {"user":"one", "password":hashp("1pass")}
datadict["2"] = {"user":"two", "password":hashp("2pass")}
datadict["3"] = {"user":"three", "password":hashp("3pass")}

##for x datadict.iteritems():
for key, value in datadict.iteritems():
  database_insert(datadict[key])

print database_report()
