# Applied Cryptography - Final Project

  Applied Cryptography Final Project - Flask web application enabled with:
  1)  https
  2) user login to exchange asymmetric and symmetric encrypted msgs (your own/system created) between users, 
  3) message verification with digital signattures
  4) storage of users and messages in sqlite
  
## Process Flow
```
  User Logs In -> 
  Plaintext is enterd 

```
User Logs In -> 
Sends Message to Another User ->  

If message is entered as plaintext:
*Calculate the SHA256 of plaintext entry
*Calculate digital signature using the msg and user's private key
*Using AES CBC, encrypt the a private shared key (shared only between the user and the server)
*Use RSA and encrypt with the Server's public key
*Encrypted value is stored in the DB

If message is entered as encrypted text (encrypted msg and digital signature must be calculated):
*Stored in the database

Now the Recipient logs in and retrieve's their messages:
* 
Message is digitally signed by the user's private key (using PKCS_PSS)
Message digital signature is stored in base64
Message is 
Message is then base64 encoded 
Message is encrypted with AES CBC 

Message is encrypted with Recipient's Sender Key
| Description            | All Columns             | 
| ---------------------- |:-----------------------:|
![Process Flow](https://raw.githubusercontent.com/ceinfo/AppliedCryptography-FinalProject/master/images/cryptoFinalEncryptFlow.png) | [Process Flow](https://raw.githubusercontent.com/ceinfo/AppliedCryptography-FinalProject/master/images/cryptoFinalEncryptFlow.png) |



## Assumptions
*Keystore to be kept in 

## Running the Project:
1) Run the following on the command line:
```
	sudo pip install virtualenv
	mkdir crypt_p2
	cd crypt_p2
	virtualenv venv
	
	. venv/bin/activate
	pip install Flask
	sudo apt-get install python-dev	
	pip install pyOpenSSL
	pip install bcrypt
	pip install PyCrypto
	export FLASK_APP=sms_encrypt.py
```

2) Start the program:
```
	cd <to directory of the project>
	python sms_encrypt.py
```

Thanks!
