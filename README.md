# Applied Cryptography - Final Project

  Applied Cryptography Final Project provides a web application which allows system users to communicate with additional security.  This project contains:
  1) Flask web application enabled with https
  2) user of the system exchange messages using symmetric encryption (shared key between user and server) and asymmetric encryption (server's public key) with AES-CBC and RSA
  3) message integrity validated using digital signatures with SHA256 and PSS
  4) users are authenticated using bcrypt to validate salted hashed passwords
  5) storage of users and messages available in Sqlite
<BR>


## Process Flow
Encrypted Flow             |  Decrypted Flow
:-------------------------:|:-------------------------:
![](https://raw.githubusercontent.com/ceinfo/AppliedCryptography-FinalProject/master/images/cryptoFinalEncryptFlow.png)  |  ![](https://raw.githubusercontent.com/ceinfo/AppliedCryptography-FinalProject/master/images/cryptoFinalDecryptFlow.png) 
<BR>


## Assumptions
```
 * The private keys of the server and user are not compromised.
 * Security mechanisms (AES, CBC, SHA256, and RSA) continue to remain secure.
```
<BR>

## Running the Project:
1) Run the following on the command line:
```
	sudo pip install virtualenv
	mkdir crypto_sms
	cd crypto_sms
	virtualenv venv
	
	. venv/bin/activate
	pip install Flask
	sudo apt-get install python-dev	
	pip install pyOpenSSL
	pip install bcrypt
	pip install PyCrypto
	export FLASK_APP=sms_encrypt.py
```
<BR>

2) Start the program:
```
	cd <to directory of the project>
	python sms_encrypt.py
```

Thanks!
