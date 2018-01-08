# Applied Cryptography - Final Project

  Applied Cryptography Final Project - Flask web application enabled with:
  1)  https
  2) user login to exchange asymmetric and symmetric encrypted msgs (your own/system created) between users, 
  3) message verification with digital signatures
  4) storage of users and messages in sqlite
  
## Process Flow

Encrypted Flow             |  Decrypted Flow
:-------------------------:|:-------------------------:
![](https://raw.githubusercontent.com/ceinfo/AppliedCryptography-FinalProject/master/images/cryptoFinalEncryptFlow.png)  |  ![](https://raw.githubusercontent.com/ceinfo/AppliedCryptography-FinalProject/master/images/cryptoFinalDecryptFlow.png) 


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
