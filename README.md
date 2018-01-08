# Applied Cryptography - Final Project 2
This project was created for the Applied Cryptography class.  This is:
 * Flask based web application enabled with https 
 * Users are authenticated  
  


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
	</code>
```

2) Start the program:
```
	cd <to directory of the project>
	python sms_encrypt.py
```

Thanks!
