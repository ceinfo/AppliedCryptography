# Crypt0_pr0j3ct_2

1) Run the following on the command line:
	
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

2) Start the program:

	cd <to directory of the project>
	python sms_encrypt.py



-----------------

General Idea:
create a facebook like website, which allows only certain group of people see owner's posts.

Backend:
Use DJANGO or FLASK, lets see which is better.

CryptoScheme:
Possible scheme can be：
Owner post a Enc(msg), which can only be decrypted using a certain key, which can only be obtained by owner's friend;
using Asymetric crypto.
