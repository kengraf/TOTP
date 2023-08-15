# TOTP
Python OTP example that works with Google Authenticator.

Basic functions to generate and validate TOTP and HOTP codes.

Missing secure secret generation.

No user management.

This repo supports a GenCyber camp lesson on pyton programming using TOTP.
The audience isn't expected to be programming or security knowledgeable.

Using a TOTP authenticator [![Binder](https://mybinder.org/badge_logo.svg)](https://mybinder.org/v2/gh/kengraf/TOTP/HEAD)

The startup of Binder.org takes a minute or so to establish an IPython
environment.  To start the lesson click on the lesson link "LESSON.ipynb".  Feel free to play/alter the steps
in the lesson.  You will be working a temporary sandbox, so can not damage the original lesson.

## Running on your own server
Install jupyter notebook
```
pip install notebook
```
Clone this repo
```
git clone https://github.com/kengraf/TOTP.git
cd TOTP
```
Run a python based web server for TOTP/HOTP page
```
python3 google_authenticator.py
```
Start the notebook
```
juptyer notebook
```


## Heroku based server deploy
The camp deployed a server for the students at http://kali.cyber-unh.org. That server no longer exists.  If you want to use the interactive part you will need to deploy your own server.

For an example of a Heroku based deploy of the server goto: https://github.com/kengraf/DeployTOTP
