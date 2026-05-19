AI/ML-Enhanced Multi-Factor Authentication (Securoserv)

How to use the system:

make sure you have python 3.14 installed


I already include our details in file:users.json. Feel free to update it, especailly the email (use real email, preferable google)

-----------------------------------------------------------------------------------------------------------------------------------
**To set up SMTP ( OTP send to email)**


IMPORTANT!!!!:

For the SMTP_PASSWORD, do not use your google password, you will need to create the App Password first in Google. Can google on how to do this, but if you stuck, can ask me, i can help


NEXT STEP:

run this in Powershell in VSC

  $env:SMTP_HOST="smtp.gmail.com"
  
  $env:SMTP_PORT="465" 
  
  $env:SMTP_USER="email@example.com"
  
  $env:SMTP_PASSWORD="<GOOGLE_APP_PASSWORD>"
  
  $env:SMTP_SENDER="email@example.com"



  **To start the app,type in Poswershell:**
  python app.py

  Click on the link http://127.0.0.1:5000, it will launch browser.


