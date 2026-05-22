import random
from app import send_otp_email, save_otp_store, load_otp_store
otp=str(random.randint(100000,999999))
store = load_otp_store()
store['felix']=otp
save_otp_store(store)
ok,msg=send_otp_email('felixnoell123@gmail.com','felix',otp)
print('OTP=', otp)
print('SEND_RESULT:', ok, msg)
