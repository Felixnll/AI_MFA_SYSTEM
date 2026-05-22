import smtplib, ssl, os
host=os.getenv('SMTP_HOST')
port=os.getenv('SMTP_PORT')
user=os.getenv('SMTP_USER')
pwd=os.getenv('SMTP_PASSWORD')
print('SMTP_HOST=', host)
print('SMTP_PORT=', port)
print('SMTP_USER set=', bool(user))
try:
    port_int = int(port) if port else 0
    ctx = ssl.create_default_context()
    if port_int == 465:
        print('Using SMTP_SSL')
        s = smtplib.SMTP_SSL(host, port_int, context=ctx, timeout=10)
    else:
        print('Using SMTP then STARTTLS')
        s = smtplib.SMTP(host, port_int, timeout=10)
        s.starttls(context=ctx)
    s.login(user, pwd)
    print('LOGIN OK')
    s.quit()
except Exception as e:
    print('ERROR:', type(e), e)
