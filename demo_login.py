import app, json

client = app.app.test_client()

print('\n=== Normal login (known device) ===')
rv = client.post('/', data={'username':'felix','password':'felix123','device_id':'laptop1'}, follow_redirects=False)
print('POST / ->', rv.status_code, 'Location:', rv.headers.get('Location'))
# read OTP store
try:
    with open('otp_store.json') as f:
        otp = json.load(f).get('felix')
except Exception:
    otp = None
print('OTP in store:', otp)
# visit OTP page and submit
rv2 = client.get('/otp')
print('/otp GET ->', rv2.status_code)
if otp:
    rv3 = client.post('/otp', data={'otp': otp}, follow_redirects=True)
    print('/otp POST ->', rv3.status_code)
    print('Main page snippet:', rv3.get_data(as_text=True)[:200])

print('\n=== Medium login (unknown device) ===')
rv = client.post('/', data={'username':'felix','password':'felix123','device_id':'phoneX'}, follow_redirects=False)
print('POST / ->', rv.status_code, 'Location:', rv.headers.get('Location'))
with client.session_transaction() as sess:
    print('session delay_until:', sess.get('delay_until'), 'otp_sent:', sess.get('otp_sent'))
    # force expiry
    sess['delay_until'] = 0
rv2 = client.post('/send_deferred_otp', json={})
print('/send_deferred_otp ->', rv2.status_code, rv2.get_data(as_text=True))
try:
    with open('otp_store.json') as f:
        otp2 = json.load(f).get('felix')
except Exception:
    otp2 = None
print('OTP after deferred send:', otp2)

print('\n=== High-risk (failed attempts) ===')
for i in range(3):
    rv = client.post('/', data={'username':'felix','password':'wrongpass','device_id':'laptop1'}, follow_redirects=True)
    text = rv.get_data(as_text=True)
    print(f'Attempt {i+1} ->', rv.status_code, 'contains access_denied?', 'Access temporarily blocked' in text or 'Invalid username or password' in text or 'access_denied' in text)

print('\nAttempt correct password after failures:')
rv = client.post('/', data={'username':'felix','password':'felix123','device_id':'laptop1'}, follow_redirects=True)
print('Status:', rv.status_code)
print(rv.get_data(as_text=True)[:400])
