import json
import os
import hashlib
from pathlib import Path

USERS_FILE = 'users.json'

if not Path(USERS_FILE).exists():
    print('users.json not found')
    exit(1)

with open(USERS_FILE, 'r', encoding='utf-8') as f:
    users = json.load(f)

changed = 0
for u, rec in users.items():
    pw = rec.get('password')
    if not pw:
        continue
    if '$' in pw:
        # already migrated
        continue
    # create salt and hash
    salt = os.urandom(8).hex()
    h = hashlib.sha256((salt + pw).encode('utf-8')).hexdigest()
    rec['password'] = f"{salt}${h}"
    users[u] = rec
    changed += 1

with open(USERS_FILE, 'w', encoding='utf-8') as f:
    json.dump(users, f, indent=2)

print(f'Migrated {changed} passwords in {USERS_FILE}')
