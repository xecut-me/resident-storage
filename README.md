# Resident Storage

## User documentation

Resident Storage is a microservice that serves as the source of truth for hackspace resident data. Other systems can rely on this service to get verified, cryptographically-chained account information.

### Getting Started

#### Web Interface

1. Open the service URL in your browser
2. Click the **Login** button in the header
3. Enter your API key when prompted
4. Your access level will be displayed in the header

The web interface provides a table view of all accounts where you can view and edit resident information based on your permissions.

#### API Access

All API endpoints require authentication via HTTP Bearer token. Include your API key in the `Authorization` header:

```
Authorization: Bearer your_api_key_here
```

### Access Levels

| Access Level | View Accounts | Edit Accounts | Add/Delete Accounts |
|-------------|---------------|---------------|---------------------|
| Read-only | Yes | No | No |
| Decentrala Election | Yes (Decentrala members only) | Residency status only | No |
| Read-write | Yes | Yes | Yes |

### Web Interface Features

#### Viewing Accounts

After logging in, you'll see a table with the following columns:
- **Username** - Unique identifier for the account
- **Telegram** - Optional Telegram username
- **Decentrala** - Whether the account is a Decentrala member
- **Resident** - Current residency status
- **OTP Prefix** - One-time key prefix for accessing a hackspace door
- **VPN** - List of VPN configurations, for each device (IP address and WireGuard public key)
- **SSH Keys** - List of SSH public keys for server access
- **Fee Payments** - Payment history with date, currency, and amount

#### Editing Accounts

If you have edit permissions:
1. Modify any field directly in the table
2. Click **Save** to submit changes
3. The page will reload on success, or display an error message

#### Managing VPN Entries

- Click **+ VPN** to add a new VPN configuration
- Enter the IP address (format: `192.168.11.x` where x is 2-250)
- Enter the WireGuard public key
- Click **X** to remove a VPN entry

#### Managing SSH Keys

- Click **+ SSH** to add a new SSH public key
- Enter the SSH public key (OpenSSH format, e.g., `ssh-ed25519 AAAA...`)
- Click **X** to remove an SSH key entry

#### Managing Fee Payments

- Click **+ Fee** to add a new payment record
- Select the date, currency (RSD, EUR, USD, RUB, ETH, BTC), and amount
- Click **X** to remove a payment entry

#### Adding/Deleting Accounts

If you have full write access:
- Click **+ Account** to create a new account
- Click **Delete** on any row to remove an account

### API Endpoints

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/` | GET | Web interface |
| `/docs` | GET | Swagger UI API documentation |
| `/accounts` | GET | Get all accounts (latest version) |
| `/accounts` | POST | Update accounts |
| `/dump` | GET | Get all historical versions, use this for crypto chain verification |
| `/me` | GET | Check your access level and permissions |

### Data Integrity

All data is cryptographically chained - each version references the SHA256 hash of the previous version. This provides an audit trail and ensures data integrity. Services consuming this data should:

1. Store their copy of relevant data in non-volatile storage
2. Periodically poll for updates
3. Verify cryptographic chain if it is capable of doing so
4. Validate data before use

## [WIP] Designing data consumers

Create ./config.json and ./resident-data and run python3 poll.py, make your command read ./resident-data/last.json

Config example

{
    "resident_storage_url": "https://example.com/accounts",
    "resident_storage_api_key",

    "strict_validation": true to fail if update chain is broken,
    "on_update_command": "python3 update-vpn.py",

    "telegram_api_key": optional,
    "telegram_notify": [
        {
            "chat_id",
            "topic_id": optional
        }
    ]
}

### How its coded

resident-data is basically a copy of ./data on server of unixtime-sha256.json files + last.json that is a copy of last json.  

poll.py each 10 minutes spawns a task, with catch-all & print exception, each task should finish in 5 minutes and 5 more minutes update process may run via on_update_command.  

Task fetches resident_storage_url/accounts with Authorization Bearer resident_storage_api_key and compares with last.json.  
If sha256 of result it got is exactly same as sha256 of last.json contents, than short-circuit exit.  
If result's .meta.last_sha256 is same as sha256 of last.json contents that this is valid transition.  

In case of valid transition or (invalid transition + strict_validation: false) we then spawn a task with on_update_command with timeout. Also new file is written and last.json is updated.  

In case of invalid transition we start full chain check by requesting GET /dump and reading all unixtime-sha256.json in resident-data, 5 min timeout still apply.  

When checking, chain of hashes server responded should have same start as recorded chain. In this case we write another files, update last.json and go valid way. If something not matches we fail validation and do not update, do not trigger on_update_command.  

Do not repeat yourself when coding.  

When first encountered invalid chain or when transition happened to new version, or in case transition happened but on_update_command exited non-zero, send a telegram notification using telegram_api_key, chat_id, topic_id.  

Send telegram message only on final actions, not checking full chain that may be valid if 2+ updates posted in one cycle.  

Encounter chain validation fail only in strict_validation mode.  

Use aiohttp==3.13.3  

### Update VPN consumer

This consumer update-vpn.py should read ./resident-data/last.json, get a dict of ip: key, override config.vpn_admin_ip with config.vpn_admin_public_key so control plane is separated from data plane.  

Validare ip's to be unique 192.168.11.x where 2 <= x <= 250 and keys unique ^[A-Za-z0-9+/]{43}=?$

When editing, use this template, config should be saved in a temp file and then sudo mv to /etc/wireguard/wg0.conf. 

```
[Interface]
PrivateKey = [config.vpn_private_key]
Address = 192.168.11.1/24
ListenPort = [config.vpn_port]

PostUp = iptables -t nat -A POSTROUTING -o eth0 -j MASQUERADE
PostDown = iptables -t nat -D POSTROUTING -o eth0 -j MASQUERADE

[Peer]
PublicKey = [wg_public_key]
AllowedIPs = [wg_ip]/32
```

And finally verify and run "sudo service wg-quick@wg0 reload", if not valid, revert.  

Admin key and ip is already in last.json, you need literally override it in dict generated and do it even if read failed and there are no peer so admin will be always able to VPN into server and fix broken updater, no softlock should be possible.  

TODO: Notify telegram.  

### Update telegram IDs consumer

This consumer update-telegram-ids.py should read ./resident-data/last.json same as VPN consumer, but it takes accounts where telegram and otp_prefix are set.  

It reads /homeassistant/automations.yaml that is list, finds one that is "alias": "Record on CODE" and its.  

```
actions:
- variables:
    uid_map:
    'otp_prefix': telegram
```

Updates it and reloads home assistant.

## Developer documentation

All code was generated based on a hand written developer documentation by Claude Code Opus 4.5. Code was human reviewed for sanity and security to prevent logic errors and language misuse.  

### Design

Write fastapi dockerized account storage microservice with role separation, HTTPBearer, pydantic validation and cryptographic chaining to last version, store in /data as unixtime-sha256.json.  

API keys are passed via env and should be at least 10 chars, crash if they are not present, secure or unique.  

Updating should take global lock. If no last version exist, stub should be returned and used as base: unixtime: 0, sha256: all 0, accounts = [].  

### Run

```
# Build and run
docker build -t resident-storage .
docker run -p 8000:8000 \
  -e READ_KEY=your_read_key_here \
  -e WRITE_KEY=your_write_key_here \
  -e DECENTRALA_ELECTION_KEY=your_election_key \
  -v /path/to/data:/data \
  resident-storage
```

### Endpoints:

GET / - redirect to Swagger UI's /docs  
GET /accounts - return last JSON file contents, do not re-serialize so hashes will match.  
POST /accounts - validate, serialize and save new version into file, return {ok: true}.  
GET /dump - return a dict with all versions, key = filename, value = string of file content.  
GET /me - returns {access: "read-only" | "read-write" | "decentrala election (just residency edit)", edit: true/false, new: true/false}  
GET /export/vpn - returns VPN config based on accounts, only that has  
GET /export/otp-map - returns OTP user map based on accounts  

#### VPN example

```
# wg-xecut-resident-vpn-telegram_username.conf
[Peer]
PublicKey = redacted
AllowedIPs = 192.168.11.x/32

# wg-xecut-vpn-telegram_username.conf
[Peer]
...
```

#### OTP map example (yaml part with padding)

```
      uid_map:
        'OTP_PREFIX': telegram_username
```

#### Decentrala key

When reading, use stub meta and filter decentrala=true only.  

When writing, take last file as base and use just payload's resident field of decentrala=true.  

### Format:

```json
{
    "meta": {
        "unixtime",
        "last_sha256"
    },
    "accounts": [
        {
            "username": unique required str,
            "telegram": unique optional str,
            "decentrala": bool,
            "resident": bool,
            "otp_prefix": unique optional str consist from 0123456789PTMBOSLA symbols cant start with P,
            "vpn": [
                {
                    "ip": unique 192.168.11.x where 2 <= x <= 250,
                    "wg_public_key": unique ^[A-Za-z0-9+/]{43}=?$
                }
            ],
            "ssh_keys": [
                unique str one line starts sk- or ssh-
            ],
            "fee_payments": [
                {
                    "date": "yyyy-mm-dd",
                    "currency": "RSD" | "EUR" | "USD" | "RUB" | "ETH" | "BTC",
                    "amount": 1234.56
                }
            ]
        }
    ]
}
```

Use same model for input validation and for output generation.  

Fee payments should be sorted in time ASC.  

Check date exist using standard library, not custom function.  

### Keys:

READ_KEY - can GET /accounts and GET /dump, edit: false, new: false  
WRITE_KEY - what READ_KEY can, plus POST /accounts, edit: true, new: true  
DECENTRALA_ELECTION_KEY - can filtered GET /accounts and POST /accounts update residency of decentrala accounts, edit: true, new: false  

When comparing keys use timing side channel resistant function to avoid key leak.  

Decentrala key should be allowed to access just /accounts and /me.  

### Use versions:

python:3.13-slim  

fastapi==0.128.0  
uvicorn[standard]==0.40.0  
pydantic==2.12.5  

### Web interface

index.html + serve in main.py  

Header button login/logout that sets/clears localStorage.apiKey, link to /docs named Swagger UI and access level from /me via innerText. Buttons should be displayed based on edit and new fields.  

All-in-one html with vanilla JS, GET /accounts and draw a table. If auth error -> show "error" and it as is using innerText.  

Draw a table of accounts:  
username text input  
telegram text input, is empty sent as null  
decentrala checkbox  
resident checkbox  
otp_prefix text input, is empty sent as null  
vpn table itself of ip (default value 192.168.11.x) and wg_public_key, when newly created, no lines by default
ssh_keys table of public keys in OpenSSH format, when newly created, no lines by default
fee_payments table itself of date, currency dropdown, amount

State is stored in HTML itself, when rendering table build it from scrath using innerText and value.  

Table should have column delete feature, add new column at end, add button should be availble even if empty.  

When saving done ok: true -> location.reload(), if error, show "error" and it as is using innerText.  

Do not repeat yourself when coding.  
