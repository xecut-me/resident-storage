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
| `/otp` | GET | Get OTP prefixes for all residents |

### Data Integrity

All data is cryptographically chained - each version references the SHA256 hash of the previous version. This provides an audit trail and ensures data integrity. Services consuming this data should:

1. Store their copy of relevant data in non-volatile storage
2. Periodically poll for updates
3. Verify cryptographic chain if it is capable of doing so
4. Validate data before use

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
GET /otp - return {version_unixtime, residents: ["", ...]} thats otp_prefix of all resident: true  

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
            "otp_prefix": unique optional str,
            "vpn": [
                {
                    "ip": unique 192.168.11.x where 2 <= x <= 250,
                    "wg_public_key": unique ^[A-Za-z0-9+/]{43}=?$
                }
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
fee_payments table itself of date, currency dropdown, amount

State is stored in HTML itself, when rendering table build it from scrath using innerText and value.  

Table should have column delete feature, add new column at end, add button should be availble even if empty.  

When saving done ok: true -> location.reload(), if error, show "error" and it as is using innerText.  

Do not repeat yourself when coding.  
