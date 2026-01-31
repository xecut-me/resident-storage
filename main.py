import hashlib
import hmac
import json
import os
import re
import threading
import time
from datetime import datetime
from pathlib import Path
from fastapi import Depends, FastAPI, HTTPException
from fastapi.responses import FileResponse, PlainTextResponse
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from pydantic import BaseModel, field_validator, model_validator

DATA_DIR = Path("/data")
STUB_SHA256 = "0" * 64

READ_KEY = os.environ.get("READ_KEY", "")
WRITE_KEY = os.environ.get("WRITE_KEY", "")
DECENTRALA_ELECTION_KEY = os.environ.get("DECENTRALA_ELECTION_KEY", "")


def validate_keys() -> None:
    keys = {"READ_KEY": READ_KEY, "WRITE_KEY": WRITE_KEY, "DECENTRALA_ELECTION_KEY": DECENTRALA_ELECTION_KEY}

    for name, value in keys.items():
        if not value:
            raise SystemExit(f"{name} is not set")
        if len(value) < 10:
            raise SystemExit(f"{name} must be at least 10 characters")

    unique_keys = set(keys.values())
    if len(unique_keys) != len(keys):
        raise SystemExit("API keys must be unique")


validate_keys()

global_lock = threading.Lock()


class FeePayment(BaseModel):
    date: str
    currency: str
    amount: float

    @field_validator("date")
    @classmethod
    def validate_date(cls, v: str) -> str:
        try:
            datetime.strptime(v, "%Y-%m-%d")
        except ValueError:
            raise ValueError("Date must be valid yyyy-mm-dd")
        return v

    @field_validator("currency")
    @classmethod
    def validate_currency(cls, v: str) -> str:
        if v not in ("RSD", "EUR", "USD", "RUB", "ETH", "BTC"):
            raise ValueError("Currency must be one of: RSD, EUR, USD, RUB, ETH, BTC")
        return v


class VPN(BaseModel):
    ip: str
    wg_public_key: str

    @field_validator("ip")
    @classmethod
    def validate_ip(cls, v: str) -> str:
        pattern = r"^192\.168\.11\.(\d+)$"
        match = re.match(pattern, v)
        if not match:
            raise ValueError("IP must be in format 192.168.11.x")
        x = int(match.group(1))
        if not (2 <= x <= 250):
            raise ValueError("IP last octet must be between 2 and 250")
        return v

    @field_validator("wg_public_key")
    @classmethod
    def validate_wg_key(cls, v: str) -> str:
        if not re.match(r"^[A-Za-z0-9+/]{43}=?$", v):
            raise ValueError("Invalid WireGuard public key format")
        return v


class Account(BaseModel):
    username: str
    telegram: str | None = None
    decentrala: bool
    resident: bool
    otp_prefix: str | None = None
    vpn: list[VPN] = []
    ssh_keys: list[str] = []
    fee_payments: list[FeePayment] = []

    @model_validator(mode="after")
    def sort_fee_payments(self) -> "Account":
        self.fee_payments = sorted(self.fee_payments, key=lambda x: x.date)
        return self

    @field_validator("username")
    @classmethod
    def validate_username(cls, v: str) -> str:
        if not v.strip():
            raise ValueError("Username cannot be empty")
        return v

    @field_validator("otp_prefix")
    @classmethod
    def validate_otp_prefix(cls, v: str | None) -> str | None:
        if v is None:
            return v
        if not v:
            raise ValueError("OTP prefix cannot be empty string")
        if not re.match(r"^[0123456789PTMBOSLA]+$", v):
            raise ValueError("OTP prefix must only contain: 0123456789PTMBOSLA")
        if v.startswith("P"):
            raise ValueError("OTP prefix cannot start with P")
        return v

    @field_validator("ssh_keys")
    @classmethod
    def validate_ssh_keys(cls, v: list[str]) -> list[str]:
        for key in v:
            if "\n" in key:
                raise ValueError("SSH key must be a single line")
            if not (key.startswith("sk-") or key.startswith("ssh-")):
                raise ValueError("SSH key must start with sk- or ssh-")
        return v


class Meta(BaseModel):
    unixtime: int
    last_sha256: str


class AccountStore(BaseModel):
    meta: Meta
    accounts: list[Account]

    @model_validator(mode="after")
    def validate_uniqueness(self) -> "AccountStore":
        usernames: list[str] = []
        telegrams: list[str] = []
        otp_prefixes: list[str] = []
        ips: list[str] = []
        wg_keys: list[str] = []
        ssh_keys: list[str] = []

        for account in self.accounts:
            usernames.append(account.username)
            if account.telegram:
                telegrams.append(account.telegram)
            if account.otp_prefix:
                otp_prefixes.append(account.otp_prefix)
            for vpn in account.vpn:
                ips.append(vpn.ip)
                wg_keys.append(vpn.wg_public_key)
            ssh_keys.extend(account.ssh_keys)

        if len(usernames) != len(set(usernames)):
            raise ValueError("Usernames must be unique")
        if len(telegrams) != len(set(telegrams)):
            raise ValueError("Telegram handles must be unique")
        if len(otp_prefixes) != len(set(otp_prefixes)):
            raise ValueError("OTP prefixes must be unique")
        if len(ips) != len(set(ips)):
            raise ValueError("VPN IPs must be unique")
        if len(wg_keys) != len(set(wg_keys)):
            raise ValueError("WireGuard public keys must be unique")
        if len(ssh_keys) != len(set(ssh_keys)):
            raise ValueError("SSH keys must be unique")

        return self


def get_stub() -> tuple[str, str]:
    stub = {"meta": {"unixtime": 0, "last_sha256": STUB_SHA256}, "accounts": []}
    content = json.dumps(stub, separators=(",", ":"))
    return content, STUB_SHA256


def compute_sha256(content: str) -> str:
    return hashlib.sha256(content.encode()).hexdigest()


def get_latest_file() -> Path | None:
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    files = sorted(DATA_DIR.glob("*-*.json"), reverse=True)
    return files[0] if files else None


def get_latest_content() -> tuple[str, str]:
    latest = get_latest_file()
    if latest is None:
        return get_stub()

    content = latest.read_text()
    sha256 = latest.name.split("-")[1].replace(".json", "")
    return content, sha256


def get_all_versions() -> dict[str, str]:
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    files = sorted(DATA_DIR.glob("*-*.json"))
    return {f.name: f.read_text() for f in files}


security = HTTPBearer()


def verify_read_key(credentials: HTTPAuthorizationCredentials = Depends(security)) -> str:
    token = credentials.credentials
    if not any(
        hmac.compare_digest(token, key)
        for key in (READ_KEY, WRITE_KEY, DECENTRALA_ELECTION_KEY)
    ):
        raise HTTPException(status_code=401, detail="Invalid API key or insufficient permissions")
    return token


def verify_write_key(credentials: HTTPAuthorizationCredentials = Depends(security)) -> str:
    token = credentials.credentials
    if not any(
        hmac.compare_digest(token, key)
        for key in (WRITE_KEY, DECENTRALA_ELECTION_KEY)
    ):
        raise HTTPException(status_code=401, detail="Invalid API key or insufficient permissions")
    return token


def verify_full_read_key(credentials: HTTPAuthorizationCredentials = Depends(security)) -> str:
    token = credentials.credentials
    if not any(
        hmac.compare_digest(token, key)
        for key in (READ_KEY, WRITE_KEY)
    ):
        raise HTTPException(status_code=401, detail="Invalid API key or insufficient permissions")
    return token


app = FastAPI()


@app.get("/", include_in_schema=False)
def root() -> FileResponse:
    return FileResponse(Path(__file__).parent / "index.html")


@app.get("/accounts")
def get_accounts(token: str = Depends(verify_read_key)) -> PlainTextResponse:
    content, _ = get_latest_content()

    if hmac.compare_digest(token, DECENTRALA_ELECTION_KEY):
        data = json.loads(content)
        data["meta"] = {"unixtime": 0, "last_sha256": STUB_SHA256}
        data["accounts"] = [acc for acc in data["accounts"] if acc.get("decentrala")]
        content = json.dumps(data, separators=(",", ":"))

    return PlainTextResponse(content=content, media_type="application/json")


@app.post("/accounts")
def post_accounts(payload: AccountStore, token: str = Depends(verify_write_key)) -> PlainTextResponse:
    with global_lock:
        current_content, current_sha256 = get_latest_content()

        if hmac.compare_digest(token, DECENTRALA_ELECTION_KEY):
            current_data = json.loads(current_content)
            current_store = AccountStore.model_validate(current_data)

            decentrala_updates = {acc.username: acc.resident for acc in payload.accounts if acc.decentrala}

            updated_accounts = []
            for acc in current_store.accounts:
                if acc.decentrala and acc.username in decentrala_updates:
                    acc.resident = decentrala_updates[acc.username]
                updated_accounts.append(acc)

            payload = AccountStore(meta=payload.meta, accounts=updated_accounts)

        new_unixtime = int(time.time())
        new_content_for_hash = json.dumps(
            {"meta": {"unixtime": new_unixtime, "last_sha256": current_sha256}, "accounts": [acc.model_dump() for acc in payload.accounts]},
            separators=(",", ":"),
        )
        new_sha256 = compute_sha256(new_content_for_hash)

        DATA_DIR.mkdir(parents=True, exist_ok=True)
        new_file = DATA_DIR / f"{new_unixtime}-{new_sha256}.json"
        new_file.write_text(new_content_for_hash)

        return PlainTextResponse(content='{"ok":true}', media_type="application/json")


@app.get("/me")
def get_me(token: str = Depends(verify_read_key)) -> dict:
    if hmac.compare_digest(token, WRITE_KEY):
        return {"access": "read-write", "edit": True, "new": True}
    elif hmac.compare_digest(token, DECENTRALA_ELECTION_KEY):
        return {"access": "decentrala election (just residency edit)", "edit": True, "new": False}
    else:
        return {"access": "read-only", "edit": False, "new": False}


@app.get("/dump")
def get_dump(_: str = Depends(verify_full_read_key)) -> dict[str, str]:
    return get_all_versions()


@app.get("/export/vpn")
def export_vpn(_: str = Depends(verify_full_read_key)) -> PlainTextResponse:
    content, _ = get_latest_content()
    data = json.loads(content)
    store = AccountStore.model_validate(data)

    lines = []
    for account in store.accounts:
        if not account.vpn:
            continue

        identifier = account.telegram or account.username
        vpn_type = "resident-vpn" if account.resident else "vpn"

        for vpn in account.vpn:
            lines.append(f"""# wg-xecut-{vpn_type}-{identifier}.conf
[Peer]
PublicKey = {vpn.wg_public_key}
AllowedIPs = {vpn.ip}/32""")

    return PlainTextResponse(content="\n\n".join(lines), media_type="text/plain")


@app.get("/export/otp-map")
def export_otp_map(_: str = Depends(verify_full_read_key)) -> PlainTextResponse:
    content, _ = get_latest_content()
    data = json.loads(content)
    store = AccountStore.model_validate(data)

    lines = ["      uid_map:"]
    for account in store.accounts:
        if not account.otp_prefix or not account.telegram:
            continue

        lines.append(f"        '{account.otp_prefix}': {account.telegram}")

    return PlainTextResponse(content="\n".join(lines), media_type="text/plain")


if __name__ == "__main__":
    import uvicorn

    uvicorn.run(app, host="0.0.0.0", port=8000)
