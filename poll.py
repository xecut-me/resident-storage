#!/usr/bin/env python3
import asyncio
import hashlib
import json
from pathlib import Path
from datetime import datetime
import aiohttp

CONFIG_PATH = Path("./config.json")
DATA_DIR = Path("./resident-data")


def load_config():
    with open(CONFIG_PATH) as f:
        return json.load(f)


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def read_last_json() -> tuple[bytes | None, dict | None]:
    last_path = DATA_DIR / "last.json"
    if not last_path.exists():
        return None, None
    content = last_path.read_bytes()
    return content, json.loads(content)


def write_update(content: bytes, parsed: dict):
    DATA_DIR.mkdir(exist_ok=True)
    ts = parsed["meta"]["unixtime"]
    content_hash = sha256(content)
    (DATA_DIR / f"{ts}-{content_hash}.json").write_bytes(content)
    (DATA_DIR / "last.json").write_bytes(content)


async def send_telegram(config: dict, message: str):
    api_key = config.get("telegram_api_key")
    notify_list = config.get("telegram_notify", [])
    if not api_key or not notify_list:
        return

    async with aiohttp.ClientSession() as session:
        for target in notify_list:
            payload = {"chat_id": target["chat_id"], "text": message}
            if topic_id := target.get("topic_id"):
                payload["message_thread_id"] = topic_id
            try:
                await session.post(
                    f"https://api.telegram.org/bot{api_key}/sendMessage",
                    json=payload,
                    timeout=aiohttp.ClientTimeout(total=30)
                )
            except Exception as e:
                print(f"Telegram send failed: {e}")


async def run_update_command(config: dict) -> bool:
    cmd = config.get("on_update_command")
    if not cmd:
        return True
    try:
        proc = await asyncio.create_subprocess_shell(
            cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE
        )
        await asyncio.wait_for(proc.wait(), timeout=300)
        return proc.returncode == 0
    except asyncio.TimeoutError:
        print("on_update_command timed out")
        return False
    except Exception as e:
        print(f"on_update_command failed: {e}")
        return False


async def fetch_current(session: aiohttp.ClientSession, config: dict) -> bytes:
    headers = {"Authorization": f"Bearer {config['resident_storage_api_key']}"}
    url = config["resident_storage_url"].rstrip("/") + "/accounts"
    async with session.get(url, headers=headers) as resp:
        resp.raise_for_status()
        return await resp.read()


async def fetch_dump(session: aiohttp.ClientSession, config: dict) -> list[dict]:
    """Fetch all versions from server and return as list of {meta, hash, data} dicts."""
    headers = {"Authorization": f"Bearer {config['resident_storage_api_key']}"}
    url = config["resident_storage_url"].rstrip("/") + "/dump"
    async with session.get(url, headers=headers) as resp:
        resp.raise_for_status()
        raw = await resp.json()  # dict[filename, json_string]

    result = []
    for filename, content_str in raw.items():
        # filename format: "{unixtime}-{hash}.json"
        parts = filename.replace(".json", "").split("-", 1)
        if len(parts) == 2:
            data = json.loads(content_str)
            result.append({
                "meta": data.get("meta", {}),
                "hash": parts[1],
                "data": data
            })
    return sorted(result, key=lambda x: x["meta"].get("unixtime", 0))


def get_local_chain() -> list[tuple[int, str]]:
    """Returns sorted list of (unixtime, hash) from local files."""
    chain = []
    for f in DATA_DIR.glob("*-*.json"):
        if f.name == "last.json":
            continue
        parts = f.stem.split("-", 1)
        if len(parts) == 2:
            chain.append((int(parts[0]), parts[1]))
    return sorted(chain)


def verify_chain(server_chain: list[dict], local_chain: list[tuple[int, str]]) -> bool:
    """Check that server chain starts with the same sequence as local chain."""
    server_pairs = [(item["meta"]["unixtime"], item["hash"]) for item in server_chain]
    for i, local_item in enumerate(local_chain):
        if i >= len(server_pairs):
            return False
        if server_pairs[i] != local_item:
            return False
    return True


def sync_from_dump(server_chain: list[dict]):
    """Write new files from server dump."""
    local_set = {f.name for f in DATA_DIR.glob("*-*.json")}
    for item in server_chain:
        ts = item["meta"]["unixtime"]
        h = item["hash"]
        fname = f"{ts}-{h}.json"
        if fname not in local_set:
            content = json.dumps(item["data"], separators=(",", ":")).encode()
            (DATA_DIR / fname).write_bytes(content)

    if server_chain:
        last_item = server_chain[-1]
        content = json.dumps(last_item["data"], separators=(",", ":")).encode()
        (DATA_DIR / "last.json").write_bytes(content)


async def poll_task(config: dict):
    last_content, last_parsed = read_last_json()
    last_hash = sha256(last_content) if last_content else None

    async with aiohttp.ClientSession(timeout=aiohttp.ClientTimeout(total=240)) as session:
        new_content = await fetch_current(session, config)
        new_hash = sha256(new_content)

        if new_hash == last_hash:
            return

        new_parsed = json.loads(new_content)
        meta_last_hash = new_parsed.get("meta", {}).get("last_sha256")
        valid_transition = (meta_last_hash == last_hash) and (last_hash is not None)

        if not valid_transition:
            print("Invalid transition detected, checking full chain...")
            dump = await fetch_dump(session, config)
            local_chain = get_local_chain()

            if not verify_chain(dump, local_chain):
                print("Chain verification failed")
                if config.get("strict_validation", True):
                    await send_telegram(config, "❌ Chain validation failed, update rejected")
                    return

            print("Chain verified, syncing from dump")
            sync_from_dump(dump)
            valid_transition = True

        if valid_transition or not config.get("strict_validation", True):
            write_update(new_content, new_parsed)
            success = await run_update_command(config)

            status = "✅" if success else "⚠️ (command failed)"
            await send_telegram(
                config,
                f"{status} Updated to version {new_parsed['meta']['unixtime']}"
            )


async def main():
    print(f"Starting poll.py at {datetime.now()}")
    DATA_DIR.mkdir(exist_ok=True)

    while True:
        config = load_config()
        try:
            await asyncio.wait_for(poll_task(config), timeout=300)
        except Exception as e:
            print(f"Poll task failed: {e}")
        await asyncio.sleep(600)


if __name__ == "__main__":
    asyncio.run(main())
