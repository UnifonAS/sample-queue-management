#!/usr/bin/env python3
"""Sample CLI for managing Unifon switchboard queues.

Supports:
- Listing queues
- Listing members of a queue
- Toggling readiness for an agent in one or all queues

Tokens are cached in token.json to avoid exhausting token limits.
"""

from __future__ import annotations

import argparse
import json
import os
import sys
import time
from typing import Any, Dict, Iterable, List, Optional, Tuple

import requests

DEFAULT_HOST = "https://bnapi.test.unifonip.no"
TOKEN_PATH = "token.json"


class TokenError(RuntimeError):
    """Raised when a token cannot be retrieved or used."""


def env_default(name: str, fallback: Optional[str] = None) -> Optional[str]:
    """Fetch default from environment if present."""
    return os.environ.get(name, fallback)


def load_cached_token(path: str) -> Optional[Tuple[str, float]]:
    """Return (access_token, expires_at) if still valid."""
    if not os.path.exists(path):
        return None
    try:
        with open(path, "r", encoding="ascii") as fp:
            data = json.load(fp)
    except (OSError, json.JSONDecodeError):
        return None
    token = data.get("access_token")
    expires_at = data.get("expires_at")
    if not token or not isinstance(expires_at, (int, float)):
        return None
    # Refresh if within 60 seconds of expiry.
    if expires_at - time.time() <= 60:
        return None
    return token, float(expires_at)


def save_token(path: str, token: str, expires_in: Optional[int]) -> None:
    expires_at = time.time() + (expires_in or 0)
    payload = {"access_token": token, "expires_at": expires_at}
    with open(path, "w", encoding="ascii") as fp:
        json.dump(payload, fp)


def request_token(host: str, client_id: str, client_secret: str, grant_type: str) -> Tuple[str, Optional[int]]:
    url = f"{host}/bnapi/v1/session/token"
    resp = requests.post(
        url,
        json={"client_id": client_id, "client_secret": client_secret, "grant_type": grant_type},
        timeout=10,
    )
    if resp.status_code != 200:
        raise TokenError(f"Token request failed: {resp.status_code} {resp.text}")
    data = resp.json()
    token = data.get("access_token")
    if not token:
        raise TokenError("Token response missing access_token")
    expires_in = data.get("expires_in")
    return token, expires_in


def get_token(args: argparse.Namespace) -> str:
    cached = load_cached_token(TOKEN_PATH)
    if cached:
        return cached[0]
    if not args.client_id or not args.client_secret:
        raise TokenError("Client credentials are required. Provide via flags or env.")
    token, expires_in = request_token(args.host, args.client_id, args.client_secret, args.grant_type)
    save_token(TOKEN_PATH, token, expires_in if isinstance(expires_in, int) else None)
    return token


def build_session(token: str) -> requests.Session:
    session = requests.Session()
    session.headers.update({"Authorization": f"Bearer {token}"})
    return session


def fetch_queue_summary(session: requests.Session, host: str) -> Dict[str, Any]:
    url = f"{host}/bnapi/v1/queue/summary"
    resp = session.get(url, timeout=10)
    if resp.status_code != 200:
        raise RuntimeError(f"Failed to fetch queue summary: {resp.status_code} {resp.text}")
    return resp.json()


def print_queues(entries: Iterable[Dict[str, Any]]) -> None:
    for entry in entries:
        queue_id = entry.get("queue_id")
        desc = entry.get("description", "")
        is_member = entry.get("is_member", False)
        favorite = entry.get("favorite", False)
        print(f"[{queue_id}] {desc} | member={is_member} favorite={favorite}")


def iter_members(queue: Dict[str, Any]) -> Iterable[Dict[str, Any]]:
    members = queue.get("members") or []
    for member in members:
        yield member


def member_devices(member: Dict[str, Any]) -> Dict[str, Dict[str, Any]]:
    return {
        "fixed": member.get("fixed") or {},
        "mobile": member.get("mobile") or {},
        "teams": member.get("teams") or {},
    }


def print_members(queue: Dict[str, Any]) -> None:
    queue_id = queue.get("queue_id")
    print(f"Members for queue {queue_id} ({queue.get('description','')}):")
    for member in iter_members(queue):
        name = f"{member.get('firstname','')} {member.get('lastname','')}".strip()
        devices = member_devices(member)
        fixed_num = devices["fixed"].get("agent") or "n/a"
        mobile_num = devices["mobile"].get("agent") or "n/a"
        ready_states = {
            "fixed": devices["fixed"].get("ready"),
            "mobile": devices["mobile"].get("ready"),
            "teams": devices["teams"].get("ready"),
        }
        ready_desc = ", ".join(f"{k}={'ready' if v else 'not ready'}" for k, v in ready_states.items() if v is not None)
        print(f"- {name} | fixed: {fixed_num} mobile: {mobile_num} | {ready_desc or 'ready state unknown'}")


def find_queue_by_id(entries: List[Dict[str, Any]], queue_id: int) -> Optional[Dict[str, Any]]:
    for entry in entries:
        if entry.get("queue_id") == queue_id:
            return entry
    return None


def set_ready(session: requests.Session, host: str, agent: str, queue_id: int, ready: bool) -> Dict[str, Any]:
    url = f"{host}/bnapi/v1/queue/members/ready"
    body = {"agent": agent, "queue_id": queue_id, "ready": ready}
    resp = session.post(url, json=body, timeout=10)
    if resp.status_code != 200:
        raise RuntimeError(f"Failed to set readiness: {resp.status_code} {resp.text}")
    return resp.json()


def member_in_queue(member: Dict[str, Any], agent: str) -> bool:
    for device in member_devices(member).values():
        if device.get("agent") == agent:
            return True
    return False


def iter_member_queues(entries: List[Dict[str, Any]], agent: str) -> Iterable[int]:
    for entry in entries:
        for member in iter_members(entry):
            if member_in_queue(member, agent):
                yield entry.get("queue_id")
                break


def parse_args(argv: Optional[List[str]] = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Manage Unifon switchboard queues")
    parser.add_argument("--host", default=env_default("UNIFON_HOST", DEFAULT_HOST), help="API host base URL")
    parser.add_argument("--client-id", default=env_default("UNIFON_CLIENT_ID"))
    parser.add_argument("--client-secret", default=env_default("UNIFON_CLIENT_SECRET"))
    parser.add_argument("--grant-type", default=env_default("UNIFON_GRANT_TYPE", "client_credentials"))

    sub = parser.add_subparsers(dest="command", required=True)

    sub.add_parser("list-queues", help="List queues available to the token")

    list_members = sub.add_parser("list-members", help="List members of a queue")
    list_members.add_argument("--queue-id", type=int, required=True)

    set_ready_cmd = sub.add_parser("set-ready", help="Toggle readiness for an agent in a queue")
    set_ready_cmd.add_argument("--agent", required=True, help="Agent identifier (mobile/fixed/teams)")
    set_ready_cmd.add_argument("--queue-id", type=int, required=True)
    set_ready_cmd.add_argument("--ready", choices=["true", "false"], required=True, help="true to set ready")

    set_ready_all = sub.add_parser("set-ready-all", help="Toggle readiness for an agent across all queues")
    set_ready_all.add_argument("--agent", required=True)
    set_ready_all.add_argument("--ready", choices=["true", "false"], required=True)

    return parser.parse_args(argv)


def main(argv: Optional[List[str]] = None) -> int:
    args = parse_args(argv)
    try:
        token = get_token(args)
    except TokenError as exc:
        print(f"Authentication failed: {exc}", file=sys.stderr)
        return 1

    session = build_session(token)

    try:
        if args.command == "list-queues":
            data = fetch_queue_summary(session, args.host)
            print_queues(data.get("entries", []))

        elif args.command == "list-members":
            data = fetch_queue_summary(session, args.host)
            queue = find_queue_by_id(data.get("entries", []), args.queue_id)
            if not queue:
                print(f"Queue {args.queue_id} not found.")
                return 1
            print_members(queue)

        elif args.command == "set-ready":
            ready = args.ready.lower() == "true"
            resp = set_ready(session, args.host, args.agent, args.queue_id, ready)
            print(json.dumps(resp, indent=2))

        elif args.command == "set-ready-all":
            ready = args.ready.lower() == "true"
            data = fetch_queue_summary(session, args.host)
            queue_ids = list(iter_member_queues(data.get("entries", []), args.agent))
            if not queue_ids:
                print(f"No queues found for agent {args.agent}.")
                return 1
            results = {}
            for qid in queue_ids:
                try:
                    results[qid] = set_ready(session, args.host, args.agent, qid, ready)
                except Exception as exc:
                    results[qid] = {"error": str(exc)}
            print(json.dumps(results, indent=2))
    except Exception as exc:  # pylint: disable=broad-except
        print(f"Error: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
