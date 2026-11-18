"""Shared test helpers."""
from datetime import datetime, timezone

from app.schemas import EventIn


def ev(**kw) -> EventIn:
    base = dict(
        timestamp=datetime.now(timezone.utc),
        source="linux",
        event_type="login",
        message="",
    )
    base.update(kw)
    return EventIn(**base)


def failed_login(ip: str, user: str = "root") -> EventIn:
    return ev(event_type="login", outcome="failure", source_ip=ip, username=user,
              message=f"Failed password for {user} from {ip}")


def ok_login(ip: str, user: str = "root") -> EventIn:
    return ev(event_type="login", outcome="success", source_ip=ip, username=user,
              message=f"Accepted password for {user} from {ip}")
