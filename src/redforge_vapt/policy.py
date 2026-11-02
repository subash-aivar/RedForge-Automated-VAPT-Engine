import ipaddress
import re
import socket
from datetime import UTC, datetime
from urllib.parse import urlparse

from pydantic import BaseModel, Field, field_validator, model_validator


class PolicyError(ValueError):
    pass


class Authorization(BaseModel):
    acknowledged: bool = False
    approved_profiles: list[str] = Field(default_factory=list)
    scanner_permissions: dict[str, bool] = Field(default_factory=dict)


class EngagementConfig(BaseModel):
    id: str = Field(pattern=r"^[A-Za-z0-9][A-Za-z0-9_-]{2,99}$")
    client: str = Field(min_length=2)
    operator: str = Field(min_length=2)
    targets: list[str] = Field(min_length=1)
    exclusions: list[str] = Field(default_factory=list)
    ports: list[int] = Field(default_factory=lambda: [80, 443])
    protocols: list[str] = Field(default_factory=lambda: ["http", "https"])
    window_start: datetime
    window_end: datetime
    max_request_rate: int = Field(default=2, ge=1, le=100)
    max_requests: int = Field(default=100, ge=1, le=1000)
    max_concurrency: int = Field(default=1, ge=1, le=10)
    request_timeout: int = Field(default=10, ge=1, le=120)
    authorization: Authorization = Field(default_factory=Authorization)
    scanners: list[str] = Field(default_factory=lambda: ["nmap", "nuclei", "semgrep", "trivy"])
    source_path: str | None = None

    @field_validator("ports")
    @classmethod
    def valid_ports(cls, value):
        if not value or any(p < 1 or p > 65535 for p in value):
            raise ValueError("ports must be between 1 and 65535")
        return sorted(set(value))

    @field_validator("protocols")
    @classmethod
    def valid_protocols(cls, value):
        if not value or any(item not in ("tcp", "http", "https") for item in value):
            raise ValueError("protocols must be TCP, HTTP, or HTTPS")
        return list(dict.fromkeys(value))

    @field_validator("targets", "exclusions")
    @classmethod
    def valid_targets(cls, values):
        for value in values:
            parse_target(value)
        return values

    @model_validator(mode="after")
    def valid_window(self):
        if self.window_start >= self.window_end:
            raise ValueError("window_start must precede window_end")
        if not self.window_start.tzinfo or not self.window_end.tzinfo:
            raise ValueError("testing window must include timezone")
        if len(self.ports) > self.max_requests:
            raise ValueError("port count exceeds max_requests budget")
        return self


def parse_target(raw: str):
    if not raw or len(raw) > 253 or any(c.isspace() for c in raw):
        raise PolicyError("invalid target")
    if "://" in raw:
        parsed = urlparse(raw)
        if parsed.scheme not in ("http", "https") or not parsed.hostname:
            raise PolicyError("only HTTP(S) targets are accepted")
        if parsed.username or parsed.password or parsed.fragment:
            raise PolicyError("target URL contains credentials or fragment")
        try:
            host = parsed.hostname.lower().rstrip(".")
            port = parsed.port
        except ValueError as exc:
            raise PolicyError("invalid target port") from exc
        if parsed.path not in ("", "/") or parsed.query:
            raise PolicyError("scope targets must be origins, without paths or queries")
        return host, port, parsed.scheme
    try:
        if "/" in raw:
            return str(ipaddress.ip_network(raw, strict=False)), None, None
        return str(ipaddress.ip_address(raw)), None, None
    except ValueError:
        pass
    host = raw.lower().rstrip(".")
    if not re.fullmatch(r"(?=.{1,253}$)[a-z0-9](?:[a-z0-9.-]*[a-z0-9])?", host):
        raise PolicyError("invalid domain")
    if ".." in host or any(len(label) > 63 or label.startswith("-") or label.endswith("-") for label in host.split(".")):
        raise PolicyError("invalid domain")
    return host, None, None


def _host_match(host, scope):
    allowed, _, _ = parse_target(scope)
    try:
        return ipaddress.ip_address(host) in ipaddress.ip_network(allowed, strict=False)
    except ValueError:
        return host == allowed


def _blocked_address(address):
    ip = ipaddress.ip_address(address)
    return not ip.is_global or ip in ipaddress.ip_network("169.254.169.254/32")


def check_target(config: EngagementConfig, target: str, *, resolve=True, allow_loopback=False):
    host, port, scheme = parse_target(target)
    if "/" in host:
        raise PolicyError("a single host or URL is required for execution")
    if any(_host_match(host, excluded) for excluded in config.exclusions):
        raise PolicyError("target is explicitly excluded")
    if not any(_host_match(host, allowed) for allowed in config.targets):
        raise PolicyError("target is outside authorized scope")
    if port and port not in config.ports:
        raise PolicyError("port is outside authorized scope")
    if scheme and scheme not in config.protocols:
        raise PolicyError("protocol is outside authorized scope")
    if resolve:
        try:
            addresses = {item[4][0] for item in socket.getaddrinfo(host, None)}
        except socket.gaierror as exc:
            raise PolicyError("DNS resolution failed") from exc
        if not addresses or any(_blocked_address(ip) and not (allow_loopback and ipaddress.ip_address(ip).is_loopback) for ip in addresses):
            raise PolicyError("DNS resolved to a blocked internal, reserved, or metadata address")
    return host


def check_asset(config: EngagementConfig, asset: str):
    if "://" in asset:
        parsed = urlparse(asset)
        if parsed.scheme not in ("http", "https") or not parsed.hostname or parsed.username or parsed.password:
            raise PolicyError("invalid finding URL")
        origin = f"{parsed.scheme}://{parsed.netloc}"
        return check_target(config, origin, resolve=False)
    return check_target(config, asset, resolve=False)


def check_redirect(config: EngagementConfig, destination: str):
    return check_target(config, destination)


def authorize(config: EngagementConfig, profile: str, *, fixture=False):
    if profile not in ("passive", "safe-active", "manual"):
        raise PolicyError("unknown profile")
    if fixture:
        return
    if not config.authorization.acknowledged or profile not in config.authorization.approved_profiles:
        raise PolicyError("engagement authorization and profile approval are required")
    current = datetime.now(UTC)
    if not config.window_start <= current <= config.window_end:
        raise PolicyError("outside authorized testing window")
    if profile == "manual":
        raise PolicyError("manual modules require separate approval and are not implemented")
