import os
import secrets
from functools import lru_cache
from datetime import datetime, timezone

from dotenv import load_dotenv
from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, ConfigDict, Field
from supabase import Client, create_client
from upstash_redis import Redis

load_dotenv()


def _required_env(name: str) -> str:
    value = (os.getenv(name) or "").strip()
    if not value:
        raise HTTPException(
            status_code=503,
            detail=f"Service configuration is missing {name}",
        )
    return value


@lru_cache(maxsize=1)
def get_supabase() -> Client:
    url = _required_env("SUPABASE_URL").rstrip("/")
    if url.lower().endswith("/rest/v1"):
        url = url[: -len("/rest/v1")]
    return create_client(url, _required_env("SUPABASE_KEY"))


@lru_cache(maxsize=1)
def get_redis() -> Redis:
    return Redis(
        url=_required_env("UPSTASH_REDIS_REST_URL"),
        token=_required_env("UPSTASH_REDIS_REST_TOKEN"),
    )


app = FastAPI(title="RDM Cyber Operations Backend")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=False,
    allow_methods=["*"],
    allow_headers=["*"],
)


class AdminLoginRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    username: str
    password: str


class TelemetryPayload(BaseModel):
    model_config = ConfigDict(extra="forbid")

    device_id: str
    device_name: str
    os_info: str
    cpu_usage: float = Field(ge=0, le=100)
    ram_usage: float = Field(ge=0, le=100)
    disk_usage: float = Field(ge=0, le=100)
    session_token: str
    ip_address: str = "127.0.0.1"
    latitude: float | None = Field(default=None, ge=-90, le=90)
    longitude: float | None = Field(default=None, ge=-180, le=180)
    city: str | None = None
    country: str | None = None


@app.get("/")
def health():
    return {"status": "ok", "service": "rdm-backend"}


@app.post("/api/admin/login")
def admin_login(creds: AdminLoginRequest):
    admin_user = os.getenv("ADMIN_USERNAME", "admin")
    admin_pass = os.getenv("ADMIN_PASSWORD", "cyber@2026")
    username_matches = secrets.compare_digest(creds.username, admin_user)
    password_matches = secrets.compare_digest(creds.password, admin_pass)
    if username_matches and password_matches:
        return {"status": "success", "message": "Authenticated", "role": "admin"}
    raise HTTPException(status_code=401, detail="Invalid admin username or password")


@app.post("/api/telemetry")
def receive_telemetry(data: TelemetryPayload):
    try:
        is_blacklisted = get_redis().get(f"blacklist:{data.session_token}")
    except Exception as exc:
        raise HTTPException(status_code=503, detail="Session validation unavailable") from exc
    if is_blacklisted:
        return {"status": "force_logout", "message": "Session terminated by Admin"}

    supabase = get_supabase()
    try:
        supabase.table("devices").upsert(
            {
                "device_id": data.device_id,
                "device_name": data.device_name,
                "os_info": data.os_info,
                "cpu_usage": data.cpu_usage,
                "ram_usage": data.ram_usage,
                "disk_usage": data.disk_usage,
                "status": "online",
                "active_session_token": data.session_token,
                "last_seen": datetime.now(timezone.utc).isoformat(),
            }
        ).execute()

        supabase.table("location_logs").insert(
            {
                "device_id": data.device_id,
                "ip_address": data.ip_address,
                "latitude": data.latitude,
                "longitude": data.longitude,
                "city": data.city,
                "country": data.country,
            }
        ).execute()
    except Exception as exc:
        raise HTTPException(status_code=502, detail="Unable to persist telemetry") from exc

    return {"status": "ok"}


@app.get("/api/devices")
def get_devices():
    try:
        supabase = get_supabase()
        devices = (
            supabase.table("devices")
            .select("*")
            .order("last_seen", desc=True)
            .execute()
        )
        logs = (
            supabase.table("location_logs")
            .select("*")
            .order("id", desc=True)
            .limit(20)
            .execute()
        )
    except Exception as exc:
        raise HTTPException(status_code=502, detail="Unable to fetch device data") from exc
    return {"devices": devices.data, "recent_logs": logs.data}


@app.post("/api/devices/{device_id}/force-logout")
def force_logout_device(device_id: str):
    try:
        supabase = get_supabase()
        res = (
            supabase.table("devices")
            .select("active_session_token")
            .eq("device_id", device_id)
            .execute()
        )
    except Exception as exc:
        raise HTTPException(status_code=502, detail="Unable to look up device") from exc
    if not res.data:
        raise HTTPException(status_code=404, detail="Device not found")

    token = res.data[0].get("active_session_token")
    try:
        if token:
            get_redis().set(f"blacklist:{token}", "revoked", ex=86400)

        supabase.table("devices").update({"status": "force_logged_out"}).eq(
            "device_id", device_id
        ).execute()
    except Exception as exc:
        raise HTTPException(status_code=502, detail="Unable to force logout device") from exc
    return {
        "status": "success",
        "message": f"Device {device_id} has been force logged out.",
    }
