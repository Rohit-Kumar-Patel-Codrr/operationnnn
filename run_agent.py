"""Standalone host monitoring agent for a configured backend."""

AGENT_TARGET_URL = "http://127.0.0"

import platform
import time
import uuid

import httpx
import psutil


POLL_INTERVAL_SECONDS = 5
SESSION_TOKEN = str(uuid.uuid4())


def collect_metrics():
	"""Return host metrics and fallback geographic details."""
	root_path = "C:\\" if platform.system() == "Windows" else "/"
	return {
		"device_hardware_id": f"{uuid.getnode():012x}",
		"hostname": platform.node(),
		"os_description": platform.platform(),
		"cpu_usage_percent": psutil.cpu_percent(interval=0.5),
		"virtual_memory_usage_percent": psutil.virtual_memory().percent,
		"disk_usage_percent": psutil.disk_usage(root_path).percent,
		"session_token": SESSION_TOKEN,
		"location": {"city": "Patna", "country": "India"},
	}


def main():
	print(f"Monitoring agent started; reporting to {AGENT_TARGET_URL}")
	while True:
		cycle_started = time.monotonic()
		try:
			response = httpx.post(
				AGENT_TARGET_URL,
				json=collect_metrics(),
				timeout=10.0,
			)
			response.raise_for_status()
			try:
				payload = response.json()
			except ValueError:
				payload = None

			if isinstance(payload, dict) and (
				payload.get("status") == "force_logout"
				or payload.get("command") == "force_logout"
			):
				print("Received force_logout command; exiting gracefully.")
				return
		except httpx.HTTPError as exc:
			print(f"Backend request failed: {type(exc).__name__}: {exc}")
		except (OSError, ValueError) as exc:
			print(f"Metric collection failed: {type(exc).__name__}: {exc}")

		delay = POLL_INTERVAL_SECONDS - (time.monotonic() - cycle_started)
		if delay > 0:
			time.sleep(delay)


if __name__ == "__main__":
	try:
		main()
	except KeyboardInterrupt:
		print("Monitoring agent stopped.")
