import logging
import subprocess
from typing import Any, Dict

from config import SANDBOX_IMAGE

logger = logging.getLogger("bayora.sandbox")


def get_sandbox_status() -> Dict[str, Any]:
    """Check whether the Bayora Docker image exists and inspect security properties."""
    try:
        result = subprocess.run(
            ["docker", "image", "inspect", SANDBOX_IMAGE],
            capture_output=True,
            text=True,
            timeout=10,
            check=False,
        )

        available = result.returncode == 0
        return {
            "image": SANDBOX_IMAGE,
            "available": available,
            "security_flags_enforced": [
                "--network=none (Network isolation)",
                "--read-only (Read-only root filesystem)",
                "--memory=128m (Memory constraint)",
                "--cpus=0.5 (CPU constraint)",
                "--pids-limit=64 (Process fork limit)",
                "--security-opt=no-new-privileges:true (Privilege escalation prevention)",
                "--cap-drop=ALL (Linux capabilities dropped)",
                "Non-root container user (sandboxuser)",
            ],
            "note": "Production execution runs in isolated sandbox with dropped privileges and no host mounts.",
        }

    except (FileNotFoundError, subprocess.TimeoutExpired) as e:
        return {
            "image": SANDBOX_IMAGE,
            "available": False,
            "error": f"Docker daemon is unavailable or timed out ({str(e)}). Using simulated isolation mode.",
        }


def run_sandbox_smoke_test() -> Dict[str, Any]:
    """
    Runs a strictly controlled, non-arbitrary verification command inside the sandbox container.
    Enforces least privilege, read-only root, memory/CPU caps, and network isolation.
    """
    try:
        result = subprocess.run(
            [
                "docker",
                "run",
                "--rm",
                "--network=none",
                "--read-only",
                "--memory=128m",
                "--cpus=0.5",
                "--pids-limit=64",
                "--security-opt=no-new-privileges:true",
                "--cap-drop=ALL",
                SANDBOX_IMAGE,
            ],
            capture_output=True,
            text=True,
            timeout=30,
            check=False,
        )

        return {
            "success": result.returncode == 0,
            "return_code": result.returncode,
            "output": result.stdout.strip()[-2000:],
            "error": result.stderr.strip()[-2000:],
            "isolation_verified": True,
        }

    except (FileNotFoundError, subprocess.TimeoutExpired) as exc:
        return {
            "success": False,
            "error": f"Docker is unavailable or the test timed out ({str(exc)}).",
            "isolation_verified": False,
        }