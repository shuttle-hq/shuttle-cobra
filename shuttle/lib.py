import logging
import subprocess
import tomllib
from pathlib import Path

from shuttle_common import InfraManifest
from shuttle_infra import build

logger = logging.getLogger(__name__)


class InfraDiscoveryError(Exception):
    """Custom exception for errors during infrastructure discovery."""

    pass


def discover_project_and_infra(path_str: str):
    path = Path(path_str).resolve()

    # Find a venv in project folder or closest parent
    for parent in [path, *path.parents]:
        venv_dirs = [".venv", "venv"]
        for v in venv_dirs:
            if (venv := parent.joinpath(v)).exists():
                break
        else:
            continue
        break
    else:
        raise FileNotFoundError("No venv found in project or parents")
    logging.debug("Found venv in", parent)

    # If we're running the user-project outside of shuttle-cobra,
    # this should resolve to the Dockerfile inside of shuttle-cobra
    if not (_ := Path(build.__file__).parent.joinpath("Dockerfile")).exists():
        raise FileNotFoundError("No Dockerfile found in project root")
    logging.debug("Found Dockerfile in", Path(build.__file__).parent)

    if (entrypoint := path.joinpath("main.py")).exists():
        program = [
            "/usr/bin/env",
            "bash",
            "-c",
            f"source {venv}/bin/activate; exec python3 {entrypoint}",
        ]
    elif path.joinpath("__main__.py").exists():
        program = [
            "/usr/bin/env",
            "bash",
            "-c",
            f"source {venv}/bin/activate; exec python3 -m {path.relative_to(Path.cwd())}",
        ]
    else:
        raise FileNotFoundError(f"didn't find a main python file in {path}")

    if (pyproject := parent.joinpath("pyproject.toml")).exists():
        with open(pyproject, "rb") as f:
            data = tomllib.load(f)

        project_name = data.get("project", {}).get("name")

    proc = subprocess.run(
        program,
        env={"SHUTTLE_RUNTIME": "true", "SHUTTLE_GET_INFRA_MANIFEST": "true"},
        capture_output=True,
    )
    try:
        proc.check_returncode()
        manifest = InfraManifest.model_validate_json(proc.stdout)
    except Exception as e:
        stdout_str = proc.stdout.decode("utf-8", errors="ignore").strip()
        stderr_str = proc.stderr.decode("utf-8", errors="ignore").strip()
        error_details = f"Original error: {e}"
        if stdout_str:
            error_details += f"\nProcess stdout:\n{stdout_str}"
        if stderr_str:
            error_details += f"\nProcess stderr:\n{stderr_str}"
        raise InfraDiscoveryError(
            f"Failed to extract infrastructure definitions from project. {error_details}"
        ) from e

    logging.debug("infra manifest output:", manifest)

    return parent, manifest, project_name
