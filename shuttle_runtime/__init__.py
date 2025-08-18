import asyncio
import os
import sys

from shuttle_common import InfraManifest

VERSION = "0.1.0-beta"
VERSION_STRING = f"shuttle_runtime (Python) {VERSION}"


# takes in the async def instead of a coroutine so that we can access
# the __shuttle_infra__ that the decorator attaches to it
def main(user_fnc):
    # import warnings
    # # ignore warning since we might not await the coroutine
    # warnings.filterwarnings("ignore", category=RuntimeWarning, message=".*coroutine '.*' was never awaited.*")

    for arg in sys.argv:
        if arg == "--version":
            print(VERSION_STRING)
            return

    if os.environ.get("SHUTTLE_RUNTIME") is None:
        print("Use 'shuttle run' to run a function wrapped in shuttle_runtime.main()")
        return

    emit_infra_manifest = os.environ.get("SHUTTLE_GET_INFRA_MANIFEST")
    if emit_infra_manifest == "true":
        if hasattr(user_fnc, "__shuttle_infra__") and isinstance(
            user_fnc.__shuttle_infra__, InfraManifest
        ):
            print(user_fnc.__shuttle_infra__.model_dump_json(), end="")
    else:
        print(f"{VERSION_STRING} starting")
        asyncio.run(user_fnc())
