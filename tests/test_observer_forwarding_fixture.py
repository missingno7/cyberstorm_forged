"""Run the harmless x86 observer forwarding fixture with a nine-second cap."""
from __future__ import annotations

import argparse
import os
import subprocess
import tempfile
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--build-dir", type=Path, default=ROOT / "carrier" / "build")
    args = parser.parse_args()
    build_dir = args.build_dir.resolve()
    fixture = build_dir / "cs_observer_forwarding_fixture.exe"
    observer = build_dir / "cs_observer.dll"
    provider = build_dir / "cs_observer_fixture_provider.dll"
    missing = [path for path in (fixture, observer, provider) if not path.is_file()]
    if missing:
        raise SystemExit("missing fixture artifacts: " + ", ".join(str(path) for path in missing))

    with tempfile.TemporaryDirectory(prefix="cs_observer_forwarding_") as temporary:
        temporary_path = Path(temporary)
        log = temporary_path / "observer.log"
        result = temporary_path / "result.txt"
        environment = os.environ.copy()
        environment["CS_OBSERVER_LOG"] = str(log)
        completed = subprocess.run(
            [str(fixture), str(observer), str(provider), str(result)],
            cwd=build_dir,
            env=environment,
            text=True,
            capture_output=True,
            timeout=9,
            check=False,
        )
        if completed.returncode != 0:
            raise SystemExit(
                f"fixture exit={completed.returncode}\nstdout={completed.stdout}\nstderr={completed.stderr}\n"
                f"result={result.read_text() if result.exists() else '<missing>'}\n"
                f"log={log.read_text() if log.exists() else '<missing>'}"
            )
        contents = result.read_text(encoding="utf-8")
        observed = log.read_text(encoding="utf-8")
        required_result = ("observer_ready=true", "forwarding_equivalent=true", "ordinal_value=9320")
        required_log = ("observer=ready pid=", "LoadLibraryA path=", "name=cs_fixture_named", "name=#7")
        if any(item not in contents for item in required_result) or any(item not in observed for item in required_log):
            raise SystemExit(f"unexpected fixture evidence\nresult={contents}\nlog={observed}")
        print("observer_forwarding_fixture=PASS")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
