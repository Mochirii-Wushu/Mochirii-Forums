#!/usr/bin/env python3
"""Hostile executable fixture for disposable launcher residue reconciliation."""

from __future__ import annotations

import json
import os
import re
import shutil
import signal
import stat
import subprocess
import sys
import tempfile
import time
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
GUARD = ROOT / "scripts" / "disposable-launcher-guard.py"
BASE_IMAGE = "discourse/base@sha256:3b1846055ca723d13ef7dc3466da61627f32e8b212283561a6c617d759fcec48"
PREEXISTING_IMAGE = "sha256:" + "f" * 64
CREATED_IMAGE = "sha256:" + "a" * 64
CREATED_CONTAINER = "b" * 64
FORBIDDEN_SENTINEL = "sentinel-launcher-secret-never-emit-7d3f1a"


ADAPTER = r'''#!/usr/bin/env python3
import json
import os
import pathlib
import shlex
import subprocess
import sys
import time

root = pathlib.Path(os.environ["MOCHIRII_DISPOSABLE_LAUNCHER_FIXTURE_ROOT"])
state_path = root / "state.json"
state = json.loads(state_path.read_text())

def save():
    temporary = state_path.with_suffix(".partial")
    temporary.write_text(json.dumps(state, sort_keys=True) + "\n")
    temporary.replace(state_path)

def values_after(flag):
    try:
        return sys.argv[sys.argv.index(flag) + 1]
    except (ValueError, IndexError):
        return ""

PLAN_KINDS = """
file file file file file
replace replace replace replace replace replace replace replace replace replace replace replace
exec exec file file file exec
file file file replace replace exec replace replace replace replace replace exec exec exec exec
exec exec exec file file file file file file replace exec replace exec exec exec replace replace replace
exec exec exec exec exec exec exec exec exec exec exec exec
replace
file file file file file file file file file file file file file file file file file file file file file file
exec
""".split()
PLAN_HOOKS = {
    23: "postgres", 35: "redis", 49: "code", 58: "web_config", 59: "web",
    60: "yarn", 61: "bundle_exec", 62: "plugin_compatibility", 65: "db_migrate",
    66: "clear_stuck_web_upgrades", 67: "assets_precompile_build", 68: "assets_precompile",
}
PLAN_EXEC_COUNTS = {
    18: 1, 19: 1, 23: 3, 29: 1, 35: 1, 36: 1, 37: 1, 38: 1,
    39: 1, 40: 3, 41: 1, 49: 17, 51: 1, 52: 1, 53: 16,
    57: 2, 58: 1, 59: 1, 60: 1, 61: 4, 62: 1, 63: 1,
    64: 1, 65: 1, 66: 1, 67: 1, 68: 1, 92: 9,
}

def trace_failure(scenario):
    return {
        "trace-terminal-code": (49, 7, 42),
        "trace-terminal-final-first": (92, 1, 37),
        "trace-terminal-final-last": (92, 9, 37),
        "trace-file-failure": (84, 0, 1),
        "trace-plan-88": (49, 7, 42),
        "trace-marker-malformed": (49, 7, 42),
        "trace-marker-oversize": (49, 7, 42),
        "trace-marker-symlink": (49, 7, 42),
        "trace-marker-mode": (49, 7, 42),
        "trace-marker-nlink": (49, 7, 42),
        "trace-marker-stage": (49, 7, 42),
        "trace-marker-ordinal": (49, 7, 42),
        "trace-marker-subcount": (49, 7, 42),
        "trace-marker-exit": (49, 7, 42),
        "trace-tolerated-62": (62, 1, 23),
        "trace-tolerated-66": (66, 1, 23),
        "trace-tolerated-then-terminal": (62, 1, 23),
    }.get(scenario)

def trace_plan(scenario):
    failure = trace_failure(scenario)
    terminal_after_tolerated = scenario == "trace-tolerated-then-terminal"
    run = []
    for ordinal, kind in enumerate(PLAN_KINDS, 1):
        hook = PLAN_HOOKS.get(ordinal)
        if kind == "exec":
            count = PLAN_EXEC_COUNTS[ordinal]
            commands = ["true"] * count
            if ordinal == 18:
                commands[0] = (
                    "test -z \"${RUBYOPT+x}\" && "
                    "test -z \"${MOCHIRII_PUPS_TRACE_MODE+x}\" && "
                    "test -z \"${MOCHIRII_PUPS_TRACE_STATE+x}\""
                )
            if failure is not None and failure[0] == ordinal and failure[1] > 0:
                commands[failure[1] - 1] = (
                    "printf '%s\\n' 'sentinel-launcher-secret-never-emit-7d3f1a' && "
                    "printf '%s\\n' 'https://secret.invalid/private docker run secret-value' >&2 && "
                    f"exit {failure[2]}"
                )
            if terminal_after_tolerated and ordinal == 65:
                commands[0] = "exit 41"
            value = {"cmd": commands}
            if hook is not None:
                value["hook"] = hook
            if ordinal in {62, 66}:
                value["raise_on_fail"] = False
            if ordinal in {19, 37, 63}:
                value["background"] = True
            run.append({"exec": value})
        elif kind == "file":
            path = root / "pups-files" / str(ordinal)
            if failure is not None and failure[0] == ordinal and failure[1] == 0:
                path = pathlib.Path("/proc/mochirii-pups-trace-forbidden")
            run.append({"file": {"path": str(path), "contents": "fixture-only\\n"}})
        elif kind == "replace":
            path = root / "pups-replacements" / str(ordinal)
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text("alpha\\n")
            run.append({"replace": {"filename": str(path), "from": "alpha", "to": "alpha"}})
        else:
            raise SystemExit(18)
    if scenario == "trace-plan-88":
        run = run[:88]
    return {"run": run}

def trace_mounts(docker_args, token):
    fields = shlex.split(docker_args)
    if any(field.startswith("--env") or field.startswith("--entrypoint") for field in fields):
        raise SystemExit(19)
    volumes = {}
    for field in fields:
        if not field.startswith("--volume="):
            continue
        source, destination, mode = field[len("--volume="):].rsplit(":", 2)
        volumes[destination] = (pathlib.Path(source), mode)
    guest_root = f"/shared/.mochirii-ci-pups-trace/{token}"
    required = {
        "/usr/local/bin/pups": "ro",
        f"{guest_root}/observer.rb": "ro",
        f"{guest_root}/state": "rw",
    }
    if set(volumes) != set(required) or any(volumes[key][1] != mode for key, mode in required.items()):
        raise SystemExit(20)
    wrapper = volumes["/usr/local/bin/pups"][0]
    observer = volumes[f"{guest_root}/observer.rb"][0]
    state_directory = volumes[f"{guest_root}/state"][0]
    if subprocess.run(["sh", "-n", str(wrapper)], check=False).returncode:
        raise SystemExit(21)
    if wrapper.parent != observer.parent or state_directory.parent != observer.parent:
        raise SystemExit(22)
    expected_wrapper = (
        "#!/bin/sh\n"
        "unset RUBYOPT MOCHIRII_PUPS_TRACE_MODE MOCHIRII_PUPS_TRACE_STATE\n"
        "export MOCHIRII_PUPS_TRACE_MODE='stage4-fixture-pups-1.4.0-v1'\n"
        f"export MOCHIRII_PUPS_TRACE_STATE='{guest_root}/state/trace.json'\n"
        f"export RUBYOPT='-r{guest_root}/observer.rb'\n"
        "exec /usr/local/bin/ruby "
        "/usr/local/lib/ruby/gems/3.4.0/gems/pups-1.4.0/bin/pups \"$@\"\n"
    )
    if wrapper.read_text() != expected_wrapper:
        raise SystemExit(25)
    return observer, state_directory

def run_trace_scenario(scenario, docker_args, token):
    observer, state_directory = trace_mounts(docker_args, token)
    cid = root / "var/discourse/cids/app_bootstrap.cid"
    cid.parent.mkdir(parents=True, exist_ok=True)
    cid.write_text("d" * 64 + "\n")
    # Keep the exact identity observable while the guard performs its first
    # bounded inventory refresh through separate fixture adapter processes.
    time.sleep(0.8)
    environment = {
        **os.environ,
        "RUBYOPT": f"-r{observer}",
        "MOCHIRII_PUPS_TRACE_MODE": "stage4-fixture-pups-1.4.0-v1",
        "MOCHIRII_PUPS_TRACE_STATE": str(state_directory / "trace.json"),
        "MOCHIRII_FORBIDDEN_SENTINEL": "sentinel-launcher-secret-never-emit-7d3f1a",
    }
    result = subprocess.run(
        [
            "/usr/local/bin/ruby",
            "/usr/local/lib/ruby/gems/3.4.0/gems/pups-1.4.0/bin/pups",
            "--stdin",
        ],
        input=json.dumps(trace_plan(scenario)),
        text=True,
        env=environment,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        check=False,
    )
    time.sleep(0.15)
    if cid.exists():
        cid.unlink()
    record = state_directory / "trace.json"
    if result.returncode == 0 and (record.exists() or record.is_symlink()):
        return 99
    if result.returncode != 0:
        metadata = record.lstat()
        if (
            metadata.st_uid != 0
            or metadata.st_gid != 0
            or metadata.st_nlink != 1
            or metadata.st_size < 1
            or metadata.st_size > 1024
            or (metadata.st_mode & 0o7777) != 0o600
        ):
            return 98
    if scenario == "trace-marker-malformed":
        record.write_text("sentinel-launcher-secret-never-emit-7d3f1a malformed")
        record.chmod(0o600)
    elif scenario == "trace-marker-oversize":
        record.write_bytes(b"x" * 1025)
        record.chmod(0o600)
    elif scenario == "trace-marker-symlink":
        victim = root / "trace-marker-victim"
        victim.write_text("victim-must-survive")
        record.unlink()
        record.symlink_to(victim)
    elif scenario == "trace-marker-mode":
        record.chmod(0o644)
    elif scenario == "trace-marker-nlink":
        os.link(record, root / "trace-marker-hardlink")
    elif scenario == "trace-marker-stage":
        document = json.loads(record.read_text())
        document["stage"] = "postgres"
        record.write_text(json.dumps(document, sort_keys=True) + "\n")
        record.chmod(0o600)
    elif scenario == "trace-marker-ordinal":
        document = json.loads(record.read_text())
        document["itemOrdinal"] = 93
        record.write_text(json.dumps(document, sort_keys=True) + "\n")
        record.chmod(0o600)
    elif scenario == "trace-marker-subcount":
        document = json.loads(record.read_text())
        document["execSubcommandCount"] = 16
        record.write_text(json.dumps(document, sort_keys=True) + "\n")
        record.chmod(0o600)
    elif scenario == "trace-marker-exit":
        document = json.loads(record.read_text())
        document["exitCode"] = 41
        record.write_text(json.dumps(document, sort_keys=True) + "\n")
        record.chmod(0o600)
    return result.returncode

args = sys.argv[1:]
if args and args[0] == "events":
    token = os.environ.get("MOCHIRII_DISPOSABLE_OPERATION_TOKEN", "")
    if len(token) != 32:
        raise SystemExit(10)
    scenario = state["scenario"]
    if scenario == "classifier-event-overflow":
        print("sentinel-launcher-secret-never-emit-7d3f1a" * 2048, flush=True)
        while True:
            time.sleep(1)
    helper = "c" * 64
    bootstrap = "d" * 64
    helper_normal = (
        (helper, "create", None), (helper, "start", None),
        (helper, "die", "0"), (helper, "destroy", None),
    )
    helper_oom = (
        (helper, "create", None), (helper, "start", None), (helper, "oom", None),
        (helper, "die", "137"), (helper, "destroy", None),
    )
    bootstrap_42 = (
        (bootstrap, "create", None), (bootstrap, "start", None),
        (bootstrap, "die", "42"), (bootstrap, "destroy", None),
    )
    bootstrap_0 = (
        (bootstrap, "create", None), (bootstrap, "start", None),
        (bootstrap, "die", "0"), (bootstrap, "destroy", None),
    )
    profiles = {
        "classifier-bootstrap-exit": helper_normal + bootstrap_42,
        "classifier-transient-empty-cid": helper_normal + bootstrap_42,
        "classifier-post-bootstrap-failure": helper_normal + bootstrap_0,
        "classifier-oom": helper_normal + (
            (bootstrap, "create", None), (bootstrap, "start", None), (bootstrap, "oom", None),
            (bootstrap, "die", "137"), (bootstrap, "destroy", None),
        ),
        "classifier-helper-oom-bootstrap-exit": helper_oom + bootstrap_42,
        "classifier-helpers-before-cid": helper_normal,
        "classifier-missing-cid": helper_normal + bootstrap_42,
        "classifier-malformed-cid": helper_normal + bootstrap_42,
        "classifier-unknown": helper_normal + ((bootstrap, "create", None),),
        "trace-terminal-code": helper_normal + bootstrap_42,
        "trace-terminal-final-first": helper_normal + (
            (bootstrap, "create", None), (bootstrap, "start", None),
            (bootstrap, "die", "37"), (bootstrap, "destroy", None),
        ),
        "trace-terminal-final-last": helper_normal + (
            (bootstrap, "create", None), (bootstrap, "start", None),
            (bootstrap, "die", "37"), (bootstrap, "destroy", None),
        ),
        "trace-file-failure": helper_normal + (
            (bootstrap, "create", None), (bootstrap, "start", None),
            (bootstrap, "die", "1"), (bootstrap, "destroy", None),
        ),
        "trace-plan-88": helper_normal + bootstrap_42,
        "trace-marker-malformed": helper_normal + bootstrap_42,
        "trace-marker-oversize": helper_normal + bootstrap_42,
        "trace-marker-symlink": helper_normal + bootstrap_42,
        "trace-marker-mode": helper_normal + bootstrap_42,
        "trace-marker-nlink": helper_normal + bootstrap_42,
        "trace-marker-stage": helper_normal + bootstrap_42,
        "trace-marker-ordinal": helper_normal + bootstrap_42,
        "trace-marker-subcount": helper_normal + bootstrap_42,
        "trace-marker-exit": helper_normal + bootstrap_42,
        "trace-tolerated-then-terminal": helper_normal + (
            (bootstrap, "create", None), (bootstrap, "start", None),
            (bootstrap, "die", "41"), (bootstrap, "destroy", None),
        ),
    }
    default = bootstrap_0
    events = profiles.get(scenario, () if scenario.startswith("classifier-") else default)
    for identity, action, exit_code in events:
        attributes = {
            "mochirii.forums.disposable-operation": token,
            "sentinel": "sentinel-launcher-secret-never-emit-7d3f1a",
            "url": "https://secret.invalid/private",
            "path": "/var/discourse/private",
            "command": "docker run secret-value",
            "name": "secret-container-name",
        }
        if exit_code is not None:
            attributes["exitCode"] = exit_code
        print(json.dumps({
            "Type": "container", "Action": action,
            "id": identity,
            "Actor": {"ID": identity, "Attributes": attributes},
        }), flush=True)
    while True:
        time.sleep(1)

if args and args[0] == "launcher":
    docker_args = values_after("--docker-args")
    token = ""
    for field in docker_args.split():
        prefix = "--label=mochirii.forums.disposable-operation="
        if field.startswith(prefix):
            token = field[len(prefix):]
    if len(token) != 32:
        raise SystemExit(9)
    scenario = state["scenario"]
    if scenario == "trace-start-check":
        if ".mochirii-ci-pups-trace" in docker_args or "RUBYOPT" in docker_args:
            raise SystemExit(23)
        image = state["tags"].get("local_discourse/app")
        if image is None:
            raise SystemExit(24)
        state["containers"]["b" * 64] = {
            "name": "app", "running": True, "image": image,
            "labels": {"mochirii.forums.disposable-operation": token},
        }
        save()
        raise SystemExit(0)
    if scenario.startswith("trace-") and args[1:3] == ["bootstrap", "app"]:
        trace_status = run_trace_scenario(scenario, docker_args, token)
        if trace_status == 0:
            state["images"].append("sha256:" + "a" * 64)
            state["images"] = sorted(set(state["images"]))
            state["tags"]["local_discourse/app"] = "sha256:" + "a" * 64
            save()
            raise SystemExit(0)
        raise SystemExit(1)
    if scenario.startswith("classifier-"):
        messages = {
            "classifier-bootstrap-exit": "bootstrap failed with exit code 42",
            "classifier-transient-empty-cid": "bootstrap cid populated after create",
            "classifier-post-bootstrap-failure": "commit failed after successful bootstrap",
            "classifier-oom": "Out of memory while compiling assets",
            "classifier-network-text": "Temporary failure in name resolution",
            "classifier-no-space-text": "No space left on device",
            "classifier-unknown": "unclassified launcher transcript text",
            "classifier-event-overflow": "oversized hostile event stream",
            "classifier-helper-oom-bootstrap-exit": "helper oom before bootstrap exit",
            "classifier-helpers-before-cid": "helper lifecycle before bootstrap cid",
            "classifier-missing-cid": "bootstrap cid was never observable",
            "classifier-malformed-cid": "bootstrap cid was malformed",
        }
        message = messages[scenario]
        cid = root / "var/discourse/cids/app_bootstrap.cid"
        cid.parent.mkdir(parents=True, exist_ok=True)
        if scenario == "classifier-transient-empty-cid":
            cid.write_bytes(b"")
            time.sleep(0.25)
            cid.write_text("d" * 64 + "\n")
        elif scenario in {
            "classifier-bootstrap-exit", "classifier-post-bootstrap-failure", "classifier-oom",
            "classifier-helper-oom-bootstrap-exit", "classifier-unknown",
        }:
            cid.write_text("d" * 64 + "\n")
        elif scenario == "classifier-malformed-cid":
            cid.write_text("not-a-valid-cid\n")
        time.sleep(0.35)
        if cid.exists():
            cid.unlink()
        print(f"sentinel-launcher-secret-never-emit-7d3f1a {message} https://secret.invalid/private")
        print(f"docker run secret-value /var/discourse/private {'e' * 64}", file=sys.stderr)
        raise SystemExit(1)
    if scenario == "unclean-exit-zero":
        cid = root / "var/discourse/cids/app_bootstrap.cid"
        cid.parent.mkdir(parents=True, exist_ok=True)
        cid.write_text("b" * 64 + "\n")
        cid.unlink()
        state["cidUnlinked"] = True
        state["finalRmFailed"] = True
        state["containers"]["b" * 64] = {
            "name": "anonymous-bootstrap", "running": False,
            "image": "sha256:" + "a" * 64,
            "labels": {"mochirii.forums.disposable-operation": token},
        }
        state["images"].append("sha256:" + "a" * 64)
        state["images"] = sorted(set(state["images"]))
        save()
        raise SystemExit(0)
    if scenario == "clean-bootstrap":
        state["images"].append("sha256:" + "a" * 64)
        state["images"] = sorted(set(state["images"]))
        state["tags"]["local_discourse/app"] = "sha256:" + "a" * 64
        save()
        raise SystemExit(0)
    if scenario == "clean-rebuild":
        state["containers"]["b" * 64] = {
            "name": "app", "running": True,
            "image": "sha256:" + "a" * 64,
            "labels": {"mochirii.forums.disposable-operation": token},
        }
        state["images"].append("sha256:" + "a" * 64)
        state["images"] = sorted(set(state["images"]))
        state["tags"]["local_discourse/app"] = "sha256:" + "a" * 64
        save()
        raise SystemExit(0)
    if scenario == "rebuild-mismatched-created-images":
        state["containers"]["b" * 64] = {
            "name": "app", "running": True,
            "image": "sha256:" + "c" * 64,
            "labels": {"mochirii.forums.disposable-operation": token},
        }
        state["images"].extend(["sha256:" + "a" * 64, "sha256:" + "c" * 64])
        state["images"] = sorted(set(state["images"]))
        state["tags"]["local_discourse/app"] = "sha256:" + "a" * 64
        save()
        raise SystemExit(0)
    if scenario == "rebuild-mismatched-preexisting-tag":
        state["containers"]["b" * 64] = {
            "name": "app", "running": True,
            "image": "sha256:" + "c" * 64,
            "labels": {"mochirii.forums.disposable-operation": token},
        }
        state["images"].append("sha256:" + "c" * 64)
        state["images"] = sorted(set(state["images"]))
        save()
        raise SystemExit(0)
    raise SystemExit(8)

if not args or args[0] != "docker":
    raise SystemExit(7)
args = args[1:]
if args[:2] == ["info", "--format"]:
    print(root)
elif args[:2] == ["container", "ls"]:
    selected = state["containers"]
    label = values_after("--filter")
    if label.startswith("label="):
        key, value = label[6:].split("=", 1)
        selected = {identity: item for identity, item in selected.items() if item["labels"].get(key) == value}
    print("\n".join(sorted(selected)))
elif args[:2] == ["image", "ls"]:
    print("\n".join(sorted(state["images"])))
elif args[:2] == ["container", "inspect"]:
    name = args[-1]
    matched = [(identity, item) for identity, item in state["containers"].items() if item["name"] == name]
    if not matched:
        raise SystemExit(1)
    identity, item = matched[0]
    print(f"{identity} {'true' if item['running'] else 'false'} {item['image']}")
elif args[:2] == ["image", "inspect"]:
    value = state["tags"].get(args[-1])
    if value is None:
        raise SystemExit(1)
    print(value)
elif args[:3] == ["container", "rm", "--force"]:
    state["containers"].pop(args[-1], None)
    save()
elif args[:3] == ["image", "rm", "--force"]:
    identity = args[-1]
    state["images"] = [value for value in state["images"] if value != identity]
    state["tags"] = {key: value for key, value in state["tags"].items() if value != identity}
    save()
else:
    raise SystemExit(6)
'''


def write_file(path: Path, payload: str, mode: int) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(payload, encoding="utf-8", newline="\n")
    path.chmod(mode)


def setup(root: Path, scenario: str) -> dict[str, str]:
    adapter = root / "adapter.py"
    write_file(adapter, ADAPTER, 0o600)
    write_file(root / "var/discourse/launcher", "#!/bin/sh\nexit 99\n", 0o700)
    gate = root / "checkout-gate.sh"
    write_file(gate, "#!/bin/sh\nexit 0\n", 0o700)
    state = {
        "scenario": scenario,
        "containers": {},
        "images": [PREEXISTING_IMAGE],
        "tags": (
            {"local_discourse/app": PREEXISTING_IMAGE}
            if scenario == "rebuild-mismatched-preexisting-tag"
            else {}
        ),
        "cidUnlinked": False,
        "finalRmFailed": False,
    }
    write_file(root / "state.json", json.dumps(state, sort_keys=True) + "\n", 0o600)
    return {
        **os.environ,
        "MOCHIRII_DISPOSABLE_LAUNCHER_FIXTURE_ROOT": str(root),
        "MOCHIRII_DISPOSABLE_LAUNCHER_MODE": "source-only-hostile-fixture",
    }


def invoke(
    root: Path,
    environment: dict[str, str],
    *,
    passed: bool,
    operation: str = "bootstrap",
) -> subprocess.CompletedProcess[str]:
    result = subprocess.run(
        [sys.executable, "-B", str(GUARD), operation, str(root / "checkout-gate.sh")],
        env=environment,
        check=False,
        capture_output=True,
        text=True,
        timeout=30,
    )
    if (result.returncode == 0) != passed:
        raise RuntimeError("Disposable launcher fixture returned an unexpected status.")
    return result


def state(root: Path) -> dict[str, object]:
    return json.loads((root / "state.json").read_text(encoding="utf-8"))


def assert_no_transaction(root: Path) -> None:
    journal = root / "var/discourse/.mochirii-disposable-launcher.transaction.json"
    if journal.exists() or journal.is_symlink():
        raise RuntimeError("Disposable launcher transaction survived terminal proof.")
    trace_namespace = root / "var/discourse/shared/standalone/.mochirii-ci-pups-trace"
    if trace_namespace.exists() or trace_namespace.is_symlink():
        raise RuntimeError("Disposable Pups trace residue survived terminal proof.")
    marker_prefix = b"MOCHIRII_DISPOSABLE_OPERATION_TOKEN="
    for entry in Path("/proc").iterdir():
        if not entry.name.isdigit():
            continue
        try:
            fields = (entry / "environ").read_bytes().split(b"\0")
        except (FileNotFoundError, PermissionError, ProcessLookupError):
            continue
        if any(field.startswith(marker_prefix) for field in fields):
            raise RuntimeError("Disposable launcher marked process survived terminal proof.")


def exit_zero_residue_fixture() -> None:
    with tempfile.TemporaryDirectory(prefix="mochirii-disposable-exit-zero-") as temporary:
        root = Path(temporary).resolve()
        environment = setup(root, "unclean-exit-zero")
        result = invoke(root, environment, passed=False)
        current = state(root)
        if current["containers"] or current["images"] != [PREEXISTING_IMAGE]:
            raise RuntimeError("Exit-zero anonymous launcher residue survived containment.")
        if current["tags"] or current["cidUnlinked"] is not True or current["finalRmFailed"] is not True:
            raise RuntimeError("Hostile launcher did not exercise CID-unlink/final-rm/exit-zero window.")
        if "did not produce the exact application image" not in result.stderr:
            raise RuntimeError("Exit-zero residue failed for the wrong reason.")
        assert_no_transaction(root)


def post_cid_crash_retry_fixture() -> None:
    with tempfile.TemporaryDirectory(prefix="mochirii-disposable-post-cid-") as temporary:
        root = Path(temporary).resolve()
        environment = setup(root, "unclean-exit-zero")
        crashed_environment = {
            **environment,
            "MOCHIRII_DISPOSABLE_LAUNCHER_FIXTURE_FAIL_AFTER": "launcher-returned",
        }
        process = subprocess.Popen(
            [sys.executable, "-B", str(GUARD), "bootstrap", str(root / "checkout-gate.sh")],
            env=crashed_environment,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        process.wait(timeout=30)
        if process.returncode not in {-signal.SIGKILL, 128 + signal.SIGKILL}:
            raise RuntimeError(f"Post-CID crash fixture did not SIGKILL: {process.returncode}")
        crashed = state(root)
        if not crashed["containers"] or CREATED_IMAGE not in crashed["images"]:
            raise RuntimeError("Post-CID crash did not retain the hostile identities.")
        journal = root / "var/discourse/.mochirii-disposable-launcher.transaction.json"
        if not journal.is_file():
            raise RuntimeError("Post-CID crash did not retain durable ownership.")
        trace_namespace = root / "var/discourse/shared/standalone/.mochirii-ci-pups-trace"
        trace_operations = list(trace_namespace.iterdir()) if trace_namespace.is_dir() else []
        if len(trace_operations) != 1 or not trace_operations[0].is_dir():
            raise RuntimeError("Post-CID crash did not retain journal-owned trace state.")
        trace_operation = trace_operations[0]
        required_trace_assets = {
            "observer.rb", "pups-wrapper", "state",
        }
        if {entry.name for entry in trace_operation.iterdir()} != required_trace_assets:
            raise RuntimeError("Post-CID crash retained different trace assets.")
        (trace_operation / ".observer.rb.123.partial").write_text("partial\n", encoding="utf-8")
        (trace_operation / ".pups-wrapper.123.partial").write_text("partial\n", encoding="utf-8")
        (trace_operation / "state/.trace.123.partial").write_text("partial\n", encoding="utf-8")

        crashed["scenario"] = "clean-bootstrap"
        write_file(root / "state.json", json.dumps(crashed, sort_keys=True) + "\n", 0o600)
        invoke(root, environment, passed=True)
        terminal = state(root)
        if terminal["containers"] or set(terminal["images"]) != {PREEXISTING_IMAGE, CREATED_IMAGE}:
            raise RuntimeError("Exact retry did not remove prior residue and adopt only the intended image.")
        if terminal["tags"] != {"local_discourse/app": CREATED_IMAGE}:
            raise RuntimeError("Exact retry did not bind the intended terminal image.")
        assert_no_transaction(root)


def rebuild_terminal_image_fixture() -> None:
    scenarios = (
        (
            "rebuild-mismatched-created-images",
            [PREEXISTING_IMAGE],
            {},
        ),
        (
            "rebuild-mismatched-preexisting-tag",
            [PREEXISTING_IMAGE],
            {"local_discourse/app": PREEXISTING_IMAGE},
        ),
    )
    for scenario, expected_images, expected_tags in scenarios:
        with tempfile.TemporaryDirectory(prefix=f"mochirii-disposable-{scenario}-") as temporary:
            root = Path(temporary).resolve()
            environment = setup(root, scenario)
            result = invoke(root, environment, operation="rebuild", passed=False)
            current = state(root)
            if current["containers"]:
                raise RuntimeError(f"Mismatched rebuild container survived containment: {scenario}")
            if current["images"] != expected_images or current["tags"] != expected_tags:
                raise RuntimeError(f"Mismatched rebuild image residue survived containment: {scenario}")
            if "named application image differs from the exact tagged application image" not in result.stderr:
                raise RuntimeError(f"Mismatched rebuild failed for the wrong reason: {scenario}")
            assert_no_transaction(root)

    with tempfile.TemporaryDirectory(prefix="mochirii-disposable-clean-rebuild-") as temporary:
        root = Path(temporary).resolve()
        environment = setup(root, "clean-rebuild")
        invoke(root, environment, operation="rebuild", passed=True)
        current = state(root)
        if (
            set(current["containers"]) != {CREATED_CONTAINER}
            or current["images"] != [CREATED_IMAGE, PREEXISTING_IMAGE]
            or current["tags"] != {"local_discourse/app": CREATED_IMAGE}
        ):
            raise RuntimeError("Matching rebuild did not adopt exactly one terminal app image.")
        assert_no_transaction(root)


def failure_classifier_fixture() -> None:
    unavailable_trace = (
        "pups_trace_valid=false",
        "pups_layout_exact=false",
        "pups_stage=unavailable",
        "pups_phase=unavailable",
        "pups_item_ordinal=-1",
        "pups_item_count=-1",
        "pups_completed_item_count=-1",
        "pups_exec_subcommand_ordinal=-1",
        "pups_exec_subcommand_count=-1",
        "pups_exit_code=-1",
    )
    classifier_scenarios = {
        "classifier-bootstrap-exit": (
            "failure_class=non-oom-container-exit",
            "event_count=8",
            "bootstrap_event_count=4",
            "helper_event_count=4",
            "oom_observed=false",
            "die_exit_code=42",
            "bootstrap_exit_code=42",
        ),
        "classifier-transient-empty-cid": (
            "failure_class=non-oom-container-exit",
            "lifecycle_valid=true",
            "bootstrap_identity_observed=true",
            "bootstrap_exit_code=42",
        ),
        "classifier-post-bootstrap-failure": (
            "failure_class=post-bootstrap-launcher-failure",
            "event_count=8",
            "bootstrap_event_count=4",
            "helper_event_count=4",
            "oom_observed=false",
            "die_exit_code=0",
            "bootstrap_exit_code=0",
        ),
        "classifier-oom": (
            "failure_class=oom-container-exit",
            "event_count=9",
            "bootstrap_event_count=5",
            "helper_event_count=4",
            "oom_observed=true",
            "die_exit_code=137",
            "bootstrap_exit_code=137",
        ),
        "classifier-helper-oom-bootstrap-exit": (
            "failure_class=non-oom-container-exit",
            "event_count=9",
            "bootstrap_event_count=4",
            "helper_event_count=5",
            "oom_observed=false",
            "bootstrap_exit_code=42",
        ),
        "classifier-helpers-before-cid": (
            "failure_class=bootstrap-unobserved",
            "bootstrap_identity_observed=false",
            "event_count=4",
            "bootstrap_event_count=0",
            "bootstrap_exit_code=-1",
        ),
        "classifier-missing-cid": (
            "failure_class=bootstrap-unobserved",
            "bootstrap_identity_observed=false",
            "event_count=8",
            "bootstrap_event_count=0",
            "bootstrap_exit_code=-1",
        ),
        "classifier-malformed-cid": (
            "failure_class=incomplete-unknown",
            "lifecycle_valid=false",
            "bootstrap_identity_observed=false",
            "bootstrap_exit_code=-1",
        ),
        "classifier-network-text": (
            "failure_class=pre-container",
            "event_count=0",
            "bootstrap_exit_code=-1",
        ),
        "classifier-no-space-text": (
            "failure_class=pre-container",
            "event_count=0",
            "bootstrap_exit_code=-1",
        ),
        "classifier-unknown": (
            "failure_class=incomplete-unknown",
            "bootstrap_identity_observed=true",
            "event_count=5",
            "bootstrap_event_count=1",
            "bootstrap_exit_code=-1",
        ),
        "classifier-event-overflow": (
            "failure_class=incomplete-unknown",
            "lifecycle_valid=false",
            "bootstrap_exit_code=-1",
        ),
    }
    scenarios = {
        scenario: required + unavailable_trace
        for scenario, required in classifier_scenarios.items()
    }
    scenarios.update({
        "trace-terminal-code": (
            "failure_class=non-oom-container-exit",
            "bootstrap_exit_code=42",
            "pups_trace_valid=true",
            "pups_layout_exact=true",
            "pups_stage=code",
            "pups_phase=terminal-failure",
            "pups_item_ordinal=49",
            "pups_item_count=92",
            "pups_completed_item_count=48",
            "pups_exec_subcommand_ordinal=7",
            "pups_exec_subcommand_count=17",
            "pups_exit_code=42",
        ),
        "trace-terminal-final-first": (
            "pups_trace_valid=true",
            "pups_layout_exact=true",
            "pups_stage=mochirii-final",
            "pups_item_ordinal=92",
            "pups_completed_item_count=91",
            "pups_exec_subcommand_ordinal=1",
            "pups_exec_subcommand_count=9",
            "pups_exit_code=37",
        ),
        "trace-terminal-final-last": (
            "pups_trace_valid=true",
            "pups_layout_exact=true",
            "pups_stage=mochirii-final",
            "pups_item_ordinal=92",
            "pups_completed_item_count=91",
            "pups_exec_subcommand_ordinal=9",
            "pups_exec_subcommand_count=9",
            "pups_exit_code=37",
        ),
        "trace-file-failure": (
            "pups_trace_valid=true",
            "pups_layout_exact=true",
            "pups_stage=mochirii-files",
            "pups_item_ordinal=84",
            "pups_completed_item_count=83",
            "pups_exec_subcommand_ordinal=0",
            "pups_exec_subcommand_count=0",
            "pups_exit_code=1",
        ),
        "trace-plan-88": (
            "pups_trace_valid=true",
            "pups_layout_exact=false",
            "pups_stage=plan-drift",
            "pups_phase=terminal-failure",
            "pups_item_ordinal=49",
            "pups_item_count=88",
            "pups_completed_item_count=48",
            "pups_exec_subcommand_ordinal=7",
            "pups_exec_subcommand_count=17",
            "pups_exit_code=42",
        ),
        "trace-tolerated-then-terminal": (
            "pups_trace_valid=true",
            "pups_layout_exact=true",
            "pups_stage=db-migrate",
            "pups_item_ordinal=65",
            "pups_completed_item_count=64",
            "pups_exec_subcommand_ordinal=1",
            "pups_exec_subcommand_count=1",
            "pups_exit_code=41",
        ),
        **{
            scenario: unavailable_trace
            for scenario in (
                "trace-marker-malformed", "trace-marker-oversize", "trace-marker-symlink",
                "trace-marker-mode", "trace-marker-nlink", "trace-marker-stage",
                "trace-marker-ordinal", "trace-marker-subcount", "trace-marker-exit",
            )
        },
    })
    safe_output = re.compile(
        r"\ADisposable launcher operation failed; operation-created residue was contained[.] "
        r"failure_class=(?:pre-container|bootstrap-unobserved|post-bootstrap-launcher-failure|non-oom-container-exit|oom-container-exit|incomplete-unknown) "
        r"launcher_rc=-?[0-9]+ elapsed_seconds=[0-9]+ lifecycle_valid=(?:true|false) "
        r"bootstrap_identity_observed=(?:true|false) event_count=[0-9]+ "
        r"bootstrap_event_count=[0-9]+ helper_event_count=[0-9]+ "
        r"container_create_count=[0-9]+ container_start_count=[0-9]+ "
        r"container_die_count=[0-9]+ container_destroy_count=[0-9]+ oom_observed=(?:true|false) "
        r"die_exit_code_observed=(?:true|false) die_exit_code=-?[0-9]+ "
        r"bootstrap_exit_code_observed=(?:true|false) bootstrap_exit_code=-?[0-9]+ "
        r"docker_free_pre_bytes=-?[0-9]+ docker_free_post_bytes=-?[0-9]+ "
        r"mem_available_pre_bytes=-?[0-9]+ mem_available_post_bytes=-?[0-9]+ "
        r"swap_free_pre_bytes=-?[0-9]+ swap_free_post_bytes=-?[0-9]+ "
        r"swap_total_pre_bytes=-?[0-9]+ swap_total_post_bytes=-?[0-9]+ "
        r"pups_trace_valid=(?:true|false) pups_layout_exact=(?:true|false) "
        r"pups_stage=(?:unavailable|postgres|redis|web-pre-code|code|redis-after-code|mochirii-after-code|web-config|web|yarn|bundle-exec|plugin-compatibility|pre-db-migrate|db-migrate|clear-stuck-web-upgrades|assets-precompile-build|assets-precompile|web-finalize|rate-limit|mochirii-files|mochirii-final|plan-drift) "
        r"pups_phase=(?:unavailable|terminal-failure) pups_item_ordinal=-?[0-9]+ "
        r"pups_item_count=-?[0-9]+ pups_completed_item_count=-?[0-9]+ "
        r"pups_exec_subcommand_ordinal=-?[0-9]+ pups_exec_subcommand_count=-?[0-9]+ "
        r"pups_exit_code=-?[0-9]+\Z"
    )
    forbidden = (
        FORBIDDEN_SENTINEL,
        "bootstrap failed with exit code",
        "bootstrap cid populated after create",
        "commit failed after successful bootstrap",
        "Out of memory",
        "Temporary failure in name resolution",
        "No space left on device",
        "unclassified launcher transcript text",
        "oversized hostile event stream",
        "helper oom before bootstrap exit",
        "helper lifecycle before bootstrap cid",
        "bootstrap cid was never observable",
        "bootstrap cid was malformed",
        "https://",
        "docker run",
        "/var/discourse",
        "secret-container-name",
        "e" * 64,
        "c" * 64,
        "d" * 64,
    )
    for scenario, required in scenarios.items():
        with tempfile.TemporaryDirectory(prefix="mochirii-disposable-classifier-") as temporary:
            root = Path(temporary).resolve()
            environment = setup(root, scenario)
            result = invoke(root, environment, passed=False)
            if result.stdout:
                raise RuntimeError("Disposable launcher classifier emitted unexpected standard output.")
            message = result.stderr.strip()
            if any(value in message for value in forbidden):
                raise RuntimeError("Disposable launcher classifier disclosed forbidden launcher evidence.")
            if safe_output.fullmatch(message) is None:
                raise RuntimeError(f"Disposable launcher classifier output escaped its fixed safe schema: {scenario}")
            if any(value not in message for value in required):
                raise RuntimeError(f"Disposable launcher classifier returned different bounded evidence: {scenario}")
            if scenario == "trace-marker-symlink":
                victim = root / "trace-marker-victim"
                if victim.read_text(encoding="utf-8") != "victim-must-survive":
                    raise RuntimeError("Disposable trace reader followed a hostile marker symlink.")
            if scenario == "trace-marker-nlink":
                hardlink = root / "trace-marker-hardlink"
                if not hardlink.is_file() or hardlink.stat().st_nlink != 1:
                    raise RuntimeError("Disposable trace cleanup altered a hostile external hardlink.")
            current = state(root)
            if current["containers"] or current["images"] != [PREEXISTING_IMAGE] or current["tags"]:
                raise RuntimeError("Disposable launcher classifier changed terminal reconciliation.")
            assert_no_transaction(root)


def pups_trace_success_fixture() -> None:
    for scenario in ("trace-tolerated-62", "trace-tolerated-66"):
        with tempfile.TemporaryDirectory(prefix=f"mochirii-disposable-{scenario}-") as temporary:
            root = Path(temporary).resolve()
            environment = setup(root, scenario)
            result = invoke(root, environment, passed=True)
            if result.stdout or result.stderr:
                raise RuntimeError("Successful disposable Pups trace fixture emitted output.")
            current = state(root)
            if (
                current["containers"]
                or set(current["images"]) != {PREEXISTING_IMAGE, CREATED_IMAGE}
                or current["tags"] != {"local_discourse/app": CREATED_IMAGE}
            ):
                raise RuntimeError("Tolerated Pups command changed bootstrap reconciliation.")
            assert_no_transaction(root)

            if scenario == "trace-tolerated-62":
                current["scenario"] = "trace-start-check"
                write_file(root / "state.json", json.dumps(current, sort_keys=True) + "\n", 0o600)
                start_result = invoke(root, environment, operation="start", passed=True)
                if start_result.stdout or start_result.stderr:
                    raise RuntimeError("Non-bootstrap disposable operation emitted trace output.")
                started = state(root)
                if (
                    set(started["containers"]) != {CREATED_CONTAINER}
                    or set(started["images"]) != {PREEXISTING_IMAGE, CREATED_IMAGE}
                    or started["tags"] != {"local_discourse/app": CREATED_IMAGE}
                ):
                    raise RuntimeError("Non-bootstrap operation changed under bootstrap-only tracing.")
                assert_no_transaction(root)


def nginx_outlet_syntax_fixture() -> None:
    nginx = shutil.which("nginx")
    ruby = shutil.which("ruby")
    if nginx is None or ruby is None:
        raise RuntimeError("Pinned Nginx and Ruby are required for the outlet syntax fixture.")

    with tempfile.TemporaryDirectory(prefix="mochirii-nginx-outlet-") as temporary:
        prefix = Path(temporary).resolve()
        rendered = prefix / "app.yml"
        environment = os.environ.copy()
        environment["FORUMS_FIXTURE_DISCOURSE_CONNECT_SECRET"] = "b" * 64
        completed = subprocess.run(
            [
                sys.executable,
                "-B",
                str(ROOT / "scripts" / "render-app-config.py"),
                "--mode",
                "stage4-connect-fixture",
                "--output",
                str(rendered),
            ],
            env=environment,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            timeout=10,
            check=False,
        )
        if completed.returncode != 0:
            raise RuntimeError("Pinned Nginx fixture could not render the exact application configuration.")

        discourse_directory = prefix / "conf.d" / "outlets" / "discourse"
        server_directory = prefix / "conf.d" / "outlets" / "server"
        discourse_directory.mkdir(parents=True)
        server_directory.mkdir(parents=True)
        extractor = r'''
require "yaml"

document = YAML.safe_load_file(ARGV.fetch(0), aliases: true)
expected = {
  "/etc/nginx/conf.d/outlets/discourse/40-mochirii-public-metadata.conf" =>
    File.join(ARGV.fetch(1), "conf.d/outlets/discourse/40-mochirii-public-metadata.conf"),
  "/etc/nginx/conf.d/outlets/server/40-mochirii-feed-denial.conf" =>
    File.join(ARGV.fetch(1), "conf.d/outlets/server/40-mochirii-feed-denial.conf"),
}
items = document.fetch("run")
expected.each do |source, destination|
  matches = items.select { |item| item["file"].is_a?(Hash) && item["file"]["path"] == source }
  abort "outlet inventory differs" unless matches.length == 1
  contents = matches.fetch(0).fetch("file").fetch("contents")
  abort "outlet contents differ" unless contents.is_a?(String) && !contents.empty?
  File.binwrite(destination, contents)
end
'''
        extracted = subprocess.run(
            [ruby, "-e", extractor, str(rendered), str(prefix)],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            timeout=10,
            check=False,
        )
        if extracted.returncode != 0:
            raise RuntimeError("Pinned Nginx fixture could not extract the exact outlet inventory.")

        configuration = prefix / "nginx.conf"
        configuration.write_text(
            "\n".join(
                (
                    "user root;",
                    f"pid {prefix / 'nginx.pid'};",
                    "error_log stderr notice;",
                    "events { worker_connections 16; }",
                    "http {",
                    "  access_log off;",
                    f"  client_body_temp_path {prefix / 'client-body'};",
                    f"  proxy_temp_path {prefix / 'proxy'};",
                    f"  fastcgi_temp_path {prefix / 'fastcgi'};",
                    f"  uwsgi_temp_path {prefix / 'uwsgi'};",
                    f"  scgi_temp_path {prefix / 'scgi'};",
                    "  map $http_x_forwarded_proto $thescheme { default http; https https; }",
                    "  upstream discourse { server 127.0.0.1:3000; }",
                    "  server {",
                    "    listen 127.0.0.1:18080;",
                    "    server_name _;",
                    "    include conf.d/outlets/server/*.conf;",
                    "    location /__mochirii_outlet_syntax__ {",
                    "      include conf.d/outlets/discourse/*.conf;",
                    "      return 204;",
                    "    }",
                    "  }",
                    "}",
                    "",
                )
            ),
            encoding="utf-8",
            newline="\n",
        )

        command = [nginx, "-t", "-p", f"{prefix}/", "-c", "nginx.conf", "-e", "stderr"]
        checked = subprocess.run(
            command,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            timeout=10,
            check=False,
        )
        if checked.returncode != 0:
            raise RuntimeError("Pinned Nginx rejected the exact rendered outlet configuration.")

        server_outlet = server_directory / "40-mochirii-feed-denial.conf"
        quoted_route = 'location ~ "^/session/email-login/[A-Za-z0-9_-]{20,256}$" {'
        unquoted_route = "location ~ ^/session/email-login/[A-Za-z0-9_-]{20,256}$ {"
        contents = server_outlet.read_text(encoding="utf-8")
        if contents.count(quoted_route) != 1 or unquoted_route in contents:
            raise RuntimeError("Administrator recovery Nginx regex is not uniquely quoted.")
        server_outlet.write_text(
            contents.replace(quoted_route, unquoted_route),
            encoding="utf-8",
            newline="\n",
        )
        hostile = subprocess.run(
            command,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            timeout=10,
            check=False,
        )
        if hostile.returncode == 0:
            raise RuntimeError("Pinned Nginx accepted the hostile unquoted bounded recovery regex.")


def run_linux() -> None:
    if os.geteuid() != 0:
        raise SystemExit("Disposable launcher fixture requires an isolated root Linux context.")
    if '["bash", str(gate)]' not in GUARD.read_text(encoding="utf-8"):
        raise RuntimeError("Disposable checkout gate is not readable from the pinned noexec fixture mount.")
    exit_zero_residue_fixture()
    post_cid_crash_retry_fixture()
    rebuild_terminal_image_fixture()
    failure_classifier_fixture()
    pups_trace_success_fixture()
    nginx_outlet_syntax_fixture()
    print("Disposable launcher immutable-ID hostile fixture passed.")


def run_in_container() -> None:
    command = [
        "docker", "run", "--rm", "--pull=never", "--network", "none", "--read-only",
        "--tmpfs", "/tmp:rw,noexec,nosuid,nodev,size=16m", "--cap-drop", "ALL",
        "--security-opt", "no-new-privileges", "--pids-limit", "64",
        "--memory", "256m", "--memory-swap", "256m", "-v", f"{ROOT}:/repo:ro",
        "--entrypoint", "python3", BASE_IMAGE, "-B",
        "/repo/scripts/test-disposable-launcher-guard.py", "--inside-linux",
    ]
    result = subprocess.run(command, check=False, capture_output=True, text=True)
    if result.returncode:
        raise RuntimeError("Pinned disposable launcher fixture failed without exposing captured output.")
    print(result.stdout.strip())


if __name__ == "__main__":
    if os.name == "nt" and "--inside-linux" not in sys.argv:
        run_in_container()
    else:
        run_linux()
