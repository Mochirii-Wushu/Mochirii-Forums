#!/usr/bin/env python3
"""Hostile crash-window checks for restore launcher journal authority."""

from __future__ import annotations

import hashlib
import json
import os
import pathlib
import shutil
import subprocess
import sys
import tempfile


ROOT = pathlib.Path(__file__).resolve().parents[1]
RESTORE = ROOT / "scripts" / "host-restore-validate.sh"
COMMIT = "1" * 40
INVENTORY_SHA = "2" * 64
LAUNCHER_OPERATION_ID = "a" * 32
PREVIOUS_IMAGE = "sha256:" + "b" * 64


def extract_journal_writer(source: str) -> str:
    function = source.index("write_restore_journal() {")
    start = source.index("<<'PY'\n", function) + len("<<'PY'\n")
    end = source.index("\nPY\n  restore_phase=", start)
    return source[start:end] + "\n"


def extract_shell_function(source: str, name: str, next_name: str) -> str:
    start = source.index(f"{name}() {{")
    end = source.index(f"\n{next_name}() {{", start)
    return source[start:end] + "\n"


def shell_path(path: pathlib.Path) -> str:
    resolved = path.resolve()
    if os.name != "nt":
        return str(resolved)
    drive = resolved.drive.rstrip(":").lower()
    tail = resolved.as_posix()[2:]
    return f"/mnt/{drive}{tail}"


def exercise_runtime_reconciliation(source: str, root: pathlib.Path) -> None:
    bash = shutil.which("bash")
    if bash is None:
        raise AssertionError("bash is required for the restore launcher runtime fixture")
    cid_function = extract_shell_function(source, "remove_launcher_cid_safely", "launcher_processes_absent")
    cid_function = cid_function.replace(
        ' || "$(stat -c \'%U:%G %a\' "${launcher_bootstrap_cid}" 2>/dev/null)" != "root:root 600"',
        "",
    )
    image_absence_function = extract_shell_function(source, "launcher_image_id_absent", "reconcile_launcher_image")
    image_function = extract_shell_function(source, "reconcile_launcher_image", "reconcile_launcher_operation")
    delete_line = 'timeout --signal=TERM --kill-after=5s 30 docker image rm --force "${durable_replacement}" >/dev/null 2>&1 || return 1'
    if image_function.count(delete_line) != 1:
        raise AssertionError("restore replacement image deletion hook differs")
    image_function = image_function.replace(delete_line, delete_line + "\n      maybe_crash post-delete || return 1", 1)
    harness = root / "runtime-reconcile.sh"
    image_state = root / "image-state"
    image_inventory = root / "image-inventory"
    container_state = root / "container-state"
    crash_seen = root / "crash-seen"
    replacement_state = root / "replacement-state"
    cid = root / "app_bootstrap.cid"
    harness.write_text(
        "#!/usr/bin/env bash\n"
        "set -euo pipefail\n"
        "image_state=$1\ncontainer_state=$2\ncrash_seen=$3\nlauncher_bootstrap_cid=$4\n"
        "launcher_operation_token=$5\nprevious_image=$6\nreplacement_image=$7\ncontainer_id=$8\nreplacement_state=$9\nimage_inventory=${10}\n"
        "crash_action=none\n"
        "timeout() {\n"
        "  while [[ $# -gt 0 && $1 == --* ]]; do shift; done\n"
        "  [[ $# -ge 2 ]] || return 1\n"
        "  shift\n"
        "  \"$@\"\n"
        "}\n"
        "sleep() { :; }\n"
        "maybe_crash() {\n"
        "  local action=$1\n"
        "  if [[ $crash_action == $action && ! -e $crash_seen ]]; then : >\"$crash_seen\"; return 99; fi\n"
        "}\n"
        "bind_launcher_replacement_image() {\n"
        "  [[ $1 == $replacement_image ]] || return 1\n"
        "  if [[ -s $replacement_state ]]; then [[ $(cat \"$replacement_state\") == $1 ]]; return; fi\n"
        "  printf '%s\\n' \"$1\" >\"$replacement_state\"\n"
        "  launcher_replacement_image_id=$1\n"
        "}\n"
        "docker() {\n"
        "  if [[ $1 == image && $2 == ls ]]; then\n"
        "    if [[ ${!#} == local_discourse/app ]]; then [[ ! -s $image_state ]] || cat \"$image_state\"; else cat \"$image_inventory\"; fi\n"
        "  elif [[ $1 == image && $2 == inspect ]]; then\n"
        "    grep -Fxq -- \"${!#}\" \"$image_inventory\"\n"
        "  elif [[ $1 == image && $2 == tag ]]; then\n"
        "    grep -Fxq -- \"$3\" \"$image_inventory\" || return 1\n"
        "    printf '%s\\n' \"$3\" >\"$image_state\"\n"
        "  elif [[ $1 == image && $2 == rm ]]; then\n"
        "    identity=${!#}\n"
        "    if [[ $identity == local_discourse/app ]]; then : >\"$image_state\"; maybe_crash untag; return; fi\n"
        "    grep -Fxv -- \"$identity\" \"$image_inventory\" >\"$image_inventory.next\" || true\n"
        "    mv \"$image_inventory.next\" \"$image_inventory\"\n"
        "    [[ ! -s $image_state || $(cat \"$image_state\") != $identity ]] || : >\"$image_state\"\n"
        "  elif [[ $1 == container && $2 == ls ]]; then\n"
        "    [[ ! -e $container_state ]] || printf '%s\\n' \"$container_id\"\n"
        "  elif [[ $1 == inspect ]]; then\n"
        "    [[ -e $container_state && ${!#} == $container_id ]] || return 1\n"
        "    printf '%s\\n' \"$launcher_operation_token\"\n"
        "  elif [[ $1 == stop ]]; then\n"
        "    [[ -e $container_state && ${!#} == $container_id ]]\n"
        "  elif [[ $1 == rm ]]; then\n"
        "    [[ -e $container_state && ${!#} == $container_id ]] || return 1\n"
        "    rm -f -- \"$container_state\"\n"
        "  else\n"
        "    return 1\n"
        "  fi\n"
        "}\n"
        + cid_function
        + image_absence_function
        + image_function
        + "printf '%s\\n%s\\n' \"$previous_image\" \"$replacement_image\" >\"$image_inventory\"\n"
        "printf '%s\\n' \"$replacement_image\" >\"$image_state\"\n"
        "launcher_previous_image_id=$previous_image\n"
        "launcher_replacement_image_id=\n: >\"$replacement_state\"\n"
        "crash_action=untag\nrm -f -- \"$crash_seen\"\n"
        "if (reconcile_launcher_image); then exit 20; fi\n"
        "launcher_replacement_image_id=$(cat \"$replacement_state\")\n"
        "[[ $launcher_replacement_image_id == $replacement_image && ! -s $image_state ]]\n"
        "grep -Fxq -- \"$replacement_image\" \"$image_inventory\"\n"
        "crash_action=none\nreconcile_launcher_image\n[[ $(cat \"$image_state\") == $previous_image ]]\n"
        "! grep -Fxq -- \"$replacement_image\" \"$image_inventory\"\n"
        "printf '%s\\n%s\\n' \"$previous_image\" \"$replacement_image\" >\"$image_inventory\"\n"
        "printf '%s\\n' \"$replacement_image\" >\"$image_state\"\n"
        ": >\"$replacement_state\"\nlauncher_replacement_image_id=\n"
        "crash_action=post-delete\nrm -f -- \"$crash_seen\"\n"
        "if (reconcile_launcher_image); then exit 23; fi\n"
        "launcher_replacement_image_id=$(cat \"$replacement_state\")\n"
        "[[ $launcher_replacement_image_id == $replacement_image && ! -s $image_state ]]\n"
        "! grep -Fxq -- \"$replacement_image\" \"$image_inventory\"\n"
        "crash_action=none\nreconcile_launcher_image\n[[ $(cat \"$image_state\") == $previous_image ]]\n"
        "printf '%s\\n' \"$replacement_image\" >>\"$image_inventory\"\n"
        "printf '%s\\n' \"$replacement_image\" >\"$image_state\"\n"
        "launcher_previous_image_id=-\nlauncher_replacement_image_id=\n: >\"$replacement_state\"\n"
        "crash_action=untag\nrm -f -- \"$crash_seen\"\n"
        "if (reconcile_launcher_image); then exit 21; fi\n"
        "[[ ! -s $image_state ]]\n"
        "launcher_replacement_image_id=$(cat \"$replacement_state\")\n"
        "[[ $launcher_replacement_image_id == $replacement_image ]]\n"
        "crash_action=none\nreconcile_launcher_image\n"
        "[[ ! -s $image_state ]]\n! grep -Fxq -- \"$replacement_image\" \"$image_inventory\"\n"
        "printf '%s\\n' \"$container_id\" >\"$launcher_bootstrap_cid\"\n"
        "chmod 0600 \"$launcher_bootstrap_cid\"\n: >\"$container_state\"\n"
        "if (remove_launcher_cid_safely; exit 99); then exit 22; else [[ $? == 99 ]]; fi\n"
        "[[ ! -e $launcher_bootstrap_cid && ! -e $container_state ]]\n"
        "remove_launcher_cid_safely\n",
        encoding="utf-8",
        newline="\n",
    )
    harness.chmod(0o700)
    result = subprocess.run(
        [
            bash,
            shell_path(harness),
            shell_path(image_state),
            shell_path(container_state),
            shell_path(crash_seen),
            shell_path(cid),
            LAUNCHER_OPERATION_ID,
            PREVIOUS_IMAGE,
            "sha256:" + "e" * 64,
            "d" * 64,
            shell_path(replacement_state),
            shell_path(image_inventory),
        ],
        check=False,
        capture_output=True,
        text=True,
        cwd=ROOT,
    )
    if result.returncode != 0:
        raise AssertionError(
            "restore launcher runtime reconciliation fixture failed\n"
            f"stdout={result.stdout!r}\nstderr={result.stderr!r}"
        )


def exercise_marked_process_reconciliation(source: str, root: pathlib.Path) -> None:
    bash = shutil.which("bash")
    if bash is None:
        raise AssertionError("bash is required for the restore marked-process fixture")
    retire_function = extract_shell_function(source, "retire_launcher_journal", "advance_restore_phase")
    generic_absence_function = extract_shell_function(
        source, "launcher_processes_absent", "control_launcher_marked_processes"
    )
    marked_functions = extract_shell_function(
        source, "control_launcher_marked_processes", "launcher_image_id_absent"
    )
    harness = root / "marked-process-reconcile.sh"
    retirement_marker = root / "marked-process-retired"
    harness.write_text(
        "#!/usr/bin/env bash\n"
        "set -euo pipefail\n"
        "launcher_operation_token=$1\nretirement_marker=$2\n"
        "launcher_previous_image_id=-\nlauncher_replacement_image_id=\n"
        "launcher_operation_command=rebuild\nlauncher_configuration_file=/fixture/app.yml\n"
        "launcher_configuration_sha256=" + "3" * 64 + "\nlauncher_restore_phase=prepared\n"
        "restore_phase=prepared\nsurvivor_pid=\n"
        "cleanup() {\n"
        "  if [[ -n $survivor_pid ]]; then kill -KILL \"$survivor_pid\" >/dev/null 2>&1 || true; wait \"$survivor_pid\" >/dev/null 2>&1 || true; fi\n"
        "}\n"
        "trap cleanup EXIT\n"
        "prove_launcher_selected_config() { printf '%s\\n' config-proof >>\"$retirement_marker\"; }\n"
        "write_restore_journal() { printf '%s\\n' retired >>\"$retirement_marker\"; }\n"
        + retire_function
        + generic_absence_function
        + marked_functions
        + "env \"MOCHIRII_RESTORE_LAUNCHER_OPERATION_TOKEN=$launcher_operation_token\" \\\n"
        "  setsid bash -c 'trap \"\" TERM; exec -a harmless-detached sleep 120' >/dev/null 2>&1 &\n"
        "survivor_pid=$!\n"
        "ready=false\n"
        "for _ in $(seq 1 50); do\n"
        "  if python3 -B - \"$survivor_pid\" \"$launcher_operation_token\" <<'PY'\n"
        "import pathlib\n"
        "import sys\n"
        "pid, token = sys.argv[1:]\n"
        "environment = pathlib.Path(f\"/proc/{pid}/environ\").read_bytes().split(b\"\\0\")\n"
        "command = pathlib.Path(f\"/proc/{pid}/cmdline\").read_bytes().split(b\"\\0\")\n"
        "marker = b\"MOCHIRII_RESTORE_LAUNCHER_OPERATION_TOKEN=\" + token.encode(\"ascii\")\n"
        "valid = (marker in environment and command[0] == b\"harmless-detached\"\n"
        "         and all(b\"./launcher\" not in field and b\"app_bootstrap.cid\" not in field for field in command))\n"
        "raise SystemExit(0 if valid else 1)\n"
        "PY\n"
        "  then ready=true; break; fi\n"
        "  sleep 0.1\n"
        "done\n"
        "[[ $ready == true ]]\n"
        "session_id=$(ps -o sid= -p \"$survivor_pid\" | tr -d ' ')\n"
        "[[ $session_id == $survivor_pid ]]\n"
        "kill -TERM \"$survivor_pid\"\nsleep 0.2\nkill -0 \"$survivor_pid\"\n"
        "launcher_processes_absent\n"
        "if launcher_marked_processes_absent; then exit 60; fi\n"
        "if retire_launcher_journal; then exit 61; fi\n"
        "[[ ! -e $retirement_marker ]]\n"
        "terminate_launcher_marked_processes\n"
        "launcher_marked_processes_absent\nlauncher_processes_absent\n"
        "wait \"$survivor_pid\" >/dev/null 2>&1 || true\n"
        "if kill -0 \"$survivor_pid\" >/dev/null 2>&1; then exit 62; fi\n"
        "survivor_pid=\ntrap - EXIT\n",
        encoding="utf-8",
        newline="\n",
    )
    harness.chmod(0o700)
    result = subprocess.run(
        [bash, shell_path(harness), LAUNCHER_OPERATION_ID, shell_path(retirement_marker)],
        check=False,
        capture_output=True,
        text=True,
        cwd=ROOT,
    )
    if result.returncode != 0:
        raise AssertionError(
            "restore marked launcher descendant reconciliation fixture failed\n"
            f"stdout={result.stdout!r}\nstderr={result.stderr!r}"
        )


def run_writer(helper: pathlib.Path, arguments: list[str], *, success: bool = True) -> subprocess.CompletedProcess[str]:
    result = subprocess.run(
        [sys.executable, "-B", str(helper), *arguments],
        check=False,
        capture_output=True,
        text=True,
        env={**os.environ, "PYTHONDONTWRITEBYTECODE": "1"},
    )
    if success != (result.returncode == 0):
        raise AssertionError(
            f"restore journal writer expectation differed: {arguments!r}\n"
            f"stdout={result.stdout!r}\nstderr={result.stderr!r}"
        )
    return result


def protected_file(path: pathlib.Path, payload: bytes) -> str:
    path.write_bytes(payload)
    path.chmod(0o600)
    return hashlib.sha256(payload).hexdigest()


def main() -> None:
    source = RESTORE.read_text(encoding="utf-8")
    run_launcher_start = source.index("run_launcher() {")
    run_launcher_end = source.index("\nterminate_active_group() {", run_launcher_start)
    run_launcher = source[run_launcher_start:run_launcher_end]
    failure_start = source.index("reconcile_launcher_failure() {")
    failure_end = source.index("\non_exit() {", failure_start)
    failure = source[failure_start:failure_end]
    retire_start = source.index("retire_launcher_journal() {")
    retire_end = source.index("\nadvance_restore_phase() {", retire_start)
    retire = source[retire_start:retire_end]
    reconcile_start = source.index("reconcile_launcher_operation() {")
    reconcile_end = source.index("\nreconcile_launcher_failure() {", reconcile_start)
    reconcile = source[reconcile_start:reconcile_end]
    resume_reconcile = source.index('if [[ -n ${launcher_operation_token} ]]; then', source.index("trap handle_operation_signal"))
    restore_execution = source.index("if phase_before production-reopening;", resume_reconcile)

    ordered_success = (
        run_launcher.index("arm_launcher_journal"),
        run_launcher.index("exec ./launcher"),
        run_launcher.index("reconcile_launcher_operation success"),
        run_launcher.index('verify-runtime-assets.sh" "${commit}" --require-container'),
        run_launcher.index("retire_launcher_journal"),
    )
    if ordered_success != tuple(sorted(ordered_success)):
        raise AssertionError("restore launcher can execute or retire before durable arm and terminal success proof")
    ordered_failure = (
        failure.index("reconcile_launcher_operation failure"),
        failure.index("stop_app_safely"),
        failure.index("retire_launcher_journal"),
    )
    if ordered_failure != tuple(sorted(ordered_failure)):
        raise AssertionError("restore launcher failure can retire before container, image, and process proof")
    ordered_retirement = (
        retire.index("launcher_marked_processes_absent"),
        retire.index("launcher_processes_absent"),
        retire.index("prove_launcher_selected_config"),
        retire.index("write_restore_journal"),
    )
    if ordered_retirement != tuple(sorted(ordered_retirement)):
        raise AssertionError("restore launcher journal can retire before exact host-process absence proof")
    ordered_reconciliation = (
        reconcile.index("terminate_launcher_marked_processes"),
        reconcile.index("launcher_marked_processes_absent"),
        reconcile.index("launcher_processes_absent"),
        reconcile.index("prove_launcher_selected_config"),
        reconcile.index("remove_launcher_cid_safely"),
    )
    if ordered_reconciliation != tuple(sorted(ordered_reconciliation)):
        raise AssertionError("restore launcher failure does not terminate marked descendants before state proof")
    if resume_reconcile >= restore_execution:
        raise AssertionError("restore launcher retry can rerun phase work before journal reconciliation")
    for required in (
        '"launcherOperationToken"',
        '"launcherPreviousImageId"',
        '"launcherReplacementImageId"',
        '"launcherCommand"',
        '"launcherConfigurationFile"',
        '"launcherConfigurationSha256"',
        '"launcherRestorePhase"',
        '[[ $# -eq 2 && ${2:-} == app ]] || return 1',
        'raise SystemExit("restore journal cannot advance while a launcher is armed")',
        'launcher_journal_unarmed || return 1',
        '-z ${launcher_configuration_file} && -z ${launcher_configuration_sha256} && -z ${launcher_restore_phase}',
        '[[ ${app_image} == "${current_image}" ]] || return 1',
        'env "MOCHIRII_RESTORE_LAUNCHER_OPERATION_TOKEN=${launcher_operation_token}"',
        'fields = pathlib.Path(f"/proc/{pid}/environ").read_bytes().split(b"\\0")',
        'pid not in safe_processes and is_marked(pid)',
        '((signal.SIGTERM, 3.0), (signal.SIGKILL, 3.0))',
        'terminate_launcher_marked_processes || return 1',
        'document.get("phase") != "event-committed"',
        "os.fsync(target.fileno())",
        "os.replace(temporary, path)",
        "descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)",
        "os.fsync(directory)",
    ):
        if required not in source:
            raise AssertionError(f"restore launcher durability primitive is absent: {required}")
    if source.count("exec ./launcher") != 1:
        raise AssertionError("restore contains a launcher execution outside its single journaled wrapper")

    with tempfile.TemporaryDirectory(prefix="mochirii-restore-launcher-") as temporary:
        root = pathlib.Path(temporary)
        root.chmod(0o700)
        helper = root / "journal-writer.py"
        writer = extract_journal_writer(source)
        if os.name == "nt":
            # NTFS/Python does not expose POSIX uid/gid or chmod semantics. The
            # production source checks remain asserted above; only this copied
            # fixture body skips those two unavailable metadata predicates.
            writer = writer.replace("metadata.st_uid != 0 or metadata.st_mode & 0o077", "False")
            writer = writer.replace(
                "metadata.st_uid != 0 or stat.S_IMODE(metadata.st_mode) != 0o600",
                "False",
            )
            writer = writer.replace("os.O_RDONLY | os.O_NOFOLLOW", "os.O_RDONLY")
            writer = writer.replace(
                "directory = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY)",
                "directory = os.open(path, os.O_RDONLY)",
            )
            writer = writer.replace(
                "import sys\n",
                "import sys\n"
                "_fixture_fsync = os.fsync\n"
                "def _portable_fixture_fsync(descriptor):\n"
                "    try:\n"
                "        _fixture_fsync(descriptor)\n"
                "    except OSError:\n"
                "        pass\n"
                "os.fsync = _portable_fixture_fsync\n",
                1,
            )
        helper.write_text(writer, encoding="utf-8")
        helper.chmod(0o600)
        journal = root / "restore-transaction.json"
        production = root / "app.yml"
        restore = root / "restore.yml"
        release = root / "release.json"
        backup = root / "backup.json"
        production_sha = protected_file(production, b"production\n")
        restore_sha = protected_file(restore, b"restore\n")
        protected_file(release, b"release\n")
        protected_file(backup, b"backup\n")

        def arguments(phase: str, launcher: tuple[object, ...] | None = None) -> list[str]:
            launcher_arguments = ["-"] * 7 if launcher is None else ["-" if value is None else str(value) for value in launcher]
            return [
                str(journal),
                phase,
                COMMIT,
                production_sha,
                str(production),
                str(restore),
                str(release),
                str(backup),
                "-",
                "-",
                "-",
                "-",
                "-",
                "-",
                "-",
                "false",
                "false",
                "0",
                INVENTORY_SHA,
                *launcher_arguments,
            ]

        run_writer(helper, arguments("prepared"))
        armed_tuple = (LAUNCHER_OPERATION_ID, PREVIOUS_IMAGE, None, "rebuild", str(production), production_sha, "prepared")
        run_writer(helper, arguments("prepared", armed_tuple))
        armed_bytes = journal.read_bytes()
        armed = json.loads(armed_bytes)
        if tuple(
            armed[key]
            for key in (
                "launcherOperationToken",
                "launcherPreviousImageId",
                "launcherReplacementImageId",
                "launcherCommand",
                "launcherConfigurationFile",
                "launcherConfigurationSha256",
                "launcherRestorePhase",
            )
        ) != armed_tuple:
            raise AssertionError("kill-after-arm lost the exact launcher authority")

        # A killed owner after arm cannot advance the restore phase or replace
        # any part of the exact launcher identity.
        run_writer(helper, arguments("isolating"), success=False)
        changed_token = ("c" * 32, *armed_tuple[1:])
        run_writer(helper, arguments("prepared", changed_token), success=False)
        changed_command = (LAUNCHER_OPERATION_ID, PREVIOUS_IMAGE, None, "restart", str(production), production_sha, "prepared")
        run_writer(helper, arguments("prepared", changed_command), success=False)

        replacement_image = "sha256:" + "e" * 64
        replacement_tuple = (
            LAUNCHER_OPERATION_ID, PREVIOUS_IMAGE, replacement_image,
            "rebuild", str(production), production_sha, "prepared",
        )
        run_writer(helper, arguments("prepared", replacement_tuple))
        armed_bytes = journal.read_bytes()
        if json.loads(armed_bytes)["launcherReplacementImageId"] != replacement_image:
            raise AssertionError("post-image-swap replacement ID was not durably bound")
        changed_replacement = (
            LAUNCHER_OPERATION_ID, PREVIOUS_IMAGE, "sha256:" + "f" * 64,
            "rebuild", str(production), production_sha, "prepared",
        )
        run_writer(helper, arguments("prepared", changed_replacement), success=False)

        # Simulate SIGKILL immediately after the exact bootstrap CID is
        # unlinked and again after the tagged image is swapped/untagged. Those
        # external mutations cannot retire or rewrite the durable prior-image
        # authority; a new process reloads the same bytes for reconciliation.
        exercise_runtime_reconciliation(source, root)
        exercise_marked_process_reconciliation(source, root)
        if journal.read_bytes() != armed_bytes:
            raise AssertionError("post-CID-unlink or image-reconciliation crash changed launcher authority")
        reloaded = json.loads(journal.read_text(encoding="utf-8"))
        if (
            reloaded["launcherPreviousImageId"] != PREVIOUS_IMAGE
            or reloaded["launcherReplacementImageId"] != replacement_image
            or reloaded["launcherOperationToken"] != LAUNCHER_OPERATION_ID
        ):
            raise AssertionError("post-image-swap crash lost the prior, replacement, or token identity")

        # Terminal proof retires only the launcher tuple and keeps the restore
        # phase fixed. A crash before the following phase advance is therefore
        # idempotently recoverable without reusing the old token.
        run_writer(helper, arguments("prepared"))
        retired = json.loads(journal.read_text(encoding="utf-8"))
        if retired["phase"] != "prepared" or any(
            retired[key] is not None
            for key in (
                "launcherOperationToken",
                "launcherPreviousImageId",
                "launcherReplacementImageId",
                "launcherCommand",
                "launcherConfigurationFile",
                "launcherConfigurationSha256",
                "launcherRestorePhase",
            )
        ):
            raise AssertionError("pre-phase-advance crash did not leave a terminal launcher tuple")
        run_writer(helper, arguments("isolating"))

        # No prior image is explicit, not conflated with an unarmed journal.
        no_image_tuple = ("f" * 32, "-", None, "rebuild", str(restore), restore_sha, "isolating")
        run_writer(helper, arguments("isolating", no_image_tuple))
        no_image = json.loads(journal.read_text(encoding="utf-8"))
        if no_image["launcherPreviousImageId"] != "-":
            raise AssertionError("no-prior-image launcher authority is ambiguous")
        run_writer(helper, arguments("isolating"))

    print("restore launcher journal hostile crash-window tests passed")


if __name__ == "__main__":
    main()
