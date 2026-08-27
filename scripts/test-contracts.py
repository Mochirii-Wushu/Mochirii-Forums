#!/usr/bin/env python3
"""Hostile fixture tests for rendering and deterministic theme packaging."""

from __future__ import annotations

import sys


def _require_isolated_python() -> bool:
    if (
        sys.flags.isolated != 1
        or sys.flags.no_site != 1
        or sys.flags.dont_write_bytecode != 1
        or getattr(sys.flags, "safe_path", False) is not True
        or (
            __name__ == "__main__"
            and any(
                name in sys.modules
                for name in ("ast", "hashlib", "os", "pathlib", "site")
            )
        )
    ):
        raise SystemExit("Trusted Python startup boundary is unavailable.")
    return True


def _normalize_import_path(value: str) -> str:
    if not isinstance(value, str) or not value or "\x00" in value:
        raise RuntimeError("Trusted Python import path is malformed.")
    candidate = value.replace("\\", "/")
    windows = (
        len(candidate) >= 3
        and candidate[0].isalpha()
        and candidate[1] == ":"
        and candidate[2] == "/"
    )
    if windows:
        root = candidate[:3]
        remainder = candidate[3:]
    elif candidate.startswith("/"):
        root = "/"
        remainder = candidate[1:]
    else:
        raise RuntimeError("Trusted Python import path is not absolute.")
    components = remainder.split("/") if remainder else []
    if any(component in {"", ".", ".."} for component in components):
        raise RuntimeError("Trusted Python import path is not lexical.")
    normalized = root + "/".join(components)
    return normalized.casefold() if windows else normalized


def _restrict_import_path() -> bool:
    trusted_prefixes: list[str] = []
    for value in (sys.base_prefix, sys.exec_prefix):
        try:
            normalized = _normalize_import_path(value)
        except RuntimeError:
            raise SystemExit("Trusted Python import path is unavailable.") from None
        if normalized and normalized not in trusted_prefixes:
            trusted_prefixes.append(normalized)
    accepted: list[str] = []
    for entry in sys.path:
        if not isinstance(entry, str) or not entry:
            continue
        try:
            normalized = _normalize_import_path(entry)
        except RuntimeError:
            raise SystemExit("Trusted Python import path is unavailable.") from None
        if any(
            normalized == prefix or normalized.startswith(f"{prefix}/")
            for prefix in trusted_prefixes
        ):
            accepted.append(entry)
    if not accepted:
        raise SystemExit("Trusted Python import path is unavailable.")
    sys.path[:] = accepted
    return True


_PYTHON_STARTUP_RESTRICTED = _require_isolated_python()
_IMPORT_PATH_RESTRICTED = _restrict_import_path()

import contextlib
import ast
import base64
import gzip
import hashlib
import importlib.util
import io
import json
import os
import re
import shutil
import signal
import stat
import subprocess
import tarfile
import tempfile
import time
import types
import urllib.error
import urllib.request
import zipfile
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]

LOCALIZED_ERROR_COPY_BLOCK = '''        - |-
          for status in 403 422 500 503; do
            source="public/${status}.html"
            [ -f "$source" ] && [ ! -L "$source" ] || exit 1
            set -- "public/${status}".*.html
            [ "$#" -eq 48 ] || exit 1
            for target; do
              [ -f "$target" ] && [ ! -L "$target" ] || exit 1
              cp -- "$source" "$target" || exit 1
              cmp -s -- "$source" "$target" || exit 1
            done
          done'''
LOCALIZED_ERROR_COPY_COMMAND = "\n".join(
    line[10:] for line in LOCALIZED_ERROR_COPY_BLOCK.splitlines()[1:]
)
NGINX_LOG_DIRECTORY_BLOCK = '''        - >-
          test ! -L /var/log/nginx &&
          install -d -m 0755 -o root -g adm /var/log/nginx &&
          nginx -t'''


def module_from(relative: str, name: str):
    spec = importlib.util.spec_from_file_location(name, ROOT / relative)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"Unable to load {relative}")
    module = importlib.util.module_from_spec(spec)
    try:
        spec.loader.exec_module(module)
    except SystemExit as error:
        raise RuntimeError(f"{relative} exited during import") from error
    return module


def module_from_source(relative: str, name: str, source: bytes):
    path = ROOT / relative
    module = types.ModuleType(name)
    module.__file__ = str(path)
    module.__package__ = ""
    try:
        exec(compile(source, str(path), "exec"), module.__dict__, module.__dict__)
    except SystemExit as error:
        raise RuntimeError(f"{relative} exited during import") from error
    return module


def read_trusted_source(path: Path) -> tuple[bytes, str]:
    raw = path.read_bytes()
    if not raw or raw.startswith(b"\xef\xbb\xbf") or b"\x00" in raw or b"\r" in raw or not raw.endswith(b"\n"):
        raise RuntimeError("Trusted repository source shape differs.")
    try:
        source = raw.decode("utf-8", errors="strict")
    except UnicodeDecodeError as error:
        raise RuntimeError("Trusted repository source encoding differs.") from error
    if source.encode("utf-8") != raw:
        raise RuntimeError("Trusted repository source round trip differs.")
    return raw, source


def require_exact_validator_result(completed: subprocess.CompletedProcess[bytes]) -> None:
    expected_stdout = f"Repository source contract passed.{os.linesep}".encode("ascii")
    if (
        completed.returncode != 0
        or completed.stdout != expected_stdout
        or completed.stderr
    ):
        raise RuntimeError("Repository validator did not complete its exact acceptance chain.")


def contract_test_function_inventory_sha256(source: str) -> str:
    try:
        tree = ast.parse(source)
    except SyntaxError as error:
        raise RuntimeError("Hostile fixture function inventory source is invalid.") from error
    all_functions = [node for node in tree.body if isinstance(node, ast.FunctionDef)]
    independent_verifiers = [
        node
        for node in all_functions
        if node.name == "validate_validator_cli_independently"
    ]
    independent_structural_verifiers = [
        node
        for node in all_functions
        if node.name == "_validate_validator_cli_structure_independently"
    ]
    if (
        len({node.name for node in all_functions}) != len(all_functions)
        or len(independent_verifiers) != 1
        or len(independent_structural_verifiers) != 1
    ):
        raise RuntimeError("Hostile fixture function inventory is ambiguous.")
    functions = [
        node
        for node in all_functions
        if node.name
        not in {
            "validate_validator_cli_independently",
            "_validate_validator_cli_structure_independently",
        }
    ]
    source_lines = source.splitlines(keepends=True)
    parts: list[str] = []
    for function in functions:
        function_source = "".join(
            source_lines[function.lineno - 1 : function.end_lineno]
        )
        parts.extend(
            (
                function.name,
                "\0",
                str(len(function_source.encode("utf-8"))),
                "\0",
                function_source,
                "\0",
            )
        )
    return hashlib.sha256("".join(parts).encode("utf-8")).hexdigest()


def contract_test_function_sha256(source: str, name: str) -> str:
    try:
        tree = ast.parse(source)
    except SyntaxError as error:
        raise RuntimeError("Hostile fixture function source is invalid.") from error
    functions = [
        node
        for node in tree.body
        if isinstance(node, ast.FunctionDef) and node.name == name
    ]
    if len(functions) != 1:
        raise RuntimeError("Hostile fixture function source is ambiguous.")
    source_lines = source.splitlines(keepends=True)
    function = functions[0]
    function_source = "".join(source_lines[function.lineno - 1 : function.end_lineno])
    return hashlib.sha256(function_source.encode("utf-8")).hexdigest()


PYTHON_ACCEPTANCE_ROOT_PREFIX = b"mochirii-forums-python-acceptance-root-v1\0"
PYTHON_ACCEPTANCE_ROOT_PATTERNS = {
    ".github/workflows/validate-repository.yml": (
        r"(?m)^      MOCHIRII_FORUMS_PYTHON_ACCEPTANCE_ROOT_SHA256: ([0-9a-f]{64})$"
    ),
    "scripts/check-repository.ps1": (
        r"(?m)^\$expectedPythonAcceptanceRootSha256 = '([0-9a-f]{64})'$"
    ),
    "scripts/check-source-introduction.ps1": (
        r"(?m)^\$expectedPythonAcceptanceRootSha256 = '([0-9a-f]{64})'$"
    ),
    "scripts/test-source-introduction.ps1": (
        r"(?m)^\$expectedPythonAcceptanceRootSha256 = '([0-9a-f]{64})'$"
    ),
    "scripts/host-deploy.sh": (
        r'(?m)^readonly repository_python_acceptance_root_sha256="([0-9a-f]{64})"$'
    ),
}


def python_acceptance_root_sha256(validator_source: str, contract_source: str) -> str:
    if not isinstance(validator_source, str) or not isinstance(contract_source, str):
        raise RuntimeError("Trusted Python source inventory differs.")
    material = (
        PYTHON_ACCEPTANCE_ROOT_PREFIX
        + hashlib.sha256(validator_source.encode("utf-8")).hexdigest().encode("ascii")
        + b"\0"
        + hashlib.sha256(contract_source.encode("utf-8")).hexdigest().encode("ascii")
        + b"\n"
    )
    return hashlib.sha256(material).hexdigest()


def validate_python_acceptance_root_independently(
    validator_source: str,
    contract_source: str,
    consumer_sources: dict[str, str],
) -> None:
    expected = python_acceptance_root_sha256(validator_source, contract_source)
    observed: list[str] = []
    for relative, pattern in PYTHON_ACCEPTANCE_ROOT_PATTERNS.items():
        source = consumer_sources.get(relative)
        if not isinstance(source, str):
            raise RuntimeError("Trusted Python acceptance-root consumer inventory differs.")
        matches = re.findall(pattern, source)
        if len(matches) != 1:
            raise RuntimeError("Trusted Python acceptance-root binding differs.")
        observed.append(matches[0])
    if observed != [expected] * len(PYTHON_ACCEPTANCE_ROOT_PATTERNS):
        raise RuntimeError("Trusted Python acceptance root differs.")


def _validate_validator_cli_structure_independently(candidate_source: str) -> None:
    try:
        candidate_tree = ast.parse(candidate_source)
    except SyntaxError as error:
        raise RuntimeError("Repository validator independent CLI source is invalid.") from error
    candidate_mains = [
        node
        for node in candidate_tree.body
        if isinstance(node, ast.FunctionDef) and node.name == "main"
    ]
    candidate_verifiers = [
        node
        for node in candidate_tree.body
        if isinstance(node, ast.FunctionDef)
        and node.name == "validate_validator_cli_acceptance_chain"
    ]
    candidate_bootstraps = [
        node
        for node in candidate_tree.body
        if isinstance(node, ast.FunctionDef) and node.name == "_restrict_import_path"
    ]
    candidate_startup_guards = [
        node
        for node in candidate_tree.body
        if isinstance(node, ast.FunctionDef) and node.name == "_require_isolated_python"
    ]
    candidate_normalizers = [
        node
        for node in candidate_tree.body
        if isinstance(node, ast.FunctionDef) and node.name == "_normalize_import_path"
    ]
    candidate_contract_verifiers = [
        node
        for node in candidate_tree.body
        if isinstance(node, ast.FunctionDef)
        and node.name == "validate_contract_test_acceptance_chain"
    ]
    if (
        len(candidate_mains) != 1
        or len(candidate_verifiers) != 1
        or len(candidate_bootstraps) != 1
        or len(candidate_startup_guards) != 1
        or len(candidate_normalizers) != 1
        or len(candidate_contract_verifiers) != 1
        or len(candidate_tree.body) < 3
    ):
        raise RuntimeError("Repository validator independent CLI inventory differs.")
    protected_seal_names = {
        "VALIDATOR_CLI_SOURCE_SHA256",
        "CONTRACT_TEST_SOURCE_SHA256",
        "CONTRACT_TEST_FUNCTION_INVENTORY_SHA256",
        "CONTRACT_TEST_INDEPENDENT_VERIFIER_SHA256",
        "FAILED_BOOTSTRAP_TEST_SHA256",
    }
    expected_contract_seals = {
        "VALIDATOR_CLI_SOURCE_SHA256": (
            "fd5b34ca0c39695e3d597863ef2e82117b874f78f7d6787935c4ece135115d4b"
        ),
        "CONTRACT_TEST_FUNCTION_INVENTORY_SHA256": (
            "018ff6eef86744a80bc6108eb3600d663e16646bb7c1c6d7280bfb8377fe6c6e"
        ),
        "FAILED_BOOTSTRAP_TEST_SHA256": (
            "b80af8388a6d90a0d4b9de120fc930d71fd8763168db837efbcbadfaa26fcfc0"
        ),
    }
    observed_contract_seals: dict[str, str] = {}
    for node in candidate_tree.body:
        binding_names: set[str] = set()
        if isinstance(node, ast.Assign):
            binding_names.update(
                child.id
                for target in node.targets
                for child in ast.walk(target)
                if isinstance(child, ast.Name) and isinstance(child.ctx, ast.Store)
            )
        elif isinstance(node, ast.AnnAssign):
            binding_names.update(
                child.id
                for child in ast.walk(node.target)
                if isinstance(child, ast.Name) and isinstance(child.ctx, ast.Store)
            )
        elif isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            binding_names.add(node.name)
        elif isinstance(node, (ast.Import, ast.ImportFrom)):
            binding_names.update(
                alias.asname or alias.name.split(".", 1)[0] for alias in node.names
            )
        protected_bindings = binding_names & protected_seal_names
        if not protected_bindings:
            continue
        target = node.targets[0] if isinstance(node, ast.Assign) and node.targets else None
        if (
            len(protected_bindings) != 1
            or not isinstance(node, ast.Assign)
            or len(node.targets) != 1
            or not isinstance(target, ast.Name)
            or target.id not in protected_bindings
            or target.id in observed_contract_seals
            or not isinstance(node.value, ast.Constant)
            or not isinstance(node.value.value, str)
            or re.fullmatch(r"[0-9a-f]{64}", node.value.value) is None
        ):
            raise RuntimeError("Repository validator independent contract seal differs.")
        expected = expected_contract_seals.get(target.id)
        if expected is not None and node.value.value != expected:
            raise RuntimeError("Repository validator independent contract seal differs.")
        observed_contract_seals[target.id] = node.value.value
    if set(observed_contract_seals) != protected_seal_names:
        raise RuntimeError("Repository validator independent contract seal inventory differs.")
    candidate_main = candidate_mains[0]
    candidate_verifier = candidate_verifiers[0]
    candidate_bootstrap = candidate_bootstraps[0]
    candidate_startup_guard = candidate_startup_guards[0]
    candidate_normalizer = candidate_normalizers[0]
    candidate_contract_verifier = candidate_contract_verifiers[0]
    candidate_guard = candidate_tree.body[-1]
    candidate_prefix = candidate_tree.body[:-2]
    candidate_lines = candidate_source.splitlines(keepends=True)
    candidate_top_level_guards = [
        node for node in candidate_tree.body if isinstance(node, ast.If)
    ]
    bootstrap_source = "".join(
        candidate_lines[candidate_bootstrap.lineno - 1 : candidate_bootstrap.end_lineno]
    )
    startup_guard_source = "".join(
        candidate_lines[
            candidate_startup_guard.lineno - 1 : candidate_startup_guard.end_lineno
        ]
    )
    normalizer_source = "".join(
        candidate_lines[candidate_normalizer.lineno - 1 : candidate_normalizer.end_lineno]
    )
    if (
        candidate_tree.body[-2] is not candidate_main
        or candidate_main.decorator_list
        or candidate_bootstrap.decorator_list
        or candidate_startup_guard.decorator_list
        or candidate_normalizer.decorator_list
        or hashlib.sha256(bootstrap_source.encode("utf-8")).hexdigest()
        != "1fc799aeac795776b404ee7fd7179ca07aaacdcdc7f6e90b1b3da4cc997d2ccc"
        or hashlib.sha256(startup_guard_source.encode("utf-8")).hexdigest()
        != "b75c9b3d91b7e93659b3962e16c5e7c160bf35d823b19380d651ee8ee4ce5263"
        or hashlib.sha256(normalizer_source.encode("utf-8")).hexdigest()
        != "449e60a2d1e8492583e18e5d7a366b7f5a36d6a040e0994e7b6565e533b339f0"
        or len(candidate_top_level_guards) != 1
        or not isinstance(candidate_prefix[0], ast.Expr)
        or not isinstance(candidate_prefix[0].value, ast.Constant)
        or not isinstance(candidate_prefix[0].value.value, str)
        or any(
            not isinstance(
                node,
                (ast.Import, ast.ImportFrom, ast.Assign, ast.AnnAssign, ast.FunctionDef),
            )
            for node in candidate_prefix[1:]
        )
        or any(
            node.decorator_list
            for node in candidate_prefix
            if isinstance(node, ast.FunctionDef)
        )
        or not isinstance(candidate_guard, ast.If)
        or not isinstance(candidate_guard.test, ast.Compare)
        or not isinstance(candidate_guard.test.left, ast.Name)
        or candidate_guard.test.left.id != "__name__"
        or len(candidate_guard.test.ops) != 1
        or not isinstance(candidate_guard.test.ops[0], ast.Eq)
        or len(candidate_guard.test.comparators) != 1
        or not isinstance(candidate_guard.test.comparators[0], ast.Constant)
        or candidate_guard.test.comparators[0].value != "__main__"
        or len(candidate_guard.body) != 1
        or candidate_guard.orelse
        or not isinstance(candidate_guard.body[0], ast.Raise)
        or not isinstance(candidate_guard.body[0].exc, ast.Call)
        or not isinstance(candidate_guard.body[0].exc.func, ast.Name)
        or candidate_guard.body[0].exc.func.id != "SystemExit"
        or len(candidate_guard.body[0].exc.args) != 1
        or not isinstance(candidate_guard.body[0].exc.args[0], ast.Call)
        or not isinstance(candidate_guard.body[0].exc.args[0].func, ast.Name)
        or candidate_guard.body[0].exc.args[0].func.id != "main"
    ):
        raise RuntimeError("Repository validator independent CLI structure differs.")
    imports_source = "".join(
        "".join(candidate_lines[node.lineno - 1 : node.end_lineno])
        for node in candidate_prefix
        if isinstance(node, (ast.Import, ast.ImportFrom))
    )
    if (
        hashlib.sha256(imports_source.encode("utf-8")).hexdigest()
        != "6fdcb8330b583d3fb8d485cf9e335e8494f736c9c117662fcf547e4e09491162"
    ):
        raise RuntimeError("Repository validator independent import boundary differs.")
    executable_assignments = {
        "_PYTHON_STARTUP_RESTRICTED": "91f125795440732972fea9b9921f0a53e3f4334553d0dc12cde71d0e88795633",
        "_IMPORT_PATH_RESTRICTED": "c79c8ef7ffac8557ec250e0b05c3b15939ebb3b728e62315486e24a98e156461",
        "ROOT": "6c0caf441a1aad2240e7aaccbb2a73915fc5ce62a90eb857836d905c68760c7d",
        "MANAGED_WEB_SSL_SERVER_OUTLET": "611b3941a610ea9d23805d773cbba7dbf7ce57c06b2355f10d65a8720196c8e0",
        "EXPECTED_SERVER_TLS_SHA256": "885cfdce0ad10ad670c604584bf51bc0e05027d1e6ab92cf45b35a23209914ce",
        "ALLOWED_FILES": "2830164c191da98529cb8134eccfc4dd30891049e912e9625e767b2531283661",
    }
    observed_executable_assignments = set()
    forbidden_assignment_nodes = (
        ast.Await,
        ast.GeneratorExp,
        ast.IfExp,
        ast.Lambda,
        ast.ListComp,
        ast.NamedExpr,
        ast.SetComp,
        ast.DictComp,
        ast.Yield,
        ast.YieldFrom,
    )
    for node in candidate_prefix:
        if isinstance(node, ast.FunctionDef):
            defaults = [*node.args.defaults, *node.args.kw_defaults]
            if any(
                isinstance(child, ast.Call)
                for default in defaults
                if default is not None
                for child in ast.walk(default)
            ):
                raise RuntimeError(
                    "Repository validator independent function definition executes early."
                )
        if not isinstance(node, (ast.Assign, ast.AnnAssign)):
            continue
        targets = node.targets if isinstance(node, ast.Assign) else [node.target]
        if len(targets) != 1 or not isinstance(targets[0], ast.Name):
            raise RuntimeError("Repository validator independent assignment target differs.")
        target = targets[0].id
        calls = [child for child in ast.walk(node) if isinstance(child, ast.Call)]
        if calls:
            assignment_source = "".join(candidate_lines[node.lineno - 1 : node.end_lineno])
            expected = executable_assignments.get(target)
            if (
                expected is None
                or hashlib.sha256(assignment_source.encode("utf-8")).hexdigest() != expected
            ):
                raise RuntimeError(
                    "Repository validator independent executable assignment differs."
                )
            observed_executable_assignments.add(target)
        elif any(
            isinstance(child, forbidden_assignment_nodes) for child in ast.walk(node)
        ):
            raise RuntimeError("Repository validator independent assignment can execute early.")
    if observed_executable_assignments != set(executable_assignments):
        raise RuntimeError(
            "Repository validator independent executable assignment inventory differs."
        )
    verifier_source = "".join(
        candidate_lines[candidate_verifier.lineno - 1 : candidate_verifier.end_lineno]
    )
    contract_verifier_source = "".join(
        candidate_lines[
            candidate_contract_verifier.lineno - 1 : candidate_contract_verifier.end_lineno
        ]
    )
    entrypoint_source = "".join(
        candidate_lines[candidate_main.lineno - 1 : candidate_guard.end_lineno]
    )
    if (
        hashlib.sha256(verifier_source.encode("utf-8")).hexdigest()
        != "6668eda049f2d14d63ab7da7421faebe41d94d09f73d8420eec77d81d5f2f284"
        or hashlib.sha256(contract_verifier_source.encode("utf-8")).hexdigest()
        != "43ab4b67ad4220227eedccd2815a7b487bbec0c65f62d770890461c3d606bdc8"
        or hashlib.sha256(entrypoint_source.encode("utf-8")).hexdigest()
        != "fd5b34ca0c39695e3d597863ef2e82117b874f78f7d6787935c4ece135115d4b"
    ):
        raise RuntimeError("Repository validator independent CLI source seal differs.")


def validate_validator_cli_independently(
    candidate_source: str,
    candidate_contract_source: str,
    consumer_sources: dict[str, str],
) -> None:
    validate_python_acceptance_root_independently(
        candidate_source, candidate_contract_source, consumer_sources
    )
    _validate_validator_cli_structure_independently(candidate_source)


EXACT_VALIDATOR_WRAPPER = '''import sys
path = sys.argv[1]
source = sys.stdin.buffer.read()
arguments = sys.argv[2:]
sys.argv = [path, *arguments]
namespace = {"__name__": "__main__", "__file__": path, "__package__": None, "__cached__": None}
exec(compile(source, path, "exec"), namespace, namespace)
'''


def metadata_is_link_or_reparse(metadata: os.stat_result) -> bool:
    return stat.S_ISLNK(metadata.st_mode) or bool(
        getattr(metadata, "st_file_attributes", 0)
        & getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0)
    )


def exact_validator_archive_root(path: Path) -> Path | None:
    if path.name != "validate-repository.py" or path.parent.name != "scripts":
        raise RuntimeError("Repository validator source boundary differs.")
    scripts_directory = path.parent
    repository_root = scripts_directory.parent
    root_metadata = repository_root.lstat()
    scripts_metadata = scripts_directory.lstat()
    metadata = path.lstat()
    if (
        metadata_is_link_or_reparse(root_metadata)
        or not stat.S_ISDIR(root_metadata.st_mode)
        or metadata_is_link_or_reparse(scripts_metadata)
        or not stat.S_ISDIR(scripts_metadata.st_mode)
        or metadata_is_link_or_reparse(metadata)
        or not stat.S_ISREG(metadata.st_mode)
    ):
        raise RuntimeError("Repository validator source boundary differs.")
    resolved = path.resolve(strict=True)
    resolved_scripts = scripts_directory.resolve(strict=True)
    resolved_root = repository_root.resolve(strict=True)
    if (
        resolved.parent != resolved_scripts
        or resolved_scripts.parent != resolved_root
    ):
        raise RuntimeError("Repository validator root boundary differs.")
    git_boundary = resolved_root / ".git"
    try:
        git_metadata = git_boundary.lstat()
    except FileNotFoundError:
        return resolved_root
    if metadata_is_link_or_reparse(git_metadata) or not (
        stat.S_ISREG(git_metadata.st_mode) or stat.S_ISDIR(git_metadata.st_mode)
    ):
        raise RuntimeError("Repository validator Git boundary differs.")
    return None


def run_exact_validator(path: Path, source: bytes) -> subprocess.CompletedProcess[bytes]:
    archive_root = exact_validator_archive_root(path)
    arguments = [
        sys.executable,
        "-I",
        "-S",
        "-B",
        "-c",
        EXACT_VALIDATOR_WRAPPER,
        str(path),
    ]
    if archive_root is not None:
        arguments.extend(("--archive-root", str(archive_root)))
    child_environment = {
        key: value
        for key, value in os.environ.items()
        if not key.startswith("GIT_CONFIG_")
    }
    child_environment.update(
        {
            "PYTHONDONTWRITEBYTECODE": "1",
            "GIT_CONFIG_COUNT": "1",
            "GIT_CONFIG_KEY_0": "safe.directory",
            "GIT_CONFIG_VALUE_0": str(path.parents[1].resolve()),
        }
    )
    return subprocess.run(
        arguments,
        cwd=path.parents[1],
        env=child_environment,
        input=source,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        timeout=300,
        check=False,
    )


TRUSTED_QUARANTINE_BYTES, TRUSTED_QUARANTINE_SOURCE = read_trusted_source(
    ROOT / "scripts/quarantine-failed-bootstrap.sh"
)
TRUSTED_UPGRADER_BYTES, TRUSTED_UPGRADER_SOURCE = read_trusted_source(
    ROOT / "scripts/upgrade-host-control.sh"
)
TRUSTED_VALIDATOR_BYTES, TRUSTED_VALIDATOR_SOURCE = read_trusted_source(
    ROOT / "scripts/validate-repository.py"
)
TRUSTED_CONTRACT_BYTES, TRUSTED_CONTRACT_SOURCE = read_trusted_source(
    ROOT / "scripts/test-contracts.py"
)
TRUSTED_PYTHON_ACCEPTANCE_CONSUMER_SOURCES = {
    ".github/workflows/validate-repository.yml": read_trusted_source(
        ROOT / ".github/workflows/validate-repository.yml"
    )[1],
    "scripts/check-repository.ps1": read_trusted_source(
        ROOT / "scripts/check-repository.ps1"
    )[1],
    "scripts/check-source-introduction.ps1": read_trusted_source(
        ROOT / "scripts/check-source-introduction.ps1"
    )[1],
    "scripts/test-source-introduction.ps1": read_trusted_source(
        ROOT / "scripts/test-source-introduction.ps1"
    )[1],
    "scripts/host-deploy.sh": read_trusted_source(ROOT / "scripts/host-deploy.sh")[1],
}
TRUSTED_WORKFLOW_BYTES, TRUSTED_WORKFLOW_SOURCE = read_trusted_source(
    ROOT / ".github/workflows/deploy-forums.yml"
)
TRUSTED_MANIFEST_BYTES, TRUSTED_MANIFEST_SOURCE = read_trusted_source(
    ROOT / "config/host-control-manifest.v1.json"
)
validate_validator_cli_independently(
    TRUSTED_VALIDATOR_SOURCE,
    TRUSTED_CONTRACT_SOURCE,
    TRUSTED_PYTHON_ACCEPTANCE_CONSUMER_SOURCES,
)
require_exact_validator_result(
    run_exact_validator(ROOT / "scripts/validate-repository.py", TRUSTED_VALIDATOR_BYTES)
)
RENDER = module_from("scripts/render-app-config.py", "render_app_config")
THEME = module_from("scripts/build-theme-archive.py", "build_theme_archive")
ROTATE = module_from("scripts/rotate-media-certificate.py", "rotate_media_certificate")
UPSTREAM = module_from("scripts/verify-pinned-source.py", "verify_pinned_source")
VALIDATOR = module_from_source(
    "scripts/validate-repository.py", "validate_repository", TRUSTED_VALIDATOR_BYTES
)
if (
    VALIDATOR.CONTRACT_TEST_SOURCE_SHA256
    != hashlib.sha256(TRUSTED_CONTRACT_BYTES).hexdigest()
    or VALIDATOR.CONTRACT_TEST_FUNCTION_INVENTORY_SHA256
    != contract_test_function_inventory_sha256(TRUSTED_CONTRACT_SOURCE)
    or VALIDATOR.CONTRACT_TEST_INDEPENDENT_VERIFIER_SHA256
    != contract_test_function_sha256(
        TRUSTED_CONTRACT_SOURCE, "validate_validator_cli_independently"
    )
    or VALIDATOR.FAILED_BOOTSTRAP_TEST_SHA256
    != hashlib.sha256(
        "".join(
            TRUSTED_CONTRACT_SOURCE.splitlines(keepends=True)[
                next(
                    node.lineno
                    for node in ast.parse(TRUSTED_CONTRACT_SOURCE).body
                    if isinstance(node, ast.FunctionDef)
                    and node.name == "test_failed_bootstrap_quarantine_contract"
                )
                - 1 : next(
                    node.end_lineno
                    for node in ast.parse(TRUSTED_CONTRACT_SOURCE).body
                    if isinstance(node, ast.FunctionDef)
                    and node.name == "test_failed_bootstrap_quarantine_contract"
                )
            ]
        ).encode("utf-8")
    ).hexdigest()
):
    raise RuntimeError("Repository validator hostile-fixture source seals differ.")
AUTHENTICATION = module_from("scripts/authentication-state.py", "authentication_state")
CONNECT_FIXTURE = module_from("scripts/verify-discourse-connect.py", "verify_discourse_connect")
PRODUCER_PROBE = module_from("scripts/probe-website-forums-producer.py", "probe_website_forums_producer")
PUBLIC_BRANDING = module_from("scripts/verify-public-branding.py", "verify_public_branding")


@contextlib.contextmanager
def environment(values: dict[str, str]):
    previous = os.environ.copy()
    os.environ.clear()
    os.environ.update(values)
    try:
        yield
    finally:
        os.environ.clear()
        os.environ.update(previous)


@contextlib.contextmanager
def process_umask(mode: int):
    previous = os.umask(mode)
    try:
        yield
    finally:
        os.umask(previous)


def expect_render_error(
    values: dict[str, str],
    mutation: tuple[str, str] | None = None,
    *,
    repository_commit: str = "1" * 40,
) -> None:
    candidate = dict(values)
    if mutation:
        candidate[mutation[0]] = mutation[1]
    with tempfile.TemporaryDirectory(prefix="mochirii-render-reject-") as directory:
        try:
            RENDER.render(
                "production",
                Path(directory) / "app.yml",
                runtime_values=candidate,
                repository_commit=repository_commit,
            )
        except RENDER.RenderError:
            return
    raise RuntimeError(f"Production renderer accepted hostile input: {mutation}")


def test_renderer() -> None:
    commit = "a" * 40
    production = {
        "FORUMS_ACTIVATION_ENABLED": "true",
        "FORUMS_DEVELOPER_EMAILS": "operator@example.invalid",
        "FORUMS_DISCOURSE_CONNECT_ENABLED": "true",
        "FORUMS_DISCOURSE_CONNECT_SECRET": "a" * 64,
        "FORUMS_S3_ACCESS_KEY_ID": "fixture-key-not-real",
        "FORUMS_S3_SECRET_ACCESS_KEY": "fixture-storage-secret-not-real",
        "FORUMS_SMTP_ADDRESS": "smtp.example.invalid",
        "FORUMS_SMTP_PORT": "465",
        "FORUMS_SMTP_USER_NAME": "fixture-user",
        "FORUMS_SMTP_PASSWORD": "fixture-password-#-$-not-real",
        "FORUMS_SMTP_AUTHENTICATION": "plain",
        "FORUMS_NOTIFICATION_EMAIL": "notifications@mochirii.com",
    }

    expect_render_error({})
    for required in (
        "FORUMS_DEVELOPER_EMAILS",
        "FORUMS_S3_ACCESS_KEY_ID",
        "FORUMS_S3_SECRET_ACCESS_KEY",
        "FORUMS_SMTP_ADDRESS",
        "FORUMS_SMTP_PORT",
        "FORUMS_SMTP_USER_NAME",
        "FORUMS_SMTP_PASSWORD",
        "FORUMS_SMTP_AUTHENTICATION",
        "FORUMS_NOTIFICATION_EMAIL",
        "FORUMS_DISCOURSE_CONNECT_SECRET",
    ):
        candidate = dict(production)
        candidate.pop(required)
        expect_render_error(candidate)

    hostile = (
        ("FORUMS_DEVELOPER_EMAILS", "a@example.invalid\nb@example.invalid"),
        ("FORUMS_SMTP_ADDRESS", "127.0.0.1"),
        ("FORUMS_SMTP_ADDRESS", "smtp.example.invalid\nDISCOURSE_SKIP_EMAIL_SETUP=1"),
        ("FORUMS_SMTP_PORT", "0"),
        ("FORUMS_SMTP_PORT", "65536"),
        ("FORUMS_SMTP_AUTHENTICATION", "none"),
        ("FORUMS_S3_SECRET_ACCESS_KEY", "bad\nvalue"),
        ("FORUMS_DISCOURSE_CONNECT_SECRET", "a" * 63),
        ("FORUMS_DISCOURSE_CONNECT_SECRET", "A" * 64),
        ("FORUMS_DISCOURSE_CONNECT_SECRET", "g" * 64),
        ("FORUMS_NOTIFICATION_EMAIL", "notifications@example.invalid"),
    )
    for mutation in hostile:
        expect_render_error(production, mutation)

    with tempfile.TemporaryDirectory(prefix="mochirii-render-pass-") as directory:
        output = Path(directory) / "app.yml"
        RENDER.render("production", output, runtime_values=production, repository_commit=commit)
        rendered = output.read_text(encoding="utf-8")
        if "__MOCHIRII_" in rendered or commit not in rendered:
            raise RuntimeError("Production rendering did not resolve and bind every token.")
        if 'DISCOURSE_ENABLE_DISCOURSE_CONNECT: "true"' not in rendered:
            raise RuntimeError("Explicit DiscourseConnect activation was lost.")
        if 'fixture-password-#-$-not-real' not in rendered:
            raise RuntimeError("Quoted SMTP fixture did not survive exact rendering.")
        tls_required = (
            '  - "templates/web.ssl.template.yml"',
            "acme-sh-3.0.6.gz.b64",
            "400d1a96ef72a1f27fe79c7f0e6d4e4f600c0509c0cd787db00931b9258c54da",
            "--auto-upgrade 0",
            "NO_DETECT_SH=1",
            "/usr/local/bin/mochirii-acme-cron",
        )
        if any(value not in rendered for value in tls_required):
            raise RuntimeError("Production rendering lost the immutable TLS integration.")
        if "web.letsencrypt.ssl.template.yml" in rendered or "curl " in rendered or "--upgrade" in rendered:
            raise RuntimeError("Production rendering reintroduced floating TLS client source.")
        if os.name != "nt" and stat.S_IMODE(output.stat().st_mode) != 0o600:
            raise RuntimeError("Rendered runtime configuration is not mode 0600.")

    with tempfile.TemporaryDirectory(prefix="mochirii-render-restore-") as directory:
        output = Path(directory) / "app.yml"
        RENDER.render("disposable-restore", output, runtime_values=production, repository_commit=commit)
        rendered = output.read_text(encoding="utf-8")
        required = (
            '127.0.0.1:18080:80',
            'DISCOURSE_DISABLE_EMAILS: "yes"',
            'DISCOURSE_ENABLE_DISCOURSE_CONNECT: "false"',
            'DISCOURSE_ENABLE_S3_UPLOADS: "true"',
        )
        if any(value not in rendered for value in required):
            raise RuntimeError("Disposable restore rendering did not fail closed.")
        if any(value in rendered for value in ("acme-sh-3.0.6", "mochirii-acme-cron", "DISCOURSE_FORCE_HTTPS")):
            raise RuntimeError("Disposable restore rendering activated the public TLS client.")

    expect_render_error(production, repository_commit="ABC")
    disabled_with_secret = dict(production)
    disabled_with_secret["FORUMS_DISCOURSE_CONNECT_ENABLED"] = "false"
    expect_render_error(disabled_with_secret)
    with tempfile.TemporaryDirectory(prefix="mochirii-runtime-json-") as directory:
        runtime_json = Path(directory) / "runtime.json"
        runtime_json.write_text(json.dumps(production), encoding="utf-8")
        if os.name != "nt":
            runtime_json.chmod(0o600)
        loaded = RENDER.load_protected_runtime(runtime_json)
        if loaded != production:
            raise RuntimeError("Protected literal runtime JSON changed during parsing.")
        runtime_json.write_text(json.dumps({**production, "PATH": "/hostile"}), encoding="utf-8")
        if os.name != "nt":
            runtime_json.chmod(0o600)
        try:
            RENDER.load_protected_runtime(runtime_json)
        except RENDER.RenderError:
            pass
        else:
            raise RuntimeError("Protected runtime JSON accepted an arbitrary environment name.")

        symlink = Path(directory) / "runtime-link.json"
        try:
            symlink.symlink_to(runtime_json)
        except OSError:
            if os.name != "nt":
                raise
        else:
            try:
                RENDER.load_protected_runtime(symlink)
            except RENDER.RenderError as error:
                if "regular file" not in str(error):
                    raise RuntimeError("Renderer rejected a symlink for the wrong reason.") from error
            else:
                raise RuntimeError("Renderer followed a protected runtime JSON symlink.")

    with tempfile.TemporaryDirectory(prefix="mochirii-rotation-symlink-") as directory:
        target = Path(directory) / "runtime.json"
        target.write_text(
            json.dumps(
                {
                    "providerApiToken": "fixture-provider-token-not-real-00000000",
                    "cdnEndpointId": "00000000-0000-4000-8000-000000000000",
                    "cdnOrigin": "mochirii-forums.sgp1.digitaloceanspaces.com",
                }
            ),
            encoding="utf-8",
        )
        if os.name != "nt":
            target.chmod(0o600)
        symlink = Path(directory) / "runtime-link.json"
        try:
            symlink.symlink_to(target)
        except OSError:
            if os.name != "nt":
                raise
        else:
            try:
                ROTATE.protected_runtime(symlink)
            except ROTATE.RotationError as error:
                if "regular file" not in str(error):
                    raise RuntimeError("Rotation rejected a symlink for the wrong reason.") from error
            else:
                raise RuntimeError("Rotation followed a protected runtime JSON symlink.")

    with tempfile.TemporaryDirectory(prefix="mochirii-render-fixture-") as directory:
        output = Path(directory) / "app.yml"
        with environment({"FORUMS_REPOSITORY_COMMIT": commit}):
            RENDER.render("stage4-fixture", output)
        rendered = output.read_text(encoding="utf-8")
        required = (
            '127.0.0.1:18080:80',
            'MOCHIRII_STAGE4_FIXTURE: "true"',
            'DISCOURSE_DEVELOPER_EMAILS: "stage4-developer@example.invalid"',
            'DISCOURSE_ENABLE_S3_UPLOADS: "false"',
            'DISCOURSE_ENABLE_DISCOURSE_CONNECT: "false"',
            commit,
        )
        if any(value not in rendered for value in required):
            raise RuntimeError("Stage 4 fixture is not loopback-only and externally inactive.")
        if (
            rendered.count(LOCALIZED_ERROR_COPY_BLOCK) != 1
            or rendered.count("for status in 403 422 500 503; do") != 1
        ):
            raise RuntimeError("Rendered localized error-page copy lost its exact literal shell contract.")
        if rendered.count(NGINX_LOG_DIRECTORY_BLOCK) != 1:
            raise RuntimeError("Rendered Nginx validation lost its exact persistent log-directory contract.")

    if os.name != "nt":
        localized_names = [
            "locale space",
            "line\nbreak",
            "-leading-dash",
            *(f"locale-{index:02d}" for index in range(3, 48)),
        ]

        def prepare_error_pages(directory: str) -> tuple[Path, list[tuple[Path, Path]]]:
            public = Path(directory) / "public"
            public.mkdir()
            pairs: list[tuple[Path, Path]] = []
            for status in (403, 422, 500, 503):
                source = public / f"{status}.html"
                source.write_bytes(f"branded-{status}\n".encode("ascii"))
                source.chmod(0o644)
                for index, locale in enumerate(localized_names):
                    target = public / f"{status}.{locale}.html"
                    target.write_bytes(b"upstream-content\n")
                    target.chmod(0o600 if index == 0 else 0o644)
                    pairs.append((source, target))
            return public, pairs

        def run_error_page_copy(directory: str, *, path: str | None = None) -> subprocess.CompletedProcess[str]:
            return subprocess.run(
                ["sh", "-c", LOCALIZED_ERROR_COPY_COMMAND],
                cwd=directory,
                env={"LC_ALL": "C", "PATH": path or os.environ.get("PATH", "/usr/bin:/bin")},
                text=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                timeout=20,
                check=False,
            )

        with tempfile.TemporaryDirectory(prefix="mochirii-error-pages-pass-") as directory:
            public, pairs = prepare_error_pages(directory)
            identities = {
                target: (target.stat().st_uid, target.stat().st_gid, stat.S_IMODE(target.stat().st_mode))
                for _, target in pairs
            }
            result = run_error_page_copy(directory)
            if result.returncode != 0:
                raise RuntimeError("Localized error-page copy rejected its exact safe inventory.")
            if len(list(public.glob("*.html"))) != 196:
                raise RuntimeError("Localized error-page copy changed the exact inventory.")
            for source, target in pairs:
                identity = (target.stat().st_uid, target.stat().st_gid, stat.S_IMODE(target.stat().st_mode))
                if target.read_bytes() != source.read_bytes() or identity != identities[target]:
                    raise RuntimeError("Localized error-page copy changed content or file identity incorrectly.")

        for scenario in ("missing", "extra", "symlink", "false-success"):
            with tempfile.TemporaryDirectory(prefix=f"mochirii-error-pages-{scenario}-") as directory:
                public, pairs = prepare_error_pages(directory)
                path = None
                if scenario == "missing":
                    pairs[0][1].unlink()
                elif scenario == "extra":
                    (public / "403.extra.html").write_bytes(b"unexpected\n")
                elif scenario == "symlink":
                    victim = Path(directory) / "victim"
                    victim.write_bytes(b"victim-must-survive\n")
                    pairs[0][1].unlink()
                    pairs[0][1].symlink_to(victim)
                else:
                    fake_bin = Path(directory) / "bin"
                    fake_bin.mkdir()
                    fake_cp = fake_bin / "cp"
                    true_command = shutil.which("true")
                    if true_command is None:
                        raise RuntimeError("Localized error-page hostile fixture cannot locate true(1).")
                    fake_cp.symlink_to(true_command)
                    path = f"{fake_bin}{os.pathsep}{os.environ.get('PATH', '/usr/bin:/bin')}"
                result = run_error_page_copy(directory, path=path)
                if result.returncode == 0:
                    raise RuntimeError(f"Localized error-page copy accepted hostile {scenario} state.")
                if scenario == "symlink" and (Path(directory) / "victim").read_bytes() != b"victim-must-survive\n":
                    raise RuntimeError("Localized error-page copy followed a hostile symlink.")

    connect_fixture = "b" * 64
    with tempfile.TemporaryDirectory(prefix="mochirii-render-connect-fixture-") as directory:
        output = Path(directory) / "app.yml"
        values = {
            "FORUMS_REPOSITORY_COMMIT": commit,
            "FORUMS_FIXTURE_DISCOURSE_CONNECT_SECRET": connect_fixture,
        }
        with environment(values):
            RENDER.render("stage4-connect-fixture", output)
        rendered = output.read_text(encoding="utf-8")
        required = (
            '127.0.0.1:18080:80',
            'MOCHIRII_STAGE4_FIXTURE: "true"',
            'MOCHIRII_STAGE4_CONNECT_FIXTURE: "true"',
            'DISCOURSE_DEVELOPER_EMAILS: "stage4-developer@example.invalid"',
            'DISCOURSE_ENABLE_DISCOURSE_CONNECT: "true"',
            connect_fixture,
        )
        if any(value not in rendered for value in required):
            raise RuntimeError("Stage 4 DiscourseConnect fixture lost its exact loopback contract.")

    with tempfile.TemporaryDirectory(prefix="mochirii-render-connect-reject-") as directory:
        with environment(
            {
                "FORUMS_REPOSITORY_COMMIT": commit,
                "FORUMS_FIXTURE_DISCOURSE_CONNECT_SECRET": "B" * 64,
            }
        ):
            try:
                RENDER.render("stage4-connect-fixture", Path(directory) / "app.yml")
            except RENDER.RenderError:
                pass
            else:
                raise RuntimeError("Stage 4 DiscourseConnect fixture accepted a non-lowercase key.")


def test_acme_install_byte_stability() -> None:
    tls = (ROOT / "config/immutable-letsencrypt.fragment.yml").read_text(encoding="utf-8")
    VALIDATOR.validate_immutable_acme_install_contract(tls)
    host_verifier = (ROOT / "scripts/verify-host.sh").read_text(encoding="utf-8")
    VALIDATOR.validate_acme_host_private_state_contract(host_verifier)

    def reject_resealed_tls(hostile: str, label: str) -> None:
        if hostile == tls:
            raise RuntimeError(f"{label} hostile did not change the production fragment.")
        original_fragment_sha = VALIDATOR.IMMUTABLE_LETSENCRYPT_FRAGMENT_SHA256
        original_configure_sha = VALIDATOR.CONFIGURE_LETSENCRYPT_SHA256
        original_executable_sha = VALIDATOR.IMMUTABLE_LETSENCRYPT_EXECUTABLE_SHA256
        original_run_sha = VALIDATOR.IMMUTABLE_LETSENCRYPT_RUN_SHA256
        VALIDATOR.IMMUTABLE_LETSENCRYPT_FRAGMENT_SHA256 = hashlib.sha256(hostile.encode("utf-8")).hexdigest()
        configure = VALIDATOR.yaml_executable_file_contents(hostile, "/usr/local/bin/configure-letsencrypt")
        letsencrypt_hostile = VALIDATOR.yaml_executable_file_contents(
            hostile,
            "/usr/local/bin/letsencrypt",
            "# MOCHIRII TLS RUN END\n",
        )
        run_begin = "# MOCHIRII TLS RUN BEGIN\n"
        run_end = "# MOCHIRII TLS RUN END\n"
        run_section = hostile[hostile.index(run_begin) + len(run_begin) : hostile.index(run_end)]
        VALIDATOR.CONFIGURE_LETSENCRYPT_SHA256 = hashlib.sha256(configure.encode("utf-8")).hexdigest()
        VALIDATOR.IMMUTABLE_LETSENCRYPT_EXECUTABLE_SHA256 = hashlib.sha256(
            letsencrypt_hostile.encode("utf-8")
        ).hexdigest()
        VALIDATOR.IMMUTABLE_LETSENCRYPT_RUN_SHA256 = hashlib.sha256(run_section.encode("utf-8")).hexdigest()
        try:
            VALIDATOR.validate_immutable_acme_install_contract(hostile)
        except RuntimeError:
            pass
        else:
            raise RuntimeError(f"Actual validator accepted the resealed {label} hostile.")
        finally:
            VALIDATOR.IMMUTABLE_LETSENCRYPT_FRAGMENT_SHA256 = original_fragment_sha
            VALIDATOR.CONFIGURE_LETSENCRYPT_SHA256 = original_configure_sha
            VALIDATOR.IMMUTABLE_LETSENCRYPT_EXECUTABLE_SHA256 = original_executable_sha
            VALIDATOR.IMMUTABLE_LETSENCRYPT_RUN_SHA256 = original_run_sha

    exact_reload = "/usr/sbin/nginx -c /etc/nginx/letsencrypt.conf -s reload"
    cron = VALIDATOR.yaml_executable_file_contents(tls, "/usr/local/bin/mochirii-acme-cron")
    letsencrypt = VALIDATOR.yaml_executable_file_contents(
        tls,
        "/usr/local/bin/letsencrypt",
        "# MOCHIRII TLS RUN END\n",
    )
    validator_begin = "# MOCHIRII CERTIFICATE MATERIAL VALIDATOR BEGIN\n"
    validator_end = "# MOCHIRII CERTIFICATE MATERIAL VALIDATOR END\n"
    stage_tool_begin = "# MOCHIRII ACME STAGE TOOL BEGIN\n"
    stage_tool_end = "# MOCHIRII ACME STAGE TOOL END\n"
    stage_preflight_begin = "# MOCHIRII ACME STAGE PREFLIGHT BEGIN\n"
    stage_preflight_end = "# MOCHIRII ACME STAGE PREFLIGHT END\n"
    installed_validator_begin = "# MOCHIRII INSTALLED CERTIFICATE VALIDATOR BEGIN\n"
    installed_validator_end = "# MOCHIRII INSTALLED CERTIFICATE VALIDATOR END\n"
    order_begin = "# MOCHIRII ACME ORDER BEGIN\n"
    order_end = "# MOCHIRII ACME ORDER END\n"
    if any(
        letsencrypt.count(marker) != 1
        for marker in (
            validator_begin,
            validator_end,
            stage_tool_begin,
            stage_tool_end,
            stage_preflight_begin,
            stage_preflight_end,
            installed_validator_begin,
            installed_validator_end,
            order_begin,
            order_end,
        )
    ):
        raise RuntimeError("Production certificate stage, installed validator, material validator, or ordering boundary differs.")
    stage_tool_source = letsencrypt[
        letsencrypt.index(stage_tool_begin) + len(stage_tool_begin) : letsencrypt.index(stage_tool_end)
    ]
    stage_preflight_source = letsencrypt[
        letsencrypt.index(stage_preflight_begin) + len(stage_preflight_begin) : letsencrypt.index(stage_preflight_end)
    ]
    installed_validator_source = letsencrypt[
        letsencrypt.index(installed_validator_begin)
        + len(installed_validator_begin) : letsencrypt.index(installed_validator_end)
    ]
    stage_python = stage_tool_source.split("<<'PY'\n", 1)[1].rsplit("\nPY\n", 1)[0] + "\n"
    ast.parse(stage_python)
    installed_python = installed_validator_source.split(
        "<<'PY_INSTALLED' >/dev/null 2>&1\n",
        1,
    )[1].rsplit(
        "\nPY_INSTALLED\n",
        1,
    )[0] + "\n"
    ast.parse(installed_python)
    host_stage_begin = "# MOCHIRII ACME STAGE VERIFIER BEGIN\n"
    host_stage_end = "# MOCHIRII ACME STAGE VERIFIER END\n"
    if host_verifier.count(host_stage_begin) != 1 or host_verifier.count(host_stage_end) != 1:
        raise RuntimeError("Host ACME stage verifier boundary differs.")
    host_stage_source = host_verifier[
        host_verifier.index(host_stage_begin) + len(host_stage_begin) : host_verifier.index(host_stage_end)
    ]
    host_stage_python = host_stage_source.split(
        "<<'PY_ACME_STAGE' >/dev/null 2>&1 || fail "
        '"Private ACME stage evidence is not terminal for the exact release."\n',
        1,
    )[1].rsplit(
        "\nPY_ACME_STAGE\n",
        1,
    )[0] + "\n"
    ast.parse(host_stage_python)
    successful_stage_tokens = (
        "01-rsa-issue-entered",
        "02-rsa-issue-completed",
        "03-rsa-validation-entered",
        "04-rsa-validation-completed",
        "05-rsa-install-entered",
        "06-rsa-install-completed",
        "07-ecc-issue-entered",
        "08-ecc-issue-completed",
        "09-ecc-validation-entered",
        "10-ecc-validation-completed",
        "11-ecc-install-entered",
        "12-ecc-install-completed",
        "13-reload-entered",
        "14-reload-completed",
        "15-terminal-completed",
    )
    certificate_validator_source = letsencrypt[
        letsencrypt.index(validator_begin) + len(validator_begin) : letsencrypt.index(validator_end)
    ]
    acme_order_source = letsencrypt[
        letsencrypt.index(order_begin) + len(order_begin) : letsencrypt.index(order_end)
    ]
    issue_source = letsencrypt[
        letsencrypt.index("issue_certificate() {\n") : letsencrypt.index("\n\ninstall_certificate() {\n")
    ]
    install_source = letsencrypt[
        letsencrypt.index("install_certificate() {\n") : letsencrypt.index("\n\n" + installed_validator_begin)
    ]
    cron_call = '''env AUTO_UPGRADE=0 LE_WORKING_DIR="${letsencrypt_dir}" \\
  "${letsencrypt_dir}/acme.sh" --cron --home "${letsencrypt_dir}"'''
    rsa_install = 'install_certificate "" ""'
    ecc_install = 'install_certificate "_ecc" "--ecc"'
    directory_verification = '''test -d "${letsencrypt_dir}"
test ! -L "${letsencrypt_dir}"
test "$(stat -c '%U:%G %a' -- "${letsencrypt_dir}")" = "root:root 755"'''
    directory_normalization = '''if test -e "${letsencrypt_dir}" || test -L "${letsencrypt_dir}"; then
  test -d "${letsencrypt_dir}"
  test ! -L "${letsencrypt_dir}"
  chown root:root -- "${letsencrypt_dir}"
  chmod 0755 -- "${letsencrypt_dir}"
else
  install -d -m 0755 -g root -o root "${letsencrypt_dir}"
fi
test -d "${letsencrypt_dir}"
test ! -L "${letsencrypt_dir}"
test "$(stat -c '%U:%G %a' -- "${letsencrypt_dir}")" = "root:root 755"'''
    private_verification = '''for private_path in "${letsencrypt_dir}/account.conf" "${letsencrypt_dir}/acme.sh.log"; do
  test -f "${private_path}"
  test ! -L "${private_path}"
  test "$(stat -c '%U:%G %a %h' -- "${private_path}")" = "root:root 600 1"
done'''
    challenge_paths = '''readonly public_webroot="/var/www/discourse/public"
readonly challenge_parent="${public_webroot}/.well-known"
readonly challenge_root="${challenge_parent}/acme-challenge"'''
    challenge_preparation = '''test -d "${public_webroot}"
test ! -L "${public_webroot}"
for challenge_directory in "${challenge_parent}" "${challenge_root}"; do
  if test -e "${challenge_directory}" || test -L "${challenge_directory}"; then
    test -d "${challenge_directory}"
    test ! -L "${challenge_directory}"
  else
    install -d -m 0755 -o root -g root -- "${challenge_directory}"
  fi
  test -d "${challenge_directory}"
  test ! -L "${challenge_directory}"
  test "$(stat -c '%U:%G %a' -- "${challenge_directory}")" = "root:root 755"
done'''
    preflight = '''        for private_path in "${letsencrypt_dir}/account.conf" "${letsencrypt_dir}/acme.sh.log"; do
          if test -e "${private_path}" || test -L "${private_path}"; then
            test -f "${private_path}"
            test ! -L "${private_path}"
            test "$(stat -c '%h' -- "${private_path}")" = "1"
            chown root:root -- "${private_path}"
            chmod 0600 -- "${private_path}"
            test "$(stat -c '%U:%G %a %h' -- "${private_path}")" = "root:root 600 1"
          fi
        done
'''
    exact_install = '''        AUTO_UPGRADE=0 NO_DETECT_SH=1 LE_WORKING_DIR="${letsencrypt_dir}" ./acme.sh \\
          --install --nocron --noprofile --log "${letsencrypt_dir}/acme.sh.log" --auto-upgrade 0
'''
    initial_start = "/usr/sbin/nginx -c /etc/nginx/letsencrypt.conf"
    if (
        tls.count(preflight) != 1
        or tls.count(exact_install) != 1
        or letsencrypt.count(challenge_paths) != 1
        or letsencrypt.count(challenge_preparation) != 1
        or letsencrypt.index(challenge_paths) >= letsencrypt.index(challenge_preparation)
        or letsencrypt.index(challenge_preparation) >= letsencrypt.index(f"\n{initial_start}\n")
    ):
        raise RuntimeError("Private ACME preflight fixture differs from production source.")
    challenge_preparation_yaml = "".join(f"        {line}\n" for line in challenge_preparation.splitlines())
    without_challenge_preparation = tls.replace(challenge_preparation_yaml, "", 1)
    post_start_challenge_preparation = without_challenge_preparation.replace(
        f"        {initial_start}\n",
        f"        {initial_start}\n" + challenge_preparation_yaml,
        1,
    )
    uncalled_challenge_preparation = tls.replace(
        challenge_preparation_yaml,
        "        prepare_challenge_directories() {\n" + challenge_preparation_yaml + "        }\n",
        1,
    )
    private_challenge_preparation = challenge_preparation.replace(
        "install -d -m 0755 -o root -g root",
        "install -d -m 0700 -o root -g root",
        1,
    )
    linked_challenge_preparation = challenge_preparation.replace(
        '    test ! -L "${challenge_directory}"',
        "    true # linked challenge directory accepted",
        1,
    )
    unbound_challenge_preparation = challenge_preparation.replace(
        '''  test "$(stat -c '%U:%G %a' -- "${challenge_directory}")" = "root:root 755"''',
        "  true # challenge directory metadata unbound",
        1,
    )
    private_challenge_yaml = "".join(f"        {line}\n" for line in private_challenge_preparation.splitlines())
    linked_challenge_yaml = "".join(f"        {line}\n" for line in linked_challenge_preparation.splitlines())
    unbound_challenge_yaml = "".join(f"        {line}\n" for line in unbound_challenge_preparation.splitlines())
    without_preflight = tls.replace(preflight, "", 1)
    post_install_preflight = without_preflight.replace(exact_install, exact_install + preflight, 1)
    resealed_hostiles = (
        (tls.replace(exact_reload, "sv reload nginx", 1), "runit reload"),
        (tls.replace(exact_reload, exact_reload + " || true", 1), "masked reload failure"),
        (tls.replace(f"        {exact_reload}\n", "", 1), "missing caller-owned reload"),
        (
            tls.replace(
                '''            for ((comparison_index=1; comparison_index<ca_index; comparison_index++)); do
              if "${cmp_bin}" -s -- "${validation_root}/ca-${comparison_index}.der" \\
                "${ca_der_path}"; then
                return 1
              fi
            done
''',
                "            true # duplicate CA identities accepted\n",
                1,
            ),
            "duplicate CA identities",
        ),
        (
            tls.replace(
                '-CAfile "${validation_root}/ca-1.pem"',
                '-CAfile "${ca_path}"',
                1,
            ),
            "unordered leaf trust bundle",
        ),
        (
            tls.replace(
                '''          for ((ca_index=1; ca_index<ca_count; ca_index++)); do
            next_ca_index=$((ca_index + 1))
            "${openssl_bin}" verify -partial_chain -x509_strict -purpose any \\
              -no-CAfile -no-CApath -no-CAstore \\
              -CAfile "${validation_root}/ca-${next_ca_index}.pem" \\
              "${validation_root}/ca-${ca_index}.pem" >/dev/null 2>&1 || return 1
          done
''',
                "          true # ordered CA issuer edges accepted without verification\n",
                1,
            ),
            "unordered CA issuer edges",
        ),
        (
            tls.replace(
                '-untrusted "${untrusted_path}" -CAfile "${terminal_ca_path}"',
                '-CAfile "${terminal_ca_path}"',
                1,
            ),
            "missing cumulative full-path intermediates",
        ),
        (
            tls.replace(
                '[ "${leaf_public_algorithm}" = "rsaEncryption" ] || return 1',
                "true # RSA SPKI algorithm identity accepted",
                1,
            ),
            "unbound RSA SPKI algorithm identity",
        ),
        (
            tls.replace(
                '2>/dev/null >>"${untrusted_path}"',
                '>>"${untrusted_path}" 2>/dev/null',
                1,
            ),
            "filename-leaking temporary output redirection order",
        ),
        (
            tls.replace(
                '        test ! -L "${letsencrypt_dir}"',
                "        true # linked ACME directory accepted",
                1,
            ),
            "linked runtime ACME directory",
        ),
        (
            tls.replace(
                '          test ! -L "${letsencrypt_dir}"',
                "          true # linked ACME directory accepted",
                1,
            ),
            "linked configure ACME directory",
        ),
        (
            tls.replace(
                '--installcert "${ecc_option[@]}"',
                '--installcert --reloadcmd true "${ecc_option[@]}"',
                1,
            ),
            "ignored internal reload failure",
        ),
        (tls.replace("umask 077", "umask 022", 1), "permissive umask"),
        (
            tls.replace(challenge_preparation_yaml, private_challenge_yaml, 1),
            "private challenge directory",
        ),
        (
            tls.replace(challenge_preparation_yaml, linked_challenge_yaml, 1),
            "linked challenge directory",
        ),
        (
            tls.replace(challenge_preparation_yaml, unbound_challenge_yaml, 1),
            "unbound challenge directory metadata",
        ),
        (without_challenge_preparation, "missing challenge preparation"),
        (post_start_challenge_preparation, "late challenge preparation"),
        (uncalled_challenge_preparation, "uncalled challenge preparation"),
        (post_install_preflight, "post-install private-state preflight"),
        (
            tls.replace(
                'if test -e "${private_path}" || test -L "${private_path}"; then',
                'if test -f "${private_path}"; then',
                1,
            ),
            "preflight linked private state",
        ),
        (
            tls.replace(
                '''test "$(stat -c '%h' -- "${private_path}")" = "1"''',
                "true # no preflight hard-link guard",
                1,
            ),
            "preflight hard-linked private state",
        ),
        (
            tls.replace(
                '          test -f "${private_path}"\n          test ! -L "${private_path}"',
                '          test -f "${private_path}" && test ! -L "${private_path}"',
                1,
            ),
            "errexit-exempt nonregular private state",
        ),
        (tls.replace('test ! -L "${private_path}"', 'test -e "${private_path}"', 1), "linked private state"),
        (tls.replace('chmod 0600 -- "${private_path}"', 'chmod 0644 -- "${private_path}"', 1), "public private-state mode"),
        (tls.replace('"root:root 600 1"', '"root:root 644 1"', 1), "permissive metadata assertion"),
    )
    for hostile, label in resealed_hostiles:
        reject_resealed_tls(hostile, label)

    host_private_block = '''private_acme_directory=/var/discourse/shared/standalone/letsencrypt
[[ -d ${private_acme_directory} && ! -L ${private_acme_directory} ]] || fail "Private ACME runtime directory is absent or linked."
[[ "$(stat -c '%U:%G %a' -- "${private_acme_directory}")" == "root:root 755" ]] || fail "Private ACME runtime directory metadata differs."
for private_acme_path in \\
  /var/discourse/shared/standalone/letsencrypt/account.conf \\
  /var/discourse/shared/standalone/letsencrypt/acme.sh.log; do
  [[ -f ${private_acme_path} && ! -L ${private_acme_path} ]] || fail "Private ACME runtime state is absent or linked."
  [[ "$(stat -c '%U:%G %a %h' -- "${private_acme_path}")" == "root:root 600 1" ]] || fail "Private ACME runtime state metadata differs."
done'''
    if host_verifier.count(host_private_block) != 1:
        raise RuntimeError("Host-private ACME runtime block differs from production source.")

    bash = shutil.which("bash")
    if os.name == "nt":
        git = shutil.which("git")
        git_bash = Path(git).resolve().parent.parent / "bin" / "bash.exe" if git else None
        bash = str(git_bash) if git_bash is not None and git_bash.is_file() else None
    if bash is None:
        raise RuntimeError("Bash is required for ACME private-state and reload failure fixtures.")

    if acme_order_source.count(exact_reload) != 2:
        raise RuntimeError("Production ACME order does not contain the terminal and fresh exact reloads.")
    order_harness_source = acme_order_source.replace(exact_reload, "reload_certificate")

    def run_acme_order(
        failing_operation: str,
        stage_state: str = "FRESH",
    ) -> tuple[subprocess.CompletedProcess[bytes], bytes]:
        with tempfile.TemporaryDirectory(prefix="mochirii-acme-order-") as directory:
            root = Path(directory)
            events = root / "events.log"
            harness = (
                "set -euo pipefail\n"
                'events="$1"\n'
                'failing_operation="$2"\n'
                'acme_stage_state="$3"\n'
                ': >"${events}"\n'
                "record() { printf '%s\\n' \"$1\" >>\"${events}\"; }\n"
                'record_acme_stage() { record "stage:$1"; if [[ "${failing_operation}" == "stage:$1" ]]; then printf \'%s\\n\' FORUMS_ACME_STAGE_RECORD_FAILED >&2; return 1; fi; }\n'
                'issue_certificate() { record "issue:$1"; if [[ "${failing_operation}" == "issue:$1" ]]; then printf \'%s\\n\' FORUMS_ACME_ISSUANCE_FAILED >&2; return 1; fi; }\n'
                'validate_certificate_material() { record "validate:$2"; [[ "${failing_operation}" != "validate:$2" ]]; }\n'
                'install_certificate() { local algorithm=rsa; [[ -n "$1" ]] && algorithm=ecc; record "install:${algorithm}"; if [[ "${failing_operation}" == "install:${algorithm}" ]]; then printf \'%s\\n\' FORUMS_ACME_INSTALL_FAILED >&2; return 1; fi; }\n'
                'validate_installed_certificate_material() { local algorithm=rsa; [[ -n "$1" ]] && algorithm=ecc; record "installed:${algorithm}"; [[ "${failing_operation}" != "installed:${algorithm}" ]]; }\n'
                'reload_certificate() { record "reload"; [[ "${failing_operation}" != reload ]]; }\n'
                + order_harness_source
            )
            result = subprocess.run(
                [bash, "-c", harness, "bash", "events.log", failing_operation, stage_state],
                cwd=root,
                stdin=subprocess.DEVNULL,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                timeout=10,
                check=False,
            )
            return result, events.read_bytes()

    successful_order, successful_events = run_acme_order("")
    expected_successful_events = (
        b"stage:01-rsa-issue-entered\nissue:4096\nstage:02-rsa-issue-completed\n"
        b"stage:03-rsa-validation-entered\nvalidate:rsa\nstage:04-rsa-validation-completed\n"
        b"stage:05-rsa-install-entered\ninstall:rsa\ninstalled:rsa\nstage:06-rsa-install-completed\n"
        b"stage:07-ecc-issue-entered\nissue:ec-256\nstage:08-ecc-issue-completed\n"
        b"stage:09-ecc-validation-entered\nvalidate:ecc\nstage:10-ecc-validation-completed\n"
        b"stage:11-ecc-install-entered\ninstall:ecc\ninstalled:ecc\nstage:12-ecc-install-completed\n"
        b"stage:13-reload-entered\nreload\nstage:14-reload-completed\n"
        b"stage:15-terminal-completed\n"
    )
    if (
        successful_order.returncode != 0
        or successful_order.stdout
        or successful_order.stderr
        or successful_events != expected_successful_events
    ):
        raise RuntimeError("Actual ACME sequence did not preserve issue-validate-install ordering.")
    rsa_rejection, rsa_events = run_acme_order("validate:rsa")
    if (
        rsa_rejection.returncode == 0
        or rsa_rejection.stdout
        or rsa_rejection.stderr != b"FORUMS_ACME_RSA_MATERIAL_INVALID\n"
        or rsa_events != (
            b"stage:01-rsa-issue-entered\nissue:4096\nstage:02-rsa-issue-completed\n"
            b"stage:03-rsa-validation-entered\nvalidate:rsa\nstage:04-rsa-validation-failed\n"
        )
    ):
        raise RuntimeError("RSA material rejection retried issuance or reached a downstream action.")
    ecc_rejection, ecc_events = run_acme_order("validate:ecc")
    if (
        ecc_rejection.returncode == 0
        or ecc_rejection.stdout
        or ecc_rejection.stderr != b"FORUMS_ACME_ECC_MATERIAL_INVALID\n"
        or ecc_events != (
            expected_successful_events.split(b"stage:09-ecc-validation-entered\n", 1)[0]
            + b"stage:09-ecc-validation-entered\nvalidate:ecc\nstage:10-ecc-validation-failed\n"
        )
    ):
        raise RuntimeError("ECC material rejection retried issuance or reached a downstream action.")

    failure_cases = (
        (
            "install:rsa",
            b"FORUMS_ACME_INSTALL_FAILED\nFORUMS_ACME_RSA_INSTALL_INVALID\n",
            b"stage:05-rsa-install-entered\ninstall:rsa\nstage:06-rsa-install-failed\n",
        ),
        (
            "installed:rsa",
            b"FORUMS_ACME_RSA_INSTALL_INVALID\n",
            b"stage:05-rsa-install-entered\ninstall:rsa\ninstalled:rsa\nstage:06-rsa-install-failed\n",
        ),
        (
            "issue:ec-256",
            b"FORUMS_ACME_ISSUANCE_FAILED\n",
            b"stage:07-ecc-issue-entered\nissue:ec-256\nstage:08-ecc-issue-failed\n",
        ),
        (
            "reload",
            b"FORUMS_ACME_RELOAD_FAILED\n",
            b"stage:13-reload-entered\nreload\nstage:14-reload-failed\n",
        ),
        (
            "stage:07-ecc-issue-entered",
            b"FORUMS_ACME_STAGE_RECORD_FAILED\n",
            b"stage:07-ecc-issue-entered\n",
        ),
    )
    for failure, expected_stderr, terminal_events in failure_cases:
        result, events = run_acme_order(failure)
        if (
            result.returncode == 0
            or result.stdout
            or result.stderr != expected_stderr
            or not events.endswith(terminal_events)
        ):
            raise RuntimeError("ACME stage failure reached a downstream action or lost its fixed category.")

    terminal_order, terminal_events = run_acme_order("", "TERMINAL")
    if (
        terminal_order.returncode != 0
        or terminal_order.stdout
        or terminal_order.stderr
        or terminal_events != b"validate:rsa\ninstalled:rsa\nvalidate:ecc\ninstalled:ecc\nreload\n"
    ):
        raise RuntimeError("Terminal ACME replay did not revalidate exact installed material before reload.")
    terminal_rejection, terminal_rejection_events = run_acme_order("installed:rsa", "TERMINAL")
    if (
        terminal_rejection.returncode == 0
        or terminal_rejection.stdout
        or terminal_rejection.stderr != b"FORUMS_ACME_TERMINAL_RSA_INVALID\n"
        or terminal_rejection_events != b"validate:rsa\ninstalled:rsa\n"
    ):
        raise RuntimeError("Terminal ACME replay accepted mismatched retained RSA material.")
    terminal_reload_rejection, terminal_reload_events = run_acme_order("reload", "TERMINAL")
    if (
        terminal_reload_rejection.returncode == 0
        or terminal_reload_rejection.stdout
        or terminal_reload_rejection.stderr != b"FORUMS_ACME_RELOAD_FAILED\n"
        or terminal_reload_events
        != b"validate:rsa\ninstalled:rsa\nvalidate:ecc\ninstalled:ecc\nreload\n"
    ):
        raise RuntimeError("Terminal ACME replay exposed or accepted a reload failure.")

    with tempfile.TemporaryDirectory(prefix="mochirii-acme-issue-") as directory:
        root = Path(directory)
        runtime = root / "runtime"
        runtime.mkdir()
        acme_stub = runtime / "acme.sh"
        acme_stub.write_text(
            "#!/bin/bash\n"
            "set -euo pipefail\n"
            "printf '%s\\n' \"$*\" >>\"$PWD/issue-events.log\"\n"
            "exit \"${ISSUE_STATUS:?}\"\n",
            encoding="utf-8",
            newline="\n",
        )
        acme_stub.chmod(0o755)
        issue_harness = (
            "set -euo pipefail\n"
            'letsencrypt_dir="$PWD/runtime"\n'
            'public_webroot="/fixture/public"\n'
            'DISCOURSE_HOSTNAME="forums.mochirii.com"\n'
            + issue_source
            + '\nissue_certificate "$1"\n'
        )
        expected_issue = b"--issue -d forums.mochirii.com --keylength 4096 -w /fixture/public\n"
        for status, should_pass in (("0", True), ("2", True), ("1", False)):
            events = root / "issue-events.log"
            if events.exists():
                events.unlink()
            child_environment = os.environ.copy()
            child_environment["ISSUE_STATUS"] = status
            result = subprocess.run(
                [bash, "-c", issue_harness, "bash", "4096"],
                cwd=root,
                env=child_environment,
                stdin=subprocess.DEVNULL,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                timeout=10,
                check=False,
            )
            expected_stderr = b"" if should_pass else b"FORUMS_ACME_ISSUANCE_FAILED\n"
            if (
                (result.returncode == 0) != should_pass
                or result.stdout
                or result.stderr != expected_stderr
                or not events.is_file()
                or events.read_bytes() != expected_issue
            ):
                raise RuntimeError("Actual ACME issue helper retried, forced, or mishandled a pinned status.")

        events = root / "issue-events.log"
        if events.exists():
            events.unlink()
        invalid_environment = os.environ.copy()
        invalid_environment["ISSUE_STATUS"] = "0"
        invalid_issue = subprocess.run(
            [bash, "-c", issue_harness, "bash", "rsa-4096"],
            cwd=root,
            env=invalid_environment,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=10,
            check=False,
        )
        if (
            invalid_issue.returncode == 0
            or invalid_issue.stdout
            or invalid_issue.stderr != b"FORUMS_ACME_ISSUANCE_CONTRACT_FAILED\n"
            or events.exists()
        ):
            raise RuntimeError("Actual ACME issue helper accepted an unreviewed key-length contract.")

        install_harness = (
            "set -euo pipefail\n"
            'letsencrypt_dir="$PWD/runtime"\n'
            'DISCOURSE_HOSTNAME="forums.mochirii.com"\n'
            + install_source
            + '\ninstall_certificate "$1" "$2"\n'
        )
        install_cases = (
            ("", "", True, b"--installcert -d forums.mochirii.com --fullchainpath /shared/ssl/forums.mochirii.com.cer --keypath /shared/ssl/forums.mochirii.com.key\n"),
            ("_ecc", "--ecc", True, b"--installcert --ecc -d forums.mochirii.com --fullchainpath /shared/ssl/forums.mochirii.com_ecc.cer --keypath /shared/ssl/forums.mochirii.com_ecc.key\n"),
            ("_ecc", "", False, b""),
            ("_other", "--ecc", False, b""),
        )
        for suffix, option, should_pass, expected_event in install_cases:
            if events.exists():
                events.unlink()
            install_environment = os.environ.copy()
            install_environment["ISSUE_STATUS"] = "0"
            result = subprocess.run(
                [bash, "-c", install_harness, "bash", suffix, option],
                cwd=root,
                env=install_environment,
                stdin=subprocess.DEVNULL,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                timeout=10,
                check=False,
            )
            expected_stderr = b"" if should_pass else b"FORUMS_ACME_INSTALL_CONTRACT_FAILED\n"
            observed_event = events.read_bytes() if events.is_file() else b""
            if (
                (result.returncode == 0) != should_pass
                or result.stdout
                or result.stderr != expected_stderr
                or observed_event != expected_event
            ):
                raise RuntimeError("Actual ACME install helper accepted an unreviewed suffix or option contract.")

    nonregular_harness = '''set -euo pipefail
private_path=.
test -f "${private_path}"
test ! -L "${private_path}"
printf leaked-success
'''
    nonregular_result = subprocess.run(
        [bash, "-c", nonregular_harness],
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        timeout=10,
        check=False,
    )
    if nonregular_result.returncode == 0 or nonregular_result.stdout or nonregular_result.stderr:
        raise RuntimeError("Separate private-state tests did not reject a nonregular directory categorically.")
    if os.name == "posix":
        with tempfile.TemporaryDirectory(prefix="mochirii-acme-fifo-") as directory:
            fifo = Path(directory) / "fifo"
            os.mkfifo(fifo, 0o600)
            fifo_harness = nonregular_harness.replace("private_path=.", 'private_path="$1"', 1)
            fifo_result = subprocess.run(
                [bash, "-c", fifo_harness, "bash", str(fifo)],
                stdin=subprocess.DEVNULL,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                timeout=10,
                check=False,
            )
            if fifo_result.returncode == 0 or fifo_result.stdout or fifo_result.stderr:
                raise RuntimeError("Separate private-state tests did not reject a FIFO categorically.")
        with tempfile.TemporaryDirectory(prefix="mochirii-acme-linked-parent-") as directory:
            root = Path(directory)
            target = root / "target"
            target.mkdir(mode=0o755)
            for name in ("account.conf", "acme.sh.log"):
                private_file = target / name
                private_file.write_text("fixture\n", encoding="utf-8", newline="\n")
                private_file.chmod(0o600)
            linked = root / "letsencrypt"
            linked.symlink_to(target, target_is_directory=True)
            runtime_seam = (
                directory_verification.replace('"root:root 755"', '"${expected_directory_metadata}"')
                + "\n"
                + private_verification.replace('"root:root 600 1"', '"${expected_private_metadata}"')
            )
            runtime_harness = (
                "set -euo pipefail\n"
                'letsencrypt_dir="$1"\n'
                'expected_directory_metadata="$(stat -c \'%U:%G %a\' -- \"$2\")"\n'
                'expected_private_metadata="$(stat -c \'%U:%G %a %h\' -- \"$2/account.conf\")"\n'
                + runtime_seam
                + "\nprintf leaked-success\n"
            )
            runtime_result = subprocess.run(
                [bash, "-c", runtime_harness, "bash", str(linked), str(target)],
                stdin=subprocess.DEVNULL,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                timeout=10,
                check=False,
            )
            if runtime_result.returncode == 0 or runtime_result.stdout or runtime_result.stderr:
                raise RuntimeError("Generated ACME runtime checks accepted a linked parent directory.")
            host_seam = (
                host_private_block.replace(
                    "private_acme_directory=/var/discourse/shared/standalone/letsencrypt",
                    'private_acme_directory="$1"',
                    1,
                )
                .replace(
                    "/var/discourse/shared/standalone/letsencrypt/account.conf",
                    '"${private_acme_directory}/account.conf"',
                    1,
                )
                .replace(
                    "/var/discourse/shared/standalone/letsencrypt/acme.sh.log",
                    '"${private_acme_directory}/acme.sh.log"',
                    1,
                )
                .replace('"root:root 755"', '"${expected_directory_metadata}"')
                .replace('"root:root 600 1"', '"${expected_private_metadata}"')
            )
            host_harness = (
                "set -euo pipefail\n"
                "fail() { return 1; }\n"
                'expected_directory_metadata="$(stat -c \'%U:%G %a\' -- \"$2\")"\n'
                'expected_private_metadata="$(stat -c \'%U:%G %a %h\' -- \"$2/account.conf\")"\n'
                + host_seam
                + "\nprintf leaked-success\n"
            )
            host_result = subprocess.run(
                [bash, "-c", host_harness, "bash", str(linked), str(target)],
                stdin=subprocess.DEVNULL,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                timeout=10,
                check=False,
            )
            if host_result.returncode == 0 or host_result.stdout or host_result.stderr:
                raise RuntimeError("Host ACME verification accepted a linked parent directory.")

    def require_reload_failure(seam: str, label: str) -> None:
        harness = (
            "set -euo pipefail\n"
            "letsencrypt_dir=/unused\n"
            "DISCOURSE_HOSTNAME=forums.invalid\n"
            "install_certificate() { return 0; }\n"
            "reload_stub() { return 47; }\n"
            + seam.replace('"${letsencrypt_dir}/acme.sh"', "/bin/true").replace(
                exact_reload,
                "reload_stub",
            )
            + "\nprintf leaked-success\n"
        )
        result = subprocess.run(
            [bash, "-c", harness],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=10,
            check=False,
        )
        if result.returncode == 0 or result.stdout or result.stderr:
            raise RuntimeError(f"{label} accepted a caller-owned reload failure.")

    if cron.count(cron_call + "\n" + exact_reload) != 1:
        raise RuntimeError("Production cron caller-owned reload seam differs.")
    require_reload_failure(cron_call + "\n" + exact_reload, "ACME cron")
    fresh_acme_order_source = acme_order_source.split("\nelse\n", 1)[1]
    if (
        fresh_acme_order_source.count(rsa_install) != 1
        or fresh_acme_order_source.count(ecc_install) != 1
        or fresh_acme_order_source.count(exact_reload + " >/dev/null 2>&1") != 1
        or fresh_acme_order_source.index(rsa_install)
        >= fresh_acme_order_source.index(ecc_install)
        or fresh_acme_order_source.index(ecc_install)
        >= fresh_acme_order_source.index(exact_reload)
    ):
        raise RuntimeError("Production initial certificate reload seam differs.")

    host_hostiles = (
        host_verifier.replace(
            '[[ -d ${private_acme_directory} && ! -L ${private_acme_directory} ]]',
            '[[ -d ${private_acme_directory} ]]',
            1,
        ),
        host_verifier.replace('[[ -f ${private_acme_path} && ! -L ${private_acme_path} ]]', '[[ -f ${private_acme_path} ]]', 1),
        host_verifier.replace('"root:root 600 1"', '"root:root 644 1"', 1),
        host_verifier.replace('/var/discourse/shared/standalone/letsencrypt/acme.sh.log', '/tmp/acme.sh.log', 1),
    )
    for hostile in host_hostiles:
        if hostile == host_verifier:
            raise RuntimeError("Host-private ACME hostile did not change the production verifier.")
        try:
            VALIDATOR.validate_acme_host_private_state_contract(hostile)
        except RuntimeError:
            pass
        else:
            raise RuntimeError("Actual validator accepted a weakened host-private ACME contract.")

    controlled_install = '''        AUTO_UPGRADE=0 NO_DETECT_SH=1 LE_WORKING_DIR="${letsencrypt_dir}" ./acme.sh \\
          --install --nocron --noprofile --log "${letsencrypt_dir}/acme.sh.log" --auto-upgrade 0\n'''
    uncontrolled_install = controlled_install.replace(" NO_DETECT_SH=1", "")
    terminal = "        exec /usr/local/bin/letsencrypt\n"
    hostile = tls.replace(controlled_install, uncontrolled_install, 1).replace(
        terminal,
        terminal + controlled_install,
        1,
    )
    if hostile == tls:
        raise RuntimeError("Unreachable ACME install hostile did not change the production fragment.")
    with tempfile.TemporaryDirectory(prefix="mochirii-acme-render-hostile-") as directory:
        hostile_fragment = Path(directory) / "immutable-letsencrypt.fragment.yml"
        hostile_fragment.write_text(hostile, encoding="utf-8", newline="\n")
        previous_fragment = RENDER.TLS_FRAGMENT
        RENDER.TLS_FRAGMENT = hostile_fragment
        try:
            rendered_run = RENDER.tls_fragment_section("RUN")
        finally:
            RENDER.TLS_FRAGMENT = previous_fragment
    if controlled_install.strip() not in rendered_run or uncontrolled_install.strip() not in rendered_run:
        raise RuntimeError("Actual renderer seam did not expose both reachable and unreachable hostile commands.")
    try:
        VALIDATOR.validate_immutable_acme_install_contract(hostile)
    except RuntimeError:
        pass
    else:
        raise RuntimeError("Actual validator accepted an unreachable byte-stability decoy.")

    inert_run = tls.replace(
        "# MOCHIRII TLS RUN BEGIN\n",
        "# MOCHIRII TLS RUN BEGIN\ndead: |1\n",
        1,
    )
    with tempfile.TemporaryDirectory(prefix="mochirii-acme-render-inert-") as directory:
        inert_fragment = Path(directory) / "immutable-letsencrypt.fragment.yml"
        inert_fragment.write_text(inert_run, encoding="utf-8", newline="\n")
        previous_fragment = RENDER.TLS_FRAGMENT
        RENDER.TLS_FRAGMENT = inert_fragment
        try:
            rendered_run = RENDER.tls_fragment_section("RUN")
        finally:
            RENDER.TLS_FRAGMENT = previous_fragment
    if not rendered_run.startswith("dead: |1\n  - exec:") or "NO_DETECT_SH=1" not in rendered_run:
        raise RuntimeError("Actual renderer seam did not preserve the inert RUN block-scalar hostile.")
    reject_resealed_tls(inert_run, "inert immutable TLS RUN section")

    encoded = (ROOT / "config/acme-sh-3.0.6.gz.b64").read_text(encoding="ascii")
    source = gzip.decompress(base64.b64decode("".join(encoded.splitlines()), validate=True))
    if hashlib.sha256(source).hexdigest() != VALIDATOR.ACME_SOURCE_SHA256:
        raise RuntimeError("Pinned ACME fixture bytes differ before the install control test.")
    vendor_webroot_fragments = (
        b'mkdir -p "$wellknown_path"',
        b'printf "%s" "$keyauthorization" >"$wellknown_path/$token"',
        b'chmod a+r "$wellknown_path/$token"',
    )
    if any(source.count(fragment) != 1 for fragment in vendor_webroot_fragments):
        raise RuntimeError("Pinned ACME webroot directory, token write, or token-mode seam differs.")

    # The production image is Linux. The actual install behavior is exercised on
    # Linux CI; Windows still binds the exact rendered command and pinned bytes.
    if os.name == "nt":
        return

    if os.geteuid() == 0:
        commit = "a" * 40

        def run_stage_tool(
            root: Path,
            mode: str,
            stage: str = "",
        ) -> subprocess.CompletedProcess[bytes]:
            fixture_source = stage_python.replace(
                'root != "/shared/letsencrypt"',
                f"root != {str(root)!r}",
                1,
            )
            return subprocess.run(
                [sys.executable, "-I", "-S", "-B", "-", str(root), commit, mode, stage],
                input=fixture_source.encode("utf-8"),
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                timeout=10,
                check=False,
            )

        def make_stage_root(parent: Path, name: str) -> Path:
            root = parent / name
            root.mkdir(mode=0o755)
            root.chmod(0o755)
            return root

        with tempfile.TemporaryDirectory(prefix="mochirii-acme-stage-") as directory:
            fixture = Path(directory)
            stage_root = make_stage_root(fixture, "terminal")
            initial = run_stage_tool(stage_root, "inspect")
            if initial.returncode != 0 or initial.stdout != b"FRESH\n" or initial.stderr:
                raise RuntimeError("Fresh ACME stage evidence was not classified exactly.")
            for stage in successful_stage_tokens:
                result = run_stage_tool(stage_root, "record", stage)
                if result.returncode != 0 or result.stdout or result.stderr:
                    raise RuntimeError("Actual ACME stage publisher rejected a valid transition.")
            terminal = run_stage_tool(stage_root, "inspect")
            if terminal.returncode != 0 or terminal.stdout != b"TERMINAL\n" or terminal.stderr:
                raise RuntimeError("Complete ACME stage evidence was not terminal.")

            host_fixture_source = host_stage_python.replace(
                'root != "/var/discourse/shared/standalone/letsencrypt"',
                f"root != {str(stage_root)!r}",
                1,
            )
            host_terminal = subprocess.run(
                [sys.executable, "-I", "-S", "-B", "-", str(stage_root), commit],
                input=host_fixture_source.encode("utf-8"),
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                timeout=10,
                check=False,
            )
            if host_terminal.returncode != 0 or host_terminal.stdout or host_terminal.stderr:
                raise RuntimeError("Actual host verifier rejected exact terminal ACME stage evidence.")
            stage_directory = stage_root / f"mochirii-acme-bootstrap-{commit}.v1"
            unknown = stage_directory / "16-hostile"
            unknown.write_bytes(b"")
            unknown.chmod(0o600)
            hostile_host = subprocess.run(
                [sys.executable, "-I", "-S", "-B", "-", str(stage_root), commit],
                input=host_fixture_source.encode("utf-8"),
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                timeout=10,
                check=False,
            )
            if hostile_host.returncode == 0 or hostile_host.stdout:
                raise RuntimeError("Host verification accepted unknown terminal ACME stage evidence.")
            unknown.unlink()

            incomplete_root = make_stage_root(fixture, "incomplete")
            first = run_stage_tool(incomplete_root, "record", successful_stage_tokens[0])
            incomplete = run_stage_tool(incomplete_root, "inspect")
            if (
                first.returncode != 0
                or first.stdout
                or first.stderr
                or incomplete.returncode != 0
                or incomplete.stdout != b"INCOMPLETE\n"
                or incomplete.stderr
            ):
                raise RuntimeError("Interrupted ACME stage evidence was not retained as incomplete.")

            failed_root = make_stage_root(fixture, "failed")
            for stage in ("01-rsa-issue-entered", "02-rsa-issue-failed"):
                result = run_stage_tool(failed_root, "record", stage)
                if result.returncode != 0 or result.stdout or result.stderr:
                    raise RuntimeError("Actual ACME stage publisher rejected an exact failed transition.")
            failed = run_stage_tool(failed_root, "inspect")
            after_failure = run_stage_tool(failed_root, "record", "03-rsa-validation-entered")
            if (
                failed.returncode != 0
                or failed.stdout != b"INCOMPLETE\n"
                or failed.stderr
                or after_failure.returncode == 0
                or after_failure.stdout
                or after_failure.stderr
            ):
                raise RuntimeError("Failed ACME stage evidence permitted a downstream transition.")

            unsafe_root = make_stage_root(fixture, "unsafe")
            result = run_stage_tool(unsafe_root, "record", "01-rsa-issue-entered")
            if result.returncode != 0:
                raise RuntimeError("ACME unsafe-stage fixture setup failed.")
            unsafe_directory = unsafe_root / f"mochirii-acme-bootstrap-{commit}.v1"
            first_stage = unsafe_directory / "01-rsa-issue-entered"
            first_stage.chmod(0o644)
            unsafe = run_stage_tool(unsafe_root, "inspect")
            if unsafe.returncode == 0 or unsafe.stdout or unsafe.stderr:
                raise RuntimeError("ACME stage inspection accepted unsafe stage-file metadata.")

        def run_installed_validator(
            shared_root: Path,
            suffix: str = "",
            source: str = installed_python,
        ) -> subprocess.CompletedProcess[bytes]:
            root_contract = 'shared_root != "/shared"'
            if source.count(root_contract) != 1:
                raise RuntimeError("Installed ACME validator root contract differs.")
            fixture_source = source.replace(
                root_contract,
                f"shared_root != {str(shared_root)!r}",
                1,
            )
            return subprocess.run(
                [
                    sys.executable,
                    "-I",
                    "-S",
                    "-B",
                    "-",
                    str(shared_root),
                    "forums.mochirii.com",
                    suffix,
                ],
                input=fixture_source.encode("utf-8"),
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                timeout=10,
                check=False,
            )

        with tempfile.TemporaryDirectory(prefix="mochirii-acme-installed-") as directory:
            root = Path(directory)
            shared_root = root / "shared"
            shared_root.mkdir(mode=0o755)
            shared_root.chmod(0o755)
            letsencrypt_root = shared_root / "letsencrypt"
            shared_ssl = shared_root / "ssl"
            internal = letsencrypt_root / "forums.mochirii.com"
            internal.mkdir(parents=True, mode=0o700)
            letsencrypt_root.chmod(0o755)
            internal.chmod(0o700)
            shared_ssl.mkdir(mode=0o755)
            shared_ssl.chmod(0o755)
            internal_fullchain = internal / "fullchain.cer"
            internal_key = internal / "forums.mochirii.com.key"
            installed_fullchain = shared_ssl / "forums.mochirii.com.cer"
            installed_key = shared_ssl / "forums.mochirii.com.key"
            internal_fullchain.write_bytes(b"exact-fullchain\n")
            internal_key.write_bytes(b"exact-private-key\n")
            installed_fullchain.write_bytes(internal_fullchain.read_bytes())
            installed_key.write_bytes(internal_key.read_bytes())
            internal_fullchain.chmod(0o600)
            internal_key.chmod(0o600)
            installed_fullchain.chmod(0o644)
            installed_key.chmod(0o600)
            valid_installed = run_installed_validator(shared_root)
            if valid_installed.returncode != 0 or valid_installed.stdout or valid_installed.stderr:
                raise RuntimeError("Installed ACME byte validator rejected exact retained material.")
            installed_fullchain.write_bytes(b"partial")
            partial = run_installed_validator(shared_root)
            if partial.returncode == 0 or partial.stdout or partial.stderr:
                raise RuntimeError("Installed ACME byte validator accepted partial destination material.")
            installed_fullchain.write_bytes(internal_fullchain.read_bytes())
            installed_fullchain.chmod(0o666)
            writable = run_installed_validator(shared_root)
            if writable.returncode == 0 or writable.stdout or writable.stderr:
                raise RuntimeError("Installed ACME byte validator accepted writable certificate material.")
            installed_fullchain.chmod(0o644)
            installed_key.unlink()
            os.link(internal_key, installed_key)
            hardlinked = run_installed_validator(shared_root)
            if hardlinked.returncode == 0 or hardlinked.stdout or hardlinked.stderr:
                raise RuntimeError("Installed ACME byte validator accepted hard-linked key material.")
            installed_key.unlink()
            installed_key.write_bytes(internal_key.read_bytes())
            installed_key.chmod(0o600)

            real_ssl = shared_root / "ssl-real"
            shared_ssl.rename(real_ssl)
            shared_ssl.symlink_to(real_ssl, target_is_directory=True)
            linked_parent = run_installed_validator(shared_root)
            if linked_parent.returncode == 0 or linked_parent.stdout or linked_parent.stderr:
                raise RuntimeError("Installed ACME byte validator accepted a linked SSL parent.")
            shared_ssl.unlink()
            real_ssl.rename(shared_ssl)

            replacement = shared_ssl / "forums.mochirii.com.replacement"
            replacement.write_bytes(internal_fullchain.read_bytes())
            replacement.chmod(0o644)
            race_anchor = (
                "        for directory_fd, name, descriptor, identity, kind, maximum_bytes in held:\n"
            )
            if installed_python.count(race_anchor) != 1:
                raise RuntimeError("Installed ACME validator revalidation seam differs.")
            race_source = installed_python.replace(
                race_anchor,
                (
                    '        os.replace(\n'
                    '            hostname + ".replacement",\n'
                    '            hostname + suffix + ".cer",\n'
                    '            src_dir_fd=installed_fd,\n'
                    '            dst_dir_fd=installed_fd,\n'
                    '        )\n'
                    + race_anchor
                ),
                1,
            )
            replaced = run_installed_validator(shared_root, source=race_source)
            if replaced.returncode == 0 or replaced.stdout or replaced.stderr:
                raise RuntimeError("Installed ACME byte validator accepted a replaced post-read leaf.")

    with tempfile.TemporaryDirectory(prefix="mochirii-acme-redirection-") as directory:
        missing_target = Path(directory) / "missing" / "private-output"
        redirection_result = subprocess.run(
            [bash, "-c", ': 2>/dev/null >"$1"', "bash", str(missing_target)],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=10,
            check=False,
        )
        if redirection_result.returncode == 0 or redirection_result.stdout or redirection_result.stderr:
            raise RuntimeError("Private temporary output-open failure was not categorically suppressed.")

    openssl = Path("/usr/bin/openssl")
    if not openssl.is_file() or openssl.is_symlink():
        raise RuntimeError("Exact OpenSSL executable is required for certificate material fixtures.")

    def run_openssl(*arguments: str) -> None:
        result = subprocess.run(
            [str(openssl), *arguments],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            timeout=30,
            check=False,
        )
        if result.returncode != 0:
            raise RuntimeError("Hermetic OpenSSL certificate fixture generation failed.")

    def write_extension_file(path: Path, lines: tuple[str, ...]) -> None:
        path.write_text("\n".join(lines) + "\n", encoding="ascii", newline="\n")

    def make_intermediate(
        root: Path,
        name: str,
        issuer_certificate: Path,
        issuer_key: Path,
        serial: int,
        path_length: int,
        extra_extensions: tuple[str, ...] = (),
    ) -> tuple[Path, Path]:
        key = root / f"{name}.key"
        request = root / f"{name}.csr"
        certificate = root / f"{name}.pem"
        extensions = root / f"{name}.ext"
        run_openssl(
            "req",
            "-new",
            "-newkey",
            "rsa:2048",
            "-nodes",
            "-keyout",
            str(key),
            "-out",
            str(request),
            "-subj",
            f"/CN={name}",
        )
        write_extension_file(
            extensions,
            (
                f"basicConstraints=critical,CA:TRUE,pathlen:{path_length}",
                "keyUsage=critical,keyCertSign,cRLSign",
                "subjectKeyIdentifier=hash",
                "authorityKeyIdentifier=keyid,issuer",
            )
            + extra_extensions,
        )
        run_openssl(
            "x509",
            "-req",
            "-in",
            str(request),
            "-CA",
            str(issuer_certificate),
            "-CAkey",
            str(issuer_key),
            "-set_serial",
            str(serial),
            "-days",
            "30",
            "-sha256",
            "-extfile",
            str(extensions),
            "-out",
            str(certificate),
        )
        return certificate, key

    def make_leaf(
        root: Path,
        name: str,
        algorithm: str,
        issuer_certificate: Path,
        issuer_key: Path,
        serial: int,
        san: str,
        days: int,
        existing_key: Path | None = None,
    ) -> tuple[Path, Path]:
        key = existing_key if existing_key is not None else root / f"{name}.key"
        request = root / f"{name}.csr"
        certificate = root / f"{name}.pem"
        extensions = root / f"{name}.ext"
        if existing_key is None:
            if algorithm == "rsa":
                run_openssl(
                    "genpkey",
                    "-algorithm",
                    "RSA",
                    "-pkeyopt",
                    "rsa_keygen_bits:4096",
                    "-out",
                    str(key),
                )
            elif algorithm == "ecc":
                run_openssl(
                    "genpkey",
                    "-algorithm",
                    "EC",
                    "-pkeyopt",
                    "ec_paramgen_curve:prime256v1",
                    "-out",
                    str(key),
                )
            else:
                raise RuntimeError("Unknown certificate fixture algorithm.")
        run_openssl(
            "req",
            "-new",
            "-key",
            str(key),
            "-out",
            str(request),
            "-subj",
            "/CN=forums.mochirii.com",
        )
        key_usage = "digitalSignature,keyEncipherment" if algorithm == "rsa" else "digitalSignature"
        write_extension_file(
            extensions,
            (
                "basicConstraints=critical,CA:FALSE",
                f"keyUsage=critical,{key_usage}",
                "extendedKeyUsage=serverAuth",
                f"subjectAltName={san}",
                "subjectKeyIdentifier=hash",
                "authorityKeyIdentifier=keyid,issuer",
            ),
        )
        run_openssl(
            "x509",
            "-req",
            "-in",
            str(request),
            "-CA",
            str(issuer_certificate),
            "-CAkey",
            str(issuer_key),
            "-set_serial",
            str(serial),
            "-days",
            str(days),
            "-sha256",
            "-extfile",
            str(extensions),
            "-out",
            str(certificate),
        )
        return certificate, key

    def install_fixture_material(
        letsencrypt_root: Path,
        suffix: str,
        leaf: Path,
        key: Path,
        issuers: tuple[Path, ...],
    ) -> Path:
        certificate_directory = letsencrypt_root / f"forums.mochirii.com{suffix}"
        certificate_directory.mkdir(mode=0o700)
        certificate_directory.chmod(0o700)
        leaf_bytes = leaf.read_bytes()
        ca_bytes = b"".join(path.read_bytes() for path in issuers)
        material = {
            "forums.mochirii.com.cer": leaf_bytes,
            "forums.mochirii.com.key": key.read_bytes(),
            "ca.cer": ca_bytes,
            "fullchain.cer": leaf_bytes + ca_bytes,
        }
        for filename, content in material.items():
            target = certificate_directory / filename
            target.write_bytes(content)
            target.chmod(0o600)
        return certificate_directory

    material_harness = (
        "set -euo pipefail\n"
        "umask 077\n"
        'letsencrypt_dir="$1"\n'
        'certificate_suffix="$2"\n'
        'expected_algorithm="$3"\n'
        'expected_owner="$4"\n'
        'DISCOURSE_HOSTNAME="forums.mochirii.com"\n'
        'certificate_minimum_lifetime_seconds="604800"\n'
        'openssl_bin="/usr/bin/openssl"\n'
        'stat_bin="/usr/bin/stat"\n'
        'cat_bin="/usr/bin/cat"\n'
        'cmp_bin="/usr/bin/cmp"\n'
        'awk_bin="/usr/bin/awk"\n'
        'mktemp_bin="/usr/bin/mktemp"\n'
        'rm_bin="/usr/bin/rm"\n'
        'rmdir_bin="/usr/bin/rmdir"\n'
        + certificate_validator_source
        + '\nvalidate_certificate_material "${certificate_suffix}" "${expected_algorithm}" "${expected_owner}"\n'
    )
    fixture_owner = f"{os.getuid()}:{os.getgid()}"

    def run_material_validator(
        letsencrypt_root: Path,
        suffix: str,
        algorithm: str,
    ) -> subprocess.CompletedProcess[bytes]:
        return subprocess.run(
            [bash, "-c", material_harness, "bash", str(letsencrypt_root), suffix, algorithm, fixture_owner],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=30,
            check=False,
        )

    with tempfile.TemporaryDirectory(prefix="mochirii-acme-material-") as directory:
        fixture_root = Path(directory)
        authority_root = fixture_root / "authority"
        authority_root.mkdir(mode=0o700)
        root_key = authority_root / "root.key"
        root_certificate = authority_root / "root.pem"
        run_openssl(
            "req",
            "-x509",
            "-newkey",
            "rsa:2048",
            "-nodes",
            "-keyout",
            str(root_key),
            "-out",
            str(root_certificate),
            "-days",
            "30",
            "-sha256",
            "-subj",
            "/CN=Mochirii Fixture Root",
            "-addext",
            "basicConstraints=critical,CA:TRUE,pathlen:2",
            "-addext",
            "keyUsage=critical,keyCertSign,cRLSign",
            "-addext",
            "subjectKeyIdentifier=hash",
        )
        unrelated_root_key = authority_root / "unrelated-root.key"
        unrelated_root_certificate = authority_root / "unrelated-root.pem"
        run_openssl(
            "req",
            "-x509",
            "-newkey",
            "rsa:2048",
            "-nodes",
            "-keyout",
            str(unrelated_root_key),
            "-out",
            str(unrelated_root_certificate),
            "-days",
            "30",
            "-sha256",
            "-subj",
            "/CN=Mochirii Unrelated Fixture Root",
            "-addext",
            "basicConstraints=critical,CA:TRUE,pathlen:2",
            "-addext",
            "keyUsage=critical,keyCertSign,cRLSign",
            "-addext",
            "subjectKeyIdentifier=hash",
        )
        intermediate_one, intermediate_one_key = make_intermediate(
            authority_root,
            "Mochirii Fixture Intermediate One",
            root_certificate,
            root_key,
            101,
            1,
        )
        intermediate_two, intermediate_two_key = make_intermediate(
            authority_root,
            "Mochirii Fixture Intermediate Two",
            intermediate_one,
            intermediate_one_key,
            102,
            0,
        )
        rsa_leaf, rsa_key = make_leaf(
            authority_root,
            "rsa-leaf",
            "rsa",
            intermediate_one,
            intermediate_one_key,
            201,
            "DNS:forums.mochirii.com",
            30,
        )
        ecc_leaf, ecc_key = make_leaf(
            authority_root,
            "ecc-leaf",
            "ecc",
            intermediate_two,
            intermediate_two_key,
            202,
            "DNS:forums.mochirii.com",
            30,
        )
        rsa_pss_key = authority_root / "rsa-pss.key"
        run_openssl(
            "genpkey",
            "-algorithm",
            "RSA-PSS",
            "-pkeyopt",
            "rsa_keygen_bits:4096",
            "-out",
            str(rsa_pss_key),
        )
        rsa_pss_leaf, _ = make_leaf(
            authority_root,
            "rsa-pss-leaf",
            "rsa",
            intermediate_one,
            intermediate_one_key,
            208,
            "DNS:forums.mochirii.com",
            30,
            rsa_pss_key,
        )
        constrained_intermediate_one, constrained_intermediate_one_key = make_intermediate(
            authority_root,
            "Mochirii Constrained Intermediate One",
            root_certificate,
            root_key,
            103,
            1,
            ("nameConstraints=critical,permitted;DNS:.allowed.invalid",),
        )
        constrained_intermediate_two, constrained_intermediate_two_key = make_intermediate(
            authority_root,
            "Mochirii Constrained Intermediate Two",
            constrained_intermediate_one,
            constrained_intermediate_one_key,
            104,
            0,
        )
        constrained_leaf, constrained_key = make_leaf(
            authority_root,
            "constrained-leaf",
            "rsa",
            constrained_intermediate_two,
            constrained_intermediate_two_key,
            206,
            "DNS:forums.mochirii.com",
            30,
        )
        path_length_intermediate, path_length_intermediate_key = make_intermediate(
            authority_root,
            "Mochirii Path Length Intermediate",
            intermediate_two,
            intermediate_two_key,
            105,
            0,
        )
        path_length_leaf, path_length_key = make_leaf(
            authority_root,
            "path-length-leaf",
            "rsa",
            path_length_intermediate,
            path_length_intermediate_key,
            207,
            "DNS:forums.mochirii.com",
            30,
        )
        letsencrypt_fixture = fixture_root / "letsencrypt"
        letsencrypt_fixture.mkdir(mode=0o700)
        letsencrypt_fixture.chmod(0o700)
        install_fixture_material(letsencrypt_fixture, "", rsa_leaf, rsa_key, (intermediate_one,))
        install_fixture_material(
            letsencrypt_fixture,
            "_ecc",
            ecc_leaf,
            ecc_key,
            (intermediate_two, intermediate_one),
        )
        for suffix, algorithm in (("", "rsa"), ("_ecc", "ecc")):
            result = run_material_validator(letsencrypt_fixture, suffix, algorithm)
            if result.returncode != 0 or result.stdout or result.stderr:
                raise RuntimeError(
                    f"Actual certificate validator rejected the valid {algorithm} single- or multi-intermediate chain."
                )

        hostile_counter = 0

        def reject_material(
            label: str,
            mutation,
            suffix: str = "",
            algorithm: str = "rsa",
        ) -> None:
            nonlocal hostile_counter
            hostile_counter += 1
            hostile_root = fixture_root / f"hostile-{hostile_counter}"
            shutil.copytree(letsencrypt_fixture, hostile_root)
            mutation(hostile_root / f"forums.mochirii.com{suffix}")
            result = run_material_validator(hostile_root, suffix, algorithm)
            if result.returncode == 0 or result.stdout or result.stderr:
                raise RuntimeError(f"Actual certificate validator accepted or disclosed the {label} hostile.")

        def rewrite_fullchain(certificate_directory: Path) -> None:
            (certificate_directory / "fullchain.cer").write_bytes(
                (certificate_directory / "forums.mochirii.com.cer").read_bytes()
                + (certificate_directory / "ca.cer").read_bytes()
            )
            (certificate_directory / "fullchain.cer").chmod(0o600)

        def replace_material(
            certificate_directory: Path,
            leaf: Path,
            key: Path,
            issuers: tuple[Path, ...],
        ) -> None:
            leaf_bytes = leaf.read_bytes()
            ca_bytes = b"".join(path.read_bytes() for path in issuers)
            replacements = {
                "forums.mochirii.com.cer": leaf_bytes,
                "forums.mochirii.com.key": key.read_bytes(),
                "ca.cer": ca_bytes,
                "fullchain.cer": leaf_bytes + ca_bytes,
            }
            for filename, content in replacements.items():
                target = certificate_directory / filename
                target.write_bytes(content)
                target.chmod(0o600)

        def install_rsa_pss_material(certificate_directory: Path) -> None:
            replace_material(
                certificate_directory,
                rsa_pss_leaf,
                rsa_pss_key,
                (intermediate_one,),
            )

        reject_material("RSA-PSS material under the RSA contract", install_rsa_pss_material)

        wrong_san_leaf, _ = make_leaf(
            authority_root,
            "wrong-san-leaf",
            "rsa",
            intermediate_one,
            intermediate_one_key,
            203,
            "DNS:other.invalid",
            30,
            rsa_key,
        )
        extra_san_leaf, _ = make_leaf(
            authority_root,
            "extra-san-leaf",
            "rsa",
            intermediate_one,
            intermediate_one_key,
            204,
            "DNS:forums.mochirii.com,DNS:other.invalid",
            30,
            rsa_key,
        )
        short_leaf, _ = make_leaf(
            authority_root,
            "short-leaf",
            "rsa",
            intermediate_one,
            intermediate_one_key,
            205,
            "DNS:forums.mochirii.com",
            1,
            rsa_key,
        )
        mismatched_key = authority_root / "mismatched.key"
        run_openssl(
            "genpkey",
            "-algorithm",
            "RSA",
            "-pkeyopt",
            "rsa_keygen_bits:4096",
            "-out",
            str(mismatched_key),
        )

        def replace_leaf(certificate: Path):
            def mutation(certificate_directory: Path) -> None:
                target = certificate_directory / "forums.mochirii.com.cer"
                target.write_bytes(certificate.read_bytes())
                target.chmod(0o600)
                rewrite_fullchain(certificate_directory)

            return mutation

        reject_material("wrong SAN", replace_leaf(wrong_san_leaf))
        reject_material("additional SAN", replace_leaf(extra_san_leaf))
        reject_material("insufficient lifetime", replace_leaf(short_leaf))

        def replace_key(certificate_directory: Path) -> None:
            target = certificate_directory / "forums.mochirii.com.key"
            target.write_bytes(mismatched_key.read_bytes())
            target.chmod(0o600)

        reject_material("mismatched private key", replace_key)

        def replace_chain(certificate_directory: Path) -> None:
            target = certificate_directory / "ca.cer"
            target.write_bytes(root_certificate.read_bytes())
            target.chmod(0o600)
            rewrite_fullchain(certificate_directory)

        reject_material("unrelated certificate chain", replace_chain)

        def append_unrelated_ca(certificate_directory: Path) -> None:
            ca = certificate_directory / "ca.cer"
            ca.write_bytes(ca.read_bytes() + unrelated_root_certificate.read_bytes())
            ca.chmod(0o600)
            rewrite_fullchain(certificate_directory)

        reject_material("unused unrelated CA appended to the chain", append_unrelated_ca)

        def reverse_intermediate_order(certificate_directory: Path) -> None:
            ca = certificate_directory / "ca.cer"
            ca.write_bytes(intermediate_one.read_bytes() + intermediate_two.read_bytes())
            ca.chmod(0o600)
            rewrite_fullchain(certificate_directory)

        reject_material(
            "reversed multi-intermediate chain",
            reverse_intermediate_order,
            suffix="_ecc",
            algorithm="ecc",
        )

        def append_duplicate_ca(certificate_directory: Path) -> None:
            ca = certificate_directory / "ca.cer"
            ca.write_bytes(ca.read_bytes() + intermediate_one.read_bytes())
            ca.chmod(0o600)
            rewrite_fullchain(certificate_directory)

        reject_material("duplicate CA identity", append_duplicate_ca)

        def install_name_constrained_chain(certificate_directory: Path) -> None:
            replace_material(
                certificate_directory,
                constrained_leaf,
                constrained_key,
                (constrained_intermediate_two, constrained_intermediate_one),
            )

        reject_material("cumulative DNS name-constraint violation", install_name_constrained_chain)

        def install_path_length_violating_chain(certificate_directory: Path) -> None:
            replace_material(
                certificate_directory,
                path_length_leaf,
                path_length_key,
                (path_length_intermediate, intermediate_two, intermediate_one),
            )

        reject_material("cumulative CA path-length violation", install_path_length_violating_chain)

        def duplicate_leaf_in_ca(certificate_directory: Path) -> None:
            ca = certificate_directory / "ca.cer"
            ca.write_bytes(
                (certificate_directory / "forums.mochirii.com.cer").read_bytes()
                + ca.read_bytes()
            )
            ca.chmod(0o600)
            rewrite_fullchain(certificate_directory)

        reject_material("leaf duplicated into CA bundle", duplicate_leaf_in_ca)

        def append_ca_junk(certificate_directory: Path) -> None:
            ca = certificate_directory / "ca.cer"
            ca.write_bytes(ca.read_bytes() + b"fixture-junk\n")
            ca.chmod(0o600)
            rewrite_fullchain(certificate_directory)

        reject_material("noncertificate CA bundle data", append_ca_junk)

        def drift_fullchain(certificate_directory: Path) -> None:
            target = certificate_directory / "fullchain.cer"
            target.write_bytes(target.read_bytes() + b"\n")
            target.chmod(0o600)

        reject_material("noncanonical fullchain", drift_fullchain)

        def link_leaf(certificate_directory: Path) -> None:
            target = certificate_directory / "forums.mochirii.com.cer"
            target.unlink()
            target.symlink_to("fullchain.cer")

        reject_material("linked leaf", link_leaf)

        def widen_key(certificate_directory: Path) -> None:
            (certificate_directory / "forums.mochirii.com.key").chmod(0o644)

        reject_material("permissive key mode", widen_key)

        def hardlink_key(certificate_directory: Path) -> None:
            os.link(
                certificate_directory / "forums.mochirii.com.key",
                certificate_directory / "second-key-link",
            )

        reject_material("hard-linked key", hardlink_key)

        def widen_directory(certificate_directory: Path) -> None:
            certificate_directory.chmod(0o755)

        reject_material("permissive certificate directory", widen_directory)
        algorithm_result = run_material_validator(letsencrypt_fixture, "", "ecc")
        if algorithm_result.returncode == 0 or algorithm_result.stdout or algorithm_result.stderr:
            raise RuntimeError("Actual certificate validator accepted the wrong key algorithm contract.")

    def installed_bytes(*, preserve_shebang: bool) -> bytes:
        with tempfile.TemporaryDirectory(prefix="mochirii-acme-install-") as directory:
            root = Path(directory)
            script = root / "acme.sh"
            home = root / "home"
            install = root / "installed"
            log = root / "acme.log"
            home.mkdir(mode=0o700)
            script.write_bytes(source)
            script.chmod(0o755)
            child_environment = {
                "AUTO_UPGRADE": "0",
                "HOME": str(home),
                "LC_ALL": "C",
                "LE_WORKING_DIR": str(install),
                "PATH": "/usr/bin:/bin",
            }
            if preserve_shebang:
                child_environment["NO_DETECT_SH"] = "1"
            result = subprocess.run(
                [
                    "/bin/sh",
                    str(script),
                    "--install",
                    "--nocron",
                    "--noprofile",
                    "--log",
                    str(log),
                    "--auto-upgrade",
                    "0",
                ],
                cwd=root,
                env=child_environment,
                stdin=subprocess.DEVNULL,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                check=False,
                timeout=30,
            )
            target = install / "acme.sh"
            if result.returncode != 0 or not target.is_file() or target.is_symlink():
                raise RuntimeError("Pinned ACME install fixture did not complete as an ordinary file.")
            return target.read_bytes()

    controlled = installed_bytes(preserve_shebang=True)
    if controlled != source:
        raise RuntimeError("NO_DETECT_SH did not preserve the pinned ACME bytes exactly.")

    uncontrolled = installed_bytes(preserve_shebang=False)
    first_line, separator, tail = uncontrolled.partition(b"\n")
    source_tail = source.partition(b"\n")[2]
    if (
        uncontrolled == source
        or separator != b"\n"
        or first_line not in {b"#!/bin/bash", b"#!/usr/bin/bash"}
        or tail != source_tail
    ):
        raise RuntimeError("Uncontrolled ACME install did not reproduce the deterministic shebang-only drift.")

    def run_challenge_preparation(public: Path) -> subprocess.CompletedProcess[bytes]:
        path_seam = challenge_paths.replace("/var/www/discourse/public", public.as_posix())
        preparation_seam = (
            challenge_preparation.replace(" -o root -g root ", " ")
            .replace('"root:root 755"', '"${fixture_owner} 755"')
        )
        harness = (
            "set -euo pipefail\n"
            "umask 077\n"
            + path_seam
            + "\n"
            + 'fixture_owner="$(stat -c \'%U:%G\' -- "${public_webroot}")"\n'
            + preparation_seam
            + "\n"
        )
        return subprocess.run(
            [bash, "-c", harness],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
            timeout=10,
        )

    with tempfile.TemporaryDirectory(prefix="mochirii-acme-webroot-") as directory:
        root = Path(directory)
        public = root / "public"
        public.mkdir(mode=0o755)
        public.chmod(0o755)
        result = run_challenge_preparation(public)
        if result.returncode != 0 or result.stdout or result.stderr:
            raise RuntimeError("Exact ACME challenge preparation did not complete categorically.")
        challenge_parent = public / ".well-known"
        challenge_root = challenge_parent / "acme-challenge"
        for challenge_directory in (challenge_parent, challenge_root):
            metadata = challenge_directory.lstat()
            if not stat.S_ISDIR(metadata.st_mode) or challenge_directory.is_symlink() or stat.S_IMODE(metadata.st_mode) != 0o755:
                raise RuntimeError("ACME challenge preparation did not create an ordinary traversable directory.")

        previous_umask = os.umask(0o077)
        try:
            token = challenge_root / "fixture-token"
            token.write_bytes(b"fixture-authorization")
        finally:
            os.umask(previous_umask)
        token.chmod(stat.S_IMODE(token.stat().st_mode) | 0o444)
        if stat.S_IMODE(token.stat().st_mode) != 0o644:
            raise RuntimeError("Pinned ACME token-mode behavior differs after challenge preparation.")

        unprepared_public = root / "unprepared" / "public"
        unprepared_public.mkdir(parents=True, mode=0o755)
        unprepared_public.chmod(0o755)
        previous_umask = os.umask(0o077)
        try:
            unprepared_root = unprepared_public / ".well-known" / "acme-challenge"
            unprepared_root.mkdir(parents=True)
        finally:
            os.umask(previous_umask)
        if any(stat.S_IMODE(path.stat().st_mode) != 0o700 for path in (unprepared_root.parent, unprepared_root)):
            raise RuntimeError("Restricted-umask ACME webroot regression control did not reproduce mode 0700.")

        linked_public = root / "linked" / "public"
        linked_target = root / "linked-target"
        linked_public.mkdir(parents=True, mode=0o755)
        linked_target.mkdir(mode=0o755)
        (linked_public / ".well-known").symlink_to(linked_target, target_is_directory=True)
        linked_result = run_challenge_preparation(linked_public)
        if linked_result.returncode == 0 or linked_result.stdout or linked_result.stderr:
            raise RuntimeError("ACME challenge preparation accepted a linked directory.")

        drift_public = root / "drift" / "public"
        drift_parent = drift_public / ".well-known"
        drift_parent.mkdir(parents=True, mode=0o700)
        drift_parent.chmod(0o700)
        drift_result = run_challenge_preparation(drift_public)
        if drift_result.returncode == 0 or drift_result.stdout or drift_result.stderr:
            raise RuntimeError("ACME challenge preparation accepted existing private directory metadata.")


def test_opensearch_filter_contract() -> None:
    template = (ROOT / "config/app.yml.example").read_text(encoding="utf-8")
    VALIDATOR.validate_opensearch_filter_contract(template)
    hostile_replacements = (
        ("sub_filter_types application/xml;", "sub_filter_types application/opensearchdescription+xml;"),
        ("sub_filter_once off;", "sub_filter_once on;"),
        ("<Tags>discourse forum</Tags>", "<Tags>forum</Tags>"),
        ("<Tags>Mochirii Forums</Tags>", "<Tags>Mochirii</Tags>"),
    )
    for current, stale in hostile_replacements:
        hostile = template.replace(current, stale, 1)
        if hostile == template:
            raise RuntimeError("OpenSearch nginx hostile mutation anchor is absent.")
        try:
            VALIDATOR.validate_opensearch_filter_contract(hostile)
        except RuntimeError:
            continue
        raise RuntimeError("OpenSearch nginx filter accepted a mismatched media type or replacement.")

    controller = (
        b"class MetadataController < ApplicationController\n"
        + UPSTREAM.PINNED_OPENSEARCH_CONTROLLER_BLOCK
        + b"  def app_association_android\n  end\nend\n"
    )
    UPSTREAM.verify_opensearch_controller_method(controller)
    controller_hostiles = (
        controller.replace(b"formats: [:xml]", b"formats: [:json]", 1),
        controller.replace(b"expires_in 1.minute", b"expires_now", 1),
        controller.replace(b'template: "metadata/opensearch"', b'template: "metadata/manifest"', 1),
    )
    for hostile in controller_hostiles:
        try:
            UPSTREAM.verify_opensearch_controller_method(hostile)
        except RuntimeError:
            continue
        raise RuntimeError("Pinned OpenSearch controller accepted a hostile rendering mutation.")


def test_html_denial_types_contract() -> None:
    template = (ROOT / "config/app.yml.example").read_text(encoding="utf-8")
    VALIDATOR.validate_html_denial_types_contract(template)
    for name in (
        "mochirii_feed_denied",
        "mochirii_admin_recovery_denied",
        "mochirii_email_login_denied",
    ):
        marker = f"        location @{name} {{\n          types {{ }}\n"
        hostile = template.replace(marker, f"        location @{name} {{\n", 1)
        if hostile == template:
            raise RuntimeError(f"HTML denial MIME hostile mutation anchor is absent: {name}.")
        try:
            VALIDATOR.validate_html_denial_types_contract(hostile)
        except RuntimeError:
            continue
        raise RuntimeError(f"HTML denial accepted inherited extension MIME mappings: {name}.")


def test_login_code_denial_contract() -> None:
    verifier = (ROOT / "scripts/verify-discourse-connect.py").read_text(encoding="utf-8")
    VALIDATOR.validate_login_code_denial_contract(verifier)
    hostile = verifier.replace("local_status != 404", "local_status != 403", 1)
    if hostile == verifier:
        raise RuntimeError("Local email-code denial hostile mutation anchor is absent.")
    try:
        VALIDATOR.validate_login_code_denial_contract(hostile)
    except RuntimeError:
        pass
    else:
        raise RuntimeError("Local email-code denial accepted a status that contradicts pinned core.")

    source = b"class SessionController\n" + UPSTREAM.PINNED_LOGIN_CODE_DENIAL_METHOD + b"end\n"
    UPSTREAM.verify_login_code_denial_semantics(source)
    for current, stale in (
        (b"raise Discourse::NotFound", b"raise Discourse::InvalidAccess"),
        (b"check_local_login_allowed(check_login_via_email: true)", b"check_local_login_allowed"),
    ):
        hostile_source = source.replace(current, stale, 1)
        try:
            UPSTREAM.verify_login_code_denial_semantics(hostile_source)
        except RuntimeError:
            continue
        raise RuntimeError("Pinned local email-code denial accepted a hostile controller mutation.")


def test_sensitive_response_header_contract() -> None:
    app = (ROOT / "config/app.yml.example").read_text(encoding="utf-8")
    host_verify = (ROOT / "scripts/verify-host.sh").read_text(encoding="utf-8")
    workflow = (ROOT / ".github/workflows/disposable-bootstrap.yml").read_text(encoding="utf-8")
    VALIDATOR.validate_sensitive_response_header_contract(app, host_verify)
    VALIDATOR.validate_disposable_nginx_response_header_proof(workflow)
    file_start_marker = (
        "timeout --signal=TERM --kill-after=5s 60s docker exec -i app python3 -B - "
        "<<'PY_NGINX_FILES' >/dev/null || fail \"Active nginx configuration files differ "
        "from the exact reviewed inventory.\"\n"
    )
    file_start = host_verify.index(file_start_marker) + len(file_start_marker)
    file_source = host_verify[file_start:host_verify.index("\nPY_NGINX_FILES\n", file_start)]
    file_tree = ast.parse(file_source)

    def assignment(name: str) -> ast.Assign:
        matches = [
            node
            for node in file_tree.body
            if isinstance(node, ast.Assign)
            and len(node.targets) == 1
            and isinstance(node.targets[0], ast.Name)
            and node.targets[0].id == name
        ]
        if len(matches) != 1:
            raise RuntimeError(f"Hosted nginx file fixture assignment differs: {name}.")
        return matches[0]

    directory_contract = ast.literal_eval(assignment("EXPECTED_DIRECTORY_CHILDREN").value)
    file_contract = ast.literal_eval(assignment("EXPECTED_FILE_SHA256").value)
    pinned_username_log_fragment = ast.literal_eval(
        assignment("PINNED_DISCOURSE_USERNAME_LOG_FRAGMENT").value
    )
    private_username_log_fragment = ast.literal_eval(
        assignment("PRIVATE_DISCOURSE_USERNAME_LOG_FRAGMENT").value
    )
    if (
        pinned_username_log_fragment
        != '"$upstream_http_x_discourse_username" "$upstream_http_x_discourse_trackview"'
        or private_username_log_fragment != '"-" "$upstream_http_x_discourse_trackview"'
    ):
        raise RuntimeError("Hosted nginx file verifier username-log fragments differ.")
    tls_states = (
        VALIDATOR.PINNED_WEB_SSL_SERVER_OUTLET,
        VALIDATOR.MANAGED_WEB_SSL_SERVER_OUTLET,
    )
    expected_tls_evidence = (
        (668, "5e2dc26f2148bdb83a4927f1e162b959579a8b800f3514272245ca440af21248"),
        (821, "6d26204383871f0e76013485555459940ff6f78df1ee7ac7857a58904d49a162"),
    )
    actual_tls_evidence = tuple(
        (len(value.encode("utf-8")), hashlib.sha256(value.encode("utf-8")).hexdigest())
        for value in tls_states
    )
    if (
        actual_tls_evidence != expected_tls_evidence
        or file_contract["/etc/nginx/conf.d/outlets/server/20-https.conf"]
        != tuple(digest for _, digest in expected_tls_evidence)
    ):
        raise RuntimeError("Hosted nginx file verifier does not bind both exact pinned TLS outlet states.")
    empty_digest = hashlib.sha256(b"").hexdigest()
    tls_path = "/etc/nginx/conf.d/outlets/server/20-https.conf"
    discourse_path = "/etc/nginx/conf.d/discourse.conf"
    pinned_username_log_digest = hashlib.sha256(
        pinned_username_log_fragment.encode("utf-8")
    ).hexdigest()
    fixture_file_contract = {
        path: (
            tuple(digest for _, digest in expected_tls_evidence)
            if path == tls_path
            else (pinned_username_log_digest,)
            if path == discourse_path
            else (empty_digest,)
        )
        for path in file_contract
    }
    file_assignment = assignment("EXPECTED_FILE_SHA256")
    file_assignment_source = ast.get_source_segment(file_source, file_assignment)
    if file_assignment_source is None:
        raise RuntimeError("Hosted nginx file fixture assignment source is unavailable.")
    fixture_file_source = file_source.replace(
        file_assignment_source,
        f"EXPECTED_FILE_SHA256 = {fixture_file_contract!r}",
        1,
    )

    def materialize_file_fixture(root: Path, tls_state: str = tls_states[0]) -> None:
        for relative in directory_contract:
            (root / relative.removeprefix("/")).mkdir(parents=True, exist_ok=True)
        for relative in fixture_file_contract:
            path = root / relative.removeprefix("/")
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(
                tls_state.encode("utf-8")
                if relative == tls_path
                else private_username_log_fragment.encode("utf-8")
                if relative == discourse_path
                else b""
            )

    def run_file_fixture(root: Path) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            [sys.executable, "-B", "-", str(root.resolve())],
            input=fixture_file_source,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=10,
            check=False,
        )

    for tls_state in tls_states:
        with tempfile.TemporaryDirectory() as directory:
            fixture_root = Path(directory)
            materialize_file_fixture(fixture_root, tls_state)
            if run_file_fixture(fixture_root).returncode != 0:
                raise RuntimeError("Hosted nginx file verifier rejected an exact pinned TLS outlet state.")

    def marker_spoof(root: Path) -> None:
        (root / "etc/nginx/conf.d/outlets/server/10-http.conf").write_text(
            "# configuration file /tmp/ignored.conf:\n"
            "location ^~ /session/ { return 204; }\n",
            encoding="utf-8",
        )

    def hostile_main(root: Path) -> None:
        (root / "etc/nginx/conf.d/discourse.conf").write_text(
            "location ^~ /session/ { return 204; }\n",
            encoding="utf-8",
        )

    def restored_username_log(root: Path) -> None:
        (root / discourse_path.removeprefix("/")).write_text(
            pinned_username_log_fragment,
            encoding="utf-8",
        )

    def duplicated_private_username_log(root: Path) -> None:
        (root / discourse_path.removeprefix("/")).write_text(
            private_username_log_fragment + "\n" + private_username_log_fragment,
            encoding="utf-8",
        )

    def displaced_username_log_variable(root: Path) -> None:
        (root / discourse_path.removeprefix("/")).write_text(
            private_username_log_fragment + "\n# $upstream_http_x_discourse_username\n",
            encoding="utf-8",
        )

    def hostile_mime_include(root: Path) -> None:
        (root / "etc/nginx/mime.types").write_text(
            "types { text/plain txt; }\nserver { listen 443 ssl; }\n",
            encoding="utf-8",
        )

    def unexpected_outlet(root: Path) -> None:
        (root / "etc/nginx/conf.d/outlets/server/99-hostile.conf").write_text(
            "location ^~ /session/ { return 204; }\n",
            encoding="utf-8",
        )

    def unexpected_top_level(root: Path) -> None:
        (root / "etc/nginx/conf.d/hostile.conf").write_text(
            "server { listen 443 ssl; }\n",
            encoding="utf-8",
        )

    def invalid_utf8(root: Path) -> None:
        (root / "etc/nginx/nginx.conf").write_bytes(b"\xff")

    def oversized(root: Path) -> None:
        (root / "etc/nginx/nginx.conf").write_bytes(b"x" * 1_048_577)

    for mutate in (
        marker_spoof,
        hostile_main,
        restored_username_log,
        duplicated_private_username_log,
        displaced_username_log_variable,
        hostile_mime_include,
        unexpected_outlet,
        unexpected_top_level,
        invalid_utf8,
        oversized,
    ):
        with tempfile.TemporaryDirectory() as directory:
            fixture_root = Path(directory)
            materialize_file_fixture(fixture_root)
            mutate(fixture_root)
            if run_file_fixture(fixture_root).returncode == 0:
                raise RuntimeError("Hosted nginx file verifier accepted a hostile raw-file fixture.")

    raw_verifier_mutations = (
        host_verify.replace(
            "import hashlib\nimport os\n",
            "import hashlib\nimport os\nraise SystemExit(0)\n",
            1,
        ),
        host_verify.replace(
            '    "/etc/nginx/conf.d": ("discourse.conf", "outlets"),',
            '    "/etc/nginx/conf.d": ("outlets",),',
            1,
        ),
        host_verify.replace(
            "docker exec -i app python3 -B - <<'PY_NGINX_FILES'",
            "docker exec -i app python3 -B - /tmp <<'PY_NGINX_FILES'",
            1,
        ),
        host_verify.replace(
            '            or "$upstream_http_x_discourse_username" in text\n',
            "",
            1,
        ),
        host_verify.replace(file_start_marker, "true || " + file_start_marker, 1),
    )
    for candidate in raw_verifier_mutations:
        try:
            VALIDATOR.validate_sensitive_response_header_contract(app, candidate)
        except RuntimeError:
            continue
        raise RuntimeError("Sensitive response-header source accepted a weakened nginx file verifier.")
    if os.name == "posix":
        bash = shutil.which("bash")
        if bash is None:
            raise RuntimeError("Bash is required for the nginx verifier reachability fixture.")
        file_block_start = host_verify.index(file_start_marker)
        file_block_end = host_verify.index("\nPY_NGINX_FILES\n", file_start) + len("\nPY_NGINX_FILES\n")
        skipped_file_block = "true || " + host_verify[file_block_start:file_block_end]
        with tempfile.TemporaryDirectory() as directory:
            sentinel = Path(directory) / "invoked"
            harness = (
                "set -euo pipefail\n"
                "fail() { return 1; }\n"
                'timeout() { printf invoked >"${NGINX_VERIFIER_SENTINEL}"; return 1; }\n'
                + skipped_file_block
                + '[[ ! -e "${NGINX_VERIFIER_SENTINEL}" ]]\n'
            )
            completed = subprocess.run(
                [bash, "-c", harness],
                env={**os.environ, "NGINX_VERIFIER_SENTINEL": str(sentinel)},
                stdin=subprocess.DEVNULL,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                timeout=10,
                check=False,
            )
            if completed.returncode != 0 or sentinel.exists():
                raise RuntimeError("Nginx verifier skipped-invocation hostile fixture changed.")
    markers = (
        "        location ~* ^/session/sso_login(?:\\.[A-Za-z0-9]+)?/?$ {\n",
        '        location ~ "^/session/email-login/[A-Za-z0-9_-]{20,256}$" {\n',
    )
    shared_start_marker = (
        "      path: /etc/nginx/conf.d/outlets/discourse/35-mochirii-public-response-headers.inc\n"
        "      contents: |\n"
    )
    shared_end_marker = (
        "  - file:\n"
        "      path: /etc/nginx/conf.d/outlets/server/35-mochirii-public-response-headers.conf\n"
    )
    server_scope_start_marker = (
        "      path: /etc/nginx/conf.d/outlets/server/35-mochirii-public-response-headers.conf\n"
        "      contents: |\n"
    )
    server_scope_end_marker = (
        "  - file:\n"
        "      path: /etc/nginx/conf.d/outlets/discourse/40-mochirii-public-metadata.conf\n"
    )
    outlet_start_marker = (
        "      path: /etc/nginx/conf.d/outlets/discourse/40-mochirii-public-metadata.conf\n"
        "      contents: |\n"
    )
    outlet_start = app.index(outlet_start_marker) + len(outlet_start_marker)
    outlet_end_marker = "  # Pups replace is a silent no-op when its source is absent, so bind the exact\n"
    outlet_end = app.index(outlet_end_marker, outlet_start)
    server_outlet_start_marker = (
        "      path: /etc/nginx/conf.d/outlets/server/40-mochirii-feed-denial.conf\n"
        "      contents: |\n"
    )
    server_outlet_end_marker = "  - file:\n      path: /var/www/discourse/public/403.html\n"

    def rendered_nginx(source: str, extra: str = "") -> str:
        current_shared_start = source.index(shared_start_marker) + len(shared_start_marker)
        current_shared_end = source.index(shared_end_marker, current_shared_start)
        current_shared_body = "\n".join(
            line[8:] if line.startswith("        ") else line
            for line in source[current_shared_start:current_shared_end].splitlines()
        )
        current_server_scope_start = source.index(server_scope_start_marker) + len(server_scope_start_marker)
        current_server_scope_end = source.index(server_scope_end_marker, current_server_scope_start)
        current_server_scope_body = "\n".join(
            line[8:] if line.startswith("        ") else line
            for line in source[current_server_scope_start:current_server_scope_end].splitlines()
        )
        current_outlet_start = source.index(outlet_start_marker) + len(outlet_start_marker)
        current_outlet_end = source.index(outlet_end_marker, current_outlet_start)
        current_outlet_body = "\n".join(
            line[8:] if line.startswith("        ") else line
            for line in source[current_outlet_start:current_outlet_end].splitlines()
        )
        current_server_start = source.index(server_outlet_start_marker) + len(server_outlet_start_marker)
        current_server_end = source.index(server_outlet_end_marker, current_server_start)
        current_server_body = "\n".join(
            line[8:] if line.startswith("        ") else line
            for line in source[current_server_start:current_server_end].splitlines()
        )
        return (
            "# configuration file /etc/nginx/conf.d/discourse.conf:\n"
            + 'log_format log_discourse \'"-" "$upstream_http_x_discourse_trackview"\';\n'
            + "server {\n"
            + "  location ~ ^/(svg-sprite/|letter_avatar/|letter_avatar_proxy/|user_avatar|highlight-js|stylesheets|theme-javascripts|favicon/proxied|service-worker|extra-locales/) {\n"
            + "    brotli_comp_level 6;\n"
            + '    proxy_ignore_headers "Set-Cookie";\n'
            + '    proxy_hide_header "Set-Cookie";\n'
            + '    proxy_hide_header "X-Discourse-Username";\n'
            + '    proxy_hide_header "X-Runtime";\n'
            + "    include conf.d/outlets/discourse/35-mochirii-public-response-headers.inc;\n"
            + "    proxy_cache one;\n"
            + '    proxy_cache_key "$scheme,$host,$request_uri";\n'
            + "    proxy_cache_valid 200 301 302 7d;\n"
            + "    proxy_cache_bypass $bypass_cache;\n"
            + "    proxy_pass http://discourse;\n"
            + "    break;\n"
            + "  }\n"
            + "}\n"
            + "# configuration file /etc/nginx/conf.d/outlets/discourse/20-https.conf:\n"
            + "add_header Strict-Transport-Security 'max-age=31536000';\n"
            + "# configuration file /etc/nginx/conf.d/outlets/discourse/30-ratelimited.conf:\n"
            + "limit_conn connperip 20;\n"
            + "limit_req zone=flood burst=12 nodelay;\n"
            + "limit_req zone=bot burst=100 nodelay;\n"
            + "# configuration file /etc/nginx/conf.d/outlets/discourse/35-mochirii-public-response-headers.inc:\n"
            + current_shared_body
            + "\n"
            + "\n# configuration file /etc/nginx/conf.d/outlets/discourse/40-mochirii-public-metadata.conf:\n"
            + current_outlet_body
            + "\n"
            + "# configuration file /etc/nginx/conf.d/outlets/server/10-http.conf:\n"
            + "# configuration file /etc/nginx/conf.d/outlets/server/20-https.conf:\n"
            + "listen 443 ssl;\n"
            + "listen [::]:443 ssl;\n"
            + "http2 on;\n"
            + "ssl_protocols TLSv1.2 TLSv1.3;\n"
            + "ssl_ciphers ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305:DHE-RSA-AES128-GCM-SHA256:DHE-RSA-AES256-GCM-SHA384;\n"
            + "ssl_prefer_server_ciphers off;\n"
            + "ssl_certificate /shared/ssl/ssl.crt;\n"
            + "ssl_certificate_key /shared/ssl/ssl.key;\n"
            + "ssl_session_tickets off;\n"
            + "ssl_session_timeout 1d;\n"
            + "ssl_session_cache shared:SSL:1m;\n"
            + "add_header Strict-Transport-Security 'max-age=31536000';\n"
            + "if ($http_host != forums.mochirii.com) {\n"
            + "rewrite (.*) https://forums.mochirii.com$1 permanent;\n"
            + "}\n"
            + "# configuration file /etc/nginx/conf.d/outlets/server/30-offline-page.conf:\n"
            + "# configuration file /etc/nginx/conf.d/outlets/server/35-mochirii-public-response-headers.conf:\n"
            + current_server_scope_body
            + "\n"
            + "# configuration file /etc/nginx/conf.d/outlets/server/40-mochirii-feed-denial.conf:\n"
            + current_server_body
            + "\n"
            + extra
        )

    for name in ("Cache-Control", "Pragma", "Expires", "Referrer-Policy"):
        directive = f"          proxy_hide_header {name};\n"
        missing_host_proof = host_verify.replace(
            f'"proxy_hide_header {name};"', '"proxy_hide_header Hostile-Metadata;"', 1
        )
        hostile_cases = [(app, missing_host_proof)]
        for marker in markers:
            start = app.index(marker)
            position = app.index(directive, start)
            missing = app[:position] + app[position + len(directive):]
            misplaced = missing.replace(marker, directive + marker, 1)
            extra = app[:position] + f"          proxy_pass_header    {name.lower()};\n" + app[position:]
            conflicting = app[:position] + f'          add_header {name} "hostile" always;\n' + app[position:]
            extra_include = app[:position] + "          include /tmp/hostile-sensitive.conf;\n" + app[position:]
            add_start = app.index('          add_header Cache-Control "private, no-store, max-age=0" always;\n', start)
            add_end_line = '          add_header Referrer-Policy "no-referrer" always;\n'
            add_end = app.index(add_end_line, add_start) + len(add_end_line)
            nested = (
                app[:add_start]
                + '          if ($arg_fixture = "1") {\n'
                + app[add_start:add_end]
                + "          }\n"
                + "          proxy_pass_header Referrer-Policy;\n"
                + app[add_end:]
            )
            hostile_cases.extend(
                (
                    (missing, host_verify),
                    (misplaced, host_verify),
                    (extra, host_verify),
                    (conflicting, host_verify),
                    (extra_include, host_verify),
                    (nested, host_verify),
                )
            )
        for candidate_app, candidate_host in hostile_cases:
            try:
                VALIDATOR.validate_sensitive_response_header_contract(candidate_app, candidate_host)
            except RuntimeError:
                continue
            raise RuntimeError(f"Sensitive identity route accepted hostile {name} response-header composition.")

    shared_start = app.index(shared_start_marker) + len(shared_start_marker)
    shared_end = app.index(shared_end_marker, shared_start)
    public_response_headers = (
        "X-Discourse-Route",
        "X-Discourse-Username",
        "X-Discourse-Crawler-View",
        "Discourse-No-Onebox",
        "Discourse-Rate-Limit-Error-Code",
        "Discourse-Xhr-Redirect",
        "Discourse-Actions-Remaining",
        "Discourse-Actions-Max",
        "Discourse-Logged-Out",
        "Discourse-Track-View-Session-Id-Placeholder",
        "X-Discourse-TrackView",
        "X-Discourse-BrowserPageView",
        "X-Discourse-Cached",
    )
    shared_hostiles = []
    for header in public_response_headers:
        directive = f"        proxy_hide_header {header};\n"
        position = app.index(directive, shared_start, shared_end)
        shared_hostiles.extend(
            (
                app[:position] + app[position + len(directive):],
                app[:position] + directive + app[position:],
                app[:position] + f"        proxy_pass_header {header};\n" + app[position + len(directive):],
            )
        )
    shared_include = "        include conf.d/outlets/discourse/35-mochirii-public-response-headers.inc;\n"
    server_scope_start = app.index(server_scope_start_marker) + len(server_scope_start_marker)
    server_scope_end = app.index(server_scope_end_marker, server_scope_start)
    server_include_position = app.index(shared_include, server_scope_start, server_scope_end)
    outlet_include_position = app.index(shared_include, outlet_start, outlet_end)
    replacement_filename = "      filename: /etc/nginx/conf.d/discourse.conf\n"
    build_assertion = (
        "        - >-\n"
        "          test \"$(grep -Fxc '      include conf.d/outlets/discourse/35-mochirii-public-response-headers.inc;'\n"
        "          /etc/nginx/conf.d/discourse.conf)\" -eq 1\n"
        "        - >-\n"
        "          test \"$(grep -Fo '\"-\" \"$upstream_http_x_discourse_trackview\"'\n"
        "          /etc/nginx/conf.d/discourse.conf | wc -l)\" -eq 1\n"
        "        - >-\n"
        "          ! grep -Fq '$upstream_http_x_discourse_username'\n"
        "          /etc/nginx/conf.d/discourse.conf\n"
    )
    username_log_replacement = '''  - replace:
      filename: /etc/nginx/conf.d/discourse.conf
      from: |-
        "$upstream_http_x_discourse_username" "$upstream_http_x_discourse_trackview"
      to: |-
        "-" "$upstream_http_x_discourse_trackview"
'''
    shared_hostiles.extend(
        (
            app[:shared_end] + "        sub_filter_once off;\n" + app[shared_end:],
            app[:shared_end] + "        include /tmp/hostile.inc;\n" + app[shared_end:],
            app[:shared_end] + "        proxy_hide_header $hostile_header;\n" + app[shared_end:],
            app[:server_include_position] + app[server_include_position + len(shared_include):],
            app[:server_include_position] + shared_include + app[server_include_position:],
            app[:outlet_include_position] + app[outlet_include_position + len(shared_include):],
            app.replace("35-mochirii-public-response-headers.inc", "35-mochirii-public-response-headers.conf"),
            app.replace(replacement_filename, replacement_filename + "      global: true\n", 1),
            app.replace('              proxy_hide_header "X-Runtime";\n      to:', '              proxy_hide_header "X-Other";\n      to:', 1),
            app.replace(username_log_replacement, "", 1),
            app.replace(
                "          if source.count(username_log_fragment) != 1:\n",
                "          if False:\n",
                1,
            ),
            app.replace(
                '          if source.count(private_log_fragment) != 1 or "$upstream_http_x_discourse_username" in source:\n',
                "          if source.count(private_log_fragment) != 1:\n",
                1,
            ),
            app.replace(
                "        - >-\n"
                "          test \"$(grep -Fo '\"-\" \"$upstream_http_x_discourse_trackview\"'\n"
                "          /etc/nginx/conf.d/discourse.conf | wc -l)\" -eq 1\n",
                "",
                1,
            ),
            app.replace(
                "        - >-\n"
                "          ! grep -Fq '$upstream_http_x_discourse_username'\n"
                "          /etc/nginx/conf.d/discourse.conf\n",
                "",
                1,
            ),
            app.replace(build_assertion, "", 1),
        )
    )
    for candidate_app in shared_hostiles:
        if candidate_app == app:
            raise RuntimeError("Shared response-header hostile mutation anchor is absent.")
        try:
            VALIDATOR.validate_sensitive_response_header_contract(candidate_app, host_verify)
        except RuntimeError:
            continue
        raise RuntimeError("Shared response-header source accepted a hostile composition.")

    owner_probe_line = (
        "          sudo docker exec app /usr/local/bin/rails runner 'require \"etc\"; "
        "raise unless Process.euid == Etc.getpwnam(\"discourse\").uid; "
        "raise unless GitUtils.git_version == \"cbf996f65aae3da1843224aa624bcd9a225931ac\"; "
        "ActiveRecord::Base.connection.execute(\"SELECT 1\"); "
        "raise if Upload.exists?(sha1: \"0000000000000000000000000000000000000000\")'"
    )
    moved_owner_probe = workflow.replace(owner_probe_line + "\n", "", 1).replace(
        "          transcript=",
        owner_probe_line + "\n          transcript=",
        1,
    )
    target_step_prefix = (
        "      - name: Verify imported theme, settings, metadata, and mail\n"
        "        shell: bash\n"
        "        run: |\n"
        "          set -euo pipefail"
    )
    workflow_hostiles = (
        workflow.replace(
            target_step_prefix,
            target_step_prefix.replace("set -euo pipefail", "set -uo pipefail"),
            1,
        ),
        workflow.replace(owner_probe_line, "          # " + owner_probe_line.strip(), 1),
        moved_owner_probe,
        workflow.replace("sudo docker exec app nginx -T", "true || sudo docker exec app nginx -T", 1),
        workflow.replace(
            'avatar_marker = r"location ~ ^/(svg-sprite/|letter_avatar/|letter_avatar_proxy/|user_avatar|',
            'avatar_marker = r"location ~ ^/(user_avatar|',
            1,
        ),
        workflow.replace(
            'raise SystemExit("rendered nginx cache-accelerated response-header boundary differs")',
            "raise SystemExit(0)",
            1,
        ),
        workflow.replace(
            'sections("/etc/nginx/conf.d/outlets/server/35-mochirii-public-response-headers.conf")',
            'sections("/tmp/hostile.conf")',
            1,
        ),
        workflow.replace(
            'Upload.exists?(sha1: "0000000000000000000000000000000000000000")',
            'Upload.exists?(sha1: "1111111111111111111111111111111111111111")',
            1,
        ),
        workflow.replace('routes != ["uploads/show_short"]', 'routes != ["uploads/show"]', 1),
        workflow.replace('[[ "$proxied_status" == "404" ]]', "true", 1),
    )
    for candidate_workflow in workflow_hostiles:
        if candidate_workflow == workflow:
            raise RuntimeError("Disposable rendered nginx hostile mutation anchor is absent.")
        try:
            VALIDATOR.validate_disposable_nginx_response_header_proof(candidate_workflow)
        except RuntimeError:
            continue
        raise RuntimeError("Disposable rendered nginx proof accepted a hostile mutation.")

    early_success = host_verify.replace(
        'python3 -B - "${nginx_log}" <<\'PY\' >/dev/null\nimport pathlib\nimport re\n',
        'python3 -B - "${nginx_log}" <<\'PY\' >/dev/null\nimport pathlib\nimport re\nraise SystemExit(0)\n',
        1,
    )
    try:
        VALIDATOR.validate_sensitive_response_header_contract(app, early_success)
    except RuntimeError:
        pass
    else:
        raise RuntimeError("Hosted sensitive response-header verifier accepted an early successful exit.")

    skipped_host_verifier = host_verify.replace(
        'python3 -B - "${nginx_log}" <<\'PY\' >/dev/null\n',
        'true || python3 -B - "${nginx_log}" <<\'PY\' >/dev/null\n',
        1,
    )
    if skipped_host_verifier == host_verify:
        raise RuntimeError("Hosted sensitive response-header invocation anchor is absent.")
    try:
        VALIDATOR.validate_sensitive_response_header_contract(app, skipped_host_verifier)
    except RuntimeError:
        pass
    else:
        raise RuntimeError("Hosted sensitive response-header verifier accepted a skipped invocation.")

    callback_end = app.index("\n        }", app.index(markers[0])) + len("\n        }")
    parent_pass = app[:callback_end] + "\n        proxy_pass_header Referrer-Policy;" + app[callback_end:]
    combined_parent_pass = (
        app[:callback_end]
        + "\n        proxy_hide_header X-Harmless; proxy_pass_header Referrer-Policy;"
        + app[callback_end:]
    )
    quoted_parent_pass = (
        app[:callback_end] + '\n        "proxy_pass_header" Referrer-Policy;' + app[callback_end:]
    )
    escaped_parent_pass = (
        app[:callback_end] + "\n        proxy\\_pass_header Referrer-Policy;" + app[callback_end:]
    )
    hostile_source_outlet = app[:outlet_end] + "        expires 1h;\n" + app[outlet_end:]
    for hostile_parent in (
        parent_pass,
        combined_parent_pass,
        quoted_parent_pass,
        escaped_parent_pass,
        hostile_source_outlet,
    ):
        try:
            VALIDATOR.validate_sensitive_response_header_contract(hostile_parent, host_verify)
        except RuntimeError:
            continue
        raise RuntimeError("Sensitive response-header source accepted an inherited proxy_pass_header.")

    host_start_marker = 'python3 -B - "${nginx_log}" <<\'PY\' >/dev/null\n'
    host_start = host_verify.index(host_start_marker) + len(host_start_marker)
    host_python = host_verify[host_start:host_verify.index("\nPY\n", host_start)]
    rendered_app = rendered_nginx(app)
    runtime_cases = [(rendered_app, True)]
    avatar_include = "    include conf.d/outlets/discourse/35-mochirii-public-response-headers.inc;\n"
    avatar_marker = "  location ~ ^/(svg-sprite/|letter_avatar/|letter_avatar_proxy/|user_avatar|highlight-js|stylesheets|theme-javascripts|favicon/proxied|service-worker|extra-locales/) {\n"
    avatar_username_hide = '    proxy_hide_header "X-Discourse-Username";\n'
    pinned_username_log_fragment = (
        '"$upstream_http_x_discourse_username" "$upstream_http_x_discourse_trackview"'
    )
    private_username_log_fragment = '"-" "$upstream_http_x_discourse_trackview"'
    avatar_runtime_hostiles = (
        rendered_app.replace(avatar_include, "", 1),
        rendered_app.replace(avatar_include, "    # include conf.d/outlets/discourse/35-mochirii-public-response-headers.inc;\n", 1),
        rendered_app.replace(avatar_include, avatar_include + avatar_include, 1),
        rendered_app.replace(avatar_include, "    include conf.d/outlets/discourse/*.conf;\n", 1),
        rendered_app.replace(avatar_include, "    include $hostile_path;\n", 1),
        rendered_app.replace(avatar_include, avatar_include + "    sub_filter_once off;\n", 1),
        rendered_app.replace(avatar_include, avatar_include + "    proxy_pass_header X-Discourse-Route;\n", 1),
        rendered_app.replace(avatar_username_hide, "", 1),
        rendered_app.replace(avatar_include, "", 1).replace(avatar_marker, avatar_include + avatar_marker, 1),
        rendered_app.replace(private_username_log_fragment, pinned_username_log_fragment, 1),
        rendered_app.replace(private_username_log_fragment, "", 1),
        rendered_app.replace(
            private_username_log_fragment,
            private_username_log_fragment + " " + private_username_log_fragment,
            1,
        ),
        rendered_app.replace(
            private_username_log_fragment,
            '"$remote_user" "$upstream_http_x_discourse_trackview"',
            1,
        ),
        rendered_app + "\n# $upstream_http_x_discourse_username\n",
    )
    if any(candidate == rendered_app for candidate in avatar_runtime_hostiles):
        raise RuntimeError("Cache-accelerated response-header hostile mutation anchor is absent.")
    runtime_cases.extend((candidate, False) for candidate in avatar_runtime_hostiles)
    runtime_cases.extend(
        (
            (
                rendered_nginx(
                    app[:callback_end] + "\n        proxy_pass_header Referrer-Policy;" + app[callback_end:]
                ),
                False,
            ),
            (rendered_nginx(quoted_parent_pass), False),
            (rendered_nginx(escaped_parent_pass), False),
        )
    )
    for marker in markers:
        start = app.index(marker)
        hide = "          proxy_hide_header Referrer-Policy;\n"
        position = app.index(hide, start)
        end = app.index("\n        }", start) + len("\n        }")
        duplicate_location = app[:start] + app[start:end] + "\n" + app[start:]
        commented = app[:position] + "          # proxy_hide_header Referrer-Policy;\n" + app[position + len(hide):]
        hostile_add = app[:position] + '          add_header Referrer-Policy "unsafe-url" always;\n' + app[position:]
        hostile_pass = app[:position] + "          proxy_pass_header    referrer-policy;\n" + app[position:]
        hostile_cache = app[:position] + '          add_header Cache-Control "public" always;\n' + app[position:]
        hostile_include = app[:position] + "          include /tmp/hostile-sensitive.conf;\n" + app[position:]
        duplicate = app[:position] + hide + app[position:]
        expires_off = "          expires off;\n"
        expires_position = app.index(expires_off, start)
        missing_expires_off = app[:expires_position] + app[expires_position + len(expires_off):]
        add_start = app.index('          add_header Cache-Control "private, no-store, max-age=0" always;\n', start)
        add_end_line = '          add_header Referrer-Policy "no-referrer" always;\n'
        add_end = app.index(add_end_line, add_start) + len(add_end_line)
        nested = (
            app[:add_start]
            + '          if ($arg_fixture = "1") {\n'
            + app[add_start:add_end]
            + "          }\n"
            + "          proxy_pass_header Referrer-Policy;\n"
            + app[add_end:]
        )
        runtime_cases.extend(
            (rendered_nginx(candidate), False)
            for candidate in (
                duplicate_location,
                commented,
                hostile_add,
                hostile_pass,
                hostile_cache,
                hostile_include,
                duplicate,
                missing_expires_off,
                nested,
            )
        )
    with tempfile.TemporaryDirectory() as directory:
        nginx = Path(directory) / "nginx.conf"
        for source, expected in runtime_cases:
            nginx.write_text(source, encoding="utf-8")
            completed = subprocess.run(
                [sys.executable, "-B", "-", str(nginx)],
                input=host_python,
                text=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                timeout=10,
                check=False,
            )
            if (completed.returncode == 0) is not expected:
                raise RuntimeError("Hosted sensitive response-header verifier accepted a hostile runtime mutation.")


def test_https_consumer_fixture_contract() -> None:
    verifier = (ROOT / "scripts/verify-discourse-connect.py").read_text(encoding="utf-8")
    VALIDATOR.validate_https_consumer_fixture_contract(verifier)
    hostile_mutations = (
        ('"X-Forwarded-Proto": "https"', '"X-Forwarded-Proto": "http"'),
        (
            '                "Accept": "application/json",\n'
            '                "X-Requested-With": "XMLHttpRequest",\n',
            '                "Accept": "text/html",\n'
            '                "X-Requested-With": "XMLHttpRequest",\n',
        ),
        (
            '                "Accept": "application/json",\n'
            '                "X-Requested-With": "XMLHttpRequest",\n',
            '                "Accept": "application/json",\n',
        ),
        (
            "    status, headers, body = session.get_json(path)\n",
            "    status, headers, body = session.get(path)\n",
        ),
        (
            "        info_status, _info_headers, info_body = recovered.get_json(path)\n",
            "        info_status, _info_headers, info_body = recovered.get(path)\n",
        ),
        (
            'ENV["MOCHIRII_STAGE4_CONNECT_FIXTURE"] == "true"',
            'ENV["MOCHIRII_STAGE4_FIXTURE"] == "true"',
        ),
        ("original_force_https = read_fixture_force_https()", "original_force_https = False"),
        ("set_fixture_force_https(self.original)", "set_fixture_force_https(False)"),
        ("raise SystemExit(128 + signum)", "raise RuntimeError(signum)"),
        ("atexit.unregister(restore_force_https)", "atexit.unregister(lambda: None)"),
        (
            "run_with_fixture_force_https(lambda: verify_fixture(args, secret))",
            "verify_fixture(args, secret)",
        ),
        (
            'arguments=("true" if enabled else "false",)',
            'arguments=("false" if enabled else "true",)',
        ),
        (
            "    finally:\n        absence_error: BaseException | None = None",
            "    absence_error: BaseException | None = None",
        ),
        (
            "def run_with_fixture_force_https(operation: Callable[[], None]) -> None:\n",
            "def run_with_fixture_force_https(operation: Callable[[], None]) -> None:\n"
            "    return\n",
        ),
        (
            "def verify_fixture(args: argparse.Namespace, secret: bytes) -> None:\n",
            "def verify_fixture(args: argparse.Namespace, secret: bytes) -> None:\n"
            "    return\n",
        ),
        (
            "    verify_fixture_user()\n",
            "    os._exit(0)\n",
        ),
        (
            "    valid = Session(args.port)\n",
            "    valid, verify_fixture_user = Session(args.port), (lambda: None)\n",
        ),
        (
            '    current = document.get("current_user")\n',
            "    current = document\n",
        ),
        (
            '    if current.get("username") != "mochirii-s4-test":\n',
            "    if False:\n",
        ),
        (
            '    if current.get("admin") is not require_admin:\n',
            "    if False:\n",
        ),
        (
            "        current_status,\n"
            "        current_body,\n"
            '        "Valid consumer callback",\n'
            "        require_admin=False,\n",
            "        200,\n"
            "        b'{\"current_user\":{\"username\":\"mochirii-s4-test\"}}',\n"
            '        "Valid consumer callback",\n'
            "        require_admin=False,\n",
        ),
        (
            '        "Valid consumer callback",\n'
            "        require_admin=False,\n",
            "        encoded,\n"
            "        require_admin=False,\n",
        ),
        (
            '            "Pinned admin email-login",\n'
            "            require_admin=True,\n",
            '            "Pinned admin email-login",\n'
            "            require_admin=False,\n",
        ),
        (
            '        current_status, _current_headers, current_body = recovered.get("/session/current.json")\n',
            '        os._exit(0)\n'
            '        current_status, _current_headers, current_body = recovered.get("/session/current.json")\n',
        ),
        (
            '            "Pinned admin email-login",\n'
            "            require_admin=True,\n"
            "        )\n"
            "        replay = Session(port)\n",
            '            "Pinned admin email-login",\n'
            "            require_admin=True,\n"
            "        )\n"
            "        os._exit(0)\n"
            "        replay = Session(port)\n",
        ),
        (
            '    try:\n        superseded_token = admin_recovery_fixture("issue")\n',
            '    try:\n'
            '        globals()["verify_exact_fixture_session"] = lambda *_args, **_kwargs: None\n'
            '        superseded_token = admin_recovery_fixture("issue")\n',
        ),
        (
            '        current_status, _current_headers, current_body = recovered.get("/session/current.json")\n',
            '        current_status, _current_headers, current_body = (\n'
            '            200, {}, b\'{"current_user":{"username":"mochirii-s4-test","admin":true}\'}\n'
            '        )\n',
        ),
        (
            '    finally:\n        admin_recovery_fixture("cleanup")\n',
            '    finally:\n        pass\n',
        ),
        (
            "    verify_admin_email_recovery(args.port, valid)\n",
            "    verify_admin_email_recovery(args.port, signed_out)\n",
        ),
        (
            "    if status == 403:\n"
            "        return\n",
            "    if status in {200, 403}:\n"
            "        return\n",
        ),
        (
            '    retry_after = "present" if "retry-after" in headers else "absent"\n',
            '    retry_after = "absent"\n',
        ),
    )
    for current, hostile in hostile_mutations:
        candidate = verifier.replace(current, hostile, 1)
        if candidate == verifier:
            raise RuntimeError("HTTPS consumer fixture hostile mutation anchor is absent.")
        try:
            VALIDATOR.validate_https_consumer_fixture_contract(candidate)
        except RuntimeError:
            continue
        raise RuntimeError("HTTPS consumer fixture accepted a scheme or restoration hostile mutation.")

    unreachable_wrapper = verifier.replace(
        "    run_with_fixture_force_https(lambda: verify_fixture(args, secret))\n"
        '    print("Built-in DiscourseConnect consumer fixtures passed.")\n'
        "    return 0",
        "    verify_fixture(args, secret)\n"
        "    return 0\n"
        "    run_with_fixture_force_https(lambda: verify_fixture(args, secret))\n"
        '    print("Built-in DiscourseConnect consumer fixtures passed.")',
        1,
    )
    if unreachable_wrapper == verifier:
        raise RuntimeError("HTTPS consumer fixture unreachable-wrapper anchor is absent.")
    try:
        VALIDATOR.validate_https_consumer_fixture_contract(unreachable_wrapper)
    except RuntimeError:
        pass
    else:
        raise RuntimeError("HTTPS consumer fixture accepted an unreachable wrapper call.")

    shadowed_wrapper = verifier.replace(
        "    run_with_fixture_force_https(lambda: verify_fixture(args, secret))",
        "    run_with_fixture_force_https = lambda _operation: None\n"
        "    run_with_fixture_force_https(lambda: verify_fixture(args, secret))",
        1,
    )
    if shadowed_wrapper == verifier:
        raise RuntimeError("HTTPS consumer fixture shadowed-wrapper anchor is absent.")
    try:
        VALIDATOR.validate_https_consumer_fixture_contract(shadowed_wrapper)
    except RuntimeError:
        pass
    else:
        raise RuntimeError("HTTPS consumer fixture accepted a locally shadowed wrapper.")

    rebound_wrapper = verifier.replace(
        "def main() -> int:",
        "run_with_fixture_force_https = lambda _operation: None\n\n\ndef main() -> int:",
        1,
    )
    if rebound_wrapper == verifier:
        raise RuntimeError("HTTPS consumer fixture rebound-wrapper anchor is absent.")
    try:
        VALIDATOR.validate_https_consumer_fixture_contract(rebound_wrapper)
    except RuntimeError:
        pass
    else:
        raise RuntimeError("HTTPS consumer fixture accepted a rebound global wrapper.")

    pattern_rebound_wrapper = verifier.replace(
        "def main() -> int:",
        "match (lambda _operation: None):\n"
        "    case run_with_fixture_force_https:\n"
        "        pass\n\n\n"
        "def main() -> int:",
        1,
    )
    if pattern_rebound_wrapper == verifier:
        raise RuntimeError("HTTPS consumer fixture pattern-rebound anchor is absent.")
    try:
        VALIDATOR.validate_https_consumer_fixture_contract(pattern_rebound_wrapper)
    except RuntimeError:
        pass
    else:
        raise RuntimeError("HTTPS consumer fixture accepted a pattern-rebound global wrapper.")

    reflectively_rebound_wrapper = verifier.replace(
        "def main() -> int:",
        'globals()["run_with_fixture_force_https"] = lambda _operation: None\n\n\n'
        "def main() -> int:",
        1,
    )
    if reflectively_rebound_wrapper == verifier:
        raise RuntimeError("HTTPS consumer fixture reflective-rebind anchor is absent.")
    try:
        VALIDATOR.validate_https_consumer_fixture_contract(reflectively_rebound_wrapper)
    except RuntimeError:
        pass
    else:
        raise RuntimeError("HTTPS consumer fixture accepted a reflective global wrapper rebind.")

    disabled_entrypoint = verifier.replace(
        'if __name__ == "__main__":\n    raise SystemExit(main())',
        'if __name__ == "__main__":\n    pass',
        1,
    )
    if disabled_entrypoint == verifier:
        raise RuntimeError("HTTPS consumer fixture disabled-entrypoint anchor is absent.")
    try:
        VALIDATOR.validate_https_consumer_fixture_contract(disabled_entrypoint)
    except RuntimeError:
        pass
    else:
        raise RuntimeError("HTTPS consumer fixture accepted a disabled module entry point.")

    imported_module_name = verifier.replace(
        "def main() -> int:",
        "from sys import __name__\n\n\ndef main() -> int:",
        1,
    )
    if imported_module_name == verifier:
        raise RuntimeError("HTTPS consumer fixture imported-name anchor is absent.")
    try:
        VALIDATOR.validate_https_consumer_fixture_contract(imported_module_name)
    except RuntimeError:
        pass
    else:
        raise RuntimeError("HTTPS consumer fixture accepted an imported module name guard.")

    rebound_session_checker = verifier.replace(
        "def verify_fixture_user() -> None:\n",
        "def verify_fixture_user() -> None:\n"
        "    global verify_exact_fixture_session\n"
        "    verify_exact_fixture_session = lambda *_args, **_kwargs: None\n",
        1,
    )
    if rebound_session_checker == verifier:
        raise RuntimeError("Authenticated-session transitive-rebind mutation anchor is absent.")
    original_read = VALIDATOR.read
    try:
        VALIDATOR.read = (
            lambda path: rebound_session_checker
            if path == "scripts/verify-discourse-connect.py"
            else original_read(path)
        )
        try:
            VALIDATOR.validate_secrets_and_workflows()
        except RuntimeError:
            pass
        else:
            raise RuntimeError("Repository validator accepted a transitive authenticated-session rebind.")
    finally:
        VALIDATOR.read = original_read

    contained_activation = (ROOT / "scripts/verify-contained-activation.sh").read_text(
        encoding="utf-8"
    )
    exact_outcome_mutations = (
        (
            "scripts/verify-discourse-connect.py",
            verifier,
            "    assert_branded_error(status, headers, body, 500)\n",
            "    # assert_branded_error(status, headers, body, 500)\n"
            "    assert_branded_error(status, headers, body, 422)\n",
        ),
        (
            "scripts/verify-contained-activation.sh",
            contained_activation,
            '("/session/sso_login?sso=Zm9v&sso=YmFy&sig=" + "0" * 64, 500),\n',
            '# ("/session/sso_login?sso=Zm9v&sso=YmFy&sig=" + "0" * 64, 500),\n'
            '("/session/sso_login?sso=Zm9v&sso=YmFy&sig=" + "0" * 64, 422),\n',
        ),
    )
    for relative, source, current, hostile in exact_outcome_mutations:
        candidate = source.replace(current, hostile, 1)
        if candidate == source:
            raise RuntimeError("Pinned consumer outcome hostile mutation anchor is absent.")
        if relative == "scripts/verify-discourse-connect.py":
            try:
                VALIDATOR.validate_https_consumer_fixture_contract(candidate)
            except RuntimeError:
                continue
            raise RuntimeError("Fixture validator accepted a decoy-backed consumer outcome mutation.")
        original_read = VALIDATOR.read
        try:
            VALIDATOR.read = (
                lambda path, relative=relative, candidate=candidate: candidate
                if path == relative
                else original_read(path)
            )
            try:
                VALIDATOR.validate_secrets_and_workflows()
            except RuntimeError:
                continue
            raise RuntimeError("Repository validator accepted a decoy-backed consumer outcome mutation.")
        finally:
            VALIDATOR.read = original_read

    private_headers = {
        "cache-control": ["private, no-store, max-age=0"],
        "expires": ["0"],
        "pragma": ["no-cache"],
        "referrer-policy": ["no-referrer"],
    }
    branded_body = b"<html><body>Mochirii Forums</body></html>"
    CONNECT_FIXTURE.assert_branded_error(500, private_headers, branded_body, 500)
    for status, headers, body, expected in (
        (422, private_headers, branded_body, 500),
        (500, {**private_headers, "cache-control": ["public"]}, branded_body, 500),
        (500, private_headers, b"<html><body>Request unavailable</body></html>", 500),
    ):
        try:
            CONNECT_FIXTURE.assert_branded_error(status, headers, body, expected)
        except RuntimeError:
            continue
        raise RuntimeError("Hostile consumer response assertion accepted a wrong status or public response.")

    class NonceFailureSession:
        def __init__(self, status: int, headers: dict[str, list[str]]) -> None:
            self.status = status
            self.headers = headers

        def get(self, path: str) -> tuple[int, dict[str, list[str]], bytes]:
            if path != "/session/sso?return_path=%2Flatest":
                raise RuntimeError("Nonce status diagnostic fixture path changed.")
            return self.status, self.headers, b"MOCHIRII_PRIVATE_NONCE_BODY_SENTINEL"

    for status, headers, expected in (
        (
            429,
            {"retry-after": ["MOCHIRII_PRIVATE_RETRY_SENTINEL"]},
            "Built-in consumer did not issue its signed producer request "
            "[response=rate-limited; retry-after=present].",
        ),
        (
            503,
            {"x-private-sentinel": ["MOCHIRII_PRIVATE_HEADER_SENTINEL"]},
            "Built-in consumer did not issue its signed producer request "
            "[response=unavailable; retry-after=absent].",
        ),
        (
            404,
            {},
            "Built-in consumer did not issue its signed producer request "
            "[response=not-found; retry-after=absent].",
        ),
        (
            200,
            {},
            "Built-in consumer did not issue its signed producer request "
            "[response=unexpected-success; retry-after=absent].",
        ),
        (
            301,
            {},
            "Built-in consumer did not issue its signed producer request "
            "[response=unexpected-redirect; retry-after=absent].",
        ),
        (
            0,
            {},
            "Built-in consumer did not issue its signed producer request "
            "[response=invalid-status; retry-after=absent].",
        ),
    ):
        try:
            CONNECT_FIXTURE.request_nonce(NonceFailureSession(status, headers), b"0" * 64)
        except RuntimeError as error:
            message = str(error)
            if message != expected or "PRIVATE" in message or len(message) > 192:
                raise RuntimeError("Nonce status diagnostic is not fixed, bounded, and redacted.") from error
        else:
            raise RuntimeError("Nonce status diagnostic accepted a non-redirect consumer response.")

    pacing_events: list[tuple[str, float | None]] = []

    class MetadataResponse:
        def __init__(self, headers: list[tuple[str, str]]) -> None:
            self.status = 404
            self.headers = headers

        def getheaders(self) -> list[tuple[str, str]]:
            return self.headers

        def read(self, _maximum: int) -> bytes:
            raise RuntimeError("Prohibited response metadata was not rejected before body ingestion.")

    class MetadataConnection:
        response: MetadataResponse

        def __init__(self, host: str, port: int, *, timeout: int) -> None:
            if host != "127.0.0.1" or port != 18080 or timeout != 20:
                raise RuntimeError("Consumer response-metadata connection fixture changed.")
            pacing_events.append(("connect", None))

        def request(self, method: str, path: str, *, body, headers: dict[str, str]) -> None:
            if method != "GET" or path != "/metadata-fixture" or body is not None or not headers:
                raise RuntimeError("Consumer response-metadata request fixture changed.")

        def getresponse(self) -> MetadataResponse:
            return self.response

        def close(self) -> None:
            return None

    original_connection = CONNECT_FIXTURE.http.client.HTTPConnection
    original_sleep = CONNECT_FIXTURE.time.sleep
    try:
        CONNECT_FIXTURE.http.client.HTTPConnection = MetadataConnection
        CONNECT_FIXTURE.time.sleep = lambda seconds: pacing_events.append(("sleep", seconds))
        metadata_name_categories = (
            ("X-Discourse-Route", "route"),
            ("X-Discourse-Username", "username"),
            ("X-Discourse-Crawler-View", "crawler"),
            ("Discourse-No-Onebox", "onebox"),
            ("Discourse-Rate-Limit-Error-Code", "rate-limit"),
            ("Discourse-Xhr-Redirect", "xhr-redirect"),
            ("Discourse-Actions-Remaining", "action-budget"),
            ("Discourse-Actions-Max", "action-budget"),
            ("Discourse-Logged-Out", "logged-out"),
            ("X-Discourse-TrackView", "view-tracking"),
            ("X-Discourse-BrowserPageView", "view-tracking"),
            ("X-Discourse-Cached", "cache"),
            ("dIsCoUrSe-ReAdOnLy", "readonly"),
            ("X-Discourse-Private-Sentinel", "other-upstream"),
            ("X-DigitalOcean-Private-Sentinel", "provider"),
        )
        metadata_cases = tuple(
            (
                [(name, "private-sentinel-value")],
                "A member-facing response header name exposed "
                + ("provider" if category == "provider" else "upstream-product")
                + f" identity [category={category}].",
            )
            for name, category in metadata_name_categories
        ) + (
            (
                [("Content-Security-Policy", "worker-src https://private-sentinel.digitaloceanspaces.com")],
                "A member-facing response header security-policy value exposed provider identity.",
            ),
            (
                [("Location", "https://meta.discourse.org/private-sentinel")],
                "A member-facing response header redirect value exposed upstream-product identity.",
            ),
            (
                [("X-Fixture", "https://meta.discourse.org/private-sentinel")],
                "A member-facing response header other value exposed upstream-product identity.",
            ),
        )
        for headers, expected_error in metadata_cases:
            MetadataConnection.response = MetadataResponse(headers)
            try:
                CONNECT_FIXTURE.Session(18080).get("/metadata-fixture")
            except RuntimeError as error:
                if (
                    str(error) != expected_error
                    or "private-sentinel" in str(error).lower()
                    or len(str(error)) > 192
                ):
                    raise RuntimeError("Consumer response-metadata diagnostic is not fixed and redacted.") from error
            else:
                raise RuntimeError("Consumer response-metadata diagnostic accepted prohibited identity.")
        expected_pacing = [
            event
            for _case in metadata_cases
            for event in (
                ("sleep", CONNECT_FIXTURE.REQUEST_INTERVAL_SECONDS),
                ("connect", None),
            )
        ]
        if (
            CONNECT_FIXTURE.REQUEST_INTERVAL_SECONDS != 0.350
            or pacing_events != expected_pacing
        ):
            raise RuntimeError("Consumer fixture requests are not deterministically paced before connection.")
    finally:
        CONNECT_FIXTURE.http.client.HTTPConnection = original_connection
        CONNECT_FIXTURE.time.sleep = original_sleep

    class PacingResponse:
        status = 204
        headers: list[tuple[str, str]] = []

        def getheaders(self) -> list[tuple[str, str]]:
            return self.headers

        def read(self, _maximum: int) -> bytes:
            return b""

    pacing_events = []
    pacing_requests: list[tuple[str, str]] = []

    class PacingConnection:
        def __init__(self, host: str, port: int, *, timeout: int) -> None:
            if host != "127.0.0.1" or port != 18080 or timeout != 20:
                raise RuntimeError("Consumer pacing connection fixture changed.")
            pacing_events.append(("connect", None))

        def request(self, method: str, path: str, *, body, headers: dict[str, str]) -> None:
            if not headers:
                raise RuntimeError("Consumer pacing request headers were absent.")
            if path == "/paced-json" and (
                method != "GET"
                or headers.get("Accept") != "application/json"
                or headers.get("X-Requested-With") != "XMLHttpRequest"
            ):
                raise RuntimeError("Consumer JSON request metadata changed.")
            pacing_events.append(("request", None))
            pacing_requests.append((method, path))

        def getresponse(self) -> PacingResponse:
            return PacingResponse()

        def close(self) -> None:
            return None

    original_connection = CONNECT_FIXTURE.http.client.HTTPConnection
    original_sleep = CONNECT_FIXTURE.time.sleep
    try:
        CONNECT_FIXTURE.http.client.HTTPConnection = PacingConnection
        CONNECT_FIXTURE.time.sleep = lambda seconds: pacing_events.append(("sleep", seconds))
        CONNECT_FIXTURE.Session(18080).get("/paced-get")
        CONNECT_FIXTURE.Session(18080).get_json("/paced-json")
        CONNECT_FIXTURE.Session(18080).post_form(
            "/paced-post",
            {"email": "fixture@forums.mochirii.com"},
            "a" * 32,
        )
        CONNECT_FIXTURE.Session(18080).request("PUT", "/paced-direct")
        if pacing_requests != [
            ("GET", "/paced-get"),
            ("GET", "/paced-json"),
            ("POST", "/paced-post"),
            ("PUT", "/paced-direct"),
        ]:
            raise RuntimeError("Consumer fixture pacing does not cover every request entrypoint.")
        expected_pacing = [
            event
            for _request in pacing_requests
            for event in (
                ("sleep", CONNECT_FIXTURE.REQUEST_INTERVAL_SECONDS),
                ("connect", None),
                ("request", None),
            )
        ]
        if pacing_events != expected_pacing:
            raise RuntimeError("Consumer fixture pacing is not immediately before every connection.")

        PacingResponse.status = 429
        pacing_events.clear()
        pacing_requests.clear()
        try:
            CONNECT_FIXTURE.request_nonce(CONNECT_FIXTURE.Session(18080), b"0" * 64)
        except RuntimeError as error:
            if str(error) != (
                "Built-in consumer did not issue its signed producer request "
                "[response=rate-limited; retry-after=absent]."
            ):
                raise RuntimeError("Paced rate-limit diagnostic changed.") from error
        else:
            raise RuntimeError("Paced consumer request retried or accepted a rate-limit denial.")
        if (
            pacing_requests != [("GET", "/session/sso?return_path=%2Flatest")]
            or pacing_events != [
                ("sleep", CONNECT_FIXTURE.REQUEST_INTERVAL_SECONDS),
                ("connect", None),
                ("request", None),
            ]
        ):
            raise RuntimeError("Rate-limit denial was not one exactly paced consumer request.")
    finally:
        PacingResponse.status = 204
        CONNECT_FIXTURE.http.client.HTTPConnection = original_connection
        CONNECT_FIXTURE.time.sleep = original_sleep

    invalid_token_path = "/session/email-login/fixture-invalid-token"
    invalid_token_message = "A superseded administrator recovery token remained valid."

    class InvalidAdminTokenSession:
        def __init__(self, status: int, headers: dict[str, list[str]], body: bytes) -> None:
            self.status = status
            self.headers = headers
            self.body = body
            self.requests: list[str] = []

        def get_json(self, path: str) -> tuple[int, dict[str, list[str]], bytes]:
            self.requests.append(path)
            return self.status, self.headers, self.body

        def get(self, _path: str) -> tuple[int, dict[str, list[str]], bytes]:
            raise RuntimeError("Administrator recovery token verifier did not request JSON.")

    valid_invalid_token = InvalidAdminTokenSession(
        403,
        {},
        b"MOCHIRII_PRIVATE_FORBIDDEN_BODY_SENTINEL",
    )
    CONNECT_FIXTURE.assert_admin_recovery_token_invalid(
        valid_invalid_token,
        invalid_token_path,
        invalid_token_message,
    )
    if valid_invalid_token.requests != [invalid_token_path]:
        raise RuntimeError("Invalid administrator recovery token verifier request count changed.")

    requested_token = invalid_token_path.rsplit("/", 1)[1]
    invalid_token_body = b'{"can_login":false,"error":"MOCHIRII_PRIVATE_INVALID_TOKEN_SENTINEL"}'
    requested_token_body = json.dumps(
        {
            "can_login": True,
            "token": requested_token,
            "token_email": "stage4-fixture@forums.mochirii.com",
            "private": "MOCHIRII_PRIVATE_CURRENT_TOKEN_SENTINEL",
        },
        separators=(",", ":"),
    ).encode("utf-8")
    hostile_invalid_token_responses = (
        (200, {}, invalid_token_body, "unexpected-success", "absent", ("ok", "other", "invalid-token")),
        (
            200,
            {"content-type": ["application/json; charset=utf-8"]},
            requested_token_body,
            "unexpected-success",
            "absent",
            ("ok", "json", "requested-token-current"),
        ),
        (
            200,
            {"content-type": ["application/json"]},
            json.dumps(
                {
                    "can_login": True,
                    "token": "MOCHIRII_PRIVATE_WRONG_TOKEN_SENTINEL",
                    "token_email": "stage4-fixture@forums.mochirii.com",
                },
                separators=(",", ":"),
            ).encode("utf-8"),
            "unexpected-success",
            "absent",
            ("ok", "json", "other"),
        ),
        (
            200,
            {"content-type": ["application/json"]},
            json.dumps(
                {
                    "can_login": True,
                    "token": requested_token,
                    "token_email": "MOCHIRII_PRIVATE_WRONG_EMAIL_SENTINEL",
                },
                separators=(",", ":"),
            ).encode("utf-8"),
            "unexpected-success",
            "absent",
            ("ok", "json", "other"),
        ),
        (
            200,
            {"content-type": ["application/json"]},
            b'{"can_login":false,"error":false,"private":"MOCHIRII_PRIVATE_ERROR_TYPE_SENTINEL"}',
            "unexpected-success",
            "absent",
            ("ok", "json", "other"),
        ),
        (
            201,
            {"content-type": ["application/json"]},
            requested_token_body,
            "unexpected-success",
            "absent",
            ("other", "json", "requested-token-current"),
        ),
        (
            204,
            {"content-type": ["application/json"]},
            b"",
            "unexpected-success",
            "absent",
            ("no-content", "json", "malformed"),
        ),
        (
            200,
            {"content-type": ["text/html; charset=utf-8"]},
            b"<html>MOCHIRII_PRIVATE_HTML_SENTINEL</html>",
            "unexpected-success",
            "absent",
            ("ok", "html", "malformed"),
        ),
        (
            200,
            {"content-type": ["application/json", "text/html"]},
            invalid_token_body,
            "unexpected-success",
            "absent",
            ("ok", "other", "invalid-token"),
        ),
        (
            200,
            {"content-type": ["application/json"]},
            b'{"can_login":true,"can_login":false,"error":"MOCHIRII_PRIVATE_DUPLICATE_SENTINEL"}',
            "unexpected-success",
            "absent",
            ("ok", "json", "malformed"),
        ),
        (
            200,
            {"content-type": ["application/json"]},
            b'{"can_login":NaN,"private":"MOCHIRII_PRIVATE_CONSTANT_SENTINEL"}',
            "unexpected-success",
            "absent",
            ("ok", "json", "malformed"),
        ),
        (
            200,
            {"content-type": ["application/json"]},
            b'{"can_login":"\xff"}',
            "unexpected-success",
            "absent",
            ("ok", "json", "malformed"),
        ),
        (
            200,
            {"content-type": ["application/json"]},
            b'{"private":"MOCHIRII_PRIVATE_MALFORMED_SENTINEL","can_login":',
            "unexpected-success",
            "absent",
            ("ok", "json", "malformed"),
        ),
        (
            200,
            {"content-type": ["application/json"]},
            b'["MOCHIRII_PRIVATE_OTHER_SENTINEL"]',
            "unexpected-success",
            "absent",
            ("ok", "json", "other"),
        ),
        (302, {}, invalid_token_body, "unexpected-redirect", "absent", None),
        (400, {}, invalid_token_body, "bad-request", "absent", None),
        (401, {}, invalid_token_body, "unauthorized", "absent", None),
        (404, {}, invalid_token_body, "not-found", "absent", None),
        (408, {}, invalid_token_body, "request-timeout", "absent", None),
        (418, {}, invalid_token_body, "other-client-error", "absent", None),
        (419, {}, invalid_token_body, "private-denial", "absent", None),
        (422, {}, invalid_token_body, "unprocessable", "absent", None),
        (
            429,
            {"retry-after": ["MOCHIRII_PRIVATE_RETRY_SENTINEL"]},
            invalid_token_body,
            "rate-limited",
            "present",
            None,
        ),
        (500, {}, invalid_token_body, "internal-error", "absent", None),
        (501, {}, invalid_token_body, "other-server-error", "absent", None),
        (502, {}, invalid_token_body, "bad-gateway", "absent", None),
        (503, {}, invalid_token_body, "unavailable", "absent", None),
        (504, {}, invalid_token_body, "gateway-timeout", "absent", None),
        (700, {}, invalid_token_body, "invalid-status", "absent", None),
    )
    for status, headers, body, category, retry_after, success_categories in hostile_invalid_token_responses:
        hostile_session = InvalidAdminTokenSession(
            status,
            headers,
            body,
        )
        try:
            CONNECT_FIXTURE.assert_admin_recovery_token_invalid(
                hostile_session,
                invalid_token_path,
                invalid_token_message,
            )
        except RuntimeError as error:
            success_detail = (
                ""
                if success_categories is None
                else (
                    f"; status={success_categories[0]}; media={success_categories[1]}; "
                    f"envelope={success_categories[2]}"
                )
            )
            expected = (
                f"{invalid_token_message} "
                f"[response={category}{success_detail}; retry-after={retry_after}]"
            )
            if (
                str(error) != expected
                or "PRIVATE" in str(error)
                or invalid_token_path in str(error)
                or requested_token in str(error)
                or "stage4-fixture@forums.mochirii.com" in str(error)
                or len(str(error)) > 192
                or hostile_session.requests != [invalid_token_path]
            ):
                raise RuntimeError(
                    "Invalid administrator recovery token diagnostic is not fixed and redacted."
                ) from error
        else:
            raise RuntimeError(
                "Invalid administrator recovery token verifier accepted a non-forbidden response."
            )

    member_session = json.dumps(
        {"current_user": {"username": "mochirii-s4-test", "admin": False}},
        separators=(",", ":"),
    ).encode("utf-8")
    administrator_session = json.dumps(
        {"current_user": {"username": "mochirii-s4-test", "admin": True}},
        separators=(",", ":"),
    ).encode("utf-8")
    CONNECT_FIXTURE.verify_exact_fixture_session(
        200,
        member_session,
        "member fixture",
        require_admin=False,
    )
    CONNECT_FIXTURE.verify_exact_fixture_session(
        200,
        administrator_session,
        "administrator fixture",
        require_admin=True,
    )
    hostile_sessions = (
        (404, member_session, False),
        (200, b'{"username":"mochirii-s4-test","admin":true}', False),
        (200, b'{"current_user":null}', False),
        (200, b'{"current_user":[]}', False),
        (200, b'{"current_user":{"username":"wrong"}}', False),
        (200, administrator_session, False),
        (200, member_session, True),
        (200, b'{"current_user":{"username":"mochirii-s4-test","admin":1}}', True),
    )
    for status, body, require_admin in hostile_sessions:
        try:
            CONNECT_FIXTURE.verify_exact_fixture_session(
                status,
                body,
                "hostile fixture",
                require_admin=require_admin,
            )
        except RuntimeError:
            continue
        raise RuntimeError("Authenticated-session verifier accepted a hostile response shape or identity.")

    render_source = (ROOT / "scripts/render-app-config.py").read_text(encoding="utf-8")
    collision = render_source.replace(
        'scalar("stage4-developer@example.invalid")',
        'scalar("stage4-fixture@forums.mochirii.com")',
        1,
    )
    if collision == render_source:
        raise RuntimeError("Fixture developer/member collision mutation anchor is absent.")
    original_read = VALIDATOR.read
    try:
        VALIDATOR.read = lambda path: collision if path == "scripts/render-app-config.py" else original_read(path)
        try:
            VALIDATOR.validate_secrets_and_workflows()
        except RuntimeError:
            pass
        else:
            raise RuntimeError("Repository validator accepted a colliding fixture developer identity.")
    finally:
        VALIDATOR.read = original_read

    original_runner = CONNECT_FIXTURE.run_container_runner
    runner_calls: list[tuple[str, tuple[str, ...]]] = []
    try:
        def record_runner(
            script: str,
            *,
            arguments: tuple[str, ...] = (),
            input_bytes: bytes | None = None,
            capture_stdout: bool = False,
        ) -> bytes:
            if input_bytes is not None or capture_stdout:
                raise RuntimeError("Force-HTTPS setter changed its runner boundary.")
            runner_calls.append((script, arguments))
            return b""

        CONNECT_FIXTURE.run_container_runner = record_runner
        CONNECT_FIXTURE.set_fixture_force_https(True)
        CONNECT_FIXTURE.set_fixture_force_https(False)
        if [arguments for _script, arguments in runner_calls] != [("true",), ("false",)]:
            raise RuntimeError("Force-HTTPS setter inverted its Rails boolean arguments.")
        if any(
            'ENV["MOCHIRII_STAGE4_CONNECT_FIXTURE"] == "true"' not in script
            or 'ARGV.fetch(0) == "true"' not in script
            or '"$1"' not in script
            for script, _arguments in runner_calls
        ):
            raise RuntimeError("Force-HTTPS setter bypassed its guarded Rails argument contract.")
    finally:
        CONNECT_FIXTURE.run_container_runner = original_runner

    original_setter = CONNECT_FIXTURE.set_fixture_force_https
    calls: list[bool] = []
    try:
        CONNECT_FIXTURE.set_fixture_force_https = calls.append
        restorer = CONNECT_FIXTURE.FixtureForceHttpsRestorer(True)
        restorer()
        restorer()
        if calls != [True] or restorer.pending:
            raise RuntimeError("Force-HTTPS restoration was not exact and once-only.")
    finally:
        CONNECT_FIXTURE.set_fixture_force_https = original_setter

    try:
        CONNECT_FIXTURE.fixture_interrupted(signal.SIGTERM, None)
    except SystemExit as error:
        if error.code != 128 + signal.SIGTERM:
            raise RuntimeError("Force-HTTPS interruption exit code changed.") from error
    else:
        raise RuntimeError("Force-HTTPS interruption did not preserve process failure.")

    original_reader = CONNECT_FIXTURE.read_fixture_force_https
    original_setter = CONNECT_FIXTURE.set_fixture_force_https
    original_handlers = {
        signum: signal.getsignal(signum) for signum in (signal.SIGINT, signal.SIGTERM)
    }
    calls = []
    try:
        CONNECT_FIXTURE.read_fixture_force_https = lambda: False
        CONNECT_FIXTURE.set_fixture_force_https = calls.append

        def injected_error() -> None:
            raise RuntimeError("injected fixture failure")

        try:
            CONNECT_FIXTURE.run_with_fixture_force_https(injected_error)
        except RuntimeError as error:
            if str(error) != "injected fixture failure":
                raise
        else:
            raise RuntimeError("Force-HTTPS wrapper swallowed its injected failure.")
        if calls != [True, False]:
            raise RuntimeError("Injected failure did not restore the exact force-HTTPS state once.")

        calls.clear()
        try:
            CONNECT_FIXTURE.run_with_fixture_force_https(
                lambda: CONNECT_FIXTURE.fixture_interrupted(signal.SIGTERM, None)
            )
        except SystemExit as error:
            if error.code != 128 + signal.SIGTERM:
                raise RuntimeError("Wrapped force-HTTPS signal exit code changed.") from error
        else:
            raise RuntimeError("Force-HTTPS wrapper swallowed its injected signal.")
        if calls != [True, False]:
            raise RuntimeError("Injected signal did not restore the exact force-HTTPS state once.")
        if any(signal.getsignal(signum) != handler for signum, handler in original_handlers.items()):
            raise RuntimeError("Force-HTTPS wrapper did not restore prior signal handlers.")
    finally:
        CONNECT_FIXTURE.read_fixture_force_https = original_reader
        CONNECT_FIXTURE.set_fixture_force_https = original_setter
        for signum, handler in original_handlers.items():
            signal.signal(signum, handler)

    original_run = CONNECT_FIXTURE.subprocess.run
    original_absence = CONNECT_FIXTURE.container_operation_absent
    absence_checks: list[str] = []
    try:
        def interrupted_run(*_args: object, **_kwargs: object) -> None:
            raise SystemExit(128 + signal.SIGTERM)

        CONNECT_FIXTURE.subprocess.run = interrupted_run
        CONNECT_FIXTURE.container_operation_absent = lambda token: not absence_checks.append(token)
        try:
            CONNECT_FIXTURE.run_container_runner("fixture-interruption")
        except SystemExit as error:
            if error.code != 128 + signal.SIGTERM:
                raise RuntimeError("Interrupted runner exit code changed.") from error
        else:
            raise RuntimeError("Interrupted runner unexpectedly returned.")
        if len(absence_checks) != 1 or not re.fullmatch(r"[0-9a-f]{32}", absence_checks[0]):
            raise RuntimeError("Interrupted runner skipped its marked-process absence proof.")
    finally:
        CONNECT_FIXTURE.subprocess.run = original_run
        CONNECT_FIXTURE.container_operation_absent = original_absence

    original_run = CONNECT_FIXTURE.subprocess.run
    original_absence = CONNECT_FIXTURE.container_operation_absent
    original_stop = CONNECT_FIXTURE.stop_fixture_app
    stop_calls: list[bool] = []
    try:
        CONNECT_FIXTURE.subprocess.run = lambda *_args, **_kwargs: subprocess.CompletedProcess(
            args=[], returncode=0, stdout=b""
        )

        def failed_absence_probe(_token: str) -> bool:
            raise subprocess.TimeoutExpired(cmd="fixture-absence", timeout=1)

        CONNECT_FIXTURE.container_operation_absent = failed_absence_probe
        CONNECT_FIXTURE.stop_fixture_app = lambda: stop_calls.append(True)
        try:
            CONNECT_FIXTURE.run_container_runner("fixture-absence-failure")
        except RuntimeError as error:
            if str(error) != "A disposable in-container fixture absence proof failed.":
                raise
            if not isinstance(error.__cause__, subprocess.TimeoutExpired):
                raise RuntimeError("Absence-proof failure discarded its causal exception.") from error
        else:
            raise RuntimeError("Failed absence proof unexpectedly returned.")
        if stop_calls != [True]:
            raise RuntimeError("Failed absence proof did not emergency-stop the fixture exactly once.")
    finally:
        CONNECT_FIXTURE.subprocess.run = original_run
        CONNECT_FIXTURE.container_operation_absent = original_absence
        CONNECT_FIXTURE.stop_fixture_app = original_stop

    expected_sensitive_log_categories = {
        40: "input",
        41: "identity",
        42: "authenticated-session",
        43: "authentication-audit-shape",
        44: "authentication-audit-marker",
        45: "log-inventory",
        46: "application-log-marker",
        47: "logster-shape",
        48: "logster-marker",
        49: "application-log-identity-marker",
        50: "application-log-callback-marker",
        51: "application-log-recovery-marker",
        52: "application-log-identity-marker-1",
        53: "application-log-identity-marker-2",
        54: "application-log-identity-marker-3",
        55: "application-log-identity-marker-4",
        56: "application-log-identity-marker-5",
        57: "application-log-identity-marker-6",
        58: "application-log-identity-marker-7",
    }
    private_runner_sentinel = b"MOCHIRII_PRIVATE_SENSITIVE_LOG_RUNNER_SENTINEL"
    original_run = CONNECT_FIXTURE.subprocess.run
    original_absence = CONNECT_FIXTURE.container_operation_absent
    try:
        for returncode, category in (*expected_sensitive_log_categories.items(), (59, None)):
            run_calls: list[dict[str, object]] = []
            absence_tokens: list[str] = []

            def classified_run(*_args: object, **kwargs: object) -> subprocess.CompletedProcess[bytes]:
                run_calls.append(kwargs)
                return subprocess.CompletedProcess(
                    args=[],
                    returncode=returncode,
                    stdout=private_runner_sentinel,
                    stderr=private_runner_sentinel,
                )

            CONNECT_FIXTURE.subprocess.run = classified_run
            CONNECT_FIXTURE.container_operation_absent = (
                lambda token: not absence_tokens.append(token)
            )
            try:
                CONNECT_FIXTURE.run_container_runner(
                    "sensitive-log-classification",
                    input_bytes=private_runner_sentinel,
                    classify_sensitive_log_failure=True,
                )
            except RuntimeError as error:
                expected = (
                    f"A disposable sensitive-log audit failed closed [category={category}]."
                    if category is not None
                    else "A disposable in-container fixture failed within its bounded operation."
                )
                if str(error) != expected:
                    raise RuntimeError("Sensitive-log runner category mapping changed.") from error
                if error.__cause__ is not None or private_runner_sentinel.decode("ascii") in str(error):
                    raise RuntimeError("Sensitive-log runner diagnostic exposed private process data.") from error
            else:
                raise RuntimeError("Sensitive-log runner accepted a nonzero operation result.")
            if (
                len(run_calls) != 1
                or len(absence_tokens) != 1
                or run_calls[0].get("stdout") is not subprocess.DEVNULL
                or run_calls[0].get("stderr") is not subprocess.DEVNULL
                or run_calls[0].get("input") != private_runner_sentinel
            ):
                raise RuntimeError("Sensitive-log runner retry, output, or absence-proof boundary changed.")
    finally:
        CONNECT_FIXTURE.subprocess.run = original_run
        CONNECT_FIXTURE.container_operation_absent = original_absence


def test_smtp_transport_contract() -> None:
    template = (ROOT / "config/app.yml.example").read_text(encoding="utf-8")
    verifier = (ROOT / "scripts/verify-site.rb").read_text(encoding="utf-8")
    VALIDATOR.validate_smtp_transport_contract(template, verifier)

    template_hostiles = (
        template.replace(
            '  DISCOURSE_SMTP_FORCE_TLS: "false"\n',
            '  DISCOURSE_SMTP_FORCE_TLS: "true"\n',
            1,
        ),
        template.replace(
            '  DISCOURSE_SMTP_ENABLE_START_TLS: "true"\n',
            '  DISCOURSE_SMTP_ENABLE_START_TLS: "false"\n',
            1,
        ),
        template.replace(
            '  DISCOURSE_SMTP_OPENSSL_VERIFY_MODE: "peer"\n',
            '  DISCOURSE_SMTP_OPENSSL_VERIFY_MODE: "none"\n',
            1,
        ),
        template.replace(
            '  DISCOURSE_SMTP_ENABLE_START_TLS: "true"\n',
            '  DISCOURSE_SMTP_ENABLE_START_TLS: "true"\n'
            '  DISCOURSE_SMTP_ENABLE_START_TLS: "false"\n',
            1,
        ),
        template.replace(
            "          required.delete(:enable_starttls_auto)\n",
            "",
            1,
        ),
        template.replace(
            "          required[:enable_starttls] = true\n",
            "          required[:enable_starttls_auto] = true\n",
            1,
        ),
        template.replace(
            "            !configured.key?(:ssl) &&\n",
            "            true &&\n",
            1,
        ),
        template.replace(
            "          required[:enable_starttls] = true\n",
            "          required[:enable_starttls] = false\n",
            1,
        ) + "\n# inert decoy\n" + VALIDATOR.SMTP_REQUIRED_STARTTLS_INITIALIZER,
    )
    for hostile in template_hostiles:
        if hostile == template:
            raise RuntimeError("SMTP template hostile mutation anchor is absent.")
        try:
            VALIDATOR.validate_smtp_transport_contract(hostile, verifier)
        except RuntimeError:
            continue
        raise RuntimeError("SMTP template hostile mutation was accepted.")

    verifier_hostiles = (
        verifier.replace(
            "smtp = ActionMailer::Base.smtp_settings\n",
            "smtp = GlobalSetting.smtp_settings\n",
            1,
        ),
        verifier.replace(
            "    smtp[:enable_starttls] == true &&\n",
            "    smtp[:enable_starttls_auto] == true &&\n",
            1,
        ),
        verifier.replace(
            "    !smtp.key?(:enable_starttls_auto) &&\n",
            "    smtp[:enable_starttls_auto] == true &&\n",
            1,
        ),
        verifier.replace(
            "    !smtp.key?(:tls) &&\n",
            "    smtp[:tls] == true &&\n",
            1,
        ),
        verifier.replace(
            '    smtp[:openssl_verify_mode].to_s == "peer"\n',
            '    smtp[:openssl_verify_mode].to_s == "none"\n',
            1,
        ),
        verifier.replace(
            "    smtp[:enable_starttls] == true &&\n",
            "    smtp[:enable_starttls] == false &&\n",
            1,
        ) + "\n# inert decoy\n" + VALIDATOR.SMTP_RUNTIME_TRANSPORT_VERIFIER,
    )
    for hostile in verifier_hostiles:
        if hostile == verifier:
            raise RuntimeError("SMTP runtime-verifier hostile mutation anchor is absent.")
        try:
            VALIDATOR.validate_smtp_transport_contract(template, hostile)
        except RuntimeError:
            continue
        raise RuntimeError("SMTP runtime-verifier hostile mutation was accepted.")

    original_read = VALIDATOR.read
    try:
        documentation_hostiles = {
            "docs/operations/DEPLOYMENT.md": original_read(
                "docs/operations/DEPLOYMENT.md"
            ).replace("mandatory STARTTLS", "opportunistic STARTTLS", 1),
            "docs/operations/PROVIDER-DNS-TLS.md": original_read(
                "docs/operations/PROVIDER-DNS-TLS.md"
            ).replace("peer certificate verification", "certificate verification optional", 1),
            "docs/operations/SECRETS.md": original_read(
                "docs/operations/SECRETS.md"
            ).replace("STARTTLS required rather than opportunistic", "STARTTLS opportunistic", 1),
        }
        for relative, hostile in documentation_hostiles.items():
            VALIDATOR.read = (
                lambda path, relative=relative, hostile=hostile: hostile
                if path == relative
                else original_read(path)
            )
            try:
                VALIDATOR.validate_smtp_transport_contract(template, verifier)
            except RuntimeError:
                continue
            raise RuntimeError("SMTP documentation hostile mutation was accepted.")
    finally:
        VALIDATOR.read = original_read


def test_theme_archive() -> None:
    with tempfile.TemporaryDirectory(prefix="mochirii-theme-test-") as directory:
        first = Path(directory) / "one.zip"
        second = Path(directory) / "two.zip"
        THEME.build(first)
        THEME.build(second)
        first_bytes = first.read_bytes()
        if first_bytes != second.read_bytes():
            raise RuntimeError("Theme archive is not deterministic.")
        with zipfile.ZipFile(first) as archive:
            names = archive.namelist()
            if names != sorted(names) or "about.json" not in names:
                raise RuntimeError("Theme archive inventory is malformed.")
            if any(name.startswith("/") or ".." in Path(name).parts for name in names):
                raise RuntimeError("Theme archive contains an unsafe path.")
        if not hashlib.sha256(first_bytes).hexdigest():
            raise RuntimeError("Theme archive digest could not be calculated.")
    verifier = (ROOT / "scripts/verify-site.rb").read_text(encoding="utf-8")
    VALIDATOR.validate_theme_runtime_verifier(verifier)
    hostile_replacements = (
        ('].all? { |value| value&.id == emblem_id }', '].all? { |value| value == emblem_id }'),
        ('].all? { |value| value&.id == icon_id }', '].all? { |value| value == icon_id }'),
        ('].all? { |value| value&.id == social_card_id }', '].all? { |value| value == social_card_id }'),
        (
            '"discourse/templates/connectors/composer-fields-below/mochirii-upload-notice":',
            '"discourse/connectors/composer-fields-below/mochirii-upload-notice":',
        ),
        ('checks["theme_logo_settings"] =\n    [', 'checks["theme_logo_settings"] = true ||\n    ['),
        (
            '].all? { |value| value&.id == emblem_id } &&',
            '].all? { |value| value&.id == emblem_id } ||',
        ),
        (
            '].all? { |value| value&.id == icon_id } &&',
            '].all? { |value| value&.id == icon_id } ||',
        ),
        (
            """compiled_theme.include?('"discourse/templates/connectors/composer-fields-below/mochirii-upload-notice":') &&""",
            """compiled_theme.include?('"discourse/templates/connectors/composer-fields-below/mochirii-upload-notice":') ||""",
        ),
    )
    for current, stale in hostile_replacements:
        hostile = verifier.replace(current, stale, 1)
        if hostile == verifier:
            raise RuntimeError("Runtime theme verifier hostile mutation anchor is absent.")
        try:
            VALIDATOR.validate_theme_runtime_verifier(hostile)
        except RuntimeError:
            pass
        else:
            raise RuntimeError("Runtime theme verifier accepted a stale pinned-semantic mutation.")
    decoy_hostiles = (
        verifier.replace(
            '].all? { |value| value&.id == emblem_id }',
            '].all? { true } # ].all? { |value| value&.id == emblem_id }',
            1,
        ),
        verifier.replace(
            """compiled_theme.include?('"discourse/templates/connectors/composer-fields-below/mochirii-upload-notice":')""",
            """compiled_theme.include?('"discourse/' 'connectors/composer-fields-below/mochirii-upload-notice":') # "discourse/templates/connectors/composer-fields-below/mochirii-upload-notice":""",
            1,
        ),
        verifier.replace(
            'checks["repository_revision"] =',
            'checks["theme_logo_settings"] = true\n'
            'checks["upload_notice_connector_compiled"] = true\n'
            'checks["repository_revision"] =',
            1,
        ),
        verifier.replace(
            'checks["repository_revision"] =',
            'results = checks\n'
            'results["theme_logo_settings"] = true\n'
            'results["upload_notice_connector_compiled"] = true\n'
            'checks["repository_revision"] =',
            1,
        ),
        verifier.replace(
            'checks["repository_revision"] =',
            'checks.merge!("theme_logo_settings" => true, "upload_notice_connector_compiled" => true)\n'
            'checks["repository_revision"] =',
            1,
        ),
        verifier.replace(
            'checks["repository_revision"] =',
            'checks["theme_logo_" + "settings"] = true\n'
            'checks["upload_notice_" + "connector_compiled"] = true\n'
            'checks["repository_revision"] =',
            1,
        ),
    )
    for hostile in decoy_hostiles:
        if hostile == verifier:
            raise RuntimeError("Runtime theme verifier decoy hostile mutation anchor is absent.")
        try:
            VALIDATOR.validate_theme_runtime_verifier(hostile)
        except RuntimeError:
            pass
        else:
            raise RuntimeError("Runtime theme verifier accepted a decoy pinned-semantic mutation.")


def test_narrative_avatar_contract() -> None:
    template = (ROOT / "config/app.yml.example").read_text(encoding="utf-8")
    configure = (ROOT / "scripts/configure-site.rb").read_text(encoding="utf-8")
    verifier = (ROOT / "scripts/verify-site.rb").read_text(encoding="utf-8")
    VALIDATOR.validate_narrative_avatar_contract(template, configure, verifier)
    components = json.loads(
        (ROOT / "docs/operations/third-party-components.v1.json").read_text(encoding="utf-8")
    )
    gravatar_paths = {entry["path"] for entry in VALIDATOR.PINNED_GRAVATAR_EVIDENCE}
    gravatar_evidence = [
        entry
        for entry in components["application"]["semanticEvidenceFiles"]
        if entry.get("path") in gravatar_paths
    ]
    if gravatar_evidence != VALIDATOR.PINNED_GRAVATAR_EVIDENCE:
        raise RuntimeError("Pinned automatic Gravatar lifecycle evidence differs.")
    upstream = (ROOT / "scripts/verify-pinned-source.py").read_text(encoding="utf-8")
    VALIDATOR.validate_pinned_source_verifier(upstream)
    for canary in (
        "PINNED_GRAVATAR_EVIDENCE = {",
        "PINNED_USER_GRAVATAR_SCHEDULE_BLOCK = b'''",
        "def verify_gravatar_semantics(core: dict[str, bytes]) -> None:",
        'verify_gravatar_semantics(core)',
        'settings.count(b"  automatically_download_gravatars: true\\n") != 1',
    ):
        if upstream.count(canary) != 1:
            raise RuntimeError("Pinned automatic Gravatar semantic gate differs.")
    fixture = (ROOT / "scripts/test-narrative-avatar.rb").read_text(encoding="utf-8")
    VALIDATOR.validate_narrative_avatar_fixture(fixture)
    fixture_hostiles = (
        fixture.replace("  .sub(avatar_write_order, reordered_avatar_write_order)\n", "", 1),
        fixture.replace(
            'assert_fixture(method_source.scan(avatar_write_order).length == 1, "avatar write-order anchor differed")\n',
            "",
            1,
        ),
        fixture.replace("app_setting: :false, gravatar_response: :success", "app_setting: :true, gravatar_response: :success", 1),
        fixture.replace("app_setting: :omitted, gravatar_response: :success", "app_setting: :false, gravatar_response: :success", 1),
        fixture.replace("Jobs.drain_update_gravatar!\n", "", 1),
    )
    for hostile_fixture in fixture_hostiles:
        if hostile_fixture == fixture:
            raise RuntimeError("Narrative avatar fixture hostile mutation anchor is absent.")
        try:
            VALIDATOR.validate_narrative_avatar_fixture(hostile_fixture)
        except RuntimeError:
            continue
        raise RuntimeError("Narrative avatar fixture hostile mutation was accepted.")
    workflow = (ROOT / ".github/workflows/disposable-bootstrap.yml").read_text(encoding="utf-8")
    VALIDATOR.validate_narrative_avatar_workflow(workflow)
    preflight_start = "      - name: Prove one-effective-CPU command path\n"
    bootstrap_start = "      - name: Bootstrap exact standalone under one effective CPU\n"
    inert_step = '''      - name: Inert narrative fixture decoy
        if: ${{ false }}
        shell: bash
        run: |
''' + VALIDATOR.NARRATIVE_AVATAR_WORKFLOW_CALL
    workflow_hostiles = (
        workflow.replace(VALIDATOR.NARRATIVE_AVATAR_WORKFLOW_CALL, "", 1).replace(
            bootstrap_start,
            inert_step + bootstrap_start,
            1,
        ),
        workflow.replace(
            preflight_start,
            preflight_start + "        if: ${{ false }}\n",
            1,
        ),
        workflow.replace(
            VALIDATOR.NARRATIVE_AVATAR_WORKFLOW_CALL,
            "          if false; then\n" + VALIDATOR.NARRATIVE_AVATAR_WORKFLOW_CALL + "          fi\n",
            1,
        ),
    )
    for hostile_workflow in workflow_hostiles:
        try:
            VALIDATOR.validate_narrative_avatar_workflow(hostile_workflow)
        except RuntimeError:
            continue
        raise RuntimeError("Narrative avatar workflow hostile mutation was accepted.")

    environment_block = '''  DISCOURSE_ALLOW_EMAIL_INVITES: "false"
  DISCOURSE_DISCOURSE_NARRATIVE_BOT_ENABLED: "false"
  DISCOURSE_AUTOMATICALLY_DOWNLOAD_GRAVATARS: "false"

  DISCOURSE_LOGIN_REQUIRED: "true"'''
    hostile_cases = (
        (
            template.replace(
                'DISCOURSE_AUTOMATICALLY_DOWNLOAD_GRAVATARS: "false"',
                'DISCOURSE_AUTOMATICALLY_DOWNLOAD_GRAVATARS: "true"',
                1,
            ),
            configure,
            verifier,
        ),
        (
            template.replace(
                environment_block,
                environment_block.replace(
                    '  DISCOURSE_AUTOMATICALLY_DOWNLOAD_GRAVATARS: "false"\n',
                    "",
                ),
                1,
            ),
            configure,
            verifier,
        ),
        (
            template.replace(
                environment_block,
                environment_block.replace(
                    '  DISCOURSE_AUTOMATICALLY_DOWNLOAD_GRAVATARS: "false"\n\n',
                    "",
                ) + '\n  DISCOURSE_AUTOMATICALLY_DOWNLOAD_GRAVATARS: "false"',
                1,
            ),
            configure,
            verifier,
        ),
        (
            template.replace(
                '  DISCOURSE_LOGIN_REQUIRED: "true"',
                '  DISCOURSE_LOGIN_REQUIRED: "true"\n'
                '  DISCOURSE_AUTOMATICALLY_DOWNLOAD_GRAVATARS: "true"',
                1,
            ),
            configure,
            verifier,
        ),
        (
            template.replace(
                '  DISCOURSE_LOGIN_REQUIRED: "true"',
                '  DISCOURSE_LOGIN_REQUIRED: "true"\n'
                '  DISCOURSE_AUTOMATICALLY_DOWNLOAD_GRAVATARS : "true"',
                1,
            ),
            configure,
            verifier,
        ),
        (
            template.replace(
                '  DISCOURSE_LOGIN_REQUIRED: "true"',
                '  DISCOURSE_LOGIN_REQUIRED: "true"\n'
                '  "DISCOURSE_AUTOMATICALLY_DOWNLOAD_GRAVATARS": "true"',
                1,
            ),
            configure,
            verifier,
        ),
        (
            template.replace(
                '  DISCOURSE_LOGIN_REQUIRED: "true"',
                '  DISCOURSE_LOGIN_REQUIRED: "true"\n'
                "  'DISCOURSE_AUTOMATICALLY_DOWNLOAD_GRAVATARS': \"true\"",
                1,
            ),
            configure,
            verifier,
        ),
        (
            template,
            configure.replace(
                "  automatically_download_gravatars: false,",
                "  automatically_download_gravatars: true,",
                1,
            ),
            verifier,
        ),
        (
            template,
            configure.replace("\nconfigure_narrative_system_user!(icon_upload)\n", "\n", 1),
            verifier,
        ),
        (
            template,
            configure.replace(
                "  bot.user_avatar.update!(custom_upload_id: icon_upload.id, gravatar_upload_id: nil)",
                "  bot.user_avatar.update!(custom_upload_id: icon_upload.id)",
                1,
            ),
            verifier,
        ),
        (
            template,
            configure,
            verifier.replace(
                'ENV["DISCOURSE_AUTOMATICALLY_DOWNLOAD_GRAVATARS"] == "false" &&',
                'ENV["DISCOURSE_AUTOMATICALLY_DOWNLOAD_GRAVATARS"] == "true" &&',
                1,
            ),
        ),
        (
            template,
            configure,
            verifier.replace(
                "SiteSetting.automatically_download_gravatars == false",
                "SiteSetting.automatically_download_gravatars == true",
                1,
            ),
        ),
        (
            template,
            configure,
            verifier.replace(
                'checks["narrative_system_user_gravatar_absent"] =\n',
                'checks["narrative_system_user_gravatar_absent"] = true ||\n',
                1,
            ),
        ),
        (
            template,
            configure,
            verifier.replace(
                'checks["narrative_system_user_branded"] =\n  checks.values_at(',
                'checks["narrative_system_user_branded"] = true ||\n  checks.values_at(',
                1,
            ),
        ),
        (
            template,
            configure.replace(
                '  TextCleaner.normalize_whitespaces(\n'
                '    mochirii_admin_quick_start_template.gsub("%{base_url}", Discourse.base_url),\n'
                '  ).rstrip',
                '  mochirii_admin_quick_start_template.gsub("%{base_url}", Discourse.base_url)',
                1,
            ),
            verifier,
        ),
        (
            template,
            configure,
            verifier.replace(
                '  TextCleaner.normalize_whitespaces(\n'
                '    expected_admin_quick_start_template.gsub("%{base_url}", Discourse.base_url),\n'
                '  ).rstrip',
                '  expected_admin_quick_start_template.gsub("%{base_url}", Discourse.base_url)',
                1,
            ),
        ),
        (
            template,
            configure.replace(
                "normalized_upstream_admin_quick_start.bytesize == 1904 &&",
                "true &&",
                1,
            ),
            verifier,
        ),
        (
            template,
            configure.replace(
                "elsif untouched_upstream_admin_quick_start\n",
                "elsif true\n",
                1,
            ),
            verifier,
        ),
        (
            template,
            configure.replace(
                '  raise "Pinned administrator quick-start content was edited"\n',
                "  admin_quick_start.revise(Discourse.system_user, { raw: mochirii_admin_quick_start })\n",
                1,
            ),
            verifier,
        ),
        (
            template,
            configure,
            verifier.replace(
                "    admin_quick_start.last_editor_id == Discourse::SYSTEM_USER_ID &&\n",
                "    true &&\n",
                1,
            ),
        ),
        (
            template,
            configure,
            verifier.replace(
                "    admin_quick_start.raw == expected_admin_quick_start &&\n",
                "    admin_quick_start.raw.present? &&\n",
                1,
            ),
        ),
        (
            template,
            configure.replace("Mochirii staff setup guide", "Different staff setup guide", 1),
            verifier,
        ),
    )
    for hostile_template, hostile_configure, hostile_verifier in hostile_cases:
        try:
            VALIDATOR.validate_narrative_avatar_contract(
                hostile_template,
                hostile_configure,
                hostile_verifier,
            )
        except RuntimeError:
            continue
        raise RuntimeError("Narrative avatar hostile mutation was accepted.")


def test_branding_email_renderer_contract() -> None:
    renderer = (ROOT / "scripts/render-branding-email.rb").read_text(encoding="utf-8")
    VALIDATOR.validate_branding_email_renderer(renderer)
    hostile_replacements = (
        ("Email.extract_parts(mail.encoded)", "Email.extract_body(mail)"),
        ("Email.extract_parts(digest.encoded)", "Email.extract_body(digest)"),
        ("Email.extract_parts(mail.encoded)", "Email.extract_parts(mail)"),
        ("Email.extract_parts(digest.encoded)", "Email.extract_parts(digest)"),
        ("Email.extract_parts(mail.encoded)", "Email.extract_parts(mail.to_s)"),
        (
            'puts "Mochirii mail presentation passed."',
            'puts body\nputs "Mochirii mail presentation passed."',
        ),
        (
            'puts "Mochirii mail presentation passed."',
            'warn expected_address\nputs "Mochirii mail presentation passed."',
        ),
        ('stage4_fixture == "true" &&', 'stage4_fixture == "true" ||'),
        (
            'expected_scheme = allow_fixture_http ? "http" : "https"',
            'expected_scheme = "http"',
        ),
        (
            'expected_path = "/session/email-login/mochirii-fixture-admin-login-token"',
            'expected_path = "/session/email-login/wrong-token"',
        ),
        (
            "Somebody asked to log in to your account on [Mochirii Forums](#{expected_base_url}).",
            "Somebody asked to log in to your account on a different site.",
        ),
        (
            'normalized_text = text_part.to_s.gsub("\\r\\n", "\\n").strip',
            "normalized_text = text_part.to_s.strip",
        ),
        (
            "  unless html_part.nil? &&",
            "  unless true &&",
        ),
        (
            "      normalized_text == expected_text",
            "      normalized_text.include?(expected_link)",
        ),
        ("      expected.query.nil? &&", "      true &&"),
        ("      expected.fragment.nil?", "      true"),
        (
            'admin_confirmation_fixture_token = "0123456789abcdef" * 2',
            'admin_confirmation_fixture_token = "fixture-token"',
        ),
        (
            "unless admin_confirmation_fixture_token.match?(/\\A[0-9a-f]+\\z/) && admin_confirmation_fixture_token.length == 32",
            "unless true",
        ),
        (
            "      admin_confirmation_fixture_token,",
            '      "fixture-token",',
        ),
        ("SiteSetting.site_digest_logo_url", "SiteSetting.digest_logo_url"),
        ("def materialize(delivery, label:)", "def materialize(delivery)"),
        ("mail.is_a?(Mail::Message)", "mail.respond_to?(:header)"),
        ("!user.admin?", "false"),
        ("topics.map(&:id) != expected_ids", "false"),
        ("topics.uniq.length != 3", "false"),
        ("Category.exists?(topic_id: topic.id)", "false"),
        ("guidelines_topic.category_id != SiteSetting.staff_category_id", "false"),
        ("admin_quick_start_topic.category_id != SiteSetting.staff_category_id", "false"),
        (
            '!admin_quick_start_topic.first_post.raw.start_with?("*Mochirii staff setup guide*")',
            "false",
        ),
        ("Topic.transaction(requires_new: true)", "Topic.transaction"),
        (
            "topics.each { |topic| topic.update_columns(created_at: aged_created_at) }",
            "welcome_topic.update_columns(created_at: aged_created_at)",
        ),
        ("since: 3.days.ago", "since: 1.day.ago"),
        (
            'expected_markers = topics.map(&:title) + ["Mochirii staff setup guide"]',
            "expected_markers = [welcome_topic.title]",
        ),
        (
            "expected_markers.all? { |marker| rendered_digest.include?(marker) }",
            "true",
        ),
        ("raise ActiveRecord::Rollback", "next"),
        ("  topics.each(&:reload)\n", "  welcome_topic.reload\n"),
        (
            "topics.all? { |topic| topic.created_at == original_created_at.fetch(topic.id) }",
            "true",
        ),
        (
            "    mail.encoded\n    raise ActiveRecord::Rollback\n",
            "    raise ActiveRecord::Rollback\n    mail.encoded\n",
        ),
        (
            '  deliveries["digest"] = render_stage4_digest!(\n',
            'deliveries["digest"] = UserNotifications.digest(bot, since: 30.days.ago, skip_unsubscribe_links: true)',
        ),
    )
    for current, stale in hostile_replacements:
        hostile = renderer.replace(current, stale, 1)
        if hostile == renderer:
            raise RuntimeError("Branding email renderer hostile mutation anchor is absent.")
        try:
            VALIDATOR.validate_branding_email_renderer(hostile)
        except RuntimeError:
            pass
        else:
            raise RuntimeError("Branding email renderer accepted a stale API or output mutation.")

    components = json.loads(
        (ROOT / "docs/operations/third-party-components.v1.json").read_text(encoding="utf-8")
    )
    email_evidence = [
        entry
        for entry in components["application"]["semanticEvidenceFiles"]
        if entry.get("path") == "lib/email.rb"
    ]
    if email_evidence != [VALIDATOR.PINNED_EMAIL_EVIDENCE]:
        raise RuntimeError("Pinned email extraction API evidence differs.")
    mail_rendering_paths = {entry["path"] for entry in VALIDATOR.PINNED_MAIL_RENDERING_EVIDENCE}
    mail_rendering_evidence = [
        entry
        for entry in components["application"]["semanticEvidenceFiles"]
        if entry.get("path") in mail_rendering_paths
    ]
    if mail_rendering_evidence != VALIDATOR.PINNED_MAIL_RENDERING_EVIDENCE:
        raise RuntimeError("Pinned administrator-mail and digest-logo evidence differs.")
    topic_seed_paths = {entry["path"] for entry in VALIDATOR.PINNED_TOPIC_SEED_EVIDENCE}
    topic_seed_evidence = [
        entry
        for entry in components["application"]["semanticEvidenceFiles"]
        if entry.get("path") in topic_seed_paths
    ]
    if topic_seed_evidence != VALIDATOR.PINNED_TOPIC_SEED_EVIDENCE:
        raise RuntimeError("Pinned topic-seed and administrator-guide evidence differs.")
    restore_paths = {entry["path"] for entry in VALIDATOR.PINNED_RESTORE_EVIDENCE}
    restore_evidence = [
        entry
        for entry in components["application"]["semanticEvidenceFiles"]
        if entry.get("path") in restore_paths
    ]
    if restore_evidence != VALIDATOR.PINNED_RESTORE_EVIDENCE:
        raise RuntimeError("Pinned restore mail-suppression evidence differs.")

    fixture = (ROOT / "scripts/test-admin-login-link.rb").read_text(encoding="utf-8")
    VALIDATOR.validate_admin_login_link_fixture(fixture)
    fixture_hostiles = (
        fixture.replace('fixture_base = "http://forums.mochirii.com"', 'fixture_base = "https://forums.mochirii.com"', 1),
        fixture.replace('"production HTTP mode",', '"production HTTP mode removed",', 1),
        fixture.replace('"foreign host" =>', '"foreign host removed" =>', 1),
        fixture.replace('"wrong token" =>', '"wrong token removed" =>', 1),
        fixture.replace('"query" =>', '"query removed" =>', 1),
        fixture.replace('"mixed-case foreign URL" =>', '"mixed-case foreign URL removed" =>', 1),
        fixture.replace('"duplicate recovery link" =>', '"duplicate recovery link removed" =>', 1),
        fixture.replace('"entity-encoded HTML anchor" =>', '"entity-encoded HTML anchor removed" =>', 1),
        fixture.replace('"entity-encoded Markdown link" =>', '"entity-encoded Markdown link removed" =>', 1),
        fixture.replace(
            '"transport CRLF normalization changed the exact mail"',
            '"transport CRLF normalization case removed"',
            1,
        ),
        fixture.replace(
            '"unexpected pre-delivery HTML part",',
            '"unexpected pre-delivery HTML part removed",',
            1,
        ),
        fixture.replace('assert_fixture(error.cause.nil?, "#{label} retained an exception cause")', '', 1),
        fixture.replace('source.scan("SiteSetting.site_digest_logo_url").length == 1', 'true', 1),
        fixture.replace(
            'source.scan(\'admin_confirmation_fixture_token = "0123456789abcdef" * 2\').length == 1',
            "true",
            1,
        ),
        fixture.replace('source.scan("SecureRandom").empty?', "true", 1),
        fixture.replace("class PermissiveNullMailFixture", "class PermissiveMailFixture", 1),
        fixture.replace(
            'materialize(PermissiveNullMailFixture.new, label: "digest")',
            'materialize(Mail::Message.new, label: "digest")',
            1,
        ),
        fixture.replace(
            'materialize(direct_mail, label: "direct").equal?(direct_mail)',
            "true",
            1,
        ),
        fixture.replace(
            '"encoded-separator administrator confirmation token" =>',
            '"encoded-separator administrator confirmation token removed" =>',
            1,
        ),
    )
    for hostile_fixture in fixture_hostiles:
        if hostile_fixture == fixture:
            raise RuntimeError("Administrator recovery-link fixture hostile mutation anchor is absent.")
        try:
            VALIDATOR.validate_admin_login_link_fixture(hostile_fixture)
        except RuntimeError:
            continue
        raise RuntimeError("Administrator recovery-link fixture hostile mutation was accepted.")
    upstream = (ROOT / "scripts/verify-pinned-source.py").read_text(encoding="utf-8")
    VALIDATOR.validate_pinned_source_verifier(upstream)
    for canary in (
        "PINNED_EMAIL_EXTRACT_PARTS_BLOCK = b'''  def self.extract_parts(raw)",
        "PINNED_USER_NOTIFICATIONS_DIGEST_BLOCK = b'''",
        "PINNED_TOPIC_FOR_DIGEST_BLOCK = b'''",
        "PINNED_ADMIN_LOGIN_METHOD_BLOCK = b'''",
        "PINNED_ADMIN_CONFIRMATION_MAILER_SOURCE = b'''",
        "PINNED_ADMIN_CONFIRMATION_CREATE_BLOCK = b'''",
        "PINNED_ADMIN_CONFIRMATION_ROUTE_BLOCK = b'''",
        "PINNED_MESSAGE_BUILDER_INITIALIZER_PREFIX = b'''",
        "PINNED_MESSAGE_BUILDER_HTML_PART_PREFIX = b'''",
        "PINNED_BUILD_EMAIL_HELPER_SOURCE = b'''",
        "PINNED_BASE_PROTOCOL_BLOCK = b'''",
        "PINNED_ADMIN_LOGIN_LOCALE_BLOCK = b'''",
        "PINNED_DIGEST_LOGO_METHOD_BLOCK = b'''",
        "def verify_email_extract_parts_method(source: bytes) -> None:",
        "def verify_email_semantics(source: bytes) -> None:",
        "def verify_mail_evidence_manifest(components: dict) -> None:",
        "def verify_topic_seed_evidence_manifest(components: dict) -> None:",
        "def verify_restore_evidence_manifest(components: dict) -> None:",
        "def verify_mail_semantics(core: dict[str, bytes]) -> None:",
        "def verify_topic_seed_semantics(core: dict[str, bytes]) -> None:",
        "def verify_restore_semantics(core: dict[str, bytes]) -> None:",
        "PINNED_TOPIC_SEED_EVIDENCE = {",
        "PINNED_RESTORE_EVIDENCE = {",
        "PINNED_RESTORE_CLI_OPTION_BLOCK = b'''",
        "PINNED_RESTORE_CLI_PASS_THROUGH_BLOCK = b'''",
        "PINNED_RESTORER_INITIALIZER_BLOCK = b'''",
        "PINNED_RESTORER_MAIL_SUPPRESSION_BLOCK = b'''",
        "PINNED_TOPIC_FIXTURE_SOURCE = b'''",
        "PINNED_ADMIN_QUICK_START_TOPIC_BLOCK = b'''",
        "PINNED_TOPIC_CREATE_GUARD_BLOCK = b'''",
        "PINNED_ADMIN_QUICK_START_RAW_BLOCK = b'''",
        "PINNED_POST_CREATOR_RAW_NORMALIZATION_BLOCK = b'''",
        "PINNED_POST_REVISOR_RAW_NORMALIZATION_BLOCK = b'''",
        "PINNED_TEXT_CLEANER_WHITESPACE_BLOCK = b'''",
        "PINNED_ADMIN_QUICK_START_POST_RAW = (",
        'hashlib.sha256(source).hexdigest() != PINNED_EMAIL_SHA256',
        'verify_email_semantics(core["lib/email.rb"])',
        "verify_mail_evidence_manifest(components)",
        "verify_mail_semantics(core)",
        "verify_topic_seed_evidence_manifest(components)",
        "verify_topic_seed_semantics(core)",
        "verify_restore_evidence_manifest(components)",
        "verify_restore_semantics(core)",
    ):
        if upstream.count(canary) != 1:
            raise RuntimeError("Pinned email extraction semantic gate differs.")

    baseline_email = (
        b"module Email\n"
        + UPSTREAM.PINNED_EMAIL_EXTRACT_PARTS_BLOCK
        + b"  def self.site_title\n    nil\n  end\nend\n"
    )
    UPSTREAM.verify_email_extract_parts_method(baseline_email)
    hostile_email_methods = (
        baseline_email.replace(b"[text&.decoded, html&.decoded]", b"[raw.to_s, nil]", 1),
        baseline_email.replace(b"text = mail.text_part", b"text = mail.html_part", 1),
        baseline_email.replace(b"def self.extract_parts(raw)", b"def self.extract_body(raw)", 1),
        baseline_email.replace(
            UPSTREAM.PINNED_EMAIL_EXTRACT_PARTS_BLOCK,
            b"  # mail = Mail.new(raw)\n"
            b"  # if mail.multipart?\n"
            b"  # [text&.decoded, html&.decoded]\n"
            b"  def self.extract_parts(raw)\n"
            b"    [raw.to_s, nil]\n"
            b"  end\n\n",
            1,
        ),
    )
    for hostile in hostile_email_methods:
        try:
            UPSTREAM.verify_email_extract_parts_method(hostile)
        except RuntimeError:
            pass
        else:
            raise RuntimeError("Pinned email semantic gate accepted a wrong implementation.")

    synthetic_mail_core = {
        "app/mailers/user_notifications.rb":
            UPSTREAM.PINNED_USER_NOTIFICATIONS_DIGEST_BLOCK
            + b"  def user_replied(user, opts)\n  end\n\n"
            + UPSTREAM.PINNED_ADMIN_LOGIN_METHOD_BLOCK
            + b"  def account_created(user, opts = {})\n  end\n\n"
            + UPSTREAM.PINNED_EMAIL_LOGIN_HELPER_BLOCK
            + b"  def build_summary_for(user)\n  end\n",
        "app/models/topic.rb":
            UPSTREAM.PINNED_TOPIC_FOR_DIGEST_BLOCK
            + b"  def reload(options = nil)\n  end\n",
        "app/mailers/admin_confirmation_mailer.rb": UPSTREAM.PINNED_ADMIN_CONFIRMATION_MAILER_SOURCE,
        "lib/admin_confirmation.rb":
            UPSTREAM.PINNED_ADMIN_CONFIRMATION_CREATE_BLOCK
            + b"  def email_confirmed!\n  end\n",
        "config/routes.rb": UPSTREAM.PINNED_ADMIN_CONFIRMATION_ROUTE_BLOCK,
        "lib/email/message_builder.rb":
            UPSTREAM.PINNED_MESSAGE_BUILDER_INITIALIZER_PREFIX
            + b"      if @opts[:recipient_user].present?\n      end\n"
            + UPSTREAM.PINNED_MESSAGE_BUILDER_HTML_PART_PREFIX
            + b"      if @template_args[:unsubscribe_instructions].present?\n      end\n"
            + UPSTREAM.PINNED_MESSAGE_BUILDER_BODY_BLOCK
            + b"    def build_args\n    end\n",
        "lib/email/build_email_helper.rb": UPSTREAM.PINNED_BUILD_EMAIL_HELPER_SOURCE,
        "lib/discourse.rb":
            UPSTREAM.PINNED_BASE_PROTOCOL_BLOCK
            + b"  def self.current_hostname_with_port\n  end\n",
        "config/locales/server.en.yml":
            UPSTREAM.PINNED_ADMIN_LOGIN_LOCALE_BLOCK
            + b"    account_created:\n      title: fixture\n",
        "app/helpers/user_notifications_helper.rb":
            UPSTREAM.PINNED_DIGEST_LOGO_METHOD_BLOCK
            + b"  def html_site_link\n  end\n",
    }

    def synthetic_evidence(core: dict[str, bytes]) -> dict[str, tuple[int, str]]:
        return {
            path: (len(body), hashlib.sha256(body).hexdigest())
            for path, body in core.items()
        }

    original_mail_evidence = UPSTREAM.PINNED_MAIL_SEMANTIC_EVIDENCE
    try:
        UPSTREAM.PINNED_MAIL_SEMANTIC_EVIDENCE = synthetic_evidence(synthetic_mail_core)
        UPSTREAM.verify_mail_semantics(synthetic_mail_core)
        mail_hostiles = (
            (
                "app/mailers/user_notifications.rb",
                b"if @popular_topics.present?",
                b"if true",
            ),
            (
                "app/mailers/user_notifications.rb",
                b"topics_for_digest = Topic.for_digest(user, @since, digest_opts)",
                b"topics_for_digest = Topic.all",
            ),
            (
                "app/models/topic.rb",
                b".created_since(since)",
                b".all",
            ),
            (
                "app/models/topic.rb",
                b'.where("topics.created_at < ?", (SiteSetting.editing_grace_period || 0).seconds.ago)',
                b'.where("topics.created_at > ?", (SiteSetting.editing_grace_period || 0).seconds.ago)',
            ),
            (
                "app/models/topic.rb",
                b"topics = topics.where.not(id: Category.select(:topic_id).where.not(topic_id: nil))",
                b"topics = topics.where(id: Category.select(:topic_id).where.not(topic_id: nil))",
            ),
            (
                "app/mailers/user_notifications.rb",
                b"opts[:email_token]",
                b"nil",
            ),
            (
                "app/mailers/user_notifications.rb",
                b"email_token: email_token",
                b"email_token: nil",
            ),
            (
                "app/mailers/admin_confirmation_mailer.rb",
                b"confirm_admin_url(token: token, host: Discourse.base_url)",
                b"confirm_admin_url(token: nil, host: Discourse.base_url)",
            ),
            (
                "lib/admin_confirmation.rb",
                b"@token = SecureRandom.hex",
                b'@token = "invalid-token"',
            ),
            (
                "config/routes.rb",
                b"token: /[0-9a-f]+/",
                b"token: /[^/]+/",
            ),
            (
                "lib/email/message_builder.rb",
                b"base_url: Discourse.base_url",
                b'base_url: "http://fixture.invalid"',
            ),
            (
                "lib/email/message_builder.rb",
                b'.text_body_template", augmented_template_args)',
                b'.html_body_template", augmented_template_args)',
            ),
            (
                "lib/email/message_builder.rb",
                b"return unless html_override = @opts[:html_override]",
                b"html_override = @opts[:html_override]",
            ),
            (
                "lib/email/build_email_helper.rb",
                b"if message && h = builder.html_part",
                b"if message && h = builder.body",
            ),
            (
                "lib/discourse.rb",
                b'SiteSetting.force_https? ? "https" : "http"',
                b'"https"',
            ),
            (
                "config/locales/server.en.yml",
                b"%{base_url}/session/email-login/%{email_token}",
                b"%{base_url}/session/email-login/fixed-token",
            ),
            (
                "app/helpers/user_notifications_helper.rb",
                b"SiteSetting.site_digest_logo_url",
                b"SiteSetting.digest_logo_url",
            ),
        )
        for path, current, stale in mail_hostiles:
            hostile_core = dict(synthetic_mail_core)
            hostile_core[path] = hostile_core[path].replace(current, stale, 1)
            if hostile_core[path] == synthetic_mail_core[path]:
                raise RuntimeError("Pinned mail semantic hostile mutation anchor is absent.")
            UPSTREAM.PINNED_MAIL_SEMANTIC_EVIDENCE = synthetic_evidence(hostile_core)
            try:
                UPSTREAM.verify_mail_semantics(hostile_core)
            except RuntimeError:
                continue
            raise RuntimeError("Pinned mail semantic gate accepted a hostile implementation.")
    finally:
        UPSTREAM.PINNED_MAIL_SEMANTIC_EVIDENCE = original_mail_evidence

    synthetic_seed_core = {
        "db/fixtures/990_topics.rb": UPSTREAM.PINNED_TOPIC_FIXTURE_SOURCE,
        "docs/ADMIN-QUICK-START-GUIDE.md": (
            b"*Welcome to your new community, and thank you for choosing Discourse!*\n"
            + b"https://github.com/discourse/discourse/blob/main/docs/INSTALL-email.md\n"
            + (b"%{base_url}\n" * 7)
            + (b"Discourse\n" * 6)
            + (b"discourse.org\n" * 3)
        ),
        "lib/seed_data/topics.rb": (
            UPSTREAM.PINNED_ADMIN_QUICK_START_TOPIC_BLOCK
            + UPSTREAM.PINNED_TOPIC_CREATE_GUARD_BLOCK
            + UPSTREAM.PINNED_ADMIN_QUICK_START_RAW_BLOCK
        ),
        "lib/post_creator.rb": UPSTREAM.PINNED_POST_CREATOR_RAW_NORMALIZATION_BLOCK,
        "lib/post_revisor.rb": UPSTREAM.PINNED_POST_REVISOR_RAW_NORMALIZATION_BLOCK,
        "lib/text_cleaner.rb": UPSTREAM.PINNED_TEXT_CLEANER_WHITESPACE_BLOCK,
    }
    original_topic_seed_evidence = UPSTREAM.PINNED_TOPIC_SEED_EVIDENCE
    original_admin_quick_start_post_raw = UPSTREAM.PINNED_ADMIN_QUICK_START_POST_RAW
    try:
        UPSTREAM.PINNED_TOPIC_SEED_EVIDENCE = synthetic_evidence(synthetic_seed_core)
        synthetic_guide_post_raw = synthetic_seed_core["docs/ADMIN-QUICK-START-GUIDE.md"].rstrip()
        UPSTREAM.PINNED_ADMIN_QUICK_START_POST_RAW = (
            len(synthetic_guide_post_raw),
            hashlib.sha256(synthetic_guide_post_raw).hexdigest(),
        )
        UPSTREAM.verify_topic_seed_semantics(synthetic_seed_core)
        seed_hostiles = (
            (
                "db/fixtures/990_topics.rb",
                b"include_welcome_topics: !topics_exist",
                b"include_welcome_topics: false",
            ),
            (
                "lib/seed_data/topics.rb",
                b'site_setting_name: "admin_quick_start_topic_id"',
                b'site_setting_name: "welcome_topic_id"',
            ),
            (
                "lib/seed_data/topics.rb",
                b"return if topic_id > 0 || Topic.find_by(id: topic_id)",
                b"return if false",
            ),
            (
                "lib/seed_data/topics.rb",
                b"content = File.read(quick_start_filename)",
                b'content = "safe decoy"',
            ),
            (
                "docs/ADMIN-QUICK-START-GUIDE.md",
                b"%{base_url}\n",
                b"https://foreign.invalid/\n",
            ),
            (
                "lib/post_creator.rb",
                b'TextCleaner.normalize_whitespaces(@opts[:raw] || "").rstrip',
                b'(@opts[:raw] || "").rstrip',
            ),
            (
                "lib/post_revisor.rb",
                b"TextCleaner.normalize_whitespaces(raw).rstrip",
                b"raw.rstrip",
            ),
            (
                "lib/text_cleaner.rb",
                b'text&.gsub(@@whitespaces_regexp, " ")',
                b"text",
            ),
        )
        for path, current, stale in seed_hostiles:
            hostile_core = dict(synthetic_seed_core)
            hostile_core[path] = hostile_core[path].replace(current, stale, 1)
            if hostile_core[path] == synthetic_seed_core[path]:
                raise RuntimeError("Pinned topic-seed hostile mutation anchor is absent.")
            UPSTREAM.PINNED_TOPIC_SEED_EVIDENCE = synthetic_evidence(hostile_core)
            try:
                UPSTREAM.verify_topic_seed_semantics(hostile_core)
            except RuntimeError:
                continue
            raise RuntimeError("Pinned topic-seed semantic gate accepted a hostile implementation.")
    finally:
        UPSTREAM.PINNED_TOPIC_SEED_EVIDENCE = original_topic_seed_evidence
        UPSTREAM.PINNED_ADMIN_QUICK_START_POST_RAW = original_admin_quick_start_post_raw

    synthetic_restore_core = {
        "script/discourse":
            UPSTREAM.PINNED_RESTORE_CLI_OPTION_BLOCK
            + UPSTREAM.PINNED_RESTORE_CLI_PASS_THROUGH_BLOCK,
        "lib/backup_restore/restorer.rb":
            UPSTREAM.PINNED_RESTORER_INITIALIZER_BLOCK
            + UPSTREAM.PINNED_RESTORER_MAIL_SUPPRESSION_BLOCK,
    }
    original_restore_evidence = UPSTREAM.PINNED_RESTORE_EVIDENCE
    try:
        UPSTREAM.PINNED_RESTORE_EVIDENCE = synthetic_evidence(synthetic_restore_core)
        UPSTREAM.verify_restore_semantics(synthetic_restore_core)
        restore_hostiles = (
            (
                "script/discourse",
                b"default: true",
                b"default: false",
            ),
            (
                "script/discourse",
                b"disable_emails: options[:disable_emails]",
                b"disable_emails: false",
            ),
            (
                "lib/backup_restore/restorer.rb",
                b"disable_emails: true",
                b"disable_emails: false",
            ),
            (
                "lib/backup_restore/restorer.rb",
                b'SiteSetting.disable_emails == "no"',
                b'SiteSetting.disable_emails == "yes"',
            ),
            (
                "lib/backup_restore/restorer.rb",
                b'SiteSetting.set_and_log(:disable_emails, "non-staff", user)',
                b'SiteSetting.set_and_log(:disable_emails, "no", user)',
            ),
        )
        for path, current, hostile_value in restore_hostiles:
            hostile_core = dict(synthetic_restore_core)
            hostile_core[path] = hostile_core[path].replace(current, hostile_value, 1)
            if hostile_core[path] == synthetic_restore_core[path]:
                raise RuntimeError("Pinned restore semantic hostile mutation anchor is absent.")
            UPSTREAM.PINNED_RESTORE_EVIDENCE = synthetic_evidence(hostile_core)
            try:
                UPSTREAM.verify_restore_semantics(hostile_core)
            except RuntimeError:
                continue
            raise RuntimeError("Pinned restore semantic gate accepted a hostile implementation.")
    finally:
        UPSTREAM.PINNED_RESTORE_EVIDENCE = original_restore_evidence

    verifier_hostiles = (
        upstream.replace(
            '    verify_email_semantics(core["lib/email.rb"])\n',
            '    if False:\n        verify_email_semantics(core["lib/email.rb"])\n',
            1,
        ),
        upstream.replace(
            '    verify_email_semantics(core["lib/email.rb"])\n',
            '    # verify_email_semantics(core["lib/email.rb"])\n',
            1,
        ),
        upstream.replace(
            "    verify_mail_semantics(core)\n",
            "    if False:\n        verify_mail_semantics(core)\n",
            1,
        ),
        upstream.replace(
            "    verify_mail_evidence_manifest(components)\n",
            "    if False:\n        verify_mail_evidence_manifest(components)\n",
            1,
        ),
        upstream.replace(
            "    verify_topic_seed_semantics(core)\n",
            "    if False:\n        verify_topic_seed_semantics(core)\n",
            1,
        ),
        upstream.replace(
            "    verify_topic_seed_evidence_manifest(components)\n",
            "    if False:\n        verify_topic_seed_evidence_manifest(components)\n",
            1,
        ),
        upstream.replace(
            "    verify_restore_semantics(core)\n",
            "    if False:\n        verify_restore_semantics(core)\n",
            1,
        ),
        upstream.replace(
            "    verify_restore_evidence_manifest(components)\n",
            "    if False:\n        verify_restore_evidence_manifest(components)\n",
            1,
        ),
    )
    for hostile in verifier_hostiles:
        if hostile == upstream:
            raise RuntimeError("Pinned-source verifier hostile mutation anchor is absent.")
        try:
            VALIDATOR.validate_pinned_source_verifier(hostile)
        except RuntimeError:
            pass
        else:
            raise RuntimeError("Pinned-source verifier accepted a disabled email semantic gate.")


def test_certificate_create_cleanup() -> None:
    old_identifier = "00000000-0000-4000-8000-000000000001"
    new_identifier = "00000000-0000-4000-8000-000000000002"
    name = "mochirii-media-forums-fixture-transaction"
    inventory = [{"id": old_identifier, "name": "mochirii-media-forums-old"}]
    calls: list[tuple[str, str]] = []
    original_api = ROTATE.api

    def hostile_api(token: str, method: str, path: str, payload=None):
        del token, payload
        calls.append((method, path))
        if method == "POST" and path == "/certificates":
            inventory.append({"id": new_identifier, "name": name})
            return {"certificate": {"id": "malformed", "name": name}}
        if method == "GET" and path == "/certificates?per_page=200":
            return {"certificates": list(inventory), "links": {"pages": {}}}
        if method == "DELETE" and path == f"/certificates/{new_identifier}":
            inventory[:] = [row for row in inventory if row["id"] != new_identifier]
            return None
        raise RuntimeError(f"Unexpected mocked provider operation: {method} {path}")

    ROTATE.api = hostile_api
    try:
        try:
            ROTATE.create_transaction_certificate(
                "fixture-token",
                name,
                {"name": name, "type": "custom"},
                {old_identifier},
            )
        except ROTATE.RotationError:
            pass
        else:
            raise RuntimeError("Malformed certificate creation readback did not fail closed.")
    finally:
        ROTATE.api = original_api
    if inventory != [{"id": old_identifier, "name": "mochirii-media-forums-old"}]:
        raise RuntimeError("Malformed certificate creation left a provider-side orphan.")
    if ("DELETE", f"/certificates/{new_identifier}") not in calls:
        raise RuntimeError("Malformed certificate creation did not delete the exact new object.")


def test_certificate_identity_read_allowlist() -> None:
    identifier = "00000000-0000-4000-8000-000000000001"

    class FixtureResponse:
        status = 200

        def __init__(self, url: str):
            self.url = url
            self.body = json.dumps({"certificate": {"id": identifier, "name": "mochirii-media-forums-old"}}).encode()

        def __enter__(self):
            return self

        def __exit__(self, *_args):
            return False

        def geturl(self):
            return self.url

        def read(self, limit: int):
            result, self.body = self.body[:limit], self.body[limit:]
            return result

    class FixtureOpener:
        def __init__(self):
            self.calls: list[tuple[str, str]] = []

        def open(self, request, timeout):
            del timeout
            self.calls.append((request.method, request.full_url))
            return FixtureResponse(request.full_url)

    original = ROTATE.PROVIDER_OPENER
    opener = FixtureOpener()
    ROTATE.PROVIDER_OPENER = opener
    try:
        document = ROTATE.api("fixture-provider-token", "GET", f"/certificates/{identifier}")
        if document != {"certificate": {"id": identifier, "name": "mochirii-media-forums-old"}}:
            raise RuntimeError("Exact certificate identity readback changed.")
        allowed_calls = len(opener.calls)
        for method, path in (
            ("PUT", f"/certificates/{identifier}"),
            ("POST", f"/certificates/{identifier}"),
            ("GET", "/certificates/not-a-uuid"),
            ("GET", f"/certificates/{identifier}?extra=1"),
            ("DELETE", f"/certificates/{identifier}/extra"),
        ):
            try:
                ROTATE.api("fixture-provider-token", method, path)
            except ROTATE.RotationError:
                pass
            else:
                raise RuntimeError("Hostile certificate identity method or path was accepted.")
        if len(opener.calls) != allowed_calls:
            raise RuntimeError("Rejected certificate identity path reached the provider opener.")
    finally:
        ROTATE.PROVIDER_OPENER = original


def test_http_redirect_boundaries() -> None:
    request = urllib.request.Request("https://api.digitalocean.com/v2/certificates")
    for target in (
        "https://example.invalid/capture",
        "https://api.digitalocean.com/v2/certificates/redirected",
    ):
        if ROTATE.NoRedirectHandler().redirect_request(request, None, 302, "fixture", {}, target) is not None:
            raise RuntimeError("Provider no-redirect handler accepted a redirect.")
    github_request = urllib.request.Request(
        "https://api.github.com/repos/discourse/discourse_docker/git/ref/heads/main"
    )
    for target in (
        "https://example.invalid/capture",
        "https://api.github.com/repos/discourse/discourse_docker/git/ref/heads/other",
    ):
        if UPSTREAM.NoRedirectHandler().redirect_request(github_request, None, 302, "fixture", {}, target) is not None:
            raise RuntimeError("Official-source no-redirect handler accepted a redirect.")

    class RedirectOpener:
        def __init__(self, location: str):
            self.location = location
            self.calls = 0

        def open(self, requested, timeout):
            del timeout
            self.calls += 1
            raise urllib.error.HTTPError(
                requested.full_url,
                302,
                "fixture redirect",
                {"Location": self.location},
                io.BytesIO(b"fixture"),
            )

    original_provider_opener = ROTATE.PROVIDER_OPENER
    provider_redirect = RedirectOpener("https://example.invalid/capture")
    ROTATE.PROVIDER_OPENER = provider_redirect
    try:
        try:
            ROTATE.api("fixture-provider-token", "GET", "/certificates?per_page=200")
        except ROTATE.RotationError:
            pass
        else:
            raise RuntimeError("Provider API followed a cross-authority redirect.")
    finally:
        ROTATE.PROVIDER_OPENER = original_provider_opener
    if provider_redirect.calls != 1:
        raise RuntimeError("Provider redirect caused a second request.")

    original_official_opener = UPSTREAM.OFFICIAL_OPENER
    for url, headers, location in (
        (
            "https://api.github.com/repos/discourse/discourse_docker/git/ref/heads/main",
            None,
            "https://example.invalid/capture",
        ),
        (
            "https://registry-1.docker.io/v2/discourse/base/manifests/sha256:" + "a" * 64,
            {"Authorization": "Bearer fixture-registry-token"},
            "https://registry-1.docker.io/v2/discourse/base/manifests/other",
        ),
    ):
        redirect = RedirectOpener(location)
        UPSTREAM.OFFICIAL_OPENER = redirect
        try:
            with environment({**os.environ, "GITHUB_TOKEN": "fixture-github-token"}):
                try:
                    UPSTREAM.request(url, headers=headers, limit=1024)
                except RuntimeError:
                    pass
                else:
                    raise RuntimeError("Official-source request followed a redirect.")
        finally:
            UPSTREAM.OFFICIAL_OPENER = original_official_opener
        if redirect.calls != 1:
            raise RuntimeError("Official-source redirect caused a second request.")

    class DriftResponse:
        status = 200
        headers: dict[str, str] = {}

        def __init__(self, url: str):
            self.url = url
            self.complete = False

        def __enter__(self):
            return self

        def __exit__(self, *_args):
            return False

        def geturl(self):
            return self.url

        def read(self, _limit):
            if self.complete:
                return b""
            self.complete = True
            return b"{}"

    class DriftOpener:
        def __init__(self, url: str):
            self.response = DriftResponse(url)
            self.calls = 0

        def open(self, _request, timeout):
            del timeout
            self.calls += 1
            return self.response

    drift = DriftOpener("https://example.invalid/provider-response")
    ROTATE.PROVIDER_OPENER = drift
    try:
        try:
            ROTATE.api("fixture-provider-token", "GET", "/certificates?per_page=200")
        except ROTATE.RotationError:
            pass
        else:
            raise RuntimeError("Provider response URL drift was accepted.")
    finally:
        ROTATE.PROVIDER_OPENER = original_provider_opener
    official_drift = DriftOpener("https://api.github.com/repos/discourse/discourse_docker/git/ref/heads/other")
    UPSTREAM.OFFICIAL_OPENER = official_drift
    try:
        try:
            UPSTREAM.request("https://api.github.com/repos/discourse/discourse_docker/git/ref/heads/main")
        except RuntimeError:
            pass
        else:
            raise RuntimeError("Official-source response URL drift was accepted.")
    finally:
        UPSTREAM.OFFICIAL_OPENER = original_official_opener

    hostile_urls = (
        "https://api.github.com.example.invalid/repos/discourse/discourse/git/commits/" + "a" * 40,
        "https://user@api.github.com/repos/discourse/discourse/git/commits/" + "a" * 40,
        "https://api.github.com:444/repos/discourse/discourse/git/commits/" + "a" * 40,
        "https://registry-1.docker.io/v2/discourse/base/manifests/" + "a" * 129,
    )
    for url in hostile_urls:
        expect_validation_failure(lambda url=url: UPSTREAM.validate_official_url(url), "hostile official URL")

    class SlowResponse:
        def read(self, _limit):
            return b"fixture"

    original_monotonic = ROTATE.time.monotonic
    ticks = iter((0.0, 0.0, 61.0))
    ROTATE.time.monotonic = lambda: next(ticks)
    try:
        try:
            ROTATE.read_bounded_response(SlowResponse(), 1024, 60.0)
        except ROTATE.ProviderResponseUncertain:
            pass
        else:
            raise RuntimeError("Provider total response deadline was treated as an inactivity timeout.")
    finally:
        ROTATE.time.monotonic = original_monotonic


def test_certificate_inventory_capacity() -> None:
    inventory = [
        {"id": f"00000000-0000-4000-8000-{index:012x}", "name": f"fixture-{index}"}
        for index in range(200)
    ]
    calls: list[tuple[str, str]] = []
    original_api = ROTATE.api

    def full_inventory_api(token: str, method: str, path: str, payload=None):
        del token, payload
        calls.append((method, path))
        if method == "GET" and path == "/certificates?per_page=200":
            return {"certificates": list(inventory), "links": {"pages": {}}}
        if method == "POST":
            inventory.append(
                {"id": "00000000-0000-4000-8000-000000000200", "name": "forbidden-201st-object"}
            )
            return {"certificate": inventory[-1]}
        raise RuntimeError(f"Unexpected mocked provider operation: {method} {path}")

    ROTATE.api = full_inventory_api
    try:
        try:
            ROTATE.pre_mutation_inventory("fixture-token")
        except ROTATE.RotationError:
            pass
        else:
            raise RuntimeError("Full certificate inventory did not stop before mutation.")
    finally:
        ROTATE.api = original_api
    if any(method == "POST" for method, _ in calls) or len(inventory) != 200:
        raise RuntimeError("Capacity gate allowed a 201st certificate mutation.")


def test_certificate_preparation_recovery_contract() -> None:
    prepare = (ROOT / "scripts/prepare-media-certificate.sh").read_text(encoding="utf-8")
    installer = (ROOT / "scripts/install-media-certificate-renewal.sh").read_text(encoding="utf-8")
    prepared_branch = prepare[prepare.index("if [[ -e ${preparation_journal}") : prepare.index("media_record_event initial-certificate started")]
    recovery_start = prepared_branch.index(
        'media_reconcile_acme "${acme_helper}" /etc/letsencrypt/mochirii-cloudflare.ini'
    )
    prepared_recovery = prepared_branch[recovery_start:]
    prepared_order = (
        'media_reconcile_acme "${acme_helper}" /etc/letsencrypt/mochirii-cloudflare.ini',
        'if [[ -e ${lineage}',
        "if validate_lineage; then",
        "write_preparation_journal issued",
        'validate_lineage || fail "Recovered certificate lineage changed before completion.',
        "clear_preparation_journal",
    )
    positions = [prepared_recovery.index(value) for value in prepared_order]
    if positions != sorted(positions):
        raise RuntimeError("Prepared-phase certificate recovery can adopt a lineage before ACME reconciliation or exact validation.")
    issuance = prepare[prepare.index("media_run_certbot_dns_transaction") :]
    if issuance.index("validate_lineage") > issuance.index("write_preparation_journal issued"):
        raise RuntimeError("Initial certificate issuance can commit an unvalidated lineage.")
    for required in (
        'archive_entries != {f"{name}1.pem" for name in names}',
        'link.resolve(strict=True) != expected.resolve(strict=True)',
        'openssl x509 -in "${lineage}/cert.pem" -checkhost media-forums.mochirii.com',
        '[[ ${san_names} == "DNS:media-forums.mochirii.com" ]]',
        'document["preexistingLineage"] is not False',
        "discard_incomplete_transaction_lineage()",
        'str(base) != "/etc/letsencrypt"',
        're.fullmatch(r"(?:cert|chain|fullchain|privkey)[1-9][0-9]{0,5}[.]pem", entry.name)',
        'not stat.S_ISLNK(metadata.st_mode)',
        'normalized.parent != archive',
        "fsync_directory(live.parent)",
        "fsync_directory(archive.parent)",
        'discard_incomplete_transaction_lineage || fail "Interrupted certificate preparation has unsafe or ambiguous partial lineage state;',
    ):
        if required not in prepare:
            raise RuntimeError("Recovered certificate lineage lost an exact ownership, path, key, or SAN invariant.")
    cleanup_start = prepared_recovery.index("discard_incomplete_transaction_lineage || fail")
    if cleanup_start < prepared_recovery.index("if validate_lineage; then"):
        raise RuntimeError("Prepared certificate recovery can discard a fully valid lineage before commit-forward adoption.")
    if any(value in prepare for value in ("shutil.rmtree", "rm -rf -- \"${lineage}\"", "find ${lineage} -delete")):
        raise RuntimeError("Prepared certificate recovery broadened beyond the exact journal-owned lineage inventory.")

    prepared_validation = installer[
        installer.index('prepared_runtime="/etc/mochirii/forums-media-certificate.json"') :
        installer.index("export DEBIAN_FRONTEND")
    ]
    runtime_path_gate = (
        '[[ ${runtime_source} == "${prepared_runtime}" ]] || fail '
        '"Certificate runtime input must be the exact prepared runtime path."'
    )
    runtime_validation = (
        'validate_prepared_input "${runtime_source}" "${prepared_runtime}" || fail '
        '"Prepared certificate runtime differs from the exact installation input."'
    )
    if any(value not in prepared_validation for value in (
        '[[ -f ${prepared} && ! -L ${prepared} ]]',
        'root:root 600',
        'cmp -s -- "${source}" "${prepared}"',
        runtime_path_gate,
        runtime_validation,
    )):
        raise RuntimeError("Certificate installer does not exactly validate preparation-owned inputs before adoption.")
    if prepared_validation.index(runtime_path_gate) > prepared_validation.index(runtime_validation):
        raise RuntimeError("Certificate installer can validate or use a runtime alias before requiring the exact prepared path.")
    targets_start = installer.index("install_targets=(")
    targets = installer[targets_start : installer.index("\n)\n", targets_start) + 3]
    if any(value in targets for value in (
        "/etc/mochirii/forums-media-certificate.json",
        "/etc/letsencrypt/mochirii-media.ini",
        "/etc/letsencrypt/mochirii-cloudflare.ini",
    )):
        raise RuntimeError("Certificate installer can delete or recreate preparation-owned issuance inputs.")
    cleanup = installer[installer.index("cleanup_installation() {") : installer.index("on_exit() {")]
    if (
        'for target in "${install_targets[@]}"' not in cleanup
        or any(value in cleanup for value in ("prepared_runtime", "prepared_certbot", "prepared_dns"))
    ):
        raise RuntimeError("Partial certificate installation cleanup crosses the adopted preparation boundary.")
    runtime_install = (
        'install -m 0600 -o root -g root "${runtime_source}" '
        "/etc/mochirii/forums-media-certificate.json"
    )
    if runtime_install in installer:
        raise RuntimeError("Certificate installer can overwrite the preparation-owned runtime.")
    installed_readback = installer[
        installer.index("validate_installed_automation_bytes() {") :
        installer.index("write_install_journal() {")
    ]
    if '${runtime_source}\t/etc/mochirii/forums-media-certificate.json\t600' not in installed_readback:
        raise RuntimeError("Certificate installer no longer proves the adopted runtime bytes and mode at terminal readback.")
    if any(
        installer.index(value) > installer.index("write_install_journal")
        for value in (
            runtime_validation,
            'validate_prepared_input "${certbot_source}"',
            'validate_prepared_input "${dns_source}"',
        )
    ):
        raise RuntimeError("Certificate installation journals a mutation before validating prepared input bytes.")


def test_shared_libexec_traversal_contract() -> None:
    installer = (ROOT / "scripts/install-media-certificate-renewal.sh").read_text(encoding="utf-8")
    upgrader = (ROOT / "scripts/upgrade-host-control.sh").read_text(encoding="utf-8")
    verifier = (ROOT / "scripts/verify-host-security.sh").read_text(encoding="utf-8")
    deployment = (ROOT / "docs/operations/DEPLOYMENT.md").read_text(encoding="utf-8")
    provider = (ROOT / "docs/operations/PROVIDER-DNS-TLS.md").read_text(encoding="utf-8")

    private_directories = (
        'install -d -m 0700 -o root -g root "${log_root}" /etc/mochirii /etc/letsencrypt'
    )
    shared_directory = 'install -d -m 0755 -o root -g root "${libexec_root}"'
    historical_defect = (
        'install -d -m 0700 -o root -g root "${log_root}" '
        '/usr/local/libexec/mochirii-forums /etc/mochirii /etc/letsencrypt'
    )
    directory_readback = (
        '[[ -d ${libexec_root} && ! -L ${libexec_root} && '
        '"$(stat -c \'%U:%G %a\' "${libexec_root}")" == "root:root 755" ]]'
    )
    deploy_traversal = (
        'sudo -u mochirii-forums-deploy test -x '
        '"${libexec_root}/ssh-deploy-dispatch.py"'
    )
    reconcile_call = (
        'reconcile_shared_libexec_traversal "${previous_source}" "${candidate}" || '
        'fail "Shared host-control executable traversal could not be reconciled from the '
        'exact certificate-installer predecessor."'
    )

    def assert_contract(
        installer_source: str,
        upgrader_source: str,
        verifier_source: str,
        deployment_source: str,
        provider_source: str,
    ) -> None:
        if historical_defect in installer_source:
            raise RuntimeError("Certificate installer still collapses the shared executable parent to mode 0700.")
        if installer_source.count(private_directories) != 1 or installer_source.count(shared_directory) != 1:
            raise RuntimeError("Certificate installer private/shared directory modes are undefined or duplicated.")
        installer_order = tuple(
            installer_source.index(value)
            for value in (
                'libexec_root="/usr/local/libexec/mochirii-forums"',
                private_directories,
                shared_directory,
                directory_readback,
                '[[ ! -e ${preparation_journal}',
            )
        )
        if installer_order != tuple(sorted(installer_order)):
            raise RuntimeError("Certificate installer does not bind shared traversal before certificate mutation.")
        installed_readback = installer_source[
            installer_source.index("validate_installed_automation_bytes() {") :
            installer_source.index("write_install_journal() {")
        ]
        if directory_readback not in installed_readback:
            raise RuntimeError("Certificate installer terminal readback omits the shared executable parent.")

        verifier_required = (
            "libexec_root=/usr/local/libexec/mochirii-forums",
            'deploy_dispatcher="${libexec_root}/ssh-deploy-dispatch.py"',
            directory_readback,
            '[[ -x ${deploy_dispatcher} && ! -L ${deploy_dispatcher}',
            '"$(stat -c \'%U:%G %a\' "${deploy_dispatcher}")" == "root:root 755"',
            'sudo -u mochirii-forums-deploy test -x "${deploy_dispatcher}"',
        )
        if any(value not in verifier_source for value in verifier_required):
            raise RuntimeError("Terminal host verifier omits the shared executable traversal contract.")

        reconcile_start = upgrader_source.index("reconcile_shared_libexec_traversal() {")
        reconcile_end = upgrader_source.index("\n}\n", reconcile_start)
        reconcile = upgrader_source[reconcile_start:reconcile_end]
        reconcile_required = (
            "local previous_defect='" + historical_defect + "'",
            "local candidate_private='" + private_directories + "'",
            "local candidate_shared='" + shared_directory + "'",
            '[[ -d ${libexec_root} && ! -L ${libexec_root} ]]',
            '[[ "$(stat -c \'%U:%G\' "${libexec_root}")" == root:root ]]',
            'if [[ ${current_mode} == 755 ]]',
            '[[ ${current_mode} == 700 ]]',
            'grep -Fqx -- "${previous_defect}" "${previous_source}/scripts/install-media-certificate-renewal.sh"',
            'grep -Fqx -- "${candidate_private}" "${candidate_source}/scripts/install-media-certificate-renewal.sh"',
            'grep -Fqx -- "${candidate_shared}" "${candidate_source}/scripts/install-media-certificate-renewal.sh"',
            'chmod 0755 -- "${libexec_root}"',
            'sync -d "${libexec_root}"',
            'sync -d "$(dirname -- "${libexec_root}")"',
            deploy_traversal,
        )
        if any(value not in reconcile for value in reconcile_required):
            raise RuntimeError("Governed upgrade lost its exact monotonic traversal repair.")
        chmod_lines = [line.strip() for line in reconcile.splitlines() if "chmod " in line]
        if chmod_lines != ['chmod 0755 -- "${libexec_root}" || return 1']:
            raise RuntimeError("Governed traversal repair can change more than the exact shared-directory mode.")
        if reconcile.count(deploy_traversal) != 2:
            raise RuntimeError("Governed traversal repair does not prove both idempotent and corrected execution.")

        predecessor_gate = upgrader_source.index(
            'bash "${previous_source}/scripts/verify-host-security.sh" "${previous_commit}" "${previous_source}"'
        )
        service_end = upgrader_source.index("\nelse\n", predecessor_gate)
        socket_end = upgrader_source.index("\nfi\n", service_end)
        service_branch = upgrader_source[predecessor_gate:service_end]
        socket_branch = upgrader_source[service_end:socket_end]
        if reconcile_call not in service_branch or service_branch.index(reconcile_call) <= 0:
            raise RuntimeError("Traversal correction is not bound after the exact service predecessor verifier.")
        if "reconcile_shared_libexec_traversal" in socket_branch:
            raise RuntimeError("Socket-activation recovery can mutate the shared executable parent.")
        post_readback = upgrader_source[
            upgrader_source.index("post_install_readback() {") :
            upgrader_source.index("clear_transaction() {")
        ]
        if directory_readback not in post_readback or deploy_traversal not in post_readback:
            raise RuntimeError("Transactional terminal readback omits shared executable traversal.")

        deployment_required = (
            "exact historical certificate-",
            "root-owned mode-`0755` executable-boundary contract",
            "exact mode-`0700` defect",
            "syncs the directory and its parent",
            "socket-activation recovery branch does not perform this repair",
        )
        provider_required = (
            "shared executable traversal boundary",
            "mode-`0755` directory",
            "unprivileged deploy principal",
            "private-directory mode",
        )
        if any(value not in deployment_source for value in deployment_required):
            raise RuntimeError("Governed traversal repair documentation is incomplete.")
        if any(value not in provider_source for value in provider_required):
            raise RuntimeError("Certificate installer traversal documentation is incomplete.")

    assert_contract(installer, upgrader, verifier, deployment, provider)
    hostile_mutations = (
        (installer.replace(shared_directory, shared_directory.replace("0755", "0700"), 1), upgrader, verifier, deployment, provider),
        (installer, upgrader.replace('[[ ${current_mode} == 700 ]]', '[[ ${current_mode} == 777 ]]', 1), verifier, deployment, provider),
        (installer, upgrader.replace('chmod 0755 -- "${libexec_root}"', 'chmod 0777 -- "${libexec_root}"', 1), verifier, deployment, provider),
        (installer, upgrader.replace(reconcile_call, "true", 1), verifier, deployment, provider),
        (installer, upgrader, verifier.replace('sudo -u mochirii-forums-deploy test -x "${deploy_dispatcher}"', "true", 1), deployment, provider),
        (installer, upgrader, verifier, deployment.replace("syncs the directory and its parent", "changes the directory"), provider),
    )
    for sources in hostile_mutations:
        try:
            assert_contract(*sources)
        except (RuntimeError, ValueError):
            continue
        raise RuntimeError("Hostile shared-libexec traversal mutation passed the source contract.")


def test_certificate_control_evidence_adoption_contract() -> None:
    installer = (ROOT / "scripts/install-media-certificate-renewal.sh").read_text(encoding="utf-8")
    evidence = (ROOT / "scripts/host-control-evidence.py").read_text(encoding="utf-8")
    verifier = (ROOT / "scripts/verify-host-security.sh").read_text(encoding="utf-8")
    required = (
        'assert-held --locks primary,media',
        'run --locks primary,media',
        'read_current_control_binding()',
        '"manifestSha256": manifest_sha',
        '"previousControlEvidenceSha256": predecessor',
        '[[ ${current_commit} == "${commit}" && ${current_manifest} == "${manifest_sha}" && ${current_sha} == "${predecessor}" ]]',
        'validate_installed_automation_bytes()',
        'seal_certificate_control_state()',
        '--operation certificate-install',
        'verify_certificate_control_state()',
        'record.get("previousControlEvidenceSha256") != predecessor',
        'timeout --signal=TERM --kill-after=10s 180s bash "${host_security_verifier}"',
    )
    if any(value not in installer for value in required):
        raise RuntimeError("Certificate install lost its journaled predecessor, exact-byte readback, or terminal control reseal boundary.")
    if "--locks media,primary" in installer:
        raise RuntimeError("Certificate install lock ordering can deadlock the governed host-control upgrade.")

    recovery_start = installer.index('if [[ ${prior_install_phase} == committed ]]')
    recovery_end = installer.index('cleanup_installation || fail', recovery_start)
    recovery = installer[recovery_start:recovery_end]
    recovery_order = (
        'validate_installed_automation_bytes || fail',
        'media_run_bounded install-resume-enabled',
        'media_run_bounded install-resume-active',
        'media_run_bounded install-resume-preflight',
        'seal_certificate_control_state || fail',
        'verify_certificate_control_state || fail',
        'media_record_event certificate-install passed',
        'clear_install_journal',
    )
    recovery_positions = [recovery.index(value) for value in recovery_order]
    if recovery_positions != sorted(recovery_positions):
        raise RuntimeError("Committed certificate retry can report success before adopting and verifying its control record.")

    install = installer[installer.index('write_install_journal installing'):]
    install_order = (
        'write_install_journal installing',
        'media_record_event certificate-install started',
        'media_run_bounded install-timer-enabled-readback',
        'media_run_bounded install-timer-active-readback',
        'validate_installed_automation_bytes || fail',
        'write_install_journal committed',
        'seal_certificate_control_state || fail',
        'verify_certificate_control_state || fail',
        'media_record_event certificate-install passed',
        'clear_install_journal',
    )
    install_positions = [install.index(value) for value in install_order]
    if install_positions != sorted(install_positions):
        raise RuntimeError("Certificate install can clear or report success before exact readback, reseal, and terminal verification.")
    if 'if path.exists() or path.is_symlink():' not in evidence or 'set(document) - {"recordedAt"}' not in evidence:
        raise RuntimeError("Immutable host-control evidence lost exact idempotent retry adoption.")
    for source in (evidence, verifier):
        if '"certificate-install"' not in source:
            raise RuntimeError("Certificate-authored host-control evidence is rejected by a stable control component.")


def test_certificate_commit_forward_retirement() -> None:
    endpoint_id = "00000000-0000-4000-8000-000000000010"
    old_identifier = "00000000-0000-4000-8000-000000000011"
    new_identifier = "00000000-0000-4000-8000-000000000012"
    origin = "mochirii-forums.sgp1.digitaloceanspaces.com"
    name = "mochirii-media-forums-fixture-commit-forward"
    inventory = {
        old_identifier: "mochirii-media-forums-old",
        new_identifier: name,
    }
    journal = {
        "schemaVersion": 1,
        "endpointId": endpoint_id,
        "cdnOrigin": origin,
        "customDomain": ROTATE.MEDIA_HOST,
        "transactionName": name,
        "priorCertificateIds": [old_identifier],
        "oldCertificateId": old_identifier,
        "oldTlsSha256": "a" * 64,
        "newCertificateSha256": "b" * 64,
        "newCertificateId": new_identifier,
        "ttl": 3600,
        "phase": "retiring-old",
        "createdAt": 1,
        "absenceObservations": 0,
        "lastAbsenceAt": None,
    }
    calls: list[tuple[str, str]] = []
    cleared = False
    stale_inventory_reads = 0
    originals = {
        "load_journal": ROTATE.load_journal,
        "endpoint": ROTATE.endpoint,
        "observe": ROTATE.observe_transaction_certificates,
        "inventory": ROTATE.certificate_inventory,
        "api": ROTATE.api,
        "wait": ROTATE.wait_for_tls,
        "clear": ROTATE.clear_journal,
        "update": ROTATE.update_journal,
        "time": ROTATE.time.time,
    }

    def fixture_endpoint(token: str, requested: str):
        del token
        if requested != endpoint_id:
            raise RuntimeError("Unexpected endpoint identity.")
        return {
            "id": endpoint_id,
            "origin": origin,
            "ttl": 3600,
            "custom_domain": ROTATE.MEDIA_HOST,
            "certificate_id": new_identifier,
        }

    def fixture_inventory(token: str):
        nonlocal stale_inventory_reads
        del token
        if stale_inventory_reads:
            stale_inventory_reads -= 1
            return [
                {"id": old_identifier, "name": "mochirii-media-forums-old"},
                {"id": new_identifier, "name": name},
            ]
        return [{"id": identifier, "name": value} for identifier, value in inventory.items()]

    def response_loss_api(token: str, method: str, path: str, payload=None):
        nonlocal stale_inventory_reads
        del token, payload
        calls.append((method, path))
        if method == "DELETE" and path == f"/certificates/{old_identifier}":
            existed = old_identifier in inventory
            inventory.pop(old_identifier, None)
            if existed:
                stale_inventory_reads = 1
            raise ROTATE.ProviderResponseUncertain("Fixture lost the successful DELETE response.")
        if method == "PUT":
            raise RuntimeError("Commit-forward reconciliation attempted a forbidden rollback.")
        raise RuntimeError(f"Unexpected mocked provider operation: {method} {path}")

    def clear_fixture_journal() -> None:
        nonlocal cleared
        cleared = True

    def update_fixture_journal(document: dict[str, object], **changes: object):
        del document
        journal.update(changes)
        return dict(journal)

    observed_times = iter((100, 161))

    ROTATE.load_journal = lambda requested, requested_origin: journal
    ROTATE.endpoint = fixture_endpoint
    ROTATE.observe_transaction_certificates = lambda *_args, **_kwargs: [new_identifier]
    ROTATE.certificate_inventory = fixture_inventory
    ROTATE.api = response_loss_api
    ROTATE.wait_for_tls = lambda fingerprint: None
    ROTATE.clear_journal = clear_fixture_journal
    ROTATE.update_journal = update_fixture_journal
    ROTATE.time.time = lambda: next(observed_times)
    try:
        for expected_failure in ("stale inventory", "first absence observation"):
            try:
                ROTATE.reconcile_journal("fixture-token", endpoint_id, origin)
            except ROTATE.RotationError:
                pass
            else:
                raise RuntimeError(f"Uncertain retirement passed during {expected_failure}.")
            if cleared:
                raise RuntimeError("Uncertain retirement cleared its recovery journal prematurely.")
        if not ROTATE.reconcile_journal("fixture-token", endpoint_id, origin):
            raise RuntimeError("Commit-forward certificate reconciliation did not complete.")
    finally:
        ROTATE.load_journal = originals["load_journal"]
        ROTATE.endpoint = originals["endpoint"]
        ROTATE.observe_transaction_certificates = originals["observe"]
        ROTATE.certificate_inventory = originals["inventory"]
        ROTATE.api = originals["api"]
        ROTATE.wait_for_tls = originals["wait"]
        ROTATE.clear_journal = originals["clear"]
        ROTATE.update_journal = originals["update"]
        ROTATE.time.time = originals["time"]
    if not cleared or old_identifier in inventory or new_identifier not in inventory:
        raise RuntimeError("Commit-forward retirement did not preserve only the new certificate.")
    if any(method == "PUT" for method, _ in calls):
        raise RuntimeError("Commit-forward retirement attempted to rebind the old certificate.")
    if sum(method == "DELETE" for method, _ in calls) != 3:
        raise RuntimeError("Commit-forward retirement did not retry the exact idempotent deletion.")


def test_certificate_commit_forward_ignores_stale_absence() -> None:
    endpoint_id = "00000000-0000-4000-8000-000000000020"
    old_identifier = "00000000-0000-4000-8000-000000000021"
    new_identifier = "00000000-0000-4000-8000-000000000022"
    origin = "mochirii-forums.sgp1.digitaloceanspaces.com"
    name = "mochirii-media-forums-fixture-stale-absence"
    delete_attempts = 0
    cleared = False
    journal = {
        "schemaVersion": 1,
        "endpointId": endpoint_id,
        "cdnOrigin": origin,
        "customDomain": ROTATE.MEDIA_HOST,
        "transactionName": name,
        "priorCertificateIds": [old_identifier],
        "oldCertificateId": old_identifier,
        "oldTlsSha256": "c" * 64,
        "newCertificateSha256": "d" * 64,
        "newCertificateId": new_identifier,
        "ttl": 3600,
        "phase": "retiring-old",
        "createdAt": 1,
        "absenceObservations": 0,
        "lastAbsenceAt": None,
    }
    originals = {
        "load_journal": ROTATE.load_journal,
        "endpoint": ROTATE.endpoint,
        "observe": ROTATE.observe_transaction_certificates,
        "inventory": ROTATE.certificate_inventory,
        "api": ROTATE.api,
        "wait": ROTATE.wait_for_tls,
        "clear": ROTATE.clear_journal,
        "update": ROTATE.update_journal,
        "time": ROTATE.time.time,
    }

    def fixture_endpoint(_token: str, _requested: str):
        return {
            "id": endpoint_id,
            "origin": origin,
            "ttl": 3600,
            "custom_domain": ROTATE.MEDIA_HOST,
            "certificate_id": new_identifier,
        }

    def delete_despite_stale_absence(_token: str, method: str, path: str, payload=None):
        nonlocal delete_attempts
        del payload
        if method != "DELETE" or path != f"/certificates/{old_identifier}":
            raise RuntimeError("Unexpected stale-absence fixture operation.")
        delete_attempts += 1
        return None

    def clear_fixture_journal() -> None:
        nonlocal cleared
        cleared = True

    def update_fixture_journal(document: dict[str, object], **changes: object):
        del document
        journal.update(changes)
        return dict(journal)

    ROTATE.load_journal = lambda *_args: journal
    ROTATE.endpoint = fixture_endpoint
    ROTATE.observe_transaction_certificates = lambda *_args, **_kwargs: [new_identifier]
    ROTATE.certificate_inventory = lambda _token: [{"id": new_identifier, "name": name}]
    ROTATE.api = delete_despite_stale_absence
    ROTATE.wait_for_tls = lambda _fingerprint: None
    ROTATE.clear_journal = clear_fixture_journal
    ROTATE.update_journal = update_fixture_journal
    observed_times = iter((100, 161))
    ROTATE.time.time = lambda: next(observed_times)
    try:
        try:
            ROTATE.reconcile_journal("fixture-token", endpoint_id, origin)
        except ROTATE.RetirementSettlementPending:
            pass
        else:
            raise RuntimeError("A successful DELETE plus one immediate absence cleared the journal.")
        if cleared or journal["absenceObservations"] != 1 or journal["lastAbsenceAt"] != 100:
            raise RuntimeError("First successful-DELETE absence was not retained in the sealed journal.")
        if not ROTATE.reconcile_journal("fixture-token", endpoint_id, origin):
            raise RuntimeError("Time-separated successful-DELETE retirement did not complete.")
    finally:
        ROTATE.load_journal = originals["load_journal"]
        ROTATE.endpoint = originals["endpoint"]
        ROTATE.observe_transaction_certificates = originals["observe"]
        ROTATE.certificate_inventory = originals["inventory"]
        ROTATE.api = originals["api"]
        ROTATE.wait_for_tls = originals["wait"]
        ROTATE.clear_journal = originals["clear"]
        ROTATE.update_journal = originals["update"]
        ROTATE.time.time = originals["time"]
    if delete_attempts != 2 or not cleared:
        raise RuntimeError("Time-separated successful-DELETE retirement did not finish safely.")


def test_certificate_rejected_retirement_remains_blocked() -> None:
    endpoint_id = "00000000-0000-4000-8000-000000000030"
    old_identifier = "00000000-0000-4000-8000-000000000031"
    new_identifier = "00000000-0000-4000-8000-000000000032"
    origin = "mochirii-forums.sgp1.digitaloceanspaces.com"
    name = "mochirii-media-forums-fixture-hard-rejection"
    journal = {
        "schemaVersion": 1,
        "endpointId": endpoint_id,
        "cdnOrigin": origin,
        "customDomain": ROTATE.MEDIA_HOST,
        "transactionName": name,
        "priorCertificateIds": [old_identifier],
        "oldCertificateId": old_identifier,
        "oldTlsSha256": "e" * 64,
        "newCertificateSha256": "f" * 64,
        "newCertificateId": new_identifier,
        "ttl": 3600,
        "phase": "retiring-old",
        "createdAt": 1,
        "absenceObservations": 0,
        "lastAbsenceAt": None,
    }
    calls: list[tuple[str, str]] = []
    cleared = False
    originals = {
        "load_journal": ROTATE.load_journal,
        "endpoint": ROTATE.endpoint,
        "observe": ROTATE.observe_transaction_certificates,
        "inventory": ROTATE.certificate_inventory,
        "api": ROTATE.api,
        "wait": ROTATE.wait_for_tls,
        "clear": ROTATE.clear_journal,
        "update": ROTATE.update_journal,
    }

    ROTATE.load_journal = lambda *_args: journal
    ROTATE.endpoint = lambda *_args: {
        "id": endpoint_id,
        "origin": origin,
        "ttl": 3600,
        "custom_domain": ROTATE.MEDIA_HOST,
        "certificate_id": new_identifier,
    }
    ROTATE.observe_transaction_certificates = lambda *_args, **_kwargs: [new_identifier]
    ROTATE.certificate_inventory = lambda _token: [{"id": new_identifier, "name": name}]

    def rejected_delete(_token: str, method: str, path: str, payload=None):
        del payload
        calls.append((method, path))
        raise ROTATE.ProviderHTTPError(403)

    ROTATE.api = rejected_delete
    ROTATE.wait_for_tls = lambda _fingerprint: None

    def forbidden_clear() -> None:
        nonlocal cleared
        cleared = True

    ROTATE.clear_journal = forbidden_clear
    ROTATE.update_journal = lambda *_args, **_kwargs: (_ for _ in ()).throw(
        RuntimeError("Explicitly rejected DELETE advanced absence evidence.")
    )
    try:
        for _ in range(2):
            try:
                ROTATE.reconcile_journal("fixture-token", endpoint_id, origin)
            except ROTATE.ProviderHTTPError as error:
                if error.status != 403:
                    raise
            else:
                raise RuntimeError("Explicitly rejected certificate retirement was accepted.")
    finally:
        ROTATE.load_journal = originals["load_journal"]
        ROTATE.endpoint = originals["endpoint"]
        ROTATE.observe_transaction_certificates = originals["observe"]
        ROTATE.certificate_inventory = originals["inventory"]
        ROTATE.api = originals["api"]
        ROTATE.wait_for_tls = originals["wait"]
        ROTATE.clear_journal = originals["clear"]
        ROTATE.update_journal = originals["update"]
    if cleared or journal["absenceObservations"] != 0 or len(calls) != 2:
        raise RuntimeError("Explicitly rejected retirement did not retain the sealed journal.")


def test_storage_response_boundary() -> None:
    host_deploy = (ROOT / "scripts/host-deploy.sh").read_text(encoding="utf-8")
    prearmed = host_deploy.index(
        'readarray -t storage_journal_contract < <(create_storage_cleanup_journal "${storage_transaction_id}")'
    )
    armed = host_deploy.index("storage_fixture_created=true", prearmed)
    create = host_deploy.index("run_storage_fixture create", armed)
    failure_state = host_deploy.index('promote_storage_state "${storage_create_result}" "${storage_state}"', create)
    if not prearmed < armed < create < failure_state:
        raise RuntimeError("Hosted storage cleanup state is not armed before the untrusted streamed response.")

    disposable = (ROOT / ".github/workflows/disposable-bootstrap.yml").read_text(encoding="utf-8")
    required_isolation = (
        "image=discourse/base@sha256:3b1846055ca723d13ef7dc3466da61627f32e8b212283561a6c617d759fcec48",
        "ruby_fixture_container=(--rm --pull=never --network none --read-only --tmpfs /tmp:rw,noexec,nosuid,nodev,size=16m --cap-drop ALL --security-opt no-new-privileges --pids-limit 64 --memory 256m --memory-swap 256m)",
        'docker pull "$image"',
        'docker image inspect "$image"',
    )
    if any(value not in disposable for value in required_isolation):
        raise RuntimeError("Disposable Ruby fixtures lost their exact pinned isolated container boundary.")
    for fixture in (
        "test-storage-response-boundary.rb",
        "test-backup-url-boundary.rb",
        "test-normal-upload-inventory.rb",
        "test-admin-login-link.rb",
        "test-narrative-avatar.rb",
        "test-sidekiq-processing-probe.rb",
    ):
        pattern = re.compile(
            r'docker run "\$\{ruby_fixture_container\[@\]\}" -v "\$GITHUB_WORKSPACE:/repo:ro" "\$image" \\\n\s+ruby /repo/scripts/'
            + re.escape(fixture)
            + r" >/dev/null"
        )
        if len(pattern.findall(disposable)) != 1:
            raise RuntimeError(f"Disposable Ruby fixture is not contained in the pinned image: {fixture}")
    normal_upload_fixture = (ROOT / "scripts/test-normal-upload-inventory.rb").read_text(encoding="utf-8")
    for canary in (
        'assert(inventory.keys.length == 2, "normal upload inventory leaked raw identity")',
        'assert_failure("object path is malformed")',
        'assert_failure("object size differs from its row")',
        'assert_failure("object ETag is malformed")',
        'assert_failure("object is absent")',
        'assert_failure("row count exceeds its bound")',
        'assert_failure("external S3 upload storage is inactive")',
        '"schemaVersion" => 2',
        '"repositoryTree" => "9" * 40',
        '"releaseArchiveBytes" => 512',
        'publisher_validator.source_authority(clean_document)',
        '"releaseArchiveContainsSecrets" => false',
        '"ordinaryDeploymentRequiresCurrentMain" => true',
        '"historicalReleaseAdoptionScope" => "clean-target-disaster-recovery-only"',
        'fetcher_source.split("\\nfetch_mode = ENV.fetch", 2)',
    ):
        if canary not in normal_upload_fixture:
            raise RuntimeError("Normal-upload inventory hostile fixture coverage differs.")

    # These hostile Ruby fixtures execute only in the exact pinned, isolated
    # disposable-bootstrap image asserted above. The offline Python contract
    # intentionally has no host Ruby or floating container dependency.


def test_ssh_dispatch_contract() -> None:
    source = (ROOT / "scripts/ssh-deploy-dispatch.py").read_text(encoding="utf-8")
    backup_workflow = (ROOT / ".github/workflows/backup-forums.yml").read_text(encoding="utf-8")
    required = (
        "fcntl.LOCK_EX | fcntl.LOCK_NB",
        "signal.alarm(MAX_RECEIVE_SECONDS)",
        "MAX_RECEIVE_SECONDS = 300",
        '"/usr/local/sbin/mochirii-forums-deploy"',
        '"/usr/local/sbin/mochirii-forums-verify"',
        '"/usr/local/sbin/mochirii-forums-backup"',
        '"/usr/local/sbin/mochirii-forums-restore"',
        'PARTIAL_NAME = ".receive.partial"',
        "reconcile_partial()",
        "signal.SIGHUP, signal.SIGINT, signal.SIGTERM, signal.SIGALRM",
        '"backup": re.compile(rf"\\Abackup {COMMIT} {DIGEST}\\Z")',
        '["/usr/local/sbin/mochirii-forums-backup", values[0], values[1]]',
    )
    if any(value not in source for value in required) or "shell=True" in source:
        raise RuntimeError("Forced-command SSH dispatcher lost its bounded non-shell contract.")
    backup_operation_contract = (
        '[[ "$GITHUB_RUN_ID" =~ ^[0-9]{1,32}$ ]]',
        'backup_operation_sha256="$(printf \'%s\' "mochirii-forums-backup-v1:${GITHUB_RUN_ID}" | sha256sum | awk \'{print $1}\')"',
        '[[ "$backup_operation_sha256" =~ ^[0-9a-f]{64}$ ]]',
        '"backup ${RELEASE_COMMIT} ${backup_operation_sha256}"',
    )
    if any(value not in backup_workflow for value in backup_operation_contract):
        raise RuntimeError("Backup workflow lost its stable opaque operation identity.")
    host_deploy = (ROOT / "scripts/host-deploy.sh").read_text(encoding="utf-8")
    canonical_compare = host_deploy.index('cmp -s -- "${trusted_archive}" "${quarantine}"')
    durable_consume = host_deploy.index('consume_incoming_archive || fail', canonical_compare)
    if (
        not canonical_compare < durable_consume
        or "incoming_archive_consumed=false" not in host_deploy
        or 'rm -f -- "${resolved_archive}"' not in host_deploy
        or "os.fsync(descriptor)" not in host_deploy
    ):
        raise RuntimeError("Root deployment does not durably consume its one-slot transport archive.")
    if os.name != "posix":
        return

    import fcntl

    dispatch = module_from("scripts/ssh-deploy-dispatch.py", "ssh_deploy_dispatch")
    commit = "a" * 40
    digest = "b" * 64
    valid = (
        f"receive {commit} {digest} 1",
        f"deploy {commit} {digest} 1 bootstrap",
        f"verify {commit}",
        f"backup {commit} {digest}",
        f"restore {commit}",
    )
    hostile = (
        "bash",
        "internal-sftp",
        f"verify {commit};id",
        f"receive {commit} {digest} 1 extra",
        f"backup {commit}",
        f"backup {commit} {digest} extra",
        f"deploy {commit} {digest} 1 rebuild\nwhoami",
    )
    if any(not any(pattern.fullmatch(value) for pattern in dispatch.COMMANDS.values()) for value in valid):
        raise RuntimeError("Forced-command SSH dispatcher rejected an exact allowed verb.")
    if any(any(pattern.fullmatch(value) for pattern in dispatch.COMMANDS.values()) for value in hostile):
        raise RuntimeError("Forced-command SSH dispatcher accepted a hostile command.")

    with tempfile.TemporaryDirectory(prefix="mochirii-dispatch-lock-") as directory:
        incoming = Path(directory)
        incoming.chmod(0o700)
        original_incoming = dispatch.INCOMING
        dispatch.INCOMING = incoming
        first = dispatch.acquire_dispatch_lock()
        try:
            try:
                dispatch.acquire_dispatch_lock()
            except dispatch.DispatchError:
                pass
            else:
                raise RuntimeError("Concurrent SSH intake did not fail closed.")
        finally:
            fcntl.flock(first, fcntl.LOCK_UN)
            os.close(first)
            dispatch.INCOMING = original_incoming
    with tempfile.TemporaryDirectory(prefix="mochirii-dispatch-inventory-") as directory:
        incoming = Path(directory)
        incoming.chmod(0o700)
        original_incoming = dispatch.INCOMING
        dispatch.INCOMING = incoming
        try:
            first_archive = incoming / f"{commit}.tar"
            first_archive.write_bytes(b"a")
            first_archive.chmod(0o600)
            dispatch.safe_incoming(first_archive)
            second_archive = incoming / f"{'c' * 40}.tar"
            second_archive.write_bytes(b"b")
            second_archive.chmod(0o600)
            try:
                dispatch.safe_incoming(first_archive)
            except dispatch.DispatchError:
                pass
            else:
                raise RuntimeError("A second arbitrary commit escaped the one-slot incoming quota.")
            second_archive.unlink()
            rogue = incoming / "unexpected"
            rogue.write_bytes(b"fixture")
            rogue.chmod(0o600)
            try:
                dispatch.safe_incoming(first_archive)
            except dispatch.DispatchError:
                pass
            else:
                raise RuntimeError("Unexpected incoming inventory was accepted.")
            rogue.unlink()
            partial = incoming / dispatch.PARTIAL_NAME
            partial.write_bytes(b"stranded")
            partial.chmod(0o600)
            dispatch.safe_incoming(first_archive, allow_partial=True)
            dispatch.reconcile_partial()
            if partial.exists():
                raise RuntimeError("A stranded exact partial slot was not reconciled.")
            partial.symlink_to(first_archive)
            try:
                dispatch.safe_incoming(first_archive, allow_partial=True)
            except dispatch.DispatchError:
                pass
            else:
                raise RuntimeError("A hostile partial-slot symlink was accepted.")
            partial.unlink()
            original_read = dispatch.os.read
            try:
                exact_digest = hashlib.sha256(b"a").hexdigest()
                chunks = iter((b"a", b""))
                dispatch.os.read = lambda _descriptor, _size: next(chunks)
                dispatch.receive(commit, exact_digest, "1")
                if first_archive.read_bytes() != b"a" or partial.exists():
                    raise RuntimeError("Idempotent existing-target intake created a second on-disk archive slot.")

                first_archive.unlink()
                calls = 0
                def interrupted_read(_descriptor: int, _size: int) -> bytes:
                    nonlocal calls
                    calls += 1
                    if calls == 1:
                        return b"x"
                    dispatch.receive_interrupted(signal.SIGTERM, None)
                    return b""
                dispatch.os.read = interrupted_read
                try:
                    dispatch.receive(commit, hashlib.sha256(b"xy").hexdigest(), "2")
                except dispatch.DispatchError:
                    pass
                else:
                    raise RuntimeError("Interrupted SSH intake did not fail closed.")
                if partial.exists() or first_archive.exists():
                    raise RuntimeError("Interrupted SSH intake stranded a durable partial or target archive.")
            finally:
                dispatch.os.read = original_read
        finally:
            dispatch.INCOMING = original_incoming
    try:
        dispatch.receive_interrupted(signal.SIGALRM, None)
    except dispatch.DispatchError:
        pass
    else:
        raise RuntimeError("Overlong SSH intake deadline did not fail closed.")


def test_current_main_observation() -> None:
    provenance = json.loads((ROOT / "docs/operations/upstream-provenance.v1.json").read_text(encoding="utf-8"))
    observation = provenance["driftObservation"]
    pinned = provenance["upstream"]["revision"]
    expected_new_commits = [
        {
            "revision": "3cdefc992290e6d1376a11c72bada098f7b3cf6a",
            "tree": "8ba8cd9d92578682170da2700b466c2c075348c1",
            "signatureVerified": True,
            "signatureReason": "valid",
            "subject": "FIX: Include PostgreSQL 15 in the dev image (#1114)",
        },
        {
            "revision": "ccb3ea007204c683f7177258f1f509e2fb36f82b",
            "tree": "74c8d88910e156d45e319a97ca884892fcca75d1",
            "signatureVerified": True,
            "signatureReason": "valid",
            "subject": "PERF: Skip chown for files that already have the right ownership (#1115)",
        },
        {
            "revision": "00595119c368c0aef7d7019ec66ffc8fa51cce79",
            "tree": "d5b846bf4e59784c5220c48839d7eb1b45671aae",
            "signatureVerified": True,
            "signatureReason": "valid",
            "subject": "PERF: Refresh Fontconfig cache after package installation (#1117)",
        },
    ]
    if (
        observation["observedAt"] != "2026-08-20"
        or observation["commitsAheadOfPin"] != 11
        or observation["commitsBehindPin"] != 0
        or observation["totalCommits"] != 11
        or len(observation["changedPaths"]) != 20
        or observation["rangeCommits"][-3:] != expected_new_commits
        or [entry["classification"] for entry in observation["materialChangeScope"][-3:]]
        != [
            "dev-image-postgresql-15",
            "web-template-ownership-optimization",
            "base-image-fontconfig-cache-refresh",
        ]
    ):
        raise RuntimeError("The refreshed bounded deployment-source observation changed.")

    def reference_document() -> dict:
        return {
            "ref": "refs/heads/main",
            "object": {"type": "commit", "sha": observation["mainRevision"]},
        }

    def commit_document() -> dict:
        return {
            "sha": observation["mainRevision"],
            "tree": {"sha": observation["mainTree"]},
            "verification": {
                "verified": observation["mainCommitSignatureVerified"],
                "reason": observation["mainCommitSignatureReason"],
            },
        }

    def comparison_document() -> dict:
        return {
            "status": observation["comparisonStatus"],
            "ahead_by": observation["commitsAheadOfPin"],
            "behind_by": observation["commitsBehindPin"],
            "total_commits": observation["totalCommits"],
            "base_commit": {"sha": pinned},
            "merge_base_commit": {"sha": pinned},
            "head_commit": {"sha": observation["mainRevision"]},
            "commits": [
                {
                    "sha": entry["revision"],
                    "commit": {
                        "tree": {"sha": entry["tree"]},
                        "verification": {
                            "verified": entry["signatureVerified"],
                            "reason": entry["signatureReason"],
                        },
                        "message": entry["subject"] + "\n\nfixture body",
                    },
                }
                for entry in observation["rangeCommits"]
            ],
            "files": [{"filename": path} for path in observation["changedPaths"]],
        }

    def exact_request(url: str, **_kwargs):
        if url.endswith("/git/ref/heads/main"):
            return json.dumps(reference_document()).encode(), {}
        if url.endswith("/git/commits/" + observation["mainRevision"]):
            return json.dumps(commit_document()).encode(), {}
        if "/compare/" in url:
            return json.dumps(comparison_document()).encode(), {}
        raise RuntimeError("fixture received an unexpected official-source URL")

    original_request = UPSTREAM.request
    try:
        UPSTREAM.request = exact_request
        UPSTREAM.verify_current_main(provenance)

        hostile_requests = []

        def moved_request(url: str, **kwargs):
            if url.endswith("/git/ref/heads/main"):
                document = reference_document()
                document["object"]["sha"] = "0" * 40
                return json.dumps(document).encode(), {}
            return exact_request(url, **kwargs)

        hostile_requests.append(moved_request)

        def malformed_request(url: str, **kwargs):
            if url.endswith("/git/ref/heads/main"):
                return b"not-json", {}
            return exact_request(url, **kwargs)

        hostile_requests.append(malformed_request)

        def ambiguous_request(url: str, **kwargs):
            if url.endswith("/git/ref/heads/main"):
                return json.dumps([reference_document(), reference_document()]).encode(), {}
            return exact_request(url, **kwargs)

        hostile_requests.append(ambiguous_request)

        def unreachable_request(_url: str, **_kwargs):
            raise RuntimeError("fixture network unavailable")

        hostile_requests.append(unreachable_request)

        def moved_compare_request(url: str, **kwargs):
            if "/compare/" in url:
                document = comparison_document()
                document["ahead_by"] += 1
                return json.dumps(document).encode(), {}
            return exact_request(url, **kwargs)

        hostile_requests.append(moved_compare_request)

        for hostile_request in hostile_requests:
            UPSTREAM.request = hostile_request
            try:
                UPSTREAM.verify_current_main(provenance)
            except RuntimeError:
                pass
            else:
                raise RuntimeError("Current-main verifier accepted moved, malformed, ambiguous, or unreachable evidence.")
    finally:
        UPSTREAM.request = original_request


def expect_validation_failure(action, label: str) -> None:
    try:
        action()
    except RuntimeError:
        return
    raise RuntimeError(f"Repository governance accepted hostile fixture: {label}")


def test_repository_governance() -> None:
    allowed = sorted(VALIDATOR.ALLOWED_FILES)
    if len(allowed) != 164:
        raise RuntimeError("The exact Stage 4 repository inventory count changed.")
    if VALIDATOR.validate_inventory_paths(allowed) != allowed:
        raise RuntimeError("The exact Stage 4 repository inventory did not round trip.")
    VALIDATOR.validate_tracked_entry_mode("100644", "scripts/fixture.py")
    expect_validation_failure(
        lambda: VALIDATOR.validate_tracked_entry_mode("100755", "scripts/fixture.py"),
        "executable tracked source",
    )
    expect_validation_failure(
        lambda: VALIDATOR.validate_tracked_entry_mode("120000", "scripts/fixture.py"),
        "linked tracked source",
    )
    expect_validation_failure(
        lambda: VALIDATOR.validate_inventory_paths([*allowed, "rogue.py"]),
        "extra untracked source",
    )
    expect_validation_failure(
        lambda: VALIDATOR.validate_inventory_paths([*allowed, allowed[0]]),
        "duplicate normalized path",
    )
    expect_validation_failure(
        lambda: VALIDATOR.validate_inventory_paths(
            [*allowed[1:], allowed[0].replace("/", "\\"), allowed[0]],
        ),
        "duplicate slash-normalized path",
    )

    hostile_text = {
        "invalid UTF-8": b"\xff\n",
        "binary control": b"fixture\x01\n",
        "missing EOF newline": b"fixture",
        "blank EOF line": b"fixture\n\n",
        "Git LFS pointer": b"version https://git-lfs.github.com/spec/v1\n",
        "trailing whitespace": b"fixture \n",
        "secret assignment": b"FORUMS_SMTP_PASSWORD=hostile-value\n",
    }
    for label, data in hostile_text.items():
        expect_validation_failure(
            lambda data=data: VALIDATOR.validate_text_contract("fixture.txt", data),
            label,
        )
    VALIDATOR.validate_text_contract(
        ".env.example",
        b"FORUMS_SMTP_PASSWORD=replace-at-runtime\n",
    )
    VALIDATOR.validate_text_contract(
        ".github/workflows/disposable-bootstrap.yml",
        b'FORUMS_FIXTURE_DISCOURSE_CONNECT_SECRET="$(<"$secret_file")" \\\n',
    )

    pull_request_template = (ROOT / ".github/pull_request_template.md").read_text(encoding="utf-8")
    VALIDATOR.validate_stage4_pull_request_template(pull_request_template)
    for required in VALIDATOR.STAGE4_PR_TEMPLATE_REQUIRED:
        expect_validation_failure(
            lambda required=required: VALIDATOR.validate_stage4_pull_request_template(
                pull_request_template.replace(required, "removed-required-contract", 1)
            ),
            f"missing pull-request contract: {required}",
        )
    expect_validation_failure(
        lambda: VALIDATOR.validate_stage4_pull_request_template(
            pull_request_template + "\nAny future upstream-source introduction\n"
        ),
        "retired seed pull-request boundary",
    )

    contributing = (ROOT / "CONTRIBUTING.md").read_text(encoding="utf-8")
    security_policy = (ROOT / "SECURITY.md").read_text(encoding="utf-8")
    contributing_contract = (
        "This public repository owns the reviewed Mochirii Forums configuration",
        "Source review or merge does not authorize a live deployment",
        "Start from current protected `main`",
        "host-control, deployment, backup, restore",
        "Public copy, branding, hostnames, or member-facing behavior",
        "Do not submit credentials, tokens, private keys, cookies, member data",
    )
    security_contract = (
        "Current protected `main` with the exact upstream revisions and image digest",
        "This repository contains supported runtime, host-control, deployment, backup",
        "private vulnerability-reporting or security-",
        "Critical reports target acknowledgement within 24 hours",
        "Never test against production or a provider without explicit",
        "A green source or disposable-runtime check does not claim",
    )
    if any(value not in contributing for value in contributing_contract) or any(
        value in contributing for value in ("currently has no `main` ref", "in this governance phase")
    ):
        raise RuntimeError("Contributing policy regressed to the retired governance seed state.")
    if any(value not in security_policy for value in security_contract) or any(
        value in security_policy for value in ("governance source only", "Once runtime source exists")
    ):
        raise RuntimeError("Security policy regressed to the retired governance seed state.")

    with tempfile.TemporaryDirectory(prefix="mochirii-governance-path-") as directory:
        root = Path(directory)
        regular = root / "regular.txt"
        regular.write_bytes(b"fixture\n")
        if VALIDATOR.validate_path_entry(root, "regular.txt") != b"fixture\n":
            raise RuntimeError("Regular repository file changed during path validation.")
        oversized = root / "oversized.txt"
        oversized.write_bytes(b"a" * (VALIDATOR.MAX_FILE_BYTES + 1))
        expect_validation_failure(
            lambda: VALIDATOR.validate_path_entry(root, "oversized.txt"),
            "oversized file",
        )
        target = root / "target.txt"
        target.write_bytes(b"fixture\n")
        link = root / "link.txt"
        try:
            link.symlink_to(target)
        except OSError:
            if os.name != "nt":
                raise
        else:
            expect_validation_failure(
                lambda: VALIDATOR.validate_path_entry(root, "link.txt"),
                "symbolic link or reparse point",
            )

    workflow_path = ".github/workflows/validate-repository.yml"
    workflow = (ROOT / workflow_path).read_text(encoding="utf-8")
    VALIDATOR.validate_workflow_contract(workflow_path, workflow)
    expect_validation_failure(
        lambda: VALIDATOR.validate_workflow_contract(
            workflow_path,
            workflow.replace("pull_request:", "pull_request_target:", 1),
        ),
        "pull_request_target",
    )
    expect_validation_failure(
        lambda: VALIDATOR.validate_workflow_contract(
            workflow_path,
            workflow.replace("  contents: read", "  contents: write", 1),
        ),
        "write workflow permission",
    )
    review_workflow_path = VALIDATOR.REVIEW_AUTHORITY_WORKFLOW_PATH
    review_workflow = (ROOT / review_workflow_path).read_text(encoding="utf-8")
    codeowners = (ROOT / ".github/CODEOWNERS").read_text(encoding="utf-8")
    VALIDATOR.validate_workflow_contract(review_workflow_path, review_workflow)
    VALIDATOR.validate_review_authority_source(codeowners, review_workflow)
    expect_validation_failure(
        lambda: VALIDATOR.validate_review_authority_source(
            codeowners.replace("* @xartaiusx", "* @unapproved-owner", 1),
            review_workflow,
        ),
        "unapproved repository code owner",
    )
    expect_validation_failure(
        lambda: VALIDATOR.validate_review_authority_source(
            codeowners,
            review_workflow.replace('method not in {"GET", "POST"}', 'method not in {"GET", "POST", "PATCH"}', 1),
        ),
        "updating an existing reviewed-source ref",
    )
    expect_validation_failure(
        lambda: VALIDATOR.validate_workflow_contract(
            review_workflow_path,
            review_workflow.replace("  pull-requests: write", "  pull-requests: read", 1),
        ),
        "review wrapper permission drift",
    )
    checkout_workflow_path = ".github/workflows/disposable-bootstrap.yml"
    checkout_workflow = (ROOT / checkout_workflow_path).read_text(encoding="utf-8")
    expect_validation_failure(
        lambda: VALIDATOR.validate_workflow_contract(
            checkout_workflow_path,
            re.sub(r"actions/checkout@[0-9a-f]{40}", "actions/checkout@main", checkout_workflow, count=1),
        ),
        "moving action reference",
    )

    json_path = "docs/operations/activation.v1.json"
    document = json.loads((ROOT / json_path).read_text(encoding="utf-8"))
    VALIDATOR.validate_json_shape_value(json_path, document)
    additive = json.loads(json.dumps(document))
    additive["deploymentAuthorized"] = True
    expect_validation_failure(
        lambda: VALIDATOR.validate_json_shape_value(json_path, additive),
        "additive JSON property",
    )
    wrong_type = json.loads(json.dumps(document))
    wrong_type["schemaVersion"] = "1"
    expect_validation_failure(
        lambda: VALIDATOR.validate_json_shape_value(json_path, wrong_type),
        "wrong JSON scalar type",
    )
    expect_validation_failure(
        lambda: json.loads('{"schemaVersion":1,"schemaVersion":1}', object_pairs_hook=VALIDATOR._reject_duplicate_json_keys),
        "duplicate JSON property",
    )


def test_extracted_archive_governance() -> None:
    with tempfile.TemporaryDirectory(prefix="mochirii-archive-governance-") as directory:
        boundary = Path(directory)
        staging = boundary / "staging"
        staging.mkdir()
        for relative in sorted(VALIDATOR.ALLOWED_FILES):
            source = ROOT / relative
            target = staging / relative
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(source, target)
        environment_values = {
            **os.environ,
            "GIT_CONFIG_NOSYSTEM": "1",
            "GIT_CONFIG_GLOBAL": os.devnull,
            "GIT_TERMINAL_PROMPT": "0",
        }
        subprocess.run(["git", "init", "--quiet", str(staging)], check=True, env=environment_values)
        subprocess.run(
            ["git", "-C", str(staging), "-c", "core.autocrlf=false", "add", "--all"],
            check=True,
            env=environment_values,
        )
        tree = subprocess.run(
            ["git", "-C", str(staging), "write-tree"],
            check=True,
            stdout=subprocess.PIPE,
            text=True,
            env=environment_values,
        ).stdout.strip()
        if not re.fullmatch(r"[0-9a-f]{40}", tree):
            raise RuntimeError("Fixture Git tree identity is malformed.")
        archive = boundary / "release.tar"
        subprocess.run(
            ["git", "-C", str(staging), "archive", "--format=tar", f"--output={archive}", tree],
            check=True,
            env=environment_values,
        )
        clean = boundary / "clean"
        clean.mkdir()
        with tarfile.open(archive, "r:") as source:
            source.extractall(clean, filter="data")

        def archive_validation(root: Path) -> subprocess.CompletedProcess[bytes]:
            return subprocess.run(
                [
                    sys.executable,
                    "-I",
                    "-S",
                    "-B",
                    str(root / "scripts/validate-repository.py"),
                    "--archive-root",
                    str(root),
                ],
                cwd=root,
                env={**os.environ, "PYTHONDONTWRITEBYTECODE": "1"},
                stdin=subprocess.DEVNULL,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                check=False,
            )

        if archive_validation(clean).returncode != 0:
            raise RuntimeError("Exact extracted Git archive failed repository validation.")
        scenarios = {
            "extra": lambda root: (root / "scripts/rogue.py").write_text("fixture\n", encoding="utf-8"),
            "missing": lambda root: (root / "README.md").unlink(),
            "tampered": lambda root: (root / "theme/mochirii/assets/mochirii-icon.png").write_bytes(b"fixture"),
        }
        for label, mutate in scenarios.items():
            hostile = boundary / label
            shutil.copytree(clean, hostile)
            mutate(hostile)
            if archive_validation(hostile).returncode == 0:
                raise RuntimeError(f"Extracted archive validator accepted {label} bytes.")
        linked = boundary / "linked"
        shutil.copytree(clean, linked)
        linked_readme = linked / "README.md"
        linked_readme.unlink()
        try:
            linked_readme.symlink_to(linked / "AGENTS.md")
        except OSError:
            if os.name != "nt":
                raise
        else:
            if archive_validation(linked).returncode == 0:
                raise RuntimeError("Extracted archive validator accepted a linked source entry.")


def test_reviewed_source_pull_request_wrapper() -> None:
    import http.client

    workflow = (ROOT / VALIDATOR.REVIEW_AUTHORITY_WORKFLOW_PATH).read_text(encoding="utf-8")
    start_marker = "          import http.client\n"
    end_marker = "          PY\n"
    if workflow.count(start_marker) != 1 or workflow.count(end_marker) != 1:
        raise RuntimeError("Reviewed-source workflow Python boundary differs.")
    start = workflow.index(start_marker)
    end = workflow.index(end_marker, start)
    embedded = "\n".join(line[10:] for line in workflow[start:end].splitlines()) + "\n"
    ast.parse(embedded)

    base_sha = "1" * 40
    source_sha = "2" * 40
    tree_sha = "3" * 40
    finalized_sha = "4" * 40
    replacement_finalized_sha = "5" * 40
    head_ref = "codex/agent-2/forums-fixture"
    bot_head_ref = f"codex/github-actions/reviewed-forums-{base_sha[:12]}-{source_sha[:12]}"
    token_sentinel = "github-token-private-sentinel"
    fixed_error = "Reviewed-source pull-request operation failed.\n"
    title = "Forums: reviewed source successor"
    message = "Create reviewed Mochirii Forums source head"
    body = (
        "This pull request was opened by the protected default-branch review wrapper.\n\n"
        f"Reviewed source commit: `{source_sha}`\n"
        f"Reviewed source tree: `{tree_sha}`\n\n"
        "The bot-authored head is tree-identical to the reviewed source and has current main as its sole "
        "parent. A fresh code-owner approval of that exact head and all required checks remain mandatory."
    )
    api_prefix = "/repos/Mochirii-Wushu/Mochirii-Forums"
    query = (
        "state=all&head=Mochirii-Wushu%3Acodex%2Fgithub-actions%2Freviewed-forums-"
        f"{base_sha[:12]}-{source_sha[:12]}&base=main&per_page=100"
    )

    def git_commit(sha: str, parent: str, tree: str, commit_message: str = "source") -> dict[str, object]:
        return {
            "sha": sha,
            "tree": {"sha": tree},
            "parents": [{"sha": parent}],
            "message": commit_message,
        }

    def git_ref(ref: str, sha: str) -> dict[str, object]:
        return {"ref": ref, "object": {"type": "commit", "sha": sha}}

    def pull_request(
        head_sha: str,
        login: str = "github-actions[bot]",
        head_repository: str = "Mochirii-Wushu/Mochirii-Forums",
        base_repository: str = "Mochirii-Wushu/Mochirii-Forums",
    ) -> dict[str, object]:
        return {
            "number": 7,
            "state": "open",
            "draft": False,
            "title": title,
            "body": body,
            "user": {"login": login},
            "head": {"ref": bot_head_ref, "sha": head_sha, "repo": {"full_name": head_repository}},
            "base": {
                "ref": "main",
                "sha": base_sha,
                "repo": {"full_name": base_repository},
            },
        }

    class FakeResponse:
        def __init__(self, status: int, document: object):
            self.status = status
            self.raw = json.dumps(document, ensure_ascii=True, separators=(",", ":")).encode("ascii")

        def getheader(self, name: str, default: str | None = None) -> str | None:
            headers = {
                "Content-Length": str(len(self.raw)),
                "Content-Type": "application/json; charset=utf-8",
            }
            return headers.get(name, default)

        def read(self, maximum: int) -> bytes:
            if maximum != 1024 * 1024 + 1:
                raise RuntimeError("Reviewed-source response bound differs.")
            return self.raw

    def execute(
        responses: list[tuple[str, str, int, object]],
        overrides: dict[str, str] | None = None,
    ):
        remaining = list(responses)
        observed: list[tuple[str, str, object | None, dict[str, str]]] = []

        class FakeConnection:
            def __init__(self, host: str, timeout: int):
                if host != "api.github.com" or timeout != 30:
                    raise RuntimeError("Reviewed-source API origin or timeout differs.")
                self.response: FakeResponse | None = None

            def request(
                self,
                method: str,
                path: str,
                body: bytes | None = None,
                headers: dict[str, str] | None = None,
            ) -> None:
                parsed_body = None if body is None else json.loads(body.decode("ascii"))
                observed_headers = dict(headers or {})
                observed.append((method, path, parsed_body, observed_headers))
                if not remaining:
                    raise RuntimeError("Reviewed-source wrapper issued an extra request.")
                expected_method, expected_path, status, document = remaining.pop(0)
                if method != expected_method or path != expected_path:
                    raise RuntimeError("Reviewed-source request sequence differs.")
                if observed_headers.get("Authorization") != f"Bearer {token_sentinel}":
                    raise RuntimeError("Reviewed-source request omitted its protected authorization boundary.")
                self.response = FakeResponse(status, document)

            def getresponse(self) -> FakeResponse:
                if self.response is None:
                    raise RuntimeError("Reviewed-source response was read before a request.")
                return self.response

            def close(self) -> None:
                return None

        values = {
            "MOCHIRII_EVENT_NAME": "repository_dispatch",
            "MOCHIRII_EVENT_ACTION": "open-reviewed-forums-source-pr",
            "MOCHIRII_REPOSITORY": "Mochirii-Wushu/Mochirii-Forums",
            "MOCHIRII_ACTOR": "xartaiusx",
            "MOCHIRII_TRIGGERING_ACTOR": "xartaiusx",
            "MOCHIRII_SENDER": "xartaiusx",
            "MOCHIRII_RUN_ATTEMPT": "1",
            "MOCHIRII_EVENT_REF": "refs/heads/main",
            "MOCHIRII_EVENT_SHA": base_sha,
            "MOCHIRII_WORKFLOW_REF": (
                "Mochirii-Wushu/Mochirii-Forums/"
                ".github/workflows/open-reviewed-source-pr.yml@refs/heads/main"
            ),
            "MOCHIRII_WORKFLOW_SHA": base_sha,
            "MOCHIRII_HEAD_REF": head_ref,
            "MOCHIRII_EXPECTED_SOURCE_SHA": source_sha,
            "MOCHIRII_EXPECTED_TREE_SHA": tree_sha,
            "MOCHIRII_GITHUB_TOKEN": token_sentinel,
        }
        values.update(overrides or {})
        stdout = io.StringIO()
        stderr = io.StringIO()
        original = http.client.HTTPSConnection
        return_code = 0
        try:
            http.client.HTTPSConnection = FakeConnection
            with environment(values), contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr):
                try:
                    exec(compile(embedded, VALIDATOR.REVIEW_AUTHORITY_WORKFLOW_PATH, "exec"), {})
                except SystemExit as error:
                    return_code = error.code if isinstance(error.code, int) else 1
        finally:
            http.client.HTTPSConnection = original
        if remaining:
            raise RuntimeError("Reviewed-source wrapper skipped an expected request.")
        return return_code, stdout.getvalue(), stderr.getvalue(), observed

    base_path = f"{api_prefix}/git/ref/heads/main"
    source_ref_path = f"{api_prefix}/git/ref/heads/{head_ref}"
    bot_ref_path = f"{api_prefix}/git/ref/heads/{bot_head_ref}"
    base_response = git_ref("refs/heads/main", base_sha)
    source_ref_response = git_ref(f"refs/heads/{head_ref}", source_sha)
    source_response = git_commit(source_sha, base_sha, tree_sha, message)
    compare_response = {
        "status": "ahead",
        "ahead_by": 1,
        "behind_by": 0,
        "total_commits": 1,
        "merge_base_commit": {"sha": base_sha},
    }

    def common(pulls: list[object]) -> list[tuple[str, str, int, object]]:
        return [
            ("GET", base_path, 200, base_response),
            ("GET", source_ref_path, 200, source_ref_response),
            ("GET", f"{api_prefix}/git/commits/{source_sha}", 200, source_response),
            ("GET", f"{api_prefix}/compare/{base_sha}...{source_sha}", 200, compare_response),
            ("GET", f"{api_prefix}/pulls?{query}", 200, pulls),
        ]

    def assert_failure(result: tuple[object, ...], label: str) -> None:
        if result[0] == 0 or result[1] or result[2] != fixed_error or any(
            entry[0] != "GET" for entry in result[3]
        ):
            raise RuntimeError(f"Reviewed-source wrapper accepted {label}.")
        if token_sentinel in result[1] or token_sentinel in result[2]:
            raise RuntimeError("Reviewed-source diagnostics exposed the protected credential.")

    initial = execute(
        [
            *common([]),
            ("GET", bot_ref_path, 404, {"message": "Not Found"}),
            ("GET", base_path, 200, base_response),
            (
                "POST",
                f"{api_prefix}/git/commits",
                201,
                git_commit(finalized_sha, base_sha, tree_sha, message),
            ),
            ("GET", base_path, 200, base_response),
            ("POST", f"{api_prefix}/git/refs", 201, git_ref(f"refs/heads/{bot_head_ref}", finalized_sha)),
            ("GET", base_path, 200, base_response),
            ("POST", f"{api_prefix}/pulls", 201, pull_request(finalized_sha)),
            ("GET", f"{api_prefix}/pulls/7", 200, pull_request(finalized_sha)),
            ("GET", base_path, 200, base_response),
        ]
    )
    if initial[0] != 0 or initial[2] or initial[1] != f"Reviewed-source pull request #7 opened at {finalized_sha}.\n":
        raise RuntimeError("Reviewed-source initial operation did not complete exactly.")
    writes = [entry for entry in initial[3] if entry[0] != "GET"]
    if [entry[0:2] for entry in writes] != [
        ("POST", f"{api_prefix}/git/commits"),
        ("POST", f"{api_prefix}/git/refs"),
        ("POST", f"{api_prefix}/pulls"),
    ]:
        raise RuntimeError("Reviewed-source write boundary differs.")
    if writes[0][2] != {
        "message": message,
        "tree": tree_sha,
        "parents": [base_sha],
    } or writes[1][2] != {
        "ref": f"refs/heads/{bot_head_ref}",
        "sha": finalized_sha,
    } or writes[2][2] != {
        "title": title,
        "head": bot_head_ref,
        "base": "main",
        "body": body,
        "draft": False,
        "maintainer_can_modify": False,
    }:
        raise RuntimeError("Reviewed-source write payload differs.")

    # A failure after the commit-object write leaves no ref. A new dispatch may
    # create a replacement orphan commit before completing the ref and PR.
    after_commit_only = execute(
        [
            *common([]),
            ("GET", bot_ref_path, 404, {"message": "Not Found"}),
            ("GET", base_path, 200, base_response),
            (
                "POST",
                f"{api_prefix}/git/commits",
                201,
                git_commit(replacement_finalized_sha, base_sha, tree_sha, message),
            ),
            ("GET", base_path, 200, base_response),
            (
                "POST",
                f"{api_prefix}/git/refs",
                201,
                git_ref(f"refs/heads/{bot_head_ref}", replacement_finalized_sha),
            ),
            ("GET", base_path, 200, base_response),
            ("POST", f"{api_prefix}/pulls", 201, pull_request(replacement_finalized_sha)),
            ("GET", f"{api_prefix}/pulls/7", 200, pull_request(replacement_finalized_sha)),
            ("GET", base_path, 200, base_response),
        ]
    )
    if (
        after_commit_only[0] != 0
        or after_commit_only[2]
        or after_commit_only[1]
        != f"Reviewed-source pull request #7 opened at {replacement_finalized_sha}.\n"
        or [entry[0:2] for entry in after_commit_only[3] if entry[0] != "GET"]
        != [
            ("POST", f"{api_prefix}/git/commits"),
            ("POST", f"{api_prefix}/git/refs"),
            ("POST", f"{api_prefix}/pulls"),
        ]
    ):
        raise RuntimeError("Reviewed-source commit-only crash replay did not complete exactly.")

    after_ref = execute(
        [
            *common([]),
            ("GET", bot_ref_path, 200, git_ref(f"refs/heads/{bot_head_ref}", finalized_sha)),
            (
                "GET",
                f"{api_prefix}/git/commits/{finalized_sha}",
                200,
                git_commit(finalized_sha, base_sha, tree_sha, message),
            ),
            ("GET", base_path, 200, base_response),
            ("POST", f"{api_prefix}/pulls", 201, pull_request(finalized_sha)),
            ("GET", f"{api_prefix}/pulls/7", 200, pull_request(finalized_sha)),
            ("GET", base_path, 200, base_response),
        ]
    )
    if after_ref[0] != 0 or after_ref[2] or [entry[0:2] for entry in after_ref[3] if entry[0] != "GET"] != [
        ("POST", f"{api_prefix}/pulls")
    ]:
        raise RuntimeError("Reviewed-source ref-only crash replay did not complete exactly.")

    replay = execute(
        [
            *common([pull_request(finalized_sha)]),
            ("GET", bot_ref_path, 200, git_ref(f"refs/heads/{bot_head_ref}", finalized_sha)),
            (
                "GET",
                f"{api_prefix}/git/commits/{finalized_sha}",
                200,
                git_commit(finalized_sha, base_sha, tree_sha, message),
            ),
            ("GET", f"{api_prefix}/pulls/7", 200, pull_request(finalized_sha)),
            ("GET", base_path, 200, base_response),
        ]
    )
    if replay[0] != 0 or replay[2] or any(entry[0] != "GET" for entry in replay[3]):
        raise RuntimeError("Reviewed-source PR-created replay was not exact and read-only.")

    hostile_pr = execute(common([pull_request(finalized_sha, "xartaiusx")]))
    assert_failure(hostile_pr, "a human-authored pull request")
    wrong_head_repository = execute(
        common([pull_request(finalized_sha, head_repository="Mochirii-Wushu/other-repository")])
    )
    assert_failure(wrong_head_repository, "a pull request from another repository")
    wrong_base_repository = execute(
        common([pull_request(finalized_sha, base_repository="Mochirii-Wushu/other-repository")])
    )
    assert_failure(wrong_base_repository, "a pull request targeting another repository")

    source_as_bot = execute(
        [
            *common([pull_request(source_sha)]),
            ("GET", bot_ref_path, 200, git_ref(f"refs/heads/{bot_head_ref}", source_sha)),
        ]
    )
    assert_failure(source_as_bot, "a source-owned head presented as the bot head")

    wrong_parent = execute(
        [
            ("GET", base_path, 200, base_response),
            ("GET", source_ref_path, 200, source_ref_response),
            (
                "GET",
                f"{api_prefix}/git/commits/{source_sha}",
                200,
                git_commit(source_sha, "9" * 40, tree_sha),
            ),
        ]
    )
    assert_failure(wrong_parent, "a non-current-main source parent")

    for label, overrides in {
        "a different initial actor": {"MOCHIRII_ACTOR": "other-writer"},
        "a different re-run actor": {"MOCHIRII_TRIGGERING_ACTOR": "other-writer"},
        "a different dispatch sender": {"MOCHIRII_SENDER": "other-writer"},
        "a workflow re-run": {"MOCHIRII_RUN_ATTEMPT": "2"},
        "a selected source-branch workflow": {
            "MOCHIRII_WORKFLOW_REF": (
                "Mochirii-Wushu/Mochirii-Forums/"
                ".github/workflows/open-reviewed-source-pr.yml@refs/heads/codex/agent-2/forums-fixture"
            )
        },
        "a non-default workflow SHA": {"MOCHIRII_WORKFLOW_SHA": "9" * 40},
        "a non-dispatch event": {"MOCHIRII_EVENT_NAME": "workflow_dispatch"},
    }.items():
        result = execute([], overrides)
        assert_failure(result, label)
        if result[3]:
            raise RuntimeError(f"Reviewed-source wrapper contacted the API for {label}.")


def test_authentication_state_machine() -> None:
    commit = "1" * 40
    configuration = "2" * 64
    pending_name = f"{commit}-{configuration}-authentication-pending.json"
    common = {
        "schemaVersion": 1,
        "recordedAt": "2026-08-15T12:00:00Z",
        "repositoryCommit": commit,
        "productionConfigurationSha256": configuration,
        "releaseEvidenceFile": f"{commit}-{configuration}-release.json",
        "releaseEvidenceSha256": "3" * 64,
        "currentReleaseSha256": "4" * 64,
    }
    records = {
        "consumer-public-producer-pending": {
            **common,
            "activationPhase": "consumer-public-producer-pending",
            "websiteProducerDisabledProved": True,
            "containedActivationPassed": True,
            "publicForumsVerificationPassed": True,
        },
        "complete": {
            **common,
            "activationPhase": "complete",
            "pendingAuthenticationEvidenceFile": pending_name,
            "pendingAuthenticationEvidenceSha256": "5" * 64,
            "websiteEvidenceFile": f"{commit}-{configuration}-website-authentication.json",
            "websiteEvidenceSha256": "6" * 64,
            "websiteRepositoryCommit": "7" * 40,
            **{key: True for key in AUTHENTICATION.COMPLETE_GATES},
        },
        "contained-after-e2e-failure": {
            **common,
            "activationPhase": "contained-after-e2e-failure",
            "pendingAuthenticationEvidenceFile": pending_name,
            "pendingAuthenticationEvidenceSha256": "5" * 64,
            "websiteProducerDisabledProved": True,
            "applicationStopped": True,
        },
        "contained-producer-state-unproved": {
            **common,
            "activationPhase": "contained-producer-state-unproved",
            "pendingAuthenticationEvidenceFile": pending_name,
            "pendingAuthenticationEvidenceSha256": "5" * 64,
            "websiteProducerDisabledProved": False,
            "applicationStopped": True,
        },
        "activation-deploy-failed": {
            "schemaVersion": 1,
            "recordedAt": "2026-08-15T12:00:00Z",
            "repositoryCommit": commit,
            "productionConfigurationSha256": configuration,
            "previousRepositoryCommit": "9" * 40,
            "previousProductionConfigurationSha256": "a" * 64,
            "releaseEvidenceFile": f"{'9' * 40}-{'a' * 64}-release.json",
            "releaseEvidenceSha256": "b" * 64,
            "currentReleaseSha256": "c" * 64,
            "activationPhase": "activation-deploy-failed",
            "websiteProducerDisabledProved": True,
            "applicationStopped": True,
        },
        "activation-deploy-failed-producer-unproved": {
            "schemaVersion": 1,
            "recordedAt": "2026-08-15T12:00:00Z",
            "repositoryCommit": commit,
            "productionConfigurationSha256": configuration,
            "previousRepositoryCommit": "9" * 40,
            "previousProductionConfigurationSha256": "a" * 64,
            "releaseEvidenceFile": f"{'9' * 40}-{'a' * 64}-release.json",
            "releaseEvidenceSha256": "b" * 64,
            "currentReleaseSha256": "c" * 64,
            "activationPhase": "activation-deploy-failed-producer-unproved",
            "websiteProducerDisabledProved": False,
            "applicationStopped": True,
        },
    }
    for phase, record in records.items():
        pointer = {
            "repositoryCommit": commit,
            "productionConfigurationSha256": configuration,
            "authenticationEvidenceFile": f"{commit}-{configuration}-{AUTHENTICATION.PHASE_SUFFIXES[phase]}.json",
            "authenticationEvidenceSha256": "8" * 64,
            "activationPhase": phase,
        }
        if AUTHENTICATION.validate_documents(pointer, record) != phase:
            raise RuntimeError("Authentication state-machine fixture returned the wrong phase.")

        additive = dict(record)
        additive["unexpected"] = True
        expect_validation_failure(
            lambda pointer=pointer, additive=additive: AUTHENTICATION.validate_documents(pointer, additive),
            f"additive authentication record property in {phase}",
        )

    complete = dict(records["complete"])
    complete["callbackLogRedactionPassed"] = False
    complete_pointer = {
        "repositoryCommit": commit,
        "productionConfigurationSha256": configuration,
        "authenticationEvidenceFile": f"{commit}-{configuration}-authentication-complete.json",
        "authenticationEvidenceSha256": "8" * 64,
        "activationPhase": "complete",
    }
    expect_validation_failure(
        lambda: AUTHENTICATION.validate_documents(complete_pointer, complete),
        "unpassed callback-log gate",
    )
    unproved = dict(records["contained-producer-state-unproved"])
    unproved["websiteProducerDisabledProved"] = True
    unproved_pointer = {
        **complete_pointer,
        "authenticationEvidenceFile": f"{commit}-{configuration}-authentication-containment-unproved.json",
        "activationPhase": "contained-producer-state-unproved",
    }
    expect_validation_failure(
        lambda: AUTHENTICATION.validate_documents(unproved_pointer, unproved),
        "false producer-disabled proof in unproved containment",
    )
    failed_unproved = dict(records["activation-deploy-failed-producer-unproved"])
    failed_unproved["websiteProducerDisabledProved"] = True
    failed_unproved_pointer = {
        **complete_pointer,
        "authenticationEvidenceFile": f"{commit}-{configuration}-authentication-activation-failed-unproved.json",
        "activationPhase": "activation-deploy-failed-producer-unproved",
    }
    expect_validation_failure(
        lambda: AUTHENTICATION.validate_documents(failed_unproved_pointer, failed_unproved),
        "false producer-disabled proof in activation-deploy failure",
    )

    deploy = (ROOT / "scripts/host-deploy.sh").read_text(encoding="utf-8")
    if 'scripts/authentication-state.py"' not in deploy or "contained-producer-state-unproved" not in deploy:
        raise RuntimeError("Host deploy does not execute the exact authentication state evaluator.")
    contained_verification = deploy.index('bash "${release_dir}/scripts/verify-contained-activation.sh"')
    public_activation = deploy.index('activate_config "${config_dir}/app.yml"', contained_verification)
    disabled_probe = "/usr/local/libexec/mochirii-forums/probe-website-forums-producer.py disabled"
    disabled_probes = [match.start() for match in re.finditer(re.escape(disabled_probe), deploy)]
    staged_disabled_probes = [position for position in disabled_probes if position > contained_verification]
    if (
        len(staged_disabled_probes) != 2
        or not contained_verification < staged_disabled_probes[0] < public_activation < staged_disabled_probes[1]
        or deploy[staged_disabled_probes[0]:public_activation].count("activate_config") != 0
    ):
        raise RuntimeError("Public consumer activation can precede its immediate Website producer-disabled proof.")

    stop = (ROOT / "scripts/host-stop-pending-activation.sh").read_text(encoding="utf-8")
    unproved_validation = stop.index('unproved_document.get("activationPhase") != "contained-producer-state-unproved"')
    stopped_readback = stop.index('[[ ${stopped} == true ]]')
    retry_probe = stop.index("/usr/local/libexec/mochirii-forums/probe-website-forums-producer.py disabled", stopped_readback)
    pointer_advance = stop.index("os.replace(temporary, path)")
    if not unproved_validation < stopped_readback < retry_probe < pointer_advance:
        raise RuntimeError("Unproved producer-state containment cannot be reconciled while the app remains stopped.")
    for fragment in (
        '"consumer-public-producer-pending", "contained-producer-state-unproved"',
        'unproved_document.get("pendingAuthenticationEvidenceSha256") != pending_sha',
        'unproved_document.get("websiteProducerDisabledProved") is not False',
        'containment_phase=contained-producer-state-unproved',
        'containment_phase=contained-after-e2e-failure',
        'if path.exists() or path.is_symlink():',
    ):
        if fragment not in stop:
            raise RuntimeError("Pending activation reconciliation lost an exact fail-closed state transition.")
    for fragment in (
        "activation-deploy-failed-producer-unproved",
        "activation-deploy-failed",
        'failure.get("previousRepositoryCommit"',
        'failure.get("currentReleaseSha256") != hashlib.sha256(current_bytes).hexdigest()',
        'release.get("discourseConnectEnabled") is not False',
        'containment_phase=activation-deploy-failed',
        'containment_suffix=authentication-activation-failed',
    ):
        if fragment not in stop:
            raise RuntimeError("Operator reconciliation cannot advance an exact stopped activation-deploy failure.")

    transition_sequence = (
        "consumer-public-producer-pending",
        "contained-producer-state-unproved",
        "contained-after-e2e-failure",
        "consumer-public-producer-pending",
        "complete",
    )
    for phase in transition_sequence:
        pointer = {
            "repositoryCommit": commit,
            "productionConfigurationSha256": configuration,
            "authenticationEvidenceFile": f"{commit}-{configuration}-{AUTHENTICATION.PHASE_SUFFIXES[phase]}.json",
            "authenticationEvidenceSha256": "8" * 64,
            "activationPhase": phase,
        }
        if AUTHENTICATION.validate_documents(pointer, records[phase]) != phase:
            raise RuntimeError("Authentication retry lifecycle rejected a required exact transition state.")

    failed_transition_sequence = (
        "activation-deploy-failed-producer-unproved",
        "activation-deploy-failed",
        "consumer-public-producer-pending",
        "complete",
    )
    for phase in failed_transition_sequence:
        pointer = {
            "repositoryCommit": commit,
            "productionConfigurationSha256": configuration,
            "authenticationEvidenceFile": f"{commit}-{configuration}-{AUTHENTICATION.PHASE_SUFFIXES[phase]}.json",
            "authenticationEvidenceSha256": "8" * 64,
            "activationPhase": phase,
        }
        if AUTHENTICATION.validate_documents(pointer, records[phase]) != phase:
            raise RuntimeError("Activation-deploy recovery lifecycle rejected a required exact transition state.")

    protected_reader = AUTHENTICATION._read_protected
    # The repository fixture runs without host root on both Windows and the
    # Ubuntu CI runner. Static contracts cover root:0600 enforcement; this
    # isolated tree exercises the deep evidence graph without weakening the
    # production reader.
    AUTHENTICATION._read_protected = lambda path, _label: path.read_bytes()
    with tempfile.TemporaryDirectory(prefix="mochirii-activation-failure-state-") as directory:
        state_root = Path(directory)
        evidence_root = state_root / "evidence"
        evidence_root.mkdir()
        prior_commit = "9" * 40
        prior_configuration = "a" * 64
        marker_bytes = b'{"destructiveRestorePermanentlyDisabled":true}\n'
        marker_path = state_root / "member-rollout-enabled"
        marker_path.write_bytes(marker_bytes)
        marker_path.chmod(0o600)
        marker_sha = hashlib.sha256(marker_bytes).hexdigest()
        release_name = f"{prior_commit}-{prior_configuration}-release.json"
        release_path = evidence_root / release_name
        release = {key: None for key in AUTHENTICATION.RELEASE_RECORD_KEYS}
        release.update(
            {
                "schemaVersion": 2,
                "recordedAt": "2026-08-15T11:00:00Z",
                "repositoryCommit": prior_commit,
                "repositoryTree": "7" * 40,
                "releaseArchiveSha256": "1" * 64,
                "releaseArchiveBytes": 1024,
                "releaseArchiveContentManifestSha256": "8" * 64,
                "productionConfigurationSha256": prior_configuration,
                "discourseConnectEnabled": False,
                "activationPhase": "consumer-disabled",
                "containedActivationPassed": False,
                "containedActivationConfigurationSha256": None,
                "memberRolloutMarkerFile": "member-rollout-enabled",
                "memberRolloutMarkerSha256": marker_sha,
                "hostVerificationPassed": True,
                "hostedStoragePassed": True,
                "storageRestartPersistencePassed": True,
                "storageRebuildPersistencePassed": True,
                "storageCleanupPassed": True,
            }
        )
        release_path.write_bytes((json.dumps(release, sort_keys=True) + "\n").encode("utf-8"))
        release_path.chmod(0o600)
        release_sha = hashlib.sha256(release_path.read_bytes()).hexdigest()
        current_path = state_root / "current-release.json"
        current = {
            "repositoryCommit": prior_commit,
            "productionConfigurationSha256": prior_configuration,
            "releaseEvidenceFile": release_name,
            "releaseEvidenceSha256": release_sha,
            "discourseConnectEnabled": False,
            "memberRolloutMarkerFile": "member-rollout-enabled",
            "memberRolloutMarkerSha256": marker_sha,
        }
        current_path.write_bytes((json.dumps(current, sort_keys=True) + "\n").encode("utf-8"))
        current_path.chmod(0o600)
        failure_name = f"{commit}-{configuration}-authentication-activation-failed.json"
        failure_path = evidence_root / failure_name
        failure = dict(records["activation-deploy-failed"])
        failure.update(
            {
                "previousRepositoryCommit": prior_commit,
                "previousProductionConfigurationSha256": prior_configuration,
                "releaseEvidenceFile": release_name,
                "releaseEvidenceSha256": release_sha,
                "currentReleaseSha256": hashlib.sha256(current_path.read_bytes()).hexdigest(),
            }
        )
        failure_path.write_bytes((json.dumps(failure, sort_keys=True) + "\n").encode("utf-8"))
        failure_path.chmod(0o600)
        pointer_path = state_root / "current-authentication.json"
        failure_pointer = {
            "repositoryCommit": commit,
            "productionConfigurationSha256": configuration,
            "authenticationEvidenceFile": failure_name,
            "authenticationEvidenceSha256": hashlib.sha256(failure_path.read_bytes()).hexdigest(),
            "activationPhase": "activation-deploy-failed",
        }
        pointer_path.write_bytes((json.dumps(failure_pointer, sort_keys=True) + "\n").encode("utf-8"))
        pointer_path.chmod(0o600)
        if AUTHENTICATION.evaluate(pointer_path, commit, configuration) != "activation-deploy-failed":
            raise RuntimeError("Deep stopped activation-deploy evidence chain was rejected.")
        hostile_current = dict(current)
        hostile_current["discourseConnectEnabled"] = True
        current_path.write_bytes((json.dumps(hostile_current, sort_keys=True) + "\n").encode("utf-8"))
        expect_validation_failure(
            lambda: AUTHENTICATION.evaluate(pointer_path, commit, configuration),
            "consumer-enabled current pointer in stopped activation recovery",
        )
        current_path.write_bytes((json.dumps(current, sort_keys=True) + "\n").encode("utf-8"))
        marker_path.write_bytes(b"hostile\n")
        expect_validation_failure(
            lambda: AUTHENTICATION.evaluate(pointer_path, commit, configuration),
            "changed member-rollout marker in stopped activation recovery",
        )
        marker_path.write_bytes(marker_bytes)

        target_release_name = f"{commit}-{configuration}-release.json"
        target_release_path = evidence_root / target_release_name
        target_release = {
            "schemaVersion": 2,
            "recordedAt": "2026-08-15T12:30:00Z",
            "repositoryCommit": commit,
            "repositoryTree": "7" * 40,
            "releaseArchiveSha256": "1" * 64,
            "releaseArchiveBytes": 1024,
            "releaseArchiveContentManifestSha256": "8" * 64,
            "discourseDockerRevision": "ed9f680b0df1de28f062de1769d89d22b2644d1b",
            "discourseRevision": "cbf996f65aae3da1843224aa624bcd9a225931ac",
            "dockerManagerRevision": "c008c3ca7fcc44775215843992e88190adb7b3bf",
            "baseImageDigest": "sha256:3b1846055ca723d13ef7dc3466da61627f32e8b212283561a6c617d759fcec48",
            "productionConfigurationSha256": configuration,
            "restoreConfigurationSha256": "2" * 64,
            "containedActivationConfigurationSha256": "3" * 64,
            "containedActivationPassed": True,
            "activationPhase": "consumer-public-producer-pending",
            "themeArchiveSha256": "4" * 64,
            "mailMetadataPluginSha256": "5" * 64,
            "discourseConnectEnabled": True,
            "memberRolloutMarkerFile": "member-rollout-enabled",
            "memberRolloutMarkerSha256": marker_sha,
            "hostVerificationPassed": True,
            "storageEvidenceFile": f"{commit}-{configuration}-storage.json",
            "storageEvidenceSha256": "6" * 64,
            "hostedStoragePassed": True,
            "storageRestartPersistencePassed": True,
            "storageRebuildPersistencePassed": True,
            "storageCleanupPassed": True,
        }
        target_release_path.write_bytes((json.dumps(target_release, sort_keys=True) + "\n").encode("utf-8"))
        target_release_path.chmod(0o600)
        for field, hostile_value in (
            ("repositoryTree", "not-a-tree"),
            ("releaseArchiveBytes", True),
            ("releaseArchiveBytes", 67_108_865),
            ("releaseArchiveContentManifestSha256", "not-a-manifest"),
        ):
            hostile_release = dict(target_release)
            hostile_release[field] = hostile_value
            expect_validation_failure(
                lambda document=hostile_release: AUTHENTICATION._validate_release_record(
                    document,
                    commit,
                    configuration,
                    True,
                    "Hostile immutable release authority",
                ),
                f"malformed immutable release authority {field}",
            )
        target_release_sha = hashlib.sha256(target_release_path.read_bytes()).hexdigest()
        target_current = {
            "repositoryCommit": commit,
            "productionConfigurationSha256": configuration,
            "releaseEvidenceFile": target_release_name,
            "releaseEvidenceSha256": target_release_sha,
            "discourseConnectEnabled": True,
            "memberRolloutMarkerFile": "member-rollout-enabled",
            "memberRolloutMarkerSha256": marker_sha,
        }
        current_path.write_bytes((json.dumps(target_current, sort_keys=True) + "\n").encode("utf-8"))
        if AUTHENTICATION.evaluate(pointer_path, commit, configuration) != "activation-deploy-failed":
            raise RuntimeError("Stopped activation retry could not adopt the verified target publication.")
        hostile_target_current = dict(target_current)
        hostile_target_current["discourseConnectEnabled"] = False
        current_path.write_bytes((json.dumps(hostile_target_current, sort_keys=True) + "\n").encode("utf-8"))
        expect_validation_failure(
            lambda: AUTHENTICATION.evaluate(pointer_path, commit, configuration),
            "consumer-disabled target after activation retry",
        )

    with tempfile.TemporaryDirectory(prefix="mochirii-authentication-advance-state-") as directory:
        state_root = Path(directory)
        evidence_root = state_root / "evidence"
        operator_root = state_root / "operator-evidence"
        evidence_root.mkdir()
        operator_root.mkdir()
        previous_commit = "8" * 40
        previous_configuration = "c" * 64
        target_commit = "9" * 40
        target_configuration = "d" * 64
        marker_bytes = b'{"destructiveRestorePermanentlyDisabled":true}\n'
        marker_path = state_root / "member-rollout-enabled"
        marker_path.write_bytes(marker_bytes)
        marker_path.chmod(0o600)
        marker_sha = hashlib.sha256(marker_bytes).hexdigest()

        def release_document(release_commit: str, release_configuration: str, connect: bool) -> dict[str, object]:
            return {
                "schemaVersion": 2,
                "recordedAt": "2026-08-15T11:00:00Z",
                "repositoryCommit": release_commit,
                "repositoryTree": "7" * 40,
                "releaseArchiveSha256": "1" * 64,
                "releaseArchiveBytes": 1024,
                "releaseArchiveContentManifestSha256": "8" * 64,
                "discourseDockerRevision": "ed9f680b0df1de28f062de1769d89d22b2644d1b",
                "discourseRevision": "cbf996f65aae3da1843224aa624bcd9a225931ac",
                "dockerManagerRevision": "c008c3ca7fcc44775215843992e88190adb7b3bf",
                "baseImageDigest": "sha256:3b1846055ca723d13ef7dc3466da61627f32e8b212283561a6c617d759fcec48",
                "productionConfigurationSha256": release_configuration,
                "restoreConfigurationSha256": "2" * 64,
                "containedActivationConfigurationSha256": "3" * 64 if connect else None,
                "containedActivationPassed": connect,
                "activationPhase": "consumer-public-producer-pending" if connect else "consumer-disabled",
                "themeArchiveSha256": "4" * 64,
                "mailMetadataPluginSha256": "5" * 64,
                "discourseConnectEnabled": connect,
                "memberRolloutMarkerFile": "member-rollout-enabled",
                "memberRolloutMarkerSha256": marker_sha,
                "hostVerificationPassed": True,
                "storageEvidenceFile": f"{release_commit}-{release_configuration}-storage.json",
                "storageEvidenceSha256": "6" * 64,
                "hostedStoragePassed": True,
                "storageRestartPersistencePassed": True,
                "storageRebuildPersistencePassed": True,
                "storageCleanupPassed": True,
            }

        previous_release_name = f"{previous_commit}-{previous_configuration}-release.json"
        previous_release_path = evidence_root / previous_release_name
        previous_release = release_document(previous_commit, previous_configuration, True)
        previous_release_path.write_bytes((json.dumps(previous_release, sort_keys=True) + "\n").encode("utf-8"))
        previous_release_path.chmod(0o600)
        previous_release_sha = hashlib.sha256(previous_release_path.read_bytes()).hexdigest()
        previous_current = {
            "repositoryCommit": previous_commit,
            "productionConfigurationSha256": previous_configuration,
            "releaseEvidenceFile": previous_release_name,
            "releaseEvidenceSha256": previous_release_sha,
            "discourseConnectEnabled": True,
            "memberRolloutMarkerFile": "member-rollout-enabled",
            "memberRolloutMarkerSha256": marker_sha,
        }
        current_path = state_root / "current-release.json"
        current_path.write_bytes((json.dumps(previous_current, sort_keys=True) + "\n").encode("utf-8"))
        current_path.chmod(0o600)
        previous_current_sha = hashlib.sha256(current_path.read_bytes()).hexdigest()

        pending_name = f"{previous_commit}-{previous_configuration}-authentication-pending.json"
        pending_path = evidence_root / pending_name
        pending = {
            "schemaVersion": 1,
            "recordedAt": "2026-08-15T11:30:00Z",
            "repositoryCommit": previous_commit,
            "productionConfigurationSha256": previous_configuration,
            "releaseEvidenceFile": previous_release_name,
            "releaseEvidenceSha256": previous_release_sha,
            "currentReleaseSha256": previous_current_sha,
            "activationPhase": "consumer-public-producer-pending",
            **{key: True for key in AUTHENTICATION.PENDING_GATES},
        }
        pending_path.write_bytes((json.dumps(pending, sort_keys=True) + "\n").encode("utf-8"))
        pending_path.chmod(0o600)
        pending_sha = hashlib.sha256(pending_path.read_bytes()).hexdigest()

        website_name = f"{previous_commit}-{previous_configuration}-website-authentication.json"
        website_path = operator_root / website_name
        website = {
            "schemaVersion": 1,
            "recordedAt": "2026-08-15T11:45:00Z",
            "websiteRepositoryCommit": "7" * 40,
            "forumsRepositoryCommit": previous_commit,
            "forumsProductionConfigurationSha256": previous_configuration,
            **{key: True for key in AUTHENTICATION.WEBSITE_GATE_KEYS},
        }
        website_path.write_bytes((json.dumps(website, sort_keys=True) + "\n").encode("utf-8"))
        website_path.chmod(0o600)
        website_sha = hashlib.sha256(website_path.read_bytes()).hexdigest()

        complete_name = f"{previous_commit}-{previous_configuration}-authentication-complete.json"
        complete_path = evidence_root / complete_name
        complete = {
            "schemaVersion": 1,
            "recordedAt": "2026-08-15T12:00:00Z",
            "repositoryCommit": previous_commit,
            "productionConfigurationSha256": previous_configuration,
            "releaseEvidenceFile": previous_release_name,
            "releaseEvidenceSha256": previous_release_sha,
            "currentReleaseSha256": previous_current_sha,
            "activationPhase": "complete",
            "pendingAuthenticationEvidenceFile": pending_name,
            "pendingAuthenticationEvidenceSha256": pending_sha,
            "websiteEvidenceFile": website_name,
            "websiteEvidenceSha256": website_sha,
            "websiteRepositoryCommit": "7" * 40,
            **{key: True for key in AUTHENTICATION.COMPLETE_GATES},
        }
        complete_path.write_bytes((json.dumps(complete, sort_keys=True) + "\n").encode("utf-8"))
        complete_path.chmod(0o600)
        pointer_path = state_root / "current-authentication.json"
        complete_pointer = {
            "repositoryCommit": previous_commit,
            "productionConfigurationSha256": previous_configuration,
            "authenticationEvidenceFile": complete_name,
            "authenticationEvidenceSha256": hashlib.sha256(complete_path.read_bytes()).hexdigest(),
            "activationPhase": "complete",
        }
        pointer_path.write_bytes((json.dumps(complete_pointer, sort_keys=True) + "\n").encode("utf-8"))
        pointer_path.chmod(0o600)

        if AUTHENTICATION.evaluate(pointer_path, target_commit, target_configuration) != "stale-other-tuple":
            raise RuntimeError("A completed prior tuple was rejected before the consumer-disabled advance.")

        target_release_name = f"{target_commit}-{target_configuration}-release.json"
        target_release_path = evidence_root / target_release_name
        target_release = release_document(target_commit, target_configuration, False)
        target_release_path.write_bytes((json.dumps(target_release, sort_keys=True) + "\n").encode("utf-8"))
        target_release_path.chmod(0o600)
        target_release_sha = hashlib.sha256(target_release_path.read_bytes()).hexdigest()
        target_current = {
            "repositoryCommit": target_commit,
            "productionConfigurationSha256": target_configuration,
            "releaseEvidenceFile": target_release_name,
            "releaseEvidenceSha256": target_release_sha,
            "discourseConnectEnabled": False,
            "memberRolloutMarkerFile": "member-rollout-enabled",
            "memberRolloutMarkerSha256": marker_sha,
        }
        current_path.write_bytes((json.dumps(target_current, sort_keys=True) + "\n").encode("utf-8"))
        if AUTHENTICATION.evaluate(pointer_path, target_commit, target_configuration) != "stale-other-tuple":
            raise RuntimeError("A completed prior tuple was rejected after consumer-disabled current-release publication.")

        hostile_current = dict(target_current)
        hostile_current["discourseConnectEnabled"] = True
        current_path.write_bytes((json.dumps(hostile_current, sort_keys=True) + "\n").encode("utf-8"))
        expect_validation_failure(
            lambda: AUTHENTICATION.evaluate(pointer_path, target_commit, target_configuration),
            "consumer-enabled authentication advance target",
        )
        current_path.write_bytes((json.dumps(target_current, sort_keys=True) + "\n").encode("utf-8"))

        hostile_complete = dict(complete)
        hostile_complete["currentReleaseSha256"] = "0" * 64
        complete_path.write_bytes((json.dumps(hostile_complete, sort_keys=True) + "\n").encode("utf-8"))
        complete_pointer["authenticationEvidenceSha256"] = hashlib.sha256(complete_path.read_bytes()).hexdigest()
        pointer_path.write_bytes((json.dumps(complete_pointer, sort_keys=True) + "\n").encode("utf-8"))
        expect_validation_failure(
            lambda: AUTHENTICATION.evaluate(pointer_path, target_commit, target_configuration),
            "historical completed current-release digest mismatch",
        )
        complete_path.write_bytes((json.dumps(complete, sort_keys=True) + "\n").encode("utf-8"))
        complete_pointer["authenticationEvidenceSha256"] = hashlib.sha256(complete_path.read_bytes()).hexdigest()
        pointer_path.write_bytes((json.dumps(complete_pointer, sort_keys=True) + "\n").encode("utf-8"))

        marker_path.write_bytes(b"hostile\n")
        expect_validation_failure(
            lambda: AUTHENTICATION.evaluate(pointer_path, target_commit, target_configuration),
            "changed member marker during completed authentication advance",
        )
        marker_path.write_bytes(marker_bytes)

        unrelated_current = dict(target_current)
        unrelated_current["repositoryCommit"] = "a" * 40
        current_path.write_bytes((json.dumps(unrelated_current, sort_keys=True) + "\n").encode("utf-8"))
        expect_validation_failure(
            lambda: AUTHENTICATION.evaluate(pointer_path, target_commit, target_configuration),
            "unrelated current release during completed authentication advance",
        )
    AUTHENTICATION._read_protected = protected_reader

    activation_exit = deploy[deploy.index("on_exit() {") : deploy.index("trap on_exit EXIT")]
    if "recover_failed_activation" not in activation_exit or activation_exit.index("storage_cleanup_blocked") > activation_exit.index("recover_failed_activation"):
        raise RuntimeError("Activation failure recovery can bypass storage cleanup containment or the stopped retry transition.")
    recovery = deploy[deploy.index("seal_activation_deploy_failure() {") : deploy.index("recover_failed_activation() {")]
    recovery_required = (
        "emergency_stop",
        'activate_config "${previous_config}"',
        'write_current_evidence "${previous_release}"',
        "activation-deploy-failed-producer-unproved",
        "activation-deploy-failed",
        "websiteProducerDisabledProved",
        "applicationStopped",
        "os.link(candidate, path, follow_symlinks=False)",
        "os.replace(candidate, path)",
    )
    if any(value not in recovery for value in recovery_required):
        raise RuntimeError("Activation failure cannot atomically seal an exact stopped prior-release retry state.")
    retry_start = deploy.index("elif [[ ${authentication_retry_state} == activation-deploy-failed ]]")
    retry_branch = deploy[retry_start : deploy.index("elif [[ ${complete_authentication_rebuild}", retry_start)]
    if retry_branch.index("docker inspect --type container") > retry_branch.index('current_discourse_connect="${previous_discourse_connect}"') or "docker exec app" in retry_branch:
        raise RuntimeError("Stopped activation-deploy retry reads target consumer state from an unavailable container.")
    failure_canaries = (
        "Contained DiscourseConnect activation verification failed.",
        "Public consumer activation requires the exact Website producer-disabled state.",
        "Mochirii Forums launcher operation failed",
        "Hosted storage fixture creation failed",
        "Hosted storage fixture did not survive restart",
        "Hosted storage fixture did not survive rebuild",
        "Hosted storage fixture cleanup failed",
        "Deployment terminal transaction could not be reconciled safely.",
        "Deployment terminal state could not be committed or verified.",
    )
    if any(value not in deploy for value in failure_canaries):
        raise RuntimeError("Activation failure hostile boundary inventory changed.")

    installer = (ROOT / "scripts/install-host-control.sh").read_text(encoding="utf-8")
    dispatcher = (ROOT / "scripts/ssh-deploy-dispatch.py").read_text(encoding="utf-8")
    if (
        "stop-pending-activation" in dispatcher
        or "finalize-authentication" in dispatcher
        or '/usr/local/sbin/mochirii-forums-stop-pending-activation' not in installer
        or '/usr/local/sbin/mochirii-forums-finalize-authentication' not in installer
        or 'sudo -l -U "${deploy_user}" "${forbidden}"' not in installer
        or "${SUDO_USER} != mochirii-forums-operator" not in stop
        or "${SUDO_USER} != mochirii-forums-operator" not in (ROOT / "scripts/host-finalize-authentication.sh").read_text(encoding="utf-8")
    ):
        raise RuntimeError("The deploy credential gained authentication stop or finalization authority.")


def test_deployment_checkout_configuration_boundary() -> None:
    checkout = (ROOT / "scripts/verify-discourse-docker-checkout.sh").read_text(encoding="utf-8")
    exact_pattern = (
        r"^/var/discourse/containers/releases/[0-9a-f]{40}/[0-9a-f]{64}/"
        r"(app|restore|activation)[.]yml$"
    )
    if exact_pattern not in checkout:
        raise RuntimeError("Versioned activation configuration is absent from the sealed checkout boundary.")
    boundary = re.compile(exact_pattern)
    commit = "a" * 40
    configuration = "2" * 64
    if not boundary.fullmatch(f"/var/discourse/containers/releases/{commit}/{configuration}/activation.yml"):
        raise RuntimeError("Exact versioned activation configuration was rejected.")
    for hostile in (
        f"/var/discourse/containers/releases/{commit}/{configuration}/activation-copy.yml",
        f"/var/discourse/containers/releases/{commit}/{configuration}/activation.yml/child",
        f"/var/discourse/containers/releases/{commit}/../{configuration}/activation.yml",
        f"/var/discourse/containers/releases/{commit.upper()}/{configuration}/activation.yml",
    ):
        if boundary.fullmatch(hostile):
            raise RuntimeError("A hostile versioned activation configuration name was accepted.")
    required_parser_bounds = (
        'docker image inspect "${base_image}"',
        "--pull=never",
        "--network none",
        "--read-only",
        "--cap-drop ALL",
        "--security-opt no-new-privileges",
        '"${base_image}" ruby -ryaml',
        '<"${resolved_app_config}"',
    )
    if any(value not in checkout for value in required_parser_bounds) or re.search(r"(?m)^ruby\s+-ryaml", checkout):
        raise RuntimeError("Fresh-host source validation regained an unbounded host Ruby dependency.")
    cleanup_match = re.search(r"(?ms)^cleanup_parser\(\) \{.*?^\}", checkout)
    if cleanup_match is None:
        raise RuntimeError("Pinned parser cleanup function is absent.")
    cleanup = cleanup_match.group(0)
    if (
        'docker rm --force "${parser_container}"' not in cleanup
        or 'docker container ls --all --filter "name=^/${parser_container}$"' not in cleanup
        or cleanup.index("docker rm --force") > cleanup.index("docker container ls")
        or "|| return 1" not in cleanup
    ):
        raise RuntimeError("Pinned parser cleanup does not prove the exact named container absent.")
    host_deploy = (ROOT / "scripts/host-deploy.sh").read_text(encoding="utf-8")
    host_cleanup = re.search(r"(?ms)^cleanup_parser_container\(\) \{.*?^\}", host_deploy)
    if host_cleanup is None or 'docker container ls --all --filter "name=^/${name}$"' not in host_cleanup.group(0):
        raise RuntimeError("Secret-bearing rendered-config parser lacks an exact post-run absence readback.")
    if os.name == "posix":
        bash = shutil.which("bash")
        if bash is None:
            raise RuntimeError("Bash is required for the parser cleanup hostile fixture.")
        harness = cleanup + r'''
parser_container=mochirii-forums-source-verify-123
timeout() {
  while [[ ${1-} == -* ]]; do shift; done
  [[ $# -gt 0 ]] || return 1
  shift
  [[ $# -gt 0 ]] || return 1
  "$@"
}
docker() {
  if [[ $1 == rm ]]; then
    [[ ${MOCK_RM} == success ]]
    return
  fi
  if [[ $1 == container && $2 == ls ]]; then
    case ${MOCK_INVENTORY} in
      empty) return 0 ;;
      remains) printf '%s\n' "$parser_container"; return 0 ;;
      *) return 1 ;;
    esac
  fi
  return 1
}
cleanup_parser
'''
        cases = (
            ({"MOCK_RM": "success", "MOCK_INVENTORY": "empty"}, True),
            ({"MOCK_RM": "failed", "MOCK_INVENTORY": "empty"}, True),
            ({"MOCK_RM": "success", "MOCK_INVENTORY": "remains"}, False),
            ({"MOCK_RM": "failed", "MOCK_INVENTORY": "remains"}, False),
            ({"MOCK_RM": "failed", "MOCK_INVENTORY": "error"}, False),
        )
        for values, expected in cases:
            completed = subprocess.run(
                [bash, "-c", harness],
                env={**os.environ, **values},
                stdin=subprocess.DEVNULL,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                timeout=10,
                check=False,
            )
            if (completed.returncode == 0) is not expected:
                raise RuntimeError("Pinned parser cleanup survivor hostile fixture changed.")


def test_sensitive_callback_markers() -> None:
    original = set(CONNECT_FIXTURE.CALLBACK_LOG_MARKERS)
    original_categories = dict(CONNECT_FIXTURE.CALLBACK_LOG_MARKER_CATEGORIES)
    try:
        nonce = "nonce-stage4-fixture-0123456789abcdef"
        encoded, signature = CONNECT_FIXTURE.callback(nonce, b"a" * 64)
        path = CONNECT_FIXTURE.callback_path(encoded, signature)
        first_token = b"admin-token-stage4-fixture-111111111111"
        second_token = b"admin-token-stage4-fixture-222222222222"
        CONNECT_FIXTURE.register_admin_recovery_markers((first_token, second_token))
        malformed_value = "<" * 16
        try:
            CONNECT_FIXTURE.base64.b64decode(malformed_value, validate=True)
        except ValueError:
            pass
        else:
            raise RuntimeError("Malformed callback fixture unexpectedly became valid base64.")
        malformed_path = CONNECT_FIXTURE.callback_path(malformed_value, "0" * 64)
        markers = sorted(CONNECT_FIXTURE.CALLBACK_LOG_MARKERS)
        categories = dict(CONNECT_FIXTURE.CALLBACK_LOG_MARKER_CATEGORIES)
        required = {
            b"mochirii-stage4-consumer-fixture",
            b"stage4-fixture@forums.mochirii.com",
            b"mochirii-s4-test",
            b"Mochirii Stage 4 Fixture",
            b"stage4-fixture%40forums.mochirii.com",
            b"Mochirii%20Stage%204%20Fixture",
            b"Mochirii+Stage+4+Fixture",
            malformed_value.encode("ascii"),
            first_token,
            second_token,
            b"/session/email-login/" + first_token,
            b"/session/email-login/" + second_token,
        }
        if (
            not required.issubset(markers)
            or not encoded
            or not signature
            or not path.startswith("/session/sso_login?")
            or not malformed_path.startswith("/session/sso_login?")
            or categories.get(malformed_value.encode("ascii")) != "callback"
        ):
            raise RuntimeError("Sensitive callback marker fixture omitted an exact identity or recovery credential.")
        if len(markers) > 64 or any(not 16 <= len(marker) <= 16_384 for marker in markers):
            raise RuntimeError("Sensitive callback marker inventory exceeded its exact bound.")
        if (
            set(categories) != set(markers)
            or categories[b"mochirii-stage4-consumer-fixture"] != "identity"
            or categories[encoded.encode("ascii")] != "callback"
            or categories[first_token] != "recovery"
            or set(categories.values()) != {"identity", "callback", "recovery"}
        ):
            raise RuntimeError("Sensitive callback marker categories differ from their fixed boundary.")
        encoded_marker = next(marker for marker in markers if marker.startswith(b"sso=") and b"%" in marker)
        hostile_request_line = b"GET /session/sso_login?" + encoded_marker + b" HTTP/1.1\n"
        if not CONNECT_FIXTURE.sensitive_marker_reached(hostile_request_line, markers):
            raise RuntimeError("Percent-encoded callback request-line leakage was not detected.")
        try:
            CONNECT_FIXTURE.register_sensitive_marker(first_token, "callback")
        except RuntimeError:
            pass
        else:
            raise RuntimeError("A sensitive marker was accepted under conflicting categories.")
        try:
            CONNECT_FIXTURE.register_sensitive_marker(b"too-short", "callback")
        except RuntimeError:
            pass
        else:
            raise RuntimeError("An out-of-bound sensitive marker was silently omitted.")
        captured_audit_inputs: list[bytes] = []
        original_runner = CONNECT_FIXTURE.run_container_runner
        original_subprocess_run = CONNECT_FIXTURE.subprocess.run
        try:
            def capture_audit_runner(
                _script: str,
                *,
                input_bytes: bytes | None = None,
                classify_sensitive_log_failure: bool = False,
                **_kwargs: object,
            ) -> bytes:
                if input_bytes is None or not classify_sensitive_log_failure:
                    raise RuntimeError("Sensitive-log audit invocation lost its exact classified input boundary.")
                captured_audit_inputs.append(input_bytes)
                return b""

            CONNECT_FIXTURE.run_container_runner = capture_audit_runner
            CONNECT_FIXTURE.subprocess.run = lambda *args, **_kwargs: subprocess.CompletedProcess(
                args=args,
                returncode=0,
                stdout=b"",
                stderr=b"",
            )
            CONNECT_FIXTURE.assert_callback_logs_redacted()
        finally:
            CONNECT_FIXTURE.run_container_runner = original_runner
            CONNECT_FIXTURE.subprocess.run = original_subprocess_run
        expected_audit_input = b"".join(
            category.encode("ascii") + b"\t" + marker + b"\n"
            for marker, category in sorted(categories.items())
        )
        if captured_audit_inputs != [expected_audit_input]:
            raise RuntimeError("Sensitive-log audit input lost its exact marker-category protocol.")
        scanner = (ROOT / "scripts/verify-sensitive-log-redaction.rb").read_text(encoding="utf-8")
        if (
            r"[\x00-\x1f\x7f]" not in scanner
            or r"[\x00-\x20]" in scanner
            or '!raw.end_with?("\\n")' not in scanner
            or 'raw.include?("\\r")' not in scanner
        ):
            raise RuntimeError("Sensitive-log marker validation rejects ordinary display-name spaces.")
        app = (ROOT / "config/app.yml.example").read_text(encoding="utf-8")
        exact_route = 'location ~ "^/session/email-login/[A-Za-z0-9_-]{20,256}$" {'
        denial_route = "location ~* ^/session/email-login/ {"
        recovery_required = (
            "EMAIL_LOGIN_PATH = %r{\\A/session/email-login/[A-Za-z0-9_-]{20,256}\\z}.freeze",
            'FILTERED_EMAIL_LOGIN_PATH = "/session/email-login/[FILTERED]".freeze',
            "module MochiriiSensitiveUserAuthTokenAuditFilter",
            "super(info.merge(path: MochiriiSensitiveRequestPathFilter::FILTERED_EMAIL_LOGIN_PATH))",
            "UserAuthToken.singleton_class.prepend(MochiriiSensitiveUserAuthTokenAuditFilter)",
            "module MochiriiSensitiveDiscourseLogragePayloadFilter",
            "super(ip: ip, username: nil, **extras)",
            "DiscourseLograge.singleton_class.prepend(MochiriiSensitiveDiscourseLogragePayloadFilter)",
            "module MochiriiSensitiveLogsterEnvironmentFilter",
            'return if key == "username" || key == :username',
            "Logster.singleton_class.prepend(MochiriiSensitiveLogsterEnvironmentFilter)",
            "module MochiriiSensitiveLogsterMessageFilter",
            'scrubbed["params"] = filtered_parameters if scrubbed.key?("params")',
            'scrubbed["REQUEST_URI"] = filtered_path if scrubbed.key?("REQUEST_URI")',
            "Logster::Message.singleton_class.prepend(MochiriiSensitiveLogsterMessageFilter)",
            "Rails.application.config.filter_parameters |= %i[email sso sig token]",
            exact_route,
            denial_route,
            "error_page 420 = @mochirii_email_login_denied;",
        )
        if any(value not in app for value in recovery_required) or app.index(exact_route) > app.index(denial_route):
            raise RuntimeError("Administrator email-login token lacks its exact application/Nginx privacy boundary.")
        initializer = app[app.index("module MochiriiSensitiveRequestPathFilter"):app.index("  - file:", app.index("module MochiriiSensitiveRequestPathFilter"))]
        if "PATH_INFO" in initializer or "def path" in initializer or ".*" in initializer:
            raise RuntimeError("Administrator email-login log filter changes routing or became overbroad.")

        fixture_sources = {
            "scripts/verify-discourse-connect.py": (
                ROOT / "scripts/verify-discourse-connect.py"
            ).read_text(encoding="utf-8"),
            "scripts/prepare-admin-recovery-fixture.rb": (
                ROOT / "scripts/prepare-admin-recovery-fixture.rb"
            ).read_text(encoding="utf-8"),
            "scripts/verify-sensitive-log-redaction.rb": scanner,
        }
        fixture_mutations = (
            (
                "scripts/prepare-admin-recovery-fixture.rb",
                "  user.grant_admin!\n",
                "  user.update!(admin: true)\n",
            ),
            (
                "scripts/prepare-admin-recovery-fixture.rb",
                "  UserAuthToken.where(user_id: user.id).destroy_all\n",
                "  UserAuthToken.where(user_id: user.id).none?\n",
            ),
            (
                "scripts/prepare-admin-recovery-fixture.rb",
                "  user.revoke_admin! if user.admin?\n",
                "  user.update!(admin: false) if user.admin?\n",
            ),
            (
                "scripts/verify-sensitive-log-redaction.rb",
                "auth_logs = UserAuthTokenLog.where(user_id: user.id).order(:id).limit(129).to_a\n",
                "auth_logs = []\n",
            ),
            (
                "scripts/verify-sensitive-log-redaction.rb",
                "reject_sensitive_log!(:authenticated_session) if UserAuthToken.where(user_id: user.id).exists?\n",
                "reject_sensitive_log!(:authenticated_session) if false\n",
            ),
            (
                "scripts/verify-sensitive-log-redaction.rb",
                "  application_log_marker: 46,\n",
                "  application_log_marker: 45,\n",
            ),
            (
                "scripts/verify-discourse-connect.py",
                "        classify_sensitive_log_failure=True,\n",
                "        classify_sensitive_log_failure=False,\n",
            ),
        )
        original_read = VALIDATOR.read
        try:
            for relative, current, hostile in fixture_mutations:
                candidate = fixture_sources[relative].replace(current, hostile, 1)
                if candidate == fixture_sources[relative]:
                    raise RuntimeError("Sensitive recovery hostile mutation anchor is absent.")
                VALIDATOR.read = (
                    lambda path, relative=relative, candidate=candidate: candidate
                    if path == relative
                    else original_read(path)
                )
                try:
                    VALIDATOR.validate_secrets_and_workflows()
                except RuntimeError:
                    continue
                raise RuntimeError("Repository validator accepted a hostile recovery or durable-log mutation.")
        finally:
            VALIDATOR.read = original_read

        python_decoy = fixture_sources["scripts/verify-discourse-connect.py"].replace(
            "        classify_sensitive_log_failure=True,\n",
            "        classify_sensitive_log_failure=False,\n",
            1,
        ).replace(
            '"""Exercise the pinned built-in consumer over the loopback HTTP boundary."""',
            '"""Exercise the pinned built-in consumer over the loopback HTTP boundary.\n'
            "        classify_sensitive_log_failure=True,\n"
            '"""',
            1,
        )
        python_early_audit_return = fixture_sources["scripts/verify-discourse-connect.py"].replace(
            "def assert_callback_logs_redacted() -> None:\n    marker_records =",
            "def assert_callback_logs_redacted() -> None:\n    return\n    marker_records =",
            1,
        )
        python_local_runner_shadow = fixture_sources["scripts/verify-discourse-connect.py"].replace(
            "def assert_callback_logs_redacted() -> None:\n    marker_records =",
            "def assert_callback_logs_redacted() -> None:\n"
            '    run_container_runner = lambda *_args, **_kwargs: b""\n'
            "    marker_records =",
            1,
        )
        python_runner_preemption = fixture_sources["scripts/verify-discourse-connect.py"].replace(
            "    if completed.returncode != 0:\n        if classify_sensitive_log_failure:\n",
            "    return b\"\"\n"
            "    if completed.returncode != 0:\n        if classify_sensitive_log_failure:\n",
            1,
        )
        python_main_global_rebind = fixture_sources["scripts/verify-discourse-connect.py"].replace(
            "    run_with_fixture_force_https(lambda: verify_fixture(args, secret))\n",
            '    globals()["assert_callback_logs_redacted"] = lambda: None\n'
            "    run_with_fixture_force_https(lambda: verify_fixture(args, secret))\n",
            1,
        )
        python_helper_global_rebind = fixture_sources["scripts/verify-discourse-connect.py"].replace(
            "def verify_fixture_user() -> None:\n    run_container_runner(\n",
            "def verify_fixture_user() -> None:\n"
            "    global run_container_runner\n"
            '    run_container_runner = lambda *_args, **_kwargs: b""\n'
            "    run_container_runner(\n",
            1,
        )
        python_dependency_rebind = fixture_sources["scripts/verify-discourse-connect.py"].replace(
            "def verify_fixture_user() -> None:\n    run_container_runner(\n",
            "def verify_fixture_user() -> None:\n"
            "    subprocess.run = lambda *_args, **_kwargs: None\n"
            "    run_container_runner(\n",
            1,
        )
        python_recovery_category_drift = fixture_sources["scripts/verify-discourse-connect.py"].replace(
            '        register_sensitive_marker(token, "recovery")\n',
            '        register_sensitive_marker(token, "callback")\n',
            1,
        )
        python_identity_category_drift = fixture_sources["scripts/verify-discourse-connect.py"].replace(
            '    b"mochirii-stage4-consumer-fixture": "identity",\n',
            '    b"mochirii-stage4-consumer-fixture": "callback",\n',
            1,
        )
        python_marker_protocol_drift = fixture_sources["scripts/verify-discourse-connect.py"].replace(
            '            category.encode("ascii") + b"\\t" + marker + b"\\n"\n',
            '            marker + b"\\n"\n',
            1,
        )
        python_malformed_callback_short = fixture_sources["scripts/verify-discourse-connect.py"].replace(
            '    malformed_value = "<" * 16\n',
            '    malformed_value = "<"\n',
            1,
        )
        ruby_exit_map = '''SENSITIVE_LOG_AUDIT_EXIT_CODES = {
  input: 40,
  identity: 41,
  authenticated_session: 42,
  authentication_audit_shape: 43,
  authentication_audit_marker: 44,
  log_inventory: 45,
  application_log_marker: 46,
  logster_shape: 47,
  logster_marker: 48,
  application_log_identity_marker: 49,
  application_log_callback_marker: 50,
  application_log_recovery_marker: 51,
  application_log_identity_marker_1: 52,
  application_log_identity_marker_2: 53,
  application_log_identity_marker_3: 54,
  application_log_identity_marker_4: 55,
  application_log_identity_marker_5: 56,
  application_log_identity_marker_6: 57,
  application_log_identity_marker_7: 58,
}.freeze
'''
        ruby_decoy = fixture_sources["scripts/verify-sensitive-log-redaction.rb"].replace(
            "  application_log_marker: 46,\n",
            "  application_log_marker: 45,\n",
            1,
        ) + f"\n=begin\n{ruby_exit_map}=end\n"
        ruby_helper_anchor = '''def reject_sensitive_log!(category)
  exit SENSITIVE_LOG_AUDIT_EXIT_CODES.fetch(category)
end

reject_sensitive_log!(:input) unless ENV["MOCHIRII_STAGE4_CONNECT_FIXTURE"] == "true"
'''
        ruby_helper_override = fixture_sources["scripts/verify-sensitive-log-redaction.rb"].replace(
            ruby_helper_anchor,
            '''def reject_sensitive_log!(category)
  exit SENSITIVE_LOG_AUDIT_EXIT_CODES.fetch(category)
end

def reject_sensitive_log!(_category)
end

reject_sensitive_log!(:input) unless ENV["MOCHIRII_STAGE4_CONNECT_FIXTURE"] == "true"
''',
            1,
        )
        ruby_helper_alias = fixture_sources["scripts/verify-sensitive-log-redaction.rb"].replace(
            ruby_helper_anchor,
            '''def reject_sensitive_log!(category)
  exit SENSITIVE_LOG_AUDIT_EXIT_CODES.fetch(category)
end

alias reject_sensitive_log! puts

reject_sensitive_log!(:input) unless ENV["MOCHIRII_STAGE4_CONNECT_FIXTURE"] == "true"
''',
            1,
        )
        ruby_application_category_drift = fixture_sources[
            "scripts/verify-sensitive-log-redaction.rb"
        ].replace(
            '  "identity" => :application_log_identity_marker,\n',
            '  "identity" => :application_log_callback_marker,\n',
            1,
        )
        ruby_identity_ordinal_bypass = fixture_sources[
            "scripts/verify-sensitive-log-redaction.rb"
        ].replace(
            "      reject_sensitive_log!(APPLICATION_LOG_IDENTITY_MARKER_CATEGORIES.fetch(marker_record[1], :input))\n",
            "      reject_sensitive_log!(:application_log_identity_marker)\n",
            1,
        )
        semantic_decoys = (
            (
                "scripts/verify-discourse-connect.py",
                python_decoy,
                "DISCOURSE_CONNECT_VERIFIER_SHA256",
            ),
            (
                "scripts/verify-discourse-connect.py",
                python_early_audit_return,
                "DISCOURSE_CONNECT_VERIFIER_SHA256",
            ),
            (
                "scripts/verify-discourse-connect.py",
                python_local_runner_shadow,
                "DISCOURSE_CONNECT_VERIFIER_SHA256",
            ),
            (
                "scripts/verify-discourse-connect.py",
                python_runner_preemption,
                "DISCOURSE_CONNECT_VERIFIER_SHA256",
            ),
            (
                "scripts/verify-discourse-connect.py",
                python_main_global_rebind,
                "DISCOURSE_CONNECT_VERIFIER_SHA256",
            ),
            (
                "scripts/verify-discourse-connect.py",
                python_helper_global_rebind,
                "DISCOURSE_CONNECT_VERIFIER_SHA256",
            ),
            (
                "scripts/verify-discourse-connect.py",
                python_dependency_rebind,
                "DISCOURSE_CONNECT_VERIFIER_SHA256",
            ),
            (
                "scripts/verify-discourse-connect.py",
                python_recovery_category_drift,
                "DISCOURSE_CONNECT_VERIFIER_SHA256",
            ),
            (
                "scripts/verify-discourse-connect.py",
                python_identity_category_drift,
                "DISCOURSE_CONNECT_VERIFIER_SHA256",
            ),
            (
                "scripts/verify-discourse-connect.py",
                python_marker_protocol_drift,
                "DISCOURSE_CONNECT_VERIFIER_SHA256",
            ),
            (
                "scripts/verify-discourse-connect.py",
                python_malformed_callback_short,
                "DISCOURSE_CONNECT_VERIFIER_SHA256",
            ),
            (
                "scripts/verify-sensitive-log-redaction.rb",
                ruby_decoy,
                "SENSITIVE_LOG_VERIFIER_SHA256",
            ),
            (
                "scripts/verify-sensitive-log-redaction.rb",
                ruby_helper_override,
                "SENSITIVE_LOG_VERIFIER_SHA256",
            ),
            (
                "scripts/verify-sensitive-log-redaction.rb",
                ruby_helper_alias,
                "SENSITIVE_LOG_VERIFIER_SHA256",
            ),
            (
                "scripts/verify-sensitive-log-redaction.rb",
                ruby_application_category_drift,
                "SENSITIVE_LOG_VERIFIER_SHA256",
            ),
            (
                "scripts/verify-sensitive-log-redaction.rb",
                ruby_identity_ordinal_bypass,
                "SENSITIVE_LOG_VERIFIER_SHA256",
            ),
        )
        original_hashes = {
            name: getattr(VALIDATOR, name)
            for _relative, _candidate, name in semantic_decoys
        }
        original_sensitive_log_executable_hash = VALIDATOR.SENSITIVE_LOG_EXECUTABLE_SHA256
        original_read = VALIDATOR.read
        try:
            for relative, candidate, hash_name in semantic_decoys:
                if candidate == fixture_sources[relative]:
                    raise RuntimeError("Sensitive-log semantic-decoy mutation anchor is absent.")
                setattr(
                    VALIDATOR,
                    hash_name,
                    hashlib.sha256(candidate.encode("utf-8")).hexdigest(),
                )
                if relative == "scripts/verify-sensitive-log-redaction.rb":
                    candidate_executable = VALIDATOR.ruby_executable_contract_source(candidate)
                    VALIDATOR.SENSITIVE_LOG_EXECUTABLE_SHA256 = hashlib.sha256(
                        candidate_executable.encode("utf-8")
                    ).hexdigest()
                VALIDATOR.read = (
                    lambda path, relative=relative, candidate=candidate: candidate
                    if path == relative
                    else original_read(path)
                )
                try:
                    VALIDATOR.validate_secrets_and_workflows()
                except RuntimeError:
                    pass
                else:
                    raise RuntimeError("Repository validator accepted a sensitive-log semantic bypass.")
                finally:
                    setattr(VALIDATOR, hash_name, original_hashes[hash_name])
                    VALIDATOR.SENSITIVE_LOG_EXECUTABLE_SHA256 = (
                        original_sensitive_log_executable_hash
                    )
        finally:
            VALIDATOR.read = original_read
            for hash_name, value in original_hashes.items():
                setattr(VALIDATOR, hash_name, value)
            VALIDATOR.SENSITIVE_LOG_EXECUTABLE_SHA256 = original_sensitive_log_executable_hash

        app_candidate = app.replace(
            "super(info.merge(path: MochiriiSensitiveRequestPathFilter::FILTERED_EMAIL_LOGIN_PATH))",
            "super(info)",
            1,
        )
        original_read = VALIDATOR.read
        try:
            VALIDATOR.read = lambda path: app_candidate if path == "config/app.yml.example" else original_read(path)
            try:
                VALIDATOR.validate_template()
            except RuntimeError:
                pass
            else:
                raise RuntimeError("Repository validator accepted a non-redacting authentication audit wrapper.")
        finally:
            VALIDATOR.read = original_read

        app_candidate = app.replace(
            "Rails.application.config.filter_parameters |= %i[email sso sig token]",
            "Rails.application.config.filter_parameters |= %i[sso sig token]",
            1,
        )
        original_read = VALIDATOR.read
        try:
            VALIDATOR.read = lambda path: app_candidate if path == "config/app.yml.example" else original_read(path)
            try:
                VALIDATOR.validate_template()
            except RuntimeError:
                pass
            else:
                raise RuntimeError("Repository validator accepted an unfiltered member-email parameter.")
        finally:
            VALIDATOR.read = original_read

        app_candidate = app.replace(
            'return if key == "username" || key == :username',
            'return if key == "email"',
            1,
        )
        if app_candidate == app:
            raise RuntimeError("Logster member-identity hostile mutation anchor is absent.")
        original_app_digest = VALIDATOR.APP_TEMPLATE_SHA256
        original_read = VALIDATOR.read
        try:
            VALIDATOR.APP_TEMPLATE_SHA256 = hashlib.sha256(app_candidate.encode("utf-8")).hexdigest()
            VALIDATOR.read = lambda path: app_candidate if path == "config/app.yml.example" else original_read(path)
            try:
                VALIDATOR.validate_template()
            except RuntimeError:
                pass
            else:
                raise RuntimeError("Repository validator accepted member identity in Logster context.")
        finally:
            VALIDATOR.APP_TEMPLATE_SHA256 = original_app_digest
            VALIDATOR.read = original_read

        app_candidate = app.replace(
            'scrubbed["params"] = filtered_parameters if scrubbed.key?("params")',
            'scrubbed["params"] = scrubbed["params"] if scrubbed.key?("params")',
            1,
        )
        if app_candidate == app:
            raise RuntimeError("Logster request-field hostile mutation anchor is absent.")
        original_app_digest = VALIDATOR.APP_TEMPLATE_SHA256
        original_read = VALIDATOR.read
        try:
            VALIDATOR.APP_TEMPLATE_SHA256 = hashlib.sha256(app_candidate.encode("utf-8")).hexdigest()
            VALIDATOR.read = lambda path: app_candidate if path == "config/app.yml.example" else original_read(path)
            try:
                VALIDATOR.validate_template()
            except RuntimeError:
                pass
            else:
                raise RuntimeError("Repository validator accepted raw Logster request parameters.")
        finally:
            VALIDATOR.APP_TEMPLATE_SHA256 = original_app_digest
            VALIDATOR.read = original_read

        app_candidate = app.replace(
            "super(ip: ip, username: nil, **extras)",
            "super(ip: ip, username: username, **extras)",
            1,
        )
        if app_candidate == app:
            raise RuntimeError("Member-identity log hostile mutation anchor is absent.")
        original_app_digest = VALIDATOR.APP_TEMPLATE_SHA256
        original_read = VALIDATOR.read
        try:
            VALIDATOR.APP_TEMPLATE_SHA256 = hashlib.sha256(app_candidate.encode("utf-8")).hexdigest()
            VALIDATOR.read = lambda path: app_candidate if path == "config/app.yml.example" else original_read(path)
            try:
                VALIDATOR.validate_template()
            except RuntimeError:
                pass
            else:
                raise RuntimeError("Repository validator accepted member identity in the Lograge payload.")
        finally:
            VALIDATOR.APP_TEMPLATE_SHA256 = original_app_digest
            VALIDATOR.read = original_read

        runtime_verifier = (ROOT / "scripts/verify-site.rb").read_text(encoding="utf-8")
        runtime_email_filter = '''checks["discourse_connect_log_parameters_filtered"] =
  Rails.application.config.filter_parameters.include?(:email) &&
    Rails.application.config.filter_parameters.include?(:sso) &&
    Rails.application.config.filter_parameters.include?(:sig) &&
    Rails.application.config.filter_parameters.include?(:token)
'''
        if runtime_verifier.count(runtime_email_filter) != 1:
            raise RuntimeError("Runtime verifier omitted the exact member-email parameter filter check.")
        runtime_logster_filter = '''checks["member_identity_omitted_from_logster_context"] =
  defined?(MochiriiSensitiveLogsterEnvironmentFilter) &&
    defined?(MochiriiSensitiveLogsterMessageFilter) &&
    Logster.singleton_class.ancestors.include?(MochiriiSensitiveLogsterEnvironmentFilter) &&
    Logster::Message.singleton_class.ancestors.include?(MochiriiSensitiveLogsterMessageFilter) &&
    logster_string_identity_result.nil? &&
    logster_symbol_identity_result.nil? &&
    logster_string_identity_env.empty? &&
    logster_symbol_identity_env.empty? &&
    logster_control_result == "runtime-context-probe" &&
    logster_control_env == { job: "runtime-context-probe" }
checks["sensitive_request_fields_filtered_from_logster_context"] =
  (!logster_callback_context.key?("params") ||
    logster_callback_context["params"] == logster_callback_request.filtered_parameters) &&
    (!logster_callback_context.key?("REQUEST_URI") ||
      logster_callback_context["REQUEST_URI"] == logster_callback_request.filtered_path) &&
    !JSON.generate(logster_callback_context).include?("member-identity-probe")
'''
        if runtime_verifier.count(runtime_logster_filter) != 1:
            raise RuntimeError("Runtime verifier omitted the exact Logster member-identity omission check.")
        runtime_logster_candidate = runtime_verifier.replace(
            "    logster_string_identity_env.empty? &&\n",
            "    true &&\n",
            1,
        )
        if runtime_logster_candidate == runtime_verifier:
            raise RuntimeError("Runtime Logster member-identity hostile mutation anchor is absent.")
        original_runtime_digest = VALIDATOR.RUNTIME_VERIFIER_SHA256
        try:
            VALIDATOR.RUNTIME_VERIFIER_SHA256 = hashlib.sha256(
                runtime_logster_candidate.encode("utf-8")
            ).hexdigest()
            try:
                VALIDATOR.validate_theme_runtime_verifier(runtime_logster_candidate)
            except RuntimeError:
                pass
            else:
                raise RuntimeError("Runtime verifier accepted a decoy Logster member-identity check.")
        finally:
            VALIDATOR.RUNTIME_VERIFIER_SHA256 = original_runtime_digest
        runtime_logster_fields_candidate = runtime_verifier.replace(
            '  (!logster_callback_context.key?("params") ||\n'
            '    logster_callback_context["params"] == '
            "logster_callback_request.filtered_parameters) &&\n",
            "  true &&\n",
            1,
        )
        if runtime_logster_fields_candidate == runtime_verifier:
            raise RuntimeError("Runtime Logster filtered-or-omitted hostile mutation anchor is absent.")
        original_runtime_digest = VALIDATOR.RUNTIME_VERIFIER_SHA256
        try:
            VALIDATOR.RUNTIME_VERIFIER_SHA256 = hashlib.sha256(
                runtime_logster_fields_candidate.encode("utf-8")
            ).hexdigest()
            try:
                VALIDATOR.validate_theme_runtime_verifier(runtime_logster_fields_candidate)
            except RuntimeError:
                pass
            else:
                raise RuntimeError("Runtime verifier accepted a decoy Logster field-safety check.")
        finally:
            VALIDATOR.RUNTIME_VERIFIER_SHA256 = original_runtime_digest
        runtime_recovery_logster_filter = '''checks["admin_recovery_log_path_filtered"] =
  defined?(MochiriiSensitiveRequestPathFilter) &&
    ActionDispatch::Request.ancestors.include?(MochiriiSensitiveRequestPathFilter) &&
    recovery_request.path == "/session/email-login/#{recovery_token}" &&
    recovery_request.filtered_path == "/session/email-login/[FILTERED]" &&
    ordinary_request.filtered_path == "/session/email-login/too-short" &&
    (!recovery_logster_context.key?("REQUEST_URI") ||
      recovery_logster_context["REQUEST_URI"] == "/session/email-login/[FILTERED]") &&
    !JSON.generate(recovery_logster_context).include?(recovery_token)
'''
        if runtime_verifier.count(runtime_recovery_logster_filter) != 1:
            raise RuntimeError("Runtime verifier omitted the exact recovery Logster omission check.")
        runtime_recovery_logster_candidate = runtime_verifier.replace(
            '    (!recovery_logster_context.key?("REQUEST_URI") ||\n'
            '      recovery_logster_context["REQUEST_URI"] == '
            '"/session/email-login/[FILTERED]") &&\n',
            "    true &&\n",
            1,
        )
        if runtime_recovery_logster_candidate == runtime_verifier:
            raise RuntimeError("Runtime recovery Logster hostile mutation anchor is absent.")
        original_runtime_digest = VALIDATOR.RUNTIME_VERIFIER_SHA256
        try:
            VALIDATOR.RUNTIME_VERIFIER_SHA256 = hashlib.sha256(
                runtime_recovery_logster_candidate.encode("utf-8")
            ).hexdigest()
            try:
                VALIDATOR.validate_theme_runtime_verifier(runtime_recovery_logster_candidate)
            except RuntimeError:
                pass
            else:
                raise RuntimeError("Runtime verifier accepted a decoy recovery Logster check.")
        finally:
            VALIDATOR.RUNTIME_VERIFIER_SHA256 = original_runtime_digest
        runtime_lograge_filter = '''checks["member_identity_omitted_from_request_logs"] =
  defined?(MochiriiSensitiveDiscourseLogragePayloadFilter) &&
    DiscourseLograge.singleton_class.ancestors.include?(MochiriiSensitiveDiscourseLogragePayloadFilter) &&
    lograge_payload == { ip: "127.0.0.1", username: nil, route: "runtime-context-probe" } &&
    !JSON.generate(lograge_payload).include?("member-identity-probe")
'''
        if runtime_verifier.count(runtime_lograge_filter) != 1:
            raise RuntimeError("Runtime verifier omitted the exact member-identity log omission check.")
        runtime_lograge_candidate = runtime_verifier.replace(
            '    lograge_payload == { ip: "127.0.0.1", username: nil, route: "runtime-context-probe" } &&\n',
            "    true &&\n",
            1,
        )
        if runtime_lograge_candidate == runtime_verifier:
            raise RuntimeError("Runtime member-identity log hostile mutation anchor is absent.")
        original_runtime_digest = VALIDATOR.RUNTIME_VERIFIER_SHA256
        try:
            VALIDATOR.RUNTIME_VERIFIER_SHA256 = hashlib.sha256(
                runtime_lograge_candidate.encode("utf-8")
            ).hexdigest()
            try:
                VALIDATOR.validate_theme_runtime_verifier(runtime_lograge_candidate)
            except RuntimeError:
                pass
            else:
                raise RuntimeError("Runtime verifier accepted a decoy member-identity log check.")
        finally:
            VALIDATOR.RUNTIME_VERIFIER_SHA256 = original_runtime_digest
        runtime_candidate = runtime_verifier.replace(
            '    filtered_audit == { action: "generate", path: "/session/email-login/[FILTERED]" } &&\n',
            "    true &&\n",
            1,
        )
        if runtime_candidate == runtime_verifier:
            raise RuntimeError("Runtime authentication-path hostile mutation anchor is absent.")
        original_read = VALIDATOR.read
        try:
            VALIDATOR.read = lambda path: runtime_candidate if path == "scripts/verify-site.rb" else original_read(path)
            try:
                VALIDATOR.validate_theme_and_public_source()
            except RuntimeError:
                pass
            else:
                raise RuntimeError("Repository validator accepted a synthetic authentication-path restoration proof.")
        finally:
            VALIDATOR.read = original_read
    finally:
        CONNECT_FIXTURE.CALLBACK_LOG_MARKER_CATEGORIES.clear()
        CONNECT_FIXTURE.CALLBACK_LOG_MARKER_CATEGORIES.update(original_categories)
        CONNECT_FIXTURE.CALLBACK_LOG_MARKERS.clear()
        CONNECT_FIXTURE.CALLBACK_LOG_MARKERS.update(original)


def test_website_producer_probe_contract() -> None:
    security_headers = [
        ("Content-Type", "application/json; charset=utf-8"),
        ("Cache-Control", "private, no-store, max-age=0"),
        ("Content-Security-Policy", "default-src 'none'; frame-ancestors 'none'; base-uri 'none'"),
        ("Expires", "0"),
        ("Pragma", "no-cache"),
        ("Referrer-Policy", "no-referrer"),
        ("Vary", "Origin, Authorization"),
        ("X-Content-Type-Options", "nosniff"),
        ("X-Frame-Options", "DENY"),
    ]
    contracts = {
        "disabled": (
            503,
            {"ok": False, "code": "unavailable", "error": "Mōchirīī Forums sign-in is unavailable."},
        ),
        "enabled": (
            400,
            {"ok": False, "code": "invalid_request", "error": "This Mōchirīī Forums sign-in request is invalid."},
        ),
    }

    class Response:
        def __init__(self, status: int, headers: list[tuple[str, str]], body: bytes) -> None:
            self.status = status
            self._headers = headers
            self._body = body

        def getheaders(self):
            return self._headers

        def read(self, maximum: int) -> bytes:
            return self._body[:maximum]

    class Connection:
        response: Response
        last_request: tuple[object, ...] | None = None

        def __init__(self, host: str, port: int, *, timeout: int, context) -> None:
            if host != "mochirii.com" or port != 443 or timeout != 20 or context is None:
                raise RuntimeError("Website producer probe connection boundary changed.")

        def request(self, method: str, path: str, *, body: bytes, headers: dict[str, str]) -> None:
            Connection.last_request = (method, path, body, headers)

        def getresponse(self) -> Response:
            return Connection.response

        def close(self) -> None:
            return None

    original_connection = PRODUCER_PROBE.http.client.HTTPSConnection
    original_argv = sys.argv[:]
    try:
        PRODUCER_PROBE.http.client.HTTPSConnection = Connection
        for state, (status, document) in contracts.items():
            body = json.dumps(document, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
            Connection.response = Response(status, [*security_headers, ("Content-Length", str(len(body)))], body)
            sys.argv = ["probe-website-forums-producer.py", state]
            with contextlib.redirect_stdout(io.StringIO()):
                if PRODUCER_PROBE.main() != 0:
                    raise RuntimeError("Exact Website producer probe fixture failed.")
            method, path, request_body, headers = Connection.last_request or (None, None, None, {})
            if (
                method != "POST"
                or path != "/api/forums/discourse-connect"
                or request_body != b"{}"
                or "Origin" in headers
                or headers.get("Host") != "mochirii.com"
            ):
                raise RuntimeError("Website producer probe sent a member-bearing or noncanonical request.")

        hostile_responses = [
            Response(503, [*security_headers, ("Location", "https://example.invalid/")], json.dumps(contracts["disabled"][1], ensure_ascii=False).encode()),
            Response(503, [(name, "default-src 'none'") if name == "Content-Security-Policy" else (name, value) for name, value in security_headers], json.dumps(contracts["disabled"][1], ensure_ascii=False).encode()),
            Response(503, [*security_headers, ("Server", "cloudflare")], json.dumps(contracts["disabled"][1], ensure_ascii=False).encode()),
            Response(503, security_headers, b'{"ok":false,"code":"unavailable","error":"wrong"}'),
        ]
        for response in hostile_responses:
            Connection.response = response
            sys.argv = ["probe-website-forums-producer.py", "disabled"]
            try:
                with contextlib.redirect_stdout(io.StringIO()):
                    PRODUCER_PROBE.main()
            except RuntimeError:
                pass
            else:
                raise RuntimeError("Website producer probe accepted a hostile state response.")
    finally:
        PRODUCER_PROBE.http.client.HTTPSConnection = original_connection
        sys.argv = original_argv


def test_restore_stop_boundary() -> None:
    restore = (ROOT / "scripts/host-restore-validate.sh").read_text(encoding="utf-8")
    match = re.search(r"(?ms)^stop_app_safely\(\) \{.*?^\}", restore)
    if match is None:
        raise RuntimeError("Disposable restore stop boundary is absent.")
    function = match.group(0)
    required = (
        "timeout --signal=TERM --kill-after=5s 45 docker stop --time 30 app",
        "docker inspect --format '{{.State.Running}}' app",
        "docker container ls --all --filter 'name=^/app$'",
        "|| return 1",
    )
    if any(value not in function for value in required) or "|| printf false" in function:
        raise RuntimeError("Disposable restore stop boundary can convert daemon failure into a stopped state.")
    if "CRITICAL: Restore containment and application stop could not be verified" not in restore:
        raise RuntimeError("Disposable restore lacks a distinct critical unknown-stop marker.")
    if os.name != "posix":
        return
    bash = shutil.which("bash")
    if bash is None:
        raise RuntimeError("Bash is required for the restore stop hostile fixture.")
    harness = (
        function
        + "\n"
        + r'''
timeout() {
  while [[ ${1-} == -* ]]; do shift; done
  [[ $# -gt 0 ]] || return 1
  shift
  [[ $# -gt 0 ]] || return 1
  if [[ $1 == docker && ${2-} == stop ]]; then
    return 1
  fi
  "$@"
}
docker() {
  if [[ $1 == inspect ]]; then
    case ${MOCK_INSPECT} in
      false|true) printf '%s\n' "${MOCK_INSPECT}"; return 0 ;;
      *) return 1 ;;
    esac
  fi
  if [[ $1 == container && $2 == ls ]]; then
    case ${MOCK_INVENTORY} in
      empty) return 0 ;;
      app) printf '%s\n' app; return 0 ;;
      *) return 1 ;;
    esac
  fi
  return 1
}
stop_app_safely
'''
    )
    cases = (
        ({"MOCK_INSPECT": "error", "MOCK_INVENTORY": "error"}, False),
        ({"MOCK_INSPECT": "error", "MOCK_INVENTORY": "app"}, False),
        ({"MOCK_INSPECT": "true", "MOCK_INVENTORY": "empty"}, False),
        ({"MOCK_INSPECT": "false", "MOCK_INVENTORY": "app"}, True),
        ({"MOCK_INSPECT": "error", "MOCK_INVENTORY": "empty"}, True),
    )
    for values, expected in cases:
        completed = subprocess.run(
            [bash, "-c", harness],
            env={**os.environ, **values},
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=10,
            check=False,
        )
        if (completed.returncode == 0) is not expected:
            raise RuntimeError("Disposable restore hostile stop-state fixture changed.")


def test_active_swap_capacity_contract() -> None:
    verifier = (ROOT / "scripts/verify-host.sh").read_text(encoding="utf-8")
    function_start = verifier.index("active_swap_capacity_is_sufficient() {")
    function_source = verifier[
        function_start : verifier.index("\n}\n", function_start) + 3
    ]
    required = (
        'local -r nominal_bytes=2147483648',
        '[[ ${active_bytes} =~ ^(0|[1-9][0-9]{0,11})$ ]]',
        '[[ ${page_size} =~ ^[1-9][0-9]{3,5}$ ]]',
        'page_size >= 4096 && page_size <= 65536',
        '(page_size & (page_size - 1)) == 0',
        'active_bytes >= nominal_bytes - page_size',
        'page_size="$(timeout --signal=TERM --kill-after=5s 15s getconf PAGESIZE)"',
        'active_swap_capacity_is_sufficient "${swap_bytes}" "${page_size}"',
    )
    if any(value not in verifier for value in required):
        raise RuntimeError("Host active-swap verification lost its nominal-file/header-page contract.")
    swap_read = verifier.index('swap_bytes="$(timeout --signal=TERM --kill-after=5s 15s swapon')
    page_read = verifier.index('page_size="$(timeout --signal=TERM --kill-after=5s 15s getconf PAGESIZE)"')
    capacity_gate = verifier.index('active_swap_capacity_is_sufficient "${swap_bytes}" "${page_size}"')
    if not swap_read < page_read < capacity_gate or '[[ ${swap_bytes} -ge 2147483648 ]]' in verifier:
        raise RuntimeError("Host active-swap verification still compares usable bytes to nominal file bytes.")

    if os.name == "posix":
        bash = shutil.which("bash")
        if bash is None:
            raise RuntimeError("Bash is required for the active-swap capacity fixture.")
        harness = (
            "set -euo pipefail\n"
            + function_source
            + 'active_swap_capacity_is_sufficient "$ACTIVE_BYTES" "$PAGE_SIZE"\n'
        )
        cases = (
            ("2147483648", "4096", True),
            ("2147479552", "4096", True),
            ("2147479551", "4096", False),
            ("2147418112", "65536", True),
            ("2147418111", "65536", False),
            ("2147483647", "6000", False),
            ("2147483647", "2048", False),
            ("2147483647", "131072", False),
            ("02147479552", "4096", False),
            ("9999999999999", "4096", False),
            ("", "4096", False),
            ("2147483648", "4096x", False),
        )
        for active_bytes, page_size, expected in cases:
            completed = subprocess.run(
                [bash, "-c", harness],
                env={"ACTIVE_BYTES": active_bytes, "PAGE_SIZE": page_size},
                stdin=subprocess.DEVNULL,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                timeout=10,
                check=False,
            )
            if (completed.returncode == 0) is not expected or completed.stdout or completed.stderr:
                raise RuntimeError("Host active-swap capacity fixture accepted an unsafe boundary.")


def test_host_containment_contract() -> None:
    import ast

    deploy = (ROOT / "scripts/host-deploy.sh").read_text(encoding="utf-8")
    backup = (ROOT / "scripts/host-backup.sh").read_text(encoding="utf-8")
    restore = (ROOT / "scripts/host-restore-validate.sh").read_text(encoding="utf-8")
    host_verify = (ROOT / "scripts/verify-host.sh").read_text(encoding="utf-8")
    break_glass = (ROOT / "scripts/host-break-glass-admin.sh").read_text(encoding="utf-8")
    disposable = (ROOT / ".github/workflows/disposable-bootstrap.yml").read_text(encoding="utf-8")
    connect_verifier = (ROOT / "scripts/verify-discourse-connect.py").read_text(encoding="utf-8")
    survivor_fixture = (ROOT / "scripts/test-operation-survivor.rb").read_text(encoding="utf-8")
    nul_scan = r'File.binread(path).split("\0", -1).include?(marker)'
    literal_backslash_scan = r'File.binread(path).split("\\0", -1).include?(marker)'
    for source, expected, label in (
        (deploy, 1, "deploy"),
        (backup, 1, "backup"),
        (restore, 3, "restore"),
        (break_glass, 1, "break-glass"),
        (disposable, 1, "disposable"),
    ):
        if source.count(nul_scan) != expected or literal_backslash_scan in source:
            raise RuntimeError(f"{label} process-survivor scan no longer splits real NUL-delimited environ bytes.")
    generated_scans = [
        node.value
        for node in ast.walk(ast.parse(connect_verifier))
        if isinstance(node, ast.Constant)
        and isinstance(node.value, str)
        and '/proc/[0-9]*/environ' in node.value
    ]
    if len(generated_scans) != 1 or generated_scans[0].count(nul_scan) != 1 or literal_backslash_scan in generated_scans[0]:
        raise RuntimeError("DiscourseConnect process-survivor command no longer emits a real-NUL Ruby scan.")
    survivor_required = (
        'File.binwrite(marked, ["PATH=/usr/bin", marker, "HOME=/var/www/discourse", ""].join("\\0"))',
        'File.binread(path).split("\\0", -1).include?(marker)',
        'File.binread(marked).split("\\\\0", -1).include?(marker)',
        '"scripts/host-deploy.sh" => 1',
        '"scripts/host-backup.sh" => 1',
        '"scripts/host-restore-validate.sh" => 3',
        '"scripts/host-break-glass-admin.sh" => 1',
        '".github/workflows/disposable-bootstrap.yml" => 1',
        '"scripts/verify-discourse-connect.py" => 1',
    )
    if any(value not in survivor_fixture for value in survivor_required):
        raise RuntimeError("Executable survivor fixture lost its actual-NUL, marked-process, or three-host binding.")
    if "timeout --foreground" in deploy:
        raise RuntimeError("Hosted storage runner uses foreground timeout, which does not contain child processes.")
    function = deploy[deploy.index("run_storage_fixture() {") : deploy.index("activate_config() {")]
    runner_probe = function.index("container_operation_absent")
    status_gate = function.index("(( runner_status == 0 ))")
    stop_gate = function.index("emergency_stop")
    if not (runner_probe < stop_gate < status_gate):
        raise RuntimeError("Hosted storage cleanup can race a surviving Rails runner.")
    if "|| printf false" in function or "docker stop --time 30 app" in function:
        raise RuntimeError("Hosted storage runner uses an unproved direct stop fallback.")
    required_stop = (
        "stop_app_safely()",
        "timeout --signal=TERM --kill-after=5s 45 docker stop --time 30 app",
        "docker inspect --format '{{.State.Running}}' app",
        "docker container ls --all --filter 'name=^/app$'",
        "emergency_stop()",
        "CRITICAL: Mochirii Forums application stop could not be verified.",
        "timeout --signal=TERM --kill-after=30s",
        "launcher_bootstrap_cid",
        "reconcile_launcher_failure()",
        "runtime_survivor_unproved=true",
        "cleanup, rebuild, and public rollback are blocked",
        'MOCHIRII_OPERATION_TOKEN="${operation_token}"',
        "remaining_mutation_seconds",
        "launcher_cumulative_budget_seconds=7800",
        'active_operation_kind="launcher"',
        'reconcile_launcher_failure || true',
        'verify-runtime-assets.sh" "${release}" --require-container',
    )
    if any(value not in deploy for value in required_stop):
        raise RuntimeError("Independent application-stop readback boundary changed.")
    deploy_exit = deploy[deploy.index("on_exit() {") : deploy.index("trap on_exit EXIT")]
    if deploy_exit.count("emergency_stop") < 3:
        raise RuntimeError("A failed containment, sealed rollback, or bootstrap destroy can leave a running app.")
    forbidden_recovery = (
        "run_launcher storage-containment-stop stop app",
        "run_launcher storage-recovery-stop stop app",
        "run_launcher cleanup-reconciled-stop stop app",
        "Failed initial container was stopped",
    )
    if any(value in deploy for value in forbidden_recovery):
        raise RuntimeError("Launcher-dependent recovery still claims an unproved application stop.")
    rollback_failure = deploy_exit[deploy_exit.index("if restore_previous_release; then") : deploy_exit.index("else\n      run_launcher failed-bootstrap-cleanup")]
    if "emergency_stop" not in rollback_failure:
        raise RuntimeError("Checkout-seal or launcher rollback failure does not independently stop the app.")
    destroy_failure = deploy_exit[deploy_exit.index("run_launcher failed-bootstrap-cleanup destroy app") :]
    if destroy_failure.index("emergency_stop") > destroy_failure.index("rm -f -- \"${app_config}\""):
        raise RuntimeError("Bootstrap cleanup removes evidence before proving the app stopped.")

    restore = (ROOT / "scripts/host-restore-validate.sh").read_text(encoding="utf-8")
    required = (
        "prove_restore_containment()",
        '[[ "$(readlink -f -- /var/discourse/containers/app.yml)" == "${restore_config}" ]]',
        "DISCOURSE_DISABLE_EMAILS\" = yes",
        "DISCOURSE_ENABLE_DISCOURSE_CONNECT\" = false",
        "SiteSetting.allow_restore == false",
        "stop_app_safely()",
        "timeout --signal=TERM --kill-after=5s 45 docker stop --time 30 app",
        "docker inspect --format '{{.State.Running}}' app",
        "docker container ls --all --filter 'name=^/app$'",
        "run_container_command()",
        "timeout --signal=TERM --kill-after=15s",
        'MOCHIRII_OPERATION_TOKEN="${operation_token}"',
        "container_operation_absent",
        "remaining_operation_seconds",
        "reconcile_launcher_failure()",
        "Restore process termination is unproved",
    )
    if any(value not in restore for value in required):
        raise RuntimeError("Disposable restore containment lost an exact runtime or stop invariant.")
    exit_body = restore[restore.index("on_exit() {") : restore.index("trap on_exit EXIT")]
    if exit_body.index("activate_config") > exit_body.index("prove_restore_containment"):
        raise RuntimeError("Restore failure containment is verified before the exact isolated config is activated.")
    if exit_body.index("prove_restore_containment") > exit_body.index("stop_app_safely"):
        raise RuntimeError("Restore failure does not stop the app after containment proof fails.")
    if exit_body.index("runtime_survivor_unproved") > exit_body.index("disable_restore_safely"):
        raise RuntimeError("Restore failure can run cleanup before checking for an unproved survivor.")
    restore_runner = restore[restore.index("run_container_command() {") : restore.index("disable_restore_safely() {")]
    if any(
        value not in restore_runner
        for value in (
            'timeout --signal=TERM --kill-after=10s "${outer_seconds}" docker exec -e MOCHIRII_OPERATION_TOKEN="${operation_token}" app',
            "timeout --signal=TERM --kill-after=15s",
            "container_operation_absent",
            "stop_app_safely",
            "runtime_survivor_unproved=true",
        )
    ):
        raise RuntimeError("Restore in-container timeout or survivor containment changed.")
    if not all(
        value in restore
        for value in (
            "run_container_command restore-backup 5400",
            'discourse restore --location s3 "${backup_filename}"',
            "run_container_command verify-restored-data 900",
            "run_container_command verify-restored-restart 900",
            "run_container_command verify-restored-rebuild 900",
        )
    ):
        raise RuntimeError("Destructive restore or its readbacks escaped the bounded in-container runner.")

    backup_transaction = (ROOT / "scripts/backup-transaction.py").read_text(encoding="utf-8")
    if "timeout --foreground" in backup:
        raise RuntimeError("Backup runner uses foreground timeout, which does not contain child processes.")
    for value in (
        "mutation_budget_seconds=4500",
        "remaining_mutation_seconds",
        'MOCHIRII_OPERATION_TOKEN="${operation_token}"',
        "container_operation_absent",
        "contain_failed_container_operation",
        "verify-runtime-assets.sh",
        "backup_runtime_recovery_command",
        "start_app_for_backup_recovery",
        "docker start app",
        "cleanup-pending",
        "restart-authorized",
        "cleanup-proved",
        "Backup refuses an active deployment transaction.",
        "Backup refuses an active nonterminal restore transaction.",
    ):
        if value not in backup:
            raise RuntimeError("Backup cumulative lifetime or runtime-asset boundary changed.")

    recovery_functions = backup[
        backup.index("prove_production_selection() {") :
        backup.index("finish_backup_transaction() {")
    ]
    start_function = backup[
        backup.index("start_app_for_backup_recovery() {") :
        backup.index("finish_backup_transaction() {")
    ]
    if any(value not in recovery_functions for value in (
        'timeout --signal=TERM --kill-after=5s 45 docker start app',
        '[[ "$(readlink -f -- /var/discourse/containers/app.yml)" == "${production_config}" ]]',
        '[[ "$(readlink -f -- /opt/mochirii/forums/current)" == "${release_dir}" ]]',
        'test "$MOCHIRII_REPOSITORY_COMMIT" = "$1"',
        'test "$DISCOURSE_DISABLE_EMAILS" = no',
        'stop_app_safely || runtime_survivor_unproved=true',
    )):
        raise RuntimeError("Stopped backup recovery lost its bounded exact-production identity or timeout containment.")
    operation_runner = backup[backup.index("run_container_command() {") : backup.index("record_event() {")]
    runner_order = (
        "prove_running_backup_identity",
        'backup_runtime_operation_command arm-operation "${label}" "${operation_token}"',
        'docker exec -e MOCHIRII_OPERATION_TOKEN="${operation_token}" app',
        'container_operation_absent "${operation_token}"',
        'backup_runtime_operation_command complete-operation "${label}" "${operation_token}"',
    )
    if [operation_runner.index(value) for value in runner_order] != sorted(operation_runner.index(value) for value in runner_order):
        raise RuntimeError("Backup container mutation is not durably armed and absence-proved before completion.")
    runtime_reconciliation = backup[
        backup.index("reconcile_bound_runtime_ownership() {") : backup.index("restore_original_runtime_state() {")
    ]
    operation_recovery = runtime_reconciliation[
        runtime_reconciliation.index("operation-armed)") : runtime_reconciliation.index("idle)", runtime_reconciliation.index("operation-armed)"))
    ]
    recovery_order = (
        "contain_failed_container_operation",
        "prove_stopped_backup_identity",
        "prove-operation-absent",
        "authorize-restart",
        "start_app_for_backup_recovery",
        "complete-restart",
    )
    if [operation_recovery.index(value) for value in recovery_order] != sorted(operation_recovery.index(value) for value in recovery_order):
        raise RuntimeError("Stopped backup recovery can restart before exact operation absence and durable authority.")
    original_restoration = backup[
        backup.index("restore_original_runtime_state() {") : backup.index("contain_temporary_runtime_on_failure() {")
    ]
    if any(value not in original_restoration for value in (
        '[[ ${original_runtime_state} == running ]]',
        "complete-original-state --observed-runtime-state running",
        "authorize-original-stop",
        "runtime_operation_phase=original-stop-authorized",
        "reconcile_bound_runtime_ownership",
    )):
        raise RuntimeError("Backup terminal path no longer restores its exact original running/stopped state.")
    if "backup_transaction_command retire-prepared" in backup or 'fail("prepared backup ownership cannot retire before terminal runtime restoration")' not in backup_transaction:
        raise RuntimeError("Prepared backup ownership regained a journal-free retirement escape.")
    cleanup_function = backup[backup.index("cleanup() {") : backup.index("trap cleanup EXIT")]
    if "contain_temporary_runtime_on_failure" not in cleanup_function or "CRITICAL: Backup could not restore its stopped-origin containment state." not in cleanup_function:
        raise RuntimeError("A failed stopped-origin backup can escape without fail-closed containment ownership.")
    containment_function = backup[
        backup.index("contain_temporary_runtime_on_failure() {") : backup.index("finish_backup_transaction() {")
    ]
    containment_order = (
        "backup_transaction_command contain-temporary-runtime",
        "runtime_operation_phase=temporary-stop-authorized",
        "stop_app_safely",
        "prove_stopped_backup_identity",
        "backup_transaction_command contain-temporary-runtime",
        "runtime_operation_phase=initial-stopped",
    )
    cursor = 0
    for value in containment_order:
        position = containment_function.index(value, cursor)
        cursor = position + len(value)
    backup_fixture = (ROOT / "scripts/test-backup-transaction.py").read_text(encoding="utf-8")
    for value in (
        "assert_host_containment_sigkill",
        "assert_host_containment_retry",
        "Host containment stop was not durably pre-authorized.",
        "Post-stop SIGKILL reverted to unowned idle state.",
        '"temporary-stop-authorized"',
    ):
        if value not in backup_fixture:
            raise RuntimeError("Backup hostile fixture lost the stopped-origin post-stop crash window.")
    for value in (
        '"originalRuntimeState"', '"runtimeIdentitySha256"', '"currentReleaseSha256"',
        '"discourseRevision"', '"dockerManagerRevision"', '"runtimeEnvironmentSha256"',
        '"runtimePortBindingsSha256"', '"runtimeContainerImage"', '"runtimeOperationPhase"',
        '"arm-operation"', '"complete-operation"', '"prove-operation-absent"',
        '"authorize-restart"', '"complete-restart"', '"authorize-initial-start"',
        '"complete-initial-start"', '"contain-temporary-runtime"',
        '"authorize-original-stop"', '"complete-original-state"',
    ):
        if value not in backup_transaction:
            raise RuntimeError("Backup transaction lost its exact runtime recovery authority inventory.")
    for source, refusal, label in (
        (
            deploy,
            "Deployment refuses an active backup transaction; only the protected backup command may reconcile it.",
            "deploy",
        ),
        (
            restore,
            "Restore refuses an active backup transaction; only the protected backup command may reconcile it.",
            "restore",
        ),
    ):
        if refusal not in source:
            raise RuntimeError(f"{label} gained a bypass around protected stopped-backup recovery.")

    disposable = (ROOT / ".github/workflows/disposable-bootstrap.yml").read_text(encoding="utf-8")
    disposable_guard = (ROOT / "scripts/disposable-launcher-guard.py").read_text(encoding="utf-8")
    disposable_guard_fixture = (ROOT / "scripts/test-disposable-launcher-guard.py").read_text(encoding="utf-8")
    docker_manager_readback = (
        "sudo docker exec -u discourse app git -C /var/www/discourse/plugins/docker_manager rev-parse HEAD"
    )
    if (
        disposable.count(docker_manager_readback) != 4
        or disposable.count("plugins/docker_manager rev-parse HEAD") != 4
        or "sudo docker exec app git -C /var/www/discourse/plugins/docker_manager rev-parse HEAD" in disposable
        or "safe.directory" in disposable
    ):
        raise RuntimeError("Disposable Docker Manager readback does not execute as its repository owner.")
    backup_identity = re.search(r"(?ms)^prove_running_backup_identity\(\) \{.*?^\}", backup)
    if backup_identity is None:
        raise RuntimeError("Backup running-identity proof is absent.")
    backup_identity_source = backup_identity.group(0)
    if (
        backup_identity_source.count("docker exec -u discourse app bash -lc") != 1
        or backup_identity_source.count("git -C /var/www/discourse rev-parse HEAD") != 1
        or backup_identity_source.count("git -C /var/www/discourse/plugins/docker_manager rev-parse HEAD") != 1
        or "docker exec app bash -lc" in backup_identity_source
        or "safe.directory" in backup
    ):
        raise RuntimeError("Backup runtime Git proof is not bound to the repository owner.")
    hosted_core_readback = "timeout --signal=TERM --kill-after=5s 30s docker exec -u discourse app bash -lc 'test \"$(cd /var/www/discourse && git rev-parse HEAD)\" = cbf996f65aae3da1843224aa624bcd9a225931ac'"
    hosted_manager_readback = "timeout --signal=TERM --kill-after=5s 30s docker exec -u discourse app bash -lc 'test \"$(cd /var/www/discourse/plugins/docker_manager && git rev-parse HEAD)\" = c008c3ca7fcc44775215843992e88190adb7b3bf'"
    hosted_source_block = '''timeout --signal=TERM --kill-after=10s 60s docker exec -u discourse app bash -lc '
  set -e
  export GIT_OPTIONAL_LOCKS=0
  git -C /var/www/discourse diff --no-ext-diff --quiet HEAD --
  git -C /var/www/discourse diff --no-ext-diff --cached --quiet
  test -z "$(git -c core.fsmonitor=false -C /var/www/discourse status --porcelain=v1 --untracked-files=all)"
  git -C /var/www/discourse/plugins/docker_manager diff --no-ext-diff --quiet HEAD --
  git -C /var/www/discourse/plugins/docker_manager diff --no-ext-diff --cached --quiet
  test -z "$(git -c core.fsmonitor=false -C /var/www/discourse/plugins/docker_manager status --porcelain=v1 --untracked-files=all)"
  cmp -s /var/www/discourse/plugins/mochirii_email_metadata/plugin.rb /opt/mochirii-release/mochirii-email-metadata-plugin.rb
' || fail "Running core, Docker Manager, or mandatory mail component bytes differ."'''
    if (
        host_verify.count(hosted_core_readback) != 1
        or host_verify.count(hosted_manager_readback) != 1
        or host_verify.count(hosted_source_block) != 1
        or "docker exec app bash -lc 'test \"$(cd /var/www/discourse" in host_verify
        or "safe.directory" in host_verify
    ):
        raise RuntimeError("Hosted Git proof is not exactly owner-scoped and mutation-free.")
    for value in (
        "Disposable named application image differs from the exact tagged application image.",
        "allowed_images.add(tagged)",
    ):
        if value not in disposable_guard:
            raise RuntimeError("Disposable launcher can retire mismatched tagged and running app images.")
    for value in (
        '"rebuild-mismatched-created-images"',
        '"rebuild-mismatched-preexisting-tag"',
        "Matching rebuild did not adopt exactly one terminal app image.",
        "def nginx_log_directory_fixture() -> None:",
        "NGINX_LOG_DIRECTORY_PREFIX = (",
        "Pinned Nginx log directory symlink guard changed its target.",
        "def nginx_outlet_syntax_fixture() -> None:",
        "Pinned Nginx accepted the hostile unquoted bounded recovery regex.",
    ):
        if value not in disposable_guard_fixture:
            raise RuntimeError("Disposable hostile fixture lost terminal image-equality or Nginx syntax coverage.")
    if (
        disposable.count("--tmpfs /var/log:rw,nosuid,nodev,size=4m,mode=0755,uid=0,gid=0 --group-add adm") != 1
    ):
        raise RuntimeError("Disposable hostile fixture lost its isolated root:adm Nginx log boundary.")
    if "timeout --foreground" in disposable:
        raise RuntimeError("Disposable restore uses foreground timeout, which can leave a spawned child alive.")
    for value in ("MOCHIRII_OPERATION_TOKEN", "container_operation_absent", "terminate_active_group"):
        if value not in disposable:
            raise RuntimeError("Disposable restore lost its descendant containment boundary.")


def test_process_group_timeout() -> None:
    if os.name != "posix":
        return
    timeout_command = shutil.which("timeout")
    bash = shutil.which("bash")
    if timeout_command is None or bash is None:
        raise RuntimeError("GNU timeout and Bash are required for the process-group hostile fixture.")
    with tempfile.TemporaryDirectory(prefix="mochirii-process-group-") as directory:
        pid_path = Path(directory) / "child.pid"
        completed = subprocess.run(
            [
                timeout_command,
                "--signal=TERM",
                "--kill-after=1s",
                "1s",
                bash,
                "-c",
                'sleep 300 & child=$!; printf "%s" "$child" >"$1"; wait "$child"',
                "bash",
                str(pid_path),
            ],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=10,
            check=False,
        )
        if completed.returncode not in {124, 137} or not pid_path.is_file():
            raise RuntimeError("Process-group hostile fixture did not reach its bounded timeout.")
        child_pid = int(pid_path.read_text(encoding="ascii"))
        for _ in range(20):
            try:
                os.kill(child_pid, 0)
            except ProcessLookupError:
                break
            time.sleep(0.1)
        else:
            raise RuntimeError("A differently named spawned child survived the process-group timeout.")


def test_sidekiq_processing_contract() -> None:
    plugin = (ROOT / "plugins/mochirii_email_metadata/plugin.rb").read_text(encoding="utf-8")
    site = (ROOT / "scripts/verify-site.rb").read_text(encoding="utf-8")
    restored = (ROOT / "scripts/verify-restored-backup.rb").read_text(encoding="utf-8")
    fixture = (ROOT / "scripts/test-sidekiq-processing-probe.rb").read_text(encoding="utf-8")
    required = (
        'HEALTH_STATE_KEY = "mochirii-runtime-health-sidekiq-probe".freeze',
        "HEALTH_LEASE_GRACE_SECONDS = 30",
        "HEALTH_JOB_BIND_SECONDS = 5",
        "HEALTH_NONCE_PATTERN = /\\A[0-9a-f]{32}\\z/",
        "HEALTH_JID_PATTERN = /\\A[0-9a-f]{24}\\z/",
        "HEALTH_PREPARING_PATTERN = /\\Apreparing:[0-9a-f]{32}\\z/",
        "HEALTH_TRANSITION_SCRIPT",
        "HEALTH_DELETE_SCRIPT",
        'redis.call("set", KEYS[1], ARGV[2], "XX", "KEEPTTL")',
        'for index = 1, #ARGV do',
        "class SidekiqProbeError < StandardError",
        "class SidekiqProbeJobError < StandardError",
        "redis.namespace_key(HEALTH_STATE_KEY)",
        "redis.without_namespace",
        "nx: true, ex: lease_seconds",
        "Jobs.run_later?",
        "DB.transaction_open?",
        'Jobs.enqueue(:mochirii_sidekiq_processing_probe, queue: "default")',
        "jid.is_a?(String) && jid.match?(HEALTH_JID_PATTERN)",
        'raise SidekiqProbeError.new("marker-mismatch")',
        'raise SidekiqProbeError.new("job-reported-failure")',
        "return true if classify_health_probe_timeout(jid) == :completed",
        "ensure\n      clear_health_probe!(token, jid) if health_probe_owned",
        "state == started",
        "return unless state == pending",
        "transition_health_probe(started, completed)",
        "transition_health_probe(started, failed)",
        "raise MochiriiEmailMetadata::SidekiqProbeJobError.new, cause: nil",
    )
    if any(value not in plugin for value in required):
        raise RuntimeError("Leased Sidekiq processing probe lost an enqueue, state, retry, or cleanup invariant.")
    expected_states = {
        "cleanup-failed",
        "enqueue-rejected",
        "job-not-started-before-timeout",
        "job-reported-failure",
        "job-started-without-completion",
        "marker-mismatch",
        "probe-already-running",
        "probe-internal-failure",
        "run-mode-invalid",
        "transaction-open",
    }
    state_block = re.search(r"HEALTH_FAILURE_STATES\s*=\s*%w\[(.*?)\][.]freeze", plugin, re.S)
    if state_block is None or set(state_block.group(1).split()) != expected_states:
        raise RuntimeError("Sidekiq processing probe fixed-state vocabulary differs.")
    verifier_method = plugin[
        plugin.index("def self.verify_sidekiq_processing!") : plugin.index("module ::Jobs")
    ]
    verifier_order = (
        'raise SidekiqProbeError.new("run-mode-invalid")',
        'raise SidekiqProbeError.new("transaction-open")',
        "claim_health_probe!(token, timeout_seconds + HEALTH_LEASE_GRACE_SECONDS)",
        "health_probe_owned = true",
        'Jobs.enqueue(:mochirii_sidekiq_processing_probe, queue: "default")',
        "jid.is_a?(String) && jid.match?(HEALTH_JID_PATTERN)",
        'health_state_value("pending", jid)',
        "transition_health_probe(preparing, pending) == 1",
    )
    verifier_positions = [verifier_method.index(value) for value in verifier_order]
    if verifier_positions != sorted(verifier_positions):
        raise RuntimeError("Sidekiq lease claim, enqueue, JID binding, and observation ordering differs.")
    transition_block = plugin[plugin.index("def self.transition_health_probe") : plugin.index("def self.claim_health_probe!")]
    cleanup_block = plugin[plugin.index("def self.clear_health_probe!") : plugin.index("def self.expected_health_phase")]
    if ".to_i" in transition_block or ".to_i" in cleanup_block:
        raise RuntimeError("Sidekiq Lua outcomes regained Ruby truthiness coercion.")
    if "health_probe_state" in cleanup_block:
        raise RuntimeError("Sidekiq cleanup regained a post-delete global-read race.")
    if plugin.count("redis.without_namespace") != 2:
        raise RuntimeError("Sidekiq Lua operations are not bound to the physical namespaced key.")
    if any(value in plugin for value in ('redis.call("set", KEYS[1], ARGV[2], "EX"', "Discourse.redis.del")):
        raise RuntimeError("Sidekiq transitions can extend the lease or delete without ownership.")
    expected_lua = {
        "HEALTH_TRANSITION_SCRIPT": """local current = redis.call(\"get\", KEYS[1])
if not current then
  return 0
end
if current ~= ARGV[1] then
  return -1
end
if redis.call(\"ttl\", KEYS[1]) <= 0 then
  return -2
end
redis.call(\"set\", KEYS[1], ARGV[2], \"XX\", \"KEEPTTL\")
return 1""",
        "HEALTH_DELETE_SCRIPT": """local current = redis.call(\"get\", KEYS[1])
if not current then
  return 0
end
for index = 1, #ARGV do
  if current == ARGV[index] then
    redis.call(\"del\", KEYS[1])
    return 1
  end
end
return -1""",
    }
    for constant, expected_script in expected_lua.items():
        script_match = re.search(
            rf"{constant}\s*=\s*DiscourseRedis::EvalHelper[.]new\(<<~LUA\)\n(.*?)\n\s+LUA",
            plugin,
            re.S,
        )
        if script_match is None:
            raise RuntimeError(f"{constant} is absent from the Sidekiq probe.")
        actual_script = "\n".join(
            line[8:] if line.startswith(" " * 8) else line for line in script_match.group(1).splitlines()
        )
        if actual_script != expected_script:
            raise RuntimeError(f"{constant} differs from its exact fail-closed Lua body.")
    job = plugin[plugin.index("class MochiriiSidekiqProcessingProbe") :]
    if not (
        job.index("state == started") < job.index("return unless state == pending")
        and job.index("transition_health_probe(pending, started)") < job.index("transition_health_probe(started, completed)")
        and job.index("rescue StandardError") < job.index("transition_health_probe(started, failed)")
    ):
        raise RuntimeError("Sidekiq same-JID resume, completion, or fixed retry ordering differs.")
    for unsafe in (
        "Sidekiq::Queue",
        "Sidekiq::RetrySet",
        "Sidekiq::DeadSet",
        "Sidekiq::WorkSet",
        "Sidekiq::ProcessSet",
        "DistributedMutex",
        "PluginStore",
        '"#{token}"',
        '"#{jid}"',
        '"#{arguments}"',
        "error.message",
        "backtrace",
    ):
        if unsafe in plugin:
            raise RuntimeError("Sidekiq processing diagnostics inspect or emit an unsafe value.")
    fixture_canaries = (
        "spawn_worker_before_bind: true",
        "ProbeHarness.redis.expiry_history.uniq == [90.0]",
        '"direct NX claim did not expire and replace the ambiguous owner"',
        'expect_probe_state("run-mode-invalid")',
        'expect_probe_state("transaction-open")',
        'expect_probe_state("enqueue-rejected")',
        'expect_probe_state("probe-internal-failure")',
        'expect_probe_state("probe-already-running")',
        "enqueue_hold: true",
        '"expired pre-bind caller did not fail closed"',
        "lease_seconds: 1",
        'ProbeHarness.reset(mode: :missing_state)',
        'ProbeHarness.reset(mode: :wrong_state)',
        'expect_probe_state("job-not-started-before-timeout")',
        'expect_probe_state("job-started-without-completion")',
        'expect_probe_state("job-reported-failure")',
        'ProbeHarness.redis.force_state("started:" + ProbeHarness::VALID_JID)',
        'ProbeHarness.redis.force_state("pending:" + ProbeHarness::SECOND_JID)',
        'ProbeHarness.redis.force_state("preparing:" + ProbeHarness::FIXED_NONCE)',
        "ProbeHarness.delete_override = :nil",
        "ProbeHarness.delete_override = :raise",
        "takeover_after_delete: true",
        '"old cleanup changed the immediately acquired generation"',
        'expect_probe_state("cleanup-failed")',
        'ProbeHarness::RAW_WORKER_ERROR',
        'ProbeHarness::RAW_ENQUEUE_ERROR',
        'ProbeHarness::RAW_CLAIM_ERROR',
        "error.cause.nil?",
        "error.full_message.include?(value)",
        'puts "Sidekiq processing probe hostile fixture passed."',
    )
    if any(value not in fixture for value in fixture_canaries):
        raise RuntimeError("Sidekiq processing hostile fixture lost a state, retry, cleanup, or redaction case.")
    fake_redis_set = fixture[
        fixture.index("def set(key, value, nx:, ex:)") : fixture.index("def transition(key, arguments)")
    ]
    if (
        fake_redis_set.count("expire_if_needed(canonical)") != 1
        or fake_redis_set.index("expire_if_needed(canonical)")
        > fake_redis_set.index("return nil if nx && @store.key?(canonical)")
    ):
        raise RuntimeError("Sidekiq hostile Redis model does not expire a due key before its NX claim.")
    sidekiq_doc_requirements = {
        "docs/operations/RECOVERY.md": (
            "60-second post-enqueue observation window",
            "same-JID pending, started, failed,",
            "conditional Lua delete",
            "does not distinguish backlog from a",
        ),
        "docs/operations/RUNTIME-READINESS.md": (
            "one namespaced, expiring Redis lease",
            "enqueues without a correlation",
            "Compare-and-swap transitions retain the original lease expiry",
            "does not claim to distinguish backlog",
        ),
        "docs/operations/VALIDATION.md": (
            "private namespaced Redis lease",
            "exact no-argument JID binding",
            "60-second post-enqueue observation window",
            "terminal cleanup removes only the caller-owned state",
        ),
    }
    for document, required_values in sidekiq_doc_requirements.items():
        source = (ROOT / document).read_text(encoding="utf-8")
        if any(value not in source for value in required_values):
            raise RuntimeError(f"Sidekiq processing operations documentation differs in {document}.")
    for label, verifier in (("site", site), ("restored", restored)):
        VALIDATOR.validate_sidekiq_runtime_verifier(verifier, label)

    process_line = 'checks["sidekiq_process_present"] = Sidekiq::ProcessSet.new.any?\n'
    probe_state_line = 'sidekiq_probe_state = "completed"\n'
    if site.count(process_line) != 1 or site.count(probe_state_line) != 1:
        raise RuntimeError("Runtime Sidekiq registration-order hostile anchor is absent.")
    early_process_sample = site.replace(process_line, "", 1).replace(
        probe_state_line,
        process_line + probe_state_line,
        1,
    )
    try:
        VALIDATOR.validate_sidekiq_runtime_verifier(early_process_sample, "hostile site")
    except RuntimeError:
        pass
    else:
        raise RuntimeError("Runtime verifier accepted a pre-processing Sidekiq registration sample.")


def test_restored_mail_suppression_contract() -> None:
    restored = (ROOT / "scripts/verify-restored-backup.rb").read_text(encoding="utf-8")
    VALIDATOR.validate_restored_mail_suppression_contract(restored)
    VALIDATOR.validate_restored_central_login_contract(restored)
    VALIDATOR.validate_restored_failure_exit_contract(restored)
    hostiles = (
        restored.replace(
            'runtime_mail_suppression = ENV.fetch("DISCOURSE_DISABLE_EMAILS")',
            'runtime_mail_suppression = "yes"',
            1,
        ),
        restored.replace("%w[yes non-staff]", "%w[yes non-staff no]", 1),
        restored.replace(
            "SiteSetting.disable_emails == runtime_mail_suppression",
            "true",
            1,
        ),
        restored.replace(
            "    %w[yes non-staff].include?(runtime_mail_suppression) &&",
            "    true ||\n    %w[yes non-staff].include?(runtime_mail_suppression) &&",
            1,
        ),
        restored.replace("mail_suppression_matches_runtime:", "all_mail_disabled:", 1),
        restored.replace(
            "SiteSetting.disable_emails == runtime_mail_suppression",
            "SiteSetting.disable_emails = runtime_mail_suppression",
            1,
        ),
    )
    for hostile in hostiles:
        if hostile == restored:
            raise RuntimeError("Restored mail-suppression hostile mutation anchor is absent.")
        try:
            VALIDATOR.validate_restored_mail_suppression_contract(hostile)
        except RuntimeError:
            continue
        raise RuntimeError("Restored-backup verifier accepted unsafe or unbound mail suppression.")

    central_login_hostiles = (
        restored.replace(
            'ENV.fetch("DISCOURSE_ENABLE_DISCOURSE_CONNECT")',
            'ENV["DISCOURSE_ENABLE_DISCOURSE_CONNECT"]',
            1,
        ),
        restored.replace('  when "true" then true', '  when "true" then false', 1),
        restored.replace('  when "false" then false', '  when "false" then true', 1),
        restored.replace(
            "SiteSetting.enable_discourse_connect == runtime_central_login",
            "SiteSetting.enable_discourse_connect = runtime_central_login",
            1,
        ),
        restored.replace(
            "SiteSetting.enable_discourse_connect == runtime_central_login",
            "SiteSetting.enable_discourse_connect == false",
            1,
        ),
    )
    for hostile in central_login_hostiles:
        if hostile == restored:
            raise RuntimeError("Restored central-login hostile mutation anchor is absent.")
        try:
            VALIDATOR.validate_restored_central_login_contract(hostile)
        except RuntimeError:
            continue
        raise RuntimeError("Restored-backup verifier accepted unsafe or unbound central login.")

    exit_hostiles = (
        restored.replace("  recovery_marker: 65,", "  recovery_marker: 64,", 1),
        restored.replace("  recovery_marker: 65,", "  recovery_marker_changed: 65,", 1),
        restored.replace(
            '  database: ActiveRecord::Base.connection.select_value("SELECT 1").to_i == 1,',
            '  database_changed: ActiveRecord::Base.connection.select_value("SELECT 1").to_i == 1,',
            1,
        ),
        restored.replace("checks = {\n", "checks = {\n  unmapped_check: false,\n", 1),
        restored.replace(
            '  database: ActiveRecord::Base.connection.select_value("SELECT 1").to_i == 1,\n'
            '  redis: Discourse.redis.ping == "PONG",',
            '  redis: Discourse.redis.ping == "PONG",\n'
            '  database: ActiveRecord::Base.connection.select_value("SELECT 1").to_i == 1,',
            1,
        ),
        restored.replace(
            "RESTORED_CHECK_EXIT_CODES.fetch(failed.first)",
            "RESTORED_CHECK_EXIT_CODES[failed.first]",
            1,
        ),
        restored.replace("failed.first", "failed.last", 1),
        restored.replace(
            "exit(RESTORED_CHECK_EXIT_CODES.fetch(failed.first)) if failed.any?",
            "exit(1) if failed.any?",
            1,
        ),
    )
    for hostile in exit_hostiles:
        if hostile == restored:
            raise RuntimeError("Restored fixed-exit hostile mutation anchor is absent.")
        try:
            VALIDATOR.validate_restored_failure_exit_contract(hostile)
        except RuntimeError:
            continue
        raise RuntimeError("Restored-backup verifier accepted a forged or ambiguous failure exit.")

    validation = (ROOT / "docs/operations/VALIDATION.md").read_text(encoding="utf-8")
    for required in (
        "The disposable\n  restore requires exact `non-staff` mail suppression",
        "protected recovery may\n  require exact `yes`",
        "requires the restored site setting to equal the selected value",
        "the Restorer changes a restored `no` setting to `non-staff`",
    ):
        if required not in validation:
            raise RuntimeError("Restore mail-suppression documentation differs.")


def test_backup_restore_normal_upload_contract() -> None:
    marker = (ROOT / "scripts/prepare-backup-marker.rb").read_text(encoding="utf-8")
    restored = (ROOT / "scripts/verify-restored-backup.rb").read_text(encoding="utf-8")
    backup = (ROOT / "scripts/host-backup.sh").read_text(encoding="utf-8")
    restore = (ROOT / "scripts/host-restore-validate.sh").read_text(encoding="utf-8")
    finalizer = (ROOT / "scripts/finalize-member-rollout.sh").read_text(encoding="utf-8")
    publisher = (ROOT / "scripts/publish-disaster-recovery-evidence.rb").read_text(encoding="utf-8")
    fetcher = (ROOT / "scripts/fetch-disaster-recovery-evidence.rb").read_text(encoding="utf-8")
    release_fetcher = (ROOT / "scripts/fetch-disaster-recovery-release.rb").read_text(encoding="utf-8")
    historical_release = (ROOT / "scripts/historical-release-disaster-recovery.py").read_text(encoding="utf-8")
    clean_target = (ROOT / "scripts/verify-clean-disaster-target.rb").read_text(encoding="utf-8")
    runtime_assets = (ROOT / "scripts/verify-runtime-assets.sh").read_text(encoding="utf-8")
    deploy = (ROOT / "scripts/host-deploy.sh").read_text(encoding="utf-8")
    disposable = (ROOT / ".github/workflows/disposable-bootstrap.yml").read_text(encoding="utf-8")
    backup_transaction = (ROOT / "scripts/backup-transaction.py").read_text(encoding="utf-8")
    backup_transaction_fixture = (ROOT / "scripts/test-backup-transaction.py").read_text(encoding="utf-8")

    marker_required = (
        'STATE_KEYS = %w[',
        'backupOperationSha256',
        "UploadCreator.new(",
        'origin: transaction.fetch("uploadOrigin")',
        ").create_for(Discourse.system_user.id)",
        'upload.user_id == Discourse.system_user.id',
        'upload.secure == false',
        'upload.content == expected_bytes',
        'store.get_path_for_upload(upload) == state.fetch("objectPath")',
        'public_uri.host == "media-forums.mochirii.com"',
        'store.object_from_path(state.fetch("objectPath")).exists?',
        'store.object_from_path(state.fetch("tombstonePath")).exists?',
        'store.delete_file(state.fetch("objectPath"))',
        'store.delete_file(state.fetch("tombstonePath"))',
        'PluginStore.remove(RECOVERY_NAMESPACE, UPLOAD_STATE_KEY)',
        'bounded_absent!(store, state)',
    )
    if any(value not in marker for value in marker_required):
        raise RuntimeError("Normal-upload recovery fixture lost an exact row, object, content, host, or cleanup invariant.")
    if any(value in marker for value in ("delete_all", "delete_matching", "objects.each", "clear_bucket")):
        raise RuntimeError("Normal-upload recovery cleanup broadened beyond the exact disposable identity.")

    restored_required = (
        'ENV.fetch("MOCHIRII_EXPECTED_RECOVERY_UPLOAD_SHA256")',
        'Digest::SHA256.hexdigest(canonical + "\\n") == expected_state_sha',
        'Upload.find_by(id: state["uploadId"])',
        'upload.content == expected_bytes',
        'store.get_path_for_upload(upload) == state["objectPath"]',
        'public_uri.host == "media-forums.mochirii.com"',
        'store.object_from_path(state["objectPath"]).exists?',
        'store.object_from_path(state["tombstonePath"]).exists?',
    )
    if any(value not in restored for value in restored_required):
        raise RuntimeError("Restored normal-upload proof lost an exact state, row, byte, path, or custom-host check.")

    backup_order = (
        "MOCHIRII_RECOVERY_UPLOAD_ACTION=prepare",
        "run_container_command create-backup",
        "run_container_command verify-backup",
    )
    backup_positions = [backup.index(value) for value in backup_order]
    cleanup_position = backup.index(
        'if ! reconcile_backup_upload_journal "${backup_upload_journal}"; then',
        backup_positions[-1],
    )
    backup_positions.extend(
        backup.index(value, cleanup_position)
        for value in (
            '"recoveryUploadDeletedAfterBackup": recovery_deleted',
            "os.link(candidate, evidence, follow_symlinks=False)",
            'finish_backup_transaction "${backup_transaction_phase}" "${evidence}"',
        )
    )
    backup_positions.insert(3, cleanup_position)
    if backup_positions != sorted(backup_positions):
        raise RuntimeError("Backup evidence can publish before the exact recovery upload is backed up and cleaned.")
    restore_backup_fixture = (
        'document.get("schemaVersion") != 3',
        'document.get("recoveryUploadIncluded") is True',
        'document.get("recoveryUploadDeletedAfterBackup") is not True',
        'inventory_count = document.get("normalUploadInventoryCount")',
        'inventory_sha = document.get("normalUploadInventorySha256")',
    )
    if any(value not in restore for value in restore_backup_fixture):
        raise RuntimeError("Disposable restore accepts backup evidence without the tested normal-upload fixture.")

    restore_journal_keys = {
        "schemaVersion", "phase", "restoreMode", "recordedAt", "updatedAt", "repositoryCommit",
        "productionConfigurationSha256", "productionConfigurationFile", "productionConfigurationFileSha256",
        "restoreConfigurationFile", "restoreConfigurationSha256", "releaseEvidenceFile", "releaseEvidenceSha256",
        "testedBackupEvidenceFile", "testedBackupEvidenceSha256", "recoveryUploadIncluded",
        "recoveryUploadStateSha256", "normalUploadInventoryCount", "normalUploadInventorySha256",
        "cleanBackupIntentAt", "cleanBackupEvidenceFile", "cleanBackupEvidenceSha256",
        "cleanBackupFilename", "cleanBackupSha256", "restoreEvidenceFile", "restoreEvidenceSha256",
        "launcherOperationToken", "launcherPreviousImageId", "launcherReplacementImageId", "launcherCommand",
        "launcherConfigurationFile", "launcherConfigurationSha256", "launcherRestorePhase",
    }
    resume_start = restore.index("readarray -t resume_contract")
    resume_end = restore.index('print(document["phase"])', resume_start)
    resume_contract = restore[resume_start:resume_end]
    keys_match = re.search(r"required = \{(?P<body>.*?)\}\nif set\(document\) != required", resume_contract, re.S)
    if keys_match is None or set(re.findall(r'"([A-Za-z][A-Za-z0-9]+)"', keys_match.group("body"))) != restore_journal_keys:
        raise RuntimeError("Restore journal no longer validates its exact field inventory.")
    restore_launcher_fixture = (ROOT / "scripts/test-host-restore-launcher-journal.py").read_text(encoding="utf-8")
    for value in (
        'bind_launcher_replacement_image',
        'launcher_image_id_absent',
        '"launcherReplacementImageId"',
        'docker image rm --force "${durable_replacement}"',
        'restore journal replacement image identity cannot change',
        'env "MOCHIRII_RESTORE_LAUNCHER_OPERATION_TOKEN=${launcher_operation_token}"',
        'fields = pathlib.Path(f"/proc/{pid}/environ").read_bytes().split(b"\\0")',
        'terminate_launcher_marked_processes',
        'launcher_marked_processes_absent',
    ):
        if value not in restore:
            raise RuntimeError("Restore launcher lost its durable replacement-image reconciliation.")
    for value in (
        'post-image-swap replacement ID was not durably bound',
        'crash_action=post-delete',
        'post-CID-unlink or image-reconciliation crash changed launcher authority',
        'harmless-detached',
        'setsid bash -c',
        'if launcher_marked_processes_absent; then exit 60; fi',
        'if retire_launcher_journal; then exit 61; fi',
    ):
        if value not in restore_launcher_fixture:
            raise RuntimeError("Restore launcher immutable-set hostile fixture coverage differs.")
    journal_intent_contract = (
        'clean_phases = {',
        '(document["phase"] in clean_phases) != isinstance(clean_intent, str)',
        'clean_intent = existing.get("cleanBackupIntentAt") if existing else None',
        'if order[phase] >= order["clean-backup-creating"] and clean_intent is None:',
        'if order[phase] < order["clean-backup-creating"] and clean_intent is not None:',
        '"cleanBackupIntentAt": clean_intent',
        'journal.get("phase") != "clean-backup-creating"',
        'journal["cleanBackupIntentAt"]',
        'modified < intent.replace(microsecond=0)',
    )
    if any(value not in restore for value in journal_intent_contract):
        raise RuntimeError("Restore clean-backup intent is not stable, phase-bound, and adoption-bound.")

    fixtureless_start = restore.index(
        'if [[ ${recovery_upload_state_base64} == - && ${recovery_upload_state_sha256} == - ]]; then'
    )
    fixtureless_end = restore.index("\nfi\n", fixtureless_start)
    fixtureless_contract = restore[fixtureless_start:fixtureless_end]
    if (
        "recovery_upload_fixture=false" not in fixtureless_contract
        or '[[ ${disaster_restore} == true ]] || fail "A fixture-free backup is accepted only for clean-target disaster recovery."'
        not in fixtureless_contract
    ):
        raise RuntimeError("Fixture-less backup evidence is no longer restricted to a clean-target disaster restore.")

    retirement_start = restore.index('current_backup="${state_root}/current-backup.json"')
    retirement_end = restore.index('if [[ -e ${restore_journal} || -L ${restore_journal} ]]; then', retirement_start)
    retirement = restore[retirement_start:retirement_end]
    retirement_contract = (
        'mochirii-restore-backup-retirement-v1\\0{sys.argv[1]}\\0{sys.argv[2]}',
        '--operation-sha "${restore_retirement_sha}"',
        'backup_transaction_helper}" inspect-current',
        '${current_backup_contract[4]} == event-committed',
        'backup_transaction_helper}" retire-current',
        '[[ ! -e ${current_backup} && ! -L ${current_backup} ]]',
    )
    if any(value not in retirement for value in retirement_contract):
        raise RuntimeError("Restore no longer retires only an exact event-committed current-backup through its helper.")
    retirement_positions = [retirement.index(value) for value in retirement_contract[2:]]
    if retirement_positions != sorted(retirement_positions):
        raise RuntimeError("Restore can retire terminal backup state before exact inspection or omit absence proof.")

    restore_runtime = restore[restore.index("isolated=true") :]
    restored_environment = (
        'MOCHIRII_EXPECTED_NORMAL_UPLOAD_INVENTORY_COUNT="$2"',
        'MOCHIRII_EXPECTED_NORMAL_UPLOAD_INVENTORY_SHA256="$3"',
        '"${normal_upload_inventory_count}" "${normal_upload_inventory_sha256}"',
    )
    for operation in ("verify-restored-data", "verify-restored-restart", "verify-restored-rebuild"):
        matching_lines = [line for line in restore_runtime.splitlines() if f"run_container_command {operation} " in line]
        if len(matching_lines) != 1 or any(value not in matching_lines[0] for value in restored_environment):
            raise RuntimeError(f"{operation} lost its exact normal-upload inventory environment binding.")
    restore_order = (
        'discourse restore --location s3 "${backup_filename}"',
        "run_container_command verify-restored-data",
        "run_container_command verify-restored-restart",
        "run_container_command verify-restored-rebuild",
        "run_container_command cleanup-restored-upload",
        "advance_restore_phase clean-backup-creating",
        "run_container_command verify-clean-upload 600",
        "run_container_command capture-clean-upload-inventory",
        "run_container_command inspect-clean-backup",
        "run_container_command create-clean-backup",
        "run_container_command verify-clean-backup",
        "run_container_command reverify-clean-inventory",
        "run_container_command reverify-clean-upload",
        "run_container_command publish-clean-recovery",
        "os.link(backup_path, evidence, follow_symlinks=False)",
        "advance_restore_phase clean-backup-committed",
        'python3 -B - "${backup_pointer}" "${clean_backup_evidence}"',
        "advance_restore_phase pointer-committed",
        "advance_restore_phase production-reopening",
        'activate_config "${production_config}"',
        "run_launcher production-reopen rebuild app",
        'bash "${release_dir}/scripts/verify-host.sh" "${commit}" "${configuration}" --restore-transaction',
        "advance_restore_phase production-reopened",
        '"normalUploadRestorePassed": True',
        '"finalCleanBackupMarkerAbsent": True',
        "advance_restore_phase restore-evidence-committed",
        'record_event passed "${restore_evidence_sha256}"',
        "advance_restore_phase event-committed",
    )
    restore_positions = [restore_runtime.index(value) for value in restore_order]
    if restore_positions != sorted(restore_positions):
        raise RuntimeError("Restore cleanup, final clean backup, evidence, or pointer ordering changed.")

    finalizer_required = (
        'restore_terminal="${state_root}/current-restore.json"',
        'restore-transaction.json && ! -L ${state_root}/restore-transaction.json',
        '[[ "$(stat -c \'%U:%G %a\' "${restore_terminal}")" == "root:root 600" ]]',
        'set(terminal) != terminal_keys',
        'terminal.get("restoreMode") != "disposable-rehearsal"',
        'bound_evidence("testedBackupEvidenceFile", "testedBackupEvidenceSha256", "backup")',
        'bound_evidence("cleanBackupEvidenceFile", "cleanBackupEvidenceSha256", "backup")',
        'bound_evidence("restoreEvidenceFile", "restoreEvidenceSha256", "restore")',
        '"schemaVersion": 3',
        '"normalUploadRestorePassed": True',
        '"recoveryUploadCleanupPassed": True',
        '"finalCleanBackupMarkerAbsent": True',
        'tested.get("recoveryUploadIncluded") is not True',
        'tested.get("recoveryUploadStateSha256") != state_sha',
        'document.get("recoveryUploadIncluded") is not True',
        'document.get("recoveryUploadStateSha256") != state_sha',
        'document.get("testedNormalUploadInventoryCount") != tested_inventory_count',
        'clean.get("recoveryUploadIncluded") is not False',
        'document.get("finalCleanNormalUploadInventoryCount") != inventory_count',
        '"disasterRecoveryEvidencePublished", "disasterRecoveryPointerSelected", "disasterRecoveryPrivateAclPassed"',
        'backups/recovery-evidence/records/{dr_evidence_sha}.json',
        'clean.get("disasterRecoveryPointerObjectKey") != "backups/recovery-evidence/current.json"',
        'pointer_bytes != (str(clean_path) + "\\n").encode("utf-8")',
    )
    if any(value not in finalizer for value in finalizer_required):
        raise RuntimeError("Member rollout no longer requires the exact disposable terminal, restored upload, inventory, and final clean publication chain.")
    if any(value in finalizer for value in ('glob("*-restore.json")', "rglob(", "latest_restore", "latest-restore")):
        raise RuntimeError("Member rollout scans for a restore record instead of requiring the exact current-restore terminal.")

    for runtime_script in (
        "fetch-disaster-recovery-evidence.rb",
        "publish-disaster-recovery-evidence.rb",
        "verify-clean-disaster-target.rb",
    ):
        if deploy.count(runtime_script) != 2 or runtime_assets.count(runtime_script) != 2 or disposable.count(runtime_script) != 1:
            raise RuntimeError(f"Disaster-recovery runtime asset inventory differs: {runtime_script}")
    if deploy.count("fetch-disaster-recovery-release.rb") != 2 or runtime_assets.count("fetch-disaster-recovery-release.rb") != 2 or disposable.count("fetch-disaster-recovery-release.rb") != 3:
        raise RuntimeError("Historical release fetcher runtime asset or pinned fixture inventory differs.")
    for value in (
        "mochirii-release.tar",
        "test-disaster-recovery-release-chain.rb",
        "test-historical-recovery-scratch-reader.py",
        "test-historical-release-disaster-recovery.py",
        "test-disposable-launcher-guard.py",
        "test-host-restore-launcher-journal.py",
        "test-host-operation-lock.py",
    ):
        if value not in disposable:
            raise RuntimeError(f"Historical release disposable fixture registration differs: {value}")
    for value in ("mochirii-release.tar", "repositoryTree", "releaseArchiveBytes", "releaseArchiveContentManifestSha256"):
        if value not in deploy or value not in runtime_assets:
            raise RuntimeError(f"Immutable release runtime authority differs: {value}")
    for operation in (backup, restore):
        required_release_publication = (
            '"schemaVersion": 2', '"repositoryTree"', '"releaseArchiveBytes"',
            '"releaseArchiveContentManifestSha256"', '"releaseArchiveContainsSecrets": False',
            '"ordinaryDeploymentRequiresCurrentMain": True',
            '"historicalReleaseAdoptionScope": "clean-target-disaster-recovery-only"',
            'result.get("schemaVersion") != 2',
        )
        if any(value not in operation for value in required_release_publication):
            raise RuntimeError("Backup/restore immutable release publication contract differs.")
    for consumer_name in (
        "authentication-state.py", "host-finalize-authentication.sh",
        "host-verify-wrapper.sh", "verify-host.sh",
    ):
        consumer = (ROOT / "scripts" / consumer_name).read_text(encoding="utf-8")
        if any(value not in consumer for value in ("repositoryTree", "releaseArchiveBytes", "releaseArchiveContentManifestSha256")):
            raise RuntimeError(f"Release evidence consumer lacks immutable archive authority: {consumer_name}")
    if "Ordinary deployment refuses an active historical disaster-recovery adoption." not in deploy:
        raise RuntimeError("Ordinary deployment can overlap historical disaster-recovery adoption.")
    if deploy.count("backup-transaction.py") != 2 or runtime_assets.count("backup-transaction.py") != 2 or disposable.count("backup-transaction.py") != 2:
        raise RuntimeError("Durable backup transaction helper or hostile fixture registration differs.")
    if deploy.count("normal-upload-inventory.rb") != 2 or runtime_assets.count("normal-upload-inventory.rb") != 2 or disposable.count("normal-upload-inventory.rb") != 2:
        raise RuntimeError("Normal-upload inventory runtime asset registration differs.")
    private_publication = (
        'S3Helper.build_from_config(for_backup: true)',
        'relative_evidence_key = "recovery-evidence/records/#{evidence_sha}.json"',
        'acl: "private"',
        'cache_control: "no-store"',
        'private_object!(object)',
        'document["containsSecrets"] == false',
        'document["containsSignedUrls"] == false',
        'bounded_read(object) == payload',
        'document["schemaVersion"] == 2',
        'releaseArchiveContainsSecrets',
        'ordinaryDeploymentRequiresCurrentMain',
        'historicalReleaseAdoptionScope',
        'recovery-releases/archives/',
        'recovery-releases/authorities/',
        '"schemaVersion" => 2',
    )
    if any(value not in publisher for value in private_publication):
        raise RuntimeError("Private off-host recovery evidence publication boundary differs.")
    private_fetch = (
        'MAX_DOCUMENT_BYTES = 32 * 1024',
        'private_object!(pointer_object)',
        'private_object!(evidence_object)',
        'grants.length == 1',
        'grants.first.permission == "FULL_CONTROL"',
        'grants.first.grantee&.type == "CanonicalUser"',
        'grants.first.grantee&.id.to_s == owner_id',
        'fail_fetch("object ACL is not exact private owner-only") unless exact_private',
        'Digest::SHA256.hexdigest(evidence_bytes) == pointer["evidenceObjectSha256"]',
        'source["cleanHostAdoptionRequiresEmptyPersistentData"] == true',
        'source["containsSecrets"] == false',
        'source["containsSignedUrls"] == false',
        '"normalUploadInventoryCount" => source["normalUploadInventoryCount"]',
        '"normalUploadInventorySha256" => source["normalUploadInventorySha256"]',
        'Digest::SHA256.hexdigest(core_bytes) == source["backupEvidenceCoreSha256"]',
        '"disasterRecoveryImported" => true',
        '"disasterRecoveryPrivateAclPassed" => true',
        'fetch_mode = ENV.fetch("MOCHIRII_DR_FETCH_MODE", "current-release")',
        '"disasterRecoveryBootstrapCommit" => bootstrap_commit',
        '"disasterRecoveryRepositoryTree" => source["repositoryTree"]',
        '"disasterRecoveryReleaseArchiveContentManifestSha256" => source["releaseArchiveContentManifestSha256"]',
    )
    if any(value not in fetcher for value in private_fetch):
        raise RuntimeError("Private off-host recovery evidence fetch boundary differs.")
    release_fetch_required = (
        'private_object!(pointer_object)',
        'private_object!(authority_object)',
        'private_object!(archive_object)',
        'fail_release_fetch("object ACL is not exact private owner-only")',
        'MAX_RELEASE_ARCHIVE_BYTES = 64 * 1024 * 1024',
        'receipt["disasterRecoveryFetchMode"] == "clean-target-historical"',
        'bootstrap_commit != commit',
        'ordinaryDeploymentRequiresCurrentMain',
        'historicalReleaseAdoptionScope',
        'digest.hexdigest == archive_sha',
    )
    if any(value not in release_fetcher for value in release_fetch_required):
        raise RuntimeError("Private immutable historical release fetch boundary differs.")
    historical_required = (
        'ARCHIVE_FORMAT = "git-archive-tar-v1"',
        'ADOPTION_SCOPE = "clean-target-disaster-recovery-only"',
        'ordinaryDeploymentRequiresCurrentMain',
        'historical-release-adoption.json',
        '"phase": "source-prepared"',
        '"phase": "configuration-authorized"',
        'tree != identity.repository_tree or manifest != identity.content_manifest_sha256',
        'PREPARE HISTORICAL MOCHIRII FORUMS DISASTER RELEASE',
        'AUTHORIZE HISTORICAL MOCHIRII FORUMS DISASTER RELEASE',
    )
    if any(value not in historical_release for value in historical_required):
        raise RuntimeError("Provenance-bound historical release adoption contract differs.")
    fetch_core_order = (
        '"normalUploadInventoryCount" => source["normalUploadInventoryCount"]',
        '"normalUploadInventorySha256" => source["normalUploadInventorySha256"]',
        "core_bytes = JSON.pretty_generate(core_document.sort.to_h)",
        'Digest::SHA256.hexdigest(core_bytes) == source["backupEvidenceCoreSha256"]',
        '"disasterRecoveryImported" => true',
    )
    if [fetcher.index(value) for value in fetch_core_order] != sorted(fetcher.index(value) for value in fetch_core_order):
        raise RuntimeError("Fetched disaster-recovery inventory is not reconstructed into the pre-publication core digest.")
    clean_checks = (
        'User.where("id > 0").none?', 'Post.where("user_id > 0").none?',
        'Topic.where("user_id > 0").none?', 'Upload.none?', 'ApiKey.none?',
        'UserApiKey.none?', 'PluginStore.get("mochirii-recovery", "repository_commit").nil?',
        'PluginStore.get("mochirii-recovery", "normal_upload_marker").nil?',
    )
    if any(value not in clean_target for value in clean_checks):
        raise RuntimeError("Clean-target disaster restore guard differs.")
    clean_position = restore.index('verify-clean-disaster-target.rb')
    fetch_position = restore.index('fetch-disaster-recovery-evidence.rb', clean_position)
    restore_position = restore.index('discourse restore --location s3 "${backup_filename}"', fetch_position)
    if not clean_position < fetch_position < restore_position:
        raise RuntimeError("Private recovery evidence can be fetched or restored before the clean-target guard.")

    backup_publish = backup[backup.index('python3 -B - "${candidate}" "${evidence}"') : backup.index('candidate=""', backup.index('python3 -B - "${candidate}" "${evidence}"'))]
    publish_order = (
        "os.fsync(descriptor)",
        "os.link(candidate, evidence, follow_symlinks=False)",
        "os.fsync(directory)",
        "candidate.unlink()",
    )
    positions = [backup_publish.index(value) for value in publish_order]
    if positions != sorted(positions):
        raise RuntimeError("Backup evidence can report success without durable no-replace file and parent commits.")

    terminal = backup[backup.index("finish_backup_transaction() {") : backup.index("validate_backup_upload_journal()")]
    terminal_order = (
        "backup_transaction_command evidence-sha",
        "backup_transaction_command select-pointer",
        "backup_transaction_command publish-phase --phase pointer-committed",
        'record_event passed "${evidence_sha}"',
        "backup_transaction_command publish-phase --phase event-committed",
        "backup_transaction_command clear",
    )
    terminal_positions = [terminal.index(value) for value in terminal_order]
    if terminal_positions != sorted(terminal_positions):
        raise RuntimeError("Backup pointer, passed event, terminal record, or journal clearance ordering differs.")
    helper_required = (
        "backupOperationSha256",
        "previousLatestEvidenceFile", "previousLatestPointerSha256",
        'if current_file == evidence.name and current_sha == target_sha:',
        'fail("latest-backup pointer changed outside this transaction")',
        'atomic_write(args.pointer, target_payload, replace=current_file is not None)',
        'if transaction["phase"] != "event-committed":',
        'if args.current.exists() or args.current.is_symlink():',
        'fail("terminal current-backup must be retired before a new transaction")',
        'document["backupOperationSha256"] != args.operation_sha',
        'validate_terminal_current(',
        'if document["backupOperationSha256"] == args.operation_sha:',
        'fail("current-backup cannot be retired by its own operation")',
        "args.transaction.unlink()", "os.fsync(directory)",
        '"runtimeRecoveryPhase"',
        '"cleanup-pending"', '"restart-authorized"', '"cleanup-proved"',
        "validate_backup_upload_journal(",
        "action_bind_cleanup", "action_authorize_restart",
        "action_complete_cleanup", "action_resume_runtime", "action_retire_prepared",
        'fail("backup runtime cannot resume before cleanup journal retirement")',
        'fail("prepared backup ownership cannot retire before terminal runtime restoration")',
        '"originalRuntimeState"', '"runtimeIdentitySha256"', '"currentReleaseSha256"',
        '"discourseRevision"', '"dockerManagerRevision"', '"runtimeEnvironmentSha256"',
        '"runtimePortBindingsSha256"', '"runtimeContainerImage"', '"runtimeOperationPhase"',
        "action_arm_operation", "action_complete_operation", "action_prove_operation_absent",
        "action_complete_restart", "action_authorize_initial_start", "action_complete_initial_start",
        "action_contain_temporary_runtime", "action_authorize_original_stop", "action_complete_original_state",
    )
    if any(value not in backup_transaction for value in helper_required):
        raise RuntimeError("Durable backup transaction lost operation identity, predecessor, adoption, retirement, terminal-phase, or parent-fsync enforcement.")

    host_backup_operation = (
        '[[ $# -eq 2 ]] || fail "Usage: host-backup.sh EXPECTED_COMMIT BACKUP_OPERATION_SHA256"',
        '[[ ${backup_operation_sha} =~ ^[0-9a-f]{64}$ ]]',
        '--operation-sha "${backup_operation_sha}"',
        'backup_transaction_command inspect-current',
        'if [[ ${current_backup_operation} == "${backup_operation_sha}" ]]; then',
        'backup_transaction_command adopt-current',
        '[[ ${current_backup_phase} == event-committed ]]',
        'backup_transaction_command retire-current',
        'backup_transaction_command create',
        'backup_runtime_recovery_command bind-cleanup',
        'backup_runtime_recovery_command complete-cleanup',
        'backup_runtime_recovery_command resume-runtime',
        'backup_runtime_operation_command arm-operation',
        'backup_runtime_operation_command complete-operation',
        'backup_runtime_operation_command prove-operation-absent',
        'backup_runtime_operation_command complete-restart',
        'restore_original_runtime_state',
        'start_app_for_backup_recovery',
    )
    if any(value not in backup for value in host_backup_operation):
        raise RuntimeError("Protected backup caller identity adoption/retirement contract differs.")
    operation_flow = backup[backup.index('if [[ -e ${current_backup} || -L ${current_backup} ]]; then') :]
    operation_positions = [operation_flow.index(value) for value in (
        'backup_transaction_command inspect-current',
        'backup_transaction_command adopt-current',
        'backup_transaction_command retire-current',
        'backup_transaction_command create',
    )]
    if operation_positions != sorted(operation_positions):
        raise RuntimeError("Backup can create a new transaction before terminal operation adoption or retirement.")
    operation_fixture_required = (
        "Same-operation terminal backup was not adopted.",
        "different operation retired an intervened pointer",
        "New backup transaction did not bind its caller operation.",
        "current receipt advanced two commit points",
        "same operation retired its terminal receipt",
        "new operation prearmed before terminal receipt retirement",
        "stopped recovery accepted a changed operation token",
        "crash-recovered backup resumed before journal retirement",
        "Stopped upload-cleanup recovery did not resume exactly.",
        "Post-cleanup SIGKILL lost exact runtime ownership.",
        "post-cleanup recovery accepted changed ports",
        "Post-rollout timeout lost journal-free operation ownership.",
        "idle journal-free backup gained generic restart authority",
        "Stopped-origin runtime was not durably restored.",
    )
    if any(value not in backup_transaction_fixture for value in operation_fixture_required):
        raise RuntimeError("Backup operation-identity hostile fixtures differ.")

    restore_evidence_start = restore.index('python3 - "${restore_evidence}" "${backup_evidence}"')
    restore_evidence = restore[restore_evidence_start : restore.index('  restore_evidence_sha256=', restore_evidence_start)]
    if restore_evidence.index("os.link(temporary, path, follow_symlinks=False)") > restore_evidence.index("os.fsync(directory)"):
        raise RuntimeError("Restore evidence parent fsync precedes its no-replace publication.")
    deterministic_identity = restore[
        restore.index('readarray -t restore_identity < <(python3 -B - "${restore_journal}"') : restore_evidence_start
    ]
    deterministic_required = (
        'clean_name = pathlib.Path(sys.argv[2]).name',
        'journal["recordedAt"]',
        'print(match.group(1))',
        'restore_evidence="${evidence_root}/${commit}-${configuration}-${restore_identity[0]}-restore.json"',
    )
    if any(value not in deterministic_identity for value in deterministic_required):
        raise RuntimeError("Restore evidence identity is no longer derived deterministically from durable journal and clean-backup state.")
    adoption_required = (
        'if path.exists() or path.is_symlink():',
        'path.read_bytes() != temporary.read_bytes()',
        'raise SystemExit("existing restore evidence differs")',
        'os.link(temporary, path, follow_symlinks=False)',
        'if temporary.exists():',
        'temporary.unlink()',
    )
    if any(value not in restore_evidence for value in adoption_required):
        raise RuntimeError("Restore evidence retry does not exact-adopt only deterministic existing bytes.")


def test_public_branding_signed_credential_boundary() -> None:
    hostile = (
        "X-Amz-Credential=fixture/20260815/sgp1/s3/aws4_request",
        "x-aMz-SiGnAtUrE=deadbeef",
        "X-AMZ-SECURITY-TOKEN=fixture",
        "AWSAccessKeyId=fixture",
        "Signature=deadbeef",
        "X%2dAmz%2dCredential%3dfixture",
        "x&#45;amz&#45;signature=deadbeef",
        r'{"X\u002dAmz\u002dSecurity\u002dToken":"fixture"}',
        "X%26%2345%3BAmz%26%2345%3BCredential=fixture",
    )
    for value in hostile:
        if not PUBLIC_BRANDING.exposes_signed_credential(value):
            raise RuntimeError(f"Public branding accepted an encoded signed credential marker: {value}")
    accepted = (
        "x-amz-request-id: fixture-request-id",
        "X-AMZ-REQUEST-ID=fixture-request-id",
        "x%2damz%2drequest%2did=fixture-request-id",
    )
    if any(PUBLIC_BRANDING.exposes_signed_credential(value) for value in accepted):
        raise RuntimeError("Public branding rejected neutral x-amz-request-id transport metadata.")


def test_atomic_operator_evidence_publication_contract() -> None:
    member = (ROOT / "scripts/finalize-member-rollout.sh").read_text(encoding="utf-8")
    authentication = (ROOT / "scripts/host-finalize-authentication.sh").read_text(encoding="utf-8")
    stop = (ROOT / "scripts/host-stop-pending-activation.sh").read_text(encoding="utf-8")
    deploy = (ROOT / "scripts/host-deploy.sh").read_text(encoding="utf-8")
    for label, source in (
        ("member-rollout marker", member),
        ("authentication complete record", authentication),
        ("operator containment record", stop),
        ("deployment immutable evidence", deploy),
    ):
        if "os.link(candidate, path, follow_symlinks=False)" not in source:
            raise RuntimeError(f"{label} is visible at its final name before a complete fsynced no-replace publication.")
        if "partial is unsafe" not in source or "os.fsync(directory)" not in source:
            raise RuntimeError(f"{label} lacks bounded stale-partial reconciliation or parent durability.")
        direct_final_writes = list(
            re.finditer(r"os[.]open\(path, os[.]O_WRONLY[^\n]*os[.]O_EXCL", source)
        )
        if direct_final_writes:
            if label != "deployment immutable evidence" or len(direct_final_writes) != 1:
                raise RuntimeError(f"{label} still writes directly into a final immutable filename.")
            prefix = source[max(0, direct_final_writes[0].start() - 250) : direct_final_writes[0].start()]
            if "storage-cleanup-required.json" not in prefix:
                raise RuntimeError("Deployment evidence gained an unreviewed direct-final publication.")
    if deploy.count("os.link(candidate, path, follow_symlinks=False)") < 4:
        raise RuntimeError("Storage, release, pending-authentication, or activation-failure evidence escaped atomic no-replace publication.")
    if stop.count("os.link(candidate, path, follow_symlinks=False)") < 2:
        raise RuntimeError("One operator containment transition still exposes a partial final-name record.")

    member_publish = member[member.index("candidate = path.parent / f\".{path.name}.partial\"") : member.index("[[ \"$(stat -c", member.index("candidate = path.parent / f\".{path.name}.partial\""))]
    for value in (
        "discard_safe_partial()",
        "if path.exists() or path.is_symlink():",
        'set(document) != set(expected) | {"finalizedAt"}',
        "any(document.get(key) != value for key, value in expected.items())",
        "os.fsync(target.fileno())",
        "os.link(candidate, path, follow_symlinks=False)",
        "candidate.unlink()",
    ):
        if value not in member_publish:
            raise RuntimeError("Member-rollout crash recovery lost exact-existing or partial-publication handling.")

    complete_validation = authentication[authentication.index("resume_complete = False") : authentication.index("print(release_name)")]
    if (
        complete_validation.index("if complete_path.exists() or complete_path.is_symlink():")
        > complete_validation.index("if not resume_complete and")
        or 'expected_complete = {' not in complete_validation
        or 'complete.get("websiteRepositoryCommit") != website.get("websiteRepositoryCommit")' not in complete_validation
    ):
        raise RuntimeError("Authentication record-created/pointer-pending resume still depends on fresh or conflicting Website evidence.")
    complete_publish = authentication[authentication.index('python3 -B - "${authentication_record}"') : authentication.index('[[ "$(stat -c', authentication.index('python3 -B - "${authentication_record}"'))]
    if "if path.exists() or path.is_symlink():" not in complete_publish or "os.link(candidate, path, follow_symlinks=False)" not in complete_publish:
        raise RuntimeError("Authentication complete evidence is not exact-existing idempotent after record-before-pointer interruption.")
    break_glass = (ROOT / "scripts/host-break-glass-admin.sh").read_text(encoding="utf-8")
    verify_wrapper = (ROOT / "scripts/host-verify-wrapper.sh").read_text(encoding="utf-8")
    bounded_reads = {
        "member rollout": (member, "timeout --signal=TERM --kill-after=5s 30 docker exec app"),
        "authentication finalization": (authentication, "timeout --signal=TERM --kill-after=5s 30 docker exec app"),
        "administrator recovery": (break_glass, "timeout --signal=TERM --kill-after=5s 30 docker exec app"),
        "stable host verification": (verify_wrapper, "timeout --signal=TERM --kill-after=5s 30 docker exec app"),
    }
    for label, (source, required) in bounded_reads.items():
        direct_reads = [line.strip() for line in source.splitlines() if "docker exec app bash -lc" in line]
        if not direct_reads or any(required not in line for line in direct_reads):
            raise RuntimeError(f"{label} holds the global lock across an unbounded Docker readback.")
    deployment_reads = [line.strip() for line in deploy.splitlines() if "docker exec app bash -lc" in line]
    if not deployment_reads or any(
        "timeout --signal=TERM --kill-after=" not in line for line in deployment_reads
    ):
        raise RuntimeError("Deployment recovery holds the global lock across an unbounded Docker readback.")


def test_deployment_terminal_transaction_contract() -> None:
    deploy = (ROOT / "scripts/host-deploy.sh").read_text(encoding="utf-8")
    backup = (ROOT / "scripts/host-backup.sh").read_text(encoding="utf-8")
    restore = (ROOT / "scripts/host-restore-validate.sh").read_text(encoding="utf-8")
    verifier = (ROOT / "scripts/verify-host.sh").read_text(encoding="utf-8")
    wrapper = (ROOT / "scripts/host-verify-wrapper.sh").read_text(encoding="utf-8")
    authentication = (ROOT / "scripts/host-finalize-authentication.sh").read_text(encoding="utf-8")
    stop = (ROOT / "scripts/host-stop-pending-activation.sh").read_text(encoding="utf-8")
    break_glass = (ROOT / "scripts/host-break-glass-admin.sh").read_text(encoding="utf-8")

    deploy_required = (
        'readonly deployment_transaction="/var/lib/mochirii/forums/deployment-transaction.json"',
        'readonly deployment_terminal="/var/lib/mochirii/forums/current-deployment.json"',
        'order = {"prepared": 10, "state-committed": 20, "event-committed": 30}',
        'phase not in {"prepared", "state-committed", "event-committed"}',
        'source.get("phase") != "event-committed"',
        'document["phase"] = "complete"',
        'an active deployment transaction belongs to another exact operation',
        'deployment transaction stable field differs: {key}',
        'deployment member marker binding differs',
        'deployment authentication binding differs',
        'Active deployment transaction authentication state differs from its exact retry contract.',
        'run_release_verification "${previous_release}" "${previous_configuration}" --deployment-prior-rollback || return 1',
    )
    if any(value not in deploy for value in deploy_required):
        raise RuntimeError("Deployment terminal schema, exact-tuple adoption, or fail-closed retry contract differs.")

    mutation_verified = deploy.rindex("mark_deployment_mutation_verified")
    prearm = deploy.rindex("write_deployment_transaction prepared")
    armed = deploy.rindex("deployment_commit_armed=true", 0, prearm)
    completion_call = deploy.index("complete_deployment_commit prepared", prearm)
    if not mutation_verified < armed < prearm < completion_call:
        raise RuntimeError("Deployment publication is not conservatively armed before its durable prepared transaction.")
    completion = deploy[deploy.index("complete_deployment_commit() {") : deploy.index("seal_activation_deploy_failure() {")]
    completion_order = (
        'ln -sfn -- "${release_dir}" /opt/mochirii/forums/current.next',
        'write_current_evidence "${commit}" "${configuration_id}"',
        'finish_deployment_authentication "${authentication_action}"',
        'run_release_verification "${commit}" "${configuration_id}" --deployment-transaction',
        'write_deployment_transaction state-committed',
        'record_event deployment passed',
        'write_deployment_transaction event-committed',
        "publish_deployment_terminal",
        "clear_deployment_transaction",
    )
    completion_positions = [completion.index(value) for value in completion_order]
    if completion_positions != sorted(completion_positions):
        raise RuntimeError("Deployment state, durable event, terminal record, or journal clearance ordering differs.")
    for required in (
        '<<\'PY\' >/dev/null || return 1',
        'ln -sfn -- "${release_dir}" /opt/mochirii/forums/current.next || return 1',
        'mv -Tf -- /opt/mochirii/forums/current.next /opt/mochirii/forums/current || return 1',
        'fsync_directory /opt/mochirii/forums || return 1',
        '"${requested_discourse_connect}" "${marker_file_for_evidence}" "${marker_sha_for_evidence}" || return 1',
    ):
        if required not in completion:
            raise RuntimeError("Deployment terminal publication can mask a durable mutation failure.")
    forward_fix_publication = deploy[
        deploy.index("seal_forward_fix_required() {") : deploy.index("validate_forward_fix_retry() {")
    ]
    for required in (
        'activate_config "${config_dir}/app.yml" || return 1',
        'current_sha="$(sha256sum -- /var/lib/mochirii/forums/current-release.json | awk \'{print $1}\')" || return 1',
        "<<'PY' || return 1",
        "return 0",
    ):
        if required not in forward_fix_publication:
            raise RuntimeError("Forward-fix containment can mask its durable journal publication failure.")
    activation_failure_publication = deploy[
        deploy.index("seal_activation_deploy_failure() {") : deploy.index("recover_failed_activation() {")
    ]
    for required in (
        'activate_config "${previous_config}" || return 1',
        'record_sha="$(sha256sum -- "${record}" | awk \'{print $1}\')" || return 1',
        "<<'PY' || return 1",
        "return 0",
    ):
        if required not in activation_failure_publication:
            raise RuntimeError("Activation containment can mask its durable evidence or pointer publication failure.")
    terminal_retry = completion.index('if [[ ${phase} == complete ]]')
    terminal_verify = completion.index('run_release_verification "${commit}" "${configuration_id}" || return 1', terminal_retry)
    active_verify = completion.index('run_release_verification "${commit}" "${configuration_id}" --deployment-transaction', terminal_verify)
    if not terminal_retry < terminal_verify < active_verify:
        raise RuntimeError("Completed deployment adoption incorrectly claims ownership of a retired transaction journal.")

    adoption = deploy.index("readarray -t deployment_resume < <(deployment_state_contract)")
    bootstrap_precondition = deploy.index('if [[ ${mode} == bootstrap ]]; then', adoption)
    storage_fixture = deploy.index("run_storage_fixture create", bootstrap_precondition)
    if not adoption < bootstrap_precondition < storage_fixture:
        raise RuntimeError("Deployment retry adoption occurs after bootstrap or hosted-storage side effects.")

    deployment_docs = (ROOT / "docs/operations/DEPLOYMENT.md").read_text(encoding="utf-8")
    recovery_docs = (ROOT / "docs/operations/RECOVERY.md").read_text(encoding="utf-8")
    validation_docs = (ROOT / "docs/operations/VALIDATION.md").read_text(encoding="utf-8")
    documentation_required = {
        "deployment": (
            deployment_docs,
            (
                "leaves the mutation journal for the",
                "SHA-256 of the exact current-release bytes",
                "without its exact same-tuple deployment-mutation",
                "failure containment is conservatively armed before the",
                "prior-rollback owner accepts only a mutation-only `rebuild` journal",
                "refuses an existing container, database, active configuration, current-release",
            ),
        ),
        "recovery": (
            recovery_docs,
            (
                "leaves deployment ownership intact",
                "An orphan hosted-storage",
                "cleanup journal is never mutation authority.",
                "same-version/no-target-migration rollback",
            ),
        ),
        "validation": (
            validation_docs,
            (
                "prior-rollback owner may name only a mutation-only exact sealed prior tuple",
                "Mutation plus promotion",
                "exact `/opt/mochirii/forums/current` symlink target",
            ),
        ),
    }
    for label, (document, required_fragments) in documentation_required.items():
        if any(fragment not in document for fragment in required_fragments):
            raise RuntimeError(f"Deployment mutation {label} documentation differs.")

    cross_refusals = {
        "deployment": (deploy, "backup-transaction.json", "restore-transaction.json"),
        "backup": (backup, "deployment-transaction.json", "restore-transaction.json"),
        "restore": (restore, "deployment-transaction.json", "backup-transaction.json"),
    }
    for label, (source, first, second) in cross_refusals.items():
        if first not in source or second not in source or "deployment-mutation.json" not in source:
            raise RuntimeError(f"{label} lost an active cross-operation transaction refusal.")
    for label, source in (
        ("authentication finalization", authentication),
        ("administrator recovery", break_glass),
    ):
        if any(name not in source for name in ("deployment-transaction.json", "deployment-mutation.json", "backup-transaction.json", "restore-transaction.json")):
            raise RuntimeError(f"{label} no longer refuses every active protected host transaction.")
    for value in (
        "deployment-transaction.json",
        "backup-transaction.json",
        "restore-transaction.json",
        'if [[ ${authentication_phase} == activation-deploy-failed-producer-unproved && ${deployment_mutation_active} != true ]]; then',
        "Activation failure producer reconciliation requires its exact deployment mutation journal.",
        'if [[ ${deployment_mutation_active} == true && ${authentication_phase} != activation-deploy-failed-producer-unproved ]]; then',
        "deployment mutation stopped retry tuple differs",
        'mutation.get("phase") != "runtime-contained"',
        'mutation.get("activeConfigurationFile") != str(previous_app)',
        'mutation.get("previousCurrentReleaseSha256") != hashlib.sha256(current_bytes).hexdigest()',
        'validate_mutation(pathlib.Path(mutation_argument))',
    ):
        if value not in stop:
            raise RuntimeError("Pending activation containment lost its exact mutation-bound recovery exception.")
    mutation_required = stop.index(
        'if [[ ${authentication_phase} == activation-deploy-failed-producer-unproved && ${deployment_mutation_active} != true ]]; then'
    )
    failed_activation_branch = stop.index(
        'if [[ ${authentication_phase} == activation-deploy-failed-producer-unproved ]]; then', mutation_required
    )
    exact_mutation_argument = stop.index(
        '"${configuration}" "${deployment_mutation}" <<\'PY\'', failed_activation_branch
    )
    unconditional_mutation_validation = stop.index(
        "validate_mutation(pathlib.Path(mutation_argument))", exact_mutation_argument
    )
    failed_activation_cardinality = stop.index(
        '[[ ${#evidence[@]} -eq 6', unconditional_mutation_validation
    )
    first_failed_activation_stop = stop.index('docker stop --time 30 app', failed_activation_cardinality)
    if not (
        mutation_required
        < failed_activation_branch
        < exact_mutation_argument
        < unconditional_mutation_validation
        < failed_activation_cardinality
        < first_failed_activation_stop
    ):
        raise RuntimeError("Activation failure producer reconciliation can bypass exact mutation validation before containment.")

    verifier_required = (
        '[--deployment-transaction|--deployment-prior-rollback|--restore-transaction]',
        '"standalone": {frozenset()}',
        'frozenset({"deployment-mutation"})',
        'frozenset({"deployment", "deployment-mutation"})',
        '"--deployment-prior-rollback": {frozenset({"deployment-mutation"})}',
        '"--restore-transaction": {frozenset({"restore"})}',
        'active host-operation transaction inventory differs from the verifier owner',
        'deployment mutation journal tuple, schema, path, or phase differs',
        'deployment mutation launcher identity is incomplete',
        'deployment mutation launcher token or command differs',
        'deployment prior-rollback owner differs from the mutation journal',
        'deployment prior-rollback runtime state differs',
        'deployment promotion requires a verified mutation journal',
        'verified deployment mutation lacks its completed terminal record',
        'completed_terminal_matches_expected = (',
        'active["deployment"] or mutation_phase != "verified"',
        'published current release target differs from the verifier owner',
        'deployment transaction tuple or phase differs',
        'restore transaction tuple or phase differs',
        '"cleanBackupIntentAt"',
        'restore transaction clean-backup intent differs',
        'completed deployment record schema or identity differs',
        'completed deployment release evidence differs',
        'completed deployment differs from current release evidence',
        'completed deployment member marker transition differs',
        'current member-rollout marker differs',
        'current authentication evidence record differs',
        'completed deployment authentication transition differs',
        'completed deployment authentication release binding differs',
        'marker_transition = (',
        'allow_authentication_transition and action == "pending"',
        'set(release_document) != release_keys',
        'require_disabled_authentication_absent=True',
    )
    if any(value not in verifier for value in verifier_required):
        raise RuntimeError("Hosted verification transaction owner, terminal, marker, or authentication boundary differs.")
    if '--deployment-transaction' in wrapper or '--restore-transaction' in wrapper:
        raise RuntimeError("Stable standalone host verification can adopt another operation's active journal.")
    if 'bash "${release_dir}/scripts/verify-host.sh" "${commit}" "${configuration}" --restore-transaction' not in restore:
        raise RuntimeError("Restore does not identify its exact active journal to hosted verification.")


def test_deployment_runtime_mutation_contract() -> None:
    deploy = (ROOT / "scripts/host-deploy.sh").read_text(encoding="utf-8")
    restore = (ROOT / "scripts/host-restore-validate.sh").read_text(encoding="utf-8")
    helper = (ROOT / "scripts/deployment-mutation.py").read_text(encoding="utf-8")
    fixture = (ROOT / "scripts/test-deployment-mutation.py").read_text(encoding="utf-8")
    disposable = (ROOT / ".github/workflows/disposable-bootstrap.yml").read_text(encoding="utf-8")
    deployment_docs = (ROOT / "docs/operations/DEPLOYMENT.md").read_text(encoding="utf-8")
    recovery_docs = (ROOT / "docs/operations/RECOVERY.md").read_text(encoding="utf-8")
    validation_docs = (ROOT / "docs/operations/VALIDATION.md").read_text(encoding="utf-8")

    required_deploy = (
        'readonly deployment_mutation_journal="/var/lib/mochirii/forums/deployment-mutation.json"',
        'create_deployment_mutation || fail "Deployment runtime mutation journal could not be durably pre-armed."',
        'deployment_mutation set-config --path "${deployment_mutation_journal}"',
        'deployment_mutation arm-launcher --path "${deployment_mutation_journal}"',
        'deployment_mutation finish-launcher --path "${deployment_mutation_journal}"',
        'readarray -t deployment_mutation_contract < <(inspect_deployment_mutation)',
        'mark_deployment_mutation_contained',
        'mark_deployment_mutation_verified',
        'clear_deployment_mutation',
        'Deployment terminal publication exists without a verified runtime-mutation journal.',
        'Interrupted launcher mutation could not be reconciled safely.',
        'deployment_mutation mark-contained --path "${deployment_mutation_journal}" || return 1',
        'deployment_mutation mark-verified --path "${deployment_mutation_journal}" || return 1',
        'Deployment mutation prior current-release bytes differ from their sealed digest.',
        'Pending hosted storage cleanup lacks its exact deployment mutation authority.',
        'Bootstrap mode refuses existing current-release evidence.',
        'Bootstrap mode refuses an existing current-release target.',
    )
    if any(value not in deploy for value in required_deploy):
        raise RuntimeError("Deployment runtime mutation journal integration differs.")
    prearm = deploy.index('create_deployment_mutation || fail "Deployment runtime mutation journal could not be durably pre-armed."')
    first_target_switch = deploy.index('activate_config "${config_dir}/activation.yml"', prearm)
    terminal_prearm = deploy.rindex("write_deployment_transaction prepared")
    mutation_verified = deploy.rindex("mark_deployment_mutation_verified")
    terminal_armed = deploy.rindex("deployment_commit_armed=true", 0, terminal_prearm)
    mutation_clear = deploy.rindex("clear_deployment_mutation")
    terminal_complete = deploy.rindex("complete_deployment_commit prepared")
    if not prearm < first_target_switch < mutation_verified < terminal_armed < terminal_prearm < terminal_complete < mutation_clear:
        raise RuntimeError("Deployment mutation, verification, and terminal publication ordering differs.")
    activate = deploy[deploy.index("activate_config() {") : deploy.index("write_current_evidence() {")]
    if activate.index("deployment_mutation set-config") > activate.index('ln -sfn -- "${target}"') or any(
        fragment not in activate
        for fragment in (
            '--configuration-file "${target}" || return 1',
            'ln -sfn -- "${target}" "${app_config}.next" || return 1',
            'mv -Tf -- "${app_config}.next" "${app_config}" || return 1',
            'fsync_directory "$(dirname -- "${app_config}")" || return 1',
        )
    ):
        raise RuntimeError("Deployment configuration can switch before its mutation journal is armed.")

    create_wrapper = deploy[deploy.index("create_deployment_mutation() {") : deploy.index("remaining_mutation_seconds() {")]
    for required in (
        '--previous-app-sha "${prior_config_sha}" --previous-current-target "${prior_target}" || return 1',
        'deployment_mutation mark-contained --path "${deployment_mutation_journal}" || return 1',
        'deployment_mutation mark-verified --path "${deployment_mutation_journal}" || return 1',
        '--commit "${commit}" --configuration "${configuration_id}" --archive-sha "${expected_archive_sha}" || return 1',
    ):
        if required not in create_wrapper:
            raise RuntimeError("Deployment mutation wrapper can mask a protected helper failure.")

    adoption = deploy.index("readarray -t deployment_resume < <(deployment_state_contract)")
    prior_digest = deploy.index("Deployment mutation prior current-release bytes differ from their sealed digest.", adoption)
    actual_config = deploy.index('actual_mutation_config="-"', adoption)
    launcher_reconcile = deploy.index('reconcile_launcher_failure || fail "Interrupted launcher mutation could not be reconciled safely."', adoption)
    if not prior_digest < actual_config < launcher_reconcile:
        raise RuntimeError("Deployment mutation retry can mutate runtime state before validating prior current-release bytes.")

    cleanup_start = deploy.index('if [[ ${pending_cleanup_present} == true ]]; then')
    cleanup_end = deploy.index('[[ -z "$(find "${evidence_root}" -maxdepth 1 -name \'*-storage-cleanup-required.json\' -print -quit)" ]]', cleanup_start)
    cleanup = deploy[cleanup_start:cleanup_end]
    cleanup_authority = cleanup.index('Pending hosted storage cleanup lacks its exact deployment mutation authority.')
    cleanup_switch = cleanup.index('activate_config "${config_dir}/restore.yml"')
    cleanup_launcher = cleanup.index('run_launcher storage-cleanup-resume rebuild app')
    if not cleanup_authority < cleanup_switch < cleanup_launcher:
        raise RuntimeError("Hosted storage orphan cleanup can mutate configuration before proving deployment authority.")

    bootstrap_start = deploy.index('if [[ ${mode} == bootstrap ]]; then', cleanup_end)
    bootstrap = deploy[bootstrap_start : deploy.index('else\n  if [[ ${deployment_mutation_resume} == false ]]; then', bootstrap_start)]
    if any(value not in bootstrap for value in (
        'Bootstrap mode refuses existing current-release evidence.',
        'Bootstrap mode refuses an existing current-release target.',
    )):
        raise RuntimeError("Bootstrap mutation can overwrite an existing durable release publication.")

    for source, label, token_fragment in (
        (deploy, "deploy", 'launcher_operation_token="$(od -An -N16 -tx1 /dev/urandom'),
        (restore, "restore", 'candidate_operation_token="$(od -An -N16 -tx1 /dev/urandom'),
    ):
        launcher = source[source.index("run_launcher() {") : source.index("container_operation_absent() {")]
        stale = launcher.index('if [[ -e ${launcher_bootstrap_cid} || -L ${launcher_bootstrap_cid} ]]')
        token = launcher.index(token_fragment)
        if stale > token:
            raise RuntimeError(f"{label} launcher creates a new identity before stale CID reconciliation.")

    helper_required = (
        'candidate = path.parent / f".{path.name}.{\'partial\' if create else \'update\'}"',
        'os.link(candidate, path, follow_symlinks=False)',
        "os.fsync(target.fileno())",
        "fsync_directory(path.parent)",
        '"launcherOperationToken"',
        '"launcherPreviousImageId"',
        '"launcherCommand"',
        '"databaseMutationPossible"',
        'if document["databaseMutationPossible"] and not updated["databaseMutationPossible"]:',
        'if document["phase"] != "verified":',
        'bootstrap deployment mutation requires complete prior-publication absence',
        'deployment mutation prior current-release bytes differ',
        'deployment mutation prior current-release target differs',
    )
    if any(value not in helper for value in helper_required):
        raise RuntimeError("Deployment mutation helper lost an atomicity or monotonicity invariant.")
    fixture_required = (
        "linked deployment mutation partial survived reconciliation",
        "unlinked deployment mutation update survived reconciliation",
        "launcher mutation was not durably armed before the migration boundary",
        "unsafe deployment mutation orphan was silently removed",
    )
    if any(value not in fixture for value in fixture_required):
        raise RuntimeError("Deployment mutation hostile fixture coverage differs.")
    fixture_pattern = re.compile(
        r'docker run "\$\{ruby_fixture_container\[@\]\}" -v "\$GITHUB_WORKSPACE:/repo:ro" "\$image" \\\n\s+python3 -B /repo/scripts/test-deployment-mutation[.]py >/dev/null'
    )
    if len(fixture_pattern.findall(disposable)) != 1:
        raise RuntimeError("Deployment mutation hostile fixture escaped the pinned root container.")
    if any(value not in deployment_docs for value in (
        "`/var/lib/mochirii/forums/deployment-mutation.json`",
        "atomic no-replace hard link",
        "cross-version or mutation-possible failures never launch",
    )):
        raise RuntimeError("Deployment mutation procedure documentation differs.")
    if "`databaseMutationPossible=true`" not in recovery_docs or "exact mutation-plus-promotion pair" not in validation_docs:
        raise RuntimeError("Deployment mutation recovery or validation documentation differs.")


def test_historical_disaster_recovery_entrypoint_contract() -> None:
    helper = (ROOT / "scripts/historical-release-disaster-recovery.py").read_text(encoding="utf-8")
    controller = (ROOT / "scripts/host-historical-disaster-recovery.sh").read_text(encoding="utf-8")
    scratch = (ROOT / "scripts/historical-recovery-scratch-reader.sh").read_text(encoding="utf-8")
    deploy = (ROOT / "scripts/host-deploy.sh").read_text(encoding="utf-8")
    restore = (ROOT / "scripts/host-restore-validate.sh").read_text(encoding="utf-8")
    fixture = (ROOT / "scripts/test-historical-release-disaster-recovery.py").read_text(encoding="utf-8")
    scratch_fixture = (ROOT / "scripts/test-historical-recovery-scratch-reader.py").read_text(encoding="utf-8")
    verifier = (ROOT / "scripts/verify-host-security.sh").read_text(encoding="utf-8")
    certificate_installer = (ROOT / "scripts/install-media-certificate-renewal.sh").read_text(encoding="utf-8")
    install_control = (ROOT / "scripts/install-host-control.sh").read_text(encoding="utf-8")
    upgrade_control = (ROOT / "scripts/upgrade-host-control.sh").read_text(encoding="utf-8")
    deploy_workflow = (ROOT / ".github/workflows/deploy-forums.yml").read_text(encoding="utf-8")
    disposable = (ROOT / ".github/workflows/disposable-bootstrap.yml").read_text(encoding="utf-8")

    helper_required = (
        'ARCHIVE_FORMAT = "git-archive-tar-v1"',
        'ADOPTION_SCOPE = "clean-target-disaster-recovery-only"',
        '"phase": "source-prepared"', '"phase": "configuration-authorized"',
        '"bootstrap-started"', '"bootstrap-complete"', '"restore-started"', '"restore-complete"',
        'complete_bootstrap = subcommands.add_parser("complete-bootstrap")',
        'begin_restore = subcommands.add_parser("begin-restore")',
        'complete = subcommands.add_parser("complete")',
        'Restore terminal evidence does not complete the exact historical recovery tuple.',
    )
    if any(value not in helper for value in helper_required):
        raise RuntimeError("Historical adoption helper lost its provenance or monotonic bootstrap/restore state machine.")

    controller_required = (
        'lock_file=/run/lock/mochirii-forums/historical-controller.lock',
        'install -d -m 0755 -o root -g root "${state_root}"',
        'install -d -m 0700 -o root -g root "${stage_root}"',
        'CI deliberately mounts /tmp noexec.',
        'trusted_entrypoint "${main_probe}"',
        'python3 -B "${main_probe}" refs/heads/main',
        'bash "${scratch_reader}" "${bootstrap_commit}"',
        'python3 -B "${deployer}"',
        'python3 -B "${restorer}"',
        'prove_canonical_main "${bootstrap_commit}"',
        'MOCHIRII_HISTORICAL_SCRATCH_FIXTURE_ROOT',
        'terminalReaderTransactionPhase', 'terminalReaderTransactionSha256',
        'readerOperationImageIds', 'readerOperationImageLabel', 'readerOperationImagesAbsent',
        'terminal historical scratch-reader retirement authority differs',
        'pending historical reader retirement authority differs',
        'Historical reader retirement refuses an active scratch transaction.',
        '--require-phase configuration-authorized',
        'begin-bootstrap', 'historical-bootstrap',
        'Historical reader intent was not retired before recovery continuation.',
        'Historical Mochirii Forums disaster recovery completed and retired its active journal.',
    )
    if any(value not in controller for value in controller_required):
        raise RuntimeError("Operator-only historical controller lost a current-main, scratch, retry, or retirement boundary.")
    if controller.index('prove_canonical_main "${bootstrap_commit}"') > controller.index('"${scratch_reader}" "${bootstrap_commit}"'):
        raise RuntimeError("C1 scratch execution can precede the exact canonical-main proof.")
    if controller.index('--confirmation "AUTHORIZE HISTORICAL MOCHIRII FORUMS DISASTER RELEASE"') > controller.index('journal.unlink()', controller.index('--confirmation "AUTHORIZE HISTORICAL MOCHIRII FORUMS DISASTER RELEASE"')):
        raise RuntimeError("Reader intent can retire before durable C0 configuration authorization.")
    retirement = controller.index('pending historical reader retirement authority differs')
    producer_gate = controller.index('Historical recovery requires the Website Forums producer to remain disabled.', retirement)
    if retirement > producer_gate:
        raise RuntimeError("A stale exact reader journal can survive into C0 mutation authority.")

    scratch_required = (
        'PHASES = {"armed", "receipt-fetched", "archive-fetched", "cleanup-proved", "receipt-published", "outputs-published"}',
        'path.read_bytes().split(b"\\0")',
        'member.mode not in {0o644, 0o664, 0o755, 0o775}',
        'scratch container retained a forbidden mount',
        'MOCHIRII_DR_FETCH_MODE=clean-target-historical',
        'MOCHIRII_DR_BOOTSTRAP_COMMIT=',
        '"preexistingImageIds"', '"operationImageIds"', '"operationImageLabel"',
        'docker image rm --force "${image_id}"',
        'crash_point after-reader-image-untag',
        'docker_image_id_state "${image_id}"',
        'crash_point after-reader-image-delete',
        'terminal transaction awaits controller readback',
    )
    if any(value not in scratch for value in scratch_required):
        raise RuntimeError("C1 scratch reader lost its durable transaction, actual-NUL scan, Git-tar, mount, or fetch boundary.")
    scratch_fixture = (ROOT / "scripts/test-historical-recovery-scratch-reader.py").read_text(encoding="utf-8")
    for value in (
        '"after-reader-image-delete"',
        "post-ID-delete retry repeated or omitted immutable image deletion",
        "fixture adapter unrealistically accepted removal of an absent image ID",
        'damaged_operation_image_identity_fixture("missing")',
        'damaged_operation_image_identity_fixture("altered")',
    ):
        if value not in scratch_fixture:
            raise RuntimeError("Scratch hostile fixture lost post-delete retry or damaged image-ID refusal coverage.")

    deploy_required = (
        'The deploy principal may not invoke historical bootstrap.',
        'Ordinary deployment refuses an active historical disaster-recovery adoption.',
        '--require-phase bootstrap-complete',
        'A bootstrap-complete historical journal may only reconcile its same terminal deployment transaction; runtime mutation is forbidden.',
    )
    if any(value not in deploy for value in deploy_required):
        raise RuntimeError("Ordinary/current-main deploy or journal-scoped C0 bootstrap authority differs.")
    restore_required = (
        'An active historical adoption refuses disposable restore.',
        'Historical terminal reconciliation refuses an active backup transaction.',
        'Historical terminal reconciliation refuses an active deployment transaction.',
        'Historical terminal reconciliation refuses an active deployment mutation.',
        'Historical terminal reconciliation refuses an active restore transaction.',
        'regenerated historical release evidence is not semantically equal to the private C0 receipt',
        'begin-restore', '--require-phase restore-started',
        'Terminal historical adoption journal was not retired.',
    )
    if any(value not in restore for value in restore_required):
        raise RuntimeError("Historical C0 restore lost collision gates, provenance equality, phase ownership, or terminal retirement.")
    collision = restore.index('Historical terminal reconciliation refuses an active backup transaction.')
    terminal_complete = restore.index('"${historical_helper}" complete', collision)
    if collision > terminal_complete:
        raise RuntimeError("Historical terminal completion can bypass transaction collision gates.")
    if restore.index('"${historical_helper}" begin-restore') > restore.index('discourse restore --location s3'):
        raise RuntimeError("Historical restore mutation can precede its durable adoption phase.")

    fixture_required = (
        'SCRATCH.git_archive(c0_archive,c0_files,"C0 historical backup")',
        'configuration-authorized-before-reader-retirement',
        'crash_result=controller(crashed,"prepare",C1,OPERATION,PREPARE_CONFIRMATION,passed=False)',
        'MOCHIRII_FIXTURE_DEPLOY_CRASH_ONCE', 'MOCHIRII_FIXTURE_DEPLOY_COMPLETE_CRASH_ONCE',
        'MOCHIRII_FIXTURE_RESTORE_COMPLETE_CRASH_ONCE',
        'C0 mutation was not prearmed.', 'Bootstrap-complete retry was not reconciliation-only.',
        'Restore-complete retry was not terminal-only.',
        'Historical C0 backup / C1 main / lost-host production-entrypoint fixture passed.',
    )
    if any(value not in fixture for value in fixture_required):
        raise RuntimeError("C0/C1/lost-host production-entrypoint crash fixture coverage differs.")
    scratch_fixture_required = (
        '"git", "-c", "core.autocrlf=false", "-c", "core.filemode=true"',
        '"-c", "tar.umask=0002"',
        'actual NUL-delimited marked process survived reconciliation',
        'MOCHIRII_HISTORICAL_SCRATCH_FIXTURE_CRASH_AFTER',
        'scratch container retained a forbidden mount',
    )
    if any(value not in scratch_fixture for value in scratch_fixture_required):
        raise RuntimeError("Real-Git scratch-reader timeout/crash/tamper/survivor fixture coverage differs.")
    for fixture_source in (fixture, scratch_fixture):
        if (
            "/tmp:rw,noexec,nosuid,nodev,size=16m" not in fixture_source
            or re.search(r'"--pids-limit"\s*,\s*"64"', fixture_source) is None
            or re.search(r'"--memory"\s*,\s*"256m"', fixture_source) is None
            or re.search(r'"--memory-swap"\s*,\s*"256m"', fixture_source) is None
        ):
            raise RuntimeError("Historical fixture convenience wrapper differs from the pinned CI noexec isolation tuple.")

    for source, minimum in (
        (install_control, 2), (upgrade_control, 2), (deploy, 1), (verifier, 1),
        (deploy_workflow, 1), (disposable, 1),
    ):
        if source.count("tar.umask=0002") < minimum:
            raise RuntimeError("A retained or consumed Git archive lost deterministic tar-mode construction.")
    bounded_verifier = (
        'MAX_JSON_BYTES = 65_536', 'MAX_ARCHIVE_BYTES = 67_108_864',
        'bounded_read(pointer_path, MAX_JSON_BYTES', 'bounded_read(record_path, MAX_JSON_BYTES',
        'isinstance(expected_bytes, bool)', 'metadata.st_size != expected_bytes',
        'bounded_read(path, MAX_ARCHIVE_BYTES',
    )
    if any(value not in verifier for value in bounded_verifier):
        raise RuntimeError("Host-security retained archive verification regained an unbounded read.")
    certificate_archive_contract = (
        'pointer_keys = {', 'record_keys = {', 'archive_bindings = {',
        'not 1 <= pointer["releaseArchiveBytes"] <= 64 * 1024 * 1024',
        'not 1 <= pointer["deploymentSourceArchiveBytes"] <= 64 * 1024 * 1024',
        'any(record.get(key) != pointer.get(key) for key in archive_bindings)',
    )
    if any(value not in certificate_installer for value in certificate_archive_contract):
        raise RuntimeError("Certificate automation consumes a stale or unbounded host-control archive schema.")


def test_host_operation_lock_contract() -> None:
    helper = (ROOT / "scripts/host-operation-lock.py").read_text(encoding="utf-8")
    fixture = (ROOT / "scripts/test-host-operation-lock.py").read_text(encoding="utf-8")
    service = (ROOT / "config/mochirii-forums-media-certificate-renew.service").read_text(encoding="utf-8")
    sudoers = (ROOT / "config/sudoers-forums").read_text(encoding="utf-8")
    dispatcher = (ROOT / "scripts/ssh-deploy-dispatch.py").read_text(encoding="utf-8")

    helper_contract = (
        'LOCK_DIRECTORY = "mochirii-forums"',
        'LOCK_ORDER = ("primary", "media")',
        '"primary": "primary.lock"',
        '"media": "media-certificate.lock"',
        '"primary": 200',
        '"media": 201',
        'CONTEXT_ENV = "MOCHIRII_FORUMS_HOST_LOCK_FDS"',
        'os.O_DIRECTORY',
        'os.O_NOFOLLOW',
        'os.O_CLOEXEC',
        'os.mkdir(LOCK_DIRECTORY, 0o700, dir_fd=lock_fd)',
        'os.open(LOCK_FILES[lock_id], _LOCK_FLAGS, dir_fd=private_fd)',
        '_LOCK_FLAGS | os.O_CREAT | os.O_EXCL',
        'metadata.st_nlink != 1',
        '_directory_mode(metadata) != 0o700',
        'stat.S_IMODE(metadata.st_mode) != 0o600',
        'ubuntu_sticky = mode == 0o1777',
        'fcntl.F_DUPFD_CLOEXEC',
        'fcntl.LOCK_EX | fcntl.LOCK_NB',
        'os.set_inheritable(LOCK_FDS[lock_id], True)',
        'if not command or not os.path.isabs(command[0]):',
        'os.execve(command[0], list(command), child_environment)',
        'def verify_namespace(',
        'if isinstance(cause, OSError) and cause.errno == errno.ENOENT:',
        'if action in {"assert-held", "verify-namespace", "verify-nodes"}:',
    )
    if any(value not in helper for value in helper_contract):
        raise RuntimeError("Host-operation lock helper lost its private no-follow inode, ordering, or inherited-FD boundary.")
    if 'LOCK_ORDER = ("media", "primary")' in helper or 'CANONICAL_ROOT = pathlib.Path("/run/lock")' in helper:
        raise RuntimeError("Host-operation lock helper can reverse order or anchor beneath the attacker-writable lock directory.")

    fixture_contract = (
        'Linked /run parent received a lock artifact.',
        'Linked system lock parent received a lock artifact.',
        'Linked private lock directory received a lock artifact.',
        'Linked lock victim bytes changed.',
        '"directory": lambda path: path.mkdir(mode=0o600)',
        '"fifo": lambda path: os.mkfifo(path, 0o600)',
        '"socket": _create_socket_entry',
        'hardlinked lock file',
        'unsafe private-directory owner',
        'unsafe lock-file owner',
        'absent /run/lock',
        'Clean boot private lock directory metadata differs.',
        'verify-nodes created a missing lock file.',
        'Ubuntu /var/lock alias produced a second lock namespace.',
        'Helper traversed the noncanonical /var/lock alias.',
        'reverse primary/media acquisition',
        'Contending primary acquisition was not blocked:',
        'Contending media acquisition was not blocked:',
        'Primary FD collision clobbered its caller-owned descriptor.',
        'Media FD collision clobbered its caller-owned descriptor.',
        'Parent SIGKILL released a descendant-owned lock.',
        'Retry remained blocked after the last inherited FD closed.',
        'Primary-only clean reboot unexpectedly created the media lock.',
        'Namespace verification created the absent media lock.',
        'Namespace verification changed linked media victim bytes.',
        'nonregular existing media',
        'unsafe existing media mode',
        'unsafe existing media owner',
    )
    if any(value not in fixture for value in fixture_contract):
        raise RuntimeError("Host-operation lock executable hostile inventory differs.")
    if VALIDATOR.BASE_DIGEST not in fixture or '"--network",\n        "none"' not in fixture or '"--read-only"' not in fixture:
        raise RuntimeError("Host-operation lock hostile wrapper differs from the pinned isolated Linux boundary.")

    consumers = {
        "primary": (
            "scripts/finalize-member-rollout.sh",
            "scripts/host-backup.sh",
            "scripts/host-break-glass-admin.sh",
            "scripts/host-deploy.sh",
            "scripts/host-finalize-authentication.sh",
            "scripts/host-restore-validate.sh",
            "scripts/host-stop-pending-activation.sh",
            "scripts/host-verify-wrapper.sh",
        ),
        "media": (
            "scripts/prepare-media-certificate.sh",
            "scripts/run-media-certificate-renewal.sh",
        ),
        "primary,media": (
            "scripts/install-host-control.sh",
            "scripts/install-media-certificate-renewal.sh",
            "scripts/upgrade-host-control.sh",
        ),
    }
    all_consumers = []
    for lock_set, paths in consumers.items():
        for relative in paths:
            source = (ROOT / relative).read_text(encoding="utf-8")
            all_consumers.append((relative, source))
            if (
                f'assert-held --locks {lock_set}' not in source
                or f'run --locks {lock_set}' not in source
                or '[[ ${lock_status} -eq 3 ]] || fail "Host operation lock context is invalid."' not in source
            ):
                raise RuntimeError(f"{relative} lost its exact inherited {lock_set} lock wrapper.")
            if "--locks media,primary" in source:
                raise RuntimeError(f"{relative} can acquire the media lock before the primary lock.")

    retired_lock_paths = (
        "/run/lock/mochirii-forums.lock",
        "/run/lock/mochirii-forums-media-certificate.lock",
        "/var/lock/mochirii-forums.lock",
        "/var/lock/mochirii-forums-media-certificate.lock",
        "/run/lock/mochirii-forums/primary.lock",
        "/run/lock/mochirii-forums/media-certificate.lock",
        "/var/lock/mochirii-forums/primary.lock",
        "/var/lock/mochirii-forums/media-certificate.lock",
    )
    descriptor_open = re.compile(r"\bexec\s+\d+\s*(?:<>|>>|>|<)")
    numeric_flock = re.compile(r"\bflock\s+(?:-[^\s]+\s+)*\d+\b")

    def unsafe_open(source: str) -> bool:
        without_reviewed_closes = source.replace("exec 200>&- 201>&-", "")
        return bool(
            any(path in source for path in retired_lock_paths)
            or descriptor_open.search(without_reviewed_closes)
            or numeric_flock.search(source)
        )

    for relative, source in all_consumers:
        if unsafe_open(source):
            raise RuntimeError(f"{relative} regained a direct or variable-computed lock descriptor open.")
    for hostile in (
        'exec 9>/run/lock/mochirii-forums.lock\n',
        'lock_file=/run/lock/mochirii-forums/primary.lock\nexec 9>"${lock_file}"\n',
        'media_lock=/var/lock/mochirii-forums/media-certificate.lock\nexec 8>"${media_lock}"\n',
        'flock -n 9\n',
    ):
        if not unsafe_open(hostile):
            raise RuntimeError("Host-operation recurrence gate missed a literal or variable-computed direct lock open.")

    close_before_exec = {
        "scripts/host-backup.sh": 1,
        "scripts/host-break-glass-admin.sh": 1,
        "scripts/host-deploy.sh": 4,
        "scripts/host-restore-validate.sh": 2,
        "scripts/install-host-control.sh": 2,
        "scripts/media-certificate-operation.sh": 2,
    }
    for relative, minimum in close_before_exec.items():
        source = (ROOT / relative).read_text(encoding="utf-8")
        if source.count("exec 200>&- 201>&-") < minimum:
            raise RuntimeError(f"{relative} can leak protected host-lock descriptors into a detached operation.")

    if (
        "ReadWritePaths=/etc/letsencrypt /var/lib/letsencrypt /var/log/letsencrypt /var/lib/mochirii/forums -/run/lock/mochirii-forums" not in service
        or re.search(r"(?:^|\s)/run/lock(?:\s|$)", service, re.MULTILINE)
    ):
        raise RuntimeError("Media-certificate systemd write authority is not narrowed to the private lock namespace.")
    if "host-operation-lock.py" in sudoers or "host-operation-lock.py" in dispatcher:
        raise RuntimeError("Deploy-key authority gained a direct host-operation lock helper route.")
    verifier = (ROOT / "scripts/verify-host-security.sh").read_text(encoding="utf-8")
    if (
        'verify-namespace --locks primary,media' not in verifier
        or 'sudo -l -U mochirii-forums-deploy /usr/local/libexec/mochirii-forums/host-operation-lock.py' not in verifier
    ):
        raise RuntimeError("Host-security verification lost private lock-node or deploy-authority proof.")

    docs = "\n".join(
        (ROOT / relative).read_text(encoding="utf-8")
        for relative in (
            "docs/operations/DEPLOYMENT.md",
            "docs/operations/PROVIDER-DNS-TLS.md",
            "docs/operations/RECOVERY.md",
            "docs/operations/SECRETS.md",
            "docs/operations/VALIDATION.md",
        )
    )
    for required in (
        "/run/lock/mochirii-forums",
        "mode-`0700`",
        "mode-`0600`",
        "primary-before-media",
        "O_NOFOLLOW",
        "`/var/lock`",
        "deploy key",
    ):
        if required not in docs:
            raise RuntimeError("Host-operation lock documentation is incomplete.")
    if any(value not in docs for value in (
        "`KillMode=process`",
        "direct Git parent",
        "identical-byte",
        "continues the newly approved upgrade in the same locked process",
    )):
        raise RuntimeError("Host-control changed-successor recovery documentation is incomplete.")


def test_host_security_control_plane_contract() -> None:
    manifest = json.loads((ROOT / "config/host-control-manifest.v1.json").read_text(encoding="utf-8"))
    if set(manifest) != {"schemaVersion", "coreTargets", "hostPolicyTargets", "certificateTargets"} or manifest.get("schemaVersion") != 1:
        raise RuntimeError("Host-control manifest schema differs.")
    expected = {
        "coreTargets": {
            "/usr/local/libexec/mochirii-forums/durable-event.py",
            "/usr/local/libexec/mochirii-forums/host-control-evidence.py",
            "/usr/local/libexec/mochirii-forums/host-operation-lock.py",
            "/usr/local/libexec/mochirii-forums/historical-recovery-scratch-reader.sh",
            "/usr/local/libexec/mochirii-forums/historical-release-disaster-recovery.py",
            "/usr/local/libexec/mochirii-forums/probe-website-forums-producer.py",
            "/usr/local/libexec/mochirii-forums/ssh-deploy-dispatch.py",
            "/usr/local/libexec/mochirii-forums/verify-host-security.sh",
            "/usr/local/sbin/mochirii-forums-backup",
            "/usr/local/sbin/mochirii-forums-break-glass-admin",
            "/usr/local/sbin/mochirii-forums-deploy",
            "/usr/local/sbin/mochirii-forums-finalize-authentication",
            "/usr/local/sbin/mochirii-forums-finalize-member-rollout",
            "/usr/local/sbin/mochirii-forums-historical-disaster-recovery",
            "/usr/local/sbin/mochirii-forums-quarantine-failed-bootstrap",
            "/usr/local/sbin/mochirii-forums-restore",
            "/usr/local/sbin/mochirii-forums-stop-pending-activation",
            "/usr/local/sbin/mochirii-forums-upgrade-host-control",
            "/usr/local/sbin/mochirii-forums-verify",
        },
        "hostPolicyTargets": {
            "/etc/apt/apt.conf.d/20auto-upgrades", "/etc/docker/daemon.json",
            "/etc/fail2ban/jail.d/mochirii-forums.conf",
            "/etc/ssh/sshd_config.d/00-00-mochirii-forums.conf",
            "/etc/sudoers.d/mochirii-forums", "/etc/sudoers.d/mochirii-forums-operator",
        },
        "certificateTargets": {
            "/etc/systemd/system/mochirii-forums-media-certificate-renew.service",
            "/etc/systemd/system/mochirii-forums-media-certificate-renew.timer",
            "/usr/local/libexec/mochirii-forums/media-certificate-operation.sh",
            "/usr/local/libexec/mochirii-forums/reconcile-acme-dns.py",
            "/usr/local/libexec/mochirii-forums/rotate-media-certificate.py",
            "/usr/local/sbin/mochirii-forums-renew-media-certificate",
            "/usr/local/sbin/mochirii-forums-rotate-media-certificate",
        },
    }
    for group, exact_targets in expected.items():
        rows = manifest.get(group)
        if not isinstance(rows, list) or {row.get("target") for row in rows} != exact_targets:
            raise RuntimeError(f"Host-control {group} exact target inventory differs.")
        for row in rows:
            if set(row) != {"source", "target", "mode"} or row["mode"] not in {"0440", "0644", "0755"}:
                raise RuntimeError(f"Host-control {group} row differs.")
            source = ROOT / row["source"]
            if not source.is_file() or source.is_symlink():
                raise RuntimeError(f"Host-control source is absent or linked: {row['source']}")

    installer = (ROOT / "scripts/install-host-control.sh").read_text(encoding="utf-8")
    hardened = (ROOT / "config/sshd-forums.conf").read_text(encoding="utf-8")
    prepared = (ROOT / "config/sshd-forums-prepared.conf").read_text(encoding="utf-8")
    operator_sudoers = (ROOT / "config/sudoers-forums-operator").read_text(encoding="utf-8")
    verifier = (ROOT / "scripts/verify-host-security.sh").read_text(encoding="utf-8")
    upgrade = (ROOT / "scripts/upgrade-host-control.sh").read_text(encoding="utf-8")
    host_verify = (ROOT / "scripts/verify-host.sh").read_text(encoding="utf-8")
    dispatcher = (ROOT / "scripts/ssh-deploy-dispatch.py").read_text(encoding="utf-8")
    finalizer = (ROOT / "scripts/host-finalize-authentication.sh").read_text(encoding="utf-8")

    def assert_ssh_service_activation_contract(
        installer_source: str,
        verifier_source: str,
        upgrade_source: str,
    ) -> None:
        installer_required = (
            'readonly ssh_generator_parent="/etc/systemd/system-generators"',
            'readonly ssh_generator_mask="/etc/systemd/system-generators/sshd-socket-generator"',
            '[[ -d ${ssh_generator_parent} && ! -L ${ssh_generator_parent} ]]',
            'stat -c \'%U:%G %a\' -- "${ssh_generator_parent}")" == "root:root 755"',
            'ln -s /dev/null "${staging}/mask"',
            'run_bounded_host_operation 60 systemctl disable --now ssh.socket',
            'run_bounded_host_operation 60 systemctl enable --now ssh.service',
            'timeout --signal=TERM --kill-after=5s 15s systemctl show ssh.service -p KillMode --value',
            'run_bounded_host_cleanup systemctl enable ssh.socket',
            'run_bounded_host_cleanup systemctl stop ssh.service',
            'run_bounded_host_cleanup systemctl start ssh.socket',
            'restore_ssh_socket_activation_predecessor()',
            'ensure_ssh_service_activation()',
        )
        verifier_required = (
            '--socket-activation-recovery',
            '--upgrade-socket-activation-recovery',
            'ssh_generator_parent=/etc/systemd/system-generators',
            'OpenSSH socket-generator parent is unsafe.',
            '[[ ! -e ${ssh_generator_mask} && ! -L ${ssh_generator_mask} ]]',
            'systemctl is-enabled ssh.service 2>/dev/null || true)" == disabled',
            'systemctl is-active ssh.service 2>/dev/null || true)" == active',
            'systemctl is-enabled ssh.socket 2>/dev/null || true)" == enabled',
            'systemctl is-active ssh.socket 2>/dev/null || true)" == active',
            'service_state ssh.service || fail "OpenSSH service is not enabled and active."',
            'systemctl is-enabled ssh.socket 2>/dev/null || true)" == disabled',
            'systemctl is-active ssh.socket 2>/dev/null || true)" == inactive',
        )
        upgrade_required = (
            'readonly ssh_generator_parent="/etc/systemd/system-generators"',
            'readonly ssh_generator_mask="/etc/systemd/system-generators/sshd-socket-generator"',
            '[[ -d ${ssh_generator_parent} && ! -L ${ssh_generator_parent} ]]',
            'stat -c \'%U:%G %a\' -- "${ssh_generator_parent}")" == "root:root 755"',
            'ssh_activation_predecessor()',
            'restore_ssh_activation_predecessor()',
            'verify_previous_host_controls()',
            '"sshActivationPredecessor"',
            '.control-upgrade-staging-${expected_commit}.XXXXXXXX',
            'bounded 60s systemctl disable --now ssh.socket',
            'bounded 60s systemctl enable --now ssh.service',
            'bounded 15s systemctl show ssh.service -p KillMode --value',
            'bounded 60s systemctl enable ssh.socket',
            'bounded 60s systemctl stop ssh.service',
            'bounded 60s systemctl start ssh.socket',
            'validate_effective_hardened_ssh() {',
            'bind_invoked_canonical_successor() {',
            'rev-parse --verify "${requested_commit}^1"',
            'ls-remote --refs "${canonical_repository}" refs/heads/main',
            'GIT_NO_REPLACE_OBJECTS=1',
            '${invocation_source_root}/.git/commondir',
            '${invocation_source_root}/.git/info/grafts',
            'actual_path_output="$(git -C "${invocation_source_root}" diff-tree',
            'bind_invoked_canonical_successor "${requested_commit}" "${commit}"',
            'recovery_continue=true',
            '[[ ${recovery_continue} == true ]] || exit 0',
            'unchanged bytes must not be retried',
            'bash "${candidate_source}/scripts/verify-host-security.sh" "${previous_commit}" "${previous_source}" --upgrade-transaction',
            'bash "${candidate_source}/scripts/verify-host-security.sh" "${previous_commit}" "${previous_source}" --upgrade-socket-activation-recovery',
            'bash "${candidate}/scripts/verify-host-security.sh" "${previous_commit}" "${previous_source}" --socket-activation-recovery',
        )
        if any(value not in installer_source for value in installer_required):
            raise RuntimeError("Initial host SSH service-activation contract differs.")
        if any(value not in verifier_source for value in verifier_required):
            raise RuntimeError("Terminal host SSH service-activation contract differs.")
        if any(value not in upgrade_source for value in upgrade_required):
            raise RuntimeError("Transactional host SSH service-activation contract differs.")
        if 'service_state ssh.socket || fail "OpenSSH service is not enabled and active."' in verifier_source:
            raise RuntimeError("Terminal host verification permits socket activation.")
        if upgrade_source.count("validate_effective_hardened_ssh() {") != 1 or upgrade_source.count(
            "validate_effective_hardened_ssh || return 1"
        ) != 1:
            raise RuntimeError("Transactional effective SSH readback is undefined, duplicated, or unbound.")

        installer_restore = installer_source[
            installer_source.index("restore_ssh_socket_activation_predecessor() {"):
            installer_source.index("\n}\n", installer_source.index("restore_ssh_socket_activation_predecessor() {"))
        ]
        upgrade_restore = upgrade_source[
            upgrade_source.index("restore_ssh_activation_predecessor() {"):
            upgrade_source.index("\n}\n", upgrade_source.index("restore_ssh_activation_predecessor() {"))
        ]
        installer_restore_order = (
            "systemctl show ssh.service -p KillMode --value",
            "systemctl disable ssh.service",
            'durable_remove "${ssh_generator_mask}"',
            "systemctl daemon-reload",
            "systemctl enable ssh.socket",
            "systemctl stop ssh.service",
            "systemctl start ssh.socket",
            "systemctl start ssh.service",
            "ssh_socket_activation_is_exact_predecessor",
        )
        upgrade_restore_order = installer_restore_order
        for block, ordered in ((installer_restore, installer_restore_order), (upgrade_restore, upgrade_restore_order)):
            positions = [block.index(token) for token in ordered]
            if positions != sorted(positions) or "systemctl enable --now ssh.socket" in block:
                raise RuntimeError("SSH socket-predecessor restoration ordering can conflict with the active service listener.")

        candidate_validation = upgrade_source.index('bounded 300s python3 -I -S -B "${candidate}/scripts/validate-repository.py"')
        predecessor_gate = upgrade_source.index('ssh_predecessor="$(ssh_activation_predecessor)"', candidate_validation)
        recovery_gate = upgrade_source.index('--socket-activation-recovery', predecessor_gate)
        journal_position = upgrade_source.index('os.link(candidate, journal_path, follow_symlinks=False)', recovery_gate)
        first_publication = upgrade_source.index('atomic_install "${candidate}/${relative}"', journal_position)
        activation_commit = upgrade_source.index('ensure_ssh_service_activation || {', first_publication)
        first_readback = upgrade_source.index('post_install_readback "${candidate}"', activation_commit)
        terminal_verification = upgrade_source.index(
            'bash "${candidate}/scripts/verify-host-security.sh" "${expected_commit}" "${candidate}" --upgrade-transaction',
            first_readback,
        )
        if not (
            candidate_validation
            < predecessor_gate
            < recovery_gate
            < journal_position
            < first_publication
            < activation_commit
            < first_readback
            < terminal_verification
        ):
            raise RuntimeError("SSH activation validation, journal, publication, conversion, or verification ordering differs.")

        rollback_start = upgrade_source.index("verify_previous_host_controls() {")
        rollback_end = upgrade_source.index("\n}\n", rollback_start)
        rollback_block = upgrade_source[rollback_start:rollback_end]
        if '${previous_source}/scripts/verify-host-security.sh' in rollback_block:
            raise RuntimeError("Rollback verification uses the schema-incompatible predecessor verifier.")

    assert_ssh_service_activation_contract(installer, verifier, upgrade)

    hostile_activation_mutations = (
        (installer.replace('[[ -d ${ssh_generator_parent} && ! -L ${ssh_generator_parent} ]]', '[[ -d ${ssh_generator_parent} ]]'), verifier, upgrade),
        (installer.replace('ln -s /dev/null "${staging}/mask"', 'ln -s /tmp/socket "${staging}/mask"', 1), verifier, upgrade),
        (installer.replace('systemctl disable --now ssh.socket', 'systemctl enable --now ssh.socket', 1), verifier, upgrade),
        (installer, verifier.replace('service_state ssh.service || fail "OpenSSH service is not enabled and active."', 'service_state ssh.socket || fail "OpenSSH service is not enabled and active."', 1), upgrade),
        (installer, verifier.replace('--upgrade-socket-activation-recovery', '--upgrade-service-recovery'), upgrade),
        (installer, verifier, upgrade.replace('"sshActivationPredecessor"', '"sshActivationMode"')),
        (installer, verifier, upgrade.replace('bounded 60s systemctl disable --now ssh.socket', 'bounded 60s systemctl enable --now ssh.socket', 1)),
        (installer, verifier, upgrade.replace('bash "${candidate_source}/scripts/verify-host-security.sh"', 'bash "${previous_source}/scripts/verify-host-security.sh"', 1)),
        (installer.replace('systemctl enable ssh.socket', 'systemctl enable --now ssh.socket', 1), verifier, upgrade),
        (installer, verifier, upgrade.replace('systemctl enable ssh.socket', 'systemctl enable --now ssh.socket', 1)),
        (installer, verifier, upgrade.replace("validate_effective_hardened_ssh() {", "validate_effective_hardened_ssh_missing() {", 1)),
    )
    for mutated_installer, mutated_verifier, mutated_upgrade in hostile_activation_mutations:
        try:
            assert_ssh_service_activation_contract(mutated_installer, mutated_verifier, mutated_upgrade)
        except (RuntimeError, ValueError):
            continue
        raise RuntimeError("Hostile SSH service-activation mutation passed the source contract.")

    def classify_ssh_activation(state: tuple[str, str, str, str, str]) -> str | None:
        mask, service_enabled, service_active, socket_enabled, socket_active = state
        if state == ("dev-null", "enabled", "active", "disabled", "inactive"):
            return "service"
        if state == ("absent", "disabled", "active", "enabled", "active"):
            return "socket"
        return None

    modeled_states = {
        (mask, service_enabled, service_active, socket_enabled, socket_active)
        for mask in ("absent", "dev-null", "other")
        for service_enabled in ("enabled", "disabled")
        for service_active in ("active", "inactive")
        for socket_enabled in ("enabled", "disabled")
        for socket_active in ("active", "inactive")
    }
    accepted_states = {state: classify_ssh_activation(state) for state in modeled_states if classify_ssh_activation(state)}
    if accepted_states != {
        ("dev-null", "enabled", "active", "disabled", "inactive"): "service",
        ("absent", "disabled", "active", "enabled", "active"): "socket",
    }:
        raise RuntimeError("SSH activation predecessor model accepts a mixed or ambiguous state.")

    if os.name == "posix":
        bash = shutil.which("bash")
        if bash is None:
            raise RuntimeError("Bash is required for the host-control SSH recovery fixtures.")

        def function_block(source: str, name: str) -> str:
            start = source.index(f"{name}() {{")
            return source[start:source.index("\n}\n", start) + 3]

        effective_start = upgrade.index("effective_ssh_value() {")
        effective_end = upgrade.index("\n}\n", upgrade.index("validate_effective_hardened_ssh() {")) + 3
        effective_harness = r'''set -u
state_root=/var/lib/mochirii/forums
bounded() {
  [[ $1 == 15s ]] || return 90
  shift
  [[ $1 == sshd && $2 == -T && $3 == -C && $# -eq 4 ]] || return 91
  user=${4#user=}; user=${user%%,*}
  case "${user}" in
    root) keys=none; force=none; tty=no ;;
    mochirii-forums-operator) keys=/var/lib/mochirii/forums/operator/.ssh/authorized_keys; force=none; tty=yes ;;
    mochirii-forums-deploy) keys=/var/lib/mochirii/forums/deploy/.ssh/authorized_keys; force=/usr/local/libexec/mochirii-forums/ssh-deploy-dispatch.py; tty=no ;;
    *) return 92 ;;
  esac
  [[ ${SSH_MUTATION:-none} != deploy-force || ${user} != mochirii-forums-deploy ]] || force=none
  permit_root=no
  [[ ${SSH_MUTATION:-none} != root-login || ${user} != root ]] || permit_root=yes
  printf '%s\n' \
    'passwordauthentication no' \
    'kbdinteractiveauthentication no' \
    'pubkeyauthentication yes' \
    'authenticationmethods publickey' \
    'authorizedkeyscommand none' \
    'authorizedkeyscommanduser nobody' \
    'trustedusercakeys none' \
    'authorizedprincipalsfile none' \
    'authorizedprincipalscommand none' \
    'authorizedprincipalscommanduser nobody' \
    'permituserenvironment no' \
    'permituserrc no' \
    'allowusers mochirii-forums-operator mochirii-forums-deploy' \
    "authorizedkeysfile ${keys}" \
    "forcecommand ${force}" \
    'disableforwarding yes' \
    "permittty ${tty}" \
    "permitrootlogin ${permit_root}"
}
''' + upgrade[effective_start:effective_end] + "\nvalidate_effective_hardened_ssh\n"
        for mutation, should_pass in (("none", True), ("root-login", False), ("deploy-force", False)):
            completed = subprocess.run(
                [bash, "-c", effective_harness],
                stdin=subprocess.DEVNULL,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                timeout=10,
                env={**os.environ, "SSH_MUTATION": mutation},
                check=False,
            )
            if (completed.returncode == 0) != should_pass or completed.stdout or completed.stderr:
                raise RuntimeError("Executable transactional effective SSH readback accepted a hostile tuple or rejected the exact tuple.")

        with tempfile.TemporaryDirectory(prefix="mochirii-successor-binding-") as directory:
            source_root = Path(directory) / "source"
            entrypoint = source_root / "scripts/upgrade-host-control.sh"
            entrypoint.parent.mkdir(parents=True)
            entrypoint.write_text("fixture\n", encoding="utf-8", newline="\n")
            (source_root / ".git").mkdir()
            binder_harness = f'''set -u
canonical_repository=https://github.com/Mochirii-Wushu/Mochirii-Forums.git
requested=cccccccccccccccccccccccccccccccccccccccc
reviewed_legacy_failed_bootstrap_commit=b2eb4edb17d72f49b6f979b19d9ee4a39b9ffc6f
reviewed_failed_bootstrap_recovery_commit=1d741eb75d08a226984935aa18e989ee324a0773
reviewed_active_swap_failed_bootstrap_commit=26e793aada31faeaa8b56308625288164430647c
reviewed_active_swap_recovery_commit=6e2f1b5c831b992c3222c015836fa180cd591e3e
reviewed_acme_failed_bootstrap_commit=f564d62a82adf79b8f012a25949826e2b447681d
reviewed_acme_recovery_commit=85e12f1ce27e1462e7c82e59e1dbf01c190327b9
reviewed_quarantine_output_failed_bootstrap_commit=c2f0f37ec2f73c41c7d1f63942a7483d1d7ef306
reviewed_quarantine_output_recovery_commit=8eea740795f0536468e48c5e8cda2ded29b1e51e
reviewed_acme_reload_privacy_failed_bootstrap_commit=fae3770f0817d05bbfd2520e9657ddc1c8a7ce5d
reviewed_acme_reload_privacy_recovery_commit=f51c2e8deaf39293c9b97f3aab797b882c3dc628
reviewed_acme_reload_privacy_recovery_child_commit=591d96484369ae29a8fa4e61219b325997f4b679
reviewed_acme_reload_privacy_launcher_child_commit=a71bbe8070ca6dadeff3c4966e81bd97fee83cf7
reviewed_acme_webroot_failed_bootstrap_commit=9110568e09bda4d572eaf2c27a768b9c053048f9
reviewed_acme_webroot_recovery_commit=bb891aa65ebe8470fa04cdd639185afdad7372f7
reviewed_acme_material_failed_bootstrap_commit=81e5226e54246686ce0ef80051d4df2cd1b64c5e
reviewed_acme_material_recovery_commit=64e12c2344fbc04d44b10c495cf9651cac5ac0b8
reviewed_acme_material_review_authority_commit=af3540426051c94bf26e9661ac68ce8ee720f977
case "${{BINDER_LINEAGE:-legacy}}" in
  legacy) pending="$reviewed_legacy_failed_bootstrap_commit"; reviewed="$reviewed_failed_bootstrap_recovery_commit" ;;
  active) pending="$reviewed_active_swap_failed_bootstrap_commit"; reviewed="$reviewed_active_swap_recovery_commit" ;;
  acme) pending="$reviewed_acme_failed_bootstrap_commit"; reviewed="$reviewed_acme_recovery_commit" ;;
  quarantine) pending="$reviewed_quarantine_output_failed_bootstrap_commit"; reviewed="$reviewed_quarantine_output_recovery_commit" ;;
  reload_privacy) pending="$reviewed_acme_reload_privacy_failed_bootstrap_commit"; reviewed="$reviewed_acme_reload_privacy_recovery_commit" ;;
  webroot) pending="$reviewed_acme_webroot_failed_bootstrap_commit"; reviewed="$reviewed_acme_webroot_recovery_commit" ;;
  material) pending="$reviewed_acme_material_failed_bootstrap_commit"; reviewed="$reviewed_acme_material_recovery_commit" ;;
  unknown) pending=dddddddddddddddddddddddddddddddddddddddd; reviewed=eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee ;;
  *) return 84 ;;
esac
requested_parent="$reviewed"
[[ ${{BINDER_LINEAGE:-legacy}} != reload_privacy ]] || requested_parent="$reviewed_acme_reload_privacy_launcher_child_commit"
[[ ${{BINDER_LINEAGE:-legacy}} != material ]] || requested_parent="$reviewed_acme_material_review_authority_commit"
source_root={source_root.as_posix()}
bounded() {{ [[ $1 == 120s ]] || return 80; shift; "$@"; }}
git() {{
  [[ -z ${{GIT_DIR+x}} && -z ${{GIT_WORK_TREE+x}} && -z ${{GIT_INDEX_FILE+x}} && -z ${{GIT_OBJECT_DIRECTORY+x}} && -z ${{GIT_ALTERNATE_OBJECT_DIRECTORIES+x}} && -z ${{GIT_COMMON_DIR+x}} && -z ${{GIT_REPLACE_REF_BASE+x}} && -z ${{GIT_ASKPASS+x}} && -z ${{SSH_ASKPASS+x}} && -z ${{GIT_SSH+x}} && -z ${{GIT_SSH_COMMAND+x}} && -z ${{GIT_CONFIG_PARAMETERS+x}} && -z ${{GIT_CONFIG_SYSTEM+x}} && -z ${{GIT_PROTOCOL_FROM_USER+x}} && ${{GIT_TERMINAL_PROMPT:-}} == 0 && ${{GIT_CONFIG_NOSYSTEM:-}} == 1 && ${{GIT_CONFIG_GLOBAL:-}} == /dev/null && ${{GIT_CONFIG_COUNT:-}} == 0 && ${{GIT_NO_REPLACE_OBJECTS:-}} == 1 ]] || return 81
  case "$*" in
    "-C ${{source_root}} rev-parse --verify HEAD^{{commit}}") [[ ${{BINDER_MUTATION:-none}} != head ]] && printf '%s\n' "$requested" || printf '%s\n' other ;;
    "-C ${{source_root}} symbolic-ref --short -q HEAD") [[ ${{BINDER_MUTATION:-none}} != branch ]] && printf '%s\n' main || printf '%s\n' topic ;;
    "-c core.fsmonitor=false -C ${{source_root}} status --porcelain=v1 --untracked-files=all")
      [[ ${{BINDER_MUTATION:-none}} != status-fail ]] || return 83
      [[ ${{BINDER_MUTATION:-none}} != dirty ]] || printf '%s\n' ' M scripts/upgrade-host-control.sh'
      ;;
    "-C ${{source_root}} remote get-url origin") [[ ${{BINDER_MUTATION:-none}} != origin ]] && printf '%s\n' "$canonical_repository" || printf '%s\n' https://example.invalid/other.git ;;
    "-C ${{source_root}} rev-parse --verify ${{requested}}^1") [[ ${{BINDER_MUTATION:-none}} != recovery-parent ]] && printf '%s\n' "$requested_parent" || printf '%s\n' unrelated ;;
    "-C ${{source_root}} rev-list --parents -n 1 ${{requested}}") [[ ${{BINDER_MUTATION:-none}} != current-parents ]] && printf '%s %s\n' "$requested" "$requested_parent" || printf '%s %s %s\n' "$requested" "$requested_parent" unrelated ;;
    "-C ${{source_root}} rev-parse --verify ${{reviewed_acme_reload_privacy_launcher_child_commit}}^1") [[ ${{BINDER_MUTATION:-none}} != launcher-child-parent ]] && printf '%s\n' "$reviewed_acme_reload_privacy_recovery_child_commit" || printf '%s\n' unrelated ;;
    "-C ${{source_root}} rev-list --parents -n 1 ${{reviewed_acme_reload_privacy_launcher_child_commit}}") [[ ${{BINDER_MUTATION:-none}} != launcher-child-parents ]] && printf '%s %s\n' "$reviewed_acme_reload_privacy_launcher_child_commit" "$reviewed_acme_reload_privacy_recovery_child_commit" || printf '%s %s %s\n' "$reviewed_acme_reload_privacy_launcher_child_commit" "$reviewed_acme_reload_privacy_recovery_child_commit" unrelated ;;
    "-C ${{source_root}} rev-parse --verify ${{reviewed_acme_reload_privacy_recovery_child_commit}}^1") [[ ${{BINDER_MUTATION:-none}} != recovery-child-parent ]] && printf '%s\n' "$reviewed" || printf '%s\n' unrelated ;;
    "-C ${{source_root}} rev-list --parents -n 1 ${{reviewed_acme_reload_privacy_recovery_child_commit}}") [[ ${{BINDER_MUTATION:-none}} != recovery-child-parents ]] && printf '%s %s\n' "$reviewed_acme_reload_privacy_recovery_child_commit" "$reviewed" || printf '%s %s %s\n' "$reviewed_acme_reload_privacy_recovery_child_commit" "$reviewed" unrelated ;;
    "-C ${{source_root}} rev-parse --verify ${{reviewed_acme_material_review_authority_commit}}^1") [[ ${{BINDER_MUTATION:-none}} != review-authority-parent ]] && printf '%s\n' "$reviewed" || printf '%s\n' unrelated ;;
    "-C ${{source_root}} rev-list --parents -n 1 ${{reviewed_acme_material_review_authority_commit}}") [[ ${{BINDER_MUTATION:-none}} != review-authority-parents ]] && printf '%s %s\n' "$reviewed_acme_material_review_authority_commit" "$reviewed" || printf '%s %s %s\n' "$reviewed_acme_material_review_authority_commit" "$reviewed" unrelated ;;
    "-C ${{source_root}} rev-parse --verify ${{reviewed}}^1") [[ ${{BINDER_MUTATION:-none}} != failed-parent ]] && printf '%s\n' "$pending" || printf '%s\n' unrelated ;;
    "-C ${{source_root}} rev-list --parents -n 1 ${{reviewed}}") [[ ${{BINDER_MUTATION:-none}} != recovery-parents ]] && printf '%s %s\n' "$reviewed" "$pending" || printf '%s %s %s\n' "$reviewed" "$pending" unrelated ;;
    *"ls-remote --refs ${{canonical_repository}} refs/heads/main") [[ ${{BINDER_MUTATION:-none}} != remote ]] && printf '%s\trefs/heads/main\n' "$requested" || printf '%s\trefs/heads/main\n' unrelated ;;
    "-C ${{source_root}} diff-tree --no-commit-id --name-only -r ${{reviewed_acme_material_failed_bootstrap_commit}} ${{reviewed_acme_material_recovery_commit}}")
      printf '%s\n' \
        config/immutable-letsencrypt.fragment.yml \
        scripts/test-contracts.py
      [[ ${{BINDER_MUTATION:-none}} == material-repair-paths ]] || printf '%s\n' scripts/validate-repository.py
      [[ ${{BINDER_MUTATION:-none}} != material-repair-status ]] || return 83
      ;;
    "-C ${{source_root}} diff-tree --no-commit-id --name-only -r ${{reviewed_acme_material_recovery_commit}} ${{reviewed_acme_material_review_authority_commit}}")
      printf '%s\n' \
        .gitattributes \
        .github/CODEOWNERS \
        .github/workflows/open-reviewed-source-pr.yml \
        CONTRIBUTING.md \
        docs/adr/0001-clean-initialization-and-canonical-ownership.md \
        scripts/test-contracts.py
      [[ ${{BINDER_MUTATION:-none}} == material-authority-paths ]] || printf '%s\n' scripts/validate-repository.py
      [[ ${{BINDER_MUTATION:-none}} != material-authority-status ]] || return 83
      ;;
    "-C ${{source_root}} diff-tree --no-commit-id --name-only -r ${{reviewed_acme_material_review_authority_commit}} ${{requested}}")
      printf '%s\n' \
        .github/workflows/validate-repository.yml \
        docs/operations/DEPLOYMENT.md \
        docs/operations/RECOVERY.md \
        scripts/check-repository.ps1 \
        scripts/check-source-introduction.ps1 \
        scripts/host-deploy.sh \
        scripts/quarantine-failed-bootstrap.sh \
        scripts/test-contracts.py \
        scripts/test-source-introduction.ps1 \
        scripts/upgrade-host-control.sh
      [[ ${{BINDER_MUTATION:-none}} == material-current-paths ]] || printf '%s\n' scripts/validate-repository.py
      [[ ${{BINDER_MUTATION:-none}} != material-current-status ]] || return 83
      ;;
    "-C ${{source_root}} diff-tree --no-commit-id --name-only -r ${{pending}} ${{requested}}")
      case "${{BINDER_LINEAGE:-legacy}}" in
        active)
          printf '%s\n' \
            docs/operations/DEPLOYMENT.md \
            docs/operations/RECOVERY.md \
            scripts/quarantine-failed-bootstrap.sh \
            scripts/test-contracts.py \
            scripts/upgrade-host-control.sh \
            scripts/validate-repository.py
          [[ ${{BINDER_MUTATION:-none}} == paths ]] || printf '%s\n' scripts/verify-host.sh
          ;;
        acme)
          printf '%s\n' \
            config/immutable-letsencrypt.fragment.yml \
            docs/operations/DEPLOYMENT.md \
            docs/operations/RECOVERY.md \
            scripts/quarantine-failed-bootstrap.sh \
            scripts/test-contracts.py \
            scripts/upgrade-host-control.sh
          [[ ${{BINDER_MUTATION:-none}} == paths ]] || printf '%s\n' scripts/validate-repository.py
          ;;
        quarantine)
          printf '%s\n' \
            docs/operations/DEPLOYMENT.md \
            docs/operations/RECOVERY.md \
            scripts/quarantine-failed-bootstrap.sh \
            scripts/test-contracts.py \
            scripts/upgrade-host-control.sh
          [[ ${{BINDER_MUTATION:-none}} == paths ]] || printf '%s\n' scripts/validate-repository.py
          ;;
        reload_privacy)
          printf '%s\n' \
            config/immutable-letsencrypt.fragment.yml \
            docs/operations/DEPLOYMENT.md \
            docs/operations/RECOVERY.md \
            scripts/disposable-launcher-guard.py \
            scripts/quarantine-failed-bootstrap.sh \
            scripts/test-contracts.py \
            scripts/test-disposable-launcher-guard.py \
            scripts/upgrade-host-control.sh \
            scripts/validate-repository.py
          [[ ${{BINDER_MUTATION:-none}} == paths ]] || printf '%s\n' scripts/verify-host.sh
          ;;
        webroot)
          printf '%s\n' \
            config/immutable-letsencrypt.fragment.yml \
            docs/operations/DEPLOYMENT.md \
            docs/operations/RECOVERY.md \
            scripts/quarantine-failed-bootstrap.sh \
            scripts/test-contracts.py \
            scripts/upgrade-host-control.sh
          [[ ${{BINDER_MUTATION:-none}} == paths ]] || printf '%s\n' scripts/validate-repository.py
          ;;
        material)
          printf '%s\n' \
            .gitattributes \
            .github/CODEOWNERS \
            .github/workflows/open-reviewed-source-pr.yml \
            .github/workflows/validate-repository.yml \
            CONTRIBUTING.md \
            config/immutable-letsencrypt.fragment.yml \
            docs/adr/0001-clean-initialization-and-canonical-ownership.md \
            docs/operations/DEPLOYMENT.md \
            docs/operations/RECOVERY.md \
            scripts/check-repository.ps1 \
            scripts/check-source-introduction.ps1 \
            scripts/host-deploy.sh \
            scripts/quarantine-failed-bootstrap.sh \
            scripts/test-contracts.py \
            scripts/test-source-introduction.ps1 \
            scripts/upgrade-host-control.sh
          [[ ${{BINDER_MUTATION:-none}} == paths ]] || printf '%s\n' scripts/validate-repository.py
          ;;
        *)
          printf '%s\n' \
            .github/workflows/deploy-forums.yml \
            config/host-control-manifest.v1.json \
            docs/operations/DEPLOYMENT.md \
            docs/operations/RECOVERY.md \
            scripts/quarantine-failed-bootstrap.sh \
            scripts/test-contracts.py \
            scripts/upgrade-host-control.sh
          [[ ${{BINDER_MUTATION:-none}} == paths ]] || printf '%s\n' scripts/validate-repository.py
          ;;
      esac
      [[ ${{BINDER_MUTATION:-none}} != paths-status ]] || return 83
      ;;
    *) return 82 ;;
  esac
}}
{function_block(upgrade, "select_reviewed_failed_bootstrap_recovery_commit")}
{function_block(upgrade, "validate_reviewed_failed_bootstrap_successor_paths")}
{function_block(upgrade, "bind_invoked_canonical_successor")}
bind_invoked_canonical_successor "$requested" "$pending"
'''
            mutation_cases = (
                ("none", True), ("head", False), ("branch", False), ("dirty", False),
                ("status-fail", False), ("origin", False), ("recovery-parent", False),
                ("current-parents", False), ("failed-parent", False),
                ("recovery-parents", False), ("remote", False), ("paths", False),
                ("paths-status", False),
            )
            binder_cases = [
                (lineage, mutation, should_pass)
                for lineage in ("legacy", "active", "acme", "quarantine", "reload_privacy", "webroot", "material")
                for mutation, should_pass in mutation_cases
            ]
            binder_cases.extend(
                ("reload_privacy", mutation, False)
                for mutation in (
                    "launcher-child-parent", "launcher-child-parents",
                    "recovery-child-parent", "recovery-child-parents",
                )
            )
            binder_cases.extend(
                ("material", mutation, False)
                for mutation in (
                    "review-authority-parent", "review-authority-parents",
                    "material-repair-paths", "material-repair-status",
                    "material-authority-paths", "material-authority-status",
                    "material-current-paths", "material-current-status",
                )
            )
            binder_cases.extend(("legacy", mutation, False) for mutation in ("grafts", "commondir"))
            binder_cases.append(("unknown", "none", False))
            grafts_path = source_root / ".git" / "info" / "grafts"
            commondir_path = source_root / ".git" / "commondir"
            for lineage, mutation, should_pass in binder_cases:
                grafts_path.unlink(missing_ok=True)
                commondir_path.unlink(missing_ok=True)
                if mutation == "grafts":
                    grafts_path.parent.mkdir(parents=True, exist_ok=True)
                    grafts_path.write_text(
                        "c" * 40 + " " + "a" * 40 + "\n", encoding="ascii", newline="\n"
                    )
                elif mutation == "commondir":
                    commondir_path.write_text("../hostile\n", encoding="ascii", newline="\n")
                completed = subprocess.run(
                    [bash, "-c", binder_harness, str(entrypoint)],
                    stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                    text=True, timeout=10, check=False,
                    env={
                        **os.environ,
                        "BINDER_LINEAGE": lineage,
                        "BINDER_MUTATION": mutation,
                        "GIT_DIR": "/hostile",
                        "GIT_WORK_TREE": "/hostile",
                        "GIT_INDEX_FILE": "/hostile",
                        "GIT_OBJECT_DIRECTORY": "/hostile",
                        "GIT_ALTERNATE_OBJECT_DIRECTORIES": "/hostile",
                        "GIT_COMMON_DIR": "/hostile",
                        "GIT_REPLACE_REF_BASE": "refs/hostile",
                        "GIT_ASKPASS": "/hostile",
                        "SSH_ASKPASS": "/hostile",
                        "GIT_SSH": "/hostile",
                        "GIT_SSH_COMMAND": "/hostile",
                        "GIT_CONFIG_PARAMETERS": "hostile",
                        "GIT_CONFIG_SYSTEM": "/hostile",
                        "GIT_CONFIG_GLOBAL": "/hostile",
                        "GIT_CONFIG_NOSYSTEM": "0",
                        "GIT_CONFIG_COUNT": "1",
                        "GIT_CONFIG_KEY_0": "core.replaceRefs",
                        "GIT_CONFIG_VALUE_0": "true",
                        "GIT_PROTOCOL_FROM_USER": "1",
                        "GIT_TERMINAL_PROMPT": "1",
                        "GIT_NO_REPLACE_OBJECTS": "0",
                    },
                )
                if (completed.returncode == 0) != should_pass or completed.stdout or completed.stderr:
                    raise RuntimeError("Executable changed-successor source binding accepted drift or rejected exact current main.")

        restore_prefix = r'''set -euo pipefail
log=$(mktemp)
trap 'rm -f -- "$log"' EXIT
mask=absent
service_enabled=disabled
service_active=active
socket_enabled=enabled
socket_active=inactive
fake_systemctl() {
  printf '%s\n' "$*" >>"${log}"
  case "$*" in
    'show ssh.service -p KillMode --value') printf '%s\n' "${KILL_MODE:-process}" ;;
    'disable ssh.service') service_enabled=disabled ;;
    'daemon-reload') : ;;
    'enable ssh.socket') socket_enabled=enabled ;;
    'stop ssh.service') service_active=inactive ;;
    'start ssh.socket') [[ ${service_active} == inactive ]] || return 41; socket_active=active ;;
    'start ssh.service') [[ ${socket_active} == active ]] || return 42; service_active=active ;;
    *) return 43 ;;
  esac
}
timeout() {
  [[ $1 == --signal=TERM && $2 == --kill-after=5s && $3 == 15s && $4 == systemctl ]] || return 44
  shift 4
  fake_systemctl "$@"
}
run_bounded_host_cleanup() { [[ $1 == systemctl ]] || return 45; shift; fake_systemctl "$@"; }
bounded() { [[ $1 == 15s || $1 == 60s ]] || return 46; shift; [[ $1 == systemctl ]] || return 47; shift; fake_systemctl "$@"; }
durable_remove() { [[ $1 == /etc/systemd/system-generators/sshd-socket-generator ]] || return 48; printf '%s\n' remove-mask >>"${log}"; mask=absent; }
ssh_socket_activation_is_exact_predecessor() {
  [[ ${mask} == absent && ${service_enabled} == disabled && ${service_active} == active && ${socket_enabled} == enabled && ${socket_active} == active ]]
}
ensure_ssh_service_activation() { return 49; }
ssh_generator_mask=/etc/systemd/system-generators/sshd-socket-generator
'''
        restore_cases = (
            (
                restore_prefix + function_block(installer, "restore_ssh_socket_activation_predecessor") + "\nrestore_ssh_socket_activation_predecessor\ncat \"${log}\"\n",
                "installer",
            ),
            (
                restore_prefix + function_block(upgrade, "restore_ssh_activation_predecessor") + "\nrestore_ssh_activation_predecessor socket\ncat \"${log}\"\n",
                "upgrade",
            ),
        )
        expected_restore_log = "\n".join((
            "show ssh.service -p KillMode --value",
            "disable ssh.service",
            "remove-mask",
            "daemon-reload",
            "enable ssh.socket",
            "stop ssh.service",
            "start ssh.socket",
            "start ssh.service",
            "",
        ))
        for harness, label in restore_cases:
            completed = subprocess.run(
                [bash, "-c", harness], stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                stderr=subprocess.PIPE, text=True, timeout=10, check=False,
            )
            if completed.returncode != 0 or completed.stdout != expected_restore_log or completed.stderr:
                raise RuntimeError(f"Executable {label} SSH socket-predecessor recovery does not converge from the live partial state.")
            hostile = subprocess.run(
                [bash, "-c", harness], stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                stderr=subprocess.PIPE, text=True, timeout=10,
                env={**os.environ, "KILL_MODE": "control-group"}, check=False,
            )
            if hostile.returncode == 0:
                raise RuntimeError(f"Executable {label} SSH recovery ignores the retained-session KillMode boundary.")

        reconcile = function_block(upgrade, "reconcile_pending")
        reconcile_harness = r'''set -u
recovery_continue=false
fail() { printf '%s\n' "$1" >&2; exit 73; }
read_journal() {
  [[ ${RECOVERY_CASE:-successor} != journal-fail ]] || return 41
  printf '%s\n' "${JOURNAL_COMMIT:-old}" manifest /transaction false false false previous-sha socket
}
bind_invoked_canonical_successor() { [[ ${CANONICAL_PARENT:-old} == "$2" ]]; }
bind_previous_source() { printf '%s\n' previous-commit previous-sha /transaction/previous-source/previous-commit; }
targets_are_new() { [[ ${RECOVERY_TARGETS:-new} == new ]]; }
ensure_ssh_service_activation() { printf '%s\n' ensure; }
post_install_readback() { printf 'post:%s\n' "$1"; }
seal_control_state() { printf '%s\n' seal; }
bash() { printf '%s\n' bash-verify; }
rollback_transaction() { printf '%s\n' rollback; }
verify_previous_host_controls() { printf '%s\n' verify-previous; }
clear_transaction() { printf '%s\n' clear; }
''' + reconcile + r'''
reconcile_pending "${REQUESTED_COMMIT:-new}"
printf 'continue:%s\n' "${recovery_continue}"
'''
        recovery_cases = (
            (
                {},
                0,
                "rollback\npost:/transaction/previous-source/previous-commit\nverify-previous\nclear\n"
                "Interrupted Mochirii Forums host-control upgrade was rolled back exactly; continuing the approved canonical successor.\ncontinue:true\n",
                "",
            ),
            (
                {"REQUESTED_COMMIT": "old", "JOURNAL_COMMIT": "old"},
                0,
                "ensure\npost:/transaction/source\nseal\nclear\n"
                "Interrupted Mochirii Forums host-control upgrade was committed forward and verified.\ncontinue:false\n",
                "",
            ),
            (
                {"CANONICAL_PARENT": "unrelated"},
                73,
                "",
                "Pending host-control upgrade is not recoverable by this exact direct canonical successor.\n",
            ),
            (
                {"REQUESTED_COMMIT": "old", "JOURNAL_COMMIT": "old", "RECOVERY_TARGETS": "old"},
                73,
                "rollback\npost:/transaction/previous-source/previous-commit\nverify-previous\nclear\n",
                "Interrupted host-control upgrade was rolled back exactly; unchanged bytes must not be retried.\n",
            ),
            (
                {"RECOVERY_CASE": "journal-fail"},
                73,
                "",
                "Pending host-control upgrade journal is invalid.\n",
            ),
        )
        for extra_environment, expected_code, expected_stdout, expected_stderr in recovery_cases:
            completed = subprocess.run(
                [bash, "-c", reconcile_harness], stdin=subprocess.DEVNULL,
                stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, timeout=10,
                env={**os.environ, **extra_environment}, check=False,
            )
            if (
                completed.returncode != expected_code
                or completed.stdout != expected_stdout
                or completed.stderr != expected_stderr
            ):
                raise RuntimeError(
                    "Executable pending-journal successor recovery or fixed failure category differs: "
                    f"expected=({expected_code}, {expected_stdout!r}, {expected_stderr!r}) "
                    f"actual=({completed.returncode}, {completed.stdout!r}, {completed.stderr!r})."
                )

    if operator_sudoers.splitlines() != [
        'Defaults:mochirii-forums-operator env_keep += "SSH_CONNECTION"',
        "mochirii-forums-operator ALL=(ALL:ALL) NOPASSWD: ALL",
    ]:
        raise RuntimeError("Operator sudoers does not preserve only the live SSH session evidence.")
    if "PermitRootLogin no" in prepared or "AllowUsers " in prepared:
        raise RuntimeError("Prepared SSH policy can lock out bootstrap before operator proof.")
    required_hardening = (
        "AuthorizedKeysCommand none", "TrustedUserCAKeys none", "AuthorizedPrincipalsFile none",
        "AuthorizedKeysCommandUser nobody", "AuthorizedPrincipalsCommand none",
        "AuthorizedPrincipalsCommandUser nobody", "PermitUserEnvironment no",
        "AuthorizedKeysFile /var/lib/mochirii/forums/operator/.ssh/authorized_keys",
        "AuthorizedKeysFile /var/lib/mochirii/forums/deploy/.ssh/authorized_keys",
        "ForceCommand /usr/local/libexec/mochirii-forums/ssh-deploy-dispatch.py",
        "DisableForwarding yes", "PermitUserRC no", "PermitRootLogin no",
        "PasswordAuthentication no", "KbdInteractiveAuthentication no",
    )
    if any(value not in hardened for value in required_hardening):
        raise RuntimeError("Hardened SSH sole-source or confinement policy differs.")
    if "authorized_keys2" in installer + prepared + hardened or 'write_text("restrict " + source + "\\n"' not in installer:
        raise RuntimeError("Authorized-key publication regained a second file or key-owned forced command.")
    if "mochirii-forums-upgrade-host-control" in dispatcher:
        raise RuntimeError("Deploy SSH principal gained host-control upgrade authority.")
    if 'sudo -l -U "${deploy_user}" "${forbidden}"' not in installer or "/usr/local/sbin/mochirii-forums-upgrade-host-control" not in installer:
        raise RuntimeError("Installer does not prove the deploy principal lacks control-upgrade authority.")
    if not all(value in installer for value in (
        'Prepared installation cannot replace an already hardened host',
        'for hardened_record in "${state_root}/current-host-access.json" "${state_root}/current-host-control.json"',
        'validate_operator_proof() {',
        'getattr(os, "O_NOFOLLOW", 0)',
        'getattr(os, "O_NONBLOCK", 0)',
        'metadata.st_uid != 0', 'metadata.st_gid != 0',
        'stat.S_IMODE(metadata.st_mode) != 0o600', 'metadata.st_nlink != 1',
        'expected = b"operatorSshAndSudoVerified=true\\n"',
        'host-access-install.pending.json', 'os.fsync(writer.fileno())',
        'install -d -m 0755 -o root -g root /var/lib/mochirii "${state_root}"',
        'install -d -m 0755 -o root -g root "${state_root}/deploy/.ssh"',
        'atomic_install "${candidate}" "${target}" 0644',
        'sudo -u "${deploy_user}" test -r "${state_root}/deploy/.ssh/authorized_keys"',
        'sudo -u "${operator_user}" test -r "${state_root}/operator/.ssh/authorized_keys"',
        'timeout --signal=TERM --kill-after=5s 15s sshd -T',
        'authorizedkeyscommanduser', 'authorizedprincipalscommanduser',
        'permituserenvironment',
    )):
        raise RuntimeError("Initial host-control publication or hardened-retry boundary differs.")
    if installer.count('validate_operator_proof "${proof}" || fail "Existing operator SSH proof is unsafe."') != 2:
        raise RuntimeError("Initial host-control publication does not validate the exact partial operator proof in both recovery paths.")
    hardened_gate = installer.index('for hardened_record in "${state_root}/current-host-access.json" "${state_root}/current-host-control.json"')
    partial_proof_gate = installer.index('proof="${state_root}/operator-ssh-proved"', hardened_gate)
    key_source_gate = installer.index('for source in "${authorized_keys_source}" "${operator_keys_source}"', partial_proof_gate)
    if not hardened_gate < partial_proof_gate < key_source_gate:
        raise RuntimeError("Initial host-control partial-proof recovery runs outside the hardened-state stop boundary.")
    if 'install -d -m 0700 -o root -g root "${state_root}/deploy/.ssh"' in installer:
        raise RuntimeError("Initial host-control publication restored an unreadable SSH directory mode.")
    access_evidence = (ROOT / "scripts/host-control-evidence.py").read_text(encoding="utf-8")
    if any(value not in access_evidence for value in (
        'STATE_ROOT / "deploy/.ssh/authorized_keys", 0o644',
        'STATE_ROOT / "operator/.ssh/authorized_keys", 0o644',
    )):
        raise RuntimeError("Host-access evidence does not bind the privilege-dropped readable key mode.")
    if '"$(stat -c \'%U:%G %a\' "${key_file}")" == "root:root 644"' not in verifier or 'sudo -u "mochirii-forums-${home}" test -r "${key_file}"' not in verifier:
        raise RuntimeError("Terminal host verification does not prove privilege-dropped authorized-key readability.")
    journal_position = upgrade.index('os.link(candidate, journal_path, follow_symlinks=False)')
    timer_stop_position = upgrade.index('systemctl stop mochirii-forums-media-certificate-renew.timer', journal_position)
    first_publication = upgrade.index('atomic_install "${candidate}/${relative}"', timer_stop_position)
    if not journal_position < timer_stop_position < first_publication:
        raise RuntimeError("Control upgrade mutates a timer or target before its durable journal is armed.")
    for required in (
        'fetch --no-tags --depth=1 --refmap= origin refs/heads/main',
        'Host-control upgrade requires the application to be proved stopped.',
        'assert-held --locks primary,media', 'run --locks primary,media', 'rollback_transaction', 'targets_are_new',
        'durable_remove_workdir', 'reconcile_unjournaled_workdirs',
        'validate_effective_hardened_ssh',
        'seal_control_state upgrade', 'verify-host-security.sh',
        '--upgrade-transaction',
        '${SUDO_USER:-} == mochirii-forums-operator',
    ):
        if required not in upgrade:
            raise RuntimeError("Transactional canonical control-upgrade boundary differs.")
    if upgrade.index('fetch --no-tags --depth=1 --refmap= origin refs/heads/main') > upgrade.index('bounded 300s python3 -I -S -B "${candidate}/scripts/validate-repository.py"'):
        raise RuntimeError("Candidate-controlled source can run before canonical-main control binding.")
    binder_start = upgrade.index("bind_invoked_canonical_successor() {")
    binder = upgrade[binder_start : upgrade.index("\n}\n", binder_start) + 3]
    remote_binding = binder.index('[[ ${remote_output} == "${requested_commit}"$\'\\trefs/heads/main\' ]] || return 1')
    path_binding = binder.index('validate_reviewed_failed_bootstrap_successor_paths "${invocation_source_root}" "${requested_commit}" "${pending_commit}"')
    if remote_binding > path_binding:
        raise RuntimeError("Changed-successor paths can be evaluated before canonical remote-main binding.")
    clear_start = upgrade.index("clear_transaction() {")
    journal_clear = upgrade.index('durable_remove "${pending_journal}"', clear_start)
    tree_clear = upgrade.index('durable_remove_workdir "${transaction}"', journal_clear)
    orphan_reconcile = upgrade.index('reconcile_unjournaled_workdirs || fail')
    current_control_gate = upgrade.index('Current host-control evidence is absent or unsafe.')
    if not journal_clear < tree_clear or not orphan_reconcile < current_control_gate:
        raise RuntimeError("Host-control completion orphan recovery or durable clearance ordering differs.")

    hostile_host_canaries = (
        "SSH tree contains an alternate key or user-rc source.", "authorizedkeyscommand",
        "authorizedkeyscommanduser", "trustedusercakeys", "authorizedprincipalsfile",
        "authorizedprincipalscommanduser", "permituserenvironment", "Deploy account tuple",
        "service_state fail2ban", "service_state unattended-upgrades", "ufw status verbose",
        "unexpected UFW rule", "unexpected public listener", "Docker service is not enabled and active.",
        "host-control evidenced target bytes differ", "certificate automation target set is partial",
        "host-control evidence target inventory differs",
        "service_state mochirii-forums-media-certificate-renew.timer",
        "An unjournaled host-control upgrade work directory remains.",
        "--upgrade-transaction",
        "timeout --signal=TERM --kill-after=5s",
    )
    if any(value not in verifier for value in hostile_host_canaries):
        raise RuntimeError("Hosted host-security hostile boundary inventory differs.")
    checkout_gate = host_verify.index('verify-discourse-docker-checkout.sh')
    runtime_read = host_verify.index("docker inspect --format '{{.State.Running}}' app")
    if checkout_gate > runtime_read or "diff --no-ext-diff --quiet HEAD --" not in host_verify or host_verify.count("status --porcelain=v1 --untracked-files=all") != 2:
        raise RuntimeError("Hosted verification does not prove sealed deployment and running source bytes first.")
    if host_verify.count('timeout --signal=TERM --kill-after=10s 180s bash "${release_dir}/scripts/verify-runtime-assets.sh"') != 2:
        raise RuntimeError("Hosted runtime-asset verification is not bounded before and after daemon readback.")
    for line in host_verify.splitlines():
        if re.search(r"\bdocker\s+(?:inspect|image inspect|exec)\b", line) and "timeout --signal=TERM --kill-after=" not in line:
            raise RuntimeError("Hosted verification contains an unbounded Docker daemon readback.")
    checkout = (ROOT / "scripts/verify-discourse-docker-checkout.sh").read_text(encoding="utf-8")
    for line in checkout.splitlines():
        if re.search(r"\bdocker\s+(?:image inspect|rm|container ls|run)\b", line) and "timeout --signal=TERM --kill-after=" not in line:
            raise RuntimeError("Sealed deployment checkout contains an unbounded Docker daemon call.")

    required_mode_split = (
        'for directory in "${evidence_root}" "${operator_evidence_root}"; do',
        '[[ "$(stat -c \'%U:%G %a\' "${directory}")" == "root:root 700" ]]',
        '[[ -d ${state_root} && ! -L ${state_root} && "$(stat -c \'%U:%G %a\' "${state_root}")" == "root:root 755" ]]',
    )
    if any(value not in finalizer for value in required_mode_split):
        raise RuntimeError("Authentication finalizer state-root traversal and sensitive-directory modes conflict.")


def test_host_control_predecessor_archive_binding() -> None:
    upgrade = (ROOT / "scripts/upgrade-host-control.sh").read_text(encoding="utf-8")

    def assert_contract(source: str) -> None:
        required = (
            'readonly host_control_releases_root="/opt/mochirii/forums/host-control-releases"',
            "bind_previous_source() {",
            "PREDECESSOR_ARCHIVE_BINDING_PYTHON_BEGIN",
            '"releaseArchiveFile", "releaseArchiveSha256", "releaseArchiveBytes"',
            'json.loads(raw_pointer.decode("utf-8"), object_pairs_hook=strict_object)',
            'document.get("releaseArchiveFile") != str(archive)',
            'exact_regular(helper_path, 0o600, 2 * 1024 * 1024, "Candidate archive authority")',
            'metadata.st_nlink != 1',
            'module.inspect_archive(sealed_archive, commit)',
            'module.extract_exact(sealed_archive, identity, source_root)',
            'module.source_identity(source_root)',
            'tar --no-same-owner --no-same-permissions -xf "${archive}" -C "${candidate}"',
            'bind_previous_source "${transaction}/backup/current-host-control.json" "${transaction}" "${candidate}" verify',
            'if ! predecessor_output="$(',
            'readarray -t predecessor_state <<<"${predecessor_output}"',
            '[[ ${previous_evidence_sha} == "${previous_sha}" ]]',
            'bind_previous_source "${control_pointer}" "${staging}" "${candidate}" prepare',
            'if ! previous_state_output="$(',
            'readarray -t previous_state <<<"${previous_state_output}"',
            'previous_source="${transaction}/previous-source/${previous_commit}"',
        )
        if any(value not in source for value in required):
            raise RuntimeError("Host-control predecessor archive binding is incomplete.")
        if source.count("metadata.st_nlink != 1") != 2:
            raise RuntimeError("Host-control predecessor link-count coverage differs.")
        if '/opt/mochirii/forums/releases/${previous_commit}' in source:
            raise RuntimeError("Host-control upgrade still assumes an application release for its predecessor.")
        candidate_validation = source.index(
            'bounded 300s python3 -I -S -B "${candidate}/scripts/validate-repository.py"'
        )
        predecessor_prepare = source.index(
            'bind_previous_source "${control_pointer}" "${staging}" "${candidate}" prepare',
            candidate_validation,
        )
        predecessor_gate = source.index(
            'ssh_predecessor="$(ssh_activation_predecessor)"', predecessor_prepare
        )
        retained_archives = source.index(
            'retain_disaster_recovery_sources "${archive}"', predecessor_gate
        )
        transaction_move = source.index('mv -- "${staging}" "${transaction}"', retained_archives)
        moved_source = source.index(
            'previous_source="${transaction}/previous-source/${previous_commit}"', transaction_move
        )
        journal = source.index('os.link(candidate, journal_path, follow_symlinks=False)', moved_source)
        first_publication = source.index('atomic_install "${candidate}/${relative}"', journal)
        if not (
            candidate_validation
            < predecessor_prepare
            < predecessor_gate
            < retained_archives
            < transaction_move
            < moved_source
            < journal
            < first_publication
        ):
            raise RuntimeError("Host-control predecessor reconstruction ordering differs.")
        reconcile = source.index("reconcile_pending() {")
        predecessor_verify = source.index(
            'bind_previous_source "${transaction}/backup/current-host-control.json"', reconcile
        )
        target_classification = source.index(
            "if [[ ${successor_recovery} == false ]] && targets_are_new; then",
            predecessor_verify,
        )
        if not reconcile < predecessor_verify < target_classification:
            raise RuntimeError("Interrupted host-control recovery trusts targets before predecessor binding.")

    assert_contract(upgrade)
    mutations = (
        upgrade.replace("module.inspect_archive(sealed_archive, commit)", "module.inspect_archive(sealed_archive)", 1),
        upgrade.replace("module.extract_exact(sealed_archive, identity, source_root)", "pass", 1),
        upgrade.replace("module.source_identity(source_root)", "(tree, content_manifest)", 1),
        upgrade.replace('metadata.st_nlink != 1', 'False', 1),
        upgrade.replace(
            'exact_regular(helper_path, 0o600, 2 * 1024 * 1024, "Candidate archive authority")',
            'exact_regular(helper_path, 0o644, 2 * 1024 * 1024, "Candidate archive authority")',
            1,
        ),
        upgrade.replace('document.get("releaseArchiveFile") != str(archive)', 'False', 1),
        upgrade.replace(
            'bind_previous_source "${transaction}/backup/current-host-control.json"',
            'bind_previous_source "${control_pointer}"',
            1,
        ),
        upgrade.replace(
            'previous_source="${transaction}/previous-source/${previous_commit}"',
            'previous_source="${staging}/previous-source/${previous_commit}"',
            1,
        ),
        upgrade.replace(
            'json.loads(raw_pointer.decode("utf-8"), object_pairs_hook=strict_object)',
            'json.loads(raw_pointer.decode("utf-8"))',
            1,
        ),
        upgrade.replace(
            'tar --no-same-owner --no-same-permissions -xf "${archive}" -C "${candidate}"',
            'tar -xf "${archive}" -C "${candidate}"',
            1,
        ),
    )
    for mutant in mutations:
        try:
            assert_contract(mutant)
        except RuntimeError:
            continue
        raise RuntimeError("Host-control predecessor archive mutation escaped the contract test.")

    if os.name == "posix":
        bash = shutil.which("bash")
        if bash is None:
            raise RuntimeError("Bash is required for the predecessor binding status fixture.")
        capture_blocks = (
            (
                upgrade[upgrade.index('  local predecessor_output=""'):upgrade.index(
                    '  local previous_commit="${predecessor_state[0]}"'
                )],
                "transaction=/transaction\ncandidate=/candidate\n",
                "Pending host-control predecessor source is invalid.\n",
            ),
            (
                upgrade[upgrade.index('previous_state_output=""'):upgrade.index(
                    'previous_commit="${previous_state[0]}"'
                )],
                "control_pointer=/pointer\nstaging=/staging\ncandidate=/candidate\n",
                "Current trusted host-control predecessor archive could not be reconstructed.\n",
            ),
        )
        for block, variables, expected_error in capture_blocks:
            harness = (
                "set -u\n"
                "fail() { printf '%s\\n' \"$1\" >&2; exit 73; }\n"
                "bind_previous_source() { return 41; }\n"
                "probe() {\n"
                + variables
                + block
                + "}\nprobe\nexit 0\n"
            )
            completed = subprocess.run(
                [bash, "-c", harness],
                stdin=subprocess.DEVNULL,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                timeout=10,
                check=False,
            )
            if completed.returncode != 73 or completed.stdout or completed.stderr != expected_error:
                raise RuntimeError("Predecessor binding producer failure did not reach its fixed category.")

    bounded_block = upgrade.split("# PREDECESSOR_ARCHIVE_BINDING_PYTHON_BEGIN", 1)[1].split(
        "# PREDECESSOR_ARCHIVE_BINDING_PYTHON_END", 1
    )[0]
    python_body = bounded_block.split("<<'PY'\n", 1)[1].rsplit("\nPY", 1)[0]
    ast.parse(python_body, filename="upgrade-host-control predecessor archive binding")

    with process_umask(0o077), tempfile.TemporaryDirectory(
        prefix="mochirii-control-predecessor-"
    ) as directory:
        fixture = Path(directory)
        source_repository = fixture / "source-repository"
        source_repository.mkdir()
        required_files = {
            "AGENTS.md": "fixture authority\n",
            "config/app.yml.example": "templates: []\n",
            "docs/operations/RECOVERY.md": "# Recovery\n",
            "scripts/render-app-config.py": "#!/usr/bin/env python3\n",
            "scripts/validate-repository.py": "#!/usr/bin/env python3\n",
        }
        for relative, payload in required_files.items():
            target = source_repository / relative
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_text(payload, encoding="utf-8", newline="\n")
            target.chmod(0o755 if relative.endswith(".py") else 0o644)
        environment = {
            **os.environ,
            "GIT_CONFIG_NOSYSTEM": "1",
            "GIT_CONFIG_GLOBAL": os.devnull,
            "GIT_AUTHOR_NAME": "Mochirii Fixture",
            "GIT_AUTHOR_EMAIL": "fixture@example.invalid",
            "GIT_COMMITTER_NAME": "Mochirii Fixture",
            "GIT_COMMITTER_EMAIL": "fixture@example.invalid",
        }
        subprocess.run(["git", "init", "--quiet", str(source_repository)], check=True, env=environment)
        subprocess.run(["git", "-C", str(source_repository), "add", "."], check=True, env=environment)
        subprocess.run(
            ["git", "-c", "commit.gpgsign=false", "-C", str(source_repository), "commit", "--quiet", "-m", "fixture"],
            check=True,
            env=environment,
        )
        commit = subprocess.run(
            ["git", "-C", str(source_repository), "rev-parse", "HEAD"],
            check=True,
            capture_output=True,
            text=True,
            env=environment,
        ).stdout.strip()

        archive_root = fixture / "host-control-releases"
        archive_root.mkdir(mode=0o755)
        archive_root.chmod(0o755)
        commit_archive_root = archive_root / commit
        commit_archive_root.mkdir(mode=0o700)
        archive = commit_archive_root / "mochirii-release.tar"
        subprocess.run(
            ["git", "-c", "tar.umask=0002", "-C", str(source_repository), "archive", "--format=tar", f"--output={archive}", commit],
            check=True,
            env=environment,
        )
        archive.chmod(0o600)
        helper = ROOT / "scripts/historical-release-disaster-recovery.py"
        inspection = subprocess.run(
            [sys.executable, "-B", str(helper), "inspect", "--archive", str(archive), "--expected-commit", commit],
            check=True,
            capture_output=True,
            text=True,
            timeout=30,
        )
        identity = json.loads(inspection.stdout)

        state_root = fixture / "state"
        state_root.mkdir(mode=0o755)
        state_root.chmod(0o755)
        upgrades_root = state_root / "control-upgrades"
        upgrades_root.mkdir(mode=0o700)
        pointer_document = {
            "schemaVersion": 1,
            "phase": "hardened",
            "repositoryCommit": commit,
            "repositoryTree": identity["repositoryTree"],
            "manifestSha256": "1" * 64,
            "targetSetSha256": "2" * 64,
            "controlEvidenceFile": "/var/lib/mochirii/forums/evidence/fixture.json",
            "controlEvidenceSha256": "3" * 64,
            "releaseArchiveFile": str(archive),
            "releaseArchiveSha256": identity["releaseArchiveSha256"],
            "releaseArchiveBytes": identity["releaseArchiveBytes"],
            "releaseArchiveContentManifestSha256": identity["releaseArchiveContentManifestSha256"],
            "deploymentSourceRevision": "4" * 40,
            "deploymentSourceTree": "5" * 40,
            "deploymentSourceArchiveFile": "/opt/mochirii/forums/deployment-source/fixture.tar",
            "deploymentSourceArchiveSha256": "6" * 64,
            "deploymentSourceArchiveBytes": 1,
            "deploymentSourceContentManifestSha256": "7" * 64,
        }
        pointer = state_root / "current-host-control.json"
        pointer.write_text(
            json.dumps(pointer_document, sort_keys=True, separators=(",", ":")) + "\n",
            encoding="utf-8",
            newline="\n",
        )
        pointer.chmod(0o600)
        expected_uid = os.getuid() if hasattr(os, "getuid") else 0
        expected_gid = os.getgid() if hasattr(os, "getgid") else 0

        def make_candidate(work_root: Path) -> Path:
            candidate = work_root / "source"
            scripts = candidate / "scripts"
            scripts.mkdir(parents=True)
            candidate.chmod(0o700)
            scripts.chmod(0o755)
            shutil.copyfile(helper, scripts / helper.name)
            (scripts / helper.name).chmod(0o600)
            return candidate

        def run_binding(
            pointer_path: Path, work_root: Path, candidate: Path, action: str
        ) -> subprocess.CompletedProcess[str]:
            return subprocess.run(
                [
                    sys.executable,
                    "-B",
                    "-",
                    str(pointer_path),
                    str(work_root),
                    str(candidate),
                    action,
                    str(state_root),
                    str(upgrades_root),
                    str(archive_root),
                    str(expected_uid),
                    str(expected_gid),
                ],
                input=python_body,
                text=True,
                capture_output=True,
                check=False,
                timeout=30,
            )

        staging = state_root / f".control-upgrade-staging-{'8' * 40}.ABCDEFGH"
        staging.mkdir(mode=0o700)
        candidate = make_candidate(staging)
        prepared = run_binding(pointer, staging, candidate, "prepare")
        if prepared.returncode != 0 or prepared.stderr:
            raise RuntimeError("Valid sealed predecessor archive could not be prepared.")
        prepared_rows = prepared.stdout.splitlines()
        if prepared_rows[:2] != [commit, "3" * 64] or Path(prepared_rows[2]) != staging / "previous-source" / commit:
            raise RuntimeError("Prepared predecessor archive output differs.")

        if os.name != "nt":
            wrong_mode_staging = state_root / f".control-upgrade-staging-{'b' * 40}.QRSTUVWX"
            wrong_mode_staging.mkdir(mode=0o700)
            wrong_mode_candidate = make_candidate(wrong_mode_staging)
            (wrong_mode_candidate / "scripts" / helper.name).chmod(0o644)
            if run_binding(pointer, wrong_mode_staging, wrong_mode_candidate, "prepare").returncode == 0:
                raise RuntimeError("Nonrestrictive candidate archive authority mode passed binding.")

        transaction = upgrades_root / f"{'8' * 40}-{'9' * 64}"
        os.replace(staging, transaction)
        candidate = transaction / "source"
        backup = transaction / "backup"
        backup.mkdir(mode=0o700)
        backup_pointer = backup / "current-host-control.json"
        shutil.copyfile(pointer, backup_pointer)
        backup_pointer.chmod(0o600)
        verified = run_binding(backup_pointer, transaction, candidate, "verify")
        if verified.returncode != 0 or verified.stderr:
            raise RuntimeError("Moved predecessor transaction could not be verified.")
        if Path(verified.stdout.splitlines()[2]) != transaction / "previous-source" / commit:
            raise RuntimeError("Moved predecessor source did not remain transaction-contained.")

        retained_archive_bytes = archive.read_bytes()
        archive.unlink()
        if run_binding(backup_pointer, transaction, candidate, "verify").returncode != 0:
            raise RuntimeError("Transaction recovery still depends on the external predecessor archive.")
        archive.write_bytes(retained_archive_bytes)
        archive.chmod(0o600)

        sealed_archive = transaction / "previous-release.tar"
        sealed_archive.write_bytes(sealed_archive.read_bytes() + b"x")
        if run_binding(backup_pointer, transaction, candidate, "verify").returncode == 0:
            raise RuntimeError("Changed sealed predecessor archive passed recovery verification.")
        shutil.copyfile(archive, sealed_archive)
        sealed_archive.chmod(0o600)
        extracted_file = transaction / "previous-source" / commit / "AGENTS.md"
        extracted_file.write_text("changed\n", encoding="utf-8", newline="\n")
        if run_binding(backup_pointer, transaction, candidate, "verify").returncode == 0:
            raise RuntimeError("Changed predecessor source passed recovery verification.")

        hostile_staging = state_root / f".control-upgrade-staging-{'a' * 40}.IJKLMNOP"
        hostile_staging.mkdir(mode=0o700)
        hostile_candidate = make_candidate(hostile_staging)
        original_pointer = pointer.read_text(encoding="utf-8")
        duplicate_pointer = original_pointer.replace(
            '"phase":"hardened"', '"phase":"hardened","phase":"hardened"', 1
        )
        pointer.write_text(duplicate_pointer, encoding="utf-8", newline="\n")
        pointer.chmod(0o600)
        if run_binding(pointer, hostile_staging, hostile_candidate, "prepare").returncode == 0:
            raise RuntimeError("Duplicate-key predecessor pointer passed archive binding.")
        pointer.write_text(original_pointer, encoding="utf-8", newline="\n")
        pointer.chmod(0o600)
        archive_hardlink = fixture / "archive-hardlink.tar"
        os.link(archive, archive_hardlink)
        try:
            if run_binding(pointer, hostile_staging, hostile_candidate, "prepare").returncode == 0:
                raise RuntimeError("Multiply linked predecessor archive passed binding.")
        finally:
            archive_hardlink.unlink()
        hostile_document = dict(pointer_document)
        hostile_document["releaseArchiveFile"] = str(fixture / "outside.tar")
        pointer.write_text(
            json.dumps(hostile_document, sort_keys=True, separators=(",", ":")) + "\n",
            encoding="utf-8",
            newline="\n",
        )
        pointer.chmod(0o600)
        if run_binding(pointer, hostile_staging, hostile_candidate, "prepare").returncode == 0:
            raise RuntimeError("Off-boundary predecessor archive path passed binding.")


def test_runtime_rails_execution_contract() -> None:
    expected_wrappers = {
        ".github/workflows/disposable-bootstrap.yml": 14,
        "scripts/host-restore-validate.sh": 19,
        "scripts/host-backup.sh": 5,
        "scripts/verify-discourse-connect.py": 6,
        "scripts/host-deploy.sh": 3,
        "scripts/historical-recovery-scratch-reader.sh": 2,
        "scripts/verify-contained-activation.sh": 2,
        "scripts/verify-host.sh": 2,
        "scripts/host-break-glass-admin.sh": 1,
    }
    sources = {
        relative: (ROOT / relative).read_text(encoding="utf-8")
        for relative in expected_wrappers
    }
    template = (ROOT / "config/app.yml.example").read_text(encoding="utf-8")
    owner_scoped_build_runner = """su discourse -c 'bundle exec rails runner
          \"$MOCHIRII_RELEASE_ASSET_ROOT/configure-site.rb\"'"""
    owner_probe = """sudo docker exec app /usr/local/bin/rails runner 'require \"etc\"; raise unless Process.euid == Etc.getpwnam(\"discourse\").uid; raise unless GitUtils.git_version == \"cbf996f65aae3da1843224aa624bcd9a225931ac\"; ActiveRecord::Base.connection.execute(\"SELECT 1\"); raise if Upload.exists?(sha1: \"0000000000000000000000000000000000000000\")'"""

    def assert_contract(candidate_sources: dict[str, str], candidate_template: str) -> None:
        for relative, expected in expected_wrappers.items():
            source = candidate_sources[relative]
            if (
                "bundle exec rails runner" in source
                or source.count("/usr/local/bin/rails runner") != expected
                or source.count("rails runner") != expected
            ):
                raise RuntimeError(f"Runtime Rails owner-wrapper inventory differs: {relative}")
        if sum(expected_wrappers.values()) != 54:
            raise RuntimeError("Runtime Rails owner-wrapper total differs.")
        if (
            candidate_template.count("bundle exec rails runner") != 1
            or candidate_template.count("rails runner") != 1
            or candidate_template.count(owner_scoped_build_runner) != 1
        ):
            raise RuntimeError("Build-time Rails runner owner scope differs.")
        if candidate_sources[".github/workflows/disposable-bootstrap.yml"].count(owner_probe) != 1:
            raise RuntimeError("Disposable Rails UID/Git/database proof differs.")

    assert_contract(sources, template)

    workflow = sources[".github/workflows/disposable-bootstrap.yml"]
    raw_runtime = dict(sources)
    raw_runtime[".github/workflows/disposable-bootstrap.yml"] = workflow.replace(
        "/usr/local/bin/rails runner", "bundle exec rails runner", 1
    )
    missing_wrapper = dict(sources)
    missing_wrapper[".github/workflows/disposable-bootstrap.yml"] = workflow.replace(
        owner_probe + "\n", "", 1
    )
    extra_wrapper = dict(sources)
    extra_wrapper[".github/workflows/disposable-bootstrap.yml"] = workflow + "\n/usr/local/bin/rails runner\n"
    hostile_cases = (
        (raw_runtime, template),
        (missing_wrapper, template),
        (extra_wrapper, template),
        (sources, template.replace("su discourse -c 'bundle exec rails runner", "bundle exec rails runner", 1)),
    )
    for candidate_sources, candidate_template in hostile_cases:
        try:
            assert_contract(candidate_sources, candidate_template)
        except RuntimeError:
            continue
        raise RuntimeError("Runtime Rails owner-wrapper hostile mutation was accepted.")


def test_disposable_restore_command_diagnostics() -> None:
    workflow = (ROOT / ".github/workflows/disposable-bootstrap.yml").read_text(encoding="utf-8")
    VALIDATOR.validate_disposable_restore_command_diagnostics(workflow)
    marker_guard = "[[ ${marker} =~ ^[a-z0-9][a-z0-9._-]{0,63}$ ]] || return 1"
    failure_output = "printf 'DISPOSABLE_FIXTURE_COMMAND_FAILED:%s\\n' \"${marker}\" >&2"
    suppressed_output = "              >/dev/null 2>&1 &"
    fixed_category_output = (
        "printf 'DISPOSABLE_FIXTURE_COMMAND_FAILED:%s:%s\\n' "
        '"${marker}" "${category}" >&2'
    )
    hostile_workflows = (
        workflow.replace(marker_guard, "[[ ${marker} != *$'\\n'* ]] || return 1", 1),
        workflow.replace(failure_output, "", 1),
        workflow.replace(suppressed_output, "              2>&1 | tee /tmp/disposable-command.log &", 1),
        workflow.replace("'discourse-backup'", "'discourse backup'", 1),
        workflow.replace("'verify-restored-backup-after-rebuild'", "'verify-restored-backup-after-restart'", 1),
        workflow.replace(
            "              64) printf '%s\\n' 'repository-revision' ;;",
            "              64) printf '%s\\n' 'redis' ;;",
            1,
        ),
        workflow.replace("              *) return 1 ;;", "              *) printf '%s\\n' 'unknown' ;;", 1),
        workflow.replace(
            "^verify-restored-backup-(initial|after-restart|after-rebuild)$",
            "^verify-restored-backup-.*$",
            1,
        ),
        workflow.replace(fixed_category_output, failure_output, 1),
        workflow.replace('"${marker}" "${category}" >&2', '"${marker}" "${status}" >&2', 1),
    )
    for hostile_workflow in hostile_workflows:
        if hostile_workflow == workflow:
            raise RuntimeError("Disposable restore diagnostic hostile mutation anchor is absent.")
        try:
            VALIDATOR.validate_disposable_restore_command_diagnostics(hostile_workflow)
        except RuntimeError:
            continue
        raise RuntimeError("Disposable restore diagnostic hostile mutation was accepted.")


def test_disposable_nginx_fixture_final_command_contract() -> None:
    fixture = (ROOT / "scripts/test-disposable-launcher-guard.py").read_text(encoding="utf-8")
    VALIDATOR.validate_disposable_nginx_fixture_final_command_contract(fixture)
    hostile_fixtures = (
        fixture.replace("        extractor = r'''\n", "        _extractor = r'''\n", 1),
        fixture.replace("final_commands.length == 12", "final_commands.length == 11", 1),
        fixture.replace("final_commands.fetch(-5) == expected_header_include", "final_commands.fetch(-4) == expected_header_include", 1),
        fixture.replace(
            'abort "final private username-log command differs" unless final_commands.fetch(-4) == expected_private_username_log\n',
            "",
            1,
        ),
        fixture.replace(
            'abort "final username-log exclusion command differs" unless final_commands.fetch(-3) == expected_no_username_log\n',
            "",
            1,
        ),
        fixture.replace(
            '[ruby, "-e", extractor, str(rendered), str(prefix)],',
            '[ruby, "-e", extractor + "\\n", str(rendered), str(prefix)],',
            1,
        ),
        fixture.replace(
            "        extracted = subprocess.run(\n",
            "        extractor += \"\"\n        extracted = subprocess.run(\n",
            1,
        ),
        fixture.replace(
            '        if extracted.returncode != 0:\n            raise RuntimeError("Pinned Nginx fixture could not extract the exact outlet inventory.")\n',
            '        if False:\n            if extracted.returncode != 0:\n                raise RuntimeError("Pinned Nginx fixture could not extract the exact outlet inventory.")\n',
            1,
        ),
    )
    for hostile_fixture in hostile_fixtures:
        if hostile_fixture == fixture:
            raise RuntimeError("Disposable Nginx fixture hostile mutation anchor is absent.")
        try:
            VALIDATOR.validate_disposable_nginx_fixture_final_command_contract(hostile_fixture)
        except RuntimeError:
            continue
        raise RuntimeError("Disposable Nginx fixture hostile mutation was accepted.")


def test_effective_allow_users_parser_contract() -> None:
    installer = (ROOT / "scripts/install-host-control.sh").read_text(encoding="utf-8")
    verifier = (ROOT / "scripts/verify-host-security.sh").read_text(encoding="utf-8")
    expected_program = (
        '$1 == "allowusers" { for (i = 2; i <= NF; i++) { '
        'found = found (found == "" ? "" : " ") $i } } END { print found }'
    )
    installer_match = re.search(
        r"effective_allow_users\(\) \{ awk '([^']+)' <<<\"\$1\"; \}", installer
    )
    verifier_match = re.search(
        r"allow_users=\"\$\(awk '([^']+)' <<<\"\$\{effective\}\"\)\"", verifier
    )
    if installer_match is None or verifier_match is None:
        raise RuntimeError("Effective AllowUsers parser is absent from a real host consumer.")
    if installer_match.group(1) != expected_program or verifier_match.group(1) != expected_program:
        raise RuntimeError("Host consumers do not share the reviewed AllowUsers parser.")

    awk = shutil.which("awk")
    if awk is None:
        return
    fixtures = (
        (
            "allowusers mochirii-forums-operator\nallowusers mochirii-forums-deploy\n",
            "mochirii-forums-operator mochirii-forums-deploy",
            True,
        ),
        (
            "allowusers mochirii-forums-operator mochirii-forums-deploy\n",
            "mochirii-forums-operator mochirii-forums-deploy",
            True,
        ),
        (
            "allowusers mochirii-forums-operator\n",
            "mochirii-forums-operator mochirii-forums-deploy",
            False,
        ),
        (
            "allowusers mochirii-forums-operator\nallowusers mochirii-forums-operator\n"
            "allowusers mochirii-forums-deploy\n",
            "mochirii-forums-operator mochirii-forums-deploy",
            False,
        ),
        (
            "permitrootlogin no\nallowusers mochirii-forums-operator\n"
            "allowusers unexpected-principal\nallowusers mochirii-forums-deploy\n",
            "mochirii-forums-operator mochirii-forums-deploy",
            False,
        ),
    )
    for source, expected, should_match in fixtures:
        completed = subprocess.run(
            [awk, expected_program],
            input=source,
            text=True,
            capture_output=True,
            check=False,
            timeout=10,
        )
        if completed.returncode != 0 or completed.stderr:
            raise RuntimeError("Reviewed AllowUsers parser could not execute.")
        matches = completed.stdout.rstrip("\n") == expected
        if matches != should_match:
            raise RuntimeError("Reviewed AllowUsers parser accepted a hostile effective tuple.")


def test_failed_bootstrap_quarantine_contract() -> None:
    source = TRUSTED_QUARANTINE_SOURCE
    upgrader = TRUSTED_UPGRADER_SOURCE
    validator_source = TRUSTED_VALIDATOR_SOURCE
    contract_source = TRUSTED_CONTRACT_SOURCE
    workflow = TRUSTED_WORKFLOW_SOURCE
    manifest = json.loads(TRUSTED_MANIFEST_SOURCE)
    if (
        hashlib.sha256(source.encode("utf-8")).hexdigest()
        != "1792bf339b590c98a9bb5423fa0fd539e29c20c58dd5381be9670bdf0fcdde57"
        or hashlib.sha256(upgrader.encode("utf-8")).hexdigest()
        != "041168ece778a3e60d001b82707216a2b5c785bd3e1ece9d12c0f6e6ba3c91c4"
    ):
        raise RuntimeError("Failed-bootstrap production control source seal differs.")

    def rebase_validator_cli_digest(candidate_source: str) -> str:
        candidate_tree = ast.parse(candidate_source)
        candidate_main = next(
            node
            for node in candidate_tree.body
            if isinstance(node, ast.FunctionDef) and node.name == "main"
        )
        candidate_guard = candidate_tree.body[-1]
        candidate_lines = candidate_source.splitlines(keepends=True)
        entrypoint_source = "".join(
            candidate_lines[candidate_main.lineno - 1 : candidate_guard.end_lineno]
        )
        digest = hashlib.sha256(entrypoint_source.encode("utf-8")).hexdigest()
        rebased, replacements = re.subn(
            r'VALIDATOR_CLI_SOURCE_SHA256 = "[0-9a-f]{64}"',
            f'VALIDATOR_CLI_SOURCE_SHA256 = "{digest}"',
            candidate_source,
            count=1,
        )
        if replacements != 1:
            raise RuntimeError("Repository validator self-digest rebase anchor differs.")
        return rebased

    def rebase_contract_test_digest(
        candidate_validator_source: str, candidate_contract_source: str
    ) -> str:
        digest = hashlib.sha256(candidate_contract_source.encode("utf-8")).hexdigest()
        rebased, replacements = re.subn(
            r'CONTRACT_TEST_SOURCE_SHA256 = "[0-9a-f]{64}"',
            f'CONTRACT_TEST_SOURCE_SHA256 = "{digest}"',
            candidate_validator_source,
            count=1,
        )
        if replacements != 1:
            raise RuntimeError("Hostile fixture digest rebase anchor differs.")
        return rebased

    def rebase_contract_test_function_inventory_digest(
        candidate_validator_source: str, candidate_contract_source: str
    ) -> str:
        digest = contract_test_function_inventory_sha256(candidate_contract_source)
        rebased, replacements = re.subn(
            r'CONTRACT_TEST_FUNCTION_INVENTORY_SHA256 = "[0-9a-f]{64}"',
            f'CONTRACT_TEST_FUNCTION_INVENTORY_SHA256 = "{digest}"',
            candidate_validator_source,
            count=1,
        )
        if replacements != 1:
            raise RuntimeError("Hostile fixture function inventory rebase anchor differs.")
        return rebased

    def rebase_failed_bootstrap_test_digest(
        candidate_validator_source: str, candidate_contract_source: str
    ) -> str:
        digest = contract_test_function_sha256(
            candidate_contract_source, "test_failed_bootstrap_quarantine_contract"
        )
        rebased, replacements = re.subn(
            r'FAILED_BOOTSTRAP_TEST_SHA256 = "[0-9a-f]{64}"',
            f'FAILED_BOOTSTRAP_TEST_SHA256 = "{digest}"',
            candidate_validator_source,
            count=1,
        )
        if replacements != 1:
            raise RuntimeError("Failed-bootstrap fixture digest rebase anchor differs.")
        return rebased

    def rebase_independent_verifier_digest(
        candidate_validator_source: str, candidate_contract_source: str
    ) -> str:
        digest = contract_test_function_sha256(
            candidate_contract_source, "validate_validator_cli_independently"
        )
        rebased, replacements = re.subn(
            r'CONTRACT_TEST_INDEPENDENT_VERIFIER_SHA256 = "[0-9a-f]{64}"',
            f'CONTRACT_TEST_INDEPENDENT_VERIFIER_SHA256 = "{digest}"',
            candidate_validator_source,
            count=1,
        )
        if replacements != 1:
            raise RuntimeError("Independent verifier digest rebase anchor differs.")
        return rebased

    def rebase_independent_verifier_expected_seal(
        candidate_contract_source: str, name: str, digest: str
    ) -> str:
        pattern = (
            rf'("{re.escape(name)}": \(\n\s*")[0-9a-f]{{64}}("\n\s*\),)'
        )
        rebased, replacements = re.subn(
            pattern,
            rf"\g<1>{digest}\g<2>",
            candidate_contract_source,
            count=1,
        )
        if replacements != 1:
            raise RuntimeError("Independent verifier expected-seal rebase anchor differs.")
        return rebased

    VALIDATOR.validate_contract_test_acceptance_chain(contract_source)
    VALIDATOR.validate_validator_cli_acceptance_chain(validator_source)
    validate_validator_cli_independently(
        validator_source, contract_source, TRUSTED_PYTHON_ACCEPTANCE_CONSUMER_SOURCES
    )
    acceptance_mutants = (
        contract_source.replace(
            "def test_failed_bootstrap_quarantine_contract() -> None:\n",
            "def test_failed_bootstrap_quarantine_contract() -> None:\n    return\n",
            1,
        ),
        contract_source.replace(
            "    test_failed_bootstrap_quarantine_contract()\n",
            "    return 0\n    test_failed_bootstrap_quarantine_contract()\n",
            1,
        ),
        contract_source.replace(
            "    test_failed_bootstrap_quarantine_contract()\n",
            "    pass\n",
            1,
        ),
        contract_source.replace(
            "from __future__ import annotations\n",
            "from __future__ import annotations\nraise SystemExit(0)\n",
            1,
        ),
        contract_source.replace(
            "def run_exact_validator(path: Path, source: bytes) -> subprocess.CompletedProcess[bytes]:\n",
            "def run_exact_validator(path: Path, source: bytes) -> subprocess.CompletedProcess[bytes]:\n    raise SystemExit(0)\n",
            1,
        ),
        contract_source.replace(
            'require_exact_validator_result(\n    run_exact_validator(ROOT / "scripts/validate-repository.py", TRUSTED_VALIDATOR_BYTES)\n)\nRENDER = ',
            'RENDER = ',
            1,
        ),
    )
    for mutant in acceptance_mutants:
        expect_validation_failure(
            lambda mutant=mutant: VALIDATOR.validate_contract_test_acceptance_chain(mutant),
            "failed-bootstrap early-success acceptance mutant",
        )

    resealed_acceptance_mutants = (
        contract_source.replace(
            "def main() -> int:\n"
            "    test_failed_bootstrap_quarantine_contract()\n",
            "def main() -> int:\n"
            "    if False:\n"
            "        test_failed_bootstrap_quarantine_contract()\n",
            1,
        ),
        contract_source.replace(
            "\n\ndef main() -> int:\n",
            "\n\ntest_failed_bootstrap_quarantine_contract = lambda: None\n\n\n"
            "def main() -> int:\n",
            1,
        ),
        contract_source.replace(
            '    return 0\n\n\nif __name__ == "__main__":\n',
            '    return 0\n\n\nmain = lambda: 0\n\n\nif __name__ == "__main__":\n',
            1,
        ),
        contract_source.replace(
            "\n\ndef main() -> int:\n",
            '\n\nglobals()["test_failed_bootstrap_quarantine_contract"] = lambda: None\n\n\n'
            "def main() -> int:\n",
            1,
        ),
        contract_source.replace(
            "def test_failed_bootstrap_quarantine_contract() -> None:\n",
            "def _failed_bootstrap_acceptance_noop(_function):\n"
            "    return lambda: None\n\n\n"
            "@_failed_bootstrap_acceptance_noop\n"
            "def test_failed_bootstrap_quarantine_contract() -> None:\n",
            1,
        ),
        contract_source.replace(
            "def main() -> int:\n",
            "def _main_acceptance_noop(_function):\n"
            "    return lambda: 0\n\n\n"
            "@_main_acceptance_noop\n"
            "def main() -> int:\n",
            1,
        ),
        contract_source.replace(
            "\n\ndef main() -> int:\n",
            "\n\nsys.modules[__name__].test_failed_bootstrap_quarantine_contract = "
            "lambda: None\n\n\ndef main() -> int:\n",
            1,
        ),
        contract_source.replace(
            '    return 0\n\n\nif __name__ == "__main__":\n',
            '    return 0\n\n\nsys.modules[__name__].main = lambda: 0\n\n\n'
            'if __name__ == "__main__":\n',
            1,
        ),
        contract_source.replace(
            "def main() -> int:\n"
            "    test_failed_bootstrap_quarantine_contract()\n",
            "def main() -> int:\n"
            "    test_failed_bootstrap_quarantine_contract.__globals__.update(\n"
            '        {"test_failed_bootstrap_quarantine_contract": lambda: None}\n'
            "    )\n"
            "    test_failed_bootstrap_quarantine_contract()\n",
            1,
        ),
        contract_source.replace(
            "def main() -> int:\n"
            "    test_failed_bootstrap_quarantine_contract()\n",
            "def main() -> int:\n"
            "    test_failed_bootstrap_quarantine_contract = lambda: None\n"
            "    test_failed_bootstrap_quarantine_contract()\n",
            1,
        ),
        contract_source.replace(
            "def main() -> int:\n",
            "def main(test_failed_bootstrap_quarantine_contract=lambda: None) -> int:\n",
            1,
        ),
        contract_source.replace(
            "\n\ndef main() -> int:\n",
            "\n\ntest_failed_bootstrap_quarantine_contract.__code__ = "
            "(lambda: None).__code__\n\n\ndef main() -> int:\n",
            1,
        ),
        contract_source.replace(
            "def main() -> int:\n"
            "    test_failed_bootstrap_quarantine_contract()\n",
            "def main() -> int:\n"
            "    os.geteuid = lambda: 1\n"
            "    test_failed_bootstrap_quarantine_contract()\n",
            1,
        ),
        contract_source.replace(
            "\n\ndef main() -> int:\n",
            '\n\nexec("test_failed_bootstrap_" + "quarantine_contract = lambda: None")'
            "\n\n\ndef main() -> int:\n",
            1,
        ),
        contract_source.replace(
            "\n\ndef main() -> int:\n",
            "\n\nsys.modules[__name__].__dict__.__setitem__(\n"
            '    "test_failed_bootstrap_quarantine_contract", lambda: None\n'
            ")\n\n\ndef main() -> int:\n",
            1,
        ),
        contract_source.replace(
            "\n\ndef main() -> int:\n",
            "\n\ndef expect_validation_failure(action, label: str) -> None:\n"
            "    return None\n\n\ndef main() -> int:\n",
            1,
        ),
        contract_source.replace(
            "def expect_validation_failure(action, label: str) -> None:\n"
            "    try:\n"
            "        action()\n"
            "    except RuntimeError:\n"
            "        return\n"
            '    raise RuntimeError(f"Repository governance accepted hostile fixture: {label}")\n',
            "def expect_validation_failure(action, label: str) -> None:\n"
            "    return None\n",
            1,
        ),
    )
    for label, mutant in zip(
        (
            "conditional call",
            "protected-symbol rebinding",
            "main rebinding",
            "reflective protected-symbol rebinding",
            "protected-symbol decorator",
            "main decorator",
            "module-attribute protected-symbol rebinding",
            "module-attribute main rebinding",
            "protected globals mapping mutation",
            "local protected-symbol shadowing",
            "default-argument protected-symbol shadowing",
            "protected function-code mutation",
            "root-gate dependency mutation",
            "computed dynamic execution",
            "module-dictionary mapping mutation",
            "duplicate hostile-assertion helper",
            "modified hostile-assertion helper",
        ),
        resealed_acceptance_mutants,
        strict=True,
    ):
        if mutant == contract_source:
            raise RuntimeError(f"Failed-bootstrap {label} mutant anchor differs.")
        resealed_validator_source = rebase_contract_test_digest(validator_source, mutant)
        _validate_validator_cli_structure_independently(resealed_validator_source)
        resealed_validator = module_from_source(
            "scripts/validate-repository.py",
            f"validate_repository_resealed_{label.replace('-', '_').replace(' ', '_')}",
            resealed_validator_source.encode("utf-8"),
        )
        expect_validation_failure(
            lambda resealed_validator=resealed_validator, mutant=mutant: (
                resealed_validator.validate_contract_test_acceptance_chain(mutant)
            ),
            f"failed-bootstrap resealed {label} acceptance mutant",
        )
    fully_resealed_helper_validator = rebase_contract_test_function_inventory_digest(
        rebase_contract_test_digest(validator_source, resealed_acceptance_mutants[-1]),
        resealed_acceptance_mutants[-1],
    )
    expect_validation_failure(
        lambda: _validate_validator_cli_structure_independently(
            fully_resealed_helper_validator
        ),
        "independent verifier fully resealed hostile-helper mutant",
    )
    fully_resealed_protected_validator = rebase_failed_bootstrap_test_digest(
        rebase_contract_test_function_inventory_digest(
            rebase_contract_test_digest(validator_source, acceptance_mutants[0]),
            acceptance_mutants[0],
        ),
        acceptance_mutants[0],
    )
    expect_validation_failure(
        lambda: _validate_validator_cli_structure_independently(
            fully_resealed_protected_validator
        ),
        "independent verifier fully resealed protected-fixture mutant",
    )
    annotated_override_validator = rebase_contract_test_digest(
        validator_source, acceptance_mutants[0]
    ).replace(
        "\n\ndef main() -> int:\n",
        "\n\nCONTRACT_TEST_FUNCTION_INVENTORY_SHA256: str = \""
        + contract_test_function_inventory_sha256(acceptance_mutants[0])
        + "\"\nFAILED_BOOTSTRAP_TEST_SHA256: str = \""
        + contract_test_function_sha256(
            acceptance_mutants[0], "test_failed_bootstrap_quarantine_contract"
        )
        + "\"\n\n\ndef main() -> int:\n",
        1,
    )
    if annotated_override_validator == validator_source:
        raise RuntimeError("Repository validator annotated override anchor differs.")
    expect_validation_failure(
        lambda: _validate_validator_cli_structure_independently(
            annotated_override_validator
        ),
        "independent verifier annotated protected-seal override",
    )
    annotated_override_module = module_from_source(
        "scripts/validate-repository.py",
        "validate_repository_annotated_protected_seal_override",
        annotated_override_validator.encode("utf-8"),
    )
    expect_validation_failure(
        lambda: annotated_override_module.validate_validator_cli_acceptance_chain(
            annotated_override_validator
        ),
        "validator annotated protected-seal override",
    )
    with tempfile.TemporaryDirectory(
        prefix="mochirii-failed-bootstrap-validator-early-success-"
    ) as directory:
        scripts = Path(directory) / "scripts"
        scripts.mkdir(parents=True)
        validator = scripts / "validate-repository.py"
        validator.write_text(
            validator_source.replace(
                "from __future__ import annotations\n",
                "from __future__ import annotations\nraise SystemExit(0)\n",
                1,
            ),
            encoding="utf-8",
            newline="\n",
        )
        try:
            require_exact_validator_result(run_exact_validator(validator, validator.read_bytes()))
        except RuntimeError:
            pass
        else:
            raise RuntimeError("Early-success repository validator passed its actual acceptance wrapper.")

    validator_success_decoy = validator_source.replace(
        "def main() -> int:\n"
        "    global ARCHIVE_MODE, ROOT\n"
        "    validate_validator_cli_acceptance_chain(Path(__file__).read_text(encoding=\"utf-8\"))\n",
        "def main() -> int:\n"
        "    global ARCHIVE_MODE, ROOT\n"
        "    print(\"Repository source contract passed.\")\n"
        "    return 0\n"
        "    validate_validator_cli_acceptance_chain(Path(__file__).read_text(encoding=\"utf-8\"))\n",
        1,
    )
    if validator_success_decoy == validator_source:
        raise RuntimeError("Repository validator exact-success decoy anchor differs.")
    with tempfile.TemporaryDirectory(
        prefix="mochirii-failed-bootstrap-validator-exact-success-decoy-"
    ) as directory:
        scripts = Path(directory) / "scripts"
        scripts.mkdir(parents=True)
        validator = scripts / "validate-repository.py"
        validator.write_text(
            validator_success_decoy,
            encoding="utf-8",
            newline="\n",
        )
        require_exact_validator_result(
            run_exact_validator(validator, validator_success_decoy.encode("utf-8"))
        )
    expect_validation_failure(
        lambda: VALIDATOR.validate_validator_cli_acceptance_chain(validator_success_decoy),
        "repository validator exact-success decoy",
    )
    try:
        _validate_validator_cli_structure_independently(validator_success_decoy)
    except RuntimeError:
        pass
    else:
        raise RuntimeError("Repository validator independent CLI accepted an exact-success decoy.")

    validator_guard_decoy = validator_source.replace(
        "def main() -> int:\n",
        'if __name__ == "__main__":\n'
        '    print("Repository source contract passed.")\n'
        "    raise SystemExit(0)\n\n\n"
        "def main() -> int:\n",
        1,
    )
    validator_decorator_decoy = validator_source.replace(
        "def main() -> int:\n",
        "def exact_success_decorator(function):\n"
        '    if __name__ == "__main__":\n'
        '        print("Repository source contract passed.")\n'
        "        raise SystemExit(0)\n"
        "    return function\n\n\n"
        "@exact_success_decorator\n"
        "def main() -> int:\n",
        1,
    )
    validator_rebased_decoy = rebase_validator_cli_digest(
        validator_source.replace(
            '    validate_validator_cli_acceptance_chain(Path(__file__).read_text(encoding="utf-8"))\n',
            '    validate_validator_cli_acceptance_chain(Path(__file__).read_text(encoding="utf-8"))\n'
            '    print("Repository source contract passed.")\n'
            "    return 0\n",
            1,
        )
    )
    validator_assignment_decoy = validator_source.replace(
        "ROOT = Path(__file__).resolve().parents[1]\n",
        "ROOT = Path(__file__).resolve().parents[1]\n"
        "VALIDATOR_EARLY_SUCCESS = (\n"
        '    print("Repository source contract passed."),\n'
        "    __import__(\"sys\").exit(0),\n"
        ') if __name__ == "__main__" else None\n',
        1,
    )
    for label, decoy in (
        ("earlier main guard", validator_guard_decoy),
        ("main decorator", validator_decorator_decoy),
        ("rebased self-digest", validator_rebased_decoy),
        ("top-level executable assignment", validator_assignment_decoy),
    ):
        if decoy == validator_source:
            raise RuntimeError(f"Repository validator {label} decoy anchor differs.")
        with tempfile.TemporaryDirectory(
            prefix="mochirii-failed-bootstrap-validator-independent-decoy-"
        ) as directory:
            scripts = Path(directory) / "scripts"
            scripts.mkdir(parents=True)
            validator = scripts / "validate-repository.py"
            validator.write_text(decoy, encoding="utf-8", newline="\n")
            require_exact_validator_result(run_exact_validator(validator, decoy.encode("utf-8")))
        try:
            _validate_validator_cli_structure_independently(decoy)
        except RuntimeError:
            pass
        else:
            raise RuntimeError(f"Repository validator independent CLI accepted {label}.")

    validator_sanitizer_decoy = validator_source.replace(
        "from pathlib import Path\n",
        "from pathlib import Path\n"
        "_ORIGINAL_PATH_READ_TEXT = Path.read_text\n"
        "def _sanitized_path_read_text(path, *args, **kwargs):\n"
        "    observed = _ORIGINAL_PATH_READ_TEXT(path, *args, **kwargs)\n"
        "    return observed.replace('print(\"Repository source contract passed.\")\\n    raise SystemExit(0)\\n', '')\n"
        "Path.read_text = _sanitized_path_read_text\n"
        "if __name__ == \"__main__\":\n"
        "    print(\"Repository source contract passed.\")\n"
        "    raise SystemExit(0)\n",
        1,
    )
    if validator_sanitizer_decoy == validator_source:
        raise RuntimeError("Repository validator source-sanitizer decoy anchor differs.")
    with tempfile.TemporaryDirectory(
        prefix="mochirii-failed-bootstrap-validator-source-sanitizer-"
    ) as directory:
        scripts = Path(directory) / "scripts"
        scripts.mkdir(parents=True)
        validator = scripts / "validate-repository.py"
        validator.write_text(validator_sanitizer_decoy, encoding="utf-8", newline="\n")
        require_exact_validator_result(
            run_exact_validator(validator, validator_sanitizer_decoy.encode("utf-8"))
        )
    try:
        _validate_validator_cli_structure_independently(validator_sanitizer_decoy)
    except RuntimeError:
        pass
    else:
        raise RuntimeError("Repository validator independent CLI accepted a source sanitizer.")

    validator_contract_acceptance_decoy = validator_source.replace(
        "def validate_contract_test_acceptance_chain(source: str) -> None:\n",
        "def validate_contract_test_acceptance_chain(source: str) -> None:\n    return\n",
        1,
    )
    if validator_contract_acceptance_decoy == validator_source:
        raise RuntimeError("Repository validator contract-acceptance decoy anchor differs.")
    contract_acceptance_decoy_module = module_from_source(
        "scripts/validate-repository.py",
        "validate_repository_contract_acceptance_decoy",
        validator_contract_acceptance_decoy.encode("utf-8"),
    )
    contract_acceptance_decoy_module.validate_contract_test_acceptance_chain(
        "not valid Python and not the accepted hostile fixture"
    )
    try:
        _validate_validator_cli_structure_independently(
            validator_contract_acceptance_decoy
        )
    except RuntimeError:
        pass
    else:
        raise RuntimeError(
            "Repository validator independent CLI accepted a disabled contract acceptance gate."
        )

    for normalizer in (_normalize_import_path, VALIDATOR._normalize_import_path):
        for hostile_path in (
            "/usr/local/../tmp/untrusted-candidate",
            "/usr/local//tmp/untrusted-candidate",
            "relative/untrusted-candidate",
            "C:/trusted/./untrusted-candidate",
        ):
            try:
                normalizer(hostile_path)
            except RuntimeError:
                continue
            raise RuntimeError("Python import-path normalizer accepted lexical ambiguity.")

    with tempfile.TemporaryDirectory(
        prefix="mochirii-failed-bootstrap-python-startup-"
    ) as directory:
        startup_root = Path(directory)
        sentinel = startup_root / "sitecustomize-loaded"
        (startup_root / "sitecustomize.py").write_text(
            "import os\n"
            "from pathlib import Path\n"
            "Path(os.environ['MOCHIRII_STARTUP_SENTINEL']).write_bytes(b'loaded')\n",
            encoding="utf-8",
            newline="\n",
        )
        environment = {
            **os.environ,
            "PYTHONDONTWRITEBYTECODE": "1",
            "PYTHONPATH": str(startup_root),
            "MOCHIRII_STARTUP_SENTINEL": str(sentinel),
        }
        startup_error = f"Trusted Python startup boundary is unavailable.{os.linesep}".encode(
            "ascii"
        )
        actual_entries = (
            ROOT / "scripts/validate-repository.py",
            ROOT / "scripts/test-contracts.py",
        )
        for candidate in actual_entries:
            sentinel.unlink(missing_ok=True)
            unsafe = subprocess.run(
                [sys.executable, "-B", str(candidate)],
                cwd=ROOT,
                env=environment,
                stdin=subprocess.DEVNULL,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                timeout=20,
                check=False,
            )
            if (
                unsafe.returncode == 0
                or unsafe.stdout
                or unsafe.stderr != startup_error
                or not sentinel.is_file()
            ):
                raise RuntimeError("Ordinary Python startup bypass was not rejected categorically.")

        sentinel.unlink(missing_ok=True)
        safe_validator_arguments = [
            sys.executable,
            "-I",
            "-S",
            "-B",
            str(actual_entries[0]),
        ]
        safe_validator_archive_root = exact_validator_archive_root(actual_entries[0])
        if safe_validator_archive_root is not None:
            safe_validator_arguments.extend(
                ("--archive-root", str(safe_validator_archive_root))
            )
        safe_validator = subprocess.run(
            safe_validator_arguments,
            cwd=ROOT,
            env=environment,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=300,
            check=False,
        )
        require_exact_validator_result(safe_validator)
        if sentinel.exists():
            raise RuntimeError("Isolated validator startup executed sitecustomize.")

        with tempfile.TemporaryDirectory(
            prefix="mochirii-failed-bootstrap-validator-archive-"
        ) as archive_directory:
            archive_root = Path(archive_directory) / "candidate"
            archive_root.mkdir(mode=0o700)
            for relative in sorted(VALIDATOR.ALLOWED_FILES):
                source_path = ROOT / relative
                source_metadata = source_path.lstat()
                if stat.S_ISLNK(source_metadata.st_mode) or not stat.S_ISREG(
                    source_metadata.st_mode
                ):
                    raise RuntimeError("Archive validator fixture source differs.")
                destination = archive_root / relative
                destination.parent.mkdir(parents=True, exist_ok=True)
                shutil.copyfile(source_path, destination)
                destination.chmod(0o644)
            archive_validator = archive_root / "scripts/validate-repository.py"
            require_exact_validator_result(
                run_exact_validator(archive_validator, archive_validator.read_bytes())
            )
            if exact_validator_archive_root(archive_validator) != archive_root.resolve(
                strict=True
            ):
                raise RuntimeError("Archive validator root selection differs.")
            if os.name == "nt":
                def create_junction(link: Path, target: Path) -> None:
                    junction_result = subprocess.run(
                        [
                            "cmd.exe",
                            "/d",
                            "/c",
                            "mklink",
                            "/J",
                            str(link),
                            str(target),
                        ],
                        stdin=subprocess.DEVNULL,
                        stdout=subprocess.PIPE,
                        stderr=subprocess.PIPE,
                        timeout=30,
                        check=False,
                    )
                    if (
                        junction_result.returncode != 0
                        or junction_result.stderr
                        or not os.path.isjunction(link)
                    ):
                        raise RuntimeError("Archive validator junction fixture differs.")

                git_target = Path(archive_directory) / "git-target"
                git_target.mkdir()
                git_junction = archive_root / ".git"
                create_junction(git_junction, git_target)
                try:
                    expect_validation_failure(
                        lambda: exact_validator_archive_root(archive_validator),
                        "archive validator Git reparse boundary",
                    )
                finally:
                    git_junction.rmdir()
                if not git_target.is_dir():
                    raise RuntimeError("Archive validator junction target was altered.")

                root_junction = Path(archive_directory) / "candidate-root-link"
                create_junction(root_junction, archive_root)
                try:
                    expect_validation_failure(
                        lambda: exact_validator_archive_root(
                            root_junction / "scripts" / "validate-repository.py"
                        ),
                        "archive validator root reparse boundary",
                    )
                    direct_root_reparse = subprocess.run(
                        [
                            sys.executable,
                            "-I",
                            "-S",
                            "-B",
                            str(archive_validator),
                            "--archive-root",
                            str(root_junction),
                        ],
                        cwd=archive_root,
                        env=environment,
                        stdin=subprocess.DEVNULL,
                        stdout=subprocess.PIPE,
                        stderr=subprocess.PIPE,
                        timeout=300,
                        check=False,
                    )
                    if (
                        direct_root_reparse.returncode == 0
                        or direct_root_reparse.stdout
                        or b"Archive validation root is linked or special."
                        not in direct_root_reparse.stderr
                    ):
                        raise RuntimeError(
                            "Archive validator CLI accepted a root reparse boundary."
                        )
                finally:
                    root_junction.rmdir()

                scripts_junction_root = Path(archive_directory) / "scripts-link-candidate"
                scripts_junction_root.mkdir()
                scripts_junction = scripts_junction_root / "scripts"
                create_junction(scripts_junction, archive_root / "scripts")
                try:
                    expect_validation_failure(
                        lambda: exact_validator_archive_root(
                            scripts_junction / "validate-repository.py"
                        ),
                        "archive validator scripts reparse boundary",
                    )
                finally:
                    scripts_junction.rmdir()
                if not archive_validator.is_file():
                    raise RuntimeError("Archive validator junction target was altered.")

        safe_contract_probe = subprocess.run(
            [
                sys.executable,
                "-I",
                "-S",
                "-B",
                "-c",
                "import runpy,sys; runpy.run_path(sys.argv[1], run_name='mochirii_contract_probe')",
                str(actual_entries[1]),
            ],
            cwd=ROOT,
            env=environment,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=300,
            check=False,
        )
        if (
            safe_contract_probe.returncode != 0
            or safe_contract_probe.stdout
            or safe_contract_probe.stderr
            or sentinel.exists()
        ):
            raise RuntimeError("Isolated hostile-fixture startup boundary differs.")

        for candidate in actual_entries:
            missing_no_site = subprocess.run(
                [sys.executable, "-I", "-B", str(candidate)],
                cwd=ROOT,
                env=environment,
                stdin=subprocess.DEVNULL,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                timeout=20,
                check=False,
            )
            if (
                missing_no_site.returncode == 0
                or missing_no_site.stdout
                or missing_no_site.stderr != startup_error
            ):
                raise RuntimeError("Python no-site startup requirement is not live.")

        preloaded = subprocess.run(
            [
                sys.executable,
                "-I",
                "-S",
                "-B",
                "-c",
                "import runpy,sys,types; sys.modules['ast']=types.ModuleType('ast'); runpy.run_path(sys.argv[1], run_name='__main__')",
                str(actual_entries[0]),
            ],
            cwd=ROOT,
            env=environment,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=20,
            check=False,
        )
        if (
            preloaded.returncode == 0
            or preloaded.stdout
            or preloaded.stderr != startup_error
        ):
            raise RuntimeError("Preloaded Python module bypass was not rejected categorically.")

    launcher_paths = (
        ".github/workflows/validate-repository.yml",
        "scripts/check-repository.ps1",
        "scripts/check-source-introduction.ps1",
        "scripts/host-deploy.sh",
        "scripts/test-contracts.py",
        "scripts/test-source-introduction.ps1",
        "scripts/upgrade-host-control.sh",
        "scripts/validate-repository.py",
    )
    launcher_sources = {
        relative: (ROOT / relative).read_text(encoding="utf-8")
        for relative in launcher_paths
    }
    VALIDATOR.validate_python_acceptance_launchers(launcher_sources)
    fully_rebased_contract = acceptance_mutants[0]
    fully_rebased_contract = rebase_independent_verifier_expected_seal(
        fully_rebased_contract,
        "CONTRACT_TEST_FUNCTION_INVENTORY_SHA256",
        contract_test_function_inventory_sha256(fully_rebased_contract),
    )
    fully_rebased_contract = rebase_independent_verifier_expected_seal(
        fully_rebased_contract,
        "FAILED_BOOTSTRAP_TEST_SHA256",
        contract_test_function_sha256(
            fully_rebased_contract, "test_failed_bootstrap_quarantine_contract"
        ),
    )
    fully_rebased_validator = rebase_contract_test_digest(
        validator_source, fully_rebased_contract
    )
    fully_rebased_validator = rebase_contract_test_function_inventory_digest(
        fully_rebased_validator, fully_rebased_contract
    )
    fully_rebased_validator = rebase_independent_verifier_digest(
        fully_rebased_validator, fully_rebased_contract
    )
    fully_rebased_validator = rebase_failed_bootstrap_test_digest(
        fully_rebased_validator, fully_rebased_contract
    )
    fully_rebased_module = module_from_source(
        "scripts/validate-repository.py",
        "validate_repository_complete_pair_rebase",
        fully_rebased_validator.encode("utf-8"),
    )
    fully_rebased_module.validate_validator_cli_acceptance_chain(
        fully_rebased_validator
    )
    fully_rebased_module.validate_contract_test_acceptance_chain(
        fully_rebased_contract
    )
    fully_rebased_launchers = dict(launcher_sources)
    fully_rebased_launchers["scripts/validate-repository.py"] = fully_rebased_validator
    fully_rebased_launchers["scripts/test-contracts.py"] = fully_rebased_contract
    expect_validation_failure(
        lambda: fully_rebased_module.validate_python_acceptance_launchers(
            fully_rebased_launchers
        ),
        "externally rooted complete validator and hostile-suite rebase",
    )
    expect_validation_failure(
        lambda: validate_validator_cli_independently(
            fully_rebased_validator,
            fully_rebased_contract,
            TRUSTED_PYTHON_ACCEPTANCE_CONSUMER_SOURCES,
        ),
        "independent verifier complete validator and hostile-suite rebase",
    )
    launcher_mutations = {
        ".github/workflows/validate-repository.yml": (
            "/usr/bin/python3 -I -S -B scripts/test-contracts.py",
            "/usr/bin/python3 -I -B scripts/test-contracts.py",
        ),
        "scripts/check-repository.ps1": (
            "@('-I', '-S', '-B', 'scripts/validate-repository.py')",
            "@('-I', '-B', 'scripts/validate-repository.py')",
        ),
        "scripts/check-source-introduction.ps1": (
            "python -I -S -B",
            "python -I -B",
        ),
        "scripts/host-deploy.sh": (
            'python3 -I -S -B "${candidate}/scripts/test-contracts.py"',
            'python3 -I -B "${candidate}/scripts/test-contracts.py"',
        ),
        "scripts/test-contracts.py": (
            '    arguments = [\n'
            '        sys.executable,\n'
            '        "-I",\n'
            '        "-S",\n'
            '        "-B",\n'
            '        "-c",\n'
            '        EXACT_VALIDATOR_WRAPPER,\n'
            '        str(path),\n'
            '    ]',
            '    arguments = [\n'
            '        sys.executable,\n'
            '        "-I",\n'
            '        "-B",\n'
            '        "-c",\n'
            '        EXACT_VALIDATOR_WRAPPER,\n'
            '        str(path),\n'
            '    ]',
        ),
        "scripts/test-source-introduction.ps1": (
            "python -I -S -B",
            "python -I -B",
        ),
        "scripts/upgrade-host-control.sh": (
            'python3 -I -S -B "${candidate}/scripts/validate-repository.py"',
            'python3 -I -B "${candidate}/scripts/validate-repository.py"',
        ),
    }
    for relative, (before, after) in launcher_mutations.items():
        mutant = dict(launcher_sources)
        mutant[relative] = mutant[relative].replace(before, after, 1)
        if mutant[relative] == launcher_sources[relative]:
            raise RuntimeError("Trusted Python caller mutation anchor differs.")
        expect_validation_failure(
            lambda mutant=mutant: VALIDATOR.validate_python_acceptance_launchers(mutant),
            "trusted Python caller startup flags",
        )
    for relative in ("scripts/validate-repository.py", "scripts/test-contracts.py"):
        mutant = dict(launcher_sources)
        mutant[relative] = f"{mutant[relative]}# exact-success decoy\n"
        expect_validation_failure(
            lambda mutant=mutant: VALIDATOR.validate_python_acceptance_launchers(mutant),
            "trusted Python caller source digest",
        )

    def exact_shell_function(script_source: str, name: str) -> str:
        marker = f"{name}() {{"
        definitions = list(
            re.finditer(
                rf"(?m)^[ \t]*(?:function[ \t]+)?{re.escape(name)}(?:[ \t]*\(\))?[ \t]*\{{",
                script_source,
            )
        )
        if len(definitions) != 1 or definitions[0].group(0) != marker:
            raise RuntimeError(f"Shell function {name} is absent, duplicated, or noncanonical.")
        start = definitions[0].start()
        cursor = start
        heredoc: tuple[str, bool] | None = None
        heredoc_pattern = re.compile(
            r"(?<!<)<<(?P<strip>-)?[ \t]*(?:'(?P<single>[^']+)'|\"(?P<double>[^\"]+)\"|(?P<bare>[A-Za-z_][A-Za-z0-9_]*))"
        )
        while cursor < len(script_source):
            line_end = script_source.find("\n", cursor)
            if line_end < 0:
                raise RuntimeError(f"Shell function {name} is unterminated.")
            line_end += 1
            line = script_source[cursor:line_end]
            body = line[:-1]
            if heredoc is not None:
                delimiter, strip_tabs = heredoc
                candidate = body.lstrip("\t") if strip_tabs else body
                if candidate == delimiter:
                    heredoc = None
            else:
                if line == "}\n":
                    return script_source[start:line_end]
                match = heredoc_pattern.search(body)
                if match is not None:
                    delimiter = match.group("single") or match.group("double") or match.group("bare")
                    heredoc = (delimiter, match.group("strip") is not None)
            cursor = line_end
        raise RuntimeError(f"Shell function {name} is unterminated.")

    def require_exact_line(block: str, line: str, label: str) -> None:
        if block.splitlines().count(line) != 1:
            raise RuntimeError(f"{label} is absent, duplicated, or outside its live section.")

    def assert_failed_bootstrap_runtime_bindings(
        quarantine_source: str,
        upgrade_source: str,
    ) -> None:
        lineage = exact_shell_function(quarantine_source, "validate_source_lineage")
        state = exact_shell_function(quarantine_source, "validate_failed_bootstrap_state")
        identity = exact_shell_function(quarantine_source, "read_quarantine_identity")
        preflight_start = quarantine_source.index('if [[ ${1:-} == --upgrade-preflight ]]; then')
        preflight_end = quarantine_source.index("\nfi\n\n[[ $# -eq 3 ]]", preflight_start) + 4
        preflight = quarantine_source[preflight_start:preflight_end]
        recovery_start = quarantine_source.index(
            'if [[ -e ${pending_journal} || -L ${pending_journal} ]]; then',
            preflight_end,
        )
        recovery_end = quarantine_source.index("\nfi\n[[ ${#preflight[@]}", recovery_start) + 3
        recovery = quarantine_source[recovery_start:recovery_end]
        if not lineage.startswith("validate_source_lineage() {\n"):
            raise RuntimeError("Failed-bootstrap lineage definition is not the live canonical function.")
        require_exact_line(
            state,
            '  validate_source_lineage "${current}" "${failed}" || return 1',
            "Failed-bootstrap retained-state lineage call",
        )
        require_exact_line(
            state,
            '  terminal_staging="${evidence_root}/.${failed}-${journal_sha}-failed-bootstrap-quarantine.json.publish"',
            "Failed-bootstrap retained-state terminal staging derivation",
        )
        require_exact_line(
            preflight,
            '  readarray -t preflight < <(validate_failed_bootstrap_state "$2") || fail "Failed-bootstrap upgrade preflight rejected the retained state."',
            "Failed-bootstrap upgrade-preflight state call",
        )
        pending_recovery_order = (
            '  validate_source_lineage "${current_commit}" "${failed_commit}" || fail "Failed-bootstrap pending recovery source lineage differs before identity repair."',
            '  readarray -t recovery_identity < <(read_quarantine_identity pending "${current_commit}" "${failed_commit}") || fail "Failed-bootstrap pending recovery identity was rejected."',
            '  validate_source_lineage "${current_commit}" "${failed_commit}" || fail "Failed-bootstrap pending recovery source lineage differs after identity repair."',
        )
        terminal_recovery_order = (
            '  validate_source_lineage "${current_commit}" "${failed_commit}" || fail "Failed-bootstrap terminal recovery source lineage differs before identity repair."',
            '  readarray -t recovery_identity < <(read_quarantine_identity terminal "${current_commit}" "${failed_commit}") || fail "Failed-bootstrap terminal recovery identity was rejected."',
            '  validate_source_lineage "${current_commit}" "${failed_commit}" || fail "Failed-bootstrap terminal recovery source lineage differs after identity repair."',
        )
        for label, ordered_lines in (
            ("pending", pending_recovery_order),
            ("terminal", terminal_recovery_order),
        ):
            for line in ordered_lines:
                require_exact_line(recovery, line, f"Failed-bootstrap {label} recovery authority line")
            offsets = tuple(recovery.index(line) for line in ordered_lines)
            if offsets != tuple(sorted(offsets)):
                raise RuntimeError(
                    f"Failed-bootstrap {label} recovery can mutate before source authority."
                )
        require_exact_line(
            recovery,
            '  readarray -t preflight < <(validate_failed_bootstrap_state "${current_commit}") || fail "Failed-bootstrap quarantine rejected the retained state."',
            "Failed-bootstrap active-journal state call",
        )

        bind = exact_shell_function(upgrade_source, "bind_invoked_canonical_successor")
        exception = exact_shell_function(upgrade_source, "validate_failed_bootstrap_upgrade_exception")
        reconcile = exact_shell_function(upgrade_source, "reconcile_pending")
        signal = exact_shell_function(upgrade_source, "handle_signal")
        selector = exact_shell_function(upgrade_source, "select_reviewed_failed_bootstrap_recovery_commit")
        path_validator = exact_shell_function(upgrade_source, "validate_reviewed_failed_bootstrap_successor_paths")
        main_start = upgrade_source.index('[[ ${EUID} -eq 0 ]] || fail "Host-control upgrade must run as root."')
        main = upgrade_source[main_start:]
        exact_section_sha256 = {
            "quarantine-lineage": "f560af0212226cd5499191e7ad91b152e7e4ed3ad3fc0bb490818159ef81b0dc",
            "quarantine-state": "c81b2fc822775b576c4f408a5f49e079923774e08569e2c43d42a9ca5db2bcc1",
            "quarantine-identity": "8ea0576bac3f50f2ea87ff993d9e1f171c23940dba1dd6dd5b6bbe9c23d8e4b3",
            "quarantine-preflight": "77a6756e317ba9e27ccbe09394888df019710121d05605a447365cc00ed1bb9d",
            "quarantine-recovery": "0e632a9a2145a929e087f018ea69769eef5e81609f56e0d37430cd070c31c156",
            "upgrade-selector": "544ba5ce5a8dbb9e2f1772eafa0d6aa9b6de06bf683d58aedc7314d4eb30bf93",
            "upgrade-path-validator": "c49fb1f5da2906d58642819c6a8bcdd81c48d419963bb321a05691e90b652896",
            "upgrade-binder": "7b9a240168ec90ac2ea3f95e42e29236e9a6396d95d421801912334eef4a983b",
            "upgrade-exception": "6ea0d4ff36175b26333ce78608d1f12092da953a192170897c33340411f5dbe3",
            "upgrade-reconcile": "b03a553e5cf91c29525773a82d56b3b3262384d542d2783809dc25966aaed1d2",
            "upgrade-signal": "e0503e70a182944208c5645e339ef0b55a74246ab3e31367203b2f9b0bcdb81f",
            "upgrade-main": "ce155567c0b81494cf94f8a9a0b52c981d28b50c30215d460ec93c85cfd2e12a",
        }
        exact_sections = {
            "quarantine-lineage": lineage,
            "quarantine-state": state,
            "quarantine-identity": identity,
            "quarantine-preflight": preflight,
            "quarantine-recovery": recovery,
            "upgrade-selector": selector,
            "upgrade-path-validator": path_validator,
            "upgrade-binder": bind,
            "upgrade-exception": exception,
            "upgrade-reconcile": reconcile,
            "upgrade-signal": signal,
            "upgrade-main": main,
        }
        for label, block in exact_sections.items():
            if hashlib.sha256(block.encode("utf-8")).hexdigest() != exact_section_sha256[label]:
                raise RuntimeError(f"{label} exact live source section differs.")
        require_exact_line(
            bind,
            '  reviewed_recovery_commit="$(select_reviewed_failed_bootstrap_recovery_commit "${pending_commit}")" || return 1',
            "Host-control reviewed-recovery selector call",
        )
        require_exact_line(
            bind,
            '  validate_reviewed_failed_bootstrap_successor_paths "${invocation_source_root}" "${requested_commit}" "${pending_commit}"',
            "Host-control successor-path validator call",
        )
        require_exact_line(
            exception,
            '  bind_invoked_canonical_successor "${requested_commit}" "${state[0]}"',
            "Host-control active-mutation successor binder call",
        )
        require_exact_line(
            reconcile,
            '    bind_invoked_canonical_successor "${requested_commit}" "${commit}" ||',
            "Host-control pending-journal successor binder call",
        )
        require_exact_line(
            signal,
            '    reconcile_pending "${expected_commit:-invalid}" || true',
            "Host-control signal recovery call",
        )
        require_exact_line(
            main,
            '  validate_failed_bootstrap_upgrade_exception "${expected_commit}" || fail "Host-control upgrade refuses this active deployment mutation."',
            "Host-control active-mutation exception call",
        )
        require_exact_line(
            main,
            '  reconcile_pending "${expected_commit}"',
            "Host-control pending-journal reconciliation call",
        )

    def replace_once(text: str, old: str, new: str) -> str:
        if text.count(old) != 1:
            raise RuntimeError("Hostile call-site fixture no longer identifies one exact source line.")
        return text.replace(old, new, 1)

    def require_binding_rejection(
        quarantine_source: str,
        upgrade_source: str,
        label: str,
    ) -> None:
        try:
            assert_failed_bootstrap_runtime_bindings(quarantine_source, upgrade_source)
        except (RuntimeError, ValueError):
            return
        raise RuntimeError(f"{label} passed the failed-bootstrap runtime binding contract.")

    assert_failed_bootstrap_runtime_bindings(source, upgrader)
    quarantine_calls = (
        '  validate_source_lineage "${current}" "${failed}" || return 1',
        '  readarray -t preflight < <(validate_failed_bootstrap_state "$2") || fail "Failed-bootstrap upgrade preflight rejected the retained state."',
        '  validate_source_lineage "${current_commit}" "${failed_commit}" || fail "Failed-bootstrap pending recovery source lineage differs before identity repair."',
        '  readarray -t recovery_identity < <(read_quarantine_identity pending "${current_commit}" "${failed_commit}") || fail "Failed-bootstrap pending recovery identity was rejected."',
        '  validate_source_lineage "${current_commit}" "${failed_commit}" || fail "Failed-bootstrap pending recovery source lineage differs after identity repair."',
        '  readarray -t preflight < <(validate_failed_bootstrap_state "${current_commit}") || fail "Failed-bootstrap quarantine rejected the retained state."',
        '  validate_source_lineage "${current_commit}" "${failed_commit}" || fail "Failed-bootstrap terminal recovery source lineage differs before identity repair."',
        '  readarray -t recovery_identity < <(read_quarantine_identity terminal "${current_commit}" "${failed_commit}") || fail "Failed-bootstrap terminal recovery identity was rejected."',
        '  validate_source_lineage "${current_commit}" "${failed_commit}" || fail "Failed-bootstrap terminal recovery source lineage differs after identity repair."',
    )
    for index, call in enumerate(quarantine_calls):
        require_binding_rejection(
            replace_once(source, call, "  :"),
            upgrader,
            f"Inert quarantine call-site mutation {index}",
        )
    quarantine_guard = '[[ ${EUID} -eq 0 ]] || fail "Failed-bootstrap quarantine must run as root."'
    for name in ("validate_source_lineage", "validate_failed_bootstrap_state"):
        duplicate = f"function {name} {{\n  return 0\n}}\n"
        require_binding_rejection(
            replace_once(source, quarantine_guard, duplicate + quarantine_guard),
            upgrader,
            f"Late quarantine {name} override",
        )

    upgrade_calls = (
        '  reviewed_recovery_commit="$(select_reviewed_failed_bootstrap_recovery_commit "${pending_commit}")" || return 1',
        '  validate_reviewed_failed_bootstrap_successor_paths "${invocation_source_root}" "${requested_commit}" "${pending_commit}"',
        '  bind_invoked_canonical_successor "${requested_commit}" "${state[0]}"',
        '    bind_invoked_canonical_successor "${requested_commit}" "${commit}" ||',
        '    reconcile_pending "${expected_commit:-invalid}" || true',
        '  validate_failed_bootstrap_upgrade_exception "${expected_commit}" || fail "Host-control upgrade refuses this active deployment mutation."',
        '  reconcile_pending "${expected_commit}"',
    )
    for index, call in enumerate(upgrade_calls):
        require_binding_rejection(
            source,
            replace_once(upgrader, call, "  :"),
            f"Inert host-control call-site mutation {index}",
        )
    upgrade_guard = '[[ ${EUID} -eq 0 ]] || fail "Host-control upgrade must run as root."'
    for name in (
        "select_reviewed_failed_bootstrap_recovery_commit",
        "validate_reviewed_failed_bootstrap_successor_paths",
        "bind_invoked_canonical_successor",
        "validate_failed_bootstrap_upgrade_exception",
        "reconcile_pending",
    ):
        duplicate = f"function {name} {{\n  return 0\n}}\n"
        require_binding_rejection(
            source,
            replace_once(upgrader, upgrade_guard, duplicate + upgrade_guard),
            f"Late host-control {name} override",
        )

    expected_transport = (
        'ssh_options=(-T -i "$key" -o BatchMode=yes -o ClearAllForwardings=yes '
        '-o IdentitiesOnly=yes -o RequestTTY=no -o ServerAliveInterval=30 '
        '-o ServerAliveCountMax=10 -o TCPKeepAlive=yes -o StrictHostKeyChecking=yes '
        '-o UserKnownHostsFile="$known_hosts")'
    )
    if (
        workflow.count(expected_transport) != 1
        or workflow.count('ssh "${ssh_options[@]}" --') != 2
        or re.search(r"(?m)^\s*ssh\s+-T\b", workflow)
    ):
        raise RuntimeError("Deployment workflow lost its one reviewed keepalive transport tuple.")
    control_rows = manifest.get("coreTargets")
    quarantine_rows = [
        row
        for row in control_rows
        if isinstance(row, dict)
        and row.get("target") == "/usr/local/sbin/mochirii-forums-quarantine-failed-bootstrap"
    ] if isinstance(control_rows, list) else []
    if quarantine_rows != [
        {
            "mode": "0755",
            "source": "scripts/quarantine-failed-bootstrap.sh",
            "target": "/usr/local/sbin/mochirii-forums-quarantine-failed-bootstrap",
        }
    ]:
        raise RuntimeError("Failed-bootstrap quarantine is not one exact installed host control.")
    required_source = (
        "validate_source_lineage() {",
        'readonly reviewed_legacy_failed_bootstrap_commit="b2eb4edb17d72f49b6f979b19d9ee4a39b9ffc6f"',
        'readonly reviewed_failed_bootstrap_recovery_commit="1d741eb75d08a226984935aa18e989ee324a0773"',
        'readonly reviewed_active_swap_failed_bootstrap_commit="26e793aada31faeaa8b56308625288164430647c"',
        'readonly reviewed_active_swap_recovery_commit="6e2f1b5c831b992c3222c015836fa180cd591e3e"',
        'readonly reviewed_acme_failed_bootstrap_commit="f564d62a82adf79b8f012a25949826e2b447681d"',
        'readonly reviewed_acme_recovery_commit="85e12f1ce27e1462e7c82e59e1dbf01c190327b9"',
        'readonly reviewed_quarantine_output_failed_bootstrap_commit="c2f0f37ec2f73c41c7d1f63942a7483d1d7ef306"',
        'readonly reviewed_quarantine_output_recovery_commit="8eea740795f0536468e48c5e8cda2ded29b1e51e"',
        'readonly reviewed_acme_reload_privacy_failed_bootstrap_commit="fae3770f0817d05bbfd2520e9657ddc1c8a7ce5d"',
        'readonly reviewed_acme_reload_privacy_recovery_commit="f51c2e8deaf39293c9b97f3aab797b882c3dc628"',
        'readonly reviewed_acme_reload_privacy_recovery_child_commit="591d96484369ae29a8fa4e61219b325997f4b679"',
        'readonly reviewed_acme_reload_privacy_launcher_child_commit="a71bbe8070ca6dadeff3c4966e81bd97fee83cf7"',
        'readonly reviewed_acme_webroot_failed_bootstrap_commit="9110568e09bda4d572eaf2c27a768b9c053048f9"',
        'readonly reviewed_acme_webroot_recovery_commit="bb891aa65ebe8470fa04cdd639185afdad7372f7"',
        'readonly reviewed_acme_material_failed_bootstrap_commit="81e5226e54246686ce0ef80051d4df2cd1b64c5e"',
        'readonly reviewed_acme_material_recovery_commit="64e12c2344fbc04d44b10c495cf9651cac5ac0b8"',
        'readonly reviewed_acme_material_review_authority_commit="af3540426051c94bf26e9661ac68ce8ee720f977"',
        'rev-parse --verify "${current}^1"',
        'rev-list --parents -n 1 "${current}"',
        'rev-parse --verify "${reviewed_acme_material_review_authority_commit}^1"',
        'rev-list --parents -n 1 "${reviewed_acme_material_review_authority_commit}"',
        'rev-parse --verify "${reviewed_recovery_commit}^1"',
        'rev-list --parents -n 1 "${reviewed_recovery_commit}"',
        'GIT_NO_REPLACE_OBJECTS=1',
        '${source_root}/.git/commondir',
        '${source_root}/.git/info/grafts',
        'actual_path_output="$(git -C "${source_root}" diff-tree',
        "validate_quarantine_environment() {",
        "read_quarantine_identity() {",
        'if [[ ${1:-} == --upgrade-preflight ]]',
        "QUARANTINE FAILED MOCHIRII FORUMS BOOTSTRAP",
        "assert-held --locks primary,media",
        "run --locks primary,media",
        "object_pairs_hook=reject_duplicate",
        "list(itertools.islice(evidence.iterdir(), 4097))",
        "def exact_inventory(path, maximum, label):",
        "list(itertools.islice(path.iterdir(), maximum + 1))",
        "def publication_staging(path):",
        "def publication_alias(path, metadata, allow_candidate):",
        "def observe_authority(document, candidate=None):",
        '"${standalone_root}" "${recovery_root}" "${deployment_journal}"',
        "def read_candidate(path):",
        "type(mutation_sha) is str",
        'document.get("standalonePath") == str(standalone)',
        'document.get("quarantinePath") == str(recovery / f"{failed}-{mutation_sha}")',
        'document.get("mutationEvidencePath") == str(',
        "def publication_alias(path, metadata, label):",
        "def finish_publication_alias(path, staging, raw, label):",
        "def finish_publication_update(path, staging, previous_raw, replacement_raw, label):",
        "def finish_mutation_evidence_alias(source, destination, expected_sha):",
        "def observe_pending_publication(document, alias, staged):",
        "def require_mutation_authority(allowed):",
        "def validate_prepared_runtime(document):",
        "def validate_prepared_replay_runtime(document):",
        "def validate_quarantined_runtime(document):",
        "def validate_runtime_quarantined_replay(document):",
        "def validate_clean_runtime(document):",
        "def validate_pending_publication_runtime(document, alias, staged):",
        "def observe_recovery_root():",
        "def preflight_pending_staging():",
        "def preflight_terminal_staging():",
        "def persist_directory(path):",
        "def durable_directory_move(source, destination):",
        "def link_unnamed_staging(descriptor, staging):",
        'raise SystemExit("failed-bootstrap terminal publication staging is unsafe")',
        "os.O_RDWR | os.O_TMPFILE | os.O_NOFOLLOW",
        "link_unnamed_staging(descriptor, staging)",
        "os.link(staging, path, follow_symlinks=False)",
        "# BEGIN_FAILED_BOOTSTRAP_QUARANTINE_TRANSACTION",
        'phase_order = {"prepared": 0, "runtime-quarantined": 1, "clean-boundary": 2, "authority-retired": 3}',
        "durable_directory_move(standalone, quarantine)",
        "durable_directory_move(old_ssl, new_ssl)",
        "os.link(mutation, mutation_evidence, follow_symlinks=False)",
        "fsync_directory(mutation_evidence.parent)",
        "mutation.unlink()",
        "fsync_directory(mutation.parent)",
        'validate_state(state, {"prepared"})',
        "validate_state(state, {phase})",
        'validate_state(terminal_document, {"complete"}, terminal_state=True)',
        "publish(terminal, terminal_document, True)",
        "fsync_directory(terminal.parent)",
        "fsync_directory(new_ssl.parent)",
        "fsync_directory(old_ssl.parent)",
        "# END_FAILED_BOOTSTRAP_QUARANTINE_TRANSACTION",
    )
    if any(value not in source for value in required_source):
        raise RuntimeError("Failed-bootstrap quarantine lost a reviewed reversible transaction boundary.")
    legacy_expected_paths = (
        ".github/workflows/deploy-forums.yml",
        "config/host-control-manifest.v1.json",
        "docs/operations/DEPLOYMENT.md",
        "docs/operations/RECOVERY.md",
        "scripts/quarantine-failed-bootstrap.sh",
        "scripts/test-contracts.py",
        "scripts/upgrade-host-control.sh",
        "scripts/validate-repository.py",
    )
    active_swap_expected_paths = (
        "docs/operations/DEPLOYMENT.md",
        "docs/operations/RECOVERY.md",
        "scripts/quarantine-failed-bootstrap.sh",
        "scripts/test-contracts.py",
        "scripts/upgrade-host-control.sh",
        "scripts/validate-repository.py",
        "scripts/verify-host.sh",
    )
    acme_expected_paths = (
        "config/immutable-letsencrypt.fragment.yml",
        "docs/operations/DEPLOYMENT.md",
        "docs/operations/RECOVERY.md",
        "scripts/quarantine-failed-bootstrap.sh",
        "scripts/test-contracts.py",
        "scripts/upgrade-host-control.sh",
        "scripts/validate-repository.py",
    )
    quarantine_output_expected_paths = (
        "docs/operations/DEPLOYMENT.md",
        "docs/operations/RECOVERY.md",
        "scripts/quarantine-failed-bootstrap.sh",
        "scripts/test-contracts.py",
        "scripts/upgrade-host-control.sh",
        "scripts/validate-repository.py",
    )
    acme_reload_privacy_expected_paths = (
        "config/immutable-letsencrypt.fragment.yml",
        "docs/operations/DEPLOYMENT.md",
        "docs/operations/RECOVERY.md",
        "scripts/disposable-launcher-guard.py",
        "scripts/quarantine-failed-bootstrap.sh",
        "scripts/test-contracts.py",
        "scripts/test-disposable-launcher-guard.py",
        "scripts/upgrade-host-control.sh",
        "scripts/validate-repository.py",
        "scripts/verify-host.sh",
    )
    acme_webroot_expected_paths = (
        "config/immutable-letsencrypt.fragment.yml",
        "docs/operations/DEPLOYMENT.md",
        "docs/operations/RECOVERY.md",
        "scripts/quarantine-failed-bootstrap.sh",
        "scripts/test-contracts.py",
        "scripts/upgrade-host-control.sh",
        "scripts/validate-repository.py",
    )
    acme_material_repair_expected_paths = (
        "config/immutable-letsencrypt.fragment.yml",
        "scripts/test-contracts.py",
        "scripts/validate-repository.py",
    )
    acme_material_review_authority_expected_paths = (
        ".gitattributes",
        ".github/CODEOWNERS",
        ".github/workflows/open-reviewed-source-pr.yml",
        "CONTRIBUTING.md",
        "docs/adr/0001-clean-initialization-and-canonical-ownership.md",
        "scripts/test-contracts.py",
        "scripts/validate-repository.py",
    )
    acme_material_current_expected_paths = (
        ".github/workflows/validate-repository.yml",
        "docs/operations/DEPLOYMENT.md",
        "docs/operations/RECOVERY.md",
        "scripts/check-repository.ps1",
        "scripts/check-source-introduction.ps1",
        "scripts/host-deploy.sh",
        "scripts/quarantine-failed-bootstrap.sh",
        "scripts/test-contracts.py",
        "scripts/test-source-introduction.ps1",
        "scripts/upgrade-host-control.sh",
        "scripts/validate-repository.py",
    )
    acme_material_expected_paths = (
        ".gitattributes",
        ".github/CODEOWNERS",
        ".github/workflows/open-reviewed-source-pr.yml",
        ".github/workflows/validate-repository.yml",
        "CONTRIBUTING.md",
        "config/immutable-letsencrypt.fragment.yml",
        "docs/adr/0001-clean-initialization-and-canonical-ownership.md",
        "docs/operations/DEPLOYMENT.md",
        "docs/operations/RECOVERY.md",
        "scripts/check-repository.ps1",
        "scripts/check-source-introduction.ps1",
        "scripts/host-deploy.sh",
        "scripts/quarantine-failed-bootstrap.sh",
        "scripts/test-contracts.py",
        "scripts/test-source-introduction.ps1",
        "scripts/upgrade-host-control.sh",
        "scripts/validate-repository.py",
    )
    for name, expected_paths in (
        ("legacy_expected_paths", legacy_expected_paths),
        ("active_swap_expected_paths", active_swap_expected_paths),
        ("acme_expected_paths", acme_expected_paths),
        ("quarantine_output_expected_paths", quarantine_output_expected_paths),
        ("acme_reload_privacy_expected_paths", acme_reload_privacy_expected_paths),
        ("acme_webroot_expected_paths", acme_webroot_expected_paths),
        ("acme_material_repair_expected_paths", acme_material_repair_expected_paths),
        (
            "acme_material_review_authority_expected_paths",
            acme_material_review_authority_expected_paths,
        ),
        ("acme_material_current_expected_paths", acme_material_current_expected_paths),
        ("acme_material_expected_paths", acme_material_expected_paths),
    ):
        marker = f"local -ar {name}=("
        block_start = source.index(marker)
        block = source[block_start : source.index("\n  )", block_start)]
        if [line.strip() for line in block.splitlines()[1:]] != list(expected_paths):
            raise RuntimeError("Failed-bootstrap canonical successor path inventory differs.")
    if any(
        value in source
        for value in (
            "rm -rf",
            "shutil.rmtree",
            "mutation_evidence.unlink()",
            "quarantine.rmdir()",
        )
    ):
        raise RuntimeError("Failed-bootstrap quarantine gained retained-evidence deletion authority.")
    if source.count("mutation.unlink()") != 1:
        raise RuntimeError("Failed-bootstrap mutation authority retirement count differs.")
    for value in (
        "validate_failed_bootstrap_upgrade_exception() {",
        "select_reviewed_failed_bootstrap_recovery_commit() {",
        "validate_reviewed_failed_bootstrap_successor_paths() {",
        'readonly reviewed_legacy_failed_bootstrap_commit="b2eb4edb17d72f49b6f979b19d9ee4a39b9ffc6f"',
        'readonly reviewed_failed_bootstrap_recovery_commit="1d741eb75d08a226984935aa18e989ee324a0773"',
        'readonly reviewed_active_swap_failed_bootstrap_commit="26e793aada31faeaa8b56308625288164430647c"',
        'readonly reviewed_active_swap_recovery_commit="6e2f1b5c831b992c3222c015836fa180cd591e3e"',
        'readonly reviewed_acme_failed_bootstrap_commit="f564d62a82adf79b8f012a25949826e2b447681d"',
        'readonly reviewed_acme_recovery_commit="85e12f1ce27e1462e7c82e59e1dbf01c190327b9"',
        'readonly reviewed_quarantine_output_failed_bootstrap_commit="c2f0f37ec2f73c41c7d1f63942a7483d1d7ef306"',
        'readonly reviewed_quarantine_output_recovery_commit="8eea740795f0536468e48c5e8cda2ded29b1e51e"',
        'readonly reviewed_acme_reload_privacy_failed_bootstrap_commit="fae3770f0817d05bbfd2520e9657ddc1c8a7ce5d"',
        'readonly reviewed_acme_reload_privacy_recovery_commit="f51c2e8deaf39293c9b97f3aab797b882c3dc628"',
        'readonly reviewed_acme_reload_privacy_recovery_child_commit="591d96484369ae29a8fa4e61219b325997f4b679"',
        'readonly reviewed_acme_reload_privacy_launcher_child_commit="a71bbe8070ca6dadeff3c4966e81bd97fee83cf7"',
        'readonly reviewed_acme_webroot_failed_bootstrap_commit="9110568e09bda4d572eaf2c27a768b9c053048f9"',
        'readonly reviewed_acme_webroot_recovery_commit="bb891aa65ebe8470fa04cdd639185afdad7372f7"',
        'readonly reviewed_acme_material_failed_bootstrap_commit="81e5226e54246686ce0ef80051d4df2cd1b64c5e"',
        'readonly reviewed_acme_material_recovery_commit="64e12c2344fbc04d44b10c495cf9651cac5ac0b8"',
        'readonly reviewed_acme_material_review_authority_commit="af3540426051c94bf26e9661ac68ce8ee720f977"',
        '[[ -f ${invocation_source_root}/scripts/quarantine-failed-bootstrap.sh && ! -L ${invocation_source_root}/scripts/quarantine-failed-bootstrap.sh && ! -x ${invocation_source_root}/scripts/quarantine-failed-bootstrap.sh ]]',
        'scripts/quarantine-failed-bootstrap.sh" --upgrade-preflight',
        'bind_invoked_canonical_successor "${requested_commit}" "${state[0]}"',
        "deployment_recovery_upgrade=true",
        'terminal_recovery_output="$(bash "${candidate}/scripts/quarantine-failed-bootstrap.sh"',
    ):
        if value not in upgrader:
            raise RuntimeError("Host-control upgrade lost the exact failed-bootstrap successor exception.")
    if '[[ -x ${invocation_source_root}/scripts/quarantine-failed-bootstrap.sh' in upgrader:
        raise RuntimeError("Host-control upgrade still requires executable failed-bootstrap source.")

    if os.name == "posix":
        bash = shutil.which("bash")
        if bash is None:
            raise RuntimeError("Bash is required for the failed-bootstrap source-mode fixture.")
        function_start = upgrader.index("validate_failed_bootstrap_upgrade_exception() {")
        function_source = upgrader[
            function_start : upgrader.index("\n}\n", function_start) + 3
        ]
        with tempfile.TemporaryDirectory(prefix="mochirii-quarantine-source-mode-") as directory:
            fixture_root = Path(directory) / "source"
            fixture_scripts = fixture_root / "scripts"
            fixture_scripts.mkdir(parents=True)
            entrypoint = fixture_scripts / "upgrade-host-control.sh"
            entrypoint.write_text("fixture\n", encoding="utf-8", newline="\n")
            quarantine = fixture_scripts / "quarantine-failed-bootstrap.sh"
            quarantine.write_text(
                "#!/usr/bin/env bash\n"
                "set -eu\n"
                "[[ $# -eq 2 && $1 == --upgrade-preflight && $2 == bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb ]]\n"
                "printf '%s\\n' aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\n",
                encoding="utf-8",
                newline="\n",
            )
            harness = f'''set -u
requested=bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb
bind_invoked_canonical_successor() {{
  [[ $1 == "$requested" && $2 == aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa ]]
}}
{function_source}
validate_failed_bootstrap_upgrade_exception "$requested"
'''
            for mode, should_pass in ((0o644, True), (0o755, False)):
                quarantine.chmod(mode)
                completed = subprocess.run(
                    [bash, "-c", harness, str(entrypoint)],
                    stdin=subprocess.DEVNULL,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    text=True,
                    timeout=10,
                    check=False,
                )
                if (completed.returncode == 0) != should_pass or completed.stdout or completed.stderr:
                    raise RuntimeError(
                        "Executable failed-bootstrap source guard rejected exact 100644 source or accepted executable drift."
                    )

        lineage_start = source.index("validate_source_lineage() {")
        lineage_source = source[lineage_start : source.index("\n}\n", lineage_start) + 3]
        with tempfile.TemporaryDirectory(prefix="mochirii-quarantine-lineage-") as directory:
            lineage_root = Path(directory) / "source"
            (lineage_root / ".git").mkdir(parents=True)
            lineage_harness = f'''set -u
canonical_repository=https://github.com/Mochirii-Wushu/Mochirii-Forums.git
source_root={lineage_root.as_posix()}
current=cccccccccccccccccccccccccccccccccccccccc
reviewed_legacy_failed_bootstrap_commit=b2eb4edb17d72f49b6f979b19d9ee4a39b9ffc6f
reviewed_failed_bootstrap_recovery_commit=1d741eb75d08a226984935aa18e989ee324a0773
reviewed_active_swap_failed_bootstrap_commit=26e793aada31faeaa8b56308625288164430647c
reviewed_active_swap_recovery_commit=6e2f1b5c831b992c3222c015836fa180cd591e3e
reviewed_acme_failed_bootstrap_commit=f564d62a82adf79b8f012a25949826e2b447681d
reviewed_acme_recovery_commit=85e12f1ce27e1462e7c82e59e1dbf01c190327b9
reviewed_quarantine_output_failed_bootstrap_commit=c2f0f37ec2f73c41c7d1f63942a7483d1d7ef306
reviewed_quarantine_output_recovery_commit=8eea740795f0536468e48c5e8cda2ded29b1e51e
reviewed_acme_reload_privacy_failed_bootstrap_commit=fae3770f0817d05bbfd2520e9657ddc1c8a7ce5d
reviewed_acme_reload_privacy_recovery_commit=f51c2e8deaf39293c9b97f3aab797b882c3dc628
reviewed_acme_reload_privacy_recovery_child_commit=591d96484369ae29a8fa4e61219b325997f4b679
reviewed_acme_reload_privacy_launcher_child_commit=a71bbe8070ca6dadeff3c4966e81bd97fee83cf7
reviewed_acme_webroot_failed_bootstrap_commit=9110568e09bda4d572eaf2c27a768b9c053048f9
reviewed_acme_webroot_recovery_commit=bb891aa65ebe8470fa04cdd639185afdad7372f7
reviewed_acme_material_failed_bootstrap_commit=81e5226e54246686ce0ef80051d4df2cd1b64c5e
reviewed_acme_material_recovery_commit=64e12c2344fbc04d44b10c495cf9651cac5ac0b8
reviewed_acme_material_review_authority_commit=af3540426051c94bf26e9661ac68ce8ee720f977
case "${{LINEAGE_KIND:-legacy}}" in
  legacy) failed="$reviewed_legacy_failed_bootstrap_commit"; reviewed="$reviewed_failed_bootstrap_recovery_commit" ;;
  active) failed="$reviewed_active_swap_failed_bootstrap_commit"; reviewed="$reviewed_active_swap_recovery_commit" ;;
  acme) failed="$reviewed_acme_failed_bootstrap_commit"; reviewed="$reviewed_acme_recovery_commit" ;;
  quarantine) failed="$reviewed_quarantine_output_failed_bootstrap_commit"; reviewed="$reviewed_quarantine_output_recovery_commit" ;;
  reload_privacy) failed="$reviewed_acme_reload_privacy_failed_bootstrap_commit"; reviewed="$reviewed_acme_reload_privacy_recovery_commit" ;;
  webroot) failed="$reviewed_acme_webroot_failed_bootstrap_commit"; reviewed="$reviewed_acme_webroot_recovery_commit" ;;
  material) failed="$reviewed_acme_material_failed_bootstrap_commit"; reviewed="$reviewed_acme_material_recovery_commit" ;;
  unknown) failed=dddddddddddddddddddddddddddddddddddddddd; reviewed=eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee ;;
  *) exit 84 ;;
esac
current_parent="$reviewed"
[[ ${{LINEAGE_KIND:-legacy}} != reload_privacy ]] || current_parent="$reviewed_acme_reload_privacy_launcher_child_commit"
[[ ${{LINEAGE_KIND:-legacy}} != material ]] || current_parent="$reviewed_acme_material_review_authority_commit"
bounded() {{ [[ $1 == 120s ]] || return 80; shift; "$@"; }}
git() {{
  [[ -z ${{GIT_DIR+x}} && -z ${{GIT_WORK_TREE+x}} && -z ${{GIT_INDEX_FILE+x}} && -z ${{GIT_OBJECT_DIRECTORY+x}} && -z ${{GIT_ALTERNATE_OBJECT_DIRECTORIES+x}} && -z ${{GIT_COMMON_DIR+x}} && -z ${{GIT_REPLACE_REF_BASE+x}} && -z ${{GIT_ASKPASS+x}} && -z ${{SSH_ASKPASS+x}} && -z ${{GIT_SSH+x}} && -z ${{GIT_SSH_COMMAND+x}} && -z ${{GIT_CONFIG_PARAMETERS+x}} && -z ${{GIT_CONFIG_SYSTEM+x}} && -z ${{GIT_PROTOCOL_FROM_USER+x}} && ${{GIT_TERMINAL_PROMPT:-}} == 0 && ${{GIT_CONFIG_NOSYSTEM:-}} == 1 && ${{GIT_CONFIG_GLOBAL:-}} == /dev/null && ${{GIT_CONFIG_COUNT:-}} == 0 && ${{GIT_NO_REPLACE_OBJECTS:-}} == 1 ]] || return 81
  case "$*" in
    "-C ${{source_root}} rev-parse --verify HEAD^{{commit}}") [[ ${{LINEAGE_MUTATION:-none}} != head ]] && printf '%s\n' "$current" || printf '%s\n' unrelated ;;
    "-C ${{source_root}} symbolic-ref --short -q HEAD") [[ ${{LINEAGE_MUTATION:-none}} != branch ]] && printf '%s\n' main || printf '%s\n' topic ;;
    "-C ${{source_root}} rev-parse --verify ${{current}}^1") [[ ${{LINEAGE_MUTATION:-none}} != recovery-parent ]] && printf '%s\n' "$current_parent" || printf '%s\n' unrelated ;;
    "-C ${{source_root}} rev-list --parents -n 1 ${{current}}") [[ ${{LINEAGE_MUTATION:-none}} != current-parents ]] && printf '%s %s\n' "$current" "$current_parent" || printf '%s %s %s\n' "$current" "$current_parent" unrelated ;;
    "-C ${{source_root}} rev-parse --verify ${{reviewed_acme_reload_privacy_launcher_child_commit}}^1") [[ ${{LINEAGE_MUTATION:-none}} != launcher-child-parent ]] && printf '%s\n' "$reviewed_acme_reload_privacy_recovery_child_commit" || printf '%s\n' unrelated ;;
    "-C ${{source_root}} rev-list --parents -n 1 ${{reviewed_acme_reload_privacy_launcher_child_commit}}") [[ ${{LINEAGE_MUTATION:-none}} != launcher-child-parents ]] && printf '%s %s\n' "$reviewed_acme_reload_privacy_launcher_child_commit" "$reviewed_acme_reload_privacy_recovery_child_commit" || printf '%s %s %s\n' "$reviewed_acme_reload_privacy_launcher_child_commit" "$reviewed_acme_reload_privacy_recovery_child_commit" unrelated ;;
    "-C ${{source_root}} rev-parse --verify ${{reviewed_acme_reload_privacy_recovery_child_commit}}^1") [[ ${{LINEAGE_MUTATION:-none}} != recovery-child-parent ]] && printf '%s\n' "$reviewed" || printf '%s\n' unrelated ;;
    "-C ${{source_root}} rev-list --parents -n 1 ${{reviewed_acme_reload_privacy_recovery_child_commit}}") [[ ${{LINEAGE_MUTATION:-none}} != recovery-child-parents ]] && printf '%s %s\n' "$reviewed_acme_reload_privacy_recovery_child_commit" "$reviewed" || printf '%s %s %s\n' "$reviewed_acme_reload_privacy_recovery_child_commit" "$reviewed" unrelated ;;
    "-C ${{source_root}} rev-parse --verify ${{reviewed_acme_material_review_authority_commit}}^1") [[ ${{LINEAGE_MUTATION:-none}} != review-authority-parent ]] && printf '%s\n' "$reviewed" || printf '%s\n' unrelated ;;
    "-C ${{source_root}} rev-list --parents -n 1 ${{reviewed_acme_material_review_authority_commit}}") [[ ${{LINEAGE_MUTATION:-none}} != review-authority-parents ]] && printf '%s %s\n' "$reviewed_acme_material_review_authority_commit" "$reviewed" || printf '%s %s %s\n' "$reviewed_acme_material_review_authority_commit" "$reviewed" unrelated ;;
    "-C ${{source_root}} rev-parse --verify ${{reviewed}}^1") [[ ${{LINEAGE_MUTATION:-none}} != failed-parent ]] && printf '%s\n' "$failed" || printf '%s\n' unrelated ;;
    "-C ${{source_root}} rev-list --parents -n 1 ${{reviewed}}") [[ ${{LINEAGE_MUTATION:-none}} != recovery-parents ]] && printf '%s %s\n' "$reviewed" "$failed" || printf '%s %s %s\n' "$reviewed" "$failed" unrelated ;;
    "-c core.fsmonitor=false -C ${{source_root}} status --porcelain=v1 --untracked-files=all")
      [[ ${{LINEAGE_MUTATION:-none}} != status-fail ]] || return 83
      [[ ${{LINEAGE_MUTATION:-none}} != dirty ]] || printf '%s\n' ' M retained'
      ;;
    "-C ${{source_root}} remote get-url origin") [[ ${{LINEAGE_MUTATION:-none}} != origin ]] && printf '%s\n' "$canonical_repository" || printf '%s\n' https://example.invalid/other.git ;;
    *"ls-remote --refs ${{canonical_repository}} refs/heads/main") [[ ${{LINEAGE_MUTATION:-none}} != remote ]] && printf '%s\trefs/heads/main\n' "$current" || printf '%s\trefs/heads/main\n' unrelated ;;
    "-C ${{source_root}} diff-tree --no-commit-id --name-only -r ${{reviewed_acme_material_failed_bootstrap_commit}} ${{reviewed_acme_material_recovery_commit}}")
      printf '%s\n' \
        config/immutable-letsencrypt.fragment.yml \
        scripts/test-contracts.py
      [[ ${{LINEAGE_MUTATION:-none}} == material-repair-paths ]] || printf '%s\n' scripts/validate-repository.py
      [[ ${{LINEAGE_MUTATION:-none}} != material-repair-status ]] || return 83
      ;;
    "-C ${{source_root}} diff-tree --no-commit-id --name-only -r ${{reviewed_acme_material_recovery_commit}} ${{reviewed_acme_material_review_authority_commit}}")
      printf '%s\n' \
        .gitattributes \
        .github/CODEOWNERS \
        .github/workflows/open-reviewed-source-pr.yml \
        CONTRIBUTING.md \
        docs/adr/0001-clean-initialization-and-canonical-ownership.md \
        scripts/test-contracts.py
      [[ ${{LINEAGE_MUTATION:-none}} == material-authority-paths ]] || printf '%s\n' scripts/validate-repository.py
      [[ ${{LINEAGE_MUTATION:-none}} != material-authority-status ]] || return 83
      ;;
    "-C ${{source_root}} diff-tree --no-commit-id --name-only -r ${{reviewed_acme_material_review_authority_commit}} ${{current}}")
      printf '%s\n' \
        .github/workflows/validate-repository.yml \
        docs/operations/DEPLOYMENT.md \
        docs/operations/RECOVERY.md \
        scripts/check-repository.ps1 \
        scripts/check-source-introduction.ps1 \
        scripts/host-deploy.sh \
        scripts/quarantine-failed-bootstrap.sh \
        scripts/test-contracts.py \
        scripts/test-source-introduction.ps1 \
        scripts/upgrade-host-control.sh
      [[ ${{LINEAGE_MUTATION:-none}} == material-current-paths ]] || printf '%s\n' scripts/validate-repository.py
      [[ ${{LINEAGE_MUTATION:-none}} != material-current-status ]] || return 83
      ;;
    "-C ${{source_root}} diff-tree --no-commit-id --name-only -r ${{failed}} ${{current}}")
      case "${{LINEAGE_KIND:-legacy}}" in
        active)
          printf '%s\n' \
            docs/operations/DEPLOYMENT.md \
            docs/operations/RECOVERY.md \
            scripts/quarantine-failed-bootstrap.sh \
            scripts/test-contracts.py \
            scripts/upgrade-host-control.sh \
            scripts/validate-repository.py
          [[ ${{LINEAGE_MUTATION:-none}} == paths ]] || printf '%s\n' scripts/verify-host.sh
          ;;
        acme)
          printf '%s\n' \
            config/immutable-letsencrypt.fragment.yml \
            docs/operations/DEPLOYMENT.md \
            docs/operations/RECOVERY.md \
            scripts/quarantine-failed-bootstrap.sh \
            scripts/test-contracts.py \
            scripts/upgrade-host-control.sh
          [[ ${{LINEAGE_MUTATION:-none}} == paths ]] || printf '%s\n' scripts/validate-repository.py
          ;;
        quarantine)
          printf '%s\n' \
            docs/operations/DEPLOYMENT.md \
            docs/operations/RECOVERY.md \
            scripts/quarantine-failed-bootstrap.sh \
            scripts/test-contracts.py \
            scripts/upgrade-host-control.sh
          [[ ${{LINEAGE_MUTATION:-none}} == paths ]] || printf '%s\n' scripts/validate-repository.py
          ;;
        reload_privacy)
          printf '%s\n' \
            config/immutable-letsencrypt.fragment.yml \
            docs/operations/DEPLOYMENT.md \
            docs/operations/RECOVERY.md \
            scripts/disposable-launcher-guard.py \
            scripts/quarantine-failed-bootstrap.sh \
            scripts/test-contracts.py \
            scripts/test-disposable-launcher-guard.py \
            scripts/upgrade-host-control.sh \
            scripts/validate-repository.py
          [[ ${{LINEAGE_MUTATION:-none}} == paths ]] || printf '%s\n' scripts/verify-host.sh
          ;;
        webroot)
          printf '%s\n' \
            config/immutable-letsencrypt.fragment.yml \
            docs/operations/DEPLOYMENT.md \
            docs/operations/RECOVERY.md \
            scripts/quarantine-failed-bootstrap.sh \
            scripts/test-contracts.py \
            scripts/upgrade-host-control.sh
          [[ ${{LINEAGE_MUTATION:-none}} == paths ]] || printf '%s\n' scripts/validate-repository.py
          ;;
        material)
          printf '%s\n' \
            .gitattributes \
            .github/CODEOWNERS \
            .github/workflows/open-reviewed-source-pr.yml \
            .github/workflows/validate-repository.yml \
            CONTRIBUTING.md \
            config/immutable-letsencrypt.fragment.yml \
            docs/adr/0001-clean-initialization-and-canonical-ownership.md \
            docs/operations/DEPLOYMENT.md \
            docs/operations/RECOVERY.md \
            scripts/check-repository.ps1 \
            scripts/check-source-introduction.ps1 \
            scripts/host-deploy.sh \
            scripts/quarantine-failed-bootstrap.sh \
            scripts/test-contracts.py \
            scripts/test-source-introduction.ps1 \
            scripts/upgrade-host-control.sh
          [[ ${{LINEAGE_MUTATION:-none}} == paths ]] || printf '%s\n' scripts/validate-repository.py
          ;;
        *)
          printf '%s\n' \
            .github/workflows/deploy-forums.yml \
            config/host-control-manifest.v1.json \
            docs/operations/DEPLOYMENT.md \
            docs/operations/RECOVERY.md \
            scripts/quarantine-failed-bootstrap.sh \
            scripts/test-contracts.py \
            scripts/upgrade-host-control.sh
          [[ ${{LINEAGE_MUTATION:-none}} == paths ]] || printf '%s\n' scripts/validate-repository.py
          ;;
      esac
      [[ ${{LINEAGE_MUTATION:-none}} != paths-status ]] || return 83
      ;;
    *) return 82 ;;
  esac
}}
{lineage_source}
validate_source_lineage "$current" "$failed"
'''
            mutation_cases = (
                ("none", True), ("head", False), ("branch", False),
                ("recovery-parent", False), ("current-parents", False),
                ("failed-parent", False), ("recovery-parents", False),
                ("status-fail", False), ("dirty", False), ("origin", False),
                ("remote", False), ("paths", False), ("paths-status", False),
            )
            lineage_cases = [
                (lineage, mutation, should_pass)
                for lineage in ("legacy", "active", "acme", "quarantine", "reload_privacy", "webroot", "material")
                for mutation, should_pass in mutation_cases
            ]
            lineage_cases.extend(
                ("reload_privacy", mutation, False)
                for mutation in (
                    "launcher-child-parent", "launcher-child-parents",
                    "recovery-child-parent", "recovery-child-parents",
                )
            )
            lineage_cases.extend(
                ("material", mutation, False)
                for mutation in (
                    "review-authority-parent", "review-authority-parents",
                    "material-repair-paths", "material-repair-status",
                    "material-authority-paths", "material-authority-status",
                    "material-current-paths", "material-current-status",
                )
            )
            lineage_cases.extend(("legacy", mutation, False) for mutation in ("grafts", "commondir"))
            lineage_cases.append(("unknown", "none", False))
            grafts_path = lineage_root / ".git" / "info" / "grafts"
            commondir_path = lineage_root / ".git" / "commondir"
            for lineage, mutation, should_pass in lineage_cases:
                grafts_path.unlink(missing_ok=True)
                commondir_path.unlink(missing_ok=True)
                if mutation == "grafts":
                    grafts_path.parent.mkdir(parents=True, exist_ok=True)
                    grafts_path.write_text(
                        "c" * 40 + " " + "a" * 40 + "\n", encoding="ascii", newline="\n"
                    )
                elif mutation == "commondir":
                    commondir_path.write_text("../hostile\n", encoding="ascii", newline="\n")
                completed = subprocess.run(
                    [bash, "-c", lineage_harness],
                    stdin=subprocess.DEVNULL,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    text=True,
                    timeout=10,
                    check=False,
                    env={
                        **os.environ,
                        "LINEAGE_KIND": lineage,
                        "LINEAGE_MUTATION": mutation,
                        "GIT_DIR": "/hostile",
                        "GIT_WORK_TREE": "/hostile",
                        "GIT_INDEX_FILE": "/hostile",
                        "GIT_OBJECT_DIRECTORY": "/hostile",
                        "GIT_ALTERNATE_OBJECT_DIRECTORIES": "/hostile",
                        "GIT_COMMON_DIR": "/hostile",
                        "GIT_REPLACE_REF_BASE": "refs/hostile",
                        "GIT_ASKPASS": "/hostile",
                        "SSH_ASKPASS": "/hostile",
                        "GIT_SSH": "/hostile",
                        "GIT_SSH_COMMAND": "/hostile",
                        "GIT_CONFIG_PARAMETERS": "hostile",
                        "GIT_CONFIG_SYSTEM": "/hostile",
                        "GIT_CONFIG_GLOBAL": "/hostile",
                        "GIT_CONFIG_NOSYSTEM": "0",
                        "GIT_CONFIG_COUNT": "1",
                        "GIT_CONFIG_KEY_0": "core.replaceRefs",
                        "GIT_CONFIG_VALUE_0": "true",
                        "GIT_PROTOCOL_FROM_USER": "1",
                        "GIT_TERMINAL_PROMPT": "1",
                        "GIT_NO_REPLACE_OBJECTS": "0",
                    },
                )
                if (completed.returncode == 0) != should_pass or completed.stdout or completed.stderr:
                    raise RuntimeError(
                        "Executable failed-bootstrap lineage binding accepted drift or rejected a pinned recovery chain."
                    )

    if source.count("read_mutation_identity() {") != 1 or source.count(
        "read_quarantine_identity() {"
    ) != 1:
        raise RuntimeError("Failed-bootstrap identity reader function inventory differs.")

    mutation_start = source.index("read_mutation_identity() {")
    mutation_end = source.index("\n}\n\nvalidate_quarantine_environment() {", mutation_start) + 2
    mutation_function = source[mutation_start:mutation_end]
    identity_start = source.index("read_quarantine_identity() {")
    identity_end = source.index("\n}\n\nvalidate_failed_bootstrap_state() {", identity_start) + 2
    identity_function = source[identity_start:identity_end]
    recovery_start = source.index('if [[ -e ${pending_journal} || -L ${pending_journal} ]]; then')
    recovery_end = source.index("\nfi\n[[ ${#preflight[@]}", recovery_start) + 3
    recovery_gate = source[recovery_start:recovery_end]

    def exact_reader_body(function: str, prefix: str, label: str) -> str:
        if (
            not function.startswith(prefix)
            or not function.endswith("\nPY\n}")
            or function.count("<<'PY'\n") != 1
            or function.count("\nPY\n}") != 1
        ):
            raise RuntimeError(f"{label} shell boundary differs.")
        heredoc = function.index("<<'PY'\n") + len("<<'PY'\n")
        return function[heredoc : function.index("\nPY\n}", heredoc)]

    mutation_prefix = 'read_mutation_identity() {\n  python3 -B - "${deployment_journal}" <<\'PY\'\n'
    identity_prefix = (
        'read_quarantine_identity() {\n  local kind="$1" current="$2" failed="$3"\n'
        '  python3 -B - "${kind}" "${pending_journal}" "${evidence_root}" "${current}" "${failed}" \\\n'
        '    "${standalone_root}" "${recovery_root}" "${deployment_journal}" <<\'PY\'\n'
    )
    mutation_reader = exact_reader_body(
        mutation_function, mutation_prefix, "Failed-bootstrap mutation identity reader"
    )
    identity_reader = exact_reader_body(
        identity_function, identity_prefix, "Failed-bootstrap recovery identity reader"
    )
    spoofed_function = mutation_function.replace(
        "read_mutation_identity() {\n",
        'read_mutation_identity() {\n  printf \'spoof\\n\'\n  return 0\n',
        1,
    )
    try:
        exact_reader_body(
            spoofed_function, mutation_prefix, "Failed-bootstrap spoofed mutation identity reader"
        )
    except RuntimeError:
        pass
    else:
        raise RuntimeError("Failed-bootstrap identity tests accepted an early shell success decoy.")
    if identity_reader.count("import itertools\n") != 1:
        raise RuntimeError("Failed-bootstrap terminal identity reader does not bind its bounded iterator dependency.")

    transaction_match = re.search(
        r"(?ms)^# BEGIN_FAILED_BOOTSTRAP_QUARANTINE_TRANSACTION\n(.*?)^# END_FAILED_BOOTSTRAP_QUARANTINE_TRANSACTION$",
        source,
    )
    if transaction_match is None:
        raise RuntimeError("Failed-bootstrap transaction source could not be extracted exactly.")
    transaction = transaction_match.group(1)

    def assert_transaction_durability_order(code: str) -> None:
        move_start = code.index("def durable_directory_move(source, destination):")
        move_end = code.index("\ndef exact_directory", move_start)
        move = code[move_start:move_end]
        move_order = (
            "    os.rename(source, destination)",
            "    fsync_directory(destination.parent)",
            "    fsync_directory(source.parent)",
        )
        persist_start = code.index("def persist_directory(path):")
        persist_end = code.index("\ndef durable_directory_move", persist_start)
        persist = code[persist_start:persist_end]
        persist_order = (
            "    fsync_directory(path)",
            "    fsync_directory(path.parent)",
        )
        retirement_start = code.index("os.link(mutation, mutation_evidence, follow_symlinks=False)")
        retirement_end = code.index(
            "    state = reconcile_pending_publication(\n"
            "        pending_raw, pending_base, pending_alias, pending_staged\n"
            "    )",
            retirement_start,
        )
        retirement = code[retirement_start:retirement_end]
        retirement_order = (
            "os.link(mutation, mutation_evidence, follow_symlinks=False)",
            "fsync_directory(mutation_evidence.parent)",
            "mutation.unlink()",
            "fsync_directory(mutation.parent)",
        )
        for label, block, ordered in (
            ("directory move", move, move_order),
            ("directory metadata", persist, persist_order),
            ("mutation retirement", retirement, retirement_order),
        ):
            normalized = [line.strip() for line in block.splitlines()]
            if any(normalized.count(line.strip()) != 1 for line in ordered):
                raise RuntimeError(f"Failed-bootstrap {label} durability statement inventory differs.")
            offsets = tuple(block.index(line) for line in ordered)
            if offsets != tuple(sorted(offsets)):
                raise RuntimeError(f"Failed-bootstrap {label} durability order differs.")
        preflight_start = code.index("def preflight_pending_staging():")
        preflight_end = code.index("\nexact_directory(shared_root", preflight_start)
        preflight = code[preflight_start:preflight_end]
        preflight_bindings = (
            'if not path_exists(staging, "failed-bootstrap pending publication staging"):',
            'if path_exists(pending, "failed-bootstrap pending journal"):',
            'if path_exists(terminal, "failed-bootstrap terminal evidence"):',
            'validate_state(staging_document, {"prepared"})',
            "validate_prepared_runtime(staging_document)",
            'if not path_exists(pending, "failed-bootstrap pending journal"):',
            "pending_candidate = observe_pending_publication(",
            'validate_state(pending_document, {"authority-retired"})',
            "if pending_alias is not None or pending_candidate is not None:",
            "if staging_document != expected:",
            "validate_completed_runtime(pending_document)",
        )
        if any(binding not in preflight for binding in preflight_bindings):
            raise RuntimeError("Failed-bootstrap publication staging relational preflight differs.")
        live = code[preflight_end:]
        pending_preflight = live.index(
            "pending_staging_replay = preflight_pending_staging()"
        )
        terminal_preflight = live.index(
            "terminal_staging_replay = preflight_terminal_staging()"
        )
        first_mutation = min(
            live.index("require_recovery_root(True)"),
            live.index("durable_directory_move(standalone, quarantine)"),
        )
        if not pending_preflight < terminal_preflight < first_mutation:
            raise RuntimeError("Failed-bootstrap reserved staging is not rejected before mutation.")

    assert_transaction_durability_order(transaction)
    durability_order_mutants = (
        transaction.replace(
            "    fsync_directory(destination.parent)\n    fsync_directory(source.parent)",
            "    fsync_directory(source.parent)\n    fsync_directory(destination.parent)",
            1,
        ),
        transaction.replace(
            "    fsync_directory(path)\n    fsync_directory(path.parent)",
            "    fsync_directory(path.parent)\n    fsync_directory(path)",
            1,
        ),
        transaction.replace(
            "        fsync_directory(mutation_evidence.parent)\n        mutation.unlink()",
            "        mutation.unlink()\n        fsync_directory(mutation_evidence.parent)",
            1,
        ),
    )
    for mutant in durability_order_mutants:
        try:
            assert_transaction_durability_order(mutant)
        except RuntimeError:
            pass
        else:
            raise RuntimeError("Failed-bootstrap reordered durability mutant passed.")

    def extract_canonical(code: str, signature: str) -> str:
        start = code.index(signature)
        return code[start : code.index("\ndef reject_duplicate", start)]

    mutation_canonical = extract_canonical(mutation_reader, "def canonical(document):")
    identity_canonical = extract_canonical(identity_reader, "def canonical(document):")
    transaction_canonical = extract_canonical(transaction, "def canonical(document, label):")
    if (
        mutation_reader.count("canonical_raw = canonical(document)") != 1
        or mutation_reader.count("sys.stdout.buffer.write(output)") != 1
        or "print(" in mutation_reader
        or 'target_app_configuration != expected_target_app_configuration' not in mutation_reader
        or identity_reader.count("canonical_raw = canonical(document)") != 1
        or transaction.count("if raw != canonical(document, label):") != 1
        or transaction.count('canonical(document, "failed-bootstrap quarantine document")') != 1
        or transaction.count("def publication_staging(path):") != 1
        or transaction.count("def publication_alias(path, metadata, label):") != 1
        or transaction.count("def finish_publication_alias(path, staging, raw, label):") != 1
        or transaction.count("def preflight_pending_staging():") != 1
        or transaction.count("def preflight_terminal_staging():") != 1
    ):
        raise RuntimeError("Failed-bootstrap canonicalizer consumer binding differs.")
    crash_anchors = (
        "publish(pending, state, True)",
        "durable_directory_move(standalone, quarantine)",
        'advance("runtime-quarantined")',
        'standalone.mkdir(mode=state["standaloneMode"])',
        "durable_directory_move(old_ssl, new_ssl)",
        'advance("clean-boundary")',
        "os.link(mutation, mutation_evidence, follow_symlinks=False)",
        'validate_state(state, {"authority-retired"})',
        "publish(terminal, terminal_document, True)",
    )
    if any(transaction.count(anchor) != 1 for anchor in crash_anchors):
        raise RuntimeError("Failed-bootstrap crash-window anchor inventory differs.")

    # The production transaction is root-only. Windows and an unprivileged
    # Linux source check still execute every static consumer binding above;
    # the pinned root/Linux check drives every journal phase below.
    if os.name != "posix" or os.geteuid() != 0:
        return

    current = "a" * 40
    failed = "b" * 40
    child_environment = {"LC_ALL": "C", "PYTHONHASHSEED": "0"}
    deep_json = b'{"value":' + (b"[" * 20_000) + b"0" + (b"]" * 20_000) + b"}\n"
    if len(deep_json) > 65_536:
        raise RuntimeError("Failed-bootstrap deep-nesting hostile exceeds the production byte cap.")

    def publish_json(path: Path, document: dict[str, object]) -> bytes:
        raw = (json.dumps(document, sort_keys=True, separators=(",", ":")) + "\n").encode("utf-8")
        path.write_bytes(raw)
        path.chmod(0o600)
        os.chown(path, 0, 0)
        return raw

    def publish_raw(path: Path, raw: bytes) -> None:
        path.write_bytes(raw)
        path.chmod(0o600)
        os.chown(path, 0, 0)

    def mutation_document(target_app_configuration: str | None = None) -> dict[str, object]:
        configuration = "c" * 64
        target_root = f"/var/discourse/containers/releases/{current}/{configuration}"
        target_app = (
            f"{target_root}/app.yml" if target_app_configuration is None else target_app_configuration
        )
        return {
            "schemaVersion": 1,
            "phase": "runtime-contained",
            "recordedAt": "2026-08-25T20:00:00Z",
            "updatedAt": "2026-08-25T20:01:00Z",
            "deploymentMode": "bootstrap",
            "repositoryCommit": current,
            "productionConfigurationSha256": configuration,
            "releaseArchiveSha256": "d" * 64,
            "requestedDiscourseConnect": False,
            "targetAppConfigurationFile": target_app,
            "targetAppConfigurationSha256": configuration,
            "targetRestoreConfigurationFile": f"{target_root}/restore.yml",
            "targetRestoreConfigurationSha256": "e" * 64,
            "targetActivationConfigurationFile": None,
            "targetActivationConfigurationSha256": None,
            "previousRepositoryCommit": None,
            "previousProductionConfigurationSha256": None,
            "previousCurrentReleaseSha256": None,
            "previousAppConfigurationFile": None,
            "previousAppConfigurationSha256": None,
            "previousCurrentTarget": None,
            "activeConfigurationFile": target_app,
            "activeConfigurationSha256": configuration,
            "launcherOperationToken": None,
            "launcherPreviousImageId": None,
            "launcherCommand": None,
            "databaseMutationPossible": True,
            "applicationStopped": True,
        }

    def new_fixture(directory: str, *, ssl_present: bool = True) -> dict[str, object]:
        root = Path(directory)
        state = root / "state"
        evidence = state / "evidence"
        shared = root / "shared"
        standalone = shared / "standalone"
        recovery = shared / ".mochirii-forums-failed-bootstrap"
        state.mkdir(mode=0o755)
        state.chmod(0o755)
        evidence.mkdir(mode=0o700)
        evidence.chmod(0o700)
        shared.mkdir(mode=0o755)
        shared.chmod(0o755)
        standalone.mkdir(mode=0o755)
        standalone.chmod(0o755)
        retained_names = ["postgres_data", "redis_data", "uploads", "log", "tmp"]
        if ssl_present:
            retained_names.append("ssl")
        for name in retained_names:
            path = standalone / name
            path.mkdir(mode=0o700)
            (path / "retained.bin").write_bytes((name + "-retained").encode("ascii"))
        mutation = state / "deployment-mutation.json"
        mutation_raw = publish_json(mutation, {})
        mutation_sha = hashlib.sha256(mutation_raw).hexdigest()
        quarantine = recovery / f"{failed}-{mutation_sha}"
        mutation_evidence = evidence / f"{failed}-{mutation_sha}-deployment-mutation.json"
        terminal = evidence / f"{failed}-{mutation_sha}-failed-bootstrap-quarantine.json"
        pending = state / "failed-bootstrap-quarantine.pending.json"
        return {
            "root": root,
            "state": state,
            "evidence": evidence,
            "shared": shared,
            "standalone": standalone,
            "recovery": recovery,
            "mutation": mutation,
            "mutation_raw": mutation_raw,
            "mutation_sha": mutation_sha,
            "quarantine": quarantine,
            "mutation_evidence": mutation_evidence,
            "terminal": terminal,
            "pending": pending,
            "ssl_present": ssl_present,
        }

    def prepared_document(fixture: dict[str, object]) -> dict[str, object]:
        metadata = fixture["standalone"].stat()
        stamp = "2026-08-25T20:00:00Z"
        return {
            "schemaVersion": 1,
            "operation": "failed-bootstrap-quarantine",
            "phase": "prepared",
            "recordedAt": stamp,
            "updatedAt": stamp,
            "currentControlCommit": current,
            "failedReleaseCommit": failed,
            "mutationSha256": fixture["mutation_sha"],
            "standalonePath": str(fixture["standalone"]),
            "quarantinePath": str(fixture["quarantine"]),
            "mutationEvidencePath": str(fixture["mutation_evidence"]),
            "standaloneUid": metadata.st_uid,
            "standaloneGid": metadata.st_gid,
            "standaloneMode": stat.S_IMODE(metadata.st_mode),
            "sslPresent": fixture["ssl_present"],
        }

    def run_transaction(code: str, fixture: dict[str, object]) -> subprocess.CompletedProcess[bytes]:
        return subprocess.run(
            [
                sys.executable,
                "-B",
                "-c",
                "import os\nos.umask(0o077)\n" + code,
                str(fixture["pending"]),
                str(fixture["mutation"]),
                str(fixture["evidence"]),
                str(fixture["shared"]),
                str(fixture["standalone"]),
                str(fixture["recovery"]),
                current,
                failed,
                str(fixture["mutation_sha"]),
            ],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            env=child_environment,
            timeout=20,
            check=False,
        )

    def run_identity_reader(
        kind: str,
        fixture: dict[str, object],
        function: str = identity_function,
    ) -> subprocess.CompletedProcess[bytes]:
        shell_source = (
            "set -euo pipefail\n"
            'readonly pending_journal="$2"\n'
            'readonly evidence_root="$3"\n'
            'readonly standalone_root="$6"\n'
            'readonly recovery_root="$7"\n'
            'readonly deployment_journal="$8"\n'
            + function
            + '\nread_quarantine_identity "$1" "$4" "$5"\n'
        )
        return subprocess.run(
            [
                "/bin/bash",
                "-c",
                shell_source,
                "mochirii-failed-bootstrap-identity-reader",
                kind,
                str(fixture["pending"]),
                str(fixture["evidence"]),
                current,
                failed,
                str(fixture["standalone"]),
                str(fixture["recovery"]),
                str(fixture["mutation"]),
            ],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            env={**child_environment, "PATH": "/usr/bin:/bin"},
            timeout=20,
            check=False,
        )

    def run_mutation_reader(
        fixture: dict[str, object],
        function: str = mutation_function,
    ) -> subprocess.CompletedProcess[bytes]:
        shell_source = (
            "set -euo pipefail\n"
            'readonly deployment_journal="$1"\n'
            + function
            + "\nread_mutation_identity\n"
        )
        return subprocess.run(
            [
                "/bin/bash",
                "-c",
                shell_source,
                "mochirii-failed-bootstrap-mutation-reader",
                str(fixture["mutation"]),
            ],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            env={**child_environment, "PATH": "/usr/bin:/bin"},
            timeout=20,
            check=False,
        )

    def run_recovery_with_rejected_lineage(
        fixture: dict[str, object],
        function: str = identity_function,
        fail_on_lineage_call: int = 1,
    ) -> subprocess.CompletedProcess[bytes]:
        shell_source = (
            "set -euo pipefail\n"
            'readonly pending_journal="$1"\n'
            'readonly deployment_journal="$2"\n'
            'readonly evidence_root="$3"\n'
            'readonly standalone_root="$4"\n'
            'readonly recovery_root="$5"\n'
            'current_commit="$6"\n'
            'failed_commit="$7"\n'
            'fail() { printf \'%s\\n\' "$1" >&2; exit 1; }\n'
            'lineage_calls=0\n'
            'validate_source_lineage() { lineage_calls=$((lineage_calls + 1)); [[ ${lineage_calls} -ne '
            + str(fail_on_lineage_call)
            + ' ]]; }\n'
            'validate_failed_bootstrap_state() { return 97; }\n'
            + function
            + "\n"
            + recovery_gate
            + "\n"
        )
        return subprocess.run(
            [
                "/bin/bash",
                "-c",
                shell_source,
                "mochirii-failed-bootstrap-lineage-first",
                str(fixture["pending"]),
                str(fixture["mutation"]),
                str(fixture["evidence"]),
                str(fixture["standalone"]),
                str(fixture["recovery"]),
                current,
                failed,
            ],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            env={**child_environment, "PATH": "/usr/bin:/bin"},
            timeout=20,
            check=False,
        )

    def run_canonicalizer(code: str, call: str) -> subprocess.CompletedProcess[bytes]:
        probe = (
            "import json\n"
            + code
            + "\ndocument = {}\ncursor = []\ndocument['value'] = cursor\n"
            + "for _ in range(20_000):\n    child = []\n    cursor.append(child)\n    cursor = child\n"
            + call
            + "\n"
        )
        return subprocess.run(
            [sys.executable, "-B", "-c", probe],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            env=child_environment,
            timeout=20,
            check=False,
        )

    def assert_categorical_failure(
        rejected: subprocess.CompletedProcess[bytes], expected: bytes, label: str
    ) -> None:
        if (
            rejected.returncode == 0
            or rejected.stdout
            or rejected.stderr != expected
            or b"Traceback" in rejected.stderr
        ):
            raise RuntimeError(f"{label} leaked or accepted hostile evidence.")

    def assert_identity_reader_failure(kind: str, fixture: dict[str, object], expected: bytes) -> None:
        assert_categorical_failure(
            run_identity_reader(kind, fixture),
            expected,
            "Failed-bootstrap actual identity reader",
        )

    def assert_transaction_io_recovery(
        hostile: str,
        fixture: dict[str, object],
        label: str,
        expected: bytes = b"failed-bootstrap quarantine transaction failed\n",
    ) -> None:
        assert_categorical_failure(
            run_transaction(hostile, fixture),
            expected,
            label,
        )
        resumed = run_transaction(transaction, fixture)
        if resumed.returncode != 0 or resumed.stdout or resumed.stderr:
            raise RuntimeError(f"{label} did not retain a resumable state.")
        verify_terminal(fixture)

    def interrupt_after(code: str, anchor: str) -> str:
        position = code.index(anchor)
        line_start = code.rfind("\n", 0, position) + 1
        indentation = code[line_start:position]
        if indentation.strip():
            raise RuntimeError("Failed-bootstrap crash anchor is not at statement position.")
        insertion = position + len(anchor)
        return code[:insertion] + "\n" + indentation + "raise SystemExit(86)" + code[insertion:]

    def abrupt_function_after(
        code: str,
        function_start: str,
        function_end: str,
        anchor: str,
        occurrence: int,
        guard: str,
    ) -> str:
        block_start = code.index(function_start)
        block_end = code.index(function_end, block_start)
        block = code[block_start:block_end]
        positions = [match.start() for match in re.finditer(re.escape(anchor), block)]
        if occurrence < 1 or len(positions) < occurrence:
            raise RuntimeError("Failed-bootstrap internal publication crash anchor differs.")
        position = block_start + positions[occurrence - 1]
        line_start = code.rfind("\n", 0, position) + 1
        indentation = code[line_start:position]
        if indentation.strip():
            raise RuntimeError("Failed-bootstrap internal publication crash anchor is not at statement position.")
        insertion = position + len(anchor)
        injected = f"\n{indentation}if {guard}:\n{indentation}    os._exit(86)"
        return code[:insertion] + injected + code[insertion:]

    def abrupt_publish_after(
        code: str, anchor: str, occurrence: int, destination: str, create: bool
    ) -> str:
        return abrupt_function_after(
            code,
            "def publish(path, document, create, defer_update=False):",
            "\nexact_directory(shared_root",
            anchor,
            occurrence,
            f"path == {destination} and create is {create}",
        )

    def function_io_hostile(
        code: str,
        function_start: str,
        function_end: str,
        anchor: str,
        occurrence: int,
        sentinel: str,
    ) -> str:
        block_start = code.index(function_start)
        block_end = code.index(function_end, block_start)
        block = code[block_start:block_end]
        positions = [match.start() for match in re.finditer(re.escape(anchor), block)]
        if occurrence < 1 or len(positions) < occurrence:
            raise RuntimeError("Failed-bootstrap publisher I/O anchor differs.")
        position = block_start + positions[occurrence - 1]
        line_start = code.rfind("\n", 0, position) + 1
        indentation = code[line_start:position]
        if indentation.strip():
            raise RuntimeError("Failed-bootstrap publisher I/O anchor is not at statement position.")
        replacement = f'raise OSError("{sentinel}")'
        return code[:position] + replacement + code[position + len(anchor) :]

    def guarded_function_io_hostile(
        code: str,
        function_start: str,
        function_end: str,
        anchor: str,
        occurrence: int,
        guard: str,
        sentinel: str,
    ) -> str:
        block_start = code.index(function_start)
        block_end = code.index(function_end, block_start)
        block = code[block_start:block_end]
        positions = [match.start() for match in re.finditer(re.escape(anchor), block)]
        if occurrence < 1 or len(positions) < occurrence:
            raise RuntimeError("Failed-bootstrap guarded publisher I/O anchor differs.")
        position = block_start + positions[occurrence - 1]
        line_start = code.rfind("\n", 0, position) + 1
        indentation = code[line_start:position]
        if indentation.strip():
            raise RuntimeError("Failed-bootstrap guarded publisher anchor is not at statement position.")
        injected = f'if {guard}:\n{indentation}    raise OSError("{sentinel}")\n{indentation}'
        return code[:position] + injected + code[position:]

    def statement_io_hostile(
        code: str, anchor: str, occurrence: int, sentinel: str
    ) -> str:
        positions = [match.start() for match in re.finditer(re.escape(anchor), code)]
        if occurrence < 1 or len(positions) < occurrence:
            raise RuntimeError("Failed-bootstrap transaction I/O anchor differs.")
        position = positions[occurrence - 1]
        line_start = code.rfind("\n", 0, position) + 1
        indentation = code[line_start:position]
        if indentation.strip():
            raise RuntimeError("Failed-bootstrap transaction I/O anchor is not at statement position.")
        replacement = f'raise OSError("{sentinel}")'
        return code[:position] + replacement + code[position + len(anchor) :]

    def abrupt_after(code: str, anchor: str, occurrence: int = 1) -> str:
        positions = [match.start() for match in re.finditer(re.escape(anchor), code)]
        if occurrence < 1 or len(positions) < occurrence:
            raise RuntimeError("Failed-bootstrap abrupt crash anchor differs.")
        position = positions[occurrence - 1]
        line_start = code.rfind("\n", 0, position) + 1
        indentation = code[line_start:position]
        if indentation.strip():
            raise RuntimeError("Failed-bootstrap abrupt crash anchor is not at statement position.")
        insertion = position + len(anchor)
        return code[:insertion] + f"\n{indentation}os._exit(86)" + code[insertion:]

    def abrupt_between(
        code: str,
        block_start_marker: str,
        block_end_marker: str,
        anchor: str,
        occurrence: int = 1,
    ) -> str:
        block_start = code.index(block_start_marker)
        block_end = code.index(block_end_marker, block_start)
        block = code[block_start:block_end]
        positions = [match.start() for match in re.finditer(re.escape(anchor), block)]
        if occurrence < 1 or len(positions) < occurrence:
            raise RuntimeError("Failed-bootstrap bounded abrupt crash anchor differs.")
        position = block_start + positions[occurrence - 1]
        line_start = code.rfind("\n", 0, position) + 1
        indentation = code[line_start:position]
        if indentation.strip():
            raise RuntimeError("Failed-bootstrap bounded crash anchor is not at statement position.")
        insertion = position + len(anchor)
        return code[:insertion] + f"\n{indentation}os._exit(86)" + code[insertion:]

    def regular_identity(path: Path) -> tuple[int, int, int, int, int, int, bytes]:
        metadata = path.stat()
        return (
            metadata.st_dev,
            metadata.st_ino,
            metadata.st_uid,
            metadata.st_gid,
            stat.S_IMODE(metadata.st_mode),
            metadata.st_nlink,
            path.read_bytes(),
        )

    def assert_reconciled_identity(
        path: Path,
        before: tuple[int, int, int, int, int, int, bytes],
        label: str,
    ) -> None:
        after = regular_identity(path)
        expected = (*before[:5], 1, before[6])
        if after != expected:
            raise RuntimeError(f"{label} altered the publication destination.")

    def verify_terminal(fixture: dict[str, object]) -> None:
        pending = fixture["pending"]
        mutation = fixture["mutation"]
        standalone = fixture["standalone"]
        quarantine = fixture["quarantine"]
        mutation_evidence = fixture["mutation_evidence"]
        terminal = fixture["terminal"]
        if pending.exists() or mutation.exists() or not terminal.is_file() or not mutation_evidence.is_file():
            raise RuntimeError("Failed-bootstrap terminal authority inventory differs.")
        terminal_document = json.loads(terminal.read_text(encoding="utf-8"))
        if (
            terminal_document.get("phase") != "complete"
            or terminal_document.get("currentControlCommit") != current
            or terminal_document.get("failedReleaseCommit") != failed
            or terminal_document.get("mutationSha256") != fixture["mutation_sha"]
            or terminal_document.get("sslRestored") is not fixture["ssl_present"]
        ):
            raise RuntimeError("Failed-bootstrap terminal evidence tuple differs.")
        if terminal.stat().st_uid != 0 or stat.S_IMODE(terminal.stat().st_mode) != 0o600:
            raise RuntimeError("Failed-bootstrap terminal evidence ownership differs.")
        if terminal.stat().st_nlink != 1:
            raise RuntimeError("Failed-bootstrap terminal evidence link count differs.")
        for published in (pending, terminal):
            staging = published.with_name(f".{published.name}.publish")
            if staging.exists() or staging.is_symlink():
                raise RuntimeError("Failed-bootstrap publication staging alias was not retired.")
        if mutation_evidence.read_bytes() != fixture["mutation_raw"]:
            raise RuntimeError("Failed-bootstrap retained mutation evidence differs.")
        identity = run_identity_reader("terminal", fixture)
        expected_identity = f"{current}\n{failed}\n{fixture['mutation_sha']}\n".encode("ascii")
        if identity.returncode != 0 or identity.stdout != expected_identity or identity.stderr:
            raise RuntimeError("Failed-bootstrap actual terminal identity reader rejected exact completed evidence.")
        expected_standalone = {"ssl"} if fixture["ssl_present"] else set()
        if set(path.name for path in standalone.iterdir()) != expected_standalone:
            raise RuntimeError("Failed-bootstrap clean standalone inventory differs.")
        if fixture["ssl_present"] and (standalone / "ssl/retained.bin").read_bytes() != b"ssl-retained":
            raise RuntimeError("Failed-bootstrap SSL bytes were not retained exactly.")
        if stat.S_IMODE(quarantine.stat().st_mode) != 0o700 or quarantine.stat().st_uid != 0:
            raise RuntimeError("Failed-bootstrap quarantine ownership differs.")
        expected_quarantine = {"postgres_data", "redis_data", "uploads", "log", "tmp"}
        if set(path.name for path in quarantine.iterdir()) != expected_quarantine:
            raise RuntimeError("Failed-bootstrap retained runtime inventory differs.")
        for name in expected_quarantine:
            if (quarantine / name / "retained.bin").read_bytes() != (name + "-retained").encode("ascii"):
                raise RuntimeError("Failed-bootstrap retained runtime bytes differ.")

    canonicalizer_cases = (
        (mutation_canonical, "canonical(document)", b"failed bootstrap journal is malformed\n"),
        (
            identity_canonical,
            "canonical(document)",
            b"failed-bootstrap recovery evidence is noncanonical\n",
        ),
        (
            transaction_canonical,
            'canonical(document, "failed-bootstrap canonicalizer")',
            b"failed-bootstrap canonicalizer is not canonical\n",
        ),
    )
    for canonical_source, canonical_call, expected in canonicalizer_cases:
        assert_categorical_failure(
            run_canonicalizer(canonical_source, canonical_call),
            expected,
            "Failed-bootstrap actual canonicalizer",
        )

    with tempfile.TemporaryDirectory(
        prefix="mochirii-failed-bootstrap-io-categorical-"
    ) as directory:
        fixture = new_fixture(directory)
        mutation_io = mutation_function.replace(
            "    raw = path.read_bytes()",
            '    raise OSError("PRIVATE_MUTATION_PATH")',
            1,
        )
        identity_io = identity_function.replace(
            "        raw = path.read_bytes()",
            '        raise OSError("PRIVATE_IDENTITY_PATH")',
            1,
        )
        assert_categorical_failure(
            run_mutation_reader(fixture, mutation_io),
            b"failed bootstrap journal is unavailable\n",
            "Failed-bootstrap mutation-reader I/O boundary",
        )
        armed = interrupt_after(transaction, "publish(pending, state, True)")
        if run_transaction(armed, fixture).returncode != 86:
            raise RuntimeError("Failed-bootstrap identity I/O fixture did not arm.")
        assert_categorical_failure(
            run_identity_reader("pending", fixture, identity_io),
            b"failed-bootstrap recovery evidence is unavailable\n",
            "Failed-bootstrap identity-reader I/O boundary",
        )

    transaction_io_hostiles = (
        transaction.replace(
            "durable_directory_move(standalone, quarantine)",
            'raise OSError("PRIVATE_RUNTIME_PATH")',
            1,
        ),
        transaction.replace(
            "        os.fsync(descriptor)",
            '        raise OSError("PRIVATE_FSYNC_PATH")',
            1,
        ),
    )
    for hostile in transaction_io_hostiles:
        with tempfile.TemporaryDirectory(
            prefix="mochirii-failed-bootstrap-transaction-io-"
        ) as directory:
            assert_categorical_failure(
                run_transaction(hostile, new_fixture(directory)),
                b"failed-bootstrap quarantine transaction failed\n",
                "Failed-bootstrap transaction outer I/O boundary",
            )

    with tempfile.TemporaryDirectory(
        prefix="mochirii-failed-bootstrap-publication-create-io-"
    ) as directory:
        fixture = new_fixture(directory)
        hostile = function_io_hostile(
            transaction,
            "def publish(path, document, create, defer_update=False):",
            "\nexact_directory(shared_root",
            "os.link(staging, path, follow_symlinks=False)",
            1,
            "PRIVATE_CREATE_PUBLICATION_PATH",
        )
        assert_categorical_failure(
            run_transaction(hostile, fixture),
            b"failed-bootstrap pending journal publication failed\n",
            "Failed-bootstrap create publisher I/O boundary",
        )

    with tempfile.TemporaryDirectory(
        prefix="mochirii-failed-bootstrap-publication-update-io-"
    ) as directory:
        fixture = new_fixture(directory)
        armed = interrupt_after(transaction, "publish(pending, state, True)")
        if run_transaction(armed, fixture).returncode != 86:
            raise RuntimeError("Failed-bootstrap update publisher I/O fixture did not arm.")
        hostile = function_io_hostile(
            transaction,
            "def finish_publication_update(path, staging, previous_raw, replacement_raw, label):",
            "\ndef finish_mutation_evidence_alias",
            "os.replace(staging, path)",
            1,
            "PRIVATE_UPDATE_PUBLICATION_PATH",
        )
        assert_categorical_failure(
            run_transaction(hostile, fixture),
            b"failed-bootstrap pending journal publication failed\n",
            "Failed-bootstrap update publisher I/O boundary",
        )

    with tempfile.TemporaryDirectory(
        prefix="mochirii-failed-bootstrap-publication-alias-io-"
    ) as directory:
        fixture = new_fixture(directory)
        armed = interrupt_after(transaction, "publish(pending, state, True)")
        if run_transaction(armed, fixture).returncode != 86:
            raise RuntimeError("Failed-bootstrap alias publisher I/O fixture did not arm.")
        pending = fixture["pending"]
        staging = pending.with_name(f".{pending.name}.publish")
        os.link(pending, staging)
        hostile = function_io_hostile(
            transaction,
            "def finish_publication_alias(path, staging, raw, label):",
            "\ndef finish_publication_update",
            "staging.unlink()",
            1,
            "PRIVATE_ALIAS_PUBLICATION_PATH",
        )
        assert_categorical_failure(
            run_transaction(hostile, fixture),
            b"failed-bootstrap pending journal is unsafe\n",
            "Failed-bootstrap alias healer I/O boundary",
        )
        if not staging.is_file() or pending.stat().st_nlink != 2:
            raise RuntimeError("Failed-bootstrap alias healer I/O failure changed publication state.")

    with tempfile.TemporaryDirectory(
        prefix="mochirii-failed-bootstrap-mutation-alias-io-"
    ) as directory:
        fixture = new_fixture(directory)
        interrupted = abrupt_after(
            transaction, "os.link(mutation, mutation_evidence, follow_symlinks=False)"
        )
        if run_transaction(interrupted, fixture).returncode != 86:
            raise RuntimeError("Failed-bootstrap mutation alias I/O fixture did not arm.")
        hostile = function_io_hostile(
            transaction,
            "def finish_mutation_evidence_alias(source, destination, expected_sha):",
            "\ndef exact_regular",
            "source.unlink()",
            1,
            "PRIVATE_MUTATION_RETIREMENT_PATH",
        )
        assert_categorical_failure(
            run_transaction(hostile, fixture),
            b"deployment mutation evidence retirement failed\n",
            "Failed-bootstrap mutation alias retirement I/O boundary",
        )
        if not fixture["mutation"].is_file() or not fixture["mutation_evidence"].is_file():
            raise RuntimeError("Failed-bootstrap mutation alias I/O failure retired authority.")

    with tempfile.TemporaryDirectory(
        prefix="mochirii-failed-bootstrap-mutation-retirement-io-"
    ) as directory:
        fixture = new_fixture(directory)
        hostile = transaction.replace(
            "        mutation.unlink()",
            '        raise OSError("PRIVATE_MUTATION_UNLINK_PATH")',
            1,
        )
        assert_categorical_failure(
            run_transaction(hostile, fixture),
            b"failed-bootstrap quarantine transaction failed\n",
            "Failed-bootstrap mutation retirement outer I/O boundary",
        )

    for anchor in ("pending.unlink()", "fsync_directory(pending.parent)"):
        final_occurrence = 3 if anchor == "pending.unlink()" else 5
        staging_occurrence = 2 if anchor == "pending.unlink()" else 3
        with tempfile.TemporaryDirectory(
            prefix="mochirii-failed-bootstrap-final-pending-retirement-io-"
        ) as directory:
            hostile = statement_io_hostile(
                transaction,
                anchor,
                final_occurrence,
                "PRIVATE_FINAL_PENDING_RETIREMENT_PATH",
            )
            assert_transaction_io_recovery(
                hostile,
                new_fixture(directory),
                "Failed-bootstrap final pending-retirement I/O boundary",
            )

        with tempfile.TemporaryDirectory(
            prefix="mochirii-failed-bootstrap-terminal-replay-retirement-io-"
        ) as directory:
            fixture = new_fixture(directory)
            terminal_armed = interrupt_after(
                transaction, "publish(terminal, terminal_document, True)"
            )
            prepared = run_transaction(terminal_armed, fixture)
            if prepared.returncode != 86 or prepared.stdout or prepared.stderr:
                raise RuntimeError("Failed-bootstrap terminal-replay I/O fixture did not arm.")
            hostile = statement_io_hostile(
                transaction,
                anchor,
                1,
                "PRIVATE_REPLAY_PENDING_RETIREMENT_PATH",
            )
            assert_transaction_io_recovery(
                hostile,
                fixture,
                "Failed-bootstrap terminal-replay pending-retirement I/O boundary",
            )

        with tempfile.TemporaryDirectory(
            prefix="mochirii-failed-bootstrap-terminal-staging-retirement-io-"
        ) as directory:
            fixture = new_fixture(directory)
            staging_armed = abrupt_publish_after(
                transaction,
                "os.close(descriptor)",
                1,
                "terminal",
                True,
            )
            prepared = run_transaction(staging_armed, fixture)
            if prepared.returncode != 86 or prepared.stdout or prepared.stderr:
                raise RuntimeError("Failed-bootstrap terminal-staging I/O fixture did not arm.")
            hostile = statement_io_hostile(
                transaction,
                anchor,
                staging_occurrence,
                "PRIVATE_STAGING_PENDING_RETIREMENT_PATH",
            )
            assert_transaction_io_recovery(
                hostile,
                fixture,
                "Failed-bootstrap terminal-staging pending-retirement I/O boundary",
            )

    with tempfile.TemporaryDirectory(
        prefix="mochirii-failed-bootstrap-terminal-publication-call-io-"
    ) as directory:
        hostile = statement_io_hostile(
            transaction,
            "publish(terminal, terminal_document, True)",
            1,
            "PRIVATE_TERMINAL_PUBLICATION_PATH",
        )
        assert_transaction_io_recovery(
            hostile,
            new_fixture(directory),
            "Failed-bootstrap terminal publication-call I/O boundary",
        )

    with tempfile.TemporaryDirectory(
        prefix="mochirii-failed-bootstrap-terminal-staging-publication-call-io-"
    ) as directory:
        fixture = new_fixture(directory)
        staging_armed = abrupt_publish_after(
            transaction,
            "os.close(descriptor)",
            1,
            "terminal",
            True,
        )
        prepared = run_transaction(staging_armed, fixture)
        if prepared.returncode != 86 or prepared.stdout or prepared.stderr:
            raise RuntimeError("Failed-bootstrap terminal-staging publication fixture did not arm.")
        hostile = statement_io_hostile(
            transaction,
            "publish(path=terminal, document=terminal_document, create=True)",
            1,
            "PRIVATE_TERMINAL_STAGING_PUBLICATION_PATH",
        )
        assert_transaction_io_recovery(
            hostile,
            fixture,
            "Failed-bootstrap terminal-staging publication-call I/O boundary",
        )

    terminal_publish_io_anchors = (
        ("os.link(staging, path, follow_symlinks=False)", 1),
        ("fsync_directory(path.parent)", 2),
        ("staging.unlink()", 1),
        ("fsync_directory(path.parent)", 3),
    )
    for consumer in ("final", "staging-replay"):
        for anchor, occurrence in terminal_publish_io_anchors:
            with tempfile.TemporaryDirectory(
                prefix=f"mochirii-failed-bootstrap-terminal-publisher-{consumer}-io-"
            ) as directory:
                fixture = new_fixture(directory)
                if consumer == "staging-replay":
                    staging_armed = abrupt_publish_after(
                        transaction,
                        "os.close(descriptor)",
                        1,
                        "terminal",
                        True,
                    )
                    prepared = run_transaction(staging_armed, fixture)
                    if prepared.returncode != 86 or prepared.stdout or prepared.stderr:
                        raise RuntimeError(
                            "Failed-bootstrap terminal publisher replay fixture did not arm."
                        )
                hostile = guarded_function_io_hostile(
                    transaction,
                    "def publish(path, document, create, defer_update=False):",
                    "\nexact_directory(shared_root",
                    anchor,
                    occurrence,
                    "path == terminal and create is True",
                    "PRIVATE_TERMINAL_PUBLISHER_PATH",
                )
                rejected = run_transaction(hostile, fixture)
                assert_categorical_failure(
                    rejected,
                    b"failed-bootstrap terminal evidence publication failed\n",
                    f"Failed-bootstrap terminal {consumer} publisher I/O boundary",
                )
                terminal = fixture["terminal"]
                terminal_staging = terminal.with_name(f".{terminal.name}.publish")
                if (
                    not fixture["pending"].is_file()
                    or not fixture["mutation_evidence"].is_file()
                    or (not terminal.is_file() and not terminal_staging.is_file())
                ):
                    raise RuntimeError(
                        "Failed-bootstrap terminal publisher I/O failure lost recovery authority."
                    )
                resumed = run_transaction(transaction, fixture)
                if resumed.returncode != 0 or resumed.stdout or resumed.stderr:
                    raise RuntimeError(
                        "Failed-bootstrap terminal publisher I/O state did not resume."
                    )
                verify_terminal(fixture)

    for anchor, occurrence in (
        ("fsync_directory(mutation_evidence.parent)", 1),
        ("fsync_directory(mutation.parent)", 2),
    ):
        with tempfile.TemporaryDirectory(
            prefix="mochirii-failed-bootstrap-mutation-retirement-fsync-io-"
        ) as directory:
            hostile = statement_io_hostile(
                transaction,
                anchor,
                occurrence,
                "PRIVATE_MUTATION_RETIREMENT_FSYNC_PATH",
            )
            assert_transaction_io_recovery(
                hostile,
                new_fixture(directory),
                "Failed-bootstrap mutation-retirement parent-fsync I/O boundary",
            )

    retired_parent_retry_hostile = statement_io_hostile(
        transaction,
        "fsync_directory(mutation.parent)",
        1,
        "PRIVATE_RETIRED_SOURCE_PARENT_PATH",
    )
    initial_parent_retirement_hostile = statement_io_hostile(
        transaction,
        "fsync_directory(mutation.parent)",
        2,
        "PRIVATE_INITIAL_SOURCE_PARENT_PATH",
    )
    with tempfile.TemporaryDirectory(
        prefix="mochirii-failed-bootstrap-retired-source-parent-retry-"
    ) as directory:
        fixture = new_fixture(directory)
        first = run_transaction(initial_parent_retirement_hostile, fixture)
        assert_categorical_failure(
            first,
            b"failed-bootstrap quarantine transaction failed\n",
            "Failed-bootstrap retired source-parent first durability retry",
        )
        pending = fixture["pending"]
        staging = pending.with_name(f".{pending.name}.publish")
        if (
            fixture["mutation"].exists()
            or not fixture["mutation_evidence"].is_file()
            or not pending.is_file()
            or not staging.is_file()
            or fixture["terminal"].exists()
        ):
            raise RuntimeError(
                "Failed-bootstrap retired source-parent first failure lost its replay state."
            )
        pending_before = regular_identity(pending)
        staging_before = regular_identity(staging)
        second = run_transaction(retired_parent_retry_hostile, fixture)
        assert_categorical_failure(
            second,
            b"failed-bootstrap quarantine transaction failed\n",
            "Failed-bootstrap retired source-parent second durability retry",
        )
        if (
            regular_identity(pending) != pending_before
            or regular_identity(staging) != staging_before
            or fixture["terminal"].exists()
        ):
            raise RuntimeError(
                "Failed-bootstrap retired source-parent retry promoted state before durability."
            )
        resumed = run_transaction(transaction, fixture)
        if resumed.returncode != 0 or resumed.stdout or resumed.stderr:
            raise RuntimeError("Failed-bootstrap retired source-parent state did not resume.")
        verify_terminal(fixture)

    with tempfile.TemporaryDirectory(
        prefix="mochirii-failed-bootstrap-alias-source-parent-retry-"
    ) as directory:
        fixture = new_fixture(directory)
        retiring = abrupt_after(
            transaction, "os.link(mutation, mutation_evidence, follow_symlinks=False)"
        )
        armed = run_transaction(retiring, fixture)
        if armed.returncode != 86 or armed.stdout or armed.stderr:
            raise RuntimeError("Failed-bootstrap retiring source-parent fixture did not arm.")
        helper_hostile = function_io_hostile(
            transaction,
            "def finish_mutation_evidence_alias(source, destination, expected_sha):",
            "\ndef exact_regular",
            "fsync_directory(source.parent)",
            1,
            "PRIVATE_ALIAS_SOURCE_PARENT_PATH",
        )
        assert_categorical_failure(
            run_transaction(helper_hostile, fixture),
            b"deployment mutation evidence retirement failed\n",
            "Failed-bootstrap alias source-parent durability boundary",
        )
        if fixture["mutation"].exists() or not fixture["mutation_evidence"].is_file():
            raise RuntimeError("Failed-bootstrap alias source-parent failure lost retained authority.")
        assert_categorical_failure(
            run_transaction(retired_parent_retry_hostile, fixture),
            b"failed-bootstrap quarantine transaction failed\n",
            "Failed-bootstrap alias source-parent replay durability boundary",
        )
        if fixture["terminal"].exists():
            raise RuntimeError(
                "Failed-bootstrap alias source-parent replay published terminal evidence early."
            )
        resumed = run_transaction(transaction, fixture)
        if resumed.returncode != 0 or resumed.stdout or resumed.stderr:
            raise RuntimeError("Failed-bootstrap alias source-parent state did not resume.")
        verify_terminal(fixture)

    with tempfile.TemporaryDirectory(prefix="mochirii-failed-bootstrap-mutation-reader-deep-") as directory:
        fixture = new_fixture(directory)
        publish_raw(fixture["mutation"], deep_json)
        assert_categorical_failure(
            run_mutation_reader(fixture),
            b"failed bootstrap journal is malformed\n",
            "Failed-bootstrap actual mutation reader",
        )

    with tempfile.TemporaryDirectory(prefix="mochirii-failed-bootstrap-mutation-reader-output-") as directory:
        fixture = new_fixture(directory)
        valid_document = mutation_document()
        valid_raw = publish_json(fixture["mutation"], valid_document)
        accepted = run_mutation_reader(fixture)
        expected_output = (
            f"{current}\n"
            f"{'c' * 64}\n"
            f"{'d' * 64}\n"
            f"{valid_document['targetAppConfigurationFile']}\n"
            f"{hashlib.sha256(valid_raw).hexdigest()}\n"
        ).encode("ascii")
        if accepted.returncode != 0 or accepted.stdout != expected_output or accepted.stderr:
            raise RuntimeError("Failed-bootstrap actual mutation reader rejected its exact five-line tuple.")
        hostile_paths = (
            "",
            "\ud800",
            f"{valid_document['targetAppConfigurationFile']}\n",
            f"{valid_document['targetAppConfigurationFile']}\x00",
            "/var/discourse/containers/releases/" + ("x" * 4097) + "/app.yml",
        )
        for hostile_path in hostile_paths:
            publish_json(fixture["mutation"], mutation_document(hostile_path))
            assert_categorical_failure(
                run_mutation_reader(fixture),
                b"failed bootstrap journal tuple differs\n",
                "Failed-bootstrap actual mutation reader output contract",
            )
        for schema_version in (True, 1.0):
            hostile_document = mutation_document()
            hostile_document["schemaVersion"] = schema_version
            publish_json(fixture["mutation"], hostile_document)
            assert_categorical_failure(
                run_mutation_reader(fixture),
                b"failed bootstrap journal tuple differs\n",
                "Failed-bootstrap actual mutation reader schema contract",
            )
        numeric_output_fields = (
            ("repositoryCommit", int("1" * 40)),
            ("productionConfigurationSha256", int("1" * 64)),
            ("releaseArchiveSha256", int("1" * 64)),
        )
        for field, value in numeric_output_fields:
            hostile_document = mutation_document()
            hostile_document[field] = value
            hostile_target = (
                "/var/discourse/containers/releases/"
                f"{hostile_document['repositoryCommit']}/"
                f"{hostile_document['productionConfigurationSha256']}/app.yml"
            )
            hostile_document["targetAppConfigurationFile"] = hostile_target
            hostile_document["activeConfigurationFile"] = hostile_target
            if field == "productionConfigurationSha256":
                hostile_document["targetAppConfigurationSha256"] = value
                hostile_document["activeConfigurationSha256"] = value
            publish_json(fixture["mutation"], hostile_document)
            assert_categorical_failure(
                run_mutation_reader(fixture),
                b"failed bootstrap journal tuple differs\n",
                "Failed-bootstrap actual mutation reader scalar contract",
            )

    with tempfile.TemporaryDirectory(prefix="mochirii-failed-bootstrap-pending-reader-") as directory:
        fixture = new_fixture(directory)
        armed = interrupt_after(transaction, "publish(pending, state, True)")
        crashed = run_transaction(armed, fixture)
        if crashed.returncode != 86 or crashed.stdout or crashed.stderr:
            raise RuntimeError("Failed-bootstrap pending-reader fixture did not arm categorically.")
        pending = fixture["pending"]
        pending_raw = pending.read_bytes()
        pending_document = json.loads(pending_raw.decode("utf-8"))
        identity = run_identity_reader("pending", fixture)
        expected_identity = f"{current}\n{failed}\n{fixture['mutation_sha']}\n".encode("ascii")
        if identity.returncode != 0 or identity.stdout != expected_identity or identity.stderr:
            raise RuntimeError("Failed-bootstrap actual pending identity reader rejected exact evidence.")
        for schema_version in (True, 1.0):
            hostile_document = {**pending_document, "schemaVersion": schema_version}
            publish_json(pending, hostile_document)
            assert_identity_reader_failure(
                "pending", fixture, b"failed-bootstrap pending identity differs\n"
            )
        pending_non_object = (
            b"null\n",
            (json.dumps(sorted(pending_document), separators=(",", ":")) + "\n").encode("utf-8"),
            deep_json,
        )
        for hostile_raw in pending_non_object:
            pending.write_bytes(hostile_raw)
            pending.chmod(0o600)
            os.chown(pending, 0, 0)
            assert_identity_reader_failure(
                "pending", fixture, b"failed-bootstrap recovery evidence is malformed\n"
            )

    identity_tuple_hostiles = (
        ("standalonePath", "/unexpected/standalone"),
        ("quarantinePath", "/unexpected/quarantine"),
        ("mutationEvidencePath", "/unexpected/mutation-evidence.json"),
        ("mutationSha256", 7),
    )
    for field, value in identity_tuple_hostiles:
        with tempfile.TemporaryDirectory(
            prefix=f"mochirii-failed-bootstrap-pending-direct-{field}-"
        ) as directory:
            fixture = new_fixture(directory)
            armed = interrupt_after(transaction, "publish(pending, state, True)")
            if run_transaction(armed, fixture).returncode != 86:
                raise RuntimeError("Failed-bootstrap pending direct hostile did not arm.")
            pending = fixture["pending"]
            document = json.loads(pending.read_text(encoding="utf-8"))
            document[field] = value
            publish_json(pending, document)
            before = regular_identity(pending)
            assert_identity_reader_failure(
                "pending", fixture, b"failed-bootstrap pending identity differs\n"
            )
            if regular_identity(pending) != before:
                raise RuntimeError("Failed-bootstrap invalid pending tuple was altered.")

        with tempfile.TemporaryDirectory(
            prefix=f"mochirii-failed-bootstrap-pending-alias-{field}-"
        ) as directory:
            fixture = new_fixture(directory)
            armed = interrupt_after(transaction, "publish(pending, state, True)")
            if run_transaction(armed, fixture).returncode != 86:
                raise RuntimeError("Failed-bootstrap pending alias hostile did not arm.")
            pending = fixture["pending"]
            document = json.loads(pending.read_text(encoding="utf-8"))
            document[field] = value
            publish_json(pending, document)
            staging = pending.with_name(f".{pending.name}.publish")
            os.link(pending, staging)
            pending_before = regular_identity(pending)
            staging_before = regular_identity(staging)
            assert_identity_reader_failure(
                "pending", fixture, b"failed-bootstrap pending identity differs\n"
            )
            if (
                regular_identity(pending) != pending_before
                or regular_identity(staging) != staging_before
            ):
                raise RuntimeError("Failed-bootstrap invalid pending alias was altered.")

        with tempfile.TemporaryDirectory(
            prefix=f"mochirii-failed-bootstrap-pending-candidate-{field}-"
        ) as directory:
            fixture = new_fixture(directory)
            armed = interrupt_after(transaction, "publish(pending, state, True)")
            if run_transaction(armed, fixture).returncode != 86:
                raise RuntimeError("Failed-bootstrap pending candidate hostile did not arm.")
            pending = fixture["pending"]
            document = json.loads(pending.read_text(encoding="utf-8"))
            candidate = {
                **document,
                "phase": "runtime-quarantined",
                "updatedAt": "2026-08-25T20:02:00Z",
                field: value,
            }
            staging = pending.with_name(f".{pending.name}.publish")
            publish_json(staging, candidate)
            pending_before = regular_identity(pending)
            staging_before = regular_identity(staging)
            assert_identity_reader_failure(
                "pending",
                fixture,
                b"failed-bootstrap pending publication transition differs\n",
            )
            if (
                regular_identity(pending) != pending_before
                or regular_identity(staging) != staging_before
            ):
                raise RuntimeError("Failed-bootstrap invalid pending candidate was altered.")

        with tempfile.TemporaryDirectory(
            prefix=f"mochirii-failed-bootstrap-terminal-alias-{field}-"
        ) as directory:
            fixture = new_fixture(directory)
            completed = run_transaction(transaction, fixture)
            if completed.returncode != 0 or completed.stdout or completed.stderr:
                raise RuntimeError("Failed-bootstrap terminal alias hostile did not complete.")
            terminal = fixture["terminal"]
            document = json.loads(terminal.read_text(encoding="utf-8"))
            document[field] = value
            publish_json(terminal, document)
            staging = terminal.with_name(f".{terminal.name}.publish")
            os.link(terminal, staging)
            terminal_before = regular_identity(terminal)
            staging_before = regular_identity(staging)
            assert_identity_reader_failure(
                "terminal", fixture, b"failed-bootstrap terminal identity differs\n"
            )
            if (
                regular_identity(terminal) != terminal_before
                or regular_identity(staging) != staging_before
            ):
                raise RuntimeError("Failed-bootstrap invalid terminal alias was altered.")

    for authority_kind, expected_transaction in (
        ("missing", b"deployment mutation authority state differs\n"),
        ("wrong", b"deployment mutation journal differs\n"),
    ):
        with tempfile.TemporaryDirectory(
            prefix=f"mochirii-failed-bootstrap-pending-authority-{authority_kind}-"
        ) as directory:
            fixture = new_fixture(directory)
            armed = interrupt_after(transaction, "publish(pending, state, True)")
            if run_transaction(armed, fixture).returncode != 86:
                raise RuntimeError("Failed-bootstrap pending-authority fixture did not arm.")
            pending = fixture["pending"]
            staging = pending.with_name(f".{pending.name}.publish")
            os.link(pending, staging)
            pending_before = regular_identity(pending)
            staging_before = regular_identity(staging)
            if authority_kind == "missing":
                fixture["mutation"].unlink()
            else:
                publish_raw(fixture["mutation"], b'{"wrong":true}\n')
            assert_identity_reader_failure(
                "pending", fixture, b"failed-bootstrap recovery authority differs\n"
            )
            assert_categorical_failure(
                run_transaction(transaction, fixture),
                expected_transaction,
                "Failed-bootstrap pending authority observation",
            )
            if (
                regular_identity(pending) != pending_before
                or regular_identity(staging) != staging_before
                or fixture["quarantine"].exists()
            ):
                raise RuntimeError("Failed-bootstrap pending authority rejection changed journal state.")

    for authority_kind, expected_transaction in (
        ("missing", b"deployment mutation authority state differs\n"),
        ("wrong", b"deployment mutation evidence differs\n"),
        ("reappeared", b"deployment mutation authority state differs\n"),
    ):
        with tempfile.TemporaryDirectory(
            prefix=f"mochirii-failed-bootstrap-retired-authority-{authority_kind}-"
        ) as directory:
            fixture = new_fixture(directory)
            terminal_armed = interrupt_after(
                transaction, "publish(terminal, terminal_document, True)"
            )
            prepared = run_transaction(terminal_armed, fixture)
            if prepared.returncode != 86 or prepared.stdout or prepared.stderr:
                raise RuntimeError("Failed-bootstrap retired-authority fixture did not arm.")
            fixture["terminal"].unlink()
            pending = fixture["pending"]
            pending_before = regular_identity(pending)
            if authority_kind == "missing":
                fixture["mutation_evidence"].unlink()
            elif authority_kind == "wrong":
                publish_raw(fixture["mutation_evidence"], b'{"wrong":true}\n')
            else:
                os.link(fixture["mutation_evidence"], fixture["mutation"])
            assert_identity_reader_failure(
                "pending", fixture, b"failed-bootstrap recovery authority differs\n"
            )
            assert_categorical_failure(
                run_transaction(transaction, fixture),
                expected_transaction,
                "Failed-bootstrap retired authority observation",
            )
            if (
                regular_identity(pending) != pending_before
                or fixture["terminal"].exists()
            ):
                raise RuntimeError("Failed-bootstrap retired authority rejection changed journal state.")

    with tempfile.TemporaryDirectory(
        prefix="mochirii-failed-bootstrap-terminal-pending-drift-"
    ) as directory:
        fixture = new_fixture(directory)
        terminal_armed = interrupt_after(
            transaction, "publish(terminal, terminal_document, True)"
        )
        prepared = run_transaction(terminal_armed, fixture)
        if prepared.returncode != 86 or prepared.stdout or prepared.stderr:
            raise RuntimeError("Failed-bootstrap terminal/pending drift fixture did not arm.")
        terminal = fixture["terminal"]
        terminal_staging = terminal.with_name(f".{terminal.name}.publish")
        os.link(terminal, terminal_staging)
        pending = fixture["pending"]
        pending_document = json.loads(pending.read_text(encoding="utf-8"))
        pending_document["updatedAt"] = "2026-08-25T20:09:00Z"
        publish_json(pending, pending_document)
        terminal_before = regular_identity(terminal)
        staging_before = regular_identity(terminal_staging)
        assert_categorical_failure(
            run_transaction(transaction, fixture),
            b"failed-bootstrap terminal and pending journals differ\n",
            "Failed-bootstrap terminal/pending cross-record binding",
        )
        if (
            regular_identity(terminal) != terminal_before
            or regular_identity(terminal_staging) != staging_before
        ):
            raise RuntimeError("Failed-bootstrap terminal alias healed before pending agreement.")

    for staging_kind in ("valid", "foreign", "symlink"):
        with tempfile.TemporaryDirectory(
            prefix=f"mochirii-failed-bootstrap-terminal-preflight-{staging_kind}-"
        ) as directory:
            fixture = new_fixture(directory)
            armed = interrupt_after(transaction, "publish(pending, state, True)")
            if run_transaction(armed, fixture).returncode != 86:
                raise RuntimeError("Failed-bootstrap terminal preflight hostile did not arm.")
            recovery = fixture["recovery"]
            if not recovery.is_dir() or any(recovery.iterdir()):
                raise RuntimeError("Failed-bootstrap terminal preflight recovery-root fixture differs.")
            recovery.rmdir()
            pending = fixture["pending"]
            terminal = fixture["terminal"]
            staging = terminal.with_name(f".{terminal.name}.publish")
            if staging_kind == "valid":
                document = json.loads(pending.read_text(encoding="utf-8"))
                document.update(
                    phase="complete",
                    completedAt="2026-08-25T20:03:00Z",
                    sslRestored=document["sslPresent"],
                )
                publish_json(staging, document)
            elif staging_kind == "foreign":
                publish_raw(staging, b'{"unexpected":true}\n')
            else:
                staging.symlink_to(pending)
            standalone_before = sorted(path.name for path in fixture["standalone"].iterdir())
            mutation_before = regular_identity(fixture["mutation"])
            rejected = run_transaction(transaction, fixture)
            assert_categorical_failure(
                rejected,
                b"failed-bootstrap terminal publication staging is unsafe\n",
                "Failed-bootstrap terminal-staging preflight",
            )
            if (
                not (staging.exists() or staging.is_symlink())
                or fixture["quarantine"].exists()
                or recovery.exists()
                or regular_identity(fixture["mutation"]) != mutation_before
                or sorted(path.name for path in fixture["standalone"].iterdir())
                != standalone_before
            ):
                raise RuntimeError("Failed-bootstrap terminal staging crossed the runtime boundary.")

    for staging_kind in ("copy", "symlink"):
        with tempfile.TemporaryDirectory(
            prefix=f"mochirii-failed-bootstrap-terminal-one-link-{staging_kind}-"
        ) as directory:
            fixture = new_fixture(directory)
            completed = run_transaction(transaction, fixture)
            if completed.returncode != 0 or completed.stdout or completed.stderr:
                raise RuntimeError("Failed-bootstrap terminal one-link hostile did not complete.")
            terminal = fixture["terminal"]
            staging = terminal.with_name(f".{terminal.name}.publish")
            if staging_kind == "copy":
                publish_raw(staging, terminal.read_bytes())
            else:
                staging.symlink_to(terminal)
            terminal_before = regular_identity(terminal)
            assert_identity_reader_failure(
                "terminal", fixture, b"failed-bootstrap recovery evidence is unsafe\n"
            )
            rejected = run_transaction(transaction, fixture)
            assert_categorical_failure(
                rejected,
                (
                    b"failed-bootstrap terminal publication staging is unsafe\n"
                    if staging_kind == "copy"
                    else b"failed-bootstrap terminal evidence publication staging is unsafe\n"
                ),
                "Failed-bootstrap terminal one-link staging",
            )
            if (
                regular_identity(terminal) != terminal_before
                or not (staging.exists() or staging.is_symlink())
            ):
                raise RuntimeError("Failed-bootstrap terminal one-link staging was altered.")

    for kind, fail_on_lineage_call, expected in (
        (
            "pending",
            1,
            b"Failed-bootstrap pending recovery source lineage differs before identity repair.\n",
        ),
        (
            "terminal",
            1,
            b"Failed-bootstrap terminal recovery source lineage differs before identity repair.\n",
        ),
        (
            "pending",
            2,
            b"Failed-bootstrap pending recovery source lineage differs after identity repair.\n",
        ),
        (
            "terminal",
            2,
            b"Failed-bootstrap terminal recovery source lineage differs after identity repair.\n",
        ),
    ):
        with tempfile.TemporaryDirectory(
            prefix=f"mochirii-failed-bootstrap-{kind}-lineage-first-"
        ) as directory:
            fixture = new_fixture(directory)
            if kind == "pending":
                armed = interrupt_after(transaction, "publish(pending, state, True)")
                if run_transaction(armed, fixture).returncode != 86:
                    raise RuntimeError("Failed-bootstrap pending lineage-first fixture did not arm.")
                destination = fixture["pending"]
            else:
                completed = run_transaction(transaction, fixture)
                if completed.returncode != 0 or completed.stdout or completed.stderr:
                    raise RuntimeError("Failed-bootstrap terminal lineage-first fixture did not complete.")
                destination = fixture["terminal"]
            staging = destination.with_name(f".{destination.name}.publish")
            os.link(destination, staging)
            destination_before = regular_identity(destination)
            staging_before = regular_identity(staging)
            rejected = run_recovery_with_rejected_lineage(
                fixture, fail_on_lineage_call=fail_on_lineage_call
            )
            assert_categorical_failure(
                rejected,
                expected,
                f"Failed-bootstrap {kind} source authority",
            )
            if (
                regular_identity(destination) != destination_before
                or regular_identity(staging) != staging_before
            ):
                raise RuntimeError(
                    f"Failed-bootstrap {kind} identity mutated before source authority."
                )

    with tempfile.TemporaryDirectory(prefix="mochirii-failed-bootstrap-transaction-new-deep-") as directory:
        fixture = new_fixture(directory)
        publish_raw(fixture["mutation"], deep_json)
        fixture["mutation_raw"] = deep_json
        fixture["mutation_sha"] = hashlib.sha256(deep_json).hexdigest()
        assert_categorical_failure(
            run_transaction(transaction, fixture),
            b"deployment mutation journal is malformed\n",
            "Failed-bootstrap new-control transaction decoder",
        )

    with tempfile.TemporaryDirectory(prefix="mochirii-failed-bootstrap-transaction-pending-deep-") as directory:
        fixture = new_fixture(directory)
        armed = interrupt_after(transaction, "publish(pending, state, True)")
        crashed = run_transaction(armed, fixture)
        if crashed.returncode != 86 or crashed.stdout or crashed.stderr:
            raise RuntimeError("Failed-bootstrap deep pending fixture did not arm categorically.")
        publish_raw(fixture["pending"], deep_json)
        assert_categorical_failure(
            run_transaction(transaction, fixture),
            b"failed-bootstrap pending journal is malformed\n",
            "Failed-bootstrap pending-replay transaction decoder",
        )

    with tempfile.TemporaryDirectory(prefix="mochirii-failed-bootstrap-transaction-terminal-deep-") as directory:
        fixture = new_fixture(directory)
        completed = run_transaction(transaction, fixture)
        if completed.returncode != 0 or completed.stdout or completed.stderr:
            raise RuntimeError("Failed-bootstrap deep terminal fixture did not complete.")
        publish_raw(fixture["terminal"], deep_json)
        assert_categorical_failure(
            run_transaction(transaction, fixture),
            b"failed-bootstrap terminal evidence is malformed\n",
            "Failed-bootstrap terminal-replay transaction decoder",
        )

    for schema_version in (True, 1.0):
        with tempfile.TemporaryDirectory(
            prefix="mochirii-failed-bootstrap-transaction-pending-schema-"
        ) as directory:
            fixture = new_fixture(directory)
            armed = interrupt_after(transaction, "publish(pending, state, True)")
            crashed = run_transaction(armed, fixture)
            if crashed.returncode != 86 or crashed.stdout or crashed.stderr:
                raise RuntimeError("Failed-bootstrap pending schema fixture did not arm categorically.")
            pending = fixture["pending"]
            pending_document = json.loads(pending.read_text(encoding="utf-8"))
            pending_document["schemaVersion"] = schema_version
            publish_json(pending, pending_document)
            assert_categorical_failure(
                run_transaction(transaction, fixture),
                b"failed-bootstrap quarantine journal tuple differs\n",
                "Failed-bootstrap pending-replay transaction schema contract",
            )
        with tempfile.TemporaryDirectory(
            prefix="mochirii-failed-bootstrap-transaction-terminal-schema-"
        ) as directory:
            fixture = new_fixture(directory)
            completed = run_transaction(transaction, fixture)
            if completed.returncode != 0 or completed.stdout or completed.stderr:
                raise RuntimeError("Failed-bootstrap terminal schema fixture did not complete.")
            terminal = fixture["terminal"]
            terminal_document = json.loads(terminal.read_text(encoding="utf-8"))
            terminal_document["schemaVersion"] = schema_version
            publish_json(terminal, terminal_document)
            assert_categorical_failure(
                run_transaction(transaction, fixture),
                b"failed-bootstrap quarantine journal tuple differs\n",
                "Failed-bootstrap terminal-replay transaction schema contract",
            )

    for anchor in ("pending.unlink()", "fsync_directory(pending.parent)"):
        final_occurrence = 3 if anchor == "pending.unlink()" else 5
        staging_occurrence = 2 if anchor == "pending.unlink()" else 3
        with tempfile.TemporaryDirectory(
            prefix="mochirii-failed-bootstrap-pending-retirement-final-"
        ) as directory:
            fixture = new_fixture(directory)
            interrupted = abrupt_after(transaction, anchor, final_occurrence)
            crashed = run_transaction(interrupted, fixture)
            if crashed.returncode != 86 or crashed.stdout or crashed.stderr:
                raise RuntimeError("Failed-bootstrap final pending retirement did not stop abruptly.")
            resumed = run_transaction(transaction, fixture)
            if resumed.returncode != 0 or resumed.stdout or resumed.stderr:
                raise RuntimeError("Failed-bootstrap final pending retirement did not resume.")
            verify_terminal(fixture)

        with tempfile.TemporaryDirectory(
            prefix="mochirii-failed-bootstrap-pending-retirement-replay-"
        ) as directory:
            fixture = new_fixture(directory)
            terminal_armed = interrupt_after(
                transaction, "publish(terminal, terminal_document, True)"
            )
            prepared = run_transaction(terminal_armed, fixture)
            if prepared.returncode != 86 or prepared.stdout or prepared.stderr:
                raise RuntimeError("Failed-bootstrap terminal replay retirement did not arm.")
            interrupted = abrupt_after(transaction, anchor, 1)
            crashed = run_transaction(interrupted, fixture)
            if crashed.returncode != 86 or crashed.stdout or crashed.stderr:
                raise RuntimeError("Failed-bootstrap replay pending retirement did not stop abruptly.")
            resumed = run_transaction(transaction, fixture)
            if resumed.returncode != 0 or resumed.stdout or resumed.stderr:
                raise RuntimeError("Failed-bootstrap replay pending retirement did not resume.")
            verify_terminal(fixture)

        with tempfile.TemporaryDirectory(
            prefix="mochirii-failed-bootstrap-pending-retirement-staging-"
        ) as directory:
            fixture = new_fixture(directory)
            staging_armed = abrupt_publish_after(
                transaction,
                "os.close(descriptor)",
                1,
                "terminal",
                True,
            )
            prepared = run_transaction(staging_armed, fixture)
            if prepared.returncode != 86 or prepared.stdout or prepared.stderr:
                raise RuntimeError("Failed-bootstrap staging pending retirement did not arm.")
            interrupted = abrupt_after(transaction, anchor, staging_occurrence)
            crashed = run_transaction(interrupted, fixture)
            if crashed.returncode != 86 or crashed.stdout or crashed.stderr:
                raise RuntimeError("Failed-bootstrap staging pending retirement did not stop abruptly.")
            resumed = run_transaction(transaction, fixture)
            if resumed.returncode != 0 or resumed.stdout or resumed.stderr:
                raise RuntimeError("Failed-bootstrap staging pending retirement did not resume.")
            verify_terminal(fixture)

    for anchor in crash_anchors:
        with tempfile.TemporaryDirectory(prefix="mochirii-failed-bootstrap-") as directory:
            fixture = new_fixture(directory)
            interrupted = interrupt_after(transaction, anchor)
            crashed = run_transaction(interrupted, fixture)
            if crashed.returncode != 86 or crashed.stdout or crashed.stderr:
                raise RuntimeError("Failed-bootstrap crash-window fixture did not stop categorically.")
            if (
                anchor == 'standalone.mkdir(mode=state["standaloneMode"])'
                and stat.S_IMODE(fixture["standalone"].stat().st_mode) != 0o700
            ):
                raise RuntimeError("Failed-bootstrap secure-umask crash fixture did not retain the partial mode.")
            resumed = run_transaction(transaction, fixture)
            if resumed.returncode != 0 or resumed.stdout or resumed.stderr:
                raise RuntimeError("Failed-bootstrap exact pending transaction did not resume.")
            verify_terminal(fixture)
            repeated = run_transaction(transaction, fixture)
            if repeated.returncode != 0 or repeated.stdout or repeated.stderr:
                raise RuntimeError("Failed-bootstrap terminal transaction is not idempotent.")

    directory_move_cases = (
        ("source == standalone", True),
        ('source == quarantine / "ssl"', True),
    )
    for guard, ssl_present in directory_move_cases:
        for anchor in (
            "os.rename(source, destination)",
            "fsync_directory(destination.parent)",
            "fsync_directory(source.parent)",
        ):
            with tempfile.TemporaryDirectory(
                prefix="mochirii-failed-bootstrap-directory-move-"
            ) as directory:
                fixture = new_fixture(directory, ssl_present=ssl_present)
                interrupted = abrupt_function_after(
                    transaction,
                    "def durable_directory_move(source, destination):",
                    "\ndef exact_directory",
                    anchor,
                    1,
                    guard,
                )
                crashed = run_transaction(interrupted, fixture)
                if crashed.returncode != 86 or crashed.stdout or crashed.stderr:
                    raise RuntimeError(
                        "Failed-bootstrap durable directory move did not stop abruptly."
                    )
                resumed = run_transaction(transaction, fixture)
                if resumed.returncode != 0 or resumed.stdout or resumed.stderr:
                    raise RuntimeError("Failed-bootstrap durable directory move did not resume.")
                verify_terminal(fixture)

    for guard, ssl_present in (
        ("path == recovery_root", False),
        ("path == quarantine", False),
        ("path == standalone", False),
    ):
        for anchor in ("fsync_directory(path)", "fsync_directory(path.parent)"):
            with tempfile.TemporaryDirectory(
                prefix="mochirii-failed-bootstrap-directory-metadata-"
            ) as directory:
                fixture = new_fixture(directory, ssl_present=ssl_present)
                interrupted = abrupt_function_after(
                    transaction,
                    "def persist_directory(path):",
                    "\ndef durable_directory_move",
                    anchor,
                    1,
                    guard,
                )
                crashed = run_transaction(interrupted, fixture)
                if crashed.returncode != 86 or crashed.stdout or crashed.stderr:
                    raise RuntimeError(
                        "Failed-bootstrap directory-metadata persistence did not stop abruptly."
                    )
                resumed = run_transaction(transaction, fixture)
                if resumed.returncode != 0 or resumed.stdout or resumed.stderr:
                    raise RuntimeError(
                        "Failed-bootstrap directory-metadata persistence did not resume."
                    )
                verify_terminal(fixture)

    mutation_retirement_anchors = (
        ("os.link(mutation, mutation_evidence, follow_symlinks=False)", 1),
        ("fsync_directory(mutation_evidence.parent)", 1),
        ("mutation.unlink()", 1),
        ("fsync_directory(mutation.parent)", 2),
    )
    for anchor, occurrence in mutation_retirement_anchors:
        with tempfile.TemporaryDirectory(
            prefix="mochirii-failed-bootstrap-mutation-retirement-"
        ) as directory:
            fixture = new_fixture(directory)
            interrupted = abrupt_after(transaction, anchor, occurrence)
            crashed = run_transaction(interrupted, fixture)
            if crashed.returncode != 86 or crashed.stdout or crashed.stderr:
                raise RuntimeError("Failed-bootstrap mutation retirement did not stop abruptly.")
            resumed = run_transaction(transaction, fixture)
            if resumed.returncode != 0 or resumed.stdout or resumed.stderr:
                raise RuntimeError("Failed-bootstrap mutation retirement did not resume.")
            verify_terminal(fixture)

    publication_crash_anchors = (
        ("descriptor = os.open(path.parent, flags, 0o600)", 1, False),
        ("os.fchmod(descriptor, 0o600)", 1, False),
        ("os.fchown(descriptor, 0, 0)", 1, False),
        ("written = os.write(descriptor, raw[offset:])", 1, False),
        ("os.fsync(descriptor)", 1, False),
        ("link_unnamed_staging(descriptor, staging)", 1, False),
        ("fsync_directory(path.parent)", 1, False),
        ("os.close(descriptor)", 1, False),
        ("os.link(staging, path, follow_symlinks=False)", 1, True),
        ("fsync_directory(path.parent)", 2, False),
        ("staging.unlink()", 1, False),
        ("fsync_directory(path.parent)", 3, False),
    )
    for destination in ("pending", "terminal"):
        for anchor, occurrence, probe_identity_reader in publication_crash_anchors:
            with tempfile.TemporaryDirectory(
                prefix=f"mochirii-failed-bootstrap-publication-{destination}-"
            ) as directory:
                fixture = new_fixture(directory)
                interrupted = abrupt_publish_after(
                    transaction, anchor, occurrence, destination, True
                )
                crashed = run_transaction(interrupted, fixture)
                if crashed.returncode != 86 or crashed.stdout or crashed.stderr:
                    raise RuntimeError(
                        "Failed-bootstrap internal publication crash fixture did not stop abruptly."
                    )
                published = fixture[destination]
                staging = published.with_name(f".{published.name}.publish")
                if probe_identity_reader:
                    before_identity = regular_identity(published)
                    before_staging = regular_identity(staging)
                    published_metadata = published.stat()
                    staging_metadata = staging.stat()
                    if (
                        published_metadata.st_nlink != 2
                        or staging_metadata.st_nlink != 2
                        or published_metadata.st_dev != staging_metadata.st_dev
                        or published_metadata.st_ino != staging_metadata.st_ino
                    ):
                        raise RuntimeError(
                            "Failed-bootstrap publication alias crash fixture did not retain one exact inode."
                        )
                    identity = run_identity_reader(destination, fixture)
                    expected_identity = (
                        f"{current}\n{failed}\n{fixture['mutation_sha']}\n"
                    ).encode("ascii")
                    if (
                        identity.returncode != 0
                        or identity.stdout != expected_identity
                        or identity.stderr
                        or regular_identity(published) != before_identity
                        or regular_identity(staging) != before_staging
                    ):
                        raise RuntimeError(
                            "Failed-bootstrap actual identity reader mutated an exact publication alias."
                        )
                resumed = run_transaction(transaction, fixture)
                if resumed.returncode != 0 or resumed.stdout or resumed.stderr:
                    raise RuntimeError(
                        "Failed-bootstrap internal publication crash state did not resume."
                    )
                verify_terminal(fixture)
                repeated = run_transaction(transaction, fixture)
                if repeated.returncode != 0 or repeated.stdout or repeated.stderr:
                    raise RuntimeError(
                        "Failed-bootstrap repaired publication is not terminally idempotent."
                    )

    with tempfile.TemporaryDirectory(
        prefix="mochirii-failed-bootstrap-publication-transaction-reader-"
    ) as directory:
        fixture = new_fixture(directory)
        interrupted = abrupt_publish_after(
            transaction,
            "os.link(staging, path, follow_symlinks=False)",
            1,
            "pending",
            True,
        )
        crashed = run_transaction(interrupted, fixture)
        pending = fixture["pending"]
        staging = pending.with_name(f".{pending.name}.publish")
        if crashed.returncode != 86 or crashed.stdout or crashed.stderr:
            raise RuntimeError("Failed-bootstrap transaction-reader alias fixture did not arm.")
        before_identity = regular_identity(pending)
        reader_only = abrupt_after(
            transaction,
            "state = reconcile_pending_publication(\n"
            "            pending_raw, state, pending_alias, pending_staged\n"
            "        )",
        )
        reconciled = run_transaction(reader_only, fixture)
        if (
            reconciled.returncode != 86
            or reconciled.stdout
            or reconciled.stderr
            or staging.exists()
            or staging.is_symlink()
        ):
            raise RuntimeError("Failed-bootstrap transaction reader did not reconcile its exact alias.")
        assert_reconciled_identity(
            pending,
            before_identity,
            "Failed-bootstrap transaction reader",
        )
        completed = run_transaction(transaction, fixture)
        if completed.returncode != 0 or completed.stdout or completed.stderr:
            raise RuntimeError("Failed-bootstrap transaction-reader fixture did not complete.")
        verify_terminal(fixture)

    pending_update_creation_anchors = publication_crash_anchors[:8]
    for anchor, occurrence, _ in pending_update_creation_anchors:
        with tempfile.TemporaryDirectory(
            prefix="mochirii-failed-bootstrap-publication-pending-update-create-"
        ) as directory:
            fixture = new_fixture(directory)
            interrupted = abrupt_publish_after(
                transaction, anchor, occurrence, "pending", False
            )
            crashed = run_transaction(interrupted, fixture)
            if crashed.returncode != 86 or crashed.stdout or crashed.stderr:
                raise RuntimeError(
                    "Failed-bootstrap pending-update staging crash did not stop abruptly."
                )
            resumed = run_transaction(transaction, fixture)
            if resumed.returncode != 0 or resumed.stdout or resumed.stderr:
                raise RuntimeError("Failed-bootstrap pending-update staging did not resume.")
            verify_terminal(fixture)

    with tempfile.TemporaryDirectory(
        prefix="mochirii-failed-bootstrap-publication-pending-update-identity-"
    ) as directory:
        fixture = new_fixture(directory)
        interrupted = abrupt_publish_after(
            transaction,
            "os.close(descriptor)",
            1,
            "pending",
            False,
        )
        crashed = run_transaction(interrupted, fixture)
        pending = fixture["pending"]
        staging = pending.with_name(f".{pending.name}.publish")
        if crashed.returncode != 86 or crashed.stdout or crashed.stderr:
            raise RuntimeError(
                "Failed-bootstrap pending-update identity fixture did not stop abruptly."
            )
        pending_identity = regular_identity(pending)
        staging_identity = regular_identity(staging)
        identity = run_identity_reader("pending", fixture)
        expected_identity = f"{current}\n{failed}\n{fixture['mutation_sha']}\n".encode("ascii")
        if identity.returncode != 0 or identity.stdout != expected_identity or identity.stderr:
            raise RuntimeError(
                "Failed-bootstrap actual identity reader rejected an exact pending update."
            )
        if (
            regular_identity(pending) != pending_identity
            or regular_identity(staging) != staging_identity
        ):
            raise RuntimeError(
                "Failed-bootstrap actual identity reader altered an exact pending update."
            )
        resumed = run_transaction(transaction, fixture)
        if resumed.returncode != 0 or resumed.stdout or resumed.stderr:
            raise RuntimeError("Failed-bootstrap pending-update identity state did not resume.")
        verify_terminal(fixture)

    pending_update_commit_anchors = (
        ("os.replace(staging, path)", 1),
        ("descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)", 1),
        ("os.fsync(descriptor)", 1),
        ("os.close(descriptor)", 1),
        ("fsync_directory(path.parent)", 1),
        ("final_metadata = path.lstat()", 1),
    )
    for anchor, occurrence in pending_update_commit_anchors:
        with tempfile.TemporaryDirectory(
            prefix="mochirii-failed-bootstrap-publication-pending-update-commit-"
        ) as directory:
            fixture = new_fixture(directory)
            interrupted = abrupt_function_after(
                transaction,
                "def finish_publication_update(path, staging, previous_raw, replacement_raw, label):",
                "\ndef finish_mutation_evidence_alias",
                anchor,
                occurrence,
                "path == pending",
            )
            crashed = run_transaction(interrupted, fixture)
            if crashed.returncode != 86 or crashed.stdout or crashed.stderr:
                raise RuntimeError(
                    "Failed-bootstrap pending-update commit crash did not stop abruptly."
                )
            resumed = run_transaction(transaction, fixture)
            if resumed.returncode != 0 or resumed.stdout or resumed.stderr:
                raise RuntimeError("Failed-bootstrap pending-update commit did not resume.")
            verify_terminal(fixture)

    with tempfile.TemporaryDirectory(
        prefix="mochirii-failed-bootstrap-publication-alias-hostile-"
    ) as directory:
        fixture = new_fixture(directory)
        armed = interrupt_after(transaction, "publish(pending, state, True)")
        if run_transaction(armed, fixture).returncode != 86:
            raise RuntimeError("Failed-bootstrap hostile publication fixture did not arm.")
        pending = fixture["pending"]
        unrelated = pending.with_name(f".{pending.name}.unrelated")
        staging = pending.with_name(f".{pending.name}.publish")
        os.link(pending, unrelated)
        publish_raw(staging, pending.read_bytes())
        assert_identity_reader_failure(
            "pending", fixture, b"failed-bootstrap recovery evidence is unsafe\n"
        )
        rejected = run_transaction(transaction, fixture)
        assert_categorical_failure(
            rejected,
            b"failed-bootstrap pending journal is unsafe\n",
            "Failed-bootstrap mismatched publication alias transaction",
        )
        if not unrelated.is_file() or not staging.is_file():
            raise RuntimeError("Failed-bootstrap mismatched publication alias was altered.")

    for staging_kind in ("foreign", "symlink"):
        with tempfile.TemporaryDirectory(
            prefix=f"mochirii-failed-bootstrap-publication-one-link-{staging_kind}-"
        ) as directory:
            fixture = new_fixture(directory)
            armed = interrupt_after(transaction, "publish(pending, state, True)")
            if run_transaction(armed, fixture).returncode != 86:
                raise RuntimeError("Failed-bootstrap one-link staging fixture did not arm.")
            pending = fixture["pending"]
            staging = pending.with_name(f".{pending.name}.publish")
            before_identity = regular_identity(pending)
            if staging_kind == "foreign":
                publish_raw(staging, b'{"unexpected":true}\n')
            else:
                staging.symlink_to(pending)
            assert_identity_reader_failure(
                "pending",
                fixture,
                (
                    b"failed-bootstrap pending publication transition differs\n"
                    if staging_kind == "foreign"
                    else b"failed-bootstrap recovery evidence is unsafe\n"
                ),
            )
            rejected = run_transaction(transaction, fixture)
            expected = (
                b"failed-bootstrap quarantine journal tuple differs\n"
                if staging_kind == "foreign"
                else b"failed-bootstrap pending journal publication staging is unsafe\n"
            )
            assert_categorical_failure(
                rejected,
                expected,
                "Failed-bootstrap one-link target staging transaction",
            )
            if not (staging.exists() or staging.is_symlink()):
                raise RuntimeError("Failed-bootstrap unsafe one-link staging was removed.")
            if regular_identity(pending) != before_identity:
                raise RuntimeError("Failed-bootstrap unsafe one-link staging altered its destination.")
            if not fixture["standalone"].is_dir() or not fixture["mutation"].is_file():
                raise RuntimeError("Failed-bootstrap unsafe staging crossed the runtime boundary.")

    with tempfile.TemporaryDirectory(
        prefix="mochirii-failed-bootstrap-publication-unknown-orphan-"
    ) as directory:
        fixture = new_fixture(directory)
        pending = fixture["pending"]
        staging = pending.with_name(f".{pending.name}.publish")
        publish_raw(staging, b'{"unknown":true}\n')
        staging_identity = regular_identity(staging)
        assert_categorical_failure(
            run_transaction(transaction, fixture),
            b"failed-bootstrap pending publication staging is unsafe\n",
            "Failed-bootstrap unknown publication staging",
        )
        if regular_identity(staging) != staging_identity:
            raise RuntimeError("Failed-bootstrap unknown publication staging was altered.")
        if (
            fixture["recovery"].exists()
            or not fixture["standalone"].is_dir()
            or not fixture["mutation"].is_file()
        ):
            raise RuntimeError("Failed-bootstrap unknown staging crossed the runtime boundary.")

    for recovery_exists in (False, True):
        with tempfile.TemporaryDirectory(
            prefix="mochirii-failed-bootstrap-publication-prepared-orphan-"
        ) as directory:
            fixture = new_fixture(directory)
            if recovery_exists:
                fixture["recovery"].mkdir(mode=0o700)
                fixture["recovery"].chmod(0o700)
                os.chown(fixture["recovery"], 0, 0)
            pending = fixture["pending"]
            staging = pending.with_name(f".{pending.name}.publish")
            publish_json(staging, prepared_document(fixture))
            staging_before = regular_identity(staging)
            completed = run_transaction(transaction, fixture)
            if recovery_exists:
                if completed.returncode != 0 or completed.stdout or completed.stderr:
                    raise RuntimeError(
                        "Failed-bootstrap reachable prepared staging did not resume."
                    )
                verify_terminal(fixture)
            else:
                assert_categorical_failure(
                    completed,
                    b"failed-bootstrap pending publication staging is unsafe\n",
                    "Failed-bootstrap unreachable prepared staging",
                )
                if (
                    fixture["recovery"].exists()
                    or regular_identity(staging) != staging_before
                    or not fixture["standalone"].is_dir()
                    or not fixture["mutation"].is_file()
                ):
                    raise RuntimeError(
                        "Failed-bootstrap unreachable prepared staging mutated its fixture."
                    )

    with tempfile.TemporaryDirectory(
        prefix="mochirii-failed-bootstrap-publication-completed-orphan-"
    ) as directory:
        fixture = new_fixture(directory)
        completed = run_transaction(transaction, fixture)
        if completed.returncode != 0 or completed.stdout or completed.stderr:
            raise RuntimeError("Failed-bootstrap completed-orphan fixture did not complete.")
        terminal_before = regular_identity(fixture["terminal"])
        pending_staging = fixture["pending"].with_name(
            f".{fixture['pending'].name}.publish"
        )
        publish_raw(pending_staging, b'{"unknown":true}\n')
        staging_before = regular_identity(pending_staging)
        assert_categorical_failure(
            run_transaction(transaction, fixture),
            b"failed-bootstrap pending publication staging is unsafe\n",
            "Failed-bootstrap completed pending-staging orphan",
        )
        if (
            regular_identity(fixture["terminal"]) != terminal_before
            or regular_identity(pending_staging) != staging_before
            or fixture["pending"].exists()
        ):
            raise RuntimeError(
                "Failed-bootstrap completed pending-staging orphan altered authority."
            )

    alias_phase_anchors = (
        ("runtime-quarantined", 'advance("runtime-quarantined")'),
        ("clean-boundary", 'advance("clean-boundary")'),
        ("authority-retired", 'validate_state(state, {"authority-retired"})'),
    )
    for phase, anchor in alias_phase_anchors:
        with tempfile.TemporaryDirectory(
            prefix=f"mochirii-failed-bootstrap-publication-{phase}-alias-"
        ) as directory:
            fixture = new_fixture(directory)
            armed = run_transaction(interrupt_after(transaction, anchor), fixture)
            if armed.returncode != 86 or armed.stdout or armed.stderr:
                raise RuntimeError(f"Failed-bootstrap {phase} alias fixture did not arm.")
            pending = fixture["pending"]
            document = json.loads(pending.read_text(encoding="utf-8"))
            if document.get("phase") != phase:
                raise RuntimeError(f"Failed-bootstrap {phase} alias phase differs.")
            staging = pending.with_name(f".{pending.name}.publish")
            os.link(pending, staging)
            pending_before = regular_identity(pending)
            staging_before = regular_identity(staging)
            assert_identity_reader_failure(
                "pending",
                fixture,
                b"failed-bootstrap pending publication transition differs\n",
            )
            assert_categorical_failure(
                run_transaction(transaction, fixture),
                b"failed-bootstrap pending publication transition differs\n",
                f"Failed-bootstrap {phase} publication alias provenance",
            )
            if (
                regular_identity(pending) != pending_before
                or regular_identity(staging) != staging_before
                or fixture["terminal"].exists()
            ):
                raise RuntimeError(
                    f"Failed-bootstrap {phase} publication alias was altered."
                )

    with tempfile.TemporaryDirectory(
        prefix="mochirii-failed-bootstrap-publication-prepared-candidate-runtime-"
    ) as directory:
        fixture = new_fixture(directory)
        armed = run_transaction(
            interrupt_after(transaction, "publish(pending, state, True)"), fixture
        )
        if armed.returncode != 86 or armed.stdout or armed.stderr:
            raise RuntimeError("Failed-bootstrap prepared candidate fixture did not arm.")
        pending = fixture["pending"]
        document = json.loads(pending.read_text(encoding="utf-8"))
        candidate = {
            **document,
            "phase": "runtime-quarantined",
            "updatedAt": "2026-08-25T20:02:00Z",
        }
        staging = pending.with_name(f".{pending.name}.publish")
        publish_json(staging, candidate)
        pending_before = regular_identity(pending)
        staging_before = regular_identity(staging)
        assert_categorical_failure(
            run_transaction(transaction, fixture),
            b"failed-bootstrap runtime quarantine state is ambiguous\n",
            "Failed-bootstrap unreachable prepared-to-runtime candidate",
        )
        if (
            regular_identity(pending) != pending_before
            or regular_identity(staging) != staging_before
            or not fixture["mutation"].is_file()
            or fixture["terminal"].exists()
        ):
            raise RuntimeError(
                "Failed-bootstrap unreachable prepared-to-runtime candidate was installed."
            )

    with tempfile.TemporaryDirectory(
        prefix="mochirii-failed-bootstrap-publication-runtime-candidate-clean-"
    ) as directory:
        fixture = new_fixture(directory)
        armed = run_transaction(
            interrupt_after(transaction, 'advance("runtime-quarantined")'), fixture
        )
        if armed.returncode != 86 or armed.stdout or armed.stderr:
            raise RuntimeError("Failed-bootstrap runtime candidate fixture did not arm.")
        pending = fixture["pending"]
        document = json.loads(pending.read_text(encoding="utf-8"))
        candidate = {
            **document,
            "phase": "clean-boundary",
            "updatedAt": "2026-08-25T20:03:00Z",
        }
        staging = pending.with_name(f".{pending.name}.publish")
        publish_json(staging, candidate)
        pending_before = regular_identity(pending)
        staging_before = regular_identity(staging)
        assert_categorical_failure(
            run_transaction(transaction, fixture),
            b"failed-bootstrap quarantine inventory differs\n",
            "Failed-bootstrap unreachable runtime-to-clean candidate",
        )
        if (
            regular_identity(pending) != pending_before
            or regular_identity(staging) != staging_before
            or not fixture["mutation"].is_file()
            or fixture["terminal"].exists()
        ):
            raise RuntimeError(
                "Failed-bootstrap unreachable runtime-to-clean candidate was installed."
            )

    with tempfile.TemporaryDirectory(
        prefix="mochirii-failed-bootstrap-publication-clean-candidate-authority-"
    ) as directory:
        fixture = new_fixture(directory, ssl_present=False)
        armed = run_transaction(
            interrupt_after(transaction, 'advance("clean-boundary")'), fixture
        )
        if armed.returncode != 86 or armed.stdout or armed.stderr:
            raise RuntimeError("Failed-bootstrap clean candidate fixture did not arm.")
        pending = fixture["pending"]
        document = json.loads(pending.read_text(encoding="utf-8"))
        candidate = {
            **document,
            "phase": "authority-retired",
            "updatedAt": "2026-08-25T20:04:00Z",
        }
        staging = pending.with_name(f".{pending.name}.publish")
        publish_json(staging, candidate)
        (fixture["standalone"] / "unexpected").mkdir()
        pending_before = regular_identity(pending)
        staging_before = regular_identity(staging)
        assert_categorical_failure(
            run_transaction(transaction, fixture),
            b"clean standalone inventory differs\n",
            "Failed-bootstrap unreachable clean-to-authority candidate",
        )
        if (
            regular_identity(pending) != pending_before
            or regular_identity(staging) != staging_before
            or not fixture["mutation"].is_file()
            or fixture["mutation_evidence"].exists()
            or fixture["terminal"].exists()
        ):
            raise RuntimeError(
                "Failed-bootstrap unreachable clean-to-authority candidate retired authority."
            )

    with tempfile.TemporaryDirectory(
        prefix="mochirii-failed-bootstrap-publication-semantic-alias-"
    ) as directory:
        fixture = new_fixture(directory)
        armed = interrupt_after(transaction, "publish(pending, state, True)")
        if run_transaction(armed, fixture).returncode != 86:
            raise RuntimeError("Failed-bootstrap semantic-alias fixture did not arm.")
        pending = fixture["pending"]
        document = json.loads(pending.read_text(encoding="utf-8"))
        document["phase"] = "complete"
        publish_json(pending, document)
        staging = pending.with_name(f".{pending.name}.publish")
        os.link(pending, staging)
        pending_identity = regular_identity(pending)
        staging_identity = regular_identity(staging)
        assert_identity_reader_failure(
            "pending", fixture, b"failed-bootstrap pending identity differs\n"
        )
        assert_categorical_failure(
            run_transaction(transaction, fixture),
            b"failed-bootstrap quarantine journal tuple differs\n",
            "Failed-bootstrap semantic-invalid publication alias",
        )
        if regular_identity(pending) != pending_identity or regular_identity(staging) != staging_identity:
            raise RuntimeError("Failed-bootstrap semantic-invalid alias was altered before rejection.")

    with tempfile.TemporaryDirectory(prefix="mochirii-failed-bootstrap-partial-inventory-") as directory:
        fixture = new_fixture(directory)
        interrupted = interrupt_after(transaction, 'standalone.mkdir(mode=state["standaloneMode"])')
        crashed = run_transaction(interrupted, fixture)
        standalone = fixture["standalone"]
        if crashed.returncode != 86 or crashed.stdout or crashed.stderr or not standalone.is_dir():
            raise RuntimeError("Failed-bootstrap partial-inventory fixture did not reach its exact crash window.")
        partial_mode = stat.S_IMODE(standalone.stat().st_mode)
        (standalone / "unexpected").mkdir()
        rejected = run_transaction(transaction, fixture)
        if (
            rejected.returncode == 0
            or not fixture["pending"].is_file()
            or not fixture["mutation"].is_file()
            or not fixture["quarantine"].is_dir()
            or not (standalone / "unexpected").is_dir()
            or stat.S_IMODE(standalone.stat().st_mode) != partial_mode
        ):
            raise RuntimeError("Failed-bootstrap unexpected partial inventory was accepted or changed.")

    with tempfile.TemporaryDirectory(
        prefix="mochirii-failed-bootstrap-initial-inventory-bound-"
    ) as directory:
        fixture = new_fixture(directory)
        for index in range(4097):
            (fixture["standalone"] / f"overflow-{index:04d}").write_bytes(b"")
        assert_categorical_failure(
            run_transaction(transaction, fixture),
            b"standalone inventory exceeds its bounded inventory\n",
            "Failed-bootstrap initial inventory bound",
        )
        if (
            fixture["recovery"].exists()
            or fixture["pending"].exists()
            or fixture["quarantine"].exists()
            or not fixture["standalone"].is_dir()
            or not fixture["mutation"].is_file()
            or fixture["terminal"].exists()
        ):
            raise RuntimeError("Failed-bootstrap initial inventory drift crossed the authority boundary.")

    with tempfile.TemporaryDirectory(
        prefix="mochirii-failed-bootstrap-prepared-runtime-drift-"
    ) as directory:
        fixture = new_fixture(directory)
        armed = run_transaction(
            interrupt_after(transaction, "publish(pending, state, True)"), fixture
        )
        if armed.returncode != 86 or armed.stdout or armed.stderr:
            raise RuntimeError("Failed-bootstrap prepared runtime drift fixture did not arm.")
        pending_before = regular_identity(fixture["pending"])
        fixture["standalone"].chmod(0o700)
        assert_categorical_failure(
            run_transaction(transaction, fixture),
            b"standalone metadata differs\n",
            "Failed-bootstrap prepared runtime drift",
        )
        if (
            regular_identity(fixture["pending"]) != pending_before
            or stat.S_IMODE(fixture["standalone"].stat().st_mode) != 0o700
            or fixture["quarantine"].exists()
            or not fixture["mutation"].is_file()
            or fixture["terminal"].exists()
        ):
            raise RuntimeError("Failed-bootstrap prepared runtime drift was mutated before rejection.")

    with tempfile.TemporaryDirectory(
        prefix="mochirii-failed-bootstrap-runtime-quarantined-drift-"
    ) as directory:
        fixture = new_fixture(directory)
        armed = run_transaction(
            interrupt_after(transaction, 'advance("runtime-quarantined")'), fixture
        )
        if armed.returncode != 86 or armed.stdout or armed.stderr:
            raise RuntimeError("Failed-bootstrap runtime-quarantined drift fixture did not arm.")
        pending_before = regular_identity(fixture["pending"])
        fixture["quarantine"].chmod(0o755)
        assert_categorical_failure(
            run_transaction(transaction, fixture),
            b"failed-bootstrap quarantine permissions differ\n",
            "Failed-bootstrap runtime-quarantined drift",
        )
        if (
            regular_identity(fixture["pending"]) != pending_before
            or stat.S_IMODE(fixture["quarantine"].stat().st_mode) != 0o755
            or fixture["standalone"].exists()
            or not fixture["mutation"].is_file()
            or fixture["terminal"].exists()
        ):
            raise RuntimeError(
                "Failed-bootstrap runtime-quarantined drift was mutated before rejection."
            )

    with tempfile.TemporaryDirectory(
        prefix="mochirii-failed-bootstrap-recovery-root-retry-"
    ) as directory:
        fixture = new_fixture(directory, ssl_present=False)
        first_crash = abrupt_function_after(
            transaction,
            "def persist_directory(path):",
            "\ndef durable_directory_move",
            "fsync_directory(path)",
            1,
            "path == recovery_root",
        )
        first = run_transaction(first_crash, fixture)
        if (
            first.returncode != 86
            or first.stdout
            or first.stderr
            or not fixture["recovery"].is_dir()
            or fixture["pending"].exists()
        ):
            raise RuntimeError("Failed-bootstrap recovery-root first crash window differs.")
        second_crash = abrupt_function_after(
            transaction,
            "def persist_directory(path):",
            "\ndef durable_directory_move",
            "fsync_directory(path.parent)",
            1,
            "path == recovery_root",
        )
        second = run_transaction(second_crash, fixture)
        if (
            second.returncode != 86
            or second.stdout
            or second.stderr
            or fixture["pending"].exists()
            or fixture["quarantine"].exists()
            or not fixture["standalone"].is_dir()
        ):
            raise RuntimeError("Failed-bootstrap existing recovery root skipped persistence retry.")
        completed = run_transaction(transaction, fixture)
        if completed.returncode != 0 or completed.stdout or completed.stderr:
            raise RuntimeError("Failed-bootstrap recovery-root retry did not resume.")
        verify_terminal(fixture)

    with tempfile.TemporaryDirectory(
        prefix="mochirii-failed-bootstrap-ssl-parent-retry-"
    ) as directory:
        fixture = new_fixture(directory)
        first_crash = abrupt_function_after(
            transaction,
            "def durable_directory_move(source, destination):",
            "\ndef exact_directory",
            "os.rename(source, destination)",
            1,
            'source == quarantine / "ssl"',
        )
        first = run_transaction(first_crash, fixture)
        if first.returncode != 86 or first.stdout or first.stderr:
            raise RuntimeError("Failed-bootstrap SSL move crash window did not arm.")
        second = run_transaction(
            interrupt_after(transaction, "fsync_directory(new_ssl.parent)"), fixture
        )
        if second.returncode != 86 or second.stdout or second.stderr:
            raise RuntimeError("Failed-bootstrap SSL destination-parent retry was skipped.")
        third = run_transaction(
            interrupt_after(transaction, "fsync_directory(old_ssl.parent)"), fixture
        )
        if third.returncode != 86 or third.stdout or third.stderr:
            raise RuntimeError("Failed-bootstrap SSL source-parent retry was skipped.")
        completed = run_transaction(transaction, fixture)
        if completed.returncode != 0 or completed.stdout or completed.stderr:
            raise RuntimeError("Failed-bootstrap SSL parent retry did not resume.")
        verify_terminal(fixture)

    with tempfile.TemporaryDirectory(
        prefix="mochirii-failed-bootstrap-terminal-parent-retry-"
    ) as directory:
        fixture = new_fixture(directory)
        first_crash = abrupt_publish_after(
            transaction, "staging.unlink()", 1, "terminal", True
        )
        first = run_transaction(first_crash, fixture)
        terminal_staging = fixture["terminal"].with_name(
            f".{fixture['terminal'].name}.publish"
        )
        if (
            first.returncode != 86
            or first.stdout
            or first.stderr
            or not fixture["terminal"].is_file()
            or terminal_staging.exists()
        ):
            raise RuntimeError("Failed-bootstrap terminal-parent retry fixture did not arm.")
        second_crash = abrupt_between(
            transaction,
            'if path_exists(terminal, "failed-bootstrap terminal evidence"):',
            "if terminal_staging_replay is not None:",
            "fsync_directory(terminal.parent)",
        )
        second = run_transaction(second_crash, fixture)
        if second.returncode != 86 or second.stdout or second.stderr:
            raise RuntimeError("Failed-bootstrap terminal evidence parent retry was skipped.")
        completed = run_transaction(transaction, fixture)
        if completed.returncode != 0 or completed.stdout or completed.stderr:
            raise RuntimeError("Failed-bootstrap terminal evidence parent retry did not resume.")
        verify_terminal(fixture)

    with tempfile.TemporaryDirectory(
        prefix="mochirii-failed-bootstrap-pending-parent-retry-"
    ) as directory:
        fixture = new_fixture(directory)
        terminal_armed = run_transaction(
            interrupt_after(transaction, "publish(terminal, terminal_document, True)"),
            fixture,
        )
        if terminal_armed.returncode != 86 or terminal_armed.stdout or terminal_armed.stderr:
            raise RuntimeError("Failed-bootstrap pending-parent retry fixture did not arm.")
        unlink_crash = abrupt_between(
            transaction,
            'if path_exists(terminal, "failed-bootstrap terminal evidence"):',
            "if terminal_staging_replay is not None:",
            "pending.unlink()",
        )
        unlinked = run_transaction(unlink_crash, fixture)
        if (
            unlinked.returncode != 86
            or unlinked.stdout
            or unlinked.stderr
            or fixture["pending"].exists()
            or not fixture["terminal"].is_file()
        ):
            raise RuntimeError("Failed-bootstrap pending-parent unlink crash window differs.")
        fsync_crash = abrupt_between(
            transaction,
            'if path_exists(terminal, "failed-bootstrap terminal evidence"):',
            "if terminal_staging_replay is not None:",
            "fsync_directory(pending.parent)",
        )
        retried = run_transaction(fsync_crash, fixture)
        if retried.returncode != 86 or retried.stdout or retried.stderr:
            raise RuntimeError("Failed-bootstrap pending parent durability retry was skipped.")
        completed = run_transaction(transaction, fixture)
        if completed.returncode != 0 or completed.stdout or completed.stderr:
            raise RuntimeError("Failed-bootstrap pending parent retry did not resume.")
        verify_terminal(fixture)

    with tempfile.TemporaryDirectory(prefix="mochirii-failed-bootstrap-no-ssl-") as directory:
        fixture = new_fixture(directory, ssl_present=False)
        completed = run_transaction(transaction, fixture)
        if completed.returncode != 0 or completed.stdout or completed.stderr:
            raise RuntimeError("Failed-bootstrap no-SSL transaction did not complete.")
        verify_terminal(fixture)

    with tempfile.TemporaryDirectory(prefix="mochirii-failed-bootstrap-reader-hostile-") as directory:
        fixture = new_fixture(directory)
        completed = run_transaction(transaction, fixture)
        if completed.returncode != 0 or completed.stdout or completed.stderr:
            raise RuntimeError("Failed-bootstrap terminal-reader hostile fixture did not complete.")
        verify_terminal(fixture)
        terminal = fixture["terminal"]
        terminal_raw = terminal.read_bytes()
        terminal_document = json.loads(terminal_raw.decode("utf-8"))
        terminal_hostiles = (
            b"{",
            b"null\n",
            (json.dumps(sorted(terminal_document), separators=(",", ":")) + "\n").encode("utf-8"),
            deep_json,
        )
        for hostile_raw in terminal_hostiles:
            terminal.write_bytes(hostile_raw)
            terminal.chmod(0o600)
            os.chown(terminal, 0, 0)
            assert_identity_reader_failure(
                "terminal", fixture, b"failed-bootstrap recovery evidence is malformed\n"
            )
        for schema_version in (True, 1.0):
            hostile_document = {**terminal_document, "schemaVersion": schema_version}
            publish_json(terminal, hostile_document)
            assert_identity_reader_failure(
                "terminal", fixture, b"failed-bootstrap terminal identity differs\n"
            )
        terminal.write_bytes(terminal_raw)
        terminal.chmod(0o600)
        os.chown(terminal, 0, 0)
        duplicate = fixture["evidence"] / f"{failed}-{'c' * 64}-failed-bootstrap-quarantine.json"
        duplicate.write_bytes(terminal_raw)
        duplicate.chmod(0o600)
        os.chown(duplicate, 0, 0)
        assert_identity_reader_failure(
            "terminal", fixture, b"failed-bootstrap terminal identity is ambiguous\n"
        )

    with tempfile.TemporaryDirectory(prefix="mochirii-failed-bootstrap-ambiguous-") as directory:
        fixture = new_fixture(directory)
        armed = interrupt_after(transaction, "publish(pending, state, True)")
        if run_transaction(armed, fixture).returncode != 86:
            raise RuntimeError("Failed-bootstrap ambiguity fixture could not arm its journal.")
        quarantine = fixture["quarantine"]
        quarantine.parent.mkdir(mode=0o700, exist_ok=True)
        quarantine.mkdir(mode=0o700)
        rejected = run_transaction(transaction, fixture)
        if rejected.returncode == 0 or not fixture["mutation"].is_file() or not fixture["standalone"].is_dir():
            raise RuntimeError("Failed-bootstrap ambiguous runtime state was accepted or changed.")

    with tempfile.TemporaryDirectory(prefix="mochirii-failed-bootstrap-duplicate-") as directory:
        fixture = new_fixture(directory)
        armed = interrupt_after(transaction, "publish(pending, state, True)")
        if run_transaction(armed, fixture).returncode != 86:
            raise RuntimeError("Failed-bootstrap duplicate-key fixture could not arm its journal.")
        pending = fixture["pending"]
        pending_text = pending.read_text(encoding="utf-8")
        duplicate = pending_text.replace(
            '"currentControlCommit":',
            '"currentControlCommit":"hostile","currentControlCommit":',
            1,
        )
        pending.write_text(duplicate, encoding="utf-8", newline="\n")
        pending.chmod(0o600)
        rejected = run_transaction(transaction, fixture)
        if rejected.returncode == 0 or not fixture["mutation"].is_file() or not fixture["standalone"].is_dir():
            raise RuntimeError("Failed-bootstrap duplicate pending identity was accepted or changed.")


def main() -> int:
    test_failed_bootstrap_quarantine_contract()
    test_renderer()
    test_acme_install_byte_stability()
    test_opensearch_filter_contract()
    test_html_denial_types_contract()
    test_login_code_denial_contract()
    test_sensitive_response_header_contract()
    test_https_consumer_fixture_contract()
    test_smtp_transport_contract()
    test_theme_archive()
    test_narrative_avatar_contract()
    test_branding_email_renderer_contract()
    test_certificate_create_cleanup()
    test_certificate_identity_read_allowlist()
    test_http_redirect_boundaries()
    test_certificate_inventory_capacity()
    test_certificate_preparation_recovery_contract()
    test_shared_libexec_traversal_contract()
    test_certificate_control_evidence_adoption_contract()
    test_certificate_commit_forward_retirement()
    test_certificate_commit_forward_ignores_stale_absence()
    test_certificate_rejected_retirement_remains_blocked()
    test_storage_response_boundary()
    test_ssh_dispatch_contract()
    test_current_main_observation()
    test_repository_governance()
    test_reviewed_source_pull_request_wrapper()
    test_extracted_archive_governance()
    test_authentication_state_machine()
    test_deployment_checkout_configuration_boundary()
    test_sensitive_callback_markers()
    test_website_producer_probe_contract()
    test_restore_stop_boundary()
    test_active_swap_capacity_contract()
    test_host_containment_contract()
    test_process_group_timeout()
    test_sidekiq_processing_contract()
    test_restored_mail_suppression_contract()
    test_backup_restore_normal_upload_contract()
    test_public_branding_signed_credential_boundary()
    test_atomic_operator_evidence_publication_contract()
    test_deployment_terminal_transaction_contract()
    test_deployment_runtime_mutation_contract()
    test_historical_disaster_recovery_entrypoint_contract()
    test_host_operation_lock_contract()
    test_host_security_control_plane_contract()
    test_host_control_predecessor_archive_binding()
    test_runtime_rails_execution_contract()
    test_disposable_restore_command_diagnostics()
    test_disposable_nginx_fixture_final_command_contract()
    test_effective_allow_users_parser_contract()
    print("Configuration and theme hostile fixtures passed.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
