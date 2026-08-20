#!/usr/bin/env python3
"""Hostile production-entrypoint fixture for C0/C1 lost-host recovery."""

from __future__ import annotations

import base64
import hashlib
import importlib.util
import json
import os
import shutil
import subprocess
import sys
import tempfile
import textwrap
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
CONTROLLER = ROOT / "scripts/host-historical-disaster-recovery.sh"
HELPER_SCRIPT = ROOT / "scripts/historical-release-disaster-recovery.py"
SCRATCH_SCRIPT = ROOT / "scripts/historical-recovery-scratch-reader.sh"
SCRATCH_FIXTURE = ROOT / "scripts/test-historical-recovery-scratch-reader.py"
HOST_DEPLOY = ROOT / "scripts/host-deploy.sh"
HOST_RESTORE = ROOT / "scripts/host-restore-validate.sh"
BASE_IMAGE = "discourse/base@sha256:3b1846055ca723d13ef7dc3466da61627f32e8b212283561a6c617d759fcec48"
DEPLOYMENT_REVISION = "ed9f680b0df1de28f062de1769d89d22b2644d1b"
C1 = "a" * 40
C0 = "b" * 40
OPERATION = "c" * 32
PREPARE_CONFIRMATION = "PREPARE HISTORICAL MOCHIRII FORUMS DISASTER RELEASE"
RESUME_CONFIRMATION = "RECOVER HISTORICAL MOCHIRII FORUMS DISASTER RELEASE"


def load_module(name: str, path: Path):
    specification = importlib.util.spec_from_file_location(name, path)
    if specification is None or specification.loader is None:
        raise RuntimeError(f"Could not load fixture module: {path}")
    module = importlib.util.module_from_spec(specification)
    sys.modules[name] = module
    specification.loader.exec_module(module)
    return module


HELPER = load_module("historical_release_dr_fixture", HELPER_SCRIPT)
SCRATCH = load_module("historical_scratch_fixture", SCRATCH_FIXTURE)
HOST_CONTROL = load_module("host_control_evidence_fixture", ROOT / "scripts/host-control-evidence.py")


def sha(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def write_protected(path: Path, value: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(value)
    path.chmod(0o600)


def write_executable(path: Path, value: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(value)
    path.chmod(0o755)


def run(command: list[str], *, env: dict[str, str] | None = None, passed: bool = True) -> subprocess.CompletedProcess[str]:
    result = subprocess.run(
        command,
        check=False,
        capture_output=True,
        text=True,
        env={**os.environ, "PYTHONDONTWRITEBYTECODE": "1", **(env or {})},
    )
    if (result.returncode == 0) != passed:
        raise RuntimeError(
            f"Command returned {result.returncode}, expected passed={passed}: {command!r}\n"
            f"stdout={result.stdout!r}\nstderr={result.stderr!r}"
        )
    return result


def receipt(*, tree: str, archive_sha: str, archive_bytes: int, manifest_sha: str, configuration_sha: str) -> dict[str, object]:
    authority = {
        "schemaVersion": 1,
        "repository": "Mochirii-Wushu/Mochirii-Forums",
        "repositoryCommit": C0,
        "repositoryTree": tree,
        "productionConfigurationSha256": configuration_sha,
        "releaseArchiveSha256": archive_sha,
        "releaseArchiveBytes": archive_bytes,
        "releaseArchiveContentManifestSha256": manifest_sha,
        "releaseArchiveObjectKey": f"backups/recovery-releases/archives/{archive_sha}.tar",
        "releaseArchiveSourceFormat": "git-archive-tar-v1",
        "containsSecrets": False,
        "containsSignedUrls": False,
        "ordinaryDeploymentRequiresCurrentMain": True,
        "historicalReleaseAdoptionScope": "clean-target-disaster-recovery-only",
    }
    authority_sha = sha((json.dumps(authority, sort_keys=True, separators=(",", ":")) + "\n").encode())
    evidence_sha = "e" * 64
    pointer_sha = "f" * 64
    return {
        "schemaVersion": 3,
        "repositoryCommit": C0,
        "productionConfigurationSha256": configuration_sha,
        "filename": "fixture-backup.tar.gz",
        "size": 4096,
        "sha256": "a" * 64,
        "lastModified": "2026-08-20T00:00:00Z",
        "privateAdminRetrievalUrlPresent": True,
        "anonymousRetrievalDenied": True,
        "anonymousCdnRetrievalDenied": True,
        "backupPrefix": "backups/",
        "normalUploadInventoryCount": 0,
        "normalUploadInventorySha256": "b" * 64,
        "restoreConfigurationSha256": configuration_sha,
        "themeArchiveSha256": "c" * 64,
        "mailMetadataPluginSha256": "d" * 64,
        "releaseEvidenceFile": f"{C0}-{configuration_sha}-release.json",
        "releaseEvidenceSha256": "1" * 64,
        "discourseDockerRevision": "2" * 40,
        "discourseRevision": "3" * 40,
        "dockerManagerRevision": "4" * 40,
        "baseImageDigest": f"sha256:{'5' * 64}",
        "discourseConnectEnabled": False,
        "memberRolloutMarkerFile": None,
        "memberRolloutMarkerSha256": None,
        "recoveryUploadIncluded": False,
        "recoveryUploadState": None,
        "recoveryUploadStateSha256": None,
        "recoveryUploadDeletedAfterBackup": False,
        "disasterRecoveryImported": True,
        "disasterRecoveryFetchMode": "clean-target-historical",
        "disasterRecoveryBootstrapCommit": C1,
        "disasterRecoveryEvidenceObjectKey": f"backups/recovery-evidence/records/{evidence_sha}.json",
        "disasterRecoveryEvidenceObjectSha256": evidence_sha,
        "disasterRecoveryPointerObjectKey": "backups/recovery-evidence/current.json",
        "disasterRecoveryPointerObjectSha256": pointer_sha,
        "disasterRecoveryRepositoryTree": tree,
        "disasterRecoveryReleaseArchiveObjectKey": f"backups/recovery-releases/archives/{archive_sha}.tar",
        "disasterRecoveryReleaseArchiveSha256": archive_sha,
        "disasterRecoveryReleaseArchiveBytes": archive_bytes,
        "disasterRecoveryReleaseArchiveContentManifestSha256": manifest_sha,
        "disasterRecoveryReleaseArchiveSourceFormat": "git-archive-tar-v1",
        "disasterRecoveryReleaseSourceAuthorityObjectKey": f"backups/recovery-releases/authorities/{authority_sha}.json",
        "disasterRecoveryReleaseSourceAuthoritySha256": authority_sha,
        "disasterRecoveryOrdinaryDeploymentRequiresCurrentMain": True,
        "disasterRecoveryHistoricalReleaseAdoptionScope": "clean-target-disaster-recovery-only",
        "disasterRecoveryPrivateAclPassed": True,
    }


FAKE_DEPLOYER = textwrap.dedent(
    r'''#!/usr/bin/env python3
import hashlib, json, os, pathlib, subprocess, sys
root = pathlib.Path(os.environ["MOCHIRII_HISTORICAL_FIXTURE_ROOT"])
state = root / "var/lib/mochirii/forums"
stage = state / "historical-recovery"
helper = os.environ["MOCHIRII_HISTORICAL_HELPER"]
args = sys.argv[1:]
if len(args) != 7 or args[4] != "historical-bootstrap": raise SystemExit(90)
incoming, commit, expected_sha, expected_bytes, _mode, journal_name, journal_sha = args
journal = pathlib.Path(journal_name); raw = journal.read_bytes(); document = json.loads(raw); phase = document.get("phase")
if commit != document.get("recoveredRepositoryCommit") or hashlib.sha256(raw).hexdigest() != journal_sha: raise SystemExit(91)
archive = pathlib.Path(incoming).read_bytes()
if hashlib.sha256(archive).hexdigest() != expected_sha or len(archive) != int(expected_bytes): raise SystemExit(92)
shared = root / "var/discourse/shared/standalone"; mutation = state / "deployment-mutation.json"; log = root / "fake-entrypoints.jsonl"
def protected(path, value):
    path.parent.mkdir(parents=True, exist_ok=True); candidate = path.with_name("." + path.name + ".partial")
    candidate.write_text(json.dumps(value, sort_keys=True, indent=2) + "\n", encoding="utf-8"); candidate.chmod(0o600); os.replace(candidate, path)
def record(value):
    with log.open("a", encoding="utf-8") as output: output.write(json.dumps(value, sort_keys=True) + "\n")
    log.chmod(0o600)
record({"entrypoint":"deploy","phaseAtEntry":phase,"sharedExisted":shared.exists(),"mutationExisted":mutation.exists()})
if phase == "bootstrap-complete":
    if not mutation.is_file() or not (state / "current-release.json").is_file(): raise SystemExit(93)
    record({"entrypoint":"deploy","reconcileOnly":True,"runtimeMutation":False}); mutation.unlink(); raise SystemExit(0)
if phase != "bootstrap-started": raise SystemExit(94)
if shared.exists() and not mutation.is_file(): raise SystemExit(95)
if not mutation.exists(): protected(mutation,{"schemaVersion":1,"phase":"runtime-mutation-prearmed","repositoryCommit":commit})
record({"entrypoint":"deploy","journalPrearmed":True,"mutationPrearmedBeforeShared":mutation.is_file(),"sharedAbsentBeforeMutation":not shared.exists()})
shared.mkdir(parents=True, exist_ok=True)
pre_crash = root / ".deploy-pre-crashed"
if os.environ.get("MOCHIRII_FIXTURE_DEPLOY_CRASH_ONCE") == "1" and not pre_crash.exists(): pre_crash.write_text("crashed\n"); raise SystemExit(41)
receipt = json.loads((stage / "fetched-recovery-receipt.json").read_text()); configuration = receipt["productionConfigurationSha256"]
evidence = state / "evidence" / f"{commit}-{configuration}-release.json"
release = {
"schemaVersion":2,"recordedAt":"2026-08-20T00:00:00Z","repositoryCommit":commit,"repositoryTree":receipt["disasterRecoveryRepositoryTree"],
"releaseArchiveSha256":receipt["disasterRecoveryReleaseArchiveSha256"],"releaseArchiveBytes":receipt["disasterRecoveryReleaseArchiveBytes"],
"releaseArchiveContentManifestSha256":receipt["disasterRecoveryReleaseArchiveContentManifestSha256"],"discourseDockerRevision":receipt["discourseDockerRevision"],
"discourseRevision":receipt["discourseRevision"],"dockerManagerRevision":receipt["dockerManagerRevision"],"baseImageDigest":receipt["baseImageDigest"],
"productionConfigurationSha256":configuration,"restoreConfigurationSha256":receipt["restoreConfigurationSha256"],"containedActivationConfigurationSha256":"6"*64,
"containedActivationPassed":False,"activationPhase":"consumer-disabled","themeArchiveSha256":receipt["themeArchiveSha256"],
"mailMetadataPluginSha256":receipt["mailMetadataPluginSha256"],"discourseConnectEnabled":False,"memberRolloutMarkerFile":None,"memberRolloutMarkerSha256":None,
"hostVerificationPassed":True,"storageEvidenceFile":"fixture-storage.json","storageEvidenceSha256":"7"*64,"hostedStoragePassed":True,
"storageRestartPersistencePassed":True,"storageRebuildPersistencePassed":True,"storageCleanupPassed":True}
protected(evidence,release); evidence_sha=hashlib.sha256(evidence.read_bytes()).hexdigest()
protected(state/"current-release.json",{"repositoryCommit":commit,"productionConfigurationSha256":configuration,"releaseEvidenceFile":evidence.name,
"releaseEvidenceSha256":evidence_sha,"discourseConnectEnabled":False,"memberRolloutMarkerFile":None,"memberRolloutMarkerSha256":None})
environment={**os.environ,"MOCHIRII_HISTORICAL_BOUNDARY_ROOT":str(root)}
result=subprocess.run(["python3","-B",helper,"complete-bootstrap","--receipt",str(stage/"fetched-recovery-receipt.json"),"--journal",str(journal),
"--current-release",str(state/"current-release.json"),"--release-evidence",str(evidence),"--confirmation","COMPLETE HISTORICAL MOCHIRII FORUMS BOOTSTRAP"],env=environment)
if result.returncode: raise SystemExit(result.returncode)
complete_crash=root/".deploy-complete-crashed"
if os.environ.get("MOCHIRII_FIXTURE_DEPLOY_COMPLETE_CRASH_ONCE")=="1" and not complete_crash.exists(): complete_crash.write_text("crashed\n"); raise SystemExit(42)
mutation.unlink()
''').encode()


FAKE_RESTORER = textwrap.dedent(
    r'''#!/usr/bin/env python3
import hashlib, json, os, pathlib, subprocess, sys
if len(sys.argv)!=3 or sys.argv[2]!="RESTORE CLEAN TARGET MOCHIRII FORUMS": raise SystemExit(80)
root=pathlib.Path(os.environ["MOCHIRII_HISTORICAL_FIXTURE_ROOT"]); state=root/"var/lib/mochirii/forums"; stage=state/"historical-recovery"
helper=os.environ["MOCHIRII_HISTORICAL_HELPER"]; journal=state/"historical-release-adoption.json"; receipt_path=stage/"fetched-recovery-receipt.json"
phase=json.loads(journal.read_text()).get("phase"); log=root/"fake-entrypoints.jsonl"
def protected(path,value):
    path.parent.mkdir(parents=True,exist_ok=True); candidate=path.with_name("."+path.name+".partial")
    candidate.write_bytes(value if isinstance(value,bytes) else (json.dumps(value,sort_keys=True,indent=2)+"\n").encode()); candidate.chmod(0o600); os.replace(candidate,path)
def record(value):
    with log.open("a",encoding="utf-8") as output: output.write(json.dumps(value,sort_keys=True)+"\n")
    log.chmod(0o600)
record({"entrypoint":"restore","phaseAtEntry":phase,"terminalOnly":phase=="restore-complete"})
environment={**os.environ,"MOCHIRII_HISTORICAL_BOUNDARY_ROOT":str(root)}
if phase=="bootstrap-complete":
    result=subprocess.run(["python3","-B",helper,"begin-restore","--receipt",str(receipt_path),"--journal",str(journal),"--confirmation","BEGIN HISTORICAL MOCHIRII FORUMS RESTORE"],env=environment)
    if result.returncode: raise SystemExit(result.returncode)
    phase="restore-started"
elif phase not in {"restore-started","restore-complete"}: raise SystemExit(81)
receipt=json.loads(receipt_path.read_text()); commit=receipt["repositoryCommit"]; configuration=receipt["productionConfigurationSha256"]
current=state/"current-release.json"; current_document=json.loads(current.read_text()); release=state/"evidence"/current_document["releaseEvidenceFile"]
clean=state/"evidence"/f"{commit}-{configuration}-20260820T000000Z-backup.json"; terminal=state/"current-restore.json"; pointer=state/"latest-backup-evidence"
if phase=="restore-started":
    protected(clean,{"repositoryCommit":commit,"productionConfigurationSha256":configuration,"releaseEvidenceFile":release.name,
    "releaseEvidenceSha256":hashlib.sha256(release.read_bytes()).hexdigest(),"finalCleanAfterRestore":True,"recoveryUploadIncluded":False,"disasterRecoveryImported":True})
    protected(terminal,{"schemaVersion":1,"phase":"complete","restoreMode":"clean-target-disaster","repositoryCommit":commit,
    "productionConfigurationSha256":configuration,"cleanBackupEvidenceFile":str(clean),"cleanBackupEvidenceSha256":hashlib.sha256(clean.read_bytes()).hexdigest()})
    protected(pointer,(str(clean)+"\n").encode())
else:
    if not clean.is_file() or not terminal.is_file() or not pointer.is_file(): raise SystemExit(82)
    record({"entrypoint":"restore","terminalReconcileOnly":True,"runtimeMutation":False})
crash_marker=root/".restore-complete-crashed"
if os.environ.get("MOCHIRII_FIXTURE_RESTORE_COMPLETE_CRASH_ONCE")=="1" and not crash_marker.exists(): environment["MOCHIRII_HISTORICAL_FIXTURE_CRASH_AFTER"]="restore-complete-transition"
result=subprocess.run(["python3","-B",helper,"complete","--receipt",str(receipt_path),"--journal",str(journal),"--current-release",str(current),
"--restore-terminal",str(terminal),"--clean-backup",str(clean),"--backup-pointer",str(pointer),"--confirmation","COMPLETE HISTORICAL MOCHIRII FORUMS RECOVERY"],env=environment)
if result.returncode:
    if environment.get("MOCHIRII_HISTORICAL_FIXTURE_CRASH_AFTER"): crash_marker.write_text("crashed\n")
    raise SystemExit(result.returncode)
''').encode()


def patch_adapter(root: Path) -> None:
    path = root / "adapter.py"
    source = path.read_text(encoding="utf-8")
    start = source.index('elif stage == "fetch-evidence":')
    end = source.index('elif stage == "fetch-release":', start)
    replacement = 'elif stage == "fetch-evidence":\n    sys.stdout.buffer.write(pathlib.Path(os.environ["MOCHIRII_FIXTURE_FULL_RECEIPT"]).read_bytes())\n'
    path.write_text(source[:start] + replacement + source[end:], encoding="utf-8")
    path.chmod(0o600)


def render_configuration(root: Path, renderer: bytes) -> bytes:
    script = root / "c0-renderer.py"; output = root / "c0-app.yml"
    write_executable(script, renderer)
    run(["python3","-B",str(script),"--mode","production","--runtime-json",str(root/"etc/mochirii/forums.runtime.json"),"--repository-commit",C0,"--output",str(output)])
    return output.read_bytes()


def install_fake_entrypoints(root: Path) -> None:
    binary=root/"bin"; binary.mkdir(parents=True,exist_ok=True)
    helper=binary/"historical-release-disaster-recovery.py"; scratch=binary/"historical-recovery-scratch-reader.sh"
    shutil.copyfile(HELPER_SCRIPT,helper); shutil.copyfile(SCRATCH_SCRIPT,scratch); helper.chmod(0o755); scratch.chmod(0o755)
    write_executable(binary/"mochirii-forums-deploy",FAKE_DEPLOYER); write_executable(binary/"mochirii-forums-restore",FAKE_RESTORER)
    write_executable(binary/"probe-canonical-main",textwrap.dedent(f'''#!/usr/bin/env python3
import os,sys
if sys.argv[1:] != ["refs/heads/main"]: raise SystemExit(2)
print(os.environ.get("MOCHIRII_FIXTURE_MAIN_COMMIT","{C1}"))
''').encode())
    write_executable(binary/"probe-website-forums-producer.py",b'#!/usr/bin/env python3\nimport os,sys\nraise SystemExit(0 if sys.argv[1:] == ["disabled"] and os.environ.get("MOCHIRII_FIXTURE_PRODUCER_PROBE_FAIL") != "1" else 2)\n')


def setup_fixture(root: Path) -> dict[str, str]:
    global C0, C1, DEPLOYMENT_REVISION
    SCRATCH.C1=""; SCRATCH.C0=""; SCRATCH.OPERATION=OPERATION; SCRATCH.DEPLOYMENT_REVISION=""
    original_forum_files=SCRATCH.forum_files
    def c1_files():
        files=original_forum_files(); files.update({
            "config/host-control-manifest.v1.json":((ROOT/"config/host-control-manifest.v1.json").read_bytes(),False),
            "scripts/historical-recovery-scratch-reader.sh":(SCRATCH_SCRIPT.read_bytes(),True),
            "scripts/host-historical-disaster-recovery.sh":(CONTROLLER.read_bytes(),True),
            "scripts/validate-repository.py":(b"#!/usr/bin/env python3\n",True)})
        return files
    SCRATCH.forum_files=c1_files
    try: scratch_environment=SCRATCH.setup(root)
    finally: SCRATCH.forum_files=original_forum_files
    C1=SCRATCH.C1; DEPLOYMENT_REVISION=SCRATCH.DEPLOYMENT_REVISION
    state=root/"var/lib/mochirii/forums"; (state/"historical-reader.json").unlink(); state.chmod(0o755)
    control_path=state/"current-host-control.json"; control=json.loads(control_path.read_text()); target_set=control["targetSetSha256"]
    for archive_path, commit, tree_key, manifest_key in (
        (Path(control["releaseArchiveFile"]), C1, "repositoryTree", "releaseArchiveContentManifestSha256"),
        (Path(control["deploymentSourceArchiveFile"]), DEPLOYMENT_REVISION, "deploymentSourceTree", "deploymentSourceContentManifestSha256"),
    ):
        reconstructed=HOST_CONTROL.archive_identity(archive_path,commit)
        if reconstructed["tree"]!=control[tree_key] or reconstructed["manifestSha256"]!=control[manifest_key]: raise RuntimeError("Host-control archive identity differs from genuine Git archive.")
    evidence_name=f"{C1}-{target_set}-host-control.json"
    evidence={"schemaVersion":1,"recordedAt":"2026-08-20T00:00:00Z","operation":"initial-install","phase":"hardened","repositoryCommit":C1,
    "repositoryTree":control["repositoryTree"],"manifestSha256":control["manifestSha256"],"targetSetSha256":target_set,"previousControlEvidenceSha256":None,"targets":{},
    **{key:control[key] for key in ("releaseArchiveFile","releaseArchiveSha256","releaseArchiveBytes","releaseArchiveContentManifestSha256","deploymentSourceRevision",
    "deploymentSourceTree","deploymentSourceArchiveFile","deploymentSourceArchiveSha256","deploymentSourceArchiveBytes","deploymentSourceContentManifestSha256")}}
    evidence_path=state/"evidence"/evidence_name; write_protected(evidence_path,(json.dumps(evidence,sort_keys=True,indent=2)+"\n").encode())
    control["controlEvidenceFile"]=evidence_name; control["controlEvidenceSha256"]=sha(evidence_path.read_bytes()); write_protected(control_path,(json.dumps(control,sort_keys=True,indent=2)+"\n").encode())
    c0_files=original_forum_files(); c0_files["scripts/validate-repository.py"]=(b"#!/usr/bin/env python3\n",True)
    c0_archive=root/"fixture-c0-release.tar"; C0,archive_sha,archive_bytes,tree,manifest=SCRATCH.git_archive(c0_archive,c0_files,"C0 historical backup")
    configuration=render_configuration(root,SCRATCH.RENDERER); fetched_receipt=receipt(tree=tree,archive_sha=archive_sha,archive_bytes=archive_bytes,manifest_sha=manifest,configuration_sha=sha(configuration))
    receipt_path=root/"fixture-full-receipt.json"; write_protected(receipt_path,(json.dumps(fetched_receipt,sort_keys=True,indent=2)+"\n").encode())
    patch_adapter(root); install_fake_entrypoints(root)
    return {**scratch_environment,"MOCHIRII_HISTORICAL_FIXTURE_ROOT":str(root),"MOCHIRII_HISTORICAL_FIXTURE_MODE":"source-only-hostile-fixture",
    "MOCHIRII_HISTORICAL_HELPER":str(root/"bin/historical-release-disaster-recovery.py"),"MOCHIRII_HISTORICAL_SCRATCH_READER":str(root/"bin/historical-recovery-scratch-reader.sh"),
    "MOCHIRII_HISTORICAL_DEPLOYER":str(root/"bin/mochirii-forums-deploy"),"MOCHIRII_HISTORICAL_RESTORER":str(root/"bin/mochirii-forums-restore"),
    "MOCHIRII_HISTORICAL_PRODUCER_PROBE":str(root/"bin/probe-website-forums-producer.py"),"MOCHIRII_HISTORICAL_MAIN_PROBE":str(root/"bin/probe-canonical-main"),
    "MOCHIRII_FIXTURE_C0":C0,"MOCHIRII_FIXTURE_C1":C1,"MOCHIRII_FIXTURE_C0_ARCHIVE_BASE64":base64.b64encode(c0_archive.read_bytes()).decode(),
    "MOCHIRII_FIXTURE_FULL_RECEIPT":str(receipt_path),"MOCHIRII_HISTORICAL_FAKE_CONTAINMENT_LOG":str(root/"containment.log")}


def controller(env: dict[str, str], *arguments: str, passed: bool = True) -> subprocess.CompletedProcess[str]:
    return run(["bash",str(CONTROLLER),*arguments],env=env,passed=passed)


def assert_reader_contract(root: Path) -> None:
    state=root/"var/lib/mochirii/forums"; shared=root/"var/discourse/shared/standalone"; absence=json.loads((state/"historical-recovery/scratch-reader-absence.json").read_text())
    if shared.exists() or absence.get("terminalReaderTransactionPhase")!="outputs-published" or len(str(absence.get("terminalReaderTransactionSha256","")))!=64 or absence.get("readerOperationImageIds") != ["sha256:"+"5"*64] or absence.get("readerOperationImageLabel") != f"mochirii.forums.historical-reader={OPERATION}" or any(absence.get(key) is not True for key in ("scratchDirectoryAbsent","readerContainerAbsent","readerOperationImagesAbsent","readerProcessAbsent","readerLauncherStateAbsent","realPersistentTargetAbsent")):
        raise RuntimeError("Controller did not bind the exact terminal scratch-reader absence proof.")
    transaction=state/f"historical-recovery/historical-reader-{OPERATION}.transaction.json"; scratch=state/f"historical-reader/{OPERATION}"
    if transaction.exists() or scratch.exists(): raise RuntimeError("Controller did not retire terminal scratch state.")
    entries=[json.loads(line) for line in (root/"adapter-log.jsonl").read_text().splitlines()]; stages=[entry["stage"] for entry in entries]
    for required in ("launcher-bootstrap","launcher-start","fetch-evidence","fetch-release","cleanup"):
        if required not in stages: raise RuntimeError(f"Actual scratch entrypoint missed {required}.")
    launchers=[entry for entry in entries if entry["stage"].startswith("launcher-")]
    if any(entry.get("configHasProductionShared") or entry.get("configHasRealTarget") or entry.get("configPublishesPort") for entry in launchers): raise RuntimeError("C1 scratch touched production storage/listeners.")
    evidence_argv="\0".join(next(entry["argv"] for entry in entries if entry["stage"]=="fetch-evidence")); release_argv="\0".join(next(entry["argv"] for entry in entries if entry["stage"]=="fetch-release"))
    if "MOCHIRII_DR_FETCH_MODE=clean-target-historical" not in evidence_argv or f"MOCHIRII_DR_BOOTSTRAP_COMMIT={C1}" not in evidence_argv or "MOCHIRII_DR_FETCH_RECEIPT_BASE64=" not in release_argv: raise RuntimeError("C1 fetch environment differs.")


def happy_crash_recovery_fixture() -> None:
    with tempfile.TemporaryDirectory(prefix="mochirii-controller-c0-c1-") as temporary:
        root=Path(temporary).resolve(); env=setup_fixture(root); controller(env,"prepare",C1,OPERATION,PREPARE_CONFIRMATION); assert_reader_contract(root)
        state=root/"var/lib/mochirii/forums"; journal=state/"historical-release-adoption.json"
        if json.loads(journal.read_text()).get("phase")!="configuration-authorized": raise RuntimeError("C0 configuration authorization differs.")
        controller(env,"prepare",C1,OPERATION,PREPARE_CONFIRMATION)
        crashing={**env,"MOCHIRII_FIXTURE_DEPLOY_CRASH_ONCE":"1","MOCHIRII_FIXTURE_DEPLOY_COMPLETE_CRASH_ONCE":"1","MOCHIRII_FIXTURE_RESTORE_COMPLETE_CRASH_ONCE":"1"}
        controller(crashing,"resume",RESUME_CONFIRMATION,passed=False)
        if json.loads(journal.read_text()).get("phase")!="bootstrap-started" or not (state/"deployment-mutation.json").is_file(): raise RuntimeError("Prearmed bootstrap crash state differs.")
        controller(crashing,"resume",RESUME_CONFIRMATION,passed=False)
        if json.loads(journal.read_text()).get("phase")!="bootstrap-complete" or not (state/"deployment-mutation.json").is_file(): raise RuntimeError("Post-completion deploy crash state differs.")
        controller(crashing,"resume",RESUME_CONFIRMATION,passed=False)
        if json.loads(journal.read_text()).get("phase")!="restore-complete" or (state/"deployment-mutation.json").exists(): raise RuntimeError("Restore-complete crash state differs.")
        terminal=state/"current-restore.json"; clean=Path(json.loads(terminal.read_text())["cleanBackupEvidenceFile"])
        before=(sha(terminal.read_bytes()),sha(clean.read_bytes()),sha((state/"current-release.json").read_bytes()))
        controller(crashing,"resume",RESUME_CONFIRMATION); after=(sha(terminal.read_bytes()),sha(clean.read_bytes()),sha((state/"current-release.json").read_bytes()))
        if before!=after or journal.exists(): raise RuntimeError("Terminal retry reran mutation or retained adoption.")
        controller(crashing,"resume",RESUME_CONFIRMATION)
        entries=[json.loads(line) for line in (root/"fake-entrypoints.jsonl").read_text().splitlines()]
        if not any(entry.get("mutationPrearmedBeforeShared") and entry.get("sharedAbsentBeforeMutation") for entry in entries): raise RuntimeError("C0 mutation was not prearmed.")
        if not any(entry.get("reconcileOnly") and entry.get("runtimeMutation") is False for entry in entries): raise RuntimeError("Bootstrap-complete retry was not reconciliation-only.")
        if not any(entry.get("terminalReconcileOnly") and entry.get("runtimeMutation") is False for entry in entries): raise RuntimeError("Restore-complete retry was not terminal-only.")
        if len((root/"containment.log").read_text().splitlines())<3: raise RuntimeError("Crash containment was not invoked.")


def prepare_retirement_crash_fixture() -> None:
    with tempfile.TemporaryDirectory(prefix="mochirii-controller-prepare-retirement-") as temporary:
        root=Path(temporary).resolve(); env=setup_fixture(root); state=root/"var/lib/mochirii/forums"
        crashed={**env,"MOCHIRII_HISTORICAL_FIXTURE_CRASH_AFTER":"configuration-authorized-before-reader-retirement"}
        crash_result=controller(crashed,"prepare",C1,OPERATION,PREPARE_CONFIRMATION,passed=False)
        reader=state/"historical-reader.json"; adoption=state/"historical-release-adoption.json"
        if not reader.is_file() or not adoption.is_file() or json.loads(adoption.read_text()).get("phase")!="configuration-authorized":
            raise RuntimeError(f"Prepare-retirement crash did not retain its exact journals: {crash_result.stderr!r}")
        stopped={**env,"MOCHIRII_FIXTURE_PRODUCER_PROBE_FAIL":"1"}
        controller(stopped,"resume",RESUME_CONFIRMATION,passed=False)
        if reader.exists() or (root/"var/discourse/shared/standalone").exists() or json.loads(adoption.read_text()).get("phase")!="configuration-authorized": raise RuntimeError("Resume did not exactly retire the stale reader before stopping safely.")
        controller(env,"prepare",C1,OPERATION,PREPARE_CONFIRMATION)


def altered_image_absence_fixture() -> None:
    for name, replacement in (("missing", None), ("altered", ["sha256:"+"9"*64])):
        with tempfile.TemporaryDirectory(prefix=f"mochirii-controller-image-{name}-") as temporary:
            root=Path(temporary).resolve(); env=setup_fixture(root); controller(env,"prepare",C1,OPERATION,PREPARE_CONFIRMATION)
            absence_path=root/"var/lib/mochirii/forums/historical-recovery/scratch-reader-absence.json"
            absence=json.loads(absence_path.read_text())
            if replacement is None: absence.pop("readerOperationImageIds")
            else: absence["readerOperationImageIds"]=replacement
            write_protected(absence_path,(json.dumps(absence,sort_keys=True,indent=2)+"\n").encode())
            result=controller(env,"resume",RESUME_CONFIRMATION,passed=False)
            if not any(word in result.stderr.lower() for word in ("image", "absence", "runtime")):
                raise RuntimeError(f"{name} image evidence failed for the wrong reason: {result.stderr!r}")
            if (root/"var/discourse/shared/standalone").exists():
                raise RuntimeError(f"{name} image evidence crossed the real persistent target boundary")


def hostile_case(name: str, mutate, expected: str) -> None:
    with tempfile.TemporaryDirectory(prefix=f"mochirii-controller-{name}-") as temporary:
        root=Path(temporary).resolve(); env=setup_fixture(root); mutate(root,env); result=controller(env,"prepare",C1,OPERATION,PREPARE_CONFIRMATION,passed=False)
        if expected not in result.stderr: raise RuntimeError(f"{name} failed for wrong reason: {result.stderr!r}")
        if (root/"var/discourse/shared/standalone").exists(): raise RuntimeError(f"{name} created real persistent target.")


def static_contract() -> None:
    controller_source=CONTROLLER.read_text(); deploy_source=HOST_DEPLOY.read_text(); restore_source=HOST_RESTORE.read_text(); dispatcher=(ROOT/"scripts/ssh-deploy-dispatch.py").read_text(); deploy_sudo=(ROOT/"config/sudoers-forums").read_text(); operator_sudo=(ROOT/"config/sudoers-forums-operator").read_text()
    assertions={"controller refusal":"SUDO_USER:-root} != mochirii-forums-deploy" in controller_source,"internal refusal":"The deploy principal may not invoke historical bootstrap" in deploy_source,
    "ordinary refusal":"Ordinary deployment refuses an active historical disaster-recovery adoption" in deploy_source,"no SSH verb":"historical" not in dispatcher.lower(),"no deploy sudo":"historical" not in deploy_sudo.lower(),
    "operator boundary":"mochirii-forums-operator" in operator_sudo,"bootstrap mutation ban":"runtime mutation is forbidden" in deploy_source,"terminal collision gate":"Historical terminal reconciliation refuses an active restore transaction" in restore_source}
    failed=[label for label,value in assertions.items() if not value]
    if failed: raise RuntimeError(f"Static refusal evidence differs: {failed}")


def oversized_archive_fixture() -> None:
    with tempfile.TemporaryDirectory(prefix="mochirii-host-control-oversized-") as temporary:
        archive=Path(temporary)/"oversized.tar"
        with archive.open("wb") as output: output.truncate(HELPER.MAX_ARCHIVE_BYTES+1)
        archive.chmod(0o600)
        try: HOST_CONTROL.archive_identity(archive,C1)
        except SystemExit as error:
            if "size is unsafe" not in str(error): raise RuntimeError(f"Oversized archive failed incorrectly: {error}") from error
        else: raise RuntimeError("Oversized archive crossed pre-read bound.")


def run_linux() -> None:
    if os.geteuid()!=0: raise SystemExit("Fixture requires isolated root Linux.")
    prepare_retirement_crash_fixture(); altered_image_absence_fixture(); happy_crash_recovery_fixture()
    hostile_case("deploy-principal",lambda _root,env:env.update({"SUDO_USER":"mochirii-forums-deploy"}),"deploy principal may not invoke")
    hostile_case("scratch-survivor",lambda _root,env:env.update({"MOCHIRII_HISTORICAL_FAKE_CONTAINER_INVENTORY":"survivor"}),"container already exists")
    hostile_case("main-drift",lambda _root,env:env.update({"MOCHIRII_FIXTURE_MAIN_COMMIT":"9"*40}),"Canonical public main no longer equals")
    def lock_symlink(root: Path,_env: dict[str,str]):
        parent=root/"run/lock"; parent.mkdir(parents=True,exist_ok=True); os.symlink(root/"var/lib/mochirii/forums",parent/"mochirii-forums")
    hostile_case("lock-symlink",lock_symlink,"lock directory ownership or mode is unsafe")
    def tamper(root: Path,_env: dict[str,str]):
        archive=root/f"opt/mochirii/forums/host-control-releases/{C1}/mochirii-release.tar"; archive.write_bytes(archive.read_bytes()+b"tamper"); archive.chmod(0o600)
    hostile_case("c1-tamper",tamper,"current host-control retained archive is unsafe")
    static_contract(); oversized_archive_fixture(); print("Historical C0 backup / C1 main / lost-host production-entrypoint fixture passed.")


def run_in_container() -> None:
    command=["docker","run","--rm","--pull=never","--network","none","--read-only","--tmpfs","/tmp:rw,noexec,nosuid,nodev,size=16m","--cap-drop","ALL","--security-opt","no-new-privileges","--pids-limit","64","--memory","256m","--memory-swap","256m","-v",f"{ROOT}:/repo:ro","--entrypoint","python3",BASE_IMAGE,"-B","/repo/scripts/test-historical-release-disaster-recovery.py","--inside-linux"]
    result=subprocess.run(command,check=False,capture_output=True,text=True)
    if result.returncode: raise RuntimeError(f"Pinned historical fixture failed\nstdout={result.stdout!r}\nstderr={result.stderr!r}")
    print(result.stdout.strip())


if __name__=="__main__":
    run_in_container() if os.name=="nt" and "--inside-linux" not in sys.argv else run_linux()
