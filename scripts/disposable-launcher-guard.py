#!/usr/bin/env python3
"""Fail-closed wrapper for Discourse launcher operations on disposable CI hosts.

The official launcher can unlink its bootstrap CID before its final container
removal and can leave an untagged image behind.  This wrapper prearms a durable
operation identity, records the complete pre-operation Docker inventory, and
reconciles by immutable container/image ID as well as by operation label.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import signal
import stat
import subprocess
import sys
import tempfile
import time
from pathlib import Path


OPERATION_ID_PATTERN = re.compile(r"[0-9a-f]{32}")
CONTAINER_ID = re.compile(r"[0-9a-f]{64}")
IMAGE_ID = re.compile(r"sha256:[0-9a-f]{64}")
OPERATIONS = {"bootstrap", "start", "restart", "rebuild"}
LABEL_KEY = "mochirii.forums.disposable-operation"
MAX_JOURNAL_BYTES = 65536
COMMAND_TIMEOUT = 45
LAUNCHER_TIMEOUT = 7200
MAX_EVENT_BYTES = 1024 * 1024
MAX_EVENT_LINE_BYTES = 65536
MAX_EVENT_COUNT = 512
MAX_CONTAINER_IDENTITIES = 64
MAX_CID_BYTES = 65
MAX_EVENT_DRAIN_BYTES = 256 * 1024
EVENT_SETTLE_TIMEOUT = 0.25
EVENT_STOP_TIMEOUT = 5
APP_RUNNING_SETTLE_TIMEOUT = 30
APP_RUNNING_SETTLE_INTERVAL = 0.25
FIXTURE_APP_RUNNING_SETTLE_TIMEOUT = 0.5
FIXTURE_APP_RUNNING_SETTLE_INTERVAL = 0.01
MAX_MEMINFO_BYTES = 65536
RESOURCE_COMMAND_TIMEOUT = 5
MAX_PUPS_TRACE_BYTES = 1024
PUPS_TRACE_MODE = "stage4-fixture-pups-1.4.0-v1"
PUPS_TRACE_PLAN = "pups-1.4.0-stage4-97-v1"
PUPS_TRACE_STAGES = {
    "postgres", "redis", "web-pre-code", "code", "redis-after-code",
    "mochirii-after-code", "web-config", "web", "yarn", "bundle-exec",
    "plugin-compatibility", "pre-db-migrate", "db-migrate",
    "clear-stuck-web-upgrades", "assets-precompile-build", "assets-precompile",
    "web-finalize", "rate-limit", "mochirii-files", "mochirii-final", "plan-drift",
}
PUPS_TRACE_PHASES = {"terminal-failure"}
PUPS_TRACE_EXEC_COUNTS = {
    18: 1, 19: 1, 23: 3, 29: 1, 35: 1, 36: 1, 37: 1, 38: 1,
    39: 1, 40: 3, 41: 1, 49: 17, 51: 1, 52: 1, 53: 16,
    57: 2, 58: 1, 59: 1, 60: 1, 61: 4, 62: 1, 63: 1,
    64: 1, 65: 1, 66: 1, 67: 1, 68: 1,
    88: 1, 90: 1, 97: 10,
}

PUPS_TRACE_OBSERVER = r'''# frozen_string_literal: true

ENV.delete("RUBYOPT")
trace_mode = ENV.delete("MOCHIRII_PUPS_TRACE_MODE")
trace_state = ENV.delete("MOCHIRII_PUPS_TRACE_STATE")
hostile_fixture_mode = ENV.delete("MOCHIRII_DISPOSABLE_LAUNCHER_MODE")
require "json"

production_state = trace_state&.match?(%r{\A/shared/[.]mochirii-ci-pups-trace/[0-9a-f]{32}/state/trace[.]json\z})
hostile_fixture_state = hostile_fixture_mode == "source-only-hostile-fixture" &&
  trace_state&.match?(%r{\A/tmp/mochirii-disposable-[A-Za-z0-9_.-]+/var/discourse/shared/standalone/[.]mochirii-ci-pups-trace/[0-9a-f]{32}/state/trace[.]json\z})

if trace_mode == "stage4-fixture-pups-1.4.0-v1" && (production_state || hostile_fixture_state)
  module MochiriiPupsTrace
    PLAN_VERSION = "pups-1.4.0-stage4-97-v1"
    MAX_BYTES = 1024
    MAX_ITEMS = 256
    ALLOWED_KINDS = %w[exec file merge replace].freeze
    ALLOWED_HOOKS = %w[
      postgres redis code web_config web yarn bundle_exec plugin_compatibility
      db_migrate clear_stuck_web_upgrades assets_precompile_build assets_precompile
    ].freeze
    EXPECTED_KINDS = %w[
      file file file file file
      replace replace replace replace replace replace replace replace replace replace replace replace
      exec exec file file file exec
      file file file replace replace exec replace replace replace replace replace exec exec exec exec
      exec exec exec file file file file file file replace exec replace exec exec exec replace replace replace
      exec exec exec exec exec exec exec exec exec exec exec exec
      replace
      file file file file file file file file file
      file file file file file file file file file
      exec replace exec
      file file file file file file
      exec
    ].freeze
    EXPECTED_HOOKS = {
      23 => "postgres", 35 => "redis", 49 => "code", 58 => "web_config",
      59 => "web", 60 => "yarn", 61 => "bundle_exec", 62 => "plugin_compatibility",
      65 => "db_migrate", 66 => "clear_stuck_web_upgrades",
      67 => "assets_precompile_build", 68 => "assets_precompile",
    }.freeze
    EXPECTED_EXEC_COUNTS = {
      18 => 1, 19 => 1, 23 => 3, 29 => 1, 35 => 1, 36 => 1, 37 => 1, 38 => 1,
      39 => 1, 40 => 3, 41 => 1, 49 => 17, 51 => 1, 52 => 1, 53 => 16,
      57 => 2, 58 => 1, 59 => 1, 60 => 1, 61 => 4, 62 => 1, 63 => 1,
      64 => 1, 65 => 1, 66 => 1, 67 => 1, 68 => 1,
      88 => 1, 90 => 1, 97 => 10,
    }.freeze

    class TraceStateError < StandardError
    end

    class << self
      def configure(path)
        @state_path = path.freeze
        @layout_exact = false
        @item_count = 0
        @current_item = 0
        @completed_items = 0
        @current_subcommand = 0
        @current_subcommand_count = 0
      end

      def structural_plan_exact?(run)
        return false unless defined?(Pups::VERSION) && Pups::VERSION == "1.4.0"
        return false unless run.is_a?(Array) && run.length == EXPECTED_KINDS.length

        kinds = []
        hooks = {}
        exec_counts = {}
        run.each_with_index do |item, index|
          return false unless item.is_a?(Hash) && item.length == 1

          kind, value = item.first
          return false unless kind.is_a?(String) && ALLOWED_KINDS.include?(kind)

          ordinal = index + 1
          kinds << kind
          if value.is_a?(Hash) && value.key?("hook")
            hook = value["hook"]
            return false unless hook.is_a?(String) && ALLOWED_HOOKS.include?(hook)
            hooks[ordinal] = hook
          end
          next unless kind == "exec"

          count =
            if value.is_a?(String)
              1
            elsif value.is_a?(Hash)
              command = value["cmd"]
              if command.is_a?(Array)
                return false unless command.all? { |entry| entry.is_a?(String) }
                command.length
              elsif command.is_a?(String)
                1
              else
                0
              end
            else
              -1
            end
          return false unless count.between?(1, 64)
          exec_counts[ordinal] = count
        end
        kinds == EXPECTED_KINDS && hooks == EXPECTED_HOOKS && exec_counts == EXPECTED_EXEC_COUNTS
      end

      def stage_for(ordinal)
        case ordinal
        when 1..23 then "postgres"
        when 24..38 then "redis"
        when 39..48 then "web-pre-code"
        when 49 then "code"
        when 50 then "redis-after-code"
        when 51..52 then "mochirii-after-code"
        when 53..58 then "web-config"
        when 59 then "web"
        when 60 then "yarn"
        when 61 then "bundle-exec"
        when 62 then "plugin-compatibility"
        when 63..64 then "pre-db-migrate"
        when 65 then "db-migrate"
        when 66 then "clear-stuck-web-upgrades"
        when 67 then "assets-precompile-build"
        when 68 then "assets-precompile"
        when 69..81 then "web-finalize"
        when 82..83 then "rate-limit"
        when 84..96 then "mochirii-files"
        when 97 then "mochirii-final"
        else "plan-drift"
        end
      end

      def bind_plan(run)
        @layout_exact = structural_plan_exact?(run)
        @item_count = run.is_a?(Array) ? [run.length, MAX_ITEMS].min : 0
        @current_item = 0
        @completed_items = 0
        @current_subcommand = 0
        @current_subcommand_count = 0
      end

      def begin_item(kind)
        @current_item += 1
        @layout_exact = false unless EXPECTED_KINDS[@current_item - 1] == kind

        @current_subcommand = 0
        @current_subcommand_count = EXPECTED_EXEC_COUNTS.fetch(@current_item, 0)
      end

      def complete_item
        @completed_items = @current_item
      end

      def begin_subcommand
        @current_subcommand += 1
        @layout_exact = false unless @current_subcommand_count.positive? &&
          @current_subcommand <= @current_subcommand_count
      end

      def terminal_failure(error)
        code =
          if error.respond_to?(:exit_code) && error.exit_code.is_a?(Integer) && error.exit_code.between?(0, 255)
            error.exit_code
          else
            1
          end
        write_record(
          layout_exact: @layout_exact,
          stage: @layout_exact ? stage_for(@current_item) : "plan-drift",
          phase: "terminal-failure",
          item_ordinal: @current_item,
          item_count: @item_count,
          completed_item_count: @completed_items,
          subcommand_ordinal: @current_subcommand,
          subcommand_count: @current_subcommand_count,
          exit_code: code,
        )
      end

      def write_record(
        layout_exact:, stage:, phase:, item_ordinal:, item_count:,
        completed_item_count:, subcommand_ordinal:, subcommand_count:, exit_code:
      )
        record = {
          "schemaVersion" => 1,
          "planVersion" => PLAN_VERSION,
          "layoutExact" => layout_exact,
          "stage" => stage,
          "phase" => phase,
          "itemOrdinal" => item_ordinal,
          "itemCount" => item_count,
          "completedItemCount" => completed_item_count,
          "execSubcommandOrdinal" => subcommand_ordinal,
          "execSubcommandCount" => subcommand_count,
          "exitCode" => exit_code,
        }
        payload = JSON.generate(record) + "\n"
        raise TraceStateError, "trace-state-write-failed" unless payload.bytesize.between?(1, MAX_BYTES)

        directory = File.dirname(@state_path)
        directory_metadata = File.lstat(directory)
        unless directory_metadata.directory? && directory_metadata.uid.zero? && directory_metadata.gid.zero? &&
            (directory_metadata.mode & 0o7777) == 0o700
          raise TraceStateError, "trace-state-write-failed"
        end

        begin
          target_metadata = File.lstat(@state_path)
          unless target_metadata.file? && target_metadata.uid.zero? && target_metadata.gid.zero? &&
              target_metadata.nlink == 1 && (target_metadata.mode & 0o7777) == 0o600 &&
              target_metadata.size.between?(1, MAX_BYTES)
            raise TraceStateError, "trace-state-write-failed"
          end
        rescue Errno::ENOENT
          nil
        end

        temporary = File.join(directory, ".trace.#{Process.pid}.partial")
        begin
          File.unlink(temporary)
        rescue Errno::ENOENT
          nil
        end
        flags = File::WRONLY | File::CREAT | File::EXCL
        flags |= File::NOFOLLOW if defined?(File::NOFOLLOW)
        File.open(temporary, flags, 0o600) do |output|
          output.chmod(0o600)
          output.write(payload)
          output.flush
          output.fsync
        end
        File.rename(temporary, @state_path)
        File.open(directory, File::RDONLY) { |handle| handle.fsync }
      rescue TraceStateError
        raise
      rescue StandardError
        raise TraceStateError, "trace-state-write-failed", []
      ensure
        if defined?(temporary) && temporary
          begin
            File.unlink(temporary)
          rescue Errno::ENOENT
            nil
          end
        end
      end

      def command_wrapper(kind)
        Module.new do
          define_method(:run) do |command, params|
            MochiriiPupsTrace.begin_item(kind)
            result = super(command, params)
            MochiriiPupsTrace.complete_item
            result
          end
        end
      end
    end

    module ConfigWrapper
      def run_commands
        MochiriiPupsTrace.bind_plan(@config["run"])
        begin
          result = super
        rescue Exception => error # rubocop:disable Lint/RescueException
          begin
            MochiriiPupsTrace.terminal_failure(error)
          rescue TraceStateError
            nil
          end
          raise
        end
        result
      end
    end

    module ExecSpawnWrapper
      def spawn(command)
        MochiriiPupsTrace.begin_subcommand
        super(command)
      end
    end
  end

  MochiriiPupsTrace.configure(trace_state)
  tracer = TracePoint.new(:end) do
    if defined?(Pups::VERSION) && defined?(Pups::Config) && defined?(Pups::Command) &&
        defined?(Pups::ExecCommand) && defined?(Pups::FileCommand) &&
        defined?(Pups::MergeCommand) && defined?(Pups::ReplaceCommand)
      Pups::Config.prepend(MochiriiPupsTrace::ConfigWrapper)
      {
        "exec" => Pups::ExecCommand,
        "file" => Pups::FileCommand,
        "merge" => Pups::MergeCommand,
        "replace" => Pups::ReplaceCommand,
      }.each do |kind, command_class|
        command_class.singleton_class.prepend(MochiriiPupsTrace.command_wrapper(kind))
      end
      Pups::ExecCommand.prepend(MochiriiPupsTrace::ExecSpawnWrapper)
      tracer.disable
    end
  end
  tracer.enable
end
'''


class GuardError(RuntimeError):
    pass


class CommandTimeoutError(GuardError):
    pass


def fail(message: str) -> "NoReturn":
    raise GuardError(message)


def fsync_directory(path: Path) -> None:
    descriptor = os.open(path, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def sha256_file(path: Path, maximum: int = MAX_JOURNAL_BYTES) -> str:
    metadata = path.lstat()
    if (
        not stat.S_ISREG(metadata.st_mode)
        or stat.S_ISLNK(metadata.st_mode)
        or metadata.st_size < 1
        or metadata.st_size > maximum
    ):
        fail(f"Protected file is unsafe: {path}")
    digest = hashlib.sha256()
    total = 0
    with path.open("rb") as source:
        while True:
            chunk = source.read(min(65536, maximum + 1 - total))
            if not chunk:
                break
            total += len(chunk)
            if total > maximum:
                fail(f"Protected file exceeds its byte boundary: {path}")
            digest.update(chunk)
    return digest.hexdigest()


def write_protected_file(path: Path, payload: bytes, mode: int) -> None:
    if path.exists() or path.is_symlink():
        fail("Disposable Pups trace asset already exists.")
    descriptor, temporary_name = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
    temporary = Path(temporary_name)
    try:
        os.fchmod(descriptor, mode)
        with os.fdopen(descriptor, "wb", closefd=True) as output:
            output.write(payload)
            output.flush()
            os.fsync(output.fileno())
        os.replace(temporary, path)
        fsync_directory(path.parent)
    finally:
        if temporary.exists() or temporary.is_symlink():
            temporary.unlink()


def pups_trace_stage(ordinal: int) -> str:
    if 1 <= ordinal <= 23:
        return "postgres"
    if 24 <= ordinal <= 38:
        return "redis"
    if 39 <= ordinal <= 48:
        return "web-pre-code"
    if ordinal == 49:
        return "code"
    if ordinal == 50:
        return "redis-after-code"
    if 51 <= ordinal <= 52:
        return "mochirii-after-code"
    if 53 <= ordinal <= 58:
        return "web-config"
    if ordinal == 59:
        return "web"
    if ordinal == 60:
        return "yarn"
    if ordinal == 61:
        return "bundle-exec"
    if ordinal == 62:
        return "plugin-compatibility"
    if 63 <= ordinal <= 64:
        return "pre-db-migrate"
    if ordinal == 65:
        return "db-migrate"
    if ordinal == 66:
        return "clear-stuck-web-upgrades"
    if ordinal == 67:
        return "assets-precompile-build"
    if ordinal == 68:
        return "assets-precompile"
    if 69 <= ordinal <= 81:
        return "web-finalize"
    if 82 <= ordinal <= 83:
        return "rate-limit"
    if 84 <= ordinal <= 96:
        return "mochirii-files"
    if ordinal == 97:
        return "mochirii-final"
    return "plan-drift"


def unavailable_pups_trace() -> dict[str, object]:
    return {
        "valid": False,
        "layoutExact": False,
        "stage": "unavailable",
        "phase": "unavailable",
        "itemOrdinal": -1,
        "itemCount": -1,
        "completedItemCount": -1,
        "execSubcommandOrdinal": -1,
        "execSubcommandCount": -1,
        "exitCode": -1,
    }


def read_pups_trace(path: Path) -> dict[str, object]:
    unavailable = unavailable_pups_trace()
    try:
        metadata = path.lstat()
    except FileNotFoundError:
        return unavailable
    if (
        not stat.S_ISREG(metadata.st_mode)
        or stat.S_ISLNK(metadata.st_mode)
        or metadata.st_uid != 0
        or metadata.st_gid != 0
        or stat.S_IMODE(metadata.st_mode) != 0o600
        or metadata.st_nlink != 1
        or metadata.st_size < 1
        or metadata.st_size > MAX_PUPS_TRACE_BYTES
    ):
        return unavailable
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(path, flags)
    except OSError:
        return unavailable
    try:
        opened = os.fstat(descriptor)
        if (
            opened.st_dev != metadata.st_dev
            or opened.st_ino != metadata.st_ino
            or opened.st_size != metadata.st_size
            or not stat.S_ISREG(opened.st_mode)
            or opened.st_uid != 0
            or opened.st_gid != 0
            or stat.S_IMODE(opened.st_mode) != 0o600
            or opened.st_nlink != 1
            or opened.st_size < 1
            or opened.st_size > MAX_PUPS_TRACE_BYTES
        ):
            return unavailable
        payload = bytearray()
        while len(payload) <= MAX_PUPS_TRACE_BYTES:
            chunk = os.read(descriptor, min(4096, MAX_PUPS_TRACE_BYTES + 1 - len(payload)))
            if not chunk:
                break
            payload.extend(chunk)
        if len(payload) > MAX_PUPS_TRACE_BYTES or os.read(descriptor, 1):
            return unavailable
    finally:
        os.close(descriptor)
    try:
        document = json.loads(bytes(payload))
    except (UnicodeDecodeError, json.JSONDecodeError):
        return unavailable
    expected = {
        "schemaVersion", "planVersion", "layoutExact", "stage", "phase",
        "itemOrdinal", "itemCount", "completedItemCount",
        "execSubcommandOrdinal", "execSubcommandCount", "exitCode",
    }
    if not isinstance(document, dict) or set(document) != expected:
        return unavailable
    numeric_keys = (
        "itemOrdinal", "itemCount", "completedItemCount",
        "execSubcommandOrdinal", "execSubcommandCount", "exitCode",
    )
    if (
        document.get("schemaVersion") != 1
        or document.get("planVersion") != PUPS_TRACE_PLAN
        or not isinstance(document.get("layoutExact"), bool)
        or document.get("stage") not in PUPS_TRACE_STAGES
        or document.get("phase") not in PUPS_TRACE_PHASES
        or any(not isinstance(document.get(key), int) or isinstance(document.get(key), bool) for key in numeric_keys)
    ):
        return unavailable
    item_ordinal = int(document["itemOrdinal"])
    item_count = int(document["itemCount"])
    completed = int(document["completedItemCount"])
    subcommand = int(document["execSubcommandOrdinal"])
    subcommand_count = int(document["execSubcommandCount"])
    exit_code = int(document["exitCode"])
    phase = str(document["phase"])
    stage = str(document["stage"])
    layout_exact = bool(document["layoutExact"])
    expected_subcommands = PUPS_TRACE_EXEC_COUNTS.get(item_ordinal, 0)
    valid_relation = (
        phase == "terminal-failure"
        and 0 <= exit_code <= 255
        and 0 <= item_count <= 256
        and 0 <= item_ordinal <= item_count
        and 0 <= completed <= item_ordinal
        and 0 <= subcommand <= subcommand_count <= 64
    )
    if valid_relation and layout_exact:
        valid_relation = (
            item_count == 97
            and 1 <= item_ordinal <= 97
            and stage == pups_trace_stage(item_ordinal)
            and completed < item_ordinal
            and subcommand_count == expected_subcommands
        )
    elif valid_relation:
        valid_relation = stage == "plan-drift"
    if not valid_relation:
        return unavailable
    return {
        "valid": True,
        "layoutExact": layout_exact,
        "stage": stage,
        "phase": phase,
        "itemOrdinal": item_ordinal,
        "itemCount": item_count,
        "completedItemCount": completed,
        "execSubcommandOrdinal": subcommand,
        "execSubcommandCount": subcommand_count,
        "exitCode": exit_code,
    }


def write_journal(path: Path, document: dict[str, object]) -> None:
    payload = (json.dumps(document, sort_keys=True, separators=(",", ":")) + "\n").encode()
    if len(payload) > MAX_JOURNAL_BYTES:
        fail("Disposable launcher journal exceeds its byte boundary.")
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    metadata = path.parent.lstat()
    if not stat.S_ISDIR(metadata.st_mode) or stat.S_ISLNK(metadata.st_mode):
        fail("Disposable launcher journal directory is unsafe.")
    descriptor, temporary_name = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
    temporary = Path(temporary_name)
    try:
        os.fchmod(descriptor, 0o600)
        with os.fdopen(descriptor, "wb", closefd=True) as output:
            output.write(payload)
            output.flush()
            os.fsync(output.fileno())
        os.replace(temporary, path)
        fsync_directory(path.parent)
    finally:
        if temporary.exists():
            temporary.unlink()


def read_journal(path: Path) -> dict[str, object]:
    metadata = path.lstat()
    if (
        not stat.S_ISREG(metadata.st_mode)
        or stat.S_ISLNK(metadata.st_mode)
        or stat.S_IMODE(metadata.st_mode) != 0o600
        or metadata.st_size < 1
        or metadata.st_size > MAX_JOURNAL_BYTES
    ):
        fail("Disposable launcher journal ownership, mode, or size is unsafe.")
    try:
        document = json.loads(path.read_bytes())
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise GuardError("Disposable launcher journal is malformed.") from error
    expected = {
        "schemaVersion", "operation", "phase", "operationToken", "checkoutGate",
        "checkoutGateSha256", "preexistingContainerIds", "preexistingImageIds",
        "createdContainerIds", "createdImageIds", "launcherPid", "cleanupProved",
    }
    if not isinstance(document, dict) or set(document) != expected:
        fail("Disposable launcher journal schema differs.")
    if (
        document.get("schemaVersion") != 1
        or document.get("operation") not in OPERATIONS
        or document.get("phase") not in {"armed", "launcher-active", "cleanup-armed", "terminal-proved"}
        or not isinstance(document.get("operationToken"), str)
        or OPERATION_ID_PATTERN.fullmatch(str(document["operationToken"])) is None
        or not isinstance(document.get("checkoutGate"), str)
        or not isinstance(document.get("checkoutGateSha256"), str)
        or re.fullmatch(r"[0-9a-f]{64}", str(document["checkoutGateSha256"])) is None
        or not isinstance(document.get("launcherPid"), int)
        or isinstance(document.get("launcherPid"), bool)
        or int(document["launcherPid"]) < 0
        or not isinstance(document.get("cleanupProved"), bool)
    ):
        fail("Disposable launcher journal values differ.")
    for key, pattern in (
        ("preexistingContainerIds", CONTAINER_ID),
        ("createdContainerIds", CONTAINER_ID),
        ("preexistingImageIds", IMAGE_ID),
        ("createdImageIds", IMAGE_ID),
    ):
        values = document.get(key)
        if (
            not isinstance(values, list)
            or values != sorted(set(values))
            or any(not isinstance(value, str) or pattern.fullmatch(value) is None for value in values)
        ):
            fail(f"Disposable launcher journal {key} differs.")
    return document


class Runtime:
    def __init__(self, root: Path, adapter: Path | None) -> None:
        self.root = root
        self.adapter = adapter
        self.discourse = root / "var/discourse"
        self.shared = self.discourse / "shared/standalone"
        self.trace_namespace = self.shared / ".mochirii-ci-pups-trace"
        self.cid = self.discourse / "cids/app_bootstrap.cid"
        self.journal = self.discourse / ".mochirii-disposable-launcher.transaction.json"
        self.launcher = self.discourse / "launcher"
        self.app_running_settle_timeout = (
            FIXTURE_APP_RUNNING_SETTLE_TIMEOUT if adapter else APP_RUNNING_SETTLE_TIMEOUT
        )
        self.app_running_settle_interval = (
            FIXTURE_APP_RUNNING_SETTLE_INTERVAL if adapter else APP_RUNNING_SETTLE_INTERVAL
        )

    def trace_paths(self, token: str) -> dict[str, Path]:
        if OPERATION_ID_PATTERN.fullmatch(token) is None:
            fail("Disposable Pups trace operation identity differs.")
        operation = self.trace_namespace / token
        return {
            "operation": operation,
            "wrapper": operation / "pups-wrapper",
            "observer": operation / "observer.rb",
            "state": operation / "state",
            "record": operation / "state/trace.json",
        }

    @staticmethod
    def _require_root_directory(path: Path) -> None:
        metadata = path.lstat()
        if (
            not stat.S_ISDIR(metadata.st_mode)
            or stat.S_ISLNK(metadata.st_mode)
            or metadata.st_uid != 0
            or metadata.st_gid != 0
            or stat.S_IMODE(metadata.st_mode) != 0o700
        ):
            fail("Disposable Pups trace directory is unsafe.")

    def prove_trace_namespace_absent(self) -> None:
        if self.trace_namespace.exists() or self.trace_namespace.is_symlink():
            fail("Unowned disposable Pups trace namespace exists before prearm.")

    def prepare_pups_trace(self, token: str) -> tuple[str, Path]:
        paths = self.trace_paths(token)
        self.shared.mkdir(mode=0o755, parents=True, exist_ok=True)
        for parent in (self.discourse, self.discourse / "shared", self.shared):
            metadata = parent.lstat()
            if not stat.S_ISDIR(metadata.st_mode) or stat.S_ISLNK(metadata.st_mode):
                fail("Disposable shared path is unsafe for Pups trace state.")
        self.trace_namespace.mkdir(mode=0o700)
        self._require_root_directory(self.trace_namespace)
        paths["operation"].mkdir(mode=0o700)
        self._require_root_directory(paths["operation"])
        paths["state"].mkdir(mode=0o700)
        self._require_root_directory(paths["state"])

        guest_root = f"/shared/.mochirii-ci-pups-trace/{token}"
        wrapper = (
            "#!/bin/sh\n"
            "unset RUBYOPT MOCHIRII_PUPS_TRACE_MODE MOCHIRII_PUPS_TRACE_STATE\n"
            f"export MOCHIRII_PUPS_TRACE_MODE='{PUPS_TRACE_MODE}'\n"
            f"export MOCHIRII_PUPS_TRACE_STATE='{guest_root}/state/trace.json'\n"
            f"export RUBYOPT='-r{guest_root}/observer.rb'\n"
            "exec /usr/local/bin/ruby "
            "/usr/local/lib/ruby/gems/3.4.0/gems/pups-1.4.0/bin/pups \"$@\"\n"
        ).encode("utf-8")
        write_protected_file(paths["observer"], PUPS_TRACE_OBSERVER.encode("utf-8"), 0o600)
        write_protected_file(paths["wrapper"], wrapper, 0o700)
        for path in paths.values():
            if any(character.isspace() for character in str(path)):
                fail("Disposable Pups trace path is not shell-safe.")
        docker_arguments = " ".join(
            (
                f"--volume={paths['wrapper']}:/usr/local/bin/pups:ro",
                f"--volume={paths['observer']}:{guest_root}/observer.rb:ro",
                f"--volume={paths['state']}:{guest_root}/state:rw",
            )
        )
        return docker_arguments, paths["record"]

    def cleanup_pups_trace(self, token: str) -> None:
        paths = self.trace_paths(token)
        namespace = self.trace_namespace
        if not namespace.exists() and not namespace.is_symlink():
            return
        self._require_root_directory(namespace)
        operation = paths["operation"]
        if not operation.exists() and not operation.is_symlink():
            if any(namespace.iterdir()):
                fail("Disposable Pups trace namespace retained another operation.")
            namespace.rmdir()
            fsync_directory(self.shared)
            return
        self._require_root_directory(operation)
        allowed_operation = {"pups-wrapper", "observer.rb", "state"}
        operation_entries = list(operation.iterdir())
        if any(
            entry.name not in allowed_operation
            and not entry.name.startswith(".pups-wrapper.")
            and not entry.name.startswith(".observer.rb.")
            for entry in operation_entries
        ):
            fail("Disposable Pups trace operation retained an unexpected entry.")
        state_path = paths["state"]
        if state_path.exists() or state_path.is_symlink():
            self._require_root_directory(state_path)
            state_entries = list(state_path.iterdir())
            if any(
                entry.name != "trace.json"
                and re.fullmatch(r"[.]trace[.][0-9]+[.]partial", entry.name) is None
                for entry in state_entries
            ):
                fail("Disposable Pups trace state retained an unexpected entry.")
            for entry in state_entries:
                metadata = entry.lstat()
                if stat.S_ISDIR(metadata.st_mode) and not stat.S_ISLNK(metadata.st_mode):
                    fail("Disposable Pups trace state retained a directory.")
                entry.unlink()
            fsync_directory(state_path)
            state_path.rmdir()
        for entry in list(operation.iterdir()):
            metadata = entry.lstat()
            if stat.S_ISDIR(metadata.st_mode) and not stat.S_ISLNK(metadata.st_mode):
                fail("Disposable Pups trace operation retained a directory.")
            entry.unlink()
        fsync_directory(operation)
        operation.rmdir()
        fsync_directory(namespace)
        if any(namespace.iterdir()):
            fail("Disposable Pups trace namespace retained another operation.")
        namespace.rmdir()
        fsync_directory(self.shared)
        if operation.exists() or operation.is_symlink() or namespace.exists() or namespace.is_symlink():
            fail("Disposable Pups trace residue survived reconciliation.")

    def run(
        self, arguments: list[str], *, timeout: float = COMMAND_TIMEOUT, check: bool = True,
    ) -> subprocess.CompletedProcess[str]:
        command = ([sys.executable, "-B", str(self.adapter)] if self.adapter else []) + arguments
        try:
            result = subprocess.run(command, text=True, capture_output=True, timeout=timeout, check=False)
        except subprocess.TimeoutExpired as error:
            raise CommandTimeoutError("Bounded disposable Docker command timed out.") from error
        if check and result.returncode:
            fail("Bounded disposable Docker command failed.")
        return result

    def docker(
        self, *arguments: str, timeout: float = COMMAND_TIMEOUT, check: bool = True,
    ) -> subprocess.CompletedProcess[str]:
        return self.run(
            (["docker"] if self.adapter else ["docker"]) + list(arguments),
            timeout=timeout,
            check=check,
        )

    def container_ids(self) -> set[str]:
        output = self.docker("container", "ls", "--all", "--no-trunc", "--format", "{{.ID}}").stdout.splitlines()
        values = {value.strip() for value in output if value.strip()}
        if any(CONTAINER_ID.fullmatch(value) is None for value in values):
            fail("Disposable container inventory is malformed.")
        return values

    def image_ids(self) -> set[str]:
        output = self.docker("image", "ls", "--all", "--no-trunc", "--quiet").stdout.splitlines()
        values = {value.strip() for value in output if value.strip()}
        if any(IMAGE_ID.fullmatch(value) is None for value in values):
            fail("Disposable image inventory is malformed.")
        return values

    def labeled_containers(self, token: str) -> set[str]:
        output = self.docker(
            "container", "ls", "--all", "--no-trunc",
            "--filter", f"label={LABEL_KEY}={token}", "--format", "{{.ID}}",
        ).stdout.splitlines()
        values = {value.strip() for value in output if value.strip()}
        if any(CONTAINER_ID.fullmatch(value) is None for value in values):
            fail("Disposable operation-label inventory is malformed.")
        return values

    def named_app(self, *, timeout: float = COMMAND_TIMEOUT) -> tuple[str, bool, str] | None:
        try:
            result = self.docker(
                "container", "inspect", "--format", "{{.Id}} {{.State.Running}} {{.Image}}", "app", check=False,
                timeout=timeout,
            )
        except CommandTimeoutError as error:
            raise GuardError("Disposable launcher did not leave the exact named application running.") from error
        if result.returncode:
            return None
        parts = result.stdout.strip().split()
        if (
            len(parts) != 3
            or CONTAINER_ID.fullmatch(parts[0]) is None
            or parts[1] not in {"true", "false"}
            or IMAGE_ID.fullmatch(parts[2]) is None
        ):
            fail("Disposable named application identity is malformed.")
        return parts[0], parts[1] == "true", parts[2]

    def tagged_app_image(self) -> str | None:
        result = self.docker("image", "inspect", "--format", "{{.Id}}", "local_discourse/app", check=False)
        if result.returncode:
            return None
        value = result.stdout.strip()
        if IMAGE_ID.fullmatch(value) is None:
            fail("Disposable tagged application image identity is malformed.")
        return value

    def remove_container(self, identity: str) -> None:
        self.docker("container", "rm", "--force", identity, check=False)

    def remove_image(self, identity: str) -> None:
        self.docker("image", "rm", "--force", identity, check=False)

    def event_command(self, token: str) -> list[str]:
        if self.adapter:
            return [sys.executable, "-B", str(self.adapter), "events"]
        return [
            "docker", "events", "--since", str(max(0, int(time.time()) - 1)),
            "--filter", f"label={LABEL_KEY}={token}", "--format", "{{json .}}",
        ]


class ContainerLifecycle:
    def __init__(self) -> None:
        self.event_count = 0
        self.create_count = 0
        self.start_count = 0
        self.die_count = 0
        self.destroy_count = 0
        self.oom_count = 0
        self.die_exit_codes: list[int] = []


class LifecycleRecorder:
    """Retain only bounded, non-secret facts from exact-label Docker events."""

    def __init__(self, runtime: Runtime, token: str, environment: dict[str, str]) -> None:
        self.runtime = runtime
        self.token = token
        self.environment = environment
        self.process: subprocess.Popen[bytes] | None = None
        self.stream: object | None = None
        self.buffer = bytearray()
        self.bytes_read = 0
        self.event_count = 0
        self.create_count = 0
        self.start_count = 0
        self.die_count = 0
        self.destroy_count = 0
        self.oom_count = 0
        self.containers: dict[str, ContainerLifecycle] = {}
        self.bootstrap_identity: str | None = None
        self.cid_incomplete_seen = False
        self.cid_malformed = False
        self.malformed = False
        self.overflow = False
        self.recorder_failed = False

    def start(self) -> None:
        try:
            self.process = subprocess.Popen(
                self.runtime.event_command(self.token),
                cwd=self.runtime.discourse,
                env=self.environment,
                stdout=subprocess.PIPE,
                stderr=subprocess.DEVNULL,
                start_new_session=True,
                bufsize=0,
            )
        except OSError:
            self.recorder_failed = True
            return
        if self.process.stdout is None:
            self.recorder_failed = True
            return
        self.stream = self.process.stdout
        try:
            os.set_blocking(self.process.stdout.fileno(), False)
        except OSError:
            self.recorder_failed = True
            self._close_stream()

    def _close_stream(self) -> None:
        if self.stream is not None:
            try:
                self.stream.close()  # type: ignore[union-attr]
            except OSError:
                pass
            self.stream = None

    def _invalidate_stream(self, *, overflow: bool = False) -> None:
        self.overflow = self.overflow or overflow
        self.malformed = self.malformed or not overflow
        self.buffer.clear()
        self._close_stream()

    def _parse_event(self, payload: bytes) -> None:
        if not payload or len(payload) > MAX_EVENT_LINE_BYTES or self.event_count >= MAX_EVENT_COUNT:
            self._invalidate_stream(overflow=self.event_count >= MAX_EVENT_COUNT)
            return
        try:
            document = json.loads(payload)
        except (UnicodeDecodeError, json.JSONDecodeError):
            self._invalidate_stream()
            return
        if not isinstance(document, dict):
            self._invalidate_stream()
            return
        actor = document.get("Actor")
        attributes = actor.get("Attributes") if isinstance(actor, dict) else None
        identity = actor.get("ID") if isinstance(actor, dict) else None
        event_type = document.get("Type")
        action = document.get("Action", document.get("status"))
        if (
            not isinstance(attributes, dict)
            or attributes.get(LABEL_KEY) != self.token
            or not isinstance(identity, str)
            or CONTAINER_ID.fullmatch(identity) is None
            or event_type != "container"
            or not isinstance(action, str)
        ):
            self._invalidate_stream()
            return
        lifecycle = self.containers.get(identity)
        if lifecycle is None:
            if len(self.containers) >= MAX_CONTAINER_IDENTITIES:
                self._invalidate_stream(overflow=True)
                return
            lifecycle = ContainerLifecycle()
            self.containers[identity] = lifecycle
        self.event_count += 1
        lifecycle.event_count += 1
        if action == "create":
            self.create_count += 1
            lifecycle.create_count += 1
        elif action == "start":
            self.start_count += 1
            lifecycle.start_count += 1
        elif action == "die":
            value = attributes.get("exitCode")
            if not isinstance(value, str) or re.fullmatch(r"[0-9]{1,3}", value) is None or int(value) > 255:
                self._invalidate_stream()
                return
            self.die_count += 1
            lifecycle.die_count += 1
            lifecycle.die_exit_codes.append(int(value))
        elif action == "destroy":
            self.destroy_count += 1
            lifecycle.destroy_count += 1
        elif action == "oom":
            self.oom_count += 1
            lifecycle.oom_count += 1

    def observe_bootstrap_cid(self, path: Path, *, final: bool = False) -> None:
        try:
            descriptor = os.open(
                path,
                os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0),
            )
        except FileNotFoundError:
            if final and self.cid_incomplete_seen:
                self.cid_malformed = True
            return
        except OSError:
            self.cid_malformed = True
            return
        try:
            metadata = os.fstat(descriptor)
            if not stat.S_ISREG(metadata.st_mode):
                self.cid_malformed = True
                return
            # Docker creates/truncates --cidfile before ContainerCreate and
            # writes the identity only after creation succeeds.  A poll may
            # therefore see a legitimate short in-progress file.  Only the
            # final observation treats a still-short file as malformed.
            if metadata.st_size < 64:
                self.cid_incomplete_seen = True
                self.cid_malformed = self.cid_malformed or final
                return
            if metadata.st_size not in {64, MAX_CID_BYTES}:
                self.cid_malformed = True
                return
            chunks: list[bytes] = []
            remaining = metadata.st_size
            while remaining:
                chunk = os.read(descriptor, remaining)
                if not chunk:
                    self.cid_malformed = True
                    return
                chunks.append(chunk)
                remaining -= len(chunk)
            payload = b"".join(chunks)
            if os.read(descriptor, 1):
                self.cid_malformed = True
                return
            value = payload.strip()
            if re.fullmatch(rb"[0-9a-f]{64}", value) is None:
                self.cid_malformed = True
                return
            identity = value.decode("ascii")
            if self.bootstrap_identity is not None and self.bootstrap_identity != identity:
                self.cid_malformed = True
                return
            self.bootstrap_identity = identity
            self.cid_incomplete_seen = False
        finally:
            os.close(descriptor)

    def drain(self) -> None:
        if self.stream is None:
            return
        drained = 0
        descriptor = self.stream.fileno()  # type: ignore[union-attr]
        while drained < MAX_EVENT_DRAIN_BYTES and self.stream is not None:
            try:
                chunk = os.read(descriptor, min(65536, MAX_EVENT_DRAIN_BYTES - drained))
            except BlockingIOError:
                break
            except OSError:
                self.recorder_failed = True
                self._close_stream()
                break
            if not chunk:
                self._close_stream()
                break
            drained += len(chunk)
            self.bytes_read += len(chunk)
            if self.bytes_read > MAX_EVENT_BYTES:
                self._invalidate_stream(overflow=True)
                break
            self.buffer.extend(chunk)
            while self.stream is not None and b"\n" in self.buffer:
                payload, _, remainder = self.buffer.partition(b"\n")
                self.buffer = bytearray(remainder)
                self._parse_event(payload)
            if len(self.buffer) > MAX_EVENT_LINE_BYTES:
                self._invalidate_stream(overflow=True)

    def stop(self) -> None:
        process = self.process
        if process is None:
            self._close_stream()
            return
        self.drain()
        if process.poll() is not None:
            self.recorder_failed = True
        else:
            settle_deadline = time.monotonic() + EVENT_SETTLE_TIMEOUT
            while self.stream is not None and time.monotonic() < settle_deadline:
                self.drain()
                time.sleep(0.01)
            try:
                os.killpg(process.pid, signal.SIGTERM)
            except ProcessLookupError:
                pass
            deadline = time.monotonic() + EVENT_STOP_TIMEOUT
            while process.poll() is None and time.monotonic() < deadline:
                self.drain()
                time.sleep(0.02)
            if process.poll() is None:
                try:
                    os.killpg(process.pid, signal.SIGKILL)
                except ProcessLookupError:
                    pass
                try:
                    process.wait(timeout=EVENT_STOP_TIMEOUT)
                except subprocess.TimeoutExpired:
                    self.recorder_failed = True
            else:
                process.wait()
        self.drain()
        if self.buffer:
            self.malformed = True
            self.buffer.clear()
        self._close_stream()
        self.process = None

    def failure_message(
        self,
        operation: str,
        launcher_status: int,
        elapsed_seconds: int,
        resources_before: dict[str, int],
        resources_after: dict[str, int],
        pups_trace: dict[str, object] | None = None,
    ) -> str:
        valid = not (self.malformed or self.overflow or self.recorder_failed or self.cid_malformed)
        bootstrap = self.containers.get(self.bootstrap_identity) if self.bootstrap_identity is not None else None
        exact_die_code = bootstrap.die_exit_codes[0] if bootstrap is not None and len(bootstrap.die_exit_codes) == 1 else -1
        if not valid:
            failure_class = "incomplete-unknown"
        elif self.bootstrap_identity is None:
            failure_class = "pre-container" if self.event_count == 0 else "bootstrap-unobserved"
        elif bootstrap is None or bootstrap.die_count != 1:
            failure_class = "incomplete-unknown"
        elif exact_die_code == 0 and bootstrap.oom_count == 0:
            failure_class = "post-bootstrap-launcher-failure"
        elif exact_die_code == 0:
            failure_class = "incomplete-unknown"
        elif bootstrap.oom_count:
            failure_class = "oom-container-exit"
        else:
            failure_class = "non-oom-container-exit"
        bootstrap_code = exact_die_code if operation == "bootstrap" else -1
        bootstrap_event_count = bootstrap.event_count if bootstrap is not None else 0
        fields: tuple[str, ...] = (
            f"failure_class={failure_class}",
            f"launcher_rc={launcher_status}",
            f"elapsed_seconds={elapsed_seconds}",
            f"lifecycle_valid={'true' if valid else 'false'}",
            f"bootstrap_identity_observed={'true' if self.bootstrap_identity is not None else 'false'}",
            f"event_count={self.event_count}",
            f"bootstrap_event_count={bootstrap_event_count}",
            f"helper_event_count={self.event_count - bootstrap_event_count}",
            f"container_create_count={self.create_count}",
            f"container_start_count={self.start_count}",
            f"container_die_count={self.die_count}",
            f"container_destroy_count={self.destroy_count}",
            f"oom_observed={'true' if bootstrap is not None and bootstrap.oom_count > 0 else 'false'}",
            f"die_exit_code_observed={'true' if exact_die_code >= 0 else 'false'}",
            f"die_exit_code={exact_die_code}",
            f"bootstrap_exit_code_observed={'true' if bootstrap_code >= 0 else 'false'}",
            f"bootstrap_exit_code={bootstrap_code}",
            f"docker_free_pre_bytes={resources_before['dockerFreeBytes']}",
            f"docker_free_post_bytes={resources_after['dockerFreeBytes']}",
            f"mem_available_pre_bytes={resources_before['memAvailableBytes']}",
            f"mem_available_post_bytes={resources_after['memAvailableBytes']}",
            f"swap_free_pre_bytes={resources_before['swapFreeBytes']}",
            f"swap_free_post_bytes={resources_after['swapFreeBytes']}",
            f"swap_total_pre_bytes={resources_before['swapTotalBytes']}",
            f"swap_total_post_bytes={resources_after['swapTotalBytes']}",
        )
        if operation == "bootstrap":
            trace = pups_trace if pups_trace is not None else unavailable_pups_trace()
            if (
                not valid
                or exact_die_code < 0
                or not trace["valid"]
                or trace["exitCode"] != exact_die_code
            ):
                trace = unavailable_pups_trace()
            fields += (
                f"pups_trace_valid={'true' if trace['valid'] else 'false'}",
                f"pups_layout_exact={'true' if trace['layoutExact'] else 'false'}",
                f"pups_stage={trace['stage']}",
                f"pups_phase={trace['phase']}",
                f"pups_item_ordinal={trace['itemOrdinal']}",
                f"pups_item_count={trace['itemCount']}",
                f"pups_completed_item_count={trace['completedItemCount']}",
                f"pups_exec_subcommand_ordinal={trace['execSubcommandOrdinal']}",
                f"pups_exec_subcommand_count={trace['execSubcommandCount']}",
                f"pups_exit_code={trace['exitCode']}",
            )
        return (
            "Disposable launcher operation failed; operation-created residue was contained. "
            + " ".join(fields)
        )


def resource_snapshot(runtime: Runtime) -> dict[str, int]:
    values = {
        "dockerFreeBytes": -1,
        "memAvailableBytes": -1,
        "swapFreeBytes": -1,
        "swapTotalBytes": -1,
    }
    try:
        result = runtime.run(
            ["docker", "info", "--format", "{{.DockerRootDir}}"],
            timeout=RESOURCE_COMMAND_TIMEOUT,
            check=False,
        )
        lines = result.stdout.splitlines()
        if result.returncode == 0 and len(lines) == 1 and 0 < len(lines[0]) <= 4096:
            docker_root = Path(lines[0])
            if docker_root.is_absolute():
                filesystem = os.statvfs(docker_root)
                free_bytes = filesystem.f_bavail * filesystem.f_frsize
                if 0 <= free_bytes <= (2**63 - 1):
                    values["dockerFreeBytes"] = free_bytes
    except (GuardError, OSError, UnicodeError, ValueError):
        pass
    try:
        with Path("/proc/meminfo").open("rb") as source:
            payload = source.read(MAX_MEMINFO_BYTES + 1)
        if len(payload) <= MAX_MEMINFO_BYTES:
            fields: dict[bytes, int] = {}
            for line in payload.splitlines():
                parts = line.split()
                if len(parts) == 3 and parts[0] in {b"MemAvailable:", b"SwapFree:", b"SwapTotal:"} and parts[2] == b"kB":
                    if re.fullmatch(rb"[0-9]{1,20}", parts[1]) is not None:
                        amount = int(parts[1]) * 1024
                        if 0 <= amount <= (2**63 - 1):
                            fields[parts[0]] = amount
            if set(fields) == {b"MemAvailable:", b"SwapFree:", b"SwapTotal:"}:
                values["memAvailableBytes"] = fields[b"MemAvailable:"]
                values["swapFreeBytes"] = fields[b"SwapFree:"]
                values["swapTotalBytes"] = fields[b"SwapTotal:"]
    except (OSError, ValueError):
        pass
    return values


def marked_processes(token: str) -> list[int]:
    marker = f"MOCHIRII_DISPOSABLE_OPERATION_TOKEN={token}".encode()
    found: list[int] = []
    for entry in Path("/proc").iterdir():
        if not entry.name.isdigit() or int(entry.name) == os.getpid():
            continue
        try:
            fields = (entry / "environ").read_bytes().split(b"\0")
        except (FileNotFoundError, PermissionError, ProcessLookupError):
            continue
        if marker in fields:
            found.append(int(entry.name))
    return found


def stop_marked_processes(token: str) -> None:
    for process_id in marked_processes(token):
        try:
            os.kill(process_id, signal.SIGTERM)
        except ProcessLookupError:
            pass
    deadline = time.monotonic() + 5
    while marked_processes(token) and time.monotonic() < deadline:
        time.sleep(0.05)
    for process_id in marked_processes(token):
        try:
            os.kill(process_id, signal.SIGKILL)
        except ProcessLookupError:
            pass
    deadline = time.monotonic() + 5
    while marked_processes(token) and time.monotonic() < deadline:
        time.sleep(0.05)
    if marked_processes(token):
        fail("Disposable launcher operation process survived reconciliation.")


def refresh_created(runtime: Runtime, document: dict[str, object]) -> tuple[set[str], set[str]]:
    containers = runtime.container_ids()
    images = runtime.image_ids()
    created_containers = (
        set(document["createdContainerIds"])
        | (containers - set(document["preexistingContainerIds"]))
        | runtime.labeled_containers(str(document["operationToken"]))
    )
    created_images = set(document["createdImageIds"]) | (images - set(document["preexistingImageIds"]))
    document["createdContainerIds"] = sorted(created_containers)
    document["createdImageIds"] = sorted(created_images)
    return created_containers, created_images


def wait_for_exact_running_app(runtime: Runtime, tagged_image: str) -> tuple[str, bool, str]:
    deadline = time.monotonic() + runtime.app_running_settle_timeout
    while True:
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            fail("Disposable launcher did not leave the exact named application running.")
        named = runtime.named_app(timeout=remaining)
        if named is not None:
            if named[2] != tagged_image:
                fail("Disposable named application image differs from the exact tagged application image.")
            if named[1]:
                return named
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            fail("Disposable launcher did not leave the exact named application running.")
        time.sleep(min(runtime.app_running_settle_interval, remaining))


def reconcile(runtime: Runtime, document: dict[str, object], success: bool) -> None:
    token = str(document["operationToken"])
    stop_marked_processes(token)
    created_containers, created_images = refresh_created(runtime, document)
    document["phase"] = "cleanup-armed"
    document["cleanupProved"] = False
    write_journal(runtime.journal, document)

    allowed_containers: set[str] = set()
    allowed_images: set[str] = set()
    if success:
        tagged = runtime.tagged_app_image()
        operation = str(document["operation"])
        if operation == "bootstrap":
            if tagged is None:
                fail("Disposable launcher did not produce the exact application image.")
            allowed_images.add(tagged)
        else:
            if tagged is None:
                fail("Disposable launcher did not retain the exact tagged application image.")
            named = wait_for_exact_running_app(runtime, tagged)
            allowed_containers.add(named[0])
            allowed_images.add(tagged)

    for identity in sorted(created_containers - allowed_containers):
        runtime.remove_container(identity)
    remaining_containers = runtime.container_ids()
    remaining_labeled = runtime.labeled_containers(token)
    if (created_containers - allowed_containers) & remaining_containers or (remaining_labeled - allowed_containers):
        fail("Disposable operation-created container survived reconciliation.")

    for identity in sorted(created_images - allowed_images):
        runtime.remove_image(identity)
    remaining_images = runtime.image_ids()
    if (created_images - allowed_images) & remaining_images:
        fail("Disposable operation-created image survived reconciliation.")

    if runtime.cid.exists() or runtime.cid.is_symlink():
        fail("Disposable launcher CID survived reconciliation.")
    if document["operation"] == "bootstrap":
        runtime.cleanup_pups_trace(token)
    document["phase"] = "terminal-proved"
    document["cleanupProved"] = True
    document["launcherPid"] = 0
    write_journal(runtime.journal, document)
    runtime.journal.unlink()
    fsync_directory(runtime.journal.parent)


def reconcile_prior(runtime: Runtime, operation: str, gate: Path, gate_sha: str) -> None:
    if not runtime.journal.exists() and not runtime.journal.is_symlink():
        return
    document = read_journal(runtime.journal)
    if (
        document["operation"] != operation
        or document["checkoutGate"] != str(gate)
        or document["checkoutGateSha256"] != gate_sha
    ):
        fail("Disposable launcher retry identity differs from its durable journal.")
    reconcile(runtime, document, False)


def main() -> int:
    if len(sys.argv) != 3 or sys.argv[1] not in OPERATIONS:
        fail("Usage: disposable-launcher-guard.py OPERATION CHECKOUT_GATE")
    operation = sys.argv[1]
    gate = Path(sys.argv[2]).resolve()
    fixture_root_value = os.environ.get("MOCHIRII_DISPOSABLE_LAUNCHER_FIXTURE_ROOT", "")
    adapter: Path | None = None
    if fixture_root_value:
        if os.environ.get("MOCHIRII_DISPOSABLE_LAUNCHER_MODE") != "source-only-hostile-fixture":
            fail("Disposable launcher fixture root requires its exact source-only mode.")
        root = Path(fixture_root_value).resolve()
        if root == Path("/tmp") or not str(root).startswith("/tmp/"):
            fail("Disposable launcher fixture root must be below /tmp.")
        adapter = root / "adapter.py"
        metadata = adapter.lstat()
        if not stat.S_ISREG(metadata.st_mode) or stat.S_ISLNK(metadata.st_mode) or stat.S_IMODE(metadata.st_mode) != 0o600:
            fail("Disposable launcher fixture adapter is unsafe.")
    else:
        if os.geteuid() != 0:
            fail("Disposable launcher guard must run as root.")
        root = Path("/")
    runtime = Runtime(root, adapter)
    if not gate.is_file() or gate.is_symlink():
        fail("Disposable launcher checkout gate is absent or linked.")
    gate_sha = sha256_file(gate)
    gate_result = subprocess.run(["bash", str(gate)], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, check=False)
    if gate_result.returncode:
        fail("Disposable launcher refused unsealed deployment source.")
    runtime.discourse.mkdir(mode=0o700, parents=True, exist_ok=True)
    reconcile_prior(runtime, operation, gate, gate_sha)
    if runtime.cid.exists() or runtime.cid.is_symlink():
        fail("Unowned disposable launcher CID exists before prearm.")
    if operation == "bootstrap":
        runtime.prove_trace_namespace_absent()

    token = os.urandom(16).hex()
    pre_containers = runtime.container_ids()
    pre_images = runtime.image_ids()
    if runtime.labeled_containers(token):
        fail("Disposable operation label existed before prearm.")
    document: dict[str, object] = {
        "schemaVersion": 1,
        "operation": operation,
        "phase": "armed",
        "operationToken": token,
        "checkoutGate": str(gate),
        "checkoutGateSha256": gate_sha,
        "preexistingContainerIds": sorted(pre_containers),
        "preexistingImageIds": sorted(pre_images),
        "createdContainerIds": [],
        "createdImageIds": [],
        "launcherPid": 0,
        "cleanupProved": False,
    }
    write_journal(runtime.journal, document)
    trace_record: Path | None = None
    environment = {
        **os.environ,
        "MOCHIRII_DISPOSABLE_OPERATION_TOKEN": token,
    }
    docker_arguments = (
        f"--label={LABEL_KEY}={token} --cpuset-cpus=0 "
        "--memory=2g --memory-swap=4g"
    )
    if operation == "bootstrap":
        trace_arguments, trace_record = runtime.prepare_pups_trace(token)
        docker_arguments = f"{docker_arguments} {trace_arguments}"
    command = [
        str(runtime.launcher), operation, "app", "--skip-prereqs", "--docker-args", docker_arguments,
    ]
    if adapter:
        command = [sys.executable, "-B", str(adapter), "launcher", *command[1:]]
    resources_before = resource_snapshot(runtime)
    recorder = LifecycleRecorder(runtime, token, environment)
    recorder.start()
    launcher_started = time.monotonic()
    try:
        process = subprocess.Popen(
            command,
            cwd=runtime.discourse,
            env=environment,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            start_new_session=True,
        )
    except OSError as error:
        recorder.stop()
        reconcile(runtime, document, False)
        raise GuardError("Disposable launcher process could not start; operation-created residue was contained.") from error
    try:
        document["phase"] = "launcher-active"
        document["launcherPid"] = process.pid
        write_journal(runtime.journal, document)
        deadline = time.monotonic() + LAUNCHER_TIMEOUT
        while process.poll() is None and time.monotonic() < deadline:
            recorder.observe_bootstrap_cid(runtime.cid)
            recorder.drain()
            refresh_created(runtime, document)
            write_journal(runtime.journal, document)
            time.sleep(0.1)
        if process.poll() is None:
            try:
                os.killpg(process.pid, signal.SIGTERM)
            except ProcessLookupError:
                pass
            try:
                process.wait(timeout=30)
            except subprocess.TimeoutExpired:
                try:
                    os.killpg(process.pid, signal.SIGKILL)
                except ProcessLookupError:
                    pass
                process.wait(timeout=5)
        recorder.observe_bootstrap_cid(runtime.cid, final=True)
        status = process.returncode if process.returncode is not None else 124
        elapsed_seconds = min(LAUNCHER_TIMEOUT + 60, max(0, int(time.monotonic() - launcher_started)))
    finally:
        recorder.stop()
    pups_trace = read_pups_trace(trace_record) if trace_record is not None else None
    resources_after = resource_snapshot(runtime)
    refresh_created(runtime, document)
    write_journal(runtime.journal, document)
    if os.environ.get("MOCHIRII_DISPOSABLE_LAUNCHER_FIXTURE_FAIL_AFTER") == "launcher-returned":
        os.kill(os.getpid(), signal.SIGKILL)
    if status == 0:
        try:
            reconcile(runtime, document, True)
        except GuardError as terminal_error:
            # Exit zero is not terminal evidence.  If the launcher left an
            # invalid output or anonymous residue, contain it under the same
            # durable identity before reporting the original failure.
            if runtime.journal.exists() and not runtime.journal.is_symlink():
                reconcile(runtime, read_journal(runtime.journal), False)
            raise terminal_error
    else:
        reconcile(runtime, document, False)
    if status:
        fail(
            recorder.failure_message(
                operation, status, elapsed_seconds, resources_before, resources_after, pups_trace,
            )
        )
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except GuardError as error:
        print(str(error), file=sys.stderr)
        raise SystemExit(1) from error
