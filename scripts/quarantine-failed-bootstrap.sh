#!/usr/bin/env bash
set -euo pipefail
umask 077
export LC_ALL=C

fail() {
  printf '%s\n' "$1" >&2
  exit 1
}

bounded() {
  timeout --signal=TERM --kill-after=5s "$@"
}

readonly canonical_repository="https://github.com/Mochirii-Wushu/Mochirii-Forums.git"
readonly source_root="/root/Mochirii-Forums"
readonly state_root="/var/lib/mochirii/forums"
readonly evidence_root="${state_root}/evidence"
readonly deployment_journal="${state_root}/deployment-mutation.json"
readonly pending_journal="${state_root}/failed-bootstrap-quarantine.pending.json"
readonly shared_root="/var/discourse/shared"
readonly standalone_root="${shared_root}/standalone"
readonly recovery_root="${shared_root}/.mochirii-forums-failed-bootstrap"
readonly reviewed_legacy_failed_bootstrap_commit="b2eb4edb17d72f49b6f979b19d9ee4a39b9ffc6f"
readonly reviewed_failed_bootstrap_recovery_commit="1d741eb75d08a226984935aa18e989ee324a0773"
readonly reviewed_active_swap_failed_bootstrap_commit="26e793aada31faeaa8b56308625288164430647c"
readonly reviewed_active_swap_recovery_commit="6e2f1b5c831b992c3222c015836fa180cd591e3e"
readonly reviewed_acme_failed_bootstrap_commit="f564d62a82adf79b8f012a25949826e2b447681d"
readonly reviewed_acme_recovery_commit="85e12f1ce27e1462e7c82e59e1dbf01c190327b9"
readonly reviewed_quarantine_output_failed_bootstrap_commit="c2f0f37ec2f73c41c7d1f63942a7483d1d7ef306"
readonly reviewed_quarantine_output_recovery_commit="8eea740795f0536468e48c5e8cda2ded29b1e51e"
readonly reviewed_acme_reload_privacy_failed_bootstrap_commit="fae3770f0817d05bbfd2520e9657ddc1c8a7ce5d"
readonly reviewed_acme_reload_privacy_recovery_commit="f51c2e8deaf39293c9b97f3aab797b882c3dc628"
readonly reviewed_acme_reload_privacy_recovery_child_commit="591d96484369ae29a8fa4e61219b325997f4b679"
readonly reviewed_acme_reload_privacy_launcher_child_commit="a71bbe8070ca6dadeff3c4966e81bd97fee83cf7"
readonly reviewed_acme_webroot_failed_bootstrap_commit="9110568e09bda4d572eaf2c27a768b9c053048f9"
readonly reviewed_acme_webroot_recovery_commit="bb891aa65ebe8470fa04cdd639185afdad7372f7"
readonly reviewed_acme_material_failed_bootstrap_commit="81e5226e54246686ce0ef80051d4df2cd1b64c5e"
readonly reviewed_acme_material_recovery_commit="64e12c2344fbc04d44b10c495cf9651cac5ac0b8"
readonly reviewed_acme_material_review_authority_commit="af3540426051c94bf26e9661ac68ce8ee720f977"
readonly reviewed_acme_stage_failed_bootstrap_commit="637a7c315574840156ac46615beb4417074088ed"
readonly reviewed_acme_stage_recovery_commit="9683e62abd3d0f41c41fc2a126a49eb33216c265"
readonly reviewed_acme_transport_failed_bootstrap_commit="ed2d1f0bedf4e7865c5ac3737fdae2308630e25a"
readonly reviewed_acme_transport_recovery_commit="5272554d33e9fcfc8f634ea14bc8e1f295b4278b"
readonly reviewed_acme_transport_postfailure_parent_commit="da21f45b6b7b0ed5514b7242113b3c5cf95e86f6"
readonly reviewed_acme_transport_postfailure_successor_commit="0050c53fea27387c85248bccd952dc4b1d483b9f"
readonly reviewed_acme_transport_current_main_commit="2ef406103c06d0b4defa339d79a08cba035239e4"

safe_source_repository_directory_identity() {
  local path="$1" descriptor="$2" metadata kind device inode uid gid mode links modified changed
  [[ ${descriptor} == true || ${descriptor} == false ]] || return 1
  [[ -d ${path} ]] || return 1
  if [[ ${descriptor} == true ]]; then
    [[ ${path} =~ ^/proc/self/fd/[1-9][0-9]*$ ]] || return 1
  else
    [[ ! -L ${path} ]] || return 1
  fi
  metadata="$(/usr/bin/stat -Lc $'%F\t%d\t%i\t%u\t%g\t%a\t%h\t%y\t%z' -- "${path}" 2>/dev/null)" || return 1
  IFS=$'\t' read -r kind device inode uid gid mode links modified changed <<<"${metadata}"
  [[ ${kind} == directory && ${device} =~ ^[0-9]+$ && ${inode} =~ ^[0-9]+$ ]] || return 1
  [[ ${uid} == 0 && ${gid} == 0 && ${mode} =~ ^[0-7]{3,4}$ && ${links} =~ ^[0-9]+$ ]] || return 1
  (( links >= 1 && (8#${mode} & 8#022) == 0 )) || return 1
  printf '%s\n' "${metadata}"
}

safe_source_repository_regular_file_identity() {
  local path="$1" descriptor="$2" maximum_size="$3" metadata metadata_after digest digest_after
  local device inode uid gid mode links size modified changed
  [[ ${descriptor} == true || ${descriptor} == false ]] || return 1
  [[ ${maximum_size} =~ ^[1-9][0-9]*$ ]] || return 1
  [[ -f ${path} ]] || return 1
  if [[ ${descriptor} == true ]]; then
    [[ ${path} =~ ^/proc/self/fd/[1-9][0-9]*$ ]] || return 1
  else
    [[ ! -L ${path} ]] || return 1
  fi
  metadata="$(/usr/bin/stat -Lc $'%d\t%i\t%u\t%g\t%a\t%h\t%s\t%y\t%z' -- "${path}" 2>/dev/null)" || return 1
  IFS=$'\t' read -r device inode uid gid mode links size modified changed <<<"${metadata}"
  [[ ${device} =~ ^[0-9]+$ && ${inode} =~ ^[0-9]+$ ]] || return 1
  [[ ${uid} == 0 && ${gid} == 0 && ( ${mode} == 600 || ${mode} == 644 ) && ${links} == 1 ]] || return 1
  [[ ${size} =~ ^[0-9]+$ ]] || return 1
  (( size > 0 && size <= maximum_size )) || return 1
  digest="$(/usr/bin/sha256sum -- "${path}" 2>/dev/null | /usr/bin/awk '{print $1}')" || return 1
  [[ ${digest} =~ ^[0-9a-f]{64}$ ]] || return 1
  metadata_after="$(/usr/bin/stat -Lc $'%d\t%i\t%u\t%g\t%a\t%h\t%s\t%y\t%z' -- "${path}" 2>/dev/null)" || return 1
  digest_after="$(/usr/bin/sha256sum -- "${path}" 2>/dev/null | /usr/bin/awk '{print $1}')" || return 1
  [[ ${metadata_after} == "${metadata}" && ${digest_after} == "${digest}" ]] || return 1
  printf '%s:%s\n' "${metadata}" "${digest}"
}

validated_source_repository_config_identity() {
  local config="$1" descriptor="$2" metadata metadata_after digest digest_after keys_output keys_text key expected value_output
  local device inode uid gid mode links size modified changed
  local -a actual_keys
  local -A seen_keys=()
  [[ ${descriptor} == true || ${descriptor} == false ]] || return 1
  [[ -f ${config} ]] || return 1
  if [[ ${descriptor} == true ]]; then
    [[ ${config} =~ ^/proc/self/fd/[1-9][0-9]*$ ]] || return 1
  else
    [[ ! -L ${config} ]] || return 1
  fi
  metadata="$(/usr/bin/stat -Lc $'%d\t%i\t%u\t%g\t%a\t%h\t%s\t%y\t%z' -- "${config}" 2>/dev/null)" || return 1
  IFS=$'\t' read -r device inode uid gid mode links size modified changed <<<"${metadata}"
  [[ ${uid} == 0 && ${gid} == 0 && ( ${mode} == 600 || ${mode} == 644 ) && ${links} == 1 ]] || return 1
  [[ ${size} =~ ^[0-9]+$ ]] || return 1
  (( size > 0 && size <= 65536 )) || return 1
  digest="$(/usr/bin/sha256sum -- "${config}" 2>/dev/null | /usr/bin/awk '{print $1}')" || return 1
  [[ ${digest} =~ ^[0-9a-f]{64}$ ]] || return 1
  keys_output="$(
    cd /
    /usr/bin/env -i PATH=/usr/bin:/bin LC_ALL=C HOME=/nonexistent \
      GIT_CONFIG_NOSYSTEM=1 GIT_CONFIG_SYSTEM=/dev/null GIT_CONFIG_GLOBAL=/dev/null \
      GIT_CONFIG_COUNT=0 GIT_NO_REPLACE_OBJECTS=1 GIT_TERMINAL_PROMPT=0 \
      GIT_PAGER=cat PAGER=cat \
      /usr/bin/git -c core.pager=cat -c pager.config=false config \
        --file "${config}" --no-includes --name-only --list 2>/dev/null && printf '\036'
  )" || return 1
  [[ ${keys_output} == *$'\036' ]] || return 1
  keys_text="${keys_output%$'\036'}"
  [[ ${keys_text} == *$'\n' ]] || return 1
  keys_text="${keys_text%$'\n'}"
  [[ -n ${keys_text} && ${keys_text} != *$'\036'* ]] || return 1
  mapfile -t actual_keys <<<"${keys_text}"
  [[ ${#actual_keys[@]} -eq 14 ]] || return 1
  for key in "${actual_keys[@]}"; do
    case "${key}" in
      core.repositoryformatversion) expected=0 ;;
      core.filemode) expected=true ;;
      core.bare) expected=false ;;
      core.logallrefupdates) expected=true ;;
      remote.origin.url) expected="${canonical_repository}" ;;
      remote.origin.fetch) expected='+refs/heads/*:refs/remotes/origin/*' ;;
      branch.main.remote) expected=origin ;;
      branch.main.merge) expected=refs/heads/main ;;
      remote.upstream.url) expected=https://github.com/discourse/discourse_docker.git ;;
      remote.upstream.fetch) expected='+refs/heads/main:refs/remotes/upstream/main' ;;
      remote.upstream.pushurl) expected=disabled://upstream-push ;;
      remote.upstream.tagopt) expected=--no-tags ;;
      remote.pushdefault) expected=origin ;;
      pull.ff) expected=only ;;
      *) return 1 ;;
    esac
    [[ -z ${seen_keys["${key}"]+present} ]] || return 1
    seen_keys["${key}"]=1
    value_output="$(
      cd /
      /usr/bin/env -i PATH=/usr/bin:/bin LC_ALL=C HOME=/nonexistent \
        GIT_CONFIG_NOSYSTEM=1 GIT_CONFIG_SYSTEM=/dev/null GIT_CONFIG_GLOBAL=/dev/null \
        GIT_CONFIG_COUNT=0 GIT_NO_REPLACE_OBJECTS=1 GIT_TERMINAL_PROMPT=0 \
        GIT_PAGER=cat PAGER=cat \
        /usr/bin/git -c core.pager=cat -c pager.config=false config \
          --file "${config}" --no-includes --get-all "${key}" 2>/dev/null && printf '\036'
    )" || return 1
    [[ ${value_output} == "${expected}"$'\n'$'\036' ]] || return 1
  done
  metadata_after="$(/usr/bin/stat -Lc $'%d\t%i\t%u\t%g\t%a\t%h\t%s\t%y\t%z' -- "${config}" 2>/dev/null)" || return 1
  digest_after="$(/usr/bin/sha256sum -- "${config}" 2>/dev/null | /usr/bin/awk '{print $1}')" || return 1
  [[ ${metadata_after} == "${metadata}" && ${digest_after} == "${digest}" ]] || return 1
  printf '%s:%s\n' "${metadata}" "${digest}"
}

validated_source_repository_boundary_identity() {
  local repository="$1" source_directory_fd="$2" git_directory_fd="$3" config_fd="$4"
  local info_directory_fd="$5" objects_directory_fd="$6" objects_info_directory_fd="$7" head_fd="$8"
  local refs_directory_fd="$9" heads_directory_fd="${10}" main_ref_fd="${11}" index_fd="${12}"
  local root_identity parent_identity source_path_identity git_path_identity info_path_identity objects_path_identity objects_info_path_identity refs_path_identity heads_path_identity
  local source_descriptor_identity git_descriptor_identity info_descriptor_identity objects_descriptor_identity objects_info_descriptor_identity refs_descriptor_identity heads_descriptor_identity
  local config_path_identity config_descriptor_identity head_path_identity head_descriptor_identity main_ref_path_identity main_ref_descriptor_identity index_path_identity index_descriptor_identity
  local head_output main_ref_output main_ref_text reserved descriptor_fd git_device child_device directory_identity
  local source_descriptor="/proc/self/fd/${source_directory_fd}"
  local git_descriptor="/proc/self/fd/${git_directory_fd}"
  local config_descriptor="/proc/self/fd/${config_fd}"
  local info_descriptor="/proc/self/fd/${info_directory_fd}"
  local objects_descriptor="/proc/self/fd/${objects_directory_fd}"
  local objects_info_descriptor="/proc/self/fd/${objects_info_directory_fd}"
  local head_descriptor="/proc/self/fd/${head_fd}"
  local refs_descriptor="/proc/self/fd/${refs_directory_fd}"
  local heads_descriptor="/proc/self/fd/${heads_directory_fd}"
  local main_ref_descriptor="/proc/self/fd/${main_ref_fd}"
  local index_descriptor="/proc/self/fd/${index_fd}"
  [[ ${repository} == /root/Mochirii-Forums ]] || return 1
  for descriptor_fd in "${source_directory_fd}" "${git_directory_fd}" "${config_fd}" "${info_directory_fd}" "${objects_directory_fd}" "${objects_info_directory_fd}" "${head_fd}" "${refs_directory_fd}" "${heads_directory_fd}" "${main_ref_fd}" "${index_fd}"; do
    [[ ${descriptor_fd} =~ ^[1-9][0-9]*$ ]] || return 1
  done
  root_identity="$(safe_source_repository_directory_identity / false)" || return 1
  parent_identity="$(safe_source_repository_directory_identity /root false)" || return 1
  source_path_identity="$(safe_source_repository_directory_identity "${repository}" false)" || return 1
  git_path_identity="$(safe_source_repository_directory_identity "${repository}/.git" false)" || return 1
  info_path_identity="$(safe_source_repository_directory_identity "${repository}/.git/info" false)" || return 1
  objects_path_identity="$(safe_source_repository_directory_identity "${repository}/.git/objects" false)" || return 1
  objects_info_path_identity="$(safe_source_repository_directory_identity "${repository}/.git/objects/info" false)" || return 1
  refs_path_identity="$(safe_source_repository_directory_identity "${repository}/.git/refs" false)" || return 1
  heads_path_identity="$(safe_source_repository_directory_identity "${repository}/.git/refs/heads" false)" || return 1
  source_descriptor_identity="$(safe_source_repository_directory_identity "${source_descriptor}" true)" || return 1
  git_descriptor_identity="$(safe_source_repository_directory_identity "${git_descriptor}" true)" || return 1
  info_descriptor_identity="$(safe_source_repository_directory_identity "${info_descriptor}" true)" || return 1
  objects_descriptor_identity="$(safe_source_repository_directory_identity "${objects_descriptor}" true)" || return 1
  objects_info_descriptor_identity="$(safe_source_repository_directory_identity "${objects_info_descriptor}" true)" || return 1
  refs_descriptor_identity="$(safe_source_repository_directory_identity "${refs_descriptor}" true)" || return 1
  heads_descriptor_identity="$(safe_source_repository_directory_identity "${heads_descriptor}" true)" || return 1
  [[ ${source_descriptor_identity} == "${source_path_identity}" ]] || return 1
  [[ ${git_descriptor_identity} == "${git_path_identity}" ]] || return 1
  [[ ${info_descriptor_identity} == "${info_path_identity}" ]] || return 1
  [[ ${objects_descriptor_identity} == "${objects_path_identity}" ]] || return 1
  [[ ${objects_info_descriptor_identity} == "${objects_info_path_identity}" ]] || return 1
  [[ ${refs_descriptor_identity} == "${refs_path_identity}" ]] || return 1
  [[ ${heads_descriptor_identity} == "${heads_path_identity}" ]] || return 1
  git_device="${git_descriptor_identity#*$'\t'}"
  git_device="${git_device%%$'\t'*}"
  [[ ${git_device} =~ ^[0-9]+$ ]] || return 1
  for directory_identity in "${info_descriptor_identity}" "${objects_descriptor_identity}" "${objects_info_descriptor_identity}" "${refs_descriptor_identity}" "${heads_descriptor_identity}"; do
    child_device="${directory_identity#*$'\t'}"
    child_device="${child_device%%$'\t'*}"
    [[ ${child_device} == "${git_device}" ]] || return 1
  done
  config_path_identity="$(validated_source_repository_config_identity "${repository}/.git/config" false)" || return 1
  config_descriptor_identity="$(validated_source_repository_config_identity "${config_descriptor}" true)" || return 1
  [[ ${config_descriptor_identity} == "${config_path_identity}" ]] || return 1
  head_path_identity="$(safe_source_repository_regular_file_identity "${repository}/.git/HEAD" false 4096)" || return 1
  head_descriptor_identity="$(safe_source_repository_regular_file_identity "${head_descriptor}" true 4096)" || return 1
  [[ ${head_descriptor_identity} == "${head_path_identity}" ]] || return 1
  head_output="$({ /usr/bin/cat -- "${head_descriptor}"; printf '\036'; } 2>/dev/null)" || return 1
  [[ ${head_output} == 'ref: refs/heads/main'$'\n'$'\036' ]] || return 1
  main_ref_path_identity="$(safe_source_repository_regular_file_identity "${repository}/.git/refs/heads/main" false 4096)" || return 1
  main_ref_descriptor_identity="$(safe_source_repository_regular_file_identity "${main_ref_descriptor}" true 4096)" || return 1
  [[ ${main_ref_descriptor_identity} == "${main_ref_path_identity}" ]] || return 1
  main_ref_output="$({ /usr/bin/cat -- "${main_ref_descriptor}"; printf '\036'; } 2>/dev/null)" || return 1
  [[ ${main_ref_output} == *$'\036' ]] || return 1
  main_ref_text="${main_ref_output%$'\036'}"
  [[ ${main_ref_text} == *$'\n' ]] || return 1
  main_ref_text="${main_ref_text%$'\n'}"
  [[ ${main_ref_text} =~ ^[0-9a-f]{40}$ ]] || return 1
  [[ ${main_ref_output} == "${main_ref_text}"$'\n'$'\036' ]] || return 1
  index_path_identity="$(safe_source_repository_regular_file_identity "${repository}/.git/index" false 67108864)" || return 1
  index_descriptor_identity="$(safe_source_repository_regular_file_identity "${index_descriptor}" true 67108864)" || return 1
  [[ ${index_descriptor_identity} == "${index_path_identity}" ]] || return 1
  for reserved in \
    "${git_descriptor}/commondir" \
    "${git_descriptor}/config.worktree" \
    "${git_descriptor}/shallow" \
    "${info_descriptor}/grafts" \
    "${info_descriptor}/attributes" \
    "${objects_info_descriptor}/alternates" \
    "${objects_info_descriptor}/http-alternates"; do
    [[ ! -e ${reserved} && ! -L ${reserved} ]] || return 1
  done
  printf '%s|%s|%s|%s|%s|%s|%s|%s|%s|%s|%s|%s|%s\n' \
    "${root_identity}" "${parent_identity}" "${source_path_identity}" "${git_path_identity}" \
    "${info_path_identity}" "${objects_path_identity}" "${objects_info_path_identity}" "${refs_path_identity}" \
    "${heads_path_identity}" "${config_path_identity}" "${head_path_identity}" "${main_ref_path_identity}" "${index_path_identity}"
}

source_repository_git() {
  local source_directory_fd="$1" git_directory_fd="$2"
  shift 2
  [[ ${source_directory_fd} =~ ^[1-9][0-9]*$ && ${git_directory_fd} =~ ^[1-9][0-9]*$ ]] || return 1
  cd /
  /usr/bin/env -i PATH=/usr/bin:/bin LC_ALL=C HOME=/nonexistent \
    GIT_CONFIG_NOSYSTEM=1 GIT_CONFIG_SYSTEM=/dev/null GIT_CONFIG_GLOBAL=/dev/null \
    GIT_CONFIG_COUNT=0 GIT_NO_REPLACE_OBJECTS=1 GIT_OPTIONAL_LOCKS=0 GIT_ATTR_NOSYSTEM=1 \
    GIT_TERMINAL_PROMPT=0 GIT_CEILING_DIRECTORIES=/ GIT_PAGER=cat PAGER=cat \
    /usr/bin/git --git-dir="/proc/self/fd/${git_directory_fd}" \
      --work-tree="/proc/self/fd/${source_directory_fd}" \
      -c core.commitGraph=false "$@"
}

validate_source_repository_operation_state() {
  local git_directory_fd="$1" lock_output operation_path operation_relative
  local -a forbidden_operation_paths=(
    MERGE_HEAD AUTO_MERGE MERGE_AUTOSTASH CHERRY_PICK_HEAD REVERT_HEAD REBASE_HEAD
    BISECT_HEAD BISECT_START BISECT_LOG BISECT_NAMES BISECT_RUN
    gc.pid refs/bisect refs/rewritten worktrees sequencer rebase-apply rebase-merge
  )
  [[ ${git_directory_fd} =~ ^[1-9][0-9]*$ ]] || return 1
  for operation_relative in "${forbidden_operation_paths[@]}"; do
    operation_path="/proc/self/fd/${git_directory_fd}/${operation_relative}"
    [[ ! -e ${operation_path} && ! -L ${operation_path} ]] || return 1
  done
  lock_output="$({
    bounded 5s /usr/bin/find -H "/proc/self/fd/${git_directory_fd}" -mindepth 1 \
      \( -type l -o -name '*.lock' \) -print -quit &&
      printf '\036'
  } 2>/dev/null)" || return 1
  (( ${#lock_output} <= 4096 )) || return 1
  [[ ${lock_output} == $'\036' ]] || return 1
}

validate_source_repository_clean_state() {
  local source_directory_fd="$1" git_directory_fd="$2"
  local status_output shared_index_output resolve_undo_output flag_option flag_output flag_text line
  local index_output index_text header mode blob stage path actual_blob tracked_path expected_file_mode
  local metadata metadata_after device inode uid gid file_mode links size modified changed
  local component prefix directory_path directory_identity directory_index
  local -a path_components tracked_directories directory_identities
  [[ ${source_directory_fd} =~ ^[1-9][0-9]*$ && ${git_directory_fd} =~ ^[1-9][0-9]*$ ]] || return 1
  validate_source_repository_operation_state "${git_directory_fd}" || return 1
  resolve_undo_output="$({
    source_repository_git "${source_directory_fd}" "${git_directory_fd}" ls-files --resolve-undo &&
      printf '\036'
  } 2>/dev/null)" || return 1
  (( ${#resolve_undo_output} <= 4194304 )) || return 1
  [[ ${resolve_undo_output} == $'\036' ]] || return 1
  status_output="$({
    source_repository_git "${source_directory_fd}" "${git_directory_fd}" \
      -c core.fsmonitor=false -c core.untrackedCache=false \
      status --porcelain=v1 --untracked-files=all --ignored=matching &&
      printf '\036'
  } 2>/dev/null)" || return 1
  (( ${#status_output} <= 262144 )) || return 1
  [[ ${status_output} == $'\036' ]] || return 1
  shared_index_output="$({
    source_repository_git "${source_directory_fd}" "${git_directory_fd}" \
      rev-parse --shared-index-path &&
      printf '\036'
  } 2>/dev/null)" || return 1
  (( ${#shared_index_output} <= 4096 )) || return 1
  [[ ${shared_index_output} == $'\036' ]] || return 1
  for flag_option in -v -f; do
    flag_output="$({
      source_repository_git "${source_directory_fd}" "${git_directory_fd}" \
        ls-files "${flag_option}" --stage &&
        printf '\036'
    } 2>/dev/null)" || return 1
    (( ${#flag_output} <= 4194304 )) || return 1
    [[ ${flag_output} == *$'\036' ]] || return 1
    flag_text="${flag_output%$'\036'}"
    [[ ${flag_text} == *$'\n' ]] || return 1
    flag_text="${flag_text%$'\n'}"
    [[ -n ${flag_text} && ${flag_text} != *$'\036'* ]] || return 1
    while IFS= read -r line; do
      [[ ${line} == H\ * ]] || return 1
    done <<<"${flag_text}"
  done
  source_repository_git "${source_directory_fd}" "${git_directory_fd}" \
    diff-index --cached --quiet --no-ext-diff HEAD -- 2>/dev/null || return 1
  index_output="$({
    source_repository_git "${source_directory_fd}" "${git_directory_fd}" \
      ls-files --stage &&
      printf '\036'
  } 2>/dev/null)" || return 1
  (( ${#index_output} <= 4194304 )) || return 1
  [[ ${index_output} == *$'\036' ]] || return 1
  index_text="${index_output%$'\036'}"
  [[ ${index_text} == *$'\n' ]] || return 1
  index_text="${index_text%$'\n'}"
  [[ -n ${index_text} && ${index_text} != *$'\036'* ]] || return 1
  while IFS= read -r line; do
    [[ ${line} == *$'\t'* ]] || return 1
    header="${line%%$'\t'*}"
    path="${line#*$'\t'}"
    read -r mode blob stage <<<"${header}"
    [[ ( ${mode} == 100644 || ${mode} == 100755 ) && ${blob} =~ ^[0-9a-f]{40}$ && ${stage} == 0 ]] || return 1
    [[ ${path} =~ ^[A-Za-z0-9._@+/-]+$ && ${path} != /* && ${path} != ../* && ${path} != */../* && ${path} != */.. ]] || return 1
    IFS=/ read -r -a path_components <<<"${path}"
    tracked_directories=()
    directory_identities=()
    prefix=
    for (( directory_index=0; directory_index < ${#path_components[@]} - 1; directory_index++ )); do
      component="${path_components[${directory_index}]}"
      [[ -n ${component} ]] || return 1
      prefix="${prefix:+${prefix}/}${component}"
      directory_path="/proc/self/fd/${source_directory_fd}/${prefix}"
      directory_identity="$(safe_source_repository_directory_identity "${directory_path}" false)" || return 1
      tracked_directories+=("${directory_path}")
      directory_identities+=("${directory_identity}")
    done
    tracked_path="/proc/self/fd/${source_directory_fd}/${path}"
    [[ -f ${tracked_path} && ! -L ${tracked_path} ]] || return 1
    case "${path}:${mode}" in
      scripts/verify-host-security.sh:100644|config/host-control-manifest.v1.json:100644)
        expected_file_mode=600
        ;;
      scripts/verify-host-security.sh:*|config/host-control-manifest.v1.json:*)
        return 1
        ;;
      *:100644)
        expected_file_mode=644
        ;;
      *:100755)
        expected_file_mode=755
        ;;
      *)
        return 1
        ;;
    esac
    metadata="$(/usr/bin/stat -Lc $'%d\t%i\t%u\t%g\t%a\t%h\t%s\t%y\t%z' -- "${tracked_path}" 2>/dev/null)" || return 1
    IFS=$'\t' read -r device inode uid gid file_mode links size modified changed <<<"${metadata}"
    [[ ${device} =~ ^[0-9]+$ && ${inode} =~ ^[0-9]+$ && ${uid} == 0 && ${gid} == 0 ]] || return 1
    [[ ${file_mode} == "${expected_file_mode}" && ${links} == 1 && ${size} =~ ^[0-9]+$ ]] || return 1
    (( size <= 67108864 )) || return 1
    actual_blob="$(source_repository_git "${source_directory_fd}" "${git_directory_fd}" \
      hash-object --no-filters -- "${tracked_path}" 2>/dev/null)" || return 1
    [[ ${actual_blob} == "${blob}" ]] || return 1
    metadata_after="$(/usr/bin/stat -Lc $'%d\t%i\t%u\t%g\t%a\t%h\t%s\t%y\t%z' -- "${tracked_path}" 2>/dev/null)" || return 1
    [[ ${metadata_after} == "${metadata}" ]] || return 1
    for (( directory_index=0; directory_index < ${#tracked_directories[@]}; directory_index++ )); do
      [[ "$(safe_source_repository_directory_identity "${tracked_directories[${directory_index}]}" false)" == "${directory_identities[${directory_index}]}" ]] || return 1
    done
  done <<<"${index_text}"
  validate_source_repository_operation_state "${git_directory_fd}" || return 1
  resolve_undo_output="$({
    source_repository_git "${source_directory_fd}" "${git_directory_fd}" ls-files --resolve-undo &&
      printf '\036'
  } 2>/dev/null)" || return 1
  (( ${#resolve_undo_output} <= 4194304 )) || return 1
  [[ ${resolve_undo_output} == $'\036' ]] || return 1
}

validate_bound_source_repository_file() {
  (
  local current="$1" relative="$2" file_fd="$3" repository_config_identity
  local source_directory_fd git_directory_fd config_fd info_directory_fd objects_directory_fd objects_info_directory_fd
  local head_fd refs_directory_fd heads_directory_fd main_ref_fd index_fd
  local path_identity descriptor_identity actual_blob expected_entry
  [[ ${current} =~ ^[0-9a-f]{40}$ && ${relative} == scripts/verify-host-security.sh && ${file_fd} =~ ^[1-9][0-9]*$ ]] || return 1
  shopt -u varredir_close
  exec {source_directory_fd}<"${source_root}" || return 1
  exec {git_directory_fd}<"${source_root}/.git" || return 1
  exec {config_fd}<"${source_root}/.git/config" || return 1
  exec {info_directory_fd}<"${source_root}/.git/info" || return 1
  exec {objects_directory_fd}<"${source_root}/.git/objects" || return 1
  exec {objects_info_directory_fd}<"${source_root}/.git/objects/info" || return 1
  exec {head_fd}<"${source_root}/.git/HEAD" || return 1
  exec {refs_directory_fd}<"${source_root}/.git/refs" || return 1
  exec {heads_directory_fd}<"${source_root}/.git/refs/heads" || return 1
  exec {main_ref_fd}<"${source_root}/.git/refs/heads/main" || return 1
  exec {index_fd}<"${source_root}/.git/index" || return 1
  validate_source_repository_operation_state "${git_directory_fd}" || return 1
  repository_config_identity="$(validated_source_repository_boundary_identity "${source_root}" "${source_directory_fd}" "${git_directory_fd}" "${config_fd}" "${info_directory_fd}" "${objects_directory_fd}" "${objects_info_directory_fd}" "${head_fd}" "${refs_directory_fd}" "${heads_directory_fd}" "${main_ref_fd}" "${index_fd}")" || return 1
  validate_source_repository_clean_state "${source_directory_fd}" "${git_directory_fd}" || return 1
  [[ "$(source_repository_git "${source_directory_fd}" "${git_directory_fd}" rev-parse --verify HEAD^{commit} 2>/dev/null)" == "${current}" ]] || return 1
  [[ "$(source_repository_git "${source_directory_fd}" "${git_directory_fd}" symbolic-ref --short -q HEAD 2>/dev/null)" == main ]] || return 1
  path_identity="$(safe_source_repository_regular_file_identity "${source_root}/${relative}" false 1048576)" || return 1
  descriptor_identity="$(safe_source_repository_regular_file_identity "/proc/self/fd/${file_fd}" true 1048576)" || return 1
  [[ ${descriptor_identity} == "${path_identity}" ]] || return 1
  actual_blob="$(source_repository_git "${source_directory_fd}" "${git_directory_fd}" \
    hash-object --no-filters -- "/proc/self/fd/${file_fd}" 2>/dev/null)" || return 1
  [[ ${actual_blob} =~ ^[0-9a-f]{40}$ ]] || return 1
  expected_entry="$(source_repository_git "${source_directory_fd}" "${git_directory_fd}" \
    ls-tree "${current}" -- "${relative}" 2>/dev/null)" || return 1
  [[ ${expected_entry} == "100644 blob ${actual_blob}"$'\t'"${relative}" ]] || return 1
  validate_source_repository_clean_state "${source_directory_fd}" "${git_directory_fd}" || return 1
  [[ "$(validated_source_repository_boundary_identity "${source_root}" "${source_directory_fd}" "${git_directory_fd}" "${config_fd}" "${info_directory_fd}" "${objects_directory_fd}" "${objects_info_directory_fd}" "${head_fd}" "${refs_directory_fd}" "${heads_directory_fd}" "${main_ref_fd}" "${index_fd}")" == "${repository_config_identity}" ]] || return 1
  validate_source_repository_operation_state "${git_directory_fd}" || return 1
  )
}

read_canonical_remote_main() {
  cd /
  /usr/bin/timeout --signal=TERM --kill-after=5s 120s \
    /usr/bin/env -i PATH=/usr/bin:/bin LC_ALL=C HOME=/nonexistent \
    GIT_CONFIG_NOSYSTEM=1 GIT_CONFIG_SYSTEM=/dev/null GIT_CONFIG_GLOBAL=/dev/null \
    GIT_CONFIG_COUNT=0 GIT_NO_REPLACE_OBJECTS=1 GIT_TERMINAL_PROMPT=0 \
    GIT_PROTOCOL_FROM_USER=0 GIT_CEILING_DIRECTORIES=/ GIT_PAGER=cat PAGER=cat \
    /usr/bin/git --git-dir=/dev/null --work-tree=/dev/null \
      -c credential.helper= -c core.askPass= -c core.pager=cat \
      -c protocol.allow=never -c protocol.https.allow=always \
      -c http.followRedirects=false -c http.proxy= \
      ls-remote --refs "${canonical_repository}" refs/heads/main 2>/dev/null
}

validate_source_lineage() {
  (
  local current="$1" failed="$2" remote_output reviewed_recovery_commit current_parent_commit actual_path_output repository_config_identity
  local source_directory_fd git_directory_fd config_fd info_directory_fd objects_directory_fd objects_info_directory_fd
  local head_fd refs_directory_fd heads_directory_fd main_ref_fd index_fd
  local -ar legacy_expected_paths=(
    .github/workflows/deploy-forums.yml
    config/host-control-manifest.v1.json
    docs/operations/DEPLOYMENT.md
    docs/operations/RECOVERY.md
    scripts/quarantine-failed-bootstrap.sh
    scripts/test-contracts.py
    scripts/upgrade-host-control.sh
    scripts/validate-repository.py
  )
  local -ar active_swap_expected_paths=(
    docs/operations/DEPLOYMENT.md
    docs/operations/RECOVERY.md
    scripts/quarantine-failed-bootstrap.sh
    scripts/test-contracts.py
    scripts/upgrade-host-control.sh
    scripts/validate-repository.py
    scripts/verify-host.sh
  )
  local -ar acme_expected_paths=(
    config/immutable-letsencrypt.fragment.yml
    docs/operations/DEPLOYMENT.md
    docs/operations/RECOVERY.md
    scripts/quarantine-failed-bootstrap.sh
    scripts/test-contracts.py
    scripts/upgrade-host-control.sh
    scripts/validate-repository.py
  )
  local -ar quarantine_output_expected_paths=(
    docs/operations/DEPLOYMENT.md
    docs/operations/RECOVERY.md
    scripts/quarantine-failed-bootstrap.sh
    scripts/test-contracts.py
    scripts/upgrade-host-control.sh
    scripts/validate-repository.py
  )
  local -ar acme_reload_privacy_expected_paths=(
    config/immutable-letsencrypt.fragment.yml
    docs/operations/DEPLOYMENT.md
    docs/operations/RECOVERY.md
    scripts/disposable-launcher-guard.py
    scripts/quarantine-failed-bootstrap.sh
    scripts/test-contracts.py
    scripts/test-disposable-launcher-guard.py
    scripts/upgrade-host-control.sh
    scripts/validate-repository.py
    scripts/verify-host.sh
  )
  local -ar acme_webroot_expected_paths=(
    config/immutable-letsencrypt.fragment.yml
    docs/operations/DEPLOYMENT.md
    docs/operations/RECOVERY.md
    scripts/quarantine-failed-bootstrap.sh
    scripts/test-contracts.py
    scripts/upgrade-host-control.sh
    scripts/validate-repository.py
  )
  local -ar acme_material_repair_expected_paths=(
    config/immutable-letsencrypt.fragment.yml
    scripts/test-contracts.py
    scripts/validate-repository.py
  )
  local -ar acme_material_review_authority_expected_paths=(
    .gitattributes
    .github/CODEOWNERS
    .github/workflows/open-reviewed-source-pr.yml
    CONTRIBUTING.md
    docs/adr/0001-clean-initialization-and-canonical-ownership.md
    scripts/test-contracts.py
    scripts/validate-repository.py
  )
  local -ar acme_material_current_expected_paths=(
    .github/workflows/validate-repository.yml
    docs/operations/DEPLOYMENT.md
    docs/operations/RECOVERY.md
    scripts/check-repository.ps1
    scripts/check-source-introduction.ps1
    scripts/host-deploy.sh
    scripts/quarantine-failed-bootstrap.sh
    scripts/test-contracts.py
    scripts/test-source-introduction.ps1
    scripts/upgrade-host-control.sh
    scripts/validate-repository.py
    scripts/verify-host-security.sh
  )
  local -ar acme_material_expected_paths=(
    .gitattributes
    .github/CODEOWNERS
    .github/workflows/open-reviewed-source-pr.yml
    .github/workflows/validate-repository.yml
    CONTRIBUTING.md
    config/immutable-letsencrypt.fragment.yml
    docs/adr/0001-clean-initialization-and-canonical-ownership.md
    docs/operations/DEPLOYMENT.md
    docs/operations/RECOVERY.md
    scripts/check-repository.ps1
    scripts/check-source-introduction.ps1
    scripts/host-deploy.sh
    scripts/quarantine-failed-bootstrap.sh
    scripts/test-contracts.py
    scripts/test-source-introduction.ps1
    scripts/upgrade-host-control.sh
    scripts/validate-repository.py
  )
  local -ar acme_stage_repair_expected_paths=(
    .github/workflows/validate-repository.yml
    config/immutable-letsencrypt.fragment.yml
    scripts/check-repository.ps1
    scripts/check-source-introduction.ps1
    scripts/host-deploy.sh
    scripts/test-contracts.py
    scripts/test-source-introduction.ps1
    scripts/validate-repository.py
    scripts/verify-host.sh
  )
  local -ar acme_stage_current_expected_paths=(
    .github/workflows/validate-repository.yml
    docs/operations/DEPLOYMENT.md
    docs/operations/RECOVERY.md
    scripts/check-repository.ps1
    scripts/check-source-introduction.ps1
    scripts/host-deploy.sh
    scripts/quarantine-failed-bootstrap.sh
    scripts/test-contracts.py
    scripts/test-source-introduction.ps1
    scripts/upgrade-host-control.sh
    scripts/validate-repository.py
  )
  local -ar acme_stage_expected_paths=(
    .github/workflows/validate-repository.yml
    config/immutable-letsencrypt.fragment.yml
    docs/operations/DEPLOYMENT.md
    docs/operations/RECOVERY.md
    scripts/check-repository.ps1
    scripts/check-source-introduction.ps1
    scripts/host-deploy.sh
    scripts/quarantine-failed-bootstrap.sh
    scripts/test-contracts.py
    scripts/test-source-introduction.ps1
    scripts/upgrade-host-control.sh
    scripts/validate-repository.py
    scripts/verify-host.sh
  )
  local -ar acme_transport_repair_expected_paths=(
    .github/workflows/disposable-bootstrap.yml
    .github/workflows/validate-repository.yml
    config/acme-sh-3.0.6.LICENSE.md
    config/acme-sh-3.0.6.gz.b64
    config/acme-sh-3.1.4.LICENSE.md
    config/acme-sh-3.1.4.gz.b64
    config/immutable-letsencrypt.fragment.yml
    docs/operations/PROVIDER-DNS-TLS.md
    docs/operations/SOURCE-PROVENANCE.md
    docs/operations/THIRD-PARTY-NOTICES.md
    docs/operations/third-party-components.v1.json
    scripts/check-repository.ps1
    scripts/check-source-introduction.ps1
    scripts/host-deploy.sh
    scripts/test-contracts.py
    scripts/test-source-introduction.ps1
    scripts/validate-repository.py
    scripts/verify-runtime-assets.sh
  )
  local -ar acme_transport_current_expected_paths=(
    .github/workflows/disposable-bootstrap.yml
    .github/workflows/validate-repository.yml
    docs/operations/DEPLOYMENT.md
    docs/operations/RECOVERY.md
    scripts/check-repository.ps1
    scripts/check-source-introduction.ps1
    scripts/finalize-member-rollout.sh
    scripts/host-backup.sh
    scripts/host-break-glass-admin.sh
    scripts/host-deploy.sh
    scripts/host-finalize-authentication.sh
    scripts/host-operation-lock.py
    scripts/host-restore-validate.sh
    scripts/host-stop-pending-activation.sh
    scripts/host-verify-wrapper.sh
    scripts/install-host-control.sh
    scripts/install-media-certificate-renewal.sh
    scripts/prepare-media-certificate.sh
    scripts/quarantine-failed-bootstrap.sh
    scripts/run-media-certificate-renewal.sh
    scripts/test-contracts.py
    scripts/test-host-operation-lock.py
    scripts/test-source-introduction.ps1
    scripts/upgrade-host-control.sh
    scripts/validate-repository.py
    scripts/verify-host-security.sh
  )
  local -ar acme_transport_postfailure_current_expected_paths=(
    .github/pull_request_template.md
    .github/workflows/disposable-bootstrap.yml
    .github/workflows/validate-repository.yml
    README.md
    config/app.yml.example
    docs/adr/0005-promote-discourse-v2026-8-0.md
    docs/operations/CURRENT-STATE.md
    docs/operations/DEPLOYMENT.md
    docs/operations/RECOVERY.md
    docs/operations/RUNTIME-READINESS.md
    docs/operations/SOURCE-PROVENANCE.md
    docs/operations/THIRD-PARTY-NOTICES.md
    docs/operations/forum-central-identity.consumer.v1.json
    docs/operations/release-evidence.v2.example.json
    docs/operations/runtime-config.v1.example.json
    docs/operations/third-party-components.v1.json
    scripts/authentication-state.py
    scripts/check-repository.ps1
    scripts/check-source-introduction.ps1
    scripts/host-backup.sh
    scripts/host-deploy.sh
    scripts/host-restore-validate.sh
    scripts/host-verify-wrapper.sh
    scripts/quarantine-failed-bootstrap.sh
    scripts/test-contracts.py
    scripts/test-source-introduction.ps1
    scripts/upgrade-host-control.sh
    scripts/validate-repository.py
    scripts/verify-host.sh
    scripts/verify-pinned-source.py
    scripts/verify-site.rb
  )
  local -ar acme_transport_current_main_expected_paths=(
    .github/workflows/validate-repository.yml
    scripts/check-repository.ps1
    scripts/check-source-introduction.ps1
    scripts/host-deploy.sh
    scripts/quarantine-failed-bootstrap.sh
    scripts/test-contracts.py
    scripts/test-source-introduction.ps1
    scripts/upgrade-host-control.sh
    scripts/validate-repository.py
  )
  local -ar acme_transport_lineage_repair_expected_paths=(
    .github/workflows/validate-repository.yml
    scripts/check-repository.ps1
    scripts/check-source-introduction.ps1
    scripts/host-deploy.sh
    scripts/quarantine-failed-bootstrap.sh
    scripts/test-contracts.py
    scripts/test-source-introduction.ps1
    scripts/upgrade-host-control.sh
    scripts/validate-repository.py
  )
  local -ar acme_transport_expected_paths=(
    .github/pull_request_template.md
    .github/workflows/disposable-bootstrap.yml
    .github/workflows/validate-repository.yml
    README.md
    config/acme-sh-3.0.6.LICENSE.md
    config/acme-sh-3.0.6.gz.b64
    config/acme-sh-3.1.4.LICENSE.md
    config/acme-sh-3.1.4.gz.b64
    config/app.yml.example
    config/immutable-letsencrypt.fragment.yml
    docs/adr/0005-promote-discourse-v2026-8-0.md
    docs/operations/CURRENT-STATE.md
    docs/operations/DEPLOYMENT.md
    docs/operations/PROVIDER-DNS-TLS.md
    docs/operations/RECOVERY.md
    docs/operations/RUNTIME-READINESS.md
    docs/operations/SOURCE-PROVENANCE.md
    docs/operations/THIRD-PARTY-NOTICES.md
    docs/operations/forum-central-identity.consumer.v1.json
    docs/operations/release-evidence.v2.example.json
    docs/operations/runtime-config.v1.example.json
    docs/operations/third-party-components.v1.json
    scripts/authentication-state.py
    scripts/check-repository.ps1
    scripts/check-source-introduction.ps1
    scripts/finalize-member-rollout.sh
    scripts/host-backup.sh
    scripts/host-break-glass-admin.sh
    scripts/host-deploy.sh
    scripts/host-finalize-authentication.sh
    scripts/host-operation-lock.py
    scripts/host-restore-validate.sh
    scripts/host-stop-pending-activation.sh
    scripts/host-verify-wrapper.sh
    scripts/install-host-control.sh
    scripts/install-media-certificate-renewal.sh
    scripts/prepare-media-certificate.sh
    scripts/quarantine-failed-bootstrap.sh
    scripts/run-media-certificate-renewal.sh
    scripts/test-contracts.py
    scripts/test-host-operation-lock.py
    scripts/test-source-introduction.ps1
    scripts/upgrade-host-control.sh
    scripts/validate-repository.py
    scripts/verify-host-security.sh
    scripts/verify-host.sh
    scripts/verify-pinned-source.py
    scripts/verify-runtime-assets.sh
    scripts/verify-site.rb
  )
  local -a actual_paths expected_paths
  case "${failed}" in
    "${reviewed_legacy_failed_bootstrap_commit}")
      reviewed_recovery_commit="${reviewed_failed_bootstrap_recovery_commit}"
      current_parent_commit="${reviewed_recovery_commit}"
      expected_paths=("${legacy_expected_paths[@]}")
      ;;
    "${reviewed_active_swap_failed_bootstrap_commit}")
      reviewed_recovery_commit="${reviewed_active_swap_recovery_commit}"
      current_parent_commit="${reviewed_recovery_commit}"
      expected_paths=("${active_swap_expected_paths[@]}")
      ;;
    "${reviewed_acme_failed_bootstrap_commit}")
      reviewed_recovery_commit="${reviewed_acme_recovery_commit}"
      current_parent_commit="${reviewed_recovery_commit}"
      expected_paths=("${acme_expected_paths[@]}")
      ;;
    "${reviewed_quarantine_output_failed_bootstrap_commit}")
      reviewed_recovery_commit="${reviewed_quarantine_output_recovery_commit}"
      current_parent_commit="${reviewed_recovery_commit}"
      expected_paths=("${quarantine_output_expected_paths[@]}")
      ;;
    "${reviewed_acme_reload_privacy_failed_bootstrap_commit}")
      reviewed_recovery_commit="${reviewed_acme_reload_privacy_recovery_commit}"
      current_parent_commit="${reviewed_acme_reload_privacy_launcher_child_commit}"
      expected_paths=("${acme_reload_privacy_expected_paths[@]}")
      ;;
    "${reviewed_acme_webroot_failed_bootstrap_commit}")
      reviewed_recovery_commit="${reviewed_acme_webroot_recovery_commit}"
      current_parent_commit="${reviewed_recovery_commit}"
      expected_paths=("${acme_webroot_expected_paths[@]}")
      ;;
    "${reviewed_acme_material_failed_bootstrap_commit}")
      reviewed_recovery_commit="${reviewed_acme_material_recovery_commit}"
      current_parent_commit="${reviewed_acme_material_review_authority_commit}"
      expected_paths=("${acme_material_expected_paths[@]}")
      ;;
    "${reviewed_acme_stage_failed_bootstrap_commit}")
      reviewed_recovery_commit="${reviewed_acme_stage_recovery_commit}"
      current_parent_commit="${reviewed_recovery_commit}"
      expected_paths=("${acme_stage_expected_paths[@]}")
      ;;
    "${reviewed_acme_transport_failed_bootstrap_commit}")
      reviewed_recovery_commit="${reviewed_acme_transport_recovery_commit}"
      current_parent_commit="${reviewed_acme_transport_current_main_commit}"
      expected_paths=("${acme_transport_expected_paths[@]}")
      ;;
    *) return 1 ;;
  esac
  unset GIT_DIR GIT_WORK_TREE GIT_INDEX_FILE GIT_OBJECT_DIRECTORY GIT_ALTERNATE_OBJECT_DIRECTORIES GIT_COMMON_DIR GIT_REPLACE_REF_BASE
  unset GIT_ASKPASS SSH_ASKPASS GIT_SSH GIT_SSH_COMMAND GIT_CONFIG_PARAMETERS GIT_CONFIG_SYSTEM GIT_PROTOCOL_FROM_USER
  export GIT_TERMINAL_PROMPT=0 GIT_CONFIG_NOSYSTEM=1 GIT_CONFIG_GLOBAL=/dev/null GIT_CONFIG_COUNT=0 GIT_NO_REPLACE_OBJECTS=1
  shopt -u varredir_close
  exec {source_directory_fd}<"${source_root}" || return 1
  exec {git_directory_fd}<"${source_root}/.git" || return 1
  exec {config_fd}<"${source_root}/.git/config" || return 1
  exec {info_directory_fd}<"${source_root}/.git/info" || return 1
  exec {objects_directory_fd}<"${source_root}/.git/objects" || return 1
  exec {objects_info_directory_fd}<"${source_root}/.git/objects/info" || return 1
  exec {head_fd}<"${source_root}/.git/HEAD" || return 1
  exec {refs_directory_fd}<"${source_root}/.git/refs" || return 1
  exec {heads_directory_fd}<"${source_root}/.git/refs/heads" || return 1
  exec {main_ref_fd}<"${source_root}/.git/refs/heads/main" || return 1
  exec {index_fd}<"${source_root}/.git/index" || return 1
  validate_source_repository_operation_state "${git_directory_fd}" || return 1
  repository_config_identity="$(validated_source_repository_boundary_identity "${source_root}" "${source_directory_fd}" "${git_directory_fd}" "${config_fd}" "${info_directory_fd}" "${objects_directory_fd}" "${objects_info_directory_fd}" "${head_fd}" "${refs_directory_fd}" "${heads_directory_fd}" "${main_ref_fd}" "${index_fd}")" || return 1
  validate_source_repository_clean_state "${source_directory_fd}" "${git_directory_fd}" || return 1
  [[ "$(source_repository_git "${source_directory_fd}" "${git_directory_fd}" rev-parse --verify HEAD^{commit} 2>/dev/null)" == "${current}" ]] || return 1
  [[ "$(source_repository_git "${source_directory_fd}" "${git_directory_fd}" symbolic-ref --short -q HEAD 2>/dev/null)" == main ]] || return 1
  [[ "$(source_repository_git "${source_directory_fd}" "${git_directory_fd}" rev-parse --verify "${current}^1" 2>/dev/null)" == "${current_parent_commit}" ]] || return 1
  [[ "$(source_repository_git "${source_directory_fd}" "${git_directory_fd}" rev-list --parents -n 1 "${current}" 2>/dev/null)" == "${current} ${current_parent_commit}" ]] || return 1
  if [[ ${failed} == "${reviewed_acme_reload_privacy_failed_bootstrap_commit}" ]]; then
    [[ "$(source_repository_git "${source_directory_fd}" "${git_directory_fd}" rev-parse --verify "${reviewed_acme_reload_privacy_launcher_child_commit}^1" 2>/dev/null)" == "${reviewed_acme_reload_privacy_recovery_child_commit}" ]] || return 1
    [[ "$(source_repository_git "${source_directory_fd}" "${git_directory_fd}" rev-list --parents -n 1 "${reviewed_acme_reload_privacy_launcher_child_commit}" 2>/dev/null)" == "${reviewed_acme_reload_privacy_launcher_child_commit} ${reviewed_acme_reload_privacy_recovery_child_commit}" ]] || return 1
    [[ "$(source_repository_git "${source_directory_fd}" "${git_directory_fd}" rev-parse --verify "${reviewed_acme_reload_privacy_recovery_child_commit}^1" 2>/dev/null)" == "${reviewed_recovery_commit}" ]] || return 1
    [[ "$(source_repository_git "${source_directory_fd}" "${git_directory_fd}" rev-list --parents -n 1 "${reviewed_acme_reload_privacy_recovery_child_commit}" 2>/dev/null)" == "${reviewed_acme_reload_privacy_recovery_child_commit} ${reviewed_recovery_commit}" ]] || return 1
  fi
  if [[ ${failed} == "${reviewed_acme_material_failed_bootstrap_commit}" ]]; then
    [[ "$(source_repository_git "${source_directory_fd}" "${git_directory_fd}" rev-parse --verify "${reviewed_acme_material_review_authority_commit}^1" 2>/dev/null)" == "${reviewed_recovery_commit}" ]] || return 1
    [[ "$(source_repository_git "${source_directory_fd}" "${git_directory_fd}" rev-list --parents -n 1 "${reviewed_acme_material_review_authority_commit}" 2>/dev/null)" == "${reviewed_acme_material_review_authority_commit} ${reviewed_recovery_commit}" ]] || return 1
  fi
  if [[ ${failed} == "${reviewed_acme_transport_failed_bootstrap_commit}" ]]; then
    [[ "$(source_repository_git "${source_directory_fd}" "${git_directory_fd}" rev-parse --verify "${reviewed_acme_transport_current_main_commit}^1" 2>/dev/null)" == "${reviewed_acme_transport_postfailure_successor_commit}" ]] || return 1
    [[ "$(source_repository_git "${source_directory_fd}" "${git_directory_fd}" rev-list --parents -n 1 "${reviewed_acme_transport_current_main_commit}" 2>/dev/null)" == "${reviewed_acme_transport_current_main_commit} ${reviewed_acme_transport_postfailure_successor_commit}" ]] || return 1
    [[ "$(source_repository_git "${source_directory_fd}" "${git_directory_fd}" rev-parse --verify "${reviewed_acme_transport_postfailure_successor_commit}^1" 2>/dev/null)" == "${reviewed_acme_transport_postfailure_parent_commit}" ]] || return 1
    [[ "$(source_repository_git "${source_directory_fd}" "${git_directory_fd}" rev-list --parents -n 1 "${reviewed_acme_transport_postfailure_successor_commit}" 2>/dev/null)" == "${reviewed_acme_transport_postfailure_successor_commit} ${reviewed_acme_transport_postfailure_parent_commit}" ]] || return 1
    [[ "$(source_repository_git "${source_directory_fd}" "${git_directory_fd}" rev-parse --verify "${reviewed_acme_transport_postfailure_parent_commit}^1" 2>/dev/null)" == "${reviewed_recovery_commit}" ]] || return 1
    [[ "$(source_repository_git "${source_directory_fd}" "${git_directory_fd}" rev-list --parents -n 1 "${reviewed_acme_transport_postfailure_parent_commit}" 2>/dev/null)" == "${reviewed_acme_transport_postfailure_parent_commit} ${reviewed_recovery_commit}" ]] || return 1
  fi
  [[ "$(source_repository_git "${source_directory_fd}" "${git_directory_fd}" rev-parse --verify "${reviewed_recovery_commit}^1" 2>/dev/null)" == "${failed}" ]] || return 1
  [[ "$(source_repository_git "${source_directory_fd}" "${git_directory_fd}" rev-list --parents -n 1 "${reviewed_recovery_commit}" 2>/dev/null)" == "${reviewed_recovery_commit} ${failed}" ]] || return 1
  remote_output="$(read_canonical_remote_main)" || return 1
  (( ${#remote_output} <= 256 )) || return 1
  [[ ${remote_output} == "${current}"$'\trefs/heads/main' ]] || return 1
  if [[ ${failed} == "${reviewed_acme_material_failed_bootstrap_commit}" ]]; then
    actual_path_output="$(source_repository_git "${source_directory_fd}" "${git_directory_fd}" diff-tree --no-commit-id --name-only -r "${failed}" "${reviewed_recovery_commit}" 2>/dev/null)" || return 1
    (( ${#actual_path_output} <= 65536 )) || return 1
    mapfile -t actual_paths <<< "${actual_path_output}"
    [[ ${#actual_paths[@]} -eq ${#acme_material_repair_expected_paths[@]} ]] || return 1
    for index in "${!acme_material_repair_expected_paths[@]}"; do
      [[ ${actual_paths[$index]} == "${acme_material_repair_expected_paths[$index]}" ]] || return 1
    done
    actual_path_output="$(source_repository_git "${source_directory_fd}" "${git_directory_fd}" diff-tree --no-commit-id --name-only -r "${reviewed_recovery_commit}" "${reviewed_acme_material_review_authority_commit}" 2>/dev/null)" || return 1
    (( ${#actual_path_output} <= 65536 )) || return 1
    mapfile -t actual_paths <<< "${actual_path_output}"
    [[ ${#actual_paths[@]} -eq ${#acme_material_review_authority_expected_paths[@]} ]] || return 1
    for index in "${!acme_material_review_authority_expected_paths[@]}"; do
      [[ ${actual_paths[$index]} == "${acme_material_review_authority_expected_paths[$index]}" ]] || return 1
    done
    actual_path_output="$(source_repository_git "${source_directory_fd}" "${git_directory_fd}" diff-tree --no-commit-id --name-only -r "${reviewed_acme_material_review_authority_commit}" "${current}" 2>/dev/null)" || return 1
    (( ${#actual_path_output} <= 65536 )) || return 1
    mapfile -t actual_paths <<< "${actual_path_output}"
    [[ ${#actual_paths[@]} -eq ${#acme_material_current_expected_paths[@]} ]] || return 1
    for index in "${!acme_material_current_expected_paths[@]}"; do
      [[ ${actual_paths[$index]} == "${acme_material_current_expected_paths[$index]}" ]] || return 1
    done
  fi
  if [[ ${failed} == "${reviewed_acme_stage_failed_bootstrap_commit}" ]]; then
    actual_path_output="$(source_repository_git "${source_directory_fd}" "${git_directory_fd}" diff-tree --no-commit-id --name-only -r "${failed}" "${reviewed_recovery_commit}" 2>/dev/null)" || return 1
    (( ${#actual_path_output} <= 65536 )) || return 1
    mapfile -t actual_paths <<< "${actual_path_output}"
    [[ ${#actual_paths[@]} -eq ${#acme_stage_repair_expected_paths[@]} ]] || return 1
    for index in "${!acme_stage_repair_expected_paths[@]}"; do
      [[ ${actual_paths[$index]} == "${acme_stage_repair_expected_paths[$index]}" ]] || return 1
    done
    actual_path_output="$(source_repository_git "${source_directory_fd}" "${git_directory_fd}" diff-tree --no-commit-id --name-only -r "${reviewed_recovery_commit}" "${current}" 2>/dev/null)" || return 1
    (( ${#actual_path_output} <= 65536 )) || return 1
    mapfile -t actual_paths <<< "${actual_path_output}"
    [[ ${#actual_paths[@]} -eq ${#acme_stage_current_expected_paths[@]} ]] || return 1
    for index in "${!acme_stage_current_expected_paths[@]}"; do
      [[ ${actual_paths[$index]} == "${acme_stage_current_expected_paths[$index]}" ]] || return 1
    done
  fi
  if [[ ${failed} == "${reviewed_acme_transport_failed_bootstrap_commit}" ]]; then
    actual_path_output="$(source_repository_git "${source_directory_fd}" "${git_directory_fd}" diff-tree --no-commit-id --name-only -r "${failed}" "${reviewed_recovery_commit}" 2>/dev/null)" || return 1
    (( ${#actual_path_output} <= 65536 )) || return 1
    mapfile -t actual_paths <<< "${actual_path_output}"
    [[ ${#actual_paths[@]} -eq ${#acme_transport_repair_expected_paths[@]} ]] || return 1
    for index in "${!acme_transport_repair_expected_paths[@]}"; do
      [[ ${actual_paths[$index]} == "${acme_transport_repair_expected_paths[$index]}" ]] || return 1
    done
    actual_path_output="$(source_repository_git "${source_directory_fd}" "${git_directory_fd}" diff-tree --no-commit-id --name-only -r "${reviewed_recovery_commit}" "${reviewed_acme_transport_postfailure_parent_commit}" 2>/dev/null)" || return 1
    (( ${#actual_path_output} <= 65536 )) || return 1
    mapfile -t actual_paths <<< "${actual_path_output}"
    [[ ${#actual_paths[@]} -eq ${#acme_transport_current_expected_paths[@]} ]] || return 1
    for index in "${!acme_transport_current_expected_paths[@]}"; do
      [[ ${actual_paths[$index]} == "${acme_transport_current_expected_paths[$index]}" ]] || return 1
    done
    actual_path_output="$(source_repository_git "${source_directory_fd}" "${git_directory_fd}" diff-tree --no-commit-id --name-only -r "${reviewed_acme_transport_postfailure_parent_commit}" "${reviewed_acme_transport_postfailure_successor_commit}" 2>/dev/null)" || return 1
    (( ${#actual_path_output} <= 65536 )) || return 1
    mapfile -t actual_paths <<< "${actual_path_output}"
    [[ ${#actual_paths[@]} -eq ${#acme_transport_postfailure_current_expected_paths[@]} ]] || return 1
    for index in "${!acme_transport_postfailure_current_expected_paths[@]}"; do
      [[ ${actual_paths[$index]} == "${acme_transport_postfailure_current_expected_paths[$index]}" ]] || return 1
    done
    actual_path_output="$(source_repository_git "${source_directory_fd}" "${git_directory_fd}" diff-tree --no-commit-id --name-only -r "${reviewed_acme_transport_postfailure_successor_commit}" "${reviewed_acme_transport_current_main_commit}" 2>/dev/null)" || return 1
    (( ${#actual_path_output} <= 65536 )) || return 1
    mapfile -t actual_paths <<< "${actual_path_output}"
    [[ ${#actual_paths[@]} -eq ${#acme_transport_current_main_expected_paths[@]} ]] || return 1
    for index in "${!acme_transport_current_main_expected_paths[@]}"; do
      [[ ${actual_paths[$index]} == "${acme_transport_current_main_expected_paths[$index]}" ]] || return 1
    done
    actual_path_output="$(source_repository_git "${source_directory_fd}" "${git_directory_fd}" diff-tree --no-commit-id --name-only -r "${reviewed_acme_transport_current_main_commit}" "${current}" 2>/dev/null)" || return 1
    (( ${#actual_path_output} <= 65536 )) || return 1
    mapfile -t actual_paths <<< "${actual_path_output}"
    [[ ${#actual_paths[@]} -eq ${#acme_transport_lineage_repair_expected_paths[@]} ]] || return 1
    for index in "${!acme_transport_lineage_repair_expected_paths[@]}"; do
      [[ ${actual_paths[$index]} == "${acme_transport_lineage_repair_expected_paths[$index]}" ]] || return 1
    done
    actual_path_output="$(source_repository_git "${source_directory_fd}" "${git_directory_fd}" diff-tree --no-commit-id --name-only -r "${reviewed_acme_transport_postfailure_successor_commit}" "${current}" 2>/dev/null)" || return 1
    (( ${#actual_path_output} <= 65536 )) || return 1
    mapfile -t actual_paths <<< "${actual_path_output}"
    [[ ${#actual_paths[@]} -eq ${#acme_transport_current_main_expected_paths[@]} ]] || return 1
    for index in "${!acme_transport_current_main_expected_paths[@]}"; do
      [[ ${actual_paths[$index]} == "${acme_transport_current_main_expected_paths[$index]}" ]] || return 1
    done
    actual_path_output="$(source_repository_git "${source_directory_fd}" "${git_directory_fd}" diff-tree --no-commit-id --name-only -r "${reviewed_acme_transport_postfailure_parent_commit}" "${current}" 2>/dev/null)" || return 1
    (( ${#actual_path_output} <= 65536 )) || return 1
    mapfile -t actual_paths <<< "${actual_path_output}"
    [[ ${#actual_paths[@]} -eq ${#acme_transport_postfailure_current_expected_paths[@]} ]] || return 1
    for index in "${!acme_transport_postfailure_current_expected_paths[@]}"; do
      [[ ${actual_paths[$index]} == "${acme_transport_postfailure_current_expected_paths[$index]}" ]] || return 1
    done
  fi
  actual_path_output="$(source_repository_git "${source_directory_fd}" "${git_directory_fd}" diff-tree --no-commit-id --name-only -r "${failed}" "${current}" 2>/dev/null)" || return 1
  (( ${#actual_path_output} <= 65536 )) || return 1
  mapfile -t actual_paths <<< "${actual_path_output}"
  [[ ${#actual_paths[@]} -eq ${#expected_paths[@]} ]] || return 1
  for index in "${!expected_paths[@]}"; do
    [[ ${actual_paths[$index]} == "${expected_paths[$index]}" ]] || return 1
  done
  validate_source_repository_clean_state "${source_directory_fd}" "${git_directory_fd}" || return 1
  [[ "$(validated_source_repository_boundary_identity "${source_root}" "${source_directory_fd}" "${git_directory_fd}" "${config_fd}" "${info_directory_fd}" "${objects_directory_fd}" "${objects_info_directory_fd}" "${head_fd}" "${refs_directory_fd}" "${heads_directory_fd}" "${main_ref_fd}" "${index_fd}")" == "${repository_config_identity}" ]] || return 1
  validate_source_repository_operation_state "${git_directory_fd}" || return 1
  )
}

read_mutation_identity() {
  /usr/bin/python3 -I -S -B - "${deployment_journal}" <<'PY'
import hashlib
import json
import itertools
import pathlib
import re
import stat
import sys

path = pathlib.Path(sys.argv[1])
try:
    metadata = path.lstat()
except OSError as error:
    raise SystemExit("failed bootstrap journal is unavailable") from error
if (
    not stat.S_ISREG(metadata.st_mode)
    or stat.S_ISLNK(metadata.st_mode)
    or metadata.st_uid != 0
    or metadata.st_gid != 0
    or stat.S_IMODE(metadata.st_mode) != 0o600
    or metadata.st_nlink != 1
    or metadata.st_size <= 0
    or metadata.st_size > 65_536
):
    raise SystemExit("failed bootstrap journal is unsafe")
try:
    raw = path.read_bytes()
except OSError as error:
    raise SystemExit("failed bootstrap journal is unavailable") from error

def canonical(document):
    try:
        return (json.dumps(document, sort_keys=True, separators=(",", ":")) + "\n").encode("utf-8")
    except (RecursionError, TypeError, ValueError) as error:
        raise SystemExit("failed bootstrap journal is malformed") from error

def reject_duplicate(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate key")
        result[key] = value
    return result

try:
    document = json.loads(raw.decode("utf-8"), object_pairs_hook=reject_duplicate)
except (UnicodeDecodeError, ValueError, json.JSONDecodeError, RecursionError) as error:
    raise SystemExit("failed bootstrap journal is malformed") from error
if not isinstance(document, dict):
    raise SystemExit("failed bootstrap journal is malformed")
keys = {
    "schemaVersion", "phase", "recordedAt", "updatedAt", "deploymentMode",
    "repositoryCommit", "productionConfigurationSha256", "releaseArchiveSha256",
    "requestedDiscourseConnect", "targetAppConfigurationFile",
    "targetAppConfigurationSha256", "targetRestoreConfigurationFile",
    "targetRestoreConfigurationSha256", "targetActivationConfigurationFile",
    "targetActivationConfigurationSha256", "previousRepositoryCommit",
    "previousProductionConfigurationSha256", "previousCurrentReleaseSha256",
    "previousAppConfigurationFile", "previousAppConfigurationSha256",
    "previousCurrentTarget", "activeConfigurationFile", "activeConfigurationSha256",
    "launcherOperationToken", "launcherPreviousImageId", "launcherCommand",
    "databaseMutationPossible", "applicationStopped",
}
canonical_raw = canonical(document)
previous = (
    "previousRepositoryCommit", "previousProductionConfigurationSha256",
    "previousCurrentReleaseSha256", "previousAppConfigurationFile",
    "previousAppConfigurationSha256", "previousCurrentTarget",
)
repository_commit = document.get("repositoryCommit")
production_configuration_sha = document.get("productionConfigurationSha256")
release_archive_sha = document.get("releaseArchiveSha256")
target_app_configuration = document.get("targetAppConfigurationFile")
expected_target_app_configuration = (
    f"/var/discourse/containers/releases/{repository_commit}/"
    f"{production_configuration_sha}/app.yml"
)
if (
    set(document) != keys
    or raw != canonical_raw
    or type(document.get("schemaVersion")) is not int
    or document.get("schemaVersion") != 1
    or document.get("phase") != "runtime-contained"
    or document.get("deploymentMode") != "bootstrap"
    or not isinstance(repository_commit, str)
    or re.fullmatch(r"[0-9a-f]{40}", repository_commit) is None
    or not isinstance(production_configuration_sha, str)
    or re.fullmatch(r"[0-9a-f]{64}", production_configuration_sha) is None
    or not isinstance(release_archive_sha, str)
    or re.fullmatch(r"[0-9a-f]{64}", release_archive_sha) is None
    or document.get("requestedDiscourseConnect") is not False
    or any(document.get(key) is not None for key in previous)
    or document.get("targetActivationConfigurationFile") is not None
    or document.get("targetActivationConfigurationSha256") is not None
    or not isinstance(target_app_configuration, str)
    or target_app_configuration != expected_target_app_configuration
    or document.get("activeConfigurationFile") != target_app_configuration
    or document.get("activeConfigurationSha256") != document.get("targetAppConfigurationSha256")
    or document.get("launcherOperationToken") is not None
    or document.get("launcherPreviousImageId") is not None
    or document.get("launcherCommand") is not None
    or document.get("databaseMutationPossible") is not True
    or document.get("applicationStopped") is not True
):
    raise SystemExit("failed bootstrap journal tuple differs")
output = (
    "\n".join(
        (
            repository_commit,
            production_configuration_sha,
            release_archive_sha,
            target_app_configuration,
            hashlib.sha256(raw).hexdigest(),
        )
    )
    + "\n"
).encode("utf-8")
sys.stdout.buffer.write(output)
PY
}

validate_quarantine_environment() {
  local app_inventory cleanup_inventory
  [[ -d ${state_root} && ! -L ${state_root} && "$(stat -c '%U:%G %a' -- "${state_root}")" == "root:root 755" ]] || return 1
  [[ -d ${evidence_root} && ! -L ${evidence_root} && "$(stat -c '%U:%G %a' -- "${evidence_root}")" == "root:root 700" ]] || return 1
  [[ -d ${shared_root} && ! -L ${shared_root} ]] || return 1
  if [[ -e ${recovery_root} || -L ${recovery_root} ]]; then
    [[ -d ${recovery_root} && ! -L ${recovery_root} && "$(stat -c '%U:%G %a' -- "${recovery_root}")" == "root:root 700" ]] || return 1
  fi
  [[ ! -e /var/lib/mochirii/forums/current-release.json && ! -L /var/lib/mochirii/forums/current-release.json ]] || return 1
  [[ ! -e /opt/mochirii/forums/current && ! -L /opt/mochirii/forums/current ]] || return 1
  [[ ! -e /var/discourse/containers/app.yml && ! -L /var/discourse/containers/app.yml ]] || return 1
  app_inventory="$(bounded 20s docker container ls --all --filter 'name=^/app$' --format '{{.Names}}' 2>/dev/null)" || return 1
  (( ${#app_inventory} <= 64 )) || return 1
  [[ -z ${app_inventory} ]] || return 1
  for path in \
    "${state_root}/deployment-transaction.json" \
    "${state_root}/deployment-forward-fix-required.json" \
    "${state_root}/current-deployment.json" \
    "${state_root}/backup-transaction.json" \
    "${state_root}/restore-transaction.json" \
    "${state_root}/media-certificate-install.pending.json" \
    "${state_root}/media-certificate-preparation.pending.json" \
    "${state_root}/media-certificate-rotation.pending.json" \
    "${state_root}/acme-challenge-transaction.json"; do
    [[ ! -e ${path} && ! -L ${path} ]] || return 1
  done
  cleanup_inventory="$(bounded 10s find "${evidence_root}" -maxdepth 1 \
    \( -name '*-storage-cleanup-required.json' -o -name '*-backup-upload-cleanup-required.json' \) \
    -print -quit 2>/dev/null)" || return 1
  (( ${#cleanup_inventory} <= 4096 )) || return 1
  [[ -z ${cleanup_inventory} ]]
}

read_quarantine_identity() {
  local kind="$1" current="$2" failed="$3"
  /usr/bin/python3 -I -S -B - "${kind}" "${pending_journal}" "${evidence_root}" "${current}" "${failed}" \
    "${standalone_root}" "${recovery_root}" "${deployment_journal}" <<'PY'
import hashlib
import itertools
import json
import os
import pathlib
import re
import stat
import sys

kind, pending_name, evidence_name, current, failed, standalone_name, recovery_name, mutation_name = sys.argv[1:9]
pending = pathlib.Path(pending_name)
evidence = pathlib.Path(evidence_name)
standalone = pathlib.Path(standalone_name)
recovery = pathlib.Path(recovery_name)
mutation = pathlib.Path(mutation_name)
sha_pattern = r"[0-9a-f]{64}"
timestamp_pattern = re.compile(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,6})?Z")
base_keys = {
    "schemaVersion", "operation", "phase", "recordedAt", "updatedAt",
    "currentControlCommit", "failedReleaseCommit", "mutationSha256",
    "standalonePath", "quarantinePath", "mutationEvidencePath",
    "standaloneUid", "standaloneGid", "standaloneMode", "sslPresent",
}
phase_order = {"prepared": 0, "runtime-quarantined": 1, "clean-boundary": 2, "authority-retired": 3}

def canonical(document):
    try:
        return (json.dumps(document, sort_keys=True, separators=(",", ":")) + "\n").encode("utf-8")
    except (RecursionError, TypeError, ValueError) as error:
        raise SystemExit("failed-bootstrap recovery evidence is noncanonical") from error

def reject_duplicate(pairs):
    document = {}
    for key, value in pairs:
        if key in document:
            raise ValueError("duplicate key")
        document[key] = value
    return document

def publication_staging(path):
    return path.with_name(f".{path.name}.publish")

def publication_alias(path, metadata, allow_candidate):
    staging = publication_staging(path)
    try:
        staging_metadata = staging.lstat()
    except FileNotFoundError:
        if metadata.st_nlink == 1:
            return None, None
        raise SystemExit("failed-bootstrap recovery evidence is unsafe")
    except OSError as error:
        raise SystemExit("failed-bootstrap recovery evidence is unsafe") from error
    if metadata.st_nlink == 1:
        if (
            not allow_candidate
            or not stat.S_ISREG(staging_metadata.st_mode)
            or stat.S_ISLNK(staging_metadata.st_mode)
            or staging_metadata.st_uid != 0
            or staging_metadata.st_gid != 0
            or stat.S_IMODE(staging_metadata.st_mode) != 0o600
            or staging_metadata.st_nlink != 1
            or staging_metadata.st_size <= 0
            or staging_metadata.st_size > 65_536
        ):
            raise SystemExit("failed-bootstrap recovery evidence is unsafe")
        return None, staging
    if metadata.st_nlink != 2:
        raise SystemExit("failed-bootstrap recovery evidence is unsafe")
    if (
        not stat.S_ISREG(staging_metadata.st_mode)
        or stat.S_ISLNK(staging_metadata.st_mode)
        or staging_metadata.st_uid != 0
        or staging_metadata.st_gid != 0
        or stat.S_IMODE(staging_metadata.st_mode) != 0o600
        or staging_metadata.st_nlink != 2
        or staging_metadata.st_dev != metadata.st_dev
        or staging_metadata.st_ino != metadata.st_ino
        or staging_metadata.st_size != metadata.st_size
    ):
        raise SystemExit("failed-bootstrap recovery evidence is unsafe")
    return staging, None

def decode_exact(raw):
    try:
        document = json.loads(raw.decode("utf-8"), object_pairs_hook=reject_duplicate)
    except (UnicodeDecodeError, ValueError, json.JSONDecodeError, RecursionError) as error:
        raise SystemExit("failed-bootstrap recovery evidence is malformed") from error
    if not isinstance(document, dict):
        raise SystemExit("failed-bootstrap recovery evidence is malformed")
    canonical_raw = canonical(document)
    if raw != canonical_raw:
        raise SystemExit("failed-bootstrap recovery evidence is noncanonical")
    return document

def read_exact(path, allow_candidate=False):
    try:
        metadata = path.lstat()
    except OSError as error:
        raise SystemExit("failed-bootstrap recovery evidence is unavailable") from error
    staging, candidate = publication_alias(path, metadata, allow_candidate)
    if (
        not stat.S_ISREG(metadata.st_mode)
        or stat.S_ISLNK(metadata.st_mode)
        or metadata.st_uid != 0
        or metadata.st_gid != 0
        or stat.S_IMODE(metadata.st_mode) != 0o600
        or metadata.st_size <= 0
        or metadata.st_size > 65_536
    ):
        raise SystemExit("failed-bootstrap recovery evidence is unsafe")
    try:
        raw = path.read_bytes()
    except OSError as error:
        raise SystemExit("failed-bootstrap recovery evidence is unavailable") from error
    return decode_exact(raw), staging, candidate, raw

def read_candidate(path):
    try:
        metadata = path.lstat()
        if (
            not stat.S_ISREG(metadata.st_mode)
            or stat.S_ISLNK(metadata.st_mode)
            or metadata.st_uid != 0
            or metadata.st_gid != 0
            or stat.S_IMODE(metadata.st_mode) != 0o600
            or metadata.st_nlink != 1
            or metadata.st_size <= 0
            or metadata.st_size > 65_536
        ):
            raise SystemExit("failed-bootstrap recovery evidence is unsafe")
        raw = path.read_bytes()
        final_metadata = path.lstat()
    except OSError as error:
        raise SystemExit("failed-bootstrap recovery evidence is unavailable") from error
    if (
        final_metadata.st_dev != metadata.st_dev
        or final_metadata.st_ino != metadata.st_ino
        or final_metadata.st_nlink != 1
        or final_metadata.st_uid != 0
        or final_metadata.st_gid != 0
        or stat.S_IMODE(final_metadata.st_mode) != 0o600
        or final_metadata.st_size != len(raw)
    ):
        raise SystemExit("failed-bootstrap recovery evidence is unsafe")
    return decode_exact(raw)

def path_exists(path):
    try:
        path.lstat()
        return True
    except FileNotFoundError:
        return False
    except OSError as error:
        raise SystemExit("failed-bootstrap recovery authority differs") from error

def read_authority(path, digest, links):
    try:
        metadata = path.lstat()
        if (
            not stat.S_ISREG(metadata.st_mode)
            or stat.S_ISLNK(metadata.st_mode)
            or metadata.st_uid != 0
            or metadata.st_gid != 0
            or stat.S_IMODE(metadata.st_mode) != 0o600
            or metadata.st_nlink not in links
            or metadata.st_size <= 0
            or metadata.st_size > 65_536
        ):
            raise SystemExit("failed-bootstrap recovery authority differs")
        raw = path.read_bytes()
        final_metadata = path.lstat()
    except OSError as error:
        raise SystemExit("failed-bootstrap recovery authority differs") from error
    if (
        final_metadata.st_dev != metadata.st_dev
        or final_metadata.st_ino != metadata.st_ino
        or final_metadata.st_uid != metadata.st_uid
        or final_metadata.st_gid != metadata.st_gid
        or final_metadata.st_mode != metadata.st_mode
        or final_metadata.st_nlink != metadata.st_nlink
        or final_metadata.st_size != len(raw)
        or hashlib.sha256(raw).hexdigest() != digest
    ):
        raise SystemExit("failed-bootstrap recovery authority differs")
    try:
        decode_exact(raw)
    except SystemExit as error:
        raise SystemExit("failed-bootstrap recovery authority differs") from error
    return metadata, raw

def observe_authority(document, candidate=None):
    digest = document["mutationSha256"]
    retained = pathlib.Path(document["mutationEvidencePath"])
    active_exists = path_exists(mutation)
    retained_exists = path_exists(retained)
    if active_exists and not retained_exists:
        read_authority(mutation, digest, {1})
        authority_state = "active"
    elif active_exists and retained_exists:
        active_metadata, active_raw = read_authority(mutation, digest, {2})
        retained_metadata, retained_raw = read_authority(retained, digest, {2})
        if (
            active_metadata.st_dev != retained_metadata.st_dev
            or active_metadata.st_ino != retained_metadata.st_ino
            or active_raw != retained_raw
        ):
            raise SystemExit("failed-bootstrap recovery authority differs")
        authority_state = "retiring"
    elif not active_exists and retained_exists:
        read_authority(retained, digest, {1})
        authority_state = "retired"
    else:
        raise SystemExit("failed-bootstrap recovery authority differs")

    phase = document["phase"]
    candidate_phase = None if candidate is None else candidate["phase"]
    if phase in {"prepared", "runtime-quarantined"}:
        allowed = {"active"}
    elif phase == "clean-boundary":
        allowed = (
            {"active", "retiring", "retired"}
            if candidate_phase == "authority-retired"
            else {"active"}
        )
    elif phase in {"authority-retired", "complete"}:
        allowed = {"retired"}
    else:
        raise SystemExit("failed-bootstrap recovery authority differs")
    if authority_state not in allowed:
        raise SystemExit("failed-bootstrap recovery authority differs")

def valid_base(document, phases):
    mode = document.get("standaloneMode")
    uid = document.get("standaloneUid")
    gid = document.get("standaloneGid")
    mutation_sha = document.get("mutationSha256")
    return (
        type(document.get("schemaVersion")) is int
        and document.get("schemaVersion") == 1
        and document.get("operation") == "failed-bootstrap-quarantine"
        and document.get("phase") in phases
        and document.get("currentControlCommit") == current
        and document.get("failedReleaseCommit") == failed
        and type(mutation_sha) is str
        and re.fullmatch(sha_pattern, mutation_sha) is not None
        and document.get("standalonePath") == str(standalone)
        and document.get("quarantinePath") == str(recovery / f"{failed}-{mutation_sha}")
        and document.get("mutationEvidencePath") == str(
            evidence / f"{failed}-{mutation_sha}-deployment-mutation.json"
        )
        and timestamp_pattern.fullmatch(str(document.get("recordedAt", ""))) is not None
        and timestamp_pattern.fullmatch(str(document.get("updatedAt", ""))) is not None
        and type(uid) is int and 0 <= uid <= 2_147_483_647
        and type(gid) is int and 0 <= gid <= 2_147_483_647
        and type(mode) is int and 0 <= mode <= 0o777
        and mode & 0o700 == 0o700 and mode & 0o002 == 0
        and type(document.get("sslPresent")) is bool
    )

if kind == "pending":
    selected = pending
    document, staging, candidate, raw = read_exact(selected, allow_candidate=True)
    if set(document) != base_keys or not valid_base(document, {"prepared", "runtime-quarantined", "clean-boundary", "authority-retired"}):
        raise SystemExit("failed-bootstrap pending identity differs")
    if staging is not None and document["phase"] != "prepared":
        raise SystemExit("failed-bootstrap pending publication transition differs")
    candidate_document = None
    if candidate is not None:
        candidate_document = read_candidate(candidate)
        if (
            set(candidate_document) != base_keys
            or not valid_base(candidate_document, set(phase_order))
            or phase_order[document["phase"]] >= len(phase_order) - 1
        ):
            raise SystemExit("failed-bootstrap pending publication transition differs")
        expected_phase = tuple(phase_order)[phase_order[document["phase"]] + 1]
        expected_candidate = {
            **document,
            "phase": expected_phase,
            "updatedAt": candidate_document["updatedAt"],
        }
        if candidate_document != expected_candidate:
            raise SystemExit("failed-bootstrap pending publication transition differs")
    observe_authority(document, candidate_document)
elif kind == "terminal":
    try:
        metadata = evidence.lstat()
        entries = list(itertools.islice(evidence.iterdir(), 4097))
    except OSError as error:
        raise SystemExit("failed-bootstrap terminal inventory is unavailable") from error
    if (
        not stat.S_ISDIR(metadata.st_mode)
        or stat.S_ISLNK(metadata.st_mode)
        or metadata.st_uid != 0
        or metadata.st_gid != 0
        or stat.S_IMODE(metadata.st_mode) != 0o700
        or len(entries) > 4096
    ):
        raise SystemExit("failed-bootstrap terminal inventory is unsafe")
    name_pattern = re.compile(rf"{re.escape(failed)}-({sha_pattern})-failed-bootstrap-quarantine\.json")
    matches = [entry for entry in entries if name_pattern.fullmatch(entry.name)]
    if len(matches) != 1:
        raise SystemExit("failed-bootstrap terminal identity is ambiguous")
    selected = matches[0]
    document, staging, candidate, raw = read_exact(selected)
    if (
        set(document) != base_keys | {"completedAt", "sslRestored"}
        or not valid_base(document, {"complete"})
        or timestamp_pattern.fullmatch(str(document.get("completedAt", ""))) is None
        or document.get("sslRestored") is not document.get("sslPresent")
        or name_pattern.fullmatch(matches[0].name).group(1) != document.get("mutationSha256")
    ):
        raise SystemExit("failed-bootstrap terminal identity differs")
    if candidate is not None:
        raise SystemExit("failed-bootstrap terminal publication staging is unsafe")
    observe_authority(document)
else:
    raise SystemExit("failed-bootstrap recovery identity kind differs")

print(document["currentControlCommit"])
print(document["failedReleaseCommit"])
print(document["mutationSha256"])
PY
}

validate_failed_bootstrap_state() {
  local current="$1" failed configuration archive_sha target_app journal_sha release_helper terminal_staging
  local -a identity inspection
  readarray -t identity < <(read_mutation_identity) || return 1
  [[ ${#identity[@]} -eq 5 ]] || return 1
  failed="${identity[0]}"
  configuration="${identity[1]}"
  archive_sha="${identity[2]}"
  target_app="${identity[3]}"
  journal_sha="${identity[4]}"
  validate_source_lineage "${current}" "${failed}" || return 1
  release_helper="/opt/mochirii/forums/releases/${failed}/scripts/deployment-mutation.py"
  [[ -f ${release_helper} && ! -L ${release_helper} ]] || return 1
  readarray -t inspection < <(/usr/bin/python3 -I -S -B "${release_helper}" inspect --path "${deployment_journal}" \
    --mode bootstrap --commit "${failed}" --configuration "${configuration}" \
    --archive-sha "${archive_sha}" --requested-connect false) || return 1
  [[ ${#inspection[@]} -eq 14 ]] || return 1
  [[ ${inspection[0]} == runtime-contained && ${inspection[7]} == "${target_app}" && ${inspection[8]} == "${configuration}" ]] || return 1
  for index in 1 2 3 4 5 6 9 10 11; do [[ ${inspection[$index]} == - ]] || return 1; done
  [[ ${inspection[12]} == true && ${inspection[13]} == true ]] || return 1
  validate_quarantine_environment || return 1
  [[ -d ${standalone_root} && ! -L ${standalone_root} ]] || return 1
  [[ -d ${standalone_root}/postgres_data && ! -L ${standalone_root}/postgres_data ]] || return 1
  [[ ! -e ${standalone_root}/ssl || ( -d ${standalone_root}/ssl && ! -L ${standalone_root}/ssl ) ]] || return 1
  [[ ! -e ${pending_journal} && ! -L ${pending_journal} ]] || return 1
  for path in \
    "${recovery_root}/${failed}-${journal_sha}" \
    "${evidence_root}/${failed}-${journal_sha}-deployment-mutation.json" \
    "${evidence_root}/${failed}-${journal_sha}-failed-bootstrap-quarantine.json"; do
    [[ ! -e ${path} && ! -L ${path} ]] || return 1
  done
  terminal_staging="${evidence_root}/.${failed}-${journal_sha}-failed-bootstrap-quarantine.json.publish"
  [[ ! -e ${terminal_staging} && ! -L ${terminal_staging} ]] || return 1
  printf '%s\n%s\n' "${failed}" "${journal_sha}"
}

[[ ${EUID} -eq 0 ]] || fail "Failed-bootstrap quarantine must run as root."
if [[ ${1:-} == --upgrade-preflight ]]; then
  [[ $# -eq 2 && $2 =~ ^[0-9a-f]{40}$ ]] || fail "Failed-bootstrap upgrade preflight arguments differ."
  readarray -t preflight < <(validate_failed_bootstrap_state "$2") || fail "Failed-bootstrap upgrade preflight rejected the retained state."
  [[ ${#preflight[@]} -eq 2 ]] || fail "Failed-bootstrap upgrade preflight output differs."
  printf '%s\n' "${preflight[0]}"
  exit 0
fi

[[ $# -eq 3 ]] || fail "Usage: mochirii-forums-quarantine-failed-bootstrap CURRENT_COMMIT FAILED_COMMIT 'QUARANTINE FAILED MOCHIRII FORUMS BOOTSTRAP'"
current_commit="$1"
failed_commit="$2"
confirmation="$3"
[[ ${current_commit} =~ ^[0-9a-f]{40}$ && ${failed_commit} =~ ^[0-9a-f]{40}$ ]] || fail "Failed-bootstrap quarantine commit is malformed."
[[ ${confirmation} == "QUARANTINE FAILED MOCHIRII FORUMS BOOTSTRAP" ]] || fail "Exact failed-bootstrap quarantine confirmation is required."
[[ ${SUDO_USER:-} == mochirii-forums-operator && -n ${SSH_CONNECTION:-} ]] || fail "Failed-bootstrap quarantine requires the separately authenticated operator SSH session."

lock_helper=/usr/local/libexec/mochirii-forums/host-operation-lock.py
if /usr/bin/python3 -I -S -B "${lock_helper}" assert-held --locks primary,media 2>/dev/null; then
  :
else
  lock_status=$?
  [[ ${lock_status} -eq 3 ]] || fail "Host operation lock context is invalid."
  exec /usr/bin/python3 -I -S -B "${lock_helper}" run --locks primary,media -- /bin/bash "$0" "$@"
fi

if [[ -e ${pending_journal} || -L ${pending_journal} ]]; then
  validate_source_lineage "${current_commit}" "${failed_commit}" || fail "Failed-bootstrap pending recovery source lineage differs before identity repair."
  readarray -t recovery_identity < <(read_quarantine_identity pending "${current_commit}" "${failed_commit}") || fail "Failed-bootstrap pending recovery identity was rejected."
  [[ ${#recovery_identity[@]} -eq 3 && ${recovery_identity[0]} == "${current_commit}" && ${recovery_identity[1]} == "${failed_commit}" && ${recovery_identity[2]} =~ ^[0-9a-f]{64}$ ]] || fail "Failed-bootstrap pending recovery tuple differs."
  preflight=("${failed_commit}" "${recovery_identity[2]}")
  validate_source_lineage "${current_commit}" "${failed_commit}" || fail "Failed-bootstrap pending recovery source lineage differs after identity repair."
elif [[ -e ${deployment_journal} || -L ${deployment_journal} ]]; then
  readarray -t preflight < <(validate_failed_bootstrap_state "${current_commit}") || fail "Failed-bootstrap quarantine rejected the retained state."
else
  validate_source_lineage "${current_commit}" "${failed_commit}" || fail "Failed-bootstrap terminal recovery source lineage differs before identity repair."
  readarray -t recovery_identity < <(read_quarantine_identity terminal "${current_commit}" "${failed_commit}") || fail "Failed-bootstrap terminal recovery identity was rejected."
  [[ ${#recovery_identity[@]} -eq 3 && ${recovery_identity[0]} == "${current_commit}" && ${recovery_identity[1]} == "${failed_commit}" && ${recovery_identity[2]} =~ ^[0-9a-f]{64}$ ]] || fail "Failed-bootstrap terminal recovery tuple differs."
  preflight=("${failed_commit}" "${recovery_identity[2]}")
  validate_source_lineage "${current_commit}" "${failed_commit}" || fail "Failed-bootstrap terminal recovery source lineage differs after identity repair."
fi
[[ ${#preflight[@]} -eq 2 && ${preflight[0]} == "${failed_commit}" && ${preflight[1]} =~ ^[0-9a-f]{64}$ ]] || fail "Failed-bootstrap quarantine tuple differs."
validate_quarantine_environment || fail "Failed-bootstrap quarantine environment differs."
# BEGIN_FAILED_BOOTSTRAP_BOUND_VERIFIER_TRANSACTION
shopt -u varredir_close
exec {source_verifier_fd}<"${source_root}/scripts/verify-host-security.sh" || fail "Current host-control verifier could not be held."
validate_bound_source_repository_file "${current_commit}" scripts/verify-host-security.sh "${source_verifier_fd}" || fail "Current host-control verifier differs before failed-bootstrap quarantine."
/usr/bin/env -i PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin LC_ALL=C HOME=/nonexistent \
  /bin/bash --noprofile --norc "/proc/self/fd/${source_verifier_fd}" "${current_commit}" "${source_root}" \
  >/dev/null 2>&1 || fail "Current host controls failed before failed-bootstrap quarantine."
[[ "$(bounded 20s systemctl is-enabled mochirii-forums-media-certificate-renew.timer 2>/dev/null)" == enabled ]] || fail "Certificate renewal timer is not enabled before failed-bootstrap quarantine."
[[ "$(bounded 20s systemctl is-active mochirii-forums-media-certificate-renew.timer 2>/dev/null)" == active ]] || fail "Certificate renewal timer is not active before failed-bootstrap quarantine."

/usr/bin/python3 -I -S -B - "${pending_journal}" "${deployment_journal}" "${evidence_root}" "${shared_root}" \
  "${standalone_root}" "${recovery_root}" "${current_commit}" "${failed_commit}" "${preflight[1]}" <<'PY'
# BEGIN_FAILED_BOOTSTRAP_QUARANTINE_TRANSACTION
import datetime as dt
import ctypes
import hashlib
import itertools
import json
import os
import pathlib
import re
import stat
import sys

pending, mutation, evidence_root, shared_root, standalone, recovery_root = map(pathlib.Path, sys.argv[1:7])
current, failed, mutation_sha = sys.argv[7:10]
if not re.fullmatch(r"[0-9a-f]{40}", current) or not re.fullmatch(r"[0-9a-f]{40}", failed) or not re.fullmatch(r"[0-9a-f]{64}", mutation_sha):
    raise SystemExit("failed-bootstrap quarantine identity is malformed")
quarantine = recovery_root / f"{failed}-{mutation_sha}"
mutation_evidence = evidence_root / f"{failed}-{mutation_sha}-deployment-mutation.json"
terminal = evidence_root / f"{failed}-{mutation_sha}-failed-bootstrap-quarantine.json"
phase_order = {"prepared": 0, "runtime-quarantined": 1, "clean-boundary": 2, "authority-retired": 3}

def categorical_io_failure(exception_type, exception, traceback):
    if issubclass(exception_type, OSError):
        sys.stderr.write("failed-bootstrap quarantine transaction failed\n")
        return
    sys.__excepthook__(exception_type, exception, traceback)

sys.excepthook = categorical_io_failure

def now():
    return dt.datetime.now(dt.timezone.utc).isoformat().replace("+00:00", "Z")

def fsync_directory(path):
    descriptor = os.open(path, os.O_RDONLY | os.O_DIRECTORY)
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)

def persist_directory(path):
    fsync_directory(path)
    fsync_directory(path.parent)

def durable_directory_move(source, destination):
    os.rename(source, destination)
    fsync_directory(destination.parent)
    fsync_directory(source.parent)

def exact_directory(path, label):
    try:
        metadata = path.lstat()
    except OSError as error:
        raise SystemExit(f"{label} is unavailable") from error
    if not stat.S_ISDIR(metadata.st_mode) or stat.S_ISLNK(metadata.st_mode):
        raise SystemExit(f"{label} is unsafe")
    return metadata

def publication_staging(path):
    return path.with_name(f".{path.name}.publish")

def publication_alias(path, metadata, label):
    if path not in {pending, terminal}:
        if metadata.st_nlink != 1:
            raise SystemExit(f"{label} is unsafe")
        return None, None
    staging = publication_staging(path)
    try:
        staging_metadata = staging.lstat()
    except FileNotFoundError:
        if metadata.st_nlink == 1:
            return None, None
        raise SystemExit(f"{label} is unsafe")
    except OSError as error:
        raise SystemExit(f"{label} is unsafe") from error
    if metadata.st_nlink == 1:
        if (
            not stat.S_ISREG(staging_metadata.st_mode)
            or stat.S_ISLNK(staging_metadata.st_mode)
            or staging_metadata.st_uid != 0
            or staging_metadata.st_gid != 0
            or stat.S_IMODE(staging_metadata.st_mode) != 0o600
            or staging_metadata.st_nlink != 1
            or staging_metadata.st_size <= 0
            or staging_metadata.st_size > 65_536
        ):
            raise SystemExit(f"{label} publication staging is unsafe")
        return None, staging
    if metadata.st_nlink != 2:
        raise SystemExit(f"{label} is unsafe")
    if (
        not stat.S_ISREG(staging_metadata.st_mode)
        or stat.S_ISLNK(staging_metadata.st_mode)
        or staging_metadata.st_uid != 0
        or staging_metadata.st_gid != 0
        or stat.S_IMODE(staging_metadata.st_mode) != 0o600
        or staging_metadata.st_nlink != 2
        or staging_metadata.st_dev != metadata.st_dev
        or staging_metadata.st_ino != metadata.st_ino
        or staging_metadata.st_size != metadata.st_size
    ):
        raise SystemExit(f"{label} is unsafe")
    return staging, None

def exact_publication_staging(path, label):
    try:
        metadata = path.lstat()
        if (
            not stat.S_ISREG(metadata.st_mode)
            or stat.S_ISLNK(metadata.st_mode)
            or metadata.st_uid != 0
            or metadata.st_gid != 0
            or stat.S_IMODE(metadata.st_mode) != 0o600
            or metadata.st_nlink != 1
            or metadata.st_size <= 0
            or metadata.st_size > 65_536
        ):
            raise SystemExit(f"{label} publication staging is unsafe")
        raw = path.read_bytes()
        final_metadata = path.lstat()
    except OSError as error:
        raise SystemExit(f"{label} publication staging is unavailable") from error
    if (
        final_metadata.st_dev != metadata.st_dev
        or final_metadata.st_ino != metadata.st_ino
        or final_metadata.st_nlink != 1
        or final_metadata.st_size != len(raw)
    ):
        raise SystemExit(f"{label} publication staging is unsafe")
    return raw

def finish_publication_alias(path, staging, raw, label):
    if staging is None:
        return
    try:
        metadata = path.lstat()
        staging_metadata = staging.lstat()
        if (
            not stat.S_ISREG(metadata.st_mode)
            or stat.S_ISLNK(metadata.st_mode)
            or metadata.st_uid != 0
            or metadata.st_gid != 0
            or stat.S_IMODE(metadata.st_mode) != 0o600
            or metadata.st_nlink != 2
            or not stat.S_ISREG(staging_metadata.st_mode)
            or stat.S_ISLNK(staging_metadata.st_mode)
            or staging_metadata.st_uid != 0
            or staging_metadata.st_gid != 0
            or stat.S_IMODE(staging_metadata.st_mode) != 0o600
            or staging_metadata.st_nlink != 2
            or metadata.st_dev != staging_metadata.st_dev
            or metadata.st_ino != staging_metadata.st_ino
            or path.read_bytes() != raw
            or staging.read_bytes() != raw
        ):
            raise SystemExit(f"{label} is unsafe")
        staging.unlink()
        fsync_directory(path.parent)
        final_metadata = path.lstat()
    except OSError as error:
        raise SystemExit(f"{label} is unsafe") from error
    if (
        final_metadata.st_dev != metadata.st_dev
        or final_metadata.st_ino != metadata.st_ino
        or final_metadata.st_nlink != 1
        or final_metadata.st_uid != 0
        or final_metadata.st_gid != 0
        or stat.S_IMODE(final_metadata.st_mode) != 0o600
    ):
        raise SystemExit(f"{label} is unsafe")

def finish_publication_update(path, staging, previous_raw, replacement_raw, label):
    try:
        metadata = path.lstat()
        staging_metadata = staging.lstat()
        if (
            not stat.S_ISREG(metadata.st_mode)
            or stat.S_ISLNK(metadata.st_mode)
            or metadata.st_uid != 0
            or metadata.st_gid != 0
            or stat.S_IMODE(metadata.st_mode) != 0o600
            or metadata.st_nlink != 1
            or not stat.S_ISREG(staging_metadata.st_mode)
            or stat.S_ISLNK(staging_metadata.st_mode)
            or staging_metadata.st_uid != 0
            or staging_metadata.st_gid != 0
            or stat.S_IMODE(staging_metadata.st_mode) != 0o600
            or staging_metadata.st_nlink != 1
            or path.read_bytes() != previous_raw
            or staging.read_bytes() != replacement_raw
        ):
            raise SystemExit(f"{label} publication update is unsafe")
        os.replace(staging, path)
        descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
        try:
            os.fsync(descriptor)
        finally:
            os.close(descriptor)
        fsync_directory(path.parent)
        final_metadata = path.lstat()
        final_raw = path.read_bytes()
    except OSError as error:
        raise SystemExit(f"{label} publication failed") from error
    if (
        not stat.S_ISREG(final_metadata.st_mode)
        or stat.S_ISLNK(final_metadata.st_mode)
        or final_metadata.st_uid != 0
        or final_metadata.st_gid != 0
        or stat.S_IMODE(final_metadata.st_mode) != 0o600
        or final_metadata.st_nlink != 1
        or final_metadata.st_dev != staging_metadata.st_dev
        or final_metadata.st_ino != staging_metadata.st_ino
        or final_raw != replacement_raw
    ):
        raise SystemExit(f"{label} publication readback differs")

def finish_mutation_evidence_alias(source, destination, expected_sha):
    try:
        source_metadata = source.lstat()
        destination_metadata = destination.lstat()
        if (
            not stat.S_ISREG(source_metadata.st_mode)
            or stat.S_ISLNK(source_metadata.st_mode)
            or source_metadata.st_uid != 0
            or source_metadata.st_gid != 0
            or stat.S_IMODE(source_metadata.st_mode) != 0o600
            or source_metadata.st_nlink != 2
            or not stat.S_ISREG(destination_metadata.st_mode)
            or stat.S_ISLNK(destination_metadata.st_mode)
            or destination_metadata.st_uid != 0
            or destination_metadata.st_gid != 0
            or stat.S_IMODE(destination_metadata.st_mode) != 0o600
            or destination_metadata.st_nlink != 2
            or source_metadata.st_dev != destination_metadata.st_dev
            or source_metadata.st_ino != destination_metadata.st_ino
        ):
            raise SystemExit("deployment mutation evidence retirement is unsafe")
        raw = source.read_bytes()
        if destination.read_bytes() != raw or hashlib.sha256(raw).hexdigest() != expected_sha:
            raise SystemExit("deployment mutation evidence retirement differs")
        decode_raw(raw, "deployment mutation evidence")
        fsync_directory(destination.parent)
        source.unlink()
        fsync_directory(source.parent)
        final_metadata = destination.lstat()
    except OSError as error:
        raise SystemExit("deployment mutation evidence retirement failed") from error
    if (
        final_metadata.st_dev != destination_metadata.st_dev
        or final_metadata.st_ino != destination_metadata.st_ino
        or final_metadata.st_nlink != 1
    ):
        raise SystemExit("deployment mutation evidence retirement differs")

def exact_regular(path, label, expected_sha=None):
    try:
        metadata = path.lstat()
    except OSError as error:
        raise SystemExit(f"{label} is unavailable") from error
    staging, candidate = publication_alias(path, metadata, label)
    if (
        not stat.S_ISREG(metadata.st_mode)
        or stat.S_ISLNK(metadata.st_mode)
        or metadata.st_uid != 0
        or metadata.st_gid != 0
        or metadata.st_size <= 0
        or metadata.st_size > 65_536
        or stat.S_IMODE(metadata.st_mode) != 0o600
    ):
        raise SystemExit(f"{label} is unsafe")
    try:
        raw = path.read_bytes()
    except OSError as error:
        raise SystemExit(f"{label} is unavailable") from error
    if expected_sha is not None and hashlib.sha256(raw).hexdigest() != expected_sha:
        raise SystemExit(f"{label} digest differs")
    return raw, staging, candidate

def exact_inventory(path, maximum, label):
    try:
        entries = list(itertools.islice(path.iterdir(), maximum + 1))
    except OSError as error:
        raise SystemExit(f"{label} is unavailable") from error
    if len(entries) > maximum:
        raise SystemExit(f"{label} exceeds its bounded inventory")
    return {entry.name for entry in entries}

def canonical(document, label):
    try:
        return (json.dumps(document, sort_keys=True, separators=(",", ":")) + "\n").encode("utf-8")
    except (RecursionError, TypeError, ValueError) as error:
        raise SystemExit(f"{label} is not canonical") from error

def reject_duplicate(pairs):
    document = {}
    for key, value in pairs:
        if key in document:
            raise ValueError("duplicate key")
        document[key] = value
    return document

def decode_raw(raw, label):
    try:
        document = json.loads(raw.decode("utf-8"), object_pairs_hook=reject_duplicate)
    except (UnicodeDecodeError, ValueError, json.JSONDecodeError, RecursionError) as error:
        raise SystemExit(f"{label} is malformed") from error
    if not isinstance(document, dict):
        raise SystemExit(f"{label} is malformed")
    if raw != canonical(document, label):
        raise SystemExit(f"{label} is not canonical")
    return document

def path_exists(path, label):
    try:
        path.lstat()
        return True
    except FileNotFoundError:
        return False
    except OSError as error:
        raise SystemExit(f"{label} is unavailable") from error

def exact_authority(path, label, links):
    try:
        metadata = path.lstat()
        if (
            not stat.S_ISREG(metadata.st_mode)
            or stat.S_ISLNK(metadata.st_mode)
            or metadata.st_uid != 0
            or metadata.st_gid != 0
            or stat.S_IMODE(metadata.st_mode) != 0o600
            or metadata.st_nlink not in links
            or metadata.st_size <= 0
            or metadata.st_size > 65_536
        ):
            raise SystemExit(f"{label} is unsafe")
        raw = path.read_bytes()
        final_metadata = path.lstat()
    except OSError as error:
        raise SystemExit(f"{label} is unavailable") from error
    if (
        final_metadata.st_dev != metadata.st_dev
        or final_metadata.st_ino != metadata.st_ino
        or final_metadata.st_uid != metadata.st_uid
        or final_metadata.st_gid != metadata.st_gid
        or final_metadata.st_mode != metadata.st_mode
        or final_metadata.st_nlink != metadata.st_nlink
        or final_metadata.st_size != len(raw)
        or hashlib.sha256(raw).hexdigest() != mutation_sha
    ):
        raise SystemExit(f"{label} differs")
    decode_raw(raw, label)
    return metadata, raw

def observe_mutation_authority():
    active_exists = path_exists(mutation, "deployment mutation journal")
    retained_exists = path_exists(mutation_evidence, "deployment mutation evidence")
    if active_exists and not retained_exists:
        exact_authority(mutation, "deployment mutation journal", {1})
        return "active"
    if active_exists and retained_exists:
        active_metadata, active_raw = exact_authority(
            mutation, "deployment mutation journal", {2}
        )
        retained_metadata, retained_raw = exact_authority(
            mutation_evidence, "deployment mutation evidence", {2}
        )
        if (
            active_metadata.st_dev != retained_metadata.st_dev
            or active_metadata.st_ino != retained_metadata.st_ino
            or active_raw != retained_raw
        ):
            raise SystemExit("deployment mutation evidence retirement differs")
        return "retiring"
    if not active_exists and retained_exists:
        exact_authority(mutation_evidence, "deployment mutation evidence", {1})
        return "retired"
    raise SystemExit("deployment mutation authority state differs")

def require_mutation_authority(allowed):
    authority_state = observe_mutation_authority()
    if authority_state not in allowed:
        raise SystemExit("deployment mutation authority state differs")
    return authority_state

def validate_prepared_runtime(document):
    metadata = exact_directory(standalone, "standalone root")
    if (
        metadata.st_uid != document["standaloneUid"]
        or metadata.st_gid != document["standaloneGid"]
        or stat.S_IMODE(metadata.st_mode) != document["standaloneMode"]
    ):
        raise SystemExit("standalone metadata differs")
    if path_exists(quarantine, "failed-bootstrap quarantine"):
        raise SystemExit("failed-bootstrap recovery target already exists")
    inventory = exact_inventory(standalone, 4096, "standalone inventory")
    if "postgres_data" not in inventory:
        raise SystemExit("standalone inventory differs")
    exact_directory(standalone / "postgres_data", "standalone PostgreSQL directory")
    ssl_exists = "ssl" in inventory
    if ssl_exists is not document["sslPresent"]:
        raise SystemExit("standalone SSL inventory differs")
    if ssl_exists:
        exact_directory(standalone / "ssl", "standalone SSL directory")

def validate_prepared_replay_runtime(document):
    source_exists = path_exists(standalone, "standalone root")
    target_exists = path_exists(quarantine, "failed-bootstrap quarantine")
    if source_exists and not target_exists:
        validate_prepared_runtime(document)
        return "source"
    if target_exists and not source_exists:
        metadata = exact_directory(quarantine, "failed-bootstrap quarantine")
        observed_metadata = (
            metadata.st_uid,
            metadata.st_gid,
            stat.S_IMODE(metadata.st_mode),
        )
        allowed_metadata = {
            (
                document["standaloneUid"],
                document["standaloneGid"],
                document["standaloneMode"],
            ),
            (0, 0, document["standaloneMode"]),
            (0, 0, 0o700),
        }
        if observed_metadata not in allowed_metadata:
            raise SystemExit("failed-bootstrap quarantine permissions differ")
        inventory = exact_inventory(
            quarantine, 4096, "failed-bootstrap quarantine inventory"
        )
        if "postgres_data" not in inventory:
            raise SystemExit("failed-bootstrap quarantine inventory differs")
        exact_directory(quarantine / "postgres_data", "quarantined PostgreSQL directory")
        ssl_exists = "ssl" in inventory
        if ssl_exists is not document["sslPresent"]:
            raise SystemExit("failed-bootstrap quarantine SSL inventory differs")
        if ssl_exists:
            exact_directory(quarantine / "ssl", "quarantined SSL directory")
        return "target"
    raise SystemExit("failed-bootstrap runtime quarantine state is ambiguous")

def validate_quarantined_runtime(document):
    if path_exists(standalone, "standalone root"):
        raise SystemExit("failed-bootstrap runtime quarantine state is ambiguous")
    metadata = exact_directory(quarantine, "failed-bootstrap quarantine")
    if metadata.st_uid != 0 or metadata.st_gid != 0 or stat.S_IMODE(metadata.st_mode) != 0o700:
        raise SystemExit("failed-bootstrap quarantine permissions differ")
    inventory = exact_inventory(quarantine, 4096, "failed-bootstrap quarantine inventory")
    if "postgres_data" not in inventory:
        raise SystemExit("failed-bootstrap quarantine inventory differs")
    exact_directory(quarantine / "postgres_data", "quarantined PostgreSQL directory")
    ssl_exists = "ssl" in inventory
    if ssl_exists is not document["sslPresent"]:
        raise SystemExit("failed-bootstrap quarantine SSL inventory differs")
    if ssl_exists:
        exact_directory(quarantine / "ssl", "quarantined SSL directory")

def validate_runtime_quarantined_replay(document):
    metadata = exact_directory(quarantine, "failed-bootstrap quarantine")
    if metadata.st_uid != 0 or metadata.st_gid != 0 or stat.S_IMODE(metadata.st_mode) != 0o700:
        raise SystemExit("failed-bootstrap quarantine permissions differ")
    quarantine_inventory = exact_inventory(
        quarantine, 4096, "failed-bootstrap quarantine inventory"
    )
    if "postgres_data" not in quarantine_inventory:
        raise SystemExit("failed-bootstrap quarantine inventory differs")
    exact_directory(quarantine / "postgres_data", "quarantined PostgreSQL directory")
    source_ssl_exists = "ssl" in quarantine_inventory
    if not path_exists(standalone, "clean standalone root"):
        if source_ssl_exists is not document["sslPresent"]:
            raise SystemExit("failed-bootstrap quarantine SSL inventory differs")
        if source_ssl_exists:
            exact_directory(quarantine / "ssl", "quarantined SSL directory")
        return "standalone-absent"

    standalone_metadata = exact_directory(standalone, "clean standalone root")
    observed_metadata = (
        standalone_metadata.st_uid,
        standalone_metadata.st_gid,
        stat.S_IMODE(standalone_metadata.st_mode),
    )
    allowed_metadata = {
        (0, 0, 0o700),
        (document["standaloneUid"], document["standaloneGid"], 0o700),
        (
            document["standaloneUid"],
            document["standaloneGid"],
            document["standaloneMode"],
        ),
    }
    if observed_metadata not in allowed_metadata:
        raise SystemExit("clean standalone metadata differs")
    standalone_inventory = exact_inventory(
        standalone, 1, "clean standalone partial inventory"
    )
    destination_ssl_exists = "ssl" in standalone_inventory
    if document["sslPresent"]:
        if source_ssl_exists and not destination_ssl_exists:
            if standalone_inventory:
                raise SystemExit("clean standalone partial inventory differs")
            exact_directory(quarantine / "ssl", "quarantined SSL directory")
            return "ssl-source"
        if not source_ssl_exists and destination_ssl_exists:
            if standalone_inventory != {"ssl"} or observed_metadata != (
                document["standaloneUid"],
                document["standaloneGid"],
                document["standaloneMode"],
            ):
                raise SystemExit("clean standalone partial inventory differs")
            exact_directory(standalone / "ssl", "restored SSL directory")
            return "ssl-destination"
        raise SystemExit("failed-bootstrap SSL recovery state is ambiguous")
    if source_ssl_exists or destination_ssl_exists or standalone_inventory:
        raise SystemExit("unexpected SSL directory appeared during failed-bootstrap quarantine")
    return "no-ssl"

def validate_clean_runtime(document):
    quarantine_metadata = exact_directory(quarantine, "failed-bootstrap quarantine")
    if (
        quarantine_metadata.st_uid != 0
        or quarantine_metadata.st_gid != 0
        or stat.S_IMODE(quarantine_metadata.st_mode) != 0o700
    ):
        raise SystemExit("failed-bootstrap quarantine permissions differ")
    quarantine_inventory = exact_inventory(
        quarantine, 4096, "failed-bootstrap quarantine inventory"
    )
    if "postgres_data" not in quarantine_inventory or "ssl" in quarantine_inventory:
        raise SystemExit("failed-bootstrap quarantine inventory differs")
    exact_directory(quarantine / "postgres_data", "quarantined PostgreSQL directory")
    clean_metadata = exact_directory(standalone, "clean standalone root")
    if (
        clean_metadata.st_uid != document["standaloneUid"]
        or clean_metadata.st_gid != document["standaloneGid"]
        or stat.S_IMODE(clean_metadata.st_mode) != document["standaloneMode"]
    ):
        raise SystemExit("clean standalone metadata differs")
    expected_inventory = {"ssl"} if document["sslPresent"] else set()
    if exact_inventory(standalone, 1, "clean standalone inventory") != expected_inventory:
        raise SystemExit("clean standalone inventory differs")
    if document["sslPresent"]:
        exact_directory(standalone / "ssl", "restored SSL directory")

def decode_canonical(path, label, expected_sha=None):
    raw, alias, candidate = exact_regular(path, label, expected_sha)
    document = decode_raw(raw, label)
    staged = None
    if candidate is not None:
        candidate_raw = exact_publication_staging(candidate, label)
        staged = (candidate, candidate_raw, decode_raw(candidate_raw, label))
    return raw, document, alias, staged

base_keys = {
    "schemaVersion", "operation", "phase", "recordedAt", "updatedAt",
    "currentControlCommit", "failedReleaseCommit", "mutationSha256",
    "standalonePath", "quarantinePath", "mutationEvidencePath",
    "standaloneUid", "standaloneGid", "standaloneMode", "sslPresent",
}
timestamp_pattern = re.compile(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,6})?Z")

def validate_state(document, phases, terminal_state=False):
    mode = document.get("standaloneMode")
    uid = document.get("standaloneUid")
    gid = document.get("standaloneGid")
    expected_keys = base_keys | ({"completedAt", "sslRestored"} if terminal_state else set())
    if (
        not isinstance(document, dict)
        or set(document) != expected_keys
        or type(document.get("schemaVersion")) is not int
        or document.get("schemaVersion") != 1
        or document.get("operation") != "failed-bootstrap-quarantine"
        or document.get("phase") not in phases
        or document.get("currentControlCommit") != current
        or document.get("failedReleaseCommit") != failed
        or document.get("mutationSha256") != mutation_sha
        or document.get("standalonePath") != str(standalone)
        or document.get("quarantinePath") != str(quarantine)
        or document.get("mutationEvidencePath") != str(mutation_evidence)
        or timestamp_pattern.fullmatch(str(document.get("recordedAt", ""))) is None
        or timestamp_pattern.fullmatch(str(document.get("updatedAt", ""))) is None
        or type(uid) is not int or not 0 <= uid <= 2_147_483_647
        or type(gid) is not int or not 0 <= gid <= 2_147_483_647
        or type(mode) is not int or not 0 <= mode <= 0o777
        or mode & 0o700 != 0o700 or mode & 0o002 != 0
        or type(document.get("sslPresent")) is not bool
    ):
        raise SystemExit("failed-bootstrap quarantine journal tuple differs")
    if terminal_state and (
        timestamp_pattern.fullmatch(str(document.get("completedAt", ""))) is None
        or document.get("sslRestored") is not document.get("sslPresent")
    ):
        raise SystemExit("failed-bootstrap terminal evidence tuple differs")

def validate_pending_transition(previous, candidate):
    validate_state(previous, set(phase_order))
    validate_state(candidate, set(phase_order))
    previous_index = phase_order[previous["phase"]]
    if previous_index >= len(phase_order) - 1:
        raise SystemExit("failed-bootstrap pending publication transition differs")
    expected_phase = tuple(phase_order)[previous_index + 1]
    expected = {**previous, "phase": expected_phase, "updatedAt": candidate["updatedAt"]}
    if candidate != expected:
        raise SystemExit("failed-bootstrap pending publication transition differs")

def bind_create_publication(path, requested, candidate, label):
    try:
        if path == pending:
            validate_state(candidate, {"prepared"})
            expected = {
                **requested,
                "recordedAt": candidate["recordedAt"],
                "updatedAt": candidate["updatedAt"],
            }
            timestamps_match = candidate["recordedAt"] == candidate["updatedAt"]
        elif path == terminal:
            validate_state(candidate, {"complete"}, terminal_state=True)
            expected = {**requested, "completedAt": candidate["completedAt"]}
            timestamps_match = True
        else:
            raise SystemExit(f"{label} publication staging differs")
    except (KeyError, SystemExit) as error:
        raise SystemExit(f"{label} publication staging differs") from error
    if not timestamps_match or candidate != expected:
        raise SystemExit(f"{label} publication staging differs")
    requested.clear()
    requested.update(candidate)

def link_unnamed_staging(descriptor, staging):
    try:
        linkat = ctypes.CDLL(None, use_errno=True).linkat
    except (AttributeError, OSError) as error:
        raise OSError("linkat is unavailable") from error
    linkat.argtypes = [ctypes.c_int, ctypes.c_char_p, ctypes.c_int, ctypes.c_char_p, ctypes.c_int]
    linkat.restype = ctypes.c_int
    if linkat(descriptor, b"", -100, os.fsencode(staging), 0x1000) != 0:
        error_number = ctypes.get_errno()
        raise OSError(error_number, "linkat failed")

def observe_pending_publication(document, alias, staged):
    validate_state(document, set(phase_order))
    if alias is not None and document["phase"] != "prepared":
        raise SystemExit("failed-bootstrap pending publication transition differs")
    if staged is None:
        return None
    _, _, candidate = staged
    validate_pending_transition(document, candidate)
    return candidate

def validate_pending_publication_runtime(document, alias, staged):
    candidate = observe_pending_publication(document, alias, staged)
    if alias is not None:
        require_mutation_authority({"active"})
        validate_prepared_runtime(document)
    elif candidate is not None:
        if candidate["phase"] == "runtime-quarantined":
            require_mutation_authority({"active"})
            validate_quarantined_runtime(candidate)
        elif candidate["phase"] == "clean-boundary":
            require_mutation_authority({"active"})
            validate_clean_runtime(candidate)
        elif candidate["phase"] == "authority-retired":
            validate_clean_runtime(candidate)
        else:
            raise SystemExit("failed-bootstrap pending publication transition differs")
    elif document["phase"] == "prepared":
        validate_prepared_replay_runtime(document)
    elif document["phase"] == "runtime-quarantined":
        validate_runtime_quarantined_replay(document)
    else:
        validate_clean_runtime(document)
    return candidate

def reconcile_pending_publication(raw, document, alias, staged):
    candidate = validate_pending_publication_runtime(document, alias, staged)
    if candidate is not None and candidate["phase"] == "authority-retired":
        require_mutation_authority({"retired"})
    finish_publication_alias(pending, alias, raw, "failed-bootstrap pending journal")
    if staged is None:
        return document
    staging, candidate_raw, _ = staged
    finish_publication_update(
        pending,
        staging,
        raw,
        candidate_raw,
        "failed-bootstrap pending journal",
    )
    return candidate

def publish(path, document, create, defer_update=False):
    raw = canonical(document, "failed-bootstrap quarantine document")
    staging = publication_staging(path)
    label = "failed-bootstrap pending journal" if path == pending else "failed-bootstrap terminal evidence"
    descriptor = -1
    try:
        try:
            metadata = path.lstat()
            path_exists = True
        except FileNotFoundError:
            metadata = None
            path_exists = False
        if path_exists:
            alias, candidate = publication_alias(path, metadata, label)
            if (
                not stat.S_ISREG(metadata.st_mode)
                or stat.S_ISLNK(metadata.st_mode)
                or metadata.st_uid != 0
                or metadata.st_gid != 0
                or stat.S_IMODE(metadata.st_mode) != 0o600
                or metadata.st_nlink not in {1, 2}
            ):
                raise SystemExit(f"{label} publication target is unsafe")
            previous_raw = path.read_bytes()
            if alias is not None:
                if previous_raw != raw:
                    raise SystemExit(f"{label} publication target differs")
                finish_publication_alias(path, alias, raw, label)
                return
            if candidate is not None:
                candidate_raw = exact_publication_staging(candidate, label)
                if create or candidate_raw != raw:
                    raise SystemExit(f"{label} publication staging differs")
                if defer_update:
                    return
                finish_publication_update(path, candidate, previous_raw, raw, label)
                return
            if create:
                if previous_raw != raw:
                    raise SystemExit(f"{label} publication target differs")
                return
        elif not create:
            raise SystemExit(f"{label} publication target is unavailable")

        try:
            staging.lstat()
            staging_exists = True
        except FileNotFoundError:
            staging_exists = False
        if staging_exists:
            candidate_raw = exact_publication_staging(staging, label)
            if create:
                bind_create_publication(path, document, decode_raw(candidate_raw, label), label)
                raw = candidate_raw
            elif candidate_raw != raw:
                raise SystemExit(f"{label} publication staging differs")
        else:
            flags = os.O_RDWR | os.O_TMPFILE | os.O_NOFOLLOW
            descriptor = os.open(path.parent, flags, 0o600)
            os.fchmod(descriptor, 0o600)
            os.fchown(descriptor, 0, 0)
            offset = 0
            while offset < len(raw):
                written = os.write(descriptor, raw[offset:])
                if written <= 0:
                    raise OSError("publication write failed")
                offset += written
            os.fsync(descriptor)
            link_unnamed_staging(descriptor, staging)
            fsync_directory(path.parent)
            os.close(descriptor)
            descriptor = -1

        if create:
            os.link(staging, path, follow_symlinks=False)
            fsync_directory(path.parent)
            staging.unlink()
            fsync_directory(path.parent)
        else:
            if defer_update:
                return
            finish_publication_update(path, staging, previous_raw, raw, label)
            return
        final_metadata = path.lstat()
        if (
            not stat.S_ISREG(final_metadata.st_mode)
            or stat.S_ISLNK(final_metadata.st_mode)
            or final_metadata.st_uid != 0
            or final_metadata.st_gid != 0
            or stat.S_IMODE(final_metadata.st_mode) != 0o600
            or final_metadata.st_nlink != 1
            or path.read_bytes() != raw
        ):
            raise SystemExit(f"{label} publication readback differs")
    except OSError as error:
        raise SystemExit(f"{label} publication failed") from error
    finally:
        if descriptor >= 0:
            os.close(descriptor)

def observe_recovery_root():
    if path_exists(recovery_root, "failed-bootstrap recovery root"):
        recovery_metadata = exact_directory(recovery_root, "failed-bootstrap recovery root")
        if (
            recovery_metadata.st_uid != 0
            or recovery_metadata.st_gid != 0
            or stat.S_IMODE(recovery_metadata.st_mode) != 0o700
        ):
            raise SystemExit("failed-bootstrap recovery root permissions differ")
        return

    raise SystemExit("failed-bootstrap recovery root is unavailable")

def require_recovery_root(allow_create):
    if path_exists(recovery_root, "failed-bootstrap recovery root"):
        observe_recovery_root()
        persist_directory(recovery_root)
        return
    if not allow_create:
        raise SystemExit("failed-bootstrap recovery root is unavailable")
    recovery_root.mkdir(mode=0o700)
    os.chown(recovery_root, 0, 0)
    persist_directory(recovery_root)

def validate_completed_runtime(document):
    require_mutation_authority({"retired"})
    validate_clean_runtime(document)

def expected_terminal_document(document, completed_at):
    return {
        **document,
        "phase": "complete",
        "completedAt": completed_at,
        "sslRestored": document["sslPresent"],
    }

def preflight_pending_staging():
    staging = publication_staging(pending)
    if not path_exists(staging, "failed-bootstrap pending publication staging"):
        return None
    if path_exists(pending, "failed-bootstrap pending journal"):
        return None
    try:
        if path_exists(terminal, "failed-bootstrap terminal evidence"):
            raise SystemExit("failed-bootstrap pending publication staging is unsafe")
        staging_raw = exact_publication_staging(staging, "failed-bootstrap pending journal")
        staging_document = decode_raw(staging_raw, "failed-bootstrap pending journal")
        validate_state(staging_document, {"prepared"})
        observe_recovery_root()
        require_mutation_authority({"active"})
        validate_prepared_runtime(staging_document)
    except (KeyError, SystemExit) as error:
        raise SystemExit("failed-bootstrap pending publication staging is unsafe") from error
    return staging_document

def preflight_terminal_staging():
    if path_exists(terminal, "failed-bootstrap terminal evidence"):
        return None
    staging = publication_staging(terminal)
    if not path_exists(staging, "failed-bootstrap terminal publication staging"):
        return None
    try:
        staging_raw = exact_publication_staging(staging, "failed-bootstrap terminal evidence")
        staging_document = decode_raw(staging_raw, "failed-bootstrap terminal evidence")
        validate_state(staging_document, {"complete"}, terminal_state=True)
        if not path_exists(pending, "failed-bootstrap pending journal"):
            raise SystemExit("failed-bootstrap terminal publication staging is unsafe")
        pending_raw, pending_document, pending_alias, pending_staged = decode_canonical(
            pending, "failed-bootstrap pending journal"
        )
        pending_candidate = observe_pending_publication(
            pending_document, pending_alias, pending_staged
        )
        validate_state(pending_document, {"authority-retired"})
        if pending_alias is not None or pending_candidate is not None:
            raise SystemExit("failed-bootstrap terminal publication staging is unsafe")
        expected = expected_terminal_document(
            pending_document, staging_document["completedAt"]
        )
        if staging_document != expected:
            raise SystemExit("failed-bootstrap terminal publication staging is unsafe")
        observe_recovery_root()
        validate_completed_runtime(pending_document)
    except (KeyError, SystemExit) as error:
        raise SystemExit("failed-bootstrap terminal publication staging is unsafe") from error
    return staging_document, pending_raw, pending_document

exact_directory(shared_root, "shared runtime root")
evidence_metadata = exact_directory(evidence_root, "evidence root")
if evidence_metadata.st_uid != 0 or evidence_metadata.st_gid != 0 or stat.S_IMODE(evidence_metadata.st_mode) != 0o700:
    raise SystemExit("evidence root permissions differ")

pending_staging_replay = preflight_pending_staging()
terminal_staging_replay = preflight_terminal_staging()

if path_exists(terminal, "failed-bootstrap terminal evidence"):
    terminal_raw, document, terminal_alias, terminal_staged = decode_canonical(
        terminal, "failed-bootstrap terminal evidence"
    )
    validate_state(document, {"complete"}, terminal_state=True)
    if terminal_staged is not None:
        raise SystemExit("failed-bootstrap terminal publication staging is unsafe")
    validate_completed_runtime(document)
    pending_record = None
    if path_exists(pending, "failed-bootstrap pending journal"):
        pending_raw, pending_document, pending_alias, pending_staged = decode_canonical(
            pending, "failed-bootstrap pending journal"
        )
        pending_candidate = observe_pending_publication(
            pending_document, pending_alias, pending_staged
        )
        validate_state(pending_document, {"authority-retired"})
        expected_pending = {key: document[key] for key in base_keys}
        expected_pending["phase"] = "authority-retired"
        if pending_candidate is not None or pending_document != expected_pending:
            raise SystemExit("failed-bootstrap terminal and pending journals differ")
        pending_record = pending_raw, pending_document, pending_alias, pending_staged
    require_recovery_root(False)
    fsync_directory(terminal.parent)
    finish_publication_alias(
        terminal,
        terminal_alias,
        terminal_raw,
        "failed-bootstrap terminal evidence",
    )
    if pending_record is not None:
        pending_raw, pending_document, pending_alias, pending_staged = pending_record
        reconcile_pending_publication(
            pending_raw, pending_document, pending_alias, pending_staged
        )
        pending.unlink()
    fsync_directory(pending.parent)
    raise SystemExit(0)

if terminal_staging_replay is not None:
    terminal_document, _, pending_document = terminal_staging_replay
    require_recovery_root(False)
    fsync_directory(pending.parent)
    publish(path=terminal, document=terminal_document, create=True)
    pending.unlink()
    fsync_directory(pending.parent)
    raise SystemExit(0)

pending_raw = None
pending_alias = None
pending_staged = None
pending_candidate = None
if path_exists(pending, "failed-bootstrap pending journal"):
    pending_raw, state, pending_alias, pending_staged = decode_canonical(
        pending, "failed-bootstrap pending journal"
    )
    pending_candidate = observe_pending_publication(state, pending_alias, pending_staged)
    if state["phase"] in {"prepared", "runtime-quarantined"}:
        allowed_authority = {"active"}
    elif state["phase"] == "clean-boundary":
        allowed_authority = (
            {"active", "retiring", "retired"}
            if pending_candidate is not None
            and pending_candidate["phase"] == "authority-retired"
            else {"active"}
        )
    else:
        allowed_authority = {"retired"}
    authority_state = require_mutation_authority(allowed_authority)
    pending_candidate = validate_pending_publication_runtime(
        state, pending_alias, pending_staged
    )
    require_recovery_root(False)
    fsync_directory(pending.parent)
    candidate_retires_authority = (
        pending_candidate is not None
        and pending_candidate["phase"] == "authority-retired"
    )
    if candidate_retires_authority:
        validate_clean_runtime(pending_candidate)
        if authority_state == "retired":
            fsync_directory(mutation.parent)
    if not (
        candidate_retires_authority
        and authority_state != "retired"
    ):
        state = reconcile_pending_publication(
            pending_raw, state, pending_alias, pending_staged
        )
        pending_alias = None
        pending_staged = None
        pending_candidate = None
else:
    require_mutation_authority({"active"})
    _, mutation_raw = exact_authority(mutation, "deployment mutation journal", {1})
    standalone_metadata = exact_directory(standalone, "standalone root")
    if path_exists(quarantine, "failed-bootstrap quarantine"):
        raise SystemExit("failed-bootstrap recovery target already exists")
    ssl_path = standalone / "ssl"
    ssl_present = path_exists(ssl_path, "standalone SSL directory")
    if ssl_present:
        exact_directory(ssl_path, "standalone SSL directory")
    stamp = now()
    state = {
        "schemaVersion": 1,
        "operation": "failed-bootstrap-quarantine",
        "phase": "prepared",
        "recordedAt": stamp,
        "updatedAt": stamp,
        "currentControlCommit": current,
        "failedReleaseCommit": failed,
        "mutationSha256": hashlib.sha256(mutation_raw).hexdigest(),
        "standalonePath": str(standalone),
        "quarantinePath": str(quarantine),
        "mutationEvidencePath": str(mutation_evidence),
        "standaloneUid": standalone_metadata.st_uid,
        "standaloneGid": standalone_metadata.st_gid,
        "standaloneMode": stat.S_IMODE(standalone_metadata.st_mode),
        "sslPresent": ssl_present,
    }
    validate_state(state, {"prepared"})
    validate_prepared_runtime(state)
    require_recovery_root(True)
    publish(pending, state, True)

def advance(phase):
    state["phase"] = phase
    state["updatedAt"] = now()
    validate_state(state, {phase})
    publish(pending, state, False)

if phase_order[state["phase"]] <= phase_order["prepared"]:
    prepared_location = validate_prepared_replay_runtime(state)
    if prepared_location == "source":
        durable_directory_move(standalone, quarantine)
    elif prepared_location == "target":
        fsync_directory(quarantine.parent)
        fsync_directory(standalone.parent)
    else:
        raise SystemExit("failed-bootstrap runtime quarantine state is ambiguous")
    os.chown(quarantine, 0, 0)
    os.chmod(quarantine, 0o700)
    persist_directory(quarantine)
    advance("runtime-quarantined")

if phase_order[state["phase"]] <= phase_order["runtime-quarantined"]:
    validate_runtime_quarantined_replay(state)
    if not standalone.exists() and not standalone.is_symlink():
        standalone.mkdir(mode=state["standaloneMode"])
    old_ssl = quarantine / "ssl"
    new_ssl = standalone / "ssl"
    partial_inventory = exact_inventory(standalone, 1, "clean standalone partial inventory")
    old_ssl_exists = old_ssl.exists() or old_ssl.is_symlink()
    new_ssl_exists = new_ssl.exists() or new_ssl.is_symlink()
    if state["sslPresent"]:
        if old_ssl_exists and not new_ssl_exists:
            exact_directory(old_ssl, "quarantined SSL directory")
            expected_partial_inventory = set()
        elif not old_ssl_exists and new_ssl_exists:
            exact_directory(new_ssl, "restored SSL directory")
            expected_partial_inventory = {"ssl"}
        else:
            raise SystemExit("failed-bootstrap SSL recovery state is ambiguous")
    else:
        if old_ssl_exists or new_ssl_exists:
            raise SystemExit("unexpected SSL directory appeared during failed-bootstrap quarantine")
        expected_partial_inventory = set()
    if partial_inventory != expected_partial_inventory:
        raise SystemExit("clean standalone partial inventory differs")
    os.chown(standalone, state["standaloneUid"], state["standaloneGid"])
    os.chmod(standalone, state["standaloneMode"])
    persist_directory(standalone)
    clean_metadata = exact_directory(standalone, "clean standalone root")
    if (
        clean_metadata.st_uid != state["standaloneUid"]
        or clean_metadata.st_gid != state["standaloneGid"]
        or stat.S_IMODE(clean_metadata.st_mode) != state["standaloneMode"]
    ):
        raise SystemExit("clean standalone metadata differs")
    if state["sslPresent"]:
        if (old_ssl.exists() or old_ssl.is_symlink()) and not (new_ssl.exists() or new_ssl.is_symlink()):
            exact_directory(old_ssl, "quarantined SSL directory")
            durable_directory_move(old_ssl, new_ssl)
        elif not (old_ssl.exists() or old_ssl.is_symlink()) and (new_ssl.exists() or new_ssl.is_symlink()):
            exact_directory(new_ssl, "restored SSL directory")
            fsync_directory(new_ssl.parent)
            fsync_directory(old_ssl.parent)
        else:
            raise SystemExit("failed-bootstrap SSL recovery state is ambiguous")
    elif old_ssl.exists() or old_ssl.is_symlink() or new_ssl.exists() or new_ssl.is_symlink():
        raise SystemExit("unexpected SSL directory appeared during failed-bootstrap quarantine")
    expected_inventory = {"ssl"} if state["sslPresent"] else set()
    if exact_inventory(standalone, 1, "clean standalone inventory") != expected_inventory:
        raise SystemExit("clean standalone inventory differs")
    advance("clean-boundary")

if phase_order[state["phase"]] <= phase_order["clean-boundary"]:
    pending_raw, pending_base, pending_alias, pending_staged = decode_canonical(
        pending, "failed-bootstrap pending journal"
    )
    pending_candidate = observe_pending_publication(
        pending_base, pending_alias, pending_staged
    )
    validate_state(pending_base, {"clean-boundary"})
    validate_clean_runtime(pending_base)
    if pending_candidate is None:
        pending_candidate = {
            **pending_base,
            "phase": "authority-retired",
            "updatedAt": now(),
        }
        validate_pending_transition(pending_base, pending_candidate)
        publish(pending, pending_candidate, False, defer_update=True)
        pending_raw, pending_base, pending_alias, pending_staged = decode_canonical(
            pending, "failed-bootstrap pending journal"
        )
        if pending_alias is not None:
            raise SystemExit("failed-bootstrap pending publication transition differs")
        observed_candidate = observe_pending_publication(
            pending_base, pending_alias, pending_staged
        )
        if observed_candidate != pending_candidate:
            raise SystemExit("failed-bootstrap pending publication transition differs")
    elif pending_candidate["phase"] != "authority-retired":
        raise SystemExit("failed-bootstrap pending publication transition differs")

    authority_state = require_mutation_authority({"active", "retiring", "retired"})
    if authority_state == "active":
        os.link(mutation, mutation_evidence, follow_symlinks=False)
        fsync_directory(mutation_evidence.parent)
        mutation.unlink()
    elif authority_state == "retiring":
        finish_mutation_evidence_alias(mutation, mutation_evidence, mutation_sha)
    require_mutation_authority({"retired"})
    fsync_directory(mutation.parent)
    state = reconcile_pending_publication(
        pending_raw, pending_base, pending_alias, pending_staged
    )
    validate_state(state, {"authority-retired"})

validate_completed_runtime(state)
terminal_document = {
    **state,
    "phase": "complete",
    "completedAt": now(),
    "sslRestored": state["sslPresent"],
}
validate_state(terminal_document, {"complete"}, terminal_state=True)
publish(terminal, terminal_document, True)
pending.unlink()
fsync_directory(pending.parent)
# END_FAILED_BOOTSTRAP_QUARANTINE_TRANSACTION
PY

[[ ! -e ${deployment_journal} && ! -L ${deployment_journal} ]] || fail "Failed-bootstrap mutation authority was not retired."
[[ -d ${standalone_root} && ! -L ${standalone_root} && ! -e ${standalone_root}/postgres_data && ! -L ${standalone_root}/postgres_data ]] || fail "Clean standalone boundary was not established."
validate_bound_source_repository_file "${current_commit}" scripts/verify-host-security.sh "${source_verifier_fd}" || fail "Current host-control verifier differs after failed-bootstrap quarantine."
/usr/bin/env -i PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin LC_ALL=C HOME=/nonexistent \
  /bin/bash --noprofile --norc "/proc/self/fd/${source_verifier_fd}" "${current_commit}" "${source_root}" \
  >/dev/null 2>&1 || fail "Current host controls failed after failed-bootstrap quarantine."
exec {source_verifier_fd}<&-
printf '%s\n' "Mochirii Forums failed bootstrap was quarantined without deleting retained runtime evidence."
# END_FAILED_BOOTSTRAP_BOUND_VERIFIER_TRANSACTION
