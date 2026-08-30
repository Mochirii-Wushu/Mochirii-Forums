#!/usr/bin/env bash
set -euo pipefail
umask 077
export LC_ALL=C

readonly canonical_repository="https://github.com/Mochirii-Wushu/Mochirii-Forums.git"
readonly deployment_source_commit="ed9f680b0df1de28f062de1769d89d22b2644d1b"
readonly deployment_source_tree="588498dffbea91592fd4e2f10166bc11c8fe7a61"
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
readonly state_root="/var/lib/mochirii/forums"
readonly evidence_root="${state_root}/evidence"
readonly upgrades_root="${state_root}/control-upgrades"
readonly pending_journal="${state_root}/control-upgrade.pending.json"
readonly control_pointer="${state_root}/current-host-control.json"
readonly host_control_releases_root="/opt/mochirii/forums/host-control-releases"
readonly libexec_root="/usr/local/libexec/mochirii-forums"
readonly ssh_generator_parent="/etc/systemd/system-generators"
readonly ssh_generator_mask="/etc/systemd/system-generators/sshd-socket-generator"
active_transaction=""
upgrade_complete=false
recovery_continue=false
postfailure_control_recovery=false

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
    expected_file_mode=644
    [[ ${mode} != 100755 ]] || expected_file_mode=755
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

fail() {
  printf '%s\n' "$1" >&2
  exit 1
}

bounded() {
  timeout --signal=TERM --kill-after=10s "$@"
}

reconcile_shared_libexec_traversal() {
  local previous_source="$1" candidate_source="$2" current_mode
  local previous_defect='install -d -m 0700 -o root -g root "${log_root}" /usr/local/libexec/mochirii-forums /etc/mochirii /etc/letsencrypt'
  local candidate_private='install -d -m 0700 -o root -g root "${log_root}" /etc/mochirii /etc/letsencrypt'
  local candidate_shared='install -d -m 0755 -o root -g root "${libexec_root}"'
  [[ -d ${libexec_root} && ! -L ${libexec_root} ]] || return 1
  [[ "$(stat -c '%U:%G' "${libexec_root}")" == root:root ]] || return 1
  current_mode="$(stat -c '%a' "${libexec_root}")"
  if [[ ${current_mode} == 755 ]]; then
    sudo -u mochirii-forums-deploy test -x "${libexec_root}/ssh-deploy-dispatch.py"
    return
  fi
  [[ ${current_mode} == 700 ]] || return 1
  grep -Fqx -- "${previous_defect}" "${previous_source}/scripts/install-media-certificate-renewal.sh" || return 1
  grep -Fqx -- "${candidate_private}" "${candidate_source}/scripts/install-media-certificate-renewal.sh" || return 1
  grep -Fqx -- "${candidate_shared}" "${candidate_source}/scripts/install-media-certificate-renewal.sh" || return 1
  chmod 0755 -- "${libexec_root}" || return 1
  sync -d "${libexec_root}" 2>/dev/null || true
  sync -d "$(dirname -- "${libexec_root}")" 2>/dev/null || true
  [[ "$(stat -c '%U:%G %a' "${libexec_root}")" == "root:root 755" ]] || return 1
  sudo -u mochirii-forums-deploy test -x "${libexec_root}/ssh-deploy-dispatch.py"
}

durable_remove() {
  /usr/bin/python3 -I -S -B - "$1" <<'PY'
import os
import pathlib
import sys
path = pathlib.Path(sys.argv[1])
try:
    path.unlink()
except FileNotFoundError:
    raise SystemExit(0)
parent = os.open(path.parent, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
try:
    os.fsync(parent)
finally:
    os.close(parent)
PY
}

systemd_unit_state() {
  local verb="$1" unit="$2" output
  output="$(bounded 15s systemctl "${verb}" "${unit}" 2>/dev/null || true)"
  (( ${#output} <= 32 )) || return 1
  printf '%s\n' "${output}"
}

ssh_generator_mask_is_exact() {
  [[ -d ${ssh_generator_parent} && ! -L ${ssh_generator_parent} ]] || return 1
  [[ "$(stat -c '%U:%G %a' -- "${ssh_generator_parent}")" == "root:root 755" ]] || return 1
  [[ -L ${ssh_generator_mask} && "$(readlink -- "${ssh_generator_mask}")" == /dev/null ]] || return 1
  [[ "$(stat -c '%U:%G' -- "${ssh_generator_mask}")" == root:root ]]
}

ssh_service_activation_is_exact() {
  ssh_generator_mask_is_exact || return 1
  [[ "$(systemd_unit_state is-enabled ssh.service)" == enabled ]] || return 1
  [[ "$(systemd_unit_state is-active ssh.service)" == active ]] || return 1
  [[ "$(systemd_unit_state is-enabled ssh.socket)" == disabled ]] || return 1
  [[ "$(systemd_unit_state is-active ssh.socket)" == inactive ]]
}

ssh_socket_activation_is_exact_predecessor() {
  [[ ! -e ${ssh_generator_mask} && ! -L ${ssh_generator_mask} ]] || return 1
  [[ "$(systemd_unit_state is-enabled ssh.service)" == disabled ]] || return 1
  [[ "$(systemd_unit_state is-active ssh.service)" == active ]] || return 1
  [[ "$(systemd_unit_state is-enabled ssh.socket)" == enabled ]] || return 1
  [[ "$(systemd_unit_state is-active ssh.socket)" == active ]]
}

ssh_activation_predecessor() {
  if ssh_service_activation_is_exact; then printf '%s\n' service
  elif ssh_socket_activation_is_exact_predecessor; then printf '%s\n' socket
  else return 1
  fi
}

effective_ssh_value() {
  local text="$1" setting="$2"
  awk -v setting="${setting}" '$1 == setting { found=$2 } END { print found }' <<<"${text}"
}

effective_ssh_allow_users() {
  awk '$1 == "allowusers" { for (i = 2; i <= NF; i++) { found = found (found == "" ? "" : " ") $i } } END { print found }' <<<"$1"
}

validate_effective_hardened_ssh_user() {
  local user="$1" effective expected_keys expected_force expected_tty
  effective="$(bounded 15s sshd -T -C "user=${user},host=forums.mochirii.com,addr=127.0.0.1")" || return 1
  (( ${#effective} <= 262144 )) || return 1
  [[ "$(effective_ssh_value "${effective}" passwordauthentication)" == no ]] || return 1
  [[ "$(effective_ssh_value "${effective}" kbdinteractiveauthentication)" == no ]] || return 1
  [[ "$(effective_ssh_value "${effective}" pubkeyauthentication)" == yes ]] || return 1
  [[ "$(effective_ssh_value "${effective}" authenticationmethods)" == publickey ]] || return 1
  [[ "$(effective_ssh_value "${effective}" authorizedkeyscommand)" == none ]] || return 1
  [[ "$(effective_ssh_value "${effective}" authorizedkeyscommanduser)" == nobody ]] || return 1
  [[ "$(effective_ssh_value "${effective}" trustedusercakeys)" == none ]] || return 1
  [[ "$(effective_ssh_value "${effective}" authorizedprincipalsfile)" == none ]] || return 1
  [[ "$(effective_ssh_value "${effective}" authorizedprincipalscommand)" == none ]] || return 1
  [[ "$(effective_ssh_value "${effective}" authorizedprincipalscommanduser)" == nobody ]] || return 1
  [[ "$(effective_ssh_value "${effective}" permituserenvironment)" == no ]] || return 1
  [[ "$(effective_ssh_value "${effective}" permituserrc)" == no ]] || return 1
  [[ "$(effective_ssh_allow_users "${effective}")" == "mochirii-forums-operator mochirii-forums-deploy" ]] || return 1
  case "${user}" in
    root) expected_keys=none; expected_force=none; expected_tty=no ;;
    mochirii-forums-operator) expected_keys="${state_root}/operator/.ssh/authorized_keys"; expected_force=none; expected_tty=yes ;;
    mochirii-forums-deploy) expected_keys="${state_root}/deploy/.ssh/authorized_keys"; expected_force=/usr/local/libexec/mochirii-forums/ssh-deploy-dispatch.py; expected_tty=no ;;
    *) return 1 ;;
  esac
  [[ "$(effective_ssh_value "${effective}" authorizedkeysfile)" == "${expected_keys}" ]] || return 1
  [[ "$(effective_ssh_value "${effective}" forcecommand)" == "${expected_force}" ]] || return 1
  [[ "$(effective_ssh_value "${effective}" disableforwarding)" == yes ]] || return 1
  [[ "$(effective_ssh_value "${effective}" permittty)" == "${expected_tty}" ]] || return 1
  [[ ${user} != root || "$(effective_ssh_value "${effective}" permitrootlogin)" == no ]]
}

validate_effective_hardened_ssh() {
  validate_effective_hardened_ssh_user root &&
    validate_effective_hardened_ssh_user mochirii-forums-operator &&
    validate_effective_hardened_ssh_user mochirii-forums-deploy
}

select_reviewed_failed_bootstrap_recovery_commit() {
  case "$1" in
    "${reviewed_legacy_failed_bootstrap_commit}")
      printf '%s\n' "${reviewed_failed_bootstrap_recovery_commit}"
      ;;
    "${reviewed_active_swap_failed_bootstrap_commit}")
      printf '%s\n' "${reviewed_active_swap_recovery_commit}"
      ;;
    "${reviewed_acme_failed_bootstrap_commit}")
      printf '%s\n' "${reviewed_acme_recovery_commit}"
      ;;
    "${reviewed_quarantine_output_failed_bootstrap_commit}")
      printf '%s\n' "${reviewed_quarantine_output_recovery_commit}"
      ;;
    "${reviewed_acme_reload_privacy_failed_bootstrap_commit}")
      printf '%s\n' "${reviewed_acme_reload_privacy_recovery_commit}"
      ;;
    "${reviewed_acme_webroot_failed_bootstrap_commit}")
      printf '%s\n' "${reviewed_acme_webroot_recovery_commit}"
      ;;
    "${reviewed_acme_material_failed_bootstrap_commit}")
      printf '%s\n' "${reviewed_acme_material_recovery_commit}"
      ;;
    "${reviewed_acme_stage_failed_bootstrap_commit}")
      printf '%s\n' "${reviewed_acme_stage_recovery_commit}"
      ;;
    "${reviewed_acme_transport_failed_bootstrap_commit}")
      printf '%s\n' "${reviewed_acme_transport_recovery_commit}"
      ;;
    *) return 1 ;;
  esac
}

validate_reviewed_failed_bootstrap_successor_paths() {
  local source_directory_fd="$1" git_directory_fd="$2" requested_commit="$3" pending_commit="$4"
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
  local actual_path_output
  local -a actual_paths expected_paths
  case "${pending_commit}" in
    "${reviewed_legacy_failed_bootstrap_commit}") expected_paths=("${legacy_expected_paths[@]}") ;;
    "${reviewed_active_swap_failed_bootstrap_commit}") expected_paths=("${active_swap_expected_paths[@]}") ;;
    "${reviewed_acme_failed_bootstrap_commit}") expected_paths=("${acme_expected_paths[@]}") ;;
    "${reviewed_quarantine_output_failed_bootstrap_commit}") expected_paths=("${quarantine_output_expected_paths[@]}") ;;
    "${reviewed_acme_reload_privacy_failed_bootstrap_commit}") expected_paths=("${acme_reload_privacy_expected_paths[@]}") ;;
    "${reviewed_acme_webroot_failed_bootstrap_commit}") expected_paths=("${acme_webroot_expected_paths[@]}") ;;
    "${reviewed_acme_material_failed_bootstrap_commit}") expected_paths=("${acme_material_expected_paths[@]}") ;;
    "${reviewed_acme_stage_failed_bootstrap_commit}") expected_paths=("${acme_stage_expected_paths[@]}") ;;
    "${reviewed_acme_transport_failed_bootstrap_commit}") expected_paths=("${acme_transport_expected_paths[@]}") ;;
    *) return 1 ;;
  esac
  if [[ ${pending_commit} == "${reviewed_acme_material_failed_bootstrap_commit}" ]]; then
    actual_path_output="$(source_repository_git "${source_directory_fd}" "${git_directory_fd}" diff-tree --no-commit-id --name-only -r "${pending_commit}" "${reviewed_acme_material_recovery_commit}" 2>/dev/null)" || return 1
    (( ${#actual_path_output} <= 65536 )) || return 1
    mapfile -t actual_paths <<< "${actual_path_output}"
    [[ ${#actual_paths[@]} -eq ${#acme_material_repair_expected_paths[@]} ]] || return 1
    for index in "${!acme_material_repair_expected_paths[@]}"; do
      [[ ${actual_paths[$index]} == "${acme_material_repair_expected_paths[$index]}" ]] || return 1
    done
    actual_path_output="$(source_repository_git "${source_directory_fd}" "${git_directory_fd}" diff-tree --no-commit-id --name-only -r "${reviewed_acme_material_recovery_commit}" "${reviewed_acme_material_review_authority_commit}" 2>/dev/null)" || return 1
    (( ${#actual_path_output} <= 65536 )) || return 1
    mapfile -t actual_paths <<< "${actual_path_output}"
    [[ ${#actual_paths[@]} -eq ${#acme_material_review_authority_expected_paths[@]} ]] || return 1
    for index in "${!acme_material_review_authority_expected_paths[@]}"; do
      [[ ${actual_paths[$index]} == "${acme_material_review_authority_expected_paths[$index]}" ]] || return 1
    done
    actual_path_output="$(source_repository_git "${source_directory_fd}" "${git_directory_fd}" diff-tree --no-commit-id --name-only -r "${reviewed_acme_material_review_authority_commit}" "${requested_commit}" 2>/dev/null)" || return 1
    (( ${#actual_path_output} <= 65536 )) || return 1
    mapfile -t actual_paths <<< "${actual_path_output}"
    [[ ${#actual_paths[@]} -eq ${#acme_material_current_expected_paths[@]} ]] || return 1
    for index in "${!acme_material_current_expected_paths[@]}"; do
      [[ ${actual_paths[$index]} == "${acme_material_current_expected_paths[$index]}" ]] || return 1
    done
  fi
  if [[ ${pending_commit} == "${reviewed_acme_stage_failed_bootstrap_commit}" ]]; then
    actual_path_output="$(source_repository_git "${source_directory_fd}" "${git_directory_fd}" diff-tree --no-commit-id --name-only -r "${pending_commit}" "${reviewed_recovery_commit}" 2>/dev/null)" || return 1
    (( ${#actual_path_output} <= 65536 )) || return 1
    mapfile -t actual_paths <<< "${actual_path_output}"
    [[ ${#actual_paths[@]} -eq ${#acme_stage_repair_expected_paths[@]} ]] || return 1
    for index in "${!acme_stage_repair_expected_paths[@]}"; do
      [[ ${actual_paths[$index]} == "${acme_stage_repair_expected_paths[$index]}" ]] || return 1
    done
    actual_path_output="$(source_repository_git "${source_directory_fd}" "${git_directory_fd}" diff-tree --no-commit-id --name-only -r "${reviewed_recovery_commit}" "${requested_commit}" 2>/dev/null)" || return 1
    (( ${#actual_path_output} <= 65536 )) || return 1
    mapfile -t actual_paths <<< "${actual_path_output}"
    [[ ${#actual_paths[@]} -eq ${#acme_stage_current_expected_paths[@]} ]] || return 1
    for index in "${!acme_stage_current_expected_paths[@]}"; do
      [[ ${actual_paths[$index]} == "${acme_stage_current_expected_paths[$index]}" ]] || return 1
    done
  fi
  if [[ ${pending_commit} == "${reviewed_acme_transport_failed_bootstrap_commit}" ]]; then
    actual_path_output="$(source_repository_git "${source_directory_fd}" "${git_directory_fd}" diff-tree --no-commit-id --name-only -r "${pending_commit}" "${reviewed_recovery_commit}" 2>/dev/null)" || return 1
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
    actual_path_output="$(source_repository_git "${source_directory_fd}" "${git_directory_fd}" diff-tree --no-commit-id --name-only -r "${reviewed_acme_transport_postfailure_parent_commit}" "${requested_commit}" 2>/dev/null)" || return 1
    (( ${#actual_path_output} <= 65536 )) || return 1
    mapfile -t actual_paths <<< "${actual_path_output}"
    [[ ${#actual_paths[@]} -eq ${#acme_transport_postfailure_current_expected_paths[@]} ]] || return 1
    for index in "${!acme_transport_postfailure_current_expected_paths[@]}"; do
      [[ ${actual_paths[$index]} == "${acme_transport_postfailure_current_expected_paths[$index]}" ]] || return 1
    done
  fi
  actual_path_output="$(source_repository_git "${source_directory_fd}" "${git_directory_fd}" diff-tree --no-commit-id --name-only -r "${pending_commit}" "${requested_commit}" 2>/dev/null)" || return 1
  (( ${#actual_path_output} <= 65536 )) || return 1
  mapfile -t actual_paths <<< "${actual_path_output}"
  [[ ${#actual_paths[@]} -eq ${#expected_paths[@]} ]] || return 1
  for index in "${!expected_paths[@]}"; do
    [[ ${actual_paths[$index]} == "${expected_paths[$index]}" ]] || return 1
  done
}

bind_invoked_canonical_successor() {
  (
  local requested_commit="$1" pending_commit="$2" invocation_script invocation_source_root remote_output reviewed_recovery_commit requested_parent_commit repository_config_identity
  local source_directory_fd git_directory_fd config_fd info_directory_fd objects_directory_fd objects_info_directory_fd
  local head_fd refs_directory_fd heads_directory_fd main_ref_fd index_fd
  reviewed_recovery_commit="$(select_reviewed_failed_bootstrap_recovery_commit "${pending_commit}")" || return 1
  requested_parent_commit="${reviewed_recovery_commit}"
  if [[ ${pending_commit} == "${reviewed_acme_reload_privacy_failed_bootstrap_commit}" ]]; then
    requested_parent_commit="${reviewed_acme_reload_privacy_launcher_child_commit}"
  fi
  if [[ ${pending_commit} == "${reviewed_acme_material_failed_bootstrap_commit}" ]]; then
    requested_parent_commit="${reviewed_acme_material_review_authority_commit}"
  fi
  if [[ ${pending_commit} == "${reviewed_acme_transport_failed_bootstrap_commit}" ]]; then
    requested_parent_commit="${reviewed_acme_transport_postfailure_parent_commit}"
  fi
  [[ -f $0 && ! -L $0 ]] || return 1
  invocation_script="$(realpath -e -- "$0")" || return 1
  invocation_source_root="$(dirname -- "$(dirname -- "${invocation_script}")")"
  unset GIT_DIR GIT_WORK_TREE GIT_INDEX_FILE GIT_OBJECT_DIRECTORY GIT_ALTERNATE_OBJECT_DIRECTORIES GIT_COMMON_DIR GIT_REPLACE_REF_BASE
  unset GIT_ASKPASS SSH_ASKPASS GIT_SSH GIT_SSH_COMMAND GIT_CONFIG_PARAMETERS GIT_CONFIG_SYSTEM GIT_PROTOCOL_FROM_USER
  export GIT_TERMINAL_PROMPT=0 GIT_CONFIG_NOSYSTEM=1 GIT_CONFIG_GLOBAL=/dev/null GIT_CONFIG_COUNT=0 GIT_NO_REPLACE_OBJECTS=1
  shopt -u varredir_close
  exec {source_directory_fd}<"${invocation_source_root}" || return 1
  exec {git_directory_fd}<"${invocation_source_root}/.git" || return 1
  exec {config_fd}<"${invocation_source_root}/.git/config" || return 1
  exec {info_directory_fd}<"${invocation_source_root}/.git/info" || return 1
  exec {objects_directory_fd}<"${invocation_source_root}/.git/objects" || return 1
  exec {objects_info_directory_fd}<"${invocation_source_root}/.git/objects/info" || return 1
  exec {head_fd}<"${invocation_source_root}/.git/HEAD" || return 1
  exec {refs_directory_fd}<"${invocation_source_root}/.git/refs" || return 1
  exec {heads_directory_fd}<"${invocation_source_root}/.git/refs/heads" || return 1
  exec {main_ref_fd}<"${invocation_source_root}/.git/refs/heads/main" || return 1
  exec {index_fd}<"${invocation_source_root}/.git/index" || return 1
  validate_source_repository_operation_state "${git_directory_fd}" || return 1
  repository_config_identity="$(validated_source_repository_boundary_identity "${invocation_source_root}" "${source_directory_fd}" "${git_directory_fd}" "${config_fd}" "${info_directory_fd}" "${objects_directory_fd}" "${objects_info_directory_fd}" "${head_fd}" "${refs_directory_fd}" "${heads_directory_fd}" "${main_ref_fd}" "${index_fd}")" || return 1
  validate_source_repository_clean_state "${source_directory_fd}" "${git_directory_fd}" || return 1
  [[ "$(source_repository_git "${source_directory_fd}" "${git_directory_fd}" rev-parse --verify HEAD^{commit} 2>/dev/null)" == "${requested_commit}" ]] || return 1
  [[ "$(source_repository_git "${source_directory_fd}" "${git_directory_fd}" symbolic-ref --short -q HEAD 2>/dev/null)" == main ]] || return 1
  [[ "$(source_repository_git "${source_directory_fd}" "${git_directory_fd}" rev-parse --verify "${requested_commit}^1" 2>/dev/null)" == "${requested_parent_commit}" ]] || return 1
  [[ "$(source_repository_git "${source_directory_fd}" "${git_directory_fd}" rev-list --parents -n 1 "${requested_commit}" 2>/dev/null)" == "${requested_commit} ${requested_parent_commit}" ]] || return 1
  if [[ ${pending_commit} == "${reviewed_acme_reload_privacy_failed_bootstrap_commit}" ]]; then
    [[ "$(source_repository_git "${source_directory_fd}" "${git_directory_fd}" rev-parse --verify "${reviewed_acme_reload_privacy_launcher_child_commit}^1" 2>/dev/null)" == "${reviewed_acme_reload_privacy_recovery_child_commit}" ]] || return 1
    [[ "$(source_repository_git "${source_directory_fd}" "${git_directory_fd}" rev-list --parents -n 1 "${reviewed_acme_reload_privacy_launcher_child_commit}" 2>/dev/null)" == "${reviewed_acme_reload_privacy_launcher_child_commit} ${reviewed_acme_reload_privacy_recovery_child_commit}" ]] || return 1
    [[ "$(source_repository_git "${source_directory_fd}" "${git_directory_fd}" rev-parse --verify "${reviewed_acme_reload_privacy_recovery_child_commit}^1" 2>/dev/null)" == "${reviewed_recovery_commit}" ]] || return 1
    [[ "$(source_repository_git "${source_directory_fd}" "${git_directory_fd}" rev-list --parents -n 1 "${reviewed_acme_reload_privacy_recovery_child_commit}" 2>/dev/null)" == "${reviewed_acme_reload_privacy_recovery_child_commit} ${reviewed_recovery_commit}" ]] || return 1
  fi
  if [[ ${pending_commit} == "${reviewed_acme_material_failed_bootstrap_commit}" ]]; then
    [[ "$(source_repository_git "${source_directory_fd}" "${git_directory_fd}" rev-parse --verify "${reviewed_acme_material_review_authority_commit}^1" 2>/dev/null)" == "${reviewed_recovery_commit}" ]] || return 1
    [[ "$(source_repository_git "${source_directory_fd}" "${git_directory_fd}" rev-list --parents -n 1 "${reviewed_acme_material_review_authority_commit}" 2>/dev/null)" == "${reviewed_acme_material_review_authority_commit} ${reviewed_recovery_commit}" ]] || return 1
  fi
  if [[ ${pending_commit} == "${reviewed_acme_transport_failed_bootstrap_commit}" ]]; then
    [[ "$(source_repository_git "${source_directory_fd}" "${git_directory_fd}" rev-parse --verify "${reviewed_acme_transport_postfailure_parent_commit}^1" 2>/dev/null)" == "${reviewed_recovery_commit}" ]] || return 1
    [[ "$(source_repository_git "${source_directory_fd}" "${git_directory_fd}" rev-list --parents -n 1 "${reviewed_acme_transport_postfailure_parent_commit}" 2>/dev/null)" == "${reviewed_acme_transport_postfailure_parent_commit} ${reviewed_recovery_commit}" ]] || return 1
  fi
  [[ "$(source_repository_git "${source_directory_fd}" "${git_directory_fd}" rev-parse --verify "${reviewed_recovery_commit}^1" 2>/dev/null)" == "${pending_commit}" ]] || return 1
  [[ "$(source_repository_git "${source_directory_fd}" "${git_directory_fd}" rev-list --parents -n 1 "${reviewed_recovery_commit}" 2>/dev/null)" == "${reviewed_recovery_commit} ${pending_commit}" ]] || return 1
  remote_output="$(read_canonical_remote_main)" || return 1
  (( ${#remote_output} <= 256 )) || return 1
  [[ ${remote_output} == "${requested_commit}"$'\trefs/heads/main' ]] || return 1
  validate_reviewed_failed_bootstrap_successor_paths "${source_directory_fd}" "${git_directory_fd}" "${requested_commit}" "${pending_commit}" || return 1
  validate_source_repository_clean_state "${source_directory_fd}" "${git_directory_fd}" || return 1
  [[ "$(validated_source_repository_boundary_identity "${invocation_source_root}" "${source_directory_fd}" "${git_directory_fd}" "${config_fd}" "${info_directory_fd}" "${objects_directory_fd}" "${objects_info_directory_fd}" "${head_fd}" "${refs_directory_fd}" "${heads_directory_fd}" "${main_ref_fd}" "${index_fd}")" == "${repository_config_identity}" ]] || return 1
  validate_source_repository_operation_state "${git_directory_fd}" || return 1
  )
}

read_bound_failed_bootstrap_preflight() {
  (
  local requested_commit="$1" invocation_script invocation_source_root remote_output repository_config_identity
  local quarantine_path quarantine_path_identity quarantine_descriptor_identity tree_output tree_metadata tree_path
  local tree_mode tree_type tree_blob tree_extra descriptor_blob output
  local source_directory_fd git_directory_fd config_fd info_directory_fd objects_directory_fd objects_info_directory_fd
  local head_fd refs_directory_fd heads_directory_fd main_ref_fd index_fd quarantine_fd
  [[ ${requested_commit} =~ ^[0-9a-f]{40}$ ]] || return 1
  [[ -f $0 && ! -L $0 ]] || return 1
  invocation_script="$(realpath -e -- "$0")" || return 1
  invocation_source_root="$(dirname -- "$(dirname -- "${invocation_script}")")"
  quarantine_path="${invocation_source_root}/scripts/quarantine-failed-bootstrap.sh"
  unset GIT_DIR GIT_WORK_TREE GIT_INDEX_FILE GIT_OBJECT_DIRECTORY GIT_ALTERNATE_OBJECT_DIRECTORIES GIT_COMMON_DIR GIT_REPLACE_REF_BASE
  unset GIT_ASKPASS SSH_ASKPASS GIT_SSH GIT_SSH_COMMAND GIT_CONFIG_PARAMETERS GIT_CONFIG_SYSTEM GIT_PROTOCOL_FROM_USER
  export GIT_TERMINAL_PROMPT=0 GIT_CONFIG_NOSYSTEM=1 GIT_CONFIG_GLOBAL=/dev/null GIT_CONFIG_COUNT=0 GIT_NO_REPLACE_OBJECTS=1
  shopt -u varredir_close
  exec {source_directory_fd}<"${invocation_source_root}" || return 1
  exec {git_directory_fd}<"${invocation_source_root}/.git" || return 1
  exec {config_fd}<"${invocation_source_root}/.git/config" || return 1
  exec {info_directory_fd}<"${invocation_source_root}/.git/info" || return 1
  exec {objects_directory_fd}<"${invocation_source_root}/.git/objects" || return 1
  exec {objects_info_directory_fd}<"${invocation_source_root}/.git/objects/info" || return 1
  exec {head_fd}<"${invocation_source_root}/.git/HEAD" || return 1
  exec {refs_directory_fd}<"${invocation_source_root}/.git/refs" || return 1
  exec {heads_directory_fd}<"${invocation_source_root}/.git/refs/heads" || return 1
  exec {main_ref_fd}<"${invocation_source_root}/.git/refs/heads/main" || return 1
  exec {index_fd}<"${invocation_source_root}/.git/index" || return 1
  exec {quarantine_fd}<"${quarantine_path}" || return 1
  validate_source_repository_operation_state "${git_directory_fd}" || return 1
  repository_config_identity="$(validated_source_repository_boundary_identity "${invocation_source_root}" "${source_directory_fd}" "${git_directory_fd}" "${config_fd}" "${info_directory_fd}" "${objects_directory_fd}" "${objects_info_directory_fd}" "${head_fd}" "${refs_directory_fd}" "${heads_directory_fd}" "${main_ref_fd}" "${index_fd}")" || return 1
  validate_source_repository_clean_state "${source_directory_fd}" "${git_directory_fd}" || return 1
  [[ "$(source_repository_git "${source_directory_fd}" "${git_directory_fd}" rev-parse --verify HEAD^{commit} 2>/dev/null)" == "${requested_commit}" ]] || return 1
  [[ "$(source_repository_git "${source_directory_fd}" "${git_directory_fd}" symbolic-ref --short -q HEAD 2>/dev/null)" == main ]] || return 1
  remote_output="$(read_canonical_remote_main)" || return 1
  (( ${#remote_output} <= 256 )) || return 1
  [[ ${remote_output} == "${requested_commit}"$'\trefs/heads/main' ]] || return 1
  quarantine_path_identity="$(safe_source_repository_regular_file_identity "${quarantine_path}" false 1048576)" || return 1
  quarantine_descriptor_identity="$(safe_source_repository_regular_file_identity "/proc/self/fd/${quarantine_fd}" true 1048576)" || return 1
  [[ ${quarantine_descriptor_identity} == "${quarantine_path_identity}" ]] || return 1
  tree_output="$(source_repository_git "${source_directory_fd}" "${git_directory_fd}" ls-tree "${requested_commit}" -- scripts/quarantine-failed-bootstrap.sh 2>/dev/null)" || return 1
  (( ${#tree_output} <= 256 )) || return 1
  IFS=$'\t' read -r tree_metadata tree_path <<<"${tree_output}"
  read -r tree_mode tree_type tree_blob tree_extra <<<"${tree_metadata}"
  [[ ${tree_mode} == 100644 && ${tree_type} == blob && ${tree_blob} =~ ^[0-9a-f]{40}$ && -z ${tree_extra} ]] || return 1
  [[ ${tree_path} == scripts/quarantine-failed-bootstrap.sh ]] || return 1
  descriptor_blob="$(source_repository_git "${source_directory_fd}" "${git_directory_fd}" hash-object --no-filters "/proc/self/fd/${quarantine_fd}" 2>/dev/null)" || return 1
  [[ ${descriptor_blob} == "${tree_blob}" ]] || return 1
  validate_source_repository_clean_state "${source_directory_fd}" "${git_directory_fd}" || return 1
  [[ "$(validated_source_repository_boundary_identity "${invocation_source_root}" "${source_directory_fd}" "${git_directory_fd}" "${config_fd}" "${info_directory_fd}" "${objects_directory_fd}" "${objects_info_directory_fd}" "${head_fd}" "${refs_directory_fd}" "${heads_directory_fd}" "${main_ref_fd}" "${index_fd}")" == "${repository_config_identity}" ]] || return 1
  validate_source_repository_operation_state "${git_directory_fd}" || return 1
  output="$(/usr/bin/env -i PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin LC_ALL=C HOME=/nonexistent \
    /bin/bash --noprofile --norc "/proc/self/fd/${quarantine_fd}" --upgrade-preflight "${requested_commit}" 2>/dev/null)" || return 1
  (( ${#output} <= 64 )) || return 1
  printf '%s\n' "${output}"
  )
}

validate_failed_bootstrap_upgrade_exception() {
  local requested_commit="$1" invocation_script invocation_source_root output
  local -a state
  [[ -f $0 && ! -L $0 ]] || return 1
  invocation_script="$(realpath -e -- "$0")" || return 1
  invocation_source_root="$(dirname -- "$(dirname -- "${invocation_script}")")"
  output="$(read_bound_failed_bootstrap_preflight "${requested_commit}")" || return 1
  readarray -t state <<<"${output}"
  [[ ${#state[@]} -eq 1 && ${state[0]} =~ ^[0-9a-f]{40}$ ]] || return 1
  bind_invoked_canonical_successor "${requested_commit}" "${state[0]}" || return 1
  if [[ ${state[0]} == "${reviewed_acme_transport_failed_bootstrap_commit}" ]]; then
    postfailure_control_recovery=true
  fi
}

publish_ssh_generator_mask() {
  local staging
  if [[ -e ${ssh_generator_parent} || -L ${ssh_generator_parent} ]]; then
    [[ -d ${ssh_generator_parent} && ! -L ${ssh_generator_parent} ]] || return 1
    [[ "$(stat -c '%U:%G %a' -- "${ssh_generator_parent}")" == "root:root 755" ]] || return 1
  else
    install -d -m 0755 -o root -g root "${ssh_generator_parent}" || return 1
  fi
  [[ ! -e ${ssh_generator_mask} && ! -L ${ssh_generator_mask} ]] || return 1
  staging="$(mktemp -d "${ssh_generator_parent}/.sshd-socket-generator.XXXXXXXX")" || return 1
  chmod 0700 "${staging}" || { rmdir -- "${staging}"; return 1; }
  ln -s /dev/null "${staging}/mask" || { rmdir -- "${staging}"; return 1; }
  mv -T -- "${staging}/mask" "${ssh_generator_mask}" || { rm -f -- "${staging}/mask"; rmdir -- "${staging}"; return 1; }
  rmdir -- "${staging}" || return 1
  sync -d "${ssh_generator_parent}" 2>/dev/null || true
  ssh_generator_mask_is_exact
}

ensure_ssh_service_activation() {
  ssh_service_activation_is_exact && return 0
  ssh_socket_activation_is_exact_predecessor || return 1
  publish_ssh_generator_mask || return 1
  bounded 60s systemctl daemon-reload >/dev/null 2>&1 || return 1
  bounded 60s systemctl disable --now ssh.socket >/dev/null 2>&1 || return 1
  bounded 60s systemctl enable --now ssh.service >/dev/null 2>&1 || return 1
  ssh_service_activation_is_exact
}

restore_ssh_activation_predecessor() {
  local predecessor="$1"
  case "${predecessor}" in
    service)
      ensure_ssh_service_activation
      ;;
    socket)
      [[ "$(bounded 15s systemctl show ssh.service -p KillMode --value 2>/dev/null)" == process ]] || return 1
      bounded 60s systemctl disable ssh.service >/dev/null 2>&1 || return 1
      durable_remove "${ssh_generator_mask}" || return 1
      bounded 60s systemctl daemon-reload >/dev/null 2>&1 || return 1
      bounded 60s systemctl enable ssh.socket >/dev/null 2>&1 || return 1
      bounded 60s systemctl stop ssh.service >/dev/null 2>&1 || return 1
      bounded 60s systemctl start ssh.socket >/dev/null 2>&1 || return 1
      bounded 60s systemctl start ssh.service >/dev/null 2>&1 || return 1
      ssh_socket_activation_is_exact_predecessor
      ;;
    *) return 1 ;;
  esac
}

durable_remove_workdir() {
  /usr/bin/python3 -I -S -B - "$1" "${upgrades_root}" "${state_root}" <<'PY'
import os
import pathlib
import re
import shutil
import stat
import sys

path = pathlib.Path(sys.argv[1])
root = pathlib.Path(sys.argv[2])
state_root = pathlib.Path(sys.argv[3])
upgrade_path = path.parent == root and re.fullmatch(r"[0-9a-f]{40}-[0-9a-f]{64}", path.name)
staging_path = path.parent == state_root and re.fullmatch(r"[.]control-upgrade-staging-[0-9a-f]{40}[.][A-Za-z0-9]{8}", path.name)
if not (upgrade_path or staging_path):
    raise SystemExit("host-control work directory identity differs")
metadata = path.lstat()
if not stat.S_ISDIR(metadata.st_mode) or stat.S_ISLNK(metadata.st_mode) or metadata.st_uid != 0 or metadata.st_gid != 0 or stat.S_IMODE(metadata.st_mode) != 0o700:
    raise SystemExit("host-control work directory is unsafe")
shutil.rmtree(path)
parent = os.open(path.parent, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
try:
    os.fsync(parent)
finally:
    os.close(parent)
PY
}

reconcile_unjournaled_workdirs() {
  local path
  [[ ! -e ${pending_journal} && ! -L ${pending_journal} ]] || return 0
  while IFS= read -r -d '' path; do
    durable_remove_workdir "${path}" || return 1
  done < <(find "${upgrades_root}" -mindepth 1 -maxdepth 1 -print0 | LC_ALL=C sort -z)
  while IFS= read -r -d '' path; do
    durable_remove_workdir "${path}" || return 1
  done < <(find "${state_root}" -mindepth 1 -maxdepth 1 -name '.control-upgrade-staging-*' -print0 | LC_ALL=C sort -z)
  [[ -z "$(find "${upgrades_root}" -mindepth 1 -maxdepth 1 -print -quit)" ]] &&
    [[ -z "$(find "${state_root}" -mindepth 1 -maxdepth 1 -name '.control-upgrade-staging-*' -print -quit)" ]]
}

atomic_install() {
  local source="$1" target="$2" mode="$3"
  /usr/bin/python3 -I -S -B - "${source}" "${target}" "${mode}" <<'PY'
import os
import pathlib
import stat
import tempfile
import sys
source = pathlib.Path(sys.argv[1])
target = pathlib.Path(sys.argv[2])
mode = int(sys.argv[3], 8)
metadata = source.lstat()
if not stat.S_ISREG(metadata.st_mode) or stat.S_ISLNK(metadata.st_mode):
    raise SystemExit("source is not regular")
target.parent.mkdir(mode=0o755, parents=True, exist_ok=True)
descriptor, candidate = tempfile.mkstemp(prefix=f".{target.name}.", dir=target.parent)
try:
    os.fchmod(descriptor, mode)
    with source.open("rb") as reader, os.fdopen(descriptor, "wb") as writer:
        descriptor = -1
        while chunk := reader.read(1024 * 1024):
            writer.write(chunk)
        writer.flush()
        os.fsync(writer.fileno())
    os.chown(candidate, 0, 0)
    os.replace(candidate, target)
    parent = os.open(target.parent, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
    try:
        os.fsync(parent)
    finally:
        os.close(parent)
finally:
    if descriptor >= 0:
        os.close(descriptor)
    try:
        os.unlink(candidate)
    except FileNotFoundError:
        pass
PY
}

retain_exact_file() {
  local source="$1" target="$2"
  if [[ -e ${target} || -L ${target} ]]; then
    [[ -f ${target} && ! -L ${target} && "$(stat -c '%U:%G %a' "${target}")" == "root:root 600" ]] || return 1
    cmp -s -- "${source}" "${target}" || return 1
  else
    atomic_install "${source}" "${target}" 0600
  fi
}

retain_disaster_recovery_sources() {
  local repository_archive="$1" commit="$2" source_root="$3" expected_tree="$4" deployment_archive inspection
  deployment_archive="$(mktemp "${state_root}/.deployment-source-${deployment_source_commit}.XXXXXXXX.tar")" || return 1
  [[ -d /var/discourse/.git && ! -L /var/discourse/.git ]] || { rm -f -- "${deployment_archive}"; return 1; }
  [[ "$(git -C /var/discourse rev-parse --verify HEAD^{commit})" == "${deployment_source_commit}" ]] || { rm -f -- "${deployment_archive}"; return 1; }
  [[ "$(git -C /var/discourse rev-parse --verify HEAD^{tree})" == "${deployment_source_tree}" ]] || { rm -f -- "${deployment_archive}"; return 1; }
  [[ -z "$(git -c core.fsmonitor=false -C /var/discourse status --porcelain=v1 --untracked-files=all)" ]] || { rm -f -- "${deployment_archive}"; return 1; }
  [[ "$(git -C /var/discourse config --local --get remote.origin.url)" == https://github.com/discourse/discourse_docker.git ]] || { rm -f -- "${deployment_archive}"; return 1; }
  [[ "$(git -C /var/discourse config --local --get remote.origin.pushurl)" == no_push://mochirii-forums-upstream ]] || { rm -f -- "${deployment_archive}"; return 1; }
  git -c tar.umask=0002 -C /var/discourse archive --format=tar --output="${deployment_archive}" "${deployment_source_commit}" >/dev/null 2>&1 || { rm -f -- "${deployment_archive}"; return 1; }
  inspection="$(/usr/bin/python3 -I -S -B "${source_root}/scripts/historical-release-disaster-recovery.py" inspect --archive "${repository_archive}" --expected-commit "${commit}")" || { rm -f -- "${deployment_archive}"; return 1; }
  (( ${#inspection} <= 4096 )) || { rm -f -- "${deployment_archive}"; return 1; }
  /usr/bin/python3 -I -S -B - "${inspection}" "${commit}" "${expected_tree}" <<'PY' >/dev/null || { rm -f -- "${deployment_archive}"; return 1; }
import json, sys
document = json.loads(sys.argv[1])
if document.get("repositoryCommit") != sys.argv[2] or document.get("repositoryTree") != sys.argv[3]:
    raise SystemExit("retained host-control archive differs from the exact Git commit tree")
PY
  install -d -m 0700 -o root -g root "/opt/mochirii/forums/host-control-releases/${commit}" /opt/mochirii/forums/deployment-source
  retain_exact_file "${repository_archive}" "/opt/mochirii/forums/host-control-releases/${commit}/mochirii-release.tar" || { rm -f -- "${deployment_archive}"; return 1; }
  retain_exact_file "${deployment_archive}" "/opt/mochirii/forums/deployment-source/${deployment_source_commit}.tar" || { rm -f -- "${deployment_archive}"; return 1; }
  rm -f -- "${deployment_archive}"
}

bind_previous_source() {
  local pointer="$1" work_root="$2" candidate_source="$3" action="$4"
  # PREDECESSOR_ARCHIVE_BINDING_PYTHON_BEGIN
  bounded 120s /usr/bin/python3 -I -S -B - \
    "${pointer}" "${work_root}" "${candidate_source}" "${action}" \
    "${state_root}" "${upgrades_root}" "${host_control_releases_root}" 0 0 <<'PY'
import hashlib
import importlib.util
import json
import os
import pathlib
import re
import stat
import sys

pointer = pathlib.Path(sys.argv[1])
work_root = pathlib.Path(sys.argv[2])
candidate_source = pathlib.Path(sys.argv[3])
action = sys.argv[4]
state_root = pathlib.Path(sys.argv[5])
upgrades_root = pathlib.Path(sys.argv[6])
archive_root = pathlib.Path(sys.argv[7])
expected_uid = int(sys.argv[8])
expected_gid = int(sys.argv[9])

HEX40 = re.compile(r"[0-9a-f]{40}")
HEX64 = re.compile(r"[0-9a-f]{64}")
POINTER_KEYS = {
    "schemaVersion", "phase", "repositoryCommit", "repositoryTree", "manifestSha256",
    "targetSetSha256", "controlEvidenceFile", "controlEvidenceSha256",
    "releaseArchiveFile", "releaseArchiveSha256", "releaseArchiveBytes",
    "releaseArchiveContentManifestSha256", "deploymentSourceRevision", "deploymentSourceTree",
    "deploymentSourceArchiveFile", "deploymentSourceArchiveSha256", "deploymentSourceArchiveBytes",
    "deploymentSourceContentManifestSha256",
}


def reject(message: str) -> None:
    raise SystemExit(message)


def exact_regular(path: pathlib.Path, mode: int, maximum: int, label: str) -> os.stat_result:
    try:
        metadata = path.lstat()
    except FileNotFoundError:
        reject(f"{label} is absent")
    if (
        not stat.S_ISREG(metadata.st_mode)
        or stat.S_ISLNK(metadata.st_mode)
        or metadata.st_size < 1
        or metadata.st_size > maximum
        or metadata.st_nlink != 1
    ):
        reject(f"{label} is unsafe")
    if os.name != "nt" and (
        metadata.st_uid != expected_uid
        or metadata.st_gid != expected_gid
        or stat.S_IMODE(metadata.st_mode) != mode
    ):
        reject(f"{label} ownership differs")
    return metadata


def exact_directory(path: pathlib.Path, mode: int, label: str) -> os.stat_result:
    try:
        metadata = path.lstat()
    except FileNotFoundError:
        reject(f"{label} is absent")
    if not stat.S_ISDIR(metadata.st_mode) or stat.S_ISLNK(metadata.st_mode):
        reject(f"{label} is unsafe")
    if os.name != "nt" and (
        metadata.st_uid != expected_uid
        or metadata.st_gid != expected_gid
        or stat.S_IMODE(metadata.st_mode) != mode
    ):
        reject(f"{label} ownership differs")
    return metadata


def same_path_identity(left: os.stat_result, right: os.stat_result) -> bool:
    return (
        left.st_dev == right.st_dev
        and left.st_ino == right.st_ino
        and left.st_mode == right.st_mode
        and left.st_mtime_ns == right.st_mtime_ns
    )


def exact_relative_directory(
    parent_descriptor: int,
    name: str,
    path: pathlib.Path,
    mode: int,
    label: str,
) -> tuple[int, os.stat_result]:
    metadata = exact_directory(path, mode, label)
    flags = (
        os.O_RDONLY
        | getattr(os, "O_DIRECTORY", 0)
        | getattr(os, "O_NOFOLLOW", 0)
        | getattr(os, "O_CLOEXEC", 0)
    )
    try:
        descriptor = os.open(name, flags, dir_fd=parent_descriptor)
    except OSError:
        reject(f"{label} is unsafe")
    opened = os.fstat(descriptor)
    if (
        not same_path_identity(opened, metadata)
        or not stat.S_ISDIR(opened.st_mode)
        or (os.name != "nt" and (
            opened.st_uid != expected_uid
            or opened.st_gid != expected_gid
            or stat.S_IMODE(opened.st_mode) != mode
        ))
    ):
        os.close(descriptor)
        reject(f"{label} changed before read")
    return descriptor, metadata


def strict_object(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            reject("Host-control pointer contains a duplicate key")
        result[key] = value
    return result


if action not in {"identity", "prepare", "verify"}:
    reject("Predecessor binding action differs")
if expected_uid < 0 or expected_gid < 0:
    reject("Predecessor binding ownership tuple differs")
state_metadata = exact_directory(state_root, 0o755, "Host-control state root")
exact_directory(upgrades_root, 0o700, "Host-control upgrades root")
exact_directory(archive_root, 0o755, "Host-control archive root")
if upgrades_root != state_root / "control-upgrades":
    reject("Host-control upgrades root differs")
backed_up_pointer = pointer != state_root / "current-host-control.json"
if action == "identity":
    if not backed_up_pointer:
        if work_root != state_root:
            reject("Current host-control identity root differs")
    else:
        exact_directory(work_root, 0o700, "Host-control work root")
        if work_root.parent != upgrades_root or re.fullmatch(
            r"[0-9a-f]{40}-[0-9a-f]{64}", work_root.name
        ) is None or pointer != work_root / "backup/current-host-control.json":
            reject("Backed-up host-control pointer path differs")
elif action == "prepare":
    exact_directory(work_root, 0o700, "Host-control work root")
    if pointer != state_root / "current-host-control.json":
        reject("Current host-control pointer path differs")
    if work_root.parent != state_root or re.fullmatch(
        r"[.]control-upgrade-staging-[0-9a-f]{40}[.][A-Za-z0-9]{8}", work_root.name
    ) is None:
        reject("Host-control preparation root differs")
else:
    exact_directory(work_root, 0o700, "Host-control work root")
    if work_root.parent != upgrades_root or re.fullmatch(
        r"[0-9a-f]{40}-[0-9a-f]{64}", work_root.name
    ) is None:
        reject("Host-control transaction root differs")
    if pointer != work_root / "backup/current-host-control.json":
        reject("Backed-up host-control pointer path differs")

work_descriptor = -1
backup_descriptor = -1
work_metadata = None
backup_metadata = None
if backed_up_pointer and os.name != "nt":
    if (
        not hasattr(os, "O_DIRECTORY")
        or not hasattr(os, "O_NOFOLLOW")
        or os.open not in os.supports_dir_fd
        or os.stat not in os.supports_dir_fd
        or os.stat not in os.supports_follow_symlinks
    ):
        reject("Host-control backup boundary is unavailable")
    directory_flags = (
        os.O_RDONLY
        | getattr(os, "O_DIRECTORY", 0)
        | getattr(os, "O_NOFOLLOW", 0)
        | getattr(os, "O_CLOEXEC", 0)
    )
    try:
        state_descriptor = os.open(state_root, directory_flags)
    except OSError:
        reject("Host-control state root is unsafe")
    if not same_path_identity(os.fstat(state_descriptor), state_metadata):
        os.close(state_descriptor)
        reject("Host-control state root changed before read")
    try:
        upgrades_descriptor, _ = exact_relative_directory(
            state_descriptor,
            upgrades_root.name,
            upgrades_root,
            0o700,
            "Host-control upgrades root",
        )
    finally:
        os.close(state_descriptor)
    try:
        work_descriptor, work_metadata = exact_relative_directory(
            upgrades_descriptor,
            work_root.name,
            work_root,
            0o700,
            "Host-control work root",
        )
    finally:
        os.close(upgrades_descriptor)
    backup_root = work_root / "backup"
    backup_descriptor, backup_metadata = exact_relative_directory(
        work_descriptor,
        "backup",
        backup_root,
        0o700,
        "Host-control backup root",
    )
    try:
        pointer_metadata = os.stat(
            "current-host-control.json",
            dir_fd=backup_descriptor,
            follow_symlinks=False,
        )
    except OSError:
        reject("Host-control pointer is absent")
    if (
        not stat.S_ISREG(pointer_metadata.st_mode)
        or pointer_metadata.st_size < 1
        or pointer_metadata.st_size > 64 * 1024
        or pointer_metadata.st_nlink != 1
        or pointer_metadata.st_uid != expected_uid
        or pointer_metadata.st_gid != expected_gid
        or stat.S_IMODE(pointer_metadata.st_mode) != 0o600
    ):
        reject("Host-control pointer is unsafe")
else:
    if backed_up_pointer:
        exact_directory(work_root / "backup", 0o700, "Host-control backup root")
    pointer_metadata = exact_regular(pointer, 0o600, 64 * 1024, "Host-control pointer")
pointer_flags = (
    os.O_RDONLY
    | getattr(os, "O_NOFOLLOW", 0)
    | getattr(os, "O_NONBLOCK", 0)
    | getattr(os, "O_BINARY", 0)
)
try:
    if backup_descriptor >= 0:
        pointer_descriptor = os.open(
            "current-host-control.json",
            pointer_flags,
            dir_fd=backup_descriptor,
        )
    else:
        pointer_descriptor = os.open(pointer, pointer_flags)
except OSError:
    reject("Host-control pointer is unsafe")
try:
    pointer_before = os.fstat(pointer_descriptor)
    if (
        pointer_before.st_dev != pointer_metadata.st_dev
        or pointer_before.st_ino != pointer_metadata.st_ino
        or pointer_before.st_size != pointer_metadata.st_size
        or pointer_before.st_mtime_ns != pointer_metadata.st_mtime_ns
        or not stat.S_ISREG(pointer_before.st_mode)
        or pointer_before.st_nlink != 1
        or (os.name != "nt" and (
            pointer_before.st_uid != expected_uid
            or pointer_before.st_gid != expected_gid
            or stat.S_IMODE(pointer_before.st_mode) != 0o600
        ))
    ):
        reject("Host-control pointer changed before read")
    chunks: list[bytes] = []
    pointer_bytes = 0
    while True:
        chunk = os.read(pointer_descriptor, 16 * 1024)
        if not chunk:
            break
        pointer_bytes += len(chunk)
        if pointer_bytes > 64 * 1024:
            reject("Host-control pointer exceeds its byte boundary")
        chunks.append(chunk)
    raw_pointer = b"".join(chunks)
    pointer_after = os.fstat(pointer_descriptor)
    if (
        pointer_after.st_dev != pointer_before.st_dev
        or pointer_after.st_ino != pointer_before.st_ino
        or pointer_after.st_size != pointer_before.st_size
        or pointer_after.st_mtime_ns != pointer_before.st_mtime_ns
        or pointer_after.st_nlink != 1
        or (os.name != "nt" and (
            pointer_after.st_uid != expected_uid
            or pointer_after.st_gid != expected_gid
            or stat.S_IMODE(pointer_after.st_mode) != 0o600
        ))
    ):
        reject("Host-control pointer changed while read")
finally:
    os.close(pointer_descriptor)
if len(raw_pointer) != pointer_metadata.st_size:
    reject("Host-control pointer byte count differs")
try:
    if backup_descriptor >= 0:
        pointer_path_after = os.stat(
            "current-host-control.json",
            dir_fd=backup_descriptor,
            follow_symlinks=False,
        )
    else:
        pointer_path_after = pointer.lstat()
except OSError:
    reject("Host-control pointer path changed while read")
if (
    pointer_path_after.st_dev != pointer_metadata.st_dev
    or pointer_path_after.st_ino != pointer_metadata.st_ino
    or pointer_path_after.st_size != pointer_metadata.st_size
    or pointer_path_after.st_mtime_ns != pointer_metadata.st_mtime_ns
):
    reject("Host-control pointer path changed while read")
if backup_descriptor >= 0:
    try:
        backup_path_after = os.stat("backup", dir_fd=work_descriptor, follow_symlinks=False)
        work_path_after = work_root.lstat()
    except OSError:
        reject("Host-control backup path changed while read")
    if (
        not same_path_identity(backup_path_after, backup_metadata)
        or not same_path_identity(work_path_after, work_metadata)
    ):
        reject("Host-control backup path changed while read")
    os.close(backup_descriptor)
    os.close(work_descriptor)
try:
    document = json.loads(raw_pointer.decode("utf-8"), object_pairs_hook=strict_object)
except (UnicodeDecodeError, json.JSONDecodeError):
    reject("Host-control pointer is malformed")
if not isinstance(document, dict) or set(document) != POINTER_KEYS:
    reject("Host-control pointer keys differ")
commit = document.get("repositoryCommit")
tree = document.get("repositoryTree")
evidence_sha = document.get("controlEvidenceSha256")
archive_sha = document.get("releaseArchiveSha256")
archive_bytes = document.get("releaseArchiveBytes")
content_manifest = document.get("releaseArchiveContentManifestSha256")
if (
    document.get("schemaVersion") != 1
    or document.get("phase") != "hardened"
    or not isinstance(commit, str)
    or HEX40.fullmatch(commit) is None
    or not isinstance(tree, str)
    or HEX40.fullmatch(tree) is None
    or not isinstance(evidence_sha, str)
    or HEX64.fullmatch(evidence_sha) is None
    or not isinstance(archive_sha, str)
    or HEX64.fullmatch(archive_sha) is None
    or not isinstance(archive_bytes, int)
    or isinstance(archive_bytes, bool)
    or not 1 <= archive_bytes <= 64 * 1024 * 1024
    or not isinstance(content_manifest, str)
    or HEX64.fullmatch(content_manifest) is None
):
    reject("Host-control predecessor identity differs")

commit_archive_root = archive_root / commit
archive = commit_archive_root / "mochirii-release.tar"
if document.get("releaseArchiveFile") != str(archive):
    reject("Host-control predecessor archive path differs")

if action == "identity":
    print(commit)
    print(evidence_sha)
    raise SystemExit(0)

helper_path = candidate_source / "scripts/historical-release-disaster-recovery.py"
exact_directory(candidate_source, 0o700, "Candidate source root")
exact_regular(helper_path, 0o600, 2 * 1024 * 1024, "Candidate archive authority")
spec = importlib.util.spec_from_file_location("mochirii_host_control_archive", helper_path)
if spec is None or spec.loader is None:
    reject("Candidate archive authority could not be loaded")
module = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = module
spec.loader.exec_module(module)

sealed_archive = work_root / "previous-release.tar"
if action == "prepare":
    if os.name != "nt" and archive_root.resolve(strict=True) != archive_root:
        reject("Host-control archive root resolves through another path")
    exact_directory(commit_archive_root, 0o700, "Host-control commit archive root")
    archive_metadata = exact_regular(archive, 0o600, 64 * 1024 * 1024, "Host-control predecessor archive")
    if archive_metadata.st_size != archive_bytes:
        reject("Host-control predecessor archive byte count differs")
    if sealed_archive.exists() or sealed_archive.is_symlink():
        reject("Sealed predecessor archive already exists")
    source_flags = (
        os.O_RDONLY
        | getattr(os, "O_NOFOLLOW", 0)
        | getattr(os, "O_NONBLOCK", 0)
        | getattr(os, "O_BINARY", 0)
    )
    source_descriptor = os.open(archive, source_flags)
    destination_descriptor = -1
    try:
        source_before = os.fstat(source_descriptor)
        if (
            not stat.S_ISREG(source_before.st_mode)
            or source_before.st_size != archive_bytes
            or source_before.st_nlink != 1
            or (os.name != "nt" and (
                source_before.st_uid != expected_uid
                or source_before.st_gid != expected_gid
                or stat.S_IMODE(source_before.st_mode) != 0o600
            ))
        ):
            reject("Opened predecessor archive identity differs")
        destination_flags = (
            os.O_WRONLY
            | os.O_CREAT
            | os.O_EXCL
            | getattr(os, "O_NOFOLLOW", 0)
            | getattr(os, "O_BINARY", 0)
        )
        destination_descriptor = os.open(sealed_archive, destination_flags, 0o600)
        copied = 0
        digest = hashlib.sha256()
        while True:
            chunk = os.read(source_descriptor, 64 * 1024)
            if not chunk:
                break
            copied += len(chunk)
            if copied > archive_bytes:
                reject("Predecessor archive grew while copied")
            digest.update(chunk)
            view = memoryview(chunk)
            while view:
                written = os.write(destination_descriptor, view)
                if written <= 0:
                    reject("Sealed predecessor archive write failed")
                view = view[written:]
        if copied != archive_bytes or digest.hexdigest() != archive_sha:
            reject("Copied predecessor archive identity differs")
        source_after = os.fstat(source_descriptor)
        if (
            source_after.st_dev != source_before.st_dev
            or source_after.st_ino != source_before.st_ino
            or source_after.st_size != source_before.st_size
            or source_after.st_mtime_ns != source_before.st_mtime_ns
            or source_after.st_nlink != 1
            or (os.name != "nt" and (
                source_after.st_uid != expected_uid
                or source_after.st_gid != expected_gid
                or stat.S_IMODE(source_after.st_mode) != 0o600
            ))
        ):
            reject("Predecessor archive changed while copied")
        destination_metadata = os.fstat(destination_descriptor)
        if hasattr(os, "fchown") and (
            destination_metadata.st_uid != expected_uid or destination_metadata.st_gid != expected_gid
        ):
            os.fchown(destination_descriptor, expected_uid, expected_gid)
        os.fsync(destination_descriptor)
    finally:
        if destination_descriptor >= 0:
            os.close(destination_descriptor)
        os.close(source_descriptor)
    archive_path_after = archive.lstat()
    if (
        archive_path_after.st_dev != archive_metadata.st_dev
        or archive_path_after.st_ino != archive_metadata.st_ino
        or archive_path_after.st_size != archive_metadata.st_size
        or archive_path_after.st_mtime_ns != archive_metadata.st_mtime_ns
        or archive_path_after.st_nlink != 1
        or (os.name != "nt" and (
            archive_path_after.st_uid != expected_uid
            or archive_path_after.st_gid != expected_gid
            or stat.S_IMODE(archive_path_after.st_mode) != 0o600
        ))
    ):
        reject("Predecessor archive path changed while copied")
    if os.name != "nt":
        descriptor = os.open(work_root, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
        try:
            os.fsync(descriptor)
        finally:
            os.close(descriptor)
else:
    exact_regular(sealed_archive, 0o600, 64 * 1024 * 1024, "Sealed predecessor archive")

identity = module.inspect_archive(sealed_archive, commit)
if (
    identity.repository_tree != tree
    or identity.archive_sha256 != archive_sha
    or identity.archive_bytes != archive_bytes
    or identity.content_manifest_sha256 != content_manifest
):
    reject("Sealed predecessor archive differs from the control pointer")

source_parent = work_root / "previous-source"
source_root = source_parent / commit
if action == "prepare":
    if source_parent.exists() or source_parent.is_symlink():
        reject("Predecessor source parent already exists")
    source_parent.mkdir(mode=0o700)
    source_parent_metadata = source_parent.lstat()
    if hasattr(os, "chown") and (
        source_parent_metadata.st_uid != expected_uid or source_parent_metadata.st_gid != expected_gid
    ):
        os.chown(source_parent, expected_uid, expected_gid)
    module.extract_exact(sealed_archive, identity, source_root)
else:
    exact_directory(source_parent, 0o700, "Predecessor source parent")

source_tree, source_manifest = module.source_identity(source_root)
if source_tree != tree or source_manifest != content_manifest:
    reject("Prepared predecessor source differs from the control pointer")
expected_files = {entry.path: 0o755 if entry.executable else 0o644 for entry in identity.files}
observed_files: set[str] = set()
for path in [source_root, *sorted(source_root.rglob("*"), key=lambda item: item.relative_to(source_root).as_posix())]:
    metadata = path.lstat()
    relative = path.relative_to(source_root).as_posix() if path != source_root else ""
    if os.name != "nt" and (metadata.st_uid != expected_uid or metadata.st_gid != expected_gid):
        reject("Prepared predecessor source ownership differs")
    if stat.S_ISDIR(metadata.st_mode) and not stat.S_ISLNK(metadata.st_mode):
        if os.name != "nt" and stat.S_IMODE(metadata.st_mode) != 0o755:
            reject("Prepared predecessor source directory mode differs")
        continue
    if not stat.S_ISREG(metadata.st_mode) or stat.S_ISLNK(metadata.st_mode) or relative not in expected_files:
        reject("Prepared predecessor source entry differs")
    if metadata.st_nlink != 1:
        reject("Prepared predecessor source file link count differs")
    if os.name != "nt" and stat.S_IMODE(metadata.st_mode) != expected_files[relative]:
        reject("Prepared predecessor source file mode differs")
    observed_files.add(relative)
if observed_files != set(expected_files):
    reject("Prepared predecessor source inventory differs")

print(commit)
print(evidence_sha)
print(source_root)
PY
  # PREDECESSOR_ARCHIVE_BINDING_PYTHON_END
}

manifest_records() {
  local source_root="$1"
  /usr/bin/python3 -I -S -B - "${source_root}" <<'PY'
import hashlib
import json
import pathlib
import re
import sys
root = pathlib.Path(sys.argv[1])
path = root / "config/host-control-manifest.v1.json"
document = json.loads(path.read_text(encoding="utf-8"))
if set(document) != {"schemaVersion", "coreTargets", "hostPolicyTargets", "certificateTargets"} or document.get("schemaVersion") != 1:
    raise SystemExit("manifest schema differs")
targets = set()
sources = set()
required_core = {
    "/usr/local/libexec/mochirii-forums/durable-event.py",
    "/usr/local/libexec/mochirii-forums/historical-release-disaster-recovery.py",
    "/usr/local/libexec/mochirii-forums/historical-recovery-scratch-reader.sh",
    "/usr/local/libexec/mochirii-forums/host-operation-lock.py",
    "/usr/local/libexec/mochirii-forums/ssh-deploy-dispatch.py",
    "/usr/local/libexec/mochirii-forums/verify-host-security.sh",
    "/usr/local/sbin/mochirii-forums-deploy",
    "/usr/local/sbin/mochirii-forums-verify",
    "/usr/local/sbin/mochirii-forums-backup",
    "/usr/local/sbin/mochirii-forums-restore",
    "/usr/local/sbin/mochirii-forums-upgrade-host-control",
    "/usr/local/sbin/mochirii-forums-historical-disaster-recovery",
}
for group in ("coreTargets", "hostPolicyTargets", "certificateTargets"):
    rows = document.get(group)
    if not isinstance(rows, list) or not rows:
        raise SystemExit("manifest group is empty")
    for row in rows:
        if not isinstance(row, dict) or set(row) != {"source", "target", "mode"}:
            raise SystemExit("manifest target row differs")
        source, target, mode = row["source"], row["target"], row["mode"]
        if not re.fullmatch(r"(?:config|scripts)/[A-Za-z0-9._-]+", source):
            raise SystemExit("manifest source differs")
        if not isinstance(target, str) or not target.startswith(("/etc/", "/usr/local/")) or ".." in pathlib.PurePosixPath(target).parts:
            raise SystemExit("manifest target differs")
        if mode not in {"0440", "0644", "0755"} or source in sources or target in targets:
            raise SystemExit("manifest target duplicate or mode differs")
        source_path = root / source
        if not source_path.is_file() or source_path.is_symlink() or source_path.stat().st_size > 2 * 1024 * 1024:
            raise SystemExit("manifest source is unsafe")
        digest = hashlib.sha256(source_path.read_bytes()).hexdigest()
        print("\t".join((group, mode, source, target, digest)))
        sources.add(source)
        targets.add(target)
if not required_core.issubset({row["target"] for row in document["coreTargets"]}):
    raise SystemExit("manifest omitted an indispensable control target")
historical_recovery = {
    "source": "scripts/historical-release-disaster-recovery.py",
    "target": "/usr/local/libexec/mochirii-forums/historical-release-disaster-recovery.py",
    "mode": "0755",
}
if historical_recovery not in document["coreTargets"]:
    raise SystemExit("manifest historical disaster-recovery authority differs")
PY
}

seal_control_state() {
  local operation="$1" commit="$2" source_root="$3" previous_sha="$4"
  /usr/local/libexec/mochirii-forums/host-control-evidence.py seal-control \
    --operation "${operation}" --commit "${commit}" --source-root "${source_root}" \
    --previous-evidence-sha256 "${previous_sha}"
}

post_install_readback() {
  local source_root="$1" certificate_installed="$2" timer_enabled="$3" timer_active="$4"
  [[ -d ${source_root} && ! -L ${source_root} ]] || return 1
  [[ -d ${libexec_root} && ! -L ${libexec_root} && "$(stat -c '%U:%G %a' "${libexec_root}")" == "root:root 755" ]] || return 1
  sudo -u mochirii-forums-deploy test -x "${libexec_root}/ssh-deploy-dispatch.py" || return 1
  bounded 20s visudo -cf /etc/sudoers.d/mochirii-forums >/dev/null 2>&1 || return 1
  bounded 20s visudo -cf /etc/sudoers.d/mochirii-forums-operator >/dev/null 2>&1 || return 1
  bounded 20s sshd -t >/dev/null 2>&1 || return 1
  bounded 30s systemctl reload ssh >/dev/null 2>&1 || return 1
  validate_effective_hardened_ssh || return 1
  bounded 30s systemctl restart fail2ban >/dev/null 2>&1 || return 1
  bounded 30s systemctl restart unattended-upgrades >/dev/null 2>&1 || return 1
  bounded 90s systemctl restart docker >/dev/null 2>&1 || return 1
  [[ "$(bounded 20s systemctl is-active fail2ban 2>/dev/null)" == active ]] || return 1
  [[ "$(bounded 20s systemctl is-active unattended-upgrades 2>/dev/null)" == active ]] || return 1
  [[ "$(bounded 20s systemctl is-active docker 2>/dev/null)" == active ]] || return 1
  if [[ ${certificate_installed} == true ]]; then
    bounded 30s systemctl daemon-reload >/dev/null 2>&1 || return 1
    if [[ ${timer_enabled} == true ]]; then
      bounded 30s systemctl enable mochirii-forums-media-certificate-renew.timer >/dev/null 2>&1 || return 1
    else
      bounded 30s systemctl disable mochirii-forums-media-certificate-renew.timer >/dev/null 2>&1 || return 1
    fi
    if [[ ${timer_active} == true ]]; then
      bounded 30s systemctl start mochirii-forums-media-certificate-renew.timer >/dev/null 2>&1 || return 1
    else
      bounded 30s systemctl stop mochirii-forums-media-certificate-renew.timer >/dev/null 2>&1 || return 1
    fi
    [[ "$(bounded 20s systemctl is-enabled mochirii-forums-media-certificate-renew.timer 2>/dev/null)" == "$([[ ${timer_enabled} == true ]] && printf enabled || printf disabled)" ]] || return 1
    [[ "$(bounded 20s systemctl is-active mochirii-forums-media-certificate-renew.timer 2>/dev/null)" == "$([[ ${timer_active} == true ]] && printf active || printf inactive)" ]] || return 1
  fi
  bounded 20s sshd -t >/dev/null 2>&1
}

clear_transaction() {
  local transaction="$1"
  durable_remove "${pending_journal}"
  [[ ${transaction} =~ ^${upgrades_root}/[0-9a-f]{40}-[0-9a-f]{64}$ ]] || return 1
  durable_remove_workdir "${transaction}"
}

rollback_transaction() {
  local transaction="$1"
  local ssh_predecessor
  ssh_predecessor="$(/usr/bin/python3 -I -S -B - "${pending_journal}" <<'PY'
import json
import pathlib
import sys

value = json.loads(pathlib.Path(sys.argv[1]).read_text(encoding="utf-8")).get("sshActivationPredecessor")
if value not in {"service", "socket"}:
    raise SystemExit("control journal SSH activation predecessor differs")
print(value)
PY
)" || return 1
  /usr/bin/python3 -I -S -B - "${pending_journal}" "${transaction}" "${control_pointer}" <<'PY'
import hashlib
import json
import os
import pathlib
import stat
import tempfile
import sys
journal_path = pathlib.Path(sys.argv[1])
transaction = pathlib.Path(sys.argv[2])
pointer_path = pathlib.Path(sys.argv[3])
journal = json.loads(journal_path.read_text(encoding="utf-8"))
for row in journal["targets"]:
    target = pathlib.Path(row["target"])
    if row["oldPresent"]:
        backup = transaction / row["backup"]
        if hashlib.sha256(backup.read_bytes()).hexdigest() != row["oldSha256"]:
            raise SystemExit("control rollback backup differs")
        descriptor, candidate = tempfile.mkstemp(prefix=f".{target.name}.rollback.", dir=target.parent)
        try:
            os.fchmod(descriptor, int(row["oldMode"], 8))
            with backup.open("rb") as reader, os.fdopen(descriptor, "wb") as writer:
                descriptor = -1
                while chunk := reader.read(1024 * 1024):
                    writer.write(chunk)
                writer.flush()
                os.fsync(writer.fileno())
            os.chown(candidate, 0, 0)
            os.replace(candidate, target)
        finally:
            if descriptor >= 0:
                os.close(descriptor)
            try:
                os.unlink(candidate)
            except FileNotFoundError:
                pass
    else:
        try:
            target.unlink()
        except FileNotFoundError:
            pass
    parent = os.open(target.parent, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
    try:
        os.fsync(parent)
    finally:
        os.close(parent)
pointer_backup = transaction / "backup/current-host-control.json"
descriptor, candidate = tempfile.mkstemp(prefix=".current-host-control.rollback.", dir=pointer_path.parent)
try:
    os.fchmod(descriptor, 0o600)
    with pointer_backup.open("rb") as reader, os.fdopen(descriptor, "wb") as writer:
        descriptor = -1
        writer.write(reader.read())
        writer.flush()
        os.fsync(writer.fileno())
    os.chown(candidate, 0, 0)
    os.replace(candidate, pointer_path)
    parent = os.open(pointer_path.parent, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
    try:
        os.fsync(parent)
    finally:
        os.close(parent)
finally:
    if descriptor >= 0:
        os.close(descriptor)
    try:
        os.unlink(candidate)
    except FileNotFoundError:
        pass
PY
  restore_ssh_activation_predecessor "${ssh_predecessor}"
}

verify_previous_host_controls() {
  local previous_commit="$1" previous_source="$2" candidate_source="$3" ssh_predecessor="$4"
  case "${ssh_predecessor}" in
    service)
      bash "${candidate_source}/scripts/verify-host-security.sh" "${previous_commit}" "${previous_source}" --upgrade-transaction >/dev/null 2>&1
      ;;
    socket)
      bash "${candidate_source}/scripts/verify-host-security.sh" "${previous_commit}" "${previous_source}" --upgrade-socket-activation-recovery >/dev/null 2>&1
      ;;
    *) return 1 ;;
  esac
}

read_journal() {
  /usr/bin/python3 -I -S -B - "${pending_journal}" "${upgrades_root}" <<'PY'
import json
import pathlib
import re
import stat
import sys
path = pathlib.Path(sys.argv[1])
root = pathlib.Path(sys.argv[2])
metadata = path.lstat()
if not stat.S_ISREG(metadata.st_mode) or stat.S_ISLNK(metadata.st_mode) or metadata.st_uid != 0 or metadata.st_gid != 0 or stat.S_IMODE(metadata.st_mode) != 0o600:
    raise SystemExit("control journal permissions differ")
document = json.loads(path.read_text(encoding="utf-8"))
keys = {
    "schemaVersion", "operation", "phase", "repositoryCommit", "manifestSha256",
    "transactionDirectory", "certificateAutomationInstalled", "certificateTimerEnabled",
    "certificateTimerActive", "previousControlEvidenceSha256", "sshActivationPredecessor", "targets",
}
if set(document) != keys or document.get("schemaVersion") != 1 or document.get("operation") != "host-control-upgrade" or document.get("phase") != "installing":
    raise SystemExit("control journal schema differs")
commit = document.get("repositoryCommit", "")
manifest = document.get("manifestSha256", "")
expected = root / f"{commit}-{manifest}"
if not re.fullmatch(r"[0-9a-f]{40}", commit) or not re.fullmatch(r"[0-9a-f]{64}", manifest) or pathlib.Path(document.get("transactionDirectory", "")) != expected:
    raise SystemExit("control journal transaction binding differs")
for key in ("certificateAutomationInstalled", "certificateTimerEnabled", "certificateTimerActive"):
    if not isinstance(document.get(key), bool):
        raise SystemExit("control journal service state differs")
if document["certificateAutomationInstalled"] is False and (document["certificateTimerEnabled"] or document["certificateTimerActive"]):
    raise SystemExit("control journal certificate state differs")
previous = document.get("previousControlEvidenceSha256", "")
if not re.fullmatch(r"[0-9a-f]{64}", previous):
    raise SystemExit("control journal predecessor differs")
ssh_predecessor = document.get("sshActivationPredecessor")
if ssh_predecessor not in {"service", "socket"}:
    raise SystemExit("control journal SSH activation predecessor differs")
rows = document.get("targets")
if not isinstance(rows, list) or not rows:
    raise SystemExit("control journal target inventory differs")
for row in rows:
    if not isinstance(row, dict) or set(row) != {"source", "target", "newMode", "newSha256", "oldPresent", "oldMode", "oldSha256", "backup"}:
        raise SystemExit("control journal target row differs")
print(commit)
print(manifest)
print(expected)
print("true" if document["certificateAutomationInstalled"] else "false")
print("true" if document["certificateTimerEnabled"] else "false")
print("true" if document["certificateTimerActive"] else "false")
print(previous)
print(ssh_predecessor)
PY
}

targets_are_new() {
  /usr/bin/python3 -I -S -B - "${pending_journal}" <<'PY'
import hashlib
import json
import pathlib
import stat
import sys
document = json.loads(pathlib.Path(sys.argv[1]).read_text(encoding="utf-8"))
for row in document["targets"]:
    path = pathlib.Path(row["target"])
    try:
        metadata = path.lstat()
    except FileNotFoundError:
        raise SystemExit(1)
    if not stat.S_ISREG(metadata.st_mode) or stat.S_ISLNK(metadata.st_mode) or metadata.st_uid != 0 or metadata.st_gid != 0 or stat.S_IMODE(metadata.st_mode) != int(row["newMode"], 8):
        raise SystemExit(1)
    if hashlib.sha256(path.read_bytes()).hexdigest() != row["newSha256"]:
        raise SystemExit(1)
PY
}

require_postfailure_predecessor() {
  [[ ${postfailure_control_recovery} == false ]] ||
    [[ $1 == "${reviewed_acme_transport_failed_bootstrap_commit}" ]] ||
    fail "Post-failure host-control recovery requires the exact reviewed predecessor controls."
}

preflight_postfailure_predecessor() {
  [[ ${postfailure_control_recovery} == true ]] || return 0
  local output="" transaction previous_sha previous_commit previous_evidence_sha
  local -a state predecessor_state
  if [[ -e ${pending_journal} || -L ${pending_journal} ]]; then
    output="$(read_journal 2>/dev/null)" || fail "Pending host-control upgrade journal is invalid."
    (( ${#output} <= 4096 )) || fail "Pending host-control upgrade journal output exceeds its boundary."
    readarray -t state <<<"${output}"
    [[ ${#state[@]} -eq 8 ]] || fail "Pending host-control upgrade state is malformed."
    transaction="${state[2]}"
    previous_sha="${state[6]}"
    output="$(bind_previous_source "${transaction}/backup/current-host-control.json" "${transaction}" "${state_root}" identity 2>/dev/null)" ||
      fail "Pending host-control predecessor identity is invalid."
  else
    output="$(bind_previous_source "${control_pointer}" "${state_root}" "${state_root}" identity 2>/dev/null)" ||
      fail "Current host-control predecessor identity is invalid."
  fi
  (( ${#output} <= 256 )) || fail "Host-control predecessor identity output exceeds its boundary."
  readarray -t predecessor_state <<<"${output}"
  [[ ${#predecessor_state[@]} -eq 2 ]] || fail "Host-control predecessor identity is malformed."
  previous_commit="${predecessor_state[0]}"
  previous_evidence_sha="${predecessor_state[1]}"
  [[ -z ${previous_sha:-} || ${previous_evidence_sha} == "${previous_sha}" ]] || fail "Pending host-control predecessor evidence differs."
  require_postfailure_predecessor "${previous_commit}"
}

reconcile_pending() {
  local requested_commit="$1"
  local journal_output="" successor_recovery=false
  if ! journal_output="$(read_journal 2>/dev/null)"; then
    fail "Pending host-control upgrade journal is invalid."
  fi
  (( ${#journal_output} <= 4096 )) || fail "Pending host-control upgrade journal output exceeds its boundary."
  readarray -t state <<<"${journal_output}"
  [[ ${#state[@]} -eq 8 ]] || fail "Pending host-control upgrade state is malformed."
  local commit="${state[0]}" transaction="${state[2]}" certificate="${state[3]}" timer_enabled="${state[4]}" timer_active="${state[5]}" previous_sha="${state[6]}" ssh_predecessor="${state[7]}"
  if [[ ${commit} != "${requested_commit}" ]]; then
    bind_invoked_canonical_successor "${requested_commit}" "${commit}" ||
      fail "Pending host-control upgrade is not recoverable by this exact direct canonical successor."
    successor_recovery=true
  fi
  local candidate="${transaction}/source"
  local predecessor_output=""
  if ! predecessor_output="$(
    bind_previous_source "${transaction}/backup/current-host-control.json" "${transaction}" "${candidate}" verify 2>/dev/null
  )"; then
    fail "Pending host-control predecessor source is invalid."
  fi
  (( ${#predecessor_output} <= 4096 )) || fail "Pending host-control predecessor output exceeds its boundary."
  readarray -t predecessor_state <<<"${predecessor_output}"
  [[ ${#predecessor_state[@]} -eq 3 ]] || fail "Pending host-control predecessor state is malformed."
  local previous_commit="${predecessor_state[0]}" previous_evidence_sha="${predecessor_state[1]}" previous_source="${predecessor_state[2]}"
  [[ ${previous_evidence_sha} == "${previous_sha}" ]] || fail "Pending host-control predecessor evidence differs."
  require_postfailure_predecessor "${previous_commit}"
  if [[ ${successor_recovery} == false ]] && targets_are_new; then
    if ! ensure_ssh_service_activation; then
      rollback_transaction "${transaction}" || fail "OpenSSH activation commit-forward failed and exact rollback is blocked."
      post_install_readback "${previous_source}" "${certificate}" "${timer_enabled}" "${timer_active}" || fail "OpenSSH activation rollback service readback failed."
      verify_previous_host_controls "${previous_commit}" "${previous_source}" "${candidate}" "${ssh_predecessor}" || fail "OpenSSH activation rollback verification failed."
      clear_transaction "${transaction}" || fail "OpenSSH activation rollback journal could not be cleared."
      fail "OpenSSH service activation failed and restored the exact prior state."
    fi
    if ! post_install_readback "${candidate}" "${certificate}" "${timer_enabled}" "${timer_active}"; then
      rollback_transaction "${transaction}" || fail "Host-control commit-forward failed and exact rollback is blocked."
      post_install_readback "${previous_source}" "${certificate}" "${timer_enabled}" "${timer_active}" || fail "Host-control rollback service readback failed."
      verify_previous_host_controls "${previous_commit}" "${previous_source}" "${candidate}" "${ssh_predecessor}" || fail "Host-control rollback verification failed."
      clear_transaction "${transaction}" || fail "Rolled-back host-control journal could not be cleared."
      fail "Host-control upgrade failed post-install verification and restored the exact prior controls."
    fi
    seal_control_state upgrade "${commit}" "${candidate}" "${previous_sha}" || fail "Host-control commit evidence could not be sealed."
    if ! bash "${candidate}/scripts/verify-host-security.sh" "${commit}" "${candidate}" --upgrade-transaction >/dev/null 2>&1; then
      rollback_transaction "${transaction}" || fail "Committed host controls failed terminal verification and exact rollback is blocked."
      post_install_readback "${previous_source}" "${certificate}" "${timer_enabled}" "${timer_active}" || fail "Terminal host-control rollback service readback failed."
      verify_previous_host_controls "${previous_commit}" "${previous_source}" "${candidate}" "${ssh_predecessor}" || fail "Terminal host-control rollback verification failed."
      clear_transaction "${transaction}" || fail "Terminally rolled-back host-control journal could not be cleared."
      fail "Committed host controls failed terminal verification; the exact prior controls were restored."
    fi
    clear_transaction "${transaction}" || fail "Completed host-control journal could not be cleared."
    printf '%s\n' "Interrupted Mochirii Forums host-control upgrade was committed forward and verified."
    return 0
  fi
  rollback_transaction "${transaction}" || fail "Interrupted host-control upgrade is mixed and exact rollback is blocked."
  post_install_readback "${previous_source}" "${certificate}" "${timer_enabled}" "${timer_active}" || fail "Interrupted host-control rollback service readback failed."
  verify_previous_host_controls "${previous_commit}" "${previous_source}" "${candidate}" "${ssh_predecessor}" || fail "Interrupted host-control rollback failed terminal security verification."
  clear_transaction "${transaction}" || fail "Rolled-back host-control journal could not be cleared."
  if [[ ${successor_recovery} == true ]]; then
    recovery_continue=true
    printf '%s\n' "Interrupted Mochirii Forums host-control upgrade was rolled back exactly; continuing the approved canonical successor."
    return 0
  fi
  fail "Interrupted host-control upgrade was rolled back exactly; unchanged bytes must not be retried."
}

handle_signal() {
  trap - HUP INT TERM
  if [[ -e ${pending_journal} || -L ${pending_journal} ]]; then
    reconcile_pending "${expected_commit:-invalid}" || true
  fi
  exit 125
}

[[ ${EUID} -eq 0 ]] || fail "Host-control upgrade must run as root."
[[ $# -eq 2 ]] || fail "Usage: mochirii-forums-upgrade-host-control EXPECTED_COMMIT 'UPGRADE MOCHIRII FORUMS CONTROL'"
expected_commit="$1"
confirmation="$2"
[[ ${expected_commit} =~ ^[0-9a-f]{40}$ ]] || fail "Host-control upgrade commit is malformed."
[[ ${confirmation} == "UPGRADE MOCHIRII FORUMS CONTROL" ]] || fail "Exact host-control upgrade confirmation is required."
[[ ${SUDO_USER:-} == mochirii-forums-operator && -n ${SSH_CONNECTION:-} ]] || fail "Host-control upgrade requires the separately authenticated operator SSH session."

lock_helper=/usr/local/libexec/mochirii-forums/host-operation-lock.py
if /usr/bin/python3 -I -S -B "${lock_helper}" assert-held --locks primary,media 2>/dev/null; then
  :
else
  lock_status=$?
  [[ ${lock_status} -eq 3 ]] || fail "Host operation lock context is invalid."
  exec /usr/bin/python3 -I -S -B "${lock_helper}" run --locks primary,media -- /bin/bash "$0" "$@"
fi
deployment_recovery_upgrade=false
if [[ -e ${state_root}/deployment-mutation.json || -L ${state_root}/deployment-mutation.json ]]; then
  validate_failed_bootstrap_upgrade_exception "${expected_commit}" || fail "Host-control upgrade refuses this active deployment mutation."
  deployment_recovery_upgrade=true
fi
preflight_postfailure_predecessor
trap handle_signal HUP INT TERM

install -d -m 0755 -o root -g root /var/lib/mochirii "${state_root}"
install -d -m 0700 -o root -g root "${evidence_root}" "${upgrades_root}"
[[ "$(stat -c '%U:%G %a' "${state_root}")" == "root:root 755" ]] || fail "Host-control state root mode differs."
reconcile_unjournaled_workdirs || fail "An unjournaled host-control work directory is unsafe or could not be durably removed."
for unresolved in \
  "${state_root}/media-certificate-install.pending.json" \
  "${state_root}/media-certificate-preparation.pending.json" \
  "${state_root}/media-certificate-rotation.pending.json" \
  "${state_root}/acme-challenge-transaction.json"; do
  [[ ! -e ${unresolved} && ! -L ${unresolved} ]] || fail "A certificate recovery transaction blocks host-control upgrade."
done
[[ -z "$(find "${evidence_root}" -maxdepth 1 \( -name '*-storage-cleanup-required.json' -o -name '*-backup-upload-cleanup-required.json' \) -print -quit)" ]] || fail "A hosted storage recovery transaction blocks host-control upgrade."

app_inventory="$(bounded 20s docker container ls --all --filter 'name=^/app$' --format '{{.Names}}' 2>/dev/null)" || fail "Application containment readback failed or timed out."
if [[ -n ${app_inventory} ]]; then
  [[ ${app_inventory} == app ]] || fail "Application container inventory differs."
  [[ "$(bounded 20s docker inspect --type container --format '{{.State.Running}}' app 2>/dev/null)" == false ]] || fail "Host-control upgrade requires the application to be proved stopped."
fi

if [[ -e ${pending_journal} || -L ${pending_journal} ]]; then
  recovery_continue=false
  reconcile_pending "${expected_commit}"
  [[ ${recovery_continue} == true ]] || exit 0
fi

[[ -f ${control_pointer} && ! -L ${control_pointer} && "$(stat -c '%U:%G %a' "${control_pointer}")" == "root:root 600" ]] || fail "Current host-control evidence is absent or unsafe."

trusted_git_options=(
  -c credential.helper=
  -c core.askPass=
  -c init.templateDir=
  -c protocol.allow=never
  -c protocol.https.allow=always
  -c http.followRedirects=false
)
unset GIT_DIR GIT_WORK_TREE GIT_INDEX_FILE GIT_OBJECT_DIRECTORY GIT_ALTERNATE_OBJECT_DIRECTORIES
unset GIT_ASKPASS SSH_ASKPASS GIT_SSH GIT_SSH_COMMAND GIT_CONFIG_PARAMETERS GIT_CONFIG_SYSTEM GIT_PROTOCOL_FROM_USER
export GIT_TERMINAL_PROMPT=0 GIT_CONFIG_NOSYSTEM=1 GIT_CONFIG_GLOBAL=/dev/null GIT_CONFIG_COUNT=0

staging="$(mktemp -d "${state_root}/.control-upgrade-staging-${expected_commit}.XXXXXXXX")"
cleanup_staging() {
  [[ -z ${staging:-} || ! -d ${staging} ]] || durable_remove_workdir "${staging}"
}
trap cleanup_staging EXIT
bare="${staging}/trusted.git"
archive="${staging}/source.tar"
candidate="${staging}/source"
mkdir -m 0700 -- "${candidate}"
git "${trusted_git_options[@]}" init --bare "${bare}" >/dev/null 2>&1 || fail "Canonical host-control verifier initialization failed."
git "${trusted_git_options[@]}" -C "${bare}" remote add origin "${canonical_repository}" >/dev/null 2>&1 || fail "Canonical host-control remote initialization failed."
bounded 120s git "${trusted_git_options[@]}" -c protocol.version=2 -C "${bare}" fetch --no-tags --depth=1 --refmap= origin refs/heads/main >/dev/null 2>&1 || fail "Canonical host-control main could not be read."
trusted_commit="$(git "${trusted_git_options[@]}" -C "${bare}" rev-parse --verify FETCH_HEAD^{commit})" || fail "Canonical host-control main did not resolve to one commit."
[[ ${trusted_commit} == "${expected_commit}" ]] || fail "Approved host-control commit is not exact current canonical main."
trusted_tree="$(git "${trusted_git_options[@]}" -C "${bare}" rev-parse --verify "${trusted_commit}^{tree}")" || fail "Canonical host-control main tree did not resolve."
[[ ${trusted_tree} =~ ^[0-9a-f]{40}$ ]] || fail "Canonical host-control main tree is malformed."
git "${trusted_git_options[@]}" -c tar.umask=0002 -C "${bare}" archive --format=tar --output="${archive}" "${trusted_commit}" >/dev/null 2>&1 || fail "Canonical host-control archive construction failed."
tar --no-same-owner --no-same-permissions -xf "${archive}" -C "${candidate}" || fail "Canonical host-control archive extraction failed."
bounded 300s /usr/bin/python3 -I -S -B "${candidate}/scripts/validate-repository.py" --archive-root "${candidate}" >/dev/null 2>&1 || fail "Canonical host-control repository validation failed."
mapfile -t records < <(manifest_records "${candidate}") || fail "Canonical host-control manifest validation failed."
[[ ${#records[@]} -ge 20 ]] || fail "Canonical host-control target inventory is incomplete."
previous_state_output=""
if ! previous_state_output="$(
  bind_previous_source "${control_pointer}" "${staging}" "${candidate}" prepare 2>/dev/null
)"; then
  fail "Current trusted host-control predecessor archive could not be reconstructed."
fi
(( ${#previous_state_output} <= 4096 )) || fail "Current host-control predecessor output exceeds its boundary."
readarray -t previous_state <<<"${previous_state_output}"
[[ ${#previous_state[@]} -eq 3 ]] || fail "Current host-control predecessor state is malformed."
previous_commit="${previous_state[0]}"
previous_evidence_sha="${previous_state[1]}"
previous_source="${previous_state[2]}"
require_postfailure_predecessor "${previous_commit}"

for record in "${records[@]}"; do
  IFS=$'\t' read -r group mode relative target digest <<<"${record}"
  case "${relative}" in
    *.sh) bash -n "${candidate}/${relative}" || fail "Candidate shell control failed syntax validation." ;;
    *.py) /usr/bin/python3 -I -S -B - "${candidate}/${relative}" <<'PY' >/dev/null || fail "Candidate Python control failed syntax validation."
import ast
import pathlib
import sys
ast.parse(pathlib.Path(sys.argv[1]).read_text(encoding="utf-8"), filename=sys.argv[1])
PY
      ;;
  esac
done
bounded 20s visudo -cf "${candidate}/config/sudoers-forums" >/dev/null 2>&1 || fail "Candidate deploy sudoers policy is invalid."
bounded 20s visudo -cf "${candidate}/config/sudoers-forums-operator" >/dev/null 2>&1 || fail "Candidate operator sudoers policy is invalid."

ssh_predecessor="$(ssh_activation_predecessor)" || fail "OpenSSH activation state is neither the reviewed service state nor the exact Ubuntu socket-activation predecessor."
if [[ ${ssh_predecessor} == service ]]; then
  bash "${previous_source}/scripts/verify-host-security.sh" "${previous_commit}" "${previous_source}" >/dev/null 2>&1 || fail "Current host controls failed the pre-upgrade security gate."
  reconcile_shared_libexec_traversal "${previous_source}" "${candidate}" || fail "Shared host-control executable traversal could not be reconciled from the exact certificate-installer predecessor."
else
  bash "${candidate}/scripts/verify-host-security.sh" "${previous_commit}" "${previous_source}" --socket-activation-recovery >/dev/null 2>&1 || fail "Current host controls failed the exact socket-activation recovery gate."
fi

certificate_count=0
certificate_present=0
for record in "${records[@]}"; do
  IFS=$'\t' read -r group mode relative target digest <<<"${record}"
  [[ ${group} == certificateTargets ]] || continue
  certificate_count=$((certificate_count + 1))
  [[ ! -e ${target} && ! -L ${target} ]] || certificate_present=$((certificate_present + 1))
done
(( certificate_present == 0 || certificate_present == certificate_count )) || fail "Installed certificate automation target set is partial."
certificate_installed=false
timer_enabled=false
timer_active=false
if (( certificate_present == certificate_count )); then
  certificate_installed=true
  [[ "$(bounded 20s systemctl is-enabled mochirii-forums-media-certificate-renew.timer 2>/dev/null)" == enabled ]] || fail "Certificate timer is not enabled before control upgrade."
  [[ "$(bounded 20s systemctl is-active mochirii-forums-media-certificate-renew.timer 2>/dev/null)" == active ]] || fail "Certificate timer is not active before control upgrade."
  timer_enabled=true
  timer_active=true
fi

retain_disaster_recovery_sources "${archive}" "${expected_commit}" "${candidate}" "${trusted_tree}" || fail "Exact C1 and official deployment-source recovery archives could not be retained."

manifest_sha="$(sha256sum -- "${candidate}/config/host-control-manifest.v1.json" | awk '{print $1}')"
transaction="${upgrades_root}/${expected_commit}-${manifest_sha}"
[[ ! -e ${transaction} && ! -L ${transaction} ]] || fail "A host-control staging directory already exists without a journal."
mv -- "${staging}" "${transaction}"
staging=""
candidate="${transaction}/source"
previous_source="${transaction}/previous-source/${previous_commit}"
sync -d "${state_root}" 2>/dev/null || true
sync -d "${upgrades_root}" 2>/dev/null || true
install -d -m 0700 -o root -g root "${transaction}/backup"
install -m 0600 -o root -g root "${control_pointer}" "${transaction}/backup/current-host-control.json"
sync -d "${transaction}/backup" 2>/dev/null || true

/usr/bin/python3 -I -S -B - "${candidate}" "${transaction}" "${pending_journal}" "${expected_commit}" "${manifest_sha}" "${certificate_installed}" "${timer_enabled}" "${timer_active}" "${previous_evidence_sha}" "${ssh_predecessor}" <<'PY'
import hashlib
import json
import os
import pathlib
import stat
import tempfile
import sys
root = pathlib.Path(sys.argv[1])
transaction = pathlib.Path(sys.argv[2])
journal_path = pathlib.Path(sys.argv[3])
commit, manifest_sha = sys.argv[4:6]
certificate, timer_enabled, timer_active = (value == "true" for value in sys.argv[6:9])
previous = sys.argv[9]
ssh_predecessor = sys.argv[10]
if ssh_predecessor not in {"service", "socket"}:
    raise SystemExit("SSH activation predecessor differs")
manifest = json.loads((root / "config/host-control-manifest.v1.json").read_text(encoding="utf-8"))
rows = []
index = 0
for group in ("coreTargets", "hostPolicyTargets", "certificateTargets"):
    if group == "certificateTargets" and not certificate:
        continue
    for item in manifest[group]:
        source = root / item["source"]
        target = pathlib.Path(item["target"])
        backup_name = f"backup/{index:03d}"
        old_present = target.exists() or target.is_symlink()
        old_mode = None
        old_sha = None
        if old_present:
            metadata = target.lstat()
            if not stat.S_ISREG(metadata.st_mode) or stat.S_ISLNK(metadata.st_mode) or metadata.st_uid != 0 or metadata.st_gid != 0:
                raise SystemExit("existing control target is unsafe")
            old_mode = f"{stat.S_IMODE(metadata.st_mode):04o}"
            old_sha = hashlib.sha256(target.read_bytes()).hexdigest()
            backup = transaction / backup_name
            descriptor = os.open(backup, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            with target.open("rb") as reader, os.fdopen(descriptor, "wb") as writer:
                while chunk := reader.read(1024 * 1024):
                    writer.write(chunk)
                writer.flush()
                os.fsync(writer.fileno())
        rows.append({
            "source": item["source"], "target": item["target"], "newMode": item["mode"],
            "newSha256": hashlib.sha256(source.read_bytes()).hexdigest(), "oldPresent": old_present,
            "oldMode": old_mode, "oldSha256": old_sha, "backup": backup_name if old_present else None,
        })
        index += 1
backup_parent = os.open(transaction / "backup", os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
try:
    os.fsync(backup_parent)
finally:
    os.close(backup_parent)
document = {
    "schemaVersion": 1, "operation": "host-control-upgrade", "phase": "installing",
    "repositoryCommit": commit, "manifestSha256": manifest_sha,
    "transactionDirectory": str(transaction), "certificateAutomationInstalled": certificate,
    "certificateTimerEnabled": timer_enabled, "certificateTimerActive": timer_active,
    "previousControlEvidenceSha256": previous, "sshActivationPredecessor": ssh_predecessor,
    "targets": rows,
}
descriptor, candidate = tempfile.mkstemp(prefix=".control-upgrade.", suffix=".json", dir=journal_path.parent)
try:
    os.fchmod(descriptor, 0o600)
    with os.fdopen(descriptor, "w", encoding="utf-8") as target:
        descriptor = -1
        json.dump(document, target, sort_keys=True, separators=(",", ":"))
        target.write("\n")
        target.flush()
        os.fsync(target.fileno())
    os.chown(candidate, 0, 0)
    os.link(candidate, journal_path, follow_symlinks=False)
    parent = os.open(journal_path.parent, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
    try:
        os.fsync(parent)
    finally:
        os.close(parent)
finally:
    if descriptor >= 0:
        os.close(descriptor)
    try:
        os.unlink(candidate)
    except FileNotFoundError:
        pass
PY

active_transaction="${transaction}"
if [[ ${certificate_installed} == true ]]; then
  bounded 30s systemctl stop mochirii-forums-media-certificate-renew.timer >/dev/null 2>&1 || fail "Certificate timer could not be stopped after the durable control-upgrade journal was armed."
fi
for record in "${records[@]}"; do
  IFS=$'\t' read -r group mode relative target digest <<<"${record}"
  if [[ ${group} == certificateTargets && ${certificate_installed} == false ]]; then
    continue
  fi
  atomic_install "${candidate}/${relative}" "${target}" "${mode}" || fail "Host-control target publication failed; the durable journal was retained."
  [[ "$(sha256sum -- "${target}" | awk '{print $1}')" == "${digest}" ]] || fail "Published host-control target digest differs; the durable journal was retained."
done

ensure_ssh_service_activation || {
  rollback_transaction "${transaction}" || fail "OpenSSH service activation failed and exact rollback is blocked."
  post_install_readback "${previous_source}" "${certificate_installed}" "${timer_enabled}" "${timer_active}" || fail "OpenSSH activation rollback service readback failed."
  verify_previous_host_controls "${previous_commit}" "${previous_source}" "${candidate}" "${ssh_predecessor}" || fail "OpenSSH activation rollback verification failed."
  clear_transaction "${transaction}" || fail "OpenSSH activation rollback journal could not be cleared."
  fail "OpenSSH service activation failed; the exact prior controls were restored."
}

post_install_readback "${candidate}" "${certificate_installed}" "${timer_enabled}" "${timer_active}" || {
  rollback_transaction "${transaction}" || fail "Host-control post-install readback failed and rollback is blocked."
  post_install_readback "${previous_source}" "${certificate_installed}" "${timer_enabled}" "${timer_active}" || fail "Host-control rollback service readback failed."
  verify_previous_host_controls "${previous_commit}" "${previous_source}" "${candidate}" "${ssh_predecessor}" || fail "Host-control rollback verification failed."
  clear_transaction "${transaction}" || fail "Rolled-back host-control journal could not be cleared."
  fail "Host-control post-install readback failed; the exact prior controls were restored."
}
seal_control_state upgrade "${expected_commit}" "${candidate}" "${previous_evidence_sha}" || fail "Host-control evidence commit failed; the durable journal was retained."
terminal_recovery_passed=true
if [[ ${deployment_recovery_upgrade} == true ]]; then
  terminal_recovery_output="$(bash "${candidate}/scripts/quarantine-failed-bootstrap.sh" --upgrade-preflight "${expected_commit}" 2>/dev/null)" || terminal_recovery_passed=false
  [[ ${#terminal_recovery_output} -le 64 && ${terminal_recovery_output} =~ ^[0-9a-f]{40}$ ]] || terminal_recovery_passed=false
fi
if [[ ${terminal_recovery_passed} != true ]] || ! bash "${candidate}/scripts/verify-host-security.sh" "${expected_commit}" "${candidate}" --upgrade-transaction >/dev/null 2>&1; then
  rollback_transaction "${transaction}" || fail "Upgraded host controls failed terminal verification and exact rollback is blocked."
  post_install_readback "${previous_source}" "${certificate_installed}" "${timer_enabled}" "${timer_active}" || fail "Terminal host-control rollback service readback failed."
  verify_previous_host_controls "${previous_commit}" "${previous_source}" "${candidate}" "${ssh_predecessor}" || fail "Terminal host-control rollback verification failed."
  clear_transaction "${transaction}" || fail "Terminally rolled-back host-control journal could not be cleared."
  fail "Upgraded host controls failed terminal verification; the exact prior controls were restored."
fi
clear_transaction "${transaction}" || fail "Completed host-control journal could not be cleared."
active_transaction=""
upgrade_complete=true
trap - EXIT HUP INT TERM
printf '%s\n' "Mochirii Forums host controls upgraded to exact canonical main and verified."
