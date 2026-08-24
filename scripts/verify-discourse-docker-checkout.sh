#!/usr/bin/env bash
set -euo pipefail
umask 077
export LC_ALL=C

fail() {
  printf '%s\n' "$1" >&2
  exit 1
}

readonly checkout="/var/discourse"
readonly app_config="/var/discourse/containers/app.yml"
readonly revision="ed9f680b0df1de28f062de1769d89d22b2644d1b"
readonly tree="588498dffbea91592fd4e2f10166bc11c8fe7a61"
readonly canonical="https://github.com/discourse/discourse_docker.git"
readonly disabled_push="no_push://mochirii-forums-upstream"
readonly base_image="discourse/base@sha256:3b1846055ca723d13ef7dc3466da61627f32e8b212283561a6c617d759fcec48"

[[ ${EUID} -eq 0 ]] || fail "Deployment-source verification must run as root."
[[ $# -eq 0 ]] || fail "Deployment-source verification accepts no arguments."
[[ -d ${checkout}/.git && ! -L ${checkout} && ! -L ${checkout}/.git ]] || fail "Official deployment checkout is absent or linked."
[[ -f ${app_config} ]] || fail "Active application configuration is absent."
resolved_app_config="$(readlink -f -- "${app_config}")"
[[ ${resolved_app_config} == "${app_config}" || ${resolved_app_config} =~ ^/var/discourse/containers/releases/[0-9a-f]{40}/[0-9a-f]{64}/(app|restore|activation)[.]yml$ ]] || fail "Active application configuration escaped the exact container boundary."
[[ -f ${resolved_app_config} && ! -L ${resolved_app_config} ]] || fail "Resolved application configuration is unsafe."

[[ "$(git -C "${checkout}" rev-parse --verify HEAD^{commit})" == "${revision}" ]] || fail "Deployment checkout commit differs."
[[ "$(git -C "${checkout}" rev-parse --verify HEAD^{tree})" == "${tree}" ]] || fail "Deployment checkout tree differs."
if git -C "${checkout}" symbolic-ref -q HEAD >/dev/null 2>&1; then
  fail "Deployment checkout follows a branch instead of a detached revision."
fi
[[ -z "$(git -c core.fsmonitor=false -C "${checkout}" status --porcelain=v1 --untracked-files=all)" ]] || fail "Deployment checkout contains tracked or untracked drift."
mapfile -t remotes < <(git -C "${checkout}" remote)
[[ ${#remotes[@]} -eq 1 && ${remotes[0]} == origin ]] || fail "Deployment checkout remote inventory differs."
[[ "$(git -C "${checkout}" config --local --get remote.origin.url)" == "${canonical}" ]] || fail "Deployment checkout fetch remote differs."
mapfile -t push_urls < <(git -C "${checkout}" config --local --get-all remote.origin.pushurl)
[[ ${#push_urls[@]} -eq 1 && ${push_urls[0]} == "${disabled_push}" ]] || fail "Deployment checkout is not pull-only."

verify_file() {
  local relative="$1"
  local expected_size="$2"
  local expected_sha="$3"
  local path="${checkout}/${relative}"
  [[ -f ${path} && ! -L ${path} ]] || fail "Pinned deployment source file is absent or linked."
  [[ "$(stat -c '%s' "${path}")" == "${expected_size}" ]] || fail "Pinned deployment source file size differs."
  [[ "$(sha256sum -- "${path}" | awk '{print $1}')" == "${expected_sha}" ]] || fail "Pinned deployment source file digest differs."
}

verify_file launcher 25507 61df33243194e85fc45ae5cad850ec6b646b8eef2ec0ff3da4974d50867c7c39
verify_file samples/standalone.yml 4878 7690f2d3ee2eee6db7a701311bff310a7822ebdd62a0fa6687c5cb5b72296644
verify_file templates/web.template.yml 17512 975f9933f31b0172679fb741193b222fdef712ebb901fdc6064634f1ec7a9037
verify_file templates/postgres.template.yml 13450 37c12ba6725be36123a0e55f56a5fd98d045300d02f83dfda213aab3849efe8f
[[ -x ${checkout}/launcher ]] || fail "Pinned launcher is not executable."

timeout --signal=TERM --kill-after=5s 15s docker image inspect "${base_image}" >/dev/null 2>&1 || fail "Pinned deployment parser image is absent."
parser_container="mochirii-forums-source-verify-$$"
cleanup_parser() {
  local inventory
  timeout --signal=TERM --kill-after=5s 15s docker rm --force "${parser_container}" >/dev/null 2>&1 || true
  inventory="$(timeout --signal=TERM --kill-after=5s 15s docker container ls --all --filter "name=^/${parser_container}$" --format '{{.Names}}' 2>/dev/null)" || return 1
  [[ -z ${inventory} ]]
}
parser_cleanup_complete=false
on_parser_exit() {
  local status=$?
  trap - EXIT HUP INT TERM
  if [[ ${parser_cleanup_complete} == false ]] && ! cleanup_parser; then
    printf '%s\n' "CRITICAL: Pinned deployment parser containment could not be proved." >&2
    status=1
  fi
  exit "${status}"
}
trap on_parser_exit EXIT
trap 'exit 1' HUP INT TERM
parser_status=0
timeout --signal=TERM --kill-after=5s 60 docker run --rm -i --pull=never \
  --name "${parser_container}" --network none --read-only --cap-drop ALL \
  --security-opt no-new-privileges --pids-limit 64 --memory 256m --memory-swap 256m \
  "${base_image}" ruby -ryaml -e '
  expected = ARGV.fetch(0)
  document = YAML.safe_load(STDIN.read, aliases: true)
  abort "base image differs" unless document.is_a?(Hash) && document["base_image"] == expected
  templates = document["templates"]
  abort "critical templates differ" unless templates.is_a?(Array) &&
    templates.include?("templates/postgres.template.yml") &&
    templates.include?("templates/redis.template.yml") &&
    templates.include?("templates/web.template.yml")
' "${base_image}" <"${resolved_app_config}" >/dev/null 2>&1 || parser_status=$?
cleanup_parser || fail "CRITICAL: Pinned deployment parser containment could not be proved."
parser_cleanup_complete=true
trap - EXIT HUP INT TERM
(( parser_status == 0 )) || fail "Active configuration lost its sealed base image or critical templates."

printf '%s\n' "Mochirii Forums deployment source verification passed."
