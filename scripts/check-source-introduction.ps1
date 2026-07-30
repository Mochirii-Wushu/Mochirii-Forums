[CmdletBinding()]
param(
    [string]$RepositoryRoot = (Resolve-Path (Join-Path $PSScriptRoot '..')).Path
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$resolvedRepositoryRoot = (Resolve-Path -LiteralPath $RepositoryRoot).Path

function Read-Json {
    param([Parameter(Mandatory)][string]$RelativePath)

    $path = Join-Path $resolvedRepositoryRoot $RelativePath
    return Get-Content -Raw -LiteralPath $path | ConvertFrom-Json
}

$source = Read-Json 'docs/operations/source-introduction.v1.json'
$runtime = Read-Json 'docs/operations/runtime-config.v1.example.json'
$recovery = Read-Json 'docs/operations/backup-restore-contract.v1.json'
$upstream = Read-Json 'docs/operations/upstream-provenance.v1.json'

if ($source.schemaVersion -ne 1 -or
    $source.status -cne 'source-only-proposal' -or
    $source.repository -cne 'Mochirii-Wushu/Mochirii-Forums' -or
    $source.upstream.repository -cne $upstream.upstream.repository -or
    $source.upstream.revision -cne $upstream.upstream.revision -or
    $source.upstream.fetchPolicy -cne 'pull-only-exact-revision' -or
    $source.upstream.pushPolicy -cne 'disabled' -or
    $source.upstream.sourceImported -ne $false -or
    $source.providerMutationAuthorized -ne $false -or
    $source.paidResourceAuthorized -ne $false) {
    throw 'Source-introduction proposal is not fail closed or does not match the reviewed upstream evidence.'
}

if ($null -ne $source.historyPreservation.selectedMethod -or
    $source.historyPreservation.reviewRequired -ne $true -or
    $source.historyPreservation.upstreamCoreModificationAllowed -ne $false) {
    throw 'History preservation must remain unresolved and upstream core modification must remain prohibited.'
}

if ($runtime.schemaVersion -ne 1 -or
    $runtime.status -cne 'redacted-non-runnable-example' -or
    $runtime.source.upstreamRevision -cne $upstream.upstream.revision -or
    $runtime.runtime.publicExposureEnabled -ne $false -or
    $runtime.runtime.jobsEnabled -ne $false -or
    $runtime.runtime.mailEnabled -ne $false) {
    throw 'Runtime example must remain redacted, non-runnable, and inactive.'
}

$requiredNullRuntimeFields = @(
    $runtime.source.repositoryCommit,
    $runtime.source.repositoryTree,
    $runtime.source.imageDigest,
    $runtime.source.sbomDigest,
    $runtime.source.provenanceReference,
    $runtime.runtime.provider,
    $runtime.runtime.region,
    $runtime.runtime.hostname,
    $runtime.secrets.runtimeStore,
    $runtime.secrets.databasePassword,
    $runtime.secrets.applicationSecret,
    $runtime.secrets.mailCredential,
    $runtime.cost.approvalReference
)
if (@($requiredNullRuntimeFields | Where-Object { $null -ne $_ }).Count -ne 0) {
    throw 'Runtime example contains a resolved provider, artifact, secret, hostname, or approval value.'
}

$activationValues = @($runtime.activation.PSObject.Properties.Value)
if (@($activationValues | Where-Object { $_ -ne $false }).Count -ne 0) {
    throw 'Every runtime activation gate must remain false.'
}

if ($recovery.schemaVersion -ne 1 -or
    $recovery.status -cne 'unexecuted-contract' -or
    $recovery.backup.encrypted -ne $true -or
    $recovery.restore.isolatedTargetRequired -ne $true -or
    $recovery.restore.outboundMailSuppressed -ne $true -or
    $recovery.restore.publicExposureDisabled -ne $true -or
    $recovery.rollback.preChangeBackupRequired -ne $true -or
    $null -ne $recovery.restore.evidenceReference -or
    $null -ne $recovery.rollback.evidenceReference -or
    $null -ne $recovery.approvalReference) {
    throw 'Backup, restore, and rollback contract must remain unexecuted and fail closed.'
}

$prohibitedRuntimeFiles = @(
    'app.yml',
    'app.yaml',
    'docker-compose.yml',
    'docker-compose.yaml',
    'Dockerfile'
)
foreach ($relativePath in $prohibitedRuntimeFiles) {
    if (Test-Path -LiteralPath (Join-Path $resolvedRepositoryRoot $relativePath)) {
        throw "Runnable forum configuration is not allowed in this source-only packet: $relativePath"
    }
}

Write-Host 'Source-introduction proposal contract passed.'
