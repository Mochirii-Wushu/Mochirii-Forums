[CmdletBinding()]
param(
    [string]$RepositoryRoot = (Join-Path $PSScriptRoot '..'),
    [switch]$Online,
    [switch]$RequireCurrentMain
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

function Get-RemoteBytes {
    param(
        [Parameter(Mandatory)][Net.Http.HttpClient]$Client,
        [Parameter(Mandatory)][string]$Uri
    )

    for ($attempt = 1; $attempt -le 3; $attempt++) {
        try {
            $download = $Client.GetByteArrayAsync($Uri).GetAwaiter().GetResult()
            Write-Output -NoEnumerate $download
            return
        }
        catch {
            if ($attempt -eq 3) {
                throw
            }
            Start-Sleep -Seconds $attempt
        }
    }
}

$resolvedRoot = (Resolve-Path -LiteralPath $RepositoryRoot).Path
$manifestPath = Join-Path $resolvedRoot 'docs/operations/upstream-provenance.v1.json'
$manifest = Get-Content -Raw -LiteralPath $manifestPath | ConvertFrom-Json

$expectedRepository = 'https://github.com/discourse/discourse_docker.git'
$expectedPaths = @('LICENSE', 'discourse-setup', 'launcher', 'samples/standalone.yml')
if ($manifest.schemaVersion -ne 1 -or
    $manifest.upstream.repository -cne $expectedRepository -or
    $manifest.upstream.branch -cne 'main' -or
    $manifest.upstream.revision -notmatch '^[0-9a-f]{40}$' -or
    $manifest.upstream.license -cne 'MIT' -or
    $manifest.upstream.reviewStatus -cne 'source-only-pin-not-approved-for-install') {
    throw 'The upstream provenance header does not match the reviewed contract.'
}

$actualPaths = @($manifest.files | ForEach-Object { "$($_.path)" })
if (($actualPaths -join "`n") -cne ($expectedPaths -join "`n")) {
    throw 'The upstream provenance file inventory is not the reviewed allowlist.'
}
foreach ($file in $manifest.files) {
    if ($file.bytes -isnot [long] -and $file.bytes -isnot [int]) {
        throw "Invalid byte count for upstream evidence path: $($file.path)"
    }
    if ([long]$file.bytes -le 0 -or "$($file.sha256)" -notmatch '^[0-9a-f]{64}$') {
        throw "Invalid hash evidence for upstream path: $($file.path)"
    }
}

if ($RequireCurrentMain -and -not $Online) {
    throw '-RequireCurrentMain also requires -Online.'
}

if ($Online) {
    $client = [Net.Http.HttpClient]::new()
    $client.Timeout = [TimeSpan]::FromSeconds(15)
    try {
        foreach ($file in $manifest.files) {
            $uri = "https://raw.githubusercontent.com/discourse/discourse_docker/$($manifest.upstream.revision)/$($file.path)"
            $bytes = Get-RemoteBytes -Client $client -Uri $uri
            $sha256 = [Convert]::ToHexString(
                [Security.Cryptography.SHA256]::HashData($bytes)
            ).ToLowerInvariant()
            if ($bytes.Length -ne [long]$file.bytes -or $sha256 -cne "$($file.sha256)") {
                throw "Downloaded bytes do not match reviewed evidence: $($file.path)"
            }
        }
    }
    finally {
        $client.Dispose()
    }

    if ($RequireCurrentMain) {
        $headLine = @(& git ls-remote $expectedRepository refs/heads/main 2>$null)
        if ($LASTEXITCODE -ne 0 -or $headLine.Count -ne 1 -or
            $headLine[0] -notmatch '^(?<sha>[0-9a-f]{40})\s+refs/heads/main$') {
            throw 'Unable to read the official upstream main revision.'
        }
        if ($Matches['sha'] -cne $manifest.upstream.revision) {
            throw 'Official upstream main moved after the reviewed evidence was recorded.'
        }
    }
}

$manifestBytes = [IO.File]::ReadAllBytes($manifestPath)
$manifestSha256 = [Convert]::ToHexString(
    [Security.Cryptography.SHA256]::HashData($manifestBytes)
).ToLowerInvariant()
Write-Host "Upstream provenance passed (manifest sha256: $manifestSha256)."
