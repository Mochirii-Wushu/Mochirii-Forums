[CmdletBinding()]
param()

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$repositoryRoot = (Resolve-Path (Join-Path $PSScriptRoot '..')).Path
$checker = Join-Path $repositoryRoot 'scripts/check-source-introduction.ps1'
$fixtureRoot = Join-Path ([IO.Path]::GetTempPath()) (
    'mochirii-forums-source-contract-' + [Guid]::NewGuid().ToString('N')
)

function Copy-Fixture {
    $operations = Join-Path $fixtureRoot 'docs/operations'
    New-Item -ItemType Directory -Path $operations -Force | Out-Null
    @(
        'source-introduction.v1.json',
        'runtime-config.v1.example.json',
        'backup-restore-contract.v1.json',
        'upstream-provenance.v1.json'
    ) | ForEach-Object {
        Copy-Item -LiteralPath (Join-Path $repositoryRoot "docs/operations/$_") `
            -Destination (Join-Path $operations $_)
    }
}

function Assert-Rejected {
    param(
        [Parameter(Mandatory)][string]$Name,
        [Parameter(Mandatory)][scriptblock]$Mutate
    )

    if (Test-Path -LiteralPath $fixtureRoot) {
        Remove-Item -LiteralPath $fixtureRoot -Recurse -Force
    }
    Copy-Fixture
    & $Mutate

    $rejected = $false
    try {
        & $checker -RepositoryRoot $fixtureRoot | Out-Null
    }
    catch {
        $rejected = $true
    }
    if (-not $rejected) {
        throw "Source-introduction contract accepted prohibited fixture: $Name"
    }
}

try {
    Copy-Fixture
    & $checker -RepositoryRoot $fixtureRoot | Out-Null

    Assert-Rejected -Name 'source-imported' -Mutate {
        $path = Join-Path $fixtureRoot 'docs/operations/source-introduction.v1.json'
        $document = Get-Content -Raw -LiteralPath $path | ConvertFrom-Json
        $document.upstream.sourceImported = $true
        $document | ConvertTo-Json -Depth 10 | Set-Content -LiteralPath $path -Encoding utf8
    }

    Assert-Rejected -Name 'public-exposure-enabled' -Mutate {
        $path = Join-Path $fixtureRoot 'docs/operations/runtime-config.v1.example.json'
        $document = Get-Content -Raw -LiteralPath $path | ConvertFrom-Json
        $document.runtime.publicExposureEnabled = $true
        $document | ConvertTo-Json -Depth 10 | Set-Content -LiteralPath $path -Encoding utf8
    }

    Assert-Rejected -Name 'resolved-secret-placeholder' -Mutate {
        $path = Join-Path $fixtureRoot 'docs/operations/runtime-config.v1.example.json'
        $document = Get-Content -Raw -LiteralPath $path | ConvertFrom-Json
        $document.secrets.applicationSecret = 'resolved-regression-placeholder'
        $document | ConvertTo-Json -Depth 10 | Set-Content -LiteralPath $path -Encoding utf8
    }

    Assert-Rejected -Name 'runnable-app-config' -Mutate {
        Set-Content -LiteralPath (Join-Path $fixtureRoot 'app.yml') `
            -Value 'regression fixture' -Encoding utf8
    }
}
finally {
    if (Test-Path -LiteralPath $fixtureRoot) {
        Remove-Item -LiteralPath $fixtureRoot -Recurse -Force
    }
}

Write-Host 'Isolated source-introduction regression fixtures passed.'
