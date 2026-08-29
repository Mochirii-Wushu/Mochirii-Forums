[CmdletBinding()]
param(
    [string]$RepositoryRoot = (Join-Path $PSScriptRoot '..'),
    [switch]$Online
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$root = (Resolve-Path -LiteralPath $RepositoryRoot).Path
$expectedValidatorSha256 = '14f050a00fd52ad8c1d26797430970ba75ec8159a3b166ea57562eb7e68c6f86'
$expectedContractSha256 = '79062059f023ceb5f00977c1b4cef9889b904e2730f842e1202158e8fc1e079e'
$expectedPythonAcceptanceRootSha256 = '90bff09179d01ec9fdac5b9fd3b3b976d3d4172272c10bee062ecf1b844650ad'

function Get-PythonAcceptanceRootSha256 {
    param(
        [Parameter(Mandatory)][string]$ValidatorSha256,
        [Parameter(Mandatory)][string]$ContractSha256
    )
    $material = [Text.Encoding]::ASCII.GetBytes(
        'mochirii-forums-python-acceptance-root-v1' +
        [char]0 + $ValidatorSha256 + [char]0 + $ContractSha256 + [char]10
    )
    return [Convert]::ToHexString(
        [Security.Cryptography.SHA256]::HashData($material)
    ).ToLowerInvariant()
}

function Assert-ExactPythonSource {
    param([Parameter(Mandatory)][string]$Path, [Parameter(Mandatory)][string]$Sha256)
    $item = Get-Item -LiteralPath $Path -Force
    if ($item.PSIsContainer -or $null -ne $item.LinkType -or $item.Length -le 0 -or $item.Length -gt 1048576) {
        throw 'Trusted Python source is absent, linked, special, or oversized.'
    }
    if ((Get-FileHash -LiteralPath $item.FullName -Algorithm SHA256).Hash.ToLowerInvariant() -ne $Sha256) {
        throw 'Trusted Python source digest differs.'
    }
}

function Invoke-Checked {
    param([Parameter(Mandatory)][string]$Command, [Parameter(Mandatory)][string[]]$Arguments)
    & $Command @Arguments
    if ($LASTEXITCODE -ne 0) {
        throw "Validation command failed: $Command $($Arguments -join ' ')"
    }
}

Push-Location -LiteralPath $root
try {
    if ((Get-PythonAcceptanceRootSha256 -ValidatorSha256 $expectedValidatorSha256 -ContractSha256 $expectedContractSha256) -ne $expectedPythonAcceptanceRootSha256) {
        throw 'Trusted Python acceptance root differs.'
    }
    Assert-ExactPythonSource -Path (Join-Path $root 'scripts/validate-repository.py') -Sha256 $expectedValidatorSha256
    Assert-ExactPythonSource -Path (Join-Path $root 'scripts/test-contracts.py') -Sha256 $expectedContractSha256
    Invoke-Checked -Command 'python' -Arguments @('-I', '-S', '-B', 'scripts/validate-repository.py')
    Invoke-Checked -Command 'python' -Arguments @('-I', '-S', '-B', 'scripts/test-contracts.py')

    $pinArguments = @('-B', 'scripts/verify-pinned-source.py')
    if ($Online) {
        $pinArguments += '--online'
    }
    Invoke-Checked -Command 'python' -Arguments $pinArguments

    & (Join-Path $root 'scripts/test-upstream-policy.ps1')

    $parseErrors = [Collections.Generic.List[string]]::new()
    foreach ($path in Get-ChildItem -LiteralPath $root -Recurse -Filter '*.ps1' -File) {
        if ($path.FullName -like "$(Join-Path $root '.git')*") {
            continue
        }
        $tokens = $null
        $errors = $null
        [void][Management.Automation.Language.Parser]::ParseFile(
            $path.FullName,
            [ref]$tokens,
            [ref]$errors
        )
        foreach ($error in @($errors)) {
            $parseErrors.Add("$($path.FullName): $($error.Message)")
        }
    }
    if ($parseErrors.Count -gt 0) {
        throw "PowerShell parsing failed:`n$($parseErrors -join "`n")"
    }

    $pythonResidue = @(
        Get-ChildItem -LiteralPath $root -Recurse -Force |
            Where-Object {
                $_.Name -eq '__pycache__' -or
                (-not $_.PSIsContainer -and $_.Extension -in @('.pyc', '.pyo'))
            }
    )
    if ($pythonResidue.Count -gt 0) {
        throw 'Generated Python bytecode residue entered the repository validation boundary.'
    }

    & git diff --check
    if ($LASTEXITCODE -ne 0) {
        throw 'git diff --check failed.'
    }
}
finally {
    Pop-Location
}

Write-Host 'Mochirii Forums repository validation passed.'
