[CmdletBinding()]
param(
    [string]$RepositoryRoot = (Join-Path $PSScriptRoot '..'),
    [switch]$Online
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$root = (Resolve-Path -LiteralPath $RepositoryRoot).Path

function Invoke-Checked {
    param([Parameter(Mandatory)][string]$Command, [Parameter(Mandatory)][string[]]$Arguments)
    & $Command @Arguments
    if ($LASTEXITCODE -ne 0) {
        throw "Validation command failed: $Command $($Arguments -join ' ')"
    }
}

Push-Location -LiteralPath $root
try {
    Invoke-Checked -Command 'python' -Arguments @('-B', 'scripts/validate-repository.py')
    Invoke-Checked -Command 'python' -Arguments @('-B', 'scripts/test-contracts.py')

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
