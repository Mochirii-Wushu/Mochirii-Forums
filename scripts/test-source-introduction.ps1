[CmdletBinding()]
param([string]$RepositoryRoot = (Join-Path $PSScriptRoot '..'))

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$expectedValidatorSha256 = '018122d69073634ce4520af8175e1d28f128ea4d04c5c757890757fc1f2b29b6'
$expectedContractSha256 = 'a98a517a0d8d5a0386764d6172d8b791ba591338d1e435d287c6c3afb05175dd'
$expectedPythonAcceptanceRootSha256 = '005d898e771ad372926221c5c63cbfd6ca69e98ba49ed123bd9bd0a26076565d'

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

if ((Get-PythonAcceptanceRootSha256 -ValidatorSha256 $expectedValidatorSha256 -ContractSha256 $expectedContractSha256) -ne $expectedPythonAcceptanceRootSha256) {
    throw 'Trusted Python acceptance root differs.'
}
$contractPath = Join-Path $RepositoryRoot 'scripts/test-contracts.py'
$contract = Get-Item -LiteralPath $contractPath -Force
if (
    $contract.PSIsContainer -or
    $null -ne $contract.LinkType -or
    $contract.Length -le 0 -or
    $contract.Length -gt 1048576 -or
    (Get-FileHash -LiteralPath $contract.FullName -Algorithm SHA256).Hash.ToLowerInvariant() -ne $expectedContractSha256
) {
    throw 'Trusted hostile-fixture source differs.'
}
& python -I -S -B $contract.FullName
if ($LASTEXITCODE -ne 0) {
    throw 'Source-introduction hostile fixtures failed.'
}
$pythonResidue = @(
    Get-ChildItem -LiteralPath $RepositoryRoot -Recurse -Force |
        Where-Object {
            $_.Name -eq '__pycache__' -or
            (-not $_.PSIsContainer -and $_.Extension -in @('.pyc', '.pyo'))
        }
)
if ($pythonResidue.Count -gt 0) {
    throw 'Generated Python bytecode residue entered the hostile-fixture boundary.'
}
