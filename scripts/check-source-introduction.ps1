[CmdletBinding()]
param([string]$RepositoryRoot = (Join-Path $PSScriptRoot '..'))

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$expectedValidatorSha256 = 'a202f2705c6aaab786b472802bbeacb7d99d6707996affea4d335ee3112eb431'
$expectedContractSha256 = 'f68ed1f607b66a4ef96482e71e2756f190f85e72c2e06e39f254c78e37ed9bb9'
$expectedPythonAcceptanceRootSha256 = 'a3cc176afb02aa436afbebb6e0f20fe6a47105b9f82da60a550845069128cdff'

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
$validatorPath = Join-Path $RepositoryRoot 'scripts/validate-repository.py'
$validator = Get-Item -LiteralPath $validatorPath -Force
if (
    $validator.PSIsContainer -or
    $null -ne $validator.LinkType -or
    $validator.Length -le 0 -or
    $validator.Length -gt 1048576 -or
    (Get-FileHash -LiteralPath $validator.FullName -Algorithm SHA256).Hash.ToLowerInvariant() -ne $expectedValidatorSha256
) {
    throw 'Trusted repository validator source differs.'
}
& python -I -S -B $validator.FullName
if ($LASTEXITCODE -ne 0) {
    throw 'Source-introduction contract failed.'
}
$pythonResidue = @(
    Get-ChildItem -LiteralPath $RepositoryRoot -Recurse -Force |
        Where-Object {
            $_.Name -eq '__pycache__' -or
            (-not $_.PSIsContainer -and $_.Extension -in @('.pyc', '.pyo'))
        }
)
if ($pythonResidue.Count -gt 0) {
    throw 'Generated Python bytecode residue entered the source-introduction boundary.'
}
