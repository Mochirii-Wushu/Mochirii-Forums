[CmdletBinding()]
param([string]$RepositoryRoot = (Join-Path $PSScriptRoot '..'))

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$expectedValidatorSha256 = 'a16f9ef9c23f1a10df5f3a65253bf0a7eaa7ec346efc436cea934359ab33f2af'
$expectedContractSha256 = '2174b162945c6cb95e0fe0107f25bc5b894add5ef96ff0a5cc9eb9f7e338af1d'
$expectedPythonAcceptanceRootSha256 = '5cfb43306edb37f4a96731f7fe3c6adfd63c5a6ef3f046e123d5af6cdad053b5'

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
