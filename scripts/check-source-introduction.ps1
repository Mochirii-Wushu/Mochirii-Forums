[CmdletBinding()]
param([string]$RepositoryRoot = (Join-Path $PSScriptRoot '..'))

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$expectedValidatorSha256 = 'ffea5da08788b2b34b8b5ac95a0e45e0227966211b1ee38feffca2fc24f28129'
$expectedContractSha256 = 'e8323a357042beb31a4879a756a43ce7fd86226b19bd48a804e14e7431c3cdb5'
$expectedPythonAcceptanceRootSha256 = 'dbd7588e9141c315cc161fd81d9cfd6f062d8795e001964bb8783a4fb63d9a57'

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
