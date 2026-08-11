[CmdletBinding()]
param(
    [string]$RepositoryRoot = (Join-Path $PSScriptRoot '..'),
    [switch]$Apply
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

if (-not $Apply) {
    throw 'No change made. Pass -Apply to configure the local pull-only upstream remote.'
}

function Get-LocalConfigValues {
    param([Parameter(Mandatory)][string]$Key)

    $output = @(& git config --local --get-all $Key 2>$null)
    $exitCode = $LASTEXITCODE
    if ($exitCode -eq 1) {
        return @()
    }
    if ($exitCode -ne 0) {
        throw "Unable to read local Git configuration key: $Key"
    }
    return @($output | ForEach-Object { "$_".Trim() })
}

function Invoke-GitChecked {
    param([Parameter(Mandatory)][string[]]$Arguments)

    & git @Arguments *> $null
    if ($LASTEXITCODE -ne 0) {
        throw "Git command failed: git $($Arguments -join ' ')"
    }
}

$resolvedRoot = (Resolve-Path -LiteralPath $RepositoryRoot).Path
$expectedOriginUrl = 'https://github.com/Mochirii-Wushu/Mochirii-Forums.git'
$upstreamUrl = 'https://github.com/discourse/discourse_docker.git'
$pushSentinel = 'disabled://upstream-push'
$expectedFetchSpec = '+refs/heads/main:refs/remotes/upstream/main'
$defaultFetchSpec = '+refs/heads/*:refs/remotes/upstream/*'
$verifyScript = Join-Path $PSScriptRoot 'verify-upstream-policy.ps1'
Push-Location -LiteralPath $resolvedRoot
try {
    $insideWorkTree = @(& git rev-parse --is-inside-work-tree 2>$null)
    if ($LASTEXITCODE -ne 0 -or $insideWorkTree.Count -ne 1 -or $insideWorkTree[0] -ne 'true') {
        throw 'The selected path is not a Git working tree.'
    }

    $originFetch = @(Get-LocalConfigValues -Key 'remote.origin.url')
    $originPush = @(Get-LocalConfigValues -Key 'remote.origin.pushurl')
    if ($originFetch.Count -ne 1 -or $originFetch[0] -cne $expectedOriginUrl) {
        throw 'Refusing to configure an upstream for an unexpected origin.'
    }
    if ($originPush.Count -gt 1 -or
        ($originPush.Count -eq 1 -and $originPush[0] -cne $expectedOriginUrl)) {
        throw 'Refusing to configure an upstream while origin has a noncanonical push URL.'
    }

    $remoteNames = @(& git remote 2>$null | ForEach-Object { "$_".Trim() } | Where-Object { $_ })
    if ($LASTEXITCODE -ne 0) {
        throw 'Unable to enumerate Git remotes.'
    }
    $unexpectedRemotes = @($remoteNames | Where-Object { $_ -notin @('origin', 'upstream') })
    if ($unexpectedRemotes.Count -gt 0) {
        throw "Refusing to configure alongside unexpected remotes: $($unexpectedRemotes -join ', ')"
    }

    $upstreamExists = $remoteNames -contains 'upstream'
    $addedUpstream = $false
    $addedPushSentinel = $false
    $addedPushDefault = $false
    $addedPullFf = $false
    $addedNoTags = $false
    $narrowedFetchSpec = $false
    $priorFetchSpec = @()
    if ($upstreamExists) {
        $existingFetch = @(Get-LocalConfigValues -Key 'remote.upstream.url')
        $existingPush = @(Get-LocalConfigValues -Key 'remote.upstream.pushurl')
        $existingFetchSpec = @(Get-LocalConfigValues -Key 'remote.upstream.fetch')
        if ($existingFetch.Count -ne 1 -or $existingFetch[0] -cne $upstreamUrl -or
            $existingFetchSpec.Count -ne 1 -or
            $existingFetchSpec[0] -notin @($expectedFetchSpec, $defaultFetchSpec)) {
            throw 'Refusing to replace an unexpected existing upstream remote.'
        }
        $priorFetchSpec = @($existingFetchSpec)
        if ($existingPush.Count -gt 1 -or
            ($existingPush.Count -eq 1 -and $existingPush[0] -cne $pushSentinel)) {
            throw 'Refusing to replace an unexpected existing upstream push URL.'
        }
    }

    $pushDefault = @(Get-LocalConfigValues -Key 'remote.pushDefault')
    if ($pushDefault.Count -gt 1 -or
        ($pushDefault.Count -eq 1 -and $pushDefault[0] -cne 'origin')) {
        throw 'Refusing to replace an unexpected push-default remote.'
    }
    $pullFf = @(Get-LocalConfigValues -Key 'pull.ff')
    if ($pullFf.Count -gt 1 -or
        ($pullFf.Count -eq 1 -and $pullFf[0] -cne 'only')) {
        throw 'Refusing to replace an unexpected pull.ff policy.'
    }
    $upstreamTagOpt = @(Get-LocalConfigValues -Key 'remote.upstream.tagOpt')
    if ($upstreamTagOpt.Count -gt 1 -or
        ($upstreamTagOpt.Count -eq 1 -and $upstreamTagOpt[0] -cne '--no-tags')) {
        throw 'Refusing to replace an unexpected upstream tag policy.'
    }

    try {
        if (-not $upstreamExists) {
            Invoke-GitChecked -Arguments @('remote', 'add', 'upstream', $upstreamUrl)
            $addedUpstream = $true
        }
        $currentFetchSpec = @(Get-LocalConfigValues -Key 'remote.upstream.fetch')
        if ($currentFetchSpec.Count -ne 1) {
            throw 'The upstream remote does not have exactly one fetch refspec.'
        }
        if ($currentFetchSpec[0] -cne $expectedFetchSpec) {
            Invoke-GitChecked -Arguments @(
                'config', '--local', '--replace-all', 'remote.upstream.fetch', $expectedFetchSpec
            )
            $narrowedFetchSpec = $true
        }
        $existingPush = @(Get-LocalConfigValues -Key 'remote.upstream.pushurl')
        if ($existingPush.Count -eq 0) {
            Invoke-GitChecked -Arguments @('remote', 'set-url', '--push', 'upstream', $pushSentinel)
            $addedPushSentinel = $true
        }
        if ($pushDefault.Count -eq 0) {
            Invoke-GitChecked -Arguments @('config', '--local', 'remote.pushDefault', 'origin')
            $addedPushDefault = $true
        }
        if ($pullFf.Count -eq 0) {
            Invoke-GitChecked -Arguments @('config', '--local', 'pull.ff', 'only')
            $addedPullFf = $true
        }
        if ($upstreamTagOpt.Count -eq 0) {
            Invoke-GitChecked -Arguments @(
                'config', '--local', 'remote.upstream.tagOpt', '--no-tags'
            )
            $addedNoTags = $true
        }

        & $verifyScript -RepositoryRoot $resolvedRoot
    }
    catch {
        $configurationError = $_
        if ($addedNoTags) {
            & git config --local --unset-all remote.upstream.tagOpt *> $null
            if ($LASTEXITCODE -ne 0) {
                throw "Upstream verification and tag-policy rollback both failed: $configurationError"
            }
        }
        if ($addedPullFf) {
            & git config --local --unset-all pull.ff *> $null
            if ($LASTEXITCODE -ne 0) {
                throw "Upstream verification and pull.ff rollback both failed: $configurationError"
            }
        }
        if ($addedPushDefault) {
            & git config --local --unset-all remote.pushDefault *> $null
            if ($LASTEXITCODE -ne 0) {
                throw "Upstream verification and push-default rollback both failed: $configurationError"
            }
        }
        if ($narrowedFetchSpec -and -not $addedUpstream) {
            & git config --local --replace-all remote.upstream.fetch $priorFetchSpec[0] *> $null
            if ($LASTEXITCODE -ne 0) {
                throw "Upstream verification and fetch-refspec rollback both failed: $configurationError"
            }
        }
        if ($addedUpstream) {
            & git remote remove upstream *> $null
            if ($LASTEXITCODE -ne 0) {
                throw "Upstream verification and rollback both failed: $configurationError"
            }
        }
        elseif ($addedPushSentinel) {
            & git config --local --unset-all remote.upstream.pushurl *> $null
            if ($LASTEXITCODE -ne 0) {
                throw "Upstream verification and rollback both failed: $configurationError"
            }
        }
        throw $configurationError
    }

    Write-Host 'Configured the local upstream as pull-only.'
}
finally {
    Pop-Location
}
