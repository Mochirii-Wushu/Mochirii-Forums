[CmdletBinding()]
param(
    [string]$RepositoryRoot = (Join-Path $PSScriptRoot '..'),
    [switch]$RequireReachable,
    [switch]$RequirePinnedHead
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

function Invoke-GitCapture {
    param([Parameter(Mandatory)][string[]]$Arguments)

    $output = @(& git @Arguments 2>$null)
    $exitCode = $LASTEXITCODE
    if ($exitCode -ne 0) {
        throw "Git command failed: git $($Arguments -join ' ')"
    }
    return @($output | ForEach-Object { "$_".Trim() } | Where-Object { $_ })
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

$resolvedRoot = (Resolve-Path -LiteralPath $RepositoryRoot).Path
$expectedOriginUrl = 'https://github.com/Mochirii-Wushu/Mochirii-Forums.git'
$expectedUpstreamUrl = 'https://github.com/discourse/discourse_docker.git'
$expectedPushSentinel = 'disabled://upstream-push'
Push-Location -LiteralPath $resolvedRoot
try {
    $insideWorkTree = @(Invoke-GitCapture -Arguments @('rev-parse', '--is-inside-work-tree'))
    if ($insideWorkTree.Count -ne 1 -or $insideWorkTree[0] -ne 'true') {
        throw 'The selected path is not a Git working tree.'
    }

    $remoteNames = @(Invoke-GitCapture -Arguments @('remote') | Sort-Object)
    $expectedRemoteNames = @('origin', 'upstream')
    if (($remoteNames -join "`n") -cne ($expectedRemoteNames -join "`n")) {
        throw "Remote inventory must contain exactly origin and upstream; found: $($remoteNames -join ', ')"
    }

    $originFetch = @(Get-LocalConfigValues -Key 'remote.origin.url')
    $originPush = @(Get-LocalConfigValues -Key 'remote.origin.pushurl')
    if ($originFetch.Count -ne 1 -or $originFetch[0] -cne $expectedOriginUrl) {
        throw 'The origin fetch URL does not match the canonical repository.'
    }
    if ($originPush.Count -gt 1 -or
        ($originPush.Count -eq 1 -and $originPush[0] -cne $expectedOriginUrl)) {
        throw 'The origin push URL is not canonical.'
    }

    $upstreamFetch = @(Get-LocalConfigValues -Key 'remote.upstream.url')
    $upstreamPush = @(Get-LocalConfigValues -Key 'remote.upstream.pushurl')
    $upstreamFetchSpec = @(Get-LocalConfigValues -Key 'remote.upstream.fetch')
    if ($upstreamFetch.Count -ne 1 -or $upstreamFetch[0] -cne $expectedUpstreamUrl) {
        throw 'The upstream fetch URL is not the approved official repository.'
    }
    if ($upstreamPush.Count -ne 1 -or $upstreamPush[0] -cne $expectedPushSentinel) {
        throw 'The upstream push URL is not the required nonfunctional sentinel.'
    }
    if ($upstreamFetchSpec.Count -ne 1 -or
        $upstreamFetchSpec[0] -cne '+refs/heads/main:refs/remotes/upstream/main') {
        throw 'The upstream fetch refspec must map only official main.'
    }

    $pushDefault = @(Get-LocalConfigValues -Key 'remote.pushDefault')
    if ($pushDefault.Count -ne 1 -or $pushDefault[0] -cne 'origin') {
        throw 'The local push default must be exactly origin.'
    }
    $pullFf = @(Get-LocalConfigValues -Key 'pull.ff')
    if ($pullFf.Count -ne 1 -or $pullFf[0] -cne 'only') {
        throw 'The local pull policy must be fast-forward-only.'
    }
    $upstreamTagOpt = @(Get-LocalConfigValues -Key 'remote.upstream.tagOpt')
    if ($upstreamTagOpt.Count -ne 1 -or $upstreamTagOpt[0] -cne '--no-tags') {
        throw 'The upstream remote must disable automatic tag following.'
    }

    $rewriteLines = @(& git config --get-regexp '^url\..*\.(insteadOf|pushInsteadOf)$' 2>$null)
    $rewriteExitCode = $LASTEXITCODE
    if ($rewriteExitCode -notin @(0, 1)) {
        throw 'Unable to inspect Git URL rewrite configuration.'
    }
    $protectedUrls = @($expectedOriginUrl, $expectedUpstreamUrl, $expectedPushSentinel)
    foreach ($line in $rewriteLines) {
        if ("$line" -notmatch '^\S+\s+(?<prefix>.+)$') {
            throw 'Unable to parse a Git URL rewrite rule.'
        }
        $prefix = $Matches['prefix'].Trim()
        foreach ($protectedUrl in $protectedUrls) {
            if ($protectedUrl.StartsWith($prefix, [StringComparison]::OrdinalIgnoreCase)) {
                throw "A Git URL rewrite can transform a protected remote URL: $prefix"
            }
        }
    }

    $effectiveOriginFetch = @(Invoke-GitCapture -Arguments @('remote', 'get-url', 'origin'))
    $effectiveOriginPush = @(Invoke-GitCapture -Arguments @('remote', 'get-url', '--push', 'origin'))
    $effectiveUpstreamFetch = @(Invoke-GitCapture -Arguments @('remote', 'get-url', 'upstream'))
    $effectiveUpstreamPush = @(Invoke-GitCapture -Arguments @('remote', 'get-url', '--push', 'upstream'))
    if ($effectiveOriginFetch.Count -ne 1 -or $effectiveOriginFetch[0] -cne $expectedOriginUrl -or
        $effectiveOriginPush.Count -ne 1 -or $effectiveOriginPush[0] -cne $expectedOriginUrl -or
        $effectiveUpstreamFetch.Count -ne 1 -or $effectiveUpstreamFetch[0] -cne $expectedUpstreamUrl -or
        $effectiveUpstreamPush.Count -ne 1 -or $effectiveUpstreamPush[0] -cne $expectedPushSentinel) {
        throw 'An effective Git remote URL differs from the reviewed topology.'
    }

    if ($RequirePinnedHead -and -not $RequireReachable) {
        throw '-RequirePinnedHead also requires -RequireReachable.'
    }
    if ($RequireReachable) {
        $remoteHead = @(Invoke-GitCapture -Arguments @(
            'ls-remote', '--exit-code', 'upstream', 'refs/heads/main'
        ))
        if ($remoteHead.Count -ne 1 -or
            $remoteHead[0] -notmatch '^(?<sha>[0-9a-f]{40})\s+refs/heads/main$') {
            throw 'The upstream main reference did not return one valid commit.'
        }
        if ($RequirePinnedHead) {
            $manifestPath = Join-Path $resolvedRoot 'docs/operations/upstream-provenance.v1.json'
            $manifest = Get-Content -Raw -LiteralPath $manifestPath | ConvertFrom-Json
            if ($Matches['sha'] -cne $manifest.upstream.revision) {
                throw 'Upstream main moved after the reviewed provenance pin.'
            }
        }
    }

    Write-Host 'Pull-only upstream remote policy passed.'
}
finally {
    Pop-Location
}
