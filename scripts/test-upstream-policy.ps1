[CmdletBinding()]
param()

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

function Invoke-GitChecked {
    param(
        [Parameter(Mandatory)][string]$WorkingDirectory,
        [Parameter(Mandatory)][string[]]$Arguments
    )

    Push-Location -LiteralPath $WorkingDirectory
    try {
        & git @Arguments *> $null
        if ($LASTEXITCODE -ne 0) {
            throw "Fixture Git command failed: git $($Arguments -join ' ')"
        }
    }
    finally {
        Pop-Location
    }
}

function ConvertTo-FileUri {
    param([Parameter(Mandatory)][string]$Path)

    $builder = [UriBuilder]::new()
    $builder.Scheme = 'file'
    $builder.Host = ''
    $builder.Path = [IO.Path]::GetFullPath($Path)
    return $builder.Uri.AbsoluteUri
}

$configureScript = Join-Path $PSScriptRoot 'configure-upstream.ps1'
$verifyScript = Join-Path $PSScriptRoot 'verify-upstream-policy.ps1'
$temporaryBase = [IO.Path]::GetFullPath([IO.Path]::GetTempPath())
$temporaryRoot = Join-Path $temporaryBase ("mochirii-forums-upstream-{0}" -f [Guid]::NewGuid())
[IO.Directory]::CreateDirectory($temporaryRoot) | Out-Null

try {
    $upstreamPath = Join-Path $temporaryRoot 'upstream.git'
    $workPath = Join-Path $temporaryRoot 'work'
    [IO.Directory]::CreateDirectory($workPath) | Out-Null
    Invoke-GitChecked -WorkingDirectory $temporaryRoot -Arguments @('init', '--bare', $upstreamPath)
    Invoke-GitChecked -WorkingDirectory $workPath -Arguments @('init', '--initial-branch=main')

    $fixturePath = Join-Path $workPath 'fixture.txt'
    [IO.File]::WriteAllText($fixturePath, "isolated fixture`n", [Text.UTF8Encoding]::new($false))
    Invoke-GitChecked -WorkingDirectory $workPath -Arguments @('add', 'fixture.txt')
    Invoke-GitChecked -WorkingDirectory $workPath -Arguments @(
        '-c', 'user.name=Mochirii Tests',
        '-c', 'user.email=tests@invalid.example',
        'commit', '-m', 'test fixture'
    )

    $originUrl = 'https://github.com/Mochirii-Wushu/Mochirii-Forums.git'
    $upstreamUrl = ConvertTo-FileUri -Path $upstreamPath
    Invoke-GitChecked -WorkingDirectory $workPath -Arguments @('remote', 'add', 'origin', $originUrl)

    Invoke-GitChecked -WorkingDirectory $workPath -Arguments @(
        'config', '--local', '--add', "url.$upstreamUrl.insteadOf", 'disabled://upstream-push'
    )
    $unsafeConfigurationRejected = $false
    try {
        & $configureScript -RepositoryRoot $workPath -Apply *> $null
    }
    catch {
        $unsafeConfigurationRejected = $true
    }
    if (-not $unsafeConfigurationRejected) {
        throw 'The configurator did not reject a protected URL rewrite.'
    }
    $remotesAfterRollback = @(& git -C $workPath remote)
    if (($remotesAfterRollback -join "`n") -cne 'origin') {
        throw 'The configurator did not restore the prior remote inventory after failure.'
    }
    Invoke-GitChecked -WorkingDirectory $workPath -Arguments @(
        'config', '--local', '--unset-all', "url.$upstreamUrl.insteadOf"
    )

    & $configureScript -RepositoryRoot $workPath -Apply
    & $configureScript -RepositoryRoot $workPath -Apply
    & $verifyScript -RepositoryRoot $workPath

    $refsBefore = @(& git --git-dir=$upstreamPath for-each-ref --format='%(refname):%(objectname)')
    Push-Location -LiteralPath $workPath
    try {
        & git push --dry-run upstream HEAD:refs/heads/probe *> $null
        $pushExitCode = $LASTEXITCODE
    }
    finally {
        Pop-Location
    }
    if ($pushExitCode -eq 0) {
        throw 'The nonfunctional upstream push sentinel unexpectedly allowed a push.'
    }
    $refsAfter = @(& git --git-dir=$upstreamPath for-each-ref --format='%(refname):%(objectname)')
    if (($refsBefore -join "`n") -cne ($refsAfter -join "`n")) {
        throw 'The isolated upstream fixture changed during the blocked-push test.'
    }

    Invoke-GitChecked -WorkingDirectory $workPath -Arguments @(
        'config', '--local', '--add', "url.$upstreamUrl.insteadOf", 'disabled://upstream-push'
    )
    $rewriteRejected = $false
    try {
        & $verifyScript -RepositoryRoot $workPath *> $null
    }
    catch {
        $rewriteRejected = $true
    }
    if (-not $rewriteRejected) {
        throw 'The verifier did not reject a rewrite of the protected push sentinel.'
    }
    Invoke-GitChecked -WorkingDirectory $workPath -Arguments @(
        'config', '--local', '--unset-all', "url.$upstreamUrl.insteadOf"
    )

    Invoke-GitChecked -WorkingDirectory $workPath -Arguments @('remote', 'add', 'unexpected', $originUrl)
    $extraRemoteRejected = $false
    try {
        & $verifyScript -RepositoryRoot $workPath *> $null
    }
    catch {
        $extraRemoteRejected = $true
    }
    if (-not $extraRemoteRejected) {
        throw 'The verifier did not reject an unexpected third remote.'
    }

    Write-Host 'Isolated upstream policy tests passed.'
}
finally {
    $resolvedTemporaryRoot = [IO.Path]::GetFullPath($temporaryRoot)
    $expectedPrefix = Join-Path $temporaryBase 'mochirii-forums-upstream-'
    if (-not $resolvedTemporaryRoot.StartsWith($expectedPrefix, [StringComparison]::OrdinalIgnoreCase)) {
        throw 'Refusing to remove a temporary path outside the isolated test boundary.'
    }
    if ([IO.Directory]::Exists($resolvedTemporaryRoot)) {
        Remove-Item -LiteralPath $resolvedTemporaryRoot -Recurse -Force
    }
}
