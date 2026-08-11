[CmdletBinding()]
param(
    [string]$RepositoryRoot = (Resolve-Path (Join-Path $PSScriptRoot '..')).Path
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$resolvedRepositoryRoot = (Resolve-Path -LiteralPath $RepositoryRoot).Path

$expectedJsonArrayPaths = @(
    'source.customizationBoundary.plugins',
    'source.customizationBoundary.themes',
    'source.customizationBoundary.integrations',
    'runtime.network.ingressAllowlist',
    'runtime.network.outboundAllowlist',
    'runtime.maintenance.supportedUpgradeMethods',
    'runtime.health.requiredChecks',
    'recovery.scope',
    'upstream.driftObservation.materialChanges',
    'upstream.files',
    'thirdParty.application.evidenceFiles',
    'thirdParty.timeBehaviorObservation.evidenceFiles',
    'thirdParty.plugins',
    'thirdParty.themes',
    'thirdParty.integrations',
    'identity.requestEnvelope.queryKeys',
    'identity.requestEnvelope.payloadRequiredFields',
    'identity.responseEnvelope.queryKeys',
    'identity.responseEnvelope.payloadRequiredFields',
    'identity.responseEnvelope.payloadOptionalFields',
    'identity.responseEnvelope.payloadForbiddenFields',
    'identity.websiteHandback.requiredGaps',
    'identity.pinnedCoreEvidence.evidenceFiles'
)
$expectedJsonObjectArrayPaths = @(
    'upstream.driftObservation.materialChanges',
    'upstream.files',
    'thirdParty.application.evidenceFiles',
    'thirdParty.timeBehaviorObservation.evidenceFiles',
    'identity.pinnedCoreEvidence.evidenceFiles'
)

$jsonObjectPropertyInventory = @'
source|schemaVersion,status,repository,upstream,historyPreservation,customizationBoundary,thirdPartyBoundary,identityBoundary,releaseRequirements,providerMutationAuthorized,paidResourceAuthorized
source.upstream|repository,revision,manifest,remoteFetchPolicy,evidencePinPolicy,pushPolicy,sourceImported
source.historyPreservation|selectedMethod,reviewRequired,repositoryOwnershipModel,upstreamCoreModificationAllowed,vendoredCoreAllowed,forkedCoreAllowed
source.customizationBoundary|manifest,plugins,themes,integrations
source.thirdPartyBoundary|manifest,coreRevisionSelected,licensesReviewed,trademarkReviewComplete,dependencyInventoryComplete
source.identityBoundary|contract,producerRepository,consumerRepository,producerContractVersion,consumerProposalVersion,customCorePluginAllowed,activationReady
source.releaseRequirements|exactSourceCommit,exactSourceTree,exactCoreRevision,supportedRelease,installerChecksum,transitiveInstallerInputs,immutableImageDigest,sbom,thirdPartyNoticeArtifact,licenseReview,trademarkReview,provenance,configurationDigest,minimumResources,persistentSharedStorage,smtp,soleIanaTimeAuthority,health,workstationIndependence,isolatedRestore,rollbackRehearsal,accountableReview
runtime|schemaVersion,recordedAt,status,environment,source,layout,installer,resources,runtime,time,identity,data,mail,secrets,network,maintenance,health,workstationIndependence,ownership,cost,activation
runtime.source|repositoryCommit,repositoryTree,upstreamRevision,imageDigest,sbomDigest,provenanceReference
runtime.layout|deploymentModel,repositoryRoot,upstreamTemplatePath,hostRuntimeConfigPath,hostPersistentPath,containerPersistentPath,runtimeConfigCommitted,runtimeConfigRootOwnedRequired,runtimeConfigContainsSecrets
runtime.installer|upstreamPath,reviewedRevision,reviewedSha256,directNetworkPipeExecutionAllowed,transitiveInputsPinned,setupWizardImageDigest,executionApproved
runtime.resources|minimum,recommended,selectedCapacity,requirementsVerified
runtime.resources.minimum|cpuCores,memoryMiB,swapMiB,diskGiB
runtime.resources.recommended|cpuCores,memoryMiB,diskGiB
runtime.runtime|provider,region,operatingSystem,containerEngine,hostname,publicExposureEnabled,jobsEnabled,mailEnabled
runtime.time|civilTimeZone,businessCalendarTimeZone,displayTimeZone,schedulerTimeZone,storageTimeZone,protocolTimeZone,displayOffsetDerivedFromIanaAtInstant,supportedSiteWideAuthorityIdentified,supportedConfigurationArtifact,customizationManifestEntry,runtimeTzdbVersion,runtimeTzdbEvidence,browserEvidence,historicalInstantEvidence,runtimeVerified
runtime.identity|contract,role,customCorePluginAllowed,producerEndpoint,secretReference,configured,verified
runtime.data|databaseVolume,uploadsVolume,backupDestination,retentionPolicy,persistentSharedStorageVerified
runtime.mail|mochiriiSmtpRequiredBeforeLaunch,smtpProvider,smtpEndpoint,discourseIdAlternativeApproved,noSendCandidateRequired,deliverabilityVerified,spfVerified,dkimVerified,dmarcVerified,bounceAndComplaintHandlingVerified
runtime.secrets|runtimeStore,databasePassword,applicationSecret,mailCredential
runtime.network|tlsTermination,ingressAllowlist,administrativeAccess,outboundAllowlist,databasePublicExposureEnabled,redisPublicExposureEnabled,localOrPrivateHostnameAllowed
runtime.maintenance|supportedUpgradeMethods,exactVersionAndDigestRequired,preChangeBackupRequired,automaticMutablePromotionAllowed,isolatedUpgradeRehearsalPassed,rollbackDecisionDocumented,evidenceReference
runtime.health|requiredChecks,passed,evidenceReference
runtime.workstationIndependence|workstationRuntimeDependencyAllowed,privateRecoveryRuntimeDependencyAllowed,localScheduledTaskAllowed,verified
runtime.ownership|releaseOwner,runtimeOwner,backupOwner,incidentOwner
runtime.cost|approvedMonthlyMinimumUsd,approvedMonthlyExpectedUsd,approvedMonthlyMaximumUsd,approvalReference
runtime.activation|sourceIntroductionApproved,supportedReleaseSelected,installerInputsPinned,providerApproved,resourceMinimumsVerified,persistentSharedStorageVerified,secretsConfigured,smtpVerified,soleIanaTimeAuthorityImplemented,soleIanaTimeAuthorityBrowserTested,runtimeTzdbVerified,backupRestorePassed,upgradeRehearsalPassed,rollbackPassed,healthChecksPassed,workstationIndependencePassed,releaseApproved
recovery|schemaVersion,recordedAt,status,scope,topology,backup,restore,rollback,approvalReference
recovery.topology|deploymentModel,hostRuntimeConfigPath,hostPersistentPath,containerPersistentPath,localBackupPath,runtimeConfigurationStoredOutsidePersistentMount
recovery.backup|applicationBackupIncludesUploadsRequired,applicationBackupIncludesUploadsVerified,encrypted,immutableRetentionRequired,leastPrivilegeRequired,offHostDestinationRequired,destinationSeparateFromUploadsRequired,independentFreshnessMonitoringRequired,artifactDigestRequired,configurationDigestRequired,destination,retention,artifactDigest,configurationDigest,scheduledCreationPassed,independentFreshnessMonitoringPassed,measuredRpoSeconds
recovery.restore|cleanHostRequired,isolatedTargetRequired,sameApplicationVersionRequired,sameDeploymentRevisionRequired,verifiedArtifactDigestRequired,outboundMailSuppressed,publicExposureDisabled,databaseIntegrityPassed,memberBoundaryPassed,uploadsPassed,jobsPassed,runtimeConfigurationPassed,postRebootPassed,workstationOffPassed,measuredRtoSeconds,evidenceReference
recovery.rollback|preChangeBackupRequired,sourceCommitRequired,coreRevisionRequired,deploymentRevisionRequired,imageDigestRequired,configurationDigestRequired,migrationCompatibilityDecisionRequired,rehearsalPassed,evidenceReference
upstream|schemaVersion,recordedAt,upstream,driftObservation,files
upstream.upstream|repository,branch,revision,license,revisionTree,revisionCommitSignatureVerified,revisionCommitSignatureReason,reviewStatus
upstream.driftObservation|observedAt,mainRevision,mainTree,mainCommitSignatureVerified,mainCommitSignatureReason,commitsAheadOfPin,commitsBehindPin,pinIsAncestor,selectedForRuntime,automaticPinUpdateAllowed,materialChangesReviewed,materialChangesInventoryComplete,materialChangesScope,materialChanges,reviewStatus
upstream.driftObservation.materialChanges[]|commit,area,requiredGate
upstream.files[]|path,bytes,sha256
thirdParty|schemaVersion,recordedAt,status,application,supportedReleaseObservation,deployment,timeBehaviorObservation,trademark,plugins,themes,integrations,dependencies,providerMutationAuthorized,paidResourceAuthorized
thirdParty.application|name,repository,revision,sourceImported,licenseSpdx,licenseEvidenceUrl,copyrightEvidenceUrl,securityGuideUrl,evidenceFiles,exactRevisionRequiredBeforeRelease
thirdParty.application.evidenceFiles[]|path,bytes,sha256
thirdParty.supportedReleaseObservation|observedAt,releaseIndex,releasePage,tagUrl,releaseFamily,channel,tag,tagObjectSha1,tagObjectType,tagSignatureStatus,peeledCommitSha1,peeledCommitTreeSha1,peeledCommitSignatureStatus,releasedAt,plannedEndOfSupport,selectedForRuntime,compatibilityReviewed
thirdParty.deployment|name,repository,revision,sourceImported,licenseSpdx,provenanceManifest
thirdParty.timeBehaviorObservation|observedAt,coreCommit,railsStorageBaseline,siteWideDisplayAuthorityProvidedByCore,localDatesMayUseBrowserOrUserZone,calendarMayUseBrowserZone,localDatesEmailTimeZoneDefault,nonSingaporeSuggestedOrDefaultZonesPresent,supportedRuntimeSolutionSelected,runtimeAndBrowserVerified,evidenceFiles
thirdParty.timeBehaviorObservation.evidenceFiles[]|path,bytes,sha256
thirdParty.trademark|owner,evidenceUrl,brandGuidanceUrl,brandGuidanceAccessedAt,officialMarksUsedPublicly,reviewRequiredBeforePublicUse
thirdParty.dependencies|status,completeGraphAuditRequired,sbomRequired,licenseReviewRequired,noticeArtifactRequired
identity|schemaVersion,contractId,contractVersion,recordedAt,status,protocol,requestEnvelope,responseEnvelope,producer,consumer,identity,security,consumerSettings,crossRepositoryEvidence,websiteHandback,pinnedCoreEvidence,activation,providerMutationAuthorized,publicExposureAuthorized
identity.protocol|name,role,builtInDiscourseImplementationRequired,customCorePluginAllowed,signatureAlgorithm,signatureEncoding,signatureInput,payloadSerialization,producerPayloadEncoding,pinnedConsumerStrictBase64DecodingProvided,queryValueEncoding,httpsRequired,nonceBound,nonceSessionBound,nonceSingleUse,nonceExpirySeconds,exactReturnUrlValidationRequired,exactReturnPath,replayValidationRequired,signatureValidatedBeforePayloadTrust
identity.requestEnvelope|queryKeys,exactOneValuePerQueryKeyRequired,additionalQueryKeysAllowed,payloadRequiredFields,returnUrlApprovedOrigin,additionalPayloadFieldsAllowed,boundedQueryBytes
identity.responseEnvelope|queryKeys,exactOneValuePerQueryKeyRequired,additionalQueryKeysAllowed,payloadRequiredFields,payloadOptionalFields,payloadForbiddenFields,sameNonceRequired,additionalPayloadFieldsAllowed,boundedPayloadBytes
identity.producer|repository,ownership,registryContractVersion,artifact,endpoint,implementationPresent,compatibilityTestPresent
identity.consumer|repository,ownership,hostname,configurationArtifact,compatibilityTestPresent
identity.identity|externalIdType,stableExternalIdRequired,verifiedEmailRequired,currentGuildEntitlementRequired,boundedUsernameRequired,boundedNameRequired,automaticGroupGrantAllowed,automaticModeratorGrantAllowed,automaticAdminGrantAllowed,revocationRequired,logoutReconciliationRequired
identity.security|sharedSecretReference,secretValueCommitted,producerConstantTimeSignatureComparisonRequired,pinnedConsumerConstantTimeSignatureComparisonProvided,payloadEncodingProvidesConfidentiality,producerRequestAndResponseLoggingAllowed,producerPayloadQueryLoggingAllowed,pinnedConsumerGenericFailureMayLogDiagnostics,consumerLoggingPrivacyReviewRequired,consumerLoggingMitigation,consumerLoggingRiskAccepted,secretRotationEvidence,secretRecoveryEvidence,breakGlassAdminRequired
identity.consumerSettings|enableDiscourseConnect,discourseConnectUrl,discourseConnectSecretReference,discourseConnectCsrfProtection,verboseDiscourseConnectLogging,enableDiscourseConnectProvider,discourseConnectOverridesGroups,configurationApproved
identity.crossRepositoryEvidence|producerConsumerFixture,producerCompatibilityResult,consumerCompatibilityResult,entitlementLossSessionRevocationResult,logoutReconciliationResult,consumerAndProxyQueryLoggingPrivacyResult,breakGlassAdminResult,rollbackWindowDays
identity.websiteHandback|registryStatusObserved,requiredGaps
identity.pinnedCoreEvidence|commit,baseParser,model,consumerController,siteSettings,evidenceFiles
identity.pinnedCoreEvidence.evidenceFiles[]|path,bytes,sha256
identity.activation|producerContractApproved,producerDeployed,consumerConfigurationApproved,secretConfigured,fieldBoundsApproved,secretRotationAndRecoveryApproved,crossRepositoryTestsPassed,revocationAndLogoutVerified,consumerLoggingPrivacyApproved,breakGlassAdminVerified,rollbackRehearsed,enabled
capabilities|schemaVersion,recordedAt,status,repository,readback,enforcement,usage,bootstrap,providerMutationAuthorized,paidPlanAuthorized
capabilities.readback|visibility,gitRepositoryEmpty,configuredDefaultBranchName,defaultBranchRefExists,organizationPlan,branchProtectionApiAvailable,branchProtectionApiStatus,branchProtectionApiMessage,rulesetsApiAvailable,rulesetsApiStatus,rulesetsApiMessage
capabilities.enforcement|privateRepositoryRulesetsAssumed,protectedEnvironmentApprovalAssumed,codeOwnerReviewEnforced,requiredPullRequestReviewEnforced,exactHeadCiRequired,accountableHumanReviewRequired
capabilities.usage|includedActionsMinutesPerMonth,includedArtifactStorageMb,artifactStorageProviderUnit,privateWorkflowRunsConsumeSharedActionsMinutes,workflowPublishesArtifactsOrCaches,billingAndBudgetReadbackComplete,zeroIncrementalCostGuaranteed
capabilities.bootstrap|oneTimeEmptyMainSeedApproved,maintainerIdentityApproved,codeownersActivationApproved,rulesetPlanApproved
'@
$expectedJsonObjectProperties = [Collections.Generic.Dictionary[string, string[]]]::new(
    [StringComparer]::Ordinal
)
foreach ($line in ($jsonObjectPropertyInventory -split "`r?`n")) {
    if ([string]::IsNullOrWhiteSpace($line)) {
        continue
    }
    $separator = $line.IndexOf('|')
    if ($separator -le 0 -or $separator -eq $line.Length - 1) {
        throw "Invalid JSON object-property inventory row: $line"
    }
    $objectPath = $line.Substring(0, $separator)
    $propertyNames = [string[]]$line.Substring($separator + 1).Split(',')
    if (-not $expectedJsonObjectProperties.TryAdd($objectPath, $propertyNames)) {
        throw "Duplicate JSON object-property inventory path: $objectPath"
    }
}
$observedJsonObjectPaths = [Collections.Generic.HashSet[string]]::new(
    [StringComparer]::Ordinal
)

function Read-Json {
    param([Parameter(Mandatory)][string]$RelativePath)

    $path = Join-Path $resolvedRepositoryRoot $RelativePath
    return Get-Content -Raw -LiteralPath $path | ConvertFrom-Json
}

function Assert-JsonScalarContract {
    param(
        [AllowNull()][object]$Node,
        [Parameter(Mandatory)][string]$Path
    )

    if ($null -eq $Node) {
        return
    }
    if ($Node -is [pscustomobject]) {
        $normalizedObjectPath = [regex]::Replace($Path, '\[\d+\]', '[]')
        if (-not $expectedJsonObjectProperties.ContainsKey($normalizedObjectPath)) {
            throw "JSON object path is not declared by the exact contract: $normalizedObjectPath"
        }
        $expectedProperties = $expectedJsonObjectProperties[$normalizedObjectPath]
        $actualProperties = [string[]]@($Node.PSObject.Properties.Name)
        if (($actualProperties -join "`n") -cne ($expectedProperties -join "`n")) {
            throw "JSON object property inventory changed: $normalizedObjectPath"
        }
        [void]$observedJsonObjectPaths.Add($normalizedObjectPath)

        foreach ($property in $Node.PSObject.Properties) {
            $propertyPath = "$Path.$($property.Name)"
            $expectsArray = $propertyPath -cin $expectedJsonArrayPaths
            $isArray = $property.Value -is [array]
            if ($expectsArray -and -not $isArray) {
                throw "JSON array contract property is not an exact array: $propertyPath"
            }
            if (-not $expectsArray -and $isArray) {
                throw "Scalar or object contract property cannot be a JSON array: $propertyPath"
            }
            $booleanSuffixPattern = '(?:Accepted|Allowed|Approved|Assumed|Authorized|Available|Committed|Complete|Configured|Deployed|Disabled|Documented|Enabled|Enforced|Exists|Guaranteed|Identified|Implemented|Imported|Passed|Pinned|Present|Provided|Ready|Rehearsed|Required|Reviewed|Selected|Suppressed|Tested|Verified)$'
            $booleanExactNames = @(
                'accountableReview',
                'calendarMayUseBrowserZone',
                'configured',
                'displayOffsetDerivedFromIanaAtInstant',
                'discourseConnectCsrfProtection',
                'discourseConnectOverridesGroups',
                'enabled',
                'enableDiscourseConnect',
                'enableDiscourseConnectProvider',
                'encrypted',
                'exactCoreRevision',
                'exactSourceCommit',
                'exactSourceTree',
                'exactRevisionRequiredBeforeRelease',
                'gitRepositoryEmpty',
                'immutableImageDigest',
                'installerChecksum',
                'isolatedRestore',
                'licenseReview',
                'localDatesMayUseBrowserOrUserZone',
                'minimumResources',
                'mochiriiSmtpRequiredBeforeLaunch',
                'nonceBound',
                'nonceSessionBound',
                'nonceSingleUse',
                'officialMarksUsedPublicly',
                'passed',
                'payloadEncodingProvidesConfidentiality',
                'persistentSharedStorage',
                'pinIsAncestor',
                'pinnedConsumerGenericFailureMayLogDiagnostics',
                'privateWorkflowRunsConsumeSharedActionsMinutes',
                'provenance',
                'rollbackRehearsal',
                'runtimeConfigContainsSecrets',
                'runtimeConfigurationStoredOutsidePersistentMount',
                'reviewRequiredBeforePublicUse',
                'sbom',
                'selectedForRuntime',
                'signatureValidatedBeforePayloadTrust',
                'siteWideDisplayAuthorityProvidedByCore',
                'smtp',
                'soleIanaTimeAuthority',
                'supportedRelease',
                'thirdPartyNoticeArtifact',
                'trademarkReview',
                'transitiveInstallerInputs',
                'verified',
                'verboseDiscourseConnectLogging',
                'workflowPublishesArtifactsOrCaches',
                'workstationIndependencePassed'
            )
            $booleanExactPaths = @(
                'source.releaseRequirements.configurationDigest',
                'source.releaseRequirements.health',
                'source.releaseRequirements.workstationIndependence'
            )
            $expectsBoolean = (
                $property.Name -cmatch $booleanSuffixPattern -or
                $property.Name -cin $booleanExactNames -or
                $propertyPath -cin $booleanExactPaths
            )
            if ($expectsBoolean -and $property.Value -isnot [bool]) {
                throw "Boolean contract property is not an exact JSON boolean: $propertyPath"
            }
            if (-not $expectsBoolean -and $property.Value -is [bool]) {
                throw "Boolean contract property is not classified by the checker: $propertyPath"
            }

            $integerNamePattern = '^(?:branchProtectionApiStatus|bytes|commitsAheadOfPin|commitsBehindPin|cpuCores|diskGiB|includedActionsMinutesPerMonth|includedArtifactStorageMb|memoryMiB|nonceExpirySeconds|rulesetsApiStatus|schemaVersion|swapMiB)$'
            $expectsInteger = $property.Name -cmatch $integerNamePattern
            $isInteger = $property.Value -is [int] -or $property.Value -is [long]
            if ($expectsInteger -and -not $isInteger) {
                throw "Integer contract property is not an exact JSON integer: $propertyPath"
            }
            if (-not $expectsInteger -and $isInteger) {
                throw "Integer contract property is not classified by the checker: $propertyPath"
            }
            $isContainer = $property.Value -is [pscustomobject] -or $isArray
            if ($null -ne $property.Value -and
                -not $isContainer -and
                -not $expectsBoolean -and
                -not $expectsInteger -and
                $property.Value -isnot [string]) {
                throw "Scalar contract property is not an exact JSON string: $propertyPath"
            }

            Assert-JsonScalarContract -Node $property.Value -Path $propertyPath
        }
        return
    }
    if ($Node -is [Collections.IEnumerable] -and $Node -isnot [string]) {
        $expectsObjectElements = $Path -cin $expectedJsonObjectArrayPaths
        $index = 0
        foreach ($item in $Node) {
            if ($expectsObjectElements -and $item -isnot [pscustomobject]) {
                throw "JSON object-array element has the wrong type: $Path[$index]"
            }
            if (-not $expectsObjectElements -and $item -isnot [string]) {
                throw "JSON string-array element has the wrong type: $Path[$index]"
            }
            Assert-JsonScalarContract -Node $item -Path "$Path[$index]"
            $index++
        }
    }
}

$source = Read-Json 'docs/operations/source-introduction.v1.json'
$runtime = Read-Json 'docs/operations/runtime-config.v1.example.json'
$recovery = Read-Json 'docs/operations/backup-restore-contract.v1.json'
$upstream = Read-Json 'docs/operations/upstream-provenance.v1.json'
$thirdParty = Read-Json 'docs/operations/third-party-components.v1.json'
$identity = Read-Json 'docs/operations/forum-central-identity.consumer.v1.json'
$capabilities = Read-Json 'docs/operations/repository-capabilities.v1.json'

$recoveryPath = Join-Path $resolvedRepositoryRoot 'docs/operations/backup-restore-contract.v1.json'
$recoverySha256 = [Convert]::ToHexString(
    [Security.Cryptography.SHA256]::HashData([IO.File]::ReadAllBytes($recoveryPath))
).ToLowerInvariant()
if ($recoverySha256 -cne '797227459ba5c6072ef35df5187f8288e8eb53bc468323e1bdf492031222b877') {
    throw 'The separately supplied backup/restore prerequisite changed without an explicit ownership decision.'
}

foreach ($contract in @(
    @{ Name = 'source'; Document = $source }
    @{ Name = 'runtime'; Document = $runtime }
    @{ Name = 'recovery'; Document = $recovery }
    @{ Name = 'upstream'; Document = $upstream }
    @{ Name = 'thirdParty'; Document = $thirdParty }
    @{ Name = 'identity'; Document = $identity }
    @{ Name = 'capabilities'; Document = $capabilities }
)) {
    Assert-JsonScalarContract -Node $contract.Document -Path $contract.Name
}

$expectedObjectPaths = [string[]]@($expectedJsonObjectProperties.Keys)
$observedObjectPaths = [string[]]@($observedJsonObjectPaths)
[Array]::Sort($expectedObjectPaths, [StringComparer]::Ordinal)
[Array]::Sort($observedObjectPaths, [StringComparer]::Ordinal)
if (($observedObjectPaths -join "`n") -cne ($expectedObjectPaths -join "`n")) {
    throw 'One or more required JSON object shapes were absent from the contracts.'
}

if ($source.schemaVersion -ne 1 -or
    $source.status -cne 'source-only-proposal' -or
    $source.repository -cne 'Mochirii-Wushu/Mochirii-Forums' -or
    $source.upstream.repository -cne $upstream.upstream.repository -or
    $source.upstream.revision -cne $upstream.upstream.revision -or
    $source.upstream.remoteFetchPolicy -cne 'pull-only-main-drift-observation' -or
    $source.upstream.evidencePinPolicy -cne 'exact-revision' -or
    $source.upstream.pushPolicy -cne 'disabled' -or
    $source.upstream.sourceImported -ne $false -or
    $source.identityBoundary.contract -cne 'docs/operations/forum-central-identity.consumer.v1.json' -or
    $source.identityBoundary.producerRepository -cne 'Mochirii-Wushu/Mochirii-Website' -or
    $source.identityBoundary.consumerRepository -cne 'Mochirii-Wushu/Mochirii-Forums' -or
    $null -ne $source.identityBoundary.producerContractVersion -or
    $source.identityBoundary.consumerProposalVersion -cne '1.0.0-proposal' -or
    $source.identityBoundary.customCorePluginAllowed -ne $false -or
    $source.identityBoundary.activationReady -ne $false -or
    $source.thirdPartyBoundary.manifest -cne 'docs/operations/third-party-components.v1.json' -or
    $source.thirdPartyBoundary.coreRevisionSelected -ne $false -or
    $source.thirdPartyBoundary.licensesReviewed -ne $false -or
    $source.thirdPartyBoundary.trademarkReviewComplete -ne $false -or
    $source.thirdPartyBoundary.dependencyInventoryComplete -ne $false -or
    $source.providerMutationAuthorized -ne $false -or
    $source.paidResourceAuthorized -ne $false) {
    throw 'Source-introduction proposal is not fail closed or does not match the reviewed upstream evidence.'
}

if ($source.historyPreservation.selectedMethod -cne 'external-upstream-reference-no-import' -or
    $source.historyPreservation.reviewRequired -ne $false -or
    $source.historyPreservation.repositoryOwnershipModel -cne 'configuration-and-isolated-overlays-only' -or
    $source.historyPreservation.upstreamCoreModificationAllowed -ne $false -or
    $source.historyPreservation.vendoredCoreAllowed -ne $false -or
    $source.historyPreservation.forkedCoreAllowed -ne $false) {
    throw 'The permanent external-reference and configuration/overlay-only ownership boundary changed.'
}

$requiredReleaseControls = @(
    'exactSourceCommit',
    'exactSourceTree',
    'exactCoreRevision',
    'supportedRelease',
    'installerChecksum',
    'transitiveInstallerInputs',
    'immutableImageDigest',
    'sbom',
    'thirdPartyNoticeArtifact',
    'licenseReview',
    'trademarkReview',
    'provenance',
    'configurationDigest',
    'minimumResources',
    'persistentSharedStorage',
    'smtp',
    'soleIanaTimeAuthority',
    'health',
    'workstationIndependence',
    'isolatedRestore',
    'rollbackRehearsal',
    'accountableReview'
)
foreach ($control in $requiredReleaseControls) {
    if ($source.releaseRequirements.$control -ne $true) {
        throw "Source-introduction release control is not required: $control"
    }
}

if ($thirdParty.schemaVersion -ne 1 -or
    $thirdParty.recordedAt -cne '2026-08-11' -or
    $thirdParty.status -cne 'source-only-inventory-runtime-unapproved' -or
    $thirdParty.application.repository -cne 'https://github.com/discourse/discourse.git' -or
    $null -ne $thirdParty.application.revision -or
    $thirdParty.application.sourceImported -ne $false -or
    $thirdParty.application.licenseSpdx -cne 'GPL-2.0-or-later' -or
    $thirdParty.application.licenseEvidenceUrl -cne 'https://github.com/discourse/discourse/blob/cbf996f65aae3da1843224aa624bcd9a225931ac/LICENSE.txt' -or
    $thirdParty.application.copyrightEvidenceUrl -cne 'https://github.com/discourse/discourse/blob/cbf996f65aae3da1843224aa624bcd9a225931ac/COPYRIGHT.md' -or
    $thirdParty.application.securityGuideUrl -cne 'https://github.com/discourse/discourse/blob/cbf996f65aae3da1843224aa624bcd9a225931ac/docs/SECURITY.md' -or
    $thirdParty.application.exactRevisionRequiredBeforeRelease -ne $true -or
    $thirdParty.supportedReleaseObservation.observedAt -cne '2026-08-11' -or
    $thirdParty.supportedReleaseObservation.releaseIndex -cne 'https://releases.discourse.org/' -or
    $thirdParty.supportedReleaseObservation.releasePage -cne 'https://releases.discourse.org/changelog/v2026.7.1/' -or
    $thirdParty.supportedReleaseObservation.tagUrl -cne 'https://github.com/discourse/discourse/tree/v2026.7.1' -or
    $thirdParty.supportedReleaseObservation.releaseFamily -cne 'v2026.7' -or
    $thirdParty.supportedReleaseObservation.channel -cne 'ESR' -or
    $thirdParty.supportedReleaseObservation.tag -cne 'v2026.7.1' -or
    $thirdParty.supportedReleaseObservation.tagObjectSha1 -cne '11c70a765e46c3229d66e108883fa2d33f5d0b81' -or
    $thirdParty.supportedReleaseObservation.tagObjectType -cne 'tag' -or
    $thirdParty.supportedReleaseObservation.tagSignatureStatus -cne 'unsigned' -or
    $thirdParty.supportedReleaseObservation.peeledCommitSha1 -cne 'cbf996f65aae3da1843224aa624bcd9a225931ac' -or
    $thirdParty.supportedReleaseObservation.peeledCommitTreeSha1 -cne '0aeceebe79c4d2da8cf0fab213514335c201bfa7' -or
    $thirdParty.supportedReleaseObservation.peeledCommitSignatureStatus -cne 'unsigned' -or
    $thirdParty.supportedReleaseObservation.releasedAt -cne '2026-07-31' -or
    $thirdParty.supportedReleaseObservation.plannedEndOfSupport -cne '2027-03-30' -or
    $thirdParty.supportedReleaseObservation.selectedForRuntime -ne $false -or
    $thirdParty.supportedReleaseObservation.compatibilityReviewed -ne $false -or
    $thirdParty.deployment.repository -cne $upstream.upstream.repository -or
    $thirdParty.deployment.revision -cne $upstream.upstream.revision -or
    $thirdParty.deployment.sourceImported -ne $false -or
    $thirdParty.deployment.licenseSpdx -cne 'MIT' -or
    $thirdParty.deployment.provenanceManifest -cne 'docs/operations/upstream-provenance.v1.json' -or
    $thirdParty.trademark.owner -cne 'Civilized Discourse Construction Kit, Inc.' -or
    $thirdParty.trademark.evidenceUrl -cne 'https://github.com/discourse/discourse/blob/cbf996f65aae3da1843224aa624bcd9a225931ac/README.md#copyright--license' -or
    $thirdParty.trademark.brandGuidanceUrl -cne 'https://www.discourse.org/brand' -or
    $thirdParty.trademark.brandGuidanceAccessedAt -cne '2026-08-02' -or
    $thirdParty.trademark.officialMarksUsedPublicly -ne $false -or
    $thirdParty.trademark.reviewRequiredBeforePublicUse -ne $true -or
    @($thirdParty.plugins).Count -ne 0 -or
    @($thirdParty.themes).Count -ne 0 -or
    @($thirdParty.integrations).Count -ne 0 -or
    $thirdParty.dependencies.status -cne 'unavailable-until-exact-core-and-image' -or
    @(
        $thirdParty.dependencies.completeGraphAuditRequired,
        $thirdParty.dependencies.sbomRequired,
        $thirdParty.dependencies.licenseReviewRequired,
        $thirdParty.dependencies.noticeArtifactRequired
    ).Where({ $_ -ne $true }).Count -ne 0 -or
    $thirdParty.providerMutationAuthorized -ne $false -or
    $thirdParty.paidResourceAuthorized -ne $false) {
    throw 'Third-party source, license, trademark, or dependency inventory is not fail closed.'
}

$expectedApplicationEvidence = @(
    [pscustomobject]@{
        path = 'LICENSE.txt'
        bytes = 18092L
        sha256 = '8177f97513213526df2cf6184d8ff986c675afb514d4e68a404010521b880643'
    }
    [pscustomobject]@{
        path = 'COPYRIGHT.md'
        bytes = 2347L
        sha256 = '72aef96034240c4ad5de7ee98fd703e402771983b635f40e430a5a372dbe4c81'
    }
    [pscustomobject]@{
        path = 'README.md'
        bytes = 7515L
        sha256 = '784611a56172ef4a2f57f79946df034f2cde084dfef0f999f2c9f788b524b6b2'
    }
    [pscustomobject]@{
        path = 'docs/SECURITY.md'
        bytes = 4570L
        sha256 = 'e47f0680555db3748ff7fef3a756f9f4344f2aee8403c1308de5bd5c784a7fab'
    }
    [pscustomobject]@{
        path = 'lib/version.rb'
        bytes = 456L
        sha256 = '03c22af27c90cb46d96f6964b0c1d7776c4e6e4fcc47f3665a2c8dab8722cbbb'
    }
)
$actualApplicationEvidence = @($thirdParty.application.evidenceFiles)
if ($actualApplicationEvidence.Count -ne $expectedApplicationEvidence.Count) {
    throw 'The Discourse application evidence inventory changed.'
}
for ($index = 0; $index -lt $expectedApplicationEvidence.Count; $index++) {
    $expected = $expectedApplicationEvidence[$index]
    $actual = $actualApplicationEvidence[$index]
    if ($actual.path -cne $expected.path -or
        [long]$actual.bytes -ne $expected.bytes -or
        $actual.sha256 -cne $expected.sha256) {
        throw "Discourse application evidence changed at index $index."
    }
}

if ($thirdParty.timeBehaviorObservation.observedAt -cne '2026-08-11' -or
    $thirdParty.timeBehaviorObservation.coreCommit -cne 'cbf996f65aae3da1843224aa624bcd9a225931ac' -or
    $thirdParty.timeBehaviorObservation.railsStorageBaseline -cne 'UTC' -or
    $thirdParty.timeBehaviorObservation.siteWideDisplayAuthorityProvidedByCore -ne $false -or
    $thirdParty.timeBehaviorObservation.localDatesMayUseBrowserOrUserZone -ne $true -or
    $thirdParty.timeBehaviorObservation.calendarMayUseBrowserZone -ne $true -or
    $thirdParty.timeBehaviorObservation.localDatesEmailTimeZoneDefault -cne 'Etc/UTC' -or
    $thirdParty.timeBehaviorObservation.nonSingaporeSuggestedOrDefaultZonesPresent -ne $true -or
    $thirdParty.timeBehaviorObservation.supportedRuntimeSolutionSelected -ne $false -or
    $thirdParty.timeBehaviorObservation.runtimeAndBrowserVerified -ne $false) {
    throw 'The pinned core time-behavior observation overclaims site-wide Singapore authority.'
}
$expectedTimeEvidence = @(
    [pscustomobject]@{
        path = 'config/application.rb'
        bytes = 9851L
        sha256 = '6482c99fc85303969ea074474a0b55544380ac0c88224f415695415c478f9184'
    }
    [pscustomobject]@{
        path = 'plugins/discourse-local-dates/config/settings.yml'
        bytes = 511L
        sha256 = 'd90d44142b07791601a82424cd8930487e24b88e2f6d563e3477884c87beec4b'
    }
    [pscustomobject]@{
        path = 'plugins/discourse-local-dates/assets/javascripts/lib/format-local-date.js'
        bytes = 1211L
        sha256 = '1695dbe04cbe0ac94fb5cd45a4b53e9e739771c1c12bb0846e5eaef483680593'
    }
    [pscustomobject]@{
        path = 'plugins/discourse-local-dates/assets/javascripts/discourse/components/modal/local-dates-create.gjs'
        bytes = 16898L
        sha256 = '9e7f075f78f58c091032eb80b215965a529a1a91006dbef99c3dd8a5681c9f8f'
    }
    [pscustomobject]@{
        path = 'plugins/discourse-calendar/assets/javascripts/discourse/components/event-date.gjs'
        bytes = 3243L
        sha256 = '25700659167534b665275606b259d9a401172e40c07e83ec76f7f01a5ffcd377'
    }
)
$actualTimeEvidence = @($thirdParty.timeBehaviorObservation.evidenceFiles)
if ($actualTimeEvidence.Count -ne $expectedTimeEvidence.Count) {
    throw 'The pinned core time-behavior evidence inventory changed.'
}
for ($index = 0; $index -lt $expectedTimeEvidence.Count; $index++) {
    $expected = $expectedTimeEvidence[$index]
    $actual = $actualTimeEvidence[$index]
    if ($actual.path -cne $expected.path -or
        [long]$actual.bytes -ne $expected.bytes -or
        $actual.sha256 -cne $expected.sha256) {
        throw "Pinned core time-behavior evidence changed at index $index."
    }
}

$installerEvidence = @(
    $upstream.files | Where-Object { $_.path -ceq 'install-discourse' }
)
if ($installerEvidence.Count -ne 1) {
    throw 'The reviewed official installer must have exactly one provenance record.'
}

if ($runtime.schemaVersion -ne 1 -or
    $runtime.recordedAt -cne '2026-08-02' -or
    $runtime.status -cne 'redacted-non-runnable-example' -or
    $runtime.environment -cne 'candidate' -or
    $runtime.source.upstreamRevision -cne $upstream.upstream.revision -or
    $runtime.layout.deploymentModel -cne 'official-discourse-docker-standalone' -or
    $runtime.layout.repositoryRoot -cne '/var/discourse' -or
    $runtime.layout.upstreamTemplatePath -cne 'samples/standalone.yml' -or
    $runtime.layout.hostRuntimeConfigPath -cne '/var/discourse/containers/app.yml' -or
    $runtime.layout.hostPersistentPath -cne '/var/discourse/shared/standalone' -or
    $runtime.layout.containerPersistentPath -cne '/shared' -or
    $runtime.layout.runtimeConfigCommitted -ne $false -or
    $runtime.layout.runtimeConfigRootOwnedRequired -ne $true -or
    $runtime.layout.runtimeConfigContainsSecrets -ne $true -or
    $runtime.installer.upstreamPath -cne 'install-discourse' -or
    $runtime.installer.reviewedRevision -cne $upstream.upstream.revision -or
    $runtime.installer.reviewedSha256 -cne $installerEvidence[0].sha256 -or
    $runtime.installer.directNetworkPipeExecutionAllowed -ne $false -or
    $runtime.installer.transitiveInputsPinned -ne $false -or
    $runtime.installer.executionApproved -ne $false -or
    $runtime.resources.minimum.cpuCores -ne 1 -or
    $runtime.resources.minimum.memoryMiB -ne 1024 -or
    $runtime.resources.minimum.swapMiB -ne 2048 -or
    $runtime.resources.minimum.diskGiB -ne 10 -or
    $runtime.resources.recommended.cpuCores -ne 2 -or
    $runtime.resources.recommended.memoryMiB -ne 2048 -or
    $runtime.resources.recommended.diskGiB -ne 20 -or
    $runtime.resources.requirementsVerified -ne $false -or
    $runtime.runtime.publicExposureEnabled -ne $false -or
    $runtime.runtime.jobsEnabled -ne $false -or
    $runtime.runtime.mailEnabled -ne $false -or
    $runtime.time.civilTimeZone -isnot [string] -or
    $runtime.time.civilTimeZone -cne 'Asia/Singapore' -or
    $runtime.time.businessCalendarTimeZone -isnot [string] -or
    $runtime.time.businessCalendarTimeZone -cne 'Asia/Singapore' -or
    $runtime.time.displayTimeZone -isnot [string] -or
    $runtime.time.displayTimeZone -cne 'Asia/Singapore' -or
    $runtime.time.schedulerTimeZone -isnot [string] -or
    $runtime.time.schedulerTimeZone -cne 'Asia/Singapore' -or
    $runtime.time.storageTimeZone -isnot [string] -or
    $runtime.time.storageTimeZone -cne 'UTC' -or
    $runtime.time.protocolTimeZone -isnot [string] -or
    $runtime.time.protocolTimeZone -cne 'UTC' -or
    $runtime.time.displayOffsetDerivedFromIanaAtInstant -isnot [bool] -or
    $runtime.time.displayOffsetDerivedFromIanaAtInstant -ne $true -or
    $runtime.time.supportedSiteWideAuthorityIdentified -isnot [bool] -or
    $runtime.time.supportedSiteWideAuthorityIdentified -ne $false -or
    $runtime.time.runtimeVerified -isnot [bool] -or
    $runtime.time.runtimeVerified -ne $false -or
    $runtime.identity.contract -cne 'docs/operations/forum-central-identity.consumer.v1.json' -or
    $runtime.identity.role -cne 'discourse-connect-consumer' -or
    $runtime.identity.customCorePluginAllowed -ne $false -or
    $runtime.identity.configured -ne $false -or
    $runtime.identity.verified -ne $false -or
    $runtime.data.persistentSharedStorageVerified -ne $false -or
    $runtime.mail.mochiriiSmtpRequiredBeforeLaunch -ne $true -or
    $runtime.mail.discourseIdAlternativeApproved -ne $false -or
    $runtime.mail.noSendCandidateRequired -ne $true -or
    $runtime.mail.deliverabilityVerified -ne $false -or
    $runtime.mail.spfVerified -ne $false -or
    $runtime.mail.dkimVerified -ne $false -or
    $runtime.mail.dmarcVerified -ne $false -or
    $runtime.mail.bounceAndComplaintHandlingVerified -ne $false -or
    @($runtime.network.ingressAllowlist).Count -ne 0 -or
    @($runtime.network.outboundAllowlist).Count -ne 0 -or
    $runtime.network.databasePublicExposureEnabled -ne $false -or
    $runtime.network.redisPublicExposureEnabled -ne $false -or
    $runtime.network.localOrPrivateHostnameAllowed -ne $false -or
    $runtime.maintenance.exactVersionAndDigestRequired -ne $true -or
    $runtime.maintenance.preChangeBackupRequired -ne $true -or
    $runtime.maintenance.automaticMutablePromotionAllowed -ne $false -or
    $runtime.maintenance.isolatedUpgradeRehearsalPassed -ne $false -or
    $runtime.maintenance.rollbackDecisionDocumented -ne $false -or
    $runtime.health.passed -ne $false -or
    $runtime.workstationIndependence.workstationRuntimeDependencyAllowed -ne $false -or
    $runtime.workstationIndependence.privateRecoveryRuntimeDependencyAllowed -ne $false -or
    $runtime.workstationIndependence.localScheduledTaskAllowed -ne $false -or
    $runtime.workstationIndependence.verified -ne $false) {
    throw 'Runtime example must remain redacted, non-runnable, and inactive.'
}

$expectedUpgradeMethods = @('admin-upgrade', 'launcher-rebuild-app')
if ((@($runtime.maintenance.supportedUpgradeMethods) -join "`n") -cne
    ($expectedUpgradeMethods -join "`n")) {
    throw 'Runtime upgrade methods do not match the reviewed official standalone contract.'
}

$expectedHealthChecks = @(
    'bounded-https-readiness',
    'database',
    'redis',
    'background-jobs',
    'persistent-storage',
    'tls-certificate',
    'outbound-mail',
    'backup-freshness',
    'resource-saturation',
    'post-reboot',
    'workstation-off'
)
if ((@($runtime.health.requiredChecks) -join "`n") -cne
    ($expectedHealthChecks -join "`n")) {
    throw 'Runtime health checks do not match the reviewed acceptance contract.'
}

$requiredNullRuntimeFields = @(
    $runtime.source.repositoryCommit,
    $runtime.source.repositoryTree,
    $runtime.source.imageDigest,
    $runtime.source.sbomDigest,
    $runtime.source.provenanceReference,
    $runtime.installer.setupWizardImageDigest,
    $runtime.resources.selectedCapacity,
    $runtime.runtime.provider,
    $runtime.runtime.region,
    $runtime.runtime.operatingSystem,
    $runtime.runtime.containerEngine,
    $runtime.runtime.hostname,
    $runtime.time.supportedConfigurationArtifact,
    $runtime.time.customizationManifestEntry,
    $runtime.time.runtimeTzdbVersion,
    $runtime.time.runtimeTzdbEvidence,
    $runtime.time.browserEvidence,
    $runtime.time.historicalInstantEvidence,
    $runtime.data.databaseVolume,
    $runtime.data.uploadsVolume,
    $runtime.data.backupDestination,
    $runtime.data.retentionPolicy,
    $runtime.mail.smtpProvider,
    $runtime.mail.smtpEndpoint,
    $runtime.identity.producerEndpoint,
    $runtime.identity.secretReference,
    $runtime.secrets.runtimeStore,
    $runtime.secrets.databasePassword,
    $runtime.secrets.applicationSecret,
    $runtime.secrets.mailCredential,
    $runtime.network.tlsTermination,
    $runtime.network.administrativeAccess,
    $runtime.maintenance.evidenceReference,
    $runtime.health.evidenceReference,
    $runtime.ownership.releaseOwner,
    $runtime.ownership.runtimeOwner,
    $runtime.ownership.backupOwner,
    $runtime.ownership.incidentOwner,
    $runtime.cost.approvedMonthlyMinimumUsd,
    $runtime.cost.approvedMonthlyExpectedUsd,
    $runtime.cost.approvedMonthlyMaximumUsd,
    $runtime.cost.approvalReference
)
if (@($requiredNullRuntimeFields | Where-Object { $null -ne $_ }).Count -ne 0) {
    throw 'Runtime example contains a resolved provider, artifact, secret, hostname, or approval value.'
}

$activationValues = @($runtime.activation.PSObject.Properties.Value)
if (@($activationValues | Where-Object { $_ -ne $false }).Count -ne 0) {
    throw 'Every runtime activation gate must remain false.'
}

if ($identity.schemaVersion -ne 1 -or
    $identity.contractId -cne 'forum-central-identity' -or
    $identity.contractVersion -cne '1.0.0-proposal' -or
    $identity.recordedAt -cne '2026-08-11' -or
    $identity.status -cne 'blocked-website-producer-contract' -or
    $identity.protocol.name -cne 'DiscourseConnect' -or
    $identity.protocol.role -cne 'discourse-consumer' -or
    $identity.protocol.builtInDiscourseImplementationRequired -ne $true -or
    $identity.protocol.customCorePluginAllowed -ne $false -or
    $identity.protocol.signatureAlgorithm -cne 'HMAC-SHA256' -or
    $identity.protocol.signatureEncoding -cne 'lowercase-hex' -or
    $identity.protocol.signatureInput -cne 'exact-standard-base64-string' -or
    $identity.protocol.payloadSerialization -cne 'application/x-www-form-urlencoded' -or
    $identity.protocol.producerPayloadEncoding -cne 'strict-standard-base64' -or
    $identity.protocol.pinnedConsumerStrictBase64DecodingProvided -ne $false -or
    $identity.protocol.queryValueEncoding -cne 'percent-encoded' -or
    $identity.protocol.httpsRequired -ne $true -or
    $identity.protocol.nonceBound -ne $true -or
    $identity.protocol.nonceSessionBound -ne $true -or
    $identity.protocol.nonceSingleUse -ne $true -or
    $identity.protocol.nonceExpirySeconds -ne 1800 -or
    $identity.protocol.exactReturnUrlValidationRequired -ne $true -or
    $identity.protocol.exactReturnPath -cne '/session/sso_login' -or
    $identity.protocol.replayValidationRequired -ne $true -or
    $identity.protocol.signatureValidatedBeforePayloadTrust -ne $true -or
    $identity.producer.repository -cne 'Mochirii-Wushu/Mochirii-Website' -or
    $identity.producer.ownership -cne 'shared-identity-producer' -or
    $identity.producer.implementationPresent -ne $false -or
    $identity.producer.compatibilityTestPresent -ne $false -or
    $identity.consumer.repository -cne 'Mochirii-Wushu/Mochirii-Forums' -or
    $identity.consumer.ownership -cne 'discourse-consumer-configuration' -or
    $identity.consumer.compatibilityTestPresent -ne $false -or
    $identity.identity.externalIdType -cne 'opaque-string' -or
    $identity.identity.stableExternalIdRequired -ne $true -or
    $identity.identity.verifiedEmailRequired -ne $true -or
    $identity.identity.currentGuildEntitlementRequired -ne $true -or
    $identity.identity.boundedUsernameRequired -ne $true -or
    $identity.identity.boundedNameRequired -ne $true -or
    $identity.identity.automaticGroupGrantAllowed -ne $false -or
    $identity.identity.automaticModeratorGrantAllowed -ne $false -or
    $identity.identity.automaticAdminGrantAllowed -ne $false -or
    $identity.identity.revocationRequired -ne $true -or
    $identity.identity.logoutReconciliationRequired -ne $true -or
    $identity.security.secretValueCommitted -ne $false -or
    $identity.security.producerConstantTimeSignatureComparisonRequired -ne $true -or
    $identity.security.pinnedConsumerConstantTimeSignatureComparisonProvided -ne $false -or
    $identity.security.payloadEncodingProvidesConfidentiality -ne $false -or
    $identity.security.producerRequestAndResponseLoggingAllowed -ne $false -or
    $identity.security.producerPayloadQueryLoggingAllowed -ne $false -or
    $identity.security.pinnedConsumerGenericFailureMayLogDiagnostics -ne $true -or
    $identity.security.consumerLoggingPrivacyReviewRequired -ne $true -or
    $identity.security.consumerLoggingRiskAccepted -ne $false -or
    $identity.security.breakGlassAdminRequired -ne $true -or
    $identity.consumerSettings.enableDiscourseConnect -ne $false -or
    $identity.consumerSettings.discourseConnectCsrfProtection -ne $true -or
    $identity.consumerSettings.verboseDiscourseConnectLogging -ne $false -or
    $identity.consumerSettings.enableDiscourseConnectProvider -ne $false -or
    $identity.consumerSettings.discourseConnectOverridesGroups -ne $false -or
    $identity.consumerSettings.configurationApproved -ne $false -or
    $identity.websiteHandback.registryStatusObserved -cne 'unversioned' -or
    $identity.pinnedCoreEvidence.commit -cne 'cbf996f65aae3da1843224aa624bcd9a225931ac' -or
    $identity.pinnedCoreEvidence.baseParser -cne 'https://github.com/discourse/discourse/blob/cbf996f65aae3da1843224aa624bcd9a225931ac/lib/discourse_connect_base.rb' -or
    $identity.pinnedCoreEvidence.model -cne 'https://github.com/discourse/discourse/blob/cbf996f65aae3da1843224aa624bcd9a225931ac/app/models/discourse_connect.rb' -or
    $identity.pinnedCoreEvidence.consumerController -cne 'https://github.com/discourse/discourse/blob/cbf996f65aae3da1843224aa624bcd9a225931ac/app/controllers/session_controller.rb' -or
    $identity.pinnedCoreEvidence.siteSettings -cne 'https://github.com/discourse/discourse/blob/cbf996f65aae3da1843224aa624bcd9a225931ac/config/site_settings.yml' -or
    $identity.providerMutationAuthorized -ne $false -or
    $identity.publicExposureAuthorized -ne $false) {
    throw 'The central-identity consumer proposal is not the reviewed built-in, fail-closed contract.'
}

$requiredIdentityNulls = @(
    $identity.producer.registryContractVersion,
    $identity.producer.artifact,
    $identity.producer.endpoint,
    $identity.consumer.hostname,
    $identity.consumer.configurationArtifact,
    $identity.security.sharedSecretReference,
    $identity.security.consumerLoggingMitigation,
    $identity.security.secretRotationEvidence,
    $identity.security.secretRecoveryEvidence,
    $identity.consumerSettings.discourseConnectUrl,
    $identity.consumerSettings.discourseConnectSecretReference,
    $identity.requestEnvelope.returnUrlApprovedOrigin,
    $identity.requestEnvelope.boundedQueryBytes,
    $identity.responseEnvelope.boundedPayloadBytes,
    $identity.crossRepositoryEvidence.producerConsumerFixture,
    $identity.crossRepositoryEvidence.producerCompatibilityResult,
    $identity.crossRepositoryEvidence.consumerCompatibilityResult,
    $identity.crossRepositoryEvidence.entitlementLossSessionRevocationResult,
    $identity.crossRepositoryEvidence.logoutReconciliationResult,
    $identity.crossRepositoryEvidence.consumerAndProxyQueryLoggingPrivacyResult,
    $identity.crossRepositoryEvidence.breakGlassAdminResult,
    $identity.crossRepositoryEvidence.rollbackWindowDays
)
if (@($requiredIdentityNulls | Where-Object { $null -ne $_ }).Count -ne 0) {
    throw 'The central-identity proposal contains a resolved producer, consumer, secret, test, or rollback value.'
}

$expectedEnvelopeKeys = @('sso', 'sig')
if ((@($identity.requestEnvelope.queryKeys) -join "`n") -cne
        ($expectedEnvelopeKeys -join "`n") -or
    (@($identity.responseEnvelope.queryKeys) -join "`n") -cne
        ($expectedEnvelopeKeys -join "`n") -or
    $identity.requestEnvelope.exactOneValuePerQueryKeyRequired -ne $true -or
    $identity.requestEnvelope.additionalQueryKeysAllowed -ne $false -or
    $identity.responseEnvelope.exactOneValuePerQueryKeyRequired -ne $true -or
    $identity.responseEnvelope.additionalQueryKeysAllowed -ne $false) {
    throw 'The DiscourseConnect request/response query envelope changed.'
}
$expectedRequestFields = @('nonce', 'return_sso_url')
if ((@($identity.requestEnvelope.payloadRequiredFields) -join "`n") -cne
        ($expectedRequestFields -join "`n") -or
    $identity.requestEnvelope.additionalPayloadFieldsAllowed -ne $false) {
    throw 'The DiscourseConnect request payload contract changed.'
}
$expectedResponseFields = @('nonce', 'external_id', 'email')
$expectedOptionalResponseFields = @('username', 'name')
$expectedForbiddenResponseFields = @(
    'admin',
    'moderator',
    'groups',
    'add_groups',
    'remove_groups',
    'require_activation',
    'logout',
    'failed',
    'avatar_url',
    'avatar_force_update',
    'bio',
    'card_background_url',
    'profile_background_url',
    'website',
    'title',
    'location',
    'custom.*'
)
if ((@($identity.responseEnvelope.payloadRequiredFields) -join "`n") -cne
        ($expectedResponseFields -join "`n") -or
    (@($identity.responseEnvelope.payloadOptionalFields) -join "`n") -cne
        ($expectedOptionalResponseFields -join "`n") -or
    (@($identity.responseEnvelope.payloadForbiddenFields) -join "`n") -cne
        ($expectedForbiddenResponseFields -join "`n") -or
    $identity.responseEnvelope.sameNonceRequired -ne $true -or
    $identity.responseEnvelope.additionalPayloadFieldsAllowed -ne $false) {
    throw 'The DiscourseConnect response payload or privilege-denial contract changed.'
}

$expectedIdentityCoreEvidence = @(
    [pscustomobject]@{
        path = 'lib/discourse_connect_base.rb'
        bytes = 3848L
        sha256 = '7aeafcf920bfa5646ee0864c1ecbe3ad24615a89505122ea88037142ad95e638'
    }
    [pscustomobject]@{
        path = 'app/models/discourse_connect.rb'
        bytes = 14298L
        sha256 = '1d6c02b7dde6940394ea6b5016ea470c8a19c0e3e4953fcfebfde46b08c3de85'
    }
    [pscustomobject]@{
        path = 'app/controllers/session_controller.rb'
        bytes = 39512L
        sha256 = '022627791f2a237c4bfb789d9523b077f995c8a649d91a01a7006898ecc256e2'
    }
    [pscustomobject]@{
        path = 'config/site_settings.yml'
        bytes = 117684L
        sha256 = 'b50499a89a4ac5bb368670617ca75513bb458750aeaced2e0c48291e5da9653c'
    }
)
$actualIdentityCoreEvidence = @($identity.pinnedCoreEvidence.evidenceFiles)
if ($actualIdentityCoreEvidence.Count -ne $expectedIdentityCoreEvidence.Count) {
    throw 'The pinned DiscourseConnect evidence inventory changed.'
}
for ($index = 0; $index -lt $expectedIdentityCoreEvidence.Count; $index++) {
    $expected = $expectedIdentityCoreEvidence[$index]
    $actual = $actualIdentityCoreEvidence[$index]
    if ($actual.path -cne $expected.path -or
        [long]$actual.bytes -ne $expected.bytes -or
        $actual.sha256 -cne $expected.sha256) {
        throw "Pinned DiscourseConnect evidence changed at index $index."
    }
}

$expectedIdentityGaps = @(
    'contract_version',
    'versioned_artifact',
    'concrete_artifact',
    'producer_compatibility_test',
    'consumer_compatibility_test',
    'cross_repository_fixture',
    'entitlement_loss_session_revocation',
    'logout_reconciliation',
    'rollback_window'
)
if ((@($identity.websiteHandback.requiredGaps) -join "`n") -cne
    ($expectedIdentityGaps -join "`n")) {
    throw 'The Website identity handback gaps changed.'
}
$identityActivationValues = @($identity.activation.PSObject.Properties.Value)
if (@($identityActivationValues | Where-Object { $_ -ne $false }).Count -ne 0) {
    throw 'Every central-identity activation gate must remain false.'
}

if ($capabilities.schemaVersion -ne 1 -or
    $capabilities.recordedAt -cne '2026-08-11' -or
    $capabilities.status -cne 'observed-private-free-empty-origin' -or
    $capabilities.repository -cne 'Mochirii-Wushu/Mochirii-Forums' -or
    $capabilities.readback.visibility -cne 'private' -or
    $capabilities.readback.gitRepositoryEmpty -ne $true -or
    $capabilities.readback.configuredDefaultBranchName -cne 'main' -or
    $capabilities.readback.defaultBranchRefExists -ne $false -or
    $capabilities.readback.organizationPlan -cne 'free' -or
    $capabilities.readback.branchProtectionApiAvailable -ne $false -or
    $capabilities.readback.branchProtectionApiStatus -ne 403 -or
    $capabilities.readback.branchProtectionApiMessage -cne 'Upgrade to GitHub Pro or make this repository public to enable this feature.' -or
    $capabilities.readback.rulesetsApiAvailable -ne $false -or
    $capabilities.readback.rulesetsApiStatus -ne 403 -or
    $capabilities.readback.rulesetsApiMessage -cne 'Upgrade to GitHub Pro or make this repository public to enable this feature.' -or
    $capabilities.enforcement.privateRepositoryRulesetsAssumed -ne $false -or
    $capabilities.enforcement.protectedEnvironmentApprovalAssumed -ne $false -or
    $capabilities.enforcement.codeOwnerReviewEnforced -ne $false -or
    $capabilities.enforcement.requiredPullRequestReviewEnforced -ne $false -or
    $capabilities.enforcement.exactHeadCiRequired -ne $true -or
    $capabilities.enforcement.accountableHumanReviewRequired -ne $true -or
    $capabilities.usage.includedActionsMinutesPerMonth -ne 2000 -or
    $capabilities.usage.includedArtifactStorageMb -ne 500 -or
    $capabilities.usage.artifactStorageProviderUnit -cne 'MB' -or
    $capabilities.usage.privateWorkflowRunsConsumeSharedActionsMinutes -ne $true -or
    $capabilities.usage.workflowPublishesArtifactsOrCaches -ne $false -or
    $capabilities.usage.billingAndBudgetReadbackComplete -ne $false -or
    $capabilities.usage.zeroIncrementalCostGuaranteed -ne $false -or
    @($capabilities.bootstrap.PSObject.Properties.Value).Where({ $_ -ne $false }).Count -ne 0 -or
    $capabilities.providerMutationAuthorized -ne $false -or
    $capabilities.paidPlanAuthorized -ne $false) {
    throw 'The private-Free repository capability record overclaims enforcement or authorization.'
}

if ($recovery.schemaVersion -ne 1 -or
    $recovery.recordedAt -cne '2026-08-02' -or
    $recovery.status -cne 'unexecuted-contract' -or
    (@($recovery.scope) -join "`n") -cne (@(
        'discourse-application-backup-with-uploads',
        'reviewed-runtime-configuration',
        'required-encryption-key-references'
    ) -join "`n") -or
    $recovery.topology.deploymentModel -cne $runtime.layout.deploymentModel -or
    $recovery.topology.hostRuntimeConfigPath -cne $runtime.layout.hostRuntimeConfigPath -or
    $recovery.topology.hostPersistentPath -cne $runtime.layout.hostPersistentPath -or
    $recovery.topology.containerPersistentPath -cne $runtime.layout.containerPersistentPath -or
    $recovery.topology.localBackupPath -cne '/var/discourse/shared/standalone/backups/default' -or
    $recovery.topology.runtimeConfigurationStoredOutsidePersistentMount -ne $true -or
    $recovery.backup.applicationBackupIncludesUploadsRequired -ne $true -or
    $recovery.backup.applicationBackupIncludesUploadsVerified -ne $false -or
    $recovery.backup.encrypted -ne $true -or
    $recovery.backup.immutableRetentionRequired -ne $true -or
    $recovery.backup.leastPrivilegeRequired -ne $true -or
    $recovery.backup.offHostDestinationRequired -ne $true -or
    $recovery.backup.destinationSeparateFromUploadsRequired -ne $true -or
    $recovery.backup.independentFreshnessMonitoringRequired -ne $true -or
    $recovery.backup.artifactDigestRequired -ne $true -or
    $recovery.backup.configurationDigestRequired -ne $true -or
    $recovery.backup.scheduledCreationPassed -ne $false -or
    $recovery.backup.independentFreshnessMonitoringPassed -ne $false -or
    $recovery.restore.cleanHostRequired -ne $true -or
    $recovery.restore.isolatedTargetRequired -ne $true -or
    $recovery.restore.sameApplicationVersionRequired -ne $true -or
    $recovery.restore.sameDeploymentRevisionRequired -ne $true -or
    $recovery.restore.verifiedArtifactDigestRequired -ne $true -or
    $recovery.restore.outboundMailSuppressed -ne $true -or
    $recovery.restore.publicExposureDisabled -ne $true -or
    @(
        $recovery.restore.databaseIntegrityPassed,
        $recovery.restore.memberBoundaryPassed,
        $recovery.restore.uploadsPassed,
        $recovery.restore.jobsPassed,
        $recovery.restore.runtimeConfigurationPassed,
        $recovery.restore.postRebootPassed,
        $recovery.restore.workstationOffPassed
    ).Where({ $_ -ne $false }).Count -ne 0 -or
    $recovery.rollback.preChangeBackupRequired -ne $true -or
    $recovery.rollback.sourceCommitRequired -ne $true -or
    $recovery.rollback.coreRevisionRequired -ne $true -or
    $recovery.rollback.deploymentRevisionRequired -ne $true -or
    $recovery.rollback.imageDigestRequired -ne $true -or
    $recovery.rollback.configurationDigestRequired -ne $true -or
    $recovery.rollback.migrationCompatibilityDecisionRequired -ne $true -or
    $recovery.rollback.rehearsalPassed -ne $false -or
    @(
        $recovery.backup.destination,
        $recovery.backup.retention,
        $recovery.backup.artifactDigest,
        $recovery.backup.configurationDigest,
        $recovery.backup.measuredRpoSeconds,
        $recovery.restore.measuredRtoSeconds
    ).Where({ $null -ne $_ }).Count -ne 0 -or
    $null -ne $recovery.restore.evidenceReference -or
    $null -ne $recovery.rollback.evidenceReference -or
    $null -ne $recovery.approvalReference) {
    throw 'Backup, restore, and rollback contract must remain unexecuted and fail closed.'
}

$prohibitedRuntimeFiles = @(
    'app.yml',
    'app.yaml',
    'docker-compose.yml',
    'docker-compose.yaml',
    'Dockerfile'
)
foreach ($relativePath in $prohibitedRuntimeFiles) {
    if (Test-Path -LiteralPath (Join-Path $resolvedRepositoryRoot $relativePath)) {
        throw "Runnable forum configuration is not allowed in this source-only packet: $relativePath"
    }
}

Write-Host 'Source-introduction proposal contract passed.'
