configuration DoD_WinSvr_2016_MS_and_DC_v2r9
{

    param(
        [string]$EnterpriseAdmins,
        [string]$DomainAdmins,  
        [bool]$EnumerateAdministrators = $true,
        [bool]$NoAutorun = $true,
        [bool]$NoDriveTypeAutoRun = $true,
        [bool]$DisableAutomaticRestartSignOn = $true,
        [bool]$LocalAccountTokenFilterPolicy = $true,
        [bool]$ProcessCreationIncludeCmdLine_Enabled = $true,
        [bool]$DisableEnclosureDownload = $true,
        [bool]$DCSettingIndex = $true,
        [bool]$ACSettingIndex = $true,
        [bool]$DisableInventory = $true,
        [bool]$AllowTelemetry = $true,
        [bool]$EnableVirtualizationBasedSecurity = $true,
        [bool]$RequirePlatformSecurityFeatures = $true,
        [bool]$HypervisorEnforcedCodeIntegrity = $true,
        [bool]$LsaCfgFlags = $true,
        [bool]$MaxSizeApplication = $true,
        [bool]$MaxSizeSecurity = $true,
        [bool]$MaxSizeSystem = $true,
        [bool]$NoAutoplayfornonVolume = $true,
        [bool]$NoBackgroundPolicy = $true,
        [bool]$NoGPOListChanges = $true,
        [bool]$EnableUserControl = $true,
        [bool]$AlwaysInstallElevated = $true,
        [bool]$AllowInsecureGuestAuth = $true,
        [bool]$NoLockScreenSlideshow = $true,
        [bool]$EnableScriptBlockLogging = $true,
        [bool]$EnableScriptBlockInvocationLogging = $true,
        [bool]$EnableTranscripting = $true,
        [bool]$OutputDirectory = $true,
        [bool]$EnableInvocationHeader = $true,
        [bool]$DontDisplayNetworkSelectionUI = $true,
        [bool]$EnumerateLocalUsers = $true,
        [bool]$EnableSmartScreen = $true,
        [bool]$AllowIndexingEncryptedStoresOrItems = $true,
        [bool]$WinRMClientAllowBasic = $true,
        [bool]$WinRMClientAllowUnencryptedTraffic = $true,
        [bool]$WinRMClientAllowDigest = $true,
        [bool]$WinRMServiceAllowBasic = $true,
        [bool]$WinRMServiceAllowUnencryptedTraffic = $true,
        [bool]$DisableRunAs = $true,
        [bool]$DisableWebPnPDownload = $true,
        [bool]$DisableHTTPPrinting = $true,
        [bool]$RestrictRemoteClients = $true,
        [bool]$DisablePasswordSaving = $true,
        [bool]$fDisableCdm = $true,
        [bool]$fPromptForPassword = $true,
        [bool]$fEncryptRPCTraffic = $true,
        [bool]$MinEncryptionLevel = $true,
        [bool]$UseLogonCredential = $true,
        [bool]$SMB1 = $true,
        [bool]$SMB10Start = $true,
        [bool]$NoNameReleaseOnDemand = $true,
        [bool]$DisableIPSourceRouting = $true,
        [bool]$EnableICMPRedirect = $true,
        [bool]$DisableIPSourceRoutingIPv6 = $true,
        [bool]$AuditCredentialValidationSuccess = $true,
        [bool]$AuditCredentialValidationFailure = $true,
        [bool]$AuditOtherAccountManagementSuccess = $true,
        [bool]$AuditOtherAccountManagementFailure = $true,
        [bool]$AuditSecurityGroupManagementSuccess = $true,
        [bool]$AuditSecurityGroupManagementFailure = $true,
        [bool]$AuditUserAccountManagementSuccess = $true,
        [bool]$AuditUserAccountManagementFailure = $true,
        [bool]$AuditPNPActivitySuccess = $true,
        [bool]$AuditPNPActivityFailure = $true,
        [bool]$AuditProcessCreationSuccess = $true,
        [bool]$AuditProcessCreationFailure = $true,
        [bool]$AuditAccountLockoutFailure = $true,
        [bool]$AuditAccountLockoutSuccess = $true,
        [bool]$AuditGroupMembershipSuccess = $true,
        [bool]$AuditGroupMembershipFailure = $true,
        [bool]$AuditLogoffSuccess = $true,
        [bool]$AuditLogoffFailure = $true,
        [bool]$AuditLogonSuccess = $true,
        [bool]$AuditLogonFailure = $true,
        [bool]$AuditSpecialLogonSuccess = $true,
        [bool]$AuditSpecialLogonFailure = $true,
        [bool]$AuditOtherObjectAccessEventsSuccess = $true,
        [bool]$AuditOtherObjectAccessEventsFailure = $true,
        [bool]$AuditRemovableStorageSuccess = $true,
        [bool]$AuditRemovableStorageFailure = $true,
        [bool]$AuditPolicyChangeSuccess = $true,
        [bool]$AuditPolicyChangeFailure = $true,
        [bool]$AuditAuthenticationPolicyChangeSuccess = $true,
        [bool]$AuditAuthenticationPolicyChangeFailure = $true,
        [bool]$AuditAuthorizationPolicyChangeSuccess = $true,
        [bool]$AuditAuthorizationPolicyChangeFailure = $true,
        [bool]$AuditSensitivePrivilegeUseSuccess = $true,
        [bool]$AuditSensitivePrivilegeUseFailure = $true,
        [bool]$AuditIPsecDriverSuccess = $true,
        [bool]$AuditIPsecDriverFailure = $true,
        [bool]$AuditOtherSystemEventsSuccess = $true,
        [bool]$AuditOtherSystemEventsFailure = $true,
        [bool]$AuditSecurityStateChangeSuccess = $true,
        [bool]$AuditSecurityStateChangeFailure = $true,
        [bool]$AuditSecuritySystemExtensionSuccess = $true,
        [bool]$AuditSecuritySystemExtensionFailure = $true,
        [bool]$AuditSystemIntegritySuccess = $true,
        [bool]$AuditSystemIntegrityFailure = $true,
        [bool]$AuditComputerAccountManagementSuccess = $true,
        [bool]$AuditComputerAccountManagementFailure = $true,
        [bool]$AuditDirectoryServiceAccessSuccess = $true,
        [bool]$AuditDirectoryServiceAccessFailure = $true,
        [bool]$AuditDirectoryServiceChangesSuccess = $true,
        [bool]$AuditDirectoryServiceChangesFailure = $true,
        [bool]$UserAccountControlRunAllAdminsInAdminApprovalMode = $true,
        [bool]$NetworkAccessRestrictAnonymousAccess = $true,
        [bool]$DomainMemberRequireStrongSessionKey = $true,
        [bool]$UserAccountControlOnlyElevateUIAccess = $true,
        [bool]$SystemCryptographyForceStrongKeyProtection = $true,
        [bool]$NetworkSecurityConfigureEncryptionTypesAllowedForKerberos = $true,
        [bool]$MicrosoftNetworkServerDigitallySignCommunications = $true,
        [bool]$NetworkAccessRestrictClientsAllowedToMakeRemoteCalls = $true,
        [bool]$SystemCryptographyUseFIPSCompliantAlgorithms = $true,
        [bool]$NetworkSecurityLANManagerAuthenticationLevel = $true,
        [bool]$NetworkSecurityAllowLocalSystemToUseComputerIdentity = $true,
        [bool]$InteractiveLogonMessageTitle = $true,
        [bool]$DomainMemberDigitallySignSecureChannelData = $true,
        [bool]$UserAccountControlAllowUIAccessApplications = $true,
        [bool]$InteractiveLogonSmartCardRemovalBehavior = $true,
        [bool]$AccountsLimitLocalAccountUseOfBlankPasswords = $true,
        [bool]$UserAccountControlVirtualizeWriteFailures = $true,
        [bool]$InteractiveLogonMessageText = $true,
        [string]$InteractiveLogonMessageText_Input,
        [bool]$NetworkAccessLetEveryonePermissionsApply = $true,
        [bool]$DomainMemberDigitallyEncryptSecureChannelData = $true,
        [bool]$UserAccountControlBehaviorOfElevationPrompt = $true,
        [bool]$MicrosoftNetworkServerDigitallySignCommunicationsAlways = $true,
        [bool]$MicrosoftNetworkClientDigitallySignCommunicationsAlways = $true,
        [bool]$NetworkSecurityMinimumSessionSecurityForNTLMSSP = $true,
        [bool]$DomainMemberDisableMachineAccountPasswordChanges = $true,
        [bool]$MicrosoftNetworkClientDigitallySignCommunicationsIfServerAgrees = $true,
        [bool]$UserAccountControlDetectApplicationInstallations = $true,
        [bool]$NetworkAccessDoNotAllowAnonymousEnumerationSAMAccounts = $true,
        [bool]$NetworkSecurityAllowLocalSystemNullSessionFallback = $true,
        [bool]$UserAccountControlAdminApprovalMode = $true,
        [bool]$MicrosoftNetworkClientSendUnencryptedPassword = $true,
        [bool]$NetworkSecurityMinimumSessionSecurityForNTLMSSPServers = $true,
        [bool]$InteractiveLogonNumberOfPreviousLogonsToCache = $true,
        [bool]$DomainMemberMaximumMachineAccountPasswordAge = $true,
        [bool]$NetworkAccessDoNotAllowAnonymousEnumerationSAMAndShares = $true,
        [bool]$AuditForceAuditPolicySubcategorySettings = $true,
        [bool]$SystemObjectsStrengthenDefaultPermissions = $true,
        [bool]$NetworkSecurityAllowPKU2UAuthenticationRequests = $true,
        [bool]$InteractiveLogonMachineInactivityLimit = $true,
        [bool]$NetworkSecurityDoNotStoreLANManagerHash = $true,
        [bool]$DomainMemberDigitallyEncryptOrSignDataAlways = $true,
        [bool]$NetworkSecurityLDAPClientSigningRequirements = $true,
        [bool]$UserAccountControlBehaviorElevationPrompt = $true,
        [bool]$AccountLockoutDurationEnabled = $true,
        [bool]$AccountLockoutThresholdEnabled = $true,
        [bool]$ResetAccountLockoutCount = $true,
        [bool]$AccountsRenameGuestAccount = $true,
        [bool]$MinimumPasswordAgeEnabled = $true,
        [bool]$PasswordComplexityEnabled = $true,
        [bool]$PasswordHistoryEnforcementEnabled = $true,
        [bool]$NetworkAccessAllowAnonymousSIDNameTranslation = $true,
        [bool]$MinimumPasswordLengthEnabled = $true,
        [bool]$AccountsRenameAdministratorAccount = $true,
        [bool]$AccountsGuestAccountStatusEnabled = $true,
        [bool]$MaximumPasswordAgeEnabled = $true,
        [bool]$ClearTextPasswordEnabled = $true,
        [bool]$EnableComputerAndUserAccountsTrustedForDelegation = $true,
        [bool]$AccessThisComputerFromTheNetwork = $true,
        [bool]$BackUpFilesAndDirectories = $true,
        [bool]$ImpersonateClientAfterAuthentication = $true,
        [bool]$PerformVolumeMaintenanceTasks = $true,
        [bool]$LoadAndUnloadDeviceDrivers = $true,
        [bool]$LockPagesInMemory = $true,
        [bool]$TakeOwnershipOfFilesOrOtherObjects = $true,
        [bool]$CreatePermanentSharedObjects = $true,
        [bool]$DenyAccessToThisComputerFromTheNetwork = $true,
        [bool]$CreateGlobalObjects = $true,
        [bool]$DenyLogOnAsABatchJob = $true,
        [bool]$RestoreFilesAndDirectories = $true,
        [bool]$AccessCredentialManagerAsTrustedCaller = $true,
        [bool]$DenyLogOnAsAService = $true,
        [bool]$IncreaseSchedulingPriority = $true,
        [bool]$ForceShutdownFromRemoteSystem = $true,
        [bool]$GenerateSecurityAudits = $true,
        [bool]$DenyLogOnLocally = $true,
        [bool]$CreateSymbolicLinks = $true,
        [bool]$DebugPrograms = $true,
        [bool]$AllowLogOnLocally = $true,
        [bool]$ManageAuditingAndSecurityLog = $true,
        [bool]$ActAsPartOfTheOperatingSystem = $true,
        [bool]$ProfileSingleProcess = $true,
        [bool]$CreateATokenObject = $true,
        [bool]$ModifyFirmwareEnvironmentValues = $true,
        [bool]$CreateAPagefile = $true,
        [bool]$DenyLogOnThroughRemoteDesktopServices = $true,
        [bool]$DomainControllerLDAPServerSigningRequirements = $true,
        [bool]$DomainControllerRefuseMachineAccountPasswordChanges = $true
    )

    Import-DSCResource -ModuleName 'GPRegistryPolicyDsc'
	Import-DSCResource -ModuleName 'AuditPolicyDSC'
	Import-DSCResource -ModuleName 'SecurityPolicyDSC'

    if ($EnumerateAdministrators) {
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\CredUI\EnumerateAdministrators'
        {
            Key = '\Software\Microsoft\Windows\CurrentVersion\Policies\CredUI'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
            ValueName = 'EnumerateAdministrators'
            ValueData = 0
        }
    }
    
    if ($NoAutorun) {
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\NoAutorun'
        {
            Key = '\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
            ValueName = 'NoAutorun'
            ValueData = 1
        }
    }
    
    if ($NoDriveTypeAutoRun) {
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\NoDriveTypeAutoRun'
        {
            Key = '\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
            ValueName = 'NoDriveTypeAutoRun'
            ValueData = 255
        }
    }
    
    if ($DisableAutomaticRestartSignOn) {
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\System\DisableAutomaticRestartSignOn'
        {
            Key = '\Software\Microsoft\Windows\CurrentVersion\Policies\System'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
            ValueName = 'DisableAutomaticRestartSignOn'
            ValueData = 1
        }
    }
    
    if ($LocalAccountTokenFilterPolicy) {
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\System\LocalAccountTokenFilterPolicy'
        {
            Key = '\Software\Microsoft\Windows\CurrentVersion\Policies\System'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
            ValueName = 'LocalAccountTokenFilterPolicy'
            ValueData = 0
        }
    }
    
    if ($ProcessCreationIncludeCmdLine_Enabled) {
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\System\Audit\ProcessCreationIncludeCmdLine_Enabled'
        {
            Key = '\Software\Microsoft\Windows\CurrentVersion\Policies\System\Audit'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
            ValueName = 'ProcessCreationIncludeCmdLine_Enabled'
            ValueData = 1
        }
    }

    if ($DisableEnclosureDownload) {
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Internet Explorer\Feeds\DisableEnclosureDownload'
        {
            Key = '\Software\Policies\Microsoft\Internet Explorer\Feeds'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
            ValueName = 'DisableEnclosureDownload'
            ValueData = 1
        }
    }
    
    if ($DCSettingIndex) {
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Power\PowerSettings\0e796bdb-100d-47d6-a2d5-f7d2daa51f51\DCSettingIndex'
        {
            Key = '\Software\Policies\Microsoft\Power\PowerSettings\0e796bdb-100d-47d6-a2d5-f7d2daa51f51'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
            ValueName = 'DCSettingIndex'
            ValueData = 1
        }
    }
    
    if ($ACSettingIndex) {
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Power\PowerSettings\0e796bdb-100d-47d6-a2d5-f7d2daa51f51\ACSettingIndex'
        {
            Key = '\Software\Policies\Microsoft\Power\PowerSettings\0e796bdb-100d-47d6-a2d5-f7d2daa51f51'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
            ValueName = 'ACSettingIndex'
            ValueData = 1
        }
    }
    
    if ($DisableInventory) {
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\AppCompat\DisableInventory'
        {
            Key = '\Software\Policies\Microsoft\Windows\AppCompat'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
            ValueName = 'DisableInventory'
            ValueData = 1
        }
    }
    
    if ($AllowTelemetry) {
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\DataCollection\AllowTelemetry'
        {
            Key = '\Software\Policies\Microsoft\Windows\DataCollection'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
            ValueName = 'AllowTelemetry'
            ValueData = 1
        }
    }
    
    if ($EnableVirtualizationBasedSecurity) {
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\DeviceGuard\EnableVirtualizationBasedSecurity'
        {
            Key = '\Software\Policies\Microsoft\Windows\DeviceGuard'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
            ValueName = 'EnableVirtualizationBasedSecurity'
            ValueData = 1
        }
    }

    if ($RequirePlatformSecurityFeatures) {
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\DeviceGuard\RequirePlatformSecurityFeatures'
        {
            Key = '\Software\Policies\Microsoft\Windows\DeviceGuard'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
            ValueName = 'RequirePlatformSecurityFeatures'
            ValueData = 1
        }
    }
    
    if ($HypervisorEnforcedCodeIntegrity) {
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\DeviceGuard\HypervisorEnforcedCodeIntegrity'
        {
            Key = '\Software\Policies\Microsoft\Windows\DeviceGuard'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
            ValueName = 'HypervisorEnforcedCodeIntegrity'
            ValueData = 0
        }
    }
    
    if ($LsaCfgFlags) {
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\DeviceGuard\LsaCfgFlags'
        {
            Key = '\Software\Policies\Microsoft\Windows\DeviceGuard'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
            ValueName = 'LsaCfgFlags'
            ValueData = 1
        }
    }
    
    if ($MaxSizeApplication) {
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\EventLog\Application\MaxSize'
        {
            Key = '\Software\Policies\Microsoft\Windows\EventLog\Application'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
            ValueName = 'MaxSize'
            ValueData = 32768
        }
    }
    
    if ($MaxSizeSecurity) {
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\EventLog\Security\MaxSize'
        {
            Key = '\Software\Policies\Microsoft\Windows\EventLog\Security'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
            ValueName = 'MaxSize'
            ValueData = 196608
        }
    }
    
    if ($MaxSizeSystem) {
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\EventLog\System\MaxSize'
        {
            Key = '\Software\Policies\Microsoft\Windows\EventLog\System'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
            ValueName = 'MaxSize'
            ValueData = 32768
        }
    }

    if ($NoAutoplayfornonVolume) {
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\Explorer\NoAutoplayfornonVolume'
        {
            Key = '\Software\Policies\Microsoft\Windows\Explorer'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
            ValueName = 'NoAutoplayfornonVolume'
            ValueData = 1
        }
    }
    
    if ($NoBackgroundPolicy) {
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\Group Policy\{35378EAC-683F-11D2-A89A-00C04FBBCFA2}\NoBackgroundPolicy'
        {
            Key = '\Software\Policies\Microsoft\Windows\Group Policy\{35378EAC-683F-11D2-A89A-00C04FBBCFA2}'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
            ValueName = 'NoBackgroundPolicy'
            ValueData = 0
        }
    }
    
    if ($NoGPOListChanges) {
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\Group Policy\{35378EAC-683F-11D2-A89A-00C04FBBCFA2}\NoGPOListChanges'
        {
            Key = '\Software\Policies\Microsoft\Windows\Group Policy\{35378EAC-683F-11D2-A89A-00C04FBBCFA2}'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
            ValueName = 'NoGPOListChanges'
            ValueData = 0
        }
    }
    
    if ($EnableUserControl) {
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\Installer\EnableUserControl'
        {
            Key = '\Software\Policies\Microsoft\Windows\Installer'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
            ValueName = 'EnableUserControl'
            ValueData = 0
        }
    }
    
    if ($AlwaysInstallElevated) {
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\Installer\AlwaysInstallElevated'
        {
            Key = '\Software\Policies\Microsoft\Windows\Installer'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
            ValueName = 'AlwaysInstallElevated'
            ValueData = 0
        }
    }

    if ($AllowInsecureGuestAuth) {
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\LanmanWorkstation\AllowInsecureGuestAuth'
        {
            Key = '\Software\Policies\Microsoft\Windows\LanmanWorkstation'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
            ValueName = 'AllowInsecureGuestAuth'
            ValueData = 0
        }
    }
    
    if ($EnableScriptBlockLogging) {
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging\EnableScriptBlockLogging'
        {
            Key = '\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
            ValueName = 'EnableScriptBlockLogging'
            ValueData = 1
        }
    }
    
    if ($NoLockScreenSlideshow) {
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\Personalization\NoLockScreenSlideshow'
        {
            Key = '\Software\Policies\Microsoft\Windows\Personalization'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
            ValueName = 'NoLockScreenSlideshow'
            ValueData = 1
        }
    }
    
    if ($EnableScriptBlockInvocationLogging) {
        RegistryPolicyFile 'DEL_\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging\EnableScriptBlockInvocationLogging'
        {
            Key = '\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging'
            ValueType = 'String'
            Ensure = 'Absent'
            TargetType = 'ComputerConfiguration'
            ValueName = 'EnableScriptBlockInvocationLogging'
            ValueData = ''
        }
    }
    
    # The following registry settings require String type handling for HardenedPaths,
    # thus they are implemented as separate conditions.
    if ($true) {
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\NetworkProvider\HardenedPaths\*\NETLOGON'
        {
            Key = '\Software\Policies\Microsoft\Windows\NetworkProvider\HardenedPaths'
            ValueType = 'String'
            TargetType = 'ComputerConfiguration'
            ValueName = '\\*\NETLOGON'
            ValueData = 'RequireMutualAuthentication=1,RequireIntegrity=1'
        }
    }
    
    if ($true) {
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\NetworkProvider\HardenedPaths\*\SYSVOL'
        {
            Key = '\Software\Policies\Microsoft\Windows\NetworkProvider\HardenedPaths'
            ValueType = 'String'
            TargetType = 'ComputerConfiguration'
            ValueName = '\\*\SYSVOL'
            ValueData = 'RequireMutualAuthentication=1,RequireIntegrity=1'
        }
    }
    if ($EnableTranscripting) {
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\PowerShell\Transcription\EnableTranscripting'
        {
            Key = '\Software\Policies\Microsoft\Windows\PowerShell\Transcription'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
            ValueName = 'EnableTranscripting'
            ValueData = 1
        }
    }
    
    if ($OutputDirectory) {
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\PowerShell\Transcription\OutputDirectory'
        {
            Key = '\Software\Policies\Microsoft\Windows\PowerShell\Transcription'
            ValueType = 'String'
            TargetType = 'ComputerConfiguration'
            ValueName = 'OutputDirectory'
            ValueData = 'C:\ProgramData\PS_Transcript'
        }
    }
    
    if ($EnableInvocationHeader) {
        RegistryPolicyFile 'DEL_\Software\Policies\Microsoft\Windows\PowerShell\Transcription\EnableInvocationHeader'
        {
            Key = '\Software\Policies\Microsoft\Windows\PowerShell\Transcription'
            ValueType = 'String'
            Ensure = 'Absent'
            TargetType = 'ComputerConfiguration'
            ValueName = 'EnableInvocationHeader'
            ValueData = ''
        }
    }
    
    if ($DontDisplayNetworkSelectionUI) {
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\System\DontDisplayNetworkSelectionUI'
        {
            Key = '\Software\Policies\Microsoft\Windows\System'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
            ValueName = 'DontDisplayNetworkSelectionUI'
            ValueData = 1
        }
    }
    
    if ($EnumerateLocalUsers) {
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\System\EnumerateLocalUsers'
        {
            Key = '\Software\Policies\Microsoft\Windows\System'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
            ValueName = 'EnumerateLocalUsers'
            ValueData = 0
        }
    }
    
    if ($EnableSmartScreen) {
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\System\EnableSmartScreen'
        {
            Key = '\Software\Policies\Microsoft\Windows\System'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
            ValueName = 'EnableSmartScreen'
            ValueData = 1
        }
    }

    if ($AllowIndexingEncryptedStoresOrItems) {
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\Windows Search\AllowIndexingEncryptedStoresOrItems'
        {
            Key = '\Software\Policies\Microsoft\Windows\Windows Search'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
            ValueName = 'AllowIndexingEncryptedStoresOrItems'
            ValueData = 0
        }
    }
    
    if ($WinRMClientAllowBasic) {
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\WinRM\Client\AllowBasic'
        {
            Key = '\Software\Policies\Microsoft\Windows\WinRM\Client'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
            ValueName = 'AllowBasic'
            ValueData = 0
        }
    }
    
    if ($WinRMClientAllowUnencryptedTraffic) {
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\WinRM\Client\AllowUnencryptedTraffic'
        {
            Key = '\Software\Policies\Microsoft\Windows\WinRM\Client'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
            ValueName = 'AllowUnencryptedTraffic'
            ValueData = 0
        }
    }
    
    if ($WinRMClientAllowDigest) {
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\WinRM\Client\AllowDigest'
        {
            Key = '\Software\Policies\Microsoft\Windows\WinRM\Client'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
            ValueName = 'AllowDigest'
            ValueData = 0
        }
    }
    
    if ($WinRMServiceAllowBasic) {
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\WinRM\Service\AllowBasic'
        {
            Key = '\Software\Policies\Microsoft\Windows\WinRM\Service'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
            ValueName = 'AllowBasic'
            ValueData = 0
        }
    }
    
    if ($WinRMServiceAllowUnencryptedTraffic) {
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\WinRM\Service\AllowUnencryptedTraffic'
        {
            Key = '\Software\Policies\Microsoft\Windows\WinRM\Service'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
            ValueName = 'AllowUnencryptedTraffic'
            ValueData = 0
        }
    }

    if ($DisableRunAs) {
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\WinRM\Service\DisableRunAs'
        {
            Key = '\Software\Policies\Microsoft\Windows\WinRM\Service'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
            ValueName = 'DisableRunAs'
            ValueData = 1
        }
    }
    
    if ($DisableWebPnPDownload) {
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows NT\Printers\DisableWebPnPDownload'
        {
            Key = '\Software\Policies\Microsoft\Windows NT\Printers'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
            ValueName = 'DisableWebPnPDownload'
            ValueData = 1
        }
    }
    
    if ($DisableHTTPPrinting) {
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows NT\Printers\DisableHTTPPrinting'
        {
            Key = '\Software\Policies\Microsoft\Windows NT\Printers'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
            ValueName = 'DisableHTTPPrinting'
            ValueData = 1
        }
    }
    
    if ($RestrictRemoteClients) {
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows NT\Rpc\RestrictRemoteClients'
        {
            Key = '\Software\Policies\Microsoft\Windows NT\Rpc'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
            ValueName = 'RestrictRemoteClients'
            ValueData = 1
        }
    }
    
    if ($DisablePasswordSaving) {
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows NT\Terminal Services\DisablePasswordSaving'
        {
            Key = '\Software\Policies\Microsoft\Windows NT\Terminal Services'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
            ValueName = 'DisablePasswordSaving'
            ValueData = 1
        }
    }
    
    if ($fDisableCdm) {
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows NT\Terminal Services\fDisableCdm'
        {
            Key = '\Software\Policies\Microsoft\Windows NT\Terminal Services'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
            ValueName = 'fDisableCdm'
            ValueData = 1
        }
    }

    if ($fPromptForPassword) {
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows NT\Terminal Services\fPromptForPassword'
        {
            Key = '\Software\Policies\Microsoft\Windows NT\Terminal Services'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
            ValueName = 'fPromptForPassword'
            ValueData = 1
        }
    }
    
    if ($fEncryptRPCTraffic) {
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows NT\Terminal Services\fEncryptRPCTraffic'
        {
            Key = '\Software\Policies\Microsoft\Windows NT\Terminal Services'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
            ValueName = 'fEncryptRPCTraffic'
            ValueData = 1
        }
    }
    
    if ($MinEncryptionLevel) {
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows NT\Terminal Services\MinEncryptionLevel'
        {
            Key = '\Software\Policies\Microsoft\Windows NT\Terminal Services'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
            ValueName = 'MinEncryptionLevel'
            ValueData = 3
        }
    }
    
    if ($UseLogonCredential) {
        RegistryPolicyFile 'Registry(POL): HKLM:\System\CurrentControlSet\Control\SecurityProviders\WDigest\UseLogonCredential'
        {
            Key = 'System\CurrentControlSet\Control\SecurityProviders\WDigest'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
            ValueName = 'UseLogonCredential'
            ValueData = 0
        }
    }
    
    if ($SMB1) {
        RegistryPolicyFile 'Registry(POL): HKLM:\System\CurrentControlSet\Services\LanmanServer\Parameters\SMB1'
        {
            Key = 'System\CurrentControlSet\Services\LanmanServer\Parameters'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
            ValueName = 'SMB1'
            ValueData = 0
        }
    }
    
    if ($SMB10Start) {
        RegistryPolicyFile 'Registry(POL): HKLM:\System\CurrentControlSet\Services\MrxSmb10\Start'
        {
            Key = 'System\CurrentControlSet\Services\MrxSmb10'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
            ValueName = 'Start'
            ValueData = 4
        }
    }

    if ($NoNameReleaseOnDemand) {
        RegistryPolicyFile 'Registry(POL): HKLM:\System\CurrentControlSet\Services\Netbt\Parameters\NoNameReleaseOnDemand'
        {
            Key = 'System\CurrentControlSet\Services\Netbt\Parameters'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
            ValueName = 'NoNameReleaseOnDemand'
            ValueData = 1
        }
    }
    
    if ($DisableIPSourceRouting) {
        RegistryPolicyFile 'Registry(POL): HKLM:\System\CurrentControlSet\Services\Tcpip\Parameters\DisableIPSourceRouting'
        {
            Key = 'System\CurrentControlSet\Services\Tcpip\Parameters'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
            ValueName = 'DisableIPSourceRouting'
            ValueData = 2
        }
    }
    
    if ($EnableICMPRedirect) {
        RegistryPolicyFile 'Registry(POL): HKLM:\System\CurrentControlSet\Services\Tcpip\Parameters\EnableICMPRedirect'
        {
            Key = 'System\CurrentControlSet\Services\Tcpip\Parameters'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
            ValueName = 'EnableICMPRedirect'
            ValueData = 0
        }
    }
    
    if ($DisableIPSourceRoutingIPv6) {
        RegistryPolicyFile 'Registry(POL): HKLM:\System\CurrentControlSet\Services\Tcpip6\Parameters\DisableIPSourceRouting'
        {
            Key = 'System\CurrentControlSet\Services\Tcpip6\Parameters'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
            ValueName = 'DisableIPSourceRouting'
            ValueData = 2
        }
    }
    
    if ($AuditCredentialValidationSuccess) {
        AuditPolicySubcategory 'Audit Credential Validation (Success) - Inclusion'
        {
            Ensure = 'Present'
            Name = 'Credential Validation'
            AuditFlag = 'Success'
        }
    }
    
    if ($AuditCredentialValidationFailure) {
        AuditPolicySubcategory 'Audit Credential Validation (Failure) - Inclusion'
        {
            Ensure = 'Present'
            Name = 'Credential Validation'
            AuditFlag = 'Failure'
        }
    }

    if ($AuditOtherAccountManagementSuccess) {
        AuditPolicySubcategory 'Audit Other Account Management Events (Success) - Inclusion'
        {
            Ensure = 'Present'
            Name = 'Other Account Management Events'
            AuditFlag = 'Success'
        }
    }
    
    if ($AuditOtherAccountManagementFailure) {
        AuditPolicySubcategory 'Audit Other Account Management Events (Failure) - Inclusion'
        {
            Ensure = 'Absent'
            Name = 'Other Account Management Events'
            AuditFlag = 'Failure'
        }
    }
    
    if ($AuditSecurityGroupManagementSuccess) {
        AuditPolicySubcategory 'Audit Security Group Management (Success) - Inclusion'
        {
            Ensure = 'Present'
            Name = 'Security Group Management'
            AuditFlag = 'Success'
        }
    }
    
    if ($AuditSecurityGroupManagementFailure) {
        AuditPolicySubcategory 'Audit Security Group Management (Failure) - Inclusion'
        {
            Ensure = 'Absent'
            Name = 'Security Group Management'
            AuditFlag = 'Failure'
        }
    }
    
    if ($AuditUserAccountManagementSuccess) {
        AuditPolicySubcategory 'Audit User Account Management (Success) - Inclusion'
        {
            Ensure = 'Present'
            Name = 'User Account Management'
            AuditFlag = 'Success'
        }
    }
    
    if ($AuditUserAccountManagementFailure) {
        AuditPolicySubcategory 'Audit User Account Management (Failure) - Inclusion'
        {
            Ensure = 'Present'
            Name = 'User Account Management'
            AuditFlag = 'Failure'
        }
    }
    
    if ($AuditPNPActivitySuccess) {
        AuditPolicySubcategory 'Audit PNP Activity (Success) - Inclusion'
        {
            Ensure = 'Present'
            Name = 'Plug and Play Events'
            AuditFlag = 'Success'
        }
    }
    
    if ($AuditPNPActivityFailure) {
        AuditPolicySubcategory 'Audit PNP Activity (Failure) - Inclusion'
        {
            Ensure = 'Absent'
            Name = 'Plug and Play Events'
            AuditFlag = 'Failure'
        }
    }

    if ($AuditProcessCreationSuccess) {
        AuditPolicySubcategory 'Audit Process Creation (Success) - Inclusion'
        {
            Ensure = 'Present'
            Name = 'Process Creation'
            AuditFlag = 'Success'
        }
    }
    
    if ($AuditProcessCreationFailure) {
        AuditPolicySubcategory 'Audit Process Creation (Failure) - Inclusion'
        {
            Ensure = 'Absent'
            Name = 'Process Creation'
            AuditFlag = 'Failure'
        }
    }
    
    if ($AuditAccountLockoutFailure) {
        AuditPolicySubcategory 'Audit Account Lockout (Failure) - Inclusion'
        {
            Ensure = 'Present'
            Name = 'Account Lockout'
            AuditFlag = 'Failure'
        }
    }
    
    if ($AuditAccountLockoutSuccess) {
        AuditPolicySubcategory 'Audit Account Lockout (Success) - Inclusion'
        {
            Ensure = 'Absent'
            Name = 'Account Lockout'
            AuditFlag = 'Success'
        }
    }
    
    if ($AuditGroupMembershipSuccess) {
        AuditPolicySubcategory 'Audit Group Membership (Success) - Inclusion'
        {
            Ensure = 'Present'
            Name = 'Group Membership'
            AuditFlag = 'Success'
        }
    }
    
    if ($AuditGroupMembershipFailure) {
        AuditPolicySubcategory 'Audit Group Membership (Failure) - Inclusion'
        {
            Ensure = 'Absent'
            Name = 'Group Membership'
            AuditFlag = 'Failure'
        }
    }
    
    if ($AuditLogoffSuccess) {
        AuditPolicySubcategory 'Audit Logoff (Success) - Inclusion'
        {
            Ensure = 'Present'
            Name = 'Logoff'
            AuditFlag = 'Success'
        }
    }

    if ($AuditLogoffFailure) {
        AuditPolicySubcategory 'Audit Logoff (Failure) - Inclusion'
        {
            Ensure = 'Absent'
            Name = 'Logoff'
            AuditFlag = 'Failure'
        }
    }
    
    if ($AuditLogonSuccess) {
        AuditPolicySubcategory 'Audit Logon (Success) - Inclusion'
        {
            Ensure = 'Present'
            Name = 'Logon'
            AuditFlag = 'Success'
        }
    }
    
    if ($AuditLogonFailure) {
        AuditPolicySubcategory 'Audit Logon (Failure) - Inclusion'
        {
            Ensure = 'Present'
            Name = 'Logon'
            AuditFlag = 'Failure'
        }
    }
    
    if ($AuditSpecialLogonSuccess) {
        AuditPolicySubcategory 'Audit Special Logon (Success) - Inclusion'
        {
            Ensure = 'Present'
            Name = 'Special Logon'
            AuditFlag = 'Success'
        }
    }
    
    if ($AuditSpecialLogonFailure) {
        AuditPolicySubcategory 'Audit Special Logon (Failure) - Inclusion'
        {
            Ensure = 'Absent'
            Name = 'Special Logon'
            AuditFlag = 'Failure'
        }
    }
    
    if ($AuditOtherObjectAccessEventsSuccess) {
        AuditPolicySubcategory 'Audit Other Object Access Events (Success) - Inclusion'
        {
            Ensure = 'Present'
            Name = 'Other Object Access Events'
            AuditFlag = 'Success'
        }
    }

    if ($AuditOtherObjectAccessEventsFailure) {
        AuditPolicySubcategory 'Audit Other Object Access Events (Failure) - Inclusion'
        {
            Ensure = 'Present'
            Name = 'Other Object Access Events'
            AuditFlag = 'Failure'
        }
    }
    
    if ($AuditRemovableStorageSuccess) {
        AuditPolicySubcategory 'Audit Removable Storage (Success) - Inclusion'
        {
            Ensure = 'Present'
            Name = 'Removable Storage'
            AuditFlag = 'Success'
        }
    }
    
    if ($AuditRemovableStorageFailure) {
        AuditPolicySubcategory 'Audit Removable Storage (Failure) - Inclusion'
        {
            Ensure = 'Present'
            Name = 'Removable Storage'
            AuditFlag = 'Failure'
        }
    }
    
    if ($AuditPolicyChangeSuccess) {
        AuditPolicySubcategory 'Audit Audit Policy Change (Success) - Inclusion'
        {
            Ensure = 'Present'
            Name = 'Audit Policy Change'
            AuditFlag = 'Success'
        }
    }
    
    if ($AuditPolicyChangeFailure) {
        AuditPolicySubcategory 'Audit Audit Policy Change (Failure) - Inclusion'
        {
            Ensure = 'Present'
            Name = 'Audit Policy Change'
            AuditFlag = 'Failure'
        }
    }
    
    if ($AuditAuthenticationPolicyChangeSuccess) {
        AuditPolicySubcategory 'Audit Authentication Policy Change (Success) - Inclusion'
        {
            Ensure = 'Present'
            Name = 'Authentication Policy Change'
            AuditFlag = 'Success'
        }
    }
    
    if ($AuditAuthenticationPolicyChangeFailure) {
        AuditPolicySubcategory 'Audit Authentication Policy Change (Failure) - Inclusion'
        {
            Ensure = 'Absent'
            Name = 'Authentication Policy Change'
            AuditFlag = 'Failure'
        }
    }

    if ($AuditAuthorizationPolicyChangeSuccess) {
        AuditPolicySubcategory 'Audit Authorization Policy Change (Success) - Inclusion'
        {
            Ensure = 'Present'
            Name = 'Authorization Policy Change'
            AuditFlag = 'Success'
        }
    }
    
    if ($AuditAuthorizationPolicyChangeFailure) {
        AuditPolicySubcategory 'Audit Authorization Policy Change (Failure) - Inclusion'
        {
            Ensure = 'Absent'
            Name = 'Authorization Policy Change'
            AuditFlag = 'Failure'
        }
    }
    
    if ($AuditSensitivePrivilegeUseSuccess) {
        AuditPolicySubcategory 'Audit Sensitive Privilege Use (Success) - Inclusion'
        {
            Ensure = 'Present'
            Name = 'Sensitive Privilege Use'
            AuditFlag = 'Success'
        }
    }
    
    if ($AuditSensitivePrivilegeUseFailure) {
        AuditPolicySubcategory 'Audit Sensitive Privilege Use (Failure) - Inclusion'
        {
            Ensure = 'Present'
            Name = 'Sensitive Privilege Use'
            AuditFlag = 'Failure'
        }
    }
    
    if ($AuditIPsecDriverSuccess) {
        AuditPolicySubcategory 'Audit IPsec Driver (Success) - Inclusion'
        {
            Ensure = 'Present'
            Name = 'IPsec Driver'
            AuditFlag = 'Success'
        }
    }
    
    if ($AuditIPsecDriverFailure) {
        AuditPolicySubcategory 'Audit IPsec Driver (Failure) - Inclusion'
        {
            Ensure = 'Present'
            Name = 'IPsec Driver'
            AuditFlag = 'Failure'
        }
    }
    
    if ($AuditOtherSystemEventsSuccess) {
        AuditPolicySubcategory 'Audit Other System Events (Success) - Inclusion'
        {
            Ensure = 'Present'
            Name = 'Other System Events'
            AuditFlag = 'Success'
        }
    }
    
    if ($AuditOtherSystemEventsFailure) {
        AuditPolicySubcategory 'Audit Other System Events (Failure) - Inclusion'
        {
            Ensure = 'Present'
            Name = 'Other System Events'
            AuditFlag = 'Failure'
        }
    }

    if ($AuditSecurityStateChangeSuccess) {
        AuditPolicySubcategory 'Audit Security State Change (Success) - Inclusion'
        {
            Ensure = 'Present'
            Name = 'Security State Change'
            AuditFlag = 'Success'
        }
    }
    
    if ($AuditSecurityStateChangeFailure) {
        AuditPolicySubcategory 'Audit Security State Change (Failure) - Inclusion'
        {
            Ensure = 'Absent'
            Name = 'Security State Change'
            AuditFlag = 'Failure'
        }
    }
    
    if ($AuditSecuritySystemExtensionSuccess) {
        AuditPolicySubcategory 'Audit Security System Extension (Success) - Inclusion'
        {
            Ensure = 'Present'
            Name = 'Security System Extension'
            AuditFlag = 'Success'
        }
    }
    
    if ($AuditSecuritySystemExtensionFailure) {
        AuditPolicySubcategory 'Audit Security System Extension (Failure) - Inclusion'
        {
            Ensure = 'Absent'
            Name = 'Security System Extension'
            AuditFlag = 'Failure'
        }
    }
    
    if ($AuditSystemIntegritySuccess) {
        AuditPolicySubcategory 'Audit System Integrity (Success) - Inclusion'
        {
            Ensure = 'Present'
            Name = 'System Integrity'
            AuditFlag = 'Success'
        }
    }
    
    if ($AuditSystemIntegrityFailure) {
        AuditPolicySubcategory 'Audit System Integrity (Failure) - Inclusion'
        {
            Ensure = 'Present'
            Name = 'System Integrity'
            AuditFlag = 'Failure'
        }
    }

    if ($AuditComputerAccountManagementSuccess) {
        AuditPolicySubcategory 'Audit Computer Account Management (Success) - Inclusion'
        {
            Ensure = 'Present'
            Name = 'Computer Account Management'
            AuditFlag = 'Success'
        }
    }
    
    if ($AuditComputerAccountManagementFailure) {
        AuditPolicySubcategory 'Audit Computer Account Management (Failure) - Inclusion'
        {
            Ensure = 'Absent'
            Name = 'Computer Account Management'
            AuditFlag = 'Failure'
        }
    }
    
    if ($AuditDirectoryServiceAccessSuccess) {
        AuditPolicySubcategory 'Audit Directory Service Access (Success) - Inclusion'
        {
            Ensure = 'Present'
            Name = 'Directory Service Access'
            AuditFlag = 'Success'
        }
    }
    
    if ($AuditDirectoryServiceAccessFailure) {
        AuditPolicySubcategory 'Audit Directory Service Access (Failure) - Inclusion'
        {
            Ensure = 'Present'
            Name = 'Directory Service Access'
            AuditFlag = 'Failure'
        }
    }
    
    if ($AuditDirectoryServiceChangesSuccess) {
        AuditPolicySubcategory 'Audit Directory Service Changes (Success) - Inclusion'
        {
            Ensure = 'Present'
            Name = 'Directory Service Changes'
            AuditFlag = 'Success'
        }
    }
    
    if ($AuditDirectoryServiceChangesFailure) {
        AuditPolicySubcategory 'Audit Directory Service Changes (Failure) - Inclusion'
        {
            Ensure = 'Absent'
            Name = 'Directory Service Changes'
            AuditFlag = 'Failure'
        }
    }
    if ($UserAccountControlRunAllAdminsInAdminApprovalMode) {
        SecurityOption 'SecurityRegistry(INF): User_Account_Control_Run_all_administrators_in_Admin_Approval_Mode'
        {
            User_Account_Control_Run_all_administrators_in_Admin_Approval_Mode = 'Enabled'
            Name = 'User_Account_Control_Run_all_administrators_in_Admin_Approval_Mode'
        }
    }
    
    if ($NetworkAccessRestrictAnonymousAccess) {
        SecurityOption 'SecurityRegistry(INF): Network_access_Restrict_anonymous_access_to_Named_Pipes_and_Shares'
        {
            Network_access_Restrict_anonymous_access_to_Named_Pipes_and_Shares = 'Enabled'
            Name = 'Network_access_Restrict_anonymous_access_to_Named_Pipes_and_Shares'
        }
    }
    
    if ($DomainMemberRequireStrongSessionKey) {
        SecurityOption 'SecurityRegistry(INF): Domain_member_Require_strong_Windows_2000_or_later_session_key'
        {
            Name = 'Domain_member_Require_strong_Windows_2000_or_later_session_key'
            Domain_member_Require_strong_Windows_2000_or_later_session_key = 'Enabled'
        }
    }
    
    if ($UserAccountControlOnlyElevateUIAccess) {
        SecurityOption 'SecurityRegistry(INF): User_Account_Control_Only_elevate_UIAccess_applications_that_are_installed_in_secure_locations'
        {
            User_Account_Control_Only_elevate_UIAccess_applications_that_are_installed_in_secure_locations = 'Enabled'
            Name = 'User_Account_Control_Only_elevate_UIAccess_applications_that_are_installed_in_secure_locations'
        }
    }
    
    if ($SystemCryptographyForceStrongKeyProtection) {
        SecurityOption 'SecurityRegistry(INF): System_cryptography_Force_strong_key_protection_for_user_keys_stored_on_the_computer'
        {
            Name = 'System_cryptography_Force_strong_key_protection_for_user_keys_stored_on_the_computer'
            System_cryptography_Force_strong_key_protection_for_user_keys_stored_on_the_computer = 'User must enter a password each time they use a key'
        }
    }
    
    if ($NetworkSecurityConfigureEncryptionTypesAllowedForKerberos) {
        SecurityOption 'SecurityRegistry(INF): Network_security_Configure_encryption_types_allowed_for_Kerberos'
        {
            Network_security_Configure_encryption_types_allowed_for_Kerberos = '2147483640'
            Name = 'Network_security_Configure_encryption_types_allowed_for_Kerberos'
        }
    }
    
    if ($MicrosoftNetworkServerDigitallySignCommunications) {
        SecurityOption 'SecurityRegistry(INF): Microsoft_network_server_Digitally_sign_communications_if_client_agrees'
        {
            Name = 'Microsoft_network_server_Digitally_sign_communications_if_client_agrees'
            Microsoft_network_server_Digitally_sign_communications_if_client_agrees = 'Enabled'
        }
    }
    if ($NetworkAccessRestrictClientsAllowedToMakeRemoteCalls) {
        SecurityOption 'SecurityRegistry(INF): Network_access_Restrict_clients_allowed_to_make_remote_calls_to_SAM'
        {
            Name = 'Network_access_Restrict_clients_allowed_to_make_remote_calls_to_SAM'
            Network_access_Restrict_clients_allowed_to_make_remote_calls_to_SAM = 'O:BAG:BAD:(A;;RC;;;BA)'
        }
    }
    
    if ($SystemCryptographyUseFIPSCompliantAlgorithms) {
        SecurityOption 'SecurityRegistry(INF): System_cryptography_Use_FIPS_compliant_algorithms_for_encryption_hashing_and_signing'
        {
            System_cryptography_Use_FIPS_compliant_algorithms_for_encryption_hashing_and_signing = 'Enabled'
            Name = 'System_cryptography_Use_FIPS_compliant_algorithms_for_encryption_hashing_and_signing'
        }
    }
    
    if ($NetworkSecurityLANManagerAuthenticationLevel) {
        SecurityOption 'SecurityRegistry(INF): Network_security_LAN_Manager_authentication_level'
        {
            Network_security_LAN_Manager_authentication_level = 'Send NTLMv2 responses only. Refuse LM & NTLM'
            Name = 'Network_security_LAN_Manager_authentication_level'
        }
    }
    
    if ($NetworkSecurityAllowLocalSystemToUseComputerIdentity) {
        SecurityOption 'SecurityRegistry(INF): Network_security_Allow_Local_System_to_use_computer_identity_for_NTLM'
        {
            Network_security_Allow_Local_System_to_use_computer_identity_for_NTLM = 'Enabled'
            Name = 'Network_security_Allow_Local_System_to_use_computer_identity_for_NTLM'
        }
    }
    
    if ($InteractiveLogonMessageTitle) {
        SecurityOption 'SecurityRegistry(INF): Interactive_logon_Message_title_for_users_attempting_to_log_on'
        {
            Name = 'Interactive_logon_Message_title_for_users_attempting_to_log_on'
            Interactive_logon_Message_title_for_users_attempting_to_log_on = 'US Department of Defense Warning Statement'
        }
    }
    
    if ($DomainMemberDigitallySignSecureChannelData) {
        SecurityOption 'SecurityRegistry(INF): Domain_member_Digitally_sign_secure_channel_data_when_possible'
        {
            Domain_member_Digitally_sign_secure_channel_data_when_possible = 'Enabled'
            Name = 'Domain_member_Digitally_sign_secure_channel_data_when_possible'
        }
    }
    if ($UserAccountControlAllowUIAccessApplications) {
        SecurityOption 'SecurityRegistry(INF): User_Account_Control_Allow_UIAccess_applications_to_prompt_for_elevation_without_using_the_secure_desktop'
        {
            User_Account_Control_Allow_UIAccess_applications_to_prompt_for_elevation_without_using_the_secure_desktop = 'Disabled'
            Name = 'User_Account_Control_Allow_UIAccess_applications_to_prompt_for_elevation_without_using_the_secure_desktop'
        }
    }
    
    if ($InteractiveLogonSmartCardRemovalBehavior) {
        SecurityOption 'SecurityRegistry(INF): Interactive_logon_Smart_card_removal_behavior'
        {
            Interactive_logon_Smart_card_removal_behavior = 'Lock workstation'
            Name = 'Interactive_logon_Smart_card_removal_behavior'
        }
    }
    
    if ($AccountsLimitLocalAccountUseOfBlankPasswords) {
        SecurityOption 'SecurityRegistry(INF): Accounts_Limit_local_account_use_of_blank_passwords_to_console_logon_only'
        {
            Name = 'Accounts_Limit_local_account_use_of_blank_passwords_to_console_logon_only'
            Accounts_Limit_local_account_use_of_blank_passwords_to_console_logon_only = 'Enabled'
        }
    }
    
    if ($UserAccountControlVirtualizeWriteFailures) {
        SecurityOption 'SecurityRegistry(INF): User_Account_Control_Virtualize_file_and_registry_write_failures_to_per_user_locations'
        {
            User_Account_Control_Virtualize_file_and_registry_write_failures_to_per_user_locations = 'Enabled'
            Name = 'User_Account_Control_Virtualize_file_and_registry_write_failures_to_per_user_locations'
        }
    }
    
    if ($InteractiveLogonMessageText) {
        SecurityOption 'SecurityRegistry(INF): Interactive_logon_Message_text_for_users_attempting_to_log_on'
        {
            Interactive_logon_Message_text_for_users_attempting_to_log_on = $InteractiveLogonMessageText_Input
            Name = 'Interactive_logon_Message_text_for_users_attempting_to_log_on'
        }
    }
    
    if ($NetworkAccessLetEveryonePermissionsApply) {
        SecurityOption 'SecurityRegistry(INF): Network_access_Let_Everyone_permissions_apply_to_anonymous_users'
        {
            Network_access_Let_Everyone_permissions_apply_to_anonymous_users = 'Disabled'
            Name = 'Network_access_Let_Everyone_permissions_apply_to_anonymous_users'
        }
    }
    
    if ($DomainMemberDigitallyEncryptSecureChannelData) {
        SecurityOption 'SecurityRegistry(INF): Domain_member_Digitally_encrypt_secure_channel_data_when_possible'
        {
            Name = 'Domain_member_Digitally_encrypt_secure_channel_data_when_possible'
            Domain_member_Digitally_encrypt_secure_channel_data_when_possible = 'Enabled'
        }
    }
    
    if ($UserAccountControlBehaviorOfElevationPrompt) {
        SecurityOption 'SecurityRegistry(INF): User_Account_Control_Behavior_of_the_elevation_prompt_for_standard_users'
        {
            User_Account_Control_Behavior_of_the_elevation_prompt_for_standard_users = 'Automatically deny elevation request'
            Name = 'User_Account_Control_Behavior_of_the_elevation_prompt_for_standard_users'
        }
    }

    if ($MicrosoftNetworkServerDigitallySignCommunicationsAlways) {
        SecurityOption 'SecurityRegistry(INF): Microsoft_network_server_Digitally_sign_communications_always'
        {
            Microsoft_network_server_Digitally_sign_communications_always = 'Enabled'
            Name = 'Microsoft_network_server_Digitally_sign_communications_always'
        }
    }
    
    if ($MicrosoftNetworkClientDigitallySignCommunicationsAlways) {
        SecurityOption 'SecurityRegistry(INF): Microsoft_network_client_Digitally_sign_communications_always'
        {
            Microsoft_network_client_Digitally_sign_communications_always = 'Enabled'
            Name = 'Microsoft_network_client_Digitally_sign_communications_always'
        }
    }
    
    if ($NetworkSecurityMinimumSessionSecurityForNTLMSSP) {
        SecurityOption 'SecurityRegistry(INF): Network_security_Minimum_session_security_for_NTLM_SSP_based_including_secure_RPC_clients'
        {
            Name = 'Network_security_Minimum_session_security_for_NTLM_SSP_based_including_secure_RPC_clients'
            Network_security_Minimum_session_security_for_NTLM_SSP_based_including_secure_RPC_clients = 'Both options checked'
        }
    }
    
    if ($DomainMemberDisableMachineAccountPasswordChanges) {
        SecurityOption 'SecurityRegistry(INF): Domain_member_Disable_machine_account_password_changes'
        {
            Domain_member_Disable_machine_account_password_changes = 'Disabled'
            Name = 'Domain_member_Disable_machine_account_password_changes'
        }
    }
    
    if ($MicrosoftNetworkClientDigitallySignCommunicationsIfServerAgrees) {
        SecurityOption 'SecurityRegistry(INF): Microsoft_network_client_Digitally_sign_communications_if_server_agrees'
        {
            Name = 'Microsoft_network_client_Digitally_sign_communications_if_server_agrees'
            Microsoft_network_client_Digitally_sign_communications_if_server_agrees = 'Enabled'
        }
    }
    
    if ($UserAccountControlDetectApplicationInstallations) {
        SecurityOption 'SecurityRegistry(INF): User_Account_Control_Detect_application_installations_and_prompt_for_elevation'
        {
            User_Account_Control_Detect_application_installations_and_prompt_for_elevation = 'Enabled'
            Name = 'User_Account_Control_Detect_application_installations_and_prompt_for_elevation'
        }
    }

    if ($NetworkAccessDoNotAllowAnonymousEnumerationSAMAccounts) {
        SecurityOption 'SecurityRegistry(INF): Network_access_Do_not_allow_anonymous_enumeration_of_SAM_accounts'
        {
            Name = 'Network_access_Do_not_allow_anonymous_enumeration_of_SAM_accounts'
            Network_access_Do_not_allow_anonymous_enumeration_of_SAM_accounts = 'Enabled'
        }
    }
    
    if ($NetworkSecurityAllowLocalSystemNullSessionFallback) {
        SecurityOption 'SecurityRegistry(INF): Network_security_Allow_LocalSystem_NULL_session_fallback'
        {
            Name = 'Network_security_Allow_LocalSystem_NULL_session_fallback'
            Network_security_Allow_LocalSystem_NULL_session_fallback = 'Disabled'
        }
    }
    
    if ($UserAccountControlAdminApprovalMode) {
        SecurityOption 'SecurityRegistry(INF): User_Account_Control_Admin_Approval_Mode_for_the_Built_in_Administrator_account'
        {
            User_Account_Control_Admin_Approval_Mode_for_the_Built_in_Administrator_account = 'Enabled'
            Name = 'User_Account_Control_Admin_Approval_Mode_for_the_Built_in_Administrator_account'
        }
    }
    
    if ($MicrosoftNetworkClientSendUnencryptedPassword) {
        SecurityOption 'SecurityRegistry(INF): Microsoft_network_client_Send_unencrypted_password_to_third_party_SMB_servers'
        {
            Microsoft_network_client_Send_unencrypted_password_to_third_party_SMB_servers = 'Disabled'
            Name = 'Microsoft_network_client_Send_unencrypted_password_to_third_party_SMB_servers'
        }
    }
    
    if ($NetworkSecurityMinimumSessionSecurityForNTLMSSPServers) {
        SecurityOption 'SecurityRegistry(INF): Network_security_Minimum_session_security_for_NTLM_SSP_based_including_secure_RPC_servers'
        {
            Name = 'Network_security_Minimum_session_security_for_NTLM_SSP_based_including_secure_RPC_servers'
            Network_security_Minimum_session_security_for_NTLM_SSP_based_including_secure_RPC_servers = 'Both options checked'
        }
    }
    
    if ($InteractiveLogonNumberOfPreviousLogonsToCache) {
        SecurityOption 'SecurityRegistry(INF): Interactive_logon_Number_of_previous_logons_to_cache_in_case_domain_controller_is_not_available'
        {
            Interactive_logon_Number_of_previous_logons_to_cache_in_case_domain_controller_is_not_available = '4'
            Name = 'Interactive_logon_Number_of_previous_logons_to_cache_in_case_domain_controller_is_not_available'
        }
    }

    if ($DomainMemberMaximumMachineAccountPasswordAge) {
        SecurityOption 'SecurityRegistry(INF): Domain_member_Maximum_machine_account_password_age'
        {
            Name = 'Domain_member_Maximum_machine_account_password_age'
            Domain_member_Maximum_machine_account_password_age = '30'
        }
    }
    
    if ($NetworkAccessDoNotAllowAnonymousEnumerationSAMAndShares) {
        SecurityOption 'SecurityRegistry(INF): Network_access_Do_not_allow_anonymous_enumeration_of_SAM_accounts_and_shares'
        {
            Name = 'Network_access_Do_not_allow_anonymous_enumeration_of_SAM_accounts_and_shares'
            Network_access_Do_not_allow_anonymous_enumeration_of_SAM_accounts_and_shares = 'Enabled'
        }
    }
    
    if ($AuditForceAuditPolicySubcategorySettings) {
        SecurityOption 'SecurityRegistry(INF): Audit_Force_audit_policy_subcategory_settings_Windows_Vista_or_later_to_override_audit_policy_category_settings'
        {
            Name = 'Audit_Force_audit_policy_subcategory_settings_Windows_Vista_or_later_to_override_audit_policy_category_settings'
            Audit_Force_audit_policy_subcategory_settings_Windows_Vista_or_later_to_override_audit_policy_category_settings = 'Enabled'
        }
    }
    
    if ($SystemObjectsStrengthenDefaultPermissions) {
        SecurityOption 'SecurityRegistry(INF): System_objects_Strengthen_default_permissions_of_internal_system_objects_eg_Symbolic_Links'
        {
            System_objects_Strengthen_default_permissions_of_internal_system_objects_eg_Symbolic_Links = 'Enabled'
            Name = 'System_objects_Strengthen_default_permissions_of_internal_system_objects_eg_Symbolic_Links'
        }
    }
    
    if ($NetworkSecurityAllowPKU2UAuthenticationRequests) {
        SecurityOption 'SecurityRegistry(INF): Network_Security_Allow_PKU2U_authentication_requests_to_this_computer_to_use_online_identities'
        {
            Network_Security_Allow_PKU2U_authentication_requests_to_this_computer_to_use_online_identities = 'Disabled'
            Name = 'Network_Security_Allow_PKU2U_authentication_requests_to_this_computer_to_use_online_identities'
        }
    }
    
    if ($InteractiveLogonMachineInactivityLimit) {
        SecurityOption 'SecurityRegistry(INF): Interactive_logon_Machine_inactivity_limit'
        {
            Name = 'Interactive_logon_Machine_inactivity_limit'
            Interactive_logon_Machine_inactivity_limit = '900'
        }
    }

    if ($NetworkSecurityDoNotStoreLANManagerHash) {
        SecurityOption 'SecurityRegistry(INF): Network_security_Do_not_store_LAN_Manager_hash_value_on_next_password_change'
        {
            Name = 'Network_security_Do_not_store_LAN_Manager_hash_value_on_next_password_change'
            Network_security_Do_not_store_LAN_Manager_hash_value_on_next_password_change = 'Enabled'
        }
    }
    
    if ($DomainMemberDigitallyEncryptOrSignDataAlways) {
        SecurityOption 'SecurityRegistry(INF): Domain_member_Digitally_encrypt_or_sign_secure_channel_data_always'
        {
            Domain_member_Digitally_encrypt_or_sign_secure_channel_data_always = 'Enabled'
            Name = 'Domain_member_Digitally_encrypt_or_sign_secure_channel_data_always'
        }
    }
    
    if ($NetworkSecurityLDAPClientSigningRequirements) {
        SecurityOption 'SecurityRegistry(INF): Network_security_LDAP_client_signing_requirements'
        {
            Name = 'Network_security_LDAP_client_signing_requirements'
            Network_security_LDAP_client_signing_requirements = 'Negotiate Signing'
        }
    }
    
    if ($UserAccountControlBehaviorElevationPrompt) {
        SecurityOption 'SecurityRegistry(INF): User_Account_Control_Behavior_of_the_elevation_prompt_for_administrators_in_Admin_Approval_Mode'
        {
            Name = 'User_Account_Control_Behavior_of_the_elevation_prompt_for_administrators_in_Admin_Approval_Mode'
            User_Account_Control_Behavior_of_the_elevation_prompt_for_administrators_in_Admin_Approval_Mode = 'Prompt for consent on the secure desktop'
        }
    }
    
    if ($AccountLockoutDurationEnabled) {
        AccountPolicy 'SecuritySetting(INF): LockoutDuration'
        {
            Account_lockout_duration = 15
            Name = 'Account_lockout_duration'
        }
    }
    
    if ($AccountLockoutThresholdEnabled) {
        AccountPolicy 'SecuritySetting(INF): LockoutBadCount'
        {
            Account_lockout_threshold = 3
            Name = 'Account_lockout_threshold'
        }
    }

    if ($ResetAccountLockoutCount) {
        AccountPolicy 'SecuritySetting(INF): ResetLockoutCount'
        {
            Reset_account_lockout_counter_after = 15
            Name = 'Reset_account_lockout_counter_after'
        }
    }
    
    if ($AccountsRenameGuestAccount) {
        SecurityOption 'SecuritySetting(INF): NewGuestName'
        {
            Name = 'Accounts_Rename_guest_account'
            Accounts_Rename_guest_account = 'Visitor'
        }
    }
    
    if ($MinimumPasswordAgeEnabled) {
        AccountPolicy 'SecuritySetting(INF): MinimumPasswordAge'
        {
            Name = 'Minimum_Password_Age'
            Minimum_Password_Age = 1
        }
    }
    
    if ($PasswordComplexityEnabled) {
        AccountPolicy 'SecuritySetting(INF): PasswordComplexity'
        {
            Password_must_meet_complexity_requirements = 'Enabled'
            Name = 'Password_must_meet_complexity_requirements'
        }
    }
    
    if ($PasswordHistoryEnforcementEnabled) {
        AccountPolicy 'SecuritySetting(INF): PasswordHistorySize'
        {
            Name = 'Enforce_password_history'
            Enforce_password_history = 24
        }
    }
    
    if ($NetworkAccessAllowAnonymousSIDNameTranslation) {
        SecurityOption 'SecuritySetting(INF): LSAAnonymousNameLookup'
        {
            Network_access_Allow_anonymous_SID_Name_translation = 'Disabled'
            Name = 'Network_access_Allow_anonymous_SID_Name_translation'
        }
    }

    if ($MinimumPasswordLengthEnabled) {
        AccountPolicy 'SecuritySetting(INF): MinimumPasswordLength'
        {
            Name = 'Minimum_Password_Length'
            Minimum_Password_Length = 14
        }
    }
    
    if ($AccountsRenameAdministratorAccount) {
        SecurityOption 'SecuritySetting(INF): NewAdministratorName'
        {
            Accounts_Rename_administrator_account = 'X_Admin'
            Name = 'Accounts_Rename_administrator_account'
        }
    }
    
    if ($AccountsGuestAccountStatusEnabled) {
        SecurityOption 'SecuritySetting(INF): EnableGuestAccount'
        {
            Name = 'Accounts_Guest_account_status'
            Accounts_Guest_account_status = 'Disabled'
        }
    }
    
    if ($MaximumPasswordAgeEnabled) {
        AccountPolicy 'SecuritySetting(INF): MaximumPasswordAge'
        {
            Maximum_Password_Age = 60
            Name = 'Maximum_Password_Age'
        }
    }
    
    if ($ClearTextPasswordEnabled) {
        AccountPolicy 'SecuritySetting(INF): ClearTextPassword'
        {
            Name = 'Store_passwords_using_reversible_encryption'
            Store_passwords_using_reversible_encryption = 'Disabled'
        }
    }

    if ($EnableComputerAndUserAccountsTrustedForDelegation) {
        UserRightsAssignment 'UserRightsAssignment(INF): Enable_computer_and_user_accounts_to_be_trusted_for_delegation'
        {
            Force = $True
            Identity = @('')
            Policy = 'Enable_computer_and_user_accounts_to_be_trusted_for_delegation'
        }
    }
    
    if ($AccessThisComputerFromTheNetwork) {
        UserRightsAssignment 'UserRightsAssignment(INF): Access_this_computer_from_the_network'
        {
            Force = $True
            Identity = @('*S-1-5-11', '*S-1-5-32-544')
            Policy = 'Access_this_computer_from_the_network'
        }
    }
    
    if ($BackUpFilesAndDirectories) {
        UserRightsAssignment 'UserRightsAssignment(INF): Back_up_files_and_directories'
        {
            Force = $True
            Identity = @('*S-1-5-32-544')
            Policy = 'Back_up_files_and_directories'
        }
    }
    
    if ($ImpersonateClientAfterAuthentication) {
        UserRightsAssignment 'UserRightsAssignment(INF): Impersonate_a_client_after_authentication'
        {
            Force = $True
            Identity = @('*S-1-5-32-544', '*S-1-5-19', '*S-1-5-20', '*S-1-5-6')
            Policy = 'Impersonate_a_client_after_authentication'
        }
    }
    
    if ($PerformVolumeMaintenanceTasks) {
        UserRightsAssignment 'UserRightsAssignment(INF): Perform_volume_maintenance_tasks'
        {
            Force = $True
            Identity = @('*S-1-5-32-544')
            Policy = 'Perform_volume_maintenance_tasks'
        }
    }

    if ($LoadAndUnloadDeviceDrivers) {
        UserRightsAssignment 'UserRightsAssignment(INF): Load_and_unload_device_drivers'
        {
            Force = $True
            Identity = @('*S-1-5-32-544')
            Policy = 'Load_and_unload_device_drivers'
        }
    }
    
    if ($LockPagesInMemory) {
        UserRightsAssignment 'UserRightsAssignment(INF): Lock_pages_in_memory'
        {
            Force = $True
            Identity = @('')
            Policy = 'Lock_pages_in_memory'
        }
    }
    
    if ($TakeOwnershipOfFilesOrOtherObjects) {
        UserRightsAssignment 'UserRightsAssignment(INF): Take_ownership_of_files_or_other_objects'
        {
            Force = $True
            Identity = @('*S-1-5-32-544')
            Policy = 'Take_ownership_of_files_or_other_objects'
        }
    }
    
    if ($CreatePermanentSharedObjects) {
        UserRightsAssignment 'UserRightsAssignment(INF): Create_permanent_shared_objects'
        {
            Force = $True
            Identity = @('')
            Policy = 'Create_permanent_shared_objects'
        }
    }

    if ($DenyAccessToThisComputerFromTheNetwork) {
        UserRightsAssignment 'UserRightsAssignment(INF): Deny_access_to_this_computer_from_the_network'
        {
            Force = $True
            Identity = @('*S-1-5-113', '*S-1-5-32-546', $EnterpriseAdmins, $DomainAdmins)
            Policy = 'Deny_access_to_this_computer_from_the_network'
        }
    }
    
    if ($CreateGlobalObjects) {
        UserRightsAssignment 'UserRightsAssignment(INF): Create_global_objects'
        {
            Force = $True
            Identity = @('*S-1-5-32-544', '*S-1-5-19', '*S-1-5-20', '*S-1-5-6')
            Policy = 'Create_global_objects'
        }
    }
    
    if ($DenyLogOnAsABatchJob) {
        UserRightsAssignment 'UserRightsAssignment(INF): Deny_log_on_as_a_batch_job'
        {
            Force = $True
            Identity = @('*S-1-5-32-546', $EnterpriseAdmins, $DomainAdmins)
            Policy = 'Deny_log_on_as_a_batch_job'
        }
    }
    
    if ($RestoreFilesAndDirectories) {
        UserRightsAssignment 'UserRightsAssignment(INF): Restore_files_and_directories'
        {
            Force = $True
            Identity = @('*S-1-5-32-544')
            Policy = 'Restore_files_and_directories'
        }
    }

    if ($AccessCredentialManagerAsTrustedCaller) {
        UserRightsAssignment 'UserRightsAssignment(INF): Access_Credential_Manager_as_a_trusted_caller'
        {
            Force = $True
            Identity = @('')
            Policy = 'Access_Credential_Manager_as_a_trusted_caller'
        }
    }
    
    if ($DenyLogOnAsAService) {
        UserRightsAssignment 'UserRightsAssignment(INF): Deny_log_on_as_a_service'
        {
            Force = $True
            Identity = @($EnterpriseAdmins, $DomainAdmins)
            Policy = 'Deny_log_on_as_a_service'
        }
    }
    
    if ($IncreaseSchedulingPriority) {
        UserRightsAssignment 'UserRightsAssignment(INF): Increase_scheduling_priority'
        {
            Force = $True
            Identity = @('*S-1-5-32-544')
            Policy = 'Increase_scheduling_priority'
        }
    }
    
    if ($ForceShutdownFromRemoteSystem) {
        UserRightsAssignment 'UserRightsAssignment(INF): Force_shutdown_from_a_remote_system'
        {
            Force = $True
            Identity = @('*S-1-5-32-544')
            Policy = 'Force_shutdown_from_a_remote_system'
        }
    }
    
    if ($GenerateSecurityAudits) {
        UserRightsAssignment 'UserRightsAssignment(INF): Generate_security_audits'
        {
            Force = $True
            Identity = @('*S-1-5-19', '*S-1-5-20')
            Policy = 'Generate_security_audits'
        }
    }
    
    if ($DenyLogOnLocally) {
        UserRightsAssignment 'UserRightsAssignment(INF): Deny_log_on_locally'
        {
            Force = $True
            Identity = @('*S-1-5-32-546', $EnterpriseAdmins, $DomainAdmins)
            Policy = 'Deny_log_on_locally'
        }
    }
    
    if ($CreateSymbolicLinks) {
        UserRightsAssignment 'UserRightsAssignment(INF): Create_symbolic_links'
        {
            Force = $True
            Identity = @('*S-1-5-32-544')
            Policy = 'Create_symbolic_links'
        }
    }

    if ($DebugPrograms) {
        UserRightsAssignment 'UserRightsAssignment(INF): Debug_programs'
        {
            Force = $True
            Identity = @('*S-1-5-32-544')
            Policy = 'Debug_programs'
        }
    }
    
    if ($AllowLogOnLocally) {
        UserRightsAssignment 'UserRightsAssignment(INF): Allow_log_on_locally'
        {
            Force = $True
            Identity = @('*S-1-5-32-544')
            Policy = 'Allow_log_on_locally'
        }
    }
    
    if ($ManageAuditingAndSecurityLog) {
        UserRightsAssignment 'UserRightsAssignment(INF): Manage_auditing_and_security_log'
        {
            Force = $True
            Identity = @('*S-1-5-32-544')
            Policy = 'Manage_auditing_and_security_log'
        }
    }
    
    if ($ActAsPartOfTheOperatingSystem) {
        UserRightsAssignment 'UserRightsAssignment(INF): Act_as_part_of_the_operating_system'
        {
            Force = $True
            Identity = @('')
            Policy = 'Act_as_part_of_the_operating_system'
        }
    }
    
    if ($ProfileSingleProcess) {
        UserRightsAssignment 'UserRightsAssignment(INF): Profile_single_process'
        {
            Force = $True
            Identity = @('*S-1-5-32-544')
            Policy = 'Profile_single_process'
        }
    }

    if ($CreateATokenObject) {
        UserRightsAssignment 'UserRightsAssignment(INF): Create_a_token_object'
        {
            Force = $True
            Identity = @('')
            Policy = 'Create_a_token_object'
        }
    }
    
    if ($ModifyFirmwareEnvironmentValues) {
        UserRightsAssignment 'UserRightsAssignment(INF): Modify_firmware_environment_values'
        {
            Force = $True
            Identity = @('*S-1-5-32-544')
            Policy = 'Modify_firmware_environment_values'
        }
    }
    
    if ($CreateAPagefile) {
        UserRightsAssignment 'UserRightsAssignment(INF): Create_a_pagefile'
        {
            Force = $True
            Identity = @('*S-1-5-32-544')
            Policy = 'Create_a_pagefile'
        }
    }
    
    if ($DenyLogOnThroughRemoteDesktopServices) {
        UserRightsAssignment 'UserRightsAssignment(INF): Deny_log_on_through_Remote_Desktop_Services'
        {
            Force = $True
            Identity = @('*S-1-5-113', '*S-1-5-32-546', $EnterpriseAdmins, $DomainAdmins)
            Policy = 'Deny_log_on_through_Remote_Desktop_Services'
        }
    }
    
    if ($DomainControllerLDAPServerSigningRequirements) {
        SecurityOption 'SecurityRegistry(INF): Domain_controller_LDAP_server_signing_requirements'
        {
            Domain_controller_LDAP_server_signing_requirements = 'Require Signing'
            Name = 'Domain_controller_LDAP_server_signing_requirements'
        }
    }
    
    if ($DomainControllerRefuseMachineAccountPasswordChanges) {
        SecurityOption 'SecurityRegistry(INF): Domain_controller_Refuse_machine_account_password_changes'
        {
            Name = 'Domain_controller_Refuse_machine_account_password_changes'
            Domain_controller_Refuse_machine_account_password_changes = 'Disabled'
        }
    }
}

