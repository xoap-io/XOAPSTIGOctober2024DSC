configuration DoD_Windows_11_v2r2
{

    param(
        [string]$EnterpriseAdmins,
        [string]$DomainAdmins,
        [bool]$SuppressionPolicy_BatFile = $true,
        [bool]$SuppressionPolicy_CmdFile = $true,
        [bool]$SuppressionPolicy_ExeFile = $true,
        [bool]$SuppressionPolicy_MscFile = $true,
        [bool]$AutoConnectAllowedOEM = $true,
        [bool]$EnumerateAdministrators = $true,
        [bool]$NoStartBanner = $true,
        [bool]$NoWebServices = $true,
        [bool]$NoAutorun = $true,
        [bool]$NoDriveTypeAutoRun = $true,
        [bool]$PreXPSP2ShellProtocolBehavior = $true,
        [bool]$PasswordComplexity = $true,
        [bool]$PasswordLength = $true,
        [bool]$PasswordAgeDays = $true,
        [bool]$LocalAccountTokenFilterPolicy = $true,
        [bool]$MSAOptional = $true,
        [bool]$DisableAutomaticRestartSignOn = $true,
        [bool]$ProcessCreationIncludeCmdLine_Enabled = $true,
        [bool]$DevicePKInitEnabled = $true,
        [bool]$DevicePKInitBehavior = $true,
        [bool]$EnhancedAntiSpoofing = $true,
        [bool]$EccCurves = $true,
        [bool]$UseAdvancedStartup = $true,
        [bool]$EnableBDEWithNoTPM = $true,
        [bool]$UseTPM = $true,
        [bool]$UseTPMPIN = $true,
        [bool]$UseTPMKey = $true,
        [bool]$UseTPMKeyPIN = $true,
        [bool]$MinimumPIN = $true,
        [bool]$DisableEnclosureDownload = $true,
        [bool]$AllowBasicAuthInClear = $true,
        [bool]$NotifyDisableIEOptions = $true,
        [bool]$RequireSecurityDevice = $true,
        [bool]$TPM12 = $true,
        [bool]$MinimumPINLength = $true,
        [bool]$DCSettingIndex = $true,
        [bool]$ACSettingIndex = $true,
        [bool]$DisableInventory = $true,
        [bool]$LetAppsActivateWithVoiceAboveLock = $true,
        [bool]$DisableWindowsConsumerFeatures = $true,
        [bool]$AllowProtectedCreds = $true,
        [bool]$LimitEnhancedDiagnosticDataWindowsAnalytics = $true,
        [bool]$AllowTelemetry = $true,
        [bool]$DODownloadMode = $true,
        [bool]$EnableVirtualizationBasedSecurity = $true,
        [bool]$RequirePlatformSecurityFeatures = $true,
        [bool]$HypervisorEnforcedCodeIntegrity = $true,
        [bool]$HVCIMATRequired = $true,
        [bool]$LsaCfgFlags = $true,
        [bool]$ConfigureSystemGuardLaunch = $true,
        [bool]$MaxSizeApplicationLog = $true,
        [bool]$MaxSizeSecurityLog = $true,
        [bool]$MaxSizeSystemLog = $true,
        [bool]$NoAutoplayForNonVolume = $true,
        [bool]$NoDataExecutionPrevention = $true,
        [bool]$NoHeapTerminationOnCorruption = $true,
        [bool]$AllowGameDVR = $true,
        [bool]$NoBackgroundPolicy = $true,
        [bool]$NoGPOListChanges = $true,
        [bool]$EnableUserControl = $true,
        [bool]$AlwaysInstallElevated = $true,
        [bool]$SafeForScripting = $true,
        [bool]$DeviceEnumerationPolicy = $true,
        [bool]$AllowInsecureGuestAuth = $true,
        [bool]$NC_ShowSharedAccessUI = $true,
        [bool]$HardenedPaths_SYSVOL = $true,
        [bool]$HardenedPaths_NETLOGON = $true,
        [bool]$NoLockScreenCamera = $true,
        [bool]$NoLockScreenSlideshow = $true,
        [bool]$EnableScriptBlockLogging = $true,
        [bool]$EnableScriptBlockInvocationLogging = $true,
        [bool]$EnableTranscripting = $true,
        [bool]$OutputDirectory = $true,
        [bool]$EnableInvocationHeader = $true,
        [bool]$DontDisplayNetworkSelectionUI = $true,
        [bool]$EnumerateLocalUsers = $true,
        [bool]$EnableSmartScreen = $true,
        [bool]$ShellSmartScreenLevel = $true,
        [bool]$AllowDomainPINLogon = $true,
        [bool]$fMinimizeConnections = $true,
        [bool]$fBlockNonDomain = $true,
        [bool]$AllowIndexingEncryptedStoresOrItems = $true,
        [bool]$AllowBasicClient = $true,
        [bool]$AllowUnencryptedTraffic = $true,
        [bool]$AllowDigest = $true,
        [bool]$AllowBasicService = $true,
        [bool]$DisableRunAs = $true,
        [bool]$DisableWebPnPDownload = $true,
        [bool]$DisableHTTPPrinting = $true,
        [bool]$RestrictRemoteClients = $true,
        [bool]$fAllowToGetHelp = $true,
        [bool]$fAllowFullControl = $true,
        [bool]$MaxTicketExpiry = $true,
        [bool]$MaxTicketExpiryUnits = $true,
        [bool]$fUseMailto = $true,
        [bool]$DisablePasswordSaving = $true,
        [bool]$fDisableCdm = $true,
        [bool]$fPromptForPassword = $true,
        [bool]$fEncryptRPCTraffic = $true,
        [bool]$MinEncryptionLevel = $true,
        [bool]$AllowWindowsInkWorkspace = $true,
        [bool]$UseLogonCredential = $true,
        [bool]$DisableExceptionChainValidation = $true,
        [bool]$DriverLoadPolicy = $true,
        [bool]$SMB1 = $true,
        [bool]$StartMrxSmb10 = $true,
        [bool]$NoNameReleaseOnDemand = $true,
        [bool]$DisableIPSourceRouting = $true,
        [bool]$EnableICMPRedirect = $true,
        [bool]$DisableIPSourceRoutingIPv6 = $true,
        [bool]$AuditCredentialValidation = $true,
        [bool]$AuditCredentialValidationFailure = $true,
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
        [bool]$AuditOtherLogonLogoffEventsSuccess = $true,
        [bool]$AuditOtherLogonLogoffEventsFailure = $true,
        [bool]$AuditSpecialLogonSuccess = $true,
        [bool]$AuditSpecialLogonFailure = $true,
        [bool]$AuditDetailedFileShareFailure = $true,
        [bool]$AuditDetailedFileShareSuccess = $true,
        [bool]$AuditFileShareSuccess = $true,
        [bool]$AuditFileShareFailure = $true,
        [bool]$AuditOtherObjectAccessEventsSuccess = $true,
        [bool]$AuditOtherObjectAccessEventsFailure = $true,
        [bool]$AuditRemovableStorageSuccess = $true,
        [bool]$AuditRemovableStorageFailure = $true,
        [bool]$AuditAuditPolicyChangeSuccess = $true,
        [bool]$AuditAuditPolicyChangeFailure = $true,
        [bool]$AuditAuthenticationPolicyChangeSuccess = $true,
        [bool]$AuditAuthenticationPolicyChangeFailure = $true,
        [bool]$AuditAuthorizationPolicyChangeSuccess = $true,
        [bool]$AuditAuthorizationPolicyChangeFailure = $true,
        [bool]$AuditMPSSVCRuleLevelPolicyChangeSuccess = $true,
        [bool]$AuditMPSSVCRuleLevelPolicyChangeFailure = $true,
        [bool]$AuditOtherPolicyChangeEventsSuccess = $true,
        [bool]$AuditOtherPolicyChangeEventsFailure = $true,
        [bool]$AuditSensitivePrivilegeUseSuccess = $true,
        [bool]$AuditSensitivePrivilegeUseFailure = $true,
        [bool]$AuditIPsecDriverFailure = $true,
        [bool]$AuditIPsecDriverSuccess = $true,
        [bool]$AuditOtherSystemEventsSuccess = $true,
        [bool]$AuditOtherSystemEventsFailure = $true,
        [bool]$AuditSecurityStateChangeSuccess = $true,
        [bool]$AuditSecurityStateChangeFailure = $true,
        [bool]$AuditSecuritySystemExtensionSuccess = $true,
        [bool]$AuditSecuritySystemExtensionFailure = $true,
        [bool]$AuditSystemIntegritySuccess = $true,
        [bool]$AuditSystemIntegrityFailure = $true,
        [bool]$UserRightsAssignmentDelegation = $true,
        [bool]$UserRightsAssignmentNetworkAccess = $true,
        [bool]$UserRightsAssignmentBackupFiles = $true,
        [bool]$UserRightsAssignmentRestoreFiles = $true,
        [bool]$UserRightsAssignmentVolumeMaintenance = $true,
        [bool]$UserRightsAssignmentLoadUnloadDrivers = $true,
        [bool]$UserRightsAssignmentLockPages = $true,
        [bool]$UserRightsAssignmentTakeOwnership = $true,
        [bool]$UserRightsAssignmentCreatePermanentSharedObjects = $true,
        [bool]$UserRightsAssignmentDenyNetworkAccess = $true,
        [bool]$UserRightsAssignmentCreateGlobalObjects = $true,
        [bool]$UserRightsAssignmentDenyLogOnAsBatchJob = $true,
        [bool]$UserRightsAssignmentAccessCredentialManager = $true,
        [bool]$UserRightsAssignmentImpersonateClient = $true,
        [bool]$UserRightsAssignmentDenyLogOnAsService = $true,
        [bool]$UserRightsAssignmentForceShutdownRemote = $true,
        [bool]$UserRightsAssignmentDenyLogOnLocally = $true,
        [bool]$UserRightsAssignmentCreateSymbolicLinks = $true,
        [bool]$UserRightsAssignmentDebugPrograms = $true,
        [bool]$UserRightsAssignmentAllowLogOnLocally = $true,
        [bool]$UserRightsAssignmentManageAuditing = $true,
        [bool]$UserRightsAssignmentActAsPartOfOS = $true,
        [bool]$UserRightsAssignmentProfileSingleProcess = $true,
        [bool]$UserRightsAssignmentCreateTokenObject = $true,
        [bool]$UserRightsAssignmentChangeSystemTime = $true,
        [bool]$UserRightsAssignmentModifyFirmwareValues = $true,
        [bool]$UserRightsAssignmentCreatePagefile = $true,
        [bool]$UserRightsAssignmentDenyLogOnThroughRDS = $true,
        [bool]$NetworkAccessRestrictClients = $true,
        [bool]$RestrictAnonymousAccess = $true,
        [bool]$StrongSessionKey = $true,
        [bool]$ElevateUIAccessApps = $true,
        [bool]$MinimumSessionSecurityNTLM = $true,
        [bool]$AllowLocalSystemNullSessionFallback = $true,
        [bool]$SystemCryptographyFIPS = $true,
        [bool]$LANManagerAuthenticationLevel = $true,
        [bool]$DisableMachineAccountPasswordChanges = $true,
        [bool]$InteractiveLogonMessageTitle = $true,
        [bool]$DigitallySignSecureChannelData = $true,
        [bool]$LimitLocalAccountUseOfBlankPasswords = $true,
        [bool]$VirtualizeFileAndRegistryFailures = $true,
        [bool]$InteractiveLogonMachineInactivityLimit = $true,
        [bool]$InteractiveLogonMessageText = $true,
        [bool]$DigitallyEncryptSecureChannelData = $true,
        [bool]$UACStandardUserElevationPrompt = $true,
        [bool]$UACAdminApprovalMode = $true,
        [bool]$NetworkServerDigitallySignCommunications = $true,
        [bool]$NetworkClientDigitallySignCommunications = $true,
        [bool]$MinimumSessionSecurityNTLMSP = $true,
        [bool]$UACRunAllAdminsInAdminApprovalMode = $true,
        [bool]$UACDetectApplicationInstallations = $true,
        [bool]$DoNotAllowAnonymousEnumeration = $true,
        [bool]$ConfigureEncryptionTypesKerberos = $true,
        [bool]$NetworkClientSendUnencryptedPassword = $true,
        [bool]$InteractiveLogonPreviousLogonsCache = $true,
        [bool]$MaxMachineAccountPasswordAge = $true,
        [bool]$DoNotAllowAnonymousEnumerationShares = $true,
        [bool]$ForceAuditPolicySubcategorySettings = $true,
        [bool]$StrengthenDefaultPermissions = $true,
        [bool]$AllowPKU2UAuthenticationRequests = $true,
        [bool]$DigitallyEncryptOrSignSecureChannelData = $true,
        [bool]$SmartCardRemovalBehavior = $true,
        [bool]$DoNotStoreLANManagerHash = $true,
        [bool]$EveryonePermissionsForAnonymousUsers = $true,
        [bool]$LDAPClientSigningRequirements = $true,
        [bool]$UACAdminElevationPromptBehavior = $true,
        [bool]$AccountLockoutDuration = $true,
        [bool]$AccountLockoutThreshold = $true,
        [bool]$ResetLockoutCount = $true,
        [bool]$RenameGuestAccount = $true,
        [bool]$MinimumPasswordAge = $true,
        [bool]$PasswordHistorySize = $true,
        [bool]$AnonymousNameLookup = $true,
        [bool]$MinimumPasswordLength = $true,
        [bool]$EnableAdminAccount = $true,
        [bool]$NewAdministratorName = $true,
        [bool]$EnableGuestAccount = $true,
        [bool]$MaximumPasswordAge = $true,
        [bool]$ClearTextPassword = $true
    )

	Import-DSCResource -ModuleName 'GPRegistryPolicyDsc'
	Import-DSCResource -ModuleName 'AuditPolicyDSC'
	Import-DSCResource -ModuleName 'SecurityPolicyDSC'

    if ($SuppressionPolicy_BatFile) {
        RegistryPolicyFile 'Registry(POL): HKLM:\SOFTWARE\Classes\batfile\shell\runasuser\SuppressionPolicy'
        {
            Key = '\SOFTWARE\Classes\batfile\shell\runasuser'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
            ValueName = 'SuppressionPolicy'
            ValueData = 4096
        }
    }
    
    if ($SuppressionPolicy_CmdFile) {
        RegistryPolicyFile 'Registry(POL): HKLM:\SOFTWARE\Classes\cmdfile\shell\runasuser\SuppressionPolicy'
        {
            Key = '\SOFTWARE\Classes\cmdfile\shell\runasuser'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
            ValueName = 'SuppressionPolicy'
            ValueData = 4096
        }
    }
    
    if ($SuppressionPolicy_ExeFile) {
        RegistryPolicyFile 'Registry(POL): HKLM:\SOFTWARE\Classes\exefile\shell\runasuser\SuppressionPolicy'
        {
            Key = '\SOFTWARE\Classes\exefile\shell\runasuser'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
            ValueName = 'SuppressionPolicy'
            ValueData = 4096
        }
    }
    
    if ($SuppressionPolicy_MscFile) {
        RegistryPolicyFile 'Registry(POL): HKLM:\SOFTWARE\Classes\mscfile\shell\runasuser\SuppressionPolicy'
        {
            Key = '\SOFTWARE\Classes\mscfile\shell\runasuser'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
            ValueName = 'SuppressionPolicy'
            ValueData = 4096
        }
    }
    
    if ($AutoConnectAllowedOEM) {
        RegistryPolicyFile 'Registry(POL): HKLM:\SOFTWARE\Microsoft\wcmsvc\wifinetworkmanager\config\AutoConnectAllowedOEM'
        {
            Key = '\SOFTWARE\Microsoft\wcmsvc\wifinetworkmanager\config'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
            ValueName = 'AutoConnectAllowedOEM'
            ValueData = 0
        }
    }
    
    if ($EnumerateAdministrators) {
        RegistryPolicyFile 'Registry(POL): HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\CredUI\EnumerateAdministrators'
        {
            Key = '\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\CredUI'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
            ValueName = 'EnumerateAdministrators'
            ValueData = 0
        }
    }

    if ($NoStartBanner) {
        RegistryPolicyFile 'Registry(POL): HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer\NoStartBanner'
        {
            Key = '\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
            ValueName = 'NoStartBanner'
            ValueData = 1
        }
    }
    
    if ($NoWebServices) {
        RegistryPolicyFile 'Registry(POL): HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer\NoWebServices'
        {
            Key = '\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
            ValueName = 'NoWebServices'
            ValueData = 1
        }
    }
    
    if ($NoAutorun) {
        RegistryPolicyFile 'Registry(POL): HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer\NoAutorun'
        {
            Key = '\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
            ValueName = 'NoAutorun'
            ValueData = 1
        }
    }
    
    if ($NoDriveTypeAutoRun) {
        RegistryPolicyFile 'Registry(POL): HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer\NoDriveTypeAutoRun'
        {
            Key = '\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
            ValueName = 'NoDriveTypeAutoRun'
            ValueData = 255
        }
    }
    
    if ($PreXPSP2ShellProtocolBehavior) {
        RegistryPolicyFile 'Registry(POL): HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer\PreXPSP2ShellProtocolBehavior'
        {
            Key = '\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
            ValueName = 'PreXPSP2ShellProtocolBehavior'
            ValueData = 0
        }
    }
    
    if ($PasswordComplexity) {
        RegistryPolicyFile 'Registry(POL): HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\LAPS\PasswordComplexity'
        {
            Key = '\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\LAPS'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
            ValueName = 'PasswordComplexity'
            ValueData = 4
        }
    }

    if ($PasswordLength) {
        RegistryPolicyFile 'Registry(POL): HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\LAPS\PasswordLength'
        {
            Key = '\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\LAPS'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
            ValueName = 'PasswordLength'
            ValueData = 14
        }
    }
    
    if ($PasswordAgeDays) {
        RegistryPolicyFile 'Registry(POL): HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\LAPS\PasswordAgeDays'
        {
            Key = '\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\LAPS'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
            ValueName = 'PasswordAgeDays'
            ValueData = 60
        }
    }
    
    if ($LocalAccountTokenFilterPolicy) {
        RegistryPolicyFile 'Registry(POL): HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\LocalAccountTokenFilterPolicy'
        {
            Key = '\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
            ValueName = 'LocalAccountTokenFilterPolicy'
            ValueData = 0
        }
    }
    
    if ($MSAOptional) {
        RegistryPolicyFile 'Registry(POL): HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\MSAOptional'
        {
            Key = '\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
            ValueName = 'MSAOptional'
            ValueData = 1
        }
    }
    
    if ($DisableAutomaticRestartSignOn) {
        RegistryPolicyFile 'Registry(POL): HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\DisableAutomaticRestartSignOn'
        {
            Key = '\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
            ValueName = 'DisableAutomaticRestartSignOn'
            ValueData = 1
        }
    }
    
    if ($ProcessCreationIncludeCmdLine_Enabled) {
        RegistryPolicyFile 'Registry(POL): HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit\ProcessCreationIncludeCmdLine_Enabled'
        {
            Key = '\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
            ValueName = 'ProcessCreationIncludeCmdLine_Enabled'
            ValueData = 1
        }
    }
    
    if ($DevicePKInitEnabled) {
        RegistryPolicyFile 'Registry(POL): HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Kerberos\Parameters\DevicePKInitEnabled'
        {
            Key = '\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Kerberos\Parameters'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
            ValueName = 'DevicePKInitEnabled'
            ValueData = 1
        }
    }

    if ($DevicePKInitBehavior) {
        RegistryPolicyFile 'Registry(POL): HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Kerberos\Parameters\DevicePKInitBehavior'
        {
            Key = '\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Kerberos\Parameters'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
            ValueName = 'DevicePKInitBehavior'
            ValueData = 0
        }
    }
    
    if ($EnhancedAntiSpoofing) {
        RegistryPolicyFile 'Registry(POL): HKLM:\SOFTWARE\Policies\Microsoft\Biometrics\FacialFeatures\EnhancedAntiSpoofing'
        {
            Key = '\SOFTWARE\Policies\Microsoft\Biometrics\FacialFeatures'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
            ValueName = 'EnhancedAntiSpoofing'
            ValueData = 1
        }
    }
    
    if ($EccCurves) {
        RegistryPolicyFile 'Registry(POL): HKLM:\SOFTWARE\Policies\Microsoft\Cryptography\Configuration\SSL\00010002\EccCurves'
        {
            Key = '\SOFTWARE\Policies\Microsoft\Cryptography\Configuration\SSL\00010002'
            ValueType = 'MultiString'
            TargetType = 'ComputerConfiguration'
            ValueName = 'EccCurves'
            ValueData = 'NistP384NistP256'
        }
    }
    
    if ($UseAdvancedStartup) {
        RegistryPolicyFile 'Registry(POL): HKLM:\SOFTWARE\Policies\Microsoft\FVE\UseAdvancedStartup'
        {
            Key = '\SOFTWARE\Policies\Microsoft\FVE'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
            ValueName = 'UseAdvancedStartup'
            ValueData = 1
        }
    }
    
    if ($EnableBDEWithNoTPM) {
        RegistryPolicyFile 'Registry(POL): HKLM:\SOFTWARE\Policies\Microsoft\FVE\EnableBDEWithNoTPM'
        {
            Key = '\SOFTWARE\Policies\Microsoft\FVE'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
            ValueName = 'EnableBDEWithNoTPM'
            ValueData = 1
        }
    }
    
    if ($UseTPM) {
        RegistryPolicyFile 'Registry(POL): HKLM:\SOFTWARE\Policies\Microsoft\FVE\UseTPM'
        {
            Key = '\SOFTWARE\Policies\Microsoft\FVE'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
            ValueName = 'UseTPM'
            ValueData = 2
        }
    }
    
    if ($UseTPMPIN) {
        RegistryPolicyFile 'Registry(POL): HKLM:\SOFTWARE\Policies\Microsoft\FVE\UseTPMPIN'
        {
            Key = '\SOFTWARE\Policies\Microsoft\FVE'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
            ValueName = 'UseTPMPIN'
            ValueData = 1
        }
    }

    if ($UseTPMKey) {
        RegistryPolicyFile 'Registry(POL): HKLM:\SOFTWARE\Policies\Microsoft\FVE\UseTPMKey'
        {
            Key = '\SOFTWARE\Policies\Microsoft\FVE'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
            ValueName = 'UseTPMKey'
            ValueData = 2
        }
    }
    
    if ($UseTPMKeyPIN) {
        RegistryPolicyFile 'Registry(POL): HKLM:\SOFTWARE\Policies\Microsoft\FVE\UseTPMKeyPIN'
        {
            Key = '\SOFTWARE\Policies\Microsoft\FVE'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
            ValueName = 'UseTPMKeyPIN'
            ValueData = 2
        }
    }
    
    if ($MinimumPIN) {
        RegistryPolicyFile 'Registry(POL): HKLM:\SOFTWARE\Policies\Microsoft\FVE\MinimumPIN'
        {
            Key = '\SOFTWARE\Policies\Microsoft\FVE'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
            ValueName = 'MinimumPIN'
            ValueData = 6
        }
    }
    
    if ($DisableEnclosureDownload) {
        RegistryPolicyFile 'Registry(POL): HKLM:\SOFTWARE\Policies\Microsoft\Internet Explorer\Feeds\DisableEnclosureDownload'
        {
            Key = '\SOFTWARE\Policies\Microsoft\Internet Explorer\Feeds'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
            ValueName = 'DisableEnclosureDownload'
            ValueData = 1
        }
    }
    
    if ($AllowBasicAuthInClear) {
        RegistryPolicyFile 'Registry(POL): HKLM:\SOFTWARE\Policies\Microsoft\Internet Explorer\Feeds\AllowBasicAuthInClear'
        {
            Key = '\SOFTWARE\Policies\Microsoft\Internet Explorer\Feeds'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
            ValueName = 'AllowBasicAuthInClear'
            ValueData = 0
        }
    }
    
    if ($NotifyDisableIEOptions) {
        RegistryPolicyFile 'Registry(POL): HKLM:\SOFTWARE\Policies\Microsoft\Internet Explorer\Main\NotifyDisableIEOptions'
        {
            Key = '\SOFTWARE\Policies\Microsoft\Internet Explorer\Main'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
            ValueName = 'NotifyDisableIEOptions'
            ValueData = 0
        }
    }
    
    if ($RequireSecurityDevice) {
        RegistryPolicyFile 'Registry(POL): HKLM:\SOFTWARE\Policies\Microsoft\PassportForWork\RequireSecurityDevice'
        {
            Key = '\SOFTWARE\Policies\Microsoft\PassportForWork'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
            ValueName = 'RequireSecurityDevice'
            ValueData = 1
        }
    }

    if ($TPM12) {
        RegistryPolicyFile 'Registry(POL): HKLM:\SOFTWARE\Policies\Microsoft\PassportForWork\ExcludeSecurityDevices\TPM12'
        {
            Key = '\SOFTWARE\Policies\Microsoft\PassportForWork\ExcludeSecurityDevices'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
            ValueName = 'TPM12'
            ValueData = 0
        }
    }
    
    if ($MinimumPINLength) {
        RegistryPolicyFile 'Registry(POL): HKLM:\SOFTWARE\Policies\Microsoft\PassportForWork\PINComplexity\MinimumPINLength'
        {
            Key = '\SOFTWARE\Policies\Microsoft\PassportForWork\PINComplexity'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
            ValueName = 'MinimumPINLength'
            ValueData = 6
        }
    }
    
    if ($DCSettingIndex) {
        RegistryPolicyFile 'Registry(POL): HKLM:\SOFTWARE\Policies\Microsoft\Power\PowerSettings\0e796bdb-100d-47d6-a2d5-f7d2daa51f51\DCSettingIndex'
        {
            Key = '\SOFTWARE\Policies\Microsoft\Power\PowerSettings\0e796bdb-100d-47d6-a2d5-f7d2daa51f51'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
            ValueName = 'DCSettingIndex'
            ValueData = 1
        }
    }
    
    if ($ACSettingIndex) {
        RegistryPolicyFile 'Registry(POL): HKLM:\SOFTWARE\Policies\Microsoft\Power\PowerSettings\0e796bdb-100d-47d6-a2d5-f7d2daa51f51\ACSettingIndex'
        {
            Key = '\SOFTWARE\Policies\Microsoft\Power\PowerSettings\0e796bdb-100d-47d6-a2d5-f7d2daa51f51'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
            ValueName = 'ACSettingIndex'
            ValueData = 1
        }
    }
    
    if ($DisableInventory) {
        RegistryPolicyFile 'Registry(POL): HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppCompat\DisableInventory'
        {
            Key = '\SOFTWARE\Policies\Microsoft\Windows\AppCompat'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
            ValueName = 'DisableInventory'
            ValueData = 1
        }
    }
    
    if ($LetAppsActivateWithVoiceAboveLock) {
        RegistryPolicyFile 'Registry(POL): HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy\LetAppsActivateWithVoiceAboveLock'
        {
            Key = '\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
            ValueName = 'LetAppsActivateWithVoiceAboveLock'
            ValueData = 2
        }
    }
    
    if ($DisableWindowsConsumerFeatures) {
        RegistryPolicyFile 'Registry(POL): HKLM:\SOFTWARE\Policies\Microsoft\Windows\CloudContent\DisableWindowsConsumerFeatures'
        {
            Key = '\SOFTWARE\Policies\Microsoft\Windows\CloudContent'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
            ValueName = 'DisableWindowsConsumerFeatures'
            ValueData = 1
        }
    }
    
    if ($AllowProtectedCreds) {
        RegistryPolicyFile 'Registry(POL): HKLM:\SOFTWARE\Policies\Microsoft\Windows\CredentialsDelegation\AllowProtectedCreds'
        {
            Key = '\SOFTWARE\Policies\Microsoft\Windows\CredentialsDelegation'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
            ValueName = 'AllowProtectedCreds'
            ValueData = 1
        }
    }

    if ($LimitEnhancedDiagnosticDataWindowsAnalytics) {
        RegistryPolicyFile 'Registry(POL): HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection\LimitEnhancedDiagnosticDataWindowsAnalytics'
        {
            Key = '\SOFTWARE\Policies\Microsoft\Windows\DataCollection'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
            ValueName = 'LimitEnhancedDiagnosticDataWindowsAnalytics'
            ValueData = 1
        }
    }
    
    if ($AllowTelemetry) {
        RegistryPolicyFile 'Registry(POL): HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection\AllowTelemetry'
        {
            Key = '\SOFTWARE\Policies\Microsoft\Windows\DataCollection'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
            ValueName = 'AllowTelemetry'
            ValueData = 1
        }
    }
    
    if ($DODownloadMode) {
        RegistryPolicyFile 'Registry(POL): HKLM:\SOFTWARE\Policies\Microsoft\Windows\DeliveryOptimization\DODownloadMode'
        {
            Key = '\SOFTWARE\Policies\Microsoft\Windows\DeliveryOptimization'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
            ValueName = 'DODownloadMode'
            ValueData = 2
        }
    }
    
    if ($EnableVirtualizationBasedSecurity) {
        RegistryPolicyFile 'Registry(POL): HKLM:\SOFTWARE\Policies\Microsoft\Windows\DeviceGuard\EnableVirtualizationBasedSecurity'
        {
            Key = '\SOFTWARE\Policies\Microsoft\Windows\DeviceGuard'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
            ValueName = 'EnableVirtualizationBasedSecurity'
            ValueData = 1
        }
    }
    
    if ($RequirePlatformSecurityFeatures) {
        RegistryPolicyFile 'Registry(POL): HKLM:\SOFTWARE\Policies\Microsoft\Windows\DeviceGuard\RequirePlatformSecurityFeatures'
        {
            Key = '\SOFTWARE\Policies\Microsoft\Windows\DeviceGuard'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
            ValueName = 'RequirePlatformSecurityFeatures'
            ValueData = 1
        }
    }
    
    if ($HypervisorEnforcedCodeIntegrity) {
        RegistryPolicyFile 'Registry(POL): HKLM:\SOFTWARE\Policies\Microsoft\Windows\DeviceGuard\HypervisorEnforcedCodeIntegrity'
        {
            Key = '\SOFTWARE\Policies\Microsoft\Windows\DeviceGuard'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
            ValueName = 'HypervisorEnforcedCodeIntegrity'
            ValueData = 1
        }
    }
    
    if ($HVCIMATRequired) {
        RegistryPolicyFile 'Registry(POL): HKLM:\SOFTWARE\Policies\Microsoft\Windows\DeviceGuard\HVCIMATRequired'
        {
            Key = '\SOFTWARE\Policies\Microsoft\Windows\DeviceGuard'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
            ValueName = 'HVCIMATRequired'
            ValueData = 0
        }
    }

    if ($LsaCfgFlags) {
        RegistryPolicyFile 'Registry(POL): HKLM:\SOFTWARE\Policies\Microsoft\Windows\DeviceGuard\LsaCfgFlags'
        {
            Key = '\SOFTWARE\Policies\Microsoft\Windows\DeviceGuard'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
            ValueName = 'LsaCfgFlags'
            ValueData = 1
        }
    }
    
    if ($ConfigureSystemGuardLaunch) {
        RegistryPolicyFile 'Registry(POL): HKLM:\SOFTWARE\Policies\Microsoft\Windows\DeviceGuard\ConfigureSystemGuardLaunch'
        {
            Key = '\SOFTWARE\Policies\Microsoft\Windows\DeviceGuard'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
            ValueName = 'ConfigureSystemGuardLaunch'
            ValueData = 0
        }
    }
    
    if ($MaxSizeApplicationLog) {
        RegistryPolicyFile 'Registry(POL): HKLM:\SOFTWARE\Policies\Microsoft\Windows\EventLog\Application\MaxSize'
        {
            Key = '\SOFTWARE\Policies\Microsoft\Windows\EventLog\Application'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
            ValueName = 'MaxSize'
            ValueData = 32768
        }
    }
    
    if ($MaxSizeSecurityLog) {
        RegistryPolicyFile 'Registry(POL): HKLM:\SOFTWARE\Policies\Microsoft\Windows\EventLog\Security\MaxSize'
        {
            Key = '\SOFTWARE\Policies\Microsoft\Windows\EventLog\Security'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
            ValueName = 'MaxSize'
            ValueData = 1024000
        }
    }
    
    if ($MaxSizeSystemLog) {
        RegistryPolicyFile 'Registry(POL): HKLM:\SOFTWARE\Policies\Microsoft\Windows\EventLog\System\MaxSize'
        {
            Key = '\SOFTWARE\Policies\Microsoft\Windows\EventLog\System'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
            ValueName = 'MaxSize'
            ValueData = 32768
        }
    }
    
    if ($NoAutoplayForNonVolume) {
        RegistryPolicyFile 'Registry(POL): HKLM:\SOFTWARE\Policies\Microsoft\Windows\Explorer\NoAutoplayfornonVolume'
        {
            Key = '\SOFTWARE\Policies\Microsoft\Windows\Explorer'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
            ValueName = 'NoAutoplayfornonVolume'
            ValueData = 1
        }
    }
    
    if ($NoDataExecutionPrevention) {
        RegistryPolicyFile 'Registry(POL): HKLM:\SOFTWARE\Policies\Microsoft\Windows\Explorer\NoDataExecutionPrevention'
        {
            Key = '\SOFTWARE\Policies\Microsoft\Windows\Explorer'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
            ValueName = 'NoDataExecutionPrevention'
            ValueData = 0
        }
    }

    if ($NoHeapTerminationOnCorruption) {
        RegistryPolicyFile 'Registry(POL): HKLM:\SOFTWARE\Policies\Microsoft\Windows\Explorer\NoHeapTerminationOnCorruption'
        {
            Key = '\SOFTWARE\Policies\Microsoft\Windows\Explorer'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
            ValueName = 'NoHeapTerminationOnCorruption'
            ValueData = 0
        }
    }
    
    if ($AllowGameDVR) {
        RegistryPolicyFile 'Registry(POL): HKLM:\SOFTWARE\Policies\Microsoft\Windows\GameDVR\AllowGameDVR'
        {
            Key = '\SOFTWARE\Policies\Microsoft\Windows\GameDVR'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
            ValueName = 'AllowGameDVR'
            ValueData = 0
        }
    }
    
    if ($NoBackgroundPolicy) {
        RegistryPolicyFile 'Registry(POL): HKLM:\SOFTWARE\Policies\Microsoft\Windows\Group Policy\{35378EAC-683F-11D2-A89A-00C04FBBCFA2}\NoBackgroundPolicy'
        {
            Key = '\SOFTWARE\Policies\Microsoft\Windows\Group Policy\{35378EAC-683F-11D2-A89A-00C04FBBCFA2}'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
            ValueName = 'NoBackgroundPolicy'
            ValueData = 0
        }
    }
    
    if ($NoGPOListChanges) {
        RegistryPolicyFile 'Registry(POL): HKLM:\SOFTWARE\Policies\Microsoft\Windows\Group Policy\{35378EAC-683F-11D2-A89A-00C04FBBCFA2}\NoGPOListChanges'
        {
            Key = '\SOFTWARE\Policies\Microsoft\Windows\Group Policy\{35378EAC-683F-11D2-A89A-00C04FBBCFA2}'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
            ValueName = 'NoGPOListChanges'
            ValueData = 0
        }
    }
    
    if ($EnableUserControl) {
        RegistryPolicyFile 'Registry(POL): HKLM:\SOFTWARE\Policies\Microsoft\Windows\Installer\EnableUserControl'
        {
            Key = '\SOFTWARE\Policies\Microsoft\Windows\Installer'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
            ValueName = 'EnableUserControl'
            ValueData = 0
        }
    }
    
    if ($AlwaysInstallElevated) {
        RegistryPolicyFile 'Registry(POL): HKLM:\SOFTWARE\Policies\Microsoft\Windows\Installer\AlwaysInstallElevated'
        {
            Key = '\SOFTWARE\Policies\Microsoft\Windows\Installer'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
            ValueName = 'AlwaysInstallElevated'
            ValueData = 0
        }
    }

    if ($SafeForScripting) {
        RegistryPolicyFile 'Registry(POL): HKLM:\SOFTWARE\Policies\Microsoft\Windows\Installer\SafeForScripting'
        {
            Key = '\SOFTWARE\Policies\Microsoft\Windows\Installer'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
            ValueName = 'SafeForScripting'
            ValueData = 0
        }
    }
    
    if ($DeviceEnumerationPolicy) {
        RegistryPolicyFile 'Registry(POL): HKLM:\SOFTWARE\Policies\Microsoft\Windows\Kernel DMA Protection\DeviceEnumerationPolicy'
        {
            Key = '\SOFTWARE\Policies\Microsoft\Windows\Kernel DMA Protection'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
            ValueName = 'DeviceEnumerationPolicy'
            ValueData = 0
        }
    }
    
    if ($AllowInsecureGuestAuth) {
        RegistryPolicyFile 'Registry(POL): HKLM:\SOFTWARE\Policies\Microsoft\Windows\LanmanWorkstation\AllowInsecureGuestAuth'
        {
            Key = '\SOFTWARE\Policies\Microsoft\Windows\LanmanWorkstation'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
            ValueName = 'AllowInsecureGuestAuth'
            ValueData = 0
        }
    }
    
    if ($NC_ShowSharedAccessUI) {
        RegistryPolicyFile 'Registry(POL): HKLM:\SOFTWARE\Policies\Microsoft\Windows\Network Connections\NC_ShowSharedAccessUI'
        {
            Key = '\SOFTWARE\Policies\Microsoft\Windows\Network Connections'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
            ValueName = 'NC_ShowSharedAccessUI'
            ValueData = 0
        }
    }
    
    if ($HardenedPaths_SYSVOL) {
        RegistryPolicyFile 'Registry(POL): HKLM:\SOFTWARE\Policies\Microsoft\Windows\NetworkProvider\HardenedPaths\*\SYSVOL'
        {
            Key = '\SOFTWARE\Policies\Microsoft\Windows\NetworkProvider\HardenedPaths'
            ValueType = 'String'
            TargetType = 'ComputerConfiguration'
            ValueName = '\\*\SYSVOL'
            ValueData = 'RequireMutualAuthentication=1, RequireIntegrity=1'
        }
    }
    
    if ($HardenedPaths_NETLOGON) {
        RegistryPolicyFile 'Registry(POL): HKLM:\SOFTWARE\Policies\Microsoft\Windows\NetworkProvider\HardenedPaths\*\NETLOGON'
        {
            Key = '\SOFTWARE\Policies\Microsoft\Windows\NetworkProvider\HardenedPaths'
            ValueType = 'String'
            TargetType = 'ComputerConfiguration'
            ValueName = '\\*\NETLOGON'
            ValueData = 'RequireMutualAuthentication=1, RequireIntegrity=1'
        }
    }
    
    if ($NoLockScreenCamera) {
        RegistryPolicyFile 'Registry(POL): HKLM:\SOFTWARE\Policies\Microsoft\Windows\Personalization\NoLockScreenCamera'
        {
            Key = '\SOFTWARE\Policies\Microsoft\Windows\Personalization'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
            ValueName = 'NoLockScreenCamera'
            ValueData = 1
        }
    }

    if ($NoLockScreenSlideshow) {
        RegistryPolicyFile 'Registry(POL): HKLM:\SOFTWARE\Policies\Microsoft\Windows\Personalization\NoLockScreenSlideshow'
        {
            Key = '\SOFTWARE\Policies\Microsoft\Windows\Personalization'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
            ValueName = 'NoLockScreenSlideshow'
            ValueData = 1
        }
    }
    
    if ($EnableScriptBlockLogging) {
        RegistryPolicyFile 'Registry(POL): HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging\EnableScriptBlockLogging'
        {
            Key = '\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
            ValueName = 'EnableScriptBlockLogging'
            ValueData = 1
        }
    }
    
    if ($EnableScriptBlockInvocationLogging) {
        RegistryPolicyFile 'DEL_\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging\EnableScriptBlockInvocationLogging'
        {
            Key = '\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging'
            ValueType = 'String'
            Ensure = 'Absent'
            TargetType = 'ComputerConfiguration'
            ValueName = 'EnableScriptBlockInvocationLogging'
            ValueData = ''
        }
    }
    
    if ($EnableTranscripting) {
        RegistryPolicyFile 'Registry(POL): HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\Transcription\EnableTranscripting'
        {
            Key = '\SOFTWARE\Policies\Microsoft\Windows\PowerShell\Transcription'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
            ValueName = 'EnableTranscripting'
            ValueData = 1
        }
    }
    
    if ($OutputDirectory) {
        RegistryPolicyFile 'Registry(POL): HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\Transcription\OutputDirectory'
        {
            Key = '\SOFTWARE\Policies\Microsoft\Windows\PowerShell\Transcription'
            ValueType = 'String'
            TargetType = 'ComputerConfiguration'
            ValueName = 'OutputDirectory'
            ValueData = 'C:\ProgramData\PS_Transcript'
        }
    }
    
    if ($EnableInvocationHeader) {
        RegistryPolicyFile 'DEL_\SOFTWARE\Policies\Microsoft\Windows\PowerShell\Transcription\EnableInvocationHeader'
        {
            Key = '\SOFTWARE\Policies\Microsoft\Windows\PowerShell\Transcription'
            ValueType = 'String'
            Ensure = 'Absent'
            TargetType = 'ComputerConfiguration'
            ValueName = 'EnableInvocationHeader'
            ValueData = ''
        }
    }

    if ($DontDisplayNetworkSelectionUI) {
        RegistryPolicyFile 'Registry(POL): HKLM:\SOFTWARE\Policies\Microsoft\Windows\System\DontDisplayNetworkSelectionUI'
        {
            Key = '\SOFTWARE\Policies\Microsoft\Windows\System'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
            ValueName = 'DontDisplayNetworkSelectionUI'
            ValueData = 1
        }
    }
    
    if ($EnumerateLocalUsers) {
        RegistryPolicyFile 'Registry(POL): HKLM:\SOFTWARE\Policies\Microsoft\Windows\System\EnumerateLocalUsers'
        {
            Key = '\SOFTWARE\Policies\Microsoft\Windows\System'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
            ValueName = 'EnumerateLocalUsers'
            ValueData = 0
        }
    }
    
    if ($EnableSmartScreen) {
        RegistryPolicyFile 'Registry(POL): HKLM:\SOFTWARE\Policies\Microsoft\Windows\System\EnableSmartScreen'
        {
            Key = '\SOFTWARE\Policies\Microsoft\Windows\System'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
            ValueName = 'EnableSmartScreen'
            ValueData = 1
        }
    }
    
    if ($ShellSmartScreenLevel) {
        RegistryPolicyFile 'Registry(POL): HKLM:\SOFTWARE\Policies\Microsoft\Windows\System\ShellSmartScreenLevel'
        {
            Key = '\SOFTWARE\Policies\Microsoft\Windows\System'
            ValueType = 'String'
            TargetType = 'ComputerConfiguration'
            ValueName = 'ShellSmartScreenLevel'
            ValueData = 'Block'
        }
    }
    
    if ($AllowDomainPINLogon) {
        RegistryPolicyFile 'Registry(POL): HKLM:\SOFTWARE\Policies\Microsoft\Windows\System\AllowDomainPINLogon'
        {
            Key = '\SOFTWARE\Policies\Microsoft\Windows\System'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
            ValueName = 'AllowDomainPINLogon'
            ValueData = 0
        }
    }
    
    if ($fMinimizeConnections) {
        RegistryPolicyFile 'Registry(POL): HKLM:\SOFTWARE\Policies\Microsoft\Windows\WcmSvc\GroupPolicy\fMinimizeConnections'
        {
            Key = '\SOFTWARE\Policies\Microsoft\Windows\WcmSvc\GroupPolicy'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
            ValueName = 'fMinimizeConnections'
            ValueData = 3
        }
    }

    if ($fBlockNonDomain) {
        RegistryPolicyFile 'Registry(POL): HKLM:\SOFTWARE\Policies\Microsoft\Windows\WcmSvc\GroupPolicy\fBlockNonDomain'
        {
            Key = '\SOFTWARE\Policies\Microsoft\Windows\WcmSvc\GroupPolicy'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
            ValueName = 'fBlockNonDomain'
            ValueData = 1
        }
    }
    
    if ($AllowIndexingEncryptedStoresOrItems) {
        RegistryPolicyFile 'Registry(POL): HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search\AllowIndexingEncryptedStoresOrItems'
        {
            Key = '\SOFTWARE\Policies\Microsoft\Windows\Windows Search'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
            ValueName = 'AllowIndexingEncryptedStoresOrItems'
            ValueData = 0
        }
    }
    
    if ($AllowBasicClient) {
        RegistryPolicyFile 'Registry(POL): HKLM:\SOFTWARE\Policies\Microsoft\Windows\WinRM\Client\AllowBasic'
        {
            Key = '\SOFTWARE\Policies\Microsoft\Windows\WinRM\Client'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
            ValueName = 'AllowBasic'
            ValueData = 0
        }
    }
    
    if ($AllowUnencryptedTraffic) {
        RegistryPolicyFile 'Registry(POL): HKLM:\SOFTWARE\Policies\Microsoft\Windows\WinRM\Client\AllowUnencryptedTraffic'
        {
            Key = '\SOFTWARE\Policies\Microsoft\Windows\WinRM\Client'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
            ValueName = 'AllowUnencryptedTraffic'
            ValueData = 0
        }
    }
    
    if ($AllowDigest) {
        RegistryPolicyFile 'Registry(POL): HKLM:\SOFTWARE\Policies\Microsoft\Windows\WinRM\Client\AllowDigest'
        {
            Key = '\SOFTWARE\Policies\Microsoft\Windows\WinRM\Client'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
            ValueName = 'AllowDigest'
            ValueData = 0
        }
    }
    
    if ($AllowBasicService) {
        RegistryPolicyFile 'Registry(POL): HKLM:\SOFTWARE\Policies\Microsoft\Windows\WinRM\Service\AllowBasic'
        {
            Key = '\SOFTWARE\Policies\Microsoft\Windows\WinRM\Service'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
            ValueName = 'AllowBasic'
            ValueData = 0
        }
    }

    if ($AllowUnencryptedTraffic) {
        RegistryPolicyFile 'Registry(POL): HKLM:\SOFTWARE\Policies\Microsoft\Windows\WinRM\Service\AllowUnencryptedTraffic'
        {
            Key = '\SOFTWARE\Policies\Microsoft\Windows\WinRM\Service'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
            ValueName = 'AllowUnencryptedTraffic'
            ValueData = 0
        }
    }
    
    if ($DisableRunAs) {
        RegistryPolicyFile 'Registry(POL): HKLM:\SOFTWARE\Policies\Microsoft\Windows\WinRM\Service\DisableRunAs'
        {
            Key = '\SOFTWARE\Policies\Microsoft\Windows\WinRM\Service'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
            ValueName = 'DisableRunAs'
            ValueData = 1
        }
    }
    
    if ($DisableWebPnPDownload) {
        RegistryPolicyFile 'Registry(POL): HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Printers\DisableWebPnPDownload'
        {
            Key = '\SOFTWARE\Policies\Microsoft\Windows NT\Printers'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
            ValueName = 'DisableWebPnPDownload'
            ValueData = 1
        }
    }
    
    if ($DisableHTTPPrinting) {
        RegistryPolicyFile 'Registry(POL): HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Printers\DisableHTTPPrinting'
        {
            Key = '\SOFTWARE\Policies\Microsoft\Windows NT\Printers'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
            ValueName = 'DisableHTTPPrinting'
            ValueData = 1
        }
    }
    
    if ($RestrictRemoteClients) {
        RegistryPolicyFile 'Registry(POL): HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Rpc\RestrictRemoteClients'
        {
            Key = '\SOFTWARE\Policies\Microsoft\Windows NT\Rpc'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
            ValueName = 'RestrictRemoteClients'
            ValueData = 1
        }
    }
    
    if ($fAllowToGetHelp) {
        RegistryPolicyFile 'Registry(POL): HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services\fAllowToGetHelp'
        {
            Key = '\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
            ValueName = 'fAllowToGetHelp'
            ValueData = 0
        }
    }

    if ($fAllowFullControl) {
        RegistryPolicyFile 'DEL_\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services\fAllowFullControl'
        {
            Key = '\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services'
            ValueType = 'String'
            Ensure = 'Absent'
            TargetType = 'ComputerConfiguration'
            ValueName = 'fAllowFullControl'
            ValueData = ''
        }
    }
    
    if ($MaxTicketExpiry) {
        RegistryPolicyFile 'DEL_\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services\MaxTicketExpiry'
        {
            Key = '\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services'
            ValueType = 'String'
            Ensure = 'Absent'
            TargetType = 'ComputerConfiguration'
            ValueName = 'MaxTicketExpiry'
            ValueData = ''
        }
    }
    
    if ($MaxTicketExpiryUnits) {
        RegistryPolicyFile 'DEL_\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services\MaxTicketExpiryUnits'
        {
            Key = '\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services'
            ValueType = 'String'
            Ensure = 'Absent'
            TargetType = 'ComputerConfiguration'
            ValueName = 'MaxTicketExpiryUnits'
            ValueData = ''
        }
    }
    
    if ($fUseMailto) {
        RegistryPolicyFile 'DEL_\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services\fUseMailto'
        {
            Key = '\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services'
            ValueType = 'String'
            Ensure = 'Absent'
            TargetType = 'ComputerConfiguration'
            ValueName = 'fUseMailto'
            ValueData = ''
        }
    }
    
    if ($DisablePasswordSaving) {
        RegistryPolicyFile 'Registry(POL): HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services\DisablePasswordSaving'
        {
            Key = '\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
            ValueName = 'DisablePasswordSaving'
            ValueData = 1
        }
    }

    if ($fDisableCdm) {
        RegistryPolicyFile 'Registry(POL): HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services\fDisableCdm'
        {
            Key = '\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
            ValueName = 'fDisableCdm'
            ValueData = 1
        }
    }
    
    if ($fPromptForPassword) {
        RegistryPolicyFile 'Registry(POL): HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services\fPromptForPassword'
        {
            Key = '\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
            ValueName = 'fPromptForPassword'
            ValueData = 1
        }
    }
    
    if ($fEncryptRPCTraffic) {
        RegistryPolicyFile 'Registry(POL): HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services\fEncryptRPCTraffic'
        {
            Key = '\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
            ValueName = 'fEncryptRPCTraffic'
            ValueData = 1
        }
    }
    
    if ($MinEncryptionLevel) {
        RegistryPolicyFile 'Registry(POL): HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services\MinEncryptionLevel'
        {
            Key = '\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
            ValueName = 'MinEncryptionLevel'
            ValueData = 3
        }
    }
    
    if ($AllowWindowsInkWorkspace) {
        RegistryPolicyFile 'Registry(POL): HKLM:\SOFTWARE\Policies\Microsoft\WindowsInkWorkspace\AllowWindowsInkWorkspace'
        {
            Key = '\SOFTWARE\Policies\Microsoft\WindowsInkWorkspace'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
            ValueName = 'AllowWindowsInkWorkspace'
            ValueData = 1
        }
    }
    
    if ($UseLogonCredential) {
        RegistryPolicyFile 'Registry(POL): HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest\UseLogonCredential'
        {
            Key = '\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
            ValueName = 'UseLogonCredential'
            ValueData = 0
        }
    }

    if ($DisableExceptionChainValidation) {
        RegistryPolicyFile 'Registry(POL): HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\kernel\DisableExceptionChainValidation'
        {
            Key = '\SYSTEM\CurrentControlSet\Control\Session Manager\kernel'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
            ValueName = 'DisableExceptionChainValidation'
            ValueData = 0
        }
    }
    
    if ($DriverLoadPolicy) {
        RegistryPolicyFile 'Registry(POL): HKLM:\SYSTEM\CurrentControlSet\Policies\EarlyLaunch\DriverLoadPolicy'
        {
            Key = '\SYSTEM\CurrentControlSet\Policies\EarlyLaunch'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
            ValueName = 'DriverLoadPolicy'
            ValueData = 3
        }
    }
    
    if ($SMB1) {
        RegistryPolicyFile 'Registry(POL): HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters\SMB1'
        {
            Key = '\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
            ValueName = 'SMB1'
            ValueData = 0
        }
    }
    
    if ($StartMrxSmb10) {
        RegistryPolicyFile 'Registry(POL): HKLM:\SYSTEM\CurrentControlSet\Services\MrxSmb10\Start'
        {
            Key = '\SYSTEM\CurrentControlSet\Services\MrxSmb10'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
            ValueName = 'Start'
            ValueData = 4
        }
    }
    
    if ($NoNameReleaseOnDemand) {
        RegistryPolicyFile 'Registry(POL): HKLM:\SYSTEM\CurrentControlSet\Services\Netbt\Parameters\NoNameReleaseOnDemand'
        {
            Key = '\SYSTEM\CurrentControlSet\Services\Netbt\Parameters'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
            ValueName = 'NoNameReleaseOnDemand'
            ValueData = 1
        }
    }

    if ($DisableIPSourceRouting) {
        RegistryPolicyFile 'Registry(POL): HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\DisableIPSourceRouting'
        {
            Key = '\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
            ValueName = 'DisableIPSourceRouting'
            ValueData = 2
        }
    }
    
    if ($EnableICMPRedirect) {
        RegistryPolicyFile 'Registry(POL): HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\EnableICMPRedirect'
        {
            Key = '\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
            ValueName = 'EnableICMPRedirect'
            ValueData = 0
        }
    }
    
    if ($DisableIPSourceRoutingIPv6) {
        RegistryPolicyFile 'Registry(POL): HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip6\Parameters\DisableIPSourceRouting'
        {
            Key = '\SYSTEM\CurrentControlSet\Services\Tcpip6\Parameters'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
            ValueName = 'DisableIPSourceRouting'
            ValueData = 2
        }
    }
    
    if ($AuditCredentialValidation) {
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
            Ensure = 'Present'
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
    
    if ($AuditOtherLogonLogoffEventsSuccess) {
        AuditPolicySubcategory 'Audit Other Logon/Logoff Events (Success) - Inclusion'
        {
            Ensure = 'Present'
            Name = 'Other Logon/Logoff Events'
            AuditFlag = 'Success'
        }
    }
    
    if ($AuditOtherLogonLogoffEventsFailure) {
        AuditPolicySubcategory 'Audit Other Logon/Logoff Events (Failure) - Inclusion'
        {
            Ensure = 'Present'
            Name = 'Other Logon/Logoff Events'
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
    
    if ($AuditDetailedFileShareFailure) {
        AuditPolicySubcategory 'Audit Detailed File Share (Failure) - Inclusion'
        {
            Ensure = 'Present'
            Name = 'Detailed File Share'
            AuditFlag = 'Failure'
        }
    }
    
    if ($AuditDetailedFileShareSuccess) {
        AuditPolicySubcategory 'Audit Detailed File Share (Success) - Inclusion'
        {
            Ensure = 'Absent'
            Name = 'Detailed File Share'
            AuditFlag = 'Success'
        }
    }
    
    if ($AuditFileShareSuccess) {
        AuditPolicySubcategory 'Audit File Share (Success) - Inclusion'
        {
            Ensure = 'Present'
            Name = 'File Share'
            AuditFlag = 'Success'
        }
    }
    
    if ($AuditFileShareFailure) {
        AuditPolicySubcategory 'Audit File Share (Failure) - Inclusion'
        {
            Ensure = 'Present'
            Name = 'File Share'
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
    
    if ($AuditAuditPolicyChangeSuccess) {
        AuditPolicySubcategory 'Audit Audit Policy Change (Success) - Inclusion'
        {
            Ensure = 'Present'
            Name = 'Audit Policy Change'
            AuditFlag = 'Success'
        }
    }
    
    if ($AuditAuditPolicyChangeFailure) {
        AuditPolicySubcategory 'Audit Audit Policy Change (Failure) - Inclusion'
        {
            Ensure = 'Absent'
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
    
    if ($AuditMPSSVCRuleLevelPolicyChangeSuccess) {
        AuditPolicySubcategory 'Audit MPSSVC Rule-Level Policy Change (Success) - Inclusion'
        {
            Ensure = 'Present'
            Name = 'MPSSVC Rule-Level Policy Change'
            AuditFlag = 'Success'
        }
    }
    
    if ($AuditMPSSVCRuleLevelPolicyChangeFailure) {
        AuditPolicySubcategory 'Audit MPSSVC Rule-Level Policy Change (Failure) - Inclusion'
        {
            Ensure = 'Present'
            Name = 'MPSSVC Rule-Level Policy Change'
            AuditFlag = 'Failure'
        }
    }

    if ($AuditOtherPolicyChangeEventsSuccess) {
        AuditPolicySubcategory 'Audit Other Policy Change Events (Success) - Inclusion'
        {
            Ensure = 'Present'
            Name = 'Other Policy Change Events'
            AuditFlag = 'Success'
        }
    }
    
    if ($AuditOtherPolicyChangeEventsFailure) {
        AuditPolicySubcategory 'Audit Other Policy Change Events (Failure) - Inclusion'
        {
            Ensure = 'Present'
            Name = 'Other Policy Change Events'
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
    
    if ($AuditIPsecDriverFailure) {
        AuditPolicySubcategory 'Audit IPsec Driver (Failure) - Inclusion'
        {
            Ensure = 'Present'
            Name = 'IPsec Driver'
            AuditFlag = 'Failure'
        }
    }
    
    if ($AuditIPsecDriverSuccess) {
        AuditPolicySubcategory 'Audit IPsec Driver (Success) - Inclusion'
        {
            Ensure = 'Absent'
            Name = 'IPsec Driver'
            AuditFlag = 'Success'
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
    
    if ($UserRightsAssignmentDelegation) {
        UserRightsAssignment 'UserRightsAssignment(INF): Enable_computer_and_user_accounts_to_be_trusted_for_delegation'
        {
            Force = $True
            Identity = @('')
            Policy = 'Enable_computer_and_user_accounts_to_be_trusted_for_delegation'
        }
    }
    
    if ($UserRightsAssignmentNetworkAccess) {
        UserRightsAssignment 'UserRightsAssignment(INF): Access_this_computer_from_the_network'
        {
            Force = $True
            Identity = @('*S-1-5-32-555', '*S-1-5-32-544')
            Policy = 'Access_this_computer_from_the_network'
        }
    }

    if ($UserRightsAssignmentBackupFiles) {
        UserRightsAssignment 'UserRightsAssignment(INF): Back_up_files_and_directories'
        {
            Force = $True
            Identity = @('*S-1-5-32-544')
            Policy = 'Back_up_files_and_directories'
        }
    }
    
    if ($UserRightsAssignmentRestoreFiles) {
        UserRightsAssignment 'UserRightsAssignment(INF): Restore_files_and_directories'
        {
            Force = $True
            Identity = @('*S-1-5-32-544')
            Policy = 'Restore_files_and_directories'
        }
    }
    
    if ($UserRightsAssignmentVolumeMaintenance) {
        UserRightsAssignment 'UserRightsAssignment(INF): Perform_volume_maintenance_tasks'
        {
            Force = $True
            Identity = @('*S-1-5-32-544')
            Policy = 'Perform_volume_maintenance_tasks'
        }
    }
    
    if ($UserRightsAssignmentLoadUnloadDrivers) {
        UserRightsAssignment 'UserRightsAssignment(INF): Load_and_unload_device_drivers'
        {
            Force = $True
            Identity = @('*S-1-5-32-544')
            Policy = 'Load_and_unload_device_drivers'
        }
    }
    
    if ($UserRightsAssignmentLockPages) {
        UserRightsAssignment 'UserRightsAssignment(INF): Lock_pages_in_memory'
        {
            Force = $True
            Identity = @('')
            Policy = 'Lock_pages_in_memory'
        }
    }
    
    if ($UserRightsAssignmentTakeOwnership) {
        UserRightsAssignment 'UserRightsAssignment(INF): Take_ownership_of_files_or_other_objects'
        {
            Force = $True
            Identity = @('*S-1-5-32-544')
            Policy = 'Take_ownership_of_files_or_other_objects'
        }
    }
    
    if ($UserRightsAssignmentCreatePermanentSharedObjects) {
        UserRightsAssignment 'UserRightsAssignment(INF): Create_permanent_shared_objects'
        {
            Force = $True
            Identity = @('')
            Policy = 'Create_permanent_shared_objects'
        }
    }
    
    if ($UserRightsAssignmentDenyNetworkAccess) {
        UserRightsAssignment 'UserRightsAssignment(INF): Deny_access_to_this_computer_from_the_network'
        {
            Force = $True
            Identity = @($DomainAdmins, $EnterpriseAdmins, '*S-1-5-32-546', '*S-1-5-113')
            Policy = 'Deny_access_to_this_computer_from_the_network'
        }
    }
    
    if ($UserRightsAssignmentCreateGlobalObjects) {
        UserRightsAssignment 'UserRightsAssignment(INF): Create_global_objects'
        {
            Force = $True
            Identity = @('*S-1-5-6', '*S-1-5-20', '*S-1-5-19', '*S-1-5-32-544')
            Policy = 'Create_global_objects'
        }
    }

    if ($UserRightsAssignmentDenyLogOnAsBatchJob) {
        UserRightsAssignment 'UserRightsAssignment(INF): Deny_log_on_as_a_batch_job'
        {
            Force = $True
            Identity = @($DomainAdmins, $EnterpriseAdmins)
            Policy = 'Deny_log_on_as_a_batch_job'
        }
    }
    
    if ($UserRightsAssignmentAccessCredentialManager) {
        UserRightsAssignment 'UserRightsAssignment(INF): Access_Credential_Manager_as_a_trusted_caller'
        {
            Force = $True
            Identity = @('')
            Policy = 'Access_Credential_Manager_as_a_trusted_caller'
        }
    }
    
    if ($UserRightsAssignmentImpersonateClient) {
        UserRightsAssignment 'UserRightsAssignment(INF): Impersonate_a_client_after_authentication'
        {
            Force = $True
            Identity = @('*S-1-5-32-544', '*S-1-5-19', '*S-1-5-20', '*S-1-5-6')
            Policy = 'Impersonate_a_client_after_authentication'
        }
    }
    
    if ($UserRightsAssignmentDenyLogOnAsService) {
        UserRightsAssignment 'UserRightsAssignment(INF): Deny_log_on_as_a_service'
        {
            Force = $True
            Identity = @($DomainAdmins, $EnterpriseAdmins)
            Policy = 'Deny_log_on_as_a_service'
        }
    }
    
    if ($UserRightsAssignmentForceShutdownRemote) {
        UserRightsAssignment 'UserRightsAssignment(INF): Force_shutdown_from_a_remote_system'
        {
            Force = $True
            Identity = @('*S-1-5-32-544')
            Policy = 'Force_shutdown_from_a_remote_system'
        }
    }
    
    if ($UserRightsAssignmentDenyLogOnLocally) {
        UserRightsAssignment 'UserRightsAssignment(INF): Deny_log_on_locally'
        {
            Force = $True
            Identity = @($DomainAdmins, $EnterpriseAdmins, '*S-1-5-32-546')
            Policy = 'Deny_log_on_locally'
        }
    }
    
    if ($UserRightsAssignmentCreateSymbolicLinks) {
        UserRightsAssignment 'UserRightsAssignment(INF): Create_symbolic_links'
        {
            Force = $True
            Identity = @('*S-1-5-32-544')
            Policy = 'Create_symbolic_links'
        }
    }
    
    if ($UserRightsAssignmentDebugPrograms) {
        UserRightsAssignment 'UserRightsAssignment(INF): Debug_programs'
        {
            Force = $True
            Identity = @('*S-1-5-32-544')
            Policy = 'Debug_programs'
        }
    }
    
    if ($UserRightsAssignmentAllowLogOnLocally) {
        UserRightsAssignment 'UserRightsAssignment(INF): Allow_log_on_locally'
        {
            Force = $True
            Identity = @('*S-1-5-32-545', '*S-1-5-32-544')
            Policy = 'Allow_log_on_locally'
        }
    }

    f ($UserRightsAssignmentManageAuditing) {
        UserRightsAssignment 'UserRightsAssignment(INF): Manage_auditing_and_security_log'
        {
            Force = $True
            Identity = @('*S-1-5-32-544')
            Policy = 'Manage_auditing_and_security_log'
        }
    }
    
    if ($UserRightsAssignmentActAsPartOfOS) {
        UserRightsAssignment 'UserRightsAssignment(INF): Act_as_part_of_the_operating_system'
        {
            Force = $True
            Identity = @('')
            Policy = 'Act_as_part_of_the_operating_system'
        }
    }
    
    if ($UserRightsAssignmentProfileSingleProcess) {
        UserRightsAssignment 'UserRightsAssignment(INF): Profile_single_process'
        {
            Force = $True
            Identity = @('*S-1-5-32-544')
            Policy = 'Profile_single_process'
        }
    }
    
    if ($UserRightsAssignmentCreateTokenObject) {
        UserRightsAssignment 'UserRightsAssignment(INF): Create_a_token_object'
        {
            Force = $True
            Identity = @('')
            Policy = 'Create_a_token_object'
        }
    }
    
    if ($UserRightsAssignmentChangeSystemTime) {
        UserRightsAssignment 'UserRightsAssignment(INF): Change_the_system_time'
        {
            Force = $True
            Identity = @('*S-1-5-19', '*S-1-5-32-544')
            Policy = 'Change_the_system_time'
        }
    }
    
    if ($UserRightsAssignmentModifyFirmwareValues) {
        UserRightsAssignment 'UserRightsAssignment(INF): Modify_firmware_environment_values'
        {
            Force = $True
            Identity = @('*S-1-5-32-544')
            Policy = 'Modify_firmware_environment_values'
        }
    }
    
    if ($UserRightsAssignmentCreatePagefile) {
        UserRightsAssignment 'UserRightsAssignment(INF): Create_a_pagefile'
        {
            Force = $True
            Identity = @('*S-1-5-32-544')
            Policy = 'Create_a_pagefile'
        }
    }
    
    if ($UserRightsAssignmentDenyLogOnThroughRDS) {
        UserRightsAssignment 'UserRightsAssignment(INF): Deny_log_on_through_Remote_Desktop_Services'
        {
            Force = $True
            Identity = @($DomainAdmins, $EnterpriseAdmins, '*S-1-5-32-546', '*S-1-5-113')
            Policy = 'Deny_log_on_through_Remote_Desktop_Services'
        }
    }

    if ($NetworkAccessRestrictClients) {
        SecurityOption 'SecurityRegistry(INF): Network_access_Restrict_clients_allowed_to_make_remote_calls_to_SAM'
        {

        Name = 'Network_access_Restrict_clients_allowed_to_make_remote_calls_to_SAM'

        Network_access_Restrict_clients_allowed_to_make_remote_calls_to_SAM = @(

        MSFT_RestrictedRemoteSamSecurityDescriptor

        {

        Permission = 'Allow'

        Identity   = 'Administrators'

        }

        )

        }
    }
    
    if ($RestrictAnonymousAccess) {
        SecurityOption 'SecurityRegistry(INF): Network_access_Restrict_anonymous_access_to_Named_Pipes_and_Shares'
        {
            Network_access_Restrict_anonymous_access_to_Named_Pipes_and_Shares = 'Enabled'
            Name = 'Network_access_Restrict_anonymous_access_to_Named_Pipes_and_Shares'
        }
    }
    
    if ($StrongSessionKey) {
        SecurityOption 'SecurityRegistry(INF): Domain_member_Require_strong_Windows_2000_or_later_session_key'
        {
            Name = 'Domain_member_Require_strong_Windows_2000_or_later_session_key'
            Domain_member_Require_strong_Windows_2000_or_later_session_key = 'Enabled'
        }
    }
    
    if ($ElevateUIAccessApps) {
        SecurityOption 'SecurityRegistry(INF): User_Account_Control_Only_elevate_UIAccess_applications_that_are_installed_in_secure_locations'
        {
            User_Account_Control_Only_elevate_UIAccess_applications_that_are_installed_in_secure_locations = 'Enabled'
            Name = 'User_Account_Control_Only_elevate_UIAccess_applications_that_are_installed_in_secure_locations'
        }
    }
    
    if ($MinimumSessionSecurityNTLM) {
        SecurityOption 'SecurityRegistry(INF): Network_security_Minimum_session_security_for_NTLM_SSP_based_including_secure_RPC_servers'
        {
            Name = 'Network_security_Minimum_session_security_for_NTLM_SSP_based_including_secure_RPC_servers'
            Network_security_Minimum_session_security_for_NTLM_SSP_based_including_secure_RPC_servers = 'Both options checked'
        }
    }
    
    if ($AllowLocalSystemNullSessionFallback) {
        SecurityOption 'SecurityRegistry(INF): Network_security_Allow_LocalSystem_NULL_session_fallback'
        {
            Name = 'Network_security_Allow_LocalSystem_NULL_session_fallback'
            Network_security_Allow_LocalSystem_NULL_session_fallback = 'Disabled'
        }
    }

    if ($SystemCryptographyFIPS) {
        SecurityOption 'SecurityRegistry(INF): System_cryptography_Use_FIPS_compliant_algorithms_for_encryption_hashing_and_signing'
        {
            System_cryptography_Use_FIPS_compliant_algorithms_for_encryption_hashing_and_signing = 'Enabled'
            Name = 'System_cryptography_Use_FIPS_compliant_algorithms_for_encryption_hashing_and_signing'
        }
    }
    
    if ($LANManagerAuthenticationLevel) {
        SecurityOption 'SecurityRegistry(INF): Network_security_LAN_Manager_authentication_level'
        {
            Network_security_LAN_Manager_authentication_level = 'Send NTLMv2 responses only. Refuse LM & NTLM'
            Name = 'Network_security_LAN_Manager_authentication_level'
        }
    }
    
    if ($DisableMachineAccountPasswordChanges) {
        SecurityOption 'SecurityRegistry(INF): Domain_member_Disable_machine_account_password_changes'
        {
            Domain_member_Disable_machine_account_password_changes = 'Disabled'
            Name = 'Domain_member_Disable_machine_account_password_changes'
        }
    }
    
    if ($InteractiveLogonMessageTitle) {
        SecurityOption 'SecurityRegistry(INF): Interactive_logon_Message_title_for_users_attempting_to_log_on'
        {
            Name = 'Interactive_logon_Message_title_for_users_attempting_to_log_on'
            Interactive_logon_Message_title_for_users_attempting_to_log_on = 'US Department of Defense Warning Statement'
        }
    }
    
    if ($DigitallySignSecureChannelData) {
        SecurityOption 'SecurityRegistry(INF): Domain_member_Digitally_sign_secure_channel_data_when_possible'
        {
            Domain_member_Digitally_sign_secure_channel_data_when_possible = 'Enabled'
            Name = 'Domain_member_Digitally_sign_secure_channel_data_when_possible'
        }
    }
    
    if ($LimitLocalAccountUseOfBlankPasswords) {
        SecurityOption 'SecurityRegistry(INF): Accounts_Limit_local_account_use_of_blank_passwords_to_console_logon_only'
        {
            Name = 'Accounts_Limit_local_account_use_of_blank_passwords_to_console_logon_only'
            Accounts_Limit_local_account_use_of_blank_passwords_to_console_logon_only = 'Enabled'
        }
    }
    
    if ($VirtualizeFileAndRegistryFailures) {
        SecurityOption 'SecurityRegistry(INF): User_Account_Control_Virtualize_file_and_registry_write_failures_to_per_user_locations'
        {
            User_Account_Control_Virtualize_file_and_registry_write_failures_to_per_user_locations = 'Enabled'
            Name = 'User_Account_Control_Virtualize_file_and_registry_write_failures_to_per_user_locations'
        }
    }

    if ($InteractiveLogonMachineInactivityLimit) {
        SecurityOption 'SecurityRegistry(INF): Interactive_logon_Machine_inactivity_limit'
        {
            Name = 'Interactive_logon_Machine_inactivity_limit'
            Interactive_logon_Machine_inactivity_limit = '900'
        }
    }
    
    if ($InteractiveLogonMessageText) {
        SecurityOption 'SecurityRegistry(INF): Interactive_logon_Message_text_for_users_attempting_to_log_on'
        {
            Interactive_logon_Message_text_for_users_attempting_to_log_on = 'You are accessing a U.S. Government (USG) Information System (IS) that is provided for USG-authorized use only.,By using this IS (which includes any device attached to this IS), you consent to the following conditions:,-The USG routinely intercepts and monitors communications on this IS for purposes including, but not limited to, penetration testing, COMSEC monitoring, network operations and defense, personnel misconduct (PM), law enforcement (LE), and counterintelligence (CI) investigations.,-At any time, the USG may inspect and seize data stored on this IS.,-Communications using or data stored on this IS are not private, are subject to routine monitoring, interception, and search, and may be disclosed or used for any USG-authorized purpose.,-This IS includes security measures (e.g., authentication and access controls) to protect USG interests--not for your personal benefit or privacy.,-Notwithstanding the above, using this IS does not constitute consent to PM, LE or CI investigative searching or monitoring of the content of privileged communications or work product related to personal representation or services by attorneys, psychotherapists, or clergy and their assistants. Such communications and work product are private and confidential. See User Agreement for details.'
            Name = 'Interactive_logon_Message_text_for_users_attempting_to_log_on'
        }
    }
    
    if ($DigitallyEncryptSecureChannelData) {
        SecurityOption 'SecurityRegistry(INF): Domain_member_Digitally_encrypt_secure_channel_data_when_possible'
        {
            Name = 'Domain_member_Digitally_encrypt_secure_channel_data_when_possible'
            Domain_member_Digitally_encrypt_secure_channel_data_when_possible = 'Enabled'
        }
    }
    
    if ($UACStandardUserElevationPrompt) {
        SecurityOption 'SecurityRegistry(INF): User_Account_Control_Behavior_of_the_elevation_prompt_for_standard_users'
        {
            User_Account_Control_Behavior_of_the_elevation_prompt_for_standard_users = 'Automatically deny elevation request'
            Name = 'User_Account_Control_Behavior_of_the_elevation_prompt_for_standard_users'
        }
    }
    
    if ($UACAdminApprovalMode) {
        SecurityOption 'SecurityRegistry(INF): User_Account_Control_Admin_Approval_Mode_for_the_Built_in_Administrator_account'
        {
            User_Account_Control_Admin_Approval_Mode_for_the_Built_in_Administrator_account = 'Enabled'
            Name = 'User_Account_Control_Admin_Approval_Mode_for_the_Built_in_Administrator_account'
        }
    }

    if ($NetworkServerDigitallySignCommunications) {
        SecurityOption 'SecurityRegistry(INF): Microsoft_network_server_Digitally_sign_communications_always'
        {
            Microsoft_network_server_Digitally_sign_communications_always = 'Enabled'
            Name = 'Microsoft_network_server_Digitally_sign_communications_always'
        }
    }
    
    if ($NetworkClientDigitallySignCommunications) {
        SecurityOption 'SecurityRegistry(INF): Microsoft_network_client_Digitally_sign_communications_always'
        {
            Microsoft_network_client_Digitally_sign_communications_always = 'Enabled'
            Name = 'Microsoft_network_client_Digitally_sign_communications_always'
        }
    }
    
    if ($MinimumSessionSecurityNTLMSP) {
        SecurityOption 'SecurityRegistry(INF): Network_security_Minimum_session_security_for_NTLM_SSP_based_including_secure_RPC_clients'
        {
            Name = 'Network_security_Minimum_session_security_for_NTLM_SSP_based_including_secure_RPC_clients'
            Network_security_Minimum_session_security_for_NTLM_SSP_based_including_secure_RPC_clients = 'Both options checked'
        }
    }
    
    if ($UACRunAllAdminsInAdminApprovalMode) {
        SecurityOption 'SecurityRegistry(INF): User_Account_Control_Run_all_administrators_in_Admin_Approval_Mode'
        {
            User_Account_Control_Run_all_administrators_in_Admin_Approval_Mode = 'Enabled'
            Name = 'User_Account_Control_Run_all_administrators_in_Admin_Approval_Mode'
        }
    }
    
    if ($UACDetectApplicationInstallations) {
        SecurityOption 'SecurityRegistry(INF): User_Account_Control_Detect_application_installations_and_prompt_for_elevation'
        {
            User_Account_Control_Detect_application_installations_and_prompt_for_elevation = 'Enabled'
            Name = 'User_Account_Control_Detect_application_installations_and_prompt_for_elevation'
        }
    }
    
    if ($DoNotAllowAnonymousEnumeration) {
        SecurityOption 'SecurityRegistry(INF): Network_access_Do_not_allow_anonymous_enumeration_of_SAM_accounts'
        {
            Name = 'Network_access_Do_not_allow_anonymous_enumeration_of_SAM_accounts'
            Network_access_Do_not_allow_anonymous_enumeration_of_SAM_accounts = 'Enabled'
        }
    }
    
    if ($ConfigureEncryptionTypesKerberos) {
        SecurityOption 'SecurityRegistry(INF): Network_security_Configure_encryption_types_allowed_for_Kerberos'
        {
            Network_security_Configure_encryption_types_allowed_for_Kerberos = '2147483640'
            Name = 'Network_security_Configure_encryption_types_allowed_for_Kerberos'
        }
    }

    if ($NetworkClientSendUnencryptedPassword) {
        SecurityOption 'SecurityRegistry(INF): Microsoft_network_client_Send_unencrypted_password_to_third_party_SMB_servers'
        {
            Microsoft_network_client_Send_unencrypted_password_to_third_party_SMB_servers = 'Disabled'
            Name = 'Microsoft_network_client_Send_unencrypted_password_to_third_party_SMB_servers'
        }
    }
    
    if ($InteractiveLogonPreviousLogonsCache) {
        SecurityOption 'SecurityRegistry(INF): Interactive_logon_Number_of_previous_logons_to_cache_in_case_domain_controller_is_not_available'
        {
            Interactive_logon_Number_of_previous_logons_to_cache_in_case_domain_controller_is_not_available = '10'
            Name = 'Interactive_logon_Number_of_previous_logons_to_cache_in_case_domain_controller_is_not_available'
        }
    }
    
    if ($MaxMachineAccountPasswordAge) {
        SecurityOption 'SecurityRegistry(INF): Domain_member_Maximum_machine_account_password_age'
        {
            Name = 'Domain_member_Maximum_machine_account_password_age'
            Domain_member_Maximum_machine_account_password_age = '30'
        }
    }
    
    if ($DoNotAllowAnonymousEnumerationShares) {
        SecurityOption 'SecurityRegistry(INF): Network_access_Do_not_allow_anonymous_enumeration_of_SAM_accounts_and_shares'
        {
            Name = 'Network_access_Do_not_allow_anonymous_enumeration_of_SAM_accounts_and_shares'
            Network_access_Do_not_allow_anonymous_enumeration_of_SAM_accounts_and_shares = 'Enabled'
        }
    }
    
    if ($ForceAuditPolicySubcategorySettings) {
        SecurityOption 'SecurityRegistry(INF): Audit_Force_audit_policy_subcategory_settings_Windows_Vista_or_later_to_override_audit_policy_category_settings'
        {
            Name = 'Audit_Force_audit_policy_subcategory_settings_Windows_Vista_or_later_to_override_audit_policy_category_settings'
            Audit_Force_audit_policy_subcategory_settings_Windows_Vista_or_later_to_override_audit_policy_category_settings = 'Enabled'
        }
    }
    
    if ($StrengthenDefaultPermissions) {
        SecurityOption 'SecurityRegistry(INF): System_objects_Strengthen_default_permissions_of_internal_system_objects_eg_Symbolic_Links'
        {
            System_objects_Strengthen_default_permissions_of_internal_system_objects_eg_Symbolic_Links = 'Enabled'
            Name = 'System_objects_Strengthen_default_permissions_of_internal_system_objects_eg_Symbolic_Links'
        }
    }
    
    if ($AllowPKU2UAuthenticationRequests) {
        SecurityOption 'SecurityRegistry(INF): Network_Security_Allow_PKU2U_authentication_requests_to_this_computer_to_use_online_identities'
        {
            Network_Security_Allow_PKU2U_authentication_requests_to_this_computer_to_use_online_identities = 'Disabled'
            Name = 'Network_Security_Allow_PKU2U_authentication_requests_to_this_computer_to_use_online_identities'
        }
    }

    if ($DigitallyEncryptOrSignSecureChannelData) {
        SecurityOption 'SecurityRegistry(INF): Domain_member_Digitally_encrypt_or_sign_secure_channel_data_always'
        {
            Domain_member_Digitally_encrypt_or_sign_secure_channel_data_always = 'Enabled'
            Name = 'Domain_member_Digitally_encrypt_or_sign_secure_channel_data_always'
        }
    }
    
    if ($SmartCardRemovalBehavior) {
        SecurityOption 'SecurityRegistry(INF): Interactive_logon_Smart_card_removal_behavior'
        {
            Interactive_logon_Smart_card_removal_behavior = 'Lock workstation'
            Name = 'Interactive_logon_Smart_card_removal_behavior'
        }
    }
    
    if ($DoNotStoreLANManagerHash) {
        SecurityOption 'SecurityRegistry(INF): Network_security_Do_not_store_LAN_Manager_hash_value_on_next_password_change'
        {
            Name = 'Network_security_Do_not_store_LAN_Manager_hash_value_on_next_password_change'
            Network_security_Do_not_store_LAN_Manager_hash_value_on_next_password_change = 'Enabled'
        }
    }
    
    if ($EveryonePermissionsForAnonymousUsers) {
        SecurityOption 'SecurityRegistry(INF): Network_access_Let_Everyone_permissions_apply_to_anonymous_users'
        {
            Network_access_Let_Everyone_permissions_apply_to_anonymous_users = 'Disabled'
            Name = 'Network_access_Let_Everyone_permissions_apply_to_anonymous_users'
        }
    }
    
    if ($LDAPClientSigningRequirements) {
        SecurityOption 'SecurityRegistry(INF): Network_security_LDAP_client_signing_requirements'
        {
            Name = 'Network_security_LDAP_client_signing_requirements'
            Network_security_LDAP_client_signing_requirements = 'Negotiate Signing'
        }
    }
    
    if ($UACAdminElevationPromptBehavior) {
        SecurityOption 'SecurityRegistry(INF): User_Account_Control_Behavior_of_the_elevation_prompt_for_administrators_in_Admin_Approval_Mode'
        {
            Name = 'User_Account_Control_Behavior_of_the_elevation_prompt_for_administrators_in_Admin_Approval_Mode'
            User_Account_Control_Behavior_of_the_elevation_prompt_for_administrators_in_Admin_Approval_Mode = 'Prompt for consent on the secure desktop'
        }
    }
    
    if ($AccountLockoutDuration) {
        AccountPolicy 'SecuritySetting(INF): LockoutDuration'
        {
            Account_lockout_duration = 15
            Name = 'Account_lockout_duration'
        }
    }
    
    if ($AccountLockoutThreshold) {
        AccountPolicy 'SecuritySetting(INF): LockoutBadCount'
        {
            Account_lockout_threshold = 3
            Name = 'Account_lockout_threshold'
        }
    }

    if ($ResetLockoutCount) {
        AccountPolicy 'SecuritySetting(INF): ResetLockoutCount'
        {
            Reset_account_lockout_counter_after = 15
            Name = 'Reset_account_lockout_counter_after'
        }
    }
    
    if ($RenameGuestAccount) {
        SecurityOption 'SecuritySetting(INF): NewGuestName'
        {
            Name = 'Accounts_Rename_guest_account'
            Accounts_Rename_guest_account = 'Visitor'
        }
    }
    
    if ($MinimumPasswordAge) {
        AccountPolicy 'SecuritySetting(INF): MinimumPasswordAge'
        {
            Name = 'Minimum_Password_Age'
            Minimum_Password_Age = 1
        }
    }
    
    if ($PasswordComplexity) {
        AccountPolicy 'SecuritySetting(INF): PasswordComplexity'
        {
            Password_must_meet_complexity_requirements = 'Enabled'
            Name = 'Password_must_meet_complexity_requirements'
        }
    }
    
    if ($PasswordHistorySize) {
        AccountPolicy 'SecuritySetting(INF): PasswordHistorySize'
        {
            Name = 'Enforce_password_history'
            Enforce_password_history = 24
        }
    }
    
    if ($AnonymousNameLookup) {
        SecurityOption 'SecuritySetting(INF): LSAAnonymousNameLookup'
        {
            Network_access_Allow_anonymous_SID_Name_translation = 'Disabled'
            Name = 'Network_access_Allow_anonymous_SID_Name_translation'
        }
    }

    if ($MinimumPasswordLength) {
        AccountPolicy 'SecuritySetting(INF): MinimumPasswordLength'
        {
            Name = 'Minimum_Password_Length'
            Minimum_Password_Length = 14
        }
    }
    
    if ($EnableAdminAccount) {
        SecurityOption 'SecuritySetting(INF): EnableAdminAccount'
        {
            Accounts_Administrator_account_status = 'Disabled'
            Name = 'Accounts_Administrator_account_status'
        }
    }
    
    if ($NewAdministratorName) {
        SecurityOption 'SecuritySetting(INF): NewAdministratorName'
        {
            Accounts_Rename_administrator_account = 'X_Admin'
            Name = 'Accounts_Rename_administrator_account'
        }
    }
    
    if ($EnableGuestAccount) {
        SecurityOption 'SecuritySetting(INF): EnableGuestAccount'
        {
            Name = 'Accounts_Guest_account_status'
            Accounts_Guest_account_status = 'Disabled'
        }
    }
    
    if ($MaximumPasswordAge) {
        AccountPolicy 'SecuritySetting(INF): MaximumPasswordAge'
        {
            Maximum_Password_Age = 60
            Name = 'Maximum_Password_Age'
        }
    }
    
    if ($ClearTextPassword) {
        AccountPolicy 'SecuritySetting(INF): ClearTextPassword'
        {
            Name = 'Store_passwords_using_reversible_encryption'
            Store_passwords_using_reversible_encryption = 'Disabled'
        }
    }

}

