configuration DoD_WinSvr_2012_R2_MS_and_DC_v3r7
{

    param(
        [bool]$EnumerateAdministrators = $true,
        [bool]$NoDriveTypeAutoRun = $true,
        [bool]$NoInternetOpenWith = $true,
        [bool]$PreXPSP2ShellProtocolBehavior = $true,
        [bool]$NoAutorun = $true,
        [bool]$LocalSourcePath = $true,
        [bool]$UseWindowsUpdate = $true,
        [bool]$RepairContentServerSource_Delete = $true,
        [bool]$DisableBkGndGroupPolicy_Delete = $true,
        [bool]$MSAOptional = $true,
        [bool]$DisableAutomaticRestartSignOn = $true,
        [bool]$LocalAccountTokenFilterPolicy = $true,
        [bool]$ProcessCreationIncludeCmdLine_Enabled = $true,
        [bool]$AutoAdminLogon = $true,
        [bool]$ScreenSaverGracePeriod = $true,
        [bool]$Biometrics_Enabled = $true,
        [bool]$BlockUserInputMethodsForSignIn = $true,
        [bool]$MicrosoftEventVwrDisableLinks = $true,
        [bool]$DisableEnclosureDownload = $true,
        [bool]$AllowBasicAuthInClear = $true,
        [bool]$Peernet_Disabled = $true,
        [bool]$DCSettingIndex = $true,
        [bool]$ACSettingIndex = $true,
        [bool]$CEIPEnable = $true,
        [bool]$DisableInventory = $true,
        [bool]$DisablePcaUI = $true,
        [bool]$AllowAllTrustedApps = $true,
        [bool]$DisablePasswordReveal = $true,
        [bool]$PreventDeviceMetadataFromNetwork = $true,
        [bool]$AllowRemoteRPC = $true,
        [bool]$DisableSystemRestore = $true,
        [bool]$DisableSendGenericDriverNotFoundToWER = $true,
        [bool]$DisableSendRequestAdditionalSoftwareToWER = $true,
        [bool]$DontSearchWindowsUpdate = $true,
        [bool]$DontPromptForWindowsUpdate = $true,
        [bool]$SearchOrderConfig = $true,
        [bool]$DriverServerSelection = $true,
        [bool]$MaxSize_Application = $true,
        [bool]$MaxSize_Security = $true,
        [bool]$MaxSize_Setup = $true,
        [bool]$MaxSize_System = $true,
        [bool]$NoHeapTerminationOnCorruption = $true,
        [bool]$NoAutoplayfornonVolume = $true,
        [bool]$NoDataExecutionPrevention = $true,
        [bool]$NoUseStoreOpenWith = $true,
        [bool]$NoBackgroundPolicy = $true,
        [bool]$NoGPOListChanges = $true,
        [bool]$PreventHandwritingErrorReports = $true,
        [bool]$SafeForScripting = $true,
        [bool]$EnableUserControl = $true,
        [bool]$DisableLUAPatching = $true,
        [bool]$AlwaysInstallElevated = $true,
        [bool]$EnableLLTDIO = $true,
        [bool]$AllowLLTDIOOnDomain = $true,
        [bool]$AllowLLTDIOOnPublicNet = $true,
        [bool]$ProhibitLLTDIOOnPrivateNet = $true,
        [bool]$EnableRspndr = $true,
        [bool]$AllowRspndrOnDomain = $true,
        [bool]$AllowRspndrOnPublicNet = $true,
        [bool]$ProhibitRspndrOnPrivateNet = $true,
        [bool]$DisableLocation = $true,
        [bool]$NC_AllowNetBridge_NLA = $true,
        [bool]$NC_StdDomainUserSetLocation = $true,
        [bool]$NoLockScreenSlideshow = $true,
        [bool]$EnableScriptBlockLogging = $true,
        [bool]$EnableScriptBlockInvocationLogging_Delete = $true,
        [bool]$DisableQueryRemoteServer = $true,
        [bool]$EnableQueryRemoteServer = $true,
        [bool]$EnumerateLocalUsers = $true,
        [bool]$DisableLockScreenAppNotifications = $true,
        [bool]$DontDisplayNetworkSelectionUI = $true,
        [bool]$EnableSmartScreen = $true,
        [bool]$PreventHandwritingDataSharing = $true,
        [bool]$Force_Tunneling = $true,
        [bool]$EnableRegistrars = $true,
        [bool]$DisableUPnPRegistrar = $true,
        [bool]$DisableInBand802DOT11Registrar = $true,
        [bool]$DisableFlashConfigRegistrar = $true,
        [bool]$DisableWPDRegistrar = $true,
        [bool]$MaxWCNDeviceNumber_Delete = $true,
        [bool]$HigherPrecedenceRegistrar_Delete = $true,
        [bool]$DisableWcnUi = $true,
        [bool]$ScenarioExecutionEnabled = $true,
        [bool]$AllowBasic = $true,
        [bool]$AllowUnencryptedTraffic = $true,
        [bool]$AllowDigest = $true,
        [bool]$AllowBasic_Service = $true,
        [bool]$AllowUnencryptedTraffic_Service = $true,
        [bool]$DisableRunAs = $true,
        [bool]$DisableHTTPPrinting = $true,
        [bool]$DisableWebPnPDownload = $true,
        [bool]$DoNotInstallCompatibleDriverFromWindowsUpdate = $true,
        [bool]$fAllowToGetHelp = $true,
        [bool]$fAllowFullControl_Delete = $true,
        [bool]$MaxTicketExpiry_Delete = $true,
        [bool]$MaxTicketExpiryUnits_Delete = $true,
        [bool]$fUseMailto_Delete = $true,
        [bool]$fPromptForPassword = $true,
        [bool]$MinEncryptionLevel = $true,
        [bool]$PerSessionTempDir = $true,
        [bool]$DeleteTempDirsOnExit = $true,
        [bool]$fAllowUnsolicited = $true,
        [bool]$fAllowUnsolicitedFullControl_Delete = $true,
        [bool]$fEncryptRPCTraffic = $true,
        [bool]$DisablePasswordSaving = $true,
        [bool]$fDisableCdm = $true,
        [bool]$LoggingEnabled = $true,
        [bool]$fDisableCcm = $true,
        [bool]$fDisableLPT = $true,
        [bool]$fDisablePNPRedir = $true,
        [bool]$fEnableSmartCard = $true,
        [bool]$RedirectOnlyDefaultClientPrinter = $true,
        [bool]$DisableAutoUpdate = $true,
        [bool]$GroupPrivacyAcceptance = $true,
        [bool]$DisableOnline = $true,
        [bool]$UseLogonCredential = $true,
        [bool]$SafeDllSearchMode = $true,
        [bool]$DriverLoadPolicy = $true,
        [bool]$WarningLevel = $true,
        [bool]$NoDefaultExempt = $true,
        [bool]$SMB1 = $true,
        [bool]$Start_MrxSmb10 = $true,
        [bool]$NoNameReleaseOnDemand = $true,
        [bool]$DisableIPSourceRouting = $true,
        [bool]$EnableICMPRedirect = $true,
        [bool]$PerformRouterDiscovery = $true,
        [bool]$KeepAliveTime = $true,
        [bool]$TcpMaxDataRetransmissions = $true,
        [bool]$EnableIPAutoConfigurationLimits = $true,
        [bool]$DisableIPSourceRouting_Tcpip6 = $true,
        [bool]$TcpMaxDataRetransmissions_Tcpip6 = $true,
        [bool]$AuditCredentialValidation_Success = $true,
        [bool]$AuditCredentialValidation_Failure = $true,
        [bool]$AuditComputerAccountManagement_Success = $true,
        [bool]$AuditComputerAccountManagement_Failure = $false,
        [bool]$AuditOtherAccountManagementEvents_Success = $true,
        [bool]$AuditOtherAccountManagementEvents_Failure = $false,
        [bool]$AuditSecurityGroupManagement_Success = $true,
        [bool]$AuditSecurityGroupManagement_Failure = $false,
        [bool]$AuditUserAccountManagement_Success = $true,
        [bool]$AuditUserAccountManagement_Failure = $true,
        [bool]$AuditProcessCreation_Success = $true,
        [bool]$AuditProcessCreation_Failure = $false,
        [bool]$AuditDirectoryServiceAccess_Success = $true,
        [bool]$AuditDirectoryServiceAccess_Failure = $true,
        [bool]$AuditDirectoryServiceChanges_Success = $true,
        [bool]$AuditDirectoryServiceChanges_Failure = $false,
        [bool]$AuditAccountLockout_Failure = $true,
        [bool]$AuditAccountLockout_Success = $false,
        [bool]$AuditLogoff_Success = $true,
        [bool]$AuditLogoff_Failure = $false,
        [bool]$AuditLogon_Success = $true,
        [bool]$AuditLogon_Failure = $true,
        [bool]$AuditSpecialLogon_Success = $true,
        [bool]$AuditSpecialLogon_Failure = $false,
        [bool]$AuditRemovableStorage_Success = $true,
        [bool]$AuditRemovableStorage_Failure = $true,
        [bool]$AuditCentralAccessPolicyStaging_Success = $true,
        [bool]$AuditCentralAccessPolicyStaging_Failure = $true,
        [bool]$AuditPolicyChange_Success = $true,
        [bool]$AuditPolicyChange_Failure = $true,
        [bool]$AuditAuthenticationPolicyChange_Success = $true,
        [bool]$AuditAuthenticationPolicyChange_Failure = $false,
        [bool]$AuditAuthorizationPolicyChange_Success = $true,
        [bool]$AuditAuthorizationPolicyChange_Failure = $false,
        [bool]$AuditSensitivePrivilegeUse_Success = $true,
        [bool]$AuditSensitivePrivilegeUse_Failure = $true,
        [bool]$AuditIPsecDriver_Success = $true,
        [bool]$AuditIPsecDriver_Failure = $true,
        [bool]$AuditOtherSystemEvents_Success = $true,
        [bool]$AuditOtherSystemEvents_Failure = $true,
        [bool]$AuditSecurityStateChange_Success = $true,
        [bool]$AuditSecurityStateChange_Failure = $false,
        [bool]$AuditSecuritySystemExtension_Success = $true,
        [bool]$AuditSecuritySystemExtension_Failure = $false,
        [bool]$AuditSystemIntegrity_Success = $true,
        [bool]$AuditSystemIntegrity_Failure = $true,
        [bool]$EnableComputerAndUserAccountsToBeTrustedForDelegation = $true,
        [bool]$AllowLogOnThroughRemoteDesktopServices = $true,
        [bool]$BackUpFilesAndDirectories = $true,
        [bool]$ImpersonateAClientAfterAuthentication = $true,
        [bool]$PerformVolumeMaintenanceTasks = $true,
        [bool]$AccessThisComputerFromTheNetwork = $true,
        [bool]$LockPagesInMemory = $true,
        [bool]$TakeOwnershipOfFilesOrOtherObjects = $true,
        [bool]$CreatePermanentSharedObjects = $true,
        [bool]$DenyAccessToThisComputerFromTheNetwork = $true,
        [bool]$CreateGlobalObjects = $true,
        [bool]$DenyLogOnAsABatchJob = $true,
        [bool]$RestoreFilesAndDirectories = $true,
        [bool]$AccessCredentialManagerAsATrustedCaller = $true,
        [bool]$AddWorkstationsToDomain = $true,
        [bool]$DenyLogOnAsAService = $true,
        [bool]$IncreaseSchedulingPriority = $true,
        [bool]$ForceShutdownFromARemoteSystem = $true,
        [bool]$GenerateSecurityAudits = $true,
        [bool]$DenyLogOnLocally = $true,
        [bool]$CreateSymbolicLinks = $true,
        [bool]$DebugPrograms = $true,
        [bool]$AllowLogOnLocally = $true,
        [bool]$ManageAuditingAndSecurityLog = $true,
        [bool]$ActAsPartOfTheOperatingSystem = $true,
        [bool]$ProfileSingleProcess = $true,
        [bool]$CreateATokenObject = $true,
        [bool]$LoadAndUnloadDeviceDrivers = $true,
        [bool]$ModifyFirmwareEnvironmentValues = $true,
        [bool]$CreateAPagefile = $true,
        [bool]$DenyLogOnThroughRemoteDesktopServices = $true,
        [bool]$UACAdminApprovalMode = $true,
        [bool]$RestrictAnonymousAccess = $true,
        [bool]$RemotelyAccessibleRegistryPaths = $true,
        [bool]$SharingAndSecurityModel = $true,
        [bool]$RequireStrongSessionKey = $true,
        [bool]$OnlyElevateUIAccessAppsInSecureLocations = $true,
        [bool]$IdleTimeBeforeSuspendingSession = $true,
        [bool]$StrongKeyProtection = $true,
        [bool]$KerberosEncryptionTypes = $true,
        [bool]$DigitallySignCommunicationsIfClientAgrees = $true,
        [bool]$UseFIPSCompliantAlgorithms = $true,
        [bool]$ShutdownWithoutLogon = $true,
        [bool]$AuditBackupAndRestorePrivilege = $true,
        [bool]$DoNotRequireCtrlAltDel = $true,
        [bool]$LANManagerAuthenticationLevel = $true,
        [bool]$DisableMachineAccountPasswordChanges = $true,
        [bool]$VirtualizeFileAndRegistryWriteFailures = $true,
        [bool]$LogonMessageTitle = $true,
        [bool]$DigitallySignSecureChannelData = $true,
        [bool]$AllowUIAccessApplicationsToPromptForElevation = $true,
        [bool]$SmartCardRemovalBehavior = $true,
        [bool]$LimitLocalAccountUseOfBlankPasswords = $true,
        [bool]$ServerSPNTargetNameValidationLevel = $true,
        [bool]$LdapServerSigningRequirements = $true,
        [bool]$AllowedToFormatAndEjectRemovableMedia = $true,
        [bool]$NamedPipesAccessedAnonymously = $true,
        [bool]$SwitchToSecureDesktopForElevation = $true,
        [bool]$MessageTextForUsersLogon = $true,
        [string]$MessageTextWhenLogging,
        [bool]$SharesAccessedAnonymously = $true,
        [bool]$EveryonePermissionsApplyToAnonymousUsers = $true,
        [bool]$DigitallyEncryptSecureChannelData = $true,
        [bool]$ElevationPromptBehaviorForStandardUsers = $true,
        [bool]$DigitallySignCommunicationsAlways_Server = $true,
        [bool]$OptionalSubsystemsEnabled = $true,
        [bool]$DigitallySignCommunicationsAlways_Client = $true,
        [bool]$MinimumSessionSecurityForNTLM = $true,
        [bool]$PromptUserToChangePasswordBeforeExpiration = $true,
        [bool]$RunAllAdministratorsInAdminApprovalMode = $true,
        [bool]$DigitallySignCommunicationsIfServerAgrees = $true,
        [bool]$DetectApplicationInstallationsAndPromptForElevation = $true,
        [bool]$DoNotAllowAnonymousEnumerationOfSAMAccounts = $true,
        [bool]$AllowLocalSystemToUseComputerIdentityForNTLM = $true,
        [bool]$RequireCaseInsensitivityForNonWindowsSubsystems = $true,
        [bool]$AllowLocalSystemNULLSessionFallback = $true,
        [bool]$ForceAuditPolicySubcategorySettings = $true,
        [bool]$OnlyElevateSignedAndValidatedExecutables = $true,
        [bool]$AuditAccessOfGlobalSystemObjects = $true,
        [bool]$SendUnencryptedPasswordToThirdPartySMBServers = $true,
        [bool]$MinimumSessionSecurityForNTLMSPBASED = $true,
        [bool]$NumberOfPreviousLogonsToCache = $true,
        [bool]$DoNotDisplayLastUserName = $true,
        [bool]$MaximumMachineAccountPasswordAge = $true,
        [bool]$DisconnectClientsWhenLogonHoursExpire = $true,
        [bool]$DoNotAllowAnonymousEnumerationOfSAMAccountsAndShares = $true,
        [bool]$RefuseMachineAccountPasswordChanges = $true,
        [bool]$PreventUsersFromInstallingPrinterDrivers = $true,
        [bool]$StrengthenDefaultPermissionsOfInternalSystemObjects = $true,
        [bool]$AllowPKU2UAuthenticationRequestsToUseOnlineIdentities = $true,
        [bool]$MachineInactivityLimit = $true,
        [bool]$DoNotStoreLANManagerHashOnNextPasswordChange = $true,
        [bool]$DigitallyEncryptOrSignSecureChannelDataAlways = $true,
        [bool]$LDAPClientSigningRequirements = $true,
        [bool]$ElevationPromptBehaviorForAdmins = $true,
        [bool]$LockoutDuration = $true,
        [bool]$LockoutBadCount = $true,
        [bool]$ResetLockoutCount = $true,
        [bool]$RenameGuestAccount = $true,
        [bool]$MinimumPasswordAge = $true,
        [bool]$PasswordComplexity = $true,
        [bool]$PasswordHistorySize = $true,
        [bool]$LSAAnonymousNameLookup = $true,
        [bool]$MinimumPasswordLength = $true,
        [bool]$RenameAdministratorAccount = $true,
        [bool]$EnableGuestAccount = $true,
        [bool]$ClearTextPassword = $true,
        [bool]$MaximumPasswordAge = $true,
        [bool]$ForceLogoffWhenHourExpire = $true
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
    
    if ($NoInternetOpenWith) {
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\NoInternetOpenWith'
        {
            Key = '\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
            ValueName = 'NoInternetOpenWith'
            ValueData = 1
        }
    }
    
    if ($PreXPSP2ShellProtocolBehavior) {
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\PreXPSP2ShellProtocolBehavior'
        {
            Key = '\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
            ValueName = 'PreXPSP2ShellProtocolBehavior'
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
    
    if ($LocalSourcePath) {
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\Servicing\LocalSourcePath'
        {
            Key = '\Software\Microsoft\Windows\CurrentVersion\Policies\Servicing'
            ValueType = 'ExpandString'
            TargetType = 'ComputerConfiguration'
            ValueName = 'LocalSourcePath'
            ValueData = $null
        }
    }

    if ($UseWindowsUpdate) {
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\Servicing\UseWindowsUpdate'
        {
            Key = '\Software\Microsoft\Windows\CurrentVersion\Policies\Servicing'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
            ValueName = 'UseWindowsUpdate'
            ValueData = 2
        }
    }
    
    if ($RepairContentServerSource_Delete) {
        RegistryPolicyFile 'DEL_\Software\Microsoft\Windows\CurrentVersion\Policies\Servicing\RepairContentServerSource'
        {
            Key = '\Software\Microsoft\Windows\CurrentVersion\Policies\Servicing'
            ValueType = 'String'
            Ensure = 'Absent'
            TargetType = 'ComputerConfiguration'
            ValueName = 'RepairContentServerSource'
            ValueData = ''
        }
    }
    
    if ($DisableBkGndGroupPolicy_Delete) {
        RegistryPolicyFile 'DEL_\Software\Microsoft\Windows\CurrentVersion\Policies\System\DisableBkGndGroupPolicy'
        {
            Key = '\Software\Microsoft\Windows\CurrentVersion\Policies\System'
            ValueType = 'String'
            Ensure = 'Absent'
            TargetType = 'ComputerConfiguration'
            ValueName = 'DisableBkGndGroupPolicy'
            ValueData = ''
        }
    }
    
    if ($MSAOptional) {
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\System\MSAOptional'
        {
            Key = '\Software\Microsoft\Windows\CurrentVersion\Policies\System'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
            ValueName = 'MSAOptional'
            ValueData = 1
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
    
    if ($AutoAdminLogon) {
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Microsoft\Windows NT\CurrentVersion\Winlogon\AutoAdminLogon'
        {
            Key = '\Software\Microsoft\Windows NT\CurrentVersion\Winlogon'
            ValueType = 'String'
            TargetType = 'ComputerConfiguration'
            ValueName = 'AutoAdminLogon'
            ValueData = '0'
        }
    }
    
    if ($ScreenSaverGracePeriod) {
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Microsoft\Windows NT\CurrentVersion\Winlogon\ScreenSaverGracePeriod'
        {
            Key = '\Software\Microsoft\Windows NT\CurrentVersion\Winlogon'
            ValueType = 'String'
            TargetType = 'ComputerConfiguration'
            ValueName = 'ScreenSaverGracePeriod'
            ValueData = '5'
        }
    }
    
    if ($Biometrics_Enabled) {
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\policies\Microsoft\Biometrics\Enabled'
        {
            Key = '\Software\policies\Microsoft\Biometrics'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
            ValueName = 'Enabled'
            ValueData = 0
        }
    }
    
    if ($BlockUserInputMethodsForSignIn) {
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\policies\Microsoft\Control Panel\International\BlockUserInputMethodsForSignIn'
        {
            Key = '\Software\policies\Microsoft\Control Panel\International'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
            ValueName = 'BlockUserInputMethodsForSignIn'
            ValueData = 1
        }
    }

    if ($MicrosoftEventVwrDisableLinks) {
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\policies\Microsoft\EventViewer\MicrosoftEventVwrDisableLinks'
        {
            Key = '\Software\policies\Microsoft\EventViewer'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
            ValueName = 'MicrosoftEventVwrDisableLinks'
            ValueData = 1
        }
    }
    
    if ($DisableEnclosureDownload) {
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\policies\Microsoft\Internet Explorer\Feeds\DisableEnclosureDownload'
        {
            Key = '\Software\policies\Microsoft\Internet Explorer\Feeds'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
            ValueName = 'DisableEnclosureDownload'
            ValueData = 1
        }
    }
    
    if ($AllowBasicAuthInClear) {
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\policies\Microsoft\Internet Explorer\Feeds\AllowBasicAuthInClear'
        {
            Key = '\Software\policies\Microsoft\Internet Explorer\Feeds'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
            ValueName = 'AllowBasicAuthInClear'
            ValueData = 0
        }
    }
    
    if ($Peernet_Disabled) {
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\policies\Microsoft\Peernet\Disabled'
        {
            Key = '\Software\policies\Microsoft\Peernet'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
            ValueName = 'Disabled'
            ValueData = 1
        }
    }
    
    if ($DCSettingIndex) {
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\policies\Microsoft\Power\PowerSettings\0e796bdb-100d-47d6-a2d5-f7d2daa51f51\DCSettingIndex'
        {
            Key = '\Software\policies\Microsoft\Power\PowerSettings\0e796bdb-100d-47d6-a2d5-f7d2daa51f51'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
            ValueName = 'DCSettingIndex'
            ValueData = 1
        }
    }
    
    if ($ACSettingIndex) {
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\policies\Microsoft\Power\PowerSettings\0e796bdb-100d-47d6-a2d5-f7d2daa51f51\ACSettingIndex'
        {
            Key = '\Software\policies\Microsoft\Power\PowerSettings\0e796bdb-100d-47d6-a2d5-f7d2daa51f51'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
            ValueName = 'ACSettingIndex'
            ValueData = 1
        }
    }

    if ($CEIPEnable) {
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\policies\Microsoft\SQMClient\Windows\CEIPEnable'
        {
            Key = '\Software\policies\Microsoft\SQMClient\Windows'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
            ValueName = 'CEIPEnable'
            ValueData = 0
        }
    }
    
    if ($DisableInventory) {
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\policies\Microsoft\Windows\AppCompat\DisableInventory'
        {
            Key = '\Software\policies\Microsoft\Windows\AppCompat'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
            ValueName = 'DisableInventory'
            ValueData = 1
        }
    }
    
    if ($DisablePcaUI) {
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\policies\Microsoft\Windows\AppCompat\DisablePcaUI'
        {
            Key = '\Software\policies\Microsoft\Windows\AppCompat'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
            ValueName = 'DisablePcaUI'
            ValueData = 0
        }
    }
    
    if ($AllowAllTrustedApps) {
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\policies\Microsoft\Windows\Appx\AllowAllTrustedApps'
        {
            Key = '\Software\policies\Microsoft\Windows\Appx'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
            ValueName = 'AllowAllTrustedApps'
            ValueData = 1
        }
    }
    
    if ($DisablePasswordReveal) {
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\policies\Microsoft\Windows\CredUI\DisablePasswordReveal'
        {
            Key = '\Software\policies\Microsoft\Windows\CredUI'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
            ValueName = 'DisablePasswordReveal'
            ValueData = 1
        }
    }

    if ($PreventDeviceMetadataFromNetwork) {
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\policies\Microsoft\Windows\Device Metadata\PreventDeviceMetadataFromNetwork'
        {
            Key = '\Software\policies\Microsoft\Windows\Device Metadata'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
            ValueName = 'PreventDeviceMetadataFromNetwork'
            ValueData = 1
        }
    }
    
    if ($AllowRemoteRPC) {
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\policies\Microsoft\Windows\DeviceInstall\Settings\AllowRemoteRPC'
        {
            Key = '\Software\policies\Microsoft\Windows\DeviceInstall\Settings'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
            ValueName = 'AllowRemoteRPC'
            ValueData = 0
        }
    }
    
    if ($DisableSystemRestore) {
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\policies\Microsoft\Windows\DeviceInstall\Settings\DisableSystemRestore'
        {
            Key = '\Software\policies\Microsoft\Windows\DeviceInstall\Settings'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
            ValueName = 'DisableSystemRestore'
            ValueData = 0
        }
    }
    
    if ($DisableSendGenericDriverNotFoundToWER) {
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\policies\Microsoft\Windows\DeviceInstall\Settings\DisableSendGenericDriverNotFoundToWER'
        {
            Key = '\Software\policies\Microsoft\Windows\DeviceInstall\Settings'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
            ValueName = 'DisableSendGenericDriverNotFoundToWER'
            ValueData = 1
        }
    }
    
    if ($DisableSendRequestAdditionalSoftwareToWER) {
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\policies\Microsoft\Windows\DeviceInstall\Settings\DisableSendRequestAdditionalSoftwareToWER'
        {
            Key = '\Software\policies\Microsoft\Windows\DeviceInstall\Settings'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
            ValueName = 'DisableSendRequestAdditionalSoftwareToWER'
            ValueData = 1
        }
    }
    
    if ($DontSearchWindowsUpdate) {
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\policies\Microsoft\Windows\DriverSearching\DontSearchWindowsUpdate'
        {
            Key = '\Software\policies\Microsoft\Windows\DriverSearching'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
            ValueName = 'DontSearchWindowsUpdate'
            ValueData = 1
        }
    }

    if ($DontPromptForWindowsUpdate) {
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\policies\Microsoft\Windows\DriverSearching\DontPromptForWindowsUpdate'
        {
            Key = '\Software\policies\Microsoft\Windows\DriverSearching'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
            ValueName = 'DontPromptForWindowsUpdate'
            ValueData = 1
        }
    }
    
    if ($SearchOrderConfig) {
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\policies\Microsoft\Windows\DriverSearching\SearchOrderConfig'
        {
            Key = '\Software\policies\Microsoft\Windows\DriverSearching'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
            ValueName = 'SearchOrderConfig'
            ValueData = 0
        }
    }
    
    if ($DriverServerSelection) {
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\policies\Microsoft\Windows\DriverSearching\DriverServerSelection'
        {
            Key = '\Software\policies\Microsoft\Windows\DriverSearching'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
            ValueName = 'DriverServerSelection'
            ValueData = 1
        }
    }
    
    if ($MaxSize_Application) {
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\policies\Microsoft\Windows\EventLog\Application\MaxSize'
        {
            Key = '\Software\policies\Microsoft\Windows\EventLog\Application'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
            ValueName = 'MaxSize'
            ValueData = 32768
        }
    }
    
    if ($MaxSize_Security) {
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\policies\Microsoft\Windows\EventLog\Security\MaxSize'
        {
            Key = '\Software\policies\Microsoft\Windows\EventLog\Security'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
            ValueName = 'MaxSize'
            ValueData = 196608
        }
    }
    
    if ($MaxSize_Setup) {
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\policies\Microsoft\Windows\EventLog\Setup\MaxSize'
        {
            Key = '\Software\policies\Microsoft\Windows\EventLog\Setup'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
            ValueName = 'MaxSize'
            ValueData = 32768
        }
    }

    if ($MaxSize_System) {
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\policies\Microsoft\Windows\EventLog\System\MaxSize'
        {
            Key = '\Software\policies\Microsoft\Windows\EventLog\System'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
            ValueName = 'MaxSize'
            ValueData = 32768
        }
    }
    
    if ($NoHeapTerminationOnCorruption) {
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\policies\Microsoft\Windows\Explorer\NoHeapTerminationOnCorruption'
        {
            Key = '\Software\policies\Microsoft\Windows\Explorer'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
            ValueName = 'NoHeapTerminationOnCorruption'
            ValueData = 0
        }
    }
    
    if ($NoAutoplayfornonVolume) {
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\policies\Microsoft\Windows\Explorer\NoAutoplayfornonVolume'
        {
            Key = '\Software\policies\Microsoft\Windows\Explorer'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
            ValueName = 'NoAutoplayfornonVolume'
            ValueData = 1
        }
    }
    
    if ($NoDataExecutionPrevention) {
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\policies\Microsoft\Windows\Explorer\NoDataExecutionPrevention'
        {
            Key = '\Software\policies\Microsoft\Windows\Explorer'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
            ValueName = 'NoDataExecutionPrevention'
            ValueData = 0
        }
    }
    
    if ($NoUseStoreOpenWith) {
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\policies\Microsoft\Windows\Explorer\NoUseStoreOpenWith'
        {
            Key = '\Software\policies\Microsoft\Windows\Explorer'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
            ValueName = 'NoUseStoreOpenWith'
            ValueData = 1
        }
    }
    if ($NoBackgroundPolicy) {
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\policies\Microsoft\Windows\Group Policy\{35378EAC-683F-11D2-A89A-00C04FBBCFA2}\NoBackgroundPolicy'
        {
            Key = '\Software\policies\Microsoft\Windows\Group Policy\{35378EAC-683F-11D2-A89A-00C04FBBCFA2}'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
            ValueName = 'NoBackgroundPolicy'
            ValueData = 0
        }
    }
    
    if ($NoGPOListChanges) {
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\policies\Microsoft\Windows\Group Policy\{35378EAC-683F-11D2-A89A-00C04FBBCFA2}\NoGPOListChanges'
        {
            Key = '\Software\policies\Microsoft\Windows\Group Policy\{35378EAC-683F-11D2-A89A-00C04FBBCFA2}'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
            ValueName = 'NoGPOListChanges'
            ValueData = 0
        }
    }
    
    if ($PreventHandwritingErrorReports) {
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\policies\Microsoft\Windows\HandwritingErrorReports\PreventHandwritingErrorReports'
        {
            Key = '\Software\policies\Microsoft\Windows\HandwritingErrorReports'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
            ValueName = 'PreventHandwritingErrorReports'
            ValueData = 1
        }
    }
    
    if ($SafeForScripting) {
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\policies\Microsoft\Windows\Installer\SafeForScripting'
        {
            Key = '\Software\policies\Microsoft\Windows\Installer'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
            ValueName = 'SafeForScripting'
            ValueData = 0
        }
    }
    
    if ($EnableUserControl) {
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\policies\Microsoft\Windows\Installer\EnableUserControl'
        {
            Key = '\Software\policies\Microsoft\Windows\Installer'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
            ValueName = 'EnableUserControl'
            ValueData = 0
        }
    }

    if ($DisableLUAPatching) {
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\policies\Microsoft\Windows\Installer\DisableLUAPatching'
        {
            Key = '\Software\policies\Microsoft\Windows\Installer'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
            ValueName = 'DisableLUAPatching'
            ValueData = 1
        }
    }
    
    if ($AlwaysInstallElevated) {
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\policies\Microsoft\Windows\Installer\AlwaysInstallElevated'
        {
            Key = '\Software\policies\Microsoft\Windows\Installer'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
            ValueName = 'AlwaysInstallElevated'
            ValueData = 0
        }
    }
    
    if ($EnableLLTDIO) {
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\policies\Microsoft\Windows\LLTD\EnableLLTDIO'
        {
            Key = '\Software\policies\Microsoft\Windows\LLTD'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
            ValueName = 'EnableLLTDIO'
            ValueData = 0
        }
    }
    
    if ($AllowLLTDIOOnDomain) {
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\policies\Microsoft\Windows\LLTD\AllowLLTDIOOnDomain'
        {
            Key = '\Software\policies\Microsoft\Windows\LLTD'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
            ValueName = 'AllowLLTDIOOnDomain'
            ValueData = 0
        }
    }
    
    if ($AllowLLTDIOOnPublicNet) {
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\policies\Microsoft\Windows\LLTD\AllowLLTDIOOnPublicNet'
        {
            Key = '\Software\policies\Microsoft\Windows\LLTD'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
            ValueName = 'AllowLLTDIOOnPublicNet'
            ValueData = 0
        }
    }

    if ($ProhibitLLTDIOOnPrivateNet) {
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\policies\Microsoft\Windows\LLTD\ProhibitLLTDIOOnPrivateNet'
        {
            Key = '\Software\policies\Microsoft\Windows\LLTD'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
            ValueName = 'ProhibitLLTDIOOnPrivateNet'
            ValueData = 0
        }
    }
    
    if ($EnableRspndr) {
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\policies\Microsoft\Windows\LLTD\EnableRspndr'
        {
            Key = '\Software\policies\Microsoft\Windows\LLTD'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
            ValueName = 'EnableRspndr'
            ValueData = 0
        }
    }
    
    if ($AllowRspndrOnDomain) {
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\policies\Microsoft\Windows\LLTD\AllowRspndrOnDomain'
        {
            Key = '\Software\policies\Microsoft\Windows\LLTD'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
            ValueName = 'AllowRspndrOnDomain'
            ValueData = 0
        }
    }
    
    if ($AllowRspndrOnPublicNet) {
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\policies\Microsoft\Windows\LLTD\AllowRspndrOnPublicNet'
        {
            Key = '\Software\policies\Microsoft\Windows\LLTD'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
            ValueName = 'AllowRspndrOnPublicNet'
            ValueData = 0
        }
    }

    if ($ProhibitRspndrOnPrivateNet) {
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\policies\Microsoft\Windows\LLTD\ProhibitRspndrOnPrivateNet'
        {
            Key = '\Software\policies\Microsoft\Windows\LLTD'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
            ValueName = 'ProhibitRspndrOnPrivateNet'
            ValueData = 0
        }
    }
    
    if ($DisableLocation) {
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\policies\Microsoft\Windows\LocationAndSensors\DisableLocation'
        {
            Key = '\Software\policies\Microsoft\Windows\LocationAndSensors'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
            ValueName = 'DisableLocation'
            ValueData = 1
        }
    }
    
    if ($NC_AllowNetBridge_NLA) {
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\policies\Microsoft\Windows\Network Connections\NC_AllowNetBridge_NLA'
        {
            Key = '\Software\policies\Microsoft\Windows\Network Connections'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
            ValueName = 'NC_AllowNetBridge_NLA'
            ValueData = 0
        }
    }
    
    if ($NC_StdDomainUserSetLocation) {
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\policies\Microsoft\Windows\Network Connections\NC_StdDomainUserSetLocation'
        {
            Key = '\Software\policies\Microsoft\Windows\Network Connections'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
            ValueName = 'NC_StdDomainUserSetLocation'
            ValueData = 1
        }
    }

    if ($NoLockScreenSlideshow) {
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\policies\Microsoft\Windows\Personalization\NoLockScreenSlideshow'
        {
            Key = '\Software\policies\Microsoft\Windows\Personalization'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
            ValueName = 'NoLockScreenSlideshow'
            ValueData = 1
        }
    }
    
    if ($EnableScriptBlockLogging) {
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\policies\Microsoft\Windows\PowerShell\ScriptBlockLogging\EnableScriptBlockLogging'
        {
            Key = '\Software\policies\Microsoft\Windows\PowerShell\ScriptBlockLogging'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
            ValueName = 'EnableScriptBlockLogging'
            ValueData = 1
        }
    }
    
    if ($EnableScriptBlockInvocationLogging_Delete) {
        RegistryPolicyFile 'DEL_\Software\policies\Microsoft\Windows\PowerShell\ScriptBlockLogging\EnableScriptBlockInvocationLogging'
        {
            Key = '\Software\policies\Microsoft\Windows\PowerShell\ScriptBlockLogging'
            ValueType = 'String'
            Ensure = 'Absent'
            TargetType = 'ComputerConfiguration'
            ValueName = 'EnableScriptBlockInvocationLogging'
            ValueData = ''
        }
    }
    
    if ($DisableQueryRemoteServer) {
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\policies\Microsoft\Windows\ScriptedDiagnosticsProvider\Policy\DisableQueryRemoteServer'
        {
            Key = '\Software\policies\Microsoft\Windows\ScriptedDiagnosticsProvider\Policy'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
            ValueName = 'DisableQueryRemoteServer'
            ValueData = 0
        }
    }

    if ($EnableQueryRemoteServer) {
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\policies\Microsoft\Windows\ScriptedDiagnosticsProvider\Policy\EnableQueryRemoteServer'
        {
            Key = '\Software\policies\Microsoft\Windows\ScriptedDiagnosticsProvider\Policy'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
            ValueName = 'EnableQueryRemoteServer'
            ValueData = 0
        }
    }
    
    if ($EnumerateLocalUsers) {
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\policies\Microsoft\Windows\System\EnumerateLocalUsers'
        {
            Key = '\Software\policies\Microsoft\Windows\System'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
            ValueName = 'EnumerateLocalUsers'
            ValueData = 0
        }
    }
    
    if ($DisableLockScreenAppNotifications) {
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\policies\Microsoft\Windows\System\DisableLockScreenAppNotifications'
        {
            Key = '\Software\policies\Microsoft\Windows\System'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
            ValueName = 'DisableLockScreenAppNotifications'
            ValueData = 1
        }
    }
    
    if ($DontDisplayNetworkSelectionUI) {
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\policies\Microsoft\Windows\System\DontDisplayNetworkSelectionUI'
        {
            Key = '\Software\policies\Microsoft\Windows\System'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
            ValueName = 'DontDisplayNetworkSelectionUI'
            ValueData = 1
        }
    }
    
    if ($EnableSmartScreen) {
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\policies\Microsoft\Windows\System\EnableSmartScreen'
        {
            Key = '\Software\policies\Microsoft\Windows\System'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
            ValueName = 'EnableSmartScreen'
            ValueData = 2
        }
    }
    
    if ($PreventHandwritingDataSharing) {
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\policies\Microsoft\Windows\TabletPC\PreventHandwritingDataSharing'
        {
            Key = '\Software\policies\Microsoft\Windows\TabletPC'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
            ValueName = 'PreventHandwritingDataSharing'
            ValueData = 1
        }
    }

    if ($Force_Tunneling) {
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\policies\Microsoft\Windows\TCPIP\v6Transition\Force_Tunneling'
        {
            Key = '\Software\policies\Microsoft\Windows\TCPIP\v6Transition'
            ValueType = 'String'
            TargetType = 'ComputerConfiguration'
            ValueName = 'Force_Tunneling'
            ValueData = 'Enabled'
        }
    }
    
    if ($EnableRegistrars) {
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\policies\Microsoft\Windows\WCN\Registrars\EnableRegistrars'
        {
            Key = '\Software\policies\Microsoft\Windows\WCN\Registrars'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
            ValueName = 'EnableRegistrars'
            ValueData = 0
        }
    }
    
    if ($DisableUPnPRegistrar) {
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\policies\Microsoft\Windows\WCN\Registrars\DisableUPnPRegistrar'
        {
            Key = '\Software\policies\Microsoft\Windows\WCN\Registrars'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
            ValueName = 'DisableUPnPRegistrar'
            ValueData = 0
        }
    }
    
    if ($DisableInBand802DOT11Registrar) {
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\policies\Microsoft\Windows\WCN\Registrars\DisableInBand802DOT11Registrar'
        {
            Key = '\Software\policies\Microsoft\Windows\WCN\Registrars'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
            ValueName = 'DisableInBand802DOT11Registrar'
            ValueData = 0
        }
    }
    
    if ($DisableFlashConfigRegistrar) {
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\policies\Microsoft\Windows\WCN\Registrars\DisableFlashConfigRegistrar'
        {
            Key = '\Software\policies\Microsoft\Windows\WCN\Registrars'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
            ValueName = 'DisableFlashConfigRegistrar'
            ValueData = 0
        }
    }
    
    if ($DisableWPDRegistrar) {
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\policies\Microsoft\Windows\WCN\Registrars\DisableWPDRegistrar'
        {
            Key = '\Software\policies\Microsoft\Windows\WCN\Registrars'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
            ValueName = 'DisableWPDRegistrar'
            ValueData = 0
        }
    }

    if ($MaxWCNDeviceNumber_Delete) {
        RegistryPolicyFile 'DEL_\Software\policies\Microsoft\Windows\WCN\Registrars\MaxWCNDeviceNumber'
        {
            Key = '\Software\policies\Microsoft\Windows\WCN\Registrars'
            ValueType = 'String'
            Ensure = 'Absent'
            TargetType = 'ComputerConfiguration'
            ValueName = 'MaxWCNDeviceNumber'
            ValueData = ''
        }
    }
    
    if ($HigherPrecedenceRegistrar_Delete) {
        RegistryPolicyFile 'DEL_\Software\policies\Microsoft\Windows\WCN\Registrars\HigherPrecedenceRegistrar'
        {
            Key = '\Software\policies\Microsoft\Windows\WCN\Registrars'
            ValueType = 'String'
            Ensure = 'Absent'
            TargetType = 'ComputerConfiguration'
            ValueName = 'HigherPrecedenceRegistrar'
            ValueData = ''
        }
    }
    
    if ($DisableWcnUi) {
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\policies\Microsoft\Windows\WCN\UI\DisableWcnUi'
        {
            Key = '\Software\policies\Microsoft\Windows\WCN\UI'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
            ValueName = 'DisableWcnUi'
            ValueData = 1
        }
    }
    
    if ($ScenarioExecutionEnabled) {
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\policies\Microsoft\Windows\WDI\{9c5a40da-b965-4fc3-8781-88dd50a6299d}\ScenarioExecutionEnabled'
        {
            Key = '\Software\policies\Microsoft\Windows\WDI\{9c5a40da-b965-4fc3-8781-88dd50a6299d}'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
            ValueName = 'ScenarioExecutionEnabled'
            ValueData = 0
        }
    }
    
    if ($AllowBasic) {
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\policies\Microsoft\Windows\WinRM\Client\AllowBasic'
        {
            Key = '\Software\policies\Microsoft\Windows\WinRM\Client'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
            ValueName = 'AllowBasic'
            ValueData = 0
        }
    }
    
    if ($AllowUnencryptedTraffic) {
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\policies\Microsoft\Windows\WinRM\Client\AllowUnencryptedTraffic'
        {
            Key = '\Software\policies\Microsoft\Windows\WinRM\Client'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
            ValueName = 'AllowUnencryptedTraffic'
            ValueData = 0
        }
    }

    if ($AllowDigest) {
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\policies\Microsoft\Windows\WinRM\Client\AllowDigest'
        {
            Key = '\Software\policies\Microsoft\Windows\WinRM\Client'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
            ValueName = 'AllowDigest'
            ValueData = 0
        }
    }
    
    if ($AllowBasic_Service) {
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\policies\Microsoft\Windows\WinRM\Service\AllowBasic'
        {
            Key = '\Software\policies\Microsoft\Windows\WinRM\Service'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
            ValueName = 'AllowBasic'
            ValueData = 0
        }
    }
    
    if ($AllowUnencryptedTraffic_Service) {
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\policies\Microsoft\Windows\WinRM\Service\AllowUnencryptedTraffic'
        {
            Key = '\Software\policies\Microsoft\Windows\WinRM\Service'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
            ValueName = 'AllowUnencryptedTraffic'
            ValueData = 0
        }
    }
    
    if ($DisableRunAs) {
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\policies\Microsoft\Windows\WinRM\Service\DisableRunAs'
        {
            Key = '\Software\policies\Microsoft\Windows\WinRM\Service'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
            ValueName = 'DisableRunAs'
            ValueData = 1
        }
    }
    
    if ($DisableHTTPPrinting) {
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\policies\Microsoft\Windows NT\Printers\DisableHTTPPrinting'
        {
            Key = '\Software\policies\Microsoft\Windows NT\Printers'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
            ValueName = 'DisableHTTPPrinting'
            ValueData = 1
        }
    }

    if ($DisableWebPnPDownload) {
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\policies\Microsoft\Windows NT\Printers\DisableWebPnPDownload'
        {
            Key = '\Software\policies\Microsoft\Windows NT\Printers'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
            ValueName = 'DisableWebPnPDownload'
            ValueData = 1
        }
    }
    
    if ($DoNotInstallCompatibleDriverFromWindowsUpdate) {
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\policies\Microsoft\Windows NT\Printers\DoNotInstallCompatibleDriverFromWindowsUpdate'
        {
            Key = '\Software\policies\Microsoft\Windows NT\Printers'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
            ValueName = 'DoNotInstallCompatibleDriverFromWindowsUpdate'
            ValueData = 1
        }
    }
    
    if ($fAllowToGetHelp) {
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\policies\Microsoft\Windows NT\Terminal Services\fAllowToGetHelp'
        {
            Key = '\Software\policies\Microsoft\Windows NT\Terminal Services'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
            ValueName = 'fAllowToGetHelp'
            ValueData = 0
        }
    }
    
    if ($fAllowFullControl_Delete) {
        RegistryPolicyFile 'DEL_\Software\policies\Microsoft\Windows NT\Terminal Services\fAllowFullControl'
        {
            Key = '\Software\policies\Microsoft\Windows NT\Terminal Services'
            ValueType = 'String'
            Ensure = 'Absent'
            TargetType = 'ComputerConfiguration'
            ValueName = 'fAllowFullControl'
            ValueData = ''
        }
    }
    
    if ($MaxTicketExpiry_Delete) {
        RegistryPolicyFile 'DEL_\Software\policies\Microsoft\Windows NT\Terminal Services\MaxTicketExpiry'
        {
            Key = '\Software\policies\Microsoft\Windows NT\Terminal Services'
            ValueType = 'String'
            Ensure = 'Absent'
            TargetType = 'ComputerConfiguration'
            ValueName = 'MaxTicketExpiry'
            ValueData = ''
        }
    }

    if ($MaxTicketExpiryUnits_Delete) {
        RegistryPolicyFile 'DEL_\Software\policies\Microsoft\Windows NT\Terminal Services\MaxTicketExpiryUnits'
        {
            Key = '\Software\policies\Microsoft\Windows NT\Terminal Services'
            ValueType = 'String'
            Ensure = 'Absent'
            TargetType = 'ComputerConfiguration'
            ValueName = 'MaxTicketExpiryUnits'
            ValueData = ''
        }
    }
    
    if ($fUseMailto_Delete) {
        RegistryPolicyFile 'DEL_\Software\policies\Microsoft\Windows NT\Terminal Services\fUseMailto'
        {
            Key = '\Software\policies\Microsoft\Windows NT\Terminal Services'
            ValueType = 'String'
            Ensure = 'Absent'
            TargetType = 'ComputerConfiguration'
            ValueName = 'fUseMailto'
            ValueData = ''
        }
    }
    
    if ($fPromptForPassword) {
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\policies\Microsoft\Windows NT\Terminal Services\fPromptForPassword'
        {
            Key = '\Software\policies\Microsoft\Windows NT\Terminal Services'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
            ValueName = 'fPromptForPassword'
            ValueData = 1
        }
    }
    
    if ($MinEncryptionLevel) {
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\policies\Microsoft\Windows NT\Terminal Services\MinEncryptionLevel'
        {
            Key = '\Software\policies\Microsoft\Windows NT\Terminal Services'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
            ValueName = 'MinEncryptionLevel'
            ValueData = 3
        }
    }

    if ($PerSessionTempDir) {
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\policies\Microsoft\Windows NT\Terminal Services\PerSessionTempDir'
        {
            Key = '\Software\policies\Microsoft\Windows NT\Terminal Services'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
            ValueName = 'PerSessionTempDir'
            ValueData = 1
        }
    }
    
    if ($DeleteTempDirsOnExit) {
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\policies\Microsoft\Windows NT\Terminal Services\DeleteTempDirsOnExit'
        {
            Key = '\Software\policies\Microsoft\Windows NT\Terminal Services'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
            ValueName = 'DeleteTempDirsOnExit'
            ValueData = 1
        }
    }
    
    if ($fAllowUnsolicited) {
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\policies\Microsoft\Windows NT\Terminal Services\fAllowUnsolicited'
        {
            Key = '\Software\policies\Microsoft\Windows NT\Terminal Services'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
            ValueName = 'fAllowUnsolicited'
            ValueData = 0
        }
    }
    
    if ($fAllowUnsolicitedFullControl_Delete) {
        RegistryPolicyFile 'DEL_\Software\policies\Microsoft\Windows NT\Terminal Services\fAllowUnsolicitedFullControl'
        {
            Key = '\Software\policies\Microsoft\Windows NT\Terminal Services'
            ValueType = 'String'
            Ensure = 'Absent'
            TargetType = 'ComputerConfiguration'
            ValueName = 'fAllowUnsolicitedFullControl'
            ValueData = ''
        }
    }
    
    if ($fEncryptRPCTraffic) {
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\policies\Microsoft\Windows NT\Terminal Services\fEncryptRPCTraffic'
        {
            Key = '\Software\policies\Microsoft\Windows NT\Terminal Services'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
            ValueName = 'fEncryptRPCTraffic'
            ValueData = 1
        }
    }

    if ($DisablePasswordSaving) {
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\policies\Microsoft\Windows NT\Terminal Services\DisablePasswordSaving'
        {
            Key = '\Software\policies\Microsoft\Windows NT\Terminal Services'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
            ValueName = 'DisablePasswordSaving'
            ValueData = 1
        }
    }
    
    if ($fDisableCdm) {
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\policies\Microsoft\Windows NT\Terminal Services\fDisableCdm'
        {
            Key = '\Software\policies\Microsoft\Windows NT\Terminal Services'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
            ValueName = 'fDisableCdm'
            ValueData = 1
        }
    }
    
    if ($LoggingEnabled) {
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\policies\Microsoft\Windows NT\Terminal Services\LoggingEnabled'
        {
            Key = '\Software\policies\Microsoft\Windows NT\Terminal Services'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
            ValueName = 'LoggingEnabled'
            ValueData = 1
        }
    }
    
    if ($fDisableCcm) {
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\policies\Microsoft\Windows NT\Terminal Services\fDisableCcm'
        {
            Key = '\Software\policies\Microsoft\Windows NT\Terminal Services'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
            ValueName = 'fDisableCcm'
            ValueData = 1
        }
    }
    
    if ($fDisableLPT) {
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\policies\Microsoft\Windows NT\Terminal Services\fDisableLPT'
        {
            Key = '\Software\policies\Microsoft\Windows NT\Terminal Services'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
            ValueName = 'fDisableLPT'
            ValueData = 1
        }
    }
    
    if ($fDisablePNPRedir) {
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\policies\Microsoft\Windows NT\Terminal Services\fDisablePNPRedir'
        {
            Key = '\Software\policies\Microsoft\Windows NT\Terminal Services'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
            ValueName = 'fDisablePNPRedir'
            ValueData = 1
        }
    }

    if ($fEnableSmartCard) {
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\policies\Microsoft\Windows NT\Terminal Services\fEnableSmartCard'
        {
            Key = '\Software\policies\Microsoft\Windows NT\Terminal Services'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
            ValueName = 'fEnableSmartCard'
            ValueData = 1
        }
    }
    
    if ($RedirectOnlyDefaultClientPrinter) {
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\policies\Microsoft\Windows NT\Terminal Services\RedirectOnlyDefaultClientPrinter'
        {
            Key = '\Software\policies\Microsoft\Windows NT\Terminal Services'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
            ValueName = 'RedirectOnlyDefaultClientPrinter'
            ValueData = 1
        }
    }
    
    if ($DisableAutoUpdate) {
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\policies\Microsoft\WindowsMediaPlayer\DisableAutoUpdate'
        {
            Key = '\Software\policies\Microsoft\WindowsMediaPlayer'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
            ValueName = 'DisableAutoUpdate'
            ValueData = 1
        }
    }
    
    if ($GroupPrivacyAcceptance) {
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\policies\Microsoft\WindowsMediaPlayer\GroupPrivacyAcceptance'
        {
            Key = '\Software\policies\Microsoft\WindowsMediaPlayer'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
            ValueName = 'GroupPrivacyAcceptance'
            ValueData = 1
        }
    }
    
    if ($DisableOnline) {
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\policies\Microsoft\WMDRM\DisableOnline'
        {
            Key = '\Software\policies\Microsoft\WMDRM'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
            ValueName = 'DisableOnline'
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
    
    if ($SafeDllSearchMode) {
        RegistryPolicyFile 'Registry(POL): HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\SafeDllSearchMode'
        {
            Key = '\SYSTEM\CurrentControlSet\Control\Session Manager'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
            ValueName = 'SafeDllSearchMode'
            ValueData = 1
        }
    }
    
    if ($DriverLoadPolicy) {
        RegistryPolicyFile 'Registry(POL): HKLM:\SYSTEM\CurrentControlSet\Policies\EarlyLaunch\DriverLoadPolicy'
        {
            Key = '\SYSTEM\CurrentControlSet\Policies\EarlyLaunch'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
            ValueName = 'DriverLoadPolicy'
            ValueData = 1
        }
    }
    
    if ($WarningLevel) {
        RegistryPolicyFile 'Registry(POL): HKLM:\SYSTEM\CurrentControlSet\Services\Eventlog\Security\WarningLevel'
        {
            Key = '\SYSTEM\CurrentControlSet\Services\Eventlog\Security'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
            ValueName = 'WarningLevel'
            ValueData = 90
        }
    }
    
    if ($NoDefaultExempt) {
        RegistryPolicyFile 'Registry(POL): HKLM:\SYSTEM\CurrentControlSet\Services\IPSEC\NoDefaultExempt'
        {
            Key = '\SYSTEM\CurrentControlSet\Services\IPSEC'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
            ValueName = 'NoDefaultExempt'
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

    if ($Start_MrxSmb10) {
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
    
    if ($PerformRouterDiscovery) {
        RegistryPolicyFile 'Registry(POL): HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\PerformRouterDiscovery'
        {
            Key = '\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
            ValueName = 'PerformRouterDiscovery'
            ValueData = 0
        }
    }
    
    if ($KeepAliveTime) {
        RegistryPolicyFile 'Registry(POL): HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\KeepAliveTime'
        {
            Key = '\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
            ValueName = 'KeepAliveTime'
            ValueData = 300000
        }
    }

    if ($TcpMaxDataRetransmissions) {
        RegistryPolicyFile 'Registry(POL): HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\TcpMaxDataRetransmissions'
        {
            Key = '\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
            ValueName = 'TcpMaxDataRetransmissions'
            ValueData = 3
        }
    }
    
    if ($EnableIPAutoConfigurationLimits) {
        RegistryPolicyFile 'Registry(POL): HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\EnableIPAutoConfigurationLimits'
        {
            Key = '\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
            ValueName = 'EnableIPAutoConfigurationLimits'
            ValueData = 1
        }
    }
    
    if ($DisableIPSourceRouting_Tcpip6) {
        RegistryPolicyFile 'Registry(POL): HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip6\Parameters\DisableIPSourceRouting'
        {
            Key = '\SYSTEM\CurrentControlSet\Services\Tcpip6\Parameters'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
            ValueName = 'DisableIPSourceRouting'
            ValueData = 2
        }
    }
    
    if ($TcpMaxDataRetransmissions_Tcpip6) {
        RegistryPolicyFile 'Registry(POL): HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip6\Parameters\TcpMaxDataRetransmissions'
        {
            Key = '\SYSTEM\CurrentControlSet\Services\Tcpip6\Parameters'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
            ValueName = 'TcpMaxDataRetransmissions'
            ValueData = 3
        }
    }

    if ($AuditCredentialValidation_Success) {
        AuditPolicySubcategory 'Audit Credential Validation (Success) - Inclusion'
        {
            Ensure = 'Present'
            Name = 'Credential Validation'
            AuditFlag = 'Success'
        }
    }
    
    if ($AuditCredentialValidation_Failure) {
        AuditPolicySubcategory 'Audit Credential Validation (Failure) - Inclusion'
        {
            Ensure = 'Present'
            Name = 'Credential Validation'
            AuditFlag = 'Failure'
        }
    }
    
    if ($AuditComputerAccountManagement_Success) {
        AuditPolicySubcategory 'Audit Computer Account Management (Success) - Inclusion'
        {
            Ensure = 'Present'
            Name = 'Computer Account Management'
            AuditFlag = 'Success'
        }
    }
    
    if ( $AuditComputerAccountManagement_Failure) {
        AuditPolicySubcategory 'Audit Computer Account Management (Failure) - Inclusion'
        {
            Ensure = 'Absent'
            Name = 'Computer Account Management'
            AuditFlag = 'Failure'
        }
    }
    
    if ($AuditOtherAccountManagementEvents_Success) {
        AuditPolicySubcategory 'Audit Other Account Management Events (Success) - Inclusion'
        {
            Ensure = 'Present'
            Name = 'Other Account Management Events'
            AuditFlag = 'Success'
        }
    }
    
    if ( $AuditOtherAccountManagementEvents_Failure) {
        AuditPolicySubcategory 'Audit Other Account Management Events (Failure) - Inclusion'
        {
            Ensure = 'Absent'
            Name = 'Other Account Management Events'
            AuditFlag = 'Failure'
        }
    }
    
    if ($AuditSecurityGroupManagement_Success) {
        AuditPolicySubcategory 'Audit Security Group Management (Success) - Inclusion'
        {
            Ensure = 'Present'
            Name = 'Security Group Management'
            AuditFlag = 'Success'
        }
    }

    if ( $AuditSecurityGroupManagement_Failure) {
        AuditPolicySubcategory 'Audit Security Group Management (Failure) - Inclusion'
        {
            Ensure = 'Absent'
            Name = 'Security Group Management'
            AuditFlag = 'Failure'
        }
    }
    
    if ($AuditUserAccountManagement_Success) {
        AuditPolicySubcategory 'Audit User Account Management (Success) - Inclusion'
        {
            Ensure = 'Present'
            Name = 'User Account Management'
            AuditFlag = 'Success'
        }
    }
    
    if ($AuditUserAccountManagement_Failure) {
        AuditPolicySubcategory 'Audit User Account Management (Failure) - Inclusion'
        {
            Ensure = 'Present'
            Name = 'User Account Management'
            AuditFlag = 'Failure'
        }
    }
    
    if ($AuditProcessCreation_Success) {
        AuditPolicySubcategory 'Audit Process Creation (Success) - Inclusion'
        {
            Ensure = 'Present'
            Name = 'Process Creation'
            AuditFlag = 'Success'
        }
    }
    
    if ( $AuditProcessCreation_Failure) {
        AuditPolicySubcategory 'Audit Process Creation (Failure) - Inclusion'
        {
            Ensure = 'Absent'
            Name = 'Process Creation'
            AuditFlag = 'Failure'
        }
    }
    
    if ($AuditDirectoryServiceAccess_Success) {
        AuditPolicySubcategory 'Audit Directory Service Access (Success) - Inclusion'
        {
            Ensure = 'Present'
            Name = 'Directory Service Access'
            AuditFlag = 'Success'
        }
    }
    
    if ($AuditDirectoryServiceAccess_Failure) {
        AuditPolicySubcategory 'Audit Directory Service Access (Failure) - Inclusion'
        {
            Ensure = 'Present'
            Name = 'Directory Service Access'
            AuditFlag = 'Failure'
        }
    }

    if ($AuditDirectoryServiceChanges_Success) {
        AuditPolicySubcategory 'Audit Directory Service Changes (Success) - Inclusion'
        {
            Ensure = 'Present'
            Name = 'Directory Service Changes'
            AuditFlag = 'Success'
        }
    }
    
    if ( $AuditDirectoryServiceChanges_Failure) {
        AuditPolicySubcategory 'Audit Directory Service Changes (Failure) - Inclusion'
        {
            Ensure = 'Absent'
            Name = 'Directory Service Changes'
            AuditFlag = 'Failure'
        }
    }
    
    if ($AuditAccountLockout_Failure) {
        AuditPolicySubcategory 'Audit Account Lockout (Failure) - Inclusion'
        {
            Ensure = 'Present'
            Name = 'Account Lockout'
            AuditFlag = 'Failure'
        }
    }
    
    if ( $AuditAccountLockout_Success) {
        AuditPolicySubcategory 'Audit Account Lockout (Success) - Inclusion'
        {
            Ensure = 'Absent'
            Name = 'Account Lockout'
            AuditFlag = 'Success'
        }
    }
    
    if ($AuditLogoff_Success) {
        AuditPolicySubcategory 'Audit Logoff (Success) - Inclusion'
        {
            Ensure = 'Present'
            Name = 'Logoff'
            AuditFlag = 'Success'
        }
    }
    
    if ( $AuditLogoff_Failure) {
        AuditPolicySubcategory 'Audit Logoff (Failure) - Inclusion'
        {
            Ensure = 'Absent'
            Name = 'Logoff'
            AuditFlag = 'Failure'
        }
    }

    if ($AuditLogon_Success) {
        AuditPolicySubcategory 'Audit Logon (Success) - Inclusion'
        {
            Ensure = 'Present'
            Name = 'Logon'
            AuditFlag = 'Success'
        }
    }
    
    if ($AuditLogon_Failure) {
        AuditPolicySubcategory 'Audit Logon (Failure) - Inclusion'
        {
            Ensure = 'Present'
            Name = 'Logon'
            AuditFlag = 'Failure'
        }
    }
    
    if ($AuditSpecialLogon_Success) {
        AuditPolicySubcategory 'Audit Special Logon (Success) - Inclusion'
        {
            Ensure = 'Present'
            Name = 'Special Logon'
            AuditFlag = 'Success'
        }
    }
    
    if ( $AuditSpecialLogon_Failure) {
        AuditPolicySubcategory 'Audit Special Logon (Failure) - Inclusion'
        {
            Ensure = 'Absent'
            Name = 'Special Logon'
            AuditFlag = 'Failure'
        }
    }
    
    if ($AuditRemovableStorage_Success) {
        AuditPolicySubcategory 'Audit Removable Storage (Success) - Inclusion'
        {
            Ensure = 'Present'
            Name = 'Removable Storage'
            AuditFlag = 'Success'
        }
    }
    
    if ($AuditRemovableStorage_Failure) {
        AuditPolicySubcategory 'Audit Removable Storage (Failure) - Inclusion'
        {
            Ensure = 'Present'
            Name = 'Removable Storage'
            AuditFlag = 'Failure'
        }
    }
    
    if ($AuditCentralAccessPolicyStaging_Success) {
        AuditPolicySubcategory 'Audit Central Access Policy Staging (Success) - Inclusion'
        {
            Ensure = 'Present'
            Name = 'Central Policy Staging'
            AuditFlag = 'Success'
        }
    }

    if ($AuditCentralAccessPolicyStaging_Failure) {
        AuditPolicySubcategory 'Audit Central Access Policy Staging (Failure) - Inclusion'
        {
            Ensure = 'Present'
            Name = 'Central Policy Staging'
            AuditFlag = 'Failure'
        }
    }
    
    if ($AuditPolicyChange_Success) {
        AuditPolicySubcategory 'Audit Audit Policy Change (Success) - Inclusion'
        {
            Ensure = 'Present'
            Name = 'Audit Policy Change'
            AuditFlag = 'Success'
        }
    }
    
    if ($AuditPolicyChange_Failure) {
        AuditPolicySubcategory 'Audit Audit Policy Change (Failure) - Inclusion'
        {
            Ensure = 'Present'
            Name = 'Audit Policy Change'
            AuditFlag = 'Failure'
        }
    }
    
    if ($AuditAuthenticationPolicyChange_Success) {
        AuditPolicySubcategory 'Audit Authentication Policy Change (Success) - Inclusion'
        {
            Ensure = 'Present'
            Name = 'Authentication Policy Change'
            AuditFlag = 'Success'
        }
    }
    
    if ( $AuditAuthenticationPolicyChange_Failure) {
        AuditPolicySubcategory 'Audit Authentication Policy Change (Failure) - Inclusion'
        {
            Ensure = 'Absent'
            Name = 'Authentication Policy Change'
            AuditFlag = 'Failure'
        }
    }
    
    if ($AuditAuthorizationPolicyChange_Success) {
        AuditPolicySubcategory 'Audit Authorization Policy Change (Success) - Inclusion'
        {
            Ensure = 'Present'
            Name = 'Authorization Policy Change'
            AuditFlag = 'Success'
        }
    }

    if ( $AuditAuthorizationPolicyChange_Failure) {
        AuditPolicySubcategory 'Audit Authorization Policy Change (Failure) - Inclusion'
        {
            Ensure = 'Absent'
            Name = 'Authorization Policy Change'
            AuditFlag = 'Failure'
        }
    }
    
    if ($AuditSensitivePrivilegeUse_Success) {
        AuditPolicySubcategory 'Audit Sensitive Privilege Use (Success) - Inclusion'
        {
            Ensure = 'Present'
            Name = 'Sensitive Privilege Use'
            AuditFlag = 'Success'
        }
    }
    
    if ($AuditSensitivePrivilegeUse_Failure) {
        AuditPolicySubcategory 'Audit Sensitive Privilege Use (Failure) - Inclusion'
        {
            Ensure = 'Present'
            Name = 'Sensitive Privilege Use'
            AuditFlag = 'Failure'
        }
    }
    
    if ($AuditIPsecDriver_Success) {
        AuditPolicySubcategory 'Audit IPsec Driver (Success) - Inclusion'
        {
            Ensure = 'Present'
            Name = 'IPsec Driver'
            AuditFlag = 'Success'
        }
    }
    
    if ($AuditIPsecDriver_Failure) {
        AuditPolicySubcategory 'Audit IPsec Driver (Failure) - Inclusion'
        {
            Ensure = 'Present'
            Name = 'IPsec Driver'
            AuditFlag = 'Failure'
        }
    }
    
    if ($AuditOtherSystemEvents_Success) {
        AuditPolicySubcategory 'Audit Other System Events (Success) - Inclusion'
        {
            Ensure = 'Present'
            Name = 'Other System Events'
            AuditFlag = 'Success'
        }
    }
    
    if ($AuditOtherSystemEvents_Failure) {
        AuditPolicySubcategory 'Audit Other System Events (Failure) - Inclusion'
        {
            Ensure = 'Present'
            Name = 'Other System Events'
            AuditFlag = 'Failure'
        }
    }
    if ($AuditSecurityStateChange_Success) {
        AuditPolicySubcategory 'Audit Security State Change (Success) - Inclusion'
        {
            Ensure = 'Present'
            Name = 'Security State Change'
            AuditFlag = 'Success'
        }
    }
    
    if ( $AuditSecurityStateChange_Failure) {
        AuditPolicySubcategory 'Audit Security State Change (Failure) - Inclusion'
        {
            Ensure = 'Absent'
            Name = 'Security State Change'
            AuditFlag = 'Failure'
        }
    }
    
    if ($AuditSecuritySystemExtension_Success) {
        AuditPolicySubcategory 'Audit Security System Extension (Success) - Inclusion'
        {
            Ensure = 'Present'
            Name = 'Security System Extension'
            AuditFlag = 'Success'
        }
    }
    
    if ( $AuditSecuritySystemExtension_Failure) {
        AuditPolicySubcategory 'Audit Security System Extension (Failure) - Inclusion'
        {
            Ensure = 'Absent'
            Name = 'Security System Extension'
            AuditFlag = 'Failure'
        }
    }
    
    if ($AuditSystemIntegrity_Success) {
        AuditPolicySubcategory 'Audit System Integrity (Success) - Inclusion'
        {
            Ensure = 'Present'
            Name = 'System Integrity'
            AuditFlag = 'Success'
        }
    }
    
    if ($AuditSystemIntegrity_Failure) {
        AuditPolicySubcategory 'Audit System Integrity (Failure) - Inclusion'
        {
            Ensure = 'Present'
            Name = 'System Integrity'
            AuditFlag = 'Failure'
        }
    }
    
    if ($EnableComputerAndUserAccountsToBeTrustedForDelegation) {
        UserRightsAssignment 'UserRightsAssignment(INF): Enable_computer_and_user_accounts_to_be_trusted_for_delegation'
        {
            Force = $True
            Identity = @('*S-1-5-32-544')
            Policy = 'Enable_computer_and_user_accounts_to_be_trusted_for_delegation'
        }
    }

    if ($AllowLogOnThroughRemoteDesktopServices) {
        UserRightsAssignment 'UserRightsAssignment(INF): Allow_log_on_through_Remote_Desktop_Services'
        {
            Force = $True
            Identity = @('*S-1-5-32-544')
            Policy = 'Allow_log_on_through_Remote_Desktop_Services'
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
    
    if ($ImpersonateAClientAfterAuthentication) {
        UserRightsAssignment 'UserRightsAssignment(INF): Impersonate_a_client_after_authentication'
        {
            Force = $True
            Identity = @('*S-1-5-6', '*S-1-5-20', '*S-1-5-19', '*S-1-5-32-544')
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
    
    if ($AccessThisComputerFromTheNetwork) {
        UserRightsAssignment 'UserRightsAssignment(INF): Access_this_computer_from_the_network'
        {
            Force = $True
            Identity = @('*S-1-5-9', '*S-1-5-11', '*S-1-5-32-544')
            Policy = 'Access_this_computer_from_the_network'
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
            Identity = @('*S-1-5-32-546')
            Policy = 'Deny_access_to_this_computer_from_the_network'
        }
    }
    
    if ($CreateGlobalObjects) {
        UserRightsAssignment 'UserRightsAssignment(INF): Create_global_objects'
        {
            Force = $True
            Identity = @('*S-1-5-6', '*S-1-5-20', '*S-1-5-19', '*S-1-5-32-544')
            Policy = 'Create_global_objects'
        }
    }
    
    if ($DenyLogOnAsABatchJob) {
        UserRightsAssignment 'UserRightsAssignment(INF): Deny_log_on_as_a_batch_job'
        {
            Force = $True
            Identity = @('*S-1-5-32-546')
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
    
    if ($AccessCredentialManagerAsATrustedCaller) {
        UserRightsAssignment 'UserRightsAssignment(INF): Access_Credential_Manager_as_a_trusted_caller'
        {
            Force = $True
            Identity = @('')
            Policy = 'Access_Credential_Manager_as_a_trusted_caller'
        }
    }
    
    if ($AddWorkstationsToDomain) {
        UserRightsAssignment 'UserRightsAssignment(INF): Add_workstations_to_domain'
        {
            Force = $True
            Identity = @('*S-1-5-32-544')
            Policy = 'Add_workstations_to_domain'
        }
    }

    if ($DenyLogOnAsAService) {
        UserRightsAssignment 'UserRightsAssignment(INF): Deny_log_on_as_a_service'
        {
            Force = $True
            Identity = @('')
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
    
    if ($ForceShutdownFromARemoteSystem) {
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
            Identity = @('*S-1-5-20', '*S-1-5-19')
            Policy = 'Generate_security_audits'
        }
    }
    
    if ($DenyLogOnLocally) {
        UserRightsAssignment 'UserRightsAssignment(INF): Deny_log_on_locally'
        {
            Force = $True
            Identity = @('*S-1-5-32-546')
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
    
    if ($LoadAndUnloadDeviceDrivers) {
        UserRightsAssignment 'UserRightsAssignment(INF): Load_and_unload_device_drivers'
        {
            Force = $True
            Identity = @('*S-1-5-32-544')
            Policy = 'Load_and_unload_device_drivers'
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
            Identity = @('*S-1-5-32-546')
            Policy = 'Deny_log_on_through_Remote_Desktop_Services'
        }
    }
    
    if ($UACAdminApprovalMode) {
        SecurityOption 'SecurityRegistry(INF): User_Account_Control_Admin_Approval_Mode_for_the_Built_in_Administrator_account'
        {
            User_Account_Control_Admin_Approval_Mode_for_the_Built_in_Administrator_account = 'Enabled'
            Name = 'User_Account_Control_Admin_Approval_Mode_for_the_Built_in_Administrator_account'
        }
    }
    
    if ($RestrictAnonymousAccess) {
        SecurityOption 'SecurityRegistry(INF): Network_access_Restrict_anonymous_access_to_Named_Pipes_and_Shares'
        {
            Network_access_Restrict_anonymous_access_to_Named_Pipes_and_Shares = 'Enabled'
            Name = 'Network_access_Restrict_anonymous_access_to_Named_Pipes_and_Shares'
        }
    }
    
    if ($RemotelyAccessibleRegistryPaths) {
        SecurityOption 'SecurityRegistry(INF): Network_access_Remotely_accessible_registry_paths_and_subpaths'
        {
            Network_access_Remotely_accessible_registry_paths_and_subpaths = 'Software\Microsoft\Windows NT\CurrentVersion\Print,Software\Microsoft\Windows NT\CurrentVersion\Windows,System\CurrentControlSet\Control\Print\Printers,System\CurrentControlSet\Services\Eventlog,Software\Microsoft\OLAP Server,System\CurrentControlSet\Control\ContentIndex,System\CurrentControlSet\Control\Terminal Server,System\CurrentControlSet\Control\Terminal Server\UserConfig,System\CurrentControlSet\Control\Terminal Server\DefaultUserConfiguration,Software\Microsoft\Windows NT\CurrentVersion\Perflib,System\CurrentControlSet\Services\SysmonLog'
            Name = 'Network_access_Remotely_accessible_registry_paths_and_subpaths'
        }
    }
    
    if ($SharingAndSecurityModel) {
        SecurityOption 'SecurityRegistry(INF): Network_access_Sharing_and_security_model_for_local_accounts'
        {
            Network_access_Sharing_and_security_model_for_local_accounts = 'Classic - Local users authenticate as themselves'
            Name = 'Network_access_Sharing_and_security_model_for_local_accounts'
        }
    }
    
    if ($RequireStrongSessionKey) {
        SecurityOption 'SecurityRegistry(INF): Domain_member_Require_strong_Windows_2000_or_later_session_key'
        {
            Domain_member_Require_strong_Windows_2000_or_later_session_key = 'Enabled'
            Name = 'Domain_member_Require_strong_Windows_2000_or_later_session_key'
        }
    }
    
    if ($OnlyElevateUIAccessAppsInSecureLocations) {
        SecurityOption 'SecurityRegistry(INF): User_Account_Control_Only_elevate_UIAccess_applications_that_are_installed_in_secure_locations'
        {
            User_Account_Control_Only_elevate_UIAccess_applications_that_are_installed_in_secure_locations = 'Enabled'
            Name = 'User_Account_Control_Only_elevate_UIAccess_applications_that_are_installed_in_secure_locations'
        }
    }

    if ($IdleTimeBeforeSuspendingSession) {
        SecurityOption 'SecurityRegistry(INF): Microsoft_network_server_Amount_of_idle_time_required_before_suspending_session'
        {
            Name = 'Microsoft_network_server_Amount_of_idle_time_required_before_suspending_session'
            Microsoft_network_server_Amount_of_idle_time_required_before_suspending_session = '15'
        }
    }
    
    if ($StrongKeyProtection) {
        SecurityOption 'SecurityRegistry(INF): System_cryptography_Force_strong_key_protection_for_user_keys_stored_on_the_computer'
        {
            Name = 'System_cryptography_Force_strong_key_protection_for_user_keys_stored_on_the_computer'
            System_cryptography_Force_strong_key_protection_for_user_keys_stored_on_the_computer = 'User must enter a password each time they use a key'
        }
    }
    
    if ($KerberosEncryptionTypes) {
        SecurityOption 'SecurityRegistry(INF): Network_security_Configure_encryption_types_allowed_for_Kerberos'
        {
            Network_security_Configure_encryption_types_allowed_for_Kerberos = 'AES128_HMAC_SHA1'
            Name = 'Network_security_Configure_encryption_types_allowed_for_Kerberos'
        }
    }
    
    if ($DigitallySignCommunicationsIfClientAgrees) {
        SecurityOption 'SecurityRegistry(INF): Microsoft_network_server_Digitally_sign_communications_if_client_agrees'
        {
            Name = 'Microsoft_network_server_Digitally_sign_communications_if_client_agrees'
            Microsoft_network_server_Digitally_sign_communications_if_client_agrees = 'Enabled'
        }
    }
    
    if ($UseFIPSCompliantAlgorithms) {
        SecurityOption 'SecurityRegistry(INF): System_cryptography_Use_FIPS_compliant_algorithms_for_encryption_hashing_and_signing'
        {
            System_cryptography_Use_FIPS_compliant_algorithms_for_encryption_hashing_and_signing = 'Enabled'
            Name = 'System_cryptography_Use_FIPS_compliant_algorithms_for_encryption_hashing_and_signing'
        }
    }
    
    if ($ShutdownWithoutLogon) {
        SecurityOption 'SecurityRegistry(INF): Shutdown_Allow_system_to_be_shut_down_without_having_to_log_on'
        {
            Shutdown_Allow_system_to_be_shut_down_without_having_to_log_on = 'Disabled'
            Name = 'Shutdown_Allow_system_to_be_shut_down_without_having_to_log_on'
        }
    }
    
    if ($AuditBackupAndRestorePrivilege) {
        SecurityOption 'SecurityRegistry(INF): Audit_Audit_the_use_of_Backup_and_Restore_privilege'
        {
            Name = 'Audit_Audit_the_use_of_Backup_and_Restore_privilege'
            Audit_Audit_the_use_of_Backup_and_Restore_privilege = 'Disabled'
        }
    }

    if ($DoNotRequireCtrlAltDel) {
        SecurityOption 'SecurityRegistry(INF): Interactive_logon_Do_not_require_CTRL_ALT_DEL'
        {
            Interactive_logon_Do_not_require_CTRL_ALT_DEL = 'Disabled'
            Name = 'Interactive_logon_Do_not_require_CTRL_ALT_DEL'
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
    
    if ($RemotelyAccessibleRegistryPaths) {
        SecurityOption 'SecurityRegistry(INF): Network_access_Remotely_accessible_registry_paths'
        {
            Network_access_Remotely_accessible_registry_paths = 'System\CurrentControlSet\Control\ProductOptions,System\CurrentControlSet\Control\Server Applications,Software\Microsoft\Windows NT\CurrentVersion'
            Name = 'Network_access_Remotely_accessible_registry_paths'
        }
    }
    
    if ($VirtualizeFileAndRegistryWriteFailures) {
        SecurityOption 'SecurityRegistry(INF): User_Account_Control_Virtualize_file_and_registry_write_failures_to_per_user_locations'
        {
            User_Account_Control_Virtualize_file_and_registry_write_failures_to_per_user_locations = 'Enabled'
            Name = 'User_Account_Control_Virtualize_file_and_registry_write_failures_to_per_user_locations'
        }
    }
    
    if ($LogonMessageTitle) {
        SecurityOption 'SecurityRegistry(INF): Interactive_logon_Message_title_for_users_attempting_to_log_on'
        {
            Name = 'Interactive_logon_Message_title_for_users_attempting_to_log_on'
            Interactive_logon_Message_title_for_users_attempting_to_log_on = 'Warning Statement'
        }
    }

    if ($DigitallySignSecureChannelData) {
        SecurityOption 'SecurityRegistry(INF): Domain_member_Digitally_sign_secure_channel_data_when_possible'
        {
            Domain_member_Digitally_sign_secure_channel_data_when_possible = 'Enabled'
            Name = 'Domain_member_Digitally_sign_secure_channel_data_when_possible'
        }
    }
    
    if ($AllowUIAccessApplicationsToPromptForElevation) {
        SecurityOption 'SecurityRegistry(INF): User_Account_Control_Allow_UIAccess_applications_to_prompt_for_elevation_without_using_the_secure_desktop'
        {
            User_Account_Control_Allow_UIAccess_applications_to_prompt_for_elevation_without_using_the_secure_desktop = 'Disabled'
            Name = 'User_Account_Control_Allow_UIAccess_applications_to_prompt_for_elevation_without_using_the_secure_desktop'
        }
    }
    
    if ($SmartCardRemovalBehavior) {
        SecurityOption 'SecurityRegistry(INF): Interactive_logon_Smart_card_removal_behavior'
        {
            Interactive_logon_Smart_card_removal_behavior = 'Lock workstation'
            Name = 'Interactive_logon_Smart_card_removal_behavior'
        }
    }
    
    if ($LimitLocalAccountUseOfBlankPasswords) {
        SecurityOption 'SecurityRegistry(INF): Accounts_Limit_local_account_use_of_blank_passwords_to_console_logon_only'
        {
            Name = 'Accounts_Limit_local_account_use_of_blank_passwords_to_console_logon_only'
            Accounts_Limit_local_account_use_of_blank_passwords_to_console_logon_only = 'Enabled'
        }
    }
    
    if ($ServerSPNTargetNameValidationLevel) {
        SecurityOption 'SecurityRegistry(INF): Microsoft_network_server_Server_SPN_target_name_validation_level'
        {
            Microsoft_network_server_Server_SPN_target_name_validation_level = 'Off'
            Name = 'Microsoft_network_server_Server_SPN_target_name_validation_level'
        }
    }
    
    if ($LdapServerSigningRequirements) {
        SecurityOption 'SecurityRegistry(INF): Domain_controller_LDAP_server_signing_requirements'
        {
            Domain_controller_LDAP_server_signing_requirements = 'Require Signing'
            Name = 'Domain_controller_LDAP_server_signing_requirements'
        }
    }
    
    if ($AllowedToFormatAndEjectRemovableMedia) {
        SecurityOption 'SecurityRegistry(INF): Devices_Allowed_to_format_and_eject_removable_media'
        {
            Devices_Allowed_to_format_and_eject_removable_media = 'Administrators'
            Name = 'Devices_Allowed_to_format_and_eject_removable_media'
        }
    }

    if ($NamedPipesAccessedAnonymously) {
        SecurityOption 'SecurityRegistry(INF): Network_access_Named_Pipes_that_can_be_accessed_anonymously'
        {
            Network_access_Named_Pipes_that_can_be_accessed_anonymously = 'lsarpc,netlogon,samr'
            Name = 'Network_access_Named_Pipes_that_can_be_accessed_anonymously'
        }
    }
    
    if ($SwitchToSecureDesktopForElevation) {
        SecurityOption 'SecurityRegistry(INF): User_Account_Control_Switch_to_the_secure_desktop_when_prompting_for_elevation'
        {
            User_Account_Control_Switch_to_the_secure_desktop_when_prompting_for_elevation = 'Enabled'
            Name = 'User_Account_Control_Switch_to_the_secure_desktop_when_prompting_for_elevation'
        }
    }
    
    if ($MessageTextForUsersLogon) {
        SecurityOption 'SecurityRegistry(INF): Interactive_logon_Message_text_for_users_attempting_to_log_on'
        {
            Interactive_logon_Message_text_for_users_attempting_to_log_on = $MessageTextWhenLogging
            Name = 'Interactive_logon_Message_text_for_users_attempting_to_log_on'
        }
    }
    
    if ($SharesAccessedAnonymously) {
        SecurityOption 'SecurityRegistry(INF): Network_access_Shares_that_can_be_accessed_anonymously'
        {
            Name = 'Network_access_Shares_that_can_be_accessed_anonymously'
            Network_access_Shares_that_can_be_accessed_anonymously = 'String'
        }
    }
    
    if ($EveryonePermissionsApplyToAnonymousUsers) {
        SecurityOption 'SecurityRegistry(INF): Network_access_Let_Everyone_permissions_apply_to_anonymous_users'
        {
            Network_access_Let_Everyone_permissions_apply_to_anonymous_users = 'Disabled'
            Name = 'Network_access_Let_Everyone_permissions_apply_to_anonymous_users'
        }
    }
    
    if ($DigitallyEncryptSecureChannelData) {
        SecurityOption 'SecurityRegistry(INF): Domain_member_Digitally_encrypt_secure_channel_data_when_possible'
        {
            Name = 'Domain_member_Digitally_encrypt_secure_channel_data_when_possible'
            Domain_member_Digitally_encrypt_secure_channel_data_when_possible = 'Enabled'
        }
    }
    
    if ($ElevationPromptBehaviorForStandardUsers) {
        SecurityOption 'SecurityRegistry(INF): User_Account_Control_Behavior_of_the_elevation_prompt_for_standard_users'
        {
            User_Account_Control_Behavior_of_the_elevation_prompt_for_standard_users = 'Automatically deny elevation request'
            Name = 'User_Account_Control_Behavior_of_the_elevation_prompt_for_standard_users'
        }
    }

    if ($DigitallySignCommunicationsAlways_Server) {
        SecurityOption 'SecurityRegistry(INF): Microsoft_network_server_Digitally_sign_communications_always'
        {
            Microsoft_network_server_Digitally_sign_communications_always = 'Enabled'
            Name = 'Microsoft_network_server_Digitally_sign_communications_always'
        }
    }
    
    if ($OptionalSubsystemsEnabled) {
        SecurityOption 'SecurityRegistry(INF): System_settings_Optional_subsystems'
        {
            System_settings_Optional_subsystems = 'String'
            Name = 'System_settings_Optional_subsystems'
        }
    }
    
    if ($DigitallySignCommunicationsAlways_Client) {
        SecurityOption 'SecurityRegistry(INF): Microsoft_network_client_Digitally_sign_communications_always'
        {
            Microsoft_network_client_Digitally_sign_communications_always = 'Enabled'
            Name = 'Microsoft_network_client_Digitally_sign_communications_always'
        }
    }
    
    if ($MinimumSessionSecurityForNTLM) {
        SecurityOption 'SecurityRegistry(INF): Network_security_Minimum_session_security_for_NTLM_SSP_based_including_secure_RPC_clients'
        {
            Name = 'Network_security_Minimum_session_security_for_NTLM_SSP_based_including_secure_RPC_clients'
            Network_security_Minimum_session_security_for_NTLM_SSP_based_including_secure_RPC_clients = 'Both options checked'
        }
    }
    
    if ($PromptUserToChangePasswordBeforeExpiration) {
        SecurityOption 'SecurityRegistry(INF): Interactive_logon_Prompt_user_to_change_password_before_expiration'
        {
            Interactive_logon_Prompt_user_to_change_password_before_expiration = '14'
            Name = 'Interactive_logon_Prompt_user_to_change_password_before_expiration'
        }
    }
    
    if ($RunAllAdministratorsInAdminApprovalMode) {
        SecurityOption 'SecurityRegistry(INF): User_Account_Control_Run_all_administrators_in_Admin_Approval_Mode'
        {
            User_Account_Control_Run_all_administrators_in_Admin_Approval_Mode = 'Enabled'
            Name = 'User_Account_Control_Run_all_administrators_in_Admin_Approval_Mode'
        }
    }
    
    if ($DigitallySignCommunicationsIfServerAgrees) {
        SecurityOption 'SecurityRegistry(INF): Microsoft_network_client_Digitally_sign_communications_if_server_agrees'
        {
            Name = 'Microsoft_network_client_Digitally_sign_communications_if_server_agrees'
            Microsoft_network_client_Digitally_sign_communications_if_server_agrees = 'Enabled'
        }
    }

    if ($DetectApplicationInstallationsAndPromptForElevation) {
        SecurityOption 'SecurityRegistry(INF): User_Account_Control_Detect_application_installations_and_prompt_for_elevation'
        {
            User_Account_Control_Detect_application_installations_and_prompt_for_elevation = 'Enabled'
            Name = 'User_Account_Control_Detect_application_installations_and_prompt_for_elevation'
        }
    }
    
    if ($DoNotAllowAnonymousEnumerationOfSAMAccounts) {
        SecurityOption 'SecurityRegistry(INF): Network_access_Do_not_allow_anonymous_enumeration_of_SAM_accounts'
        {
            Name = 'Network_access_Do_not_allow_anonymous_enumeration_of_SAM_accounts'
            Network_access_Do_not_allow_anonymous_enumeration_of_SAM_accounts = 'Enabled'
        }
    }
    
    if ($AllowLocalSystemToUseComputerIdentityForNTLM) {
        SecurityOption 'SecurityRegistry(INF): Network_security_Allow_Local_System_to_use_computer_identity_for_NTLM'
        {
            Network_security_Allow_Local_System_to_use_computer_identity_for_NTLM = 'Enabled'
            Name = 'Network_security_Allow_Local_System_to_use_computer_identity_for_NTLM'
        }
    }
    
    if ($RequireCaseInsensitivityForNonWindowsSubsystems) {
        SecurityOption 'SecurityRegistry(INF): System_objects_Require_case_insensitivity_for_non_Windows_subsystems'
        {
            Name = 'System_objects_Require_case_insensitivity_for_non_Windows_subsystems'
            System_objects_Require_case_insensitivity_for_non_Windows_subsystems = 'Enabled'
        }
    }
    
    if ($AllowLocalSystemNULLSessionFallback) {
        SecurityOption 'SecurityRegistry(INF): Network_security_Allow_LocalSystem_NULL_session_fallback'
        {
            Name = 'Network_security_Allow_LocalSystem_NULL_session_fallback'
            Network_security_Allow_LocalSystem_NULL_session_fallback = 'Disabled'
        }
    }
    
    if ($ForceAuditPolicySubcategorySettings) {
        SecurityOption 'SecurityRegistry(INF): Audit_Force_audit_policy_subcategory_settings_Windows_Vista_or_later_to_override_audit_policy_category_settings'
        {
            Name = 'Audit_Force_audit_policy_subcategory_settings_Windows_Vista_or_later_to_override_audit_policy_category_settings'
            Audit_Force_audit_policy_subcategory_settings_Windows_Vista_or_later_to_override_audit_policy_category_settings = 'Enabled'
        }
    }

    if ($OnlyElevateSignedAndValidatedExecutables) {
        SecurityOption 'SecurityRegistry(INF): User_Account_Control_Only_elevate_executables_that_are_signed_and_validated'
        {
            Name = 'User_Account_Control_Only_elevate_executables_that_are_signed_and_validated'
            User_Account_Control_Only_elevate_executables_that_are_signed_and_validated = 'Disabled'
        }
    }
    
    if ($AuditAccessOfGlobalSystemObjects) {
        SecurityOption 'SecurityRegistry(INF): Audit_Audit_the_access_of_global_system_objects'
        {
            Name = 'Audit_Audit_the_access_of_global_system_objects'
            Audit_Audit_the_access_of_global_system_objects = 'Disabled'
        }
    }
    
    if ($SendUnencryptedPasswordToThirdPartySMBServers) {
        SecurityOption 'SecurityRegistry(INF): Microsoft_network_client_Send_unencrypted_password_to_third_party_SMB_servers'
        {
            Microsoft_network_client_Send_unencrypted_password_to_third_party_SMB_servers = 'Disabled'
            Name = 'Microsoft_network_client_Send_unencrypted_password_to_third_party_SMB_servers'
        }
    }
    
    if ($MinimumSessionSecurityForNTLMSPBASED) {
        SecurityOption 'SecurityRegistry(INF): Network_security_Minimum_session_security_for_NTLM_SSP_based_including_secure_RPC_servers'
        {
            Name = 'Network_security_Minimum_session_security_for_NTLM_SSP_based_including_secure_RPC_servers'
            Network_security_Minimum_session_security_for_NTLM_SSP_based_including_secure_RPC_servers = 'Both options checked'
        }
    }
    
    if ($NumberOfPreviousLogonsToCache) {
        SecurityOption 'SecurityRegistry(INF): Interactive_logon_Number_of_previous_logons_to_cache_in_case_domain_controller_is_not_available'
        {
            Interactive_logon_Number_of_previous_logons_to_cache_in_case_domain_controller_is_not_available = '4'
            Name = 'Interactive_logon_Number_of_previous_logons_to_cache_in_case_domain_controller_is_not_available'
        }
    }
    
    if ($DoNotDisplayLastUserName) {
        SecurityOption 'SecurityRegistry(INF): Interactive_logon_Do_not_display_last_user_name'
        {
            Name = 'Interactive_logon_Do_not_display_last_user_name'
            Interactive_logon_Do_not_display_last_user_name = 'Enabled'
        }
    }

    if ($MaximumMachineAccountPasswordAge) {
        SecurityOption 'SecurityRegistry(INF): Domain_member_Maximum_machine_account_password_age'
        {
            Name = 'Domain_member_Maximum_machine_account_password_age'
            Domain_member_Maximum_machine_account_password_age = '30'
        }
    }
    
    if ($DisconnectClientsWhenLogonHoursExpire) {
        SecurityOption 'SecurityRegistry(INF): Microsoft_network_server_Disconnect_clients_when_logon_hours_expire'
        {
            Microsoft_network_server_Disconnect_clients_when_logon_hours_expire = 'Enabled'
            Name = 'Microsoft_network_server_Disconnect_clients_when_logon_hours_expire'
        }
    }
    
    if ($DoNotAllowAnonymousEnumerationOfSAMAccountsAndShares) {
        SecurityOption 'SecurityRegistry(INF): Network_access_Do_not_allow_anonymous_enumeration_of_SAM_accounts_and_shares'
        {
            Name = 'Network_access_Do_not_allow_anonymous_enumeration_of_SAM_accounts_and_shares'
            Network_access_Do_not_allow_anonymous_enumeration_of_SAM_accounts_and_shares = 'Enabled'
        }
    }
    
    if ($RefuseMachineAccountPasswordChanges) {
        SecurityOption 'SecurityRegistry(INF): Domain_controller_Refuse_machine_account_password_changes'
        {
            Name = 'Domain_controller_Refuse_machine_account_password_changes'
            Domain_controller_Refuse_machine_account_password_changes = 'Disabled'
        }
    }
    
    if ($PreventUsersFromInstallingPrinterDrivers) {
        SecurityOption 'SecurityRegistry(INF): Devices_Prevent_users_from_installing_printer_drivers'
        {
            Name = 'Devices_Prevent_users_from_installing_printer_drivers'
            Devices_Prevent_users_from_installing_printer_drivers = 'Enabled'
        }
    }
    
    if ($StrengthenDefaultPermissionsOfInternalSystemObjects) {
        SecurityOption 'SecurityRegistry(INF): System_objects_Strengthen_default_permissions_of_internal_system_objects_eg_Symbolic_Links'
        {
            System_objects_Strengthen_default_permissions_of_internal_system_objects_eg_Symbolic_Links = 'Enabled'
            Name = 'System_objects_Strengthen_default_permissions_of_internal_system_objects_eg_Symbolic_Links'
        }
    }
    
    if ($AllowPKU2UAuthenticationRequestsToUseOnlineIdentities) {
        SecurityOption 'SecurityRegistry(INF): Network_Security_Allow_PKU2U_authentication_requests_to_this_computer_to_use_online_identities'
        {
            Network_Security_Allow_PKU2U_authentication_requests_to_this_computer_to_use_online_identities = 'Disabled'
            Name = 'Network_Security_Allow_PKU2U_authentication_requests_to_this_computer_to_use_online_identities'
        }
    }

    if ($MachineInactivityLimit) {
        SecurityOption 'SecurityRegistry(INF): Interactive_logon_Machine_inactivity_limit'
        {
            Name = 'Interactive_logon_Machine_inactivity_limit'
            Interactive_logon_Machine_inactivity_limit = '900'
        }
    }
    
    if ($DoNotStoreLANManagerHashOnNextPasswordChange) {
        SecurityOption 'SecurityRegistry(INF): Network_security_Do_not_store_LAN_Manager_hash_value_on_next_password_change'
        {
            Name = 'Network_security_Do_not_store_LAN_Manager_hash_value_on_next_password_change'
            Network_security_Do_not_store_LAN_Manager_hash_value_on_next_password_change = 'Enabled'
        }
    }
    
    if ($DigitallyEncryptOrSignSecureChannelDataAlways) {
        SecurityOption 'SecurityRegistry(INF): Domain_member_Digitally_encrypt_or_sign_secure_channel_data_always'
        {
            Domain_member_Digitally_encrypt_or_sign_secure_channel_data_always = 'Enabled'
            Name = 'Domain_member_Digitally_encrypt_or_sign_secure_channel_data_always'
        }
    }
    
    if ($LDAPClientSigningRequirements) {
        SecurityOption 'SecurityRegistry(INF): Network_security_LDAP_client_signing_requirements'
        {
            Name = 'Network_security_LDAP_client_signing_requirements'
            Network_security_LDAP_client_signing_requirements = 'Negotiate Signing'
        }
    }
    
    if ($ElevationPromptBehaviorForAdmins) {
        SecurityOption 'SecurityRegistry(INF): User_Account_Control_Behavior_of_the_elevation_prompt_for_administrators_in_Admin_Approval_Mode'
        {
            Name = 'User_Account_Control_Behavior_of_the_elevation_prompt_for_administrators_in_Admin_Approval_Mode'
            User_Account_Control_Behavior_of_the_elevation_prompt_for_administrators_in_Admin_Approval_Mode = 'Prompt for consent'
        }
    }
    
    if ($LockoutDuration) {
        AccountPolicy 'SecuritySetting(INF): LockoutDuration'
        {
            Account_lockout_duration = 15
            Name = 'Account_lockout_duration'
        }
    }
    
    if ($LockoutBadCount) {
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
    
    if ($LSAAnonymousNameLookup) {
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

    if ($RenameAdministratorAccount) {
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
    
    if ($ClearTextPassword) {
        AccountPolicy 'SecuritySetting(INF): ClearTextPassword'
        {
            Name = 'Store_passwords_using_reversible_encryption'
            Store_passwords_using_reversible_encryption = 'Disabled'
        }
    }
    
    if ($MaximumPasswordAge) {
        AccountPolicy 'SecuritySetting(INF): MaximumPasswordAge'
        {
            Maximum_Password_Age = 60
            Name = 'Maximum_Password_Age'
        }
    }
    
    if ($ForceLogoffWhenHourExpire) {
        SecurityOption 'SecuritySetting(INF): ForceLogoffWhenHourExpire'
        {
            Network_security_Force_logoff_when_logon_hours_expire = 'Enabled'
            Name = 'Network_security_Force_logoff_when_logon_hours_expire'
        }
    }
    
}

