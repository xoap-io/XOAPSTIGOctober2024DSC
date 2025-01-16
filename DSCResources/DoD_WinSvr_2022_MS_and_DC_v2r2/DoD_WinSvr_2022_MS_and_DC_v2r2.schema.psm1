configuration DoD_WinSvr_2022_MS_and_DC_v2r2
{

    param(
        [string]$EnterpriseAdmins,
        [string]$DomainAdmins,
        [bool]$EnumerateAdministrators = $true,
        [bool]$NoAutorun = $true,
        [bool]$NoDriveTypeAutoRun = $true,
        [bool]$PreXPSP2ShellProtocolBehavior = $true,
        [bool]$PasswordComplexity = $true,
        [bool]$PasswordLength = $true,
        [bool]$PasswordAgeDays = $true,
        [bool]$DisableAutomaticRestartSignOn = $true,
        [bool]$LocalAccountTokenFilterPolicy = $true,
        [bool]$ProcessCreationIncludeCmdLine_Enabled = $true,
        [bool]$DisableEnclosureDownload = $true,
        [bool]$AllowBasicAuthInClear = $true,
        [bool]$DCSettingIndex = $true,
        [bool]$ACSettingIndex = $true,
        [bool]$DisableInventory = $true,
        [bool]$AllowProtectedCreds = $true,
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
        [bool]$NoAutoplayfornonVolume = $true,
        [bool]$NoDataExecutionPrevention = $true,
        [bool]$NoHeapTerminationOnCorruption = $true,
        [bool]$NoBackgroundPolicy = $true,
        [bool]$NoGPOListChanges = $true,
        [bool]$EnableUserControl = $true,
        [bool]$AlwaysInstallElevated = $true,
        [bool]$SafeForScripting = $true,
        [bool]$AllowInsecureGuestAuth = $true,
        [bool]$HardenedPathsSYSVOL = $true,
        [bool]$HardenedPathsNETLOGON = $true,
        [bool]$NoLockScreenSlideshow = $true,
        [bool]$EnableScriptBlockLogging = $true,
        [bool]$EnableScriptBlockInvocationLogging = $true,
        [bool]$EnableTranscripting = $true,
        [bool]$SetOutputDirectory = $true,
        [bool]$EnableInvocationHeader = $true,
        [bool]$DontDisplayNetworkSelectionUI = $true,
        [bool]$EnableSmartScreen = $true,
        [bool]$BlockShellSmartScreen = $true,
        [bool]$EnumerateLocalUsers = $true,
        [bool]$AllowIndexingEncryptedStoresOrItems = $true,
        [bool]$AllowBasic = $true,
        [bool]$AllowUnencryptedTraffic = $true,
        [bool]$AllowDigest = $true,
        [bool]$AllowBasicWinRMService = $true,
        [bool]$AllowUnencryptedTrafficService = $true,
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
        [bool]$DriverLoadPolicy = $true,
        [bool]$SMB1 = $true,
        [bool]$StartMrxSmb10 = $true,
        [bool]$NoNameReleaseOnDemand = $true,
        [bool]$DisableIPSourceRouting = $true,
        [bool]$EnableICMPRedirect = $true,
        [bool]$DisableIPSourceRoutingIPv6 = $true,
        [bool]$AuditCredentialValidationSuccess = $true,
        [bool]$AuditCredentialValidationFailure = $true,
        [bool]$AuditOtherAccountManagementEventsSuccess = $true,
        [bool]$AuditOtherAccountManagementEventsFailure = $true,
        [bool]$AuditSecurityGroupManagementSuccess = $true,
        [bool]$AuditSecurityGroupManagementFailure = $true,
        [bool]$AuditUserAccountManagementSuccess = $true,
        [bool]$AuditUserAccountManagementFailure = $true,
        [bool]$AuditPnpActivitySuccess = $true,
        [bool]$AuditPnpActivityFailure = $true,
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
        [bool]$AuditIpsecDriverSuccess = $true,
        [bool]$AuditIpsecDriverFailure = $true,
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
        [bool]$RestrictClientsToSAM = $true,
        [bool]$RestrictAnonymousAccess = $true,
        [bool]$RequireStrongSessionKey = $true,
        [bool]$ElevateUIAccessApplications = $true,
        [bool]$MinimumSessionSecurityNTLM = $true,
        [bool]$ConfigureKerberosEncryptionTypes = $true,
        [bool]$DigitallySignCommunications = $true,
        [bool]$UseFIPSCompliantAlgorithms = $true,
        [bool]$LanManagerAuthenticationLevel = $true,
        [bool]$AllowLocalSystemNTLM = $true,
        [bool]$InteractiveLogonMessageTitle = $true,
        [bool]$DigitallySignSecureChannelData = $true,
        [bool]$AllowUIAccessElevateWithoutSecureDesktop = $true,
        [bool]$SmartCardRemovalBehavior = $true,
        [bool]$LimitLocalAccountBlankPasswords = $true,
        [bool]$VirtualizeFileAndRegistryWriteFailures = $true,
        [bool]$InteractiveLogonMessageText = $true,
        [string]$InteractiveLogonMessageText_Input,
        [bool]$LetEveryonePermissionsApplyToAnonymousUsers = $true,
        [bool]$DigitallyEncryptSecureChannelData = $true,
        [bool]$ElevationPromptBehavior = $true,
        [bool]$DigitallySignCommunicationsAlwaysServer = $true,
        [bool]$ForceStrongKeyProtection = $true,
        [bool]$DigitallySignCommunicationsAlwaysClient = $true,
        [bool]$DisableMachineAccountPasswordChanges = $true,
        [bool]$RunAllAdministratorsInAdminApprovalMode = $true,
        [bool]$DigitallySignCommunicationsIfServerAgrees = $true,
        [bool]$DetectApplicationInstallationsPromptForElevation = $true,
        [bool]$DoNotAllowAnonymousEnumerationOfSAMAccounts = $true,
        [bool]$AllowLocalSystemNullSessionFallback = $true,
        [bool]$AdminApprovalModeForBuiltInAdmin = $true,
        [bool]$SendUnencryptedPasswordToThirdPartySMBServers = $true,
        [bool]$PreviousLogonsToCache = $true,
        [bool]$MaximumMachineAccountPasswordAge = $true,
        [bool]$DoNotAllowAnonymousEnumerationOfSAMAccountsAndShares = $true,
        [bool]$ForceAuditPolicySubcategorySettings = $true,
        [bool]$StrengthenDefaultPermissionsOfInternalSystemObjects = $true,
        [bool]$Allow_PKUL2U_Authentication = $true,
        [bool]$Machine_Inactivity_Limit = $true,
        [bool]$Do_Not_Store_LM_Hash = $true,
        [bool]$Encrypt_Secure_Channel_Data = $true,
        [bool]$LDAP_Client_Signing_Requirements = $true,
        [bool]$UAC_Elevation_Prompt_Behavior = $true,
        [bool]$Lockout_Duration = $true,
        [bool]$Lockout_Bad_Count = $true,
        [bool]$Reset_Lockout_Count = $true,
        [bool]$Rename_Guest_Account = $true,
        [bool]$Minimum_Password_Age = $true,
        [bool]$Password_Complexity = $true,
        [bool]$Password_History_Size = $true,
        [bool]$LSA_Anonymous_Name_Lookup = $true,
        [bool]$Minimum_Password_Length = $true,
        [bool]$Rename_Administrator_Account = $true,
        [bool]$Enable_Guest_Account = $true,
        [bool]$Maximum_Password_Age = $true,
        [bool]$Clear_Text_Password = $true,
        [bool]$Trusted_For_Delegation = $true,
        [bool]$Access_From_Network = $true,
        [bool]$Backup_Files_And_Directories = $true,
        [bool]$Impersonate_Client_After_Authentication = $true,
        [bool]$Perform_Volume_Maintenance_Tasks = $true,
        [bool]$Load_Unload_Device_Drivers = $true,
        [bool]$Take_Ownership_Of_Files = $true,
        [bool]$Create_Permanent_Shared_Objects = $true,
        [bool]$Deny_Access_From_Network = $true,
        [bool]$Create_Global_Objects = $true,
        [bool]$Deny_Log_On_As_Batch_Job = $true,
        [bool]$Restore_Files_And_Directories = $true,
        [bool]$Lock_Pages_In_Memory = $true,
        [bool]$Deny_Log_On_As_Service = $true,
        [bool]$Increase_Scheduling_Priority = $true,
        [bool]$Force_Shutdown_From_Remote_System = $true,
        [bool]$Generate_Security_Audits = $true,
        [bool]$Deny_Log_On_Locally = $true,
        [bool]$Create_Symbolic_Links = $true,
        [bool]$Debug_Programs = $true,
        [bool]$Allow_Log_On_Locally = $true,
        [bool]$Manage_Auditing_And_Security_Log = $true,
        [bool]$Act_As_Part_Of_Operating_System = $true,
        [bool]$Profile_Single_Process = $true,
        [bool]$Create_Token_Object = $true,
        [bool]$Access_Credential_Manager = $true,
        [bool]$Modify_Firmware_Environment_Values = $true,
        [bool]$Create_Pagefile = $true,
        [bool]$Deny_Log_On_Through_RDS = $true,
        [bool]$Add_Workstations_To_Domain = $true,
        [bool]$Allow_Log_On_Through_RDS = $true,
        [bool]$LDAP_Server_Signing_Requirements = $true,
        [bool]$Refuse_Machine_Account_Password_Changes = $true,
        [bool]$Ticket_Validate_Client = $true,
        [bool]$Max_Renew_Age = $true
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
    
    if ($PasswordComplexity) {
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\LAPS\PasswordComplexity'
        {
            Key = '\Software\Microsoft\Windows\CurrentVersion\Policies\LAPS'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
            ValueName = 'PasswordComplexity'
            ValueData = 4
        }
    }
    
    if ($PasswordLength) {
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\LAPS\PasswordLength'
        {
            Key = '\Software\Microsoft\Windows\CurrentVersion\Policies\LAPS'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
            ValueName = 'PasswordLength'
            ValueData = 14
        }
    }

    if ($PasswordAgeDays) {
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\LAPS\PasswordAgeDays'
        {
            Key = '\Software\Microsoft\Windows\CurrentVersion\Policies\LAPS'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
            ValueName = 'PasswordAgeDays'
            ValueData = 60
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

    if ($AllowBasicAuthInClear) {
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Internet Explorer\Feeds\AllowBasicAuthInClear'
        {
            Key = '\Software\Policies\Microsoft\Internet Explorer\Feeds'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
            ValueName = 'AllowBasicAuthInClear'
            ValueData = 0
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
    
    if ($AllowProtectedCreds) {
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\CredentialsDelegation\AllowProtectedCreds'
        {
            Key = '\Software\Policies\Microsoft\Windows\CredentialsDelegation'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
            ValueName = 'AllowProtectedCreds'
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
    
    if ($DODownloadMode) {
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\DeliveryOptimization\DODownloadMode'
        {
            Key = '\Software\Policies\Microsoft\Windows\DeliveryOptimization'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
            ValueName = 'DODownloadMode'
            ValueData = 2
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
            ValueData = 3
        }
    }
    
    if ($HVCIMATRequired) {
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\DeviceGuard\HVCIMATRequired'
        {
            Key = '\Software\Policies\Microsoft\Windows\DeviceGuard'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
            ValueName = 'HVCIMATRequired'
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
    
    if ($ConfigureSystemGuardLaunch) {
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\DeviceGuard\ConfigureSystemGuardLaunch'
        {
            Key = '\Software\Policies\Microsoft\Windows\DeviceGuard'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
            ValueName = 'ConfigureSystemGuardLaunch'
            ValueData = 0
        }
    }
    
    if ($MaxSizeApplicationLog) {
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\EventLog\Application\MaxSize'
        {
            Key = '\Software\Policies\Microsoft\Windows\EventLog\Application'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
            ValueName = 'MaxSize'
            ValueData = 32768
        }
    }
    
    if ($MaxSizeSecurityLog) {
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\EventLog\Security\MaxSize'
        {
            Key = '\Software\Policies\Microsoft\Windows\EventLog\Security'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
            ValueName = 'MaxSize'
            ValueData = 196608
        }
    }
    
    if ($MaxSizeSystemLog) {
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

    if ($NoDataExecutionPrevention) {
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\Explorer\NoDataExecutionPrevention'
        {
            Key = '\Software\Policies\Microsoft\Windows\Explorer'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
            ValueName = 'NoDataExecutionPrevention'
            ValueData = 0
        }
    }
    
    if ($NoHeapTerminationOnCorruption) {
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\Explorer\NoHeapTerminationOnCorruption'
        {
            Key = '\Software\Policies\Microsoft\Windows\Explorer'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
            ValueName = 'NoHeapTerminationOnCorruption'
            ValueData = 0
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
    if ($SafeForScripting) {
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\Installer\SafeForScripting'
        {
            Key = '\Software\Policies\Microsoft\Windows\Installer'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
            ValueName = 'SafeForScripting'
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
    
    if ($HardenedPathsSYSVOL) {
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\NetworkProvider\HardenedPaths\*\SYSVOL'
        {
            Key = '\Software\Policies\Microsoft\Windows\NetworkProvider\HardenedPaths'
            ValueType = 'String'
            TargetType = 'ComputerConfiguration'
            ValueName = '\\*\SYSVOL'
            ValueData = 'RequireMutualAuthentication=1, RequireIntegrity=1'
        }
    }
    
    if ($HardenedPathsNETLOGON) {
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\NetworkProvider\HardenedPaths\*\NETLOGON'
        {
            Key = '\Software\Policies\Microsoft\Windows\NetworkProvider\HardenedPaths'
            ValueType = 'String'
            TargetType = 'ComputerConfiguration'
            ValueName = '\\*\NETLOGON'
            ValueData = 'RequireMutualAuthentication=1, RequireIntegrity=1'
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

    if (-not $EnableScriptBlockInvocationLogging) {
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
    
    if ($SetOutputDirectory) {
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\PowerShell\Transcription\OutputDirectory'
        {
            Key = '\Software\Policies\Microsoft\Windows\PowerShell\Transcription'
            ValueType = 'String'
            TargetType = 'ComputerConfiguration'
            ValueName = 'OutputDirectory'
            ValueData = 'C:\ProgramData\PS_Transcript'
        }
    }
    
    if (-not $EnableInvocationHeader) {
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
    
    if ($BlockShellSmartScreen) {
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\System\ShellSmartScreenLevel'
        {
            Key = '\Software\Policies\Microsoft\Windows\System'
            ValueType = 'String'
            TargetType = 'ComputerConfiguration'
            ValueName = 'ShellSmartScreenLevel'
            ValueData = 'Block'
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
    
    if ($AllowBasic) {
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\WinRM\Client\AllowBasic'
        {
            Key = '\Software\Policies\Microsoft\Windows\WinRM\Client'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
            ValueName = 'AllowBasic'
            ValueData = 0
        }
    }
    
    if ($AllowUnencryptedTraffic) {
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\WinRM\Client\AllowUnencryptedTraffic'
        {
            Key = '\Software\Policies\Microsoft\Windows\WinRM\Client'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
            ValueName = 'AllowUnencryptedTraffic'
            ValueData = 0
        }
    }

    if (-not $AllowDigest) {
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\WinRM\Client\AllowDigest'
        {
            Key = '\Software\Policies\Microsoft\Windows\WinRM\Client'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
            ValueName = 'AllowDigest'
            ValueData = 0
        }
    }
    
    if (-not $AllowBasicWinRMService) {
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\WinRM\Service\AllowBasic'
        {
            Key = '\Software\Policies\Microsoft\Windows\WinRM\Service'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
            ValueName = 'AllowBasic'
            ValueData = 0
        }
    }
    
    if (-not $AllowUnencryptedTrafficService) {
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
    
    if (-not $UseLogonCredential) {
        RegistryPolicyFile 'Registry(POL): HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest\UseLogonCredential'
        {
            Key = '\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
            ValueName = 'UseLogonCredential'
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

    if (-not $SMB1) {
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
    
    if (-not $EnableICMPRedirect) {
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
    
    if ($AuditOtherAccountManagementEventsSuccess) {
        AuditPolicySubcategory 'Audit Other Account Management Events (Success) - Inclusion'
        {
            Ensure = 'Present'
            Name = 'Other Account Management Events'
            AuditFlag = 'Success'
        }
    }
    
    if (-not $AuditOtherAccountManagementEventsFailure) {
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
    
    if (-not $AuditSecurityGroupManagementFailure) {
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

    if ($AuditPnpActivitySuccess) {
        AuditPolicySubcategory 'Audit PNP Activity (Success) - Inclusion'
        {
            Ensure = 'Present'
            Name = 'Plug and Play Events'
            AuditFlag = 'Success'
        }
    }
    
    if (-not $AuditPnpActivityFailure) {
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
    
    if (-not $AuditProcessCreationFailure) {
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
    
    if (-not $AuditAccountLockoutSuccess) {
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
    
    if (-not $AuditGroupMembershipFailure) {
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
    
    if (-not $AuditLogoffFailure) {
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
    
    if (-not $AuditSpecialLogonFailure) {
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
    
    if (-not $AuditAuthenticationPolicyChangeFailure) {
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
    
    if (-not $AuditAuthorizationPolicyChangeFailure) {
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
    
    if ($AuditIpsecDriverSuccess) {
        AuditPolicySubcategory 'Audit IPsec Driver (Success) - Inclusion'
        {
            Ensure = 'Present'
            Name = 'IPsec Driver'
            AuditFlag = 'Success'
        }
    }
    
    if ($AuditIpsecDriverFailure) {
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
    
    if (-not $AuditSecurityStateChangeFailure) {
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
    
    if (-not $AuditSecuritySystemExtensionFailure) {
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
    
    if (-not $AuditComputerAccountManagementFailure) {
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
    
    if (-not $AuditDirectoryServiceChangesFailure) {
        AuditPolicySubcategory 'Audit Directory Service Changes (Failure) - Inclusion'
        {
            Ensure = 'Absent'
            Name = 'Directory Service Changes'
            AuditFlag = 'Failure'
        }
    }

    if ($RestrictClientsToSAM) {
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
    
    if ($RequireStrongSessionKey) {
        SecurityOption 'SecurityRegistry(INF): Domain_member_Require_strong_Windows_2000_or_later_session_key'
        {
            Name = 'Domain_member_Require_strong_Windows_2000_or_later_session_key'
            Domain_member_Require_strong_Windows_2000_or_later_session_key = 'Enabled'
        }
    }
    
    if ($ElevateUIAccessApplications) {
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
    
    if ($ConfigureKerberosEncryptionTypes) {
        SecurityOption 'SecurityRegistry(INF): Network_security_Configure_encryption_types_allowed_for_Kerberos'
        {
            Network_security_Configure_encryption_types_allowed_for_Kerberos = 'AES256_HMAC_SHA1'
            Name = 'Network_security_Configure_encryption_types_allowed_for_Kerberos'
        }
    }
    
    if ($DigitallySignCommunications) {
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

    if ($LanManagerAuthenticationLevel) {
        SecurityOption 'SecurityRegistry(INF): Network_security_LAN_Manager_authentication_level'
        {
            Network_security_LAN_Manager_authentication_level = 'Send NTLMv2 responses only. Refuse LM & NTLM'
            Name = 'Network_security_LAN_Manager_authentication_level'
        }
    }
    
    if ($AllowLocalSystemNTLM) {
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
    
    if ($DigitallySignSecureChannelData) {
        SecurityOption 'SecurityRegistry(INF): Domain_member_Digitally_sign_secure_channel_data_when_possible'
        {
            Domain_member_Digitally_sign_secure_channel_data_when_possible = 'Enabled'
            Name = 'Domain_member_Digitally_sign_secure_channel_data_when_possible'
        }
    }
    
    if (-not $AllowUIAccessElevateWithoutSecureDesktop) {
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
    
    if ($LimitLocalAccountBlankPasswords) {
        SecurityOption 'SecurityRegistry(INF): Accounts_Limit_local_account_use_of_blank_passwords_to_console_logon_only'
        {
            Name = 'Accounts_Limit_local_account_use_of_blank_passwords_to_console_logon_only'
            Accounts_Limit_local_account_use_of_blank_passwords_to_console_logon_only = 'Enabled'
        }
    }
    
    if ($VirtualizeFileAndRegistryWriteFailures) {
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
    
    if (-not $LetEveryonePermissionsApplyToAnonymousUsers) {
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
    
    if (-not $ElevationPromptBehavior) {
        SecurityOption 'SecurityRegistry(INF): User_Account_Control_Behavior_of_the_elevation_prompt_for_standard_users'
        {
            User_Account_Control_Behavior_of_the_elevation_prompt_for_standard_users = 'Automatically deny elevation request'
            Name = 'User_Account_Control_Behavior_of_the_elevation_prompt_for_standard_users'
        }
    }
    
    if ($DigitallySignCommunicationsAlwaysServer) {
        SecurityOption 'SecurityRegistry(INF): Microsoft_network_server_Digitally_sign_communications_always'
        {
            Microsoft_network_server_Digitally_sign_communications_always = 'Enabled'
            Name = 'Microsoft_network_server_Digitally_sign_communications_always'
        }
    }
    
    if ($ForceStrongKeyProtection) {
        SecurityOption 'SecurityRegistry(INF): System_cryptography_Force_strong_key_protection_for_user_keys_stored_on_the_computer'
        {
            Name = 'System_cryptography_Force_strong_key_protection_for_user_keys_stored_on_the_computer'
            System_cryptography_Force_strong_key_protection_for_user_keys_stored_on_the_computer = 'User must enter a password each time they use a key'
        }
    }
    
    if ($DigitallySignCommunicationsAlwaysClient) {
        SecurityOption 'SecurityRegistry(INF): Microsoft_network_client_Digitally_sign_communications_always'
        {
            Microsoft_network_client_Digitally_sign_communications_always = 'Enabled'
            Name = 'Microsoft_network_client_Digitally_sign_communications_always'
        }
    }

    if ($MinimumSessionSecurityNTLM) {
        SecurityOption 'SecurityRegistry(INF): Network_security_Minimum_session_security_for_NTLM_SSP_based_including_secure_RPC_clients'
        {
            Name = 'Network_security_Minimum_session_security_for_NTLM_SSP_based_including_secure_RPC_clients'
            Network_security_Minimum_session_security_for_NTLM_SSP_based_including_secure_RPC_clients = 'Both options checked'
        }
    }
    
    if (-not $DisableMachineAccountPasswordChanges) {
        SecurityOption 'SecurityRegistry(INF): Domain_member_Disable_machine_account_password_changes'
        {
            Domain_member_Disable_machine_account_password_changes = 'Disabled'
            Name = 'Domain_member_Disable_machine_account_password_changes'
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
    
    if ($DetectApplicationInstallationsPromptForElevation) {
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
    
    if (-not $AllowLocalSystemNullSessionFallback) {
        SecurityOption 'SecurityRegistry(INF): Network_security_Allow_LocalSystem_NULL_session_fallback'
        {
            Name = 'Network_security_Allow_LocalSystem_NULL_session_fallback'
            Network_security_Allow_LocalSystem_NULL_session_fallback = 'Disabled'
        }
    }

    if ($AdminApprovalModeForBuiltInAdmin) {
        SecurityOption 'SecurityRegistry(INF): User_Account_Control_Admin_Approval_Mode_for_the_Built_in_Administrator_account'
        {
            User_Account_Control_Admin_Approval_Mode_for_the_Built_in_Administrator_account = 'Enabled'
            Name = 'User_Account_Control_Admin_Approval_Mode_for_the_Built_in_Administrator_account'
        }
    }
    
    if (-not $SendUnencryptedPasswordToThirdPartySMBServers) {
        SecurityOption 'SecurityRegistry(INF): Microsoft_network_client_Send_unencrypted_password_to_third_party_SMB_servers'
        {
            Microsoft_network_client_Send_unencrypted_password_to_third_party_SMB_servers = 'Disabled'
            Name = 'Microsoft_network_client_Send_unencrypted_password_to_third_party_SMB_servers'
        }
    }
    
    if ($PreviousLogonsToCache) {
        SecurityOption 'SecurityRegistry(INF): Interactive_logon_Number_of_previous_logons_to_cache_in_case_domain_controller_is_not_available'
        {
            Interactive_logon_Number_of_previous_logons_to_cache_in_case_domain_controller_is_not_available = '4'
            Name = 'Interactive_logon_Number_of_previous_logons_to_cache_in_case_domain_controller_is_not_available'
        }
    }
    
    if ($MaximumMachineAccountPasswordAge) {
        SecurityOption 'SecurityRegistry(INF): Domain_member_Maximum_machine_account_password_age'
        {
            Name = 'Domain_member_Maximum_machine_account_password_age'
            Domain_member_Maximum_machine_account_password_age = '30'
        }
    }
    
    if ($DoNotAllowAnonymousEnumerationOfSAMAccountsAndShares) {
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
    
    if ($StrengthenDefaultPermissionsOfInternalSystemObjects) {
        SecurityOption 'SecurityRegistry(INF): System_objects_Strengthen_default_permissions_of_internal_system_objects_eg_Symbolic_Links'
        {
            System_objects_Strengthen_default_permissions_of_internal_system_objects_eg_Symbolic_Links = 'Enabled'
            Name = 'System_objects_Strengthen_default_permissions_of_internal_system_objects_eg_Symbolic_Links'
        }
    }

    if ($Allow_PKUL2U_Authentication) {
        SecurityOption 'SecurityRegistry(INF): Network_Security_Allow_PKU2U_authentication_requests_to_this_computer_to_use_online_identities'
        {
            Network_Security_Allow_PKU2U_authentication_requests_to_this_computer_to_use_online_identities = 'Disabled'
            Name = 'Network_Security_Allow_PKU2U_authentication_requests_to_this_computer_to_use_online_identities'
        }
    }
    
    if ($Machine_Inactivity_Limit) {
        SecurityOption 'SecurityRegistry(INF): Interactive_logon_Machine_inactivity_limit'
        {
            Name = 'Interactive_logon_Machine_inactivity_limit'
            Interactive_logon_Machine_inactivity_limit = '900'
        }
    }
    
    if ($Do_Not_Store_LM_Hash) {
        SecurityOption 'SecurityRegistry(INF): Network_security_Do_not_store_LAN_Manager_hash_value_on_next_password_change'
        {
            Name = 'Network_security_Do_not_store_LAN_Manager_hash_value_on_next_password_change'
            Network_security_Do_not_store_LAN_Manager_hash_value_on_next_password_change = 'Enabled'
        }
    }
    
    if ($Encrypt_Secure_Channel_Data) {
        SecurityOption 'SecurityRegistry(INF): Domain_member_Digitally_encrypt_or_sign_secure_channel_data_always'
        {
            Domain_member_Digitally_encrypt_or_sign_secure_channel_data_always = 'Enabled'
            Name = 'Domain_member_Digitally_encrypt_or_sign_secure_channel_data_always'
        }
    }
    
    if ($LDAP_Client_Signing_Requirements) {
        SecurityOption 'SecurityRegistry(INF): Network_security_LDAP_client_signing_requirements'
        {
            Name = 'Network_security_LDAP_client_signing_requirements'
            Network_security_LDAP_client_signing_requirements = 'Negotiate Signing'
        }
    }
    
    if ($UAC_Elevation_Prompt_Behavior) {
        SecurityOption 'SecurityRegistry(INF): User_Account_Control_Behavior_of_the_elevation_prompt_for_administrators_in_Admin_Approval_Mode'
        {
            Name = 'User_Account_Control_Behavior_of_the_elevation_prompt_for_administrators_in_Admin_Approval_Mode'
            User_Account_Control_Behavior_of_the_elevation_prompt_for_administrators_in_Admin_Approval_Mode = 'Prompt for consent on the secure desktop'
        }
    }
    
    if ($Lockout_Duration) {
        AccountPolicy 'SecuritySetting(INF): LockoutDuration'
        {
            Account_lockout_duration = 15
            Name = 'Account_lockout_duration'
        }
    }
    
    if ($Lockout_Bad_Count) {
        AccountPolicy 'SecuritySetting(INF): LockoutBadCount'
        {
            Account_lockout_threshold = 3
            Name = 'Account_lockout_threshold'
        }
    }
    if ($Reset_Lockout_Count) {
        AccountPolicy 'SecuritySetting(INF): ResetLockoutCount'
        {
            Reset_account_lockout_counter_after = 15
            Name = 'Reset_account_lockout_counter_after'
        }
    }
    
    if ($Rename_Guest_Account) {
        SecurityOption 'SecuritySetting(INF): NewGuestName'
        {
            Name = 'Accounts_Rename_guest_account'
            Accounts_Rename_guest_account = 'Visitor'
        }
    }
    
    if ($Minimum_Password_Age) {
        AccountPolicy 'SecuritySetting(INF): MinimumPasswordAge'
        {
            Name = 'Minimum_Password_Age'
            Minimum_Password_Age = 1
        }
    }
    
    if ($Password_Complexity) {
        AccountPolicy 'SecuritySetting(INF): PasswordComplexity'
        {
            Password_must_meet_complexity_requirements = 'Enabled'
            Name = 'Password_must_meet_complexity_requirements'
        }
    }
    
    if ($Password_History_Size) {
        AccountPolicy 'SecuritySetting(INF): PasswordHistorySize'
        {
            Name = 'Enforce_password_history'
            Enforce_password_history = 24
        }
    }
    
    if ($LSA_Anonymous_Name_Lookup) {
        SecurityOption 'SecuritySetting(INF): LSAAnonymousNameLookup'
        {
            Network_access_Allow_anonymous_SID_Name_translation = 'Disabled'
            Name = 'Network_access_Allow_anonymous_SID_Name_translation'
        }
    }
    
    if ($Minimum_Password_Length) {
        AccountPolicy 'SecuritySetting(INF): MinimumPasswordLength'
        {
            Name = 'Minimum_Password_Length'
            Minimum_Password_Length = 14
        }
    }

    if ($Rename_Administrator_Account) {
        SecurityOption 'SecuritySetting(INF): NewAdministratorName'
        {
            Accounts_Rename_administrator_account = 'X_Admin'
            Name = 'Accounts_Rename_administrator_account'
        }
    }
    
    if ($Enable_Guest_Account) {
        SecurityOption 'SecuritySetting(INF): EnableGuestAccount'
        {
            Name = 'Accounts_Guest_account_status'
            Accounts_Guest_account_status = 'Disabled'
        }
    }
    
    if ($Maximum_Password_Age) {
        AccountPolicy 'SecuritySetting(INF): MaximumPasswordAge'
        {
            Maximum_Password_Age = 60
            Name = 'Maximum_Password_Age'
        }
    }
    
    if ($Clear_Text_Password) {
        AccountPolicy 'SecuritySetting(INF): ClearTextPassword'
        {
            Name = 'Store_passwords_using_reversible_encryption'
            Store_passwords_using_reversible_encryption = 'Disabled'
        }
    }
    
    if ($Trusted_For_Delegation) {
        UserRightsAssignment 'UserRightsAssignment(INF): Enable_computer_and_user_accounts_to_be_trusted_for_delegation'
        {
            Force = $True
            Identity = @('')
            Policy = 'Enable_computer_and_user_accounts_to_be_trusted_for_delegation'
        }
    }
    
    if ($Access_From_Network) {
        UserRightsAssignment 'UserRightsAssignment(INF): Access_this_computer_from_the_network'
        {
            Force = $True
            Identity = @('*S-1-5-11', '*S-1-5-32-544')
            Policy = 'Access_this_computer_from_the_network'
        }
    }
    
    if ($Backup_Files_And_Directories) {
        UserRightsAssignment 'UserRightsAssignment(INF): Back_up_files_and_directories'
        {
            Force = $True
            Identity = @('*S-1-5-32-544')
            Policy = 'Back_up_files_and_directories'
        }
    }

    if ($Impersonate_Client_After_Authentication) {
        UserRightsAssignment 'UserRightsAssignment(INF): Impersonate_a_client_after_authentication'
        {
            Force = $True
            Identity = @('*S-1-5-6', '*S-1-5-20', '*S-1-5-19', '*S-1-5-32-544')
            Policy = 'Impersonate_a_client_after_authentication'
        }
    }
    
    if ($Perform_Volume_Maintenance_Tasks) {
        UserRightsAssignment 'UserRightsAssignment(INF): Perform_volume_maintenance_tasks'
        {
            Force = $True
            Identity = @('*S-1-5-32-544')
            Policy = 'Perform_volume_maintenance_tasks'
        }
    }
    
    if ($Load_Unload_Device_Drivers) {
        UserRightsAssignment 'UserRightsAssignment(INF): Load_and_unload_device_drivers'
        {
            Force = $True
            Identity = @('*S-1-5-32-544')
            Policy = 'Load_and_unload_device_drivers'
        }
    }
    
    if ($Take_Ownership_Of_Files) {
        UserRightsAssignment 'UserRightsAssignment(INF): Take_ownership_of_files_or_other_objects'
        {
            Force = $True
            Identity = @('*S-1-5-32-544')
            Policy = 'Take_ownership_of_files_or_other_objects'
        }
    }
    
    if ($Create_Permanent_Shared_Objects) {
        UserRightsAssignment 'UserRightsAssignment(INF): Create_permanent_shared_objects'
        {
            Force = $True
            Identity = @('')
            Policy = 'Create_permanent_shared_objects'
        }
    }
    
    if ($Deny_Access_From_Network) {
        UserRightsAssignment 'UserRightsAssignment(INF): Deny_access_to_this_computer_from_the_network'
        {
            Force = $True
            Identity = @($DomainAdmins, $EnterpriseAdmins, '*S-1-5-32-546', '*S-1-5-114')
            Policy = 'Deny_access_to_this_computer_from_the_network'
        }
    }

    if ($Create_Global_Objects) {
        UserRightsAssignment 'UserRightsAssignment(INF): Create_global_objects'
        {
            Force = $True
            Identity = @('*S-1-5-32-544', '*S-1-5-19', '*S-1-5-20', '*S-1-5-6')
            Policy = 'Create_global_objects'
        }
    }
    
    if ($Deny_Log_On_As_Batch_Job) {
        UserRightsAssignment 'UserRightsAssignment(INF): Deny_log_on_as_a_batch_job'
        {
            Force = $True
            Identity = @($DomainAdmins, $EnterpriseAdmins, '*S-1-5-32-546')
            Policy = 'Deny_log_on_as_a_batch_job'
        }
    }
    
    if ($Restore_Files_And_Directories) {
        UserRightsAssignment 'UserRightsAssignment(INF): Restore_files_and_directories'
        {
            Force = $True
            Identity = @('*S-1-5-32-544')
            Policy = 'Restore_files_and_directories'
        }
    }
    
    if ($Lock_Pages_In_Memory) {
        UserRightsAssignment 'UserRightsAssignment(INF): Lock_pages_in_memory'
        {
            Force = $True
            Identity = @('')
            Policy = 'Lock_pages_in_memory'
        }
    }
    
    if ($Deny_Log_On_As_Service) {
        UserRightsAssignment 'UserRightsAssignment(INF): Deny_log_on_as_a_service'
        {
            Force = $True
            Identity = @($DomainAdmins, $EnterpriseAdmins)
            Policy = 'Deny_log_on_as_a_service'
        }
    }

    if ($Increase_Scheduling_Priority) {
        UserRightsAssignment 'UserRightsAssignment(INF): Increase_scheduling_priority'
        {
            Force = $True
            Identity = @('*S-1-5-32-544')
            Policy = 'Increase_scheduling_priority'
        }
    }
    
    if ($Force_Shutdown_From_Remote_System) {
        UserRightsAssignment 'UserRightsAssignment(INF): Force_shutdown_from_a_remote_system'
        {
            Force = $True
            Identity = @('*S-1-5-32-544')
            Policy = 'Force_shutdown_from_a_remote_system'
        }
    }
    
    if ($Generate_Security_Audits) {
        UserRightsAssignment 'UserRightsAssignment(INF): Generate_security_audits'
        {
            Force = $True
            Identity = @('*S-1-5-20', '*S-1-5-19')
            Policy = 'Generate_security_audits'
        }
    }
    
    if ($Deny_Log_On_Locally) {
        UserRightsAssignment 'UserRightsAssignment(INF): Deny_log_on_locally'
        {
            Force = $True
            Identity = @($DomainAdmins, $EnterpriseAdmins, '*S-1-5-32-546')
            Policy = 'Deny_log_on_locally'
        }
    }
    
    if ($Create_Symbolic_Links) {
        UserRightsAssignment 'UserRightsAssignment(INF): Create_symbolic_links'
        {
            Force = $True
            Identity = @('*S-1-5-32-544')
            Policy = 'Create_symbolic_links'
        }
    }
    
    if ($Debug_Programs) {
        UserRightsAssignment 'UserRightsAssignment(INF): Debug_programs'
        {
            Force = $True
            Identity = @('*S-1-5-32-544')
            Policy = 'Debug_programs'
        }
    }
    
    if ($Allow_Log_On_Locally) {
        UserRightsAssignment 'UserRightsAssignment(INF): Allow_log_on_locally'
        {
            Force = $True
            Identity = @('*S-1-5-32-544')
            Policy = 'Allow_log_on_locally'
        }
    }

    if ($Manage_Auditing_And_Security_Log) {
        UserRightsAssignment 'UserRightsAssignment(INF): Manage_auditing_and_security_log'
        {
            Force = $True
            Identity = @('*S-1-5-32-544')
            Policy = 'Manage_auditing_and_security_log'
        }
    }
    
    if ($Act_As_Part_Of_Operating_System) {
        UserRightsAssignment 'UserRightsAssignment(INF): Act_as_part_of_the_operating_system'
        {
            Force = $True
            Identity = @('')
            Policy = 'Act_as_part_of_the_operating_system'
        }
    }
    
    if ($Profile_Single_Process) {
        UserRightsAssignment 'UserRightsAssignment(INF): Profile_single_process'
        {
            Force = $True
            Identity = @('*S-1-5-32-544')
            Policy = 'Profile_single_process'
        }
    }
    
    if ($Create_Token_Object) {
        UserRightsAssignment 'UserRightsAssignment(INF): Create_a_token_object'
        {
            Force = $True
            Identity = @('')
            Policy = 'Create_a_token_object'
        }
    }
    
    if ($Access_Credential_Manager) {
        UserRightsAssignment 'UserRightsAssignment(INF): Access_Credential_Manager_as_a_trusted_caller'
        {
            Force = $True
            Identity = @('')
            Policy = 'Access_Credential_Manager_as_a_trusted_caller'
        }
    }
    
    if ($Modify_Firmware_Environment_Values) {
        UserRightsAssignment 'UserRightsAssignment(INF): Modify_firmware_environment_values'
        {
            Force = $True
            Identity = @('*S-1-5-32-544')
            Policy = 'Modify_firmware_environment_values'
        }
    }
    
    if ($Create_Pagefile) {
        UserRightsAssignment 'UserRightsAssignment(INF): Create_a_pagefile'
        {
            Force = $True
            Identity = @('*S-1-5-32-544')
            Policy = 'Create_a_pagefile'
        }
    }
    
    if ($Deny_Log_On_Through_RDS) {
        UserRightsAssignment 'UserRightsAssignment(INF): Deny_log_on_through_Remote_Desktop_Services'
        {
            Force = $True
            Identity = @($DomainAdmins, $EnterpriseAdmins, '*S-1-5-32-546', '*S-1-5-113')
            Policy = 'Deny_log_on_through_Remote_Desktop_Services'
        }
    }

    if ($Add_Workstations_To_Domain) {
        UserRightsAssignment 'UserRightsAssignment(INF): Add_workstations_to_domain'
        {
            Force = $True
            Identity = @('*S-1-5-32-544')
            Policy = 'Add_workstations_to_domain'
        }
    }
    
    if ($Allow_Log_On_Through_RDS) {
        UserRightsAssignment 'UserRightsAssignment(INF): Allow_log_on_through_Remote_Desktop_Services'
        {
            Force = $True
            Identity = @('*S-1-5-32-544')
            Policy = 'Allow_log_on_through_Remote_Desktop_Services'
        }
    }
    
    if ($LDAP_Server_Signing_Requirements) {
        SecurityOption 'SecurityRegistry(INF): Domain_controller_LDAP_server_signing_requirements'
        {
            Domain_controller_LDAP_server_signing_requirements = 'Require Signing'
            Name = 'Domain_controller_LDAP_server_signing_requirements'
        }
    }
    
    if ($Refuse_Machine_Account_Password_Changes) {
        SecurityOption 'SecurityRegistry(INF): Domain_controller_Refuse_machine_account_password_changes'
        {
            Name = 'Domain_controller_Refuse_machine_account_password_changes'
            Domain_controller_Refuse_machine_account_password_changes = 'Disabled'
        }
    }
    
    if ($Ticket_Validate_Client) {
        AccountPolicy 'SecuritySetting(INF): TicketValidateClient'
        {
            Enforce_user_logon_restrictions = 'Enabled'
            Name = 'Enforce_user_logon_restrictions'
        }
    }
    
    if ($Max_Renew_Age) {
        AccountPolicy 'SecuritySetting(INF): MaxRenewAge'
        {
            Maximum_lifetime_for_user_ticket_renewal = 8
            Name = 'Maximum_lifetime_for_user_ticket_renewal'
        }
    }

    
}

