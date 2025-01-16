configuration DoD_Windows_10_v3r2
{

    param(
        [string]$EnterpriseAdmins,
        [string]$DomainAdmins,
        [bool]$BatFile_SuppressionPolicy = $true,
        [bool]$CmdFile_SuppressionPolicy = $true,
        [bool]$ExeFile_SuppressionPolicy = $true,
        [bool]$MscFile_SuppressionPolicy = $true,
        [bool]$AutoConnectAllowedOEM = $true,
        [bool]$EnumerateAdministrators = $true,
        [bool]$NoWebServices = $true,
        [bool]$NoAutorun = $true,
        [bool]$NoDriveTypeAutoRun = $true,
        [bool]$NoStartBanner = $true,
        [bool]$PreXPSP2ShellProtocolBehavior = $true,
        [bool]$PasswordComplexity = $true,
        [bool]$PasswordLength = $true,
        [bool]$PasswordAgeDays = $true,
        [bool]$MSAOptional = $true,
        [bool]$DisableAutomaticRestartSignOn = $true,
        [bool]$LocalAccountTokenFilterPolicy = $true,
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
        [bool]$PreventCertErrorOverrides = $true,
        [bool]$FormSuggest_Passwords = $true,
        [bool]$EnabledV9 = $true,
        [bool]$PreventOverrideAppRepUnknown = $true,
        [bool]$PreventOverride = $true,
        [bool]$RequireSecurityDevice = $true,
        [bool]$ExcludeSecurityDevices_TPM12 = $true,
        [bool]$MinimumPINLength = $true,
        [bool]$DCSettingIndex = $true,
        [bool]$ACSettingIndex = $true,
        [bool]$DisableInventory = $true,
        [bool]$LetAppsActivateWithVoiceAboveLock = $true,
        [bool]$DisableWindowsConsumerFeatures = $true,
        [bool]$AllowProtectedCreds = $true,
        [bool]$AllowTelemetry = $true,
        [bool]$LimitEnhancedDiagnosticDataWindowsAnalytics = $true,
        [bool]$DODownloadMode = $true,
        [bool]$EnableVirtualizationBasedSecurity = $true,
        [bool]$RequirePlatformSecurityFeatures = $true,
        [bool]$HypervisorEnforcedCodeIntegrity = $true,
        [bool]$HVCIMATRequired = $true,
        [bool]$LsaCfgFlags = $true,
        [bool]$ConfigureSystemGuardLaunch = $true,
        [bool]$MaxSize_Application = $true,
        [bool]$MaxSize_Security = $true,
        [bool]$MaxSize_System = $true,
        [bool]$NoAutoplayfornonVolume = $true,
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
        [bool]$fBlockNonDomain = $true,
        [bool]$fMinimizeConnections = $true,
        [bool]$AllowIndexingEncryptedStoresOrItems = $true,
        [bool]$AllowBasic_Client = $true,
        [bool]$AllowUnencryptedTraffic_Client = $true,
        [bool]$AllowDigest_Client = $true,
        [bool]$AllowBasic_Service = $true,
        [bool]$AllowUnencryptedTraffic_Service = $true,
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
        [bool]$Start_MrxSmb10 = $true,
        [bool]$NoNameReleaseOnDemand = $true,
        [bool]$DisableIPSourceRouting = $true,
        [bool]$EnableICMPRedirect = $true,
        [bool]$DisableIPSourceRouting_Tcpip6 = $true,
        [bool]$AuditCredentialValidationSuccess = $true,
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
        [bool]$AuditPolicyChangeSuccess = $true,
        [bool]$AuditPolicyChangeFailure = $true,
        [bool]$AuditAuthenticationPolicyChangeSuccess = $true,
        [bool]$AuditAuthenticationPolicyChangeFailure = $true,
        [bool]$AuditAuthorizationPolicyChangeSuccess = $true,
        [bool]$AuditAuthorizationPolicyChangeFailure = $true,
        [bool]$AuditMPSSVCRuleLevelPolicyChangeSuccess = $true,
        [bool]$AuditMPSSVCRuleLevelPolicyChangeFailure = $true,
        [bool]$AuditOtherPolicyChangeEventsFailure = $true,
        [bool]$AuditOtherPolicyChangeEventsSuccess = $true,
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
        [bool]$EnableComputerAndUserAccountsToBeTrustedForDelegation = $true,
        [bool]$AccessThisComputerFromTheNetwork = $true,
        [bool]$BackupFilesAndDirectories = $true,
        [bool]$Impersonate_a_client_after_authentication = $true,
        [bool]$Perform_volume_maintenance_tasks = $true,
        [bool]$Load_and_unload_device_drivers = $true,
        [bool]$Lock_pages_in_memory = $true,
        [bool]$Take_ownership_of_files_or_other_objects = $true,
        [bool]$Create_permanent_shared_objects = $true,
        [bool]$Deny_access_to_this_computer_from_the_network = $true,
        [bool]$Create_global_objects = $true,
        [bool]$Deny_log_on_as_a_batch_job = $true,
        [bool]$Restore_files_and_directories = $true,
        [bool]$Access_Credential_Manager_as_a_trusted_caller = $true,
        [bool]$Deny_log_on_as_a_service = $true,
        [bool]$Force_shutdown_from_a_remote_system = $true,
        [bool]$Deny_log_on_locally = $true,
        [bool]$Create_symbolic_links = $true,
        [bool]$Debug_programs = $true,
        [bool]$Allow_log_on_locally = $true,
        [bool]$Manage_auditing_and_security_log = $true,
        [bool]$Act_as_part_of_the_operating_system = $true,
        [bool]$Profile_single_process = $true,
        [bool]$Create_a_token_object = $true,
        [bool]$Change_the_system_time = $true,
        [bool]$Modify_firmware_environment_values = $true,
        [bool]$Create_a_pagefile = $true,
        [bool]$Deny_log_on_through_Remote_Desktop_Services = $true,
        [bool]$Network_access_Restrict_clients_allowed_to_make_remote_calls_to_SAM = $true,
        [bool]$Network_access_Restrict_anonymous_access_to_Named_Pipes_and_Shares = $true,
        [bool]$Domain_member_Require_strong_Windows_2000_or_later_session_key = $true,
        [bool]$User_Account_Control_Only_elevate_UIAccess_applications_that_are_installed_in_secure_locations = $true,
        [bool]$Network_security_Minimum_session_security_for_NTLM_SSP_based_including_secure_RPC_servers = $true,
        [bool]$Network_security_Configure_encryption_types_allowed_for_Kerberos = $true,
        [bool]$System_cryptography_Use_FIPS_compliant_algorithms_for_encryption_hashing_and_signing = $true,
        [bool]$Network_security_LAN_Manager_authentication_level = $true,
        [bool]$Domain_member_Disable_machine_account_password_changes = $true,
        [bool]$Interactive_logon_Message_title_for_users_attempting_to_log_on = $true,
        [bool]$Domain_member_Digitally_sign_secure_channel_data_when_possible = $true,
        [bool]$Interactive_logon_Smart_card_removal_behavior = $true,
        [bool]$Accounts_Limit_local_account_use_of_blank_passwords_to_console_logon_only = $true,
        [bool]$User_Account_Control_Virtualize_file_and_registry_write_failures_to_per_user_locations = $true,
        [bool]$Interactive_logon_Message_text_for_users_attempting_to_log_on = $true,
        [bool]$Domain_member_Digitally_encrypt_secure_channel_data_when_possible = $true,
        [bool]$User_Account_Control_Behavior_of_the_elevation_prompt_for_standard_users = $true,
        [bool]$Microsoft_network_server_Digitally_sign_communications_always = $true,
        [bool]$Microsoft_network_client_Digitally_sign_communications_always = $true,
        [bool]$Network_security_Minimum_session_security_for_NTLM_SSP_based_including_secure_RPC_clients = $true,
        [bool]$User_Account_Control_Run_all_administrators_in_Admin_Approval_Mode = $true,
        [bool]$User_Account_Control_Detect_application_installations_and_prompt_for_elevation = $true,
        [bool]$Network_access_Do_not_allow_anonymous_enumeration_of_SAM_accounts = $true,
        [bool]$Network_security_Allow_LocalSystem_NULL_session_fallback = $true,
        [bool]$User_Account_Control_Admin_Approval_Mode_for_the_Built_in_Administrator_account = $true,
        [bool]$Microsoft_network_client_Send_unencrypted_password_to_third_party_SMB_servers = $true,
        [bool]$Interactive_logon_Number_of_previous_logons_to_cache_in_case_domain_controller_is_not_available = $true,
        [bool]$Domain_member_Maximum_machine_account_password_age = $true,
        [bool]$Network_access_Do_not_allow_anonymous_enumeration_of_SAM_accounts_and_shares = $true,
        [bool]$Audit_Force_audit_policy_subcategory_settings_Windows_Vista_or_later_to_override_audit_policy_category_settings = $true,
        [bool]$System_objects_Strengthen_default_permissions_of_internal_system_objects_eg_Symbolic_Links = $true,
        [bool]$Network_Security_Allow_PKU2U_authentication_requests_to_this_computer_to_use_online_identities = $true,
        [bool]$Domain_member_Digitally_encrypt_or_sign_secure_channel_data_always = $true,
        [bool]$Interactive_logon_Machine_inactivity_limit = $true,
        [bool]$Network_security_Do_not_store_LAN_Manager_hash_value_on_next_password_change = $true,
        [bool]$Network_access_Let_Everyone_permissions_apply_to_anonymous_users = $true,
        [bool]$Network_security_LDAP_client_signing_requirements = $true,
        [bool]$User_Account_Control_Behavior_of_the_elevation_prompt_for_administrators_in_Admin_Approval_Mode = $true,
        [bool]$Account_lockout_duration = $true,
        [bool]$Account_lockout_threshold = $true,
        [bool]$Reset_account_lockout_counter_after = $true,
        [bool]$Accounts_Rename_guest_account = $true,
        [bool]$Minimum_Password_Age = $true,
        [bool]$Password_must_meet_complexity_requirements = $true,
        [bool]$Enforce_password_history = $true,
        [bool]$Network_access_Allow_anonymous_SID_Name_translation = $true,
        [bool]$Minimum_Password_Length = $true,
        [bool]$Accounts_Administrator_account_status = $true,
        [bool]$Accounts_Rename_administrator_account = $true,
        [bool]$Accounts_Guest_account_status = $true,
        [bool]$Maximum_Password_Age = $true,
        [bool]$Store_passwords_using_reversible_encryption = $true
    )

    Import-DSCResource -ModuleName 'GPRegistryPolicyDsc'
	Import-DSCResource -ModuleName 'AuditPolicyDSC'
	Import-DSCResource -ModuleName 'SecurityPolicyDSC'

    if ($BatFile_SuppressionPolicy) {
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Classes\batfile\shell\runasuser\SuppressionPolicy'
        {
            Key = '\Software\Classes\batfile\shell\runasuser'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
            ValueName = 'SuppressionPolicy'
            ValueData = 4096
        }
    }
    
    if ($CmdFile_SuppressionPolicy) {
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Classes\cmdfile\shell\runasuser\SuppressionPolicy'
        {
            Key = '\Software\Classes\cmdfile\shell\runasuser'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
            ValueName = 'SuppressionPolicy'
            ValueData = 4096
        }
    }
    
    if ($ExeFile_SuppressionPolicy) {
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Classes\exefile\shell\runasuser\SuppressionPolicy'
        {
            Key = '\Software\Classes\exefile\shell\runasuser'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
            ValueName = 'SuppressionPolicy'
            ValueData = 4096
        }
    }
    
    if ($MscFile_SuppressionPolicy) {
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Classes\mscfile\shell\runasuser\SuppressionPolicy'
        {
            Key = '\Software\Classes\mscfile\shell\runasuser'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
            ValueName = 'SuppressionPolicy'
            ValueData = 4096
        }
    }
    
    if ($AutoConnectAllowedOEM) {
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Microsoft\wcmsvc\wifinetworkmanager\config\AutoConnectAllowedOEM'
        {
            Key = '\Software\Microsoft\wcmsvc\wifinetworkmanager\config'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
            ValueName = 'AutoConnectAllowedOEM'
            ValueData = 0
        }
    }
    
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

    if ($NoWebServices) {
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\NoWebServices'
        {
            Key = '\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
            ValueName = 'NoWebServices'
            ValueData = 1
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
    
    if ($NoStartBanner) {
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\NoStartBanner'
        {
            Key = '\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
            ValueName = 'NoStartBanner'
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
    
    if ($DevicePKInitEnabled) {
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\System\Kerberos\Parameters\DevicePKInitEnabled'
        {
            Key = '\Software\Microsoft\Windows\CurrentVersion\Policies\System\Kerberos\Parameters'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
            ValueName = 'DevicePKInitEnabled'
            ValueData = 1
        }
    }
    
    if ($DevicePKInitBehavior) {
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\System\Kerberos\Parameters\DevicePKInitBehavior'
        {
            Key = '\Software\Microsoft\Windows\CurrentVersion\Policies\System\Kerberos\Parameters'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
            ValueName = 'DevicePKInitBehavior'
            ValueData = 0
        }
    }
    
    if ($EnhancedAntiSpoofing) {
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Biometrics\FacialFeatures\EnhancedAntiSpoofing'
        {
            Key = '\Software\Policies\Microsoft\Biometrics\FacialFeatures'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
            ValueName = 'EnhancedAntiSpoofing'
            ValueData = 1
        }
    }

    if ($EccCurves) {
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Cryptography\Configuration\SSL\00010002\EccCurves'
        {
            Key = '\Software\Policies\Microsoft\Cryptography\Configuration\SSL\00010002'
            ValueType = 'MultiString'
            TargetType = 'ComputerConfiguration'
            ValueName = 'EccCurves'
            ValueData = 'NistP384NistP256'
        }
    }
    
    if ($UseAdvancedStartup) {
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\FVE\UseAdvancedStartup'
        {
            Key = '\Software\Policies\Microsoft\FVE'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
            ValueName = 'UseAdvancedStartup'
            ValueData = 1
        }
    }
    
    if ($EnableBDEWithNoTPM) {
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\FVE\EnableBDEWithNoTPM'
        {
            Key = '\Software\Policies\Microsoft\FVE'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
            ValueName = 'EnableBDEWithNoTPM'
            ValueData = 1
        }
    }
    
    if ($UseTPM) {
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\FVE\UseTPM'
        {
            Key = '\Software\Policies\Microsoft\FVE'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
            ValueName = 'UseTPM'
            ValueData = 2
        }
    }
    
    if ($UseTPMPIN) {
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\FVE\UseTPMPIN'
        {
            Key = '\Software\Policies\Microsoft\FVE'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
            ValueName = 'UseTPMPIN'
            ValueData = 1
        }
    }
    
    if ($UseTPMKey) {
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\FVE\UseTPMKey'
        {
            Key = '\Software\Policies\Microsoft\FVE'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
            ValueName = 'UseTPMKey'
            ValueData = 2
        }
    }

    if ($UseTPMKeyPIN) {
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\FVE\UseTPMKeyPIN'
        {
            Key = '\Software\Policies\Microsoft\FVE'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
            ValueName = 'UseTPMKeyPIN'
            ValueData = 2
        }
    }
    
    if ($MinimumPIN) {
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\FVE\MinimumPIN'
        {
            Key = '\Software\Policies\Microsoft\FVE'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
            ValueName = 'MinimumPIN'
            ValueData = 6
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
    
    if ($NotifyDisableIEOptions) {
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Internet Explorer\Main\NotifyDisableIEOptions'
        {
            Key = '\Software\Policies\Microsoft\Internet Explorer\Main'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
            ValueName = 'NotifyDisableIEOptions'
            ValueData = 0
        }
    }
    
    if ($PreventCertErrorOverrides) {
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\MicrosoftEdge\Internet Settings\PreventCertErrorOverrides'
        {
            Key = '\Software\Policies\Microsoft\MicrosoftEdge\Internet Settings'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
            ValueName = 'PreventCertErrorOverrides'
            ValueData = 1
        }
    }

    if ($FormSuggest_Passwords) {
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\MicrosoftEdge\Main\FormSuggest Passwords'
        {
            Key = '\Software\Policies\Microsoft\MicrosoftEdge\Main'
            ValueType = 'String'
            TargetType = 'ComputerConfiguration'
            ValueName = 'FormSuggest Passwords'
            ValueData = 'no'
        }
    }
    
    if ($EnabledV9) {
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\MicrosoftEdge\PhishingFilter\EnabledV9'
        {
            Key = '\Software\Policies\Microsoft\MicrosoftEdge\PhishingFilter'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
            ValueName = 'EnabledV9'
            ValueData = 1
        }
    }
    
    if ($PreventOverrideAppRepUnknown) {
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\MicrosoftEdge\PhishingFilter\PreventOverrideAppRepUnknown'
        {
            Key = '\Software\Policies\Microsoft\MicrosoftEdge\PhishingFilter'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
            ValueName = 'PreventOverrideAppRepUnknown'
            ValueData = 1
        }
    }
    
    if ($PreventOverride) {
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\MicrosoftEdge\PhishingFilter\PreventOverride'
        {
            Key = '\Software\Policies\Microsoft\MicrosoftEdge\PhishingFilter'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
            ValueName = 'PreventOverride'
            ValueData = 1
        }
    }
    
    if ($RequireSecurityDevice) {
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\PassportForWork\RequireSecurityDevice'
        {
            Key = '\Software\Policies\Microsoft\PassportForWork'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
            ValueName = 'RequireSecurityDevice'
            ValueData = 1
        }
    }
    
    if ($ExcludeSecurityDevices_TPM12) {
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\PassportForWork\ExcludeSecurityDevices\TPM12'
        {
            Key = '\Software\Policies\Microsoft\PassportForWork\ExcludeSecurityDevices'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
            ValueName = 'TPM12'
            ValueData = 0
        }
    }

    if ($MinimumPINLength) {
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\PassportForWork\PINComplexity\MinimumPINLength'
        {
            Key = '\Software\Policies\Microsoft\PassportForWork\PINComplexity'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
            ValueName = 'MinimumPINLength'
            ValueData = 6
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
    
    if ($LetAppsActivateWithVoiceAboveLock) {
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\AppPrivacy\LetAppsActivateWithVoiceAboveLock'
        {
            Key = '\Software\Policies\Microsoft\Windows\AppPrivacy'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
            ValueName = 'LetAppsActivateWithVoiceAboveLock'
            ValueData = 2
        }
    }
    
    if ($DisableWindowsConsumerFeatures) {
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\CloudContent\DisableWindowsConsumerFeatures'
        {
            Key = '\Software\Policies\Microsoft\Windows\CloudContent'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
            ValueName = 'DisableWindowsConsumerFeatures'
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
            ValueData = 2
        }
    }
    
    if ($LimitEnhancedDiagnosticDataWindowsAnalytics) {
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\DataCollection\LimitEnhancedDiagnosticDataWindowsAnalytics'
        {
            Key = '\Software\Policies\Microsoft\Windows\DataCollection'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
            ValueName = 'LimitEnhancedDiagnosticDataWindowsAnalytics'
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
            ValueData = 1
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
    
    if ($MaxSize_Application) {
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\EventLog\Application\MaxSize'
        {
            Key = '\Software\Policies\Microsoft\Windows\EventLog\Application'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
            ValueName = 'MaxSize'
            ValueData = 32768
        }
    }
    
    if ($MaxSize_Security) {
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\EventLog\Security\MaxSize'
        {
            Key = '\Software\Policies\Microsoft\Windows\EventLog\Security'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
            ValueName = 'MaxSize'
            ValueData = 1024000
        }
    }

    if ($MaxSize_System) {
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
    
    if ($AllowGameDVR) {
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\GameDVR\AllowGameDVR'
        {
            Key = '\Software\Policies\Microsoft\Windows\GameDVR'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
            ValueName = 'AllowGameDVR'
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
    
    if ($DeviceEnumerationPolicy) {
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\Kernel DMA Protection\DeviceEnumerationPolicy'
        {
            Key = '\Software\Policies\Microsoft\Windows\Kernel DMA Protection'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
            ValueName = 'DeviceEnumerationPolicy'
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

    if ($NC_ShowSharedAccessUI) {
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\Network Connections\NC_ShowSharedAccessUI'
        {
            Key = '\Software\Policies\Microsoft\Windows\Network Connections'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
            ValueName = 'NC_ShowSharedAccessUI'
            ValueData = 0
        }
    }
    
    if ($HardenedPaths_SYSVOL) {
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\NetworkProvider\HardenedPaths\*\SYSVOL'
        {
            Key = '\Software\Policies\Microsoft\Windows\NetworkProvider\HardenedPaths'
            ValueType = 'String'
            TargetType = 'ComputerConfiguration'
            ValueName = '\\*\SYSVOL'
            ValueData = 'RequireMutualAuthentication=1,RequireIntegrity=1'
        }
    }
    
    if ($HardenedPaths_NETLOGON) {
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\NetworkProvider\HardenedPaths\*\NETLOGON'
        {
            Key = '\Software\Policies\Microsoft\Windows\NetworkProvider\HardenedPaths'
            ValueType = 'String'
            TargetType = 'ComputerConfiguration'
            ValueName = '\\*\NETLOGON'
            ValueData = 'RequireMutualAuthentication=1,RequireIntegrity=1'
        }
    }
    
    if ($NoLockScreenCamera) {
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\Personalization\NoLockScreenCamera'
        {
            Key = '\Software\Policies\Microsoft\Windows\Personalization'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
            ValueName = 'NoLockScreenCamera'
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
    
    if ($ShellSmartScreenLevel) {
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\System\ShellSmartScreenLevel'
        {
            Key = '\Software\Policies\Microsoft\Windows\System'
            ValueType = 'String'
            TargetType = 'ComputerConfiguration'
            ValueName = 'ShellSmartScreenLevel'
            ValueData = 'Block'
        }
    }
    
    if ($AllowDomainPINLogon) {
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\System\AllowDomainPINLogon'
        {
            Key = '\Software\Policies\Microsoft\Windows\System'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
            ValueName = 'AllowDomainPINLogon'
            ValueData = 0
        }
    }
    
    if ($fBlockNonDomain) {
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\WcmSvc\GroupPolicy\fBlockNonDomain'
        {
            Key = '\Software\Policies\Microsoft\Windows\WcmSvc\GroupPolicy'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
            ValueName = 'fBlockNonDomain'
            ValueData = 1
        }
    }
    
    if ($fMinimizeConnections) {
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\WcmSvc\GroupPolicy\fMinimizeConnections'
        {
            Key = '\Software\Policies\Microsoft\Windows\WcmSvc\GroupPolicy'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
            ValueName = 'fMinimizeConnections'
            ValueData = 3
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
    
    if ($ShellSmartScreenLevel) {
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\System\ShellSmartScreenLevel'
        {
            Key = '\Software\Policies\Microsoft\Windows\System'
            ValueType = 'String'
            TargetType = 'ComputerConfiguration'
            ValueName = 'ShellSmartScreenLevel'
            ValueData = 'Block'
        }
    }
    
    if ($AllowDomainPINLogon) {
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\System\AllowDomainPINLogon'
        {
            Key = '\Software\Policies\Microsoft\Windows\System'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
            ValueName = 'AllowDomainPINLogon'
            ValueData = 0
        }
    }
    
    if ($fBlockNonDomain) {
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\WcmSvc\GroupPolicy\fBlockNonDomain'
        {
            Key = '\Software\Policies\Microsoft\Windows\WcmSvc\GroupPolicy'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
            ValueName = 'fBlockNonDomain'
            ValueData = 1
        }
    }
    
    if ($fMinimizeConnections) {
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\WcmSvc\GroupPolicy\fMinimizeConnections'
        {
            Key = '\Software\Policies\Microsoft\Windows\WcmSvc\GroupPolicy'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
            ValueName = 'fMinimizeConnections'
            ValueData = 3
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
    
    if ($AllowBasic_Client) {
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\WinRM\Client\AllowBasic'
        {
            Key = '\Software\Policies\Microsoft\Windows\WinRM\Client'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
            ValueName = 'AllowBasic'
            ValueData = 0
        }
    }
    
    if ($AllowUnencryptedTraffic_Client) {
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\WinRM\Client\AllowUnencryptedTraffic'
        {
            Key = '\Software\Policies\Microsoft\Windows\WinRM\Client'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
            ValueName = 'AllowUnencryptedTraffic'
            ValueData = 0
        }
    }
    
    if ($AllowDigest_Client) {
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\WinRM\Client\AllowDigest'
        {
            Key = '\Software\Policies\Microsoft\Windows\WinRM\Client'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
            ValueName = 'AllowDigest'
            ValueData = 0
        }
    }
    
    if ($AllowBasic_Service) {
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\WinRM\Service\AllowBasic'
        {
            Key = '\Software\Policies\Microsoft\Windows\WinRM\Service'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
            ValueName = 'AllowBasic'
            ValueData = 0
        }
    }
    
    if ($AllowUnencryptedTraffic_Service) {
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
    
    if ($fAllowToGetHelp) {
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows NT\Terminal Services\fAllowToGetHelp'
        {
            Key = '\Software\Policies\Microsoft\Windows NT\Terminal Services'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
            ValueName = 'fAllowToGetHelp'
            ValueData = 0
        }
    }
    
    if ($fAllowFullControl) {
        RegistryPolicyFile 'DEL_\Software\Policies\Microsoft\Windows NT\Terminal Services\fAllowFullControl'
        {
            Key = '\Software\Policies\Microsoft\Windows NT\Terminal Services'
            ValueType = 'String'
            Ensure = 'Absent'
            TargetType = 'ComputerConfiguration'
            ValueName = 'fAllowFullControl'
            ValueData = ''
        }
    }
    
    if ($MaxTicketExpiry) {
        RegistryPolicyFile 'DEL_\Software\Policies\Microsoft\Windows NT\Terminal Services\MaxTicketExpiry'
        {
            Key = '\Software\Policies\Microsoft\Windows NT\Terminal Services'
            ValueType = 'String'
            Ensure = 'Absent'
            TargetType = 'ComputerConfiguration'
            ValueName = 'MaxTicketExpiry'
            ValueData = ''
        }
    }
    
    if ($MaxTicketExpiryUnits) {
        RegistryPolicyFile 'DEL_\Software\Policies\Microsoft\Windows NT\Terminal Services\MaxTicketExpiryUnits'
        {
            Key = '\Software\Policies\Microsoft\Windows NT\Terminal Services'
            ValueType = 'String'
            Ensure = 'Absent'
            TargetType = 'ComputerConfiguration'
            ValueName = 'MaxTicketExpiryUnits'
            ValueData = ''
        }
    }

    if ($fUseMailto) {
        RegistryPolicyFile 'DEL_\Software\Policies\Microsoft\Windows NT\Terminal Services\fUseMailto'
        {
            Key = '\Software\Policies\Microsoft\Windows NT\Terminal Services'
            ValueType = 'String'
            Ensure = 'Absent'
            TargetType = 'ComputerConfiguration'
            ValueName = 'fUseMailto'
            ValueData = ''
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
    
    if ($AllowWindowsInkWorkspace) {
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\WindowsInkWorkspace\AllowWindowsInkWorkspace'
        {
            Key = '\Software\Policies\Microsoft\WindowsInkWorkspace'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
            ValueName = 'AllowWindowsInkWorkspace'
            ValueData = 1
        }
    }

    if ($UseLogonCredential) {
        RegistryPolicyFile 'Registry(POL): HKLM:\System\CurrentControlSet\Control\SecurityProviders\WDigest\UseLogonCredential'
        {
            Key = '\System\CurrentControlSet\Control\SecurityProviders\WDigest'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
            ValueName = 'UseLogonCredential'
            ValueData = 0
        }
    }
    
    if ($DisableExceptionChainValidation) {
        RegistryPolicyFile 'Registry(POL): HKLM:\System\CurrentControlSet\Control\Session Manager\kernel\DisableExceptionChainValidation'
        {
            Key = '\System\CurrentControlSet\Control\Session Manager\kernel'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
            ValueName = 'DisableExceptionChainValidation'
            ValueData = 0
        }
    }
    
    if ($DriverLoadPolicy) {
        RegistryPolicyFile 'Registry(POL): HKLM:\System\CurrentControlSet\Policies\EarlyLaunch\DriverLoadPolicy'
        {
            Key = '\System\CurrentControlSet\Policies\EarlyLaunch'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
            ValueName = 'DriverLoadPolicy'
            ValueData = 3
        }
    }
    
    if ($SMB1) {
        RegistryPolicyFile 'Registry(POL): HKLM:\System\CurrentControlSet\Services\LanmanServer\Parameters\SMB1'
        {
            Key = '\System\CurrentControlSet\Services\LanmanServer\Parameters'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
            ValueName = 'SMB1'
            ValueData = 0
        }
    }
    
    if ($Start_MrxSmb10) {
        RegistryPolicyFile 'Registry(POL): HKLM:\System\CurrentControlSet\Services\MrxSmb10\Start'
        {
            Key = '\System\CurrentControlSet\Services\MrxSmb10'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
            ValueName = 'Start'
            ValueData = 4
        }
    }
    
    if ($NoNameReleaseOnDemand) {
        RegistryPolicyFile 'Registry(POL): HKLM:\System\CurrentControlSet\Services\Netbt\Parameters\NoNameReleaseOnDemand'
        {
            Key = '\System\CurrentControlSet\Services\Netbt\Parameters'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
            ValueName = 'NoNameReleaseOnDemand'
            ValueData = 1
        }
    }
    
    if ($DisableIPSourceRouting) {
        RegistryPolicyFile 'Registry(POL): HKLM:\System\CurrentControlSet\Services\Tcpip\Parameters\DisableIPSourceRouting'
        {
            Key = '\System\CurrentControlSet\Services\Tcpip\Parameters'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
            ValueName = 'DisableIPSourceRouting'
            ValueData = 2
        }
    }

    if ($EnableICMPRedirect) {
        RegistryPolicyFile 'Registry(POL): HKLM:\System\CurrentControlSet\Services\Tcpip\Parameters\EnableICMPRedirect'
        {
            Key = '\System\CurrentControlSet\Services\Tcpip\Parameters'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
            ValueName = 'EnableICMPRedirect'
            ValueData = 0
        }
    }
    
    if ($DisableIPSourceRouting_Tcpip6) {
        RegistryPolicyFile 'Registry(POL): HKLM:\System\CurrentControlSet\Services\Tcpip6\Parameters\DisableIPSourceRouting'
        {
            Key = '\System\CurrentControlSet\Services\Tcpip6\Parameters'
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
    
    if ($AuditOtherPolicyChangeEventsFailure) {
        AuditPolicySubcategory 'Audit Other Policy Change Events (Failure) - Inclusion'
        {
            Ensure = 'Present'
            Name = 'Other Policy Change Events'
            AuditFlag = 'Failure'
        }
    }
    
    if ($AuditOtherPolicyChangeEventsSuccess) {
        AuditPolicySubcategory 'Audit Other Policy Change Events (Success) - Inclusion'
        {
            Ensure = 'Absent'
            Name = 'Other Policy Change Events'
            AuditFlag = 'Success'
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
    
    if ($EnableComputerAndUserAccountsToBeTrustedForDelegation) {
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
            Identity = @('*S-1-5-32-555', '*S-1-5-32-544')
            Policy = 'Access_this_computer_from_the_network'
        }
    }
    
    if ($BackupFilesAndDirectories) {
        UserRightsAssignment 'UserRightsAssignment(INF): Back_up_files_and_directories'
        {
            Force = $True
            Identity = @('*S-1-5-32-544')
            Policy = 'Back_up_files_and_directories'
        }
    }

    if ($Impersonate_a_client_after_authentication) {
        UserRightsAssignment 'UserRightsAssignment(INF): Impersonate_a_client_after_authentication'
        {
            Force = $True
            Identity = @('*S-1-5-6', '*S-1-5-20', '*S-1-5-19', '*S-1-5-32-544')
            Policy = 'Impersonate_a_client_after_authentication'
        }
    }
    
    if ($Perform_volume_maintenance_tasks) {
        UserRightsAssignment 'UserRightsAssignment(INF): Perform_volume_maintenance_tasks'
        {
            Force = $True
            Identity = @('*S-1-5-32-544')
            Policy = 'Perform_volume_maintenance_tasks'
        }
    }
    
    if ($Load_and_unload_device_drivers) {
        UserRightsAssignment 'UserRightsAssignment(INF): Load_and_unload_device_drivers'
        {
            Force = $True
            Identity = @('*S-1-5-32-544')
            Policy = 'Load_and_unload_device_drivers'
        }
    }
    
    if ($Lock_pages_in_memory) {
        UserRightsAssignment 'UserRightsAssignment(INF): Lock_pages_in_memory'
        {
            Force = $True
            Identity = @('')
            Policy = 'Lock_pages_in_memory'
        }
    }
    
    if ($Take_ownership_of_files_or_other_objects) {
        UserRightsAssignment 'UserRightsAssignment(INF): Take_ownership_of_files_or_other_objects'
        {
            Force = $True
            Identity = @('*S-1-5-32-544')
            Policy = 'Take_ownership_of_files_or_other_objects'
        }
    }
    
    if ($Create_permanent_shared_objects) {
        UserRightsAssignment 'UserRightsAssignment(INF): Create_permanent_shared_objects'
        {
            Force = $True
            Identity = @('')
            Policy = 'Create_permanent_shared_objects'
        }
    }
    
    if ($Deny_access_to_this_computer_from_the_network) {
        UserRightsAssignment 'UserRightsAssignment(INF): Deny_access_to_this_computer_from_the_network'
        {
            Force = $True
            Identity = @('*S-1-5-113', '*S-1-5-32-546', $EnterpriseAdmins, $DomainAdmins)
            Policy = 'Deny_access_to_this_computer_from_the_network'
        }
    }
    
    if ($Create_global_objects) {
        UserRightsAssignment 'UserRightsAssignment(INF): Create_global_objects'
        {
            Force = $True
            Identity = @('*S-1-5-6', '*S-1-5-20', '*S-1-5-19', '*S-1-5-32-544')
            Policy = 'Create_global_objects'
        }
    }

    if ($Deny_log_on_as_a_batch_job) {
        UserRightsAssignment 'UserRightsAssignment(INF): Deny_log_on_as_a_batch_job'
        {
            Force = $True
            Identity = @($EnterpriseAdmins, $DomainAdmins)
            Policy = 'Deny_log_on_as_a_batch_job'
        }
    }
    
    if ($Restore_files_and_directories) {
        UserRightsAssignment 'UserRightsAssignment(INF): Restore_files_and_directories'
        {
            Force = $True
            Identity = @('*S-1-5-32-544')
            Policy = 'Restore_files_and_directories'
        }
    }
    
    if ($Access_Credential_Manager_as_a_trusted_caller) {
        UserRightsAssignment 'UserRightsAssignment(INF): Access_Credential_Manager_as_a_trusted_caller'
        {
            Force = $True
            Identity = @('')
            Policy = 'Access_Credential_Manager_as_a_trusted_caller'
        }
    }
    
    if ($Deny_log_on_as_a_service) {
        UserRightsAssignment 'UserRightsAssignment(INF): Deny_log_on_as_a_service'
        {
            Force = $True
            Identity = @($DomainAdmins, $EnterpriseAdmins)
            Policy = 'Deny_log_on_as_a_service'
        }
    }
    
    if ($Force_shutdown_from_a_remote_system) {
        UserRightsAssignment 'UserRightsAssignment(INF): Force_shutdown_from_a_remote_system'
        {
            Force = $True
            Identity = @('*S-1-5-32-544')
            Policy = 'Force_shutdown_from_a_remote_system'
        }
    }
    
    if ($Deny_log_on_locally) {
        UserRightsAssignment 'UserRightsAssignment(INF): Deny_log_on_locally'
        {
            Force = $True
            Identity = @('*S-1-5-32-546', $EnterpriseAdmins, $DomainAdmins)
            Policy = 'Deny_log_on_locally'
        }
    }
    
    if ($Create_symbolic_links) {
        UserRightsAssignment 'UserRightsAssignment(INF): Create_symbolic_links'
        {
            Force = $True
            Identity = @('*S-1-5-32-544')
            Policy = 'Create_symbolic_links'
        }
    }
    
    if ($Debug_programs) {
        UserRightsAssignment 'UserRightsAssignment(INF): Debug_programs'
        {
            Force = $True
            Identity = @('*S-1-5-32-544')
            Policy = 'Debug_programs'
        }
    }
    
    if ($Allow_log_on_locally) {
        UserRightsAssignment 'UserRightsAssignment(INF): Allow_log_on_locally'
        {
            Force = $True
            Identity = @('*S-1-5-32-545', '*S-1-5-32-544')
            Policy = 'Allow_log_on_locally'
        }
    }

    if ($Manage_auditing_and_security_log) {
        UserRightsAssignment 'UserRightsAssignment(INF): Manage_auditing_and_security_log'
        {
            Force = $True
            Identity = @('*S-1-5-32-544')
            Policy = 'Manage_auditing_and_security_log'
        }
    }
    
    if ($Act_as_part_of_the_operating_system) {
        UserRightsAssignment 'UserRightsAssignment(INF): Act_as_part_of_the_operating_system'
        {
            Force = $True
            Identity = @('')
            Policy = 'Act_as_part_of_the_operating_system'
        }
    }
    
    if ($Profile_single_process) {
        UserRightsAssignment 'UserRightsAssignment(INF): Profile_single_process'
        {
            Force = $True
            Identity = @('*S-1-5-32-544')
            Policy = 'Profile_single_process'
        }
    }
    
    if ($Create_a_token_object) {
        UserRightsAssignment 'UserRightsAssignment(INF): Create_a_token_object'
        {
            Force = $True
            Identity = @('')
            Policy = 'Create_a_token_object'
        }
    }
    
    if ($Change_the_system_time) {
        UserRightsAssignment 'UserRightsAssignment(INF): Change_the_system_time'
        {
            Force = $True
            Identity = @('*S-1-5-80-3169285310-278349998-1452333686-3865143136-4212226833', '*S-1-5-19', '*S-1-5-32-544')
            Policy = 'Change_the_system_time'
        }
    }
    
    if ($Modify_firmware_environment_values) {
        UserRightsAssignment 'UserRightsAssignment(INF): Modify_firmware_environment_values'
        {
            Force = $True
            Identity = @('*S-1-5-32-544')
            Policy = 'Modify_firmware_environment_values'
        }
    }
    
    if ($Create_a_pagefile) {
        UserRightsAssignment 'UserRightsAssignment(INF): Create_a_pagefile'
        {
            Force = $True
            Identity = @('*S-1-5-32-544')
            Policy = 'Create_a_pagefile'
        }
    }
    
    if ($Deny_log_on_through_Remote_Desktop_Services) {
        UserRightsAssignment 'UserRightsAssignment(INF): Deny_log_on_through_Remote_Desktop_Services'
        {
            Force = $True
            Identity = @('*S-1-5-113', '*S-1-5-32-546', $EnterpriseAdmins, $DomainAdmins)
            Policy = 'Deny_log_on_through_Remote_Desktop_Services'
        }
    }

    if ($Network_access_Restrict_clients_allowed_to_make_remote_calls_to_SAM) {
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
    
    if ($Network_access_Restrict_anonymous_access_to_Named_Pipes_and_Shares) {
        SecurityOption 'SecurityRegistry(INF): Network_access_Restrict_anonymous_access_to_Named_Pipes_and_Shares'
        {
            Network_access_Restrict_anonymous_access_to_Named_Pipes_and_Shares = 'Enabled'
            Name = 'Network_access_Restrict_anonymous_access_to_Named_Pipes_and_Shares'
        }
    }
    
    if ($Domain_member_Require_strong_Windows_2000_or_later_session_key) {
        SecurityOption 'SecurityRegistry(INF): Domain_member_Require_strong_Windows_2000_or_later_session_key'
        {
            Name = 'Domain_member_Require_strong_Windows_2000_or_later_session_key'
            Domain_member_Require_strong_Windows_2000_or_later_session_key = 'Enabled'
        }
    }
    
    if ($User_Account_Control_Only_elevate_UIAccess_applications_that_are_installed_in_secure_locations) {
        SecurityOption 'SecurityRegistry(INF): User_Account_Control_Only_elevate_UIAccess_applications_that_are_installed_in_secure_locations'
        {
            User_Account_Control_Only_elevate_UIAccess_applications_that_are_installed_in_secure_locations = 'Enabled'
            Name = 'User_Account_Control_Only_elevate_UIAccess_applications_that_are_installed_in_secure_locations'
        }
    }
    
    if ($Network_security_Minimum_session_security_for_NTLM_SSP_based_including_secure_RPC_servers) {
        SecurityOption 'SecurityRegistry(INF): Network_security_Minimum_session_security_for_NTLM_SSP_based_including_secure_RPC_servers'
        {
            Name = 'Network_security_Minimum_session_security_for_NTLM_SSP_based_including_secure_RPC_servers'
            Network_security_Minimum_session_security_for_NTLM_SSP_based_including_secure_RPC_servers = 'Both options checked'
        }
    }
    
    if ($Network_security_Configure_encryption_types_allowed_for_Kerberos) {
        SecurityOption 'SecurityRegistry(INF): Network_security_Configure_encryption_types_allowed_for_Kerberos'
        {
            Network_security_Configure_encryption_types_allowed_for_Kerberos = '2147483640'
            Name = 'Network_security_Configure_encryption_types_allowed_for_Kerberos'
        }
    }
    
    if ($System_cryptography_Use_FIPS_compliant_algorithms_for_encryption_hashing_and_signing) {
        SecurityOption 'SecurityRegistry(INF): System_cryptography_Use_FIPS_compliant_algorithms_for_encryption_hashing_and_signing'
        {
            System_cryptography_Use_FIPS_compliant_algorithms_for_encryption_hashing_and_signing = 'Enabled'
            Name = 'System_cryptography_Use_FIPS_compliant_algorithms_for_encryption_hashing_and_signing'
        }
    }
    
    if ($Network_security_LAN_Manager_authentication_level) {
        SecurityOption 'SecurityRegistry(INF): Network_security_LAN_Manager_authentication_level'
        {
            Network_security_LAN_Manager_authentication_level = 'Send NTLMv2 responses only. Refuse LM & NTLM'
            Name = 'Network_security_LAN_Manager_authentication_level'
        }
    }

    if ($Domain_member_Disable_machine_account_password_changes) {
        SecurityOption 'SecurityRegistry(INF): Domain_member_Disable_machine_account_password_changes'
        {
            Domain_member_Disable_machine_account_password_changes = 'Disabled'
            Name = 'Domain_member_Disable_machine_account_password_changes'
        }
    }
    
    if ($Interactive_logon_Message_title_for_users_attempting_to_log_on) {
        SecurityOption 'SecurityRegistry(INF): Interactive_logon_Message_title_for_users_attempting_to_log_on'
        {
            Name = 'Interactive_logon_Message_title_for_users_attempting_to_log_on'
            Interactive_logon_Message_title_for_users_attempting_to_log_on = 'US Department of Defense Warning Statement'
        }
    }

    if ($Domain_member_Digitally_sign_secure_channel_data_when_possible) {
        SecurityOption 'SecurityRegistry(INF): Domain_member_Digitally_sign_secure_channel_data_when_possible'
        {
            Domain_member_Digitally_sign_secure_channel_data_when_possible = 'Enabled'
            Name = 'Domain_member_Digitally_sign_secure_channel_data_when_possible'
        }
    }
    
    if ($Interactive_logon_Smart_card_removal_behavior) {
        SecurityOption 'SecurityRegistry(INF): Interactive_logon_Smart_card_removal_behavior'
        {
            Interactive_logon_Smart_card_removal_behavior = 'Lock workstation'
            Name = 'Interactive_logon_Smart_card_removal_behavior'
        }
    }
    
    if ($Accounts_Limit_local_account_use_of_blank_passwords_to_console_logon_only) {
        SecurityOption 'SecurityRegistry(INF): Accounts_Limit_local_account_use_of_blank_passwords_to_console_logon_only'
        {
            Name = 'Accounts_Limit_local_account_use_of_blank_passwords_to_console_logon_only'
            Accounts_Limit_local_account_use_of_blank_passwords_to_console_logon_only = 'Enabled'
        }
    }
    
    if ($User_Account_Control_Virtualize_file_and_registry_write_failures_to_per_user_locations) {
        SecurityOption 'SecurityRegistry(INF): User_Account_Control_Virtualize_file_and_registry_write_failures_to_per_user_locations'
        {
            User_Account_Control_Virtualize_file_and_registry_write_failures_to_per_user_locations = 'Enabled'
            Name = 'User_Account_Control_Virtualize_file_and_registry_write_failures_to_per_user_locations'
        }
    }
    
    if ($Interactive_logon_Message_text_for_users_attempting_to_log_on) {
        SecurityOption 'SecurityRegistry(INF): Interactive_logon_Message_text_for_users_attempting_to_log_on'
        {
            Interactive_logon_Message_text_for_users_attempting_to_log_on = 'You are accessing a U.S. Government (USG) Information System (IS) that is provided for USG-authorized use only. By using this IS (which includes any device attached to this IS), you consent to the following conditions: The USG routinely intercepts and monitors communications on this IS for purposes including but not limited to penetration testing, COMSEC monitoring, network operations and defense, personnel misconduct (PM), law enforcement (LE), and counterintelligence (CI) investigations. At any time, the USG may inspect and seize data stored on this IS. Communications using or data stored on this IS are not private, are subject to routine monitoring, interception, and search, and may be disclosed or used for any USG-authorized purpose. This IS includes security measures (e.g., authentication and access controls) to protect USG interests--not for your personal benefit or privacy. Notwithstanding the above, using this IS does not constitute consent to PM, LE or CI investigative searching or monitoring of the content of privileged communications or work product related to personal representation or services by attorneys, psychotherapists, or clergy and their assistants. Such communications and work product are private and confidential. See User Agreement for details.'
            Name = 'Interactive_logon_Message_text_for_users_attempting_to_log_on'
        }
    }
    
    if ($Domain_member_Digitally_encrypt_secure_channel_data_when_possible) {
        SecurityOption 'SecurityRegistry(INF): Domain_member_Digitally_encrypt_secure_channel_data_when_possible'
        {
            Name = 'Domain_member_Digitally_encrypt_secure_channel_data_when_possible'
            Domain_member_Digitally_encrypt_secure_channel_data_when_possible = 'Enabled'
        }
    }
    
    if ($User_Account_Control_Behavior_of_the_elevation_prompt_for_standard_users) {
        SecurityOption 'SecurityRegistry(INF): User_Account_Control_Behavior_of_the_elevation_prompt_for_standard_users'
        {
            User_Account_Control_Behavior_of_the_elevation_prompt_for_standard_users = 'Automatically deny elevation request'
            Name = 'User_Account_Control_Behavior_of_the_elevation_prompt_for_standard_users'
        }
    }

    if ($Microsoft_network_server_Digitally_sign_communications_always) {
        SecurityOption 'SecurityRegistry(INF): Microsoft_network_server_Digitally_sign_communications_always'
        {
            Microsoft_network_server_Digitally_sign_communications_always = 'Enabled'
            Name = 'Microsoft_network_server_Digitally_sign_communications_always'
        }
    }
    
    if ($Microsoft_network_client_Digitally_sign_communications_always) {
        SecurityOption 'SecurityRegistry(INF): Microsoft_network_client_Digitally_sign_communications_always'
        {
            Microsoft_network_client_Digitally_sign_communications_always = 'Enabled'
            Name = 'Microsoft_network_client_Digitally_sign_communications_always'
        }
    }
    
    if ($Network_security_Minimum_session_security_for_NTLM_SSP_based_including_secure_RPC_clients) {
        SecurityOption 'SecurityRegistry(INF): Network_security_Minimum_session_security_for_NTLM_SSP_based_including_secure_RPC_clients'
        {
            Name = 'Network_security_Minimum_session_security_for_NTLM_SSP_based_including_secure_RPC_clients'
            Network_security_Minimum_session_security_for_NTLM_SSP_based_including_secure_RPC_clients = 'Both options checked'
        }
    }
    
    if ($User_Account_Control_Run_all_administrators_in_Admin_Approval_Mode) {
        SecurityOption 'SecurityRegistry(INF): User_Account_Control_Run_all_administrators_in_Admin_Approval_Mode'
        {
            User_Account_Control_Run_all_administrators_in_Admin_Approval_Mode = 'Enabled'
            Name = 'User_Account_Control_Run_all_administrators_in_Admin_Approval_Mode'
        }
    }
    
    if ($User_Account_Control_Detect_application_installations_and_prompt_for_elevation) {
        SecurityOption 'SecurityRegistry(INF): User_Account_Control_Detect_application_installations_and_prompt_for_elevation'
        {
            User_Account_Control_Detect_application_installations_and_prompt_for_elevation = 'Enabled'
            Name = 'User_Account_Control_Detect_application_installations_and_prompt_for_elevation'
        }
    }
    
    if ($Network_access_Do_not_allow_anonymous_enumeration_of_SAM_accounts) {
        SecurityOption 'SecurityRegistry(INF): Network_access_Do_not_allow_anonymous_enumeration_of_SAM_accounts'
        {
            Name = 'Network_access_Do_not_allow_anonymous_enumeration_of_SAM_accounts'
            Network_access_Do_not_allow_anonymous_enumeration_of_SAM_accounts = 'Enabled'
        }
    }
    
    if ($Network_security_Allow_LocalSystem_NULL_session_fallback) {
        SecurityOption 'SecurityRegistry(INF): Network_security_Allow_LocalSystem_NULL_session_fallback'
        {
            Name = 'Network_security_Allow_LocalSystem_NULL_session_fallback'
            Network_security_Allow_LocalSystem_NULL_session_fallback = 'Disabled'
        }
    }

    if ($User_Account_Control_Admin_Approval_Mode_for_the_Built_in_Administrator_account) {
        SecurityOption 'SecurityRegistry(INF): User_Account_Control_Admin_Approval_Mode_for_the_Built_in_Administrator_account'
        {
            User_Account_Control_Admin_Approval_Mode_for_the_Built_in_Administrator_account = 'Enabled'
            Name = 'User_Account_Control_Admin_Approval_Mode_for_the_Built_in_Administrator_account'
        }
    }
    
    if ($Microsoft_network_client_Send_unencrypted_password_to_third_party_SMB_servers) {
        SecurityOption 'SecurityRegistry(INF): Microsoft_network_client_Send_unencrypted_password_to_third_party_SMB_servers'
        {
            Microsoft_network_client_Send_unencrypted_password_to_third_party_SMB_servers = 'Disabled'
            Name = 'Microsoft_network_client_Send_unencrypted_password_to_third_party_SMB_servers'
        }
    }
    
    if ($Interactive_logon_Number_of_previous_logons_to_cache_in_case_domain_controller_is_not_available) {
        SecurityOption 'SecurityRegistry(INF): Interactive_logon_Number_of_previous_logons_to_cache_in_case_domain_controller_is_not_available'
        {
            Interactive_logon_Number_of_previous_logons_to_cache_in_case_domain_controller_is_not_available = '10'
            Name = 'Interactive_logon_Number_of_previous_logons_to_cache_in_case_domain_controller_is_not_available'
        }
    }
    
    if ($Domain_member_Maximum_machine_account_password_age) {
        SecurityOption 'SecurityRegistry(INF): Domain_member_Maximum_machine_account_password_age'
        {
            Name = 'Domain_member_Maximum_machine_account_password_age'
            Domain_member_Maximum_machine_account_password_age = '30'
        }
    }
    
    if ($Network_access_Do_not_allow_anonymous_enumeration_of_SAM_accounts_and_shares) {
        SecurityOption 'SecurityRegistry(INF): Network_access_Do_not_allow_anonymous_enumeration_of_SAM_accounts_and_shares'
        {
            Name = 'Network_access_Do_not_allow_anonymous_enumeration_of_SAM_accounts_and_shares'
            Network_access_Do_not_allow_anonymous_enumeration_of_SAM_accounts_and_shares = 'Enabled'
        }
    }
    
    if ($Audit_Force_audit_policy_subcategory_settings_Windows_Vista_or_later_to_override_audit_policy_category_settings) {
        SecurityOption 'SecurityRegistry(INF): Audit_Force_audit_policy_subcategory_settings_Windows_Vista_or_later_to_override_audit_policy_category_settings'
        {
            Name = 'Audit_Force_audit_policy_subcategory_settings_Windows_Vista_or_later_to_override_audit_policy_category_settings'
            Audit_Force_audit_policy_subcategory_settings_Windows_Vista_or_later_to_override_audit_policy_category_settings = 'Enabled'
        }
    }
    
    if ($System_objects_Strengthen_default_permissions_of_internal_system_objects_eg_Symbolic_Links) {
        SecurityOption 'SecurityRegistry(INF): System_objects_Strengthen_default_permissions_of_internal_system_objects_eg_Symbolic_Links'
        {
            System_objects_Strengthen_default_permissions_of_internal_system_objects_eg_Symbolic_Links = 'Enabled'
            Name = 'System_objects_Strengthen_default_permissions_of_internal_system_objects_eg_Symbolic_Links'
        }
    }

    if ($Network_Security_Allow_PKU2U_authentication_requests_to_this_computer_to_use_online_identities) {
        SecurityOption 'SecurityRegistry(INF): Network_Security_Allow_PKU2U_authentication_requests_to_this_computer_to_use_online_identities'
        {
            Network_Security_Allow_PKU2U_authentication_requests_to_this_computer_to_use_online_identities = 'Disabled'
            Name = 'Network_Security_Allow_PKU2U_authentication_requests_to_this_computer_to_use_online_identities'
        }
    }
    
    if ($Domain_member_Digitally_encrypt_or_sign_secure_channel_data_always) {
        SecurityOption 'SecurityRegistry(INF): Domain_member_Digitally_encrypt_or_sign_secure_channel_data_always'
        {
            Domain_member_Digitally_encrypt_or_sign_secure_channel_data_always = 'Enabled'
            Name = 'Domain_member_Digitally_encrypt_or_sign_secure_channel_data_always'
        }
    }
    
    if ($Interactive_logon_Machine_inactivity_limit) {
        SecurityOption 'SecurityRegistry(INF): Interactive_logon_Machine_inactivity_limit'
        {
            Name = 'Interactive_logon_Machine_inactivity_limit'
            Interactive_logon_Machine_inactivity_limit = '900'
        }
    }
    
    if ($Network_security_Do_not_store_LAN_Manager_hash_value_on_next_password_change) {
        SecurityOption 'SecurityRegistry(INF): Network_security_Do_not_store_LAN_Manager_hash_value_on_next_password_change'
        {
            Name = 'Network_security_Do_not_store_LAN_Manager_hash_value_on_next_password_change'
            Network_security_Do_not_store_LAN_Manager_hash_value_on_next_password_change = 'Enabled'
        }
    }
    
    if ($Network_access_Let_Everyone_permissions_apply_to_anonymous_users) {
        SecurityOption 'SecurityRegistry(INF): Network_access_Let_Everyone_permissions_apply_to_anonymous_users'
        {
            Network_access_Let_Everyone_permissions_apply_to_anonymous_users = 'Disabled'
            Name = 'Network_access_Let_Everyone_permissions_apply_to_anonymous_users'
        }
    }
    
    if ($Network_security_LDAP_client_signing_requirements) {
        SecurityOption 'SecurityRegistry(INF): Network_security_LDAP_client_signing_requirements'
        {
            Name = 'Network_security_LDAP_client_signing_requirements'
            Network_security_LDAP_client_signing_requirements = 'Negotiate Signing'
        }
    }
    
    if ($User_Account_Control_Behavior_of_the_elevation_prompt_for_administrators_in_Admin_Approval_Mode) {
        SecurityOption 'SecurityRegistry(INF): User_Account_Control_Behavior_of_the_elevation_prompt_for_administrators_in_Admin_Approval_Mode'
        {
            Name = 'User_Account_Control_Behavior_of_the_elevation_prompt_for_administrators_in_Admin_Approval_Mode'
            User_Account_Control_Behavior_of_the_elevation_prompt_for_administrators_in_Admin_Approval_Mode = 'Prompt for consent on the secure desktop'
        }
    }
    if ($Account_lockout_duration) {
        AccountPolicy 'SecuritySetting(INF): LockoutDuration'
        {
            Account_lockout_duration = 15
            Name = 'Account_lockout_duration'
        }
    }
    
    if ($Account_lockout_threshold) {
        AccountPolicy 'SecuritySetting(INF): LockoutBadCount'
        {
            Account_lockout_threshold = 3
            Name = 'Account_lockout_threshold'
        }
    }
    
    if ($Reset_account_lockout_counter_after) {
        AccountPolicy 'SecuritySetting(INF): ResetLockoutCount'
        {
            Reset_account_lockout_counter_after = 15
            Name = 'Reset_account_lockout_counter_after'
        }
    }
    
    if ($Accounts_Rename_guest_account) {
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
    
    if ($Password_must_meet_complexity_requirements) {
        AccountPolicy 'SecuritySetting(INF): PasswordComplexity'
        {
            Password_must_meet_complexity_requirements = 'Enabled'
            Name = 'Password_must_meet_complexity_requirements'
        }
    }
    
    if ($Enforce_password_history) {
        AccountPolicy 'SecuritySetting(INF): PasswordHistorySize'
        {
            Name = 'Enforce_password_history'
            Enforce_password_history = 24
        }
    }
    if ($Network_access_Allow_anonymous_SID_Name_translation) {
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
    
    if ($Accounts_Administrator_account_status) {
        SecurityOption 'SecuritySetting(INF): EnableAdminAccount'
        {
            Accounts_Administrator_account_status = 'Disabled'
            Name = 'Accounts_Administrator_account_status'
        }
    }
    
    if ($Accounts_Rename_administrator_account) {
        SecurityOption 'SecuritySetting(INF): NewAdministratorName'
        {
            Accounts_Rename_administrator_account = 'X_Admin'
            Name = 'Accounts_Rename_administrator_account'
        }
    }
    
    if ($Accounts_Guest_account_status) {
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
    
    if ($Store_passwords_using_reversible_encryption) {
        AccountPolicy 'SecuritySetting(INF): ClearTextPassword'
        {
            Name = 'Store_passwords_using_reversible_encryption'
            Store_passwords_using_reversible_encryption = 'Disabled'
        }
    }
}

