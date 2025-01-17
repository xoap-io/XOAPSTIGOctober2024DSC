configuration DoD_Internet_Explorer_11_v2r4
{
    param(
        [bool]$RunThisTimeEnabled = $true,
        [bool]$VersionCheckEnabled = $true,
        [bool]$History = $true,
        [bool]$RunInvalidSignatures = $true,
        [bool]$CheckExeSignatures = $true,
        [bool]$Disabled = $true,
        [bool]$DisableEPMCompat = $true,
        [bool]$Isolation64Bit = $true,
        [bool]$Isolation = $true,
        [bool]$NotifyDisableIEOptions = $true,
        [bool]$FeatureControlReserved = $true,
        [bool]$FeatureControlExplorerExe = $true,
        [bool]$FeatureDisableMKProtocolIExploreExe = $true,
        [bool]$FeatureMimeHandlingReserved = $true,
        [bool]$FeatureMimeHandlingExplorerExe = $true,
        [bool]$FeatureMimeHandlingIExploreExe = $true,
        [bool]$FeatureMimeSniffingReserved = $true,
        [bool]$FeatureMIME_SniffingExplorerExe = $true,
        [bool]$FeatureMIME_SniffingIExploreExe = $true,
        [bool]$FeatureRestrictActiveXInstallReserved = $true,
        [bool]$FeatureRestrictActiveXInstallExplorerExe = $true,
        [bool]$FeatureRestrictActiveXInstallIExploreExe = $true,
        [bool]$FeatureRestrictFileDownloadReserved = $true,
        [bool]$FeatureRestrictFileDownloadExplorerExe = $true,
        [bool]$FeatureRestrictFileDownloadIExploreExe = $true,
        [bool]$FeatureSecurityBandReserved = $true,
        [bool]$FeatureSecurityBandExplorerExe = $true,
        [bool]$FeatureSecurityBandIExploreExe = $true,
        [bool]$FeatureWindowRestrictionsReserved = $true,
        [bool]$FeatureWindowRestrictionsExplorerExe = $true,
        [bool]$FeatureWindowRestrictionsIExploreExe = $true,
        [bool]$FeatureZoneElevationReserved = $true,
        [bool]$FeatureZoneElevationExplorerExe = $true,
        [bool]$FeatureZoneElevationIExploreExe = $true,
        [bool]$PreventOverride = $true,
        [bool]$PreventOverrideAppRepUnknown = $true,
        [bool]$EnabledV9 = $true,
        [bool]$ClearBrowsingHistoryOnExit = $true,
        [bool]$CleanHistory = $true,
        [bool]$EnableInPrivateBrowsing = $true,
        [bool]$NoCrashDetection = $true,
        [bool]$DisableSecuritySettingsCheck = $true,
        [bool]$BlockNonAdminActiveXInstall = $true,
        [bool]$SecurityZonesMapEdit = $true,
        [bool]$SecurityOptionsEdit = $true,
        [bool]$SecurityHKLMOnly = $true,
        [bool]$LockdownZones1_1C00 = $true,
        [bool]$LockdownZones2_1C00 = $true,
        [bool]$LockdownZones4_1C00 = $true,
        [bool]$DaysToKeep = $true,
        [bool]$UNCAsIntranet = $true,
        [bool]$Zones0_270C = $true,
        [bool]$Zones0_1C00 = $true,
        [bool]$Zones1_270C = $true,
        [bool]$Zones1_1201 = $true,
        [bool]$Zones1_1C00 = $true,
        [bool]$Zones2_270C = $true,
        [bool]$Zones2_1201 = $true,
        [bool]$Zones2_1C00 = $true,
        [bool]$Zones3_1406 = $true,
        [bool]$Zones3_1407 = $true,
        [bool]$Zones3_1802 = $true,
        [bool]$Zones3_2402 = $true,
        [bool]$Zones3_120b = $true,
        [bool]$Zones3_120c = $true,
        [bool]$Zones3_1206 = $true,
        [bool]$Zones3_2102 = $true,
        [bool]$Zones3_1209 = $true,
        [bool]$Zones3_2103 = $true,
        [bool]$Zones3_2200 = $true,
        [bool]$Zones3_270C = $true,
        [bool]$Zones3_1001 = $true,
        [bool]$Zones3_1004 = $true,
        [bool]$Zones3_2709 = $true,
        [bool]$Zones3_2708 = $true,
        [bool]$Zones3_160A = $true,
        [bool]$Zones3_1201 = $true,
        [bool]$Zones3_1C00 = $true,
        [bool]$Zones3_1804 = $true,
        [bool]$Zones3_1A00 = $true,
        [bool]$Zones3_1607 = $true,
        [bool]$Zones3_2004 = $true,
        [bool]$Zones3_2001 = $true,
        [bool]$Zones3_1806 = $true,
        [bool]$Zones3_1409 = $true,
        [bool]$Zones3_2500 = $true,
        [bool]$Zones3_2301 = $true,
        [bool]$Zones3_1809 = $true,
        [bool]$Zones3_1606 = $true,
        [bool]$Zones3_2101 = $true,
        [bool]$Zones3_140C = $true,
        [bool]$Zones4_1406 = $true,
        [bool]$Zones4_1400 = $true,
        [bool]$Zones4_2000 = $true,
        [bool]$Zones4_1407 = $true,
        [bool]$Zones4_1802 = $true,
        [bool]$Zones4_1803 = $true,
        [bool]$Zones4_2402 = $true,
        [bool]$Zones4_1608 = $true,
        [bool]$Zones4_120b = $true,
        [bool]$Zones4_120c = $true,
        [bool]$Zones4_1206 = $true,
        [bool]$Zones4_2102 = $true,
        [bool]$Zones4_1209 = $true,
        [bool]$Zones4_2103 = $true,
        [bool]$Zones4_2200 = $true,
        [bool]$Zones4_270C = $true,
        [bool]$Zones4_1001 = $true,
        [bool]$Zones4_1004 = $true,
        [bool]$Zones4_2709 = $true,
        [bool]$Zones4_2708 = $true,
        [bool]$Zones4_160A = $true,
        [bool]$Zones4_1201 = $true,
        [bool]$Zones4_1C00 = $true,
        [bool]$Zones4_1804 = $true,
        [bool]$Zones4_1A00 = $true,
        [bool]$Zones4_1607 = $true,
        [bool]$Zones4_2004 = $true,
        [bool]$Zones4_1200 = $true,
        [bool]$Zones4_1405 = $true,
        [bool]$Zones4_1402 = $true,
        [bool]$Zones4_1806 = $true,
        [bool]$Zones4_1409 = $true,
        [bool]$Zones4_2500 = $true,
        [bool]$Zones4_2301 = $true,
        [bool]$Zones4_1809 = $true,
        [bool]$Zones4_1606 = $true,
        [bool]$Zones4_2101 = $true,
        [bool]$Zones4_2001 = $true,
        [bool]$Zones4_140C = $true
    )
	
    Import-DSCResource -ModuleName 'GPRegistryPolicyDsc'
	Import-DSCResource -ModuleName 'AuditPolicyDSC'
	Import-DSCResource -ModuleName 'SecurityPolicyDSC'

    if ($RunThisTimeEnabled) {
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\Ext\RunThisTimeEnabled'
        {
            Key = '\Software\Microsoft\Windows\CurrentVersion\Policies\Ext'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
            ValueName = 'RunThisTimeEnabled'
            ValueData = 0
        }
    }
    
    if ($VersionCheckEnabled) {
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\Ext\VersionCheckEnabled'
        {
            Key = '\Software\Microsoft\Windows\CurrentVersion\Policies\Ext'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
            ValueName = 'VersionCheckEnabled'
            ValueData = 1
        }
    }
    
    if ($History) {
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Internet Explorer\Control Panel\History'
        {
            Key = '\Software\Policies\Microsoft\Internet Explorer\Control Panel'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
            ValueName = 'History'
            ValueData = 1
        }
    }
    
    if ($RunInvalidSignatures) {
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Internet Explorer\Download\RunInvalidSignatures'
        {
            Key = '\Software\Policies\Microsoft\Internet Explorer\Download'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
            ValueName = 'RunInvalidSignatures'
            ValueData = 0
        }
    }
    
    if ($CheckExeSignatures) {
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Internet Explorer\Download\CheckExeSignatures'
        {
            Key = '\Software\Policies\Microsoft\Internet Explorer\Download'
            ValueType = 'String'
            TargetType = 'ComputerConfiguration'
            ValueName = 'CheckExeSignatures'
            ValueData = 'yes'
        }
    }

    if ($Disabled) {
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Internet Explorer\IEDevTools\Disabled'
        {
            Key = '\Software\Policies\Microsoft\Internet Explorer\IEDevTools'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
            ValueName = 'Disabled'
            ValueData = 1
        }
    }
    
    if ($DisableEPMCompat) {
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Internet Explorer\Main\DisableEPMCompat'
        {
            Key = '\Software\Policies\Microsoft\Internet Explorer\Main'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
            ValueName = 'DisableEPMCompat'
            ValueData = 1
        }
    }
    
    if ($Isolation64Bit) {
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Internet Explorer\Main\Isolation64Bit'
        {
            Key = '\Software\Policies\Microsoft\Internet Explorer\Main'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
            ValueName = 'Isolation64Bit'
            ValueData = 1
        }
    }
    
    if ($Isolation) {
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Internet Explorer\Main\Isolation'
        {
            Key = '\Software\Policies\Microsoft\Internet Explorer\Main'
            ValueType = 'String'
            TargetType = 'ComputerConfiguration'
            ValueName = 'Isolation'
            ValueData = 'PMEM'
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
    
    if ($FeatureControlReserved) {
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_DISABLE_MK_PROTOCOL\(Reserved)'
        {
            Key = '\Software\Policies\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_DISABLE_MK_PROTOCOL'
            ValueType = 'String'
            TargetType = 'ComputerConfiguration'
            ValueName = '(Reserved)'
            ValueData = '1'
        }
    }
    
    if ($FeatureControlExplorerExe) {
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_DISABLE_MK_PROTOCOL\explorer.exe'
        {
            Key = '\Software\Policies\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_DISABLE_MK_PROTOCOL'
            ValueType = 'String'
            TargetType = 'ComputerConfiguration'
            ValueName = 'explorer.exe'
            ValueData = '1'
        }
    }

    if ($FeatureDisableMKProtocolIExploreExe) {
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_DISABLE_MK_PROTOCOL\iexplore.exe'
        {
            Key = '\Software\Policies\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_DISABLE_MK_PROTOCOL'
            ValueType = 'String'
            TargetType = 'ComputerConfiguration'
            ValueName = 'iexplore.exe'
            ValueData = '1'
        }
    }
    
    if ($FeatureMimeHandlingReserved) {
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_MIME_HANDLING\(Reserved)'
        {
            Key = '\Software\Policies\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_MIME_HANDLING'
            ValueType = 'String'
            TargetType = 'ComputerConfiguration'
            ValueName = '(Reserved)'
            ValueData = '1'
        }
    }
    
    if ($FeatureMimeHandlingExplorerExe) {
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_MIME_HANDLING\explorer.exe'
        {
            Key = '\Software\Policies\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_MIME_HANDLING'
            ValueType = 'String'
            TargetType = 'ComputerConfiguration'
            ValueName = 'explorer.exe'
            ValueData = '1'
        }
    }
    
    if ($FeatureMimeHandlingIExploreExe) {
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_MIME_HANDLING\iexplore.exe'
        {
            Key = '\Software\Policies\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_MIME_HANDLING'
            ValueType = 'String'
            TargetType = 'ComputerConfiguration'
            ValueName = 'iexplore.exe'
            ValueData = '1'
        }
    }
    
    if ($FeatureMimeSniffingReserved) {
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_MIME_SNIFFING\(Reserved)'
        {
            Key = '\Software\Policies\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_MIME_SNIFFING'
            ValueType = 'String'
            TargetType = 'ComputerConfiguration'
            ValueName = '(Reserved)'
            ValueData = '1'
        }
    }

    if ($FeatureMIME_SniffingExplorerExe) {
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_MIME_SNIFFING\explorer.exe'
        {
            Key = '\Software\Policies\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_MIME_SNIFFING'
            ValueType = 'String'
            TargetType = 'ComputerConfiguration'
            ValueName = 'explorer.exe'
            ValueData = '1'
        }
    }
    
    if ($FeatureMIME_SniffingIExploreExe) {
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_MIME_SNIFFING\iexplore.exe'
        {
            Key = '\Software\Policies\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_MIME_SNIFFING'
            ValueType = 'String'
            TargetType = 'ComputerConfiguration'
            ValueName = 'iexplore.exe'
            ValueData = '1'
        }
    }
    
    if ($FeatureRestrictActiveXInstallReserved) {
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_RESTRICT_ACTIVEXINSTALL\(Reserved)'
        {
            Key = '\Software\Policies\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_RESTRICT_ACTIVEXINSTALL'
            ValueType = 'String'
            TargetType = 'ComputerConfiguration'
            ValueName = '(Reserved)'
            ValueData = '1'
        }
    }
    
    if ($FeatureRestrictActiveXInstallExplorerExe) {
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_RESTRICT_ACTIVEXINSTALL\explorer.exe'
        {
            Key = '\Software\Policies\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_RESTRICT_ACTIVEXINSTALL'
            ValueType = 'String'
            TargetType = 'ComputerConfiguration'
            ValueName = 'explorer.exe'
            ValueData = '1'
        }
    }
    
    if ($FeatureRestrictActiveXInstallIExploreExe) {
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_RESTRICT_ACTIVEXINSTALL\iexplore.exe'
        {
            Key = '\Software\Policies\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_RESTRICT_ACTIVEXINSTALL'
            ValueType = 'String'
            TargetType = 'ComputerConfiguration'
            ValueName = 'iexplore.exe'
            ValueData = '1'
        }
    }
    if ($FeatureRestrictFileDownloadReserved) {
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_RESTRICT_FILEDOWNLOAD\(Reserved)'
        {
            Key = '\Software\Policies\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_RESTRICT_FILEDOWNLOAD'
            ValueType = 'String'
            TargetType = 'ComputerConfiguration'
            ValueName = '(Reserved)'
            ValueData = '1'
        }
    }
    
    if ($FeatureRestrictFileDownloadExplorerExe) {
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_RESTRICT_FILEDOWNLOAD\explorer.exe'
        {
            Key = '\Software\Policies\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_RESTRICT_FILEDOWNLOAD'
            ValueType = 'String'
            TargetType = 'ComputerConfiguration'
            ValueName = 'explorer.exe'
            ValueData = '1'
        }
    }
    
    if ($FeatureRestrictFileDownloadIExploreExe) {
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_RESTRICT_FILEDOWNLOAD\iexplore.exe'
        {
            Key = '\Software\Policies\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_RESTRICT_FILEDOWNLOAD'
            ValueType = 'String'
            TargetType = 'ComputerConfiguration'
            ValueName = 'iexplore.exe'
            ValueData = '1'
        }
    }
    
    if ($FeatureSecurityBandReserved) {
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_SECURITYBAND\(Reserved)'
        {
            Key = '\Software\Policies\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_SECURITYBAND'
            ValueType = 'String'
            TargetType = 'ComputerConfiguration'
            ValueName = '(Reserved)'
            ValueData = '1'
        }
    }
    
    if ($FeatureSecurityBandExplorerExe) {
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_SECURITYBAND\explorer.exe'
        {
            Key = '\Software\Policies\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_SECURITYBAND'
            ValueType = 'String'
            TargetType = 'ComputerConfiguration'
            ValueName = 'explorer.exe'
            ValueData = '1'
        }
    }
    
    if ($FeatureSecurityBandIExploreExe) {
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_SECURITYBAND\iexplore.exe'
        {
            Key = '\Software\Policies\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_SECURITYBAND'
            ValueType = 'String'
            TargetType = 'ComputerConfiguration'
            ValueName = 'iexplore.exe'
            ValueData = '1'
        }
    }
    if ($FeatureWindowRestrictionsReserved) {
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_WINDOW_RESTRICTIONS\(Reserved)'
        {
            Key = '\Software\Policies\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_WINDOW_RESTRICTIONS'
            ValueType = 'String'
            TargetType = 'ComputerConfiguration'
            ValueName = '(Reserved)'
            ValueData = '1'
        }
    }
    
    if ($FeatureWindowRestrictionsExplorerExe) {
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_WINDOW_RESTRICTIONS\explorer.exe'
        {
            Key = '\Software\Policies\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_WINDOW_RESTRICTIONS'
            ValueType = 'String'
            TargetType = 'ComputerConfiguration'
            ValueName = 'explorer.exe'
            ValueData = '1'
        }
    }
    
    if ($FeatureWindowRestrictionsIExploreExe) {
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_WINDOW_RESTRICTIONS\iexplore.exe'
        {
            Key = '\Software\Policies\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_WINDOW_RESTRICTIONS'
            ValueType = 'String'
            TargetType = 'ComputerConfiguration'
            ValueName = 'iexplore.exe'
            ValueData = '1'
        }
    }
    
    if ($FeatureZoneElevationReserved) {
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_ZONE_ELEVATION\(Reserved)'
        {
            Key = '\Software\Policies\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_ZONE_ELEVATION'
            ValueType = 'String'
            TargetType = 'ComputerConfiguration'
            ValueName = '(Reserved)'
            ValueData = '1'
        }
    }
    
    if ($FeatureZoneElevationExplorerExe) {
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_ZONE_ELEVATION\explorer.exe'
        {
            Key = '\Software\Policies\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_ZONE_ELEVATION'
            ValueType = 'String'
            TargetType = 'ComputerConfiguration'
            ValueName = 'explorer.exe'
            ValueData = '1'
        }
    }
    
    if ($FeatureZoneElevationIExploreExe) {
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_ZONE_ELEVATION\iexplore.exe'
        {
            Key = '\Software\Policies\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_ZONE_ELEVATION'
            ValueType = 'String'
            TargetType = 'ComputerConfiguration'
            ValueName = 'iexplore.exe'
            ValueData = '1'
        }
    }
    if ($PreventOverride) {
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Internet Explorer\PhishingFilter\PreventOverride'
        {
            Key = '\Software\Policies\Microsoft\Internet Explorer\PhishingFilter'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
            ValueName = 'PreventOverride'
            ValueData = 1
        }
    }
    
    if ($PreventOverrideAppRepUnknown) {
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Internet Explorer\PhishingFilter\PreventOverrideAppRepUnknown'
        {
            Key = '\Software\Policies\Microsoft\Internet Explorer\PhishingFilter'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
            ValueName = 'PreventOverrideAppRepUnknown'
            ValueData = 1
        }
    }
    
    if ($EnabledV9) {
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Internet Explorer\PhishingFilter\EnabledV9'
        {
            Key = '\Software\Policies\Microsoft\Internet Explorer\PhishingFilter'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
            ValueName = 'EnabledV9'
            ValueData = 1
        }
    }
    
    if ($ClearBrowsingHistoryOnExit) {
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Internet Explorer\Privacy\ClearBrowsingHistoryOnExit'
        {
            Key = '\Software\Policies\Microsoft\Internet Explorer\Privacy'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
            ValueName = 'ClearBrowsingHistoryOnExit'
            ValueData = 0
        }
    }
    
    if ($CleanHistory) {
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Internet Explorer\Privacy\CleanHistory'
        {
            Key = '\Software\Policies\Microsoft\Internet Explorer\Privacy'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
            ValueName = 'CleanHistory'
            ValueData = 0
        }
    }
    
    if ($EnableInPrivateBrowsing) {
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Internet Explorer\Privacy\EnableInPrivateBrowsing'
        {
            Key = '\Software\Policies\Microsoft\Internet Explorer\Privacy'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
            ValueName = 'EnableInPrivateBrowsing'
            ValueData = 0
        }
    }

    if ($NoCrashDetection) {
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Internet Explorer\Restrictions\NoCrashDetection'
        {
            Key = '\Software\Policies\Microsoft\Internet Explorer\Restrictions'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
            ValueName = 'NoCrashDetection'
            ValueData = 1
        }
    }
    
    if ($DisableSecuritySettingsCheck) {
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Internet Explorer\Security\DisableSecuritySettingsCheck'
        {
            Key = '\Software\Policies\Microsoft\Internet Explorer\Security'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
            ValueName = 'DisableSecuritySettingsCheck'
            ValueData = 0
        }
    }
    
    if ($BlockNonAdminActiveXInstall) {
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Internet Explorer\Security\ActiveX\BlockNonAdminActiveXInstall'
        {
            Key = '\Software\Policies\Microsoft\Internet Explorer\Security\ActiveX'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
            ValueName = 'BlockNonAdminActiveXInstall'
            ValueData = 1
        }
    }
    
    if ($SecurityZonesMapEdit) {
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Security_zones_map_edit'
        {
            Key = '\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
            ValueName = 'Security_zones_map_edit'
            ValueData = 1
        }
    }
    
    if ($SecurityOptionsEdit) {
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Security_options_edit'
        {
            Key = '\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
            ValueName = 'Security_options_edit'
            ValueData = 1
        }
    }
    
    if ($SecurityHKLMOnly) {
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Security_HKLM_only'
        {
            Key = '\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
            ValueName = 'Security_HKLM_only'
            ValueData = 1
        }
    }

    if ($LockdownZones1_1C00) {
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Lockdown_Zones\1\1C00'
        {
            Key = '\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Lockdown_Zones\1'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
            ValueName = '1C00'
            ValueData = 0
        }
    }
    
    if ($LockdownZones2_1C00) {
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Lockdown_Zones\2\1C00'
        {
            Key = '\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Lockdown_Zones\2'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
            ValueName = '1C00'
            ValueData = 0
        }
    }
    
    if ($LockdownZones4_1C00) {
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Lockdown_Zones\4\1C00'
        {
            Key = '\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Lockdown_Zones\4'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
            ValueName = '1C00'
            ValueData = 0
        }
    }
    
    if ($DaysToKeep) {
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Url History\DaysToKeep'
        {
            Key = '\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Url History'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
            ValueName = 'DaysToKeep'
            ValueData = 40
        }
    }
    
    if ($UNCAsIntranet) {
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\ZoneMap\UNCAsIntranet'
        {
            Key = '\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\ZoneMap'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
            ValueName = 'UNCAsIntranet'
            ValueData = 0
        }
    }
    
    if ($Zones0_270C) {
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\0\270C'
        {
            Key = '\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\0'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
            ValueName = '270C'
            ValueData = 0
        }
    }

    if ($Zones0_1C00) {
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\0\1C00'
        {
            Key = '\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\0'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
            ValueName = '1C00'
            ValueData = 0
        }
    }
    
    if ($Zones1_270C) {
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\1\270C'
        {
            Key = '\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\1'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
            ValueName = '270C'
            ValueData = 0
        }
    }
    
    if ($Zones1_1201) {
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\1\1201'
        {
            Key = '\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\1'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
            ValueName = '1201'
            ValueData = 3
        }
    }
    
    if ($Zones1_1C00) {
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\1\1C00'
        {
            Key = '\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\1'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
            ValueName = '1C00'
            ValueData = 65536
        }
    }
    
    if ($Zones2_270C) {
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\2\270C'
        {
            Key = '\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\2'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
            ValueName = '270C'
            ValueData = 0
        }
    }
    
    if ($Zones2_1201) {
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\2\1201'
        {
            Key = '\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\2'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
            ValueName = '1201'
            ValueData = 3
        }
    }
    if ($Zones2_1C00) {
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\2\1C00'
        {
            Key = '\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\2'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
            ValueName = '1C00'
            ValueData = 65536
        }
    }
    
    if ($Zones3_1406) {
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3\1406'
        {
            Key = '\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
            ValueName = '1406'
            ValueData = 3
        }
    }
    
    if ($Zones3_1407) {
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3\1407'
        {
            Key = '\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
            ValueName = '1407'
            ValueData = 3
        }
    }
    
    if ($Zones3_1802) {
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3\1802'
        {
            Key = '\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
            ValueName = '1802'
            ValueData = 3
        }
    }
    
    if ($Zones3_2402) {
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3\2402'
        {
            Key = '\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
            ValueName = '2402'
            ValueData = 3
        }
    }
    
    if ($Zones3_120b) {
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3\120b'
        {
            Key = '\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
            ValueName = '120b'
            ValueData = 3
        }
    }
    if ($Zones3_120c) {
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3\120c'
        {
            Key = '\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
            ValueName = '120c'
            ValueData = 3
        }
    }
    
    if ($Zones3_1206) {
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3\1206'
        {
            Key = '\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
            ValueName = '1206'
            ValueData = 3
        }
    }
    
    if ($Zones3_2102) {
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3\2102'
        {
            Key = '\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
            ValueName = '2102'
            ValueData = 3
        }
    }
    
    if ($Zones3_1209) {
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3\1209'
        {
            Key = '\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
            ValueName = '1209'
            ValueData = 3
        }
    }
    
    if ($Zones3_2103) {
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3\2103'
        {
            Key = '\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
            ValueName = '2103'
            ValueData = 3
        }
    }
    
    if ($Zones3_2200) {
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3\2200'
        {
            Key = '\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
            ValueName = '2200'
            ValueData = 3
        }
    }
    
    if ($Zones3_270C) {
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3\270C'
        {
            Key = '\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
            ValueName = '270C'
            ValueData = 0
        }
    }
    if ($Zones3_1001) {
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3\1001'
        {
            Key = '\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
            ValueName = '1001'
            ValueData = 3
        }
    }
    
    if ($Zones3_1004) {
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3\1004'
        {
            Key = '\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
            ValueName = '1004'
            ValueData = 3
        }
    }
    
    if ($Zones3_2709) {
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3\2709'
        {
            Key = '\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
            ValueName = '2709'
            ValueData = 3
        }
    }
    
    if ($Zones3_2708) {
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3\2708'
        {
            Key = '\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
            ValueName = '2708'
            ValueData = 3
        }
    }
    
    if ($Zones3_160A) {
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3\160A'
        {
            Key = '\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
            ValueName = '160A'
            ValueData = 3
        }
    }
    
    if ($Zones3_1201) {
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3\1201'
        {
            Key = '\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
            ValueName = '1201'
            ValueData = 3
        }
    }
    if ($Zones3_1C00) {
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3\1C00'
        {
            Key = '\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
            ValueName = '1C00'
            ValueData = 0
        }
    }
    
    if ($Zones3_1804) {
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3\1804'
        {
            Key = '\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
            ValueName = '1804'
            ValueData = 3
        }
    }
    
    if ($Zones3_1A00) {
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3\1A00'
        {
            Key = '\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
            ValueName = '1A00'
            ValueData = 65536
        }
    }
    
    if ($Zones3_1607) {
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3\1607'
        {
            Key = '\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
            ValueName = '1607'
            ValueData = 3
        }
    }
    
    if ($Zones3_2004) {
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3\2004'
        {
            Key = '\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
            ValueName = '2004'
            ValueData = 3
        }
    }
    
    if ($Zones3_2001) {
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3\2001'
        {
            Key = '\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
            ValueName = '2001'
            ValueData = 3
        }
    }
    if ($Zones3_1806) {
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3\1806'
        {
            Key = '\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
            ValueName = '1806'
            ValueData = 1
        }
    }
    
    if ($Zones3_1409) {
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3\1409'
        {
            Key = '\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
            ValueName = '1409'
            ValueData = 0
        }
    }
    
    if ($Zones3_2500) {
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3\2500'
        {
            Key = '\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
            ValueName = '2500'
            ValueData = 0
        }
    }
    
    if ($Zones3_2301) {
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3\2301'
        {
            Key = '\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
            ValueName = '2301'
            ValueData = 0
        }
    }
    
    if ($Zones3_1809) {
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3\1809'
        {
            Key = '\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
            ValueName = '1809'
            ValueData = 0
        }
    }
    
    if ($Zones3_1606) {
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3\1606'
        {
            Key = '\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
            ValueName = '1606'
            ValueData = 3
        }
    }

    if ($Zones3_2101) {
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3\2101'
        {
            Key = '\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
            ValueName = '2101'
            ValueData = 3
        }
    }
    
    if ($Zones3_140C) {
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3\140C'
        {
            Key = '\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
            ValueName = '140C'
            ValueData = 3
        }
    }
    
    if ($Zones4_1406) {
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\4\1406'
        {
            Key = '\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\4'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
            ValueName = '1406'
            ValueData = 3
        }
    }
    
    if ($Zones4_1400) {
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\4\1400'
        {
            Key = '\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\4'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
            ValueName = '1400'
            ValueData = 3
        }
    }
    
    if ($Zones4_2000) {
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\4\2000'
        {
            Key = '\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\4'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
            ValueName = '2000'
            ValueData = 3
        }
    }
    
    if ($Zones4_1407) {
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\4\1407'
        {
            Key = '\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\4'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
            ValueName = '1407'
            ValueData = 3
        }
    }

    if ($Zones4_1802) {
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\4\1802'
        {
            Key = '\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\4'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
            ValueName = '1802'
            ValueData = 3
        }
    }
    
    if ($Zones4_1803) {
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\4\1803'
        {
            Key = '\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\4'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
            ValueName = '1803'
            ValueData = 3
        }
    }
    
    if ($Zones4_2402) {
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\4\2402'
        {
            Key = '\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\4'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
            ValueName = '2402'
            ValueData = 3
        }
    }
    
    if ($Zones4_1608) {
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\4\1608'
        {
            Key = '\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\4'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
            ValueName = '1608'
            ValueData = 3
        }
    }
    
    if ($Zones4_120b) {
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\4\120b'
        {
            Key = '\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\4'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
            ValueName = '120b'
            ValueData = 3
        }
    }
    
    if ($Zones4_120c) {
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\4\120c'
        {
            Key = '\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\4'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
            ValueName = '120c'
            ValueData = 3
        }
    }

    if ($Zones4_1206) {
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\4\1206'
        {
            Key = '\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\4'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
            ValueName = '1206'
            ValueData = 3
        }
    }
    
    if ($Zones4_2102) {
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\4\2102'
        {
            Key = '\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\4'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
            ValueName = '2102'
            ValueData = 3
        }
    }
    
    if ($Zones4_1209) {
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\4\1209'
        {
            Key = '\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\4'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
            ValueName = '1209'
            ValueData = 3
        }
    }
    
    if ($Zones4_2103) {
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\4\2103'
        {
            Key = '\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\4'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
            ValueName = '2103'
            ValueData = 3
        }
    }
    
    if ($Zones4_2200) {
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\4\2200'
        {
            Key = '\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\4'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
            ValueName = '2200'
            ValueData = 3
        }
    }
    
    if ($Zones4_270C) {
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\4\270C'
        {
            Key = '\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\4'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
            ValueName = '270C'
            ValueData = 0
        }
    }

    if ($Zones4_1001) {
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\4\1001'
        {
            Key = '\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\4'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
            ValueName = '1001'
            ValueData = 3
        }
    }
    
    if ($Zones4_1004) {
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\4\1004'
        {
            Key = '\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\4'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
            ValueName = '1004'
            ValueData = 3
        }
    }
    
    if ($Zones4_2709) {
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\4\2709'
        {
            Key = '\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\4'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
            ValueName = '2709'
            ValueData = 3
        }
    }
    
    if ($Zones4_2708) {
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\4\2708'
        {
            Key = '\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\4'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
            ValueName = '2708'
            ValueData = 3
        }
    }
    
    if ($Zones4_160A) {
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\4\160A'
        {
            Key = '\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\4'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
            ValueName = '160A'
            ValueData = 3
        }
    }
    
    if ($Zones4_1201) {
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\4\1201'
        {
            Key = '\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\4'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
            ValueName = '1201'
            ValueData = 3
        }
    }
    if ($Zones4_1C00) {
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\4\1C00'
        {
            Key = '\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\4'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
            ValueName = '1C00'
            ValueData = 0
        }
    }
    
    if ($Zones4_1804) {
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\4\1804'
        {
            Key = '\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\4'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
            ValueName = '1804'
            ValueData = 3
        }
    }
    
    if ($Zones4_1A00) {
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\4\1A00'
        {
            Key = '\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\4'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
            ValueName = '1A00'
            ValueData = 196608
        }
    }
    
    if ($Zones4_1607) {
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\4\1607'
        {
            Key = '\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\4'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
            ValueName = '1607'
            ValueData = 3
        }
    }
    
    if ($Zones4_2004) {
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\4\2004'
        {
            Key = '\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\4'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
            ValueName = '2004'
            ValueData = 3
        }
    }
    if ($Zones4_1200) {
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\4\1200'
        {
            Key = '\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\4'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
            ValueName = '1200'
            ValueData = 3
        }
    }
    
    if ($Zones4_1405) {
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\4\1405'
        {
            Key = '\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\4'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
            ValueName = '1405'
            ValueData = 3
        }
    }
    
    if ($Zones4_1402) {
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\4\1402'
        {
            Key = '\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\4'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
            ValueName = '1402'
            ValueData = 3
        }
    }
    
    if ($Zones4_1806) {
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\4\1806'
        {
            Key = '\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\4'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
            ValueName = '1806'
            ValueData = 3
        }
    }
    if ($Zones4_1409) {
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\4\1409'
        {
            Key = '\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\4'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
            ValueName = '1409'
            ValueData = 0
        }
    }
    
    if ($Zones4_2500) {
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\4\2500'
        {
            Key = '\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\4'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
            ValueName = '2500'
            ValueData = 0
        }
    }
    
    if ($Zones4_2301) {
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\4\2301'
        {
            Key = '\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\4'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
            ValueName = '2301'
            ValueData = 0
        }
    }
    
    if ($Zones4_1809) {
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\4\1809'
        {
            Key = '\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\4'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
            ValueName = '1809'
            ValueData = 0
        }
    }
    
    if ($Zones4_1606) {
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\4\1606'
        {
            Key = '\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\4'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
            ValueName = '1606'
            ValueData = 3
        }
    }
    
    if ($Zones4_2101) {
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\4\2101'
        {
            Key = '\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\4'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
            ValueName = '2101'
            ValueData = 3
        }
    }
    
    if ($Zones4_2001) {
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\4\2001'
        {
            Key = '\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\4'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
            ValueName = '2001'
            ValueData = 3
        }
    }
    
    if ($Zones4_140C) {
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\4\140C'
        {
            Key = '\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\4'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
            ValueName = '140C'
            ValueData = 3
        }
    }
}

