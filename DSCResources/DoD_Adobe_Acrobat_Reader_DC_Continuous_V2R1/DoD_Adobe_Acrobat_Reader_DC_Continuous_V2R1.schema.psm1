configuration DoD_Adobe_Acrobat_Reader_DC_Continuous_V2R1
{

    param(
        [bool]$DisableMaintenance = $true,
        [bool]$bEnhancedSecurityStandalone = $true,
        [bool]$bProtectedMode = $true,
        [bool]$iProtectedView = $true,
        [bool]$iFileAttachmentPerms = $true,
        [bool]$bEnableFlash = $true,
        [bool]$bDisablePDFHandlerSwitching = $true,
        [bool]$bAcroSuppressUpsell = $true,
        [bool]$bEnhancedSecurityInBrowser = $true,
        [bool]$bDisableTrustedFolders = $true,
        [bool]$bDisableTrustedSites = $true,
        [bool]$bAdobeSendPluginToggle = $true,
        [bool]$iURLPerms = $true,
        [bool]$iUnknownURLPerms = $true,
        [bool]$bToggleAdobeDocumentServices = $true,
        [bool]$bTogglePrefsSync = $true,
        [bool]$bToggleWebConnectors = $true,
        [bool]$bToggleAdobeSign = $true,
        [bool]$bUpdater = $true,
        [bool]$bDisableSharePointFeatures = $true,
        [bool]$bDisableWebmail = $true,
        [bool]$bShowWelcomeScreen = $true      
    )

	Import-DSCResource -ModuleName 'GPRegistryPolicyDsc'
	Import-DSCResource -ModuleName 'AuditPolicyDSC'
	Import-DSCResource -ModuleName 'SecurityPolicyDSC'

    if ($DisableMaintenance) {
        RegistryPolicyFile 'Registry(POL): HKLM:\SOFTWARE\Adobe\Acrobat Reader\DC\Installer\DisableMaintenance'
        {
            Key = '\SOFTWARE\Adobe\Acrobat Reader\DC\Installer'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
            ValueName = 'DisableMaintenance'
            ValueData = 1
        }
    }
    
    if ($bEnhancedSecurityStandalone) {
        RegistryPolicyFile 'Registry(POL): HKLM:\SOFTWARE\Policies\Adobe\Acrobat Reader\DC\FeatureLockdown\bEnhancedSecurityStandalone'
        {
            Key = '\SOFTWARE\Policies\Adobe\Acrobat Reader\DC\FeatureLockdown'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
            ValueName = 'bEnhancedSecurityStandalone'
            ValueData = 1
        }
    }
    
    if ($bProtectedMode) {
        RegistryPolicyFile 'Registry(POL): HKLM:\SOFTWARE\Policies\Adobe\Acrobat Reader\DC\FeatureLockdown\bProtectedMode'
        {
            Key = '\SOFTWARE\Policies\Adobe\Acrobat Reader\DC\FeatureLockdown'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
            ValueName = 'bProtectedMode'
            ValueData = 1
        }
    }
    
    if ($iProtectedView) {
        RegistryPolicyFile 'Registry(POL): HKLM:\SOFTWARE\Policies\Adobe\Acrobat Reader\DC\FeatureLockdown\iProtectedView'
        {
            Key = '\SOFTWARE\Policies\Adobe\Acrobat Reader\DC\FeatureLockdown'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
            ValueName = 'iProtectedView'
            ValueData = 2
        }
    }

    if ($iFileAttachmentPerms) {
        RegistryPolicyFile 'Registry(POL): HKLM:\SOFTWARE\Policies\Adobe\Acrobat Reader\DC\FeatureLockdown\iFileAttachmentPerms'
        {
            Key = '\SOFTWARE\Policies\Adobe\Acrobat Reader\DC\FeatureLockdown'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
            ValueName = 'iFileAttachmentPerms'
            ValueData = 1
        }
    }
    
    if ($bEnableFlash) {
        RegistryPolicyFile 'Registry(POL): HKLM:\SOFTWARE\Policies\Adobe\Acrobat Reader\DC\FeatureLockdown\bEnableFlash'
        {
            Key = '\SOFTWARE\Policies\Adobe\Acrobat Reader\DC\FeatureLockdown'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
            ValueName = 'bEnableFlash'
            ValueData = 0
        }
    }
    
    if ($bDisablePDFHandlerSwitching) {
        RegistryPolicyFile 'Registry(POL): HKLM:\SOFTWARE\Policies\Adobe\Acrobat Reader\DC\FeatureLockdown\bDisablePDFHandlerSwitching'
        {
            Key = '\SOFTWARE\Policies\Adobe\Acrobat Reader\DC\FeatureLockdown'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
            ValueName = 'bDisablePDFHandlerSwitching'
            ValueData = 1
        }
    }
    
    if ($bAcroSuppressUpsell) {
        RegistryPolicyFile 'Registry(POL): HKLM:\SOFTWARE\Policies\Adobe\Acrobat Reader\DC\FeatureLockdown\bAcroSuppressUpsell'
        {
            Key = '\SOFTWARE\Policies\Adobe\Acrobat Reader\DC\FeatureLockdown'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
            ValueName = 'bAcroSuppressUpsell'
            ValueData = 1
        }
    }

    if ($bEnhancedSecurityInBrowser) {
        RegistryPolicyFile 'Registry(POL): HKLM:\SOFTWARE\Policies\Adobe\Acrobat Reader\DC\FeatureLockdown\bEnhancedSecurityInBrowser'
        {
            Key = '\SOFTWARE\Policies\Adobe\Acrobat Reader\DC\FeatureLockdown'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
            ValueName = 'bEnhancedSecurityInBrowser'
            ValueData = 1
        }
    }
    
    if ($bDisableTrustedFolders) {
        RegistryPolicyFile 'Registry(POL): HKLM:\SOFTWARE\Policies\Adobe\Acrobat Reader\DC\FeatureLockdown\bDisableTrustedFolders'
        {
            Key = '\SOFTWARE\Policies\Adobe\Acrobat Reader\DC\FeatureLockdown'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
            ValueName = 'bDisableTrustedFolders'
            ValueData = 1
        }
    }
    
    if ($bDisableTrustedSites) {
        RegistryPolicyFile 'Registry(POL): HKLM:\SOFTWARE\Policies\Adobe\Acrobat Reader\DC\FeatureLockdown\bDisableTrustedSites'
        {
            Key = '\SOFTWARE\Policies\Adobe\Acrobat Reader\DC\FeatureLockdown'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
            ValueName = 'bDisableTrustedSites'
            ValueData = 1
        }
    }
    
    if ($bAdobeSendPluginToggle) {
        RegistryPolicyFile 'Registry(POL): HKLM:\SOFTWARE\Policies\Adobe\Acrobat Reader\DC\FeatureLockdown\cCloud\bAdobeSendPluginToggle'
        {
            Key = '\SOFTWARE\Policies\Adobe\Acrobat Reader\DC\FeatureLockdown\cCloud'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
            ValueName = 'bAdobeSendPluginToggle'
            ValueData = 1
        }
    }

    if ($iURLPerms) {
        RegistryPolicyFile 'Registry(POL): HKLM:\SOFTWARE\Policies\Adobe\Acrobat Reader\DC\FeatureLockdown\cDefaultLaunchURLPerms\iURLPerms'
        {
            Key = '\SOFTWARE\Policies\Adobe\Acrobat Reader\DC\FeatureLockdown\cDefaultLaunchURLPerms'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
            ValueName = 'iURLPerms'
            ValueData = 1
        }
    }
    
    if ($iUnknownURLPerms) {
        RegistryPolicyFile 'Registry(POL): HKLM:\SOFTWARE\Policies\Adobe\Acrobat Reader\DC\FeatureLockdown\cDefaultLaunchURLPerms\iUnknownURLPerms'
        {
            Key = '\SOFTWARE\Policies\Adobe\Acrobat Reader\DC\FeatureLockdown\cDefaultLaunchURLPerms'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
            ValueName = 'iUnknownURLPerms'
            ValueData = 3
        }
    }
    
    if ($bToggleAdobeDocumentServices) {
        RegistryPolicyFile 'Registry(POL): HKLM:\SOFTWARE\Policies\Adobe\Acrobat Reader\DC\FeatureLockdown\cServices\bToggleAdobeDocumentServices'
        {
            Key = '\SOFTWARE\Policies\Adobe\Acrobat Reader\DC\FeatureLockdown\cServices'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
            ValueName = 'bToggleAdobeDocumentServices'
            ValueData = 1
        }
    }
    
    if ($bTogglePrefsSync) {
        RegistryPolicyFile 'Registry(POL): HKLM:\SOFTWARE\Policies\Adobe\Acrobat Reader\DC\FeatureLockdown\cServices\bTogglePrefsSync'
        {
            Key = '\SOFTWARE\Policies\Adobe\Acrobat Reader\DC\FeatureLockdown\cServices'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
            ValueName = 'bTogglePrefsSync'
            ValueData = 1
        }
    }
    if ($bToggleWebConnectors) {
        RegistryPolicyFile 'Registry(POL): HKLM:\SOFTWARE\Policies\Adobe\Acrobat Reader\DC\FeatureLockdown\cServices\bToggleWebConnectors'
        {
            Key = '\SOFTWARE\Policies\Adobe\Acrobat Reader\DC\FeatureLockdown\cServices'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
            ValueName = 'bToggleWebConnectors'
            ValueData = 1
        }
    }
    
    if ($bToggleAdobeSign) {
        RegistryPolicyFile 'Registry(POL): HKLM:\SOFTWARE\Policies\Adobe\Acrobat Reader\DC\FeatureLockdown\cServices\bToggleAdobeSign'
        {
            Key = '\SOFTWARE\Policies\Adobe\Acrobat Reader\DC\FeatureLockdown\cServices'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
            ValueName = 'bToggleAdobeSign'
            ValueData = 1
        }
    }
    
    if ($bUpdater) {
        RegistryPolicyFile 'Registry(POL): HKLM:\SOFTWARE\Policies\Adobe\Acrobat Reader\DC\FeatureLockdown\cServices\bUpdater'
        {
            Key = '\SOFTWARE\Policies\Adobe\Acrobat Reader\DC\FeatureLockdown\cServices'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
            ValueName = 'bUpdater'
            ValueData = 0
        }
    }
    
    if ($bDisableSharePointFeatures) {
        RegistryPolicyFile 'Registry(POL): HKLM:\SOFTWARE\Policies\Adobe\Acrobat Reader\DC\FeatureLockdown\cSharePoint\bDisableSharePointFeatures'
        {
            Key = '\SOFTWARE\Policies\Adobe\Acrobat Reader\DC\FeatureLockdown\cSharePoint'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
            ValueName = 'bDisableSharePointFeatures'
            ValueData = 1
        }
    }
    
    if ($bDisableWebmail) {
        RegistryPolicyFile 'Registry(POL): HKLM:\SOFTWARE\Policies\Adobe\Acrobat Reader\DC\FeatureLockdown\cWebmailProfiles\bDisableWebmail'
        {
            Key = '\SOFTWARE\Policies\Adobe\Acrobat Reader\DC\FeatureLockdown\cWebmailProfiles'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
            ValueName = 'bDisableWebmail'
            ValueData = 1
        }
    }
    
    if ($bShowWelcomeScreen) {
        RegistryPolicyFile 'Registry(POL): HKLM:\SOFTWARE\Policies\Adobe\Acrobat Reader\DC\FeatureLockdown\cWelcomeScreen\bShowWelcomeScreen'
        {
            Key = '\SOFTWARE\Policies\Adobe\Acrobat Reader\DC\FeatureLockdown\cWelcomeScreen'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
            ValueName = 'bShowWelcomeScreen'
            ValueData = 0
        }
    }
    
    if ($DisableMaintenance) {
        RegistryPolicyFile 'Registry(POL): HKLM:\SOFTWARE\Wow6432Node\Adobe\Acrobat Reader\DC\Installer\DisableMaintenance'
        {
            Key = '\SOFTWARE\Wow6432Node\Adobe\Acrobat Reader\DC\Installer'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
            ValueName = 'DisableMaintenance'
            ValueData = 1
        }
    }
}

