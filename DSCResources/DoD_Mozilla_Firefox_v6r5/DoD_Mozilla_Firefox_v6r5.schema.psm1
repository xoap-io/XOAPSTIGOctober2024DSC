configuration DoD_Mozilla_Firefox_v6r5
{

    param(
        [bool]$SSLVersionMin = $true,
        [bool]$ExtensionUpdate = $true,
        [bool]$DisableFormHistory = $true,
        [bool]$PasswordManagerEnabled = $true,
        [bool]$DisableTelemetry = $true,
        [bool]$DisableDeveloperTools = $true,
        [bool]$DisableForgetButton = $true,
        [bool]$DisablePrivateBrowsing = $true,
        [bool]$SearchSuggestEnabled = $true,
        [bool]$NetworkPrediction = $true,
        [bool]$DisableFirefoxAccounts = $true,
        [bool]$DisableFeedbackCommands = $true,
        [bool]$Preferences = $true,
        [bool]$DisablePocket = $true,
        [bool]$DisableFirefoxStudies = $true,
        [bool]$ImportEnterpriseRoots = $true,
        [bool]$DisabledCiphersTLS_RSA_WITH_3DES_EDE_CBC_SHA = $true,
        [bool]$EnableTrackingProtectionFingerprinting = $true,
        [bool]$EnableTrackingProtectionCryptomining = $true,
        [bool]$EncryptedMediaExtensionsEnabled = $true,
        [bool]$EncryptedMediaExtensionsLocked = $true,
        [bool]$FirefoxHomeSearch = $true,
        [bool]$FirefoxHomeTopSites = $true,
        [bool]$FirefoxHomeSponsoredTopSites = $true,
        [bool]$FirefoxHomeHighlights = $true,
        [bool]$FirefoxHomePocket = $true,
        [bool]$FirefoxHomeSponsoredPocket = $true,
        [bool]$Snippets = $true,
        [bool]$Locked = $true,
        [bool]$InstallAddonsPermissionDefault = $true,
        [bool]$PermissionsAutoplayDefault = $true,
        [bool]$PopupBlockingDefault = $true,
        [bool]$PopupBlockingLocked = $true,
        [bool]$PopupBlockingAllow1 = $true,
        [bool]$PopupBlockingAllow2 = $true,
        [bool]$SanitizeOnShutdownCache = $true,
        [bool]$SanitizeOnShutdownCookies = $true,
        [bool]$SanitizeOnShutdownDownloads = $true,
        [bool]$SanitizeOnShutdownFormData = $true,
        [bool]$SanitizeOnShutdownHistory = $true,
        [bool]$SanitizeOnShutdownSessions = $true,
        [bool]$SanitizeOnShutdownSiteSettings = $true,
        [bool]$SanitizeOnShutdownOfflineApps = $true,
        [bool]$SanitizeOnShutdownLocked = $true,
        [bool]$ExtensionRecommendations = $true
    )

    Import-DSCResource -ModuleName 'GPRegistryPolicyDsc'
	Import-DSCResource -ModuleName 'AuditPolicyDSC'
	Import-DSCResource -ModuleName 'SecurityPolicyDSC'

    if ($SSLVersionMin) {
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Mozilla\Firefox\SSLVersionMin'
        {
            Key = '\Software\Policies\Mozilla\Firefox'
            ValueType = 'String'
            TargetType = 'ComputerConfiguration'
            ValueName = 'SSLVersionMin'
            ValueData = 'tls1.2'
        }
    }
    
    if ($ExtensionUpdate) {
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Mozilla\Firefox\ExtensionUpdate'
        {
            Key = '\Software\Policies\Mozilla\Firefox'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
            ValueName = 'ExtensionUpdate'
            ValueData = 0
        }
    }
    
    if ($DisableFormHistory) {
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Mozilla\Firefox\DisableFormHistory'
        {
            Key = '\Software\Policies\Mozilla\Firefox'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
            ValueName = 'DisableFormHistory'
            ValueData = 1
        }
    }
    
    if ($PasswordManagerEnabled) {
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Mozilla\Firefox\PasswordManagerEnabled'
        {
            Key = '\Software\Policies\Mozilla\Firefox'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
            ValueName = 'PasswordManagerEnabled'
            ValueData = 0
        }
    }
    
    if ($DisableTelemetry) {
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Mozilla\Firefox\DisableTelemetry'
        {
            Key = '\Software\Policies\Mozilla\Firefox'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
            ValueName = 'DisableTelemetry'
            ValueData = 1
        }
    }
    
    if ($DisableDeveloperTools) {
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Mozilla\Firefox\DisableDeveloperTools'
        {
            Key = '\Software\Policies\Mozilla\Firefox'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
            ValueName = 'DisableDeveloperTools'
            ValueData = 1
        }
    }

    if ($DisableForgetButton) {
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Mozilla\Firefox\DisableForgetButton'
        {
            Key = '\Software\Policies\Mozilla\Firefox'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
            ValueName = 'DisableForgetButton'
            ValueData = 1
        }
    }
    
    if ($DisablePrivateBrowsing) {
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Mozilla\Firefox\DisablePrivateBrowsing'
        {
            Key = '\Software\Policies\Mozilla\Firefox'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
            ValueName = 'DisablePrivateBrowsing'
            ValueData = 1
        }
    }
    
    if ($SearchSuggestEnabled) {
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Mozilla\Firefox\SearchSuggestEnabled'
        {
            Key = '\Software\Policies\Mozilla\Firefox'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
            ValueName = 'SearchSuggestEnabled'
            ValueData = 0
        }
    }
    
    if ($NetworkPrediction) {
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Mozilla\Firefox\NetworkPrediction'
        {
            Key = '\Software\Policies\Mozilla\Firefox'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
            ValueName = 'NetworkPrediction'
            ValueData = 0
        }
    }
    
    if ($DisableFirefoxAccounts) {
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Mozilla\Firefox\DisableFirefoxAccounts'
        {
            Key = '\Software\Policies\Mozilla\Firefox'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
            ValueName = 'DisableFirefoxAccounts'
            ValueData = 1
        }
    }
    if ($DisableFeedbackCommands) {
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Mozilla\Firefox\DisableFeedbackCommands'
        {
            Key = '\Software\Policies\Mozilla\Firefox'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
            ValueName = 'DisableFeedbackCommands'
            ValueData = 1
        }
    }
    
    if ($Preferences) {
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Mozilla\Firefox\Preferences'
        {
            Key = '\Software\Policies\Mozilla\Firefox'
            ValueType = 'MultiString'
            TargetType = 'ComputerConfiguration'
            ValueName = 'Preferences'
            ValueData = '{"security.default_personal_cert": {"Value": "Ask Every Time","Status": "locked"},"browser.search.update": {"Value": false,"Status": "locked"},"dom.disable_window_move_resize": {"Value": true,"Status": "locked"},"dom.disable_window_flip": {"Value": true,"Status": "locked"},"browser.contentblocking.category": {"Value": "strict","Status": "locked"},"extensions.htmlaboutaddons.recommendations.enabled": {"Value": false,"Status": "locked"}}'
        }
    }
    
    if ($DisablePocket) {
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Mozilla\Firefox\DisablePocket'
        {
            Key = '\Software\Policies\Mozilla\Firefox'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
            ValueName = 'DisablePocket'
            ValueData = 1
        }
    }
    
    if ($DisableFirefoxStudies) {
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Mozilla\Firefox\DisableFirefoxStudies'
        {
            Key = '\Software\Policies\Mozilla\Firefox'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
            ValueName = 'DisableFirefoxStudies'
            ValueData = 1
        }
    }
    
    if ($ImportEnterpriseRoots) {
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Mozilla\Firefox\Certificates\ImportEnterpriseRoots'
        {
            Key = '\Software\Policies\Mozilla\Firefox\Certificates'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
            ValueName = 'ImportEnterpriseRoots'
            ValueData = 1
        }
    }
    
    if ($DisabledCiphersTLS_RSA_WITH_3DES_EDE_CBC_SHA) {
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Mozilla\Firefox\DisabledCiphers\TLS_RSA_WITH_3DES_EDE_CBC_SHA'
        {
            Key = '\Software\Policies\Mozilla\Firefox\DisabledCiphers'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
            ValueName = 'TLS_RSA_WITH_3DES_EDE_CBC_SHA'
            ValueData = 1
        }
    }

    if ($EnableTrackingProtectionFingerprinting) {
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Mozilla\Firefox\EnableTrackingProtection\Fingerprinting'
        {
            Key = '\Software\Policies\Mozilla\Firefox\EnableTrackingProtection'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
            ValueName = 'Fingerprinting'
            ValueData = 1
        }
    }
    
    if ($EnableTrackingProtectionCryptomining) {
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Mozilla\Firefox\EnableTrackingProtection\Cryptomining'
        {
            Key = '\Software\Policies\Mozilla\Firefox\EnableTrackingProtection'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
            ValueName = 'Cryptomining'
            ValueData = 1
        }
    }
    
    if ($EncryptedMediaExtensionsEnabled) {
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Mozilla\Firefox\EncryptedMediaExtensions\Enabled'
        {
            Key = '\Software\Policies\Mozilla\Firefox\EncryptedMediaExtensions'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
            ValueName = 'Enabled'
            ValueData = 0
        }
    }
    
    if ($EncryptedMediaExtensionsLocked) {
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Mozilla\Firefox\EncryptedMediaExtensions\Locked'
        {
            Key = '\Software\Policies\Mozilla\Firefox\EncryptedMediaExtensions'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
            ValueName = 'Locked'
            ValueData = 1
        }
    }
    
    if ($FirefoxHomeSearch) {
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Mozilla\Firefox\FirefoxHome\Search'
        {
            Key = '\Software\Policies\Mozilla\Firefox\FirefoxHome'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
            ValueName = 'Search'
            ValueData = 0
        }
    }

    if ($Snippets) {
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Mozilla\Firefox\FirefoxHome\Snippets'
        {
            Key = '\Software\Policies\Mozilla\Firefox\FirefoxHome'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
            ValueName = 'Snippets'
            ValueData = 0
        }
    }
    
    if ($Locked) {
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Mozilla\Firefox\FirefoxHome\Locked'
        {
            Key = '\Software\Policies\Mozilla\Firefox\FirefoxHome'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
            ValueName = 'Locked'
            ValueData = 1
        }
    }
    
    if ($InstallAddonsPermissionDefault) {
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Mozilla\Firefox\InstallAddonsPermission\Default'
        {
            Key = '\Software\Policies\Mozilla\Firefox\InstallAddonsPermission'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
            ValueName = 'Default'
            ValueData = 0
        }
    }
    
    if ($PermissionsAutoplayDefault) {
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Mozilla\Firefox\Permissions\Autoplay\Default'
        {
            Key = '\Software\Policies\Mozilla\Firefox\Permissions\Autoplay'
            ValueType = 'String'
            TargetType = 'ComputerConfiguration'
            ValueName = 'Default'
            ValueData = 'block-audio-video'
        }
    }
    
    if ($PopupBlockingDefault) {
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Mozilla\Firefox\PopupBlocking\Default'
        {
            Key = '\Software\Policies\Mozilla\Firefox\PopupBlocking'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
            ValueName = 'Default'
            ValueData = 1
        }
    }

    if ($PopupBlockingLocked) {
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Mozilla\Firefox\PopupBlocking\Locked'
        {
            Key = '\Software\Policies\Mozilla\Firefox\PopupBlocking'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
            ValueName = 'Locked'
            ValueData = 1
        }
    }
    
    if ($PopupBlockingAllow1) {
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Mozilla\Firefox\PopupBlocking\Allow\1'
        {
            Key = '\Software\Policies\Mozilla\Firefox\PopupBlocking\Allow'
            ValueType = 'String'
            TargetType = 'ComputerConfiguration'
            ValueName = '1'
            ValueData = '.mil'
        }
    }
    
    if ($PopupBlockingAllow2) {
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Mozilla\Firefox\PopupBlocking\Allow\2'
        {
            Key = '\Software\Policies\Mozilla\Firefox\PopupBlocking\Allow'
            ValueType = 'String'
            TargetType = 'ComputerConfiguration'
            ValueName = '2'
            ValueData = '.gov'
        }
    }
    
    if ($SanitizeOnShutdownCache) {
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Mozilla\Firefox\SanitizeOnShutdown\Cache'
        {
            Key = '\Software\Policies\Mozilla\Firefox\SanitizeOnShutdown'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
            ValueName = 'Cache'
            ValueData = 0
        }
    }
    
    if ($SanitizeOnShutdownCookies) {
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Mozilla\Firefox\SanitizeOnShutdown\Cookies'
        {
            Key = '\Software\Policies\Mozilla\Firefox\SanitizeOnShutdown'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
            ValueName = 'Cookies'
            ValueData = 0
        }
    }
    
    if ($SanitizeOnShutdownDownloads) {
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Mozilla\Firefox\SanitizeOnShutdown\Downloads'
        {
            Key = '\Software\Policies\Mozilla\Firefox\SanitizeOnShutdown'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
            ValueName = 'Downloads'
            ValueData = 0
        }
    }
    
    if ($SanitizeOnShutdownFormData) {
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Mozilla\Firefox\SanitizeOnShutdown\FormData'
        {
            Key = '\Software\Policies\Mozilla\Firefox\SanitizeOnShutdown'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
            ValueName = 'FormData'
            ValueData = 0
        }
    }
    
    if ($SanitizeOnShutdownHistory) {
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Mozilla\Firefox\SanitizeOnShutdown\History'
        {
            Key = '\Software\Policies\Mozilla\Firefox\SanitizeOnShutdown'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
            ValueName = 'History'
            ValueData = 0
        }
    }
    
    if ($SanitizeOnShutdownSessions) {
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Mozilla\Firefox\SanitizeOnShutdown\Sessions'
        {
            Key = '\Software\Policies\Mozilla\Firefox\SanitizeOnShutdown'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
            ValueName = 'Sessions'
            ValueData = 0
        }
    }
    
    if ($SanitizeOnShutdownSiteSettings) {
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Mozilla\Firefox\SanitizeOnShutdown\SiteSettings'
        {
            Key = '\Software\Policies\Mozilla\Firefox\SanitizeOnShutdown'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
            ValueName = 'SiteSettings'
            ValueData = 0
        }
    }
    
    if ($SanitizeOnShutdownOfflineApps) {
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Mozilla\Firefox\SanitizeOnShutdown\OfflineApps'
        {
            Key = '\Software\Policies\Mozilla\Firefox\SanitizeOnShutdown'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
            ValueName = 'OfflineApps'
            ValueData = 0
        }
    }
    
    if ($SanitizeOnShutdownLocked) {
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Mozilla\Firefox\SanitizeOnShutdown\Locked'
        {
            Key = '\Software\Policies\Mozilla\Firefox\SanitizeOnShutdown'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
            ValueName = 'Locked'
            ValueData = 1
        }
    }
    
    if ($ExtensionRecommendations) {
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Mozilla\Firefox\UserMessaging\ExtensionRecommendations'
        {
            Key = '\Software\Policies\Mozilla\Firefox\UserMessaging'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
            ValueName = 'ExtensionRecommendations'
            ValueData = 0
        }
    }
    
}

