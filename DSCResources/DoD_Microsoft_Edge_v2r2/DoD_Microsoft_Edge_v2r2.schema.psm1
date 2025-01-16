configuration DoD_Microsoft_Edge_v2r2
{

    param(
        [bool]$SyncDisabled = $true,
        [bool]$ImportBrowserSettings = $true,
        [bool]$DeveloperToolsAvailability = $true,
        [bool]$PromptForDownloadLocation = $true,
        [bool]$PreventSmartScreenPromptOverride = $true,
        [bool]$PreventSmartScreenPromptOverrideForFiles = $true,
        [bool]$InPrivateModeAvailability = $true,
        [bool]$AllowDeletingBrowserHistory = $true,
        [bool]$BackgroundModeEnabled = $true,
        [bool]$DefaultPopupsSetting = $true,
        [bool]$NetworkPredictionOptions = $true,
        [bool]$SearchSuggestEnabled = $true,
        [bool]$ImportAutofillFormData = $true,
        [bool]$ImportCookies = $true,
        [bool]$ImportExtensions = $true,
        [bool]$ImportHistory = $true,
        [bool]$ImportHomepage = $true,
        [bool]$ImportOpenTabs = $true,
        [bool]$ImportPaymentInfo = $true,
        [bool]$ImportSavedPasswords = $true,
        [bool]$ImportSearchEngine = $true,
        [bool]$ImportShortcuts = $true,
        [bool]$AutoplayAllowed = $true,
        [bool]$EnableMediaRouter = $true,
        [bool]$AutofillCreditCardEnabled = $true,
        [bool]$AutofillAddressEnabled = $true,
        [bool]$PersonalizationReportingEnabled = $true,
        [bool]$DefaultGeolocationSetting = $true,
        [bool]$PasswordManagerEnabled = $true,
        [bool]$IsolateOrigins = $true,
        [bool]$SmartScreenEnabled = $true,
        [bool]$SmartScreenPuaEnabled = $true,
        [bool]$PaymentMethodQueryEnabled = $true,
        [bool]$AlternateErrorPagesEnabled = $true,
        [bool]$UserFeedbackAllowed = $true,
        [bool]$EdgeCollectionsEnabled = $true,
        [bool]$ConfigureShare = $true,
        [bool]$BrowserGuestModeEnabled = $true,
        [bool]$BuiltInDnsClientEnabled = $true,
        [bool]$SitePerProcess = $true,
        [bool]$ManagedSearchEngines = $true,
        [bool]$AuthSchemes = $true,
        [bool]$DefaultWebUsbGuardSetting = $true,
        [bool]$DefaultWebBluetoothGuardSetting = $true,
        [bool]$TrackingPrevention = $true,
        [bool]$RelaunchNotification = $true,
        [bool]$ProxySettings = $true,
        [bool]$EnableOnlineRevocationChecks = $true,
        [bool]$QuicAllowed = $true,
        [bool]$DownloadRestrictions = $true,
        [bool]$VisualSearchEnabled = $true,
        [bool]$HubsSidebarEnabled = $true,
        [bool]$DefaultCookiesSetting = $true,
        [bool]$ConfigureFriendlyURLFormat = $true,
        [bool]$AutoplayAllowlist1 = $true,
        [bool]$AutoplayAllowlist2 = $true,
        [bool]$ExtensionInstallBlocklist1 = $true,
        [bool]$PopupsAllowedForUrls1 = $true,
        [bool]$PopupsAllowedForUrls2 = $true
    )

	Import-DSCResource -ModuleName 'GPRegistryPolicyDsc'
	Import-DSCResource -ModuleName 'AuditPolicyDSC'
	Import-DSCResource -ModuleName 'SecurityPolicyDSC'

    if ($SyncDisabled) {
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Edge\SyncDisabled'
        {
            Key = '\Software\Policies\Microsoft\Edge'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
            ValueName = 'SyncDisabled'
            ValueData = 1
        }
    }
    
    if ($ImportBrowserSettings) {
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Edge\ImportBrowserSettings'
        {
            Key = '\Software\Policies\Microsoft\Edge'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
            ValueName = 'ImportBrowserSettings'
            ValueData = 0
        }
    }
    
    if ($DeveloperToolsAvailability) {
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Edge\DeveloperToolsAvailability'
        {
            Key = '\Software\Policies\Microsoft\Edge'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
            ValueName = 'DeveloperToolsAvailability'
            ValueData = 2
        }
    }
    
    if ($PromptForDownloadLocation) {
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Edge\PromptForDownloadLocation'
        {
            Key = '\Software\Policies\Microsoft\Edge'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
            ValueName = 'PromptForDownloadLocation'
            ValueData = 1
        }
    }
    
    if ($PreventSmartScreenPromptOverride) {
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Edge\PreventSmartScreenPromptOverride'
        {
            Key = '\Software\Policies\Microsoft\Edge'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
            ValueName = 'PreventSmartScreenPromptOverride'
            ValueData = 1
        }
    }
    
    if ($PreventSmartScreenPromptOverrideForFiles) {
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Edge\PreventSmartScreenPromptOverrideForFiles'
        {
            Key = '\Software\Policies\Microsoft\Edge'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
            ValueName = 'PreventSmartScreenPromptOverrideForFiles'
            ValueData = 1
        }
    }
    if ($InPrivateModeAvailability) {
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Edge\InPrivateModeAvailability'
        {
            Key = '\Software\Policies\Microsoft\Edge'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
            ValueName = 'InPrivateModeAvailability'
            ValueData = 1
        }
    }
    
    if ($AllowDeletingBrowserHistory) {
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Edge\AllowDeletingBrowserHistory'
        {
            Key = '\Software\Policies\Microsoft\Edge'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
            ValueName = 'AllowDeletingBrowserHistory'
            ValueData = 0
        }
    }
    
    if ($BackgroundModeEnabled) {
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Edge\BackgroundModeEnabled'
        {
            Key = '\Software\Policies\Microsoft\Edge'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
            ValueName = 'BackgroundModeEnabled'
            ValueData = 0
        }
    }
    
    if ($DefaultPopupsSetting) {
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Edge\DefaultPopupsSetting'
        {
            Key = '\Software\Policies\Microsoft\Edge'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
            ValueName = 'DefaultPopupsSetting'
            ValueData = 2
        }
    }

    if ($NetworkPredictionOptions) {
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Edge\NetworkPredictionOptions'
        {
            Key = '\Software\Policies\Microsoft\Edge'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
            ValueName = 'NetworkPredictionOptions'
            ValueData = 2
        }
    }
    
    if ($SearchSuggestEnabled) {
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Edge\SearchSuggestEnabled'
        {
            Key = '\Software\Policies\Microsoft\Edge'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
            ValueName = 'SearchSuggestEnabled'
            ValueData = 0
        }
    }
    
    if ($ImportAutofillFormData) {
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Edge\ImportAutofillFormData'
        {
            Key = '\Software\Policies\Microsoft\Edge'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
            ValueName = 'ImportAutofillFormData'
            ValueData = 0
        }
    }
    
    if ($ImportCookies) {
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Edge\ImportCookies'
        {
            Key = '\Software\Policies\Microsoft\Edge'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
            ValueName = 'ImportCookies'
            ValueData = 0
        }
    }
    
    if ($ImportExtensions) {
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Edge\ImportExtensions'
        {
            Key = '\Software\Policies\Microsoft\Edge'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
            ValueName = 'ImportExtensions'
            ValueData = 0
        }
    }

    if ($ImportHistory) {
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Edge\ImportHistory'
        {
            Key = '\Software\Policies\Microsoft\Edge'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
            ValueName = 'ImportHistory'
            ValueData = 0
        }
    }
    
    if ($ImportHomepage) {
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Edge\ImportHomepage'
        {
            Key = '\Software\Policies\Microsoft\Edge'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
            ValueName = 'ImportHomepage'
            ValueData = 0
        }
    }
    
    if ($ImportOpenTabs) {
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Edge\ImportOpenTabs'
        {
            Key = '\Software\Policies\Microsoft\Edge'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
            ValueName = 'ImportOpenTabs'
            ValueData = 0
        }
    }
    
    if ($ImportPaymentInfo) {
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Edge\ImportPaymentInfo'
        {
            Key = '\Software\Policies\Microsoft\Edge'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
            ValueName = 'ImportPaymentInfo'
            ValueData = 0
        }
    }
    
    if ($ImportSavedPasswords) {
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Edge\ImportSavedPasswords'
        {
            Key = '\Software\Policies\Microsoft\Edge'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
            ValueName = 'ImportSavedPasswords'
            ValueData = 0
        }
    }

    if ($ImportSearchEngine) {
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Edge\ImportSearchEngine'
        {
            Key = '\Software\Policies\Microsoft\Edge'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
            ValueName = 'ImportSearchEngine'
            ValueData = 0
        }
    }
    
    if ($ImportShortcuts) {
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Edge\ImportShortcuts'
        {
            Key = '\Software\Policies\Microsoft\Edge'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
            ValueName = 'ImportShortcuts'
            ValueData = 0
        }
    }
    
    if ($AutoplayAllowed) {
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Edge\AutoplayAllowed'
        {
            Key = '\Software\Policies\Microsoft\Edge'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
            ValueName = 'AutoplayAllowed'
            ValueData = 0
        }
    }
    
    if ($EnableMediaRouter) {
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Edge\EnableMediaRouter'
        {
            Key = '\Software\Policies\Microsoft\Edge'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
            ValueName = 'EnableMediaRouter'
            ValueData = 0
        }
    }
    if ($AutofillCreditCardEnabled) {
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Edge\AutofillCreditCardEnabled'
        {
            Key = '\Software\Policies\Microsoft\Edge'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
            ValueName = 'AutofillCreditCardEnabled'
            ValueData = 0
        }
    }
    
    if ($AutofillAddressEnabled) {
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Edge\AutofillAddressEnabled'
        {
            Key = '\Software\Policies\Microsoft\Edge'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
            ValueName = 'AutofillAddressEnabled'
            ValueData = 0
        }
    }
    
    if ($PersonalizationReportingEnabled) {
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Edge\PersonalizationReportingEnabled'
        {
            Key = '\Software\Policies\Microsoft\Edge'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
            ValueName = 'PersonalizationReportingEnabled'
            ValueData = 0
        }
    }
    
    if ($DefaultGeolocationSetting) {
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Edge\DefaultGeolocationSetting'
        {
            Key = '\Software\Policies\Microsoft\Edge'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
            ValueName = 'DefaultGeolocationSetting'
            ValueData = 2
        }
    }
    
    if ($PasswordManagerEnabled) {
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Edge\PasswordManagerEnabled'
        {
            Key = '\Software\Policies\Microsoft\Edge'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
            ValueName = 'PasswordManagerEnabled'
            ValueData = 0
        }
    }

    if ($IsolateOrigins) {
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Edge\IsolateOrigins'
        {
            Key = '\Software\Policies\Microsoft\Edge'
            ValueType = 'String'
            TargetType = 'ComputerConfiguration'
            ValueName = 'IsolateOrigins'
            ValueData = $null
        }
    }
    
    if ($SmartScreenEnabled) {
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Edge\SmartScreenEnabled'
        {
            Key = '\Software\Policies\Microsoft\Edge'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
            ValueName = 'SmartScreenEnabled'
            ValueData = 1
        }
    }
    
    if ($SmartScreenPuaEnabled) {
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Edge\SmartScreenPuaEnabled'
        {
            Key = '\Software\Policies\Microsoft\Edge'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
            ValueName = 'SmartScreenPuaEnabled'
            ValueData = 1
        }
    }
    
    if ($PaymentMethodQueryEnabled) {
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Edge\PaymentMethodQueryEnabled'
        {
            Key = '\Software\Policies\Microsoft\Edge'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
            ValueName = 'PaymentMethodQueryEnabled'
            ValueData = 0
        }
    }
    
    if ($AlternateErrorPagesEnabled) {
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Edge\AlternateErrorPagesEnabled'
        {
            Key = '\Software\Policies\Microsoft\Edge'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
            ValueName = 'AlternateErrorPagesEnabled'
            ValueData = 0
        }
    }

    if ($UserFeedbackAllowed) {
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Edge\UserFeedbackAllowed'
        {
            Key = '\Software\Policies\Microsoft\Edge'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
            ValueName = 'UserFeedbackAllowed'
            ValueData = 0
        }
    }
    
    if ($EdgeCollectionsEnabled) {
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Edge\EdgeCollectionsEnabled'
        {
            Key = '\Software\Policies\Microsoft\Edge'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
            ValueName = 'EdgeCollectionsEnabled'
            ValueData = 0
        }
    }
    
    if ($ConfigureShare) {
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Edge\ConfigureShare'
        {
            Key = '\Software\Policies\Microsoft\Edge'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
            ValueName = 'ConfigureShare'
            ValueData = 1
        }
    }
    
    if ($BrowserGuestModeEnabled) {
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Edge\BrowserGuestModeEnabled'
        {
            Key = '\Software\Policies\Microsoft\Edge'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
            ValueName = 'BrowserGuestModeEnabled'
            ValueData = 0
        }
    }
    
    if ($BuiltInDnsClientEnabled) {
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Edge\BuiltInDnsClientEnabled'
        {
            Key = '\Software\Policies\Microsoft\Edge'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
            ValueName = 'BuiltInDnsClientEnabled'
            ValueData = 0
        }
    }
    if ($SitePerProcess) {
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Edge\SitePerProcess'
        {
            Key = '\Software\Policies\Microsoft\Edge'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
            ValueName = 'SitePerProcess'
            ValueData = 1
        }
    }
    
    if ($ManagedSearchEngines) {
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Edge\ManagedSearchEngines'
        {
            Key = '\Software\Policies\Microsoft\Edge'
            ValueType = 'String'
            TargetType = 'ComputerConfiguration'
            ValueName = 'ManagedSearchEngines'
            ValueData = '[{"allow_search_engine_discovery": false},{"is_default": true,"name": "Microsoft Bing","keyword": "bing","search_url": "https://www.bing.com/search?q={searchTerms}"},{"name": "Google","keyword": "google","search_url": "https://www.google.com/search?q={searchTerms}"}]'
        }
    }
    
    if ($AuthSchemes) {
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Edge\AuthSchemes'
        {
            Key = '\Software\Policies\Microsoft\Edge'
            ValueType = 'String'
            TargetType = 'ComputerConfiguration'
            ValueName = 'AuthSchemes'
            ValueData = 'ntlm,negotiate'
        }
    }
    
    if ($DefaultWebUsbGuardSetting) {
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Edge\DefaultWebUsbGuardSetting'
        {
            Key = '\Software\Policies\Microsoft\Edge'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
            ValueName = 'DefaultWebUsbGuardSetting'
            ValueData = 2
        }
    }
    
    if ($DefaultWebBluetoothGuardSetting) {
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Edge\DefaultWebBluetoothGuardSetting'
        {
            Key = '\Software\Policies\Microsoft\Edge'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
            ValueName = 'DefaultWebBluetoothGuardSetting'
            ValueData = 2
        }
    }

    if ($TrackingPrevention) {
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Edge\TrackingPrevention'
        {
            Key = '\Software\Policies\Microsoft\Edge'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
            ValueName = 'TrackingPrevention'
            ValueData = 2
        }
    }
    
    if ($RelaunchNotification) {
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Edge\RelaunchNotification'
        {
            Key = '\Software\Policies\Microsoft\Edge'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
            ValueName = 'RelaunchNotification'
            ValueData = 2
        }
    }
    
    if ($ProxySettings) {
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Edge\ProxySettings'
        {
            Key = '\Software\Policies\Microsoft\Edge'
            ValueType = 'String'
            TargetType = 'ComputerConfiguration'
            ValueName = 'ProxySettings'
            ValueData = 'ADD YOUR PROXY CONFIGURATIONS HERE'
        }
    }
    
    if ($EnableOnlineRevocationChecks) {
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Edge\EnableOnlineRevocationChecks'
        {
            Key = '\Software\Policies\Microsoft\Edge'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
            ValueName = 'EnableOnlineRevocationChecks'
            ValueData = 1
        }
    }

    if ($QuicAllowed) {
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Edge\QuicAllowed'
        {
            Key = '\Software\Policies\Microsoft\Edge'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
            ValueName = 'QuicAllowed'
            ValueData = 0
        }
    }
    
    if ($DownloadRestrictions) {
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Edge\DownloadRestrictions'
        {
            Key = '\Software\Policies\Microsoft\Edge'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
            ValueName = 'DownloadRestrictions'
            ValueData = 1
        }
    }
    
    if ($VisualSearchEnabled) {
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Edge\VisualSearchEnabled'
        {
            Key = '\Software\Policies\Microsoft\Edge'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
            ValueName = 'VisualSearchEnabled'
            ValueData = 0
        }
    }
    
    if ($HubsSidebarEnabled) {
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Edge\HubsSidebarEnabled'
        {
            Key = '\Software\Policies\Microsoft\Edge'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
            ValueName = 'HubsSidebarEnabled'
            ValueData = 0
        }
    }
    
    if ($DefaultCookiesSetting) {
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Edge\DefaultCookiesSetting'
        {
            Key = '\Software\Policies\Microsoft\Edge'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
            ValueName = 'DefaultCookiesSetting'
            ValueData = 4
        }
    }
    
    if ($ConfigureFriendlyURLFormat) {
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Edge\ConfigureFriendlyURLFormat'
        {
            Key = '\Software\Policies\Microsoft\Edge'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
            ValueName = 'ConfigureFriendlyURLFormat'
            ValueData = 1
        }
    }

    if ($AutoplayAllowlist1) {
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Edge\AutoplayAllowlist\1'
        {
            Key = '\Software\Policies\Microsoft\Edge\AutoplayAllowlist'
            ValueType = 'String'
            TargetType = 'ComputerConfiguration'
            ValueName = '1'
            ValueData = '[*.]gov'
        }
    }
    
    if ($AutoplayAllowlist2) {
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Edge\AutoplayAllowlist\2'
        {
            Key = '\Software\Policies\Microsoft\Edge\AutoplayAllowlist'
            ValueType = 'String'
            TargetType = 'ComputerConfiguration'
            ValueName = '2'
            ValueData = '[*.]mil'
        }
    }
    
    if ($ExtensionInstallBlocklist1) {
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Edge\ExtensionInstallBlocklist\1'
        {
            Key = '\Software\Policies\Microsoft\Edge\ExtensionInstallBlocklist'
            ValueType = 'String'
            TargetType = 'ComputerConfiguration'
            ValueName = '1'
            ValueData = '*'
        }
    }
    
    if ($PopupsAllowedForUrls1) {
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Edge\PopupsAllowedForUrls\1'
        {
            Key = '\Software\Policies\Microsoft\Edge\PopupsAllowedForUrls'
            ValueType = 'String'
            TargetType = 'ComputerConfiguration'
            ValueName = '1'
            ValueData = '[*.]mil'
        }
    }
    
    if ($PopupsAllowedForUrls2) {
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Edge\PopupsAllowedForUrls\2'
        {
            Key = '\Software\Policies\Microsoft\Edge\PopupsAllowedForUrls'
            ValueType = 'String'
            TargetType = 'ComputerConfiguration'
            ValueName = '2'
            ValueData = '[*.]gov'
        }
    }
}

