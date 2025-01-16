configuration DoD_Google_Chrome_v2r10
{
    param(
        [bool]$RemoteAccessHostFirewallTraversal = $true,
        [bool]$DefaultPopupsSetting = $true,
        [bool]$DefaultGeolocationSetting = $true,
        [bool]$DefaultSearchProviderName = $true,
        [bool]$DefaultSearchProviderEnabled = $true,
        [bool]$PasswordManagerEnabled = $true,
        [bool]$BackgroundModeEnabled = $true,
        [bool]$SyncDisabled = $true,
        [bool]$CloudPrintProxyEnabled = $true,
        [bool]$MetricsReportingEnabled = $true,
        [bool]$SearchSuggestEnabled = $true,
        [bool]$ImportSavedPasswords = $true,
        [bool]$IncognitoModeAvailability = $true,
        [bool]$SavingBrowserHistoryDisabled = $true,
        [bool]$AllowDeletingBrowserHistory = $true,
        [bool]$PromptForDownloadLocation = $true,
        [bool]$AutoplayAllowed = $true,
        [bool]$SafeBrowsingExtendedReportingEnabled = $true,
        [bool]$DefaultWebUsbGuardSetting = $true,
        [bool]$EnableMediaRouter = $true,
        [bool]$UrlKeyedAnonymizedDataCollectionEnabled = $true,
        [bool]$WebRtcEventLogCollectionAllowed = $true,
        [bool]$NetworkPredictionOptions = $true,
        [bool]$DeveloperToolsAvailability = $true,
        [bool]$BrowserGuestModeEnabled = $true,
        [bool]$AutofillCreditCardEnabled = $true,
        [bool]$AutofillAddressEnabled = $true,
        [bool]$ImportAutofillFormData = $true,
        [bool]$SafeBrowsingProtectionLevel = $true,
        [bool]$DefaultSearchProviderSearchURL = $true,
        [bool]$DownloadRestrictions = $true,
        [bool]$DefaultWebBluetoothGuardSetting = $true,
        [bool]$QuicAllowed = $true,
        [bool]$EnableOnlineRevocationChecks = $true,
        [bool]$DefaultCookiesSetting = $true,
        [bool]$AutoplayAllowlist1 = $true,
        [bool]$AutoplayAllowlist2 = $true,
        [bool]$ExtensionInstallAllowlist1 = $true,
        [bool]$ExtensionInstallAllowlist2 = $true,
        [bool]$ExtensionInstallBlocklist1 = $true,
        [bool]$URLBlocklist1 = $true
    )

    Import-DSCResource -ModuleName 'GPRegistryPolicyDsc'
	Import-DSCResource -ModuleName 'AuditPolicyDSC'
	Import-DSCResource -ModuleName 'SecurityPolicyDSC'

    if ($RemoteAccessHostFirewallTraversal) {
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Google\Chrome\RemoteAccessHostFirewallTraversal'
        {
            Key = '\Software\Policies\Google\Chrome'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
            ValueName = 'RemoteAccessHostFirewallTraversal'
            ValueData = 0
        }
    }
    
    if ($DefaultPopupsSetting) {
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Google\Chrome\DefaultPopupsSetting'
        {
            Key = '\Software\Policies\Google\Chrome'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
            ValueName = 'DefaultPopupsSetting'
            ValueData = 2
        }
    }
    
    if ($DefaultGeolocationSetting) {
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Google\Chrome\DefaultGeolocationSetting'
        {
            Key = '\Software\Policies\Google\Chrome'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
            ValueName = 'DefaultGeolocationSetting'
            ValueData = 2
        }
    }
    
    if ($DefaultSearchProviderName) {
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Google\Chrome\DefaultSearchProviderName'
        {
            Key = '\Software\Policies\Google\Chrome'
            ValueType = 'String'
            TargetType = 'ComputerConfiguration'
            ValueName = 'DefaultSearchProviderName'
            ValueData = 'Google Encrypted'
        }
    }

    if ($DefaultSearchProviderEnabled) {
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Google\Chrome\DefaultSearchProviderEnabled'
        {
            Key = '\Software\Policies\Google\Chrome'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
            ValueName = 'DefaultSearchProviderEnabled'
            ValueData = 1
        }
    }
    
    if ($PasswordManagerEnabled) {
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Google\Chrome\PasswordManagerEnabled'
        {
            Key = '\Software\Policies\Google\Chrome'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
            ValueName = 'PasswordManagerEnabled'
            ValueData = 0
        }
    }
    
    if ($BackgroundModeEnabled) {
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Google\Chrome\BackgroundModeEnabled'
        {
            Key = '\Software\Policies\Google\Chrome'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
            ValueName = 'BackgroundModeEnabled'
            ValueData = 0
        }
    }
    
    if ($SyncDisabled) {
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Google\Chrome\SyncDisabled'
        {
            Key = '\Software\Policies\Google\Chrome'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
            ValueName = 'SyncDisabled'
            ValueData = 1
        }
    }
    
    if ($CloudPrintProxyEnabled) {
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Google\Chrome\CloudPrintProxyEnabled'
        {
            Key = '\Software\Policies\Google\Chrome'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
            ValueName = 'CloudPrintProxyEnabled'
            ValueData = 0
        }
    }
    
    if ($MetricsReportingEnabled) {
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Google\Chrome\MetricsReportingEnabled'
        {
            Key = '\Software\Policies\Google\Chrome'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
            ValueName = 'MetricsReportingEnabled'
            ValueData = 0
        }
    }

    if ($SearchSuggestEnabled) {
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Google\Chrome\SearchSuggestEnabled'
        {
            Key = '\Software\Policies\Google\Chrome'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
            ValueName = 'SearchSuggestEnabled'
            ValueData = 0
        }
    }
    
    if ($ImportSavedPasswords) {
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Google\Chrome\ImportSavedPasswords'
        {
            Key = '\Software\Policies\Google\Chrome'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
            ValueName = 'ImportSavedPasswords'
            ValueData = 0
        }
    }
    
    if ($IncognitoModeAvailability) {
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Google\Chrome\IncognitoModeAvailability'
        {
            Key = '\Software\Policies\Google\Chrome'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
            ValueName = 'IncognitoModeAvailability'
            ValueData = 1
        }
    }
    
    if ($SavingBrowserHistoryDisabled) {
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Google\Chrome\SavingBrowserHistoryDisabled'
        {
            Key = '\Software\Policies\Google\Chrome'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
            ValueName = 'SavingBrowserHistoryDisabled'
            ValueData = 0
        }
    }
    
    if ($AllowDeletingBrowserHistory) {
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Google\Chrome\AllowDeletingBrowserHistory'
        {
            Key = '\Software\Policies\Google\Chrome'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
            ValueName = 'AllowDeletingBrowserHistory'
            ValueData = 0
        }
    }
    
    if ($PromptForDownloadLocation) {
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Google\Chrome\PromptForDownloadLocation'
        {
            Key = '\Software\Policies\Google\Chrome'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
            ValueName = 'PromptForDownloadLocation'
            ValueData = 1
        }
    }

    if ($AutoplayAllowed) {
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Google\Chrome\AutoplayAllowed'
        {
            Key = '\Software\Policies\Google\Chrome'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
            ValueName = 'AutoplayAllowed'
            ValueData = 0
        }
    }
    
    if ($SafeBrowsingExtendedReportingEnabled) {
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Google\Chrome\SafeBrowsingExtendedReportingEnabled'
        {
            Key = '\Software\Policies\Google\Chrome'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
            ValueName = 'SafeBrowsingExtendedReportingEnabled'
            ValueData = 0
        }
    }
    
    if ($DefaultWebUsbGuardSetting) {
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Google\Chrome\DefaultWebUsbGuardSetting'
        {
            Key = '\Software\Policies\Google\Chrome'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
            ValueName = 'DefaultWebUsbGuardSetting'
            ValueData = 2
        }
    }
    
    if ($EnableMediaRouter) {
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Google\Chrome\EnableMediaRouter'
        {
            Key = '\Software\Policies\Google\Chrome'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
            ValueName = 'EnableMediaRouter'
            ValueData = 0
        }
    }
    
    if ($UrlKeyedAnonymizedDataCollectionEnabled) {
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Google\Chrome\UrlKeyedAnonymizedDataCollectionEnabled'
        {
            Key = '\Software\Policies\Google\Chrome'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
            ValueName = 'UrlKeyedAnonymizedDataCollectionEnabled'
            ValueData = 0
        }
    }
    
    if ($WebRtcEventLogCollectionAllowed) {
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Google\Chrome\WebRtcEventLogCollectionAllowed'
        {
            Key = '\Software\Policies\Google\Chrome'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
            ValueName = 'WebRtcEventLogCollectionAllowed'
            ValueData = 0
        }
    }
    if ($NetworkPredictionOptions) {
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Google\Chrome\NetworkPredictionOptions'
        {
            Key = '\Software\Policies\Google\Chrome'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
            ValueName = 'NetworkPredictionOptions'
            ValueData = 2
        }
    }
    
    if ($DeveloperToolsAvailability) {
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Google\Chrome\DeveloperToolsAvailability'
        {
            Key = '\Software\Policies\Google\Chrome'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
            ValueName = 'DeveloperToolsAvailability'
            ValueData = 2
        }
    }
    
    if ($BrowserGuestModeEnabled) {
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Google\Chrome\BrowserGuestModeEnabled'
        {
            Key = '\Software\Policies\Google\Chrome'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
            ValueName = 'BrowserGuestModeEnabled'
            ValueData = 0
        }
    }
    
    if ($AutofillCreditCardEnabled) {
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Google\Chrome\AutofillCreditCardEnabled'
        {
            Key = '\Software\Policies\Google\Chrome'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
            ValueName = 'AutofillCreditCardEnabled'
            ValueData = 0
        }
    }
    
    if ($AutofillAddressEnabled) {
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Google\Chrome\AutofillAddressEnabled'
        {
            Key = '\Software\Policies\Google\Chrome'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
            ValueName = 'AutofillAddressEnabled'
            ValueData = 0
        }
    }
    
    if ($ImportAutofillFormData) {
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Google\Chrome\ImportAutofillFormData'
        {
            Key = '\Software\Policies\Google\Chrome'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
            ValueName = 'ImportAutofillFormData'
            ValueData = 0
        }
    }

    if ($SafeBrowsingProtectionLevel) {
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Google\Chrome\SafeBrowsingProtectionLevel'
        {
            Key = '\Software\Policies\Google\Chrome'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
            ValueName = 'SafeBrowsingProtectionLevel'
            ValueData = 1
        }
    }
    
    if ($DefaultSearchProviderSearchURL) {
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Google\Chrome\DefaultSearchProviderSearchURL'
        {
            Key = '\Software\Policies\Google\Chrome'
            ValueType = 'String'
            TargetType = 'ComputerConfiguration'
            ValueName = 'DefaultSearchProviderSearchURL'
            ValueData = 'https://www.google.com/search?q={searchTerms}'
        }
    }
    
    if ($DownloadRestrictions) {
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Google\Chrome\DownloadRestrictions'
        {
            Key = '\Software\Policies\Google\Chrome'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
            ValueName = 'DownloadRestrictions'
            ValueData = 1
        }
    }
    
    if ($DefaultWebBluetoothGuardSetting) {
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Google\Chrome\DefaultWebBluetoothGuardSetting'
        {
            Key = '\Software\Policies\Google\Chrome'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
            ValueName = 'DefaultWebBluetoothGuardSetting'
            ValueData = 2
        }
    }
    
    if ($QuicAllowed) {
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Google\Chrome\QuicAllowed'
        {
            Key = '\Software\Policies\Google\Chrome'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
            ValueName = 'QuicAllowed'
            ValueData = 0
        }
    }
    
    if ($EnableOnlineRevocationChecks) {
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Google\Chrome\EnableOnlineRevocationChecks'
        {
            Key = '\Software\Policies\Google\Chrome'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
            ValueName = 'EnableOnlineRevocationChecks'
            ValueData = 1
        }
    }
    
    if ($DefaultCookiesSetting) {
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Google\Chrome\DefaultCookiesSetting'
        {
            Key = '\Software\Policies\Google\Chrome'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
            ValueName = 'DefaultCookiesSetting'
            ValueData = 4
        }
    }
    if ($AutoplayAllowlist1) {
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Google\Chrome\AutoplayAllowlist\1'
        {
            Key = '\Software\Policies\Google\Chrome\AutoplayAllowlist'
            ValueType = 'String'
            TargetType = 'ComputerConfiguration'
            ValueName = '1'
            ValueData = '[*.]mil'
        }
    }
    
    if ($AutoplayAllowlist2) {
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Google\Chrome\AutoplayAllowlist\2'
        {
            Key = '\Software\Policies\Google\Chrome\AutoplayAllowlist'
            ValueType = 'String'
            TargetType = 'ComputerConfiguration'
            ValueName = '2'
            ValueData = '[*.]gov'
        }
    }
    
    if ($ExtensionInstallAllowlist1) {
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Google\Chrome\ExtensionInstallAllowlist\1'
        {
            Key = '\Software\Policies\Google\Chrome\ExtensionInstallAllowlist'
            ValueType = 'String'
            TargetType = 'ComputerConfiguration'
            ValueName = '1'
            ValueData = 'oiigbmnaadbkfbmpbfijlflahbdbdgdf'
        }
    }
    
    if ($ExtensionInstallAllowlist2) {
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Google\Chrome\ExtensionInstallAllowlist\2'
        {
            Key = '\Software\Policies\Google\Chrome\ExtensionInstallAllowlist'
            ValueType = 'String'
            TargetType = 'ComputerConfiguration'
            ValueName = '2'
            ValueData = 'maafgiompdekodanheihhgilkjchcakm;https://outlook.office.com/owa/SmimeCrxUpdate.ashx'
        }
    }
    if ($ExtensionInstallBlocklist1) {
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Google\Chrome\ExtensionInstallBlocklist\1'
        {
            Key = '\Software\Policies\Google\Chrome\ExtensionInstallBlocklist'
            ValueType = 'String'
            TargetType = 'ComputerConfiguration'
            ValueName = '1'
            ValueData = '*'
        }
    }
    
    if ($URLBlocklist1) {
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Google\Chrome\URLBlocklist\1'
        {
            Key = '\Software\Policies\Google\Chrome\URLBlocklist'
            ValueType = 'String'
            TargetType = 'ComputerConfiguration'
            ValueName = '1'
            ValueData = 'javascript://*'
        }
    }
}

