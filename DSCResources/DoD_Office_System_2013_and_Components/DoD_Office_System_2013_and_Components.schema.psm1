configuration DoD_Office_System_2013_and_Components
{

    param(
        [bool]$FeatureControl_aptca_allowlist = $true,
        [bool]$FeatureControl_groove_addon_management = $true,
        [bool]$FeatureControl_excel_addon_management = $true,
        [bool]$FeatureControl_mspub_addon_management = $true,
        [bool]$FeatureControl_powerpnt_addon_management = $true,
        [bool]$FeatureControl_pptview_addon_management = $true,
        [bool]$FeatureControl_visio_addon_management = $true,
        [bool]$FeatureControl_winproj_addon_management = $true,
        [bool]$FeatureControl_winword_addon_management = $true,
        [bool]$FeatureControl_outlook_addon_management = $true,
        [bool]$FeatureControl_spdesign_addon_management = $true,
        [bool]$FeatureControl_exprwd_addon_management = $true,
        [bool]$FeatureControl_msaccess_addon_management = $true,
        [bool]$FeatureControl_onenote_addon_management = $true,
        [bool]$FeatureControl_mse7_addon_management = $true,
        [bool]$FeatureControl_groove_http_username_password_disable = $true,
        [bool]$FeatureControl_excel_http_username_password_disable = $true,
        [bool]$FeatureControl_mspub_http_username_password_disable = $true,
        [bool]$FeatureControl_powerpnt_http_username_password_disable = $true,
        [bool]$FeatureControl_pptview_http_username_password_disable = $true,
        [bool]$FeatureControl_visio_http_username_password_disable = $true,
        [bool]$FeatureControl_winproj_http_username_password_disable = $true,
        [bool]$FeatureControl_winword_http_username_password_disable = $true,
        [bool]$FeatureControl_outlook_http_username_password_disable = $true,
        [bool]$FeatureControl_spdesign_http_username_password_disable = $true,
        [bool]$FeatureControl_exprwd_http_username_password_disable = $true,
        [bool]$FeatureControl_msaccess_http_username_password_disable = $true,
        [bool]$FeatureControl_onenote_http_username_password_disable = $true,
        [bool]$FeatureControl_mse7_http_username_password_disable = $true,
        [bool]$FeatureControl_winproj_restrict_activexinstall = $true,
        [bool]$FeatureControl_winword_restrict_activexinstall = $true,
        [bool]$FeatureControl_outlook_restrict_activexinstall = $true,
        [bool]$FeatureControl_spdesign_restrict_activexinstall = $true,
        [bool]$FeatureControl_exprwd_restrict_activexinstall = $true,
        [bool]$FeatureControl_msaccess_restrict_activexinstall = $true,
        [bool]$FeatureControl_onenote_restrict_activexinstall = $true,
        [bool]$FeatureControl_mse7_restrict_activexinstall = $true,
        [bool]$FeatureControl_groove_restrict_filedownload = $true,
        [bool]$FeatureControl_excel_restrict_filedownload = $true,
        [bool]$FeatureControl_mspub_restrict_filedownload = $true,
        [bool]$FeatureControl_powerpnt_restrict_filedownload = $true,
        [bool]$FeatureControl_pptview_restrict_filedownload = $true,
        [bool]$FeatureControl_visio_restrict_filedownload = $true,
        [bool]$FeatureControl_winproj_restrict_filedownload = $true,
        [bool]$FeatureControl_winword_restrict_filedownload = $true,
        [bool]$FeatureControl_outlook_restrict_filedownload = $true,
        [bool]$FeatureControl_spdesign_restrict_filedownload = $true,
        [bool]$FeatureControl_exprwd_restrict_filedownload = $true,
        [bool]$FeatureControl_msaccess_restrict_filedownload = $true,
        [bool]$FeatureControl_onenote_restrict_filedownload = $true,
        [bool]$FeatureControl_mse7_restrict_filedownload = $true,
        [bool]$FeatureControl_groove_safe_bindtoobject = $true,
        [bool]$FeatureControl_excel_safe_bindtoobject = $true,
        [bool]$FeatureControl_mspub_safe_bindtoobject = $true,
        [bool]$FeatureControl_powerpnt_safe_bindtoobject = $true,
        [bool]$FeatureControl_pptview_safe_bindtoobject = $true,
        [bool]$FeatureControl_visio_safe_bindtoobject = $true,
        [bool]$FeatureControl_winproj_safe_bindtoobject = $true,
        [bool]$FeatureControl_winword_safe_bindtoobject = $true,
        [bool]$FeatureControl_outlook_safe_bindtoobject = $true,
        [bool]$FeatureControl_spdesign_safe_bindtoobject = $true,
        [bool]$FeatureControl_exprwd_safe_bindtoobject = $true,
        [bool]$FeatureControl_msaccess_safe_bindtoobject = $true,
        [bool]$FeatureControl_onenote_safe_bindtoobject = $true,
        [bool]$FeatureControl_mse7_safe_bindtoobject = $true,
        [bool]$FeatureControl_groove_unc_savedfilecheck = $true,
        [bool]$FeatureControl_excel_unc_savedfilecheck = $true,
        [bool]$FeatureControl_mspub_unc_savedfilecheck = $true,
        [bool]$FeatureControl_powerpnt_unc_savedfilecheck = $true,
        [bool]$FeatureControl_pptview_unc_savedfilecheck = $true,
        [bool]$FeatureControl_visio_unc_savedfilecheck = $true,
        [bool]$FeatureControl_winproj_unc_savedfilecheck = $true,
        [bool]$FeatureControl_winword_unc_savedfilecheck = $true,
        [bool]$FeatureControl_outlook_unc_savedfilecheck = $true,
        [bool]$FeatureControl_spdesign_unc_savedfilecheck = $true,
        [bool]$FeatureControl_exprwd_unc_savedfilecheck = $true,
        [bool]$FeatureControl_msaccess_unc_savedfilecheck = $true,
        [bool]$FeatureControl_onenote_unc_savedfilecheck = $true,
        [bool]$FeatureControl_mse7_unc_savedfilecheck = $true,
        [bool]$FeatureControl_groove_validate_navigate_url = $true,
        [bool]$FeatureControl_excel_validate_navigate_url = $true,
        [bool]$FeatureControl_mspub_validate_navigate_url = $true,
        [bool]$FeatureControl_powerpnt_validate_navigate_url = $true,
        [bool]$FeatureControl_pptview_validate_navigate_url = $true,
        [bool]$FeatureControl_visio_validate_navigate_url = $true,
        [bool]$FeatureControl_winproj_validate_navigate_url = $true,
        [bool]$FeatureControl_winword_validate_navigate_url = $true,
        [bool]$FeatureControl_outlook_validate_navigate_url = $true,
        [bool]$FeatureControl_spdesign_validate_navigate_url = $true,
        [bool]$FeatureControl_exprwd_validate_navigate_url = $true,
        [bool]$FeatureControl_msaccess_validate_navigate_url = $true,
        [bool]$FeatureControl_onenote_validate_navigate_url = $true,
        [bool]$FeatureControl_mse7_validate_navigate_url = $true,
        [bool]$FeatureControl_groove_weboc_popupmanagement = $true,
        [bool]$FeatureControl_excel_weboc_popupmanagement = $true,
        [bool]$FeatureControl_mspub_weboc_popupmanagement = $true,
        [bool]$FeatureControl_powerpnt_weboc_popupmanagement = $true,
        [bool]$FeatureControl_pptview_weboc_popupmanagement = $true,
        [bool]$FeatureControl_visio_weboc_popupmanagement = $true,
        [bool]$FeatureControl_winproj_weboc_popupmanagement = $true,
        [bool]$FeatureControl_winword_weboc_popupmanagement = $true,
        [bool]$FeatureControl_outlook_weboc_popupmanagement = $true,
        [bool]$FeatureControl_spdesign_weboc_popupmanagement = $true,
        [bool]$FeatureControl_exprwd_weboc_popupmanagement = $true,
        [bool]$FeatureControl_msaccess_weboc_popupmanagement = $true,
        [bool]$FeatureControl_onenote_weboc_popupmanagement = $true,
        [bool]$FeatureControl_mse7_weboc_popupmanagement = $true,
        [bool]$FeatureControl_groove_window_restrictions = $true,
        [bool]$FeatureControl_excel_window_restrictions = $true,
        [bool]$FeatureControl_mspub_window_restrictions = $true,
        [bool]$FeatureControl_powerpnt_window_restrictions = $true,
        [bool]$FeatureControl_pptview_window_restrictions = $true,
        [bool]$FeatureControl_visio_window_restrictions = $true,
        [bool]$FeatureControl_winproj_window_restrictions = $true,
        [bool]$FeatureControl_winword_window_restrictions = $true,
        [bool]$FeatureControl_outlook_window_restrictions = $true,
        [bool]$FeatureControl_spdesign_window_restrictions = $true,
        [bool]$FeatureControl_exprwd_window_restrictions = $true,
        [bool]$FeatureControl_msaccess_window_restrictions = $true,
        [bool]$FeatureControl_onenote_window_restrictions = $true,
        [bool]$FeatureControl_mse7_window_restrictions = $true,
        [bool]$FeatureControl_groove_zone_elevation = $true,
        [bool]$FeatureControl_excel_zone_elevation = $true,
        [bool]$FeatureControl_mspub_zone_elevation = $true,
        [bool]$FeatureControl_powerpnt_zone_elevation = $true,
        [bool]$FeatureControl_pptview_zone_elevation = $true,
        [bool]$FeatureControl_visio_zone_elevation = $true,
        [bool]$FeatureControl_winproj_zone_elevation = $true,
        [bool]$FeatureControl_winword_zone_elevation = $true,
        [bool]$FeatureControl_outlook_zone_elevation = $true,
        [bool]$FeatureControl_spdesign_zone_elevation = $true,
        [bool]$FeatureControl_exprwd_zone_elevation = $true,
        [bool]$FeatureControl_msaccess_zone_elevation = $true,
        [bool]$FeatureControl_onenote_zone_elevation = $true,
        [bool]$FeatureControl_mse7_zone_elevation = $true,
        [bool]$FeatureControl_enableautomaticupdates = $true,
        [bool]$FeatureControl_hideenabledisableupdates = $true,
        [bool]$FeatureControl_savepassword = $true,
        [bool]$FeatureControl_enablesiphighsecuritymode = $true,
        [bool]$FeatureControl_disablehttpconnect = $true,
        [bool]$FeatureControl_outlooksecuretempfolder_delete = $true,
        [bool]$FeatureControl_fileextensionsremovelevel1_delete = $true,
        [bool]$FeatureControl_fileextensionsremovelevel2_delete = $true,
        [bool]$FeatureControl_loadcontrolsinforms_delete = $true,
        [bool]$FeatureControl_uficontrols_delete = $true
    )

    Import-DSCResource -ModuleName 'GPRegistryPolicyDsc'
	Import-DSCResource -ModuleName 'AuditPolicyDSC'
	Import-DSCResource -ModuleName 'SecurityPolicyDSC'

    if ($FeatureControl_aptca_allowlist) {
        RegistryPolicyFile 'Registry(POL): HKLM:\software\policies\microsoft\office\15.0\infopath\security\aptca_allowlist'
        {
            Key = '\software\policies\microsoft\office\15.0\infopath\security'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
            ValueName = 'aptca_allowlist'
            ValueData = 1
        }
    }
    
    if ($FeatureControl_groove_addon_management) {
        RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_addon_management\groove.exe'
        {
            Key = '\software\microsoft\internet explorer\main\featurecontrol\feature_addon_management'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
            ValueName = 'groove.exe'
            ValueData = 1
        }
    }
    
    if ($FeatureControl_excel_addon_management) {
        RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_addon_management\excel.exe'
        {
            Key = '\software\microsoft\internet explorer\main\featurecontrol\feature_addon_management'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
            ValueName = 'excel.exe'
            ValueData = 1
        }
    }
    
    if ($FeatureControl_mspub_addon_management) {
        RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_addon_management\mspub.exe'
        {
            Key = '\software\microsoft\internet explorer\main\featurecontrol\feature_addon_management'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
            ValueName = 'mspub.exe'
            ValueData = 1
        }
    }
    
    if ($FeatureControl_powerpnt_addon_management) {
        RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_addon_management\powerpnt.exe'
        {
            Key = '\software\microsoft\internet explorer\main\featurecontrol\feature_addon_management'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
            ValueName = 'powerpnt.exe'
            ValueData = 1
        }
    }
    
    if ($FeatureControl_pptview_addon_management) {
        RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_addon_management\pptview.exe'
        {
            Key = '\software\microsoft\internet explorer\main\featurecontrol\feature_addon_management'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
            ValueName = 'pptview.exe'
            ValueData = 1
        }
    }
    
    if ($FeatureControl_visio_addon_management) {
        RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_addon_management\visio.exe'
        {
            Key = '\software\microsoft\internet explorer\main\featurecontrol\feature_addon_management'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
            ValueName = 'visio.exe'
            ValueData = 1
        }
    }

    if ($FeatureControl_winproj_addon_management) {
        RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_addon_management\winproj.exe'
        {
            Key = '\software\microsoft\internet explorer\main\featurecontrol\feature_addon_management'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
            ValueName = 'winproj.exe'
            ValueData = 1
        }
    }
    
    if ($FeatureControl_winword_addon_management) {
        RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_addon_management\winword.exe'
        {
            Key = '\software\microsoft\internet explorer\main\featurecontrol\feature_addon_management'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
            ValueName = 'winword.exe'
            ValueData = 1
        }
    }
    
    if ($FeatureControl_outlook_addon_management) {
        RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_addon_management\outlook.exe'
        {
            Key = '\software\microsoft\internet explorer\main\featurecontrol\feature_addon_management'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
            ValueName = 'outlook.exe'
            ValueData = 1
        }
    }
    
    if ($FeatureControl_spdesign_addon_management) {
        RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_addon_management\spdesign.exe'
        {
            Key = '\software\microsoft\internet explorer\main\featurecontrol\feature_addon_management'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
            ValueName = 'spdesign.exe'
            ValueData = 1
        }
    }
    
    if ($FeatureControl_exprwd_addon_management) {
        RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_addon_management\exprwd.exe'
        {
            Key = '\software\microsoft\internet explorer\main\featurecontrol\feature_addon_management'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
            ValueName = 'exprwd.exe'
            ValueData = 0
        }
    }
    
    if ($FeatureControl_msaccess_addon_management) {
        RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_addon_management\msaccess.exe'
        {
            Key = '\software\microsoft\internet explorer\main\featurecontrol\feature_addon_management'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
            ValueName = 'msaccess.exe'
            ValueData = 1
        }
    }

    if ($FeatureControl_onenote_addon_management) {
        RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_addon_management\onenote.exe'
        {
            Key = '\software\microsoft\internet explorer\main\featurecontrol\feature_addon_management'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
            ValueName = 'onenote.exe'
            ValueData = 1
        }
    }
    
    if ($FeatureControl_mse7_addon_management) {
        RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_addon_management\mse7.exe'
        {
            Key = '\software\microsoft\internet explorer\main\featurecontrol\feature_addon_management'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
            ValueName = 'mse7.exe'
            ValueData = 0
        }
    }
    
    if ($FeatureControl_groove_http_username_password_disable) {
        RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_http_username_password_disable\groove.exe'
        {
            Key = '\software\microsoft\internet explorer\main\featurecontrol\feature_http_username_password_disable'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
            ValueName = 'groove.exe'
            ValueData = 1
        }
    }
    
    if ($FeatureControl_excel_http_username_password_disable) {
        RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_http_username_password_disable\excel.exe'
        {
            Key = '\software\microsoft\internet explorer\main\featurecontrol\feature_http_username_password_disable'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
            ValueName = 'excel.exe'
            ValueData = 1
        }
    }
    
    if ($FeatureControl_mspub_http_username_password_disable) {
        RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_http_username_password_disable\mspub.exe'
        {
            Key = '\software\microsoft\internet explorer\main\featurecontrol\feature_http_username_password_disable'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
            ValueName = 'mspub.exe'
            ValueData = 1
        }
    }

    if ($FeatureControl_powerpnt_http_username_password_disable) {
        RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_http_username_password_disable\powerpnt.exe'
        {
            Key = '\software\microsoft\internet explorer\main\featurecontrol\feature_http_username_password_disable'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
            ValueName = 'powerpnt.exe'
            ValueData = 1
        }
    }
    
    if ($FeatureControl_pptview_http_username_password_disable) {
        RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_http_username_password_disable\pptview.exe'
        {
            Key = '\software\microsoft\internet explorer\main\featurecontrol\feature_http_username_password_disable'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
            ValueName = 'pptview.exe'
            ValueData = 1
        }
    }
    
    if ($FeatureControl_visio_http_username_password_disable) {
        RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_http_username_password_disable\visio.exe'
        {
            Key = '\software\microsoft\internet explorer\main\featurecontrol\feature_http_username_password_disable'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
            ValueName = 'visio.exe'
            ValueData = 1
        }
    }
    
    if ($FeatureControl_winproj_http_username_password_disable) {
        RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_http_username_password_disable\winproj.exe'
        {
            Key = '\software\microsoft\internet explorer\main\featurecontrol\feature_http_username_password_disable'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
            ValueName = 'winproj.exe'
            ValueData = 1
        }
    }
    
    if ($FeatureControl_winword_http_username_password_disable) {
        RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_http_username_password_disable\winword.exe'
        {
            Key = '\software\microsoft\internet explorer\main\featurecontrol\feature_http_username_password_disable'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
            ValueName = 'winword.exe'
            ValueData = 1
        }
    }
    
    if ($FeatureControl_outlook_http_username_password_disable) {
        RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_http_username_password_disable\outlook.exe'
        {
            Key = '\software\microsoft\internet explorer\main\featurecontrol\feature_http_username_password_disable'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
            ValueName = 'outlook.exe'
            ValueData = 1
        }
    }

    if ($FeatureControl_spdesign_http_username_password_disable) {
        RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_http_username_password_disable\spdesign.exe'
        {
            Key = '\software\microsoft\internet explorer\main\featurecontrol\feature_http_username_password_disable'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
            ValueName = 'spdesign.exe'
            ValueData = 1
        }
    }
    
    if ($FeatureControl_exprwd_http_username_password_disable) {
        RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_http_username_password_disable\exprwd.exe'
        {
            Key = '\software\microsoft\internet explorer\main\featurecontrol\feature_http_username_password_disable'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
            ValueName = 'exprwd.exe'
            ValueData = 0
        }
    }
    
    if ($FeatureControl_msaccess_http_username_password_disable) {
        RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_http_username_password_disable\msaccess.exe'
        {
            Key = '\software\microsoft\internet explorer\main\featurecontrol\feature_http_username_password_disable'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
            ValueName = 'msaccess.exe'
            ValueData = 1
        }
    }
    
    if ($FeatureControl_onenote_http_username_password_disable) {
        RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_http_username_password_disable\onenote.exe'
        {
            Key = '\software\microsoft\internet explorer\main\featurecontrol\feature_http_username_password_disable'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
            ValueName = 'onenote.exe'
            ValueData = 1
        }
    }
    
    if ($FeatureControl_mse7_http_username_password_disable) {
        RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_http_username_password_disable\mse7.exe'
        {
            Key = '\software\microsoft\internet explorer\main\featurecontrol\feature_http_username_password_disable'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
            ValueName = 'mse7.exe'
            ValueData = 0
        }
    }

    if ($FeatureControl_winproj_restrict_activexinstall) {
        RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_restrict_activexinstall\winproj.exe'
        {
            Key = '\software\microsoft\internet explorer\main\featurecontrol\feature_restrict_activexinstall'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
            ValueName = 'winproj.exe'
            ValueData = 1
        }
    }
    
    if ($FeatureControl_winword_restrict_activexinstall) {
        RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_restrict_activexinstall\winword.exe'
        {
            Key = '\software\microsoft\internet explorer\main\featurecontrol\feature_restrict_activexinstall'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
            ValueName = 'winword.exe'
            ValueData = 1
        }
    }
    
    if ($FeatureControl_outlook_restrict_activexinstall) {
        RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_restrict_activexinstall\outlook.exe'
        {
            Key = '\software\microsoft\internet explorer\main\featurecontrol\feature_restrict_activexinstall'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
            ValueName = 'outlook.exe'
            ValueData = 1
        }
    }
    
    if ($FeatureControl_spdesign_restrict_activexinstall) {
        RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_restrict_activexinstall\spdesign.exe'
        {
            Key = '\software\microsoft\internet explorer\main\featurecontrol\feature_restrict_activexinstall'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
            ValueName = 'spdesign.exe'
            ValueData = 1
        }
    }
    
    if ($FeatureControl_exprwd_restrict_activexinstall) {
        RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_restrict_activexinstall\exprwd.exe'
        {
            Key = '\software\microsoft\internet explorer\main\featurecontrol\feature_restrict_activexinstall'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
            ValueName = 'exprwd.exe'
            ValueData = 0
        }
    }
    
    if ($FeatureControl_msaccess_restrict_activexinstall) {
        RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_restrict_activexinstall\msaccess.exe'
        {
            Key = '\software\microsoft\internet explorer\main\featurecontrol\feature_restrict_activexinstall'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
            ValueName = 'msaccess.exe'
            ValueData = 1
        }
    }

    if ($FeatureControl_onenote_restrict_activexinstall) {
        RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_restrict_activexinstall\onenote.exe'
        {
            Key = '\software\microsoft\internet explorer\main\featurecontrol\feature_restrict_activexinstall'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
            ValueName = 'onenote.exe'
            ValueData = 1
        }
    }
    
    if ($FeatureControl_mse7_restrict_activexinstall) {
        RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_restrict_activexinstall\mse7.exe'
        {
            Key = '\software\microsoft\internet explorer\main\featurecontrol\feature_restrict_activexinstall'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
            ValueName = 'mse7.exe'
            ValueData = 0
        }
    }
    
    if ($FeatureControl_groove_restrict_filedownload) {
        RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_restrict_filedownload\groove.exe'
        {
            Key = '\software\microsoft\internet explorer\main\featurecontrol\feature_restrict_filedownload'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
            ValueName = 'groove.exe'
            ValueData = 1
        }
    }
    
    if ($FeatureControl_excel_restrict_filedownload) {
        RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_restrict_filedownload\excel.exe'
        {
            Key = '\software\microsoft\internet explorer\main\featurecontrol\feature_restrict_filedownload'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
            ValueName = 'excel.exe'
            ValueData = 1
        }
    }
    
    if ($FeatureControl_mspub_restrict_filedownload) {
        RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_restrict_filedownload\mspub.exe'
        {
            Key = '\software\microsoft\internet explorer\main\featurecontrol\feature_restrict_filedownload'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
            ValueName = 'mspub.exe'
            ValueData = 1
        }
    }

    if ($FeatureControl_powerpnt_restrict_filedownload) {
        RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_restrict_filedownload\powerpnt.exe'
        {
            Key = '\software\microsoft\internet explorer\main\featurecontrol\feature_restrict_filedownload'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
            ValueName = 'powerpnt.exe'
            ValueData = 1
        }
    }
    
    if ($FeatureControl_pptview_restrict_filedownload) {
        RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_restrict_filedownload\pptview.exe'
        {
            Key = '\software\microsoft\internet explorer\main\featurecontrol\feature_restrict_filedownload'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
            ValueName = 'pptview.exe'
            ValueData = 1
        }
    }
    
    if ($FeatureControl_visio_restrict_filedownload) {
        RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_restrict_filedownload\visio.exe'
        {
            Key = '\software\microsoft\internet explorer\main\featurecontrol\feature_restrict_filedownload'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
            ValueName = 'visio.exe'
            ValueData = 1
        }
    }
    
    if ($FeatureControl_winproj_restrict_filedownload) {
        RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_restrict_filedownload\winproj.exe'
        {
            Key = '\software\microsoft\internet explorer\main\featurecontrol\feature_restrict_filedownload'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
            ValueName = 'winproj.exe'
            ValueData = 1
        }
    }
    
    if ($FeatureControl_winword_restrict_filedownload) {
        RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_restrict_filedownload\winword.exe'
        {
            Key = '\software\microsoft\internet explorer\main\featurecontrol\feature_restrict_filedownload'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
            ValueName = 'winword.exe'
            ValueData = 1
        }
    }

    if ($FeatureControl_outlook_restrict_filedownload) {
        RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_restrict_filedownload\outlook.exe'
        {
            Key = '\software\microsoft\internet explorer\main\featurecontrol\feature_restrict_filedownload'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
            ValueName = 'outlook.exe'
            ValueData = 1
        }
    }
    
    if ($FeatureControl_spdesign_restrict_filedownload) {
        RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_restrict_filedownload\spdesign.exe'
        {
            Key = '\software\microsoft\internet explorer\main\featurecontrol\feature_restrict_filedownload'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
            ValueName = 'spdesign.exe'
            ValueData = 1
        }
    }
    
    if ($FeatureControl_exprwd_restrict_filedownload) {
        RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_restrict_filedownload\exprwd.exe'
        {
            Key = '\software\microsoft\internet explorer\main\featurecontrol\feature_restrict_filedownload'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
            ValueName = 'exprwd.exe'
            ValueData = 0
        }
    }
    
    if ($FeatureControl_msaccess_restrict_filedownload) {
        RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_restrict_filedownload\msaccess.exe'
        {
            Key = '\software\microsoft\internet explorer\main\featurecontrol\feature_restrict_filedownload'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
            ValueName = 'msaccess.exe'
            ValueData = 1
        }
    }
    
    if ($FeatureControl_onenote_restrict_filedownload) {
        RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_restrict_filedownload\onenote.exe'
        {
            Key = '\software\microsoft\internet explorer\main\featurecontrol\feature_restrict_filedownload'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
            ValueName = 'onenote.exe'
            ValueData = 1
        }
    }

    if ($FeatureControl_mse7_restrict_filedownload) {
        RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_restrict_filedownload\mse7.exe'
        {
            Key = '\software\microsoft\internet explorer\main\featurecontrol\feature_restrict_filedownload'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
            ValueName = 'mse7.exe'
            ValueData = 0
        }
    }
    
    if ($FeatureControl_groove_safe_bindtoobject) {
        RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_safe_bindtoobject\groove.exe'
        {
            Key = '\software\microsoft\internet explorer\main\featurecontrol\feature_safe_bindtoobject'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
            ValueName = 'groove.exe'
            ValueData = 1
        }
    }
    
    if ($FeatureControl_excel_safe_bindtoobject) {
        RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_safe_bindtoobject\excel.exe'
        {
            Key = '\software\microsoft\internet explorer\main\featurecontrol\feature_safe_bindtoobject'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
            ValueName = 'excel.exe'
            ValueData = 1
        }
    }
    
    if ($FeatureControl_mspub_safe_bindtoobject) {
        RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_safe_bindtoobject\mspub.exe'
        {
            Key = '\software\microsoft\internet explorer\main\featurecontrol\feature_safe_bindtoobject'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
            ValueName = 'mspub.exe'
            ValueData = 1
        }
    }
    
    if ($FeatureControl_powerpnt_safe_bindtoobject) {
        RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_safe_bindtoobject\powerpnt.exe'
        {
            Key = '\software\microsoft\internet explorer\main\featurecontrol\feature_safe_bindtoobject'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
            ValueName = 'powerpnt.exe'
            ValueData = 1
        }
    }

    if ($FeatureControl_pptview_safe_bindtoobject) {
        RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_safe_bindtoobject\pptview.exe'
        {
            Key = '\software\microsoft\internet explorer\main\featurecontrol\feature_safe_bindtoobject'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
            ValueName = 'pptview.exe'
            ValueData = 1
        }
    }
    
    if ($FeatureControl_visio_safe_bindtoobject) {
        RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_safe_bindtoobject\visio.exe'
        {
            Key = '\software\microsoft\internet explorer\main\featurecontrol\feature_safe_bindtoobject'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
            ValueName = 'visio.exe'
            ValueData = 1
        }
    }
    
    if ($FeatureControl_winproj_safe_bindtoobject) {
        RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_safe_bindtoobject\winproj.exe'
        {
            Key = '\software\microsoft\internet explorer\main\featurecontrol\feature_safe_bindtoobject'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
            ValueName = 'winproj.exe'
            ValueData = 1
        }
    }
    
    if ($FeatureControl_winword_safe_bindtoobject) {
        RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_safe_bindtoobject\winword.exe'
        {
            Key = '\software\microsoft\internet explorer\main\featurecontrol\feature_safe_bindtoobject'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
            ValueName = 'winword.exe'
            ValueData = 1
        }
    }
    
    if ($FeatureControl_outlook_safe_bindtoobject) {
        RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_safe_bindtoobject\outlook.exe'
        {
            Key = '\software\microsoft\internet explorer\main\featurecontrol\feature_safe_bindtoobject'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
            ValueName = 'outlook.exe'
            ValueData = 1
        }
    }

    if ($FeatureControl_spdesign_safe_bindtoobject) {
        RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_safe_bindtoobject\spdesign.exe'
        {
            Key = '\software\microsoft\internet explorer\main\featurecontrol\feature_safe_bindtoobject'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
            ValueName = 'spdesign.exe'
            ValueData = 1
        }
    }
    
    if ($FeatureControl_exprwd_safe_bindtoobject) {
        RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_safe_bindtoobject\exprwd.exe'
        {
            Key = '\software\microsoft\internet explorer\main\featurecontrol\feature_safe_bindtoobject'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
            ValueName = 'exprwd.exe'
            ValueData = 0
        }
    }
    
    if ($FeatureControl_msaccess_safe_bindtoobject) {
        RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_safe_bindtoobject\msaccess.exe'
        {
            Key = '\software\microsoft\internet explorer\main\featurecontrol\feature_safe_bindtoobject'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
            ValueName = 'msaccess.exe'
            ValueData = 1
        }
    }
    
    if ($FeatureControl_onenote_safe_bindtoobject) {
        RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_safe_bindtoobject\onenote.exe'
        {
            Key = '\software\microsoft\internet explorer\main\featurecontrol\feature_safe_bindtoobject'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
            ValueName = 'onenote.exe'
            ValueData = 1
        }
    }
    
    if ($FeatureControl_mse7_safe_bindtoobject) {
        RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_safe_bindtoobject\mse7.exe'
        {
            Key = '\software\microsoft\internet explorer\main\featurecontrol\feature_safe_bindtoobject'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
            ValueName = 'mse7.exe'
            ValueData = 0
        }
    }

    if ($FeatureControl_groove_unc_savedfilecheck) {
        RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_unc_savedfilecheck\groove.exe'
        {
            Key = '\software\microsoft\internet explorer\main\featurecontrol\feature_unc_savedfilecheck'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
            ValueName = 'groove.exe'
            ValueData = 1
        }
    }
    
    if ($FeatureControl_excel_unc_savedfilecheck) {
        RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_unc_savedfilecheck\excel.exe'
        {
            Key = '\software\microsoft\internet explorer\main\featurecontrol\feature_unc_savedfilecheck'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
            ValueName = 'excel.exe'
            ValueData = 1
        }
    }
    
    if ($FeatureControl_mspub_unc_savedfilecheck) {
        RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_unc_savedfilecheck\mspub.exe'
        {
            Key = '\software\microsoft\internet explorer\main\featurecontrol\feature_unc_savedfilecheck'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
            ValueName = 'mspub.exe'
            ValueData = 1
        }
    }
    
    if ($FeatureControl_powerpnt_unc_savedfilecheck) {
        RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_unc_savedfilecheck\powerpnt.exe'
        {
            Key = '\software\microsoft\internet explorer\main\featurecontrol\feature_unc_savedfilecheck'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
            ValueName = 'powerpnt.exe'
            ValueData = 1
        }
    }
    
    if ($FeatureControl_pptview_unc_savedfilecheck) {
        RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_unc_savedfilecheck\pptview.exe'
        {
            Key = '\software\microsoft\internet explorer\main\featurecontrol\feature_unc_savedfilecheck'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
            ValueName = 'pptview.exe'
            ValueData = 1
        }
    }

    if ($FeatureControl_visio_unc_savedfilecheck) {
        RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_unc_savedfilecheck\visio.exe'
        {
            Key = '\software\microsoft\internet explorer\main\featurecontrol\feature_unc_savedfilecheck'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
            ValueName = 'visio.exe'
            ValueData = 1
        }
    }
    
    if ($FeatureControl_winproj_unc_savedfilecheck) {
        RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_unc_savedfilecheck\winproj.exe'
        {
            Key = '\software\microsoft\internet explorer\main\featurecontrol\feature_unc_savedfilecheck'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
            ValueName = 'winproj.exe'
            ValueData = 1
        }
    }
    
    if ($FeatureControl_winword_unc_savedfilecheck) {
        RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_unc_savedfilecheck\winword.exe'
        {
            Key = '\software\microsoft\internet explorer\main\featurecontrol\feature_unc_savedfilecheck'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
            ValueName = 'winword.exe'
            ValueData = 1
        }
    }
    
    if ($FeatureControl_outlook_unc_savedfilecheck) {
        RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_unc_savedfilecheck\outlook.exe'
        {
            Key = '\software\microsoft\internet explorer\main\featurecontrol\feature_unc_savedfilecheck'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
            ValueName = 'outlook.exe'
            ValueData = 1
        }
    }

    if ($FeatureControl_spdesign_unc_savedfilecheck) {
        RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_unc_savedfilecheck\spdesign.exe'
        {
            Key = '\software\microsoft\internet explorer\main\featurecontrol\feature_unc_savedfilecheck'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
            ValueName = 'spdesign.exe'
            ValueData = 1
        }
    }
    
    if ($FeatureControl_exprwd_unc_savedfilecheck) {
        RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_unc_savedfilecheck\exprwd.exe'
        {
            Key = '\software\microsoft\internet explorer\main\featurecontrol\feature_unc_savedfilecheck'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
            ValueName = 'exprwd.exe'
            ValueData = 0
        }
    }
    
    if ($FeatureControl_msaccess_unc_savedfilecheck) {
        RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_unc_savedfilecheck\msaccess.exe'
        {
            Key = '\software\microsoft\internet explorer\main\featurecontrol\feature_unc_savedfilecheck'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
            ValueName = 'msaccess.exe'
            ValueData = 1
        }
    }
    
    if ($FeatureControl_onenote_unc_savedfilecheck) {
        RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_unc_savedfilecheck\onenote.exe'
        {
            Key = '\software\microsoft\internet explorer\main\featurecontrol\feature_unc_savedfilecheck'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
            ValueName = 'onenote.exe'
            ValueData = 1
        }
    }
    
    if ($FeatureControl_mse7_unc_savedfilecheck) {
        RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_unc_savedfilecheck\mse7.exe'
        {
            Key = '\software\microsoft\internet explorer\main\featurecontrol\feature_unc_savedfilecheck'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
            ValueName = 'mse7.exe'
            ValueData = 0
        }
    }
    
    if ($FeatureControl_groove_validate_navigate_url) {
        RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_validate_navigate_url\groove.exe'
        {
            Key = '\software\microsoft\internet explorer\main\featurecontrol\feature_validate_navigate_url'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
            ValueName = 'groove.exe'
            ValueData = 1
        }
    }
    
    if ($FeatureControl_excel_validate_navigate_url) {
        RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_validate_navigate_url\excel.exe'
        {
            Key = '\software\microsoft\internet explorer\main\featurecontrol\feature_validate_navigate_url'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
            ValueName = 'excel.exe'
            ValueData = 1
        }
    }

    if ($FeatureControl_mspub_validate_navigate_url) {
        RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_validate_navigate_url\mspub.exe'
        {
            Key = '\software\microsoft\internet explorer\main\featurecontrol\feature_validate_navigate_url'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
            ValueName = 'mspub.exe'
            ValueData = 1
        }
    }
    
    if ($FeatureControl_powerpnt_validate_navigate_url) {
        RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_validate_navigate_url\powerpnt.exe'
        {
            Key = '\software\microsoft\internet explorer\main\featurecontrol\feature_validate_navigate_url'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
            ValueName = 'powerpnt.exe'
            ValueData = 1
        }
    }
    
    if ($FeatureControl_pptview_validate_navigate_url) {
        RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_validate_navigate_url\pptview.exe'
        {
            Key = '\software\microsoft\internet explorer\main\featurecontrol\feature_validate_navigate_url'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
            ValueName = 'pptview.exe'
            ValueData = 1
        }
    }
    
    if ($FeatureControl_visio_validate_navigate_url) {
        RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_validate_navigate_url\visio.exe'
        {
            Key = '\software\microsoft\internet explorer\main\featurecontrol\feature_validate_navigate_url'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
            ValueName = 'visio.exe'
            ValueData = 1
        }
    }
    
    if ($FeatureControl_winproj_validate_navigate_url) {
        RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_validate_navigate_url\winproj.exe'
        {
            Key = '\software\microsoft\internet explorer\main\featurecontrol\feature_validate_navigate_url'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
            ValueName = 'winproj.exe'
            ValueData = 1
        }
    }

    if ($FeatureControl_winword_validate_navigate_url) {
        RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_validate_navigate_url\winword.exe'
        {
            Key = '\software\microsoft\internet explorer\main\featurecontrol\feature_validate_navigate_url'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
            ValueName = 'winword.exe'
            ValueData = 1
        }
    }
    
    if ($FeatureControl_outlook_validate_navigate_url) {
        RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_validate_navigate_url\outlook.exe'
        {
            Key = '\software\microsoft\internet explorer\main\featurecontrol\feature_validate_navigate_url'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
            ValueName = 'outlook.exe'
            ValueData = 1
        }
    }
    
    if ($FeatureControl_spdesign_validate_navigate_url) {
        RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_validate_navigate_url\spdesign.exe'
        {
            Key = '\software\microsoft\internet explorer\main\featurecontrol\feature_validate_navigate_url'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
            ValueName = 'spdesign.exe'
            ValueData = 1
        }
    }
    
    if ($FeatureControl_exprwd_validate_navigate_url) {
        RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_validate_navigate_url\exprwd.exe'
        {
            Key = '\software\microsoft\internet explorer\main\featurecontrol\feature_validate_navigate_url'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
            ValueName = 'exprwd.exe'
            ValueData = 0
        }
    }
    
    if ($FeatureControl_msaccess_validate_navigate_url) {
        RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_validate_navigate_url\msaccess.exe'
        {
            Key = '\software\microsoft\internet explorer\main\featurecontrol\feature_validate_navigate_url'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
            ValueName = 'msaccess.exe'
            ValueData = 1
        }
    }

    if ($FeatureControl_onenote_validate_navigate_url) {
        RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_validate_navigate_url\onenote.exe'
        {
            Key = '\software\microsoft\internet explorer\main\featurecontrol\feature_validate_navigate_url'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
            ValueName = 'onenote.exe'
            ValueData = 1
        }
    }
    
    if ($FeatureControl_mse7_validate_navigate_url) {
        RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_validate_navigate_url\mse7.exe'
        {
            Key = '\software\microsoft\internet explorer\main\featurecontrol\feature_validate_navigate_url'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
            ValueName = 'mse7.exe'
            ValueData = 0
        }
    }
    
    if ($FeatureControl_groove_weboc_popupmanagement) {
        RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_weboc_popupmanagement\groove.exe'
        {
            Key = '\software\microsoft\internet explorer\main\featurecontrol\feature_weboc_popupmanagement'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
            ValueName = 'groove.exe'
            ValueData = 1
        }
    }
    
    if ($FeatureControl_excel_weboc_popupmanagement) {
        RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_weboc_popupmanagement\excel.exe'
        {
            Key = '\software\microsoft\internet explorer\main\featurecontrol\feature_weboc_popupmanagement'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
            ValueName = 'excel.exe'
            ValueData = 1
        }
    }
    
    if ($FeatureControl_mspub_weboc_popupmanagement) {
        RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_weboc_popupmanagement\mspub.exe'
        {
            Key = '\software\microsoft\internet explorer\main\featurecontrol\feature_weboc_popupmanagement'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
            ValueName = 'mspub.exe'
            ValueData = 1
        }
    }
    
    if ($FeatureControl_powerpnt_weboc_popupmanagement) {
        RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_weboc_popupmanagement\powerpnt.exe'
        {
            Key = '\software\microsoft\internet explorer\main\featurecontrol\feature_weboc_popupmanagement'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
            ValueName = 'powerpnt.exe'
            ValueData = 1
        }
    }

    if ($FeatureControl_pptview_weboc_popupmanagement) {
        RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_weboc_popupmanagement\pptview.exe'
        {
            Key = '\software\microsoft\internet explorer\main\featurecontrol\feature_weboc_popupmanagement'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
            ValueName = 'pptview.exe'
            ValueData = 1
        }
    }
    
    if ($FeatureControl_visio_weboc_popupmanagement) {
        RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_weboc_popupmanagement\visio.exe'
        {
            Key = '\software\microsoft\internet explorer\main\featurecontrol\feature_weboc_popupmanagement'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
            ValueName = 'visio.exe'
            ValueData = 1
        }
    }
    
    if ($FeatureControl_winproj_weboc_popupmanagement) {
        RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_weboc_popupmanagement\winproj.exe'
        {
            Key = '\software\microsoft\internet explorer\main\featurecontrol\feature_weboc_popupmanagement'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
            ValueName = 'winproj.exe'
            ValueData = 1
        }
    }
    
    if ($FeatureControl_winword_weboc_popupmanagement) {
        RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_weboc_popupmanagement\winword.exe'
        {
            Key = '\software\microsoft\internet explorer\main\featurecontrol\feature_weboc_popupmanagement'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
            ValueName = 'winword.exe'
            ValueData = 1
        }
    }
    
    if ($FeatureControl_outlook_weboc_popupmanagement) {
        RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_weboc_popupmanagement\outlook.exe'
        {
            Key = '\software\microsoft\internet explorer\main\featurecontrol\feature_weboc_popupmanagement'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
            ValueName = 'outlook.exe'
            ValueData = 1
        }
    }
    
    if ($FeatureControl_spdesign_weboc_popupmanagement) {
        RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_weboc_popupmanagement\spdesign.exe'
        {
            Key = '\software\microsoft\internet explorer\main\featurecontrol\feature_weboc_popupmanagement'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
            ValueName = 'spdesign.exe'
            ValueData = 1
        }
    }

    if ($FeatureControl_exprwd_weboc_popupmanagement) {
        RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_weboc_popupmanagement\exprwd.exe'
        {
            Key = '\software\microsoft\internet explorer\main\featurecontrol\feature_weboc_popupmanagement'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
            ValueName = 'exprwd.exe'
            ValueData = 0
        }
    }
    
    if ($FeatureControl_msaccess_weboc_popupmanagement) {
        RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_weboc_popupmanagement\msaccess.exe'
        {
            Key = '\software\microsoft\internet explorer\main\featurecontrol\feature_weboc_popupmanagement'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
            ValueName = 'msaccess.exe'
            ValueData = 1
        }
    }
    
    if ($FeatureControl_onenote_weboc_popupmanagement) {
        RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_weboc_popupmanagement\onenote.exe'
        {
            Key = '\software\microsoft\internet explorer\main\featurecontrol\feature_weboc_popupmanagement'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
            ValueName = 'onenote.exe'
            ValueData = 1
        }
    }
    
    if ($FeatureControl_mse7_weboc_popupmanagement) {
        RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_weboc_popupmanagement\mse7.exe'
        {
            Key = '\software\microsoft\internet explorer\main\featurecontrol\feature_weboc_popupmanagement'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
            ValueName = 'mse7.exe'
            ValueData = 0
        }
    }
    
    if ($FeatureControl_groove_window_restrictions) {
        RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_window_restrictions\groove.exe'
        {
            Key = '\software\microsoft\internet explorer\main\featurecontrol\feature_window_restrictions'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
            ValueName = 'groove.exe'
            ValueData = 1
        }
    }
    
    if ($FeatureControl_excel_window_restrictions) {
        RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_window_restrictions\excel.exe'
        {
            Key = '\software\microsoft\internet explorer\main\featurecontrol\feature_window_restrictions'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
            ValueName = 'excel.exe'
            ValueData = 1
        }
    }
    
    if ($FeatureControl_mspub_window_restrictions) {
        RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_window_restrictions\mspub.exe'
        {
            Key = '\software\microsoft\internet explorer\main\featurecontrol\feature_window_restrictions'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
            ValueName = 'mspub.exe'
            ValueData = 1
        }
    }

    if ($FeatureControl_powerpnt_window_restrictions) {
        RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_window_restrictions\powerpnt.exe'
        {
            Key = '\software\microsoft\internet explorer\main\featurecontrol\feature_window_restrictions'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
            ValueName = 'powerpnt.exe'
            ValueData = 1
        }
    }
    
    if ($FeatureControl_pptview_window_restrictions) {
        RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_window_restrictions\pptview.exe'
        {
            Key = '\software\microsoft\internet explorer\main\featurecontrol\feature_window_restrictions'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
            ValueName = 'pptview.exe'
            ValueData = 1
        }
    }
    
    if ($FeatureControl_visio_window_restrictions) {
        RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_window_restrictions\visio.exe'
        {
            Key = '\software\microsoft\internet explorer\main\featurecontrol\feature_window_restrictions'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
            ValueName = 'visio.exe'
            ValueData = 1
        }
    }
    
    if ($FeatureControl_winproj_window_restrictions) {
        RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_window_restrictions\winproj.exe'
        {
            Key = '\software\microsoft\internet explorer\main\featurecontrol\feature_window_restrictions'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
            ValueName = 'winproj.exe'
            ValueData = 1
        }
    }
    
    if ($FeatureControl_winword_window_restrictions) {
        RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_window_restrictions\winword.exe'
        {
            Key = '\software\microsoft\internet explorer\main\featurecontrol\feature_window_restrictions'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
            ValueName = 'winword.exe'
            ValueData = 1
        }
    }
    
    if ($FeatureControl_outlook_window_restrictions) {
        RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_window_restrictions\outlook.exe'
        {
            Key = '\software\microsoft\internet explorer\main\featurecontrol\feature_window_restrictions'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
            ValueName = 'outlook.exe'
            ValueData = 1
        }
    }

    if ($FeatureControl_spdesign_window_restrictions) {
        RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_window_restrictions\spdesign.exe'
        {
            Key = '\software\microsoft\internet explorer\main\featurecontrol\feature_window_restrictions'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
            ValueName = 'spdesign.exe'
            ValueData = 1
        }
    }
    
    if ($FeatureControl_exprwd_window_restrictions) {
        RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_window_restrictions\exprwd.exe'
        {
            Key = '\software\microsoft\internet explorer\main\featurecontrol\feature_window_restrictions'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
            ValueName = 'exprwd.exe'
            ValueData = 0
        }
    }
    
    if ($FeatureControl_msaccess_window_restrictions) {
        RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_window_restrictions\msaccess.exe'
        {
            Key = '\software\microsoft\internet explorer\main\featurecontrol\feature_window_restrictions'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
            ValueName = 'msaccess.exe'
            ValueData = 1
        }
    }
    
    if ($FeatureControl_onenote_window_restrictions) {
        RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_window_restrictions\onenote.exe'
        {
            Key = '\software\microsoft\internet explorer\main\featurecontrol\feature_window_restrictions'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
            ValueName = 'onenote.exe'
            ValueData = 1
        }
    }
    
    if ($FeatureControl_mse7_window_restrictions) {
        RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_window_restrictions\mse7.exe'
        {
            Key = '\software\microsoft\internet explorer\main\featurecontrol\feature_window_restrictions'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
            ValueName = 'mse7.exe'
            ValueData = 0
        }
    }
    
    if ($FeatureControl_groove_zone_elevation) {
        RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_zone_elevation\groove.exe'
        {
            Key = '\software\microsoft\internet explorer\main\featurecontrol\feature_zone_elevation'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
            ValueName = 'groove.exe'
            ValueData = 1
        }
    }
    
    if ($FeatureControl_excel_zone_elevation) {
        RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_zone_elevation\excel.exe'
        {
            Key = '\software\microsoft\internet explorer\main\featurecontrol\feature_zone_elevation'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
            ValueName = 'excel.exe'
            ValueData = 1
        }
    }

    if ($FeatureControl_mspub_zone_elevation) {
        RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_zone_elevation\mspub.exe'
        {
            Key = '\software\microsoft\internet explorer\main\featurecontrol\feature_zone_elevation'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
            ValueName = 'mspub.exe'
            ValueData = 1
        }
    }
    
    if ($FeatureControl_powerpnt_zone_elevation) {
        RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_zone_elevation\powerpnt.exe'
        {
            Key = '\software\microsoft\internet explorer\main\featurecontrol\feature_zone_elevation'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
            ValueName = 'powerpnt.exe'
            ValueData = 1
        }
    }
    
    if ($FeatureControl_pptview_zone_elevation) {
        RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_zone_elevation\pptview.exe'
        {
            Key = '\software\microsoft\internet explorer\main\featurecontrol\feature_zone_elevation'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
            ValueName = 'pptview.exe'
            ValueData = 1
        }
    }
    
    if ($FeatureControl_visio_zone_elevation) {
        RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_zone_elevation\visio.exe'
        {
            Key = '\software\microsoft\internet explorer\main\featurecontrol\feature_zone_elevation'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
            ValueName = 'visio.exe'
            ValueData = 1
        }
    }
    
    if ($FeatureControl_winproj_zone_elevation) {
        RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_zone_elevation\winproj.exe'
        {
            Key = '\software\microsoft\internet explorer\main\featurecontrol\feature_zone_elevation'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
            ValueName = 'winproj.exe'
            ValueData = 1
        }
    }
    
    if ($FeatureControl_winword_zone_elevation) {
        RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_zone_elevation\winword.exe'
        {
            Key = '\software\microsoft\internet explorer\main\featurecontrol\feature_zone_elevation'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
            ValueName = 'winword.exe'
            ValueData = 1
        }
    }

    if ($FeatureControl_outlook_zone_elevation) {
        RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_zone_elevation\outlook.exe'
        {
            Key = '\software\microsoft\internet explorer\main\featurecontrol\feature_zone_elevation'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
            ValueName = 'outlook.exe'
            ValueData = 1
        }
    }
    
    if ($FeatureControl_spdesign_zone_elevation) {
        RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_zone_elevation\spdesign.exe'
        {
            Key = '\software\microsoft\internet explorer\main\featurecontrol\feature_zone_elevation'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
            ValueName = 'spdesign.exe'
            ValueData = 1
        }
    }
    
    if ($FeatureControl_exprwd_zone_elevation) {
        RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_zone_elevation\exprwd.exe'
        {
            Key = '\software\microsoft\internet explorer\main\featurecontrol\feature_zone_elevation'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
            ValueName = 'exprwd.exe'
            ValueData = 0
        }
    }
    
    if ($FeatureControl_msaccess_zone_elevation) {
        RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_zone_elevation\msaccess.exe'
        {
            Key = '\software\microsoft\internet explorer\main\featurecontrol\feature_zone_elevation'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
            ValueName = 'msaccess.exe'
            ValueData = 1
        }
    }
    
    if ($FeatureControl_onenote_zone_elevation) {
        RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_zone_elevation\onenote.exe'
        {
            Key = '\software\microsoft\internet explorer\main\featurecontrol\feature_zone_elevation'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
            ValueName = 'onenote.exe'
            ValueData = 1
        }
    }
    
    if ($FeatureControl_mse7_zone_elevation) {
        RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_zone_elevation\mse7.exe'
        {
            Key = '\software\microsoft\internet explorer\main\featurecontrol\feature_zone_elevation'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
            ValueName = 'mse7.exe'
            ValueData = 0
        }
    }

    if ($FeatureControl_enableautomaticupdates) {
        RegistryPolicyFile 'Registry(POL): HKLM:\software\policies\microsoft\office\15.0\common\officeupdate\enableautomaticupdates'
        {
            Key = '\software\policies\microsoft\office\15.0\common\officeupdate'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
            ValueName = 'enableautomaticupdates'
            ValueData = 1
        }
    }
    
    if ($FeatureControl_hideenabledisableupdates) {
        RegistryPolicyFile 'Registry(POL): HKLM:\software\policies\microsoft\office\15.0\common\officeupdate\hideenabledisableupdates'
        {
            Key = '\software\policies\microsoft\office\15.0\common\officeupdate'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
            ValueName = 'hideenabledisableupdates'
            ValueData = 1
        }
    }
    
    if ($FeatureControl_groove_safe_bindtoobject) {
        RegistryPolicyFile 'Registry(POL): HKLM:\software\wow6432node\microsoft\internet explorer\main\featurecontrol\feature_safe_bindtoobject\groove.exe'
        {
            Key = '\software\wow6432node\microsoft\internet explorer\main\featurecontrol\feature_safe_bindtoobject'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
            ValueName = 'groove.exe'
            ValueData = 1
        }
    }
    
    if ($FeatureControl_excel_safe_bindtoobject) {
        RegistryPolicyFile 'Registry(POL): HKLM:\software\wow6432node\microsoft\internet explorer\main\featurecontrol\feature_safe_bindtoobject\excel.exe'
        {
            Key = '\software\wow6432node\microsoft\internet explorer\main\featurecontrol\feature_safe_bindtoobject'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
            ValueName = 'excel.exe'
            ValueData = 1
        }
    }
    
    if ($FeatureControl_mspub_safe_bindtoobject) {
        RegistryPolicyFile 'Registry(POL): HKLM:\software\wow6432node\microsoft\internet explorer\main\featurecontrol\feature_safe_bindtoobject\mspub.exe'
        {
            Key = '\software\wow6432node\microsoft\internet explorer\main\featurecontrol\feature_safe_bindtoobject'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
            ValueName = 'mspub.exe'
            ValueData = 1
        }
    }

    if ($FeatureControl_savepassword) {
        RegistryPolicyFile 'Registry(POL): HKLM:\software\policies\microsoft\office\15.0\lync\savepassword'
        {
            Key = '\software\policies\microsoft\office\15.0\lync'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
            ValueName = 'savepassword'
            ValueData = 0
        }
    }
    
    if ($FeatureControl_enablesiphighsecuritymode) {
        RegistryPolicyFile 'Registry(POL): HKLM:\software\policies\microsoft\office\15.0\lync\enablesiphighsecuritymode'
        {
            Key = '\software\policies\microsoft\office\15.0\lync'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
            ValueName = 'enablesiphighsecuritymode'
            ValueData = 1
        }
    }
    
    if ($FeatureControl_disablehttpconnect) {
        RegistryPolicyFile 'Registry(POL): HKLM:\software\policies\microsoft\office\15.0\lync\disablehttpconnect'
        {
            Key = '\software\policies\microsoft\office\15.0\lync'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
            ValueName = 'disablehttpconnect'
            ValueData = 1
        }
    }
    
    if ($FeatureControl_outlooksecuretempfolder_delete) {
        RegistryPolicyFile 'DEL_CU:\software\policies\microsoft\office\15.0\outlook\security\outlooksecuretempfolder'
        {
            Key = 'HKCU:\software\policies\microsoft\office\15.0\outlook\security'
            ValueType = 'String'
            Ensure = 'Absent'
            TargetType = 'ComputerConfiguration'
            ValueName = 'outlooksecuretempfolder'
            ValueData = ''
        }
    }

    if ($FeatureControl_fileextensionsremovelevel1_delete) {
        RegistryPolicyFile 'DEL_CU:\software\policies\microsoft\office\15.0\outlook\security\fileextensionsremovelevel1'
        {
            Key = 'HKCU:\software\policies\microsoft\office\15.0\outlook\security'
            ValueType = 'String'
            Ensure = 'Absent'
            TargetType = 'ComputerConfiguration'
            ValueName = 'fileextensionsremovelevel1'
            ValueData = ''
        }
    }
    
    if ($FeatureControl_fileextensionsremovelevel2_delete) {
        RegistryPolicyFile 'DEL_CU:\software\policies\microsoft\office\15.0\outlook\security\fileextensionsremovelevel2'
        {
            Key = 'HKCU:\software\policies\microsoft\office\15.0\outlook\security'
            ValueType = 'String'
            Ensure = 'Absent'
            TargetType = 'ComputerConfiguration'
            ValueName = 'fileextensionsremovelevel2'
            ValueData = ''
        }
    }
    
    if ($FeatureControl_loadcontrolsinforms_delete) {
        RegistryPolicyFile 'DEL_CU:\keycupoliciesmsvbasecurity\loadcontrolsinforms'
        {
            Key = 'HKCU:\keycupoliciesmsvbasecurity'
            ValueType = 'String'
            Ensure = 'Absent'
            TargetType = 'ComputerConfiguration'
            ValueName = 'loadcontrolsinforms'
            ValueData = ''
        }
    }
    
    if ($FeatureControl_uficontrols_delete) {
        RegistryPolicyFile 'DEL_CU:\software\policies\microsoft\office\common\security\uficontrols'
        {
            Key = 'HKCU:\software\policies\microsoft\office\common\security'
            ValueType = 'String'
            Ensure = 'Absent'
            TargetType = 'ComputerConfiguration'
            ValueName = 'uficontrols'
            ValueData = ''
        }
    }
}

