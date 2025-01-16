configuration DoD_Office_2019-M365_Apps_v3r1
{
    param(
        [bool]$DeleteCUFileExtensionsRemoveLevel1 = $true,
        [bool]$DeleteCUFileExtensionsRemoveLevel2 = $true,
        [bool]$FeatureAddonManagementGroove = $true,
        [bool]$FeatureAddonManagementExcel = $true,
        [bool]$FeatureAddonManagementMspub = $true,
        [bool]$FeatureAddonManagementPowerPnt = $true,
        [bool]$FeatureAddonManagementPptView = $true,
        [bool]$FeatureAddonManagementVisio = $true,
        [bool]$FeatureAddonManagementWinProj = $true,
        [bool]$FeatureAddonManagementWinWord = $true,
        [bool]$FeatureAddonManagementOutlook = $true,
        [bool]$FeatureAddonManagementSPDesignExe = $true,
        [bool]$FeatureAddonManagementExprwdExe = $true,
        [bool]$FeatureAddonManagementMsAccessExe = $true,
        [bool]$FeatureAddonManagementOneNoteExe = $true,
        [bool]$FeatureAddonManagementMse7Exe = $true,
        [bool]$FeatureHttpUsernamePasswordDisableGrooveExe = $true,
        [bool]$FeatureHttpUsernamePasswordDisableExcelExe = $true,
        [bool]$FeatureHttpUsernamePasswordDisableMsPubExe = $true,
        [bool]$FeatureHttpUsernamePasswordDisablePowerPntExe = $true,
        [bool]$FeatureHttpUsernamePasswordDisablePptViewExe = $true,
        [bool]$FeatureHttpUsernamePasswordDisableVisioExe = $true,
        [bool]$FeatureHttpUsernamePasswordDisableWinProjExe = $true,
        [bool]$FeatureHttpUsernamePasswordDisableWinWordExe = $true,
        [bool]$FeatureHttpUsernamePasswordDisableOutlookExe = $true,
        [bool]$FeatureHttpUsernamePasswordDisableSPDesignExe = $true,
        [bool]$FeatureHttpUsernamePasswordDisableExprWdExe = $true,
        [bool]$FeatureHttpUsernamePasswordDisableMsAccessExe = $true,
        [bool]$FeatureHttpUsernamePasswordDisableOneNoteExe = $true,
        [bool]$FeatureHttpUsernamePasswordDisableMse7Exe = $true,
        [bool]$FeatureLocalMachineLockdownGrooveExe = $true,
        [bool]$FeatureLocalMachineLockdownExcelExe = $true,
        [bool]$FeatureLocalMachineLockdownMsPubExe = $true,
        [bool]$FeatureLocalMachineLockdownPowerPntExe = $true,
        [bool]$FeatureLocalMachineLockdownPptViewExe = $true,
        [bool]$FeatureLocalMachineLockdownVisioExe = $true,
        [bool]$FeatureLocalMachineLockdownWinProjExe = $true,
        [bool]$FeatureLocalMachineLockdownWinWordExe = $true,
        [bool]$FeatureLocalMachineLockdownOutlookExe = $true,
        [bool]$FeatureLocalMachineLockdownSPDesignExe = $true,
        [bool]$FeatureLocalMachineLockdownExprWdExe = $true,
        [bool]$FeatureLocalMachineLockdownMsAccessExe = $true,
        [bool]$FeatureLocalMachineLockdownOneNoteExe = $true,
        [bool]$FeatureLocalMachineLockdownMse7Exe = $true,
        [bool]$FeatureMimeHandlingGrooveExe = $true,
        [bool]$FeatureMimeHandlingExcelExe = $true,
        [bool]$FeatureMimeHandlingMsPubExe = $true,
        [bool]$FeatureMimeHandlingPowerPntExe = $true,
        [bool]$FeatureMimeHandlingPptViewExe = $true,
        [bool]$FeatureMimeHandlingVisioExe = $true,
        [bool]$FeatureMimeHandlingWinProjExe = $true,
        [bool]$FeatureMimeHandlingWinWordExe = $true,
        [bool]$FeatureMimeHandlingOutlookExe = $true,
        [bool]$FeatureMimeHandlingSPDesignExe = $true,
        [bool]$FeatureMimeHandlingExprWdExe = $true,
        [bool]$FeatureMimeHandlingMsAccessExe = $true,
        [bool]$FeatureMimeHandlingOneNoteExe = $true,
        [bool]$FeatureMimeHandlingMse7Exe = $true,
        [bool]$FeatureMimeSniffingGrooveExe = $true,
        [bool]$FeatureMimeSniffingExcelExe = $true,
        [bool]$FeatureMimeSniffingMsPubExe = $true,
        [bool]$FeatureMimeSniffingPowerPntExe = $true,
        [bool]$FeatureMimeSniffingPptViewExe = $true,
        [bool]$FeatureMimeSniffingVisioExe = $true,
        [bool]$FeatureMimeSniffingWinProjExe = $true,
        [bool]$FeatureMimeSniffingWinWordExe = $true,
        [bool]$FeatureMimeSniffingOutlookExe = $true,
        [bool]$FeatureMimeSniffingSPDesignExe = $true,
        [bool]$FeatureMimeSniffingExprWdExe = $true,
        [bool]$FeatureMimeSniffingMsAccessExe = $true,
        [bool]$FeatureMimeSniffingOneNoteExe = $true,
        [bool]$FeatureMimeSniffingMse7Exe = $true,
        [bool]$FeatureObjectCachingGrooveExe = $true,
        [bool]$FeatureObjectCachingExcelExe = $true,
        [bool]$FeatureObjectCachingMsPubExe = $true,
        [bool]$FeatureObjectCachingPowerPntExe = $true,
        [bool]$FeatureObjectCachingPptViewExe = $true,
        [bool]$FeatureObjectCachingVisioExe = $true,
        [bool]$FeatureObjectCachingWinProjExe = $true,
        [bool]$FeatureObjectCachingWinWordExe = $true,
        [bool]$FeatureObjectCachingOutlookExe = $true,
        [bool]$FeatureControl_groove = $true,
        [bool]$FeatureControl_excel = $true,
        [bool]$FeatureControl_mspub = $true,
        [bool]$FeatureControl_powerpnt = $true,
        [bool]$FeatureControl_pptview = $true,
        [bool]$FeatureControl_visio = $true,
        [bool]$FeatureControl_winproj = $true,
        [bool]$FeatureControl_winword = $true,
        [bool]$FeatureControl_outlook = $true,
        [bool]$FeatureControl_spdesign = $true,
        [bool]$FeatureControl_exprwd = $true,
        [bool]$FeatureControl_msaccess = $true,
        [bool]$FeatureControl_onenote = $true,
        [bool]$FeatureControl_mse7 = $true,
        [bool]$FeatureControl_groove_download = $true,
        [bool]$FeatureControl_excel_download = $true,
        [bool]$FeatureControl_mspub_download = $true,
        [bool]$FeatureControl_powerpnt_download = $true,
        [bool]$FeatureControl_pptview_download = $true,
        [bool]$FeatureControl_visio_download = $true,
        [bool]$FeatureControl_winproj_download = $true,
        [bool]$FeatureControl_winword_download = $true,
        [bool]$FeatureControl_outlook_download = $true,
        [bool]$FeatureControl_spdesign_download = $true,
        [bool]$FeatureControl_exprwd_download = $true,
        [bool]$FeatureControl_msaccess_download = $true,
        [bool]$FeatureControl_onenote_download = $true,
        [bool]$FeatureControl_mse7_download = $true,
        [bool]$FeatureControl_groove_security = $true,
        [bool]$FeatureControl_excel_security = $true,
        [bool]$FeatureControl_mspub_security = $true,
        [bool]$FeatureControl_powerpnt_security = $true,
        [bool]$FeatureControl_pptview_security = $true,
        [bool]$FeatureControl_visio_security = $true,
        [bool]$FeatureControl_winproj_security = $true,
        [bool]$FeatureControl_winword_security = $true,
        [bool]$FeatureControl_outlook_security = $true,
        [bool]$FeatureControl_spdesign_security = $true,
        [bool]$FeatureControl_exprwd_security = $true,
        [bool]$FeatureControl_msaccess_security = $true,
        [bool]$FeatureControl_onenote_security = $true,
        [bool]$FeatureControl_mse7_security = $true,
        [bool]$FeatureControl_groove_unc_check = $true,
        [bool]$FeatureControl_excel_unc_check = $true,
        [bool]$FeatureControl_mspub_unc_check = $true,
        [bool]$FeatureControl_powerpnt_unc_check = $true,
        [bool]$FeatureControl_pptview_unc_check = $true,
        [bool]$FeatureControl_visio_unc_check = $true,
        [bool]$FeatureControl_winproj_unc_check = $true,
        [bool]$FeatureControl_winword_unc_check = $true,
        [bool]$FeatureControl_outlook_unc_check = $true,
        [bool]$FeatureControl_spdesign_unc_check = $true,
        [bool]$FeatureControl_exprwd_unc_check = $true,
        [bool]$FeatureControl_msaccess_unc_check = $true,
        [bool]$FeatureControl_onenote_unc_check = $true,
        [bool]$FeatureControl_mse7_unc_check = $true,
        [bool]$FeatureControl_groove_validate_url = $true,
        [bool]$FeatureControl_excel_validate_url = $true,
        [bool]$FeatureControl_mspub_validate_url = $true,
        [bool]$FeatureControl_powerpnt_validate_url = $true,
        [bool]$FeatureControl_pptview_validate_url = $true,
        [bool]$FeatureControl_visio_validate_url = $true,
        [bool]$FeatureControl_winproj_validate_url = $true,
        [bool]$FeatureControl_winword_validate_url = $true,
        [bool]$FeatureControl_outlook_validate_url = $true,
        [bool]$FeatureControl_spdesign_validate_url = $true,
        [bool]$FeatureControl_exprwd_validate_url = $true,
        [bool]$FeatureControl_msaccess_validate_url = $true,
        [bool]$FeatureControl_onenote_validate_url = $true,
        [bool]$FeatureControl_mse7_validate_url = $true,
        [bool]$FeatureControl_groove_window_restriction = $true,
        [bool]$FeatureControl_excel_window_restriction = $true,
        [bool]$FeatureControl_mspub_window_restriction = $true,
        [bool]$FeatureControl_powerpnt_window_restriction = $true,
        [bool]$FeatureControl_pptview_window_restriction = $true,
        [bool]$FeatureControl_visio_window_restriction = $true,
        [bool]$FeatureControl_winproj_window_restriction = $true,
        [bool]$FeatureControl_winword_window_restriction = $true,
        [bool]$FeatureControl_outlook_window_restriction = $true,
        [bool]$FeatureControl_spdesign_window_restriction = $true,
        [bool]$FeatureControl_exprwd_window_restriction = $true,
        [bool]$FeatureControl_msaccess_window_restriction = $true,
        [bool]$FeatureControl_onenote_window_restriction = $true,
        [bool]$FeatureControl_mse7_window_restriction = $true,
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
        [bool]$FeatureControl_D27CDB6E_ActivationFilterOverride = $true,
        [bool]$FeatureControl_D27CDB6E_CompatibilityFlags = $true,
        [bool]$FeatureControl_D27CDB70_ActivationFilterOverride = $true,
        [bool]$FeatureControl_D27CDB70_CompatibilityFlags = $true,
        [bool]$FeatureControl_Comment = $true,
        [bool]$FeatureControl_D27CDB6E_Office_ActivationFilterOverride = $true,
        [bool]$FeatureControl_D27CDB6E_Office_CompatibilityFlags = $true,
        [bool]$FeatureControl_D27CDB70_Office_ActivationFilterOverride = $true,
        [bool]$FeatureControl_D27CDB70_Office_CompatibilityFlags = $true,
        [bool]$FeatureControl_EnableSipHighSecurityMode = $true,
        [bool]$FeatureControl_DisableHttpConnect = $true,
        [bool]$WOW6432Node_D27CDB6E_16_ActivationFilterOverride = $true,
        [bool]$WOW6432Node_D27CDB6E_16_CompatibilityFlags = $true,
        [bool]$WOW6432Node_D27CDB70_16_ActivationFilterOverride = $true,
        [bool]$WOW6432Node_D27CDB70_16_CompatibilityFlags = $true,
        [bool]$WOW6432Node_D27CDB6E_Common_ActivationFilterOverride = $true,
        [bool]$WOW6432Node_D27CDB6E_Common_CompatibilityFlags = $true,
        [bool]$WOW6432Node_D27CDB70_Common_ActivationFilterOverride = $true,
        [bool]$WOW6432Node_D27CDB70_Common_CompatibilityFlags = $true
    )

	Import-DSCResource -ModuleName 'GPRegistryPolicyDsc'
	Import-DSCResource -ModuleName 'AuditPolicyDSC'
	Import-DSCResource -ModuleName 'SecurityPolicyDSC'

    
    if ($FeatureAddonManagementGroove) {
        RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_addon_management\groove.exe'
        {
            Key = '\software\microsoft\internet explorer\main\featurecontrol\feature_addon_management'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
            ValueName = 'groove.exe'
            ValueData = 1
        }
    }
    
    if ($FeatureAddonManagementExcel) {
        RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_addon_management\excel.exe'
        {
            Key = '\software\microsoft\internet explorer\main\featurecontrol\feature_addon_management'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
            ValueName = 'excel.exe'
            ValueData = 1
        }
    }
    
    if ($FeatureAddonManagementMspub) {
        RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_addon_management\mspub.exe'
        {
            Key = '\software\microsoft\internet explorer\main\featurecontrol\feature_addon_management'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
            ValueName = 'mspub.exe'
            ValueData = 1
        }
    }
    
    if ($FeatureAddonManagementPowerPnt) {
        RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_addon_management\powerpnt.exe'
        {
            Key = '\software\microsoft\internet explorer\main\featurecontrol\feature_addon_management'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
            ValueName = 'powerpnt.exe'
            ValueData = 1
        }
    }
    
    if ($FeatureAddonManagementPptView) {
        RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_addon_management\pptview.exe'
        {
            Key = '\software\microsoft\internet explorer\main\featurecontrol\feature_addon_management'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
            ValueName = 'pptview.exe'
            ValueData = 1
        }
    }
    
    if ($FeatureAddonManagementVisio) {
        RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_addon_management\visio.exe'
        {
            Key = '\software\microsoft\internet explorer\main\featurecontrol\feature_addon_management'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
            ValueName = 'visio.exe'
            ValueData = 1
        }
    }
    
    if ($FeatureAddonManagementWinProj) {
        RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_addon_management\winproj.exe'
        {
            Key = '\software\microsoft\internet explorer\main\featurecontrol\feature_addon_management'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
            ValueName = 'winproj.exe'
            ValueData = 1
        }
    }
    
    if ($FeatureAddonManagementWinWord) {
        RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_addon_management\winword.exe'
        {
            Key = '\software\microsoft\internet explorer\main\featurecontrol\feature_addon_management'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
            ValueName = 'winword.exe'
            ValueData = 1
        }
    }
    
    if ($FeatureAddonManagementOutlook) {
        RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_addon_management\outlook.exe'
        {
            Key = '\software\microsoft\internet explorer\main\featurecontrol\feature_addon_management'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
            ValueName = 'outlook.exe'
            ValueData = 1
        }
    }

    if ($FeatureAddonManagementSPDesignExe) {
        RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_addon_management\spdesign.exe'
        {
            Key = '\software\microsoft\internet explorer\main\featurecontrol\feature_addon_management'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
            ValueName = 'spdesign.exe'
            ValueData = 1
        }
    }
    
    if ($FeatureAddonManagementExprwdExe) {
        RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_addon_management\exprwd.exe'
        {
            Key = '\software\microsoft\internet explorer\main\featurecontrol\feature_addon_management'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
            ValueName = 'exprwd.exe'
            ValueData = 1
        }
    }
    
    if ($FeatureAddonManagementMsAccessExe) {
        RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_addon_management\msaccess.exe'
        {
            Key = '\software\microsoft\internet explorer\main\featurecontrol\feature_addon_management'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
            ValueName = 'msaccess.exe'
            ValueData = 1
        }
    }
    
    if ($FeatureAddonManagementOneNoteExe) {
        RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_addon_management\onenote.exe'
        {
            Key = '\software\microsoft\internet explorer\main\featurecontrol\feature_addon_management'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
            ValueName = 'onenote.exe'
            ValueData = 1
        }
    }
    
    if ($FeatureAddonManagementMse7Exe) {
        RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_addon_management\mse7.exe'
        {
            Key = '\software\microsoft\internet explorer\main\featurecontrol\feature_addon_management'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
            ValueName = 'mse7.exe'
            ValueData = 1
        }
    }
    
    if ($FeatureHttpUsernamePasswordDisableGrooveExe) {
        RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_http_username_password_disable\groove.exe'
        {
            Key = '\software\microsoft\internet explorer\main\featurecontrol\feature_http_username_password_disable'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
            ValueName = 'groove.exe'
            ValueData = 1
        }
    }

    if ($FeatureHttpUsernamePasswordDisableExcelExe) {
        RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_http_username_password_disable\excel.exe'
        {
            Key = '\software\microsoft\internet explorer\main\featurecontrol\feature_http_username_password_disable'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
            ValueName = 'excel.exe'
            ValueData = 1
        }
    }
    
    if ($FeatureHttpUsernamePasswordDisableMsPubExe) {
        RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_http_username_password_disable\mspub.exe'
        {
            Key = '\software\microsoft\internet explorer\main\featurecontrol\feature_http_username_password_disable'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
            ValueName = 'mspub.exe'
            ValueData = 1
        }
    }
    
    if ($FeatureHttpUsernamePasswordDisablePowerPntExe) {
        RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_http_username_password_disable\powerpnt.exe'
        {
            Key = '\software\microsoft\internet explorer\main\featurecontrol\feature_http_username_password_disable'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
            ValueName = 'powerpnt.exe'
            ValueData = 1
        }
    }
    
    if ($FeatureHttpUsernamePasswordDisablePptViewExe) {
        RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_http_username_password_disable\pptview.exe'
        {
            Key = '\software\microsoft\internet explorer\main\featurecontrol\feature_http_username_password_disable'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
            ValueName = 'pptview.exe'
            ValueData = 1
        }
    }
    
    if ($FeatureHttpUsernamePasswordDisableVisioExe) {
        RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_http_username_password_disable\visio.exe'
        {
            Key = '\software\microsoft\internet explorer\main\featurecontrol\feature_http_username_password_disable'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
            ValueName = 'visio.exe'
            ValueData = 1
        }
    }

    if ($FeatureHttpUsernamePasswordDisableWinProjExe) {
        RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_http_username_password_disable\winproj.exe'
        {
            Key = '\software\microsoft\internet explorer\main\featurecontrol\feature_http_username_password_disable'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
            ValueName = 'winproj.exe'
            ValueData = 1
        }
    }
    
    if ($FeatureHttpUsernamePasswordDisableWinWordExe) {
        RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_http_username_password_disable\winword.exe'
        {
            Key = '\software\microsoft\internet explorer\main\featurecontrol\feature_http_username_password_disable'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
            ValueName = 'winword.exe'
            ValueData = 1
        }
    }
    
    if ($FeatureHttpUsernamePasswordDisableOutlookExe) {
        RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_http_username_password_disable\outlook.exe'
        {
            Key = '\software\microsoft\internet explorer\main\featurecontrol\feature_http_username_password_disable'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
            ValueName = 'outlook.exe'
            ValueData = 1
        }
    }
    
    if ($FeatureHttpUsernamePasswordDisableSPDesignExe) {
        RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_http_username_password_disable\spdesign.exe'
        {
            Key = '\software\microsoft\internet explorer\main\featurecontrol\feature_http_username_password_disable'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
            ValueName = 'spdesign.exe'
            ValueData = 1
        }
    }
    
    if ($FeatureHttpUsernamePasswordDisableExprWdExe) {
        RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_http_username_password_disable\exprwd.exe'
        {
            Key = '\software\microsoft\internet explorer\main\featurecontrol\feature_http_username_password_disable'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
            ValueName = 'exprwd.exe'
            ValueData = 1
        }
    }

    if ($FeatureHttpUsernamePasswordDisableMsAccessExe) {
        RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_http_username_password_disable\msaccess.exe'
        {
            Key = '\software\microsoft\internet explorer\main\featurecontrol\feature_http_username_password_disable'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
            ValueName = 'msaccess.exe'
            ValueData = 1
        }
    }
    
    if ($FeatureHttpUsernamePasswordDisableOneNoteExe) {
        RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_http_username_password_disable\onenote.exe'
        {
            Key = '\software\microsoft\internet explorer\main\featurecontrol\feature_http_username_password_disable'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
            ValueName = 'onenote.exe'
            ValueData = 1
        }
    }
    
    if ($FeatureHttpUsernamePasswordDisableMse7Exe) {
        RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_http_username_password_disable\mse7.exe'
        {
            Key = '\software\microsoft\internet explorer\main\featurecontrol\feature_http_username_password_disable'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
            ValueName = 'mse7.exe'
            ValueData = 1
        }
    }
    
    if ($FeatureLocalMachineLockdownGrooveExe) {
        RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_localmachine_lockdown\groove.exe'
        {
            Key = '\software\microsoft\internet explorer\main\featurecontrol\feature_localmachine_lockdown'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
            ValueName = 'groove.exe'
            ValueData = 1
        }
    }

    if ($FeatureLocalMachineLockdownExcelExe) {
        RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_localmachine_lockdown\excel.exe'
        {
            Key = '\software\microsoft\internet explorer\main\featurecontrol\feature_localmachine_lockdown'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
            ValueName = 'excel.exe'
            ValueData = 1
        }
    }
    
    if ($FeatureLocalMachineLockdownMsPubExe) {
        RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_localmachine_lockdown\mspub.exe'
        {
            Key = '\software\microsoft\internet explorer\main\featurecontrol\feature_localmachine_lockdown'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
            ValueName = 'mspub.exe'
            ValueData = 1
        }
    }
    
    if ($FeatureLocalMachineLockdownPowerPntExe) {
        RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_localmachine_lockdown\powerpnt.exe'
        {
            Key = '\software\microsoft\internet explorer\main\featurecontrol\feature_localmachine_lockdown'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
            ValueName = 'powerpnt.exe'
            ValueData = 1
        }
    }
    
    if ($FeatureLocalMachineLockdownPptViewExe) {
        RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_localmachine_lockdown\pptview.exe'
        {
            Key = '\software\microsoft\internet explorer\main\featurecontrol\feature_localmachine_lockdown'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
            ValueName = 'pptview.exe'
            ValueData = 1
        }
    }
    if ($FeatureLocalMachineLockdownVisioExe) {
        RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_localmachine_lockdown\visio.exe'
        {
            Key = '\software\microsoft\internet explorer\main\featurecontrol\feature_localmachine_lockdown'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
            ValueName = 'visio.exe'
            ValueData = 1
        }
    }
    
    if ($FeatureLocalMachineLockdownWinProjExe) {
        RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_localmachine_lockdown\winproj.exe'
        {
            Key = '\software\microsoft\internet explorer\main\featurecontrol\feature_localmachine_lockdown'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
            ValueName = 'winproj.exe'
            ValueData = 1
        }
    }
    
    if ($FeatureLocalMachineLockdownWinWordExe) {
        RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_localmachine_lockdown\winword.exe'
        {
            Key = '\software\microsoft\internet explorer\main\featurecontrol\feature_localmachine_lockdown'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
            ValueName = 'winword.exe'
            ValueData = 1
        }
    }
    
    if ($FeatureLocalMachineLockdownOutlookExe) {
        RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_localmachine_lockdown\outlook.exe'
        {
            Key = '\software\microsoft\internet explorer\main\featurecontrol\feature_localmachine_lockdown'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
            ValueName = 'outlook.exe'
            ValueData = 1
        }
    }
    
    if ($FeatureLocalMachineLockdownSPDesignExe) {
        RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_localmachine_lockdown\spdesign.exe'
        {
            Key = '\software\microsoft\internet explorer\main\featurecontrol\feature_localmachine_lockdown'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
            ValueName = 'spdesign.exe'
            ValueData = 1
        }
    }
    
    if ($FeatureLocalMachineLockdownExprWdExe) {
        RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_localmachine_lockdown\exprwd.exe'
        {
            Key = '\software\microsoft\internet explorer\main\featurecontrol\feature_localmachine_lockdown'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
            ValueName = 'exprwd.exe'
            ValueData = 1
        }
    }

    if ($FeatureLocalMachineLockdownMsAccessExe) {
        RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_localmachine_lockdown\msaccess.exe'
        {
            Key = '\software\microsoft\internet explorer\main\featurecontrol\feature_localmachine_lockdown'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
            ValueName = 'msaccess.exe'
            ValueData = 1
        }
    }
    
    if ($FeatureLocalMachineLockdownOneNoteExe) {
        RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_localmachine_lockdown\onenote.exe'
        {
            Key = '\software\microsoft\internet explorer\main\featurecontrol\feature_localmachine_lockdown'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
            ValueName = 'onenote.exe'
            ValueData = 1
        }
    }
    
    if ($FeatureLocalMachineLockdownMse7Exe) {
        RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_localmachine_lockdown\mse7.exe'
        {
            Key = '\software\microsoft\internet explorer\main\featurecontrol\feature_localmachine_lockdown'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
            ValueName = 'mse7.exe'
            ValueData = 1
        }
    }
    
    if ($FeatureMimeHandlingGrooveExe) {
        RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_mime_handling\groove.exe'
        {
            Key = '\software\microsoft\internet explorer\main\featurecontrol\feature_mime_handling'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
            ValueName = 'groove.exe'
            ValueData = 1
        }
    }
    
    if ($FeatureMimeHandlingExcelExe) {
        RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_mime_handling\excel.exe'
        {
            Key = '\software\microsoft\internet explorer\main\featurecontrol\feature_mime_handling'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
            ValueName = 'excel.exe'
            ValueData = 1
        }
    }

    if ($FeatureMimeHandlingMsPubExe) {
        RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_mime_handling\mspub.exe'
        {
            Key = '\software\microsoft\internet explorer\main\featurecontrol\feature_mime_handling'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
            ValueName = 'mspub.exe'
            ValueData = 1
        }
    }
    
    if ($FeatureMimeHandlingPowerPntExe) {
        RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_mime_handling\powerpnt.exe'
        {
            Key = '\software\microsoft\internet explorer\main\featurecontrol\feature_mime_handling'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
            ValueName = 'powerpnt.exe'
            ValueData = 1
        }
    }
    
    if ($FeatureMimeHandlingPptViewExe) {
        RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_mime_handling\pptview.exe'
        {
            Key = '\software\microsoft\internet explorer\main\featurecontrol\feature_mime_handling'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
            ValueName = 'pptview.exe'
            ValueData = 1
        }
    }
    
    if ($FeatureMimeHandlingVisioExe) {
        RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_mime_handling\visio.exe'
        {
            Key = '\software\microsoft\internet explorer\main\featurecontrol\feature_mime_handling'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
            ValueName = 'visio.exe'
            ValueData = 1
        }
    }
    
    if ($FeatureMimeHandlingWinProjExe) {
        RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_mime_handling\winproj.exe'
        {
            Key = '\software\microsoft\internet explorer\main\featurecontrol\feature_mime_handling'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
            ValueName = 'winproj.exe'
            ValueData = 1
        }
    }

    if ($FeatureMimeHandlingWinWordExe) {
        RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_mime_handling\winword.exe'
        {
            Key = '\software\microsoft\internet explorer\main\featurecontrol\feature_mime_handling'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
            ValueName = 'winword.exe'
            ValueData = 1
        }
    }
    
    if ($FeatureMimeHandlingOutlookExe) {
        RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_mime_handling\outlook.exe'
        {
            Key = '\software\microsoft\internet explorer\main\featurecontrol\feature_mime_handling'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
            ValueName = 'outlook.exe'
            ValueData = 1
        }
    }
    
    if ($FeatureMimeHandlingSPDesignExe) {
        RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_mime_handling\spdesign.exe'
        {
            Key = '\software\microsoft\internet explorer\main\featurecontrol\feature_mime_handling'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
            ValueName = 'spdesign.exe'
            ValueData = 1
        }
    }
    
    if ($FeatureMimeHandlingExprWdExe) {
        RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_mime_handling\exprwd.exe'
        {
            Key = '\software\microsoft\internet explorer\main\featurecontrol\feature_mime_handling'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
            ValueName = 'exprwd.exe'
            ValueData = 1
        }
    }
    
    if ($FeatureMimeHandlingMsAccessExe) {
        RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_mime_handling\msaccess.exe'
        {
            Key = '\software\microsoft\internet explorer\main\featurecontrol\feature_mime_handling'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
            ValueName = 'msaccess.exe'
            ValueData = 1
        }
    }
    
    if ($FeatureMimeHandlingOneNoteExe) {
        RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_mime_handling\onenote.exe'
        {
            Key = '\software\microsoft\internet explorer\main\featurecontrol\feature_mime_handling'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
            ValueName = 'onenote.exe'
            ValueData = 1
        }
    }

    if ($FeatureMimeHandlingMse7Exe) {
        RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_mime_handling\mse7.exe'
        {
            Key = '\software\microsoft\internet explorer\main\featurecontrol\feature_mime_handling'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
            ValueName = 'mse7.exe'
            ValueData = 1
        }
    }
    
    if ($FeatureMimeSniffingGrooveExe) {
        RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_mime_sniffing\groove.exe'
        {
            Key = '\software\microsoft\internet explorer\main\featurecontrol\feature_mime_sniffing'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
            ValueName = 'groove.exe'
            ValueData = 1
        }
    }
    
    if ($FeatureMimeSniffingExcelExe) {
        RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_mime_sniffing\excel.exe'
        {
            Key = '\software\microsoft\internet explorer\main\featurecontrol\feature_mime_sniffing'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
            ValueName = 'excel.exe'
            ValueData = 1
        }
    }
    
    if ($FeatureMimeSniffingMsPubExe) {
        RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_mime_sniffing\mspub.exe'
        {
            Key = '\software\microsoft\internet explorer\main\featurecontrol\feature_mime_sniffing'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
            ValueName = 'mspub.exe'
            ValueData = 1
        }
    }
    
    if ($FeatureMimeSniffingPowerPntExe) {
        RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_mime_sniffing\powerpnt.exe'
        {
            Key = '\software\microsoft\internet explorer\main\featurecontrol\feature_mime_sniffing'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
            ValueName = 'powerpnt.exe'
            ValueData = 1
        }
    }

    if ($FeatureMimeSniffingPptViewExe) {
        RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_mime_sniffing\pptview.exe'
        {
            Key = '\software\microsoft\internet explorer\main\featurecontrol\feature_mime_sniffing'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
            ValueName = 'pptview.exe'
            ValueData = 1
        }
    }
    
    if ($FeatureMimeSniffingVisioExe) {
        RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_mime_sniffing\visio.exe'
        {
            Key = '\software\microsoft\internet explorer\main\featurecontrol\feature_mime_sniffing'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
            ValueName = 'visio.exe'
            ValueData = 1
        }
    }
    
    if ($FeatureMimeSniffingWinProjExe) {
        RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_mime_sniffing\winproj.exe'
        {
            Key = '\software\microsoft\internet explorer\main\featurecontrol\feature_mime_sniffing'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
            ValueName = 'winproj.exe'
            ValueData = 1
        }
    }
    
    if ($FeatureMimeSniffingWinWordExe) {
        RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_mime_sniffing\winword.exe'
        {
            Key = '\software\microsoft\internet explorer\main\featurecontrol\feature_mime_sniffing'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
            ValueName = 'winword.exe'
            ValueData = 1
        }
    }
    
    if ($FeatureMimeSniffingOutlookExe) {
        RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_mime_sniffing\outlook.exe'
        {
            Key = '\software\microsoft\internet explorer\main\featurecontrol\feature_mime_sniffing'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
            ValueName = 'outlook.exe'
            ValueData = 1
        }
    }
    
    if ($FeatureMimeSniffingSPDesignExe) {
        RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_mime_sniffing\spdesign.exe'
        {
            Key = '\software\microsoft\internet explorer\main\featurecontrol\feature_mime_sniffing'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
            ValueName = 'spdesign.exe'
            ValueData = 1
        }
    }

    if ($FeatureMimeSniffingExprWdExe) {
        RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_mime_sniffing\exprwd.exe'
        {
            Key = '\software\microsoft\internet explorer\main\featurecontrol\feature_mime_sniffing'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
            ValueName = 'exprwd.exe'
            ValueData = 1
        }
    }
    
    if ($FeatureMimeSniffingMsAccessExe) {
        RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_mime_sniffing\msaccess.exe'
        {
            Key = '\software\microsoft\internet explorer\main\featurecontrol\feature_mime_sniffing'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
            ValueName = 'msaccess.exe'
            ValueData = 1
        }
    }
    
    if ($FeatureMimeSniffingOneNoteExe) {
        RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_mime_sniffing\onenote.exe'
        {
            Key = '\software\microsoft\internet explorer\main\featurecontrol\feature_mime_sniffing'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
            ValueName = 'onenote.exe'
            ValueData = 1
        }
    }
    
    if ($FeatureMimeSniffingMse7Exe) {
        RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_mime_sniffing\mse7.exe'
        {
            Key = '\software\microsoft\internet explorer\main\featurecontrol\feature_mime_sniffing'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
            ValueName = 'mse7.exe'
            ValueData = 1
        }
    }
    
    if ($FeatureObjectCachingGrooveExe) {
        RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_object_caching\groove.exe'
        {
            Key = '\software\microsoft\internet explorer\main\featurecontrol\feature_object_caching'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
            ValueName = 'groove.exe'
            ValueData = 1
        }
    }
    
    if ($FeatureObjectCachingExcelExe) {
        RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_object_caching\excel.exe'
        {
            Key = '\software\microsoft\internet explorer\main\featurecontrol\feature_object_caching'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
            ValueName = 'excel.exe'
            ValueData = 1
        }
    }

    if ($FeatureObjectCachingMsPubExe) {
        RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_object_caching\mspub.exe'
        {
            Key = '\software\microsoft\internet explorer\main\featurecontrol\feature_object_caching'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
            ValueName = 'mspub.exe'
            ValueData = 1
        }
    }
    
    if ($FeatureObjectCachingPowerPntExe) {
        RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_object_caching\powerpnt.exe'
        {
            Key = '\software\microsoft\internet explorer\main\featurecontrol\feature_object_caching'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
            ValueName = 'powerpnt.exe'
            ValueData = 1
        }
    }
    
    if ($FeatureObjectCachingPptViewExe) {
        RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_object_caching\pptview.exe'
        {
            Key = '\software\microsoft\internet explorer\main\featurecontrol\feature_object_caching'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
            ValueName = 'pptview.exe'
            ValueData = 1
        }
    }
    
    if ($FeatureObjectCachingVisioExe) {
        RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_object_caching\visio.exe'
        {
            Key = '\software\microsoft\internet explorer\main\featurecontrol\feature_object_caching'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
            ValueName = 'visio.exe'
            ValueData = 1
        }
    }
    
    if ($FeatureObjectCachingWinProjExe) {
        RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_object_caching\winproj.exe'
        {
            Key = '\software\microsoft\internet explorer\main\featurecontrol\feature_object_caching'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
            ValueName = 'winproj.exe'
            ValueData = 1
        }
    }
    
    if ($FeatureObjectCachingWinWordExe) {
        RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_object_caching\winword.exe'
        {
            Key = '\software\microsoft\internet explorer\main\featurecontrol\feature_object_caching'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
            ValueName = 'winword.exe'
            ValueData = 1
        }
    }
    
    if ($FeatureObjectCachingOutlookExe) {
        RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_object_caching\outlook.exe'
        {
            Key = '\software\microsoft\internet explorer\main\featurecontrol\feature_object_caching'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
            ValueName = 'outlook.exe'
            ValueData = 1
        }
    }

    if ($FeatureControl_spdesign) {
        RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_object_caching\spdesign.exe'
        {
            Key = '\software\microsoft\internet explorer\main\featurecontrol\feature_object_caching'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
            ValueName = 'spdesign.exe'
            ValueData = 1
        }
    }
    
    if ($FeatureControl_exprwd) {
        RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_object_caching\exprwd.exe'
        {
            Key = '\software\microsoft\internet explorer\main\featurecontrol\feature_object_caching'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
            ValueName = 'exprwd.exe'
            ValueData = 1
        }
    }
    
    if ($FeatureControl_msaccess) {
        RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_object_caching\msaccess.exe'
        {
            Key = '\software\microsoft\internet explorer\main\featurecontrol\feature_object_caching'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
            ValueName = 'msaccess.exe'
            ValueData = 1
        }
    }
    
    if ($FeatureControl_onenote) {
        RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_object_caching\onenote.exe'
        {
            Key = '\software\microsoft\internet explorer\main\featurecontrol\feature_object_caching'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
            ValueName = 'onenote.exe'
            ValueData = 1
        }
    }
    
    if ($FeatureControl_mse7) {
        RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_object_caching\mse7.exe'
        {
            Key = '\software\microsoft\internet explorer\main\featurecontrol\feature_object_caching'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
            ValueName = 'mse7.exe'
            ValueData = 1
        }
    }
    
    if ($FeatureControl_groove) {
        RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_restrict_activexinstall\groove.exe'
        {
            Key = '\software\microsoft\internet explorer\main\featurecontrol\feature_restrict_activexinstall'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
            ValueName = 'groove.exe'
            ValueData = 1
        }
    }

    if ($FeatureControl_excel) {
        RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_restrict_activexinstall\excel.exe'
        {
            Key = '\software\microsoft\internet explorer\main\featurecontrol\feature_restrict_activexinstall'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
            ValueName = 'excel.exe'
            ValueData = 1
        }
    }
    
    if ($FeatureControl_mspub) {
        RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_restrict_activexinstall\mspub.exe'
        {
            Key = '\software\microsoft\internet explorer\main\featurecontrol\feature_restrict_activexinstall'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
            ValueName = 'mspub.exe'
            ValueData = 1
        }
    }
    
    if ($FeatureControl_powerpnt) {
        RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_restrict_activexinstall\powerpnt.exe'
        {
            Key = '\software\microsoft\internet explorer\main\featurecontrol\feature_restrict_activexinstall'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
            ValueName = 'powerpnt.exe'
            ValueData = 1
        }
    }
    
    if ($FeatureControl_pptview) {
        RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_restrict_activexinstall\pptview.exe'
        {
            Key = '\software\microsoft\internet explorer\main\featurecontrol\feature_restrict_activexinstall'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
            ValueName = 'pptview.exe'
            ValueData = 1
        }
    }
    
    if ($FeatureControl_visio) {
        RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_restrict_activexinstall\visio.exe'
        {
            Key = '\software\microsoft\internet explorer\main\featurecontrol\feature_restrict_activexinstall'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
            ValueName = 'visio.exe'
            ValueData = 1
        }
    }

    if ($FeatureControl_winproj) {
        RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_restrict_activexinstall\winproj.exe'
        {
            Key = '\software\microsoft\internet explorer\main\featurecontrol\feature_restrict_activexinstall'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
            ValueName = 'winproj.exe'
            ValueData = 1
        }
    }
    
    if ($FeatureControl_winword) {
        RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_restrict_activexinstall\winword.exe'
        {
            Key = '\software\microsoft\internet explorer\main\featurecontrol\feature_restrict_activexinstall'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
            ValueName = 'winword.exe'
            ValueData = 1
        }
    }
    
    if ($FeatureControl_outlook) {
        RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_restrict_activexinstall\outlook.exe'
        {
            Key = '\software\microsoft\internet explorer\main\featurecontrol\feature_restrict_activexinstall'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
            ValueName = 'outlook.exe'
            ValueData = 1
        }
    }
    
    if ($FeatureControl_spdesign) {
        RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_restrict_activexinstall\spdesign.exe'
        {
            Key = '\software\microsoft\internet explorer\main\featurecontrol\feature_restrict_activexinstall'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
            ValueName = 'spdesign.exe'
            ValueData = 1
        }
    }
    
    if ($FeatureControl_exprwd) {
        RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_restrict_activexinstall\exprwd.exe'
        {
            Key = '\software\microsoft\internet explorer\main\featurecontrol\feature_restrict_activexinstall'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
            ValueName = 'exprwd.exe'
            ValueData = 1
        }
    }
    
    if ($FeatureControl_msaccess) {
        RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_restrict_activexinstall\msaccess.exe'
        {
            Key = '\software\microsoft\internet explorer\main\featurecontrol\feature_restrict_activexinstall'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
            ValueName = 'msaccess.exe'
            ValueData = 1
        }
    }

    if ($FeatureControl_onenote) {
        RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_restrict_activexinstall\onenote.exe'
        {
            Key = '\software\microsoft\internet explorer\main\featurecontrol\feature_restrict_activexinstall'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
            ValueName = 'onenote.exe'
            ValueData = 1
        }
    }
    
    if ($FeatureControl_mse7) {
        RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_restrict_activexinstall\mse7.exe'
        {
            Key = '\software\microsoft\internet explorer\main\featurecontrol\feature_restrict_activexinstall'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
            ValueName = 'mse7.exe'
            ValueData = 1
        }
    }
    
    if ($FeatureControl_groove_download) {
        RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_restrict_filedownload\groove.exe'
        {
            Key = '\software\microsoft\internet explorer\main\featurecontrol\feature_restrict_filedownload'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
            ValueName = 'groove.exe'
            ValueData = 1
        }
    }
    
    if ($FeatureControl_excel_download) {
        RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_restrict_filedownload\excel.exe'
        {
            Key = '\software\microsoft\internet explorer\main\featurecontrol\feature_restrict_filedownload'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
            ValueName = 'excel.exe'
            ValueData = 1
        }
    }
    
    if ($FeatureControl_mspub_download) {
        RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_restrict_filedownload\mspub.exe'
        {
            Key = '\software\microsoft\internet explorer\main\featurecontrol\feature_restrict_filedownload'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
            ValueName = 'mspub.exe'
            ValueData = 1
        }
    }
    
    if ($FeatureControl_powerpnt_download) {
        RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_restrict_filedownload\powerpnt.exe'
        {
            Key = '\software\microsoft\internet explorer\main\featurecontrol\feature_restrict_filedownload'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
            ValueName = 'powerpnt.exe'
            ValueData = 1
        }
    }

    if ($FeatureControl_pptview_download) {
        RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_restrict_filedownload\pptview.exe'
        {
            Key = '\software\microsoft\internet explorer\main\featurecontrol\feature_restrict_filedownload'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
            ValueName = 'pptview.exe'
            ValueData = 1
        }
    }
    
    if ($FeatureControl_visio_download) {
        RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_restrict_filedownload\visio.exe'
        {
            Key = '\software\microsoft\internet explorer\main\featurecontrol\feature_restrict_filedownload'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
            ValueName = 'visio.exe'
            ValueData = 1
        }
    }
    
    if ($FeatureControl_winproj_download) {
        RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_restrict_filedownload\winproj.exe'
        {
            Key = '\software\microsoft\internet explorer\main\featurecontrol\feature_restrict_filedownload'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
            ValueName = 'winproj.exe'
            ValueData = 1
        }
    }
    
    if ($FeatureControl_winword_download) {
        RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_restrict_filedownload\winword.exe'
        {
            Key = '\software\microsoft\internet explorer\main\featurecontrol\feature_restrict_filedownload'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
            ValueName = 'winword.exe'
            ValueData = 1
        }
    }
    
    if ($FeatureControl_outlook_download) {
        RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_restrict_filedownload\outlook.exe'
        {
            Key = '\software\microsoft\internet explorer\main\featurecontrol\feature_restrict_filedownload'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
            ValueName = 'outlook.exe'
            ValueData = 1
        }
    }
    
    if ($FeatureControl_spdesign_download) {
        RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_restrict_filedownload\spdesign.exe'
        {
            Key = '\software\microsoft\internet explorer\main\featurecontrol\feature_restrict_filedownload'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
            ValueName = 'spdesign.exe'
            ValueData = 1
        }
    }

    if ($FeatureControl_exprwd_download) {
        RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_restrict_filedownload\exprwd.exe'
        {
            Key = '\software\microsoft\internet explorer\main\featurecontrol\feature_restrict_filedownload'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
            ValueName = 'exprwd.exe'
            ValueData = 1
        }
    }
    
    if ($FeatureControl_msaccess_download) {
        RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_restrict_filedownload\msaccess.exe'
        {
            Key = '\software\microsoft\internet explorer\main\featurecontrol\feature_restrict_filedownload'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
            ValueName = 'msaccess.exe'
            ValueData = 1
        }
    }
    
    if ($FeatureControl_onenote_download) {
        RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_restrict_filedownload\onenote.exe'
        {
            Key = '\software\microsoft\internet explorer\main\featurecontrol\feature_restrict_filedownload'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
            ValueName = 'onenote.exe'
            ValueData = 1
        }
    }
    
    if ($FeatureControl_mse7_download) {
        RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_restrict_filedownload\mse7.exe'
        {
            Key = '\software\microsoft\internet explorer\main\featurecontrol\feature_restrict_filedownload'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
            ValueName = 'mse7.exe'
            ValueData = 1
        }
    }
    
    if ($FeatureControl_groove_security) {
        RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_securityband\groove.exe'
        {
            Key = '\software\microsoft\internet explorer\main\featurecontrol\feature_securityband'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
            ValueName = 'groove.exe'
            ValueData = 1
        }
    }
    
    if ($FeatureControl_excel_security) {
        RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_securityband\excel.exe'
        {
            Key = '\software\microsoft\internet explorer\main\featurecontrol\feature_securityband'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
            ValueName = 'excel.exe'
            ValueData = 1
        }
    }

    if ($FeatureControl_mspub_security) {
        RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_securityband\mspub.exe'
        {
            Key = '\software\microsoft\internet explorer\main\featurecontrol\feature_securityband'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
            ValueName = 'mspub.exe'
            ValueData = 1
        }
    }
    
    if ($FeatureControl_powerpnt_security) {
        RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_securityband\powerpnt.exe'
        {
            Key = '\software\microsoft\internet explorer\main\featurecontrol\feature_securityband'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
            ValueName = 'powerpnt.exe'
            ValueData = 1
        }
    }
    
    if ($FeatureControl_pptview_security) {
        RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_securityband\pptview.exe'
        {
            Key = '\software\microsoft\internet explorer\main\featurecontrol\feature_securityband'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
            ValueName = 'pptview.exe'
            ValueData = 1
        }
    }
    
    if ($FeatureControl_visio_security) {
        RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_securityband\visio.exe'
        {
            Key = '\software\microsoft\internet explorer\main\featurecontrol\feature_securityband'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
            ValueName = 'visio.exe'
            ValueData = 1
        }
    }
    
    if ($FeatureControl_winproj_security) {
        RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_securityband\winproj.exe'
        {
            Key = '\software\microsoft\internet explorer\main\featurecontrol\feature_securityband'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
            ValueName = 'winproj.exe'
            ValueData = 1
        }
    }

    if ($FeatureControl_winword_security) {
        RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_securityband\winword.exe'
        {
            Key = '\software\microsoft\internet explorer\main\featurecontrol\feature_securityband'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
            ValueName = 'winword.exe'
            ValueData = 1
        }
    }
    
    if ($FeatureControl_outlook_security) {
        RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_securityband\outlook.exe'
        {
            Key = '\software\microsoft\internet explorer\main\featurecontrol\feature_securityband'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
            ValueName = 'outlook.exe'
            ValueData = 1
        }
    }
    
    if ($FeatureControl_spdesign_security) {
        RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_securityband\spdesign.exe'
        {
            Key = '\software\microsoft\internet explorer\main\featurecontrol\feature_securityband'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
            ValueName = 'spdesign.exe'
            ValueData = 1
        }
    }
    
    if ($FeatureControl_exprwd_security) {
        RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_securityband\exprwd.exe'
        {
            Key = '\software\microsoft\internet explorer\main\featurecontrol\feature_securityband'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
            ValueName = 'exprwd.exe'
            ValueData = 1
        }
    }
    
    if ($FeatureControl_msaccess_security) {
        RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_securityband\msaccess.exe'
        {
            Key = '\software\microsoft\internet explorer\main\featurecontrol\feature_securityband'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
            ValueName = 'msaccess.exe'
            ValueData = 1
        }
    }

    if ($FeatureControl_onenote_security) {
        RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_securityband\onenote.exe'
        {
            Key = '\software\microsoft\internet explorer\main\featurecontrol\feature_securityband'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
            ValueName = 'onenote.exe'
            ValueData = 1
        }
    }
    
    if ($FeatureControl_mse7_security) {
        RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_securityband\mse7.exe'
        {
            Key = '\software\microsoft\internet explorer\main\featurecontrol\feature_securityband'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
            ValueName = 'mse7.exe'
            ValueData = 1
        }
    }
    
    if ($FeatureControl_groove_unc_check) {
        RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_unc_savedfilecheck\groove.exe'
        {
            Key = '\software\microsoft\internet explorer\main\featurecontrol\feature_unc_savedfilecheck'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
            ValueName = 'groove.exe'
            ValueData = 1
        }
    }
    
    if ($FeatureControl_excel_unc_check) {
        RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_unc_savedfilecheck\excel.exe'
        {
            Key = '\software\microsoft\internet explorer\main\featurecontrol\feature_unc_savedfilecheck'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
            ValueName = 'excel.exe'
            ValueData = 1
        }
    }
    
    if ($FeatureControl_mspub_unc_check) {
        RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_unc_savedfilecheck\mspub.exe'
        {
            Key = '\software\microsoft\internet explorer\main\featurecontrol\feature_unc_savedfilecheck'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
            ValueName = 'mspub.exe'
            ValueData = 1
        }
    }

    if ($FeatureControl_powerpnt_unc_check) {
        RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_unc_savedfilecheck\powerpnt.exe'
        {
            Key = '\software\microsoft\internet explorer\main\featurecontrol\feature_unc_savedfilecheck'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
            ValueName = 'powerpnt.exe'
            ValueData = 1
        }
    }
    
    if ($FeatureControl_pptview_unc_check) {
        RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_unc_savedfilecheck\pptview.exe'
        {
            Key = '\software\microsoft\internet explorer\main\featurecontrol\feature_unc_savedfilecheck'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
            ValueName = 'pptview.exe'
            ValueData = 1
        }
    }
    
    if ($FeatureControl_visio_unc_check) {
        RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_unc_savedfilecheck\visio.exe'
        {
            Key = '\software\microsoft\internet explorer\main\featurecontrol\feature_unc_savedfilecheck'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
            ValueName = 'visio.exe'
            ValueData = 1
        }
    }
    
    if ($FeatureControl_winproj_unc_check) {
        RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_unc_savedfilecheck\winproj.exe'
        {
            Key = '\software\microsoft\internet explorer\main\featurecontrol\feature_unc_savedfilecheck'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
            ValueName = 'winproj.exe'
            ValueData = 1
        }
    }
    
    if ($FeatureControl_winword_unc_check) {
        RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_unc_savedfilecheck\winword.exe'
        {
            Key = '\software\microsoft\internet explorer\main\featurecontrol\feature_unc_savedfilecheck'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
            ValueName = 'winword.exe'
            ValueData = 1
        }
    }
    
    if ($FeatureControl_outlook_unc_check) {
        RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_unc_savedfilecheck\outlook.exe'
        {
            Key = '\software\microsoft\internet explorer\main\featurecontrol\feature_unc_savedfilecheck'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
            ValueName = 'outlook.exe'
            ValueData = 1
        }
    }

    if ($FeatureControl_spdesign_unc_check) {
        RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_unc_savedfilecheck\spdesign.exe'
        {
            Key = '\software\microsoft\internet explorer\main\featurecontrol\feature_unc_savedfilecheck'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
            ValueName = 'spdesign.exe'
            ValueData = 1
        }
    }
    
    if ($FeatureControl_exprwd_unc_check) {
        RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_unc_savedfilecheck\exprwd.exe'
        {
            Key = '\software\microsoft\internet explorer\main\featurecontrol\feature_unc_savedfilecheck'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
            ValueName = 'exprwd.exe'
            ValueData = 1
        }
    }
    
    if ($FeatureControl_msaccess_unc_check) {
        RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_unc_savedfilecheck\msaccess.exe'
        {
            Key = '\software\microsoft\internet explorer\main\featurecontrol\feature_unc_savedfilecheck'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
            ValueName = 'msaccess.exe'
            ValueData = 1
        }
    }
    
    if ($FeatureControl_onenote_unc_check) {
        RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_unc_savedfilecheck\onenote.exe'
        {
            Key = '\software\microsoft\internet explorer\main\featurecontrol\feature_unc_savedfilecheck'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
            ValueName = 'onenote.exe'
            ValueData = 1
        }
    }
    
    if ($FeatureControl_mse7_unc_check) {
        RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_unc_savedfilecheck\mse7.exe'
        {
            Key = '\software\microsoft\internet explorer\main\featurecontrol\feature_unc_savedfilecheck'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
            ValueName = 'mse7.exe'
            ValueData = 1
        }
    }

    if ($FeatureControl_groove_validate_url) {
        RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_validate_navigate_url\groove.exe'
        {
            Key = '\software\microsoft\internet explorer\main\featurecontrol\feature_validate_navigate_url'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
            ValueName = 'groove.exe'
            ValueData = 1
        }
    }
    
    if ($FeatureControl_excel_validate_url) {
        RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_validate_navigate_url\excel.exe'
        {
            Key = '\software\microsoft\internet explorer\main\featurecontrol\feature_validate_navigate_url'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
            ValueName = 'excel.exe'
            ValueData = 1
        }
    }
    
    if ($FeatureControl_mspub_validate_url) {
        RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_validate_navigate_url\mspub.exe'
        {
            Key = '\software\microsoft\internet explorer\main\featurecontrol\feature_validate_navigate_url'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
            ValueName = 'mspub.exe'
            ValueData = 1
        }
    }
    
    if ($FeatureControl_powerpnt_validate_url) {
        RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_validate_navigate_url\powerpnt.exe'
        {
            Key = '\software\microsoft\internet explorer\main\featurecontrol\feature_validate_navigate_url'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
            ValueName = 'powerpnt.exe'
            ValueData = 1
        }
    }
    
    if ($FeatureControl_pptview_validate_url) {
        RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_validate_navigate_url\pptview.exe'
        {
            Key = '\software\microsoft\internet explorer\main\featurecontrol\feature_validate_navigate_url'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
            ValueName = 'pptview.exe'
            ValueData = 1
        }
    }

    if ($FeatureControl_visio_validate_url) {
        RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_validate_navigate_url\visio.exe'
        {
            Key = '\software\microsoft\internet explorer\main\featurecontrol\feature_validate_navigate_url'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
            ValueName = 'visio.exe'
            ValueData = 1
        }
    }
    
    if ($FeatureControl_winproj_validate_url) {
        RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_validate_navigate_url\winproj.exe'
        {
            Key = '\software\microsoft\internet explorer\main\featurecontrol\feature_validate_navigate_url'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
            ValueName = 'winproj.exe'
            ValueData = 1
        }
    }
    
    if ($FeatureControl_winword_validate_url) {
        RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_validate_navigate_url\winword.exe'
        {
            Key = '\software\microsoft\internet explorer\main\featurecontrol\feature_validate_navigate_url'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
            ValueName = 'winword.exe'
            ValueData = 1
        }
    }
    
    if ($FeatureControl_outlook_validate_url) {
        RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_validate_navigate_url\outlook.exe'
        {
            Key = '\software\microsoft\internet explorer\main\featurecontrol\feature_validate_navigate_url'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
            ValueName = 'outlook.exe'
            ValueData = 1
        }
    }
    
    if ($FeatureControl_spdesign_validate_url) {
        RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_validate_navigate_url\spdesign.exe'
        {
            Key = '\software\microsoft\internet explorer\main\featurecontrol\feature_validate_navigate_url'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
            ValueName = 'spdesign.exe'
            ValueData = 1
        }
    }

    if ($FeatureControl_exprwd_validate_url) {
        RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_validate_navigate_url\exprwd.exe'
        {
            Key = '\software\microsoft\internet explorer\main\featurecontrol\feature_validate_navigate_url'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
            ValueName = 'exprwd.exe'
            ValueData = 1
        }
    }
    
    if ($FeatureControl_msaccess_validate_url) {
        RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_validate_navigate_url\msaccess.exe'
        {
            Key = '\software\microsoft\internet explorer\main\featurecontrol\feature_validate_navigate_url'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
            ValueName = 'msaccess.exe'
            ValueData = 1
        }
    }
    
    if ($FeatureControl_onenote_validate_url) {
        RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_validate_navigate_url\onenote.exe'
        {
            Key = '\software\microsoft\internet explorer\main\featurecontrol\feature_validate_navigate_url'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
            ValueName = 'onenote.exe'
            ValueData = 1
        }
    }
    
    if ($FeatureControl_mse7_validate_url) {
        RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_validate_navigate_url\mse7.exe'
        {
            Key = '\software\microsoft\internet explorer\main\featurecontrol\feature_validate_navigate_url'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
            ValueName = 'mse7.exe'
            ValueData = 1
        }
    }
    
    if ($FeatureControl_groove_window_restriction) {
        RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_window_restrictions\groove.exe'
        {
            Key = '\software\microsoft\internet explorer\main\featurecontrol\feature_window_restrictions'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
            ValueName = 'groove.exe'
            ValueData = 1
        }
    }

    if ($FeatureControl_excel_window_restriction) {
        RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_window_restrictions\excel.exe'
        {
            Key = '\software\microsoft\internet explorer\main\featurecontrol\feature_window_restrictions'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
            ValueName = 'excel.exe'
            ValueData = 1
        }
    }
    
    if ($FeatureControl_mspub_window_restriction) {
        RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_window_restrictions\mspub.exe'
        {
            Key = '\software\microsoft\internet explorer\main\featurecontrol\feature_window_restrictions'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
            ValueName = 'mspub.exe'
            ValueData = 1
        }
    }
    
    if ($FeatureControl_powerpnt_window_restriction) {
        RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_window_restrictions\powerpnt.exe'
        {
            Key = '\software\microsoft\internet explorer\main\featurecontrol\feature_window_restrictions'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
            ValueName = 'powerpnt.exe'
            ValueData = 1
        }
    }
    
    if ($FeatureControl_pptview_window_restriction) {
        RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_window_restrictions\pptview.exe'
        {
            Key = '\software\microsoft\internet explorer\main\featurecontrol\feature_window_restrictions'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
            ValueName = 'pptview.exe'
            ValueData = 1
        }
    }
    
    if ($FeatureControl_visio_window_restriction) {
        RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_window_restrictions\visio.exe'
        {
            Key = '\software\microsoft\internet explorer\main\featurecontrol\feature_window_restrictions'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
            ValueName = 'visio.exe'
            ValueData = 1
        }
    }

    if ($FeatureControl_winproj_window_restriction) {
        RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_window_restrictions\winproj.exe'
        {
            Key = '\software\microsoft\internet explorer\main\featurecontrol\feature_window_restrictions'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
            ValueName = 'winproj.exe'
            ValueData = 1
        }
    }
    
    if ($FeatureControl_winword_window_restriction) {
        RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_window_restrictions\winword.exe'
        {
            Key = '\software\microsoft\internet explorer\main\featurecontrol\feature_window_restrictions'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
            ValueName = 'winword.exe'
            ValueData = 1
        }
    }
    
    if ($FeatureControl_outlook_window_restriction) {
        RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_window_restrictions\outlook.exe'
        {
            Key = '\software\microsoft\internet explorer\main\featurecontrol\feature_window_restrictions'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
            ValueName = 'outlook.exe'
            ValueData = 1
        }
    }
    
    if ($FeatureControl_spdesign_window_restriction) {
        RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_window_restrictions\spdesign.exe'
        {
            Key = '\software\microsoft\internet explorer\main\featurecontrol\feature_window_restrictions'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
            ValueName = 'spdesign.exe'
            ValueData = 1
        }
    }
    
    if ($FeatureControl_exprwd_window_restriction) {
        RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_window_restrictions\exprwd.exe'
        {
            Key = '\software\microsoft\internet explorer\main\featurecontrol\feature_window_restrictions'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
            ValueName = 'exprwd.exe'
            ValueData = 1
        }
    }

    if ($FeatureControl_msaccess_window_restriction) {
        RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_window_restrictions\msaccess.exe'
        {
            Key = '\software\microsoft\internet explorer\main\featurecontrol\feature_window_restrictions'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
            ValueName = 'msaccess.exe'
            ValueData = 1
        }
    }
    
    if ($FeatureControl_onenote_window_restriction) {
        RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_window_restrictions\onenote.exe'
        {
            Key = '\software\microsoft\internet explorer\main\featurecontrol\feature_window_restrictions'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
            ValueName = 'onenote.exe'
            ValueData = 1
        }
    }
    
    if ($FeatureControl_mse7_window_restriction) {
        RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_window_restrictions\mse7.exe'
        {
            Key = '\software\microsoft\internet explorer\main\featurecontrol\feature_window_restrictions'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
            ValueName = 'mse7.exe'
            ValueData = 1
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
            ValueData = 1
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
            ValueData = 1
        }
    }
    
    if ($FeatureControl_D27CDB6E_ActivationFilterOverride) {
        RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\Office\16.0\Common\COM Compatibility\{D27CDB6E-AE6D-11CF-96B8-444553540000}\ActivationFilterOverride'
        {
            Key = '\software\microsoft\Office\16.0\Common\COM Compatibility\{D27CDB6E-AE6D-11CF-96B8-444553540000}'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
            ValueName = 'ActivationFilterOverride'
            ValueData = 0
        }
    }
    
    if ($FeatureControl_D27CDB6E_CompatibilityFlags) {
        RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\Office\16.0\Common\COM Compatibility\{D27CDB6E-AE6D-11CF-96B8-444553540000}\Compatibility Flags'
        {
            Key = '\software\microsoft\Office\16.0\Common\COM Compatibility\{D27CDB6E-AE6D-11CF-96B8-444553540000}'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
            ValueName = 'Compatibility Flags'
            ValueData = 1024
        }
    }
    
    if ($FeatureControl_D27CDB70_ActivationFilterOverride) {
        RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\Office\16.0\Common\COM Compatibility\{D27CDB70-AE6D-11CF-96B8-444553540000}\ActivationFilterOverride'
        {
            Key = '\software\microsoft\Office\16.0\Common\COM Compatibility\{D27CDB70-AE6D-11CF-96B8-444553540000}'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
            ValueName = 'ActivationFilterOverride'
            ValueData = 0
        }
    }
    
    if ($FeatureControl_D27CDB70_CompatibilityFlags) {
        RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\Office\16.0\Common\COM Compatibility\{D27CDB70-AE6D-11CF-96B8-444553540000}\Compatibility Flags'
        {
            Key = '\software\microsoft\Office\16.0\Common\COM Compatibility\{D27CDB70-AE6D-11CF-96B8-444553540000}'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
            ValueName = 'Compatibility Flags'
            ValueData = 1024
        }
    }
    
    if ($FeatureControl_Comment) {
        RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\Office\Common\COM Compatibility\Comment'
        {
            Key = '\software\microsoft\Office\Common\COM Compatibility'
            ValueType = 'String'
            TargetType = 'ComputerConfiguration'
            ValueName = 'Comment'
            ValueData = 'Block all Flash activation'
        }
    }

    if ($FeatureControl_D27CDB6E_Office_ActivationFilterOverride) {
        RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\Office\Common\COM Compatibility\{D27CDB6E-AE6D-11CF-96B8-444553540000}\ActivationFilterOverride'
        {
            Key = '\software\microsoft\Office\Common\COM Compatibility\{D27CDB6E-AE6D-11CF-96B8-444553540000}'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
            ValueName = 'ActivationFilterOverride'
            ValueData = 0
        }
    }
    
    if ($FeatureControl_D27CDB6E_Office_CompatibilityFlags) {
        RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\Office\Common\COM Compatibility\{D27CDB6E-AE6D-11CF-96B8-444553540000}\Compatibility Flags'
        {
            Key = '\software\microsoft\Office\Common\COM Compatibility\{D27CDB6E-AE6D-11CF-96B8-444553540000}'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
            ValueName = 'Compatibility Flags'
            ValueData = 1024
        }
    }
    
    if ($FeatureControl_D27CDB70_Office_ActivationFilterOverride) {
        RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\Office\Common\COM Compatibility\{D27CDB70-AE6D-11CF-96B8-444553540000}\ActivationFilterOverride'
        {
            Key = '\software\microsoft\Office\Common\COM Compatibility\{D27CDB70-AE6D-11CF-96B8-444553540000}'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
            ValueName = 'ActivationFilterOverride'
            ValueData = 0
        }
    }
    
    if ($FeatureControl_D27CDB70_Office_CompatibilityFlags) {
        RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\Office\Common\COM Compatibility\{D27CDB70-AE6D-11CF-96B8-444553540000}\Compatibility Flags'
        {
            Key = '\software\microsoft\Office\Common\COM Compatibility\{D27CDB70-AE6D-11CF-96B8-444553540000}'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
            ValueName = 'Compatibility Flags'
            ValueData = 1024
        }
    }
    
    if ($FeatureControl_EnableSipHighSecurityMode) {
        RegistryPolicyFile 'Registry(POL): HKLM:\software\policies\microsoft\office\16.0\lync\enablesiphighsecuritymode'
        {
            Key = '\software\policies\microsoft\office\16.0\lync'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
            ValueName = 'enablesiphighsecuritymode'
            ValueData = 1
        }
    }
    
    if ($FeatureControl_DisableHttpConnect) {
        RegistryPolicyFile 'Registry(POL): HKLM:\software\policies\microsoft\office\16.0\lync\disablehttpconnect'
        {
            Key = '\software\policies\microsoft\office\16.0\lync'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
            ValueName = 'disablehttpconnect'
            ValueData = 1
        }
    }

    if ($WOW6432Node_D27CDB6E_16_ActivationFilterOverride) {
        RegistryPolicyFile 'Registry(POL): HKLM:\software\WOW6432Node\Microsoft\Office\16.0\Common\COM Compatibility\{D27CDB6E-AE6D-11CF-96B8-444553540000}\ActivationFilterOverride'
        {
            Key = '\software\WOW6432Node\Microsoft\Office\16.0\Common\COM Compatibility\{D27CDB6E-AE6D-11CF-96B8-444553540000}'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
            ValueName = 'ActivationFilterOverride'
            ValueData = 0
        }
    }
    
    if ($WOW6432Node_D27CDB6E_16_CompatibilityFlags) {
        RegistryPolicyFile 'Registry(POL): HKLM:\software\WOW6432Node\Microsoft\Office\16.0\Common\COM Compatibility\{D27CDB6E-AE6D-11CF-96B8-444553540000}\Compatibility Flags'
        {
            Key = '\software\WOW6432Node\Microsoft\Office\16.0\Common\COM Compatibility\{D27CDB6E-AE6D-11CF-96B8-444553540000}'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
            ValueName = 'Compatibility Flags'
            ValueData = 1024
        }
    }
    
    if ($WOW6432Node_D27CDB70_16_ActivationFilterOverride) {
        RegistryPolicyFile 'Registry(POL): HKLM:\software\WOW6432Node\Microsoft\Office\16.0\Common\COM Compatibility\{D27CDB70-AE6D-11CF-96B8-444553540000}\ActivationFilterOverride'
        {
            Key = '\software\WOW6432Node\Microsoft\Office\16.0\Common\COM Compatibility\{D27CDB70-AE6D-11CF-96B8-444553540000}'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
            ValueName = 'ActivationFilterOverride'
            ValueData = 0
        }
    }
    
    if ($WOW6432Node_D27CDB70_16_CompatibilityFlags) {
        RegistryPolicyFile 'Registry(POL): HKLM:\software\WOW6432Node\Microsoft\Office\16.0\Common\COM Compatibility\{D27CDB70-AE6D-11CF-96B8-444553540000}\Compatibility Flags'
        {
            Key = '\software\WOW6432Node\Microsoft\Office\16.0\Common\COM Compatibility\{D27CDB70-AE6D-11CF-96B8-444553540000}'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
            ValueName = 'Compatibility Flags'
            ValueData = 1024
        }
    }
    
    if ($WOW6432Node_D27CDB6E_Common_ActivationFilterOverride) {
        RegistryPolicyFile 'Registry(POL): HKLM:\software\WOW6432Node\Microsoft\Office\Common\COM Compatibility\{D27CDB6E-AE6D-11CF-96B8-444553540000}\ActivationFilterOverride'
        {
            Key = '\software\WOW6432Node\Microsoft\Office\Common\COM Compatibility\{D27CDB6E-AE6D-11CF-96B8-444553540000}'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
            ValueName = 'ActivationFilterOverride'
            ValueData = 0
        }
    }

    if ($WOW6432Node_D27CDB6E_Common_CompatibilityFlags) {
        RegistryPolicyFile 'Registry(POL): HKLM:\software\WOW6432Node\Microsoft\Office\Common\COM Compatibility\{D27CDB6E-AE6D-11CF-96B8-444553540000}\Compatibility Flags'
        {
            Key = '\software\WOW6432Node\Microsoft\Office\Common\COM Compatibility\{D27CDB6E-AE6D-11CF-96B8-444553540000}'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
            ValueName = 'Compatibility Flags'
            ValueData = 1024
        }
    }
    
    if ($WOW6432Node_D27CDB70_Common_ActivationFilterOverride) {
        RegistryPolicyFile 'Registry(POL): HKLM:\software\WOW6432Node\Microsoft\Office\Common\COM Compatibility\{D27CDB70-AE6D-11CF-96B8-444553540000}\ActivationFilterOverride'
        {
            Key = '\software\WOW6432Node\Microsoft\Office\Common\COM Compatibility\{D27CDB70-AE6D-11CF-96B8-444553540000}'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
            ValueName = 'ActivationFilterOverride'
            ValueData = 0
        }
    }
    
    if ($WOW6432Node_D27CDB70_Common_CompatibilityFlags) {
        RegistryPolicyFile 'Registry(POL): HKLM:\software\WOW6432Node\Microsoft\Office\Common\COM Compatibility\{D27CDB70-AE6D-11CF-96B8-444553540000}\Compatibility Flags'
        {
            Key = '\software\WOW6432Node\Microsoft\Office\Common\COM Compatibility\{D27CDB70-AE6D-11CF-96B8-444553540000}'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
            ValueName = 'Compatibility Flags'
            ValueData = 1024
        }
    }
}

