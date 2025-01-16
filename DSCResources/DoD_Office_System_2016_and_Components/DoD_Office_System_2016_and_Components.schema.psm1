configuration DoD_Office_System_2016_and_Components
{

    param(
        [bool]$OneDrive_AllowTenantList_1111 = $true,
        [bool]$Excel_EncryptedMacroScan = $false,
        [bool]$Excel_WebServiceFunctionWarnings = $false,
        [bool]$Excel_OpenInProtectedView = $false,
        [bool]$Outlook_FileExtensionsRemoveLevel1 = $false,
        [bool]$Outlook_FileExtensionsRemoveLevel2 = $false,
        [bool]$KeyCU_LoadControlsInForms = $false,
        [bool]$KeyCU_UFIControls = $false,
        [bool]$IE_AddOnManagement_Grove = $true,
        [bool]$IE_AddOnManagement_Excel = $true,
        [bool]$IE_AddOnManagement_MSPub = $true,
        [bool]$IE_AddOnManagement_PowerPNT = $true,
        [bool]$IE_AddOnManagement_PPTView = $true,
        [bool]$IE_AddOnManagement_Visio = $true,
        [bool]$IE_AddOnManagement_WinProj = $true,
        [bool]$IE_AddOnManagement_WinWord = $true,
        [bool]$IE_AddOnManagement_Outlook = $true,
        [bool]$IE_AddOnManagement_SPDesign = $false,
        [bool]$IE_AddOnManagement_ExprWD = $false,
        [bool]$IE_AddOnManagement_MSAccess = $true,
        [bool]$IE_AddOnManagement_OneNote = $true,
        [bool]$IE_AddOnManagement_MSE7 = $false,
        [bool]$IE_HTTPUsernamePasswordDisable_Grove = $true,
        [bool]$IE_HTTPUsernamePasswordDisable_Excel = $true,
        [bool]$IE_HTTPUsernamePasswordDisable_MSPub = $true,
        [bool]$IE_HTTPUsernamePasswordDisable_PowerPNT = $true,
        [bool]$IE_HTTPUsernamePasswordDisable_PPTView = $true,
        [bool]$IE_HTTPUsernamePasswordDisable_Visio = $true,
        [bool]$IE_HTTPUsernamePasswordDisable_WinProj = $true,
        [bool]$IE_HTTPUsernamePasswordDisable_WinWord = $true,
        [bool]$IE_HTTPUsernamePasswordDisable_Outlook = $true,
        [bool]$IE_HTTPUsernamePasswordDisable_SPDesign = $false,
        [bool]$IE_HTTPUsernamePasswordDisable_ExprWD = $false,
        [bool]$IE_HTTPUsernamePasswordDisable_MSAccess = $true,
        [bool]$IE_HTTPUsernamePasswordDisable_OneNote = $true,
        [bool]$IE_HTTPUsernamePasswordDisable_MSE7 = $false,
        [bool]$IE_RestrictActiveXInstall_Grove = $true,
        [bool]$IE_RestrictActiveXInstall_Excel = $true,
        [bool]$IE_RestrictActiveXInstall_MSPub = $true,
        [bool]$IE_RestrictActiveXInstall_PowerPNT = $true,
        [bool]$IE_RestrictActiveXInstall_PPTView = $true,
        [bool]$IE_RestrictActiveXInstall_Visio = $true,
        [bool]$IE_RestrictActiveXInstall_WinProj = $true,
        [bool]$IE_RestrictActiveXInstall_WinWord = $true,
        [bool]$IE_RestrictActiveXInstall_Outlook = $true,
        [bool]$IE_RestrictActiveXInstall_SPDesign = $false,
        [bool]$IE_RestrictActiveXInstall_ExprWD = $false,
        [bool]$IE_RestrictActiveXInstall_MSAccess = $true,
        [bool]$IE_RestrictActiveXInstall_OneNote = $true,
        [bool]$IE_RestrictActiveXInstall_MSE7 = $false,
        [bool]$IE_RestrictFileDownload_Grove = $true,
        [bool]$IE_RestrictFileDownload_Excel = $true,
        [bool]$IE_RestrictFileDownload_MSPub = $true,
        [bool]$IE_RestrictFileDownload_PowerPNT = $true,
        [bool]$IE_RestrictFileDownload_PPTView = $true,
        [bool]$IE_RestrictFileDownload_Visio = $true,
        [bool]$IE_RestrictFileDownload_WinProj = $true,
        [bool]$IE_RestrictFileDownload_WinWord = $true,
        [bool]$IE_RestrictFileDownload_Outlook = $true,
        [bool]$IE_RestrictFileDownload_SPDesign = $false,
        [bool]$IE_RestrictFileDownload_ExprWD = $false,
        [bool]$IE_RestrictFileDownload_MSAccess = $true,
        [bool]$IE_RestrictFileDownload_OneNote = $true,
        [bool]$IE_RestrictFileDownload_MSE7 = $false,
        [bool]$IE_SafeBindToObject_Grove = $true,
        [bool]$IE_SafeBindToObject_Excel = $true,
        [bool]$IE_SafeBindToObject_MSPub = $true,
        [bool]$IE_SafeBindToObject_PowerPNT = $true,
        [bool]$IE_SafeBindToObject_PPTView = $true,
        [bool]$IE_SafeBindToObject_Visio = $true,
        [bool]$IE_SafeBindToObject_WinProj = $true,
        [bool]$IE_SafeBindToObject_WinWord = $true,
        [bool]$IE_SafeBindToObject_Outlook = $true,
        [bool]$IE_SafeBindToObject_SPDesign = $false,
        [bool]$IE_SafeBindToObject_ExprWD = $false,
        [bool]$IE_SafeBindToObject_MSAccess = $true,
        [bool]$IE_SafeBindToObject_OneNote = $true,
        [bool]$IE_SafeBindToObject_MSE7 = $false,
        [bool]$IE_UNCSavedFileCheck_Grove = $true,
        [bool]$IE_UNCSavedFileCheck_Excel = $true,
        [bool]$IE_UNCSavedFileCheck_MSPub = $true,
        [bool]$IE_UNCSavedFileCheck_PowerPNT = $true,
        [bool]$IE_UNCSavedFileCheck_PPTView = $true,
        [bool]$IE_UNCSavedFileCheck_Visio = $true,
        [bool]$IE_UNCSavedFileCheck_WinProj = $true,
        [bool]$IE_UNCSavedFileCheck_WinWord = $true,
        [bool]$IE_UNCSavedFileCheck_Outlook = $true,
        [bool]$IE_UNCSavedFileCheck_SPDesign = $false,
        [bool]$IE_UNCSavedFileCheck_ExprWD = $false,
        [bool]$IE_UNCSavedFileCheck_MSAccess = $true,
        [bool]$IE_UNCSavedFileCheck_OneNote = $true,
        [bool]$IE_UNCSavedFileCheck_MSE7 = $false,
        [bool]$IE_ValidateNavigateURL_Grove = $true,
        [bool]$IE_ValidateNavigateURL_Excel = $true,
        [bool]$IE_ValidateNavigateURL_MSPub = $true,
        [bool]$IE_ValidateNavigateURL_PowerPNT = $true,
        [bool]$IE_ValidateNavigateURL_PPTView = $true,
        [bool]$IE_ValidateNavigateURL_Visio = $true,
        [bool]$IE_ValidateNavigateURL_WinProj = $true,
        [bool]$IE_ValidateNavigateURL_WinWord = $true,
        [bool]$IE_ValidateNavigateURL_Outlook = $true,
        [bool]$IE_ValidateNavigateURL_SPDesign = $false,
        [bool]$IE_ValidateNavigateURL_ExprWD = $false,
        [bool]$IE_ValidateNavigateURL_MSAccess = $true,
        [bool]$IE_ValidateNavigateURL_OneNote = $true,
        [bool]$IE_ValidateNavigateURL_MSE7 = $false,
        [bool]$IE_WebocPopupManagement_Grove = $true,
        [bool]$IE_WebocPopupManagement_Excel = $true,
        [bool]$IE_WebocPopupManagement_MSPub = $true,
        [bool]$IE_WebocPopupManagement_PowerPNT = $true,
        [bool]$IE_WebocPopupManagement_PPTView = $true,
        [bool]$IE_WebocPopupManagement_Visio = $true,
        [bool]$IE_WebocPopupManagement_WinProj = $true,
        [bool]$IE_WebocPopupManagement_WinWord = $true,
        [bool]$IE_WebocPopupManagement_Outlook = $true,
        [bool]$IE_WebocPopupManagement_SPDesign = $false,
        [bool]$IE_WebocPopupManagement_ExprWD = $false,
        [bool]$IE_WebocPopupManagement_MSAccess = $true,
        [bool]$IE_WebocPopupManagement_OneNote = $true,
        [bool]$IE_WebocPopupManagement_MSE7 = $false,
        [bool]$IE_WindowRestrictions_Grove = $true,
        [bool]$IE_WindowRestrictions_Excel = $true,
        [bool]$IE_WindowRestrictions_MSPub = $true,
        [bool]$IE_WindowRestrictions_PowerPNT = $true,
        [bool]$IE_WindowRestrictions_PPTView = $true,
        [bool]$IE_WindowRestrictions_Visio = $true,
        [bool]$IE_WindowRestrictions_WinProj = $true,
        [bool]$IE_WindowRestrictions_WinWord = $true,
        [bool]$IE_WindowRestrictions_Outlook = $true,
        [bool]$IE_WindowRestrictions_SPDesign = $false,
        [bool]$IE_WindowRestrictions_ExprWD = $false,
        [bool]$IE_WindowRestrictions_MSAccess = $true,
        [bool]$IE_WindowRestrictions_OneNote = $true,
        [bool]$IE_WindowRestrictions_MSE7 = $false,
        [bool]$IE_ZoneElevation_Grove = $true,
        [bool]$IE_ZoneElevation_Excel = $true,
        [bool]$IE_ZoneElevation_MSPub = $true,
        [bool]$IE_ZoneElevation_PowerPNT = $true,
        [bool]$IE_ZoneElevation_PPTView = $true,
        [bool]$IE_ZoneElevation_Visio = $true,
        [bool]$IE_ZoneElevation_WinProj = $true,
        [bool]$IE_ZoneElevation_WinWord = $true,
        [bool]$IE_ZoneElevation_Outlook = $true,
        [bool]$IE_ZoneElevation_SPDesign = $false,
        [bool]$IE_ZoneElevation_ExprWD = $false,
        [bool]$IE_ZoneElevation_MSAccess = $true,
        [bool]$IE_ZoneElevation_OneNote = $true,
        [bool]$IE_ZoneElevation_MSE7 = $false,
        [bool]$PowerPoint_RunPrograms = $false,
        [bool]$PowerPoint_OpenInProtectedView = $false,
        [bool]$Lync_SavePassword = $false,
        [bool]$Lync_EnableSIPHighSecurityMode = $true,
        [bool]$Lync_DisableHTTPConnect = $true,
        [bool]$Word_BypassEncryptedMacroScan = $false,
        [bool]$Word_OpenInProtectedView = $false
    )

    Import-DSCResource -ModuleName 'GPRegistryPolicyDsc'
	Import-DSCResource -ModuleName 'AuditPolicyDSC'
	Import-DSCResource -ModuleName 'SecurityPolicyDSC'

    if ($OneDrive_AllowTenantList_1111) {
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\OneDrive\AllowTenantList\1111-2222-3333-4444'
        {
            Key = '\Software\Policies\Microsoft\OneDrive\AllowTenantList'
            ValueType = 'String'
            TargetType = 'ComputerConfiguration'
            ValueName = '1111-2222-3333-4444'
            ValueData = '1111-2222-3333-4444'
        }
    }
    
    if ( $Excel_EncryptedMacroScan) {
        RegistryPolicyFile 'DEL_CU:\software\policies\microsoft\office\16.0\excel\security\excelbypassencryptedmacroscan'
        {
            Key = 'HKCU:\software\policies\microsoft\office\16.0\excel\security'
            ValueType = 'String'
            Ensure = 'Absent'
            TargetType = 'ComputerConfiguration'
            ValueName = 'excelbypassencryptedmacroscan'
            ValueData = ''
        }
    }
    
    if ( $Excel_WebServiceFunctionWarnings) {
        RegistryPolicyFile 'DEL_CU:\software\policies\microsoft\office\16.0\excel\security\webservicefunctionwarnings'
        {
            Key = 'HKCU:\software\policies\microsoft\office\16.0\excel\security'
            ValueType = 'String'
            Ensure = 'Absent'
            TargetType = 'ComputerConfiguration'
            ValueName = 'webservicefunctionwarnings'
            ValueData = ''
        }
    }
    
    if ( $Excel_OpenInProtectedView) {
        RegistryPolicyFile 'DEL_CU:\software\policies\microsoft\office\16.0\excel\security\filevalidation\openinprotectedview'
        {
            Key = 'HKCU:\software\policies\microsoft\office\16.0\excel\security\filevalidation'
            ValueType = 'String'
            Ensure = 'Absent'
            TargetType = 'ComputerConfiguration'
            ValueName = 'openinprotectedview'
            ValueData = ''
        }
    }
    
    if ( $Outlook_FileExtensionsRemoveLevel1) {
        RegistryPolicyFile 'DEL_CU:\software\policies\microsoft\office\16.0\outlook\security\fileextensionsremovelevel1'
        {
            Key = 'HKCU:\software\policies\microsoft\office\16.0\outlook\security'
            ValueType = 'String'
            Ensure = 'Absent'
            TargetType = 'ComputerConfiguration'
            ValueName = 'fileextensionsremovelevel1'
            ValueData = ''
        }
    }
    
    if ( $Outlook_FileExtensionsRemoveLevel2) {
        RegistryPolicyFile 'DEL_CU:\software\policies\microsoft\office\16.0\outlook\security\fileextensionsremovelevel2'
        {
            Key = 'HKCU:\software\policies\microsoft\office\16.0\outlook\security'
            ValueType = 'String'
            Ensure = 'Absent'
            TargetType = 'ComputerConfiguration'
            ValueName = 'fileextensionsremovelevel2'
            ValueData = ''
        }
    }

    if ( $KeyCU_LoadControlsInForms) {
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
    
    if ( $KeyCU_UFIControls) {
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
    
    if ($IE_AddOnManagement_Grove) {
        RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_addon_management\groove.exe'
        {
            Key = '\software\microsoft\internet explorer\main\featurecontrol\feature_addon_management'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
            ValueName = 'groove.exe'
            ValueData = 1
        }
    }
    
    if ($IE_AddOnManagement_Excel) {
        RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_addon_management\excel.exe'
        {
            Key = '\software\microsoft\internet explorer\main\featurecontrol\feature_addon_management'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
            ValueName = 'excel.exe'
            ValueData = 1
        }
    }
    
    if ($IE_AddOnManagement_MSPub) {
        RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_addon_management\mspub.exe'
        {
            Key = '\software\microsoft\internet explorer\main\featurecontrol\feature_addon_management'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
            ValueName = 'mspub.exe'
            ValueData = 1
        }
    }
    
    if ($IE_AddOnManagement_PowerPNT) {
        RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_addon_management\powerpnt.exe'
        {
            Key = '\software\microsoft\internet explorer\main\featurecontrol\feature_addon_management'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
            ValueName = 'powerpnt.exe'
            ValueData = 1
        }
    }
    
    if ($IE_AddOnManagement_PPTView) {
        RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_addon_management\pptview.exe'
        {
            Key = '\software\microsoft\internet explorer\main\featurecontrol\feature_addon_management'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
            ValueName = 'pptview.exe'
            ValueData = 1
        }
    }

    if ($IE_AddOnManagement_Visio) {
        RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_addon_management\visio.exe'
        {
            Key = '\software\microsoft\internet explorer\main\featurecontrol\feature_addon_management'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
            ValueName = 'visio.exe'
            ValueData = 1
        }
    }
    
    if ($IE_AddOnManagement_WinProj) {
        RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_addon_management\winproj.exe'
        {
            Key = '\software\microsoft\internet explorer\main\featurecontrol\feature_addon_management'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
            ValueName = 'winproj.exe'
            ValueData = 1
        }
    }
    
    if ($IE_AddOnManagement_WinWord) {
        RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_addon_management\winword.exe'
        {
            Key = '\software\microsoft\internet explorer\main\featurecontrol\feature_addon_management'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
            ValueName = 'winword.exe'
            ValueData = 1
        }
    }
    
    if ($IE_AddOnManagement_Outlook) {
        RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_addon_management\outlook.exe'
        {
            Key = '\software\microsoft\internet explorer\main\featurecontrol\feature_addon_management'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
            ValueName = 'outlook.exe'
            ValueData = 1
        }
    }
    
    if ( $IE_AddOnManagement_SPDesign) {
        RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_addon_management\spdesign.exe'
        {
            Key = '\software\microsoft\internet explorer\main\featurecontrol\feature_addon_management'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
            ValueName = 'spdesign.exe'
            ValueData = 0
        }
    }
    
    if ( $IE_AddOnManagement_ExprWD) {
        RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_addon_management\exprwd.exe'
        {
            Key = '\software\microsoft\internet explorer\main\featurecontrol\feature_addon_management'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
            ValueName = 'exprwd.exe'
            ValueData = 0
        }
    }
    
    if ($IE_AddOnManagement_MSAccess) {
        RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_addon_management\msaccess.exe'
        {
            Key = '\software\microsoft\internet explorer\main\featurecontrol\feature_addon_management'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
            ValueName = 'msaccess.exe'
            ValueData = 1
        }
    }
    
    if ($IE_AddOnManagement_OneNote) {
        RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_addon_management\onenote.exe'
        {
            Key = '\software\microsoft\internet explorer\main\featurecontrol\feature_addon_management'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
            ValueName = 'onenote.exe'
            ValueData = 1
        }
    }

    if ( $IE_AddOnManagement_MSE7) {
        RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_addon_management\mse7.exe'
        {
            Key = '\software\microsoft\internet explorer\main\featurecontrol\feature_addon_management'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
            ValueName = 'mse7.exe'
            ValueData = 0
        }
    }
    
    if ($IE_HTTPUsernamePasswordDisable_Grove) {
        RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_http_username_password_disable\groove.exe'
        {
            Key = '\software\microsoft\internet explorer\main\featurecontrol\feature_http_username_password_disable'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
            ValueName = 'groove.exe'
            ValueData = 1
        }
    }
    
    if ($IE_HTTPUsernamePasswordDisable_Excel) {
        RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_http_username_password_disable\excel.exe'
        {
            Key = '\software\microsoft\internet explorer\main\featurecontrol\feature_http_username_password_disable'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
            ValueName = 'excel.exe'
            ValueData = 1
        }
    }
    
    if ($IE_HTTPUsernamePasswordDisable_MSPub) {
        RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_http_username_password_disable\mspub.exe'
        {
            Key = '\software\microsoft\internet explorer\main\featurecontrol\feature_http_username_password_disable'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
            ValueName = 'mspub.exe'
            ValueData = 1
        }
    }
    
    if ($IE_HTTPUsernamePasswordDisable_PowerPNT) {
        RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_http_username_password_disable\powerpnt.exe'
        {
            Key = '\software\microsoft\internet explorer\main\featurecontrol\feature_http_username_password_disable'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
            ValueName = 'powerpnt.exe'
            ValueData = 1
        }
    }
    
    if ($IE_HTTPUsernamePasswordDisable_PPTView) {
        RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_http_username_password_disable\pptview.exe'
        {
            Key = '\software\microsoft\internet explorer\main\featurecontrol\feature_http_username_password_disable'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
            ValueName = 'pptview.exe'
            ValueData = 1
        }
    }

    if ($IE_HTTPUsernamePasswordDisable_Visio) {
        RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_http_username_password_disable\visio.exe'
        {
            Key = '\software\microsoft\internet explorer\main\featurecontrol\feature_http_username_password_disable'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
            ValueName = 'visio.exe'
            ValueData = 1
        }
    }
    
    if ($IE_HTTPUsernamePasswordDisable_WinProj) {
        RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_http_username_password_disable\winproj.exe'
        {
            Key = '\software\microsoft\internet explorer\main\featurecontrol\feature_http_username_password_disable'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
            ValueName = 'winproj.exe'
            ValueData = 1
        }
    }
    
    if ($IE_HTTPUsernamePasswordDisable_WinWord) {
        RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_http_username_password_disable\winword.exe'
        {
            Key = '\software\microsoft\internet explorer\main\featurecontrol\feature_http_username_password_disable'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
            ValueName = 'winword.exe'
            ValueData = 1
        }
    }
    
    if ($IE_HTTPUsernamePasswordDisable_Outlook) {
        RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_http_username_password_disable\outlook.exe'
        {
            Key = '\software\microsoft\internet explorer\main\featurecontrol\feature_http_username_password_disable'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
            ValueName = 'outlook.exe'
            ValueData = 1
        }
    }
    
    if ( $IE_HTTPUsernamePasswordDisable_SPDesign) {
        RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_http_username_password_disable\spdesign.exe'
        {
            Key = '\software\microsoft\internet explorer\main\featurecontrol\feature_http_username_password_disable'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
            ValueName = 'spdesign.exe'
            ValueData = 0
        }
    }
    
    if ( $IE_HTTPUsernamePasswordDisable_ExprWD) {
        RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_http_username_password_disable\exprwd.exe'
        {
            Key = '\software\microsoft\internet explorer\main\featurecontrol\feature_http_username_password_disable'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
            ValueName = 'exprwd.exe'
            ValueData = 0
        }
    }
    
    if ($IE_HTTPUsernamePasswordDisable_MSAccess) {
        RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_http_username_password_disable\msaccess.exe'
        {
            Key = '\software\microsoft\internet explorer\main\featurecontrol\feature_http_username_password_disable'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
            ValueName = 'msaccess.exe'
            ValueData = 1
        }
    }

    if ($IE_HTTPUsernamePasswordDisable_OneNote) {
        RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_http_username_password_disable\onenote.exe'
        {
            Key = '\software\microsoft\internet explorer\main\featurecontrol\feature_http_username_password_disable'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
            ValueName = 'onenote.exe'
            ValueData = 1
        }
    }
    
    if ( $IE_HTTPUsernamePasswordDisable_MSE7) {
        RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_http_username_password_disable\mse7.exe'
        {
            Key = '\software\microsoft\internet explorer\main\featurecontrol\feature_http_username_password_disable'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
            ValueName = 'mse7.exe'
            ValueData = 0
        }
    }
    
    if ($IE_RestrictActiveXInstall_Grove) {
        RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_restrict_activexinstall\groove.exe'
        {
            Key = '\software\microsoft\internet explorer\main\featurecontrol\feature_restrict_activexinstall'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
            ValueName = 'groove.exe'
            ValueData = 1
        }
    }
    
    if ($IE_RestrictActiveXInstall_Excel) {
        RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_restrict_activexinstall\excel.exe'
        {
            Key = '\software\microsoft\internet explorer\main\featurecontrol\feature_restrict_activexinstall'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
            ValueName = 'excel.exe'
            ValueData = 1
        }
    }
    
    if ($IE_RestrictActiveXInstall_MSPub) {
        RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_restrict_activexinstall\mspub.exe'
        {
            Key = '\software\microsoft\internet explorer\main\featurecontrol\feature_restrict_activexinstall'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
            ValueName = 'mspub.exe'
            ValueData = 1
        }
    }
    
    if ($IE_RestrictActiveXInstall_PowerPNT) {
        RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_restrict_activexinstall\powerpnt.exe'
        {
            Key = '\software\microsoft\internet explorer\main\featurecontrol\feature_restrict_activexinstall'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
            ValueName = 'powerpnt.exe'
            ValueData = 1
        }
    }
    
    if ($IE_RestrictActiveXInstall_PPTView) {
        RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_restrict_activexinstall\pptview.exe'
        {
            Key = '\software\microsoft\internet explorer\main\featurecontrol\feature_restrict_activexinstall'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
            ValueName = 'pptview.exe'
            ValueData = 1
        }
    }
    
    if ($IE_RestrictActiveXInstall_Visio) {
        RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_restrict_activexinstall\visio.exe'
        {
            Key = '\software\microsoft\internet explorer\main\featurecontrol\feature_restrict_activexinstall'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
            ValueName = 'visio.exe'
            ValueData = 1
         }

    }

    if ($IE_RestrictActiveXInstall_WinProj) {
        RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_restrict_activexinstall\winproj.exe'
        {
            Key = '\software\microsoft\internet explorer\main\featurecontrol\feature_restrict_activexinstall'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
            ValueName = 'winproj.exe'
            ValueData = 1
        }
    }
    
    if ($IE_RestrictActiveXInstall_WinWord) {
        RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_restrict_activexinstall\winword.exe'
        {
            Key = '\software\microsoft\internet explorer\main\featurecontrol\feature_restrict_activexinstall'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
            ValueName = 'winword.exe'
            ValueData = 1
        }
    }
    
    if ($IE_RestrictActiveXInstall_Outlook) {
        RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_restrict_activexinstall\outlook.exe'
        {
            Key = '\software\microsoft\internet explorer\main\featurecontrol\feature_restrict_activexinstall'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
            ValueName = 'outlook.exe'
            ValueData = 1
        }
    }
    
    if ( $IE_RestrictActiveXInstall_SPDesign) {
        RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_restrict_activexinstall\spdesign.exe'
        {
            Key = '\software\microsoft\internet explorer\main\featurecontrol\feature_restrict_activexinstall'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
            ValueName = 'spdesign.exe'
            ValueData = 0
        }
    }
    
    if ( $IE_RestrictActiveXInstall_ExprWD) {
        RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_restrict_activexinstall\exprwd.exe'
        {
            Key = '\software\microsoft\internet explorer\main\featurecontrol\feature_restrict_activexinstall'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
            ValueName = 'exprwd.exe'
            ValueData = 0
        }
    }
    
    if ($IE_RestrictActiveXInstall_MSAccess) {
        RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_restrict_activexinstall\msaccess.exe'
        {
            Key = '\software\microsoft\internet explorer\main\featurecontrol\feature_restrict_activexinstall'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
            ValueName = 'msaccess.exe'
            ValueData = 1
        }
    }

    if ($IE_RestrictActiveXInstall_OneNote) {
        RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_restrict_activexinstall\onenote.exe'
        {
            Key = '\software\microsoft\internet explorer\main\featurecontrol\feature_restrict_activexinstall'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
            ValueName = 'onenote.exe'
            ValueData = 1
        }
    }
    
    if ( $IE_RestrictActiveXInstall_MSE7) {
        RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_restrict_activexinstall\mse7.exe'
        {
            Key = '\software\microsoft\internet explorer\main\featurecontrol\feature_restrict_activexinstall'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
            ValueName = 'mse7.exe'
            ValueData = 0
        }
    }
    
    if ($IE_RestrictFileDownload_Grove) {
        RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_restrict_filedownload\groove.exe'
        {
            Key = '\software\microsoft\internet explorer\main\featurecontrol\feature_restrict_filedownload'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
            ValueName = 'groove.exe'
            ValueData = 1
        }
    }
    
    if ($IE_RestrictFileDownload_Excel) {
        RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_restrict_filedownload\excel.exe'
        {
            Key = '\software\microsoft\internet explorer\main\featurecontrol\feature_restrict_filedownload'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
            ValueName = 'excel.exe'
            ValueData = 1
        }
    }
    
    if ($IE_RestrictFileDownload_MSPub) {
        RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_restrict_filedownload\mspub.exe'
        {
            Key = '\software\microsoft\internet explorer\main\featurecontrol\feature_restrict_filedownload'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
            ValueName = 'mspub.exe'
            ValueData = 1
        }
    }
    
    if ($IE_RestrictFileDownload_PowerPNT) {
        RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_restrict_filedownload\powerpnt.exe'
        {
            Key = '\software\microsoft\internet explorer\main\featurecontrol\feature_restrict_filedownload'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
            ValueName = 'powerpnt.exe'
            ValueData = 1
        }
    }

    if ($IE_RestrictFileDownload_PPTView) {
        RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_restrict_filedownload\pptview.exe'
        {
            Key = '\software\microsoft\internet explorer\main\featurecontrol\feature_restrict_filedownload'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
            ValueName = 'pptview.exe'
            ValueData = 1
        }
    }
    
    if ($IE_RestrictFileDownload_Visio) {
        RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_restrict_filedownload\visio.exe'
        {
            Key = '\software\microsoft\internet explorer\main\featurecontrol\feature_restrict_filedownload'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
            ValueName = 'visio.exe'
            ValueData = 1
        }
    }
    
    if ($IE_RestrictFileDownload_WinProj) {
        RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_restrict_filedownload\winproj.exe'
        {
            Key = '\software\microsoft\internet explorer\main\featurecontrol\feature_restrict_filedownload'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
            ValueName = 'winproj.exe'
            ValueData = 1
        }
    }
    
    if ($IE_RestrictFileDownload_WinWord) {
        RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_restrict_filedownload\winword.exe'
        {
            Key = '\software\microsoft\internet explorer\main\featurecontrol\feature_restrict_filedownload'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
            ValueName = 'winword.exe'
            ValueData = 1
        }
    }
    
    if ($IE_RestrictFileDownload_Outlook) {
        RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_restrict_filedownload\outlook.exe'
        {
            Key = '\software\microsoft\internet explorer\main\featurecontrol\feature_restrict_filedownload'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
            ValueName = 'outlook.exe'
            ValueData = 1
        }
    }
    
    if ( $IE_RestrictFileDownload_SPDesign) {
        RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_restrict_filedownload\spdesign.exe'
        {
            Key = '\software\microsoft\internet explorer\main\featurecontrol\feature_restrict_filedownload'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
            ValueName = 'spdesign.exe'
            ValueData = 0
        }
    }

    if ( $IE_RestrictFileDownload_ExprWD) {
        RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_restrict_filedownload\exprwd.exe'
        {
            Key = '\software\microsoft\internet explorer\main\featurecontrol\feature_restrict_filedownload'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
            ValueName = 'exprwd.exe'
            ValueData = 0
        }
    }
    
    if ($IE_RestrictFileDownload_MSAccess) {
        RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_restrict_filedownload\msaccess.exe'
        {
            Key = '\software\microsoft\internet explorer\main\featurecontrol\feature_restrict_filedownload'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
            ValueName = 'msaccess.exe'
            ValueData = 1
        }
    }
    
    if ($IE_RestrictFileDownload_OneNote) {
        RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_restrict_filedownload\onenote.exe'
        {
            Key = '\software\microsoft\internet explorer\main\featurecontrol\feature_restrict_filedownload'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
            ValueName = 'onenote.exe'
            ValueData = 1
        }
    }
    
    if ( $IE_RestrictFileDownload_MSE7) {
        RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_restrict_filedownload\mse7.exe'
        {
            Key = '\software\microsoft\internet explorer\main\featurecontrol\feature_restrict_filedownload'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
            ValueName = 'mse7.exe'
            ValueData = 0
        }
    }
    
    if ($IE_SafeBindToObject_Grove) {
        RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_safe_bindtoobject\groove.exe'
        {
            Key = '\software\microsoft\internet explorer\main\featurecontrol\feature_safe_bindtoobject'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
            ValueName = 'groove.exe'
            ValueData = 1
        }
    }
    
    if ($IE_SafeBindToObject_Excel) {
        RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_safe_bindtoobject\excel.exe'
        {
            Key = '\software\microsoft\internet explorer\main\featurecontrol\feature_safe_bindtoobject'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
            ValueName = 'excel.exe'
            ValueData = 1
        }
    }

    if ($IE_SafeBindToObject_MSPub) {
        RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_safe_bindtoobject\mspub.exe'
        {
            Key = '\software\microsoft\internet explorer\main\featurecontrol\feature_safe_bindtoobject'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
            ValueName = 'mspub.exe'
            ValueData = 1
        }
    }
    
    if ($IE_SafeBindToObject_PowerPNT) {
        RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_safe_bindtoobject\powerpnt.exe'
        {
            Key = '\software\microsoft\internet explorer\main\featurecontrol\feature_safe_bindtoobject'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
            ValueName = 'powerpnt.exe'
            ValueData = 1
        }
    }
    
    if ($IE_SafeBindToObject_PPTView) {
        RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_safe_bindtoobject\pptview.exe'
        {
            Key = '\software\microsoft\internet explorer\main\featurecontrol\feature_safe_bindtoobject'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
            ValueName = 'pptview.exe'
            ValueData = 1
        }
    }
    
    if ($IE_SafeBindToObject_Visio) {
        RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_safe_bindtoobject\visio.exe'
        {
            Key = '\software\microsoft\internet explorer\main\featurecontrol\feature_safe_bindtoobject'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
            ValueName = 'visio.exe'
            ValueData = 1
        }
    }
    
    if ($IE_SafeBindToObject_WinProj) {
        RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_safe_bindtoobject\winproj.exe'
        {
            Key = '\software\microsoft\internet explorer\main\featurecontrol\feature_safe_bindtoobject'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
            ValueName = 'winproj.exe'
            ValueData = 1
        }
    }
    
    if ($IE_SafeBindToObject_WinWord) {
        RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_safe_bindtoobject\winword.exe'
        {
            Key = '\software\microsoft\internet explorer\main\featurecontrol\feature_safe_bindtoobject'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
            ValueName = 'winword.exe'
            ValueData = 1
        }
    }

    if ($IE_SafeBindToObject_Outlook) {
        RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_safe_bindtoobject\outlook.exe'
        {
            Key = '\software\microsoft\internet explorer\main\featurecontrol\feature_safe_bindtoobject'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
            ValueName = 'outlook.exe'
            ValueData = 1
        }
    }
    
    if ( $IE_SafeBindToObject_SPDesign) {
        RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_safe_bindtoobject\spdesign.exe'
        {
            Key = '\software\microsoft\internet explorer\main\featurecontrol\feature_safe_bindtoobject'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
            ValueName = 'spdesign.exe'
            ValueData = 0
        }
    }
    
    if ( $IE_SafeBindToObject_ExprWD) {
        RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_safe_bindtoobject\exprwd.exe'
        {
            Key = '\software\microsoft\internet explorer\main\featurecontrol\feature_safe_bindtoobject'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
            ValueName = 'exprwd.exe'
            ValueData = 0
        }
    }
    
    if ($IE_SafeBindToObject_MSAccess) {
        RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_safe_bindtoobject\msaccess.exe'
        {
            Key = '\software\microsoft\internet explorer\main\featurecontrol\feature_safe_bindtoobject'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
            ValueName = 'msaccess.exe'
            ValueData = 1
        }
    }
    
    if ($IE_SafeBindToObject_OneNote) {
        RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_safe_bindtoobject\onenote.exe'
        {
            Key = '\software\microsoft\internet explorer\main\featurecontrol\feature_safe_bindtoobject'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
            ValueName = 'onenote.exe'
            ValueData = 1
        }
    }
    
    if ( $IE_SafeBindToObject_MSE7) {
        RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_safe_bindtoobject\mse7.exe'
        {
            Key = '\software\microsoft\internet explorer\main\featurecontrol\feature_safe_bindtoobject'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
            ValueName = 'mse7.exe'
            ValueData = 0
        }
    }
    
    if ($IE_UNCSavedFileCheck_Grove) {
        RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_unc_savedfilecheck\groove.exe'
        {
            Key = '\software\microsoft\internet explorer\main\featurecontrol\feature_unc_savedfilecheck'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
            ValueName = 'groove.exe'
            ValueData = 1
        }
    }

    if ($IE_UNCSavedFileCheck_Excel) {
        RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_unc_savedfilecheck\excel.exe'
        {
            Key = '\software\microsoft\internet explorer\main\featurecontrol\feature_unc_savedfilecheck'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
            ValueName = 'excel.exe'
            ValueData = 1
        }
    }
    
    if ($IE_UNCSavedFileCheck_MSPub) {
        RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_unc_savedfilecheck\mspub.exe'
        {
            Key = '\software\microsoft\internet explorer\main\featurecontrol\feature_unc_savedfilecheck'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
            ValueName = 'mspub.exe'
            ValueData = 1
        }
    }
    
    if ($IE_UNCSavedFileCheck_PowerPNT) {
        RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_unc_savedfilecheck\powerpnt.exe'
        {
            Key = '\software\microsoft\internet explorer\main\featurecontrol\feature_unc_savedfilecheck'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
            ValueName = 'powerpnt.exe'
            ValueData = 1
        }
    }
    
    if ($IE_UNCSavedFileCheck_PPTView) {
        RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_unc_savedfilecheck\pptview.exe'
        {
            Key = '\software\microsoft\internet explorer\main\featurecontrol\feature_unc_savedfilecheck'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
            ValueName = 'pptview.exe'
            ValueData = 1
        }
    }
    
    if ($IE_UNCSavedFileCheck_Visio) {
        RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_unc_savedfilecheck\visio.exe'
        {
            Key = '\software\microsoft\internet explorer\main\featurecontrol\feature_unc_savedfilecheck'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
            ValueName = 'visio.exe'
            ValueData = 1
        }
    }
    
    if ($IE_UNCSavedFileCheck_WinProj) {
        RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_unc_savedfilecheck\winproj.exe'
        {
            Key = '\software\microsoft\internet explorer\main\featurecontrol\feature_unc_savedfilecheck'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
            ValueName = 'winproj.exe'
            ValueData = 1
        }
    }
    
    if ($IE_UNCSavedFileCheck_WinWord) {
        RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_unc_savedfilecheck\winword.exe'
        {
            Key = '\software\microsoft\internet explorer\main\featurecontrol\feature_unc_savedfilecheck'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
            ValueName = 'winword.exe'
            ValueData = 1
        }
    }

    if ($IE_UNCSavedFileCheck_Outlook) {
        RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_unc_savedfilecheck\outlook.exe'
        {
            Key = '\software\microsoft\internet explorer\main\featurecontrol\feature_unc_savedfilecheck'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
            ValueName = 'outlook.exe'
            ValueData = 1
        }
    }
    
    if ( $IE_UNCSavedFileCheck_SPDesign) {
        RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_unc_savedfilecheck\spdesign.exe'
        {
            Key = '\software\microsoft\internet explorer\main\featurecontrol\feature_unc_savedfilecheck'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
            ValueName = 'spdesign.exe'
            ValueData = 0
        }
    }
    
    if ( $IE_UNCSavedFileCheck_ExprWD) {
        RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_unc_savedfilecheck\exprwd.exe'
        {
            Key = '\software\microsoft\internet explorer\main\featurecontrol\feature_unc_savedfilecheck'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
            ValueName = 'exprwd.exe'
            ValueData = 0
        }
    }
    
    if ($IE_UNCSavedFileCheck_MSAccess) {
        RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_unc_savedfilecheck\msaccess.exe'
        {
            Key = '\software\microsoft\internet explorer\main\featurecontrol\feature_unc_savedfilecheck'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
            ValueName = 'msaccess.exe'
            ValueData = 1
        }
    }
    
    if ($IE_UNCSavedFileCheck_OneNote) {
        RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_unc_savedfilecheck\onenote.exe'
        {
            Key = '\software\microsoft\internet explorer\main\featurecontrol\feature_unc_savedfilecheck'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
            ValueName = 'onenote.exe'
            ValueData = 1
        }
    }
    
    if ( $IE_UNCSavedFileCheck_MSE7) {
        RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_unc_savedfilecheck\mse7.exe'
        {
            Key = '\software\microsoft\internet explorer\main\featurecontrol\feature_unc_savedfilecheck'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
            ValueName = 'mse7.exe'
            ValueData = 0
        }
    }

    if ($IE_ValidateNavigateURL_Grove) {
        RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_validate_navigate_url\groove.exe'
        {
            Key = '\software\microsoft\internet explorer\main\featurecontrol\feature_validate_navigate_url'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
            ValueName = 'groove.exe'
            ValueData = 1
        }
    }
    
    if ($IE_ValidateNavigateURL_Excel) {
        RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_validate_navigate_url\excel.exe'
        {
            Key = '\software\microsoft\internet explorer\main\featurecontrol\feature_validate_navigate_url'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
            ValueName = 'excel.exe'
            ValueData = 1
        }
    }
    
    if ($IE_ValidateNavigateURL_MSPub) {
        RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_validate_navigate_url\mspub.exe'
        {
            Key = '\software\microsoft\internet explorer\main\featurecontrol\feature_validate_navigate_url'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
            ValueName = 'mspub.exe'
            ValueData = 1
        }
    }
    
    if ($IE_ValidateNavigateURL_PowerPNT) {
        RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_validate_navigate_url\powerpnt.exe'
        {
            Key = '\software\microsoft\internet explorer\main\featurecontrol\feature_validate_navigate_url'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
            ValueName = 'powerpnt.exe'
            ValueData = 1
        }
    }
    
    if ($IE_ValidateNavigateURL_PPTView) {
        RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_validate_navigate_url\pptview.exe'
        {
            Key = '\software\microsoft\internet explorer\main\featurecontrol\feature_validate_navigate_url'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
            ValueName = 'pptview.exe'
            ValueData = 1
        }
    }
    
    if ($IE_ValidateNavigateURL_Visio) {
        RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_validate_navigate_url\visio.exe'
        {
            Key = '\software\microsoft\internet explorer\main\featurecontrol\feature_validate_navigate_url'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
            ValueName = 'visio.exe'
            ValueData = 1
        }
    }
    
    if ($IE_ValidateNavigateURL_WinProj) {
        RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_validate_navigate_url\winproj.exe'
        {
            Key = '\software\microsoft\internet explorer\main\featurecontrol\feature_validate_navigate_url'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
            ValueName = 'winproj.exe'
            ValueData = 1
        }
    }

    if ($IE_ValidateNavigateURL_WinWord) {
        RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_validate_navigate_url\winword.exe'
        {
            Key = '\software\microsoft\internet explorer\main\featurecontrol\feature_validate_navigate_url'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
            ValueName = 'winword.exe'
            ValueData = 1
        }
    }
    
    if ($IE_ValidateNavigateURL_Outlook) {
        RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_validate_navigate_url\outlook.exe'
        {
            Key = '\software\microsoft\internet explorer\main\featurecontrol\feature_validate_navigate_url'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
            ValueName = 'outlook.exe'
            ValueData = 1
        }
    }
    
    if ( $IE_ValidateNavigateURL_SPDesign) {
        RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_validate_navigate_url\spdesign.exe'
        {
            Key = '\software\microsoft\internet explorer\main\featurecontrol\feature_validate_navigate_url'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
            ValueName = 'spdesign.exe'
            ValueData = 0
        }
    }
    
    if ( $IE_ValidateNavigateURL_ExprWD) {
        RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_validate_navigate_url\exprwd.exe'
        {
            Key = '\software\microsoft\internet explorer\main\featurecontrol\feature_validate_navigate_url'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
            ValueName = 'exprwd.exe'
            ValueData = 0
        }
    }
    
    if ($IE_ValidateNavigateURL_MSAccess) {
        RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_validate_navigate_url\msaccess.exe'
        {
            Key = '\software\microsoft\internet explorer\main\featurecontrol\feature_validate_navigate_url'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
            ValueName = 'msaccess.exe'
            ValueData = 1
        }
    }
    
    if ($IE_ValidateNavigateURL_OneNote) {
        RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_validate_navigate_url\onenote.exe'
        {
            Key = '\software\microsoft\internet explorer\main\featurecontrol\feature_validate_navigate_url'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
            ValueName = 'onenote.exe'
            ValueData = 1
        }
    }
    
    if ( $IE_ValidateNavigateURL_MSE7) {
        RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_validate_navigate_url\mse7.exe'
        {
            Key = '\software\microsoft\internet explorer\main\featurecontrol\feature_validate_navigate_url'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
            ValueName = 'mse7.exe'
            ValueData = 0
        }
    }

    if ($IE_WebocPopupManagement_Grove) {
        RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_weboc_popupmanagement\groove.exe'
        {
            Key = '\software\microsoft\internet explorer\main\featurecontrol\feature_weboc_popupmanagement'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
            ValueName = 'groove.exe'
            ValueData = 1
        }
    }
    
    if ($IE_WebocPopupManagement_Excel) {
        RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_weboc_popupmanagement\excel.exe'
        {
            Key = '\software\microsoft\internet explorer\main\featurecontrol\feature_weboc_popupmanagement'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
            ValueName = 'excel.exe'
            ValueData = 1
        }
    }
    
    if ($IE_WebocPopupManagement_MSPub) {
        RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_weboc_popupmanagement\mspub.exe'
        {
            Key = '\software\microsoft\internet explorer\main\featurecontrol\feature_weboc_popupmanagement'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
            ValueName = 'mspub.exe'
            ValueData = 1
        }
    }
    
    if ($IE_WebocPopupManagement_PowerPNT) {
        RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_weboc_popupmanagement\powerpnt.exe'
        {
            Key = '\software\microsoft\internet explorer\main\featurecontrol\feature_weboc_popupmanagement'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
            ValueName = 'powerpnt.exe'
            ValueData = 1
        }
    }
    
    if ($IE_WebocPopupManagement_PPTView) {
        RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_weboc_popupmanagement\pptview.exe'
        {
            Key = '\software\microsoft\internet explorer\main\featurecontrol\feature_weboc_popupmanagement'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
            ValueName = 'pptview.exe'
            ValueData = 1
        }
    }
    
    if ($IE_WebocPopupManagement_Visio) {
        RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_weboc_popupmanagement\visio.exe'
        {
            Key = '\software\microsoft\internet explorer\main\featurecontrol\feature_weboc_popupmanagement'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
            ValueName = 'visio.exe'
            ValueData = 1
        }
    }
    
    if ($IE_WebocPopupManagement_WinProj) {
        RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_weboc_popupmanagement\winproj.exe'
        {
            Key = '\software\microsoft\internet explorer\main\featurecontrol\feature_weboc_popupmanagement'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
            ValueName = 'winproj.exe'
            ValueData = 1
        }
    }

    if ($IE_WebocPopupManagement_WinWord) {
        RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_weboc_popupmanagement\winword.exe'
        {
            Key = '\software\microsoft\internet explorer\main\featurecontrol\feature_weboc_popupmanagement'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
            ValueName = 'winword.exe'
            ValueData = 1
        }
    }
    
    if ($IE_WebocPopupManagement_Outlook) {
        RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_weboc_popupmanagement\outlook.exe'
        {
            Key = '\software\microsoft\internet explorer\main\featurecontrol\feature_weboc_popupmanagement'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
            ValueName = 'outlook.exe'
            ValueData = 1
        }
    }
    
    if ( $IE_WebocPopupManagement_SPDesign) {
        RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_weboc_popupmanagement\spdesign.exe'
        {
            Key = '\software\microsoft\internet explorer\main\featurecontrol\feature_weboc_popupmanagement'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
            ValueName = 'spdesign.exe'
            ValueData = 0
        }
    }
    
    if ( $IE_WebocPopupManagement_ExprWD) {
        RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_weboc_popupmanagement\exprwd.exe'
        {
            Key = '\software\microsoft\internet explorer\main\featurecontrol\feature_weboc_popupmanagement'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
            ValueName = 'exprwd.exe'
            ValueData = 0
        }
    }
    
    if ($IE_WebocPopupManagement_MSAccess) {
        RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_weboc_popupmanagement\msaccess.exe'
        {
            Key = '\software\microsoft\internet explorer\main\featurecontrol\feature_weboc_popupmanagement'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
            ValueName = 'msaccess.exe'
            ValueData = 1
        }
    }
    
    if ($IE_WebocPopupManagement_OneNote) {
        RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_weboc_popupmanagement\onenote.exe'
        {
            Key = '\software\microsoft\internet explorer\main\featurecontrol\feature_weboc_popupmanagement'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
            ValueName = 'onenote.exe'
            ValueData = 1
        }
    }
    
    if ( $IE_WebocPopupManagement_MSE7) {
        RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_weboc_popupmanagement\mse7.exe'
        {
            Key = '\software\microsoft\internet explorer\main\featurecontrol\feature_weboc_popupmanagement'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
            ValueName = 'mse7.exe'
            ValueData = 0
        }
    }

    if ($IE_WindowRestrictions_Grove) {
        RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_window_restrictions\groove.exe'
        {
            Key = '\software\microsoft\internet explorer\main\featurecontrol\feature_window_restrictions'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
            ValueName = 'groove.exe'
            ValueData = 1
        }
    }
    
    if ($IE_WindowRestrictions_Excel) {
        RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_window_restrictions\excel.exe'
        {
            Key = '\software\microsoft\internet explorer\main\featurecontrol\feature_window_restrictions'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
            ValueName = 'excel.exe'
            ValueData = 1
        }
    }
    
    if ($IE_WindowRestrictions_MSPub) {
        RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_window_restrictions\mspub.exe'
        {
            Key = '\software\microsoft\internet explorer\main\featurecontrol\feature_window_restrictions'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
            ValueName = 'mspub.exe'
            ValueData = 1
        }
    }
    
    if ($IE_WindowRestrictions_PowerPNT) {
        RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_window_restrictions\powerpnt.exe'
        {
            Key = '\software\microsoft\internet explorer\main\featurecontrol\feature_window_restrictions'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
            ValueName = 'powerpnt.exe'
            ValueData = 1
        }
    }
    
    if ($IE_WindowRestrictions_PPTView) {
        RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_window_restrictions\pptview.exe'
        {
            Key = '\software\microsoft\internet explorer\main\featurecontrol\feature_window_restrictions'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
            ValueName = 'pptview.exe'
            ValueData = 1
        }
    }
    
    if ($IE_WindowRestrictions_Visio) {
        RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_window_restrictions\visio.exe'
        {
            Key = '\software\microsoft\internet explorer\main\featurecontrol\feature_window_restrictions'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
            ValueName = 'visio.exe'
            ValueData = 1
        }
    }

    if ($IE_WindowRestrictions_WinProj) {
        RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_window_restrictions\winproj.exe'
        {
            Key = '\software\microsoft\internet explorer\main\featurecontrol\feature_window_restrictions'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
            ValueName = 'winproj.exe'
            ValueData = 1
        }
    }
    
    if ($IE_WindowRestrictions_WinWord) {
        RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_window_restrictions\winword.exe'
        {
            Key = '\software\microsoft\internet explorer\main\featurecontrol\feature_window_restrictions'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
            ValueName = 'winword.exe'
            ValueData = 1
        }
    }
    
    if ($IE_WindowRestrictions_Outlook) {
        RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_window_restrictions\outlook.exe'
        {
            Key = '\software\microsoft\internet explorer\main\featurecontrol\feature_window_restrictions'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
            ValueName = 'outlook.exe'
            ValueData = 1
        }
    }
    
    if ( $IE_WindowRestrictions_SPDesign) {
        RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_window_restrictions\spdesign.exe'
        {
            Key = '\software\microsoft\internet explorer\main\featurecontrol\feature_window_restrictions'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
            ValueName = 'spdesign.exe'
            ValueData = 0
        }
    }
    
    if ( $IE_WindowRestrictions_ExprWD) {
        RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_window_restrictions\exprwd.exe'
        {
            Key = '\software\microsoft\internet explorer\main\featurecontrol\feature_window_restrictions'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
            ValueName = 'exprwd.exe'
            ValueData = 0
        }
    }
    
    if ($IE_WindowRestrictions_MSAccess) {
        RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_window_restrictions\msaccess.exe'
        {
            Key = '\software\microsoft\internet explorer\main\featurecontrol\feature_window_restrictions'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
            ValueName = 'msaccess.exe'
            ValueData = 1
        }
    }
    
    if ($IE_WindowRestrictions_OneNote) {
        RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_window_restrictions\onenote.exe'
        {
            Key = '\software\microsoft\internet explorer\main\featurecontrol\feature_window_restrictions'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
            ValueName = 'onenote.exe'
            ValueData = 1
        }
    }

    if ( $IE_WindowRestrictions_MSE7) {
        RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_window_restrictions\mse7.exe'
        {
            Key = '\software\microsoft\internet explorer\main\featurecontrol\feature_window_restrictions'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
            ValueName = 'mse7.exe'
            ValueData = 0
        }
    }
    
    if ($IE_ZoneElevation_Grove) {
        RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_zone_elevation\groove.exe'
        {
            Key = '\software\microsoft\internet explorer\main\featurecontrol\feature_zone_elevation'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
            ValueName = 'groove.exe'
            ValueData = 1
        }
    }
    
    if ($IE_ZoneElevation_Excel) {
        RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_zone_elevation\excel.exe'
        {
            Key = '\software\microsoft\internet explorer\main\featurecontrol\feature_zone_elevation'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
            ValueName = 'excel.exe'
            ValueData = 1
        }
    }
    
    if ($IE_ZoneElevation_MSPub) {
        RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_zone_elevation\mspub.exe'
        {
            Key = '\software\microsoft\internet explorer\main\featurecontrol\feature_zone_elevation'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
            ValueName = 'mspub.exe'
            ValueData = 1
        }
    }
    
    if ($IE_ZoneElevation_PowerPNT) {
        RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_zone_elevation\powerpnt.exe'
        {
            Key = '\software\microsoft\internet explorer\main\featurecontrol\feature_zone_elevation'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
            ValueName = 'powerpnt.exe'
            ValueData = 1
        }
    }
    
    if ($IE_ZoneElevation_PPTView) {
        RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_zone_elevation\pptview.exe'
        {
            Key = '\software\microsoft\internet explorer\main\featurecontrol\feature_zone_elevation'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
            ValueName = 'pptview.exe'
            ValueData = 1
        }
    }
    
    if ($IE_ZoneElevation_Visio) {
        RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_zone_elevation\visio.exe'
        {
            Key = '\software\microsoft\internet explorer\main\featurecontrol\feature_zone_elevation'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
            ValueName = 'visio.exe'
            ValueData = 1
        }
    }

    if ($IE_ZoneElevation_WinProj) {
        RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_zone_elevation\winproj.exe'
        {
            Key = '\software\microsoft\internet explorer\main\featurecontrol\feature_zone_elevation'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
            ValueName = 'winproj.exe'
            ValueData = 1
        }
    }
    
    if ($IE_ZoneElevation_WinWord) {
        RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_zone_elevation\winword.exe'
        {
            Key = '\software\microsoft\internet explorer\main\featurecontrol\feature_zone_elevation'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
            ValueName = 'winword.exe'
            ValueData = 1
        }
    }
    
    if ($IE_ZoneElevation_Outlook) {
        RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_zone_elevation\outlook.exe'
        {
            Key = '\software\microsoft\internet explorer\main\featurecontrol\feature_zone_elevation'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
            ValueName = 'outlook.exe'
            ValueData = 1
        }
    }
    
    if ( $IE_ZoneElevation_SPDesign) {
        RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_zone_elevation\spdesign.exe'
        {
            Key = '\software\microsoft\internet explorer\main\featurecontrol\feature_zone_elevation'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
            ValueName = 'spdesign.exe'
            ValueData = 0
        }
    }
    
    if ( $IE_ZoneElevation_ExprWD) {
        RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_zone_elevation\exprwd.exe'
        {
            Key = '\software\microsoft\internet explorer\main\featurecontrol\feature_zone_elevation'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
            ValueName = 'exprwd.exe'
            ValueData = 0
        }
    }
    
    if ($IE_ZoneElevation_MSAccess) {
        RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_zone_elevation\msaccess.exe'
        {
            Key = '\software\microsoft\internet explorer\main\featurecontrol\feature_zone_elevation'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
            ValueName = 'msaccess.exe'
            ValueData = 1
        }
    }

    if ($IE_ZoneElevation_OneNote) {
        RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_zone_elevation\onenote.exe'
        {
            Key = '\software\microsoft\internet explorer\main\featurecontrol\feature_zone_elevation'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
            ValueName = 'onenote.exe'
            ValueData = 1
        }
    }
    
    if ( $IE_ZoneElevation_MSE7) {
        RegistryPolicyFile 'Registry(POL): HKLM:\software\microsoft\internet explorer\main\featurecontrol\feature_zone_elevation\mse7.exe'
        {
            Key = '\software\microsoft\internet explorer\main\featurecontrol\feature_zone_elevation'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
            ValueName = 'mse7.exe'
            ValueData = 0
        }
    }
    
    if ($IE_SafeBindToObject_Grove) {
        RegistryPolicyFile 'Registry(POL): HKLM:\software\wow6432node\policies\microsoft\internet explorer\main\featurecontrol\feature_safe_bindtoobject\groove.exe'
        {
            Key = '\software\wow6432node\policies\microsoft\internet explorer\main\featurecontrol\feature_safe_bindtoobject'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
            ValueName = 'groove.exe'
            ValueData = 1
        }
    }
    
    if ($IE_SafeBindToObject_Excel) {
        RegistryPolicyFile 'Registry(POL): HKLM:\software\wow6432node\policies\microsoft\internet explorer\main\featurecontrol\feature_safe_bindtoobject\excel.exe'
        {
            Key = '\software\wow6432node\policies\microsoft\internet explorer\main\featurecontrol\feature_safe_bindtoobject'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
            ValueName = 'excel.exe'
            ValueData = 1
        }
    }
    
    if ($IE_SafeBindToObject_MSPub) {
        RegistryPolicyFile 'Registry(POL): HKLM:\software\wow6432node\policies\microsoft\internet explorer\main\featurecontrol\feature_safe_bindtoobject\mspub.exe'
        {
            Key = '\software\wow6432node\policies\microsoft\internet explorer\main\featurecontrol\feature_safe_bindtoobject'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
            ValueName = 'mspub.exe'
            ValueData = 1
        }
    }
    
    if ($IE_SafeBindToObject_PowerPNT) {
        RegistryPolicyFile 'Registry(POL): HKLM:\software\wow6432node\policies\microsoft\internet explorer\main\featurecontrol\feature_safe_bindtoobject\powerpnt.exe'
        {
            Key = '\software\wow6432node\policies\microsoft\internet explorer\main\featurecontrol\feature_safe_bindtoobject'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
            ValueName = 'powerpnt.exe'
            ValueData = 1
        }
    }

    if ($IE_SafeBindToObject_PPTView) {
        RegistryPolicyFile 'Registry(POL): HKLM:\software\wow6432node\policies\microsoft\internet explorer\main\featurecontrol\feature_safe_bindtoobject\pptview.exe'
        {
            Key = '\software\wow6432node\policies\microsoft\internet explorer\main\featurecontrol\feature_safe_bindtoobject'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
            ValueName = 'pptview.exe'
            ValueData = 1
        }
    }
    
    if ($IE_SafeBindToObject_Visio) {
        RegistryPolicyFile 'Registry(POL): HKLM:\software\wow6432node\policies\microsoft\internet explorer\main\featurecontrol\feature_safe_bindtoobject\visio.exe'
        {
            Key = '\software\wow6432node\policies\microsoft\internet explorer\main\featurecontrol\feature_safe_bindtoobject'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
            ValueName = 'visio.exe'
            ValueData = 1
        }
    }
    
    if ($IE_SafeBindToObject_WinProj) {
        RegistryPolicyFile 'Registry(POL): HKLM:\software\wow6432node\policies\microsoft\internet explorer\main\featurecontrol\feature_safe_bindtoobject\winproj.exe'
        {
            Key = '\software\wow6432node\policies\microsoft\internet explorer\main\featurecontrol\feature_safe_bindtoobject'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
            ValueName = 'winproj.exe'
            ValueData = 1
        }
    }
    
    if ($IE_SafeBindToObject_WinWord) {
        RegistryPolicyFile 'Registry(POL): HKLM:\software\wow6432node\policies\microsoft\internet explorer\main\featurecontrol\feature_safe_bindtoobject\winword.exe'
        {
            Key = '\software\wow6432node\policies\microsoft\internet explorer\main\featurecontrol\feature_safe_bindtoobject'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
            ValueName = 'winword.exe'
            ValueData = 1
        }
    }
    
    if ($IE_SafeBindToObject_Outlook) {
        RegistryPolicyFile 'Registry(POL): HKLM:\software\wow6432node\policies\microsoft\internet explorer\main\featurecontrol\feature_safe_bindtoobject\outlook.exe'
        {
            Key = '\software\wow6432node\policies\microsoft\internet explorer\main\featurecontrol\feature_safe_bindtoobject'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
            ValueName = 'outlook.exe'
            ValueData = 1
        }
    }
    
    if ( $IE_SafeBindToObject_SPDesign) {
        RegistryPolicyFile 'Registry(POL): HKLM:\software\wow6432node\policies\microsoft\internet explorer\main\featurecontrol\feature_safe_bindtoobject\spdesign.exe'
        {
            Key = '\software\wow6432node\policies\microsoft\internet explorer\main\featurecontrol\feature_safe_bindtoobject'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
            ValueName = 'spdesign.exe'
            ValueData = 0
        }
    }
    if ( $IE_SafeBindToObject_ExprWD) {
        RegistryPolicyFile 'Registry(POL): HKLM:\software\wow6432node\policies\microsoft\internet explorer\main\featurecontrol\feature_safe_bindtoobject\exprwd.exe'
        {
            Key = '\software\wow6432node\policies\microsoft\internet explorer\main\featurecontrol\feature_safe_bindtoobject'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
            ValueName = 'exprwd.exe'
            ValueData = 0
        }
    }
    
    if ($IE_SafeBindToObject_MSAccess) {
        RegistryPolicyFile 'Registry(POL): HKLM:\software\wow6432node\policies\microsoft\internet explorer\main\featurecontrol\feature_safe_bindtoobject\msaccess.exe'
        {
            Key = '\software\wow6432node\policies\microsoft\internet explorer\main\featurecontrol\feature_safe_bindtoobject'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
            ValueName = 'msaccess.exe'
            ValueData = 1
        }
    }
    
    if ($IE_SafeBindToObject_OneNote) {
        RegistryPolicyFile 'Registry(POL): HKLM:\software\wow6432node\policies\microsoft\internet explorer\main\featurecontrol\feature_safe_bindtoobject\onenote.exe'
        {
            Key = '\software\wow6432node\policies\microsoft\internet explorer\main\featurecontrol\feature_safe_bindtoobject'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
            ValueName = 'onenote.exe'
            ValueData = 1
        }
    }
    
    if ( $IE_SafeBindToObject_MSE7) {
        RegistryPolicyFile 'Registry(POL): HKLM:\software\wow6432node\policies\microsoft\internet explorer\main\featurecontrol\feature_safe_bindtoobject\mse7.exe'
        {
            Key = '\software\wow6432node\policies\microsoft\internet explorer\main\featurecontrol\feature_safe_bindtoobject'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
            ValueName = 'mse7.exe'
            ValueData = 0
        }
    }
    
    RegistryPolicyFile 'DEL_CU:\software\policies\microsoft\office\16.0\powerpoint\security\powerpointbypassencryptedmacroscan'
    {
        Key = 'HKCU:\software\policies\microsoft\office\16.0\powerpoint\security'
        ValueType = 'String'
        Ensure = 'Absent'
        TargetType = 'ComputerConfiguration'
        ValueName = 'powerpointbypassencryptedmacroscan'
        ValueData = ''
    }
    if ( $PowerPoint_RunPrograms) {
        RegistryPolicyFile 'DEL_CU:\software\policies\microsoft\office\16.0\powerpoint\security\runprograms'
        {
            Key = 'HKCU:\software\policies\microsoft\office\16.0\powerpoint\security'
            ValueType = 'String'
            Ensure = 'Absent'
            TargetType = 'ComputerConfiguration'
            ValueName = 'runprograms'
            ValueData = ''
        }
    }
    
    if ( $PowerPoint_OpenInProtectedView) {
        RegistryPolicyFile 'DEL_CU:\software\policies\microsoft\office\16.0\powerpoint\security\filevalidation\openinprotectedview'
        {
            Key = 'HKCU:\software\policies\microsoft\office\16.0\powerpoint\security\filevalidation'
            ValueType = 'String'
            Ensure = 'Absent'
            TargetType = 'ComputerConfiguration'
            ValueName = 'openinprotectedview'
            ValueData = ''
        }
    }
    
    if ( $Lync_SavePassword) {
        RegistryPolicyFile 'Registry(POL): HKLM:\software\policies\microsoft\office\16.0\lync\savepassword'
        {
            Key = '\software\policies\microsoft\office\16.0\lync'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
            ValueName = 'savepassword'
            ValueData = 0
        }
    }
    
    if ($Lync_EnableSIPHighSecurityMode) {
        RegistryPolicyFile 'Registry(POL): HKLM:\software\policies\microsoft\office\16.0\lync\enablesiphighsecuritymode'
        {
            Key = '\software\policies\microsoft\office\16.0\lync'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
            ValueName = 'enablesiphighsecuritymode'
            ValueData = 1
        }
    }
    
    if ($Lync_DisableHTTPConnect) {
        RegistryPolicyFile 'Registry(POL): HKLM:\software\policies\microsoft\office\16.0\lync\disablehttpconnect'
        {
            Key = '\software\policies\microsoft\office\16.0\lync'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
            ValueName = 'disablehttpconnect'
            ValueData = 1
        }
    }
    
    if ( $Word_BypassEncryptedMacroScan) {
        RegistryPolicyFile 'DEL_CU:\software\policies\microsoft\office\16.0\word\security\wordbypassencryptedmacroscan'
        {
            Key = 'HKCU:\software\policies\microsoft\office\16.0\word\security'
            ValueType = 'String'
            Ensure = 'Absent'
            TargetType = 'ComputerConfiguration'
            ValueName = 'wordbypassencryptedmacroscan'
            ValueData = ''
        }
    }
    
    if ( $Word_OpenInProtectedView) {
        RegistryPolicyFile 'DEL_CU:\software\policies\microsoft\office\16.0\word\security\filevalidation\openinprotectedview'
        {
            Key = 'HKCU:\software\policies\microsoft\office\16.0\word\security\filevalidation'
            ValueType = 'String'
            Ensure = 'Absent'
            TargetType = 'ComputerConfiguration'
            ValueName = 'openinprotectedview'
            ValueData = ''
        }
    }
}

