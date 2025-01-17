configuration DoD_Microsoft_Defender_Antivirus_STIG_v2r4
{
    param(
        [bool]$PUAProtection = $true,
        [bool]$DisableAutoExclusions = $true,
        [bool]$DisableRemovableDriveScanning = $true,
        [bool]$DisableEmailScanning = $true,
        [bool]$ScheduleDay = $true,
        [bool]$ASSignatureDue = $true,
        [bool]$DisableBlockAtFirstSeen = $true,
        [bool]$SpynetReporting = $true,
        [bool]$SubmitSamplesConsent = $true,
        [bool]$ThreatsThreatSeverityDefaultAction = $true,
        [bool]$ThreatSeverityDefaultAction5 = $true,
        [bool]$ThreatSeverityDefaultAction4 = $true,
        [bool]$ThreatSeverityDefaultAction2 = $true,
        [bool]$ThreatSeverityDefaultAction1 = $true,
        [bool]$ExploitGuardASRRules = $true,
        [bool]$ExploitGuardASRRuleBE9BA2D9 = $true,
        [bool]$ASRRuleD4F940AB = $true,
        [bool]$ASRRule3B576869 = $true,
        [bool]$ASRRule75668C1F = $true,
        [bool]$ASRRuleD3E037E1 = $true,
        [bool]$ASRRule5BEB7EFE = $true,
        [bool]$ASRRule92E97FA1 = $true,
        [bool]$EnableNetworkProtection = $true
    )

    Import-DSCResource -ModuleName 'GPRegistryPolicyDsc'
	Import-DSCResource -ModuleName 'AuditPolicyDSC'
	Import-DSCResource -ModuleName 'SecurityPolicyDSC'

    if ($PUAProtection) {
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows Defender\PUAProtection'
        {
            Key = '\Software\Policies\Microsoft\Windows Defender'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
            ValueName = 'PUAProtection'
            ValueData = 1
        }
    }
    
    if ($DisableAutoExclusions) {
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows Defender\Exclusions\DisableAutoExclusions'
        {
            Key = '\Software\Policies\Microsoft\Windows Defender\Exclusions'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
            ValueName = 'DisableAutoExclusions'
            ValueData = 0
        }
    }
    
    if ($DisableRemovableDriveScanning) {
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows Defender\Scan\DisableRemovableDriveScanning'
        {
            Key = '\Software\Policies\Microsoft\Windows Defender\Scan'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
            ValueName = 'DisableRemovableDriveScanning'
            ValueData = 0
        }
    }
    
    if ($DisableEmailScanning) {
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows Defender\Scan\DisableEmailScanning'
        {
            Key = '\Software\Policies\Microsoft\Windows Defender\Scan'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
            ValueName = 'DisableEmailScanning'
            ValueData = 0
        }
    }
    
    if ($ScheduleDay) {
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows Defender\Scan\ScheduleDay'
        {
            Key = '\Software\Policies\Microsoft\Windows Defender\Scan'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
            ValueName = 'ScheduleDay'
            ValueData = 0
        }
    }
    
    if ($ASSignatureDue) {
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows Defender\Signature Updates\ASSignatureDue'
        {
            Key = '\Software\Policies\Microsoft\Windows Defender\Signature Updates'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
            ValueName = 'ASSignatureDue'
            ValueData = 7
        }
    }

    if ($AVSignatureDue) {
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows Defender\Signature Updates\AVSignatureDue'
        {
            Key = '\Software\Policies\Microsoft\Windows Defender\Signature Updates'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
            ValueName = 'AVSignatureDue'
            ValueData = 7
        }
    }
    
    if ($ScheduleDay) {
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows Defender\Signature Updates\ScheduleDay'
        {
            Key = '\Software\Policies\Microsoft\Windows Defender\Signature Updates'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
            ValueName = 'ScheduleDay'
            ValueData = 0
        }
    }
    
    if ($DisableBlockAtFirstSeen) {
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows Defender\Spynet\DisableBlockAtFirstSeen'
        {
            Key = '\Software\Policies\Microsoft\Windows Defender\Spynet'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
            ValueName = 'DisableBlockAtFirstSeen'
            ValueData = 0
        }
    }
    
    if ($SpynetReporting) {
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows Defender\Spynet\SpynetReporting'
        {
            Key = '\Software\Policies\Microsoft\Windows Defender\Spynet'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
            ValueName = 'SpynetReporting'
            ValueData = 2
        }
    }
    
    if ($SubmitSamplesConsent) {
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows Defender\Spynet\SubmitSamplesConsent'
        {
            Key = '\Software\Policies\Microsoft\Windows Defender\Spynet'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
            ValueName = 'SubmitSamplesConsent'
            ValueData = 1
        }
    }
    
    if ($ThreatsThreatSeverityDefaultAction) {
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows Defender\Threats\Threats_ThreatSeverityDefaultAction'
        {
            Key = '\Software\Policies\Microsoft\Windows Defender\Threats'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
            ValueName = 'Threats_ThreatSeverityDefaultAction'
            ValueData = 1
        }
    }

    if ($ThreatSeverityDefaultAction5) {
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows Defender\Threats\ThreatSeverityDefaultAction\5'
        {
            Key = '\Software\Policies\Microsoft\Windows Defender\Threats\ThreatSeverityDefaultAction'
            ValueType = 'String'
            TargetType = 'ComputerConfiguration'
            ValueName = '5'
            ValueData = '2'
        }
    }
    
    if ($ThreatSeverityDefaultAction4) {
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows Defender\Threats\ThreatSeverityDefaultAction\4'
        {
            Key = '\Software\Policies\Microsoft\Windows Defender\Threats\ThreatSeverityDefaultAction'
            ValueType = 'String'
            TargetType = 'ComputerConfiguration'
            ValueName = '4'
            ValueData = '2'
        }
    }
    
    if ($ThreatSeverityDefaultAction2) {
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows Defender\Threats\ThreatSeverityDefaultAction\2'
        {
            Key = '\Software\Policies\Microsoft\Windows Defender\Threats\ThreatSeverityDefaultAction'
            ValueType = 'String'
            TargetType = 'ComputerConfiguration'
            ValueName = '2'
            ValueData = '2'
        }
    }
    
    if ($ThreatSeverityDefaultAction1) {
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows Defender\Threats\ThreatSeverityDefaultAction\1'
        {
            Key = '\Software\Policies\Microsoft\Windows Defender\Threats\ThreatSeverityDefaultAction'
            ValueType = 'String'
            TargetType = 'ComputerConfiguration'
            ValueName = '1'
            ValueData = '2'
        }
    }
    
    if ($ExploitGuardASRRules) {
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\ASR\ExploitGuard_ASR_Rules'
        {
            Key = '\Software\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\ASR'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
            ValueName = 'ExploitGuard_ASR_Rules'
            ValueData = 1
        }
    }
    
    if ($ExploitGuardASRRuleBE9BA2D9) {
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\ASR\Rules\BE9BA2D9-53EA-4CDC-84E5-9B1EEEE46550'
        {
            Key = '\Software\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\ASR\Rules'
            ValueType = 'String'
            TargetType = 'ComputerConfiguration'
            ValueName = 'BE9BA2D9-53EA-4CDC-84E5-9B1EEEE46550'
            ValueData = '1'
        }
    }

    if ($ASRRuleD4F940AB) {
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\ASR\Rules\D4F940AB-401B-4EFC-AADC-AD5F3C50688A'
        {
            Key = '\Software\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\ASR\Rules'
            ValueType = 'String'
            TargetType = 'ComputerConfiguration'
            ValueName = 'D4F940AB-401B-4EFC-AADC-AD5F3C50688A'
            ValueData = '1'
        }
    }
    
    if ($ASRRule3B576869) {
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\ASR\Rules\3B576869-A4EC-4529-8536-B80A7769E899'
        {
            Key = '\Software\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\ASR\Rules'
            ValueType = 'String'
            TargetType = 'ComputerConfiguration'
            ValueName = '3B576869-A4EC-4529-8536-B80A7769E899'
            ValueData = '1'
        }
    }
    
    if ($ASRRule75668C1F) {
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\ASR\Rules\75668C1F-73B5-4CF0-BB93-3ECF5CB7CC84'
        {
            Key = '\Software\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\ASR\Rules'
            ValueType = 'String'
            TargetType = 'ComputerConfiguration'
            ValueName = '75668C1F-73B5-4CF0-BB93-3ECF5CB7CC84'
            ValueData = '1'
        }
    }
    
    if ($ASRRuleD3E037E1) {
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\ASR\Rules\D3E037E1-3EB8-44C8-A917-57927947596D'
        {
            Key = '\Software\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\ASR\Rules'
            ValueType = 'String'
            TargetType = 'ComputerConfiguration'
            ValueName = 'D3E037E1-3EB8-44C8-A917-57927947596D'
            ValueData = '1'
        }
    }
    
    if ($ASRRule5BEB7EFE) {
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\ASR\Rules\5BEB7EFE-FD9A-4556-801D-275E5FFC04CC'
        {
            Key = '\Software\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\ASR\Rules'
            ValueType = 'String'
            TargetType = 'ComputerConfiguration'
            ValueName = '5BEB7EFE-FD9A-4556-801D-275E5FFC04CC'
            ValueData = '1'
        }
    }

    if ($ASRRule92E97FA1) {
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\ASR\Rules\92E97FA1-2EDF-4476-BDD6-9DD0B4DDDC7B'
        {
            Key = '\Software\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\ASR\Rules'
            ValueType = 'String'
            TargetType = 'ComputerConfiguration'
            ValueName = '92E97FA1-2EDF-4476-BDD6-9DD0B4DDDC7B'
            ValueData = '1'
        }
    }
    
    if ($EnableNetworkProtection) {
        RegistryPolicyFile 'Registry(POL): HKLM:\Software\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\Network Protection\EnableNetworkProtection'
        {
            Key = '\Software\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\Network Protection'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
            ValueName = 'EnableNetworkProtection'
            ValueData = 1
        }
    }
}

