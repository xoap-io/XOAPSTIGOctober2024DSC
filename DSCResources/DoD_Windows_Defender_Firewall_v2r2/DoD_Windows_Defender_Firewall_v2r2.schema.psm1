configuration DoD_Windows_Defender_Firewall_v2r2
{
    param(
        [bool]$PolicyVersion = $true,
        [bool]$EnableFirewall = $true,
        [bool]$DefaultOutboundAction = $true,
        [bool]$DefaultInboundAction = $true,
        [bool]$LogFileSize = $true,
        [bool]$LogDroppedPackets_Domain = $true,
        [bool]$LogSuccessfulConnections_Domain = $true,
        [bool]$EnableFirewall_Private = $true,
        [bool]$DefaultOutboundAction_Private = $true,
        [bool]$DefaultInboundAction_Private = $true,
        [bool]$LogFileSize_Private = $true,
        [bool]$LogDroppedPackets_Private = $true,
        [bool]$LogSuccessfulConnections_Private = $true,
        [bool]$EnableFirewall_Public = $true,
        [bool]$DefaultOutboundAction_Public = $true,
        [bool]$DefaultInboundAction_Public = $true,
        [bool]$AllowLocalPolicyMerge = $true,
        [bool]$AllowLocalIPsecPolicyMerge = $true,
        [bool]$LogFileSize_Public = $true,
        [bool]$LogDroppedPackets_Public = $true,
        [bool]$LogSuccessfulConnections_Public = $true

    )

    Import-DSCResource -ModuleName 'GPRegistryPolicyDsc'
	Import-DSCResource -ModuleName 'AuditPolicyDSC'
	Import-DSCResource -ModuleName 'SecurityPolicyDSC'

    if ($PolicyVersion) {
        RegistryPolicyFile 'Registry(POL): HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\PolicyVersion'
        {
            Key = '\SOFTWARE\Policies\Microsoft\WindowsFirewall'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
            ValueName = 'PolicyVersion'
            ValueData = 539
        }
    }
    
    if ($EnableFirewall) {
        RegistryPolicyFile 'Registry(POL): HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\DomainProfile\EnableFirewall'
        {
            Key = '\SOFTWARE\Policies\Microsoft\WindowsFirewall\DomainProfile'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
            ValueName = 'EnableFirewall'
            ValueData = 1
        }
    }
    
    if ($DefaultOutboundAction) {
        RegistryPolicyFile 'Registry(POL): HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\DomainProfile\DefaultOutboundAction'
        {
            Key = '\SOFTWARE\Policies\Microsoft\WindowsFirewall\DomainProfile'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
            ValueName = 'DefaultOutboundAction'
            ValueData = 0
        }
    }
    
    if ($DefaultInboundAction) {
        RegistryPolicyFile 'Registry(POL): HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\DomainProfile\DefaultInboundAction'
        {
            Key = '\SOFTWARE\Policies\Microsoft\WindowsFirewall\DomainProfile'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
            ValueName = 'DefaultInboundAction'
            ValueData = 1
        }
    }
    
    if ($LogFileSize) {
        RegistryPolicyFile 'Registry(POL): HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\DomainProfile\Logging\LogFileSize'
        {
            Key = '\SOFTWARE\Policies\Microsoft\WindowsFirewall\DomainProfile\Logging'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
            ValueName = 'LogFileSize'
            ValueData = 16384
        }
    }

    if ($LogDroppedPackets_Domain) {
        RegistryPolicyFile 'Registry(POL): HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\DomainProfile\Logging\LogDroppedPackets'
        {
            Key = '\SOFTWARE\Policies\Microsoft\WindowsFirewall\DomainProfile\Logging'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
            ValueName = 'LogDroppedPackets'
            ValueData = 1
        }
    }
    
    if ($LogSuccessfulConnections_Domain) {
        RegistryPolicyFile 'Registry(POL): HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\DomainProfile\Logging\LogSuccessfulConnections'
        {
            Key = '\SOFTWARE\Policies\Microsoft\WindowsFirewall\DomainProfile\Logging'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
            ValueName = 'LogSuccessfulConnections'
            ValueData = 1
        }
    }
    
    if ($EnableFirewall_Private) {
        RegistryPolicyFile 'Registry(POL): HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\PrivateProfile\EnableFirewall'
        {
            Key = '\SOFTWARE\Policies\Microsoft\WindowsFirewall\PrivateProfile'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
            ValueName = 'EnableFirewall'
            ValueData = 1
        }
    }
    
    if ($DefaultOutboundAction_Private) {
        RegistryPolicyFile 'Registry(POL): HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\PrivateProfile\DefaultOutboundAction'
        {
            Key = '\SOFTWARE\Policies\Microsoft\WindowsFirewall\PrivateProfile'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
            ValueName = 'DefaultOutboundAction'
            ValueData = 0
        }
    }
    
    if ($DefaultInboundAction_Private) {
        RegistryPolicyFile 'Registry(POL): HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\PrivateProfile\DefaultInboundAction'
        {
            Key = '\SOFTWARE\Policies\Microsoft\WindowsFirewall\PrivateProfile'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
            ValueName = 'DefaultInboundAction'
            ValueData = 1
        }
    }
    
    if ($LogFileSize_Private) {
        RegistryPolicyFile 'Registry(POL): HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\PrivateProfile\Logging\LogFileSize'
        {
            Key = '\SOFTWARE\Policies\Microsoft\WindowsFirewall\PrivateProfile\Logging'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
            ValueName = 'LogFileSize'
            ValueData = 16384
        }
    }
    
    if ($LogDroppedPackets_Private) {
        RegistryPolicyFile 'Registry(POL): HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\PrivateProfile\Logging\LogDroppedPackets'
        {
            Key = '\SOFTWARE\Policies\Microsoft\WindowsFirewall\PrivateProfile\Logging'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
            ValueName = 'LogDroppedPackets'
            ValueData = 1
        }
    }

    if ($LogSuccessfulConnections_Private) {
        RegistryPolicyFile 'Registry(POL): HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\PrivateProfile\Logging\LogSuccessfulConnections'
        {
            Key = '\SOFTWARE\Policies\Microsoft\WindowsFirewall\PrivateProfile\Logging'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
            ValueName = 'LogSuccessfulConnections'
            ValueData = 1
        }
    }
    
    if ($EnableFirewall_Public) {
        RegistryPolicyFile 'Registry(POL): HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\PublicProfile\EnableFirewall'
        {
            Key = '\SOFTWARE\Policies\Microsoft\WindowsFirewall\PublicProfile'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
            ValueName = 'EnableFirewall'
            ValueData = 1
        }
    }
    
    if ($DefaultOutboundAction_Public) {
        RegistryPolicyFile 'Registry(POL): HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\PublicProfile\DefaultOutboundAction'
        {
            Key = '\SOFTWARE\Policies\Microsoft\WindowsFirewall\PublicProfile'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
            ValueName = 'DefaultOutboundAction'
            ValueData = 0
        }
    }
    
    if ($DefaultInboundAction_Public) {
        RegistryPolicyFile 'Registry(POL): HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\PublicProfile\DefaultInboundAction'
        {
            Key = '\SOFTWARE\Policies\Microsoft\WindowsFirewall\PublicProfile'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
            ValueName = 'DefaultInboundAction'
            ValueData = 1
        }
    }
    
    if ($AllowLocalPolicyMerge) {
        RegistryPolicyFile 'Registry(POL): HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\PublicProfile\AllowLocalPolicyMerge'
        {
            Key = '\SOFTWARE\Policies\Microsoft\WindowsFirewall\PublicProfile'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
            ValueName = 'AllowLocalPolicyMerge'
            ValueData = 0
        }
    }
    
    if ($AllowLocalIPsecPolicyMerge) {
        RegistryPolicyFile 'Registry(POL): HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\PublicProfile\AllowLocalIPsecPolicyMerge'
        {
            Key = '\SOFTWARE\Policies\Microsoft\WindowsFirewall\PublicProfile'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
            ValueName = 'AllowLocalIPsecPolicyMerge'
            ValueData = 0
        }
    }

    if ($LogFileSize_Public) {
        RegistryPolicyFile 'Registry(POL): HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\PublicProfile\Logging\LogFileSize'
        {
            Key = '\SOFTWARE\Policies\Microsoft\WindowsFirewall\PublicProfile\Logging'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
            ValueName = 'LogFileSize'
            ValueData = 16384
        }
    }
    
    if ($LogDroppedPackets_Public) {
        RegistryPolicyFile 'Registry(POL): HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\PublicProfile\Logging\LogDroppedPackets'
        {
            Key = '\SOFTWARE\Policies\Microsoft\WindowsFirewall\PublicProfile\Logging'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
            ValueName = 'LogDroppedPackets'
            ValueData = 1
        }
    }
    
    if ($LogSuccessfulConnections_Public) {
        RegistryPolicyFile 'Registry(POL): HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\PublicProfile\Logging\LogSuccessfulConnections'
        {
            Key = '\SOFTWARE\Policies\Microsoft\WindowsFirewall\PublicProfile\Logging'
            ValueType = 'Dword'
            TargetType = 'ComputerConfiguration'
            ValueName = 'LogSuccessfulConnections'
            ValueData = 1
        }
    }
}

