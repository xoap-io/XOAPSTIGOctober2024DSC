# XOAPSTIGOCTOBER2024

This repository contains the XOAPSTIGOctober2024DSC DSC module.

## Code of Conduct

This project has adopted this [Code of Conduct](CODE_OF_CONDUCT.md).

## Contributing

Please check out common DSC Community [contributing guidelines](https://dsccommunity.org/guidelines/contributing).

## Change log

A full list of changes in each version can be found in the [change log](CHANGELOG.md).

## Documentation

The XOAP STIG October 2024 DSC module contains the following resources:

- DoD_Adobe_Acrobat_Pro_DC_Continuous_V2R1
- DoD_Adobe_Acrobat_Reader_DC_Continuous_V2R1
- DoD_Google_Chrome_v2r10
- DoD_Internet_Explorer_11_v2r4
- DoD_Microsoft_Defender_Antivirus_STIG_v2r4
- DoD_Microsoft_Edge_v2r2
- DoD_Mozilla_Firefox_v6r5
- DoD_Office_2019-M365_Apps_v3r1
- DoD_Office_System_2013_and_Components
- DoD_Office_System_2016_and_Components
- DoD_Windows_10_v3r2
- DoD_Windows_11_v2r2
- DoD_Windows_Defender_Firewall_v2r2
- DoD_WinSvr_2012_R2_MS_and_DC_v3r7
- DoD_WinSvr_2016_MS_and_DC_v2r9
- DoD_WinSvr_2019_MS_and_DC_v3r2
- DoD_WinSvr_2022_MS_and_DC_v2r2


## Prerequisites

Be sure that the following DSC modules are installed on your system:

- GPRegistryPolicyDsc (1.2.0)
- AuditPolicyDSC (1.4.0.0)
- SecurityPolicyDSC (2.10.0.0)


### Configuration Examples

To implement the STIG October 2024 DSC module, add the following resources to your DSC configuration and adjust accordingly:

```powershell
Import-DSCResource -Module 'XOAPSTIGOctober2024DSC' -Name 'DoD_WinSvr_2022_MS_and_DC_v2r2' -ModuleVersion '1.0.0'

Configuration XOAPSTIGOctober2024DSC
{
    param
    (
      [Parameter(Mandatory = $false)]
      EnumerateAdministrators = $true,

      [Parameter(Mandatory = $false)]
      NoAutorun = $true
    )

    Node 'localhost'
    {
        DoD_WinSvr_2022_MS_and_DC_v2r2 Example
        {
            EnumerateAdministrators = $using:EnumerateAdministrators
            NoAutorun = $using:NoAutorun
        }
    }
}

XOAPSTIGOctober2024DSC -OutputPath 'C:\XOAPSTIGOctober2024Output'
