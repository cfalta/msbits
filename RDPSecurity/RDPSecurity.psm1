Set-StrictMode -Version 1.0
function Get-ComputerCertificate
{
<#
.SYNOPSIS

Just a wrapper around "Get-ChildItem 'Cert:\LocalMachine\My'" with a predefined filter option for certificates that are based on templates.

Author: Christoph Falta (@cfalta)

.DESCRIPTION

Just a wrapper around "Get-ChildItem 'Cert:\LocalMachine\My'" with a predefined filter option for certificates that are based on templates.

.PARAMETER Thumbprint

A predefined certificate thumbprint to search for.

.PARAMETER Filter

A predefined filter. At the moment, the only supported filter is "ShowOnlyCertsFromTemplates". 
It filters on certificates that have the Certificate Template Information extension -> OID = '1.3.6.1.4.1.311.21.7' 

.EXAMPLE

Get-ComputerCertificate -Thumbprint AAAAAA...

Description
-----------

Get a specific certificate from the local computer store based on the thumbprint.

.EXAMPLE

Get-ComputerCertificate

Description
-----------

Get all certificates from the local computer store.

.EXAMPLE

Get-ComputerCertificate -Filter ShowOnlyCertsFromTemplates

Description
-----------

Get all certificates from the local computer store that match the given filter.

.LINK

https://github.com/cfalta/MSBits

#>
    [CmdletBinding()]
    Param (
        #Thumbprint to search for. if omitted, will return all certs via: Get-ChildItem 'Cert:\LocalMachine\My'
        [Parameter(Mandatory = $false)]
        [ValidateNotNullOrEmpty()]
        [String]
        $Thumbprint,
        
        #Returns only certificates that match a certain filter:
            # ShowOnlyCertsFromTemplates = return only certs that have the Certificate Template Information extension -> OID = '1.3.6.1.4.1.311.21.7' 
        [Parameter(Mandatory = $false)]
        [ValidateNotNullOrEmpty()]
        [ValidateSet("ShowOnlyCertsFromTemplates")]
        [String]$Filter)

$Result = @()

if($PSBoundParameters["Thumbprint"])
{
    $Result += Get-ChildItem 'Cert:\LocalMachine\My' | Where-Object {$_.Thumbprint -eq $Thumbprint }
}
else
{
    if($PSBoundParameters["Filter"])
    {
        switch ($Filter) {
            ShowOnlyCertsFromTemplates { $Certificates = Get-ChildItem 'Cert:\LocalMachine\My' | Where-Object{ $_.Extensions | Where-Object { $_.Oid.Value -eq '1.3.6.1.4.1.311.21.7' }} }
            Default { $Certificates = "" }
        }
        $Result += $Certificates
    }
    else
    {
       $Result += Get-ChildItem 'Cert:\LocalMachine\My'
    }

}

$Result

}

function Get-RDPCertificate
{
<#
.SYNOPSIS

Show the currenlty configured RDP certificate

Author: Christoph Falta (@cfalta)

.DESCRIPTION

Grabs the thumbprint of the currently configured RDP certificate via WMI and finds the corresponding certificate object from the local machine store. 
Returns the certificate object and extends the Certificate Template Information OID (if existent) into separate attributes for easy of access.

.EXAMPLE

Get-RDPCertificate

Description
-----------

Show the currenlty configured RDP certificate

.LINK

https://github.com/cfalta/MSBits

#>
    $TSSettings = Get-WmiObject -Class "Win32_TSGeneralSetting" -Namespace root\cimv2\terminalservices -Filter "TerminalName='RDP-TCP'"
    
    Get-ComputerCertificate -Thumbprint $TSSettings.SSLCertificateSHA1Hash | Expand-CertificateTemplateInformation   
}

function Expand-CertificateTemplateInformation
{
<#
.SYNOPSIS

Add certificate template information to the standard X509Certificate2 object Powershell returns. 

Author: Christoph Falta (@cfalta)

.DESCRIPTION

Gets all certificates from the local machine store and parses the contents of the Certificate Template Information extension into separate attributes for ease of access.
Expects X509Certificate2 objects as input. Takes input from pipeline.

.EXAMPLE

Get-Childitem CERT:\LocalMachine\My | Expand-CertificateTemplateInformation

Description
-----------

Add certificate template information to the standard X509Certificate2 object returned by Get-Childitem in this example. 

.LINK

https://github.com/cfalta/MSBits

#>

    [CmdletBinding()]
    Param (
        #Certificate objects, returned by something like: Get-ChildItem 'Cert:\LocalMachine\My'
        [Parameter(Mandatory = $true, ValueFromPipeline=$true)]
        [ValidateNotNullOrEmpty()]
        [System.Security.Cryptography.X509Certificates.X509Certificate2]
        $Certificate)
    
    begin{

        $TemplateExtensionOID = '1.3.6.1.4.1.311.21.7'
        
    }
    process
    {
        #Extract Template Name, ID, Major and Minor Version from Extension
        $TemplateExtension = $Certificate.Extensions | Where-Object { $_.Oid.Value -eq $TemplateExtensionOID }
        if($TemplateExtension)
        {
        
            $TemplateExtensionValue = $TemplateExtension.Format(1) 
            $TemplateExtensionValue = $TemplateExtensionValue.Split([Environment]::NewLine)

            $AttrTemplateName = $TemplateExtensionValue[0].split("=")[0]
            $AttrTemplateValue = $TemplateExtensionValue[0].split("=")[1]

            #Try to check if the value contains the friendly name as well as the template ID
            if($AttrTemplateValue.contains("(") -and $AttrTemplateValue.contains(")"))
            {
                $AttrTemplateValueName = $AttrTemplateValue.split("(")[0]
                $AttrTemplateValueId = $AttrTemplateValue.split("(")[1].Trim(")")
            }
            else
            {
                $AttrTemplateValueName = ""
                $AttrTemplateValueId = $AttrTemplateValue
            }

            $AttrMajorVersionName = $TemplateExtensionValue[2].split("=")[0]
            $AttrMajorVersionValue = $TemplateExtensionValue[2].split("=")[1]

            $AttrMinorVersionName = $TemplateExtensionValue[4].split("=")[0]
            $AttrMinorVersionValue = $TemplateExtensionValue[4].split("=")[1]

            #Sanity checks
            if($AttrTemplateName -eq "Template" -and $AttrMajorVersionName -eq "Major Version Number" -and $AttrMinorVersionName -eq "Minor Version Number")
            {
                # Adding the template info as new attributes
                $Certificate | Add-Member -MemberType NoteProperty -Name CertificateTemplateName -Value $AttrTemplateValueName -Force
                $Certificate | Add-Member -MemberType NoteProperty -Name CertificateTemplateId -Value $AttrTemplateValueId -Force
                $Certificate | Add-Member -MemberType NoteProperty -Name CertificateTemplateMajorVersion -Value $AttrMajorVersionValue -Force
                $Certificate | Add-Member -MemberType NoteProperty -Name CertificateTemplateMinorVersion -Value $AttrMinorVersionValue -Force
            }

        }

        $Certificate
    
    }

    end {}
}

function Test-RDPCertficate
{
<#
.SYNOPSIS

Verifies if a certain certificate matches defined criteria to be used as RDP certificate. Returns either $True or $False.
Use -Verbose for detailed output.

Author: Christoph Falta (@cfalta)

.DESCRIPTION

Tests the currently configured RDP certificate or a certificate from the local machine store identified by thumbprint against the following criteria:

- Matches certificate template name or template ID. Supplied via $CertificateTemplateName or $CertificateTemplateID
- Has a private key
- Is valid for at least another X days, where X is definied in $DaysLeft. Default is 30 days.
- The hostname of the computer set in $env:hostname matches the subject of the certificate. Implemented through Powershells "-match" operator.
    This is an optional parameter set by the $MatchHostname switch

Returns $true if ALL tests pass, otherwise returns $false

.PARAMETER Thumbprint

A predefined certificate thumbprint to test. Note that this certificate needs to exist in the local machine cert store.

.PARAMETER CertificateTemplateName

Returns $true only if the Certificate Template Name definied in the Certificate Template Information extension matches this variable.
Can't be used together with $CertificateTemplateId. Either of the two is mandatory.

.PARAMETER CertificateTemplateId

Returns $true only if the Certificate Template ID definied in the Certificate Template Information extension matches this variable.
Can't be used together with $CertificateTemplateName. Either of the two is mandatory.

.PARAMETER DaysLeft

Returns $true only if the certificate is valid for at least another X days, where X is definied in $DaysLeft. Default is 30 days.

.PARAMETER MatchHostname

Returns $true if the hostname of the computer set in $env:hostname matches the subject of the certificate. Implemented through Powershells "-match" operator.
This is an optional parameter.


.EXAMPLE

Test-RDPCertificate -CertificateTemplateName ContosoComputer

Description
-----------

Checks if the RDP certificate currently in use was issued using a template called "ContosoComputer". Also makes sure that it is valid for at least another 30 days (implicit check in this case).

.EXAMPLE

Test-RDPCertificate -CertificateTemplateName ContosoComputer -DaysLeft 90 -MatchHostname

Description
-----------

Checks if the RDP certificate currently in use was issued using a template called "ContosoComputer". 
Also makes sure that it is valid for at least another 90 days and the hostname of the computer matches the subject in the certificate.

.EXAMPLE

Test-RDPCertificate -Thumbprint a909502dd82ae... -CertificateTemplateId 1.3.6.1... -DaysLeft 90 -MatchHostname

Description
-----------

Verifies that the certificate in the local machine store identified by the -Thumbprint parameter:
 - was issued via a certificate template identified by the supplied CertificateTemplateId 
 - is valid for at least another 90 days
 - hostname of the computer matches the subject in the certificate.

Thumbprint and ID redacted for better readability.

.LINK

https://github.com/cfalta/MSBits

#>

[CmdletBinding()]
Param (

    #Certificate thumbprint of the cert to test. If omited, will test the currently configured RDP cert.
    [Parameter(Mandatory = $false, ParameterSetName="ByName")]
    [Parameter(Mandatory = $false, ParameterSetName="ById")]
    [ValidateNotNullOrEmpty()]
    [String]
    $Thumbprint,

    #Certificate template to look for by name
    [Parameter(Mandatory = $true, ParameterSetName="ByName")]
    [ValidateNotNullOrEmpty()]
    [String]
    $CertificateTemplateName,

    #Certificate template to look for by Id
    [Parameter(Mandatory = $true, ParameterSetName="ById")]
    [ValidateNotNullOrEmpty()]
    [String]
    $CertificateTemplateId,

    #Match hostname with cert subject
    [Parameter(Mandatory = $false, ParameterSetName="ByName")]
    [Parameter(Mandatory = $false, ParameterSetName="ById")]
    [ValidateNotNullOrEmpty()]
    [Switch]
    $MatchHostname,

    #The existing certificate needs to be valid (NotAfter) at least X more days. Default ist 30 days.
    [Parameter(Mandatory = $false, ParameterSetName="ByName")]
    [Parameter(Mandatory = $false, ParameterSetName="ById")]
    [ValidateNotNullOrEmpty()]
    [int32]
    $DaysLeft = 30
    )

if ($PSBoundParameters["Thumbprint"]) 
{
    $CurrentCertThumbprint = $Thumbprint
}
else 
{
    $TSSettings = Get-WmiObject -Class "Win32_TSGeneralSetting" -Namespace root\cimv2\terminalservices -Filter "TerminalName='RDP-TCP'"
    $CurrentCertThumbprint = $TSSettings.SSLCertificateSHA1Hash
}

$CertObject = Get-ComputerCertificate -Thumbprint $CurrentCertThumbprint | Expand-CertificateTemplateInformation

if($CertObject)
{
    Write-Verbose "[TEST] Certificate $($CertObject.Thumbprint) exists in store: TRUE"

    if($CertObject.HasPrivateKey)
    {
        Write-Verbose "[TEST] Private key available: TRUE"

        if(($CertObject.CertificateTemplateName -and $PSBoundParameters['CertificateTemplateName']) -or ($CertObject.CertificateTemplateId -and $PSBoundParameters['CertificateTemplateId'] ))
                                                                                                                                                                                                                                                        {
        Write-Verbose "[TEST] Certificate contains template name or ID: TRUE"

            $TemplateMatch = $false
            if($PSBoundParameters['CertificateTemplateName'])
            {
                if($CertObject.CertificateTemplateName -eq $CertificateTemplateName)
                {
                    Write-Verbose "[TEST] Template name match - $($CertObject.CertificateTemplateName) -eq $($CertificateTemplateName) : TRUE"
                    $TemplateMatch = $true
                }
                else
                {
                    Write-Verbose "[TEST] Template name match - $($CertObject.CertificateTemplateName) -eq $($CertificateTemplateName) : FALSE"
                    return $false
                }
            }
            if($PSBoundParameters['CertificateTemplateId'])
            {
                if($CertObject.CertificateTemplateId -eq $CertificateTemplateId)
                {
                    Write-Verbose "[TEST] Template ID match - $($CertObject.CertificateTemplateId) -eq $($CertificateTemplateId) : TRUE"
                    $TemplateMatch = $true
                }
                else
                {
                    Write-Verbose "[TEST] Template ID match - $($CertObject.CertificateTemplateId) -eq $($CertificateTemplateId) : FALSE"
                    return $false
                }
            }

            if($TemplateMatch)
            {
                $TimeBoundary = (get-date).adddays($DaysLeft)
                $NotAfterAsTime = [datetime]$CertObject.NotAfter

                if($NotAfterAsTime -gt $TimeBoundary)
                {
                    Write-Verbose "[TEST] NotAfter-Time is valid for at least $($DaysLeft) more days - $($NotAfterAsTime) -gt $($TimeBoundary): TRUE"

                    if($PSBoundParameters["MatchHostname"])
                    {
    
                        if($CertObject.Subject -match $env:COMPUTERNAME)
                        {
                            Write-Verbose "[TEST] Hostname matches subject - $($env:COMPUTERNAME) -match $($CertObject.Subject): TRUE"
                            return $true
                        }
                        else
                        {
                            Write-Verbose "[TEST] Hostname matches subject - $($env:COMPUTERNAME) -match $($CertObject.Subject): FALSE"
                            return $false
                        }
                    }
                    else
                    {
                        return $true
                    }
                }
                else {
                    Write-Verbose "[TEST] NotAfter-Time is valid for at least $($DaysLeft) more days - $($NotAfterAsTime) -gt $($TimeBoundary): FALSE"
                    return $false
                }
            }
    }
        else
        {
            Write-Verbose "[TEST] Certificate contains template name or ID: FALSE"
            return $false
        }
    }
    else
    {
        Write-Verbose "[TEST] Private key available: FALSE"
        return $false
    }
}
else
{
    Write-Verbose "[TEST] Certificate $($TSSettings.SSLCertificateSHA1Hash) exists in store: FALSE"
    return $false
}

}

function Set-RDPCertficate
{
<#
.SYNOPSIS

Sets the certificate identified by $Thumbprint to be used by the RDP service.

Author: Christoph Falta (@cfalta)

.DESCRIPTION

Uses Get-WmiObject to access the current RDP service configuration (class Win32_TSGeneralSetting) and then set the attribute SSLCertificateSHA1Hash to the hash identified by $Thumbprint.
This will make the RDP service use the specified certificate for new connections.


.PARAMETER Thumbprint

Thumbprint of the certificate to be used. Note that this certificate needs to exist in the local machine cert store.



.EXAMPLE

Set-RDPCertificate -Thumbprint a909502dd82ae...

Description
-----------

Sets the RDP certificate to the certificate that has the thumbprint a909502dd82ae...


.LINK

https://github.com/cfalta/MSBits

#>
[CmdletBinding()]
Param (
    #Certificate thumbprint of the cert we want to set as RDP certificate
    [Parameter(Mandatory = $true)]
    [ValidateNotNullOrEmpty()]
    [String]
    $Thumbprint)

    $NewRDPCert = Get-ComputerCertificate | Where-Object {$_.HasPrivateKey -and ($_.Thumbprint -eq $Thumbprint)}
    
    if($NewRDPCert)
    {
        try 
        {
            $TSSettings = Get-WmiObject -Class "Win32_TSGeneralSetting" -Namespace root\cimv2\terminalservices -Filter "TerminalName='RDP-TCP'"
            Set-WmiInstance -Path $TSSettings.__path -argument @{SSLCertificateSHA1Hash="$($NewRDPCert.Thumbprint)"} -ErrorAction Stop
        }
        catch
        {
            Write-Error "Unable to set RDP certificate. Make sure you run this command with administrative rights."
        }

    }
    else
    {
        Write-Error "Unable to verify certificate. Make sure it exists and a private key is available."
    }

 
}

function Register-RDPCertificate
{
<#
.SYNOPSIS

Use this function to set a certificate based on a specified certificate template as the RDP service certificate.

Author: Christoph Falta (@cfalta)

.DESCRIPTION

The function will first check if the current certificate matches the definied criteria and abort if it does, unless the $Force switch is set. 

If the current certificate does not meet the criteria or the force switch is used, go through all certificates in the local machine store and verify for each certificate:

- It matches certificate template name or template ID. Supplied via $CertificateTemplateName or $CertificateTemplateID
- Has a private key
- Is valid for at least another X days, where X is definied in $DaysLeft. Default is 30 days.
- The hostname of the computer set in $env:hostname matches the subject of the certificate. Implemented through Powershells "-match" operator.
    This is an optional parameter set by the $MatchHostname switch

Configures the matching certificate for the RDP service. If more than one certificate fulfills all checks, the one with the longest remaining validity period (NotAfter) is used.

.PARAMETER CertificateTemplateName

Searches for certificates where the Certificate Template Name definied in the Certificate Template Information extension matches this variable.
Can't be used together with $CertificateTemplateId. Either of the two is mandatory.

.PARAMETER CertificateTemplateId

Searches for certificates where the Certificate Template Id definied in the Certificate Template Information extension matches this variable.
Can't be used together with $CertificateTemplateName. Either of the two is mandatory.

.PARAMETER DaysLeft

Searches for certificates which are valid for at least another X days, where X is definied in $DaysLeft. Default is 30 days.

.PARAMETER MatchHostname

Searches for certificates where the hostname of the computer set in $env:hostname matches the subject of the certificate. Implemented through Powershells "-match" operator.
This is an optional parameter.


.EXAMPLE

Register-RDPCertificate -CertificateTemplateName ContosoComputer

Description
-----------

Set the RDP service certificate to a certificate issued using a template called "ContosoComputer". Also makes sure that it is valid for at least another 30 days (implicit check in this case).

.EXAMPLE

Register-RDPCertificate -CertificateTemplateName ContosoComputer -DaysLeft 90 -MatchHostname

Description
-----------

Set the RDP service certificate to a certificate issued using a template called "ContosoComputer". 
Also makes sure that it is valid for at least another 90 days and the hostname of the computer matches the subject in the certificate.

.EXAMPLE

Register-RDPCertificate -CertificateTemplateId 1.3.6.1... -DaysLeft 90 -MatchHostname -Force

Description
-----------

Set the RDP service certificate to a certificate issued using a template identified by its ID. 
Also makes sure that it is valid for at least another 90 days and the hostname of the computer matches the subject in the certificate.
Overwrites the current configuration in any case due to the $Force switch being used.

Thumbprint redacted for better readability.

.LINK

https://github.com/cfalta/MSBits

#>
[CmdletBinding()]
Param (
    #Certificate template to look for by name
    [Parameter(Mandatory = $true, ParameterSetName="ByName")]
    [ValidateNotNullOrEmpty()]
    [String]
    $CertificateTemplateName,

    #Certificate template to look for by Id
    [Parameter(Mandatory = $true, ParameterSetName="ById")]
    [ValidateNotNullOrEmpty()]
    [String]
    $CertificateTemplateId,

    #Match hostname with cert subject
    [Parameter(Mandatory = $false, ParameterSetName="ByName")]
    [Parameter(Mandatory = $false, ParameterSetName="ById")]
    [ValidateNotNullOrEmpty()]
    [Switch]
    $MatchHostname,

    #The existing certificate needs to be valid (NotAfter) at least X more days. Default ist 30 days.
    [Parameter(Mandatory = $false, ParameterSetName="ByName")]
    [Parameter(Mandatory = $false, ParameterSetName="ById")]
    [ValidateNotNullOrEmpty()]
    [int32]
    $DaysLeft = 30,

    #Force indicates that the configuration should be changed if a valid certificate is found, regardless of the existing RDP certificate
    [Parameter(Mandatory = $false, ParameterSetName="ByName")]
    [Parameter(Mandatory = $false, ParameterSetName="ById")]
    [ValidateNotNullOrEmpty()]
    [Switch]
    $Force
    
    )

$EligibleCerts = @()
$CertsFromTemplates = Get-ComputerCertificate -Filter ShowOnlyCertsFromTemplates

if($PSBoundParameters["CertificateTemplateName"])
{
    if((Test-RDPCertficate -CertificateTemplateName $CertificateTemplateName) -and -not $PSBoundParameters["Force"])
    {
        Write-Output "Current RDP certificate satisfies requirements. Nothing to do."
        return
    }
    else
    {
        $EligibleCerts += $CertsFromTemplates | Where-Object { Test-RDPCertficate -Thumbprint $_.thumbprint -CertificateTemplateName $CertificateTemplateName -MatchHostname:$MatchHostname -DaysLeft $DaysLeft}
    }
}
if($PSBoundParameters["CertificateTemplateId"])
{    
    if((Test-RDPCertficate -CertificateTemplateId $CertificateTemplateId) -and -not $PSBoundParameters["Force"])
    {
        Write-Output "Current RDP certificate satisfies requirements. Nothing to do."
        return
    }
    else
    {
        $EligibleCerts += $CertsFromTemplates | Where-Object { Test-RDPCertficate -Thumbprint $_.thumbprint -CertificateTemplateId $CertificateTemplateId -MatchHostname:$MatchHostname -DaysLeft $DaysLeft}
    }
}

if($EligibleCerts)
{
    if($EligibleCerts.count -eq 1)
    {
        $NewRDPCert = $EligibleCerts | Expand-CertificateTemplateInformation
    }
    if($EligibleCerts.count -gt 1)
    {
        Write-Verbose "Got more than one matching certificate. Will go for the last NotAfter-date."
        $NewRDPCert = $EligibleCerts | Sort-Object -Property NotAfter -Descending | Select-Object -First 1 | Expand-CertificateTemplateInformation
    }

    if($NewRDPCert)
    {
        Write-Verbose "Setting RDP certificate: `n   Thumbprint: $($NewRDPCert.Thumbprint)`n   Template: $($NewRDPCert.CertificateTemplateName)`n   Subject: $($NewRDPCert.Subject)`n   NotBefore: $($NewRDPCert.NotBefore)`n   NotAfter: $($NewRDPCert.NotAfter)"

        Set-RDPCertficate -Thumbprint $NewRDPCert.Thumbprint
    }
}
else
{
    Write-Error "No valid certificate was found."
}

} 
 
function Get-RDPSecurity
{
<#
.SYNOPSIS

Query the current RDP service configuration for the Security Layer (RDP OR TLS) and the NLA (Network Level Authentication) state.

Author: Christoph Falta (@cfalta)

.DESCRIPTION

Query the current RDP service configuration for the Security Layer (RDP OR TLS) and the NLA (Network Level Authentication) state. Return a custom PSObject mit config values and descriptions.

.EXAMPLE

Get-RDPSecurity

Description
-----------

Query the current RDP service configuration for the Security Layer (RDP OR TLS) and the NLA (Network Level Authentication) state.

.LINK

https://github.com/cfalta/MSBits

#>
    $LayerDescription = @{
    
    "0" = "RDP Security Layer"
    "1" = "Negotiate"
    "2" = "TLS Security Layer"

    }

    $NetworkLevelAuthDescription = @{
    
    "0" = "NLA NOT required"
    "1" = "NLA required" 

    }
    
    $TSSettings = Get-WmiObject -Class "Win32_TSGeneralSetting" -Namespace root\cimv2\terminalservices -Filter "TerminalName='RDP-TCP'"
    $SecurityLayer = $TSSettings.SecurityLayer
    $NLA = $TSSettings.UserAuthenticationRequired
    
    [pscustomobject]@{
    
    SecurityLayer = $SecurityLayer
    SecurityLayerDescription = $LayerDescription["$SecurityLayer"]
    NLA = $NLA
    NLADescription = $NetworkLevelAuthDescription["$NLA"]
    
    }

}

function Set-RDPSecurity
{
<#
.SYNOPSIS

Set Security Layer (RDP OR TLS) or NLA (Network Level Authentication) configuration.

Author: Christoph Falta (@cfalta)

.DESCRIPTION

Allows you to set the Security Layer (RDP OR TLS) and/or the NLA (Network Level Authentication) configuration on the current host. Shows a warning if you set it to an insecure value.

.PARAMETER SecurityLayer

Set the Security Layer to RDP, Negotiate or TLS. Anything other than TLS is insecure and should not be used.

.PARAMETER EnforceNLA

Toggle enforcement of Network Level Authentication. Disabling NLA isn't a good idea in almost all cases.


.EXAMPLE

Set-RDPSecurity -SecurityLayer TLS -EnforceNLA True

Description
-----------

Sets the Security Layer to TLS and enforces NLA. This is the recommended configuration from a security point of view.

.LINK

https://github.com/cfalta/MSBits

#>
    [CmdletBinding()]
    Param (
    #Security Layer, possible values predefined
    [Parameter(Mandatory = $false)]
    [ValidateSet("TLS","Negotiate","RDP")]
    [String]
    $SecurityLayer,
    
    #Enforce NLA - yes or no
    [Parameter(Mandatory = $false)]
    [ValidateSet("True","False")]
    [String]
    $EnforceNLA
    )

    $LayerValues = @{
    
        "TLS" = 2
        "Negotiate" = 1
        "RDP" = 0
        }

    $NLAValues = @{
    
            "False" = 0
            "True" = 1  
    }

    if($PSBoundParameters["SecurityLayer"])
    {
        $UserSuppliedLayerValue = $LayerValues[$SecurityLayer]
        if($UserSuppliedLayerValue -ne 2)
        {
            Write-Warning "Caution: anything other than TLS Security Layer is insecure and opens the RDP service to attacks (e.g. MitM)."
        }
    
        try 
        {
            $TSSettings = Get-WmiObject -Class "Win32_TSGeneralSetting" -Namespace root\cimv2\terminalservices -Filter "TerminalName='RDP-TCP'"
            $TSSettings.SetSecurityLayer($UserSuppliedLayerValue)
        }
        catch
        {
            Write-Error "Unable to set WMI instance. Make sure you run this command with administrative rights."
        }
    }

    if($PSBoundParameters["EnforceNLA"])
    {
        $UserSuppliedNLAValue = $NLAValues[$EnforceNLA]
        if($UserSuppliedNLAValue -ne 1)
        {
            Write-Warning "Caution: disabling NLA is considered insecure and opens the RDP service to attacks."
        }
    
        try 
        {
            $TSSettings = Get-WmiObject -Class "Win32_TSGeneralSetting" -Namespace root\cimv2\terminalservices -Filter "TerminalName='RDP-TCP'"
            $TSSettings.SetUserAuthenticationRequired($UserSuppliedNLAValue)
        }
        catch
        {
            Write-Error "Unable to set WMI instance. Make sure you run this command with administrative rights."
        }
    }


}