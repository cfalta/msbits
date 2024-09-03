# RDPSecurity

Some useful function to secure an RDP service. Most notably a function (Register-RDPCertificate) meant to make sure that you always use valid TLS certificates for your RDP connections.

Included functions:

- Get-ComputerCertificate
- Expand-CertificateTemplateInformation
- Get-RDPCertificate
- Test-RDPCertficate
- Set-RDPCertficate
- Register-RDPCertificate
- Get-RDPSecurity
- Set-RDPSecurity


# Examples

## Make sure you always have valid RDP certificates

- **Step 1:** deploy computer certificates to all Windows hosts automatically (e.g. through auto enrollment)
- **Step 2:** deploy this Powershell module on the hosts or include it in a custom script
- **Step 3:** create a scheduled task on every host that runs `Register-RDPCertificate` once a day/week/etc (see example below) - done :)


```Powershell
Register-RDPCertificate -CertificateTemplateName ContosoComputer -DaysLeft 40 -MatchHostname
```

Set the RDP service certificate to a certificate issued using a template called "ContosoComputer". The certificate needs to exist in the local machine store.
Also makes sure that it is valid for at least another 90 days and the hostname of the computer matches the subject in the certificate.

**More detailed logic explanation:**

The function will first check if the current RDP service certificate matches the definied criteria and abort if it does, unless the $Force switch is set. 

If the current certificate does not meet the criteria or the force switch is used, go through all certificates in the local machine store and verify for each certificate:

- It matches certificate template name or template ID. Supplied via $CertificateTemplateName or $CertificateTemplateID
- Has a private key
- Is valid for at least another X days, where X is definied in $DaysLeft. Default is 30 days
- The hostname of the computer set in $env:hostname matches the subject of the certificate. Implemented through Powershells "-match" operator.
    This is an optional parameter set by the $MatchHostname switch

Configures the matching certificate for the RDP service. If more than one certificate fulfills all checks, the one with the longest remaining validity period (NotAfter) is used.

## Verify and fix common RDP security settings

```Powershell
Get-RDPSecurity
```

Query the current RDP service configuration for the Security Layer (RDP OR TLS) and the NLA (Network Level Authentication) state. Return a custom PSObject mit config values and descriptions.

```Powershell
Set-RDPSecurity -SecurityLayer TLS -EnforceNLA True
```

Sets the Security Layer to TLS and enforces NLA. This is the recommended configuration from a security point of view.