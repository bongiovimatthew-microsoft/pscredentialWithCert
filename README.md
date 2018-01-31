# PSCredential and Smartcard Certificates 

## Overview

This project provides example code for how to use `CredMarshalCredential` and `CredUnmarshalCredential` to manage 
a `CERT_CREDENTIAL_INFO` data blob on a `PSCredential` object. This logic is the same logic used by the 
`Get-Credential` PowerShell cmdlet. 

For a detailed walkthrough, see [this blog post](https://blogs.technet.microsoft.com/heyscriptingguy/2017/12/15/powershell-support-for-certificate-credentials/)

## Additional Resources 

1. [LogonUser API](https://msdn.microsoft.com/en-us/library/windows/desktop/aa378184(v=vs.85).aspx)

2. [CredMarshalCredential function](https://msdn.microsoft.com/en-us/library/windows/desktop/aa374801(v=vs.85).aspx)

3. [CredUnmarshalCredential function](https://msdn.microsoft.com/en-us/library/windows/desktop/aa375184(v=vs.85).aspx)

4. [CERT_CREDENTIAL_INFO struct](https://msdn.microsoft.com/en-us/library/windows/desktop/aa374753(v=vs.85).aspx)

5. [PSCredential object](https://docs.microsoft.com/en-us/dotnet/api/system.management.automation.pscredential?view=powershellsdk-1.1.0)

## Contributing

This project welcomes contributions and suggestions. 
