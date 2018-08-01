# PowerShell - PSCredential and Smartcard Certificates 

## Overview

This project provides example PowerShell code for how to read and use PSCredential objects that contain Smartcard credentials. 

This project contains the following PowerShell examples: 

1. __[ReverseMarshal.ps1](./ReverseMarshal.ps1)__ - takes a PSCredential object, determines if the inner credential is a username/password or a smartcard. If it's a smartcard, we unpack the credential and locate the correct certificate from the CurrentUser store. 


2. __[ReadFromAnySmartcard.ps1](./ReadFromAnySmartcard.ps1)__ - locates all smartcard certificates from the CurrentUser store, presents the user with a list of smartcard certificates to choose from, collects the user PIN, and then generates a PSCredential from the chosen smartcard certificate. (Credit to Joshua Chase for this code)


## Contributing

This project welcomes contributions and suggestions. 