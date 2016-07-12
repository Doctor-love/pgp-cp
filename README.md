# pgp-cp - Copies PGP signed file to destination if signature is trusted

## Description
Proof of concept script written in Python to copy a file if the specified detached signature is trusted.  
Such a process could for example be used to deploy configuration from removable media in a somewhat secure manner.  

The script requires Python 2.7 and the third-party ["gnupg" module](https://pypi.python.org/pypi/gnupg).     

## Disclaimer
As stated above, this is a proof of concept and relies on external dependencies which have not been audited.  
PGP is probably way more advanced than what's needed for this type of application.  
Therefore, it should only be seen as inspiration at the moment.  
