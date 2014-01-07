# How to use

Put your cert files to the profile directory or %AppDir%/defaults/ (ex. "C:\Program Files (x86)\Mozilla Firefox\defaults").
After you restart Firefox, cert files will be imported automatically.

## Supported file types

Supported certs are "PEM" format files, converted from DER X509 files.
You must put files with a suffix ".crt", ".cer", or ".pem".
Sample certs are avialable at ./doc/*.pem

Cert types are automatically detected. However, you can override the type via preferences.
Sample configurations are avialable at ./doc/sample.js

## Security exceptions

If you put security exceptions for a cert file as "<the nmae of the cert file>.override" into the directory same to the cert file, then exceptions defined in the file will be automatically applied.
Sample configurations are avialable at ./doc/newcert.pem.override

