# How to use

Put your cert files to the profile directory or %AppDir%/defaults/ (ex. "C:\Program Files (x86)\Mozilla Firefox\defaults").
After you restart Firefox, cert files will be imported automatically.

This is mainly desinged for corporate-use.

## Supported file types

Supported certs are "PEM" format files, converted from DER X509 files.
You must put files with a suffix ".crt", ".cer", or ".pem".
Sample certs are avialable at ./doc/*.pem in the repository.

Cert types are automatically detected. However, you can override the type via preferences.
Sample configurations are avialable at ./doc/sample.js in the repository.

## Security exceptions

If you put security exceptions for a cert file as "<the nmae of the cert file>.override" into the directory same to the cert file, then exceptions defined in the file will be automatically applied.
Sample configurations are avialable at ./doc/newcert.pem.override in the repository.

## How to try

 1. Prepare configurations.
    1. Uninstall old certimporter.
    2. Go to about:config.
    3. Reset all preferences with their name like "extensions.certimporter.certs.*.lastOverrideDate".
    4. Set "extensions.certimporter.debug" to "true".
    5. Open the cerfiticate manager.
    6. Go to the "Authorities" tab.
    7. Delete two CA certs:
       * "!example" > "site.example.com"
       * "!example" > "example.com"
    8. Go to the "Servers" tab.
    9. Delete three exceptions:
       * "(Unknown)" > "(NotStored)" > "site.example.com:443"
       * "(Unknown)" > "(NotStored)" > "foo.example.com:443"
       * "(Unknown)" > "(NotStored)" > "bar.example.com:443"
    10. Restart Firefox.
    11. Open the cerfiticate manager.
    12. Confirm that there is no such item in the "Authorities" tab, like:
        * "!example"
    13. Confirm that there is no exception item in the the "Servers" tab, like:
        * "(Unknown)" > "(NotStored)" > "(something).example.com:443"
 2. Install certimporter.
 3. Put these files to the "defaults" directory under your Firefox's installed directory.
    * doc/cacert.pem
    * doc/newcert.pem
    * doc/newcert.pem.override
 4. Restart Firefox.
 5. Open the cerfiticate manager.
 6. Confirm that there are automatically registered CA certs:
    * "!example" > "site.example.com"
    * "!example" > "example.com"
 7. Confirm that there are automatically registered exceptions:
    * "(Unknown)" > "(NotStored)" > "site.example.com:443"
    * "(Unknown)" > "(NotStored)" > "foo.example.com:443"
    * "(Unknown)" > "(NotStored)" > "bar.example.com:443"

