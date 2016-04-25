# Abstract

Provides ability to import any cert files as new CA certs silently.

After [bug 1265113](https://bugzilla.mozilla.org/show_bug.cgi?id=1265113) is landed and an preference `security.enterprise_roots.enabled` is configured to `true`, Firefox uses external cert database of Windows itself.
Then you don't have to use this addon to import custom CA certs into Firefox's cert database.


# How to use

Put your cert files to the profile directory or %AppDir%/defaults/ (ex. "C:\Program Files (x86)\Mozilla Firefox\defaults").
After you restart Firefox, cert files will be imported automatically.

This is mainly desinged for corporate-use.

## Supported file types

Supported certs are "PEM" format files, converted from DER X509 files.
(If you are planning to migrate an existing cert from Internet Explorer to Firefox, you can export it by choosing the format "Base 64 encoded X.509".)
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
 5. A confirmation dialog to register new CA cert appears.
    Then, click the "OK" button.
 6. Open the cerfiticate manager.
 7. Confirm that there are automatically registered CA certs:
    * "!example" > "site.example.com"
    * "!example" > "example.com"
 8. Confirm that there are automatically registered exceptions:
    * "(Unknown)" > "(NotStored)" > "site.example.com:443"
    * "(Unknown)" > "(NotStored)" > "foo.example.com:443"
    * "(Unknown)" > "(NotStored)" > "bar.example.com:443"

