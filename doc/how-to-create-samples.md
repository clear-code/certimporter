# How to create sample cert by OpenSSL on Ubuntu 12.04

Login as the root.

    $ sudo su

Create a new CA.

    # mkdir -p /usr/local/ssl
    # cd /usr/local/ssl
    # /usr/local/ssl/misc/CA.sh -newca

 * name = !example
 * common name = example.com

Change OpenSSL's configuration.

    # vi /etc/ssl/openssl.cnf

Then change or add the configuration of nsCertType, as:

    [ usr_cert ]
    ...
    nsCertType = sslCA

Create a new server cert.

    # /usr/local/ssl/misc/CA.sh -newreq

 * name = !example
 * common name = site.example.com

    # /usr/local/ssl/misc/CA.sh -sign

Extend certs' lifetime.

    # openssl ca -policy policy_anything -days 365000 -out demoCA/cacert.pem -infiles demoCA/careq.pem
    # openssl ca -policy policy_anything -days 365000 -out newcert.pem -infiles newreq.pem

If you see an error like:

    failed to update database
    TXT_DB error number 2
    Signed certificate is in newcert.pem

Then, revoke the cert like:

    # openssl ca -revoke demoCA/newcerts/(the latest file in the directory).pem

And retry the last process you saw the error.

After all, update files in the repository.

    # cp demoCA/cacert.pem /path/to/repository/doc/
    # cp newcert.pem /path/to/repository/doc/

(based on steps described on http://l-w-i.net/t/openssl/cert_001.txt )
