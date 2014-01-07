How to create sample cert by OpenSSL:

First, create the secret key.

    $ openssl genrsa 2048 > secret.key

Create a CA cert file.

    $ openssl req -new -key secret.key > ca.csr

Type "!Sample" for all fields except "Country Name" and the "challenge password".

    $ openssl x509 -days 3650 -req -signkey secret.key < ca.csr > ca.crt

(based on steps described on http://d.hatena.ne.jp/ozuma/20130511/1368284304 )
