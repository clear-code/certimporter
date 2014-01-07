How to create sample cert by OpenSSL:

    $ openssl genrsa 2048 > sample.key
    $ openssl req -new -key sample.key > sample.csr
    $ openssl x509 -days 3650 -req -signkey sample.key < sample.csr > sample.crt

(based on steps described on http://d.hatena.ne.jp/ozuma/20130511/1368284304 )
