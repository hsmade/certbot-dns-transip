===============================
certbot-dns-transip
===============================

.. image:: https://readthedocs.org/projects/certbot-dns-transip/badge/?version=stable
   :target: https://certbot-dns-transip.readthedocs.io/en/stable/?badge=stable
   :alt: Documentation Status
   
.. image:: https://www.travis-ci.org/hsmade/certbot-dns-transip.svg?branch=master&status=passed
   :target: https://www.travis-ci.org/github/hsmade/certbot-dns-transip
   :alt: Build Status

Certbot plugin to authenticate using dns TXT records via Transip API


* Documentation: https://readthedocs.org/projects/certbot-dns-transip/

You can also run this directly from Docker, and get the certificates and keys written to disk for further processing.

For example the following command can be used. This assumes the `transip.ini` file and the keyfile are present in `/tmp/letsencrypt`. ::

    docker run -ti -v `/tmp/letsencrypt`:/etc/letsencrypt \
        -w /etc/letsencrypt \
        hsmade/certbot-transip \
        certonly -n \
        -d 'your.domain.com' \
        -a dns-transip \
        --dns-transip-credentials /etc/letsencrypt/transip.ini \
        --dns-transip-propagation-seconds 240 \
        -m your@domain.com \
        --agree-tos \
        --eff-email

The contents of `transip.ini` are as follows. ::

    dns_transip_key_file = transip.key
    dns_transip_username = my_user
    
Finally, the key file is an RSA private key
