=====
Usage
=====

To use certbot-dns-transip in a project:

.. code-block:: bash

    # Get an API key from TransIP

    # Convert the key to an RSA key
    $ openssl rsa -in /etc/letsencrypt/transip.key -out /etc/letsencrypt/transip-rsa.key

    # make sure the rights are set correctly
    $ chmod 600 /etc/letsencrypt/transip-rsa.key

    $ cat /etc/letsencrypt/transip-rsa.key
    -----BEGIN RSA PRIVATE KEY-----
    MIIE........
    -----END RSA PRIVATE KEY-----

    # Create a transip.ini file
    $ cat //etc/letsencrypttransip.ini
    dns_transip_username = my_username
    dns_transip_key_file = /etc/letsencrypt/transip-rsa.key

    # Execute certbot
    $ docker run -ti -v `/etc/letsencrypt`:/etc/letsencrypt \
             hsmade/certbot-transip \
             certonly -n \
             -d 'your.domain.com' \
             -a dns-transip \
             --dns-transip-credentials /etc/letsencrypt/transip.ini \
             --dns-transip-propagation-seconds 240 \
             -m your@domain.com \
             --agree-tos \
             --eff-email

    # make sure to use the propagation wait time of at least 240 seconds, as Transip doesn't refresh the zones that often.

================
IP Whitelistsing
================
By default the access token generated to do the api requests will only allow requests from whitelisted ip addresses. If the
key you use doesn't require whitelisting you can disable this by adding `dns_transip_global_key = yes` to the ini file.
