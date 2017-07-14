=====
Usage
=====

To use certbot-dns-transip in a project:

.. code-block:: bash

    $ certbot certonly -d <host.domain.tld> -a certbot-dns-transip:dns-transip --certbot-dns-transip:dns-transip-credentials transip.ini --dns-transip-propagation-seconds 240
    # make sure to use the propagation wait time of at least 240 seconds, as Transip doesn't refresh the zones that often.
    $ cat transip.ini
    certbot_dns_transip:dns_transip_username = my_username
    certbot_dns_transip:dns_transip_key_file = transip.key
    $ cat transip.key
    -----BEGIN RSA PRIVATE KEY-----
    MIIE........
    -----END RSA PRIVATE KEY-----



