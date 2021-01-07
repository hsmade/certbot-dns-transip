=====
Usage
=====

To use certbot-dns-transip in a project:

.. code-block:: bash

    # Get an API key from TransIP
    
    # Convert the key to an RSA key
    $ openssl rsa -in transip.key -out transip-rsa.key
    
    # make sure the rights are set correctly
    $ chmod 600 transip-rsa.key
    
    $ cat transip-rsa.key
    -----BEGIN RSA PRIVATE KEY-----
    MIIE........
    -----END RSA PRIVATE KEY-----
  
    # Create a transip.ini file
    $ cat transip.ini
    dns_transip_username = my_username
    dns_transip_key_file = /full/path/to/transip-rsa.key
    
    # Execute certbot
    $ certbot certonly -d <host.domain.tld> -a certbot-dns-transip:dns-transip --certbot-dns-transip:dns-transip-credentials transip.ini --certbot-dns-transip:dns-transip-propagation-seconds 240
    # make sure to use the propagation wait time of at least 240 seconds, as Transip doesn't refresh the zones that often.
