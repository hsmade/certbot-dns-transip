=====
Usage
=====

To use certbot-dns-transip in a project:

.. code-block:: bash

    certbot certonly -d <host.domain.tld> --dns-transip --dns-transip-credentials transip.ini --dns-transip-propagation-seconds 120
    # make sure to use the propagation wait time of at least 120 seconds, as Transip doesn't refresh the zones that often.

