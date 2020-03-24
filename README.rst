===============================
certbot-dns-transip
===============================

Certbot plugin to authenticate using dns TXT records via Transip API


* Documentation: https://readthedocs.org/projects/certbot-dns-transip/

You can also run this directly from Docker, and get the certificates and keys written to disk for further processing.

For example the following command can be used. This assumes the `transip.ini` file and the keyfile are present in `/tmp/letsencrypt`. ::

    docker run -ti -v `/tmp/letsencrypt`:/etc/letsencrypt \
        hsmade/certbot-transip \
        certonly -n \
        -d 'your.domain.com' \
        -a certbot-dns-transip:dns-transip \
        --certbot-dns-transip:dns-transip-credentials /etc/letsencrypt/transip.ini \
        --certbot-dns-transip:dns-transip-propagation-seconds 240 \
        -m your@domain.com \
        --agree-tos \
        --eff-email
