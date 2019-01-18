===============================
certbot-dns-transip
===============================

Certbot plugin to authenticate using dns TXT records via Transip API


* Documentation: https://readthedocs.org/projects/certbot-dns-transip/

* Running with docker: `docker run -ti -v $PWD/transip.ini:/transip.ini -v $PWD/transip-rsa.key:/transip-rsa.key hsmade/certbot-transip certonly -d <host.domain.tld> -a certbot-dns-transip:dns-transip --certbot-dns-transip:dns-transip-credentials transip.ini --certbot-dns-transip:dns-transip-propagation-seconds 240`
