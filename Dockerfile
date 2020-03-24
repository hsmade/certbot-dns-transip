FROM python:3.6
RUN pip install certbot-dns-transip
ENTRYPOINT ["certbot"]
