FROM python:3.11
RUN pip install certbot-dns-transip
ENTRYPOINT ["certbot"]
