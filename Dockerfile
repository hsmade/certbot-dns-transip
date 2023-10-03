FROM python:3.12
RUN pip install certbot-dns-transip
ENTRYPOINT ["certbot"]
