FROM python:3.14
RUN pip install certbot-dns-transip
ENTRYPOINT ["certbot"]
