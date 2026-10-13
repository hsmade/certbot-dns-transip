FROM python:3.15
RUN pip install certbot-dns-transip
ENTRYPOINT ["certbot"]
