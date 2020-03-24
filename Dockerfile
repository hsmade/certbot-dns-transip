FROM python:3.8
RUN pip install certbot-dns-transip
ENTRYPOINT ["certbot"]
