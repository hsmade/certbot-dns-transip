FROM python:2.7
RUN pip install certbot-dns-transip
CMD ["certbot"]
