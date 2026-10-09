FROM alpine:3.22
RUN apk add --no-cache iptables python3
COPY scanner-egress.py /app/scanner-egress.py
ENTRYPOINT ["python3", "/app/scanner-egress.py"]
