FROM alpine:3.22
RUN apk add --no-cache iptables iproute2 python3
COPY scanner-egress.py /app/scanner-egress.py
COPY egress-check.py /app/egress-check.py
ENTRYPOINT ["python3", "/app/scanner-egress.py"]
