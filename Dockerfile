# This is a Dockerfile to create a container running Python 3.7 containing the
# openVulnQuery module. The openVulnQuery module is a client for the Cisco
# openVuln API.
#
# Author: Omar Santos, os@cisco.com


FROM python:3.7.10-alpine as builder

WORKDIR /build
COPY . .
RUN python3 setup.py bdist_wheel


FROM python:3.7.10-alpine

COPY --from=builder /build/dist/*.whl /whl/
RUN python3 -m pip --no-cache-dir install /whl/*.whl \
    && rm -rf /whl

CMD ["/usr/local/bin/python3"]
