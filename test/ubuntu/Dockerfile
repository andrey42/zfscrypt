ARG RELEASE=latest
FROM ubuntu:${RELEASE}
ENV DEBIAN_FRONTEND=noninteractive
COPY ./entrypoint.sh /
COPY ./usr /usr
RUN apt-get update && apt-get install --no-install-recommends --yes coreutils gcc grep make libpam-dev libzfslinux-dev zfsutils && pam-auth-update --enable zfscrypt && chmod 0755 /entrypoint.sh
ENTRYPOINT ["/entrypoint.sh"]
WORKDIR /workdir
VOLUME /workdir
