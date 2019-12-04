ARG RELEASE=latest
FROM archlinux:${RELEASE}
COPY ./entrypoint.sh /
COPY ./etc /etc
RUN pacman-key --init && pacman-key --populate archlinux && pacman-key --recv-keys F75D9D76 && pacman-key --lsign-key F75D9D76 && pacman -Syy --needed --noconfirm coreutils gcc grep make pam zfs-utils && chmod 0755 /entrypoint.sh
ENTRYPOINT ["/entrypoint.sh"]
WORKDIR /workdir
VOLUME /workdir
