ARG DISTRO=debian:13
FROM ${DISTRO}
ENV container=docker
COPY install.sh /opt/checks/install.sh
COPY deploy /opt/checks/deploy
COPY tests/linux-distro.sh tests/linux-distro.py /opt/checks/tests/
COPY distro-binary/dist-dev/firewall-ui-linux-amd64 /opt/testbin/firewall-ui
RUN chmod 0755 /opt/testbin/firewall-ui && bash /opt/checks/tests/linux-distro.sh prepare
STOPSIGNAL SIGRTMIN+3
ENTRYPOINT []
CMD ["/usr/lib/systemd/systemd", "--log-target=console"]
