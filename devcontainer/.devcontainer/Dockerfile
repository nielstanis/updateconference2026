FROM mcr.microsoft.com/devcontainers/dotnet:1-10.0-noble

RUN rm -f /etc/apt/sources.list.d/yarn* \
    && apt-get update \
    && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
        dnsutils ipset iptables jq \
    && rm -rf /var/lib/apt/lists/*

COPY --chmod=0755 init-firewall.sh /usr/local/bin/init-firewall.sh

RUN rm -f /etc/sudoers.d/vscode \
    && echo "vscode ALL=(root) NOPASSWD: /usr/local/bin/init-firewall.sh" \
        > /etc/sudoers.d/vscode-firewall \
    && chmod 0440 /etc/sudoers.d/vscode-firewall \
    && visudo -c \
    && ! sudo -l -U vscode | grep -qF '(ALL' \
    && install -d -o vscode -g vscode /home/vscode/.copilot
