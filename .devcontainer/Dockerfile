FROM mcr.microsoft.com/devcontainers/python:3.12-bookworm

USER root

RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        git \
        curl \
        ca-certificates \
        jq \
        ripgrep \
        less \
        vim \
        procps \
        build-essential \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/*

# Codex CLI用のNode.jsをインストール
ARG NODE_MAJOR=22

RUN curl -fsSL https://deb.nodesource.com/setup_${NODE_MAJOR}.x | bash - \
    && apt-get install -y --no-install-recommends nodejs \
    && npm install --global @openai/codex \
    && npm cache clean --force \
    && rm -rf /var/lib/apt/lists/*

USER vscode

WORKDIR /workspaces/vuln-intel-agent
