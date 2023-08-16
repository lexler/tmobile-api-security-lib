FROM bitnami/dotnet-sdk:latest

RUN dotnet tool install -g MarkdownSnippets.Tool
ENV PATH="$PATH:/app/.dotnet/tools"

WORKDIR /app/repo
ENTRYPOINT ["/bin/bash"]