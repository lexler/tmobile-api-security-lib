docker build . -t markdown_snippets
docker run -it --entrypoint sh -v /Users/ladak/Documents/GitHub/tmobile-api-security-lib:/app/repo markdown_snippets