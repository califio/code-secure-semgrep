# When updating version make sure to check on semgrepignore file as well
FROM golang:1.23-alpine AS build
ENV CGO_ENABLED=0 GOOS=linux
WORKDIR /go/src/buildapp
COPY . .
RUN PATH_TO_MODULE=`go list -m` && go build -o /analyzer

FROM semgrep/semgrep:1.99
ENV SEMGREP_R2C_INTERNAL_EXPLICIT_SEMGREPIGNORE "/semgrepignore"
ENV PIP_NO_CACHE_DIR=off
COPY semgrepignore /semgrepignore
COPY --from=build /analyzer /analyzer
ENTRYPOINT []
CMD ["/analyzer", "run"]
