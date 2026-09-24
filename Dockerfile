# syntax=docker/dockerfile:1

FROM golang:1.23-alpine AS build
WORKDIR /src
COPY go.mod ./
COPY cmd ./cmd
COPY internal ./internal
RUN go vet ./... && go test ./...
RUN CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /out/api ./cmd/api

FROM alpine:3.20
RUN addgroup -S app && adduser -S app -G app
COPY --from=build /out/api /usr/local/bin/api
USER app
ENV ADDR=:8080
EXPOSE 8080
ENTRYPOINT ["api"]
