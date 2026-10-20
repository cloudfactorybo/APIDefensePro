# syntax=docker/dockerfile:1.7

FROM golang:1.25-alpine AS build
WORKDIR /src

COPY go.mod go.sum ./
RUN go mod download

COPY . .
RUN CGO_ENABLED=0 GOOS=linux go build -trimpath -ldflags='-s -w' -o /out/defensepro-api   ./cmd/server \
 && CGO_ENABLED=0 GOOS=linux go build -trimpath -ldflags='-s -w' -o /out/defensepro-admin ./cmd/admin

FROM alpine:3.19
RUN apk add --no-cache ca-certificates tzdata \
 && addgroup -S defensepro && adduser -S -G defensepro defensepro

COPY --from=build /out/defensepro-api   /usr/local/bin/defensepro-api
COPY --from=build /out/defensepro-admin /usr/local/bin/defensepro-admin

USER defensepro
EXPOSE 8080
ENTRYPOINT ["defensepro-api"]
