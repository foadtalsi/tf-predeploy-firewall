FROM golang:1.23-alpine AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 go build -o /tf-predeploy-firewall ./cmd/scanner

FROM alpine:3.20
RUN apk add --no-cache git ca-certificates
COPY --from=build /tf-predeploy-firewall /usr/local/bin/tf-predeploy-firewall
ENTRYPOINT ["/usr/local/bin/tf-predeploy-firewall"]
