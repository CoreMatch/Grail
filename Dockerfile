# Grail 节点镜像（root / mirror 通用，角色由挂载的配置决定）。
# 构建：docker build -t grail:local .
# 运行：docker run -v <配置/凭据/数据目录> ... grail:local server --config /etc/grail/grail.yaml --credentials /etc/grail/credentials.json
FROM golang:1.26 AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 go build -o /out/grail .

FROM debian:bookworm-slim
RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates && rm -rf /var/lib/apt/lists/*
COPY --from=build /out/grail /usr/local/bin/grail
ENTRYPOINT ["grail"]
CMD ["server", "--config", "/etc/grail/grail.yaml", "--credentials", "/etc/grail/credentials.json"]
