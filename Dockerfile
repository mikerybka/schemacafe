FROM archlinux:latest

RUN pacman -Syu --noconfirm go

COPY go.mod go.sum /src/
WORKDIR /src
RUN go mod download

COPY . .

ENTRYPOINT [ "go", "run", "cmd/server/main.go" ]
