package main

import (
	"flag"
	"runtime"

	"github.com/aricart/cm"
)

func main() {
	var server cm.CredentialsManager
	flag.StringVar(&server.NatsHostPort, "nats hostport", "localhost:4222", "NATS hostport")
	flag.StringVar(&server.CredentialsFile, "creds", "", "NATS credentials file")
	flag.StringVar(&server.DataDir, "data", "", "data directory")
	flag.Parse()
	server.Run()
	runtime.Goexit()
}
