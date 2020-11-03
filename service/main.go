package main

import (
	"flag"
	"runtime"

	"github.com/aricart/cm"
)

func main() {
	var config cm.CredentialsManager
	flag.StringVar(&config.NatsHostPort, "nats hostport", "localhost:4222", "NATS hostport")
	flag.StringVar(&config.CredentialsFile, "creds", "", "NATS credentials file")
	flag.StringVar(&config.DataDir, "data", "", "data directory")
	flag.Parse()
	config.Run()
	runtime.Goexit()
}
