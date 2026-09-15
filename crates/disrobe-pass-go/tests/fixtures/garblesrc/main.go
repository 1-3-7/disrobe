package main

import "os"

var sink int

//go:noinline
func emit(s string) {
	sink += len(s)
}

func main() {
	emit("the quick brown fox jumps over the lazy dog by the riverbank twice")
	emit("failed to connect to the upstream server: invalid session token given")
	emit("https://telemetry.example.invalid/v2/collect/beacon/report/endpoint")
	emit("permission was denied while opening the configuration registry hive")
	emit("the secret key material has been rotated so the cache must be cleared")
	emit("C:\\Windows\\System32\\drivers\\etc\\hosts could not be opened to write")
	emit("the rate limiter rejected the inbound request from this remote client")
	emit("a fatal panic occurred inside the message dispatch goroutine handler!")
	os.Exit(sink & 0)
}
