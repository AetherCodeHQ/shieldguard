package main

import "os/exec"

var apiKey = os.Getenv("API_KEY")

func main() {
exec.Command("ls", "/tmp")
}
