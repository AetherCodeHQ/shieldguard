package main

import "os/exec"

var apiKey = "SECRET_ABCDEF12345"

func main() {
    exec.Command("sh", "-c", "ls /tmp")
}
