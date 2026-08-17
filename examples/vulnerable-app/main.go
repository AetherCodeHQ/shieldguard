package main

import (
    "fmt"
    "os"
    "os/exec"
)

func main() {
    var apiKey = "SECRET_ABCDEF12345"
    fmt.Println("Vulnerable App Running...", apiKey)

    cmd := exec.Command("sh", "-c", "ls /tmp")
    _ = cmd.Run()
}