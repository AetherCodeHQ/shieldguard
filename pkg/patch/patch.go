package patch

import (
    "bufio"
    "fmt"
    "os"
    "os/exec"
    "strings"
)

func IsWorkTreeClean() bool {
    cmd := exec.Command("git", "status", "--porcelain")
    out, err := cmd.Output()
    if err != nil {
        return false
    }
    return len(strings.TrimSpace(string(out))) == 0
}

func ApplyLineFix(filePath string, lineNo int, newCode string) error {
    file, err := os.Open(filePath)
    if err != nil {
        return fmt.Errorf("could not open file: %w", err)
    }
    defer file.Close()

    var lines []string
    scanner := bufio.NewScanner(file)
    currentLine := 0

    for scanner.Scan() {
        currentLine++
        if currentLine == lineNo {
            lines = append(lines, newCode)
        } else {
            lines = append(lines, scanner.Text())
        }
    }

    if err := scanner.Err(); err != nil {
        return err
    }

    content := strings.Join(lines, "\n") + "\n"
    if err := os.WriteFile(filePath, []byte(content), 0644); err != nil {
        _ = exec.Command("git", "checkout", "--", filePath).Run()
        return fmt.Errorf("could not write patch, change reverted: %w", err)
    }
    return nil
}
