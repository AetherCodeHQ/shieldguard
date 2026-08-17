package patch

import (
    "bufio"
    "fmt"
    "os"
    "strings"
)

func ApplyLineFix(filePath string, lineNo int, newCode string) error {
    file, err := os.Open(filePath)
    if err != nil {
        return fmt.Errorf("dosya acilamadi: %w", err)
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
    return os.WriteFile(filePath, []byte(content), 0644)
}
