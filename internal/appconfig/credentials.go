package appconfig

import (
	"bufio"
	"fmt"
	"os"
	"strconv"
	"strings"
)

// ContainerCredentials reloads credentials saved by the web panel. Parse the
// systemd environment format as data, without executing shell substitutions.
func ContainerCredentials(path, username, password string) (string, string, error) {
	f, err := os.Open(path)
	if os.IsNotExist(err) {
		return username, password, nil
	}
	if err != nil {
		return "", "", err
	}
	defer f.Close()
	scanner := bufio.NewScanner(f)
	scanner.Buffer(make([]byte, 4096), 1024*1024)
	for scanner.Scan() {
		key, value, ok := strings.Cut(scanner.Text(), "=")
		if !ok || (key != "FIREWALL_UI_USERNAME" && key != "FIREWALL_UI_PASSWORD") {
			continue
		}
		decoded, err := strconv.Unquote(value)
		if err != nil || strings.ContainsAny(decoded, "\r\n\x00") {
			return "", "", fmt.Errorf("invalid saved credential %s", key)
		}
		if key == "FIREWALL_UI_USERNAME" {
			username = decoded
		} else {
			password = decoded
		}
	}
	return username, password, scanner.Err()
}
