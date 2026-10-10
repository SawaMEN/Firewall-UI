package appconfig

import (
	"os"
	"path/filepath"
	"testing"
)

func TestContainerCredentialsSurviveRestart(t *testing.T) {
	path := filepath.Join(t.TempDir(), "environment")
	// Shell-like text is a valid password and must never be interpreted.
	// Use the same escaping as the web credentials writer.
	password := "$(exit 1) $HOME `id` \"quote\" \\"
	raw := "FIREWALL_UI_USERNAME=\"new-admin\"\nFIREWALL_UI_PASSWORD=\"$(exit 1) $HOME `id` \\\"quote\\\" \\\\\"\n"
	if err := os.WriteFile(path, []byte(raw), 0600); err != nil {
		t.Fatal(err)
	}
	user, got, err := ContainerCredentials(path, "old-admin", "old-password")
	if err != nil || user != "new-admin" || got != password {
		t.Fatalf("saved credentials were not restored: user=%q err=%v", user, err)
	}
}

func TestContainerCredentialsMissingAndMalformed(t *testing.T) {
	path := filepath.Join(t.TempDir(), "environment")
	user, password, err := ContainerCredentials(path, "admin", "1")
	if err != nil || user != "admin" || password != "1" {
		t.Fatal("missing file must preserve initial environment credentials")
	}
	if err := os.WriteFile(path, []byte("FIREWALL_UI_PASSWORD=unquoted\n"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, _, err := ContainerCredentials(path, "admin", "1"); err == nil {
		t.Fatal("malformed saved credentials must not silently restore an old password")
	}
}
