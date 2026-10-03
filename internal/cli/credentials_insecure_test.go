package cli

import "testing"

func TestRefuseInsecureServerURL(t *testing.T) {
	allowed := []string{
		"https://safegrd.dev",
		"http://localhost:8080",
		"http://127.0.0.1:8080",
		"http://[::1]:8080",
		"http://host.docker.internal:8080",
	}
	for _, u := range allowed {
		if err := refuseInsecureServerURL(u); err != nil {
			t.Errorf("%s refused: %v", u, err)
		}
	}
	refused := []string{
		"http://safegrd.dev",
		"http://10.0.0.5:8080",
		"http://host.docker.internal.example.com:8080",
		"http://docker.internal:8080",
	}
	for _, u := range refused {
		if err := refuseInsecureServerURL(u); err == nil {
			t.Errorf("%s allowed over plain http", u)
		}
	}
}
