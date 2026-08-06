package parser

import "testing"

func TestIISParser(t *testing.T) {
	parser, err := New("iis_w3c", "iis")
	if err != nil {
		t.Fatal(err)
	}
	_, err = parser.Parse("#Fields: date time s-ip cs-method cs-uri-stem cs-uri-query s-port cs-username c-ip cs(User-Agent) cs(Referer) sc-status sc-substatus sc-win32-status time-taken")
	if err != nil {
		t.Fatal(err)
	}
	event, err := parser.Parse("2026-08-06 10:00:01 10.0.0.5 GET /login.aspx user=admin 443 - 203.0.113.10 Mozilla/5.0 - 401 0 0 21")
	if err != nil {
		t.Fatal(err)
	}
	if event.HTTP.Path != "/login.aspx" || event.HTTP.Status != 401 || event.Network.SourceIP != "203.0.113.10" {
		t.Fatalf("unexpected event: %+v", event)
	}
}

func TestNginxParser(t *testing.T) {
	parser, err := New("nginx_combined", "nginx")
	if err != nil {
		t.Fatal(err)
	}
	event, err := parser.Parse(`203.0.113.10 - alice [06/Aug/2026:17:42:01 +0700] "GET /api/items?id=9 HTTP/1.1" 200 123 "-" "curl/8.0"`)
	if err != nil {
		t.Fatal(err)
	}
	if event.HTTP.Path != "/api/items" || event.HTTP.Query != "id=9" || event.HTTP.Status != 200 {
		t.Fatalf("unexpected event: %+v", event)
	}
}

func TestMySQLParserFingerprintsQuery(t *testing.T) {
	parser, err := New("mysql_general", "mysql")
	if err != nil {
		t.Fatal(err)
	}
	event, err := parser.Parse("2026-08-06T10:00:01.000000Z 12 Query SELECT * FROM users WHERE id=42")
	if err != nil {
		t.Fatal(err)
	}
	if event.Kind != "database.query" || event.Database.QueryFingerprint == "" {
		t.Fatalf("unexpected event: %+v", event)
	}
}
