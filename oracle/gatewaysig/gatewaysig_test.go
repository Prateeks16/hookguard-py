package gatewaysig

import "testing"

func TestSignVerify(t *testing.T) {
	secret := []byte("internal")
	body := []byte(`{"x":1}`)
	sig := Sign(secret, "stripe", body)

	if err := Verify(secret, "stripe", body, sig); err != nil {
		t.Fatalf("roundtrip should pass: %v", err)
	}
	if err := Verify(secret, "github", body, sig); err == nil {
		t.Fatal("different provider should fail (provenance binding)")
	}
	if err := Verify(secret, "stripe", []byte(`{"x":2}`), sig); err == nil {
		t.Fatal("tampered body should fail")
	}
	if err := Verify([]byte("wrong"), "stripe", body, sig); err == nil {
		t.Fatal("wrong internal secret should fail")
	}
	if err := Verify(secret, "stripe", body, "nothex"); err == nil {
		t.Fatal("bad encoding should fail")
	}
}
