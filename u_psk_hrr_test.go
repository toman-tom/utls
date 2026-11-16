package tls

import "testing"

// TestUTLSResumesAcrossHelloRetryRequest checks that a hello offering a PSK
// still resumes when the server first asks for another key share: the second
// hello keeps the PSK, with binders over the retried handshake.
func TestUTLSResumesAcrossHelloRetryRequest(t *testing.T) {
	spec := func() *ClientHelloSpec {
		return &ClientHelloSpec{
			CipherSuites: []uint16{TLS_AES_128_GCM_SHA256},
			Extensions: []TLSExtension{
				&SNIExtension{},
				&SupportedVersionsExtension{Versions: []uint16{VersionTLS13}},
				&SupportedCurvesExtension{Curves: []CurveID{X25519, CurveP256}},
				&SignatureAlgorithmsExtension{SupportedSignatureAlgorithms: []SignatureScheme{PSSWithSHA256, PKCS1WithSHA256}},
				&KeyShareExtension{KeyShares: []KeyShare{{Group: X25519}}},
				&PSKKeyExchangeModesExtension{Modes: []uint8{pskModeDHE}},
				&UtlsPreSharedKeyExtension{},
			},
		}
	}
	clientConfig := testConfig.Clone()
	clientConfig.ServerName = "example.golang"
	clientConfig.ClientSessionCache = NewLRUClientSessionCache(1)
	clientConfig.OmitEmptyPsk = true
	server := func(curve CurveID) *Config {
		c := testConfig.Clone()
		c.CurvePreferences = []CurveID{curve}
		c.SetSessionTicketKeys([][32]byte{{1}})
		return c
	}

	if _, _, err := testUtlsHandshake(t, clientConfig, server(X25519), spec()); err != nil {
		t.Fatalf("first handshake: %v", err)
	}
	serverState, clientState, err := testUtlsHandshake(t, clientConfig, server(CurveP256), spec())
	if err != nil {
		t.Fatalf("resumed handshake: %v", err)
	}
	if !clientState.testingOnlyDidHRR {
		t.Fatal("the server sent no HelloRetryRequest; the test is not exercising one")
	}
	if !serverState.DidResume || !clientState.DidResume {
		t.Fatalf("server resumed %v, client resumed %v; want both", serverState.DidResume, clientState.DidResume)
	}
}
