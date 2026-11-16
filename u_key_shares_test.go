package tls

import "testing"

// TestUTLSServerSelectsAnyClassicalKeyShare checks that a server may select
// any classical key share a hello offers, not only the first, as it may with
// Windows (X25519, P-256, P-384) and Firefox (X25519, P-256).
func TestUTLSServerSelectsAnyClassicalKeyShare(t *testing.T) {
	groups := []CurveID{X25519, CurveP256, CurveP384}
	spec := func() *ClientHelloSpec {
		return &ClientHelloSpec{
			CipherSuites: []uint16{TLS_AES_128_GCM_SHA256, TLS_AES_256_GCM_SHA384},
			Extensions: []TLSExtension{
				&SNIExtension{},
				&SupportedVersionsExtension{Versions: []uint16{VersionTLS13}},
				&SupportedCurvesExtension{Curves: groups},
				&SignatureAlgorithmsExtension{SupportedSignatureAlgorithms: []SignatureScheme{
					ECDSAWithP256AndSHA256, PSSWithSHA256, PKCS1WithSHA256,
				}},
				&KeyShareExtension{KeyShares: []KeyShare{{Group: X25519}, {Group: CurveP256}, {Group: CurveP384}}},
			},
		}
	}
	for _, group := range groups {
		t.Run(group.String(), func(t *testing.T) {
			serverConfig := testConfig.Clone()
			serverConfig.CurvePreferences = []CurveID{group}
			_, state, err := testUtlsHandshake(t, testConfig.Clone(), serverConfig, spec())
			if err != nil {
				t.Fatal(err)
			}
			if state.testingOnlyCurveID != group || state.testingOnlyDidHRR {
				t.Fatalf("negotiated %v (HelloRetryRequest %v), want %v without one", state.testingOnlyCurveID, state.testingOnlyDidHRR, group)
			}
		})
	}
}
