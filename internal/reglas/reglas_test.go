/*
Copyright 2026.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package reglas

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"testing"
	"time"

	securityv1alpha1 "github.com/fizsar/quantum-ready-operator/api/v1alpha1"
)

// autofirmado genera un certificado autofirmado con la clave indicada.
func autofirmado(t *testing.T, privada crypto.Signer) *x509.Certificate {
	t.Helper()
	plantilla := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "prueba"},
		NotBefore:    time.Now(),
		NotAfter:     time.Now().Add(time.Hour),
	}
	der, err := x509.CreateCertificate(rand.Reader, plantilla, plantilla, privada.Public(), privada)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return cert
}

func TestAuditarClasificaClaveYFirmaConSuRiesgo(t *testing.T) {
	rsaClave, _ := rsa.GenerateKey(rand.Reader, 2048)
	ecClave, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	_, edClave, _ := ed25519.GenerateKey(rand.Reader)

	casos := []struct {
		nombre     string
		clave      crypto.Signer
		algoritmo  string
		exposicion securityv1alpha1.Exposicion
		alcance    securityv1alpha1.Alcance
		riesgo     string
		global     string
	}{
		{"RSA alta/alto", rsaClave, "RSA", "alta", "alto", "Urgente (16)", "Crítico"},
		{"ECDSA baja/alto", ecClave, "ECDSA", "baja", "alto", "Alto (8)", "Alto"},
		{"Ed25519 baja/bajo", edClave, "Ed25519", "baja", "bajo", "Medio (4)", "Medio"},
	}
	for _, c := range casos {
		t.Run(c.nombre, func(t *testing.T) {
			resultado, err := Auditar(autofirmado(t, c.clave), c.exposicion, c.alcance)
			if err != nil {
				t.Fatal(err)
			}
			if len(resultado.SinRegla) != 0 {
				t.Fatalf("no debería haber algoritmos sin regla: %v", resultado.SinRegla)
			}
			if len(resultado.Hallazgos) != 2 {
				t.Fatalf("se esperaban 2 hallazgos (clave pública y firma), hay %d", len(resultado.Hallazgos))
			}
			for i, origen := range []securityv1alpha1.Origen{
				securityv1alpha1.OrigenClavePublica, securityv1alpha1.OrigenFirma,
			} {
				esperado := securityv1alpha1.Hallazgo{
					Algoritmo: c.algoritmo, Origen: origen,
					Categoria: securityv1alpha1.CategoriaCritico, RiesgoCombinado: c.riesgo,
				}
				if resultado.Hallazgos[i] != esperado {
					t.Errorf("hallazgo %d = %+v, se esperaba %+v", i, resultado.Hallazgos[i], esperado)
				}
			}
			if resultado.RiesgoGlobal != c.global {
				t.Errorf("RiesgoGlobal = %q, se esperaba %q", resultado.RiesgoGlobal, c.global)
			}
		})
	}
}

func TestAlgoritmosSinReglaNoInventanCategoriaNiRiesgo(t *testing.T) {
	cert := &x509.Certificate{
		PublicKeyAlgorithm: x509.DSA,
		SignatureAlgorithm: x509.DSAWithSHA256,
	}
	resultado, err := Auditar(cert, "alta", "alto")
	if err != nil {
		t.Fatal(err)
	}
	if len(resultado.Hallazgos) != 0 {
		t.Errorf("no debería haber hallazgos: %+v", resultado.Hallazgos)
	}
	if len(resultado.SinRegla) != 2 || resultado.SinRegla[0] != "DSA" {
		t.Errorf("SinRegla = %v", resultado.SinRegla)
	}
	if resultado.RiesgoGlobal != "" {
		t.Errorf("sin hallazgos, el riesgo global debe quedar vacío, no %q", resultado.RiesgoGlobal)
	}
}

func TestAuditarPropagaElErrorDeUnaExposicionNoValida(t *testing.T) {
	rsaClave, _ := rsa.GenerateKey(rand.Reader, 2048)
	if _, err := Auditar(autofirmado(t, rsaClave), "media", "alto"); err == nil {
		t.Error("una exposición no válida debería dar error")
	}
}
