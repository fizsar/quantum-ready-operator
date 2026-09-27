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

func TestAuditarClasificaClaveYFirma(t *testing.T) {
	rsaClave, _ := rsa.GenerateKey(rand.Reader, 2048)
	ecClave, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	_, edClave, _ := ed25519.GenerateKey(rand.Reader)

	casos := []struct {
		nombre    string
		clave     crypto.Signer
		algoritmo string
	}{
		{"RSA", rsaClave, "RSA"},
		{"ECDSA", ecClave, "ECDSA"},
		{"Ed25519", edClave, "Ed25519"},
	}
	for _, c := range casos {
		t.Run(c.nombre, func(t *testing.T) {
			hallazgos, sinRegla := Auditar(autofirmado(t, c.clave))
			if len(sinRegla) != 0 {
				t.Fatalf("no debería haber algoritmos sin regla: %v", sinRegla)
			}
			if len(hallazgos) != 2 {
				t.Fatalf("se esperaban 2 hallazgos (clave pública y firma), hay %d", len(hallazgos))
			}
			for i, origen := range []securityv1alpha1.Origen{
				securityv1alpha1.OrigenClavePublica, securityv1alpha1.OrigenFirma,
			} {
				h := hallazgos[i]
				if h.Algoritmo != c.algoritmo || h.Origen != origen ||
					h.Categoria != securityv1alpha1.CategoriaCritico || h.RiesgoCombinado != "" {
					t.Errorf("hallazgo %d inesperado: %+v", i, h)
				}
			}
		})
	}
}

func TestAlgoritmosSinReglaNoInventanCategoria(t *testing.T) {
	cert := &x509.Certificate{
		PublicKeyAlgorithm: x509.DSA,
		SignatureAlgorithm: x509.DSAWithSHA256,
	}
	hallazgos, sinRegla := Auditar(cert)
	if len(hallazgos) != 0 {
		t.Errorf("no debería haber hallazgos: %+v", hallazgos)
	}
	if len(sinRegla) != 2 || sinRegla[0] != "DSA" {
		t.Errorf("sinRegla = %v", sinRegla)
	}
	if PeorCaso(hallazgos) != "" {
		t.Error("sin hallazgos, el peor caso debe quedar vacío")
	}
}

func TestPeorCasoUsaLosPesosDeLaFase1(t *testing.T) {
	h := func(c securityv1alpha1.Categoria) securityv1alpha1.Hallazgo {
		return securityv1alpha1.Hallazgo{Categoria: c}
	}
	casos := []struct {
		hallazgos []securityv1alpha1.Hallazgo
		esperado  securityv1alpha1.Categoria
	}{
		{[]securityv1alpha1.Hallazgo{h(securityv1alpha1.CategoriaAceptable), h(securityv1alpha1.CategoriaObsoleto),
			h(securityv1alpha1.CategoriaAdvertencia)}, securityv1alpha1.CategoriaObsoleto},
		{[]securityv1alpha1.Hallazgo{h(securityv1alpha1.CategoriaObsoleto), h(securityv1alpha1.CategoriaCritico)},
			securityv1alpha1.CategoriaCritico},
		{[]securityv1alpha1.Hallazgo{h(securityv1alpha1.CategoriaPostCuantico)}, securityv1alpha1.CategoriaPostCuantico},
	}
	for _, c := range casos {
		if got := PeorCaso(c.hallazgos); got != c.esperado {
			t.Errorf("PeorCaso(%v) = %q, se esperaba %q", c.hallazgos, got, c.esperado)
		}
	}
}
