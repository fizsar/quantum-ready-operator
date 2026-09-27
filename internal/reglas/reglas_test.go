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
	"reflect"
	"testing"
	"time"

	securityv1alpha1 "github.com/fizsar/quantum-ready-operator/api/v1alpha1"
)

const (
	critico   = securityv1alpha1.CategoriaCritico
	obsoleto  = securityv1alpha1.CategoriaObsoleto
	aceptable = securityv1alpha1.CategoriaAceptable
	clave     = securityv1alpha1.OrigenClavePublica
	firmaO    = securityv1alpha1.OrigenFirma
)

// autofirmado genera un certificado autofirmado real con la clave indicada.
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

// Cada rama de la tabla de firmas: familia y resumen de cada constante de x509.
func TestDescomponerFirma(t *testing.T) {
	casos := []struct {
		algoritmo     x509.SignatureAlgorithm
		familia, hash string
	}{
		{x509.MD2WithRSA, "RSA", "MD2"},
		{x509.MD5WithRSA, "RSA", "MD5"},
		{x509.SHA1WithRSA, "RSA", "SHA-1"},
		{x509.SHA256WithRSA, "RSA", "SHA-256"},
		{x509.SHA384WithRSA, "RSA", "SHA-384"},
		{x509.SHA512WithRSA, "RSA", "SHA-512"},
		{x509.SHA256WithRSAPSS, "RSA", "SHA-256"},
		{x509.SHA384WithRSAPSS, "RSA", "SHA-384"},
		{x509.SHA512WithRSAPSS, "RSA", "SHA-512"},
		{x509.ECDSAWithSHA1, "ECDSA", "SHA-1"},
		{x509.ECDSAWithSHA256, "ECDSA", "SHA-256"},
		{x509.ECDSAWithSHA384, "ECDSA", "SHA-384"},
		{x509.ECDSAWithSHA512, "ECDSA", "SHA-512"},
		{x509.PureEd25519, "Ed25519", ""}, // resumen no separable
		{x509.DSAWithSHA1, "DSA", "SHA-1"},
		{x509.DSAWithSHA256, "DSA", "SHA-256"},
		{x509.UnknownSignatureAlgorithm, x509.UnknownSignatureAlgorithm.String(), ""},
	}
	for _, c := range casos {
		familia, hash := DescomponerFirma(c.algoritmo)
		if familia != c.familia || hash != c.hash {
			t.Errorf("DescomponerFirma(%v) = %q, %q; se esperaba %q, %q",
				c.algoritmo, familia, hash, c.familia, c.hash)
		}
	}
}

// Cada rama de la clasificación de resúmenes, con el certificado como lo vería
// el operador (clave pública RSA): 3 hallazgos por certificado.
func TestAuditarClasificaElResumenDeLaFirma(t *testing.T) {
	casos := []struct {
		algoritmo x509.SignatureAlgorithm
		hash      string
		categoria securityv1alpha1.Categoria
		riesgo    string // con exposición baja y alcance bajo
	}{
		{x509.MD5WithRSA, "MD5", obsoleto, "Bajo (3)"},
		{x509.SHA1WithRSA, "SHA-1", obsoleto, "Bajo (3)"},
		{x509.SHA256WithRSA, "SHA-256", aceptable, "Bajo (1)"},
		{x509.SHA384WithRSA, "SHA-384", aceptable, "Bajo (1)"},
		{x509.SHA512WithRSA, "SHA-512", aceptable, "Bajo (1)"},
	}
	for _, c := range casos {
		cert := &x509.Certificate{PublicKeyAlgorithm: x509.RSA, SignatureAlgorithm: c.algoritmo}
		resultado, err := Auditar(cert, "baja", "bajo")
		if err != nil {
			t.Fatal(err)
		}
		esperado := []securityv1alpha1.Hallazgo{
			{Algoritmo: "RSA", Origen: clave, Categoria: critico, RiesgoCombinado: "Medio (4)"},
			{Algoritmo: "RSA", Origen: firmaO, Categoria: critico, RiesgoCombinado: "Medio (4)"},
			{Algoritmo: c.hash, Origen: firmaO, Categoria: c.categoria, RiesgoCombinado: c.riesgo},
		}
		if !reflect.DeepEqual(resultado.Hallazgos, esperado) {
			t.Errorf("%v:\n  hallazgos = %+v\n  esperados = %+v", c.algoritmo, resultado.Hallazgos, esperado)
		}
		if resultado.RiesgoGlobal != "Medio" { // el peor caso es la familia (Medio), no el hash
			t.Errorf("%v: RiesgoGlobal = %q, se esperaba \"Medio\"", c.algoritmo, resultado.RiesgoGlobal)
		}
	}
}

// Certificados reales generados en el test: la firma que elige Go para cada clave.
func TestAuditarCertificadosReales(t *testing.T) {
	rsaClave, _ := rsa.GenerateKey(rand.Reader, 2048)
	ec256, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	ec384, _ := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	_, edClave, _ := ed25519.GenerateKey(rand.Reader)

	casos := []struct {
		nombre    string
		clave     crypto.Signer
		hallazgos []securityv1alpha1.Hallazgo
		global    string
	}{
		{"RSA con SHA-256", rsaClave, []securityv1alpha1.Hallazgo{
			{Algoritmo: "RSA", Origen: clave, Categoria: critico, RiesgoCombinado: "Urgente (16)"},
			{Algoritmo: "RSA", Origen: firmaO, Categoria: critico, RiesgoCombinado: "Urgente (16)"},
			{Algoritmo: "SHA-256", Origen: firmaO, Categoria: aceptable, RiesgoCombinado: "Medio (4)"},
		}, "Crítico"},
		{"ECDSA P-256 con SHA-256", ec256, []securityv1alpha1.Hallazgo{
			{Algoritmo: "ECDSA", Origen: clave, Categoria: critico, RiesgoCombinado: "Urgente (16)"},
			{Algoritmo: "ECDSA", Origen: firmaO, Categoria: critico, RiesgoCombinado: "Urgente (16)"},
			{Algoritmo: "SHA-256", Origen: firmaO, Categoria: aceptable, RiesgoCombinado: "Medio (4)"},
		}, "Crítico"},
		{"ECDSA P-384 con SHA-384", ec384, []securityv1alpha1.Hallazgo{
			{Algoritmo: "ECDSA", Origen: clave, Categoria: critico, RiesgoCombinado: "Urgente (16)"},
			{Algoritmo: "ECDSA", Origen: firmaO, Categoria: critico, RiesgoCombinado: "Urgente (16)"},
			{Algoritmo: "SHA-384", Origen: firmaO, Categoria: aceptable, RiesgoCombinado: "Medio (4)"},
		}, "Crítico"},
		{"Ed25519 sin resumen separable", edClave, []securityv1alpha1.Hallazgo{
			{Algoritmo: "Ed25519", Origen: clave, Categoria: critico, RiesgoCombinado: "Urgente (16)"},
			{Algoritmo: "Ed25519", Origen: firmaO, Categoria: critico, RiesgoCombinado: "Urgente (16)"},
		}, "Crítico"},
	}
	for _, c := range casos {
		t.Run(c.nombre, func(t *testing.T) {
			resultado, err := Auditar(autofirmado(t, c.clave), "alta", "alto")
			if err != nil {
				t.Fatal(err)
			}
			if len(resultado.SinRegla) != 0 {
				t.Errorf("no debería haber algoritmos sin regla: %v", resultado.SinRegla)
			}
			if !reflect.DeepEqual(resultado.Hallazgos, c.hallazgos) {
				t.Errorf("hallazgos = %+v\nesperados = %+v", resultado.Hallazgos, c.hallazgos)
			}
			if resultado.RiesgoGlobal != c.global {
				t.Errorf("RiesgoGlobal = %q, se esperaba %q", resultado.RiesgoGlobal, c.global)
			}
		})
	}
}

// El riesgo global sigue siendo el peor caso con los nuevos hallazgos: si la
// familia no tiene regla, lo marca el resumen (SHA-1, Obsoleto × alta × alto =
// Urgente -> Crítico).
func TestRiesgoGlobalConHallazgosDeResumen(t *testing.T) {
	cert := &x509.Certificate{PublicKeyAlgorithm: x509.DSA, SignatureAlgorithm: x509.DSAWithSHA1}
	resultado, err := Auditar(cert, "alta", "alto")
	if err != nil {
		t.Fatal(err)
	}
	esperado := []securityv1alpha1.Hallazgo{
		{Algoritmo: "SHA-1", Origen: firmaO, Categoria: obsoleto, RiesgoCombinado: "Urgente (12)"},
	}
	if !reflect.DeepEqual(resultado.Hallazgos, esperado) {
		t.Errorf("hallazgos = %+v, esperados %+v", resultado.Hallazgos, esperado)
	}
	if !reflect.DeepEqual(resultado.SinRegla, []string{"DSA", "DSA"}) {
		t.Errorf("SinRegla = %v", resultado.SinRegla)
	}
	if resultado.RiesgoGlobal != "Crítico" {
		t.Errorf("RiesgoGlobal = %q, se esperaba \"Crítico\"", resultado.RiesgoGlobal)
	}
}

func TestAlgoritmosSinReglaNoInventanCategoriaNiRiesgo(t *testing.T) {
	casos := []struct {
		nombre   string
		cert     *x509.Certificate
		sinRegla []string
	}{
		{"familias desconocidas", &x509.Certificate{
			PublicKeyAlgorithm: x509.UnknownPublicKeyAlgorithm,
			SignatureAlgorithm: x509.UnknownSignatureAlgorithm,
		}, []string{x509.UnknownPublicKeyAlgorithm.String(), x509.UnknownSignatureAlgorithm.String()}},
		{"resumen MD2 sin regla", &x509.Certificate{
			PublicKeyAlgorithm: x509.DSA,
			SignatureAlgorithm: x509.MD2WithRSA,
		}, []string{"DSA", "MD2"}},
	}
	for _, c := range casos {
		resultado, err := Auditar(c.cert, "alta", "alto")
		if err != nil {
			t.Fatal(err)
		}
		for _, h := range resultado.Hallazgos {
			if h.Algoritmo == "MD2" || h.Algoritmo == x509.UnknownSignatureAlgorithm.String() {
				t.Errorf("%s: un algoritmo sin regla no debe ser hallazgo: %+v", c.nombre, h)
			}
		}
		if !reflect.DeepEqual(resultado.SinRegla, c.sinRegla) {
			t.Errorf("%s: SinRegla = %v, se esperaba %v", c.nombre, resultado.SinRegla, c.sinRegla)
		}
	}
	vacio, _ := Auditar(casos[0].cert, "alta", "alto")
	if len(vacio.Hallazgos) != 0 || vacio.RiesgoGlobal != "" {
		t.Errorf("sin hallazgos, el riesgo global debe quedar vacío: %+v", vacio)
	}
}

func TestAuditarPropagaElErrorDeUnaExposicionNoValida(t *testing.T) {
	cert := &x509.Certificate{PublicKeyAlgorithm: x509.RSA, SignatureAlgorithm: x509.SHA256WithRSA}
	if _, err := Auditar(cert, "media", "alto"); err == nil {
		t.Error("una exposición no válida debería dar error")
	}
}
