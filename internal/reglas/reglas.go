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

// Package reglas es el equivalente mínimo en Go del libro de reglas de la
// Fase 1 (quantum_ready/reglas.py y riesgo.py del proyecto QuantumReady). De
// momento solo clasifica RSA, ECDSA y Ed25519; el resto del libro se migrará
// más adelante.
package reglas

import (
	"crypto/x509"

	securityv1alpha1 "github.com/fizsar/quantum-ready-operator/api/v1alpha1"
)

// Regla es la clasificación de un algoritmo y el motivo.
type Regla struct {
	Categoria securityv1alpha1.Categoria
	Motivo    string
}

// Tabla contiene las reglas disponibles, con las mismas categorías y motivos
// que la Fase 1.
var Tabla = map[string]Regla{
	"RSA":     {securityv1alpha1.CategoriaCritico, "Roto por Shor (factorización de enteros)."},
	"ECDSA":   {securityv1alpha1.CategoriaCritico, "Roto por Shor (logaritmo discreto en curvas elípticas)."},
	"Ed25519": {securityv1alpha1.CategoriaCritico, "Roto por Shor (logaritmo discreto en curvas elípticas)."},
}

// AlgoritmoClavePublica devuelve la familia del algoritmo de la clave pública.
func AlgoritmoClavePublica(cert *x509.Certificate) string {
	switch cert.PublicKeyAlgorithm {
	case x509.RSA:
		return "RSA"
	case x509.ECDSA:
		return "ECDSA"
	case x509.Ed25519:
		return "Ed25519"
	default:
		return cert.PublicKeyAlgorithm.String()
	}
}

// AlgoritmoFirma devuelve la familia del algoritmo con el que se firmó el
// certificado. El hash de la firma (p. ej. SHA-1) todavía no se clasifica.
func AlgoritmoFirma(cert *x509.Certificate) string {
	switch cert.SignatureAlgorithm {
	case x509.MD2WithRSA, x509.MD5WithRSA, x509.SHA1WithRSA, x509.SHA256WithRSA,
		x509.SHA384WithRSA, x509.SHA512WithRSA, x509.SHA256WithRSAPSS,
		x509.SHA384WithRSAPSS, x509.SHA512WithRSAPSS:
		return "RSA"
	case x509.ECDSAWithSHA1, x509.ECDSAWithSHA256, x509.ECDSAWithSHA384, x509.ECDSAWithSHA512:
		return "ECDSA"
	case x509.PureEd25519:
		return "Ed25519"
	default:
		return cert.SignatureAlgorithm.String()
	}
}

// Resultado de auditar un certificado.
type Resultado struct {
	Hallazgos []securityv1alpha1.Hallazgo
	// RiesgoGlobal por la regla del peor caso sobre el riesgo combinado.
	RiesgoGlobal string
	// SinRegla son los algoritmos encontrados que la tabla todavía no
	// clasifica: se informa de ellos sin inventarles una categoría.
	SinRegla []string
}

// Auditar clasifica la clave pública y la firma del certificado y calcula el
// riesgo combinado de cada hallazgo con la exposición y el alcance del servicio.
func Auditar(cert *x509.Certificate, exposicion securityv1alpha1.Exposicion,
	alcance securityv1alpha1.Alcance) (Resultado, error) {
	encontrados := []struct {
		algoritmo string
		origen    securityv1alpha1.Origen
	}{
		{AlgoritmoClavePublica(cert), securityv1alpha1.OrigenClavePublica},
		{AlgoritmoFirma(cert), securityv1alpha1.OrigenFirma},
	}
	var resultado Resultado
	var niveles []string
	for _, e := range encontrados {
		regla, ok := Tabla[e.algoritmo]
		if !ok {
			resultado.SinRegla = append(resultado.SinRegla, e.algoritmo)
			continue
		}
		riesgo, err := RiesgoCombinado(regla.Categoria, exposicion, alcance)
		if err != nil {
			return Resultado{}, err
		}
		resultado.Hallazgos = append(resultado.Hallazgos, securityv1alpha1.Hallazgo{
			Algoritmo:       e.algoritmo,
			Origen:          e.origen,
			Categoria:       regla.Categoria,
			RiesgoCombinado: riesgo.String(),
		})
		niveles = append(niveles, riesgo.Nivel)
	}
	resultado.RiesgoGlobal = RiesgoGlobal(niveles)
	return resultado, nil
}
