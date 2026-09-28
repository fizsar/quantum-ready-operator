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

// Package reglas es el equivalente en Go de una parte del libro de reglas de
// la Fase 1 (quantum_ready/reglas.py y riesgo.py del proyecto QuantumReady):
// las familias RSA, ECDSA y Ed25519 y los resúmenes (hash) de las firmas.
package reglas

import (
	"crypto/x509"

	securityv1alpha1 "github.com/fizsar/quantum-ready-operator/api/v1alpha1"
)

// Regla es la clasificación de un algoritmo, el motivo y quién lo resuelve.
type Regla struct {
	Categoria securityv1alpha1.Categoria
	Motivo    string
	// Remedio es "" si el algoritmo no necesita remedio (Aceptable).
	Remedio securityv1alpha1.TipoRemedio
}

const (
	critico             = securityv1alpha1.CategoriaCritico
	obsoleto            = securityv1alpha1.CategoriaObsoleto
	aceptable           = securityv1alpha1.CategoriaAceptable
	corregibleHoy       = securityv1alpha1.RemedioCorregibleHoy
	pendienteEcosistema = securityv1alpha1.RemedioPendienteEcosistema
)

// Tabla contiene las reglas disponibles, con las mismas categorías y motivos
// que la Fase 1. El remedio sigue el reparto de la Fase 4: en un certificado,
// tanto la clave pública como la firma sirven para autenticar (firmar), no
// para intercambiar claves, así que RSA, ECDSA y Ed25519 esperan a ML-DSA /
// SLH-DSA (pendiente_ecosistema) y ninguno es migracion_disponible.
var Tabla = map[string]Regla{
	// Familias de clave pública y de firma: rotas por Shor
	"RSA":     {critico, "Roto por Shor (factorización de enteros).", pendienteEcosistema},
	"ECDSA":   {critico, "Roto por Shor (logaritmo discreto en curvas elípticas).", pendienteEcosistema},
	"Ed25519": {critico, "Roto por Shor (logaritmo discreto en curvas elípticas).", pendienteEcosistema},
	// Resúmenes (hash) de la firma: los rotos se corrigen hoy reemitiendo el certificado
	"MD5":     {obsoleto, "Colisiones prácticas desde 2004.", corregibleHoy},
	"SHA-1":   {obsoleto, "Colisión práctica demostrada (SHAttered, 2017).", corregibleHoy},
	"SHA-256": {aceptable, "Grover lo deja en 128 bits efectivos, suficiente hoy.", ""},
	"SHA-384": {aceptable, "Margen amplio incluso frente a Grover.", ""},
	"SHA-512": {aceptable, "Margen amplio incluso frente a Grover.", ""},
}

// firma descompone un algoritmo de firma en su familia y su resumen.
type firma struct {
	familia string
	// hash es "" cuando el resumen forma parte del propio esquema de firma
	// (Ed25519) y no es un parámetro separable.
	hash string
}

// firmas asigna a cada x509.SignatureAlgorithm su familia y su resumen.
var firmas = map[x509.SignatureAlgorithm]firma{
	x509.MD2WithRSA:       {"RSA", "MD2"},
	x509.MD5WithRSA:       {"RSA", "MD5"},
	x509.SHA1WithRSA:      {"RSA", "SHA-1"},
	x509.SHA256WithRSA:    {"RSA", "SHA-256"},
	x509.SHA384WithRSA:    {"RSA", "SHA-384"},
	x509.SHA512WithRSA:    {"RSA", "SHA-512"},
	x509.SHA256WithRSAPSS: {"RSA", "SHA-256"},
	x509.SHA384WithRSAPSS: {"RSA", "SHA-384"},
	x509.SHA512WithRSAPSS: {"RSA", "SHA-512"},
	x509.ECDSAWithSHA1:    {"ECDSA", "SHA-1"},
	x509.ECDSAWithSHA256:  {"ECDSA", "SHA-256"},
	x509.ECDSAWithSHA384:  {"ECDSA", "SHA-384"},
	x509.ECDSAWithSHA512:  {"ECDSA", "SHA-512"},
	x509.PureEd25519:      {"Ed25519", ""},
	x509.DSAWithSHA1:      {"DSA", "SHA-1"},
	x509.DSAWithSHA256:    {"DSA", "SHA-256"},
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

// DescomponerFirma devuelve la familia y el resumen del algoritmo de firma.
// Un algoritmo que no está en la tabla devuelve su nombre como familia y
// ningún resumen.
func DescomponerFirma(algoritmo x509.SignatureAlgorithm) (familia, hash string) {
	if f, ok := firmas[algoritmo]; ok {
		return f.familia, f.hash
	}
	return algoritmo.String(), ""
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

// Auditar clasifica el certificado y calcula el riesgo combinado de cada
// hallazgo con la exposición y el alcance del servicio. Como en la Fase 1:
// la clave pública da un hallazgo (su familia) y la firma da dos (su familia
// y su resumen), salvo en Ed25519, cuyo resumen no es separable.
func Auditar(cert *x509.Certificate, exposicion securityv1alpha1.Exposicion,
	alcance securityv1alpha1.Alcance) (Resultado, error) {
	familiaFirma, hashFirma := DescomponerFirma(cert.SignatureAlgorithm)
	encontrados := []struct {
		algoritmo string
		origen    securityv1alpha1.Origen
	}{
		{AlgoritmoClavePublica(cert), securityv1alpha1.OrigenClavePublica},
		{familiaFirma, securityv1alpha1.OrigenFirma},
	}
	if hashFirma != "" {
		encontrados = append(encontrados, struct {
			algoritmo string
			origen    securityv1alpha1.Origen
		}{hashFirma, securityv1alpha1.OrigenFirma})
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
			TipoRemedio:     regla.Remedio,
		})
		niveles = append(niveles, riesgo.Nivel)
	}
	resultado.RiesgoGlobal = RiesgoGlobal(niveles)
	return resultado, nil
}
