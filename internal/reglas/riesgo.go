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
	"fmt"

	securityv1alpha1 "github.com/fizsar/quantum-ready-operator/api/v1alpha1"
)

// Modelo de riesgo combinado, el mismo que quantum_ready/riesgo.py (Fase 1),
// que también usa el informe ejecutivo de la Fase 4:
//
//	riesgo = peso de la categoría × peso de la exposición × peso del alcance   (0–16)

// pesos de cada categoría (PESOS_CATEGORIA en riesgo.py).
var pesos = map[securityv1alpha1.Categoria]int{
	securityv1alpha1.CategoriaCritico:      4,
	securityv1alpha1.CategoriaObsoleto:     3,
	securityv1alpha1.CategoriaAdvertencia:  2,
	securityv1alpha1.CategoriaAceptable:    1,
	securityv1alpha1.CategoriaPostCuantico: 0,
}

// PESOS_EXPOSICION y PESOS_ALCANCE en riesgo.py.
var (
	pesosExposicion = map[securityv1alpha1.Exposicion]int{"alta": 2, "baja": 1}
	pesosAlcance    = map[securityv1alpha1.Alcance]int{"alto": 2, "bajo": 1}
)

// Niveles de riesgo combinado.
const (
	NivelNinguno = "Ninguno"
	NivelBajo    = "Bajo"
	NivelMedio   = "Medio"
	NivelAlto    = "Alto"
	NivelUrgente = "Urgente"
)

// umbrales: puntuación máxima incluida en cada nivel (UMBRALES en riesgo.py).
var umbrales = []struct {
	maximo int
	nivel  string
}{
	{0, NivelNinguno},
	{3, NivelBajo},
	{7, NivelMedio},
	{11, NivelAlto},
	{16, NivelUrgente},
}

// NivelDe devuelve el nivel de una puntuación de 0 a 16.
func NivelDe(puntuacion int) (string, error) {
	for _, u := range umbrales {
		if puntuacion >= 0 && puntuacion <= u.maximo {
			return u.nivel, nil
		}
	}
	return "", fmt.Errorf("puntuación fuera de rango: %d", puntuacion)
}

// Riesgo es el riesgo combinado de un hallazgo.
type Riesgo struct {
	Puntuacion int
	Nivel      string
}

// String usa el mismo formato que el resumen de la Fase 1: "Urgente (16)".
func (r Riesgo) String() string {
	return fmt.Sprintf("%s (%d)", r.Nivel, r.Puntuacion)
}

// RiesgoCombinado = categoría × exposición × alcance. Devuelve error si algún
// valor no está en las tablas (el esquema del CRD ya impide exposición y
// alcance no válidos).
func RiesgoCombinado(categoria securityv1alpha1.Categoria, exposicion securityv1alpha1.Exposicion,
	alcance securityv1alpha1.Alcance) (Riesgo, error) {
	c, okC := pesos[categoria]
	e, okE := pesosExposicion[exposicion]
	a, okA := pesosAlcance[alcance]
	if !okC || !okE || !okA {
		return Riesgo{}, fmt.Errorf("no se puede calcular el riesgo de categoría %q, exposición %q y alcance %q",
			categoria, exposicion, alcance)
	}
	puntuacion := c * e * a
	nivel, err := NivelDe(puntuacion)
	if err != nil {
		return Riesgo{}, err
	}
	return Riesgo{puntuacion, nivel}, nil
}

// Niveles del riesgo global (riesgo_global en el generador de la Fase 4).
const (
	GlobalCritico = "Crítico"
	GlobalAlto    = "Alto"
	GlobalMedio   = "Medio"
	GlobalBajo    = "Bajo"
)

// RiesgoGlobal aplica la regla del peor caso de la Fase 4 sobre los niveles de
// riesgo combinado: algún Urgente -> Crítico; si no, algún Alto -> Alto; si
// no, algún Medio -> Medio; si no, Bajo.
//
// A diferencia de la Fase 4, sin hallazgos devuelve "" en lugar de "Bajo":
// aquí solo ocurre cuando los algoritmos del certificado no tienen regla, y
// "Bajo" daría a entender que se evaluaron.
func RiesgoGlobal(niveles []string) string {
	if len(niveles) == 0 {
		return ""
	}
	hay := map[string]bool{}
	for _, n := range niveles {
		hay[n] = true
	}
	switch {
	case hay[NivelUrgente]:
		return GlobalCritico
	case hay[NivelAlto]:
		return GlobalAlto
	case hay[NivelMedio]:
		return GlobalMedio
	default:
		return GlobalBajo
	}
}
