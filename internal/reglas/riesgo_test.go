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
	"testing"

	securityv1alpha1 "github.com/fizsar/quantum-ready-operator/api/v1alpha1"
)

// Los mismos límites que test_umbrales de la Fase 1 (tests/test_reglas.py).
func TestNivelDeEnLosLimitesDeCadaUmbral(t *testing.T) {
	casos := []struct {
		puntuacion int
		nivel      string
	}{
		{0, NivelNinguno},
		{1, NivelBajo}, {3, NivelBajo},
		{4, NivelMedio}, {7, NivelMedio},
		{8, NivelAlto}, {11, NivelAlto},
		{12, NivelUrgente}, {16, NivelUrgente},
	}
	for _, c := range casos {
		nivel, err := NivelDe(c.puntuacion)
		if err != nil || nivel != c.nivel {
			t.Errorf("NivelDe(%d) = %q, %v; se esperaba %q", c.puntuacion, nivel, err, c.nivel)
		}
	}
	for _, fuera := range []int{-1, 17} {
		if _, err := NivelDe(fuera); err == nil {
			t.Errorf("NivelDe(%d) debería dar error", fuera)
		}
	}
}

// Al menos un caso real (categoría × exposición × alcance) por cada nivel, los
// mismos que test_riesgo de la Fase 1.
func TestRiesgoCombinadoUnCasoPorNivel(t *testing.T) {
	casos := []struct {
		categoria  securityv1alpha1.Categoria
		exposicion securityv1alpha1.Exposicion
		alcance    securityv1alpha1.Alcance
		esperado   string
	}{
		{securityv1alpha1.CategoriaPostCuantico, "alta", "alto", "Ninguno (0)"},
		{securityv1alpha1.CategoriaAceptable, "baja", "bajo", "Bajo (1)"},
		{securityv1alpha1.CategoriaAdvertencia, "baja", "bajo", "Bajo (2)"},
		{securityv1alpha1.CategoriaObsoleto, "baja", "bajo", "Bajo (3)"},
		{securityv1alpha1.CategoriaCritico, "baja", "bajo", "Medio (4)"},
		{securityv1alpha1.CategoriaAceptable, "alta", "alto", "Medio (4)"},
		{securityv1alpha1.CategoriaObsoleto, "alta", "bajo", "Medio (6)"},
		{securityv1alpha1.CategoriaCritico, "alta", "bajo", "Alto (8)"},
		{securityv1alpha1.CategoriaCritico, "baja", "alto", "Alto (8)"},
		{securityv1alpha1.CategoriaAdvertencia, "alta", "alto", "Alto (8)"},
		{securityv1alpha1.CategoriaObsoleto, "alta", "alto", "Urgente (12)"},
		{securityv1alpha1.CategoriaCritico, "alta", "alto", "Urgente (16)"},
	}
	for _, c := range casos {
		riesgo, err := RiesgoCombinado(c.categoria, c.exposicion, c.alcance)
		if err != nil || riesgo.String() != c.esperado {
			t.Errorf("RiesgoCombinado(%s, %s, %s) = %q, %v; se esperaba %q",
				c.categoria, c.exposicion, c.alcance, riesgo, err, c.esperado)
		}
	}
}

func TestRiesgoCombinadoRechazaValoresDesconocidos(t *testing.T) {
	if _, err := RiesgoCombinado(securityv1alpha1.CategoriaCritico, "media", "alto"); err == nil {
		t.Error("una exposición desconocida debería dar error, no un riesgo inventado")
	}
	if _, err := RiesgoCombinado("Inventada", "alta", "alto"); err == nil {
		t.Error("una categoría desconocida debería dar error")
	}
}

// La regla del peor caso de la Fase 4 (test_riesgo_global en tests/test_informe.py).
func TestRiesgoGlobalReglaDelPeorCaso(t *testing.T) {
	casos := []struct {
		niveles  []string
		esperado string
	}{
		{[]string{NivelUrgente}, GlobalCritico},
		{[]string{NivelBajo, NivelAlto, NivelMedio}, GlobalAlto}, // ningún Urgente, sí Alto
		{[]string{NivelMedio, NivelBajo}, GlobalMedio},
		{[]string{NivelBajo, NivelNinguno}, GlobalBajo},
		{[]string{NivelNinguno, NivelBajo, NivelMedio, NivelAlto, NivelUrgente}, GlobalCritico},
		{nil, ""}, // sin hallazgos (algoritmos sin regla): no se inventa "Bajo"
	}
	for _, c := range casos {
		if got := RiesgoGlobal(c.niveles); got != c.esperado {
			t.Errorf("RiesgoGlobal(%v) = %q, se esperaba %q", c.niveles, got, c.esperado)
		}
	}
}
