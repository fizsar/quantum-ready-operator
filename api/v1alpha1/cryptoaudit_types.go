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

package v1alpha1

import (
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
)

// ReferenciaSecret identifica el Secret de tipo kubernetes.io/tls que se audita.
type ReferenciaSecret struct {
	// name es el nombre del Secret.
	// +kubebuilder:validation:MinLength=1
	// +required
	Name string `json:"name"`

	// namespace del Secret. Si se omite, se usa el namespace del CryptoAudit.
	// +optional
	Namespace string `json:"namespace,omitempty"`
}

// Exposicion indica si el servicio que usa el Secret es accesible desde internet.
// +kubebuilder:validation:Enum=alta;baja
type Exposicion string

// Alcance indica si el servicio da acceso a toda la red o a varios sistemas.
// +kubebuilder:validation:Enum=alto;bajo
type Alcance string

// Categoria usa los mismos nombres que el libro de reglas de la Fase 1 (Python).
// +kubebuilder:validation:Enum=Crítico;Advertencia;Obsoleto;Aceptable;Post-cuántico
type Categoria string

const (
	CategoriaCritico      Categoria = "Crítico"
	CategoriaAdvertencia  Categoria = "Advertencia"
	CategoriaObsoleto     Categoria = "Obsoleto"
	CategoriaAceptable    Categoria = "Aceptable"
	CategoriaPostCuantico Categoria = "Post-cuántico"
)

// Origen indica de qué parte del certificado sale el algoritmo.
// +kubebuilder:validation:Enum=clavePublica;firma
type Origen string

const (
	OrigenClavePublica Origen = "clavePublica"
	OrigenFirma        Origen = "firma"
)

// CryptoAuditSpec define qué Secret auditar y el contexto del servicio que lo usa.
type CryptoAuditSpec struct {
	// targetRef es el Secret de tipo kubernetes.io/tls a auditar.
	// +required
	TargetRef ReferenciaSecret `json:"targetRef"`

	// exposicion del servicio: "alta" (accesible desde internet) o "baja" (solo red interna).
	// +required
	Exposicion Exposicion `json:"exposicion"`

	// alcance del servicio: "alto" (da acceso a toda la red o a varios sistemas) o "bajo".
	// +required
	Alcance Alcance `json:"alcance"`
}

// Hallazgo es un algoritmo encontrado en el certificado y su clasificación.
type Hallazgo struct {
	// algoritmo encontrado (RSA, ECDSA, Ed25519...).
	Algoritmo string `json:"algoritmo"`

	// origen: clave pública del certificado o algoritmo de su firma.
	Origen Origen `json:"origen"`

	// categoria según el libro de reglas.
	Categoria Categoria `json:"categoria"`

	// riesgoCombinado = categoría × exposición × alcance, como en la Fase 1.
	// TODO: todavía no se calcula; queda vacío.
	// +optional
	RiesgoCombinado string `json:"riesgoCombinado,omitempty"`
}

// CryptoAuditStatus es el resultado de la última auditoría.
type CryptoAuditStatus struct {
	// hallazgos de la última auditoría.
	// +optional
	Hallazgos []Hallazgo `json:"hallazgos,omitempty"`

	// riesgoGlobal por la regla del peor caso.
	// +optional
	RiesgoGlobal string `json:"riesgoGlobal,omitempty"`

	// ultimaAuditoria es cuándo se auditó el certificado por última vez.
	// +optional
	UltimaAuditoria metav1.Time `json:"ultimaAuditoria,omitzero"`

	// conditions represent the current state of the CryptoAudit resource.
	// Each condition has a unique type and reflects the status of a specific aspect of the resource.
	//
	// Standard condition types include:
	// - "Available": the resource is fully functional
	// - "Progressing": the resource is being created or updated
	// - "Degraded": the resource failed to reach or maintain its desired state
	//
	// The status of each condition is one of True, False, or Unknown.
	// +listType=map
	// +listMapKey=type
	// +optional
	Conditions []metav1.Condition `json:"conditions,omitempty"`
}

// +kubebuilder:object:root=true
// +kubebuilder:subresource:status
// +kubebuilder:printcolumn:name="Secret",type=string,JSONPath=`.spec.targetRef.name`
// +kubebuilder:printcolumn:name="Riesgo",type=string,JSONPath=`.status.riesgoGlobal`
// +kubebuilder:printcolumn:name="Auditado",type=string,JSONPath=`.status.conditions[?(@.type=="Auditado")].status`
// +kubebuilder:printcolumn:name="Ultima-Auditoria",type=date,JSONPath=`.status.ultimaAuditoria`

// CryptoAudit is the Schema for the cryptoaudits API
type CryptoAudit struct {
	metav1.TypeMeta `json:",inline"`

	// metadata is a standard object metadata
	// +optional
	metav1.ObjectMeta `json:"metadata,omitzero"`

	// spec defines the desired state of CryptoAudit
	// +required
	Spec CryptoAuditSpec `json:"spec"`

	// status defines the observed state of CryptoAudit
	// +optional
	Status CryptoAuditStatus `json:"status,omitzero"`
}

// +kubebuilder:object:root=true

// CryptoAuditList contains a list of CryptoAudit
type CryptoAuditList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitzero"`
	Items           []CryptoAudit `json:"items"`
}

func init() {
	SchemeBuilder.Register(func(s *runtime.Scheme) error {
		s.AddKnownTypes(SchemeGroupVersion, &CryptoAudit{}, &CryptoAuditList{})
		return nil
	})
}
