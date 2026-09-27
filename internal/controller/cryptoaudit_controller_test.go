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

package controller

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"

	securityv1alpha1 "github.com/fizsar/quantum-ready-operator/api/v1alpha1"
)

// certificadoRSA devuelve un certificado autofirmado RSA-2048 y su clave, en PEM.
func certificadoRSA() (certPEM, clavePEM []byte) {
	privada, err := rsa.GenerateKey(rand.Reader, 2048)
	Expect(err).NotTo(HaveOccurred())
	plantilla := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "web.prueba"},
		NotBefore:    time.Now(),
		NotAfter:     time.Now().Add(time.Hour),
	}
	der, err := x509.CreateCertificate(rand.Reader, plantilla, plantilla, &privada.PublicKey, privada)
	Expect(err).NotTo(HaveOccurred())
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}),
		pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(privada)})
}

var _ = Describe("CryptoAudit Controller", func() {
	const namespace = "default"
	ctx := context.Background()

	reconciliar := func(nombre string) (reconcile.Result, *securityv1alpha1.CryptoAudit) {
		r := &CryptoAuditReconciler{Client: k8sClient, Scheme: k8sClient.Scheme()}
		clave := types.NamespacedName{Name: nombre, Namespace: namespace}
		resultado, err := r.Reconcile(ctx, reconcile.Request{NamespacedName: clave})
		Expect(err).NotTo(HaveOccurred()) // los fallos de auditoría no son errores del operador
		auditoria := &securityv1alpha1.CryptoAudit{}
		Expect(k8sClient.Get(ctx, clave, auditoria)).To(Succeed())
		return resultado, auditoria
	}

	crearAuditoria := func(nombre, secret string) {
		Expect(k8sClient.Create(ctx, &securityv1alpha1.CryptoAudit{
			ObjectMeta: metav1.ObjectMeta{Name: nombre, Namespace: namespace},
			Spec: securityv1alpha1.CryptoAuditSpec{
				TargetRef:  securityv1alpha1.ReferenciaSecret{Name: secret},
				Exposicion: "alta",
				Alcance:    "bajo",
			},
		})).To(Succeed())
	}

	// borrar elimina los objetos creados por un test (los que no existan se ignoran).
	borrar := func(objetos ...client.Object) {
		for _, obj := range objetos {
			Expect(client.IgnoreNotFound(k8sClient.Delete(ctx, obj))).To(Succeed())
		}
	}
	auditoria := func(nombre string) client.Object {
		return &securityv1alpha1.CryptoAudit{ObjectMeta: metav1.ObjectMeta{Name: nombre, Namespace: namespace}}
	}
	secret := func(nombre string) client.Object {
		return &corev1.Secret{ObjectMeta: metav1.ObjectMeta{Name: nombre, Namespace: namespace}}
	}

	It("audita el certificado de un Secret TLS y escribe el status", func() {
		cert, clave := certificadoRSA()
		Expect(k8sClient.Create(ctx, &corev1.Secret{
			ObjectMeta: metav1.ObjectMeta{Name: "web-tls", Namespace: namespace},
			Type:       corev1.SecretTypeTLS,
			Data:       map[string][]byte{corev1.TLSCertKey: cert, corev1.TLSPrivateKeyKey: clave},
		})).To(Succeed())
		crearAuditoria("web", "web-tls")
		DeferCleanup(borrar, auditoria("web"), secret("web-tls"))

		resultado, a := reconciliar("web")

		Expect(resultado.RequeueAfter).To(BeZero())
		Expect(a.Status.Hallazgos).To(Equal([]securityv1alpha1.Hallazgo{
			{Algoritmo: "RSA", Origen: securityv1alpha1.OrigenClavePublica, Categoria: securityv1alpha1.CategoriaCritico},
			{Algoritmo: "RSA", Origen: securityv1alpha1.OrigenFirma, Categoria: securityv1alpha1.CategoriaCritico},
		}))
		Expect(a.Status.RiesgoGlobal).To(Equal("Crítico"))
		Expect(a.Status.UltimaAuditoria.IsZero()).To(BeFalse())
		condicion := meta.FindStatusCondition(a.Status.Conditions, CondicionAuditado)
		Expect(condicion).NotTo(BeNil())
		Expect(condicion.Status).To(Equal(metav1.ConditionTrue))
		Expect(condicion.Reason).To(Equal(RazonAuditoriaCompletada))
	})

	It("deja una Condition de error si el Secret no existe, sin fallar", func() {
		crearAuditoria("ausente", "no-existe")
		DeferCleanup(borrar, auditoria("ausente"))

		resultado, a := reconciliar("ausente")

		Expect(resultado.RequeueAfter).To(Equal(reintentoTrasFallo))
		Expect(a.Status.Hallazgos).To(BeEmpty())
		condicion := meta.FindStatusCondition(a.Status.Conditions, CondicionAuditado)
		Expect(condicion).NotTo(BeNil())
		Expect(condicion.Status).To(Equal(metav1.ConditionFalse))
		Expect(condicion.Reason).To(Equal(RazonSecretNoEncontrado))
	})

	It("rechaza un Secret que no es de tipo kubernetes.io/tls", func() {
		Expect(k8sClient.Create(ctx, &corev1.Secret{
			ObjectMeta: metav1.ObjectMeta{Name: "opaco", Namespace: namespace},
			Data:       map[string][]byte{"clave": []byte("valor")},
		})).To(Succeed())
		crearAuditoria("opaco", "opaco")
		DeferCleanup(borrar, auditoria("opaco"), secret("opaco"))

		_, a := reconciliar("opaco")

		condicion := meta.FindStatusCondition(a.Status.Conditions, CondicionAuditado)
		Expect(condicion).NotTo(BeNil())
		Expect(condicion.Status).To(Equal(metav1.ConditionFalse))
		Expect(condicion.Reason).To(Equal(RazonTipoDeSecret))
	})
})
