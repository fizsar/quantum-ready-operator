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
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
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
	"k8s.io/client-go/kubernetes/scheme"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/cache"
	metricsserver "sigs.k8s.io/controller-runtime/pkg/metrics/server"

	securityv1alpha1 "github.com/fizsar/quantum-ready-operator/api/v1alpha1"
)

// certificadoPEM devuelve un certificado autofirmado con la clave dada y la
// clave en PKCS#8, ambos en PEM.
func certificadoPEM(privada crypto.Signer) (certPEM, clavePEM []byte) {
	plantilla := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()),
		Subject:      pkix.Name{CommonName: "watch.prueba"},
		NotBefore:    time.Now(),
		NotAfter:     time.Now().Add(time.Hour),
	}
	der, err := x509.CreateCertificate(rand.Reader, plantilla, plantilla, privada.Public(), privada)
	Expect(err).NotTo(HaveOccurred())
	pkcs8, err := x509.MarshalPKCS8PrivateKey(privada)
	Expect(err).NotTo(HaveOccurred())
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}),
		pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: pkcs8})
}

var _ = Describe("CryptoAudit Controller con el watch de Secrets", Ordered, func() {
	const (
		namespace = "watch"
		nombre    = "auditoria"
		secret    = "secret-vigilado"
		// "Casi al instante": el watch debe reaccionar en segundos, no en el
		// minuto del antiguo reintento por temporizador.
		plazo = 5 * time.Second
	)
	var cancelarManager context.CancelFunc
	claveAuditoria := types.NamespacedName{Namespace: namespace, Name: nombre}

	BeforeAll(func() {
		Expect(k8sClient.Create(ctx, &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: namespace}})).To(Succeed())
		// Manager real (índice + watch), limitado a su namespace para no
		// interferir con los tests que llaman a Reconcile en "default".
		mgr, err := ctrl.NewManager(cfg, ctrl.Options{
			Scheme:                 scheme.Scheme,
			Metrics:                metricsserver.Options{BindAddress: "0"},
			HealthProbeBindAddress: "0",
			Cache:                  cache.Options{DefaultNamespaces: map[string]cache.Config{namespace: {}}},
		})
		Expect(err).NotTo(HaveOccurred())
		Expect((&CryptoAuditReconciler{
			Client:    mgr.GetClient(),
			Scheme:    mgr.GetScheme(),
			LectorAPI: mgr.GetAPIReader(),
		}).SetupWithManager(mgr)).To(Succeed())
		var ctxManager context.Context
		ctxManager, cancelarManager = context.WithCancel(ctx)
		go func() {
			defer GinkgoRecover()
			Expect(mgr.Start(ctxManager)).To(Succeed())
		}()
	})

	AfterAll(func() {
		cancelarManager()
	})

	// condicion devuelve la Condition Auditado del CryptoAudit, o nil.
	condicion := func() *metav1.Condition {
		a := &securityv1alpha1.CryptoAudit{}
		if err := k8sClient.Get(ctx, claveAuditoria, a); err != nil {
			return nil
		}
		return meta.FindStatusCondition(a.Status.Conditions, CondicionAuditado)
	}
	razon := func() string {
		if c := condicion(); c != nil {
			return c.Reason
		}
		return ""
	}
	algoritmos := func() []string {
		a := &securityv1alpha1.CryptoAudit{}
		if err := k8sClient.Get(ctx, claveAuditoria, a); err != nil {
			return nil
		}
		var nombres []string
		for _, h := range a.Status.Hallazgos {
			nombres = append(nombres, h.Algoritmo)
		}
		return nombres
	}
	secretTLS := func(privada crypto.Signer) *corev1.Secret {
		cert, clave := certificadoPEM(privada)
		return &corev1.Secret{
			ObjectMeta: metav1.ObjectMeta{Name: secret, Namespace: namespace},
			Type:       corev1.SecretTypeTLS,
			Data:       map[string][]byte{corev1.TLSCertKey: cert, corev1.TLSPrivateKeyKey: clave},
		}
	}
	generacion := func() int64 {
		a := &securityv1alpha1.CryptoAudit{}
		Expect(k8sClient.Get(ctx, claveAuditoria, a)).To(Succeed())
		return a.Generation
	}

	It("sin el Secret, el CryptoAudit queda en SecretNoEncontrado", func() {
		Expect(k8sClient.Create(ctx, &securityv1alpha1.CryptoAudit{
			ObjectMeta: metav1.ObjectMeta{Name: nombre, Namespace: namespace},
			Spec: securityv1alpha1.CryptoAuditSpec{
				TargetRef:  securityv1alpha1.ReferenciaSecret{Name: secret},
				Exposicion: "alta",
				Alcance:    "alto",
			},
		})).To(Succeed())
		Eventually(razon, plazo, 50*time.Millisecond).Should(Equal(RazonSecretNoEncontrado))
	})

	It("al crear el Secret, se audita en segundos", func() {
		rsaClave, err := rsa.GenerateKey(rand.Reader, 2048)
		Expect(err).NotTo(HaveOccurred())
		Expect(k8sClient.Create(ctx, secretTLS(rsaClave))).To(Succeed())
		Eventually(razon, plazo, 50*time.Millisecond).Should(Equal(RazonAuditoriaCompletada))
		Expect(algoritmos()).To(Equal([]string{"RSA", "RSA", "SHA-256"}))
	})

	It("al cambiar el certificado del Secret, cambian los hallazgos sin tocar el CryptoAudit", func() {
		antes := generacion()
		ecClave, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		Expect(err).NotTo(HaveOccurred())
		actual := &corev1.Secret{}
		Expect(k8sClient.Get(ctx, types.NamespacedName{Namespace: namespace, Name: secret}, actual)).To(Succeed())
		actual.Data = secretTLS(ecClave).Data
		Expect(k8sClient.Update(ctx, actual)).To(Succeed())

		Eventually(algoritmos, plazo, 50*time.Millisecond).Should(Equal([]string{"ECDSA", "ECDSA", "SHA-256"}))
		Expect(generacion()).To(Equal(antes)) // el spec del CryptoAudit no ha cambiado
	})

	It("al borrar el Secret, pasa a SecretNoEncontrado en segundos", func() {
		Expect(k8sClient.Delete(ctx, &corev1.Secret{
			ObjectMeta: metav1.ObjectMeta{Name: secret, Namespace: namespace},
		})).To(Succeed())
		Eventually(razon, plazo, 50*time.Millisecond).Should(Equal(RazonSecretNoEncontrado))
		Expect(algoritmos()).To(BeEmpty())
		Expect(condicion().Status).To(Equal(metav1.ConditionFalse))
	})

	It("al recrear el Secret con el mismo nombre, vuelve a Auditado=True", func() {
		rsaClave, err := rsa.GenerateKey(rand.Reader, 2048)
		Expect(err).NotTo(HaveOccurred())
		Expect(k8sClient.Create(ctx, secretTLS(rsaClave))).To(Succeed())
		Eventually(razon, plazo, 50*time.Millisecond).Should(Equal(RazonAuditoriaCompletada))
		Expect(condicion().Status).To(Equal(metav1.ConditionTrue))
		Expect(algoritmos()).To(Equal([]string{"RSA", "RSA", "SHA-256"}))
	})
})

var _ = Describe("Índice de CryptoAudit por Secret", func() {
	It("usa el namespace del CryptoAudit si targetRef no indica otro", func() {
		a := &securityv1alpha1.CryptoAudit{ObjectMeta: metav1.ObjectMeta{Namespace: "equipo-a"}}
		a.Spec.TargetRef.Name = "web-tls"
		Expect(valorIndiceSecret(a)).To(Equal([]string{"equipo-a/web-tls"}))

		a.Spec.TargetRef.Namespace = "certificados"
		Expect(valorIndiceSecret(a)).To(Equal([]string{"certificados/web-tls"}))

		Expect(valorIndiceSecret(&corev1.Secret{})).To(BeNil())
	})
})
