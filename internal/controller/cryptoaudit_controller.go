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
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"strings"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/builder"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/handler"
	logf "sigs.k8s.io/controller-runtime/pkg/log"
	"sigs.k8s.io/controller-runtime/pkg/predicate"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"

	securityv1alpha1 "github.com/fizsar/quantum-ready-operator/api/v1alpha1"
	"github.com/fizsar/quantum-ready-operator/internal/reglas"
)

const (
	// CondicionAuditado indica si el certificado del Secret se ha podido auditar.
	CondicionAuditado = "Auditado"

	RazonAuditoriaCompletada = "AuditoriaCompletada"
	RazonSecretNoEncontrado  = "SecretNoEncontrado"
	RazonTipoDeSecret        = "TipoDeSecretIncorrecto"
	RazonCertificadoNoValido = "CertificadoNoValido"
	RazonSpecNoValido        = "SpecNoValido"

	// IndiceSecret indexa cada CryptoAudit por el Secret que audita
	// ("namespace/nombre"), para encontrar rápido a quién afecta un Secret.
	IndiceSecret = ".spec.targetRef"
)

// CryptoAuditReconciler reconciles a CryptoAudit object
type CryptoAuditReconciler struct {
	client.Client
	Scheme *runtime.Scheme

	// LectorAPI lee los Secrets directamente del API server. El watch de
	// Secrets solo guarda metadatos en caché: su contenido (certificados y
	// claves privadas) se lee aquí, bajo demanda, y nunca queda en memoria.
	LectorAPI client.Reader
}

// +kubebuilder:rbac:groups=security.fizsar.github.io,resources=cryptoaudits,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups=security.fizsar.github.io,resources=cryptoaudits/status,verbs=get;update;patch
// +kubebuilder:rbac:groups=security.fizsar.github.io,resources=cryptoaudits/finalizers,verbs=update
// +kubebuilder:rbac:groups="",resources=secrets,verbs=get;list;watch

// Reconcile audita el certificado del Secret referenciado por un CryptoAudit
// y escribe el resultado en su status.
func (r *CryptoAuditReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	log := logf.FromContext(ctx)

	var auditoria securityv1alpha1.CryptoAudit
	if err := r.Get(ctx, req.NamespacedName, &auditoria); err != nil {
		return ctrl.Result{}, client.IgnoreNotFound(err)
	}

	clave := secretDe(&auditoria)

	var secret corev1.Secret
	if err := r.lector().Get(ctx, clave, &secret); err != nil {
		if apierrors.IsNotFound(err) {
			return r.fallo(ctx, &auditoria, RazonSecretNoEncontrado,
				fmt.Sprintf("no existe el Secret %s", clave))
		}
		return ctrl.Result{}, err // error transitorio: controller-runtime reintenta
	}
	if secret.Type != corev1.SecretTypeTLS {
		return r.fallo(ctx, &auditoria, RazonTipoDeSecret,
			fmt.Sprintf("el Secret %s es de tipo %q; se esperaba %q", clave, secret.Type, corev1.SecretTypeTLS))
	}
	cert, err := primerCertificado(secret.Data[corev1.TLSCertKey])
	if err != nil {
		return r.fallo(ctx, &auditoria, RazonCertificadoNoValido,
			fmt.Sprintf("%s del Secret %s: %v", corev1.TLSCertKey, clave, err))
	}

	resultado, err := reglas.Auditar(cert, auditoria.Spec.Exposicion, auditoria.Spec.Alcance)
	if err != nil {
		// El esquema del CRD ya limita exposición y alcance: no debería ocurrir.
		return r.fallo(ctx, &auditoria, RazonSpecNoValido, err.Error())
	}
	auditoria.Status.Hallazgos = resultado.Hallazgos
	auditoria.Status.RiesgoGlobal = resultado.RiesgoGlobal
	auditoria.Status.UltimaAuditoria = metav1.Now()
	mensaje := fmt.Sprintf("certificado %q del Secret %s: %d hallazgos",
		cert.Subject.CommonName, clave, len(resultado.Hallazgos))
	if len(resultado.SinRegla) > 0 {
		mensaje += "; algoritmos sin regla todavía: " + strings.Join(resultado.SinRegla, ", ")
	}
	meta.SetStatusCondition(&auditoria.Status.Conditions, metav1.Condition{
		Type:               CondicionAuditado,
		Status:             metav1.ConditionTrue,
		Reason:             RazonAuditoriaCompletada,
		Message:            mensaje,
		ObservedGeneration: auditoria.Generation,
	})
	if err := r.Status().Update(ctx, &auditoria); err != nil {
		return ctrl.Result{}, err
	}
	log.Info("auditoría completada", "secret", clave.String(),
		"riesgoGlobal", auditoria.Status.RiesgoGlobal, "hallazgos", len(resultado.Hallazgos))
	return ctrl.Result{}, nil
}

// fallo deja constancia en una Condition de por qué no se pudo auditar, sin
// devolver error: el operador sigue funcionando. No hace falta reintentar por
// temporizador: el watch de Secrets vuelve a disparar la auditoría en cuanto
// el Secret aparece, cambia o se borra.
func (r *CryptoAuditReconciler) fallo(ctx context.Context, auditoria *securityv1alpha1.CryptoAudit,
	razon, mensaje string) (ctrl.Result, error) {
	logf.FromContext(ctx).Info("auditoría no realizada", "razon", razon, "detalle", mensaje)
	// Los hallazgos anteriores ya no describen el Secret actual: se retiran.
	// UltimaAuditoria conserva la fecha de la última auditoría completada.
	auditoria.Status.Hallazgos = nil
	auditoria.Status.RiesgoGlobal = ""
	meta.SetStatusCondition(&auditoria.Status.Conditions, metav1.Condition{
		Type:               CondicionAuditado,
		Status:             metav1.ConditionFalse,
		Reason:             razon,
		Message:            mensaje,
		ObservedGeneration: auditoria.Generation,
	})
	if err := r.Status().Update(ctx, auditoria); err != nil {
		return ctrl.Result{}, err
	}
	return ctrl.Result{}, nil
}

func (r *CryptoAuditReconciler) lector() client.Reader {
	if r.LectorAPI != nil {
		return r.LectorAPI
	}
	return r.Client
}

// primerCertificado devuelve el primer certificado PEM (el del servidor; el
// resto de la cadena todavía no se audita).
func primerCertificado(datos []byte) (*x509.Certificate, error) {
	if len(datos) == 0 {
		return nil, errors.New("vacío")
	}
	for resto := datos; ; {
		var bloque *pem.Block
		bloque, resto = pem.Decode(resto)
		if bloque == nil {
			return nil, errors.New("no contiene ningún bloque PEM CERTIFICATE")
		}
		if bloque.Type == "CERTIFICATE" {
			return x509.ParseCertificate(bloque.Bytes)
		}
	}
}

// secretDe devuelve el Secret que audita un CryptoAudit (por defecto, en su
// mismo namespace).
func secretDe(a *securityv1alpha1.CryptoAudit) types.NamespacedName {
	namespace := a.Spec.TargetRef.Namespace
	if namespace == "" {
		namespace = a.Namespace
	}
	return types.NamespacedName{Namespace: namespace, Name: a.Spec.TargetRef.Name}
}

// valorIndiceSecret es la función del índice IndiceSecret.
func valorIndiceSecret(obj client.Object) []string {
	a, ok := obj.(*securityv1alpha1.CryptoAudit)
	if !ok {
		return nil
	}
	return []string{secretDe(a).String()}
}

// auditoriasDelSecret traduce un evento de un Secret (alta, cambio o borrado)
// en peticiones de reconciliación para los CryptoAudit que lo referencian.
func (r *CryptoAuditReconciler) auditoriasDelSecret(ctx context.Context, secret client.Object) []reconcile.Request {
	clave := types.NamespacedName{Namespace: secret.GetNamespace(), Name: secret.GetName()}
	var auditorias securityv1alpha1.CryptoAuditList
	if err := r.List(ctx, &auditorias, client.MatchingFields{IndiceSecret: clave.String()}); err != nil {
		logf.FromContext(ctx).Error(err, "no se pudieron buscar los CryptoAudit del Secret", "secret", clave.String())
		return nil
	}
	peticiones := make([]reconcile.Request, 0, len(auditorias.Items))
	for _, a := range auditorias.Items {
		peticiones = append(peticiones, reconcile.Request{
			NamespacedName: types.NamespacedName{Namespace: a.Namespace, Name: a.Name},
		})
	}
	return peticiones
}

// SetupWithManager sets up the controller with the Manager.
func (r *CryptoAuditReconciler) SetupWithManager(mgr ctrl.Manager) error {
	if err := mgr.GetFieldIndexer().IndexField(context.Background(), &securityv1alpha1.CryptoAudit{},
		IndiceSecret, valorIndiceSecret); err != nil {
		return err
	}
	return ctrl.NewControllerManagedBy(mgr).
		// Solo cambios de spec (metadata.generation): cada actualización de
		// status genera un evento, y sin este filtro la propia escritura de
		// UltimaAuditoria volvería a disparar la reconciliación en bucle.
		For(&securityv1alpha1.CryptoAudit{}, builder.WithPredicates(predicate.GenerationChangedPredicate{})).
		// Cualquier alta, cambio o borrado de un Secret vuelve a auditar los
		// CryptoAudit que lo referencian. Solo se vigilan sus metadatos: un
		// cambio de contenido cambia resourceVersion y basta para el evento, y
		// la caché nunca guarda certificados ni claves privadas.
		Watches(&corev1.Secret{}, handler.EnqueueRequestsFromMapFunc(r.auditoriasDelSecret), builder.OnlyMetadata).
		Named("cryptoaudit").
		Complete(r)
}
