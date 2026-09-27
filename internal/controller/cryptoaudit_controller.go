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
	"time"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/builder"
	"sigs.k8s.io/controller-runtime/pkg/client"
	logf "sigs.k8s.io/controller-runtime/pkg/log"
	"sigs.k8s.io/controller-runtime/pkg/predicate"

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

	// Todavía no se vigilan los Secrets: si falta o no es válido, se reintenta
	// periódicamente por si aparece o se corrige.
	reintentoTrasFallo = time.Minute
)

// CryptoAuditReconciler reconciles a CryptoAudit object
type CryptoAuditReconciler struct {
	client.Client
	Scheme *runtime.Scheme

	// LectorAPI lee los Secrets directamente del API server. El cliente con
	// caché empezaría a vigilar TODOS los Secrets del clúster (list/watch) al
	// pedir uno; así basta el permiso get y no se guardan secretos en memoria.
	LectorAPI client.Reader
}

// +kubebuilder:rbac:groups=security.fizsar.github.io,resources=cryptoaudits,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups=security.fizsar.github.io,resources=cryptoaudits/status,verbs=get;update;patch
// +kubebuilder:rbac:groups=security.fizsar.github.io,resources=cryptoaudits/finalizers,verbs=update
// +kubebuilder:rbac:groups="",resources=secrets,verbs=get

// Reconcile audita el certificado del Secret referenciado por un CryptoAudit
// y escribe el resultado en su status.
func (r *CryptoAuditReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	log := logf.FromContext(ctx)

	var auditoria securityv1alpha1.CryptoAudit
	if err := r.Get(ctx, req.NamespacedName, &auditoria); err != nil {
		return ctrl.Result{}, client.IgnoreNotFound(err)
	}

	ref := auditoria.Spec.TargetRef
	namespace := ref.Namespace
	if namespace == "" {
		namespace = auditoria.Namespace
	}
	clave := types.NamespacedName{Namespace: namespace, Name: ref.Name}

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

	hallazgos, sinRegla := reglas.Auditar(cert)
	auditoria.Status.Hallazgos = hallazgos
	auditoria.Status.RiesgoGlobal = string(reglas.PeorCaso(hallazgos))
	auditoria.Status.UltimaAuditoria = metav1.Now()
	mensaje := fmt.Sprintf("certificado %q del Secret %s: %d hallazgos",
		cert.Subject.CommonName, clave, len(hallazgos))
	if len(sinRegla) > 0 {
		mensaje += "; algoritmos sin regla todavía: " + strings.Join(sinRegla, ", ")
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
		"riesgoGlobal", auditoria.Status.RiesgoGlobal, "hallazgos", len(hallazgos))
	return ctrl.Result{}, nil
}

// fallo deja constancia en una Condition de por qué no se pudo auditar, sin
// devolver error: el operador sigue funcionando y vuelve a intentarlo.
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
	return ctrl.Result{RequeueAfter: reintentoTrasFallo}, nil
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

// SetupWithManager sets up the controller with the Manager.
func (r *CryptoAuditReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		// Solo cambios de spec (metadata.generation): cada actualización de
		// status genera un evento, y sin este filtro la propia escritura de
		// UltimaAuditoria volvería a disparar la reconciliación en bucle.
		For(&securityv1alpha1.CryptoAudit{}, builder.WithPredicates(predicate.GenerationChangedPredicate{})).
		Named("cryptoaudit").
		Complete(r)
}
