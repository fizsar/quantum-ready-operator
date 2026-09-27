# quantum-ready-operator

Operador de Kubernetes en Go que audita la cripto-agilidad de los Secrets TLS
del clúster: lee el certificado de cada Secret, identifica sus algoritmos y
señala los vulnerables: las familias que un ordenador cuántico podrá romper
(RSA, ECDSA y Ed25519) y los resúmenes de firma ya rotos (MD5 y SHA-1).

## Contexto

Es la Fase 6 de [QuantumReady](https://github.com/fizsar/QuantumReady), un
proyecto que empezó como escáner de archivos de configuración (Fase 1) y
evolucionó hacia la auditoría continua dentro del propio clúster de
Kubernetes. La clasificación de los algoritmos sigue el libro de reglas de la
Fase 1: mismas categorías (Crítico, Obsoleto, Advertencia, Aceptable,
Post-cuántico) y mismos motivos.

## Cómo funciona

Cada auditoría es un recurso `CryptoAudit` (grupo `security.fizsar.github.io`,
versión `v1alpha1`) que apunta a un Secret de tipo `kubernetes.io/tls`:

```yaml
apiVersion: security.fizsar.github.io/v1alpha1
kind: CryptoAudit
metadata:
  name: web
spec:
  targetRef:
    name: web-rsa-tls        # namespace opcional; por defecto, el del CryptoAudit
  exposicion: alta           # alta | baja
  alcance: bajo              # alto | bajo
```

El operador lee el Secret, extrae el certificado de `tls.crt` con
`crypto/x509`, clasifica el algoritmo de su clave pública y, de su firma, la
familia y el resumen (hash), y escribe el resultado en `status`: los hallazgos, el riesgo global, la fecha de
la auditoría y una condición `Auditado`.

### Qué reconoce

Igual que el analizador de certificados de la Fase 1, la clave pública da un
hallazgo y la firma da dos (familia y resumen):

| Origen | Algoritmos | Categoría |
|---|---|---|
| Clave pública | RSA, ECDSA, Ed25519 | Crítico (rotos por Shor) |
| Firma: familia | RSA, ECDSA, Ed25519 | Crítico (rotos por Shor) |
| Firma: resumen | MD5, SHA-1 | Obsoleto (colisiones prácticas) |
| Firma: resumen | SHA-256, SHA-384, SHA-512 | Aceptable |

Ed25519 no tiene un resumen separable (forma parte del propio esquema de
firma), así que solo da el hallazgo de familia. La familia y el resumen salen
de la constante `x509.SignatureAlgorithm`, sin analizar cadenas de texto. Los
algoritmos sin regla no se convierten en hallazgos: se mencionan en la
condición `Auditado`, sin inventarles una categoría.

### Riesgo

Cada hallazgo lleva su **riesgo combinado**, con el mismo modelo que la Fase 1:
peso de la categoría (Crítico 4, Obsoleto 3, Advertencia 2, Aceptable 1,
Post-cuántico 0) × exposición (alta 2, baja 1) × alcance (alto 2, bajo 1), de 0 a
16, con los niveles Ninguno (0), Bajo (1-3), Medio (4-7), Alto (8-11) y Urgente
(12-16). El **riesgo global** sigue la regla del peor caso de la Fase 4: algún
Urgente → Crítico; si no, algún Alto → Alto; si no, algún Medio → Medio; si no,
Bajo. Si el Secret no existe o no es de tipo
TLS, la condición `Auditado` queda en `False` con el motivo, y el operador sigue
funcionando.

Decisiones de diseño:

- **Vigilancia real de los Secrets.** Cuando un Secret se crea, cambia o se
  borra, el operador vuelve a auditar al instante los `CryptoAudit` que lo
  referencian (un índice por `spec.targetRef` los localiza). En kind, cada
  cambio se refleja en `status` en menos de un segundo.
- **El contenido de los Secrets nunca se cachea.** El permiso sobre Secrets es
  `get;list;watch`, imprescindible para vigilarlos, pero el watch es solo de
  metadatos (`OnlyMetadata`): la caché del operador guarda nombres y versiones,
  no certificados ni claves privadas. El contenido se lee bajo demanda,
  directamente del API server, solo al auditar.
- **Solo se reconcilia cuando cambia el `spec`.** Cada escritura en `status`
  genera un evento; sin ese filtro, la propia fecha de la auditoría volvería a
  disparar la reconciliación en bucle.

## Requisitos

| Herramienta | Versión | Para qué |
|---|---|---|
| Go | 1.26 o posterior (el `go.mod` exige 1.26; probado con 1.27.1) | compilar y ejecutar |
| Clúster de Kubernetes | probado con kind v0.33.0 (Kubernetes 1.37.0) | donde se audita |
| Docker | probado con 29.8.1 | lo necesita kind |
| kubectl | probado con 1.37.1 | crear recursos y ver resultados |
| make | probado con GNU Make 4.4.1 | todas las tareas del proyecto |
| kubebuilder | v4.16.0 | solo para desarrollo (añadir APIs); no hace falta para probarlo |

El Makefile descarga por su cuenta en `bin/` el resto de herramientas
(`controller-gen`, `kustomize`, los binarios de envtest).

## Cómo probarlo

Estos son los pasos que se han ejecutado sobre un clúster kind.

**1. Instalar el CRD y arrancar el operador** (terminal 1):

```bash
git clone https://github.com/fizsar/quantum-ready-operator.git
cd quantum-ready-operator
kind create cluster        # si todavía no tienes un clúster
make install               # aplica el CRD CryptoAudit al clúster
make run                   # arranca el operador en local, con tu kubeconfig
```

`make run` usa los permisos de tu kubeconfig, no el `ClusterRole` del operador:
ese RBAC solo se aplica cuando el operador se despliega dentro del clúster.

**2. Crear un Secret TLS de prueba y auditarlo** (terminal 2):

```bash
openssl req -x509 -newkey rsa:2048 -sha256 -nodes -days 30 \
  -subj "/CN=web.ejemplo.test" -keyout web.key -out web.crt
kubectl create secret tls web-rsa-tls --cert=web.crt --key=web.key

kubectl apply -f - <<'EOF'
apiVersion: security.fizsar.github.io/v1alpha1
kind: CryptoAudit
metadata:
  name: web
spec:
  targetRef:
    name: web-rsa-tls
  exposicion: alta
  alcance: bajo
EOF
```

**3. Ver el resultado:**

```bash
kubectl get cryptoaudits
kubectl get cryptoaudit web -o yaml
```

Salida real de una prueba con tres Secrets (RSA, ECDSA y Ed25519) y distintas
combinaciones de exposición y alcance. La columna RIESGO-COMBINADO es la del
primer hallazgo (la clave pública, Crítico), que es también el que marca el
riesgo global: un resumen Aceptable u Obsoleto nunca supera a su familia
Crítico con la misma exposición y alcance.

```
NOMBRE              SECRET            EXPOSICION   ALCANCE   RIESGO-COMBINADO   RIESGO-GLOBAL   AUDITADO
ecdsa-alta-bajo     api-ecdsa-tls     alta         bajo      Alto (8)           Alto            True
ecdsa-baja-alto     api-ecdsa-tls     baja         alto      Alto (8)           Alto            True
ed25519-alta-alto   sso-ed25519-tls   alta         alto      Urgente (16)       Crítico         True
ed25519-baja-bajo   sso-ed25519-tls   baja         bajo      Medio (4)          Medio           True
rsa-alta-alto       web-rsa-tls       alta         alto      Urgente (16)       Crítico         True
rsa-baja-bajo       web-rsa-tls       baja         bajo      Medio (4)          Medio           True
```

`status` real de un certificado RSA firmado con SHA-1 (generado con
`openssl req -x509 -newkey rsa:2048 -sha1`), con exposición alta y alcance alto:

```yaml
status:
  conditions:
  - lastTransitionTime: "2026-09-27T23:10:18Z"
    message: 'certificado "legado-sha1.ejemplo.test" del Secret default/legado-sha1-tls:
      3 hallazgos'
    observedGeneration: 1
    reason: AuditoriaCompletada
    status: "True"
    type: Auditado
  hallazgos:
  - algoritmo: RSA
    categoria: Crítico
    origen: clavePublica
    riesgoCombinado: Urgente (16)
  - algoritmo: RSA
    categoria: Crítico
    origen: firma
    riesgoCombinado: Urgente (16)
  - algoritmo: SHA-1
    categoria: Obsoleto
    origen: firma
    riesgoCombinado: Urgente (12)
  riesgoGlobal: Crítico
  ultimaAuditoria: "2026-09-27T23:10:18Z"
```

Un certificado ECDSA P-384 firmado con SHA-384 da ECDSA Crítico (clave y firma)
y SHA-384 Aceptable; uno Ed25519, solo los dos hallazgos Ed25519.

Cambiar el `spec` vuelve a auditar: al pasar `rsa-baja-bajo` a exposición alta,
su riesgo cambió de Medio (4) a Alto (8) sin recrear el recurso.

Si el Secret no existe o no es de tipo TLS, la condición `Auditado` queda en
`False` con el motivo (`SecretNoEncontrado`, `TipoDeSecretIncorrecto`).

El esquema rechaza valores no válidos; por ejemplo, `exposicion: media` da
`spec.exposicion: Unsupported value: "media": supported values: "alta", "baja"`.

**Limpiar:**

```bash
kubectl delete cryptoaudit web && kubectl delete secret web-rsa-tls
make uninstall             # quita el CRD del clúster
```

## Tests

```bash
make test
```

Ejecuta los tests contra un servidor de API real (envtest): el reconciliador
con un Secret RSA, un Secret inexistente y un Secret que no es TLS; el watch,
con un manager real que crea, cambia, borra y recrea el Secret; y el índice por
Secret (cobertura del 84,8 %); y la tabla de reglas (cada familia y cada resumen
de firma, con certificados reales) y el modelo de riesgo (98,1 %), con al menos
un caso por cada nivel de riesgo y los límites de cada umbral.

## Estado actual

**Primer hito funcional, no un producto completo.** Ya funciona el camino de
datos completo: el operador lee un Secret real, extrae los algoritmos de su
certificado, calcula su riesgo combinado con la exposición y el alcance del
servicio, y lo refleja en `status`. Falta:

- **Solo Secrets TLS.** No se auditan otros recursos (Ingress, Services,
  configuraciones de mallas de servicio…).
- **Algunos algoritmos de certificado aún sin regla.** Respecto al analizador de
  certificados de la Fase 1, faltan DSA (Crítico en la Fase 1) y la detección
  de firmas post-cuánticas (ML-DSA, SLH-DSA). Hoy se mencionan en la condición
  `Auditado` como algoritmos sin regla.
- **Solo el primer certificado** de `tls.crt`; el resto de la cadena no se
  audita.
- **Probado solo con `make run`.** El despliegue dentro del clúster (imagen,
  `make deploy`) no se ha probado todavía.
- **API `v1alpha1`:** el esquema puede cambiar.
