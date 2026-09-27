# quantum-ready-operator

Operador de Kubernetes en Go que audita la cripto-agilidad de los Secrets TLS
del clúster: lee el certificado de cada Secret, identifica sus algoritmos y
señala los que un ordenador cuántico podrá romper (de momento, RSA, ECDSA y
Ed25519).

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
`crypto/x509`, clasifica el algoritmo de su clave pública y el de su firma, y
escribe el resultado en `status`: los hallazgos, el riesgo global, la fecha de
la auditoría y una condición `Auditado`. Si el Secret no existe o no es de tipo
TLS, la condición `Auditado` queda en `False` con el motivo, y el operador sigue
funcionando.

Dos decisiones de diseño:

- **Los Secrets se leen sin caché.** El cliente con caché de controller-runtime
  empezaría a vigilar todos los Secrets del clúster al pedir uno; leyéndolo
  directamente de la API, basta el permiso `get` sobre Secrets (sin `list` ni
  `watch`).
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

Salida real con ese Secret RSA y otros casos de prueba (un certificado ECDSA,
uno Ed25519, un Secret inexistente y un Secret que no es TLS):

```
NAME             SECRET            RIESGO     AUDITADO   ULTIMA-AUDITORIA
api              api-ecdsa-tls     Crítico    True       5s
secret-ausente   no-existe                    False
secret-no-tls    no-es-tls                    False
sso              sso-ed25519-tls   Crítico    True       5s
web              web-rsa-tls       Crítico    True       5s
```

```yaml
status:
  conditions:
  - lastTransitionTime: "2026-09-27T17:40:35Z"
    message: 'certificado "web.ejemplo.test" del Secret default/web-rsa-tls: 2 hallazgos'
    observedGeneration: 1
    reason: AuditoriaCompletada
    status: "True"
    type: Auditado
  hallazgos:
  - algoritmo: RSA
    categoria: Crítico
    origen: clavePublica
  - algoritmo: RSA
    categoria: Crítico
    origen: firma
  riesgoGlobal: Crítico
  ultimaAuditoria: "2026-09-27T17:40:35Z"
```

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
con un Secret RSA, un Secret inexistente y un Secret que no es TLS (cobertura
del 83,9 %), y la tabla de reglas (100 %).

## Estado actual

**Primer hito funcional, no un producto completo.** Ya funciona el camino de
datos completo: el operador lee un Secret real, extrae los algoritmos de su
certificado y los refleja en `status`. Falta:

- **Riesgo combinado.** `spec.exposicion` y `spec.alcance` se validan pero
  todavía no se usan: `riesgoCombinado` queda vacío (Fase 1: categoría ×
  exposición × alcance).
- **Riesgo global provisional.** Mientras no haya riesgo combinado,
  `riesgoGlobal` aplica la regla del peor caso sobre la categoría, no sobre el
  riesgo combinado como en la Fase 4.
- **Sin vigilancia de Secrets.** Si cambia el certificado de un Secret, no se
  vuelve a auditar hasta que cambie el `CryptoAudit`. Si el Secret falta o no
  es válido, se reintenta cada minuto.
- **Solo Secrets TLS.** No se auditan otros recursos (Ingress, Services,
  configuraciones de mallas de servicio…).
- **Tabla de reglas mínima.** Solo RSA, ECDSA y Ed25519, por familia de
  algoritmo: el hash de la firma (SHA-1, MD5) todavía no se clasifica y el resto
  del libro de reglas de la Fase 1 no se ha migrado. Los algoritmos sin regla se
  mencionan en la condición `Auditado` sin inventarles una categoría.
- **Solo el primer certificado** de `tls.crt`; el resto de la cadena no se
  audita.
- **Probado solo con `make run`.** El despliegue dentro del clúster (imagen,
  `make deploy`) no se ha probado todavía.
- **API `v1alpha1`:** el esquema puede cambiar.
