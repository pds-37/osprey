# GuardianOS v2 — Dependency Model & Canonical Component Identity

## Canonical Identity Resolution
GuardianOS enforces deterministic, ecosystem-aware Package URLs (PURLs) according to the Package URL specification (`pkg:<type>/<namespace>/<name>@<version>`).

### Supported Ecosystems
| Ecosystem | Type Prefix | Canonicalization Rules | Example |
| :--- | :--- | :--- | :--- |
| **PyPI** | `pkg:pypi` | Lowercase, dashes replace dots/underscores | `pkg:pypi/pillow@10.2.0` |
| **npm** | `pkg:npm` | Scoped packages retain `@namespace/name` | `pkg:npm/@babel/core@7.24.0` |
| **Debian** | `pkg:deb` | `debian` namespace, strict versioning | `pkg:deb/debian/libheif@1.19.7` |
| **RPM** | `pkg:rpm` | Vendor namespace (fedora, redhat) | `pkg:rpm/redhat/openssl@3.0.7` |
| **Golang** | `pkg:golang` | Full repository path module name | `pkg:golang/github.com/gin-gonic/gin@v1.9.1` |
| **Docker** | `pkg:docker` | Image repository and tag | `pkg:docker/image-service@latest` |
| **Maven** | `pkg:maven` | GroupId and ArtifactId | `pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1` |

---

## The Three Dependency States

```
Manifest (package.json / requirements.txt)
   ↓
[DECLARED]
   ↓
Container Build (apt-get / pip install / node_modules)
   ↓
[INSTALLED]
   ↓
Kubernetes Pod / Docker Daemon Execution
   ↓
[RUNNING]
```

1. **DECLARED**: Present in source manifests or lockfiles. May not be present in production if filtered out (e.g. devDependencies).
2. **INSTALLED**: Present in the container filesystem or OS root. May be present but never loaded into memory.
3. **RUNNING**: Executing in memory within a live production workload with active network listeners or entry points.
