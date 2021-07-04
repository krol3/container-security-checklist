# Security Checklist for Build Container Images

Checklist to build and secure the images.
* [Secure the Build](##secure-the-build)
* [Secure the Container Registry](##secure-the-container-registry)
* [Secure the Container Runtime](##secure-the-container-runtime)
* [Secure the Infrastructure](##secure-the-infrastructure)
* [Secure the Data](##secure-the-data)
* [Secure the Workloads](##secure-the-workloads)

![Build](https://raw.githubusercontent.com/cncf/tag-security/main/security-whitepaper/cnswp-images/RackMultipart20201111_figure3.png)
Figure by [cncf/tag-security](https://github.com/cncf/sig-security/)

## Secure the Build

### Hardening Code - Secure SDLC (Software Development Life Cycle )
- [x] Do a static analysis of the code and libraries used by the code to surface any vulnerabilities in the code and its dependencies. 
  - [Source code analysis tools](https://owasp.org/www-community/Free_for_Open_Source_Application_Security_Tools): SAST, IAST.

### Image Hardening

- [x] Minimize the surface attack.
  - Package a single app per container. Small container images.
  - Minimize the number of layers.
    - Best practices linter dockerfile.
    - Multi-staged builds. A well-designed multi-stage build contains only the minimal binary files and dependencies required for the final image, with no build tools or intermediate files. This significantly reduces the attack surface.
    - Optimize cache.
  - Use the minimal base image: alpine, scratch, [distroless](https://github.com/GoogleContainerTools/distroless) images.
- [x] Use official base images.
  - Avoid unknown public images.
- [x] Rootless. Run as a non-root user. Least privileged user
  - Create a dedicated user and group on the image.
  - Do not use a UID below 10,000. For best security, always run your processes as a UID above 10,000.
- [x] Avoid privileged containers, which lets a container run as root on the local machine.
- [x] Use only the necessary Privileged Capabilities.
  - Drop kernel modules, system time, trace processes (CAP_SYS_MODULE, CAP_SYS_TIME, CAP_SYS_PTRACE ).
- [x] Enable the `--read-only` mode in docker, if it's possible.
- [x] Don't leave sensitive information (secrets, tokens, keys, etc) in the image.
- [x] Not mounting Host Path.
- [x] Use Metadata Labels for Images.
- [x] Properly image tag.
  - Tagging using semantic versioning.
  - Not use mutable tags(latest,staging,etc). Use Inmutable tags(SHA-256, commit).
  - [The challengue of uniquely identifying your images](https://blog.aquasec.com/docker-image-tags)
- [x] Signatures of container images. 
  - Sign and verify images to mitigate MITM attacks
  - [Notary](https://github.com/notaryproject/notaryproject)
  - [Cosign](https://github.com/sigstore/cosign)
- [x] Security profiles: SELinux, AppArmor, Seccomp.
- Static code analysys tool for Dockerfile like a linter.
  - [Hadolint](https://github.com/hadolint/hadolint)
- [x] Scan container images for CVE (Common Vulnerabilities and Exposures).
  - [Trivy](https://github.com/aquasecurity/trivy)
- [x] Used dynamic analysis techniques for containers.
  - Packers (including encrypters), and downloaders are all able to evade static scanning by, for example, encrypting binary code that is only executed in memory, making the malware active only in runtime.

### Build Resources
- [Azure best practices for build containers]()
- [Docker best practices for build containers](https://docs.docker.com/develop/develop-images/dockerfile_best-practices/)
- [Google best practices for build containers](https://cloud.google.com/solutions/best-practices-for-building-containers)
## Secure the Container Registry

Best configurations with ECR, ACR, Harbor, etc. Best practices.
- [x] Lock down access to the image registry (who can push/pull). There is no guarantee that the image you are pulling from the registry is trusted. It may unintentionally contain security vulnerabilities, or may have intentionally been replaced with an image compromised by attackers.
- [x] Use a private registry deployed behind firewall, to reduce the risk of tampering.
- [x] Registry uses RBAC (Role Based Access Control) to restrict which users can upload and download images from it.
### Registry Resources
- [Azure ACR](https://docs.microsoft.com/en-us/azure/container-registry/security-controls-policy)
- [Azure best practices for Azure Container Registry](https://docs.microsoft.com/en-us/azure/container-registry/container-registry-best-practices)
- [Amazon ECR](https://docs.aws.amazon.com/AmazonECR/latest/userguide/security.html)
- [Google Artifact Registry ](https://cloud.google.com/artifact-registry/docs/docker/authentication)
- [Harbor](https://goharbor.io/)

## Secure the Container Runtime
- [x] Applied the secure configurations in the container runtime. By default is insecure.
- [x] Restrict access to container runtime daemon/APIs
- [x] Use if it's possible in Rootless Mode.

### Docker
- [x] [CIS Docker Bench](https://github.com/docker/docker-bench-security). 
- [x] [Content trust in Docker](https://docs.docker.com/engine/security/trust/)
- [x] Avoid misconfigured exposed Docker API Ports, attackers used the misconfigured port to deploy and run a malicious image that contained malware that was specifically designed to evade static scanning.
- [x] Do not expose the Docker Daemon socket. The Docker daemon socket is a Unix network socket that facilitates communication with the Docker API. By default, this socket is owned by the root user. If anyone else obtains access to the socket, they will have permissions equivalent to root access to the host.

```
            -v /var/run/docker.sock://var/run/docker.sock
```

## Secure the Infrastructure
- [x] Use CIS-Benchmark for the operating system.
- [x] Keep host Up to date.
- [x] Use secure computing (seccomp) to restrict host system call (syscall) access from containers.
- [x] Use Security-Enhanced Linux (SELinux) to further isolate containers.

## Secure the Data
- [x] Don't leak sensitive info in the images.
- [x] Use a proper filesystem encryption technology for container storage
- [x] Provide write/execute access only to the containers that need to modify the data in a specific host filesystem path
- [x] OPA to write controls like only allowing Read-only Root Filesystem access, listing allowed host filesystem paths to mount, and listing allowed Flex volume drivers.
- [x] Automatically scan container images for sensitive data such as credentials, tokens, SSH keys, TLS certificates, database names or connection strings and so on, before pushing them to a container registry (can be done locally and in CI).
- [x] Limit storage related syscalls and capabilities to prevent runtime privilege escalation.

## Secure the Workloads
- [x] Avoid privileged containers
- [x] Limit container resources. When a container is compromised, attackers may try to make use of the underlying host resources to perform malicious activity. Set memory and CPU usage limits to minimize the impact of breaches for resource-intensive containers.
- [x] Segregate container networks. Ensure that containers can connect to each other only if absolutely necessary, and avoid connecting sensitive containers to public-facing networks.
- [x] Improve container isolation. Ideally, the operating system on a container host should protect the host kernel from container escapes, and prevent mutual influence between containers.
- [x] Set filesystem and volumes to Read only. This can prevent malicious activity such as deploying malware on the container or modifying configuration.
- [x] Complete lifecycle management restrict system calls from Within Containers
- [x] Monitor Container Activity. Analyze collected events to detect suspicious behaviourial patterns.
- [x] Automatically update security reports in response to workloads and other changes.
## DevSecOps Samples
- [Docker Security Best Practices by Rani Osnat - AquaSecurity](https://blog.aquasec.com/docker-security-best-practices)
- [Applying devsecops in a Golang app with trivy-github-actions by Daniel Pacak - AquaSecurity](https://blog.aquasec.com/devsecops-with-trivy-github-actions)
- [Golang App Sample - Static analyisis](https://github.com/krol3/go_api_simple)
- [Java App Sample - Container scanning](https://github.com/krol3/java-docker/blob/main/.github/workflows/scanning.yaml)
