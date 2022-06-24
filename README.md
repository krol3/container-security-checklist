# Container Security Checklist: From the image to the workload

# Table Of Contents

  - [Cloud Native Concepts](#cloud-native-concepts)
  - [Container Threat Model](#container-threat-model)
  - [Container Security Checklist](#container-security-checklist)
  - [Secure the Build](#secure-the-build)
    - [Secure Supply Chain](#secure-supply-chain)
    - [Hardening Code - Secure SDLC (Software Development Life Cycle)](#hardening-code---secure-sdlc-software-development-life-cycle)
    - [Secure the Image - Hardening](#secure-the-image---hardening)
    - [Image Scanning](#image-scanning)
    - [Image Signing](#image-signing)
  - [Secure the Container Registry](#secure-the-container-registry)
    - [Registry Resources](#registry-resources)
  - [Secure the Container Runtime](#secure-the-container-runtime)
    - [Why is important Runtime Security?](#why-is-important-runtime-security)
    - [Constraints](#constraints)
    - [Docker Security](#docker-security)
  - [Secure the Infrastructure](#secure-the-infrastructure)
  - [Secure the Data](#secure-the-data)
    - [Secrets Management Tools](#secrets-management-tools)
  - [Secure the Workloads... Running the containers](#secure-the-workloads-running-the-containers)
  - [Container Security Guides](#container-security-guides)
  - [Further reading:](#further-reading)
  - [Collaborate](#collaborate)


---

## Cloud Native Concepts

| Legacy apps   |      Cloud Native apps      |  Cloud Native Security |
|----------|:-------------:|------:|
| Infrequent releases |  frequently releases, using CI/CD | Shifting left with automated testing |
| Persistent workloads |  Ephemeral workloads. Ensure that your containers are stateless and immutable |  Runtime controls that follow the workload |
| Fixed address | Orchestrated containers. Kubernetes creates DNS records for services and pods |   Identity-based segmentation |
| Hypervisor or hardware isolation | Shared kernel, obscured OS | Enforce least privilege on each workload |
| Very little open source | Open source everywhere | SCA - Software composition analysis |
| Propietary software | Proprietary code, Open source, Third-party software |  Software supply chain risk |
| Vertical control of the stack | multi-cloud | Detecting cloud services missconfigurations |

> Table by Aqua Cloud Native Security Platform, more details [download here](https://f.hubspotusercontent40.net/hubfs/1665891/Buyers_Guide/Aqua_Buyers_Guide_Cloud_Native_Security_Platform.pdf)
## Container Threat Model

[![thread-model](https://www.oreilly.com/library/view/container-security/9781492056690/assets/cose_0101.png)](https://medium.com/oreillymedia/container-security-threats-38649261fb4f)
Figure by [Container Security by Liz Rice](https://www.oreilly.com/library/view/container-security/9781492056690/)

- Insecure Host
- Misconfiguration container
- Vulnerable application
- Supply chain attacks
- Expose secrets
- Insecure networking
- Integrity and confidentiality of OS images
- Container escape vulnerabilities

## Container Security Checklist

Checklist to build and secure the images across the following phases:

* [Secure the Build](#secure-the-build)
* [Secure the Container Registry](#secure-the-container-registry)
* [Secure the Container Runtime](#secure-the-container-runtime)
* [Secure the Infrastructure](#secure-the-infrastructure)
* [Secure the Data](#secure-the-data)
* [Secure the Workloads](#secure-the-workloads-running-the-containers)

![Build](https://raw.githubusercontent.com/cncf/tag-security/main/security-whitepaper/v1/cnswp-images/RackMultipart20201111_figure3.png)
Figure by [cncf/tag-security](https://github.com/cncf/sig-security/)

---
## Secure the Build

### Secure Supply Chain
- Know where images, packages came from.
### Hardening Code - Secure SDLC (Software Development Life Cycle)
- [x] Do a static analysis of the code and libraries used by the code to surface any vulnerabilities in the code and its dependencies. 
  -  Improve the security and quality of their code. [OWASP Open Source Application Security tools](https://owasp.org/www-community/Free_for_Open_Source_Application_Security_Tools): SAST, IAST.

### Secure the Image - Hardening

You can build the container images using [Docker](https://docs.docker.com/engine/reference/commandline/build/), [Kaniko](https://github.com/GoogleContainerTools/kaniko).

- *Reduce the attack surface*

>    Package a single application per container. Small container images.
>    Minimize the number of layers.

- Use the minimal OS image:
  - [Alpine images](https://hub.docker.com/_/alpine)
  - [Scratch images](https://hub.docker.com/_/scratch)
  - [Distroless images](https://github.com/GoogleContainerTools/distroless)
- Use OS optimized for running containers:
  - [Flatcar images](https://www.flatcar.org/docs/latest/installing/)
  - [CodeOS by Fedora](https://getfedora.org/coreos/) replaced the Project Atomic.
  - [Bottlerocket by Aws](https://aws.amazon.com/bottlerocket/)
  - [k3os by Rancher](https://github.com/rancher/k3os)
  - [Container-Optimized OS - COS by Google](https://cloud.google.com/container-optimized-os/docs/concepts/features-and-benefits), based on [Chromium-os](https://www.chromium.org/chromium-os/) used by Google

> - [Do you use Alpine, distroless or vanilla images? ...](https://learnk8s.io/blog/smaller-docker-images)
> - [7 Google best practices for building containers](https://cloud.google.com/blog/products/containers-kubernetes/7-best-practices-for-building-containers)

- Multi-staged builds.

>   A well-designed multi-stage build contains only the minimal binary files and dependencies required for the final image, with no build tools or intermediate files.
>   Optimize cache.

- [x] Use official base images.
  - Avoid unknown public images.
- [x] Rootless. Run as a non-root user. Least privileged user
- [x] Create a dedicated user and group on the image.

> Do not use a UID below 10,000. For best security, always run your processes as a UID above 10,000.
> Remove setuid and setgid permissions from the images

- [x] Avoid privileged containers, which lets a container run as root on the local machine.
- [x] Use only the necessary Privileged Capabilities.
  - Drop kernel modules, system time, trace processes (CAP_SYS_MODULE, CAP_SYS_TIME, CAP_SYS_PTRACE ).
- [x] Enable the `--read-only` mode in docker, if it's possible.
- [x] Don't leave sensitive information (secrets, tokens, keys, etc) in the image.
- [x] Not mounting Host Path.
- [x] Use Metadata Labels for Images, such as licensing information, sources, names of authors, and relation of containers to projects or components.
- [x] Used fixed image tag for inmutability.
  - Tagging using semantic versioning.
  - Not use mutable tags(latest,staging,etc). Use Inmutable tags(SHA-256, commit).
  - [The challengue of uniquely identifying your images](https://blog.aquasec.com/docker-image-tags)

```
Pulling images by digest
docker images --digests
docker pull alpine@sha256:b7233dafbed64e3738630b69382a8b231726aa1014ccaabc1947c5308a8910a7
```

- [x] Enanbled Security profiles: SELinux, AppArmor, Seccomp.

- [x] Static code analysys tool for Dockerfile like a linter. **Detect misconfigurations**
  - [Hadolint](https://github.com/hadolint/hadolint)
  - Packers (including encrypters), and downloaders are all able to evade static scanning by, for example, encrypting binary code that is only executed in memory, making the malware active only in runtime.
  - Trivy detect missconfigurations 

### Image Scanning

- [x] Check image for Common Vulnerabilities and Exposures (CVE)
- [x] Check image for secrets
- [x] Prevent attacks using the Supply Chain Attack
- [x] Scan container images for CVE (Common Vulnerabilities and Exposures).
- [x] Used dynamic analysis techniques for containers.

**Container Security Scanners**

- [Trivy by AquaSecurity](https://github.com/aquasecurity/trivy)
- [Clair by Quay](https://github.com/quay/clair)
- [Anchore](https://anchore.com/opensource/)
- [Dagda](https://github.com/eliasgranderubio/dagda/)
- [GitGuardian Shield](https://github.com/GitGuardian/ggshield/)

Comparing the container scanners results:
- [Container Vulnerability Scanning Fun by Rory](https://raesene.github.io/blog/2020/06/21/Container_Vulnerability_Scanning_Fun/)
- [Comparison – Anchore Engine vs Clair vs Trivy by Alfredo Pardo](https://www.a10o.net/devsecops/docker-image-security-static-analysis-tool-comparison-anchore-engine-vs-clair-vs-trivy/)

### Image Signing

Sign and verify images to mitigate MITM attacks. Docker offers a Content Trust mechanism that allows you to cryptographically sign images using a private key. This guarantees the image, and its tags, have not been modified.

- [Notary](https://github.com/notaryproject/notaryproject). Implementation of TUF specification.
- [sigstore/Cosign](https://github.com/sigstore/cosign)
- [Sigstore: A Solution to Software Supply Chain Security](https://itnext.io/sigstore-a-solution-to-software-supply-chain-security-35bc96bddad5)
- [Zero-Trust supply chains with Sigstore and SPIFFE/SPIRE](https://github.com/sigstore/community/blob/main/docs/zero-trust-supply-chains.pdf)

**More Material about build containers**
- [Azure best practices for build containers](https://docs.microsoft.com/en-us/azure/container-registry/container-registry-best-practices)
- [Docker best practices for build containers](https://docs.docker.com/develop/develop-images/dockerfile_best-practices/)
- [Google best practices for build containers](https://cloud.google.com/solutions/best-practices-for-building-containers)

## Secure the Container Registry

Best configurations with ECR, ACR, Harbor, etc. Best practices.
- [x] Lock down access to the image registry (who can push/pull) to restrict which users can upload and download images from it. Uses Role Based Access Control (RBAC)

>    There is no guarantee that the image you are pulling from the registry is trusted.
>    It may unintentionally contain security vulnerabilities, or may have intentionally been replaced with an image compromised by attackers.

- [x] Use a private registry deployed behind firewall, to reduce the risk of tampering.

### Registry Resources
- [Azure ACR](https://docs.microsoft.com/en-us/azure/container-registry/security-controls-policy)
- [Azure best practices for Azure Container Registry](https://docs.microsoft.com/en-us/azure/container-registry/container-registry-best-practices)
- [Amazon ECR](https://docs.aws.amazon.com/AmazonECR/latest/userguide/security.html)
- [Google Artifact Registry ](https://cloud.google.com/artifact-registry/docs/docker/authentication)
- [Harbor](https://goharbor.io/)

## Secure the Container Runtime

See the following container runtimes, there are three main types of container runtimes—low-level runtimes, high-level runtimes, and  virtualized runtimes or sandboxed.

1. Low-Level Container Runtimes:
- [runC](https://github.com/opencontainers/runc)
- [crun](https://github.com/containers/crun)
- [containerd](https://containerd.io/)
2. High-Level Container Runtimes
- [Docker Engine](https://docs.docker.com)
- [Podman](https://podman.io/)
- [CRI-O](https://github.com/cri-o/cri-o) - OCI-based implementation of Kubernetes Container Runtime Interface
- [Mirantes Container Runtime](https://docs.mirantis.com/mcr/20.10/overview.html)
3. Sandboxed and Virtualized Container Runtimes
- [gVisor](https://gvisor.dev/)
- [nabla-containers](https://nabla-containers.github.io/)
- [kata-containers](https://github.com/kata-containers)
### Why is important Runtime Security?
- Detection of IOC (Indicator Of Compromise)
- Detect Zero Days attack
- Compliance requirement
- Recommended in highly dynamic environments

### Constraints
- Event context
- Safety
- Low overhead
- Wide support of kernels


Enable detection of anomalous behaviour in applications.

- [x] Applied the secure configurations in the container runtime. By default is insecure.
- [x] Restrict access to container runtime daemon/APIs
- [x] Use if it's possible in Rootless Mode.

### Docker Security

- [x] Avoid misconfigured exposed Docker API Ports, attackers used the misconfigured port to deploy and run a malicious image that contained malware that was specifically designed to evade static scanning.
- [x] TLS encryption between the Docker client and daemon. Do not expose the Docker engine using Unix socket or remotely using http.

>    Never make the daemon socket available for remote connections, unless you are using Docker’s encrypted HTTPS socket, which supports authentication.

- [x] Limit the usage of mount Docker socket in a container in an untrusted environment.

- [x] Do not run Docker images with an option that exposes the socket in the container.

      -v /var/run/docker.sock://var/run/docker.sock

>    The Docker daemon socket is a Unix network socket that facilitates communication with the Docker API. By default, this socket is owned by the root user. If anyone else obtains access to the socket, they will have permissions equivalent to root access to the host.

- [x] Run Docker in [Rootless Mode](https://docs.docker.com/engine/security/rootless/). `docker context use rootless`
- [x] Enable the [user namespaces](https://docs.docker.com/engine/security/userns-remap/).
- [x] Enable Docker Content Trust. Docker. `DOCKER_CONTENT_TRUST=1`
      . Docker Content Trust implements [The Update Framework](https://theupdateframework.io/) (TUF)
      . Powered by [Notary](https://github.com/notaryproject/notary), an open-source TUF-client and server that can operate over arbitrary trusted collections of data.

- [x] Do not run Docker without the default **seccomp profile**: `seccomp=unconfined`

> - [Seccomp enabled by default](https://docs.docker.com/engine/security/seccomp/). See the Docker profile [here](https://docs.docker.com/engine/security/seccomp/)
> - [Hardening Docker and Kubernetes with seccomp](https://martinheinz.dev/blog/41)

**More Material about Docker Security**
- [Docker Security Labs](https://github.com/docker/labs/tree/master/security)
- [CIS Docker Bench](https://github.com/docker/docker-bench-security).
- [Content trust in Docker](https://docs.docker.com/engine/security/trust/)
- [Docker Security Playground - DSP](https://github.com/DockerSecurityPlayground/DSP) - Network Security and Penetration Test techniques
## Secure the Infrastructure

**Risk:**
- If host is compromised, the container will be too.
- Kernel exploits

**Best practices:**
- [x] Keep the host kernel patched to prevent a range of known vulnerabilities, many of which can result in container escape. Since the kernel is shared by the container and the host, the kernel exploits when an attacker manages
to run on a container can directly affect the host.
- [x] Use CIS-Benchmark for the operating system.

- [x] Use secure computing (seccomp) to restrict host system call (syscall) access from containers.
- [x] Use Security-Enhanced Linux (SELinux) to further isolate containers.

## Secure the Data

- [x] Don't leak sensitive info in the images, avoid using environment variables for your sensitive information.
> Secrets are Digital credentials:
> - passwords
> - API keys & Tokens
> - SSH keys
> - Private certificates for secure communication, transmitting and receiving data (TLS, SSL, and so on)
> - Private encryption keys for systems like PGP
> - Database names or connection strings.
> - Sensitive configuration settings (email address, usernames, debug flags, etc.)

- [x] Use a proper filesystem encryption technology for container storage
- [x] Use volume mounts to pass secrets to a container at runtime
- [x] Provide write/execute access only to the containers that need to modify the data in a specific host filesystem path
- [x] OPA to write controls like only allowing Read-only Root Filesystem access, listing allowed host filesystem paths to mount, and listing allowed Flex volume drivers.
- [x] Automatically scan container images for sensitive data such as credentials, tokens, SSH keys, TLS certificates, database names or connection strings and so on, before pushing them to a container registry (can be done locally and in CI).
- [x] Limit storage related syscalls and capabilities to prevent runtime privilege escalation.

- [x] Implement RBAC, or role-based access control. Every human or application only needs the minimum secrets required to operate, nothing more. **Principle of Least Privilege**.
- [x] Run audits regularly. Centralized audit trails are the key to knowing all the key security events.
- [x] Rotate secrets, a standard security practice.
- [x] Automatically create and store secrets

### Secrets Management Tools

Open source tools:
- [detect-secrets by Yelp](https://github.com/Yelp/detect-secrets): detecting and preventing secrets in code.
- [git-secrets by awslabs](https://github.com/awslabs/git-secrets#nix-linux-macos): Prevents you from committing secrets and credentials into git repositories

Cloud Provider Key Management
- [AWS Secrets Manager](https://aws.amazon.com/secrets-manager/)
- [Azure Key Vault](https://docs.microsoft.com/en-us/azure/key-vault/general/basic-concepts)
- [Google Secret Manager](https://cloud.google.com/secret-manager)

Enterprise secrets vault:
- [HashiCorp Vault](https://www.vaultproject.io/)
- [CyberArk Conjur](https://www.cyberark.com/products/secrets-manager-enterprise/)

## Secure the Workloads... Running the containers
- [x] Avoid privileged containers

    • Root access to all devices
    • Ability to tamper with Linux security modules like AppArmor and SELinux
    • Ability to install a new instance of the Docker platform, using the host’s kernel capabilities, and run Docker within Docker.

>    To check if the container is running in privileged mode
>        `docker inspect --format =’{{. HostConfig.Privileged}}’[container_id]`

- [x] Limit container resources.

>    When a container is compromised, attackers may try to make use of the underlying host resources to perform malicious activity.
>    Set memory and CPU usage limits to minimize the impact of breaches for resource-intensive containers.

```
docker run -d --name container-1 --cpuset-cpus 0 --cpu-shares 768 cpu-stress
```

- [x] Preventing a fork bomb. `docker run --rm -it --pids-limit 200 debian:jessie `

- [x] Segregate container networks.

  -  The default bridge network exists on all Docker hosts—if you do not specify a different network, new containers automatically connect to it.
  -  Use custom bridge networks to control which containers can communicate between them, and to enable automatic DNS resolution from container name to IP address.
  - Ensure that containers can connect to each other only if absolutely necessary, and avoid connecting sensitive containers to public-facing networks.
  - Docker provides network drivers that let you create your own bridge network, overlay network, or macvlan network. If you need more control, you can create a Docker network plugin.

- [x] Improve container isolation.

>   Protecting a container is exactly the same as protecting any process running on Linux.
>   Ideally, the operating system on a container host should protect the host kernel from container escapes, and prevent mutual influence between containers.

- [x] Set filesystem and volumes to Read only. 

>    This can prevent malicious activity such as deploying malware on the container or modifying configuration.
>         `docker run --read-only alpine`

- [x] Complete lifecycle management restrict system calls from Within Containers
- [x] Monitor Container Activity. Analyze collected events to detect suspicious behaviourial patterns.
- [x] Create an incident response process to ensure rapid response in the case of an attack.
- [x] Apply automated patching
- [x] Confirms Inmutability. Implement drift prevention to ensure container inmutability.
- [x] Ensure you have robust auditing and forensics for quick troubleshooting and compliance reporting.

## Container Security Guides

* [SP 800-190 - Application Container Security Guide by NIST](https://csrc.nist.gov/publications/detail/sp/800-190/final)
## Further reading:
- [Linux Capabilities](https://www.kernel.org/doc/ols/2008/ols2008v1-pages-163-172.pdf): making them work, published in hernel.org 2008.
- [Using seccomp to limit the kernel attack surface](https://man7.org/conf/lpc2015/limiting_kernel_attack_surface_with_seccomp-LPC_2015-Kerrisk.pdf)
- [Docker Security Best Practices by Rani Osnat - AquaSecurity](https://blog.aquasec.com/docker-security-best-practices)
- [Applying devsecops in a Golang app with trivy-github-actions by Daniel Pacak - AquaSecurity](https://blog.aquasec.com/devsecops-with-trivy-github-actions)

## Collaborate

If you find any typos, errors, outdated resources; or if you have a different point of view. Please open a pull request or contact me.

Pull requests and stars are always welcome 🙌
