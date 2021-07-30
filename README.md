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

### Secure the Image - Hardening
- *Reduce the attack suface*

      Package a single app per container. Small container images.
      Minimize the number of layers.

- Use the minimal base image: alpine, scratch, [distroless](https://github.com/GoogleContainerTools/distroless) images.
- Multi-staged builds.

      A well-designed multi-stage build contains only the minimal binary files and dependencies required for the final image, with no build tools or intermediate files.
      Optimize cache.

- Detect misconfigurations.

- [x] Use official base images.
  - Avoid unknown public images.
- [x] Rootless. Run as a non-root user. Least privileged user
  
- [x] Create a dedicated user and group on the image.

      Do not use a UID below 10,000. For best security, always run your processes as a UID above 10,000.
      Remove setuid and setgid permissions from the images

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
- [x] Signing images.

      Sign and verify images to mitigate MITM attacks
      Docker offers a Content Trust mechanism that allows you to cryptographically sign images using a private key. This guarantees the image, and its tags, have not been modified.

      - [Notary](https://github.com/notaryproject/notaryproject)
      - [Cosign](https://github.com/sigstore/cosign)

- [x] Security profiles: SELinux, AppArmor, Seccomp.
- Static code analysys tool for Dockerfile like a linter.
  - [Hadolint](https://github.com/hadolint/hadolint)
  - Packers (including encrypters), and downloaders are all able to evade static scanning by, for example, encrypting binary code that is only executed in memory, making the malware active only in runtime.

### Check image for Common Vulnerabilities and Exposures (CVE)
- [x] Prevent attacks using the Supply Chain Attack
- [x] Scan container images for CVE (Common Vulnerabilities and Exposures).
  - [Trivy](https://github.com/aquasecurity/trivy)
- [x] Used dynamic analysis techniques for containers.

### Integrates shift-left security
Vulnerability scanning as a automated step in your CI/CD pipeline

- [Trivy](https://github.com/aquasecurity/trivy)
- Clair
- Anchore

Comparing the container scanners results:
- [Container Vulnerability Scanning Fun by Rory](https://raesene.github.io/blog/2020/06/21/Container_Vulnerability_Scanning_Fun/)
- [Comparison – Anchore Engine vs Clair vs Trivy by Alfredo Pardo](https://www.a10o.net/devsecops/docker-image-security-static-analysis-tool-comparison-anchore-engine-vs-clair-vs-trivy/)
### Build Resources
- [Azure best practices for build containers]()
- [Docker best practices for build containers](https://docs.docker.com/develop/develop-images/dockerfile_best-practices/)
- [Google best practices for build containers](https://cloud.google.com/solutions/best-practices-for-building-containers)
## Secure the Container Registry

Best configurations with ECR, ACR, Harbor, etc. Best practices.
- [x] Lock down access to the image registry (who can push/pull) to restrict which users can upload and download images from it. Uses Role Based Access Control (RBAC)

      There is no guarantee that the image you are pulling from the registry is trusted.
      It may unintentionally contain security vulnerabilities, or may have intentionally been replaced with an image compromised by attackers.

- [x] Use a private registry deployed behind firewall, to reduce the risk of tampering.
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

- [x] Avoid misconfigured exposed Docker API Ports, attackers used the misconfigured port to deploy and run a malicious image that contained malware that was specifically designed to evade static scanning.
- [x] Configure TLS authentication for Docker daemon and centralized and remote logging.
- [x] Do not expose the Docker Daemon socket.

      The Docker daemon socket is a Unix network socket that facilitates communication with the Docker API. By default, this socket is owned by the root user. If anyone else obtains access to the socket, they will have permissions equivalent to root access to the host.

      To avoid this issue, follow these best practices:
      • Never make the daemon socket available for remote connections, unless you are using Docker’s encrypted HTTPS socket, which supports authentication.
      • Do not run Docker images with an option like this which exposes the socket in the container.
             -v /var/run/docker.sock://var/run/docker.sock

- [x] Run Docker in Rootless Mode

      docker context use rootless

#### Tools

- [CIS Docker Bench](https://github.com/docker/docker-bench-security).
- [Content trust in Docker](https://docs.docker.com/engine/security/trust/)
## Secure the Infrastructure
- [x] Keep host Up to date to prevent a range of known vulnerabilities, many of which can result in container espaces. Since the kernel is shared by the container and the host, kernel exploits when an attacker manages
to run on a container can directly affect the host.
- [x] Use CIS-Benchmark for the operating system.

- [x] Use secure computing (seccomp) to restrict host system call (syscall) access from containers.
- [x] Use Security-Enhanced Linux (SELinux) to further isolate containers.

## Secure the Data
- [x] Don't leak sensitive info in the images such as credentials, tokens, SSH keys, TLS certificates, database names or connection strings.
- [x] Use a proper filesystem encryption technology for container storage
- [x] Provide write/execute access only to the containers that need to modify the data in a specific host filesystem path
- [x] OPA to write controls like only allowing Read-only Root Filesystem access, listing allowed host filesystem paths to mount, and listing allowed Flex volume drivers.
- [x] Automatically scan container images for sensitive data such as credentials, tokens, SSH keys, TLS certificates, database names or connection strings and so on, before pushing them to a container registry (can be done locally and in CI).
- [x] Limit storage related syscalls and capabilities to prevent runtime privilege escalation.

## Secure the Workloads... Running the containers
- [x] Avoid privileged containers

      • Root access to all devices
      • Ability to tamper with Linux security modules like AppArmor and SELinux
      • Ability to install a new instance of the Docker platform, using the host’s kernel capabilities, and run Docker within Docker.

      To check if the container is running in privileged mode:
          docker inspect --format =’{{. HostConfig.Privileged}}’[container_id]

- [x] Limit container resources.

      When a container is compromised, attackers may try to make use of the underlying host resources to perform malicious activity. 
      Set memory and CPU usage limits to minimize the impact of breaches for resource-intensive containers.

- [x] Segregate container networks.

      The default bridge network exists on all Docker hosts—if you do not specify a different network, new containers automatically connect to it.
      Use custom bridge networks to control which containers can communicate between them, and to enable automatic DNS resolution from container name to IP address.
      Ensure that containers can connect to each other only if absolutely necessary, and avoid connecting sensitive containers to public-facing networks.
      Docker provides network drivers that let you create your own bridge network, overlay network, or macvlan network. If you need more control, you can create a Docker network plugin.

- [x] Improve container isolation.

      Protecting a container is exactly the same as protecting any process running on Linux.
      Ideally, the operating system on a container host should protect the host kernel from container escapes, and prevent mutual influence between containers.

- [x] Set filesystem and volumes to Read only. 

      This can prevent malicious activity such as deploying malware on the container or modifying configuration.
            docker run --read-only alpine

- [x] Complete lifecycle management restrict system calls from Within Containers
- [x] Monitor Container Activity. Analyze collected events to detect suspicious behaviourial patterns.
- [x] Create an incident response process to ensure rapid response in the case of an attack.
- [x] Apply automated patching
- [x] Confirms Inmutability. Implement drift prevention to ensure container inmutability.
- [x] Ensure you have robust auditing and forensics for quick troubleshooting and compliance reporting.
## Resources
- [Docker Security Best Practices by Rani Osnat - AquaSecurity](https://blog.aquasec.com/docker-security-best-practices)
- [Applying devsecops in a Golang app with trivy-github-actions by Daniel Pacak - AquaSecurity](https://blog.aquasec.com/devsecops-with-trivy-github-actions)
