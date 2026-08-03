Grype is a vulnerability scanner for container images, file systems, and Software Bills of Materials (SBOMs). It checks for known CVEs across multiple package ecosystems using the Grype vulnerability database.

*** Note: All of the below commands can be run with podman ... (e.g podman run --rm registry.access.redhat.com/hi/grype:latest version)

USAGE:

   ./run-grype-scan.sh <image-name>

For details about the grype command-line tool and the vulnerability database, see the Grype documentation.
Displaying the Version

docker run --rm registry.access.redhat.com/hi/grype:latest version

Scanning a Container Image

Scan a container image for known vulnerabilities. Mount the Podman authentication file so that grype can pull from authenticated registries:

docker run --rm \
  -v $HOME/.config/containers/auth.json:/tmp/.docker/config.json:ro,Z \
  registry.access.redhat.com/hi/grype:latest \
  registry.access.redhat.com/hi/core-runtime:latest

Scanning a Local Directory

Use a bind mount to scan a directory on the host:

docker run --rm \
  --volume <directory>:/workspace:ro,z \
  registry.access.redhat.com/hi/grype:latest dir:/workspace

Note that the directory mounted to the container must be readable by UID 65532.
Scanning an SBOM

Scan a Software Bill of Materials (SBOM) for vulnerabilities. CycloneDX and SPDX are accepted as input formats:

docker run --rm \
  --volume <directory>:/workspace:ro,z \
  registry.access.redhat.com/hi/grype:latest sbom:/workspace/sbom.json

Scanning an OCI Archive

Scan a locally saved OCI archive:

docker save --format oci-archive -o image.oci <image>
docker run --rm \
  --volume $(pwd):/workspace:ro,z \
  registry.access.redhat.com/hi/grype:latest oci-archive:/workspace/image.oci

Output Formats

Use --output to select the output format. The examples below scan the Red Hat Hardened Images core-runtime image:

# Default table output
docker run --rm registry.access.redhat.com/hi/grype:latest \
  registry:registry.access.redhat.com/hi/core-runtime:latest --output table

# JSON
docker run --rm registry.access.redhat.com/hi/grype:latest \
  registry:registry.access.redhat.com/hi/core-runtime:latest --output json

# CycloneDX JSON
docker run --rm registry.access.redhat.com/hi/grype:latest \
  registry:registry.access.redhat.com/hi/core-runtime:latest --output cyclonedx-json

# SARIF
docker run --rm registry.access.redhat.com/hi/grype:latest \
  registry:registry.access.redhat.com/hi/core-runtime:latest --output sarif

Vulnerability Database

Grype downloads its vulnerability database on first use and caches it for subsequent runs. To persist the cache across container invocations, mount a named volume at the cache directory:

docker run --rm \
  --volume grype-db:/tmp/.cache/grype:z \
  registry.access.redhat.com/hi/grype:latest \
  registry:registry.access.redhat.com/hi/core-runtime:latest

To update the database manually:

docker run --rm \
  --volume grype-db:/tmp/.cache/grype:z \
  registry.access.redhat.com/hi/grype:latest db update

