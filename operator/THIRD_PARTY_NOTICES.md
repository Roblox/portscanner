<!--
SPDX-FileCopyrightText: 2026 Roblox
SPDX-License-Identifier: MIT AND Apache-2.0
-->

# Third-party notices

This repository depends on or interoperates with the projects listed below.
The links point to upstream licensing material; this inventory does not make an
independent license determination. Before distributing an image or binary,
verify the exact resolved versions and preserve all notices required by those
upstream projects.

## Scanner runtime

### Nmap

The scanner boundary invokes the separately packaged Nmap executable.

- Project: <https://nmap.org/>
- Upstream legal and licensing information:
  <https://nmap.org/book/man-legal.html>
- Source distributions: <https://nmap.org/download.html>

Nmap has project-specific licensing terms. Consult the terms shipped with the
exact Nmap release and distribution package rather than inferring them from
this notice.

## Python runtime and libraries

### Python

- Project: <https://www.python.org/>
- Upstream licensing information: <https://docs.python.org/3/license.html>

### Pydantic and pydantic-core

- Projects: <https://github.com/pydantic/pydantic> and
  <https://github.com/pydantic/pydantic-core>
- Upstream licensing files:
  <https://github.com/pydantic/pydantic/blob/main/LICENSE> and
  <https://github.com/pydantic/pydantic-core/blob/main/LICENSE>

### Boto3 and Botocore

- Projects: <https://github.com/boto/boto3> and
  <https://github.com/boto/botocore>
- Upstream licensing files:
  <https://github.com/boto/boto3/blob/develop/LICENSE> and
  <https://github.com/boto/botocore/blob/develop/LICENSE.txt>

### Kubernetes Python client

- Project: <https://github.com/kubernetes-client/python>
- Upstream licensing file:
  <https://github.com/kubernetes-client/python/blob/master/LICENSE>

### defusedxml

- Project: <https://github.com/tiran/defusedxml>
- Upstream licensing file:
  <https://github.com/tiran/defusedxml/blob/main/LICENSE>

### Psycopg

- Project: <https://github.com/psycopg/psycopg>
- Upstream licensing information:
  <https://github.com/psycopg/psycopg/blob/master/LICENSE.txt>

## Go operator

The statically linked operator includes Kubernetes API machinery, client-go,
controller-runtime, and `golang.org/x` modules. Their exact resolved versions
are recorded in `operator/go.sum`.

- Kubernetes projects: <https://github.com/kubernetes/kubernetes>,
  <https://github.com/kubernetes/client-go>, and
  <https://github.com/kubernetes-sigs/controller-runtime>
- Kubernetes and controller-runtime license:
  <https://www.apache.org/licenses/LICENSE-2.0>
- Bundled image license text: `/licenses/Apache-2.0.txt`
- Go supplemental repositories and licenses:
  <https://pkg.go.dev/golang.org/x>

## Build, test, and repository tooling

Development and build environments may also resolve uv, Hatchling, setuptools,
pytest, Ruff, mypy, jsonschema, and REUSE. Their authoritative notices and
license files are distributed by the corresponding upstream projects and
package artifacts. They are not necessarily included in runtime images.
