<!--
SPDX-FileCopyrightText: 2026 Roblox
SPDX-License-Identifier: MIT
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
  <https://github.com/boto/botocore/blob/develop/LICENSE>

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
  <https://github.com/psycopg/psycopg/tree/master/LICENSE.txt>

## Build, test, and repository tooling

Development and build environments may also resolve uv, Hatchling, setuptools,
pytest, Ruff, mypy, jsonschema, and REUSE. Their authoritative notices and
license files are distributed by the corresponding upstream projects and
package artifacts. They are not necessarily included in runtime images.
