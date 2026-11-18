# Third-party notices

StackVend is licensed under the [Apache License 2.0](LICENSE). This repository also contains, unmodified, the
third-party files listed below. Each keeps its own licence.

## Files in this repository

The Control Center serves these browser scripts from `apps/control-center/static/vendor/` (versions, source URLs and
checksums: [`VENDOR_MANIFEST.json`](apps/control-center/static/vendor/VENDOR_MANIFEST.json)).

| File | Project | Licence | Copyright |
| :--- | :--- | :--- | :--- |
| `alpinejs-3.14.9.min.js` | [Alpine.js](https://github.com/alpinejs/alpine) 3.14.9 | MIT | Copyright © 2019-2021 Caleb Porzio and contributors |
| `marked-15.0.12.min.js` | [marked](https://github.com/markedjs/marked) 15.0.12 | MIT | Copyright (c) 2018+, MarkedJS; Copyright (c) 2011-2018, Christopher Jeffrey |
| `mermaid-10.9.3.min.js` | [Mermaid](https://github.com/mermaid-js/mermaid) 10.9.3 | MIT | Copyright (c) 2014 - 2022 Knut Sveidqvist |
| `purify-3.2.6.min.js` | [DOMPurify](https://github.com/cure53/DOMPurify) 3.2.6 | Apache-2.0 OR MPL-2.0 | Copyright (c) Cure53 and other contributors |
| `tailwind-play-3.4.17.js` | [Tailwind CSS](https://github.com/tailwindlabs/tailwindcss) 3.4.17 (Play CDN build) | MIT | Copyright (c) Tailwind Labs, Inc. |

**Libraries bundled inside `mermaid-10.9.3.min.js`.** The Mermaid build is a single bundle of Mermaid and its
dependencies. Among them: [elkjs](https://github.com/kieler/elkjs) (Eclipse Layout Kernel, licensed under the
[Eclipse Public License 2.0](https://www.eclipse.org/legal/epl-2.0/); its source code is available from that
repository), DOMPurify 3.1.6 (Apache-2.0 OR MPL-2.0), js-yaml 4.1.0 (MIT), and the MIT- or ISC-licensed libraries
Mermaid 10.9.3 lists as dependencies in its `package.json` (for example d3, dagre-d3-es, cytoscape, lodash-es,
khroma, stylis and dayjs). The licence notices that these libraries include in the bundle are kept as they are.

### MIT License (Alpine.js, marked, Mermaid, Tailwind CSS)

> Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated
> documentation files (the "Software"), to deal in the Software without restriction, including without limitation the
> rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to
> permit persons to whom the Software is furnished to do so, subject to the following conditions:
>
> The above copyright notice and this permission notice shall be included in all copies or substantial portions of
> the Software.
>
> THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE
> WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR
> COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR
> OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.

DOMPurify is used under the Apache License 2.0, the same licence as StackVend (see [`LICENSE`](LICENSE)).

## Not part of this repository

These are installed or downloaded when you build or run StackVend; they are not copied into this repository.

* **Python packages** listed in the `requirements.txt` files are installed when the container images are built. Most
  are Apache-2.0, MIT or BSD licensed. Two to note: `PyGithub` is LGPL-3.0 (used as an unmodified library) and
  `dulwich` is dual-licensed Apache-2.0 OR GPL-2.0-or-later.
* **OpenTofu** (MPL-2.0) and the Terraform providers `google`, `google-beta`, `kubernetes` and `random` (MPL-2.0) are
  downloaded at run time by the Terraform tool server and the `tf-applier` job (the OpenTofu binary is used only
  after its release archive matches a pinned checksum).
* **Google Cloud buildpacks** and base images are pulled by Cloud Build when images are built.
