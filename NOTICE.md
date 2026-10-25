# Anti-DoS-Valve Project
Copyright 2024-2026 Henning Brune.

This product includes software developed by the Anti-DoS-Valve Project
(https://github.com/ihbrune/Anti-DoS-Valve) and is licensed under the
Apache License, Version 2.0 (see LICENSE.md).

===============================================================================
Third-Party Software and Licenses
===============================================================================

This project directly bundles or vendors the following third-party software:

-------------------------------------------------------------------------------
1. Chart.js (v4.4.7)
-------------------------------------------------------------------------------
* File: `collector/src/main/resources/static/js/chart.umd.min.js`
* Project URL: https://www.chartjs.org/
* Repository: https://github.com/chartjs/Chart.js
* License: MIT License
* Copyright: (c) 2014-2024 Chart.js Contributors

License text:
```
The MIT License (MIT)

Copyright (c) 2014-2024 Chart.js Contributors

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
```

Bundled sub-dependency inside `chart.umd.min.js`:
* `@kurkle/color` (v0.3.2)
  * Project URL: https://github.com/kurkle/color
  * License: MIT License
  * Copyright: (c) 2020-2023 Jukka Kurkela

-------------------------------------------------------------------------------
2. htmx (v2.0.3)
-------------------------------------------------------------------------------
* File: `collector/src/main/resources/static/js/htmx.min.js`
* Project URL: https://htmx.org/
* Repository: https://github.com/bigskysoftware/htmx
* License: BSD 2-Clause License
* Copyright: (c) 2020-2024 Carson Gross, Big Sky Software

License text:
```
BSD 2-Clause License

Copyright (c) 2020, Carson Gross
All rights reserved.

Redistribution and use in source and binary forms, with or without
modification, are permitted provided that the following conditions are met:

1. Redistributions of source code must retain the above copyright notice, this
   list of conditions and the following disclaimer.

2. Redistributions in binary form must reproduce the above copyright notice,
   this list of conditions and the following disclaimer in the documentation
   and/or other materials provided with the distribution.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE
FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
```

-------------------------------------------------------------------------------
3. Major Java Runtime Dependencies (Collector Module)
-------------------------------------------------------------------------------
The Collector module (`anti-dos-collector`) links against several open-source
libraries at runtime, all distributed under permissive licenses compatible with
Apache License 2.0:

* Spring Boot / Spring Framework - Apache License 2.0 (VMware, Inc. / Broadcom)
* SQLite JDBC Driver - Apache License 2.0 / Public Domain SQLite Core (Xerial)
* PostgreSQL JDBC Driver - BSD 2-Clause License (PostgreSQL Global Development Group)
* Flyway Core - Apache License 2.0 (Redgate Software)
* MaxMind GeoIP2 / MMDB Reader - Apache License 2.0 (MaxMind, Inc.)
* CommonMark Java - BSD 2-Clause License (Atlassian / Robin Stocker)
* Jackson (core, databind, annotations) - Apache License 2.0 (FasterXML, LLC)
* HikariCP - Apache License 2.0 (Brett Wooldridge)
* Thymeleaf - Apache License 2.0 (Daniel Fernández)
* SLF4J - MIT License (QOS.ch)

-------------------------------------------------------------------------------
4. Apache Tomcat Valve (`anti-dos-valve`)
-------------------------------------------------------------------------------
The core Valve module contains zero bundled third-party runtime dependencies.
Compilation and runtime interface binding target Apache Tomcat (Catalina),
licensed under the Apache License 2.0 by the Apache Software Foundation.
