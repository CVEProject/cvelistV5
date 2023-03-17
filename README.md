# CVE List V5

> **Work In Progress** - use for notional workflow and integration only until the public release

This repository is a read-only JSON 5.0 view of the official CVE List. It is a work in progress.

- `preview_cves` directory contains all of the current CVEs from the official CVE Services API. It is named `preview_cves` because this repository is still a work in progress. It will eventually be named `cves` when development work is complete.  The baseline (from a git history point of view) is [Commit c56c2de](https://github.com/CVEProject/cvelistV5/tree/c56c2de4ad9bb897e4bc03e800e7377ae31db3ab)  committed 2023-03-02 21:18:43.000Z.
- `review_set` directory has been removed. It contained old data from October 2022, and was only used for review purposes in October 2022.

Until CVE Services "Hard Deploy" (targeted for 1st QT, 2023) is completed, the official published CVE List can be found at the following locations.

1. https://cve.org/Downloads: This location contains the traditional downloadable CVE list that is available in the following formats: csv, html, tzt, xml.

2. https://github.com/CVEProject/cvelist (JSON 4.0): The github submission pilot will continue to be maintained during the course of the JSON 4.0 --> JSON 5.0 transition. The format is JSON 4.0 ( but it will include downconverted JSON 5.0 records)

3. https://www.cve.org (JSON 5.0) : (CVE ID retrieval pane at the top of the page): This view provides a rendering of individual records in JSON 5.0 format (and will include all JSON 4.0 records that have been upconverted to JSON 5.0).
