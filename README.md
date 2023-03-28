# CVE List V5

This repository is a JSON 5.0 cache of the official CVE List.
- `cves` directory contains all of the current CVEs from the official CVE Services API.
- `review_set` directory has been removed.  It contained old data from October 2022, and was only used for review purposes in October 2022.

The files here are identical in content to the JSON files retrieved from the [CVE Web Services](https://www.cve.org), with the exception that the files are prettyprinted here (using 4 spaces) for viewing.

## Deprecated Services

1. https://cve.org/Downloads: This location contains the traditional downloadable CVE list that is available in the following formats: csv, html, tzt, xml.

2. https://github.com/CVEProject/cvelist (JSON 4.0): The github submission pilot will continue to be maintained during the course of the JSON 4.0 --> JSON 5.0 transition. The format is JSON 4.0 ( but it will include downconverted JSON 5.0 records)
