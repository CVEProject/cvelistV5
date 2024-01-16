# CVE List V5

The [CVE List](https://www.cve.org/ResourcesSupport/Glossary?activeTerm=glossaryCVEList) is catalog of all [CVE Records](https://www.cve.org/ResourcesSupport/Glossary?activeTerm=glossaryRecord) identified by, or reported to, the [CVE Program](https://www.cve.org/).

This repository hosts bulk download files of CVE Records in [CVE JSON 5.0 format](https://www.cve.org/AllResources/CveServices#cve-json-5) (view the [schema](https://github.com/CVEProject/cve-schema)). You may search, download, and use the content hosted in this repository, per the [CVE Program Terms of Use](https://www.cve.org/Legal/TermsOfUse).

**Legacy Format Downloads Available for Limited Time**—[Legacy format CVE List downloads](https://www.cve.org/Downloads#legacy-format) that are currently available for download on the CVE.ORG website, which are derived from CVE JSON 4.0, will be [phased out in the first half of 2024](https://medium.com/@cve_program/deprecation-of-legacy-cve-download-formats-now-underway-43701aafcc67). Learn more [here](https://medium.com/@cve_program/deprecation-of-legacy-cve-download-formats-now-underway-43701aafcc67).

## Releases

This repository includes [release versions](https://github.com/CVEProject/cvelistV5/releases) of all current CVE Records generated from the official CVE Services API. Baseline releases are issued once per day at midnight and posted in the following file name format: CVE Prefix-Year-Month-Day _ Greenwich Mean Time (GMT), (e.g., “CVE 2023-03-28_0000Z”). Hourly updates are also provided on the [Releases](https://github.com/CVEProject/cvelistV5/releases) page using the same file name format, with time changes encoded at the end.

Each baseline or hourly release includes three items:

- ZIP file of all current CVE Records at midnight (e.g., “2023-03-28_all_CVEs.zip”)
- ZIP file of all CVE Records added or modified since midnight (e.g., “2023-03-28_delta_CVEs_at_2200Z.zip”)
- Release Notes for the specific release

NOTE: The most [current release](https://github.com/CVEProject/cvelistV5/releases) contains the most up-to-date CVE List content. Hourly updates contain only the most recent updates.

## Known Issues with the cvelistV5 repository

The CVE Program is currently aware of the following issues with regard to CVE List downloads. These issues are currently being addressed by the [CVE Automation Working Group (AWG)](https://www.cve.org/ProgramOrganization/WorkingGroups#AutomationWorkingGroupAWG). Updates or resolutions will be noted here when available.

1. **Added 3/28/2023:** CVE Records published prior to 2023 may have significant publication, reserved, and update date discrepancies. As a result, this repository should not be used for CVE production metrics at this time. A fix will be forthcoming. 

Issues listed in this section are not included in the [Repository Issue Tracker](https://github.com/CVEProject/cvelistV5/issues).

## Reporting Issues 

Please use one of the following: 

- [Report repository and download file issues](https://github.com/CVEProject/cvelistV5/issues) (via the cvelistV5 repository Issue Tracker on GitHub)
- [Report issues with the content of a CVE Record](https://cveform.mitre.org/) (via the CVE Program Request Web Forms) 

## Pull Requests Not Allowed 

This repository contains CVE Records published by CVE Program partners. It does not accept pull requests.

## Cloning this Repository

You may clone the repository using [git clone](https://github.com/git-guides/git-clone). However, pull requests will not be accepted. 

## Help

Please use the [CVE Request Web Forms](https://cveform.mitre.org/) and select “Other” from the dropdown.

