>**Note 2024-09-17 CVE Repository Historical Record Correction:** CVE Records originally published prior to 2023 with incorrect Reserved/Published/Update dates have been corrected.  This action corrected approximately 27,000 records that had erroneously been assigned incorrect Reserved, Published or Updated dates as part of JSON 5.0 CVE Record adoption.

> **Note 2024-07-31 CVE Records may now contain a new container called the *CVE Program Container***:  This new container provides additional information added by the CVE Program to include Program-added references.  Users of this repository may need to process two containers.  See below for more information.   

> **Note 2024-05-08 5:30pm**:  CVE REST Services was updated to the CVE Record Format Schema 5.1 on 2024-05-08 at 5:30pm EDT.  With this update, a CVE Record in this repository may now be either a 5.0 or a 5.1 formatted record.   The format is reflected in the the "dataversion" field.  Users of this repository who "validate" CVE records are advised to validate records by using the  appropriate version of the schema (i.e, 5.0 or 5.1) as reflected in this field.  Users should not determine which schema to use based on the deployment date of the new format (i.e., 2024-05-08 at 5:30pm EDT)  as there are inconsistencies in published/updated date values.
>  
# CVE List V5

This repository is the official [CVE List](https://www.cve.org/ResourcesSupport/Glossary?activeTerm=glossaryCVEList).  It is a catalog of all [CVE Records](https://www.cve.org/ResourcesSupport/Glossary?activeTerm=glossaryRecord) identified by, or reported to, the [CVE Program](https://www.cve.org/).

This repository hosts downloadable files of CVE Records in the [CVE Record Format](https://www.cve.org/AllResources/CveServices#cve-json-5) (view the [schema](https://github.com/CVEProject/cve-schema)). They are updated regularly (about every 7 minutes) using the official CVE Services API.  You may search, download, and use the content hosted in this repository, per the [CVE Program Terms of Use](https://www.cve.org/Legal/TermsOfUse).

**Legacy Format Downloads No Longer Supported**—All support for the legacy CVE content download formats (i.e., CSV, HTML, XML, and CVRF) ended on June 30, 2024. These legacy download formats, which will no longer be updated and were phased out over the first six months of 2024, have been replaced by this repository as the only supported method for CVE Record downloads. Learn more [here](https://www.cve.org/Media/News/item/blog/2024/07/02/Legacy-CVE-Download-Formats-No-Longer-Supported). 

## CVE Record Containers

CVE Records may now consist of multiple containers:
* A CNA container
* The CVE Program Container
* Optional multiple ADP-specific containers

### CVE Program Container

All CVE Program-added references after 7/31/2024 for a CVE Record will be stored in the CVE Program Container of that Record.  CNA-provided references will continue to be stored in the CNA Container. 

The CVE Program Container is implemented in an [ADP container format](https://cveproject.github.io/cve-schema/schema/docs/#oneOf_i0_containers_adp) in the CVE Record.

Specific JSON/CVE Record fields that will be in the CVE Program Container are as follows:
* adp:title field: "**CVE Program Container**"
* adp:providerMetadata:shortName:"**CVE**"
* adp:references field as described [here](https://cveproject.github.io/cve-schema/schema/docs/#oneOf_i0_containers_adp_items_references)

References in the CVE Program Container maintain the same format as references in a CNA Container.

The CVE Program container may contain references that have the *x_transferred* tag.  References with this tag were read from the CNA container on 7/31/2024.  This is a "one time" copy to maintain the "state" of the CNA reference list as of 7/31/2024.   CVE Program-added references after this date will not have the *x_transfered" tag.

In the case of new CVE records created after 7/31/2024, if no Program provided enriched data is added, there will be no CVE Porgram Container associated with the CVE Record. 

#### Implementation Considerations: 

*Required Containers processing:*  After 7/31//2024, to retrieve all information about a reported vulnerability in the CVE Repositoyr, tool vendors and community users will need to examine the CVE Record CNA Container and the CVE Program Container (if one exists).  These two containers are minimially required to obtain the core information required by the Program.  All other ADP constainers remain optional from a Program perspective.

*Potential for Duplicate References* The possibility of reference duplications is an artifact of having more than one organizatoin providing references in separate locations.   Downstream users will have to determine the appropriate way to resovle potential reference duplications between the CNA container and the CVE Program Container.   

### CISA-ADP Container

The CISA-ADP Container was launched on June 4 to provide value added information for CVE Records going forward, and retroactively to February, 2024.

The CISA ADP is providing three components to enrich CVE Records:
1. [Stakeholder-Specific vulnerability Categorization (SSVC)](https://www.cisa.gov/stakeholder-specific-vulnerability-categorization-ssvc)
1. [Known Exploitable Vulnerabilities (KEV)](https://www.cisa.gov/known-exploited-vulnerabilities-catalog) catalog data
1. "Vulnrichment" updates (e.g., missing [CVSS](https://www.first.org/cvss/), [CWE](https://cwe.mitre.org/), [CPE information](https://nvd.nist.gov/products/cpe) for CVE Records that meet specific threat characteristics, and for when CNAs do not provide it themselves)

Reference the [CISA ADP Process](https://www.cve.org/ProgramOrganization/ADPs)  or the [CISA Vulnrichment github site](https://github.com/cisagov/vulnrichment) for a full description of what information is provided and the format in which it is recorded. 

## How to Download the CVE List

There are 2 main ways to download CVE Records from this repository:
1. using [`git` clients](https://git-scm.com/) — this is the fastest way to keep the CVE List up-to-date using tools most developers are familiar with.  For more information, see [the `git` section ](#git), below
2. using the Releases zip files.  For more information, see [the Releases section](#releases), below.

## git

Using the [`git` command line tool](https://git-scm.com/) or [any git UI clients](https://git-scm.com/downloads/guis) is the easiest way to stay up-to-date with the CVE List.  To get started, clone this repository:  `git clone git@github.com:CVEProject/cvelistV5.git`.
Once cloned, `git pull` at any time you need to get the latest updates, just like any other GitHub repository.

## Releases

This repository includes [release versions](https://github.com/CVEProject/cvelistV5/releases) of all current CVE Records generated from the official CVE Services API. All times are listed in [Coordinated Universal Time (UTC)](https://en.wikipedia.org/wiki/Coordinated_Universal_Time).  Each release contains a description of CVEs added or updated since the last release, and an Assets section containing the downloads.  Note that the zip files are quite large and so will take some time to download.
* Baseline downloads are issued at the end of each day at midnight and posted under Assets in the following file name format: `Year-Month-Day_all_CVEs_at_midnight.zip`, (e.g., `2024-04-04_all_CVEs_at_midnight.zip`).  This file remains unchanged for 24 hours.  If you are updating your CVE List using zip files daily (or less frequently), this is the best one to use.
* Hourly updates are also provided under Assets using the file name format: `Year-Month-Day _delta_CVEs_at_Hour 00Z.zip`, (e.g., `2024-04-04_delta_CVEs_at_0100Z.zip`).  This is useful if you need your CVE List to be accurate hourly.  Be aware that this file only contains the deltas since the baseline zip file.

## Known Issues with the cvelistV5 repository

The CVE Program is currently aware of the following issues with regard to CVE List downloads. These issues are currently being addressed by the [CVE Automation Working Group (AWG)](https://www.cve.org/ProgramOrganization/WorkingGroups#AutomationWorkingGroupAWG). Updates or resolutions will be noted here when available.

1. **Updated 9/17/2024:** Some CVE Records published prior to 2023 had publication, reserved, and update date discrepancies. As of 9/17/2024 this has been corrected.
   
1. **Added 9/17/2024:** Publication and update date discrepancies exist for CVE recrods published by the MITRE CNA-LR between May 8, 2024 and June 7, 2024 (affecting approximately 515 records).  
Users of this repository for CVE metrics (and other publication/udpate data senstive analysis) should be aware of this issue.  A fix will be forthcoming.

    

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

