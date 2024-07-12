> **Note 2024-07-11 on upcoming CVE Program Container launch**:  On July 17, 2024 the CVE Program Secretariat will begin populating a new “Secretariat Program Container”  which will be implemented as an [adp container](https://cveproject.github.io/cve-schema/schema/docs/#oneOf_i0_containers_adp) in the CVE record.  Over time, this new container will house various “value added” Secretariat/Program data that will further enrich CVE Records.
>
>On July 17, the Secretariat will begin placing additional references that it finds through its reference scraping capability into this new container.  (It will no longer place these references in the CNA container of the record as it has in the past.)  
>
>After the deployment is complete (which is scheduled to be run from July 17 through July 31), each CVE Record that is in the the CVE Repository on July 17  will have this new Secretariat Program Container.  The Secretariat container for these records will contain two types of references:
>1. references that are part of a “snapshot” (i.e, copy) list of all the references that are in the CNA container as of July 17, 2024.  This list of references is  only a “snapshot in time” and will not kept "in sync" with the CNA provided reference over time.
>
> 2.	newly scraped references that have been identified by the Secretariat on (or after) July 17.  
To support downstream users in determining which references have been “copied” and which references have been provided by the Secretariat, the copied references will be labeled with an *x_transferred*  tag.   References provided by the Secretariat will have no tag.
>
>Moving forward, all Secretariat provided references for a CVE Record will be stored in the Secretariat Program Container of that record.  If there is no Secretariat provided enriched data (e.g, no scraped references) for a CVE Record, there will be no Secretariat Program Container associated with the CVE Record.  Aslo note, CVE Records published after July 17 will have no references that are tagged *x_transferred*.
>
>**Parsing the Secretariat Program Container:** References in the Secretariat Program Container maintain the same format and properties as in the record's CNA container (see adp references definition/description [here](https://cveproject.github.io/cve-schema/schema/docs/#oneOf_i0_containers_adp_items_references)).  
>
> **Potential for Duplicate References:**  The possibility of reference duplication is an artifact of having more than one organization providing references in separate locations. Users of CVE data should recognize the possibility for duplicate references and be prepared to address that possibility in their processing.  Initially, the *x_transferred* tag can offer a clue that a reference is a duplicate (as it was originally copied from the CNA container).  However over time, the *x_transferred* tag will become less relevant as CNAs may delete references in the CNA container making the  *x_transferred* tagged reference in the Secretariat Program Container no longer  duplicate reference.   In addition a CNA may add a reference that already exists in the Secretariat Program Container making a reference not tagged as an *x_transferred* reference in the Secretariat Program Container a duplicate of one that is in the CNA container.  In the end, downstream users will have to determine the appropriate manner in which to resolve potential reference duplication between the CNA container and the Secretariat Program Container for their use. 

> **Note 2024-05-08 5:30pm**:  CVE REST Services was updated to the CVE Record Format Schema 5.1 on 2024-05-08 at 5:30pm EDT.  With this update, a CVE Record in this repository may now be either a 5.0 or a 5.1 formatted record.   The format is reflected in the the "dataversion" field.  Users of this repository who "validate" CVE records are advised to validate records by using the  appropriate version of the schema (i.e, 5.0 or 5.1) as reflected in this field.  Users should not determine which schema to use based on the deployment date of the new format (i.e., 2024-05-08 at 5:30pm EDT)  as there are inconsistencies in published/updated date values.
>  
# CVE List V5

This repository is the official [CVE List](https://www.cve.org/ResourcesSupport/Glossary?activeTerm=glossaryCVEList).  It is a catalog of all [CVE Records](https://www.cve.org/ResourcesSupport/Glossary?activeTerm=glossaryRecord) identified by, or reported to, the [CVE Program](https://www.cve.org/).

This repository hosts downloadable files of CVE Records in the [CVE Record Format](https://www.cve.org/AllResources/CveServices#cve-json-5) (view the [schema](https://github.com/CVEProject/cve-schema)). They are updated regularly (about every 7 minutes) using the official CVE Services API.  You may search, download, and use the content hosted in this repository, per the [CVE Program Terms of Use](https://www.cve.org/Legal/TermsOfUse).

**Legacy Format Downloads No Longer Supported**—All support for the legacy CVE content download formats (i.e., CSV, HTML, XML, and CVRF) ended on June 30, 2024. These legacy download formats, which will no longer be updated and were phased out over the first six months of 2024, have been replaced by this repository as the only supported method for CVE Record downloads. Learn more [here](https://www.cve.org/Media/News/item/blog/2024/07/02/Legacy-CVE-Download-Formats-No-Longer-Supported). 

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

1. **Added 3/28/2023:** CVE Records published prior to 2023 may have significant publication, reserved, and update date discrepancies. As a result, this repository should not be used for CVE production metrics at this time. A fix will be forthcoming. 

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

