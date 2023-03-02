/**
 * Wrapper object that provides access to the CVE ID Services API
 *  Note that the location of the CVE Services API, username, password, tokens, etc., is
 *    set in the project's .env file.
 */
import { ApiService } from './ApiService.js';
export interface CveIdResponse {
    cve_ids: CveIdData[];
    totalCount: number;
    itemsPerPage: number;
    pageCount: number;
    currentPage: number;
    prevPage: number | null;
    nextPage: number | null;
}
export interface CveIdData {
    "requested_by": {
        "user": string;
        "cna": string;
    };
    "time": {
        "created": string;
        "modified": string;
    };
    "cve_id": string;
    "cve_year": string;
    "state": "RESERVED" | "PUBLISHED" | "REJECTED";
    "reserved": string;
    "owning_cna": string;
}
export interface CveIdApiOptions {
    cve_id_year?: string;
    page?: number;
    state?: "RESERVED" | "PUBLISHED" | "REJECTED";
    time_reserved_lt?: string;
    time_reserved_gt?: string;
    time_modified_lt?: string;
    time_modified_gt?: string;
}
export declare class CveIdService extends ApiService {
    constructor();
    /** returns all the pages for a set of options
     *  Note, however, that due to a bug, if the total number of items exceeds
     *    some large number (e.g., records in 2020), then the server returns
     *         "error": "SERVICE_NOT_AVAILABLE",
     *    so for now, to get all the records for a given year, it is safer
     *    to use getCveIdsUsingYear() below, which divides each year and
     *    calls this function summing up all results
     */
    getAllCveIdsPages(options: CveIdApiOptions): Promise<CveIdResponse>;
    /** returns the CVE IDs from a specified year by breaking the year
     *  into quarters and summing each quarter.  This is because when the
     *  number of records for a year exceeds some large number, the server
     *  responds with "error": "SERVICE_NOT_AVAILABLE"
     *
     */
    getCveIdsUsingYear(year: string): Promise<CveIdResponse>;
    /** wrapper for /cve-id */
    cveIds(option: CveIdApiOptions): Promise<CveIdResponse>;
}
