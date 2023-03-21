/**
 *  CveId is an object that represents a CVE ID and provides
 *  helper functions to use it
 */
export declare class CveIdError extends Error {
}
export declare class CveId {
    /** internal representation of the CVE ID */
    id: string;
    /**
     * @param id a string representing a CVE ID (e.g., CVE-1999-0001)
     * @throws CveIdError if id is not a valid CVE ID
     */
    constructor(id: string | CveId);
    /**
     * returns the partial CVE Path based on the CVE ID
     * @returns the partial CVE path, e.g., 1999/0xxx/CVE-1999-0001
     */
    getCvePath(): string;
    /**
     * returns the full CVE Path based on the CVEID and pwd
     * @returns the full CVE Path, e.g., /user/cve/cves/1999/0xxx/CVE-1999-0001
     */
    getFullCvePath(): string;
    /** returns an array of CVE years represented as numbers [1999...2024] */
    static getAllYears(): ReadonlyArray<number>;
    /** given a cveId, returns the git hub repository partial directory it should go into
     *  @param cveId string representing the CVE ID (e.g., CVE-1999-0001)
     *  @returns string representing the partial path the cve belongs in (e.g., /1999/1xxx/CVE-1999-0001)
    */
    static getCveDir(cveId: string | CveId): string;
    /** given a cveId, returns the git hub repository partial path it should go into
     *  @param cveId string representing the CVE ID (e.g., CVE-1999-0001)
     *  @returns string representing the partial path the cve belongs in (e.g., /1999/1xxx/CVE-1999-0001)
    */
    static toCvePath(cveId: string | CveId): string;
}
