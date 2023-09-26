/**
 *  CveId is an object that represents a CVE ID and provides
 *  helper functions to use it
 */
export declare class CveIdError extends Error {
}
export declare type CveIdComponents = [
    boolean,
    string | undefined,
    string | undefined,
    string | undefined,
    string | undefined
];
export declare class CveId {
    /** internal representation of the CVE ID */
    id: string;
    /**
     * @param id a CveId instance or a string representing a CVE ID (e.g., CVE-1999-0001)
     * @throws CveIdError if id is not a valid CVE ID
     */
    constructor(id: string | CveId);
    /** returns the CVE ID as a string */
    toString(): string;
    /** properly outputs the CVE ID in JSON.stringify() */
    toJSON(): string;
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
    /**
     * returns the official CVEProject/cvelistV5 URL to this CVE ID
     */
    getRawGithubUrl(): string;
    private static _years;
    /**
     * checks if a string is a valid CveID
     *  @param id a string to test for CveID validity
     *  @returns a tuple:
     *    [0]:  (boolean) true iff valid CveID
     *    [1]:  (string) "CVE"
     *    [2]:  (string) year
     *    [3]:  (string) id/thousands
     *    [4]:  (string) id
     *    For example, CVE-1999-12345 would return
     *    [true,"CVE","1999","12xxx", "12345"]
     */
    static toComponents(cveId: string | CveId): CveIdComponents;
    /**
     * checks if a string is a valid CveID
     *  @param id a string to test for CveID validity
     *  @returns true iff str is a valid CveID
     */
    static isValidCveId(id: string): boolean;
    /** returns an array of CVE years represented as numbers [1999...2025]
     *  the algorithm takes the current year from the current (local) time,
     *    then adds 2 more years to end to accommodate future CVEs,
     *    and adds 1970 in front
     */
    static getAllYears(): ReadonlyArray<number>;
    /** given a cveId, returns the git hub repository partial directory it should go into
     *  @param cveId string or CveId object representing the CVE ID (e.g., CVE-1999-0001)
     *  @returns string representing the partial path the cve belongs in (e.g., /1999/1xxx)
    */
    static getCveDir(cveId: string | CveId): string;
    /** given a cveId, returns the git hub repository partial path (directory and filename without extension) it should go into
     *  @param cveId string representing the CVE ID (e.g., CVE-1999-0001)
     *  @returns string representing the partial path the cve belongs in (e.g., /1999/1xxx/CVE-1999-0001)
     */
    static toCvePath(cveId: string | CveId): string;
}
