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
    /** kFirstYear: The first year CVE IDs started to be assigned.*/
    static readonly kFirstYear: number;
    /** kTestYear: An arbitrary year, that does not overlap with a valid CVE ID year, used for development and testing. */
    static readonly kTestYear: number;
    private static _years;
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
     * returns the raw github URL to this CVE ID
     */
    getRawGithubUrl(): string;
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
    /** returns an array of CVE years represented as numbers (e.g. [1970,1999..2025])
     *  the algorithm builds the valid years from 1999 to the environment variable CVES_MAX_ALLOWABLE_CVE_YEAR
     *  (or if the environment variable is not present, current year + 2)
     *  and adds 1970 in front for test CVEs
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
    /** comparator for use with sort() to sort CVE IDs "numerically" by year and then by the ID so that
     *  CVE-1999-2001 comes before CVE-1999-10001 and CVE-2000-110022
     *  This is needed because different systems (e.g., fs when sorting local directories, and opensearch sorted responses)
     *  sort strings differently.  This standardizes on a single sorting algorithm
     *  @param a string representing a CVE ID
     *  @param b string representing another CVE ID
     */
    static comparator(a: string, b: string): number;
}
