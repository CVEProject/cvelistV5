import { Cve5, CveMetadata, Containers } from './generated/transform.tools/cve5.js';
export { CveId, CveIdError } from './core/CveId.js';
export interface WriteFileOptions {
    prettyprint?: boolean;
}
export declare class Cve implements Cve5 {
    _defaultOutdir: string;
    cveId: string;
    containers: Containers;
    cveMetadata: CveMetadata;
    dataType?: string;
    dataVersion?: number;
    sourceObj: {};
    /** reads in a proper CVE JSON 5 obj (e.g., JSON.parse()'d content of a file or the response from the CVE API 2.1)
     *  @param obj a Javascript object that conforms to the CVE JSON 5 specification
     *  @todo verify it is a CVE JSON 5 format that we know how to work with
    */
    constructor(obj: Cve5);
    /** given a cveId, returns the git hub repository partial path it should go into
     *  @param cveId string representing the CVE ID (e.g., CVE-1999-0001)
     *  @returns string representing the partial path the cve belongs in (e.g., /1999/1xxx/CVE-1999-0001)
    */
    static toCvePath(cveId: string): string;
    /** returns an array of CVE years represented as numbers [1999...2024] */
    static getAllYears(): ReadonlyArray<number>;
    toCvePath(): string;
    toJsonString(prettyPrint?: boolean): string;
    readJsonFile(relFilepath: string): Cve;
    writeJsonFile(relFilepath: string, prettyprint?: boolean): void;
    writeToCvePath(repositoryRoot: String): void;
}
