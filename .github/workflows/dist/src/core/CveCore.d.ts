/**
 *  CveCore is made up of mostly the metadata portion of a CVE JSON 5 object
 *    plus (eventually) of additional metadata (such as SHA) that is useful for managing/validating CVEs
 */
import { CveMetadata } from '../generated/transform.tools/cve5.js';
import { Cve } from '../Cve.js';
import { CveId } from './CveId.js';
export { CveId, CveIdError } from './CveId.js';
export declare type IsoDate = string;
export declare class CveCore {
    cveId: CveId;
    state?: string;
    assignerOrgId?: string;
    assignerShortName?: string;
    dateReserved?: IsoDate;
    datePublished?: IsoDate;
    dateUpdated?: IsoDate;
    constructor(cveId: string | CveId);
    static fromCveMetadata(metadata: Partial<CveMetadata>): CveCore;
    /**
     * returns the CveId from a full or partial path (assuming the file is in the repository directory)
     *  @param path the full or partial file path to CVE JSON file
     *  @returns the CveId calculated from the filename, or "" if not valid
     */
    static getCveIdfromRepositoryFilePath(path: string): string;
    /**
     * returns the CveId from a full or partial path (assuming the file is in the repository directory)
     *  @param path the full or partial file path to CVE JSON file
     *  @returns the CveId calculated from the filename
     */
    static fromRepositoryFilePath(path: string): CveCore;
    static fromCve(cve: Cve): CveCore;
    toJson(whitespace?: number): string;
    getCvePath(): string;
}
