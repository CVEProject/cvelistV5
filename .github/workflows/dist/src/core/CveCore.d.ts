/**
 *  CveCore is made up of mostly the metadata portion of a CVE JSON 5 object
 *    plus (eventually) of additional metadata (such as SHA) that is useful for managing/validating CVEs
 */
import { CveMetadata } from '../generated/transform.tools/cve5.js';
import { Cve } from '../Cve.js';
export declare type IsoDate = string;
export declare type CveId = string;
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
    static fromCve(cve: Cve): CveCore;
    toJson(whitespace?: number): string;
    getCvePath(): string;
}
