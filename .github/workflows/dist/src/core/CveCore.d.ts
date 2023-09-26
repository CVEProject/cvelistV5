/**
 *  CveCore is made up of the metadata portion of a CVE JSON 5 object
 *  Note that it is convenient to store additional data for some operations,
 *  and for that, the CveCorePlus object should be used
 */
import { CveId } from './CveId.js';
import { CveMetadata } from '../generated/quicktools/CveRecordV5.js';
import { CveRecord } from './CveRecord.js';
export { CveId, CveIdError } from './CveId.js';
declare type IsoDate = string;
export declare class CveCore {
    cveId: CveId;
    state?: string;
    assignerOrgId?: string;
    assignerShortName?: string;
    dateReserved?: IsoDate;
    datePublished?: IsoDate;
    dateUpdated?: IsoDate;
    /**
     * constructor which builds a minimum CveCore from a CveId or string
     * @param cveId a CveId or string
     */
    constructor(cveId: string | CveId);
    /**
     * builds a full CveCore using provided metadata
     * @param metadata the CveMetadata in CVE JSON 5.0 schema
     * @returns
     */
    static fromCveMetadata(metadata: Partial<CveMetadata>): CveCore;
    set(metadata: Partial<CveMetadata>): void;
    updateFromJsonString(jsonstr: string): void;
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
    /** returns a CveCore object from a CveRecord */
    static fromCveRecord(cveRecord: CveRecord): CveCore;
    getCvePath(): string;
}
