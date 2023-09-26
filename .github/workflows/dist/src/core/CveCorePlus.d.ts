/**
 *  CveCorePlus extends CveCore by adding things that are useful
 *  for various purposes (e.g., activity logs, delta, twitter):
 *  Currently, it adds:
 *    - description from container.cna.description
 *    - githubLink calculated based on GH_OWNER and GH_REPO currently running in
 */
import { CveId } from './CveId.js';
import { CveCore } from './CveCore.js';
import { CveMetadata } from '../generated/quicktools/CveRecordV5.js';
import { CveRecord } from './CveRecord.js';
export { CveId } from './CveId.js';
export { CveCore } from './CveCore.js';
export declare class CveCorePlus extends CveCore {
    description?: string;
    githubUrl?: string;
    /** optional field for storing timestamp when the update github action added
     *  this to the repository
     */
    /**
     * constructor which builds a minimum CveCore from a CveId or string
     * @param cveId a CveId or string
     */
    constructor(cveId: string | CveId);
    /** factory method that synchronously reads in a CVE Record from a CVE JSON 5.0 formatted file
     *  @param relFilepath relative or full path to the file
     *  @returns a CveCorePlus object or undefined if the JSON file cannot be read
     */
    static fromJsonFile(relFilepath: string): CveCorePlus | undefined;
    /**
     * builds a full CveCorePlus using provided metadata
     * @param metadata the CveMetadata in CVE JSON 5.0 schema
     * @returns
     */
    static fromCveMetadata(metadata: Partial<CveMetadata>): CveCorePlus;
    /**
     * builds a full CveCorePlus from a CveCore
     * @param cveCore a CveCore object
     * @returns a CveCorePlus object
     */
    static fromCveCore(cveCore: CveCore): CveCorePlus;
    /**
     * builds a full CveCorePlus from a CveCore
     * @param cveCore a CveCore object
     * @returns a CveCorePlus object
     */
    static fromCveRecord(cve: CveRecord): CveCorePlus;
    set(metadata: Partial<CveMetadata>): void;
    /**
     * update CveCorePlus with additional data from the repository
     * @returns true iff a JSON file was found and readable to fill in
     * ALL the fields in the CveCorePlus data structure
     */
    updateFromLocalRepository(): boolean;
}
