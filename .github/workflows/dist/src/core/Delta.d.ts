/**
 *  Delta object, calculates deltas in activities
 */
import { CveCore } from './CveCore.js';
export declare type IsoDate = string;
export declare enum DeltaQueue {
    kNew = 1,
    kPublished = 2,
    kUpdated = 3,
    kUnknown = 4
}
export declare class Delta {
    numberOfChanges: number;
    new: CveCore[];
    updated: CveCore[];
    unknown: CveCore[];
    /** constructor
     *  @param prevDelta a previous delta to intialize this object, essentially appending new
     *                   deltas to the privous ones (default is none)
     */
    constructor(prevDelta?: Partial<Delta>);
    /**
     * Factory that generates a new Delta from git log based on a time window
     * @param start git log start time window
     * @param stop git log stop time window (defaults to now)
     */
    static newDeltaFromGitHistory(start: string, stop?: string, repository?: string): Promise<Delta>;
    /** returns useful metadata given a repository filespec:
     *   - its CVE ID (for example, CVE-1970-0001)
     *   - its partial path in the repository (for example, ./abc/def/CVE-1970-0001)
     *  @param path a full or partial filespec (for example, ./abc/def/CVE-1970-0001.json)
     *  @todo should be in a separate CveId or Cve class
     */
    static getCveIdMetaData(path: string): [string | undefined, string | undefined];
    /** calculates the delta filtering using the specified directory
     *  @param prevDelta the previous delta
     *  @param dir directory to filter (note that this cannot have `./` or `../` since this is only doing a simple string match)
     */
    static calculateDelta(prevDelta: Partial<Delta>, dir: string): Promise<Delta>;
    /**
     * pure function:  given origQueue, this will either add cve if it is not already in origQueue
     * or replace the original in origQueue with cve
     * @param cve the CVE to be added/replaced
     * @param origQueue the original queue
     * @returns a typle:
     *    [0] is the new queue (with the CVE either added or replace older)
     *    [1] either 0 if CVE is replaced, or 1 if new, intended to be += to this.numberOfChanges (deprecated)
     */
    private _addOrReplace;
    /** calculates the numberOfChanges property
     * @returns the total number of deltas in all the queues
     */
    calculateNumDelta(): number;
    /** adds a cveCore object into one of the queues in a delta object
     *  @param cve a CveCore object to be added
     *  @param queue the DeltaQueue enum specifying which queue to add to
     */
    add(cve: CveCore, queue: DeltaQueue): void;
    /** summarize the information in this Delta object in human-readable form */
    toText(): string;
    /** writes the delta to a JSON file
     *  @param relFilepath relative path from current directory
    */
    writeFile(relFilepath?: string): void;
    /**
     * Copies delta CVEs to a specified directory, and optionally zip the resulting directory
     * @param relDir optional relative path from current directory to write the delta CVEs, default is `deltas` directory
     * @param zipFile optional relative path from the current directory to write the zip file, default is NOT to write to zip
     */
    writeCves(relDir?: string, zipFile?: any): void;
    writeTextFile(relFilepath?: string): void;
}
