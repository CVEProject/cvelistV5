/**
 *  DeltaLog - log of current and recent historical deltas
 *  Intent is to log all deltas from the current delta to recent historical deltas,
 *  so key information is stored, and other systems using deltas as polling integration points
 *  can poll at almost arbitrary frequency
 *
 *  The deltas in the DeltaLog is intended to provide most of the useful information
 *  about a CVE, so that
 *    1. the data can be used as a filter
 *    2. minimize REST calls to CVE REST Services
 */
import { Delta } from './Delta.js';
import { IsoDateString } from '../common/IsoDateString.js';
export declare class DeltaLog extends Array<Delta> {
    static kDeltaLogFilename: string;
    static kDeltaLogFile: string;
    /** constructor */
    constructor();
    /** constructs a DeltaLog by reading in the deltaLog file
     *  @param pruneOlderThan optional ISO date, any items older than that date will
     *    not be included in the resulting DeltaLog
     *  @param relFilepath optional path to the logfile (defaults to cves/deltaLog.json)
     *
    */
    static fromLogFile(relFilepath?: string, pruneOlderThan?: IsoDateString): DeltaLog;
    /**
     * prepends a delta to log
     * @param delta the Delta object to prepend
     */
    prepend(delta: Delta): void;
    /** sorts the Deltas in place by the `fetchTime` property
     *  @param direction: one of
     *            - "latestFirst" - reverse chronological order (default)
     *            - "latestLast" - chronological order
    */
    sortByFetchTme(direction?: "latestFirst" | "latestLast"): DeltaLog;
    /** writes deltas to a file
     *  @param relFilepath optional relative or full filepath
     *  @returns true iff the file was written (which only happens when
     *    there the [0] delta has changes)
      */
    writeFile(relFilepath?: string): boolean;
}
