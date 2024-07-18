/**
 *  DeltaLog - log of current and recent historical deltas
 *  Intent is to log all deltas from the current delta to recent historical deltas,
 *  so key information is stored, and other systems using deltas as polling integration points
 *  can poll at any frequency less than the period
 *  defined in `.env`'s `CVES_DEFAULT_DELTA_LOG_HISTORY_IN_DAYS` environment variable
 *  (30 days is current default)
 *
 *  The deltas in the DeltaLog is intended to provide just sufficient information
 *  to decide if a downstream app should be updated:
 *    1. CVEs that were added
 *    2. CVEs there were updated
 *    3. URLs to GitHub and CVE REST Services to retrieve full CVE details
 *    4. timestamp when the CVEs were committed to the repository
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
    /** prunes and returns a NEW delta log with specified start and stop fetchTimes
     *
     */
    static pruneByFetchTime(origLog: DeltaLog, startDate: IsoDateString | string, stopDate?: IsoDateString | string): DeltaLog;
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
    /**
     * Creates a single Delta object that contains all of the CVEs in each queue as if
     * all the operations within the time window had happened as a single event
     * Note that if a CVE was published and then subsequently updated, that CVE
     *  will show up in both the new and updated queues.  If you want all CVEs
     *  from both new and updated queues, run getAllUniqueNewAndUpdatedCves() on the returned Delta object
     *
     * @param startWindow IsoDateString for start of time window
     * @param stopWindow  optional IsoDateString for stop of time window
     * @returns a single Delta object with all of the consolidated data from all the Deltas in the time window
     */
    consolidateDeltas(startWindow: IsoDateString, stopWindow?: IsoDateString): Delta;
    /** writes deltas to a file
     *  @param relFilepath optional relative or full filepath
     *  @returns true iff the file was written (which only happens when
     *    there the [0] delta has changes)
      */
    writeFile(relFilepath?: string): boolean;
    static fitDeltaLogToFileSize(relFilePath: string, fileSizeLimitBytes: number): boolean;
}
