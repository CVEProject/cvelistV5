/**
 * Updates /cves by dates using CveService
 */
import { Activity, ActivityStep } from '../core/Activity.js';
import { ActivityLogOptions, ActivityLog } from '../core/ActivityLog.js';
export declare const kActivity_UpdateByModificationDateWindow = "UPDATE_BY_MODIFICATION_DATE_WINDOW";
export declare const kActivity_UpdateByPage = "UPDATE_BY_PAGE";
export declare class CveUpdater {
    static _recsPerPage: number;
    /** repository base path */
    _repository_base: string;
    _release_note_path: string;
    _recent_activities_path: string;
    _activityLog: ActivityLog;
    constructor(activity: string, logOptions: ActivityLogOptions);
    /** retrieves CVEs added or updated in a window of time
     *  NOTE that if the number of records is > max, then the window is narrowed
     *  until the number of records is <= max, and only this narrowed window (called a frame) of CVEs
     *  is returned.  It is the responsibility of the caller to repeat
     *  the call (with new startWindow set to previous endWindow) until
     *  new startWindow is >= the original endWindow.  See tests for example.
     *
     *  @param startWindow requested start window, MUST BE ISO
     *  @param endWindow requested end window, MUST BE ISO
     *  @param max max records requested (default is 500)
     *             if the number of records in [startWindow,endWindow] > max, then endWindow is shortened until
     *             number of records < max
     *  @param writeDir a path to write CVE JSON objects to (defaults to undefined, which will not persist any CVEs, useful when trying to query statistics about CVEs)
     *  @returns an Activity with data and properties OR
     *           null if params are detected to be a no-op
     *
     *  @todo NOTE that there is a known bug at present, where if there were > max records that were changed in less than 1 second
     *  this will go into an endless loop.
     *    Note that this has not happened in the last few weeks (hk on 4/5/23).  In the review, Thu suggested to add a sleep function, which I think may be
     *    a good starting point to fix this problem
    */
    getFirstCvesFrame(startWindow: string, endWindow: string, max?: number, writeDir?: string | undefined): Promise<ActivityStep | undefined>;
    /** retrieves the CVEs in a window of time
     *  @param startWindow requested start window, MUST BE ISO
     *  @param endWindow requested end window, MUST BE ISO
     *  @param max max records requested
     *             if the number of records in [startWindow,endWindow] > max, then endWindow is shortened until
     *             number of records < max
     *  @returns an Activity with data and properties OR
     *           null if params are detected to be a no-op
    */
    getCvesInWindow(startWindow: string, endWindow: string, max?: number, writeDir?: string | undefined): Promise<Activity>;
    /** reads recent activities data */
    readRecentActivities(): Activity[];
    /** write recent activities to file */
    writeRecentActivities(): boolean;
}
