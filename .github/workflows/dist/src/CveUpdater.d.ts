/**
 * Updates repository's CVEs using CveService
 */
import { Activity, ActivityStep } from './core/Activity.js';
import { ActivityLogOptions, ActivityLog } from './core/ActivityLog.js';
export declare const kActivity_UpdateByModificationDateWindow = "UPDATE_BY_MODIFICATION_DATE_WINDOW";
export declare const kActivity_UpdateByPage = "UPDATE_BY_PAGE";
export declare class CveUpdater {
    /** repository base path */
    _repository_base: string;
    _release_note_path: string;
    _recent_activities_path: string;
    _activityLog: ActivityLog;
    constructor(activity: string, logOptions: ActivityLogOptions);
    /** retrieves the CVEs in a window of time
     *  @param startWindow requested start window, MUST BE ISO
     *  @param endWindow requested end window, MUST BE ISO
     *  @param max max records requested
     *             if the number of records in [startWindow,endWindow] > max, then endWindow is shortened until
     *             number of records < max
     *  @returns an Activity with data and properties OR
     *           null if params are detected to be a no-op
     *
     *  @todo NOTE that there is a known bug at present, where if there were > max records that were changed in less than 1 second
     *  this will go into an endless loop
    */
    getFirstCvesFrame(startWindow: string, endWindow: string, max?: number, writeDir?: string): Promise<ActivityStep>;
    /** retrieves the CVEs in a window of time
     *  @param startWindow requested start window, MUST BE ISO
     *  @param endWindow requested end window, MUST BE ISO
     *  @param max max records requested
     *             if the number of records in [startWindow,endWindow] > max, then endWindow is shortened until
     *             number of records < max
     *  @returns an Activity with data and properties OR
     *           null if params are detected to be a no-op
    */
    getCvesInWindow(startWindow: string, endWindow: string, max?: number, writeDir?: string): Promise<Activity>;
    /** retrieves all CVEs by page
     *  @param page requested page number
     *  @returns an Activity with data and properties OR
     *           null if params are detected to be a no-op
    */
    getCvesByPage(page: number, writeDir?: string): Promise<ActivityStep>;
    /** reads recent activities data */
    readRecentActivities(): Activity[];
    /** write recent activities to file */
    writeRecentActivities(): boolean;
}
