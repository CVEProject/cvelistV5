/**
 *  ActivityLog - log of activities
 *  Intent is to log everything that makes changes to the repository, so key information is stored from
 *  GitHub action to GitHub action (e.g., stopdate of last activity for re-running a command)
 */
import { Activity } from './Activity.js';
export interface ActivityLogOptions {
    path?: string;
    filename?: string;
    logCurrentActivity?: boolean;
    logAlways?: boolean;
    logKeepPrevious?: boolean;
}
export declare class ActivityLog {
    _options: ActivityLogOptions;
    _fullpath: string;
    _activities: Activity[];
    constructor(options: ActivityLogOptions);
    clearActivities(): void;
    /**
     * @returns the most recent activity object
     */
    getMostRecentActivity(): Activity;
    /**
     * prepends activity to activities
     * @param activity the activity object to prepend
     * @returns the current list of activities, after prepending
     */
    prepend(activity: Activity): Activity[];
    /** writes activities to a file
      * @return true iff the file was written
      */
    writeRecentFile(): boolean;
    /** reads in the recent activities into _activities */
    static readFile(relFilepath: string): Activity[];
    /** writes to activity file */
    static writeFile(relFilepath: string, body: string): void;
}
