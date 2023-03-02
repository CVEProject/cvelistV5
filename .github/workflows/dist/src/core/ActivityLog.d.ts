/**
 *  ActivityLog - log of activities
 *  Intent is to log everything that makes changes to the repository
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
