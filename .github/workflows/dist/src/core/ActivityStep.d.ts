/**
 *  Activity logs
 */
export interface ActivityError {
    [key: string]: string;
}
export interface ActivityNotes {
    [key: string]: string;
}
export interface ActivityAction {
    startTime: string;
    stopTime: string;
    duration: string;
    name: string;
    url?: string;
    "action-op": {
        status: `complete` | `failed`;
        errors?: ActivityError[];
        notes?: ActivityNotes;
    };
    delta: {
        newCves: string[];
        updatedCves: string[];
    };
}
export interface ActivityOperation {
    activity: string;
    startTime: string;
    stopTime: string;
    duration: string;
    summary: {
        startWindow?: string;
        endWindow?: string;
        page?: number;
        count: number;
        cveIds?: string[];
    };
}
export interface Activity {
    action: ActivityAction;
    operation: ActivityOperation;
}
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
    writeRecentFile(): void;
    /** reads in the recent activities into _activities */
    static readFile(relFilepath: string): Activity[];
    /** writes to activity file */
    static writeFile(relFilepath: string, body: string): void;
}
