import { Delta } from '../core/Delta.js';
export interface ActivityError {
    [key: string]: string;
}
export interface ActivityNotes {
    [key: string]: string;
}
export declare enum ActivityStatus {
    Unknown = "unknown",
    NoStarted = "not_started",
    InProgress = "in_progress",
    Completed = "completed",
    Failed = "failed"
}
export interface ActivityProps {
    startTime: string;
    stopTime: string;
    duration: string;
    name: string;
    url?: string;
    status: ActivityStatus;
    errors?: ActivityError[];
    notes?: ActivityNotes;
    delta?: Delta;
    steps?: ActivityStep[];
}
export interface ActivityStep {
    stepDescription: string;
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
export declare class Activity implements ActivityProps {
    startTime: string;
    stopTime: string;
    duration: string;
    name: string;
    url?: string;
    status: ActivityStatus;
    errors?: ActivityError[];
    notes?: ActivityNotes;
    delta?: Delta;
    steps: ActivityStep[];
    constructor(props?: ActivityProps);
    equalTo(props: ActivityProps): boolean;
    prependStep(step: ActivityStep): ActivityStep[];
}
