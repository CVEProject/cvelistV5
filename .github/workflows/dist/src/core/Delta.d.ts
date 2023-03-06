export declare type IsoDate = string;
export declare type CveId = string;
export interface CveCore {
    cveId: string;
    state?: string;
    assignerOrgId?: string;
    assignerShortName?: string;
    dateReserved?: IsoDate;
    datePublished?: IsoDate;
    dateUpdated?: IsoDate;
}
export interface DeltaProps {
    published?: CveCore[];
    updated?: CveCore[];
    unknown?: CveCore[];
}
export declare enum DeltaQueue {
    kPublished = 1,
    kUpdated = 2
}
export declare class Delta implements DeltaProps {
    published: CveCore[];
    updated: CveCore[];
    unknown: CveCore[];
    constructor(prevDelta?: DeltaProps);
    static calculateDelta(prevDelta: Delta): Delta;
    add(cve: CveCore, queue: DeltaQueue): void;
}
