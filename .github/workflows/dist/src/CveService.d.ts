import { Cve } from './Cve.js';
import { ApiService } from './ApiService.js';
export interface CveApiOptions {
    id?: string;
    queryString?: string;
}
export declare class CveService extends ApiService {
    constructor();
    /** returns the CVE with id
     *
     */
    getCveUsingId(id: string): Promise<Cve>;
    /** returns array of CVE that has been added/modified/deleted since timestamp window */
    getAllCvesChangedInTimeFrame(start: string, stop: string): Promise<Cve[]>;
    /** wrapper for /cve */
    cve(option: CveApiOptions): Promise<any>;
}
