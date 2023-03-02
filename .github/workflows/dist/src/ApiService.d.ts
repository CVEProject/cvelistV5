export declare class ApiService {
    /** url to CVE ID services */
    _url: string;
    /** default header when sending requests to CVE services */
    _headers: {
        "Content-Type": string;
        "CVE-API-ORG": string;
        "CVE-API-USER": string;
        "CVE-API-KEY": string;
        redirect: string;
    };
    /** gets the current timestamp  */
    static timestamp(humanReadable?: boolean): string;
    /** wrapper for /cve-id */
    constructor(url: string);
}
