/**
 * Abstract base class providing common functions for the CveXXXServices classes
 *  Note that the location of the CVE Services API, username, password, tokens, etc.
 *    are all set in the project's .env file, which must be defined before using
 */
export declare abstract class ApiBaseService {
    /** full url to CVE Service */
    _url: string;
    /** default header when sending requests to CVE Services */
    _headers: {
        "Content-Type": string;
        "CVE-API-ORG": string;
        "CVE-API-USER": string;
        "CVE-API-KEY": string;
        redirect: string;
    };
    /** customize ApiService for specific web service (e.g., '/api/cve')
     *  @param rootpath path starting with '/',  (e.g., '/api/cve')
     */
    constructor(rootpath: string);
}
