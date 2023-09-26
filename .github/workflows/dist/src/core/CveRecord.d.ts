import { CveId } from './CveId.js';
import { CveRecordV5, CveMetadata, Containers } from '../generated/quicktools/CveRecordV5.js';
export { CveId, CveIdError } from './CveId.js';
export interface WriteFileOptions {
    prettyprint?: boolean;
}
export declare class CveRecord implements CveRecordV5 {
    _defaultOutdir: string;
    cveId: string;
    containers: Containers;
    cveMetadata: CveMetadata;
    dataType?: string;
    dataVersion?: number;
    sourceObj: unknown;
    /** reads in a proper CVE Record JSON v5 format obj (e.g., JSON.parse()'d content of a file or the response from the CVE API 2.1)
     *  @param obj a Javascript object that conforms to the CVE Record JSON v5 format specification
     *  @todo verify it is a CVE Record JSON v5 format format that we know how to work with
     */
    constructor(obj: CveRecordV5);
    /** factory method that converts a CveId to a path in the
     *  default `/cves` subdirectory, and synchronously reads in that CVE JSON 5.0 formatted file
     *  and builds a CveRecord
     *  @param cveId a string or CveId object
     *  @param cves_directory (optional) relative or full path to where to find CVEs, if null, use .env spec
     *    (e.g., `./test/fixtures/cve/5`)
     *  @returns a CveRecord
     */
    static fromCveId(cve_id: string | CveId, cves_directory?: string): CveRecord | undefined;
    /** factory method that synchronously reads in a CVE Record from a CVE JSON 5.0 formatted file
     *  @param relFilepath relative or full path to the file
     *  @returns a CveRecord
     */
    static fromJsonFile(relFilepath: string): CveRecord | undefined;
    /** returns the description from containers.cna.descriptions that has the language specified
     * @param lang the ISO 639-1 lanugage code (defaults to 'en', which will also match 'en', 'En-US', 'en-uk', etc.)
     * @returns the description, or undefined if it can't find the description in the specified language
     */
    getDescription(lang?: string): string | undefined;
    /** returns the git hub repository partial path this CveRecord should go into
     *  @returns string representing the partial path the cve belongs in (e.g., /1999/1xxx/CVE-1999-0001)
     */
    toCvePath(): string;
    /** prints object in JSON format
     *  @param prettyPrint boolean to set pretty printing (default is true)
     *  @returns a JSON string
     */
    toJsonString(prettyPrint?: boolean): string;
    /** writes a CVE Record to a file in CVE JSON 5.0 format
     *  @param relFilepath relative path to the file
     *  @param prettyprint boolean to set whether to pretty print the output
     */
    writeJsonFile(relFilepath: string, prettyprint?: boolean): void;
    /** writes a CVE Record to a file in CVE JSON 5.0 format
     *  @param repositoryRoot path where the repository is (the full path will be determined by the CveID)
     *  @param prettyprint boolean to set whether to pretty print the output
     *  @returns the full path where the file was written to
     */
    writeToCvePath(repositoryRoot: string, prettyprint?: boolean): string;
}
