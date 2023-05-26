/** Class representing a strongly opinionated ISO Date+Time+TZ string with utils
 *  Note that this class was written to be very opinionated. See IsoDateString.test.ts for properly formatted
 *    and improperly formatted strings.  In general, the output of Date.toISOString() is
 *    the preferred format, with some exceptions as noted in IsoDateString.test.ts
 *
 *  Note that in the future, if necessary, we can extend what this class covers, but for now
 *    this strict and opinionated set is very useful for processing ISO Date+Time+TZ strings
*/
/** a regular expression to represent an ISO Date+Time+TZ string
 *  taken from https://stackoverflow.com/a/3143231/1274852
 *  works for cases used in CVE representations
 */
export declare const IsoDateStringRegEx: RegExp;
export declare class IsoDateString {
    _isoDateString: string;
    /** returns a IsoDateString object iff isoDateStr is a properly formatted ISO Date+Time+TZ string */
    constructor(isoDateStr: string);
    /** returns the number of characters in the string representation */
    length(): number;
    /** returns the string representation */
    toString(): string;
    /** returns a JS Date object from the string representation */
    toDate(): Date;
    /** strict testing of a string for being a valid ISO Date+Time+TZ string  */
    static isIsoDateString(str: string): boolean;
}
