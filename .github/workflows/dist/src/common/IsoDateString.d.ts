/** Class representing a strongly opinionated ISO Date+Time+TZ string with utils
 *  Note that this class was written to be very opinionated. See IsoDateString.test.ts for properly formatted
 *    and improperly formatted strings.  In general, the output of Date.toISOString() is
 *    the preferred format, with some exceptions as noted in IsoDateString.test.ts
 *
 *  Note that in the future, if necessary, we can extend what this class covers, but for now
 *    this strict and opinionated set is very useful for processing ISO Date+Time+TZ strings
 */
export declare const IsoDateStringRegEx: RegExp;
export declare const GregorianLeapDateRegEx: RegExp;
export declare class IsoDateString {
    _isoDateString: string;
    _date: Date;
    /** returns a IsoDateString object iff isoDateStr is a properly formatted ISO Date+Time+TZ string,
     *  or if a string is not specified, then this will create a IsoDateString of "now" using new Date()
     *  Note that the constructor will always create a new IsoDateString containing a valid value, or it will throw an exception
     *  @param isoDateStr a properly formatted ISO Date+Time+TZ string (defaults to now)
     *  @param assumeZ set to true if want to assume a trailing Z for GMT/Zulu time zone (default is false)
     *                 this is needed because CVEs timestamps may be missing the timezone, and we are assuming it to be GMT
     */
    constructor(isoDateStr?: string, assumeZ?: boolean);
    /**
     * builds an IsoDateString using a Javascript Date object
     * @param date a JavaScript Date object
     * @returns an IsoDateString
     */
    static fromDate(date: Date): IsoDateString;
    /**
     * builds an IsoDateString using the number of seconds since 1/1/1970
     * @param secsSince1970 number representing seconds since 1/1/1970
     * @returns an IsoDateString
     */
    static fromNumber(secsSince1970: number): IsoDateString;
    static fromIsoDateString(isoDateStr: IsoDateString): IsoDateString;
    /** returns the number of characters in the string representation */
    length(): number;
    /** returns the string representation */
    toString(): string;
    /**
     * @returns a number representing the number of millisecs since 1970-01-01T00:00:00.000Z
     */
    toNumber(): number;
    /** properly outputs the object in JSON.stringify() */
    toJSON(): string;
    /** returns a JS Date object from the string representation */
    toDate(): Date;
    /** strict testing of a string for being a valid ISO Date+Time+TZ string  */
    static isIsoDateString(str: string): boolean;
    /**
     * return a new IsoDateString that is minutes ago or since
     * @param minutes positive number to minutes ago, negative number for minutes since
     * @returns a new IsoDateString that is specified minutes ago or since
     */
    minutesAgo(minutes: number | string): IsoDateString;
    /**
     * return a new IsoDateString that is hours ago or since
     * @param hours positive number to hours ago, negative number for hours since
     * @returns a new IsoDateString that is specified hours ago or since
     */
    hoursAgo(hours: number | string): IsoDateString;
    /**
     * return a new IsoDateString that is days ago or since
     * @param days positive number to days ago, negative number for days since
     * @returns a new IsoDateString that is specified days ago or since
     */
    daysAgo(days: number | string): IsoDateString;
}
