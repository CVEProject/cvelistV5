/**
 * Utility class to facilitate dates in Javascript, standardizing all dates to
 *  ISO format:  2023-03-25T00:00:00.000Z
 */
export declare class DateUtils {
    /**
     * @param timestamp a Date timestamp object, defaults to current timestamp
     * @returns the current date in ISO format
     */
    static getIsoDate(timestamp?: Date): string;
    /**
     * gets the date and time portions of a Date object as a tuple, defaults to current timestamp
     * @param date the Date object
     * @returns date portion of date as a string
     */
    static dateComponents(date?: Date): string[];
    /**
     * gets the date portion of a Date object as a string, defaults to current timestamp
     * @param date the Date object
     * @returns date portion of date as a string
     */
    static dateStringFromDate(date?: Date): string;
    /**
     * returns today's midnight (i.e., today's date with hours all set to 0)
     */
    static getMidnight(): Date;
}
