import { Command } from 'commander';
/**
 * Abstract base class for common functionality to all other XXXCommand classes
 */
export declare abstract class GenericCommand {
    /** command name */
    _name: string;
    /** the Command object from the commander library */
    _program: Command;
    /** ----- cveUtils version string ----- ----- */
    /** The version string is taken from the version string in package.json to promote a consistent
     *  location for setting cveUtils metadata.  It is purposely set in "code" instead of in `.env`
     *  because it should be "baked in" to the code instead of potentially changeable at runtime.
     *  This way, if there is a problem in CVEProject/cvelistV5, the output in github actions will
     *  reflect the actual version of this app, and it will
     *  simplify figuring out what the exact code looked like based on the tag.
     *
     */
    static __utilVersionString: string;
    static getUtilityVersion(): string;
    private static setUtilityVersion;
    /** constructor
     * @param name the command name
     * @param program the Command object (from main.ts)
     */
    constructor(name: string, program: Command);
    _startTimestamp: number;
    /** resets the command timer */
    timerReset(): number;
    /** returns the number of seconds since timerReset() */
    timerSinceStart(): number;
    /** common functions to run before run()
     *  All subclasses should call this first in the overridden run() function
    */
    prerun(options: any): void;
    /** common functions to run after run()
     *  All subclasses should call this last in the overridden run() function
    */
    postrun(options: any): void;
    /** this is the method that performs the work for a specific command in the subclass
     *  All subclasses should override this
     */
    run(options: any): Promise<void>;
}
