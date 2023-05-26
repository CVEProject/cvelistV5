import { Command } from 'commander';
/**
 * Abstract base class for common functionality to all other XXXCommand classes
 */
export declare abstract class GenericCommand {
    /** command name */
    _name: string;
    /** the Command object from the commander library */
    _program: Command;
    /** constructor
     * @param name the command name
     * @param program the Command object (from main.ts)
     */
    constructor(name: string, program: Command);
    /** ----- version string ----- ----- */
    static __versionString: string;
    static getUtilityVersion(): string;
    static setUtilityVersion(versionString: string): string;
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
