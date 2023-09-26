import { Command } from 'commander';
import { GenericCommand } from './GenericCommand.js';
/** Command to update local repository using CVE REST API */
export declare class UpdateCommand extends GenericCommand {
    /** default number of minutes to look back when a start date is not specified */
    static defaultMins: number;
    constructor(program: Command);
    /** determines the time options (start, stop, minutesAgo) behavior */
    static determineQueryTimeOptions(options: any, now: string): any;
    /** runs the command using user set or default/calculated options */
    run(options: any): Promise<void>;
}
