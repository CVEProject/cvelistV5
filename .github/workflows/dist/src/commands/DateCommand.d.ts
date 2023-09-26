import { Command } from 'commander';
import { GenericCommand } from './GenericCommand.js';
/** Command to print out current date in various formats */
export declare class DateCommand extends GenericCommand {
    constructor(program: Command);
    run(options: any): Promise<void>;
}
