import { Command } from 'commander';
import { GenericCommand } from './GenericCommand.js';
export declare class UpdateCommand extends GenericCommand {
    static defaultMins: number;
    constructor(program: Command);
    static determineQueryOptions(options: any, now: string): any;
    run(options: any): Promise<void>;
}
