import { Command } from 'commander';
import { GenericCommand } from './GenericCommand.js';
export declare class RebuildCommand extends GenericCommand {
    constructor(program: Command);
    run(options: any): Promise<void>;
}
