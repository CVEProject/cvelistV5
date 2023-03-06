import { Command } from 'commander';
import { GenericCommand } from './GenericCommand.js';
export declare class GithubCommand extends GenericCommand {
    constructor(program: Command);
    static shouldCollect(element: any, options: any): boolean;
    static collectRuns(options: any, octokit: any): Promise<any[]>;
    run(options: any): Promise<void>;
}
