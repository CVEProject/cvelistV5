import { Command } from 'commander';
import { Octokit } from "octokit";
import { GenericCommand } from './GenericCommand.js';
export declare class GithubCommand extends GenericCommand {
    constructor(program: Command);
    /** connects to github using the env specified access token, owner, and repo
     *  @returns the octokit object
     */
    static connect(owner?: string, repo?: string): Promise<Octokit>;
    run(options: any): Promise<void>;
}
