import { Command } from 'commander';
export declare class GenericCommand {
    _name: string;
    _program: Command;
    constructor(name: string, program: Command);
    static getUtilityVersion(): string;
    _startTimestamp: number;
    timerReset(): number;
    timerSinceStart(): number;
    prerun(options: any): void;
    postrun(options: any): void;
    run(name: any, options: any, command: any): Promise<void>;
}
