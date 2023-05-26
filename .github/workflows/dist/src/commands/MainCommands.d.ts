/** object that encapsulates all tested and available cli commands */
export declare class MainCommands {
    protected _program: any;
    constructor(version: string);
    run(): Promise<void>;
}
