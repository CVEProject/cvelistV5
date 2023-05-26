/** a wrapper/fascade class to make it easier to work with the file system SYNCRHONOUSLY */
export declare class FsUtils {
    path: string;
    constructor(path: any);
    /**
     * synchronously returns whether the path exists
     * (very thin wrapper for fs.existsSync which is NOT deprecated, unlike fs.exists)
     * @param path the full or partial path to test
     * @returns true iff the specified path exists
     */
    static exists(path: string): boolean;
    /**
     * synchronously removes the specified file iff it exists
     * @param path
     * @returns true if the file was removed, false if it did not exist in the first place
     */
    static rm(path: string): boolean;
    static ls(path: string): string[];
    /**
     * Synchronously generate a zip file from an array of files (no directories)
     * @param filepaths array of filenames to be zipped
     * @param resultFilepath filepath for resulting zip file
     * @param zipVirtualDir dir name in zip, defaults to `files`
     *                      (for example, if you want to add all the files
     *                       into a zip folder called abc,
     *                        you would pass 'abc' here)
     * @param dir path to directory where files are located
     */
    static generateZipfile(filepaths: string | string[], resultFilepath: string, zipVirtualDir?: string, dir?: string): void;
}
