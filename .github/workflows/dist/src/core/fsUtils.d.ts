/** a wrapper/fascade class to make it easier to work with the file system */
export declare class FsUtils {
    path: string;
    constructor(path: any);
    static ls(path: string): string[];
    /**
     * Synchronously generate a zip file from an array of files (no directories)
     * @param filepaths array of filenames to be zipped
     * @param resultFilepath filename for resulting zip file
     * @param zipVirtualDir dir name in zip, defaults to `files`
     *                      (for example, if you want to add all the files
     *                       into a zip folder called abc,
     *                        you would pass 'abc' here)
     * @param dir path to directory where files are located
     */
    static generateZipfile(filepaths: string | string[], resultFilepath: string, zipVirtualDir?: string, dir?: string): void;
}
