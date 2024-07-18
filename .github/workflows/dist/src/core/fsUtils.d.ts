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
    static deleteProperties(obj: unknown, propPath: string): unknown;
    /** returns true iff the content of file at path 1 and the file at path 2 are exactly the same
     *  @param path1 the relative or fullpath to a file
     *  @param path2 the relative or fullpath to another file
     *  @param ignoreJsonProps optional array of json paths to ignore, e.g., ["cveMetadata.datePublished", "cveMetadata.dateUpdated", "cveMetadata.dateReserved"]
     */
    static isSameContent(path1: string, path2: string, ignoreJsonProps?: string[]): boolean;
    /**
     * Condense json data file.
     * NOTE: Will overwrite the given file!
     * condenseLevels:
     *  0: pretty indent with 2 space
     *  1: pretty indent with 1 space
     *  2: strip leading whitespace from pretty file
     *  3: minified / no whitespace
     *
     * @param condenseLevel level to condense to.
     * @param filePath file with json data to be changed.
     * @returns the new file size in bytes.
     * @throws Error if invalid condenseLevel or invalid filePath argument.
     */
    static condenseJsonDataFile(condenseLevel: number, filePath: string): number;
}
