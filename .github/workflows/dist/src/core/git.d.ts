/** a wrapper/fascade class to make it easier to use git libraries from within cve utils
 *  Note that because the git utility (and thus this class and the SimpleGit library this class
 *  depends on) is meant to be used by one process at a time in each "clone" (i.e., each directory
 *  that contains a `.git` subdirectory), there are operations that is not easily used or tested
 *  in an asynchronous environment (e.g., cveUtils and jest tests).
 *
 *  Specifically, the methods `status()`, `add()`, and "rm()" can have non-deterministric behavior
 *  when used asynchronously in multiple places.
 *
 *  To successfully test these methods, follow the style/pattern of testing described in cveUtil's
 *  GitLab Issue 7.
*/
import { CommitResult, Response, SimpleGit, StatusResult } from 'simple-git';
import { Delta } from './Delta.js';
export { StatusResult, Response };
export declare class Git {
    localDir: string;
    git: SimpleGit;
    /** constructor
     * @param init initializer
     */
    constructor(init?: Partial<Git>);
    /** returns git status in a promise
     *  Note that this operation may not be deterministic if, for example, the `rm` method is called
     *  asynchronously elsewhere in the app.  See the note for this class above for more details.
     *
     *  Note that while StatusResult shows files with paths relative to pwd, working
     *  with those files (for example, add or rm) requires a full path
    */
    status(): Promise<StatusResult>;
    static genericCallback(err: any): void;
    /** calculates the delta filtering using the specified directory
     *  @param prevDelta the previous delta
     *  @param dir directory to filter (note that this cannot have `./` or `../` since this is only doing a simple string match)
     */
    static calculateDelta(prevDelta: Partial<Delta>, dir: string): Promise<Delta>;
    /**
     * Factory that generates a new Delta from git log based on a time window
     * @param start git log start time window
     * @param stop git log stop time window (defaults to now)
     */
    static newDeltaFromGitHistory(start: string, stop?: string, repository?: string): Promise<Delta>;
    /** git add files to git stage
     *  Note that this operation may not be deterministic if, for example, the `rm` method is called
     *  asynchronously elsewhere in the app.  See the note for this class above for more details.
     *
     *  @param fullPathFiles a single file or array of files to be added to stage
     *    Note that fullPathFiles must be either full path specs or partial paths from this.localDir
     *    Note that fullPathFiles should NOT be a directory
     *
     */
    add(fullPathFiles: string | string[]): Promise<Response<string>>;
    /** git rm files from git stage
     *  Note that this operation may not be deterministic if, for example, the `rm` method is called
     *  asynchronously elsewhere in the app.  See the note for this class above for more details.
     *
     *  @param fullPathFiles a single file or array of files to be added to stage
     *    Note that fullPathFiles must be either full path specs or partial paths from this.localDir
     *    Note that fullPathFiles should NOT be a directory
    */
    rm(fullPathFiles: string | string[]): Promise<Response<void>>;
    /**
     * commits staged files
     * @param msg commit message
     * @returns CommitResult
     *
     */
    commit(msg: string): Promise<CommitResult>;
    /**
     *  logs commit hash and date between time window
     */
    logCommitHashInWindow(start: string, stop: string): Promise<string[]>;
    /**
     *  logs changed filenames in time window
     */
    logChangedFilenamesInTimeWindow(start: string, stop: string): Promise<string[]>;
    /**
     *  logs deltas in time window
     */
    logDeltasInTimeWindow(start: string, stop: string): Promise<Delta>;
}
