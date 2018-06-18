its finally time to learn git


CURRENTLY: https://www.atlassian.com/git/tutorials


HEAD - a ref stored in .git/HEAD. Refers to the commit or branch which is currently checked out (what files are actually in our working directory)

remote - A repository somewhere else (not on this computer). Creating a remote using git is like giving a nickname for a url. 

ref or reference - A ref is a nickname for a commit, because otherwise you would have to refer to a commit using its hash. Internally, git uses refs to do branches and tags! the history of a branch is found by following the branch ref to get the HEAD commit, then following that backwards.
The file .git/HEAD refers to the current ref that is checked out.
The .git/refs/heads/ directory contains refs which are all the local branches

tag - just a ref, made and manipulated using 'git tag'. tags are used most often to mark shipped versions or save a state of the repository. By default 'git tag' will tag HEAD, but it can be passed a specific commit. Use 'git tag -a' to create an "annotated tag", basically just storing some more meta info.

The Three Trees of Git - working directory, staging index, commit history. sounds like a bad horror movie. This is actually a horrible name as they are not trees, but I didn't write the documentation. Basically this means that there are 3 main data structures for storing info about your repo, and changes between commits.
described here: https://www.atlassian.com/git/tutorials/undoing-changes/git-reset
 * Working directory - Your working copy. You might not think of this as a data structure, but git does a bit of work behind the scenes to keep track of things
 * Staging index - add things to this using 'git add'. basically a place you put changes in before they are committed.
 * Commit history - Stores all commits

gitignore - Files to ignore in the repository. Using 1 and 2 star wildcards, can provide more general patterns.
Prepending a '/' will only match starting in the repository root.
If a '/' is appended, the pattern will only match directories. No slash appended could match directories or files.
If the pattern matches a directory, all files and directories in that directory will be ignored.
some common patterns:
 - **/a/b will match a/b ANYWHERE in the repository.

 If you want to have a "gitignore" kind of effect without other users of the repository having it, add your patterns to .git/info/exclude

'git checkout BRANCH' - The usual way we move between local branches.
'git checkout -b NEW_BRANCH <EXISTING_BRANCH>' - convience method to make a new branch. if EXISTING_BRANCH is provided, the new branch will be a copy of that. Otherwise it is a copy of HEAD
'check checkout --track REMOTE/BRANCH' - Checkout and track a remote branch

'git checkout COMMIT' - Move HEAD to the given commit. This will update the files in the working directory to match the given commit. If you give it a non-branch commit that will put you into a detached head state!

'git checkout FILE' - Different from the commit checkout. Will grab that file from HEAD. You can use this to just revert changes you have made to a file.

'git branch -d BRANCH' - delete a branch locally
'git push REMOTE --delte BRANCH' - delete a branch on a remote

.git/objects - keys for an internal hashmap. There are a bunch of directories here. For a simple object (usually a commit?), the directory name is the first 2 letters of the SHA hash, and the file name is the rest of the hash. There are more but I don't feel like reading it: https://git-scm.com/book/en/v2/Git-Internals-Git-Objects

'git fetch REMOTE BRANCH' - downloads the branch info. These commits will be saved into the .git/objects directory so you can now check them out. However a local branch will NOT be created, so this does not change your local history.
To get a local branch into your repository, it might look like this. This assumes you don't have the remote set up yet:
'git remote remote_repository_1 git@remotesite.com:path/to/repo.git'
'git fetch remote_repository_1 progress_remote_branch'
'git checkout progress_remote_branch' to put repo in detached head state, and check out the contents of this branch.
'git checkout -b progress_local_branch' to create a new local branch.
There may be a way to combine the 2 checkouts into 1 command?

It is worth noting that 'git pull' is pretty much a fetch followed by a merge!

Detached head state - This is a problem that happens when you checkout a specific commit (using a hash or ref) that does not correspond to a branch ref. Because HEAD is not pointing to a branch, if you make changes then commit, the changes may be lost forever!

'git merge BRANCH' - Will attempt to bring changes made in BRANCH to the current branch. Git does this by finding the best (first?) common ansestor (this is the commit before they branched off, or earlier) then looking at the changes since then. It will then create a commit which brings the changes made in BRANCH in. If both branches modified the same line/section of a file, there will be a conflict. Use a text editor to fix the conflicts to your liking, do some 'git add' then do a 'git commit'.
Fast forward merge - Merging B2 into B. If B has had no changes since B2 was created, git can just move the B pointer to B2. Very easy!

stashing - 
'git stash save' OR 'git stash' - saves the state of your working directory. --include-untracked option will also stash untracked files
'git stash list' - list current saved stashes
'git stash apply [STASH]' - applies STASH or the most recently saved stash to the current branch.
'git stash drop STASH' - remove STASH from the saved list
'git stash pop STASH' - apply then drop stash

'git reset --hard COMMIT' - move HEAD and the current branch head to COMMIT. Will update the staging index, working directory, and commit history. Trying to push this to a remote repository may throw an error, however: for that use 'git revert' instead
'git reset FILE' or 'git reset COMMIT FILE' is different! Essentially this will reset the the file in the staging area to that commit. Without a commit argument it will default to HEAD, and is the recommended way to un-stage a file

'git revert COMMIT' - Undo some changes without losing them in the git history (like you would with 'git reset --hard'). It generates a "reverse commit" which will undo the changes made in COMMIT. Add the --no-commit flag to stage but not commit the changes.
If you want to generate a compound "reverse commit", then run 'git revert COMMIT --no-commit' on the most recent one, then the next oldest, ect. Finally, commit the combined changes.


'git init' - initialize this as a git repository (.git directory)

'git init --bare' - Bare repos do not contain a working copy of the code. They are made to be a hub or node which can be cloned and updated by developers. You do not do development in a bare repo.


'git remote' or 'git remote -v' - list the remote names and their corresponding URLs

Configuration: There are actually 3 different config files in 3 different locations. The first is --system, shared by all users on the machine. The second is --global which is used by a single user. Finally --local will configure for a git repo (in the .git directory). Git will search for local space first, then global, then system
Configuration guide: https://git-scm.com/book/en/v2/Customizing-Git-Git-Configuration
'git config --global user.name NAME' - set default username to NAME