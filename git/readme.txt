its finally time to learn git


CURRENTLY: https://www.atlassian.com/git/tutorials
doing the 'git tag' stuff
https://www.atlassian.com/git/tutorials/inspecting-a-repository/git-tag

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


'git checkout COMMIT' - Move HEAD to the given commit. This will update the files in the working directory to match the given commit. Usually you provide a branch as the argument.. if you give it a non-branch commit that will put you into a detached head state!

Detached head state - This is a problem that happens when you checkout a specific commit (using a hash or ref) that does not correspond to a branch ref. Because HEAD is not pointing to a branch, if you make changes then commit, the changes may be lost forever!


'git reset COMMIT' - move HEAD and the current branch head to COMMIT. Will update the staging index, working directory, and commit history. 


'git init' - initialize this as a git repository (.git directory)

'git init --bare' - Bare repos do not contain a working copy of the code. They are made to be a hub or node which can be cloned and updated by developers. You do not do development in a bare repo.


'git remote' or 'git remote -v' - list the remote names and their corresponding URLs

Configuration: There are actually 3 different config files in 3 different locations. The first is --system, shared by all users on the machine. The second is --global which is used by a single user. Finally --local will configure for a git repo (in the .git directory). Git will search for local space first, then global, then system
Configuration guide: https://git-scm.com/book/en/v2/Customizing-Git-Git-Configuration
'git config --global user.name NAME' - set default username to NAME