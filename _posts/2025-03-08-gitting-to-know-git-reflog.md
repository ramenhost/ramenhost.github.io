---
title: "Gitting to know git reflog"
description: "A deep dive into git reflog with examples"
date: 2025-03-08 15:15:00 +0530
categories: [General]
tags: [git, programming]
media_subpath: ../../images/git-reflog
---

We know that git tracks changes to files in working directory, allowing us to easily undo modifications or revert to previous states. But what happens when we accidentally delete an unpublished branch or perform hard reset to a wrong commit? That's when we need undo button for the git operation itself. Have you ever used `git reset --hard` and then scrambled to recover your changes by copying commands from Stackoverflow or ChatGPT? If so, you've likely encountered `git reflog`. Think of it as a micro version control (log) for your Git references. For straight forward reverting of file changes, read this blog post from GitHub, [How to undo (almost) anything with Git](https://github.blog/open-source/git/how-to-undo-almost-anything-with-git/). While the GitHub's post covers reflog in brief, it doesn't delve into reflog's full power. There are articles with reflog commands to recover but I did not see any that explained why or how it works. This post aims to explain the internals of git in the context of reflog with examples.

## Some Git Internals
In order for `git reflog` and `git reset` commands to not seem magical, let's understand how git stores commits and references. The following information changed the way I think about git and I hope it does the same for you. Make sure to read it slowly and visualize the concepts.

### Commits
It is a common misconception that git stores commits as diffs from the previous commit. While this mental model is useful, it is not entirely accurate. Git stores snapshots of the entire working directory at each commit. This doesn't mean that git duplicates the entire working directory every time you commit, it uses packfiles and file hashes to optimize storage (don't worry about this for now). Just remember that given a commit ID, git can recreate the entire working directory at that commit, from the snapshots. 

The folder `.git/objects` inside a repository is sort of an object database where git stores many objects. Now, what are these objects? Git stores commits, trees, and blobs as objects. A commit object contains metadata like author, commit message, parent commit ID, and a reference to a tree object (the snapshot of working directory). A tree object contains references to blobs (files) and other tree objects (subdirectories). A blob object contains the file contents. What matters is that given a commit ID, git can fetch the tree object ID and from there, recursively fetch all the blobs to recreate the working directory at that commit. Julia Evans (@b0rk) has a great zine on this topic, [Git - wizardzines](https://wizardzines.com/zines/git/).

![inside a git commit](inside-commit.png)
Source: [https://wizardzines.com/zines/git/](https://wizardzines.com/zines/git/)

### References
Branches, tags, and HEAD are examples of references. Git references are pointers to commits. To create a branch, git creates a file in `.git/refs/heads` with the branch name as the filename and the commit ID as the content. All the information that git stores for a branch is only the commit ID as seen in below example.

```bash
$ git branch                              
* devel
  master

$ cat .git/refs/heads/master
c0c0f13291ba4aa367cfd2736ab6e85dcdb2a979

$ cat .git/refs/heads/devel 
758f588337b33c22b0c2da81bab80e5b9b5555e8
```

> For demostration puposes, I decided to use the [`rohitmungre/hello-world`](https://github.com/rohitmungre/hello-world) repository. Someone is in a journey of writing write hello world in all programming languages. As a moral support, I decided to use this repository for examples. 
{: .prompt-info}

But, when we do `git log`, we can see the all commits in the branch. The reason this works is each commit object contains parent commit ID. Think of commits like a linked list, each commit points to its parent commit forming a chain. We need the tip commit ID to traverse the chain and see all the commits. References, including branches, are just pointers to the tip of the chain i.e. references are head pointers of the linked list. A branch name, which is a reference, is just a convenient way to refer to the tip commit.

HEAD is a special reference that points to another reference. The HEAD, stored in `.git/HEAD`, is by which git knows what is the current branch (the commit chain that is currently checked out in the working directory). When switching branches, git updates HEAD file with name of the target branch. In short, we could have multiple chains of commits, each chain starting from a reference. The HEAD points to one among them denoting the chain that is currently checked out.

```bash
$ git branch
* devel
  master

$ cat .git/HEAD
ref: refs/heads/devel
```

![how git log works](git-log.png)

## Git reflog
Before we dive into reflog, let's understand what happens when we do a `git reset --hard`. The `git reset` command is used to move the branch reference to a different commit. The `--hard` option tells git to update the working directory to match the commit contents. `git reset --hard HEAD~1` is used to remove the latest commit from the branch. The `HEAD~1` is a shorthand for the commit that is one before the current commit.

```bash
$ cat .git/refs/heads/devel 
758f588337b33c22b0c2da81bab80e5b9b5555e8

$ git reset --hard HEAD~1
HEAD is now at 0733b44 Create hello.bf

$ cat .git/refs/heads/devel
0733b445485af40a798d6d07dc72f84986025975
```

![how git reset looks](git-reset-looks.png)

But what happened to the `758f588` commit? It is still there, but the branch reference is no longer pointing to it. 

```bash
$ cat .git/refs/heads/devel 
758f588337b33c22b0c2da81bab80e5b9b5555e8

$ git reset --hard HEAD~1
HEAD is now at 0733b44 Create hello.bf

$ cat .git/refs/heads/devel
0733b445485af40a798d6d07dc72f84986025975


$ git cat-file -p 758f588337b33c22b0c2da81bab80e5b9b5555e8       
tree 2b0424507c2767b5a7f5d35e6278419cdeb9132a
parent 0733b445485af40a798d6d07dc72f84986025975
author Rohit Mungre <rohitmungre@users.noreply.github.com> 1740835749 +0000
committer GitHub <noreply@github.com> 1741364083 +0000

develop hello.hs
```

As seen above, the commit object of `758f588` is still there, but the branch reference is no longer pointing to it. The commit `758f588` is no longer connected to any chain that starts from a reference (`refs/heads/devel` or `refs/heads/master`). This is why the commit is not visible in `git log`. But the commit object, including its snapshot, is still present in the object database. Hence, a more accurate representation of the reset operation would be below.

![how git reset works](git-reset-actual.png)

If we know the lost commit ID, we can still see the commit. We can also reset back to that commit and recover the changes. But who remembers commit IDs? This is where reflog comes in. Reflog is a log of all changes to references. When we do a `git reset --hard`, git logs the previous commit ID in reflog. This is why reflog can be used to recover from accidental resets.

```bash
$ git reflog                                              
0733b44 (HEAD -> devel) HEAD@{0}: reset: moving to HEAD~1
758f588 HEAD@{1}: commit (amend): develop hello.hs
c0c0f13 (origin/master, origin/HEAD, master) HEAD@{2}: checkout: moving from master to devel
```

The reflog shows the previous commit ID and the operation that was performed. The `HEAD@{0}` (first entry in reflog) is the current tip commit ID that HEAD resolves to. The `HEAD@{1}` refers to the commit ID that HEAD resolved to before that. This is accompanied with the operation that changed the HEAD. To undo the reset command, we can do either of the below.

```bash
$ git reset --hard HEAD@{1}
HEAD is now at 758f588 develop hello.hs

$ git reset --hard 758f588        
HEAD is now at 758f588 develop hello.hs
```

So, does git ever delete a commit? It does, but only after a grace period (default 2 weeks). Git has a garbage collection mechanism that runs periodically and deletes unreachable objects (including commits that are not linked to any chain starting from a reference). But until then, we can recover from accidental resets using reflog.

The reflog works the same for any reference, not just HEAD. For example, `devel{2}` refers to the commit ID that was stored in `./git/refs/heads/devel` two changes ago to that reference. We can see the reflog for a specific reference using `git reflog <ref>`. `git reflog` without any arguments shows the reflog for HEAD.

```bash
$ git reflog devel        
758f588 (HEAD -> devel) devel@{0}: reset: moving to HEAD@{1}
0733b44 devel@{1}: reset: moving to HEAD~1
758f588 (HEAD -> devel) devel@{2}: commit (amend): develop hello.hs
```

## Various ways reflog can save the day
Now, let's see how reflog can be used to recover from various git mishaps.

### Scenario 1: Accidental reset to a wrong commit!
As we saw earlier, reflog can be used to recover from accidental resets. If you reset to a wrong commit, you can use reflog to reset to `HEAD@{1}` or any commit ID that was logged in reflog.

```bash
git reset --hard HEAD@{N}
```

### Scenario 2: Deleted a local branch by mistake!
When a branch is deleted, the branch reference is removed, but the commits are still there. We can use reflog to recover the branch.

```bash
$ git switch master
Switched to branch 'master'
Your branch is up to date with 'origin/master'.

$ git branch         
  devel
* master

$ cat .git/refs/heads/devel
758f588337b33c22b0c2da81bab80e5b9b5555e8

$ git branch -D devel
Deleted branch devel (was 758f588).

$ git branch         
* master
```

![branch deletion](delete-devel.png)

Now, let's use reflog to find the lost commit ID. When we moved from devel to master, the HEAD reference `.git/HEAD` was updated to point to `refs/heads/master`. This change to HEAD reference would have been captured by reflog. With this, we can know the commit ID that HEAD was pointing to before the branch was deleted.

```bash
$ git reflog         
c0c0f13 (HEAD -> master, origin/master, origin/HEAD) HEAD@{0}: checkout: moving from devel to master
758f588 HEAD@{1}: reset: moving to 758f588
```

As seen in reflog, the tip of the devel branch was `758f588`. Now, we must checkout to that commit. Wait, checkout? how does `checkout` differ from `reset`? The `reset` command moves the current branch (master) reference to a different commit. We don't want to change tip of master. The `checkout` command moves the HEAD reference to a different branch/commit. 

![checkout to an unreachable commit](checkout-deleted-commit.png)

```bash
$ git checkout HEAD@{1}                              
Note: switching to 'HEAD@{1}'.

You are in 'detached HEAD' state. You can look around, make experimental
changes and commit them, and you can discard any commits you make in this
state without impacting any branches by switching back to a branch.

If you want to create a new branch to retain commits you create, you may
do so (now or later) by using -c with the switch command. Example:

  git switch -c <new-branch-name>

Or undo this operation with:

  git switch -

Turn off this advice by setting config variable advice.detachedHead to false

HEAD is now at 758f588 develop hello.hs
```

Detached HEAD state? What is that? When we checkout to a commit ID, we are in a detached HEAD state. This means HEAD is not pointing to any branch, instead it is pointing to a commit directly.

```bash
$ cat .git/HEAD            
758f588337b33c22b0c2da81bab80e5b9b5555e8
```

The content of `.git/HEAD` would normally be `ref/heads/master` or `ref/heads/devel`. But in detached HEAD state, it is the commit ID itself. We have recovered the commit chain, but just not the branch yet. From here, we can create a new branch `devel` that would set the branch reference to the same commit as HEAD.

```bash
$ git switch -c devel  
Switched to a new branch 'devel'

$ git branch         
* devel
  master
```

![recovered devel from detached HEAD](branch-from-detached-head.png)

### Scenario 3: Unwanted amend commit happened!
Let's say we have made changes and committed them. But we realize that we missed something and want to amend the commit. We can use `git commit --amend` to add the changes to the previous commit. As a shell "up arrow" enthusiast, I have done amend commit instead of a new commit sometimes. How do we undo this while preserving the changes?

Remember that commit ID is the SHA-1 hash of the commit object, which includes the tree hash and commit details. In case, any of the commit details change, the commit ID would change. When we do `git commit --amend`, git creates a new commit object and replaces the branch reference.

```bash
$ git status           
On branch devel
Changes to be committed:
  (use "git restore --staged <file>..." to unstage)
        modified:   hello.py

$ git log -n2 --oneline
758f588 (HEAD -> devel) develop hello.hs
0733b44 Create hello.bf

$ git commit --amend   
[devel 2942b82] develop hello.hs
 2 files changed, 2 insertions(+), 2 deletions(-)
 create mode 100644 hello.hs

$ git log -n2 --oneline
2942b82 (HEAD -> devel) develop hello.hs
0733b44 Create hello.bf
```

Do you see how the commit ID changed from `758f588` to `2942b82`? It is because git has created an enirely new commit object. 

![amend commit](amend-commit.png)

The previous commit object ID can be found in reflog.

```bash
$ git reflog           
2942b82 (HEAD -> devel) HEAD@{0}: commit (amend): develop hello.hs
758f588 HEAD@{1}: checkout: moving from 758f588337b33c22b0c2da81bab80e5b9b5555e8 to devel
```

To reset back to the state before the amend commit, we can do a `git reset --soft`. `--soft` because we want to keep the changes in the working directory.

```bash
$ git reset --soft HEAD@{1}

$ git status               
On branch devel
Changes to be committed:
  (use "git restore --staged <file>..." to unstage)
        modified:   hello.py

$ git log -n2 --oneline
758f588 (HEAD -> devel) develop hello.hs
0733b44 Create hello.bf
```

## Caveats
1. Reflog captures only the changes to references (HEAD or branches). It cannot help recover uncommited changes to files.
2. Reflog is local to the repository. If you have cloned a repository, you won't have reflog of the remote repository.
3. Unreachable commits and other objects are deleted by git garbage collection (default 2 weeks). If you have lost a commit and it is not in reflog, it is likely gone. The `gc.pruneExpire` configuration can be used to change the grace period.
