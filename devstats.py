#! /usr/bin/env python
import argparse
import os
import sys

import git

SINCE = "Feb 1 2023"
UNTIL = "May 1 2023"


class Config:
    # Repos in which we count releases
    RELEASE_REPOS = (
        "zeek/zeek",
        "auxil/spicy/spicy"
    )

    # Repos in which we count commits
    COMMIT_REPOS = (
        "auxil/bifcl",
        "auxil/binpac",
        "auxil/broker",
        "auxil/btest",
        "auxil/gen-zam",
        "auxil/netcontrol-connectors",
        "auxil/package-manager",
        "auxil/paraglob",
        "auxil/rapidjson",
        "auxil/spicy-plugin",
        "auxil/spicy/spicy",
        "auxil/zeek-af_packet-plugin",
        "auxil/zeek-archiver",
        "auxil/zeek-aux",
        "auxil/zeek-client",
        "auxil/zeekctl",
        "auxil/zeekjs",
        "cmake",
        "doc",
        "src/3rdparty",
    )

    def __init__(self, rootdir):
        self.rootdir = rootdir


class Results:
    def __init__(self, cfg):
        self.cfg = cfg

    def get_commits(self):
        for repopath in self.cfg.COMMIT_REPOS:
            abs_repopath = os.path.join(self.cfg.root, repopath)
            if not os.path.isdir(abs_repopath):
                print(f"Skipping {repopath}, not a directory")
                continue
            repo = git.Repo(abs_repopath)

def main():
    return 0

if __name__ == '__main__':
    sys.exit(main())
