#! /usr/bin/env python
import argparse
import os
import re
import sys

import git

SINCE = "Feb 1 2023"
UNTIL = "May 1 2023"


class Config:
    # Repos in which we count releases
    RELEASE_REPOS = (
        "", # Zeek itself
        "auxil/spicy/spicy"
    )

    # Repos in which we count commits
    COMMIT_REPOS = (
        "",
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

    def __init__(self, since, until, rootdir):
        self.since = since
        self.until = until
        self.rootdir = rootdir


class Analysis:
    def __init__(self, cfg):
        self.cfg = cfg
        self.commits = None
        self.releases = None

    def run(self):
        self.commits = self.get_commits()
        self.releases = self.get_releases()

    def print(self):
        print(self.releases)

    def get_commits(self):
        # Returns a table with key being the repo and val being the number of
        # commits.
        res = {}

        for repopath in self.cfg.COMMIT_REPOS:
            abs_repopath = os.path.join(self.cfg.rootdir, repopath)
            if not os.path.isdir(abs_repopath):
                print(f"Skipping {repopath}, not a directory")
                continue

            repo = git.Repo(abs_repopath)
            reponame = self._get_reponame(repo.remotes.origin.url, repopath)

            commits = repo.git.log("--oneline",
                                   "--since", self.cfg.since,
                                   "--until", self.cfg.until)
            res[reponame] = len(commits.splitlines())

        return res

    def get_releases(self):
        # Returns a table with key being the repo and the val being an ordered
        # list of releases made (via their tags, so e.g. v1.2.3).
        res = {}

        for repopath in self.cfg.RELEASE_REPOS:
            abs_repopath = os.path.join(self.cfg.rootdir, repopath)
            if not os.path.isdir(abs_repopath):
                print(f"Skipping {repopath}, not a directory")
                continue

            repo = git.Repo(abs_repopath)
            commits = repo.git.log("--tags", "--simplify-by-decoration", "--oneline",
                                   "--pretty=%H %D",
                                   "--since", self.cfg.since,
                                   "--until", self.cfg.until)

            version_re = re.compile(r"(v\d+\.\d+(\.\d+)?)(,|$)")
            reponame = self._get_reponame(repo.remotes.origin.url, repopath)

            for line in commits.splitlines():
                mob = version_re.search(line)
                try:
                    ver = mob.group(1)
                    if reponame not in res:
                        res[reponame] = []
                    res[reponame].append(ver)
                except (AttributeError, IndexError):
                    pass

            if repopath in res:
                res[reponame] = sorted(res[repopath])

        return res

    def _get_reponame(self, url, alternative=None):
        try:
            parts = url.split('/')
            return parts[-2] + '/' + parts[-1]
        except (AttributeError, IndexError):
            pass
        return alternative


def main():
    parser = argparse.ArgumentParser()

    parser.add_argument("--since", metavar="DATE",
                        help="Start date of analysis, e.g. 'Jan 1 2023'")
    parser.add_argument("--until", metavar="DATE",
                        help="End date of analysis, e.g. 'Jan 1 2023'")
    parser.add_argument("--zeekroot", metavar="PATH",
                        help="Toplevel of local Zeek source git clone",
                        default=".")

    args = parser.parse_args()

    if args.since is None:
        print("Need a start date.")
        return 1
    if args.until is None:
        print("Need an end date.")
        return 1
    if not os.path.isdir(args.zeekroot):
        print("Please provide local Zeek clone directory via --zeekroot.")

    cfg = Config(args.since, args.until, args.zeekroot)
    analysis = Analysis(cfg)
    analysis.run()
    analysis.print()

    return 0

if __name__ == '__main__':
    sys.exit(main())
