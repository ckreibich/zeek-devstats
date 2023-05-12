#! /usr/bin/env python
import argparse
import contextlib
import json
import os
import re
import shutil
import subprocess
import sys

from collections import OrderedDict
from datetime import datetime

import git

class Config:
    # Repos in which we count releases
    RELEASE_REPOS = (
        "", # Zeek itself
        "auxil/spicy/spicy"
    )

    # Repos in which we count commits / PRs
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
    REPORT_WIDTH = 50

    def __init__(self, cfg):
        self.cfg = cfg
        self.result = None

    def run(self):
        pass

    def print(self):
        pass

    def _get_reponame(self, url, alternative=None):
        try:
            parts = url.split("/")
            return parts[-2] + "/" + parts[-1]
        except (AttributeError, IndexError):
            pass
        return alternative


class CommitsAnalysis(Analysis):
    def run(self):
        # A table with key being the repo and val being the number of commits.
        res = OrderedDict()

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

        self.result = res

    def print(self):
        total = 0

        print("Commits")
        print("-" * self.REPORT_WIDTH)

        for repo in sorted(self.result.keys()):
            commits = self.result[repo]
            total += commits
            print(f"{repo:<40}     {commits:5}")

        print("-" * self.REPORT_WIDTH)
        print(f"{'TOTAL':<40}     {total:5}")


class ReleaseAnalysis(Analysis):
    def run(self):
        # A table with key being the repo and the val being an ordered
        # list of releases made (via their tags, so e.g. v1.2.3).
        res = OrderedDict()

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

        self.result = res

    def print(self):
        total = 0

        print("Releases")
        print("-" * self.REPORT_WIDTH)

        for repo in sorted(self.result.keys()):
            print(repo)
            for release in sorted(self.result[repo]):
                suffix = ""
                if release.endswith(".0"):
                    suffix = "  (major)"
                print(f"  {release}{suffix}")
                total += 1

        print("-" * self.REPORT_WIDTH)
        print(f"{'TOTAL':<40}     {total:5}")


class MergeAnalysis(Analysis):
    def run(self):
        # A table with key being the repo and the val being a table with two
        # keys, "total" and "security", for overall branches merged and the
        # subset that constitutes security fixes. The latter is identified from
        # branches merged that start with "security/topic".
        res = OrderedDict()

        for repopath in self.cfg.COMMIT_REPOS:
            abs_repopath = os.path.join(self.cfg.rootdir, repopath)
            if not os.path.isdir(abs_repopath):
                print(f"Skipping {repopath}, not a directory")
                continue

            repo = git.Repo(abs_repopath)
            reponame = self._get_reponame(repo.remotes.origin.url, repopath)
            merges = repo.git.log("--merges", "--oneline",
                                  "--since", self.cfg.since,
                                  "--until", self.cfg.until)

            merge_lines = merges.splitlines()
            res[reponame] = {'total': len(merge_lines)}
            security_prs = 0
            for line in merge_lines:
                if 'security/topic' in line:
                    security_prs += 1
            res[reponame]['security'] = security_prs

        self.result = res


class PrAnalysis(Analysis):
    def run(self):
        # A table from repo name to a table with two keys: "prs", the number of
        # PRs in the time interval found, and "comments", the total count of
        # comments across those PRs.
        #
        # This requires the "gh" tool, which is slow.
        #
        res = OrderedDict()

        if shutil.which("gh") is None:
            self.result = {}
            return

        for repopath in self.cfg.COMMIT_REPOS:
            abs_repopath = os.path.join(self.cfg.rootdir, repopath)
            if not os.path.isdir(abs_repopath):
                print(f"Skipping {repopath}, not a directory")
                continue

            # We need comparable timestamps so we can check whether a given PR
            # got merged between --since and --until. So the user can provide
            # these flexibly, we get the whole range of commits, but with
            # ISO-format date strings, and grab earliest and latest. The
            # rationale is that if there are no commits, there are no (merged)
            # PRs.
            repo = git.Repo(abs_repopath)
            reponame = self._get_reponame(repo.remotes.origin.url, repopath)
            commits = repo.git.log("--pretty=%ai",
                                   "--since", self.cfg.since,
                                   "--until", self.cfg.until)

            commits = sorted(commits.splitlines())
            if not commits:
                continue

            min_date = datetime.fromisoformat(commits[0])
            max_date = datetime.fromisoformat(commits[-1])

            with contextlib.chdir(abs_repopath):
                # Limit retrieval to 1000 PRs. If we ever do that many in one
                # quarter, well, ... good for us.
                ret = subprocess.run(["gh", "pr", "list",
                                      "--state", "merged",
                                      "--limit", "1000",
                                      "--json", "id,mergedAt,comments"],
                                     capture_output=True)

                prdata = json.loads(ret.stdout)
                comments = 0
                prs = 0
                for pr in prdata:
                    merge_date = datetime.fromisoformat(pr["mergedAt"])
                    if min_date <= merge_date and merge_date <= max_date:
                        comments += len(pr["comments"])
                        prs += 1

                res[reponame] = {"prs": prs, "comments": comments}

        self.result = res


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

    analyses = [
        CommitsAnalysis(cfg),
        ReleaseAnalysis(cfg),
        MergeAnalysis(cfg),
        PrAnalysis(cfg),
    ]

    for an in analyses:
        an.run()
        an.print()
        print()

    return 0

if __name__ == '__main__':
    sys.exit(main())
