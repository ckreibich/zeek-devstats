#! /usr/bin/env python
import argparse
import contextlib
import datetime
import json
import os
import re
import shutil
import subprocess
import sys

from collections import OrderedDict

import git
import texttable

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

    # Authors we consider part of the Zeek team, per their Github ID.
    # We match it case-insensitively.
    MERGE_MASTERS = {
        "0xxon",
        "awelzel",
        "bbannier",
        "ckreibich",
        "neverlord",
        "rsmmr",
        "timwoj",
    }

    def __init__(self, rootdir, since=None, until=None):
        self.rootdir = rootdir
        self.since = self._get_datetime(since)
        self.until = self._get_datetime(until)

    def _get_datetime(self, date):
        if date is None:
            return date

        dt = datetime.datetime.fromisoformat(date)
        if dt.tzinfo is None:
            dt = datetime.datetime(
                dt.year, dt.month, dt.day, dt.hour,
                dt.minute, dt.second, tzinfo=datetime.timezone.utc)

        return dt


class Analysis:
    REPORT_WIDTH = 50
    REPO_WIDTH = 30

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

    def _build_git_args(self, args):
        scope = []
        if self.cfg.since is not None:
            scope.append(["--since", self.cfg.since.isoformat()])
        if self.cfg.until is not None:
            scope.append(["--until", self.cfg.until.isoformat()])
        return args + scope

    def _print_table(self, table, title):
        tstring = table.draw()
        maxlen = max([len(row) for row in tstring.splitlines()])

        print(title)
        print("=" * maxlen)
        print(tstring)


class CommitsAnalysis(Analysis):
    NAME = "commits"

    def run(self):
        res = OrderedDict()

        for repopath in self.cfg.COMMIT_REPOS:
            abs_repopath = os.path.join(self.cfg.rootdir, repopath)
            if not os.path.isdir(abs_repopath):
                print(f"Skipping {repopath}, not a directory")
                continue

            repo = git.Repo(abs_repopath)
            reponame = self._get_reponame(repo.remotes.origin.url, repopath)

            args = self._build_git_args(["--oneline"])
            commits = repo.git.log(*args)
            res[reponame] = len(commits.splitlines())

        self.result = res

    def print(self):
        table = texttable.Texttable()
        table.set_deco(table.HEADER)
        table.header(['repo', 'commits'])
        table.set_cols_dtype(['t', 'i'])
        table.set_cols_align(['l', 'r'])

        total = 0

        for repo in sorted(self.result.keys()):
            commits = self.result[repo]
            total += commits
            table.add_row([repo, commits])

        table.add_row(['TOTAL', total])
        self._print_table(table, "Commits")


class ReleaseAnalysis(Analysis):
    NAME = "releases"

    def run(self):
        res = OrderedDict()

        for repopath in self.cfg.RELEASE_REPOS:
            abs_repopath = os.path.join(self.cfg.rootdir, repopath)
            if not os.path.isdir(abs_repopath):
                print(f"Skipping {repopath}, not a directory")
                continue

            repo = git.Repo(abs_repopath)
            args = self._build_git_args(
                ["--tags", "--simplify-by-decoration",
                 "--oneline", "--pretty=%H %D"])
            commits = repo.git.log(*args)

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
        table = texttable.Texttable()
        table.set_deco(table.HEADER)
        table.header(['repo', 'major', 'total'])
        table.set_cols_dtype(['t', 'i', 'i'])
        table.set_cols_align(['l', 'r', 'r'])

        total = 0
        major = 0

        for repo in sorted(self.result.keys()):
            table.add_row([repo, "", ""])
            for release in sorted(self.result[repo]):
                if release.endswith(".0"):
                    major += 1
                    table.add_row([f"  {release}", "*", "*"])
                else:
                    table.add_row([f"  {release}", ".", "*"])
                total += 1

        table.add_row(['TOTAL', major, total])
        self._print_table(table, "Releases")


class MergeAnalysis(Analysis):
    NAME = "merges"

    def run(self):
        res = OrderedDict()

        for repopath in self.cfg.COMMIT_REPOS:
            abs_repopath = os.path.join(self.cfg.rootdir, repopath)
            if not os.path.isdir(abs_repopath):
                print(f"Skipping {repopath}, not a directory")
                continue

            repo = git.Repo(abs_repopath)
            reponame = self._get_reponame(repo.remotes.origin.url, repopath)
            args = self._build_git_args(["--merges", "--oneline"])
            merges = repo.git.log(*args)

            merge_lines = merges.splitlines()
            res[reponame] = {'total': len(merge_lines)}
            security_prs = 0
            for line in merge_lines:
                if 'security/topic' in line:
                    security_prs += 1
            res[reponame]['security'] = security_prs

        self.result = res

    def print(self):
        table = texttable.Texttable()
        table.set_deco(table.HEADER)
        table.header(['repo', 'security', 'total'])
        table.set_cols_dtype(['t', 'i', 'i'])
        table.set_cols_align(['l', 'r', 'r'])

        total = 0
        total_sec = 0

        for repo in sorted(self.result.keys()):
            merges = self.result[repo]['total']
            security = self.result[repo]['security']
            total += merges
            total_sec += security
            table.add_row([repo, security, merges])

        table.add_row(['TOTAL', total_sec, total])
        self._print_table(table, "Merges")


class PrAnalysis(Analysis):
    NAME = "prs"

    def run(self):
        # This requires the "gh" tool, which is slow.
        res = OrderedDict()

        if shutil.which("gh") is None:
            self.result = {}
            return

        for repopath in self.cfg.COMMIT_REPOS:
            abs_repopath = os.path.join(self.cfg.rootdir, repopath)
            if not os.path.isdir(abs_repopath):
                print(f"Skipping {repopath}, not a directory")
                continue

            repo = git.Repo(abs_repopath)
            reponame = self._get_reponame(repo.remotes.origin.url, repopath)

            with contextlib.chdir(abs_repopath):
                # Limit retrieval to 1000 PRs. If we ever do that many in one
                # quarter, well, ... good for us.
                ret = subprocess.run(["gh", "pr", "list",
                                      "--state", "merged",
                                      "--limit", "1000",
                                      "--json", "number,author,mergedAt,comments"],
                                     capture_output=True)

                try:
                    prdata = json.loads(ret.stdout)
                except json.decoder.JSONDecodeError:
                    continue

                total = 0
                comments = 0
                contribs = 0

                for pr in prdata:
                    # gh reports PRs in reverse chronological order.
                    merge_date = datetime.datetime.fromisoformat(pr["mergedAt"])
                    if self.cfg.until and merge_date > self.cfg.until:
                        continue # too new
                    if self.cfg.since and merge_date < self.cfg.since:
                        break # too old -- as will be all others

                    if pr["author"]["login"].lower() not in self.cfg.MERGE_MASTERS:
                        contribs += 1
                    comments += len(pr["comments"])
                    total += 1

                res[reponame] = {"total": total,
                                 "comments": comments,
                                 "contribs": contribs}
        self.result = res

    def print(self):
        table = texttable.Texttable()
        table.set_deco(table.HEADER)
        table.header(["repo", "comments", "contribs", "total"])
        table.set_cols_dtype(["t", "i", "i", "i"])
        table.set_cols_align(["l", "r", "r", "r"])

        total = 0
        total_comments = 0
        total_contribs = 0

        for repo in sorted(self.result.keys()):
            prs = self.result[repo]["total"]
            comments = self.result[repo]["comments"]
            contribs = self.result[repo]["contribs"]

            total += prs
            total_comments += comments
            total_contribs += contribs

            table.add_row([repo, comments, contribs, prs])

        table.add_row(["TOTAL", total_comments, total_contribs, total])
        self._print_table(table, "Pull Requests")


class IssueAnalysis(Analysis):
    NAME = "issues"

    def run(self):
        # This requires the "gh" tool, which is slow.
        res = OrderedDict()

        if shutil.which("gh") is None:
            self.result = {}
            return

        for repopath in self.cfg.COMMIT_REPOS:
            abs_repopath = os.path.join(self.cfg.rootdir, repopath)
            if not os.path.isdir(abs_repopath):
                print(f"Skipping {repopath}, not a directory")
                continue

            repo = git.Repo(abs_repopath)
            reponame = self._get_reponame(repo.remotes.origin.url, repopath)

            with contextlib.chdir(abs_repopath):
                # Limit retrieval to 1000 PRs. If we ever do that many in one
                # quarter, well, ... good for us.
                ret = subprocess.run(["gh", "issue", "list",
                                      "--state", "all",
                                      "--limit", "1000",
                                      "--json", "number,author,createdAt,closedAt"],
                                     capture_output=True)

                try:
                    issdata = json.loads(ret.stdout)
                except json.decoder.JSONDecodeError:
                    continue

                active = 0
                opened = 0
                closed = 0
                contribs = 0

                for iss in issdata:
                    # gh reports issues in reverse chronological order of creation.
                    open_date = datetime.datetime.fromisoformat(iss["createdAt"])
                    close_date = None
                    if iss["closedAt"] is not None:
                        close_date = datetime.datetime.fromisoformat(iss["closedAt"])

                    if self.cfg.until and open_date <= self.cfg.until:
                        if close_date is None:
                            active += 1
                        if self.cfg.since and open_date > self.cfg.since:
                            opened += 1
                            if iss["author"]["login"].lower() not in self.cfg.MERGE_MASTERS:
                                contribs += 1

                    if close_date is not None:
                        if self.cfg.until and close_date > self.cfg.until:
                            continue
                        if self.cfg.since and close_date >= self.cfg.since:
                            closed += 1

                res[reponame] = {"active": active,
                                 "opened": opened,
                                 "closed": closed,
                                 "contribs": contribs}
        self.result = res

    def print(self):
        table = texttable.Texttable()
        table.set_deco(table.HEADER)
        table.header(["repo", "opened", "closed", "contribs", "active"])
        table.set_cols_dtype(["t", "i", "i", "i", "i"])
        table.set_cols_align(["l", "r", "r", "r", "r"])

        total_active = 0
        total_opened = 0
        total_closed = 0
        total_contribs = 0

        for repo in sorted(self.result.keys()):
            active = self.result[repo]["active"]
            opened = self.result[repo]["opened"]
            closed = self.result[repo]["closed"]
            contribs = self.result[repo]["contribs"]

            total_active += active
            total_opened += opened
            total_closed += closed
            total_contribs += contribs

            table.add_row([repo, opened, closed, contribs, active])

        table.add_row(["TOTAL", total_opened, total_closed, total_contribs, total_active])
        self._print_table(table, "Issues")


def main():
    parser = argparse.ArgumentParser()

    parser.add_argument("--since", metavar="DATE",
                        help="Start of analysis in ISO format, e.g. YYYY-MM-DD")
    parser.add_argument("--until", metavar="DATE",
                        help="End of analysis in ISO format, e.g. YYYY-MM-DD")
    parser.add_argument("--analysis", metavar="NAME",
                        help="Run only one given analysis: commits, releases merges, prs, issues")
    parser.add_argument("--zeekroot", metavar="PATH",
                        help="Toplevel of local Zeek source git clone",
                        default=".")

    args = parser.parse_args()

    if args.since is None:
        print("Need a start date.")
        return 1
    if not os.path.isdir(args.zeekroot):
        print("Please provide local Zeek clone directory via --zeekroot.")

    try:
        cfg = Config(args.zeekroot, args.since, args.until)
    except ValueError as err:
        print("Configuration error: %s" % err)
        return 1

    analyses = [
        CommitsAnalysis(cfg),
        ReleaseAnalysis(cfg),
        MergeAnalysis(cfg),
        PrAnalysis(cfg),
        IssueAnalysis(cfg),
    ]

    print("ZEEK ACTIVITY REPORT")
    print("====================")
    print()
    print(f"Since: {cfg.since}")
    print(f"Until: {cfg.until if cfg.until else 'now'}")
    print()

    for an in analyses:
        if args.analysis and an.NAME.lower() != args.analysis.lower():
            continue
        an.run()
        an.print()
        print()

    return 0

if __name__ == "__main__":
    sys.exit(main())
