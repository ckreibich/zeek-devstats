#! /usr/bin/env python
import argparse
import configparser
import contextlib
import datetime
import json
import os
import pathlib
import re
import shutil
import subprocess
import sys
import tempfile
import time
import urllib.request
import urllib.parse

from collections import OrderedDict

import git
import texttable


def msg(content):
    print(content, file=sys.stderr)


class Table(texttable.Texttable):
    """A specialization of text tables for our needs.

    This always has the same header decoration, and the ability to default
    column types and alignments unless the user overrides them.
    """
    def __init__(self, columns, dtypes=None, alignments=None):
        super().__init__()
        self.set_deco(self.HEADER)
        self.header(columns)

        # Default: first column is text, all others integer:
        if dtypes is None:
            dtypes = ["t"] + ["i"] * (len(columns)-1)
        # Default: first column is left-aligned, all others right:
        if alignments is None:
            alignments = ["l"] + ["r"] * (len(columns)-1)

        self.set_cols_dtype(dtypes)
        self.set_cols_align(alignments)

    def add_row_if(self, row, cond=True):
        """Helper to only add a row if the provided condition is true."""
        if cond:
            self.add_row(row)

class Config:
    # Repos in which we count releases
    RELEASE_REPOS = (
        "", # Zeek itself
        "auxil/spicy"
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
        "auxil/spicy",
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

    # Same, but for other Corelight folks.
    CORELIGHTERS = {
        "ajs1k",
        "benjeems",
        "ekoyle",
        "JustinAzoff",
        "markoverholser",
        "keithjjones",
        "pauldokas",
        "retr0h",
        "sethhall",
        "stevesmoot",
        "simeonmiteff",
        "vpax",
        "ynadji",
    }

    def __init__(self, rootdir, since=None, until=None):
        self.rootdir = rootdir
        # These need to be datetimes, not dates, so we can compare smoothly to
        # datetimes involved in git operations.
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
    def __init__(self, cfg, run):
        self.cfg = cfg
        self.run = run
        self.result = None

    def crunch(self):
        """Conduct the analysis.

        This populates object-local state, and does nothing else.  For
        reporting, see print(). This should store the various results in the
        self.result member, usually as a dict.
        """

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

    @staticmethod
    def print(analyses):
        """Prints the results of the analysis.

        analyses: a list of Analyses to summarize.
        """

    @staticmethod
    def print_table(table, title):
        """Helper to print out the given Table instance and title."""
        tstring = table.draw()
        maxlen = max([len(row) for row in tstring.splitlines()])

        print(title)
        print("=" * maxlen)
        print(tstring)


class CommitsAnalysis(Analysis):
    NAME = "commits"

    def crunch(self):
        res = OrderedDict()

        for repopath in self.cfg.COMMIT_REPOS:
            abs_repopath = os.path.join(self.cfg.rootdir, repopath)
            if not os.path.isdir(abs_repopath):
                msg(f"Skipping {repopath}, not a directory")
                continue

            repo = git.Repo(abs_repopath)
            reponame = self._get_reponame(repo.remotes.origin.url, repopath)

            args = self._build_git_args(["--oneline"])
            commits = repo.git.log(*args)
            res[reponame] = len(commits.splitlines())

        self.result = res

    @staticmethod
    def print(analyses):
        table = Table(["repo", "commits"])

        def process(anl, detailed):
            total = 0

            for repo in sorted(anl.result.keys()):
                commits = anl.result[repo]
                total += commits
                table.add_row_if([repo, commits], detailed)

            table.add_row([f"TOTAL in {anl.run.timeframe()}", total])

        for idx, anl in enumerate(analyses):
            process(anl, idx == 0)

        Analysis.print_table(table, "Commits")


class ReleaseAnalysis(Analysis):
    NAME = "releases"

    def crunch(self):
        res = OrderedDict()

        for repopath in self.cfg.RELEASE_REPOS:
            abs_repopath = os.path.join(self.cfg.rootdir, repopath)
            if not os.path.isdir(abs_repopath):
                msg(f"Skipping {repopath}, not a directory")
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

    @staticmethod
    def print(analyses):
        table = Table(["repo", "major", "total"])

        def process(anl, detailed):
            total = 0
            major = 0

            for repo in sorted(anl.result.keys()):
                table.add_row_if([repo, "", ""], detailed)
                for release in sorted(anl.result[repo]):
                    if release.endswith(".0"):
                        major += 1
                        table.add_row_if([f"  {release}", "*", "*"], detailed)
                    else:
                        table.add_row_if([f"  {release}", ".", "*"], detailed)
                    total += 1

            table.add_row([f"TOTAL in {anl.run.timeframe()}", major, total])

        for idx, anl in enumerate(analyses):
            process(anl, idx == 0)

        Analysis.print_table(table, "Releases")


class MergeAnalysis(Analysis):
    NAME = "merges"

    def crunch(self):
        res = OrderedDict()

        for repopath in self.cfg.COMMIT_REPOS:
            abs_repopath = os.path.join(self.cfg.rootdir, repopath)
            if not os.path.isdir(abs_repopath):
                msg(f"Skipping {repopath}, not a directory")
                continue

            repo = git.Repo(abs_repopath)
            reponame = self._get_reponame(repo.remotes.origin.url, repopath)
            args = self._build_git_args(["--merges", "--oneline"])
            merges = repo.git.log(*args)

            merge_lines = merges.splitlines()
            res[reponame] = {"total": len(merge_lines)}
            security_prs = 0
            for line in merge_lines:
                if "security/topic" in line:
                    security_prs += 1
            res[reponame]["security"] = security_prs

        self.result = res

    @staticmethod
    def print(analyses):
        table = Table(["repo", "security", "total"])

        def process(anl, detailed):
            total = 0
            total_sec = 0

            for repo in sorted(anl.result.keys()):
                merges = anl.result[repo]["total"]
                security = anl.result[repo]["security"]
                total += merges
                total_sec += security
                table.add_row_if([repo, security, merges], detailed)

            table.add_row([f"TOTAL in {anl.run.timeframe()}", total_sec, total])

        for idx, anl in enumerate(analyses):
            process(anl, idx == 0)

        Analysis.print_table(table, "Merges")


class PrAnalysis(Analysis):
    NAME = "prs"

    def crunch(self):
        res = OrderedDict()
        self.result = {}

        # This requires the "gh" tool ... which is slow.
        if shutil.which("gh") is None:
            return

        # All PRs contributed by Corelighters other than the merge masters.
        self.result["pr-contribs-cl"] = []
        # All PRs contributed by any other community members.
        self.result["pr-contribs"] = []

        for repopath in self.cfg.COMMIT_REPOS:
            abs_repopath = os.path.join(self.cfg.rootdir, repopath)
            if not os.path.isdir(abs_repopath):
                msg(f"Skipping {repopath}, not a directory")
                continue

            repo = git.Repo(abs_repopath)
            reponame = self._get_reponame(repo.remotes.origin.url, repopath)

            with contextlib.chdir(abs_repopath):
                # Higher limits (like the original 1000) can lead to "transform:
                # short source buffer" messages.
                ret = subprocess.run(["gh", "pr", "list",
                                      "--state", "merged",
                                      "--limit", "500",
                                      "--json", "url,number,author,mergedAt,comments,title"],
                                     capture_output=True)

                try:
                    prdata = json.loads(ret.stdout)
                except json.decoder.JSONDecodeError as err:
                    msg(f"JSON error decoding 'gh pr list' result in {repopath}: {err}")
                    continue

                total = 0
                comments = 0
                cl_contribs = 0
                contribs = 0

                for pr in prdata:
                    # gh reports PRs in reverse chronological order.
                    merge_date = datetime.datetime.fromisoformat(pr["mergedAt"])
                    if self.cfg.until and merge_date > self.cfg.until:
                        continue # too new
                    if self.cfg.since and merge_date < self.cfg.since:
                        break # too old -- as will be all others

                    if pr["author"]["login"].lower() not in self.cfg.MERGE_MASTERS:
                        if pr["author"]["login"].lower() in self.cfg.CORELIGHTERS:
                            key = "pr-contribs-cl"
                            cl_contribs += 1
                        else:
                            key = "pr-contribs"
                            contribs += 1

                        prdata = {
                            "author": pr["author"]["login"],
                            "title": pr["title"],
                            "url": pr["url"],
                        }

                        if "name" in pr["author"] and pr["author"]["name"].strip():
                            prdata["author"] = f"{pr['author']['name']} ({pr['author']['login']})"

                        self.result[key].append(prdata)

                    comments += len(pr["comments"])
                    total += 1

                res[reponame] = {"total": total,
                                 "comments": comments,
                                 "cl_contribs": cl_contribs,
                                 "contribs": contribs}
        self.result["repos"] = res

    @staticmethod
    def print(analyses):
        table = Table(["repo", "comments", "cl_contribs", "contribs", "total"])

        def process(anl, detailed):
            total = 0
            total_comments = 0
            total_cl_contribs = 0
            total_contribs = 0

            res = anl.result["repos"]

            for repo in sorted(res.keys()):
                prs = res[repo]["total"]
                comments = res[repo]["comments"]
                cl_contribs = res[repo]["cl_contribs"]
                contribs = res[repo]["contribs"]

                total += prs
                total_comments += comments
                total_cl_contribs += cl_contribs
                total_contribs += contribs

                table.add_row_if([repo, comments, cl_contribs, contribs, prs], detailed)

            table.add_row([f"TOTAL in {anl.run.timeframe()}",
                           total_comments, total_cl_contribs,
                           total_contribs, total])

        for idx, anl in enumerate(analyses):
            process(anl, idx == 0)

        Analysis.print_table(table, "Pull Requests")

        # Print out contributed PRs in more detail, focusing on the
        # first analysis (most recent quarter, etc):
        anl = analyses[0]

        for key, title in [["pr-contribs-cl", "Corelight"],
                           ["pr-contribs", "Community"]]:
            if not anl.result[key]:
                continue
            print()
            print(f"{title} PR contributions in {anl.run.timeframe()}:")
            for prdata in anl.result[key]:
                print("- Title:  " + prdata["title"])
                print("  Author: " + prdata["author"])
                print("  URL:    " + prdata["url"])


class IssueAnalysis(Analysis):
    NAME = "issues"

    def crunch(self):
        # This requires the "gh" tool, which is slow.
        res = OrderedDict()

        if shutil.which("gh") is None:
            self.result = {}
            return

        for repopath in self.cfg.COMMIT_REPOS:
            abs_repopath = os.path.join(self.cfg.rootdir, repopath)
            if not os.path.isdir(abs_repopath):
                msg(f"Skipping {repopath}, not a directory")
                continue

            repo = git.Repo(abs_repopath)
            reponame = self._get_reponame(repo.remotes.origin.url, repopath)

            with contextlib.chdir(abs_repopath):
                ret = subprocess.run(["gh", "issue", "list",
                                      "--state", "all",
                                      "--limit", "1000",
                                      "--json", "number,author,createdAt,closedAt"],
                                     capture_output=True)

                # There may not have been any activity.
                if not ret.stdout.strip():
                    continue

                try:
                    issdata = json.loads(ret.stdout)
                except json.decoder.JSONDecodeError as err:
                    msg(f"JSON error decoding 'gh issue list' result in {repopath}: {err}")
                    continue

                active = 0
                opened = 0
                closed = 0
                cl_contribs = 0
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
                                if iss["author"]["login"].lower() in self.cfg.CORELIGHTERS:
                                    cl_contribs += 1
                                else:
                                    contribs += 1

                    if close_date is not None:
                        if self.cfg.until and close_date > self.cfg.until:
                            continue
                        if self.cfg.since and close_date >= self.cfg.since:
                            closed += 1

                res[reponame] = {"active": active,
                                 "opened": opened,
                                 "closed": closed,
                                 "cl_contribs": cl_contribs,
                                 "contribs": contribs}
        self.result = res

    @staticmethod
    def print(analyses):
        table = Table(["repo", "opened", "closed", "cl_contribs", "contribs", "active"])

        def process(anl, detailed):
            total_active = 0
            total_opened = 0
            total_closed = 0
            total_cl_contribs = 0
            total_contribs = 0

            for repo in sorted(anl.result.keys()):
                active = anl.result[repo]["active"]
                opened = anl.result[repo]["opened"]
                closed = anl.result[repo]["closed"]
                cl_contribs = anl.result[repo]["cl_contribs"]
                contribs = anl.result[repo]["contribs"]

                total_active += active
                total_opened += opened
                total_closed += closed
                total_cl_contribs += cl_contribs
                total_contribs += contribs

                table.add_row_if([repo, opened, closed, cl_contribs, contribs, active], detailed)

            table.add_row([f"TOTAL in {anl.run.timeframe()}",
                           total_opened, total_closed, total_cl_contribs,
                           total_contribs, total_active])

        for idx, anl in enumerate(analyses):
            process(anl, idx == 0)

        Analysis.print_table(table, "Issues")


class PackagesAnalysis(Analysis):
    NAME = "packages"
    REPO_URL = "https://github.com/zeek/packages"

    def crunch(self):
        self.result = OrderedDict()
        self.result["contribs"] = []
        self.result["contribs-cl"] = []
        self.result["contribs-zeek"] = []

        old_packages = set()
        new_packages = set()

        with tempfile.TemporaryDirectory() as dir:
            repo = git.Repo.clone_from(self.REPO_URL, dir)

            args = self._build_git_args(["--pretty=format:%H"])
            commits = repo.git.log(*args).splitlines()
            newest_hash = commits[0]
            oldest_hash = commits[-1]

            # Read aggregate.meta at the earliest and latest commit; the number
            # of sections in it is the number of packages.
            repo.git.checkout(oldest_hash)
            meta = configparser.ConfigParser()
            meta.read(os.path.join(dir, "aggregate.meta"))
            self.result["total_oldest"] = len(meta.sections())
            self.result["cl_oldest"] = 0
            self.result["zeek_oldest"] = 0

            for package in meta.sections():
                old_packages.add(package)
                if package.startswith("corelight/"):
                    self.result["cl_oldest"] += 1
                elif package.startswith("zeek/"):
                    self.result["zeek_oldest"] += 1

            repo.git.checkout(newest_hash)
            meta = configparser.ConfigParser()
            meta.read(os.path.join(dir, "aggregate.meta"))
            self.result["total_newest"] = len(meta.sections())
            self.result["cl_newest"] = 0
            self.result["zeek_newest"] = 0

            for package in meta.sections():
                new_packages.add(package)
                if package.startswith('corelight/'):
                    self.result["cl_newest"] += 1
                elif package.startswith("zeek/"):
                    self.result["zeek_newest"] += 1

        delta_packages = new_packages - old_packages
        for package in delta_packages:
            pdata = {
                "name": package,
                "url": meta.get(package, "url"),
            }

            if package.startswith("corelight/"):
                self.result["contribs-cl"].append(pdata)
            elif package.startswith("zeek/"):
                self.result["contribs-zeek"].append(pdata)
            else:
                self.result["contribs"].append(pdata)


    @staticmethod
    def print(analyses):
        table = Table(["timeframe", "total", "zeek_new", "cl_new", "community_new"])

        def process(anl):
            new = anl.result["total_newest"] - anl.result["total_oldest"]
            cl_new = anl.result["cl_newest"] - anl.result["cl_oldest"]
            zeek_new = anl.result["zeek_newest"] - anl.result["zeek_oldest"]
            community_new = new - cl_new

            table.add_row([anl.run.timeframe(),
                           anl.result["total_newest"],
                           zeek_new, cl_new, community_new])

        for anl in analyses:
            process(anl)

        Analysis.print_table(table, "Packages")

        # Print out contributed packages in more detail, focusing on the
        # first analysis (most recent quarter, etc):
        anl = analyses[0]

        for key, title in [["contribs", "Community"],
                           ["contribs-cl", "Corelight"],
                           ["contribs-zeek", "Zeek"]]:
            if not anl.result[key]:
                continue
            print()
            print(f"{title} package contributions in {anl.run.timeframe()}:")
            for pdata in anl.result[key]:
                print(f"- {pdata['url']}")


class DiscourseAnalysis(Analysis):
    NAME = "discourse"

    # File that contains API key for running GET queries against Discourse
    API_KEY_FILE = pathlib.Path.home() / ".config" / "discourse" / "key"
    # Our discourse server
    SERVER = "https://community.zeek.org"

    def __init__(self, cfg, run):
        super().__init__(cfg, run)
        with open(self.API_KEY_FILE) as hdl:
            self.api_key = hdl.readline().strip()

    def crunch(self):
        res = OrderedDict()

        for category in ["Zeek", "Development"]:
            queryparts = ["%23" + category]

            if self.cfg.since is not None:
                queryparts.append(f"after:{self.cfg.since.date()}")
            if self.cfg.until is not None:
                queryparts.append(f"before:{self.cfg.until.date()}")

            querystring = "q=" + "+".join(queryparts)

            req = urllib.request.Request(
                f"{self.SERVER}/search.json?{querystring}",
                headers={
                    "Api-Key": self.api_key,
                    "Api-Username": "christian",
                })

            with urllib.request.urlopen(req) as query:
                if query.status != 200:
                    msg(f"HTTP query error, status code {query.status}")
                    continue
                try:
                    searchdata = json.loads(query.read())
                except json.decoder.JSONDecodeError:
                    msg("JSON error decoding search query result")
                    continue

            topics = set()
            total_posts = 0

            for post in searchdata["posts"]:
                topics.add(post["topic_id"])

            for topic in topics:
                req = urllib.request.Request(
                    f"{self.SERVER}/t/{topic}.json",
                    headers={
                        "Api-Key": self.api_key,
                        "Api-Username": "christian",
                    })

                try:
                    with urllib.request.urlopen(req) as query:
                        if query.status != 200:
                            print(f"HTTP query error, status code {query.status}")
                            continue
                        try:
                            topicdata = json.loads(query.read())
                        except json.decoder.JSONDecodeError:
                            print("JSON error decoding topic query result")
                            continue
                except urllib.error.HTTPError as err:
                    if err.code == 429:
                        msg("HTTP rate limit hit, aborting analysis")
                        return
                    else:
                        msg(f"HTTP error: {err}")

                total_posts += topicdata["posts_count"]

                # Basic rate-limiting -- apparently the Discourse API will
                # object once we hit 60 queries per minute.
                time.sleep(1)

            res[category] = {
                "topics": len(topics),
                "posts": total_posts,
            }

        self.result = res

    @staticmethod
    def print(analyses):
        table = Table(["category", "topics", "posts"])

        def process(anl, detailed):
            total_topics, total_posts = 0, 0

            for category, data in anl.result.items():
                table.add_row_if([category, data["topics"], data["posts"]], detailed)
                total_topics += data["topics"]
                total_posts += data["posts"]

            table.add_row([f"TOTAL in {anl.run.timeframe()}", total_topics, total_posts])

        for idx, anl in enumerate(analyses):
            process(anl, idx == 0)

        Analysis.print_table(table, "Discourse Support")


class Quarter:
    START_MONTHS = [11,8,5,2]
    NAMES = {2: "Q1", 5: "Q2", 8: "Q3", 11: "Q4"}
    LENGTH_MONTHS = 3

    def __init__(self, lookupdate=None):
        self.startdate = None
        self.enddate = None

        if lookupdate is None:
            lookupdate = datetime.date.today()

        for month in self.START_MONTHS:
            if month > lookupdate.month:
                continue
            self.startdate = datetime.date(lookupdate.year, month, 1)
            if month + self.LENGTH_MONTHS > 12:
                self.enddate = datetime.date(
                    lookupdate.year + 1, (month + self.LENGTH_MONTHS) % 12, 1)
            else:
                self.enddate = datetime.date(
                    lookupdate.year, (month + self.LENGTH_MONTHS) % 12, 1)
            return

        # If we get here it's January, so the quarter started in the year prior.
        self.startdate = datetime.date(lookupdate.year-1, 11, 1)
        self.enddate = datetime.date(lookupdate.year, 2, 1)

    def __repr__(self):
        return f"{self.startdate.year}/{self.name()}"

    def name(self):
        return self.NAMES[self.startdate.month]

    def previous(self):
        return Quarter(self.startdate - datetime.timedelta(days=1))

    def next(self):
        return Quarter(self.enddate)


class Run:
    def __init__(self, args, quarter=None):
        self.args = args
        self.quarter = quarter
        self.analyses = OrderedDict()

        if quarter is not None:
            self.cfg = Config(args.zeekroot, str(quarter.startdate), str(quarter.enddate))
        else:
            self.cfg = Config(args.zeekroot, args.since, args.until)

        for cls in Analysis.__subclasses__():
            if args.analysis and cls.NAME.lower() != args.analysis.lower():
                continue
            try:
                an = cls(self.cfg, self)
                self.analyses[an.NAME] = an
            except Exception as err:
                msg(f"Initialization error for {cls.__name__} ({err}), skipping")

    def run(self):
        for _, an in self.analyses.items():
            if self.args.verbose:
                msg(f"Running {an.NAME} for {self.timeframe()}")
            an.crunch()

    def timeframe(self):
        if self.quarter is not None:
            return str(self.quarter)
        if self.cfg.until is not None:
            return f"{self.cfg.since.date()} - {self.cfg.until.date()}"
        return f"{self.cfg.since.date()} - today"


class Report:
    """A report consists of one or more Run instnaces.

    It can print a summary of these. It assumes that the first run is the most
    important, and the others (if any) just provide additional context.
    """
    def __init__(self, runs):
        self.runs = runs

        # Take the analyses in each run and group them by their type (all merge
        # analyses in a sequence, all issues analyses, etc), in the order
        # implied by the given runs.
        self.analyses = OrderedDict()
        self.analyses_cls = {}

        for run in self.runs:
            for name, analysis in run.analyses.items():
                try:
                    self.analyses[name].append(analysis)
                except KeyError:
                    self.analyses[name] = [analysis]
                    self.analyses_cls[name] = analysis.__class__

    def print(self):
        print("ZEEK ACTIVITY REPORT")
        print("====================")
        print()
        print(self.runs[0].timeframe())
        print()

        for name in self.analyses:
            self.analyses_cls[name].print(self.analyses[name])
            print()


def main():
    analysis_names = [cls.NAME for cls in Analysis.__subclasses__()]

    parser = argparse.ArgumentParser()

    parser.add_argument("--verbose", action="store_true",
                        help="Verbose output to stderr during calculations",
                        default=False)
    parser.add_argument("--since", metavar="DATE",
                        help="Start of analysis in ISO format, e.g. YYYY-MM-DD")
    parser.add_argument("--until", metavar="DATE",
                        help="End of analysis in ISO format, e.g. YYYY-MM-DD")
    parser.add_argument("--analysis", metavar="NAME",
                        help=f"Run only one analysis: {', '.join(analysis_names)}")
    parser.add_argument("--zeekroot", metavar="PATH",
                        help="Toplevel of local Zeek source git clone",
                        default=".")

    args = parser.parse_args()

    if not os.path.isdir(args.zeekroot):
        msg("Please provide local Zeek clone directory via --zeekroot.")
        return 1

    # Without explicit start/end dates, we compare the past 3 quarters.
    if args.since is None and args.until is None:
        q1 = Quarter().previous()
        q2 = q1.previous()
        q3 = q2.previous()
        runs = []

        # The quarters go back in time:
        for q in [q1, q2, q3]:
            try:
                run = Run(args, quarter=q)
            except ValueError as err:
                msg("Configuration error, skipping: %s" % err)
                continue
            run.run()
            runs.append(run)

        report = Report(runs)
        report.print()
    else:
        if args.since is None:
            msg("Need a start date.")
            return 1

        try:
            run = Run(args)
        except ValueError as err:
            msg("Configuration error: %s" % err)
            return 1

        run.run()

        report = Report([run])
        report.print()

    return 0

if __name__ == "__main__":
    sys.exit(main())
