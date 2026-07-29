# @author Couchbase <info@couchbase.com>
# @copyright 2026-Present Couchbase, Inc.
#
# Use of this software is governed by the Business Source License included in
# the file licenses/BSL-Couchbase.txt.  As of the Change Date specified in that
# file, in accordance with the Business Source License, use of this software
# will be governed by the Apache License, Version 2.0, included in the file
# licenses/APL2.txt.

"""Coverage of the lines you changed, as reported by git.

run.py already knows how to collect per-line coverage for a list of modules.
This module answers the follow-up question: of the lines git says I changed,
which ones did the tests actually execute?

Coverage line numbers come from the compiled beam, i.e. the working tree, so
the working tree is always the new side of the diff and only the base varies.
That leaves a stale build as the one way to end up with line numbers that do
not match the coverage data - see check_consistency().
"""

import os
import re
import subprocess
from dataclasses import dataclass, field

import testlib


DEFAULT_MODE = 'uncommitted'

# A mode is just the base: ([git arguments naming it], description). An empty
# argument list is the index.
BASES = {
    'uncommitted': (['HEAD'], 'working tree vs. HEAD (not committed yet)'),
    'unstaged': ([], 'working tree vs. index (not staged yet)')}

REMOVED_MODES = {
    'staged': "the coverage data describes the working tree, so a comparison "
              "that leaves it out cannot be measured - use --diff-coverage "
              "or --diff-coverage=unstaged",
    'last-commit': "use --diff-coverage=HEAD^"}

HUNK_RE = re.compile(r'^@@ -\d+(?:,\d+)? \+(\d+)(?:,(\d+))? @@')

# Lines of context shown around uncovered lines in the annotated diff.
DISPLAY_CONTEXT = 3


class DiffCoverageError(Exception):
    """Raised for anything the user has to fix on the command line."""


@dataclass
class ChangedModule:
    module: str
    path: str
    lines: set


@dataclass
class DiffInfo:
    mode: str
    description: str
    command: str
    changed: dict                     # module name -> ChangedModule
    skipped: list                     # [(path, reason)]
    display_diff: str
    warnings: list = field(default_factory=list)
    untracked: list = field(default_factory=list)   # counted whole

    def modules(self):
        return sorted(self.changed)

    def changed_line_count(self):
        return sum([len(c.lines) for c in self.changed.values()])


@dataclass
class ModuleResult:
    module: str
    path: str
    changed: int          # lines the diff touched
    relevant: int         # of those, the ones cover can measure
    covered: int
    uncovered: list
    has_data: bool

    def percentage(self):
        if self.relevant == 0:
            return None
        return self.covered * 100 / self.relevant


@dataclass
class DiffResult:
    modules: list
    changed: int
    relevant: int
    covered: int
    no_data: list

    def percentage(self):
        if self.relevant == 0:
            return None
        return self.covered * 100 / self.relevant


def git(args):
    """Run git at the top of the ns_server checkout.

    core.quotePath=false keeps non-ASCII paths readable. Never raises on a git
    failure - callers turn a non-zero exit into a proper error message.
    """
    cmd = ['git', '-c', 'core.quotePath=false'] + args
    res = subprocess.run(cmd, cwd=testlib.get_ns_server_dir(),
                         capture_output=True, text=True)
    return res.stdout, res.stderr, res.returncode


def git_succ(args, default=''):
    out, _, rc = git(args)
    return out if rc == 0 else default


def merge_base(left, right):
    out, err, rc = git(['merge-base', left, right])
    if rc != 0:
        raise DiffCoverageError(f"git merge-base {left} {right} failed:\n"
                                f"{err.strip()}")
    base = out.strip()
    return [base], (f"working tree vs. the merge base of {left} and {right} "
                    f"({base[:12]})")


def resolve_base(mode):
    """Turn a mode into the base to compare the working tree against.

    Returns ([git arguments naming the base], description). Raises
    DiffCoverageError for anything that does not name one.
    """
    if mode in BASES:
        return BASES[mode]
    if mode in REMOVED_MODES:
        raise DiffCoverageError(f"--diff-coverage={mode} is not supported: "
                                f"{REMOVED_MODES[mode]}")
    if '...' in mode:
        left, _, right = mode.partition('...')
        return merge_base(left or 'HEAD', right or 'HEAD')
    if '..' in mode:
        raise DiffCoverageError(
            f"--diff-coverage={mode} is a commit range, which leaves out the "
            f"working tree the coverage was collected from. Give a single "
            f"revision to compare the working tree against, e.g. HEAD^, or "
            f"A...B for the merge base of A and B")
    return [mode], f"working tree vs. {mode}"


def diff_args(base, unified):
    # --src-prefix/--dst-prefix defeat a local diff.noprefix or
    # diff.mnemonicPrefix setting, so '+++ b/<path>' stays parseable. The
    # trailing '--' keeps git from reading an unknown revision as a path, which
    # turns a typo into a one line error instead of a usage dump.
    return ['diff', '--no-color', '--no-ext-diff', '--no-textconv', '-M',
            '--src-prefix=a/', '--dst-prefix=b/',
            '--diff-filter=d', f'--unified={unified}'] + base + ['--']


def strip_prefix(path):
    return path[2:] if path.startswith('b/') else path


def iter_diff_files(text):
    """Split a unified diff into (path, [(hunk_header, body_lines)]).

    Body lines always start with '+', '-' or ' ', so a line starting with
    'diff --git ' or '@@' can never be content and needs no disambiguation.
    """
    path = None
    hunks = []
    hunk = None
    for line in text.splitlines():
        if line.startswith('diff --git '):
            if path is not None:
                yield path, hunks
            path, hunks, hunk = None, [], None
        elif line.startswith('+++ '):
            new_path = line[4:].strip()
            path = None if new_path == '/dev/null' \
                else strip_prefix(new_path)
        elif line.startswith('@@'):
            hunk = (line, [])
            hunks.append(hunk)
        elif hunk is not None:
            hunk[1].append(line)
    if path is not None:
        yield path, hunks


def parse_unified_diff(text):
    """Map each new-side path to the set of lines added or modified.

    '@@ -a,b +c,d @@' means d lines starting at c on the new side. A missing d
    means 1, and d == 0 is a pure deletion which contributes nothing.
    """
    result = {}
    for path, hunks in iter_diff_files(text):
        lines = result.setdefault(path, set())
        for header, _ in hunks:
            match = HUNK_RE.match(header)
            if match is None:
                continue
            start = int(match.group(1))
            count = 1 if match.group(2) is None else int(match.group(2))
            lines.update(range(start, start + count))
    return result


def path_to_module(path, excluded_modules):
    """Map a repo relative path to (module, skip_reason).

    Exactly one of the two is None.
    """
    parts = path.split('/')
    ext = os.path.splitext(path)[1]
    if ext == '.hrl':
        return None, "header file, affects every module including it"
    if ext in ('.yrl', '.xrl'):
        return None, "grammar file, line numbers do not map to the " \
                     "generated module"
    if ext != '.erl':
        return None, "not an Erlang module"
    if len(parts) < 4 or parts[0] != 'apps' or parts[2] != 'src':
        return None, "not under apps/*/src, so not instrumented"
    module = os.path.splitext(parts[-1])[0]
    if module in excluded_modules:
        return None, "excluded from code coverage"
    return module, None


def untracked_erl_files():
    # Relative pathspecs are scoped to the cwd subtree, and git() runs at the
    # top of the checkout, so this covers the whole repository.
    out = git_succ(['ls-files', '--others', '--exclude-standard'])
    return [p for p in out.splitlines() if p.endswith('.erl')]


def whole_file_lines(path):
    full_path = os.path.join(testlib.get_ns_server_dir(), path)
    try:
        with open(full_path, 'r', errors='replace') as f:
            return set(range(1, sum(1 for _ in f) + 1))
    except OSError:
        return set()


def diff_for_new_file(path):
    """A diff for an untracked file, which git diff cannot produce."""
    out, _, rc = git(['diff', '--no-color', '--no-ext-diff',
                      '--src-prefix=a/', '--dst-prefix=b/',
                      f'--unified={DISPLAY_CONTEXT}', '--no-index',
                      '--', '/dev/null', path])
    # --no-index reports differences with exit code 1, like plain diff(1)
    return out if rc in (0, 1) else ""


def check_consistency(changed):
    """Warn when the reported line numbers cannot be trusted.

    The diff always has the working tree on the new side, so a stale build is
    the only thing left that can shift the numbers.
    """
    warnings = []
    for module in sorted(changed):
        path = changed[module].path
        app = path.split('/')[1]
        src = os.path.join(testlib.get_ns_server_dir(), path)
        beam = os.path.join(testlib.get_app_ebin_dir(app), f"{module}.beam")
        if not os.path.exists(beam):
            warnings.append(f"{module}.beam does not exist, {module} has "
                            f"never been compiled")
        elif os.path.getmtime(beam) < os.path.getmtime(src):
            warnings.append(f"{path} is newer than {module}.beam, rebuild "
                            f"or the reported line numbers will be wrong")
    return warnings


def collect_untracked(excluded_modules, skipped):
    """Untracked Erlang modules, counted whole.

    No diff can show them whatever the base, yet a new module with no tests is
    exactly what this is meant to catch. Anything that is not an instrumented
    module is skipped here, so an unrelated .erl costs no git diff of its own.
    """
    result = {}
    for path in untracked_erl_files():
        module, reason = path_to_module(path, excluded_modules)
        if module is None:
            skipped.append((path, reason))
            continue
        lines = whole_file_lines(path)
        if lines:
            result[path] = lines
    return result


def collect(mode, excluded_modules):
    """Work out which modules and lines changed. Raises DiffCoverageError."""
    base, description = resolve_base(mode)
    args = diff_args(base, 0)
    out, err, rc = git(args)
    if rc != 0:
        raise DiffCoverageError(f"git {' '.join(args)} failed:\n"
                                f"{err.strip()}")
    per_path = parse_unified_diff(out)

    display, _, display_rc = git(diff_args(base, DISPLAY_CONTEXT))
    if display_rc != 0:
        display = out

    skipped = []
    untracked = collect_untracked(excluded_modules, skipped)
    for path in sorted(untracked):
        per_path[path] = untracked[path]
        display += diff_for_new_file(path)

    changed = {}
    for path in sorted(per_path):
        module, reason = path_to_module(path, excluded_modules)
        if module is not None and per_path[path]:
            changed[module] = ChangedModule(module, path, per_path[path])
        else:
            skipped.append((path, reason if reason is not None
                            else "no lines added or modified"))

    return DiffInfo(mode=mode,
                    description=description,
                    command='git ' + ' '.join(args),
                    changed=changed,
                    skipped=sorted(skipped),
                    display_diff=display,
                    warnings=check_consistency(changed),
                    untracked=sorted(untracked))


def compute(diff_info, line_coverage):
    """Intersect the changed lines with the per-line coverage data.

    Only lines cover knows about are counted. Native line coverage instruments
    body lines, so comments, specs, attributes, blank lines, clause heads and
    guards all drop out of both the numerator and the denominator - hence the
    separate 'changed' and 'relevant' counts.
    """
    modules = []
    no_data = []
    total_changed = 0
    total_relevant = 0
    total_covered = 0

    for module in diff_info.modules():
        info = diff_info.changed[module]
        module_lines = line_coverage.get(module)
        total_changed += len(info.lines)
        if module_lines is None:
            no_data.append(module)
            modules.append(ModuleResult(module, info.path, len(info.lines),
                                        0, 0, [], False))
            continue

        covered = 0
        uncovered = []
        for line in sorted(info.lines):
            calls = module_lines.get(line)
            if calls is None:
                continue
            if calls > 0:
                covered += 1
            else:
                uncovered.append(line)

        relevant = covered + len(uncovered)
        total_relevant += relevant
        total_covered += covered
        modules.append(ModuleResult(module, info.path, len(info.lines),
                                    relevant, covered, uncovered, True))

    return DiffResult(modules=modules, changed=total_changed,
                      relevant=total_relevant, covered=total_covered,
                      no_data=no_data)


def format_summary(result):
    """The block printed in the final run summary.

    The 26 character label column matches the surrounding summary lines.
    """
    percentage = result.percentage()
    if percentage is None:
        lines = ["Changed-lines coverage:   n/a (no measurable lines "
                 "changed)"]
    else:
        lines = [f"Changed-lines coverage:   {percentage:.2f}% "
                 f"({result.covered} / {result.relevant} measurable lines)"]
    lines.append(f"Changed lines:            {result.changed} changed, "
                 f"{result.relevant} measurable")

    # No measurable line count means no place in the percentage above, so say
    # it next to that percentage: those lines never ran.
    if result.no_data:
        unmeasured = sum([m.changed for m in result.modules if not m.has_data])
        lines.append("No coverage data:         "
                     f"{', '.join(result.no_data)} "
                     f"({unmeasured} changed line(s) never measured, "
                     f"not counted above)")

    width = max([len(m.module) for m in result.modules], default=0)
    for m in result.modules:
        if not m.has_data:
            detail = f"no coverage data, {m.changed} line(s) changed"
            percentage_str = "    n/a"
        elif m.relevant == 0:
            detail = f"no measurable lines, {m.changed} line(s) changed"
            percentage_str = "    n/a"
        else:
            detail = f"({m.covered} / {m.relevant})"
            percentage_str = f"{m.percentage():6.2f}%"
        lines.append(f"  {m.module:<{width}}  {percentage_str}  {detail}")
    return '\n'.join(lines)


def format_skipped(diff_info):
    return '\n'.join([f"  {path}: {reason}"
                      for path, reason in diff_info.skipped])


def format_warnings(diff_info, colors=False):
    lines = []
    for warning in diff_info.warnings:
        text = f"  WARNING: {warning}"
        lines.append(testlib.yellow(text) if colors else text)
    return '\n'.join(lines)


def render_hunk(header, body, uncovered, colors):
    """Render one hunk, or None if it contains no uncovered line."""
    match = HUNK_RE.match(header)
    if match is None:
        return None
    lineno = int(match.group(1))
    rendered = []
    found = False
    for line in body:
        if line.startswith('+') or line.startswith(' '):
            if lineno in uncovered:
                found = True
                text = f"  ! {lineno:>6}  {line}"
                rendered.append(testlib.red(text) if colors else text)
            else:
                rendered.append(f"    {lineno:>6}  {line}")
            lineno += 1
        else:
            rendered.append(f"    {'':>6}  {line}")
    if not found:
        return None
    return '\n'.join([f"  {header}"] + rendered)


def format_uncovered(diff_info, result, colors=False):
    """An annotated diff of just the hunks with uncovered changed lines."""
    uncovered = {m.path: set(m.uncovered) for m in result.modules
                 if m.uncovered}
    if not uncovered:
        return ""

    out = []
    for path, hunks in iter_diff_files(diff_info.display_diff):
        if path not in uncovered:
            continue
        shown = [rendered for rendered in
                 [render_hunk(header, body, uncovered[path], colors)
                  for header, body in hunks]
                 if rendered is not None]
        if shown:
            out.append(path)
            out.extend(shown)
            out.append("")
    return '\n'.join(out).rstrip('\n')


def write_report(report_dir, diff_info, result):
    os.makedirs(report_dir, exist_ok=True)
    path = os.path.join(report_dir, 'diff_coverage.txt')
    parts = [f"Diff coverage: {diff_info.description}",
             f"Command: {diff_info.command}",
             "",
             format_summary(result),
             ""]
    if diff_info.warnings:
        parts += [format_warnings(diff_info), ""]
    if diff_info.skipped:
        parts += ["Skipped:", format_skipped(diff_info), ""]
    uncovered = format_uncovered(diff_info, result)
    if uncovered:
        parts += ["Changed lines not covered by the tests, '!' marks an "
                  "uncovered line:", "", uncovered, ""]
    with open(path, 'w') as f:
        f.write('\n'.join(parts))
    return path
