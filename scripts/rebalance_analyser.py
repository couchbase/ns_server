#!/usr/bin/env python3
# @author Couchbase <info@couchbase.com>
# @copyright 2023 Couchbase, Inc.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
import argparse
import subprocess
import sys


def main():
    args = parse_args()

    """
     /jq/master_events/plot-bucket-rebalance is intended to be called in
     the following manor:

       ./read master_events.log | \
          ./last-rebalance | \
          ./plot-bucket_rebalance "bucket-name"

    We use subprocess.Popen and subprocess.PIPE to achieve the above in
    Python.
    """

    scriptdir = sys.path[0]
    master_events = subprocess.Popen([scriptdir + "/jq/master_events/read",
                                     args.master_events],
                                     stdout=subprocess.PIPE)
    last_rebalance = subprocess.Popen(
        [scriptdir + "/jq/master_events/last-rebalance"],
        stdin=master_events.stdout, stdout=subprocess.PIPE)

    subprocess.run([scriptdir + "/jq/master_events/plot-bucket-rebalance",
                    args.bucket],
                   stdin=last_rebalance.stdout)


def parse_args():
    arg_parser = argparse.ArgumentParser(
        prog="./rebalance_analyser.py",
        description="Generate a plot of the vbucket moves for a bucket "
                    "rebalance from a master_events.log. If a bucket is not "
                    "specified, the last bucket that began rebalancing is used."
    )
    arg_parser.add_argument(
        '--master-events', '-m',
        type=str,
        required=True,
        metavar="<path>",
        help=f'Master events log read from')
    arg_parser.add_argument(
        '--bucket', '-b',
        type=str,
        default="",
        metavar="<name>",
        help=f'Bucket')

    return arg_parser.parse_args()


if __name__ == '__main__':
    main()
