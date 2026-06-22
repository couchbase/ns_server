#!/usr/bin/env python3
#
# @author Couchbase <info@couchbase.com>
# @copyright 2024-Present Couchbase, Inc.
#
# Use of this software is governed by the Business Source License included in
# the file licenses/BSL-Couchbase.txt.  As of the Change Date specified in that
# file, in accordance with the Business Source License, use of this software
# will be governed by the Apache License, Version 2.0, included in the file
# licenses/APL2.txt.
import os.path
import subprocess

from installed_script_helpers import find_valid_binary, basedir

def run_config_remap(initargs,
                     output_path,
                     extra_args,
                     rewrite=None,
                     rewrite_if=None,
                     disable_fusion=False,
                     disable_continuous_backup=False,
                     log_level='info',
                     capture_output=False,
                     root_dir=basedir()):
    if rewrite is not None:
        for one in rewrite:
            print(f"rewrite: {one}")
            extra_args += ['--rewrite'] + one
    if rewrite_if is not None:
        for path, old, new in rewrite_if:
            print(f"rewrite-if: {path} {old} -> {new}")
            extra_args += ['--rewrite-if', path, old, new]
    if disable_continuous_backup:
        extra_args += ['--rewrite',
                       '[{bucket, _, props}, continuous_backup_enabled]',
                       'false']
    if disable_fusion:
        rewrite_states = ['enabled', 'enabling', 'stopping', 'stopped',
                          'disabling']
        for state in rewrite_states:
            extra_args += ['--rewrite-if',
                           '[fusion_config, state]',
                           state, 'disabling']
            extra_args += ['--rewrite-if',
                           '[{bucket, _, props}, magma_fusion_state]',
                           state, 'disabling']

    escript_path = find_valid_binary('escript', root_dir)
    escript_wrapper_path = find_valid_binary('escript-wrapper', root_dir)
    config_remap_path = find_valid_binary('config_remap', root_dir)

    initargs_path = ''
    for possible_initargs in initargs:
        if os.path.exists(possible_initargs):
            initargs_path = possible_initargs
            break
        raise RuntimeError("Did not find initargs")

    cmd = [escript_path,
           escript_wrapper_path,
           '--initargs-path', initargs_path,
           '--', config_remap_path,
           '--initargs-path', initargs_path,
           '--output-path', output_path,
           '--log-level', log_level] + extra_args

    pr = subprocess.run(cmd, capture_output=capture_output)
    pr.check_returncode()

def run_config_remap_via_escript_wrapper(initargs,
                                         output_path,
                                         remap,
                                         rewrite=None,
                                         rewrite_if=None,
                                         disable_fusion=False,
                                         disable_continuous_backup=False,
                                         log_level='info',
                                         capture_output=False,
                                         root_dir=basedir()):
    extra_args = []
    for remap_arg in remap:
        print(f"remap: {remap_arg}")
        extra_args += ['--remap'] + remap_arg

    extra_args = ['--regenerate-cookie',
                  '--regenerate-cluster-uuid',
                  '--remove-alternate-addresses',
                  '--disable-auto-failover'] + extra_args

    run_config_remap(initargs, output_path, extra_args, rewrite, rewrite_if,
                     disable_fusion, disable_continuous_backup, log_level,
                     capture_output, root_dir)

def disable_afo_via_config_remap(initargs,
                                 output_path,
                                 rewrite=None,
                                 rewrite_if=None,
                                 disable_fusion=False,
                                 disable_continuous_backup=False,
                                 log_level='info',
                                 capture_output=False,
                                 root_dir=basedir()):
    extra_args = ['--disable-auto-failover']
    run_config_remap(initargs, output_path, extra_args, rewrite, rewrite_if,
                     disable_fusion, disable_continuous_backup, log_level,
                     capture_output, root_dir)
