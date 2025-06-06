%% @author Couchbase <info@couchbase.com>
%% @copyright 2009-Present Couchbase, Inc.
%%
%% Use of this software is governed by the Business Source License included in
%% the file licenses/BSL-Couchbase.txt.  As of the Change Date specified in that
%% file, in accordance with the Business Source License, use of this software
%% will be governed by the Apache License, Version 2.0, included in the file
%% licenses/APL2.txt.
%%
-module(path_config).

-include("ns_common.hrl").

-export([component_path/1, component_path/2,
         tempfile/2, tempfile/3, minidump_dir/0, ensure_directories/0,
         get_path/2]).

%% used by ns_config_default
-export([default_memcached_config_path/0]).
-export([default_sigar_port_config_path/0]).

component_path_key(tmp) -> path_config_tmpdir;
component_path_key(data) -> path_config_datadir;
component_path_key(bin) -> path_config_bindir;
component_path_key(lib) -> path_config_libdir;
component_path_key(etc) -> path_config_etcdir;
component_path_key(sec) -> path_config_secdir.

-spec component_path(etc | tmp | data | lib | bin | sec) -> string().
component_path(NameAtom) ->
    %% Check for overrides to one of the typical directories
    try ets:lookup(path_config_override, component_path_key(NameAtom)) of
        [{_,X}|_] -> X;
        _ ->
            erlang:error({empty_for, NameAtom})
    catch error:badarg ->
            {ok, RV} = application:get_env(ns_server,
                                           component_path_key(NameAtom)),
            RV
    end.

-spec component_path(etc | tmp | data | lib | bin | sec, string()) -> string().
component_path(NameAtom, SubPath) ->
    filename:join(component_path(NameAtom), SubPath).

-spec get_path(etc | tmp | data | lib | bin | sec, string()) -> string().
get_path(DefaultComponent, Name) ->
    %% Check for path overrides to individual components
    try ets:lookup(path_config_override, Name) of
        [{_, X}] -> filename:join(X, Name);
        _ ->
            %% Not found, fallback to the default dir
            component_path(DefaultComponent, Name)
    catch error:badarg ->
        component_path(DefaultComponent, Name)
    end.

tempfile(Dir, Prefix, Suffix) ->
    Unique = erlang:unique_integer(),
    Pid = os:getpid(),
    Filename = Prefix ++ integer_to_list(Unique) ++ "_" ++
               Pid ++ Suffix,
    filename:join(Dir, Filename).

tempfile(Prefix, Suffix) ->
    Dir = component_path(tmp),
    tempfile(Dir, Prefix, Suffix).

default_memcached_config_path() ->
    filename:join(component_path(data, "config"), "memcached.json").

default_sigar_port_config_path() ->
    filename:join(component_path(data, "config"), "sigar_port.json").

minidump_dir() ->
    path_config:component_path(data, "crash").

%% Ensure the 'data' and 'tmp' paths exist and are writable. The path is
%% created if needed.
ensure_directories() ->
    Msg = "Unable to validate path ~p (reason: ~p). It must be a directory "
          "creatable/writable by the 'couchbase' user.",

    DataPath = component_path(data),
    case misc:mkdir_p(DataPath) of
        ok -> ok;
        {error, Reason} ->
            ?log_error(Msg, [DataPath, Reason]),
            exit({data_path, DataPath, Reason})
    end,

    TmpPath = component_path(tmp),
    case misc:ensure_writable_dir(component_path(tmp)) of
        ok -> ok;
        {error, TmpReason} ->
            ?log_error(Msg, [TmpPath, TmpReason]),
            exit({tmp_path, TmpPath, TmpReason})
    end.
