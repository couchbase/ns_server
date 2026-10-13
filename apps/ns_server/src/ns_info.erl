%% @author Couchbase <info@couchbase.com>
%% @copyright 2009-Present Couchbase, Inc.
%%
%% Use of this software is governed by the Business Source License included in
%% the file licenses/BSL-Couchbase.txt.  As of the Change Date specified in that
%% file, in accordance with the Business Source License, use of this software
%% will be governed by the Apache License, Version 2.0, included in the file
%% licenses/APL2.txt.
%%
-module(ns_info).

-include("ns_common.hrl").

-ifdef(TEST).
-include_lib("eunit/include/eunit.hrl").
-endif.

-export([version/0, version/1, runtime/0, basic_info/0]).

version() ->
    lists:map(fun({App, _, Version}) -> {App, Version} end,
              application:loaded_applications()).

version(App) ->
    proplists:get_value(App, version()).

runtime() ->
    {WallClockMSecs, _} = erlang:statistics(wall_clock),
    [{otp_release, erlang:system_info(otp_release)},
     {erl_version, erlang:system_info(version)},
     {erl_version_long, erlang:system_info(system_version)},
     {system_arch_raw, erlang:system_info(system_architecture)},
     {system_arch, system_arch()},
     {localtime, erlang:localtime()},
     {memory, misc:memory()},
     {loaded, erlang:loaded()},
     {applications, application:loaded_applications()},
     {pre_loaded, erlang:pre_loaded()},
     {process_count, erlang:system_info(process_count)},
     {node, erlang:node()},
     {nodes, erlang:nodes()},
     {registered, erlang:registered()},
     {cookie, erlang:get_cookie()},
     {wordsize, erlang:system_info(wordsize)},
     {wall_clock, trunc(WallClockMSecs / 1000)}].


basic_info() ->
    {WallClockMSecs, _} = erlang:statistics(wall_clock),
    {erlang:node(),
     [{version, version()},
      {supported_compat_version, cluster_compat_mode:supported_compat_version()},
      {advertised_version, cluster_compat_mode:mb_master_advertised_version()},
      {system_arch, system_arch()},
      {os_name, os_name()},
      {os_kernel, os_kernel()},
      {wall_clock, trunc(WallClockMSecs / 1000)},
      {memory_data, memory_quota:this_node_memory_data()},
      {disk_data, ns_disksup:get_disk_data()}]}.

system_arch() ->
    case erlang:system_info(system_architecture) of
        % Per bug 607, erlang R13B03 doesn't know it's on a 64-bit windows,
        % and always reports "win32".
        "win32" ->
            case erlang:system_info({wordsize, external}) of
                4 -> "win32";
                8 -> "win64"
            end;
        X -> X
    end.

%% Not cached on Linux: an in-place distro upgrade rewrites os-release without
%% restarting us, and reading it is cheap. Elsewhere it takes a command or a
%% registry read, which is too costly for every heartbeat.
os_name() ->
    case os:type() of
        {unix, linux} ->
            read(os_name, fun () ->
                                  read_os_release(["/etc/os-release",
                                                   "/usr/lib/os-release"])
                          end);
        _ ->
            cached(os_name, fun read_os_name/0)
    end.

%% The kernel only changes across a reboot, which restarts us anyway.
os_kernel() ->
    cached(os_kernel, fun read_os_kernel/0).

cached(Key, Fun) ->
    case persistent_term:get({?MODULE, Key}, undefined) of
        undefined ->
            Value = read(Key, Fun),
            %% Retry a failed read on the next heartbeat rather than report
            %% "unknown" until restart.
            Value =/= "unknown" andalso
                persistent_term:put({?MODULE, Key}, Value),
            Value;
        Value ->
            Value
    end.

read(Key, Fun) ->
    try Fun()
    catch T:E ->
            warn_once(Key, "Failed to read ~p: ~p", [Key, {T, E}]),
            "unknown"
    end.

read_os_name() ->
    case os:type() of
        {unix, darwin} ->
            cmd("sw_vers -productName") ++ " " ++
                cmd("sw_vers -productVersion");
        {win32, _} ->
            {ok, Reg} = win32reg:open([read]),
            try
                ok = win32reg:change_key(
                       Reg, "\\hklm\\SOFTWARE\\Microsoft\\Windows NT"
                       "\\CurrentVersion"),
                {ok, Name} = win32reg:value(Reg, "ProductName"),
                {ok, Build} = win32reg:value(Reg, "CurrentBuildNumber"),
                windows_product_name(Name, list_to_integer(Build))
            after
                win32reg:close(Reg)
            end;
        _ ->
            "unknown"
    end.

%% Windows 11 still reports itself as Windows 10 in ProductName; build 22000
%% is the first Windows 11 build. Server editions are named correctly.
windows_product_name("Windows 10" ++ Rest, Build) when Build >= 22000 ->
    "Windows 11" ++ Rest;
windows_product_name(Name, _Build) ->
    Name.

%% os:cmd/1 doesn't fail when the command does, and would otherwise return the
%% shell's error message.
cmd(Cmd) ->
    case string:trim(os:cmd(Cmd ++ " 2>/dev/null")) of
        "" ->
            error({command_failed, Cmd});
        Out ->
            Out
    end.

read_os_release([]) ->
    warn_once(os_name, "No readable os-release file", []),
    "unknown";
read_os_release([File | Rest]) ->
    case file:read_file(File) of
        {ok, Bin} ->
            case parse_os_release(Bin) of
                "unknown" ->
                    warn_once(os_name, "No PRETTY_NAME or NAME in ~s",
                              [File]),
                    "unknown";
                Name ->
                    Name
            end;
        {error, _} ->
            read_os_release(Rest)
    end.

%% A failed read is retried on every heartbeat, so only warn about the first.
warn_once(Key, Fmt, Args) ->
    WarnedKey = {?MODULE, Key, warned},
    persistent_term:get(WarnedKey, false) orelse
        begin
            ?log_warning(Fmt, Args),
            persistent_term:put(WarnedKey, true)
        end.

parse_os_release(Bin) ->
    Props = lists:filtermap(
              fun (Line) ->
                      case string:split(Line, "=") of
                          [K, V] -> {true, {K, string:trim(V, both, "\"'")}};
                          _ -> false
                      end
              end, string:split(unicode:characters_to_list(Bin), "\n", all)),
    %% Without a name, VERSION alone isn't useful, and the caller relies on
    %% "unknown" to warn about it.
    case non_empty("PRETTY_NAME", Props) of
        undefined ->
            case non_empty("NAME", Props) of
                undefined ->
                    "unknown";
                Name ->
                    case non_empty("VERSION", Props) of
                        undefined -> Name;
                        Version -> Name ++ " " ++ Version
                    end
            end;
        PrettyName ->
            PrettyName
    end.

%% Returns the value trimmed of whitespace. An empty value is treated as
%% missing.
non_empty(Key, Props) ->
    case proplists:get_value(Key, Props) of
        undefined ->
            undefined;
        V ->
            case string:trim(V) of
                "" -> undefined;
                Trimmed -> Trimmed
            end
    end.

%% os:version/0 drops the distro suffix of the release (e.g. "-193.el8"),
%% which is the part needed to identify the exact kernel build.
read_os_kernel() ->
    case os:type() of
        {unix, linux} ->
            {ok, Bin} = file:read_file("/proc/sys/kernel/osrelease"),
            string:trim(binary_to_list(Bin));
        {unix, _} ->
            cmd("uname -r");
        _ ->
            lists:flatten(
              lists:join(".", [integer_to_list(N) ||
                                  N <- tuple_to_list(os:version())]))
    end.

-ifdef(TEST).
parse_os_release_test() ->
    ?assertEqual("Red Hat Enterprise Linux 8.2 (Ootpa)",
                 parse_os_release(
                   <<"NAME=\"Red Hat Enterprise Linux\"\n"
                     "VERSION=\"8.2 (Ootpa)\"\n"
                     "PRETTY_NAME=\"Red Hat Enterprise Linux 8.2 (Ootpa)\"\n"
                     >>)),
    ?assertEqual("Ubuntu 22.04",
                 parse_os_release(<<"NAME='Ubuntu'\nVERSION=22.04\n">>)),
    ?assertEqual("Ubuntu 22.04",
                 parse_os_release(
                   <<"PRETTY_NAME=\"\"\nNAME=Ubuntu\nVERSION=22.04\n">>)),
    ?assertEqual("unknown", parse_os_release(<<"VERSION=22.04\n">>)),
    ?assertEqual("Fedora 40",
                 parse_os_release(<<"PRETTY_NAME=\" Fedora 40 \"\n">>)),
    ?assertEqual("Fedora",
                 parse_os_release(<<"NAME=\" Fedora \"\nVERSION=\" \"\n">>)),
    ?assertEqual("unknown",
                 parse_os_release(<<"NAME=\" \"\nVERSION=22.04\n">>)),
    ?assertEqual("unknown", parse_os_release(<<>>)),
    ?assertEqual([16#00E9], parse_os_release(<<"PRETTY_NAME=\"\xc3\xa9\"">>)).

windows_product_name_test() ->
    ?assertEqual("Windows 11 Pro",
                 windows_product_name("Windows 10 Pro", 22631)),
    ?assertEqual("Windows 10 Pro",
                 windows_product_name("Windows 10 Pro", 19045)),
    ?assertEqual("Windows Server 2025 Datacenter",
                 windows_product_name("Windows Server 2025 Datacenter", 26100)).
-endif.
