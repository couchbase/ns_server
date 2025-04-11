%% @author Couchbase <info@couchbase.com>
%% @copyright 2013-Present Couchbase, Inc.
%%
%% Use of this software is governed by the Business Source License included in
%% the file licenses/BSL-Couchbase.txt.  As of the Change Date specified in that
%% file, in accordance with the Business Source License, use of this software
%% will be governed by the Apache License, Version 2.0, included in the file
%% licenses/APL2.txt.

-module(ns_babysitter).

-behavior(application).

-export([start/2, stop/1]).

-export([setup_server_profile/0]).

-include("ns_common.hrl").
-include_lib("ale/include/ale.hrl").

start(_, _) ->
    %% we're reading environment of ns_server application. Thus we
    %% need to load it.
    ok = application:load(ns_server),

    %% if erlang:send is done toward an unconnected node, the function will
    %% not return until the connection setup had completed (or failed).
    %% It leads to some processes get stuck for 7 seconds when they are trying
    %% to handle a call from ns_server during ns_server's rename
    %% This setting forbids auto connect back to ns_server. It guarantees that
    %% attempt to send message to not existing node will not block.
    %% (blocking send is fixed in erl21 so this hack can be removed)
    application:set_env(kernel, dist_auto_connect, never),

    setup_static_config(),

    init_master_password(),

    init_logging(),

    %% To initialize logging static config must be setup thus this weird
    %% machinery is required to log messages from setup_static_config().
    self() ! done,
    log_pending(),

    maybe_set_cpu_count_env(),
    %% We can't reduce the number of threads dynamically for this VM,
    %% so we are reducing the number of online schedulers instead which should
    %% reduce the number of "active" threads
    maybe_adjust_online_schedulers(),

    {have_host, true} = {have_host, ('nonode@nohost' =/= node())},

    ok = dist_manager:configure_net_kernel(),

    Cookie =
        case erlang:get_cookie() of
            nocookie ->
                NewCookie = misc:generate_cookie(),
                erlang:set_cookie(node(), NewCookie),
                NewCookie;
            SomeCookie ->
                SomeCookie
        end,

    ?log_info("babysitter cookie: ~p~n",
              [ns_cookie_manager:sanitize_cookie(Cookie)]),

    make_pidfile(),

    % Clear the HTTP proxy environment variables as they are honored, when they
    % are set, by the golang net/http package.
    true = os:unsetenv("http_proxy"),
    true = os:unsetenv("https_proxy"),

    %% Sets config_profile for babysitter context. Does NOT run continuity
    %% checker so babysitter will allow different profiles. That said, it will
    %% crash as soon as ns_server is attempted if the profile has changed.
    setup_server_profile(),
    ns_babysitter_sup:start_link().

log_pending() ->
    receive
        done ->
            ok;
        {LogLevel, Fmt, Args} ->
            ?ALE_LOG(LogLevel, Fmt, Args),
            log_pending()
    end.

setup_server_profile() ->
    ProfileName = case os:getenv("CB_FORCE_PROFILE") of
                      Str when is_list(Str), length(Str) > 0 -> Str;
                      _ -> config_profile:load()
                  end,
    {Data, N} = case application:get_env(ns_server, config_path) of
                    {ok, Path} ->
                        File = filename:join(filename:dirname(Path),
                                             string:join([ProfileName,
                                                          "_profile"],
                                                         "")),

                        %% Server will crash if profile file cannot be loaded.
                        {load_config(File), ProfileName};
                    _ ->
                        exit("FATAL: ns_server application env does not "
                             "contain config_path.")
                end,
    ?log_debug("Using profile '~s': ~p", [N, Data]),
    config_profile:set_data(Data).

load_config(Path) ->
    case file:consult(Path) of
        {ok, T} when is_list(T) ->
            T;
        {error, Reason} ->
            Msg = io_lib:format("failed to read static config: ~s with error: "
                                "~p. It must be readable file with list of "
                                "pairs~n", [Path, Reason]),
            erlang:error(lists:flatten(Msg))
    end.

get_config_path() ->
    case application:get_env(ns_server, config_path) of
        {ok, V} -> V;
        _ ->
            erlang:error("config_path parameter for ns_server application is "
                         "missing!")
    end.

setup_static_config() ->
    Terms = case file:consult(get_config_path()) of
                {ok, T} when is_list(T) ->
                    T;
                _ ->
                    erlang:error("failed to read static config: " ++ get_config_path() ++ ". It must be readable file with list of pairs~n")
            end,
    self() ! {info, "Static config terms:~n~p", [Terms]},
    lists:foreach(fun ({K,V}) ->
                          case application:get_env(ns_server, K) of
                              undefined ->
                                  application:set_env(ns_server, K, V);
                              _ ->
                                  self() ! {warn,
                                            "not overriding parameter ~p, which is given from command line",
                                            [K]}
                          end
                  end, Terms).

init_master_password() ->
    %% Running in a separate process in order to avoid having the EXIT message
    %% in mailbox after stopping the cb_gosecrets_runner process (note that root
    %% process traps exit)
    Self = self(),
    misc:executing_on_new_process(
      fun () ->
          %% Note that we don't have logger here, but we need the master
          %% password in order to start the logger, so the idea is simple:
          %% 1. We start tempory cb_gosecrets_runner with a dummy logger
          %% 2. It waits for the master password to be passed
          %% 3. If password is correct it puts it to the app's env
          %% 4. The temporary cb_gosecrets_runner process stops
          %% 5. Logger starts and uses that saved password to decrypt log
          %%    encryption keys (logDek)
          %% 6. ns_babysitter starts its main babysitter where
          %%    cb_gosecrets_runner starts again (with normal logger this time)
          %% Note that cb_gosecrets_runner that starts later never asks for
          %% password, it uses the one that is set here.
          Log = dummy_logger(Self),
          case cb_gosecrets_runner:start_link(Log, true, true) of
              {ok, _} ->
                  ok = cb_gosecrets_runner:stop();
              {error, shutdown} ->
                  misc:halt(1);
              {error, Reason} ->
                  Log(error, "Failed to start cb_gosecrets_runner: ~p",
                      [Reason]),
                  misc:halt(1)
          end
      end).

-define(GOSECRETS_DBG_VAR, "CB_DEBUG_GOSECRETS").

dummy_logger(Proc) ->
    fun (LogLevel, F, A) ->
        SkipDebug = (os:getenv(?GOSECRETS_DBG_VAR) == false),
        case LogLevel of
            debug when SkipDebug -> ok;
            error when SkipDebug ->
                io:format(F ++
                          " (set "?GOSECRETS_DBG_VAR"=1 to see debug output)~n",
                          A);
            _ ->
                io:format(F ++ "~n", A)
        end,
        Proc ! {LogLevel, F, A}
    end.

init_log_encryption() ->
    Log = dummy_logger(self()),
    Opts = #{hidden_pass => cb_gosecrets_runner:extract_hidden_pass(Log),
             log_fun => Log},
    case cb_deks_raw_utils:bootstrap_get_deks(logDek, Opts) of
        {ok, DekSnapshot} ->
            Log(debug, "Initializing log encryption (dek_id: ~p)",
                [cb_crypto:get_dek_id(DekSnapshot)]),
            ale:init_log_encryption_ds(DekSnapshot);
        {error, Reason} ->
            Log(error, "Failed to initialize log encryption: ~s",
                [cb_deks_raw_utils:format_error(Reason)]),
            misc:halt(1)
    end.

init_logging() ->
    ale:with_configuration_batching(
      fun () ->
              do_init_logging()
      end),
    ale:info(?NS_SERVER_LOGGER, "Brought up babysitter logging").

do_init_logging() ->
    {ok, Dir} = application:get_env(ns_server, error_logger_mf_dir),

    ok = init_log_encryption(),

    ok = misc:mkdir_p(Dir),
    ok = convert_disk_log_files(Dir),

    ok = ns_server:start_disk_sink(babysitter_sink, ?BABYSITTER_LOG_FILENAME),

    ok = ale:start_logger(?NS_SERVER_LOGGER, debug),
    ok = ale:set_loglevel(?ERROR_LOGGER, debug),
    ok = logger:set_primary_config(level, info),

    ok = ale:add_sink(?NS_SERVER_LOGGER, babysitter_sink, debug),
    ok = ale:add_sink(?ERROR_LOGGER, babysitter_sink, debug),

    case misc:get_env_default(ns_server, dont_suppress_stderr_logger, false) of
        true ->
            ale:stop_sink(stderr),
            ok = ale:start_sink(stderr, ale_stderr_sink, []),

            lists:foreach(
              fun (Logger) ->
                      ok = ale:add_sink(Logger, stderr, debug)
              end, [?NS_SERVER_LOGGER, ?ERROR_LOGGER]);
        false ->
            ok
    end.

stop(_) ->
    ale:info(?NS_SERVER_LOGGER, "Received shutdown request. Terminating."),
    ale:sync_all_sinks(),
    delete_pidfile().

convert_disk_log_files(Dir) ->
    lists:foreach(
      fun (Log) ->
              ok = convert_disk_log_file(Dir, Log)
      end,
      [?DEFAULT_LOG_FILENAME,
       ?ERRORS_LOG_FILENAME,
       ?VIEWS_LOG_FILENAME,
       ?MAPREDUCE_ERRORS_LOG_FILENAME,
       ?COUCHDB_LOG_FILENAME,
       ?DEBUG_LOG_FILENAME,
       ?XDCR_TARGET_LOG_FILENAME,
       ?STATS_LOG_FILENAME,
       ?BABYSITTER_LOG_FILENAME,
       ?REPORTS_LOG_FILENAME,
       ?ACCESS_LOG_FILENAME]).

convert_disk_log_file(Dir, Name) ->
    [OldName, "log"] = string:tokens(Name, "."),

    IdxFile = filename:join(Dir, OldName ++ ".idx"),
    SizFile = filename:join(Dir, OldName ++ ".siz"),

    case filelib:is_regular(IdxFile) of
        true ->
            {Ix, NFiles} = read_disk_log_index_file(filename:join(Dir, OldName)),
            Ixs = lists:seq(Ix, 1, -1) ++ lists:seq(NFiles, Ix + 1, -1),

            lists:foreach(
              fun ({NewIx, OldIx}) ->
                      OldPath = filename:join(Dir,
                                              OldName ++
                                                  "." ++ integer_to_list(OldIx)),
                      NewSuffix = case NewIx of
                                      0 ->
                                          ".log";
                                      _ ->
                                          ".log." ++ integer_to_list(NewIx)
                                  end,
                      NewPath = filename:join(Dir, OldName ++ NewSuffix),

                      case file:rename(OldPath, NewPath) of
                          {error, enoent} ->
                              ok;
                          ok ->
                              ok
                      end,

                      file:delete(SizFile),
                      file:delete(IdxFile)
              end, misc:enumerate(Ixs, 0));
        false ->
            ok
    end.

read_disk_log_index_file(Path) ->
    {Ix, _, _, NFiles} = disk_log_1:read_index_file(Path),

    %% Index can be one greater than number of files. This means that maximum
    %% number of files is not yet reached.
    %%
    %% Pretty weird behavior: if we're writing to the first file out of 20
    %% read_index_file returns {1, _, _, 1}. But as we move to the second file
    %% the result becomes be {2, _, _, 1}.
    case Ix =:= NFiles + 1 of
        true ->
            {Ix, Ix};
        false ->
            {Ix, NFiles}
    end.

make_pidfile() ->
    case application:get_env(ns_babysitter, pidfile) of
        {ok, ""} -> ok;
        {ok, PidFile} -> make_pidfile(PidFile);
        X -> X
    end.

make_pidfile(PidFile) ->
    Pid = os:getpid(),
    %% Pid is a string representation of the process id, so we append
    %% a newline to the end.
    ok = misc:write_file(PidFile, list_to_binary(Pid ++ "\n")),
    ok.

delete_pidfile() ->
    case application:get_env(ns_babysitter, pidfile) of
        {ok, ""} -> ok;
        {ok, PidFile} -> delete_pidfile(PidFile);
        X -> X
    end.

delete_pidfile(PidFile) ->
    ok = file:delete(PidFile).

maybe_set_cpu_count_env() ->
    case misc:read_cpu_count_env() of
        {ok, _} -> ok;
        undefined -> set_cpu_count_var(determine_cpu_num())
    end.

set_cpu_count_var(CPUCount) when is_integer(CPUCount), CPUCount =< 0 -> ok;
set_cpu_count_var(CPUCount) when is_integer(CPUCount) ->
    os:putenv(?CPU_COUNT_VAR, integer_to_list(CPUCount)).

determine_cpu_num() ->
    {ok, _} = sigar:start_link(),
    CGroupsStats = sigar:get_cgroups_info(),
    sigar:stop(),
    case CGroupsStats of
        #{<<"supported">> := true, <<"num_cpu_prc">> := CPUPercent}
          when is_number(CPUPercent), CPUPercent > 0 ->
            CPUCount = ceil(CPUPercent/100),
            ?log_info("CGroup CPU count is ~p (~b%)", [CPUCount, CPUPercent]),
            CPUCount;
        #{<<"supported">> := false} ->
            ?log_info("CGroups not supported by host"),
            0;
        #{} ->
            ?log_info("CGroups cpu limit not set"),
            0
    end.

maybe_adjust_online_schedulers() ->
    case misc:read_cpu_count_env() of
        {ok, CPUCount} when CPUCount > 0 ->
            Schedulers = erlang:system_info(schedulers),
            OldOnlineSchedulers = erlang:system_info(schedulers_online),
            OnlineSchedulers = min(CPUCount, Schedulers),
            ?log_info("Adjusting the number of schdulers online: ~b -> ~b "
                      "(total number of schedulers: ~b)",
                      [OldOnlineSchedulers, OnlineSchedulers, Schedulers]),
            erlang:system_flag(schedulers_online, OnlineSchedulers),
            ok;
        undefined ->
            ?log_info("Skipping adjustment of online schedulers"),
            ok
    end.
