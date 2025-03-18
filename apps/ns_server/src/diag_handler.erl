%% @author Couchbase <info@couchbase.com>
%% @copyright 2009-Present Couchbase, Inc.
%%
%% Use of this software is governed by the Business Source License included in
%% the file licenses/BSL-Couchbase.txt.  As of the Change Date specified in that
%% file, in accordance with the Business Source License, use of this software
%% will be governed by the Apache License, Version 2.0, included in the file
%% licenses/APL2.txt.
%%
%% @doc Implementation of diagnostics web requests
-module(diag_handler).
-author('NorthScale <info@northscale.com>').

-include_lib("ns_common/include/cut.hrl").
-include("ns_common.hrl").
-include("ns_log.hrl").
-include_lib("kernel/include/file.hrl").

-ifdef(TEST).
-include_lib("eunit/include/eunit.hrl").
-endif.

-export([handle_diag/1,
         handle_sasl_logs/1, handle_sasl_logs/2,
         handle_diag_ale/1,
         handle_diag_eval/1,
         handle_diag_master_events/1,
         handle_diag_vbuckets/1,
         handle_diag_get_password/1,
         handle_diag_encryption_at_rest/1,
         arm_timeout/2, arm_timeout/1, disarm_timeout/1,
         grab_process_info/1, manifest/0,
         diagnosing_timeouts/1,
         %% rpc-ed to grab babysitter and couchdb processes
         grab_process_infos/0,
         %% rpc-ed to grab couchdb ets_tables
         grab_all_ets_tables/0]).

-define(ETS_MAX_TABLE_CHUNK, ?get_param(cbcollect_max_ets_chunk, 10_000)).

%% Read the manifest.xml file
manifest() ->
    case file:read_file(filename:join(path_config:component_path(bin, ".."), "manifest.xml")) of
        {ok, C} ->
            string:tokens(binary_to_list(C), "\n");
        _ -> []
    end.

%% works like lists:foldl(Fun, Acc, binary:split(Binary, Separator, [global]))
%%
%% But without problems of binary:split. See MB-9534
split_fold_incremental(Binary, Separator, NumMatches, Fun, Acc) ->
    CP = binary:compile_pattern(Separator),
    Len = erlang:size(Binary),
    split_fold_incremental_loop(Binary, CP, Len, Fun, Acc, NumMatches, 0).

split_fold_incremental_loop(_Binary, _CP, _Len, _Fun, Acc, 0, _Start) ->
    %% Reached the maximum number of matches.
    Acc;
split_fold_incremental_loop(_Binary, _CP, Len, _Fun, Acc, _NumMatches, Start)
  when Start > Len ->
    Acc;
split_fold_incremental_loop(Binary, CP, Len, Fun, Acc, NumMatches, Start) ->
    {MatchPos, MatchLen} =
        case binary:match(Binary, CP, [{scope, {Start, Len - Start}}]) of
            nomatch ->
                %% NOTE: 1 here will move Start _past_ Len on next
                %% loop iteration
                {Len, 1};
            MatchPair ->
                MatchPair
        end,
    NewPiece = binary:part(Binary, Start, MatchPos - Start),
    NewAcc = Fun(NewPiece, Acc),
    split_fold_incremental_loop(Binary, CP, Len, Fun,
                                NewAcc, NumMatches - 1, MatchPos + MatchLen).

-spec sanitize_backtrace(term(), binary()) -> [binary()].
sanitize_backtrace(Name, Backtrace) ->
    SanitizeRegisters =
        case Name of
            auth ->
                true;
            memcached_passwords ->
                true;
            {lhttpc_client, request} ->
                true;
            _ ->
                false
        end,
    case SanitizeRegisters of
        true ->
            {ok, RE} = re:compile(<<"^Program counter: 0x[0-9a-f]+ |^0x[0-9a-f]+ Return addr 0x[0-9a-f]+">>),
            do_sanitize_backtrace(Backtrace, fun (X) -> re:run(X, RE) end);
        false ->
            do_sanitize_backtrace(Backtrace, fun (X) -> X end)
    end.

do_sanitize_backtrace(Backtrace, Fun) ->
    R = split_fold_incremental(
          Backtrace, <<"\n">>, 200,
          fun (X, Acc) ->
                  case Fun(X) of
                      nomatch ->
                          Acc;
                      _ when size(X) =< 120 ->
                          [binary:copy(X) | Acc];
                      _ ->
                          [binary:copy(binary:part(X, 1, 120)) | Acc]
                  end
          end, []),
    lists:reverse(R).

massage_messages(Messages) ->
    [massage_message(M) || M <- lists:sublist(Messages, 10)].

massage_message(Message) ->
    iolist_to_binary(io_lib:format("~W", [Message, 25])).

grab_process_info(Pid) ->
    case erlang:process_info(Pid,
                             [registered_name,
                              status,
                              initial_call,
                              backtrace,
                              error_handler,
                              garbage_collection,
                              garbage_collection_info,
                              links,
                              monitors,
                              monitored_by,
                              memory,
                              messages,
                              message_queue_len,
                              reductions,
                              trap_exit,
                              current_location,
                              dictionary]) of
        undefined ->
            undefined;
        PureInfo ->
            Backtrace = proplists:get_value(backtrace, PureInfo),

            NewBacktrace = case {proplists:get_value(registered_name, PureInfo),
                                 proplists:get_value(initial_call, PureInfo)} of
                               {[], {M,F,_}} ->
                                   sanitize_backtrace({M,F}, Backtrace);
                               {Name, _} ->
                                   sanitize_backtrace(Name, Backtrace)
                            end,

            Messages = proplists:get_value(messages, PureInfo),
            NewMessages = massage_messages(Messages),

            Dictionary = proplists:get_value(dictionary, PureInfo),
            NewDictionary = [{K, trim_term(V, 250)} || {K, V} <- Dictionary],

            misc:update_proplist(PureInfo,
                                 [{backtrace, NewBacktrace},
                                  {messages, NewMessages},
                                  {dictionary, NewDictionary}])
    end.

task_status_all() ->
    local_tasks:all() ++ ns_couchdb_api:get_tasks().

do_diag_per_node() ->
    work_queue:submit_sync_work(
      diag_handler_worker,
      fun () ->
              (catch collect_diag_per_node(40000))
      end).

collect_diag_per_node(Timeout) ->
    ReplyRef = make_ref(),
    Parent = self(),
    {ChildPid, ChildRef} =
        spawn_monitor(
          fun () ->
                  Reply = fun (Key, Value) ->
                                  Parent ! {ReplyRef, {Key, Value}},
                                  ?log_debug("Collected data for key ~p", [Key])
                          end,

                  ChildPid = self(),
                  proc_lib:spawn_link(
                    fun () ->
                            erlang:monitor(process, Parent),
                            erlang:monitor(process, ChildPid),

                            receive
                                {'DOWN', _, _, _, Reason} ->
                                    exit(ChildPid, Reason)
                            end
                    end),

                  try
                      collect_diag_per_node_body(Reply)
                  catch
                      T:E:S ->
                          Reply(partial_results_reason,
                                {process_died, {T, E, S}})
                  end
          end),

    TRef = erlang:send_after(Timeout, self(), timeout),

    try
        collect_diag_per_node_loop(ReplyRef, ChildRef, [])
    after
        erlang:cancel_timer(TRef),
        receive
            timeout -> ok
        after
            0 -> ok
        end,

        erlang:demonitor(ChildRef, [flush]),
        exit(ChildPid, kill),

        flush_leftover_replies(ReplyRef)
    end.

flush_leftover_replies(ReplyRef) ->
    receive
        {ReplyRef, _} ->
            flush_leftover_replies(ReplyRef)
    after
        0 -> ok
    end.

collect_diag_per_node_loop(ReplyRef, ChildRef, Results) ->
    receive
        {ReplyRef, Item} ->
            collect_diag_per_node_loop(ReplyRef, ChildRef, [Item | Results]);
        timeout ->
            [{partial_results_reason, timeout} | Results];
        {'DOWN', ChildRef, process, _, _} ->
            Results
    end.

collect_diag_per_node_body(Reply) ->
    ?log_debug("Start collecting diagnostic data"),
    ActiveBuckets = ns_memcached:active_buckets(),
    PersistentBuckets = [B || B <- ActiveBuckets,
                              ns_bucket:is_named_bucket_persistent(B)],

    Reply(processes, grab_process_infos()),
    Reply(babysitter_processes, (catch grab_babysitter_process_infos())),
    Reply(couchdb_processes, (catch grab_couchdb_process_infos())),
    Reply(version, ns_info:version()),
    Reply(manifest, manifest()),
    Reply(config, ns_config_log:sanitize(ns_config:get_kv_list())),
    Reply(basic_info, element(2, ns_info:basic_info())),
    ns_bootstrap:ensure_os_mon(),
    Reply(memory, memsup:get_memory_data()),
    Reply(disk, (catch ns_disksup:get_disk_data())),
    Reply(active_tasks, task_status_all()),
    Reply(ns_server_stats, (catch ns_server_stats:get_ns_server_stats())),
    Reply(active_buckets, ActiveBuckets),
    Reply(replication_docs, (catch goxdcr_rest:find_all_replication_docs(5000))),
    Reply(design_docs, [{Bucket, (catch capi_utils:full_live_ddocs(Bucket, 2000))} ||
                           Bucket <- PersistentBuckets]),
    Reply(ets_tables, grab_later),
    Reply(couchdb_ets_tables, (catch grab_couchdb_ets_tables())),
    Reply(internal_settings, (catch menelaus_web_settings:build_kvs(internal))),
    Reply(logging, (catch ale:capture_logging_diagnostics())),
    Reply(system_info, (catch grab_system_info())).

grab_babysitter_process_infos() ->
    rpc:call(ns_server:get_babysitter_node(), ?MODULE, grab_process_infos, [], 5000).

grab_couchdb_process_infos() ->
    rpc:call(ns_node_disco:couchdb_node(), ?MODULE, grab_process_infos, [], 5000).

grab_process_infos() ->
    grab_process_infos_loop(erlang:processes(), []).

grab_process_infos_loop([], Acc) ->
    Acc;
grab_process_infos_loop([P | RestPids], Acc) ->
    case catch grab_process_info(P) of
        undefined ->
            %% Pid gone, skip it.
            grab_process_infos_loop(RestPids, Acc);
        Info ->
            NewAcc = [{P, Info} | Acc],
            grab_process_infos_loop(RestPids, NewAcc)
    end.

grab_couchdb_ets_tables() ->
    rpc:call(ns_node_disco:couchdb_node(), ?MODULE, grab_all_ets_tables, [], 5000).

get_ets_table_sanitizer(menelaus_ui_auth, _Info) ->
    skip;
get_ets_table_sanitizer(menelaus_ui_auth_by_expiration, _Info) ->
    skip;
get_ets_table_sanitizer(chronicle_mem_log, _Info) ->
    skip;
get_ets_table_sanitizer(kv, _Info) ->
    skip;
get_ets_table_sanitizer(menelaus_web_cache, _Info) ->
    {ok, fun ns_cluster:sanitize_node_info/1};
get_ets_table_sanitizer(ns_couchdb_chronicle_dup, _Info) ->
    {ok, fun ({K, V}) ->  {K, chronicle_kv_log:sanitize(K, V)} end};
get_ets_table_sanitizer(ldap_auth_cache, _Info) ->
    skip;
get_ets_table_sanitizer(ldap_groups_cache, _Info) ->
    skip;
get_ets_table_sanitizer(_, Info) ->
    case proplists:get_value(name, Info) of
        ssl_otp_pem_cache ->
            skip;
        cookies ->
            skip;
        kv ->
            skip;
        _ ->
            {ok, ns_config_log:sanitize(_, true)}
    end.

get_ets_table_info(Table) ->
    case ets:info(Table) of
        undefined ->
            {error, not_found};
        Info ->
            {ok, Info}
    end.

stream_ets_table(Table, Info, Fun, State) ->
    try
        do_stream_ets_table(Table, Info, Fun, State)
    catch
        T:E:S ->
            {error, {failed, T, E, S}}
    end.

do_stream_ets_table(Table, Info, Fun, State) ->
    case get_ets_table_sanitizer(Table, Info) of
        skip ->
            {error, skipped};
        {ok, Sanitizer} ->
            SanitizerFun =
                fun (Element, Acc) ->
                        Fun(Sanitizer(Element), Acc)
                end,
            FinalState =
                case proplists:get_value(protection, Info) of
                    private ->
                        %% Skip private tables as they are not
                        %% accessible and will lead to a badarg error.
                        ["Inaccessible private table"];
                    _ ->
                        case proplists:get_value(size, Info) >
                            ?ETS_MAX_TABLE_CHUNK of
                            true ->
                                {Chunk, _} =
                                    ets:select(Table, [{'$1', [], ['$1']}],
                                               ?ETS_MAX_TABLE_CHUNK),
                                lists:foldl(SanitizerFun, State, Chunk);
                            false ->
                                ets:foldl(SanitizerFun, State, Table)
                        end
                end,
            {ok, FinalState}
    end.

grab_all_ets_tables() ->
    All = ets:all(),
    FilteredLdapCaches =
        case (catch ets:lookup(ldap_groups_cache, tables)) of
            [{tables, {GroupCacheA, GroupCacheB}} | _] ->
                %% ldap_groups_cache should also be skipped but that is done in
                %% the normal spot at:
                %% diag_handler:get_ets_table_sanitizer/2
                lists:filter(
                  ?cut(not lists:member(_, [GroupCacheA, GroupCacheB])), All);
            _ ->
                All
        end,
    lists:flatmap(fun grab_ets_table/1, FilteredLdapCaches).

grab_ets_table(Table) ->
    case get_ets_table_info(Table) of
        {ok, Info} ->
            case stream_ets_table(Table, Info,
                                  fun (Elem, AccValues) ->
                                          [Elem | AccValues]
                                  end, []) of
                {ok, ReversedValues} ->
                    [{{Table, Info}, lists:reverse(ReversedValues)}];
                Error ->
                    [{{Table, Info}, [Error]}]
            end;
        _Error ->
            []
    end.

diag_format_timestamp(EpochMilliseconds) ->
    SecondsRaw = trunc(EpochMilliseconds/1000),
    MicroSecs = (EpochMilliseconds rem 1000) * 1000,
    AsNow = {SecondsRaw div 1000000, SecondsRaw rem 1000000, MicroSecs},
    ale_default_formatter:format_time(AsNow).

generate_diag_filename() ->
    SystemTime = erlang:timestamp(),
    {{YYYY, MM, DD}, {Hour, Min, Sec}} = calendar:now_to_local_time(SystemTime),
    io_lib:format("ns-diag-~4.4.0w~2.2.0w~2.2.0w~2.2.0w~2.2.0w~2.2.0w.txt",
                  [YYYY, MM, DD, Hour, Min, Sec]).

diag_format_log_entry(Type, Code, Module, Node, TStamp, ShortText, Text) ->
    FormattedTStamp = diag_format_timestamp(TStamp),
    io_lib:format("~s ~s:~B:~s:~s(~s) - ~s~n",
                  [FormattedTStamp, Module, Code, Type, ShortText, Node, Text]).

handle_diag(Req) ->
    trace_memory("Starting to handle diag."),
    Params = mochiweb_request:parse_qs(Req),
    MaybeContDisp = case proplists:get_value("mode", Params) of
                        "view" -> [];
                        _ -> [{"Content-Disposition", "attachment; filename=" ++ generate_diag_filename()}]
                    end,

    Resp = handle_just_diag(Req, MaybeContDisp),
    mochiweb_response:write_chunk(<<>>, Resp),
    trace_memory("Finished handling diag.").

grab_per_node_diag() ->
    grab_per_node_diag(45000).

grab_per_node_diag(Timeout) ->
    Result = case async:run_with_timeout(fun () ->
                                                 do_diag_per_node()
                                         end, Timeout) of
                 {ok, R} ->
                     R;
                 {error, timeout} ->
                     diag_failed
             end,

    [{node(), Result}].

handle_just_diag(Req, Extra) ->
    Resp = menelaus_util:reply_ok(Req, "text/plain; charset=utf-8", chunked, Extra),

    mochiweb_response:write_chunk(<<"logs:\n-------------------------------\n">>, Resp),
    lists:foreach(fun (#log_entry{node = Node,
                                  module = Module,
                                  code = Code,
                                  msg = Msg,
                                  args = Args,
                                  cat = Cat,
                                  tstamp = TStamp}) ->
                          try io_lib:format(Msg, Args) of
                              S ->
                                  CodeString = ns_log:code_string(Module, Code),
                                  Type = menelaus_alert:category_bin(Cat),
                                  TStampEpoch = misc:timestamp_to_time(TStamp, millisecond),
                                  mochiweb_response:write_chunk(
                                    iolist_to_binary(
                                      diag_format_log_entry(
                                        Type, Code, Module, Node, TStampEpoch,
                                        CodeString, S)),
                                    Resp)
                          catch _:_ -> ok
                          end
                  end, lists:keysort(#log_entry.tstamp, ns_log:recent())),
    mochiweb_response:write_chunk(<<"-------------------------------\n\n\n">>,
                                  Resp),

    mochiweb_response:write_chunk(
      <<"Event Logs:\n-------------------------------\n">>, Resp),

    lists:foreach(fun (Event) ->
                          JSON = try
                                     menelaus_util:encode_json(Event)
                                 catch
                                     T:E:S ->
                                         ?log_error(
                                           "Event JSON encoding error - ~p~n"
                                           "Event - ~p~n", [{T,E,S}, Event]),
                                         encoding_error
                                 end,
                          case JSON of
                              encoding_error ->
                                  ok;
                              _ ->
                                  mochiweb_response:write_chunk([JSON, $\n],
                                                                Resp)
                          end
                  end, event_log_server:build_events_json(undefined, -1, [])),

    mochiweb_response:write_chunk(
      <<"-------------------------------\n\n\n">>, Resp),

    Results = grab_per_node_diag(),
    handle_per_node_just_diag(Resp, Results),

    Buckets = lists:sort(fun (A,B) -> element(1, A) =< element(1, B) end,
                         ns_bucket:get_buckets()),

    Ctx = menelaus_web_node:get_context(undefined, true, unstable),
    Infos = [["nodes_info = ~p",
              ns_cluster:sanitize_node_info(
                menelaus_web_node:build_nodes_info(Ctx))],
             ["buckets = ~p", ns_config_log:sanitize(Buckets)],
             ["config_profile = ~p", config_profile:get()]] ++
        case cgroups:supported() andalso cgroups:has_feature_enabled() of
            true ->
                ["cgroup_overrides = ~p", ns_cgroups_manager:get_overrides()];
            false ->
                []
        end,
    [begin
         Text = io_lib:format(Fmt ++ "~n~n", Args),
         mochiweb_response:write_chunk(list_to_binary(Text), Resp)
     end || [Fmt | Args] <- Infos],

    mochiweb_response:write_chunk(
      <<"Encryption-at-rest:\n-------------------------------\n">>, Resp),
    mochiweb_response:write_chunk(cb_cluster_secrets:diag_info(), Resp),

    Resp.

write_chunk_format(Resp, Fmt, Args) ->
    Text = io_lib:format(Fmt, Args),
    mochiweb_response:write_chunk(list_to_binary(Text), Resp).

handle_per_node_just_diag(_Resp, []) ->
    erlang:garbage_collect();
handle_per_node_just_diag(Resp, [{Node, Diag} | Results]) ->
    erlang:garbage_collect(),

    trace_memory("Processing diag info for node ~p", [Node]),
    do_handle_per_node_just_diag(Resp, Node, Diag),
    handle_per_node_just_diag(Resp, Results).

do_handle_per_node_just_diag(Resp, Node, Failed) when not is_list(Failed) ->
    write_chunk_format(Resp, "per_node_diag(~p) = ~p~n~n~n", [Node, Failed]);
do_handle_per_node_just_diag(Resp, Node, PerNodeDiag) ->
    do_handle_per_node_processes(Resp, Node, PerNodeDiag).

get_other_node_processes(Key, PerNodeDiag) ->
    Processes = proplists:get_value(Key, PerNodeDiag, []),
    %% it may be rpc or any other error; just pretend it's the process so that
    %% the error is visible
    case is_list(Processes) of
        true ->
            Processes;
        false ->
            [Processes]
    end.

write_processes(Resp, Node, Key, Processes) ->
    misc:executing_on_new_process(
      fun () ->
              write_chunk_format(Resp, "per_node_~p(~p) =~n", [Key, Node]),
              lists:foreach(
                fun (Process) ->
                        write_chunk_format(Resp, "     ~p~n", [Process])
                end, Processes),
              mochiweb_response:write_chunk(<<"\n\n">>, Resp)
      end).

do_handle_per_node_processes(Resp, Node, PerNodeDiag) ->
    erlang:garbage_collect(),
    trace_memory("Starting pretty printing processes for ~p", [Node]),

    Processes = proplists:get_value(processes, PerNodeDiag),

    BabysitterProcesses = get_other_node_processes(babysitter_processes, PerNodeDiag),
    CouchdbProcesses = get_other_node_processes(couchdb_processes, PerNodeDiag),

    DiagNoProcesses = lists:keydelete(
                        processes, 1,
                        lists:keydelete(babysitter_processes, 1,
                                        lists:keydelete(couchdb_processes, 1, PerNodeDiag))),

    write_processes(Resp, Node, processes, Processes),
    write_processes(Resp, Node, babysitter_processes, BabysitterProcesses),
    write_processes(Resp, Node, couchdb_processes, CouchdbProcesses),

    trace_memory("Finished pretty printing processes for ~p", [Node]),
    do_handle_per_node_ets_tables(Resp, Node, DiagNoProcesses).

print_ets_table(Resp, Node, Key, Table, Info, Values) ->
    trace_memory("Printing ets table ~p for node ~p", [Table, Node]),
    misc:executing_on_new_process(
      fun () ->
              do_print_ets_table(Resp, Node, Key, Table, Info, Values)
      end).

do_print_ets_table(Resp, Node, Key, Table, [], grab_later) ->
    case get_ets_table_info(Table) of
        {ok, Info} ->
            ProducerFun =
                fun (Callback) ->
                        case stream_ets_table(Table, Info,
                                              fun (Value, _) ->
                                                      Callback(Value)
                                              end, unused) of
                            {ok, _} ->
                                ok;
                            Error ->
                                Error
                        end
                end,

            format_ets_table(Resp, Node, Key, Table, Info, ProducerFun);
        _Error ->
            ok
    end;
do_print_ets_table(Resp, Node, Key, Table, Info, Values) ->
    format_ets_table(Resp, Node, Key, Table, Info,
                     lists:foreach(_, Values)).

format_ets_table(Resp, Node, Key, Table, Info, ProduceValues) ->
    write_chunk_format(Resp, "per_node_~p(~p, ~p) =~n",
                       [Key, Node, Table]),
    case Info of
        [] ->
            ok;
        _ ->
            write_chunk_format(Resp, "  Info: ~p~n", [Info])
    end,

    mochiweb_response:write_chunk(<<"  Values: \n">>, Resp),
    case ProduceValues(?cut(write_chunk_format(Resp, "    ~p~n", [_]))) of
        ok ->
            ok;
        Error ->
            write_chunk_format(Resp, "    ~p~n", [Error])
    end,
    mochiweb_response:write_chunk(<<"\n">>, Resp).

write_ets_tables(Resp, Node, Key, PerNodeDiag) ->
    trace_memory("Starting pretty printing ets tables for ~p", [{Node, Key}]),
    EtsTables = case proplists:get_value(Key, PerNodeDiag, []) of
                    grab_later ->
                        [{T, grab_later} || T <- ets:all()];
                    EtsTables0 when is_list(EtsTables0) ->
                        EtsTables0;
                    Other ->
                        [{'_', [Other]}]
                end,
    erlang:garbage_collect(),

    lists:foreach(
      fun ({{Table, Info}, Values}) ->
              print_ets_table(Resp, Node, Key, Table, Info, Values);
          ({Table, Values}) ->
              print_ets_table(Resp, Node, Key, Table, [], Values)
      end, EtsTables),

    trace_memory("Finished pretty printing ets tables for ~p", [{Node, Key}]),
    lists:keydelete(Key, 1, PerNodeDiag).

do_handle_per_node_ets_tables(Resp, Node, PerNodeDiag) ->
    PerNodeDiag1 = write_ets_tables(Resp, Node, ets_tables, PerNodeDiag),
    PerNodeDiag2 = write_ets_tables(Resp, Node, couchdb_ets_tables, PerNodeDiag1),
    do_continue_handling_per_node_just_diag(Resp, Node, PerNodeDiag2).

do_continue_handling_per_node_just_diag(Resp, Node, Diag) ->
    erlang:garbage_collect(),

    misc:executing_on_new_process(
      fun () ->
              write_chunk_format(Resp, "per_node_diag(~p) =~n", [Node]),
              write_chunk_format(Resp, "     ~p~n", [Diag])
      end),

    mochiweb_response:write_chunk(<<"\n\n">>, Resp).

handle_log(Resp, LogName) ->
    LogsHeader = io_lib:format("logs_node (~s):~n"
                               "-------------------------------~n", [LogName]),
    mochiweb_response:write_chunk(list_to_binary(LogsHeader), Resp),
    ns_log_browser:stream_logs(LogName,
                               fun (Data) -> mochiweb_response:write_chunk(Data, Resp) end),
    mochiweb_response:write_chunk(<<"-------------------------------\n">>, Resp).

handle_sasl_logs(LogName, Req) ->
    FullLogName = LogName ++ ".log",
    case ns_log_browser:log_exists(FullLogName) of
        true ->
            Resp = menelaus_util:reply_ok(Req, "text/plain; charset=utf-8", chunked),
            handle_log(Resp, FullLogName),
            mochiweb_response:write_chunk(<<"">>, Resp);
        false ->
            menelaus_util:reply_text(Req, "Requested log file not found.\r\n", 404)
    end.

handle_sasl_logs(Req) ->
    handle_sasl_logs("debug", Req).

plist_to_ejson_rewriter([Tuple|_] = ListOfTuples) when is_tuple(Tuple) ->
    Objects = [misc:rewrite(fun plist_to_ejson_rewriter/1, PL)
               || PL <- ListOfTuples],
    {stop, {Objects}};
plist_to_ejson_rewriter(_Other) ->
    continue.

handle_diag_ale(Req) ->
    PList = ale:capture_logging_diagnostics(),
    Objects = misc:rewrite(fun plist_to_ejson_rewriter/1, PList),
    menelaus_util:reply_json(Req, Objects).

arm_timeout(Millis) ->
    arm_timeout(Millis,
                fun (Pid) ->
                        Info = (catch grab_process_info(Pid)),
                        ?log_error("slow process ~p info:~n~p~n", [Pid, Info])
                end).

arm_timeout(Millis, Callback) ->
    Pid = self(),
    spawn_link(fun () ->
                       receive
                           done -> ok
                       after Millis ->
                               erlang:unlink(Pid),
                               Callback(Pid)
                       end,
                       erlang:unlink(Pid)
               end).

disarm_timeout(Pid) ->
    Pid ! done.

diagnosing_timeouts(Body) ->
    OnTimeout = fun (Error) ->
                        timeout_diag_logger:log_diagnostics(Error),
                        exit(Error)
                end,

    try Body()
    catch
        exit:{timeout, _} = Error ->
            OnTimeout(Error);
        exit:timeout = Error ->
            OnTimeout(Error)
    end.

grab_system_info() ->
    Allocators = [temp_alloc,
                  eheap_alloc,
                  binary_alloc,
                  ets_alloc,
                  driver_alloc,
                  sl_alloc,
                  ll_alloc,
                  fix_alloc,
                  std_alloc,
                  sys_alloc,
                  mseg_alloc],

    Kinds = lists:flatten(
              [allocated_areas,
               allocator,
               alloc_util_allocators,

               [[{allocator, A},
                 {allocator_sizes, A}] || A <- Allocators],

               [{cpu_topology, T} || T <- [defined, detected, used]],

               build_type,
               c_compiler_used,
               check_io,
               compat_rel,
               creation,
               debug_compiled,
               dist,
               dist_buf_busy_limit,
               dist_ctrl,
               driver_version,
               dynamic_trace,
               dynamic_trace_probes,
               ets_limit,
               fullsweep_after,
               garbage_collection,
               heap_sizes,
               heap_type,
               kernel_poll,
               logical_processors,
               logical_processors_available,
               logical_processors_online,
               machine,
               min_heap_size,
               min_bin_vheap_size,
               modified_timing_level,
               multi_scheduling,
               multi_scheduling_blockers,
               otp_release,
               port_count,
               port_limit,
               process_count,
               process_limit,
               scheduler_bind_type,
               scheduler_bindings,
               scheduler_id,
               schedulers,
               schedulers_online,
               smp_support,
               system_version,
               system_architecture,
               threads,
               thread_pool_size,
               trace_control_word,
               update_cpu_info,
               version,
               wordsize]),

    [{K, (catch erlang:system_info(K))} || K <- Kinds].

handle_diag_eval(Req) ->
    case ns_config:read_key_fast(allow_nonlocal_eval, false) of
        true -> ok;
        false -> menelaus_util:ensure_local(Req)
    end,
    Snippet = binary_to_list(mochiweb_request:recv_body(Req)),

    ?log_error("WARNING: /diag/eval:~n~n~s", [Snippet]),

    try misc:eval(Snippet, erl_eval:add_binding('Req', Req, erl_eval:new_bindings())) of
        {value, Value, _} ->
            case Value of
                done ->
                    ok;
                {json, V} ->
                    menelaus_util:reply_json(Req, V, 200);
                _ ->
                    menelaus_util:reply_text(Req, io_lib:format("~p", [Value]), 200)
            end
    catch
        T:E:S ->
            Msg = io_lib:format("/diag/eval failed.~nError: ~p~nBacktrace:~n~p",
                                [{T, E}, S]),
            ?log_error("Server error during processing: ~s", [Msg]),
            menelaus_util:reply_text(Req, Msg, 500)
    end.

handle_diag_master_events(Req) ->
    Params = mochiweb_request:parse_qs(Req),
    case proplists:get_value("o", Params) of
        undefined ->
            do_handle_diag_master_events(Req);
        _ ->
            Body = master_activity_events:format_some_history(
                     master_activity_events_keeper:get_history()),
            menelaus_util:reply_ok(Req, "text/kind-of-json; charset=utf-8", Body)
    end.

do_handle_diag_master_events(Req) ->
    Resp = menelaus_util:reply_ok(Req, "text/kind-of-json; charset=utf-8", chunked),
    Parent = self(),
    Sock = mochiweb_request:get(socket, Req),
    inet:setopts(Sock, [{active, true}]),
    spawn_link(
      fun () ->
              master_activity_events:stream_events(
                fun (Event, _Ignored, Config) ->
                        IOList =
                            master_activity_events:event_to_formatted_iolist(
                              Event,
                              Config),
                        case IOList of
                            [] ->
                                ok;
                            _ ->
                                Parent ! {write_chunk, IOList}
                        end,
                        ok
                end, [])
      end),
    Loop = fun (Loop) ->
                   receive
                       {tcp_closed, _} ->
                           exit(self(), shutdown);
                       {tcp, _, _} ->
                           %% eat & ignore
                           Loop(Loop);
                       {write_chunk, Chunk} ->
                           mochiweb_response:write_chunk(Chunk, Resp),
                           Loop(Loop)
                   end
           end,
    Loop(Loop).


diag_vbucket_accumulate_vbucket_stats(K, V, Dict) ->
    case misc:split_binary_at_char(K, $:) of
        {<<"vb_",VB/binary>>, AttrName} ->
            SubDict = case dict:find(VB, Dict) of
                          error ->
                              dict:new();
                          {ok, X} -> X
                      end,
            dict:store(VB, dict:store(AttrName, V, SubDict), Dict);
        _ ->
            Dict
    end.

diag_vbucket_per_node(BucketName, Node) ->
    {ok, RV1} = ns_memcached:raw_stats(Node, BucketName, <<"vbucket-details">>, fun diag_vbucket_accumulate_vbucket_stats/3, dict:new()),
    {ok, RV2} = ns_memcached:raw_stats(Node, BucketName, <<"checkpoint">>, fun diag_vbucket_accumulate_vbucket_stats/3, RV1),
    RV2.

handle_diag_vbuckets(Req) ->
    Params = mochiweb_request:parse_qs(Req),
    BucketName = proplists:get_value("bucket", Params),
    {ok, BucketConfig} = ns_bucket:get_bucket(BucketName),
    Nodes = ns_node_disco:nodes_actual(),
    RawPerNode = misc:parallel_map(fun (Node) ->
                                           diag_vbucket_per_node(BucketName, Node)
                                   end, Nodes, 30000),
    PerNodeStates = lists:zip(Nodes,
                              [{[{K, {dict:to_list(V)}}
                                 || {K, V} <- dict:to_list(Dict)]}
                               || Dict <- RawPerNode]),
    JSON = {[{name, list_to_binary(BucketName)},
             {bucketMap, proplists:get_value(map, BucketConfig, [])},
             %% {ffMap, proplists:get_value(fastForwardMap, BucketConfig, [])},
             {perNodeStates, {PerNodeStates}}]},
    Hash = integer_to_list(erlang:phash2(JSON)),
    ExtraHeaders = [{"Cache-Control", "must-revalidate"},
                    {"ETag", Hash}],
    case mochiweb_request:get_header_value("if-none-match", Req) of
        Hash ->
            menelaus_util:reply(Req, 304, ExtraHeaders);
        _ ->
            menelaus_util:reply_json(Req, JSON, 200, ExtraHeaders)
    end.

handle_diag_get_password(Req) ->
    menelaus_util:ensure_local(Req),
    menelaus_util:reply_text(Req, ns_config_auth:get_password(special), 200).

handle_diag_encryption_at_rest(Req) ->
    menelaus_util:reply_text(Req, cb_cluster_secrets:diag_info(), 200).

trace_memory(Format) ->
    trace_memory(Format, []).

trace_memory(Format, Params) ->
    {memory, PMem} = erlang:process_info(self(), memory),
    ?log_debug(Format ++ " Process Memory: ~p, Erlang Memory: ~p",
               Params ++ [PMem, erlang:memory()]).


-ifdef(TEST).
split_incremental(Binary, Separator, NumMatches) ->
    R = split_fold_incremental(Binary, Separator, NumMatches,
                               fun (Part, Acc) ->
                                       [Part | Acc]
                               end, []),
    lists:reverse(R).

split_incremental_test() ->
    String1 = <<"abc\n\ntext">>,
    String2 = <<"abc\n\ntext\n">>,
    String3 = <<"\nabc\n\ntext\n">>,
    Split1a = binary:split(String1, <<"\n">>, [global]),
    Split2a = binary:split(String2, <<"\n">>, [global]),
    Split3a = binary:split(String3, <<"\n">>, [global]),
    ?assertEqual(Split1a, split_incremental(String1, <<"\n">>, 100)),
    ?assertEqual(Split2a, split_incremental(String2, <<"\n">>, 100)),
    ?assertEqual(Split3a, split_incremental(String3, <<"\n">>, 100)),
    ?assertEqual([<<"abc">>, <<>>], split_incremental(String1, <<"\n">>, 2)).
-endif.

%% Trim a deeply nested term to a smaller one. Each nested term amounts to one
%% unit of size. Binaries are treated specially though: the length of the
%% binary is its size.
trim_term(Term, MaxSize) ->
    {R, _} = generic:maybe_transform(
               fun (_, 0) ->
                       {stop, '...', 0};
                   (T, S) when is_binary(T) ->
                       Size = byte_size(T),
                       case Size > S of
                           true ->
                               Part = binary:part(T, 0, S),
                               {stop, <<Part/binary, "...">>, 0};
                           false ->
                               {stop, T, S - Size}
                       end;
                   (T, S) ->
                       {continue, T, S - 1}
               end, MaxSize, Term),
    R.

-ifdef(TEST).
trim_term_test() ->
    [1, 2 | '...'] = trim_term([1, 2, 3, 4, 5, 6, 7], 4),
    [<<"123...">> | '...'] = trim_term([<<"12345">>, 6, 7], 4),
    [<<"123">> | '...'] = trim_term([<<"123">>, 4, 5], 4),
    {1, 2, 3, '...', '...'} = trim_term({1, 2, 3, 4, 5}, 4),

    %% Maps are unordered, so we have to use a singleton map here. Otherwise
    %% we don't know which part of the map is supposed to get trimmed.
    #{1 := '...'} = trim_term(#{1 => 2}, 2).
-endif.
