%% @copyright 2021-Present Couchbase, Inc.
%%
%% Use of this software is governed by the Business Source License included in
%% the file licenses/BSL-Couchbase.txt.  As of the Change Date specified in that
%% file, in accordance with the Business Source License, use of this software
%% will be governed by the Apache License, Version 2.0, included in the file
%% licenses/APL2.txt.
%%
-module(event_log_server).

-behaviour(gossip_replicator).

-include_lib("ns_common/include/cut.hrl").

-ifdef(TEST).
-include_lib("eunit/include/eunit.hrl").
-endif.

-define(DEFAULT_EVENTS_SIZE, 10000).

%% Percentage value used to determine the max length of pending_list.
%% Derived based on the max_events configured.
-define(PENDING_LEN_PERCENT, 10).

% The server_name used by gossip_replicator to register this server.
-define(SERVER, ?MODULE).

-define(METADATA_SEQNUM, seq_num).

%% Max time to hold onto recently received event log UUID's to help with
%% deduplication.
-define(DEDUP_GC_TIME, 60000). %% 60 secs in millsecs

%% API
-export([start_link/0]).

-export([log/3, recent/0, delete_log/0, build_events_json/3,
         recent/1, reencrypt_data_on_disk/0, get_in_use_deks/0]).

%% exports for gossip_replicator.
-export([init/1,
         handle_add_log/3,
         add_local_node_metadata/2,
         strip_local_node_metadata/1,
         merge_remote_logs/3,
         merge_pending_list/3,
         modify_recent/2,
         handle_notify/1,
         handle_info/3]).

-include("ns_common.hrl").

-record(log_entry, {timestamp   :: string(),
                    uuid        :: binary(),
                    event       :: term()}).

-record(event_log_state, {seq_num,
                          dedup_list = []}).

start_link() ->
    Config = ns_config:get(),
    FileName = ns_config:search_node_prop(Config, event_log, filename),
    MaxEvents = get_event_logs_limit(),
    MaxPending = compute_max_pending_len(MaxEvents),
    gossip_replicator:start_link(?SERVER, [?MODULE, FileName, MaxPending,
                                           MaxEvents]).

ns_config_event_handler({event_logs_limit, MaxEvents}) ->
    MaxPending = compute_max_pending_len(MaxEvents),
    gossip_replicator:change_config(?SERVER, MaxEvents, MaxPending);
ns_config_event_handler(_KV) ->
    ok.

get_event_logs_limit() ->
   ns_config:read_key_fast(event_logs_limit, ?DEFAULT_EVENTS_SIZE).

init(Recent) ->
    send_dedup_gc_msg(),
    ns_pubsub:subscribe_link(ns_config_events,
                             fun ns_config_event_handler/1),
    %% Retrieve the max seq_num from previous logs if any.
    SeqNum = lists:foldl(fun(Log, MaxS) ->
                           max(MaxS, get_seqnum(Log))
                         end, 0, Recent),
    case SeqNum of
        0 ->
            #event_log_state{seq_num = 0};
        _ ->
            %% Notify any existing menelaus_web streaming processes of the
            %% current max seq_num.
            handle_notify(#event_log_state{seq_num = SeqNum})
    end.

handle_add_log(Log, #event_log_state{dedup_list = DedupList} = State,
               ReplicateFun) ->
    %% Check if the log is already present in dedup list and accordingly
    %% add the log.
    %% NOTE: It can happen that a duplicate log's UUID is removed from the
    %% dedup_list, dedup of such logs will happen when merge_pending_list is
    %% called.

    LogUUID = Log#log_entry.uuid,
    IsDupFun = fun ({Id, _}) ->
                       case Id of
                           LogUUID -> true;
                           _ -> false
                       end
               end,

    case lists:any(IsDupFun, DedupList) of
        true ->
            State;
        false ->
            ReplicateFun(Log),
            State#event_log_state{
              dedup_list = [{LogUUID, erlang:timestamp()} | DedupList]}
    end.

add_local_node_metadata(Logs, #event_log_state{seq_num = SeqNum} = State) ->
    Len = length(Logs),
    MetaLogs = lists:zipwith(fun(C, Log) ->
                               add_seqnum(C, Log)
                             end, lists:seq(SeqNum + 1, SeqNum + Len),
                             Logs),
    {MetaLogs, State#event_log_state{seq_num = SeqNum + Len}}.

strip_local_node_metadata(Logs) ->
    strip_seqnum_in_logs(Logs).

modify_recent(Recent, RecentMax) ->
    lists:sublist(Recent, RecentMax).

%% Logs in Pending list are ordered in the sequence they are received by the
%% gossip_replictor gen_server and therefore have to sorted by order_entries/2
%% before being merged with the Recent Logs.
%%
%% Note: Pending list can have duplicate logs. Consider the following sequence
%% of events:
%%
%% 1) A log with UUID1 was added. After a minute the log is removed from the
%%    dedup_list via handle_info(dedup_gc, ...).
%% 2) log with UUID1 is added again (due to a client re-try after more that 60
%%    secs, highly unlikely, but can still happen).
%% 3) Flush pending list wasn't called between 1 and 2.
%%
%% Pending list now has duplicate entries (2 logs with UUID1).
%% Therefore as an extra caution sort 'Pending' list using lists:usort/2.
merge_pending_list(Recent, Pending, MaxLen) ->
    lists:sublist(
      lists:umerge(fun order_entries/2,
                   Recent,
                   lists:usort(fun order_entries/2, Pending)),
                   MaxLen).

%% NOTE: Both RemoteLogs and LocalLogs are already sorted by order_entries/2.
merge_remote_logs(LocalLogs, RemoteLogs, MaxLen) ->
    lists:sublist(lists:umerge(fun order_entries/2,
                               RemoteLogs,
                               LocalLogs),
                  MaxLen).

handle_notify(State) ->
    SeqNum = State#event_log_state.seq_num,
    gen_event:notify(event_log_events, {seq_num, SeqNum}),
    State.

handle_info(dedup_gc, #event_log_state{dedup_list = DedupList0} = State,
            _ReplicateFun) ->
    send_dedup_gc_msg(),
    Now = erlang:timestamp(),
    DedupList = lists:filter(fun ({_UUID, Time}) ->
                                      timer:now_diff(Now, Time) / 1000
                                           < ?DEDUP_GC_TIME
                             end, DedupList0),
    State#event_log_state{dedup_list = DedupList};
handle_info(_Info, State, _ReplicatorFun) ->
    State.

%%--------------------------------------------------------------------
%%% Internal functions
%%--------------------------------------------------------------------
%%

send_dedup_gc_msg() ->
    erlang:send_after(?DEDUP_GC_TIME, self(), dedup_gc).

order_entries([{?METADATA_SEQNUM, _} | #log_entry{timestamp = TimestampA,
                                                  uuid = UUIDA}],
              [{?METADATA_SEQNUM, _} | #log_entry{timestamp = TimestampB,
                                                  uuid = UUIDB}]) ->
    {TimestampA, UUIDA} >= {TimestampB, UUIDB};
order_entries(#log_entry{timestamp = TimestampA,
                         uuid = UUIDA},
              #log_entry{timestamp = TimestampB,
                         uuid = UUIDB}) ->
    {TimestampA, UUIDA} >= {TimestampB, UUIDB}.

strip_seqnum_in_logs(Logs) ->
    [strip_seqnum(Log) || Log <- Logs].

strip_seqnum([{?METADATA_SEQNUM, _} | Log]) ->
    Log;
strip_seqnum(Log) ->
    Log.

get_seqnum([{?METADATA_SEQNUM, SeqNum} | _]) ->
    SeqNum.

add_seqnum(Counter, Log) ->
    [{?METADATA_SEQNUM, Counter} | Log].

get_event(#log_entry{event = Event}) ->
    Event.

compute_max_pending_len(MaxEventsLen) ->
    (?PENDING_LEN_PERCENT * MaxEventsLen) div 100.

%% APIS

-spec(log(string(), binary(), term()) -> ok).
log(Timestamp, Id, Event) ->
    Log = #log_entry{timestamp = Timestamp, uuid = Id, event = Event},
    gossip_replicator:add_log(?SERVER, Log).

delete_log() ->
    gossip_replicator:delete_logs(event_log).

reencrypt_data_on_disk() ->
    gossip_replicator:reencrypt_data_on_disk(?SERVER).

get_in_use_deks() ->
    gossip_replicator:get_in_use_deks(?SERVER).

-spec recent() -> list(#log_entry{}).
recent() ->
    gossip_replicator:recent(?SERVER).

recent(undefined) ->
    recent(0);
recent(StartSeqNum) ->
    {MaxSeqNum, Logs} =
      lists:foldl(
        fun(Log, {M, AccIn}) ->
             case get_seqnum(Log) of
                 X when X > StartSeqNum ->
                     %% Accumulate the max seq_num from the list of
                     %% logs.
                     %% The streaming API consuming these logs will
                     %% use this as marker indicating uptil where the
                     %% logs have been consumed.
                     {max(X,M), [Log | AccIn]};
                 _ ->
                     {M, AccIn}
             end
         end, {StartSeqNum, []}, recent()),
    {MaxSeqNum, [{get_event(strip_seqnum(L))} || L <- Logs]}.

-spec build_events_json(SinceTime :: undefined | string(),
                        Limit :: -1 | non_neg_integer(),
                        %% The content of the filters is opaque to this
                        %% module which results in using term()
                        Filters :: [] | [{term(), term()}]) ->
        [term()].
build_events_json(_SinceTime, 0, _Filters) ->
    [];
build_events_json(SinceTime, Limit, Filters) ->
    Logs = recent(),
    build_events_json_inner(Logs, SinceTime, Limit, Filters).

build_events_json_inner(Logs0, SinceTime, Limit, Filters) ->
    Logs1 =
        lists:filter(
          fun (Log) ->
                  case SinceTime of
                      undefined ->
                          matches_filters(Log, Filters);
                      _ ->
                          case time_in_range(Log, SinceTime) of
                              false ->
                                  false;
                              true ->
                                  matches_filters(Log, Filters)
                          end
                  end
          end, Logs0),
    Logs =
        case Limit of
            -1 ->
                Logs1;
            L ->
                case SinceTime of
                    undefined ->
                        %% If SinceTime is 'undefined', return the most recent
                        %% "Limit" number of logs.
                        lists:sublist(Logs1, L);
                    _ ->
                        %% SinceTime was specified, return the specified number
                        %% of events since SinceTime (which may not include
                        %% most recent events).
                        misc:tail_of_length(Logs1, L)
                end
        end,

    %% Reverse the logs since they are stored in the descending order of time.
    [{get_event(strip_seqnum(Log))} || Log <- lists:reverse(Logs)].

time_in_range(Log, SinceTime) ->
    Log0 = strip_seqnum(Log),
    TStamp = Log0#log_entry.timestamp,
    TStamp >= SinceTime.

matches_filters(_Log, []) ->
    true;
matches_filters(Log, Filters) ->
    Event = get_event(strip_seqnum(Log)),
    lists:all(
      fun ({Key, Value}) ->
              event_matches_filter(Event, Key, Value)
      end, Filters).

%% Some events are constructed with binaries and some with atoms so we have
%% to handle all the cases.
%%
%% Have to handle case such as:
%%     {<<"component">>,<<"analytics">>},
%% vs
%%     {component,data},
%%
%% Using a filter:
%%     [{component,"ns_server"},{severity,"info"},{event_id,1}]
%%
%% To do this we do the comparisons using binaries
event_matches_filter(Event, Key, Value) ->
    KeyBin = misc:convert_to_binary(Key),
    ValueBin = misc:convert_to_binary(Value),
    lists:any(
      fun ({K, V}) ->
              KBin = misc:convert_to_binary(K),
              case KeyBin =:= KBin of
                  true ->
                      VBin = misc:convert_to_binary(V),
                      ValueBin =:= VBin;
                  false ->
                      false
              end
      end, Event).


-ifdef(TEST).
order_entries_test() ->
    A = #log_entry{timestamp="2021-08-23T05:24:32.585Z",
                   uuid = "f493e1e4-4fe2-4cc8-87b1-10e615510f76"},
    B = #log_entry{timestamp="2021-08-23T05:24:09.625Z",
                   uuid = "7c5e1975-c8ff-4d23-a672-46a114e4a963"},
    [A, B] = lists:sort(fun order_entries/2, [A, B]),
    [A, B] = lists:sort(fun order_entries/2, [B, A]).

merge_remote_logs_test() ->
    A = #log_entry{timestamp = "2021-08-23T05:24:32.585Z",
                   uuid = "f493e1e4-4fe2-4cc8-87b1-10e615510f76"},
    B = #log_entry{timestamp = "2021-08-23T05:24:32.585Z",
                   uuid = "7c5e1975-c8ff-4d23-a672-46a114e4a963"},
    C = #log_entry{timestamp = "2021-08-23T05:24:30.585Z",
                   uuid = "90d0ee97-5e19-471d-9d20-2372d54f0712"},

    %% Assert the expected sorting order.
    Logs = [A, B, C] = lists:sort(fun order_entries/2, [A, B, C]),

    [A, B, C] = merge_remote_logs(Logs, [], 5),
    [A, B, C] = merge_remote_logs([], Logs, 5),
    [A, B, C] = merge_remote_logs(Logs, Logs, 5),
    [A, B, C] = merge_remote_logs(Logs, [A], 5),
    [A, B, C] = merge_remote_logs([A], Logs, 5),
    [A, B, C] = merge_remote_logs(Logs, [B], 5),
    [A, B, C] = merge_remote_logs([B], Logs, 5),
    [A, B, C] = merge_remote_logs(Logs, [C], 5),
    [A, B, C] = merge_remote_logs([C], Logs, 5),

    [A, B, C] = merge_remote_logs(Logs, [B, C], 5),
    [A, B, C] = merge_remote_logs([B, C], Logs, 5),

    [A, B, C] = merge_remote_logs(Logs, [A, C], 5),
    [A, B, C] = merge_remote_logs([A, C], Logs, 5),

    [A, B, C] = merge_remote_logs(Logs, [A, B], 5),
    [A, B, C] = merge_remote_logs([A, B], Logs, 5),
    [A, B] = merge_remote_logs([A, B], Logs, 2),

    D = #log_entry{timestamp = "2021-08-23T05:24:40.585Z",
                   uuid = "c42f0f48-580c-45aa-bd29-56f6a6432469"},

    [D, A, B, C] = merge_remote_logs(Logs, [D], 5),
    [D, A, B, C] = merge_remote_logs([D], Logs, 5),
    [D, A, B, C] = merge_remote_logs([D, B], Logs, 5),
    [D, A, B, C] = merge_remote_logs(Logs, [D, B], 5).

event_filter_info_test() ->
    Events =
        [[{seq_num,19}|
          {log_entry,"2024-07-03T19:22:07.081Z",
           <<"92c5a173-bb80-46db-b894-837b928cc082">>,
           [{timestamp,<<"2024-07-03T19:22:07.081Z">>},
            {event_id,1},
            {component,ns_server},
            {severity,info},
            {uuid,<<"92c5a173-bb80-46db-b894-837b928cc082">>}]}],
         [{seq_num,18}|
          {log_entry,"2024-07-03T19:22:07.072Z",
           <<"ba8aca40-1a45-4ac0-b23f-e8ee33645b55">>,
           [{timestamp,<<"2024-07-03T19:22:07.072Z">>},
            {event_id,1},
            {component,data},
            {severity,info},
            {uuid,<<"ba8aca40-1a45-4ac0-b23f-e8ee33645b55">>}]}],
         [{seq_num,15}|
          {log_entry,"2024-07-03T19:22:06.778Z",
           <<"c28bd440-d89b-4e72-919f-77223661eb61">>,
           [{timestamp,<<"2024-07-03T19:22:06.778Z">>},
            {event_id,1},
            {component,ns_server},
            {severity,info},
            {uuid,<<"c28bd440-d89b-4e72-919f-77223661eb61">>}]}],
         [{seq_num,14}|
          {log_entry,"2024-07-03T19:22:06.489Z",
           <<"62ffec3d-fea6-4a32-9f9b-6a8bf5ee5b80">>,
           [{timestamp,<<"2024-07-03T19:22:06.489Z">>},
            {event_id,1},
            {component,eventing},
            {severity,info},
            {uuid,<<"62ffec3d-fea6-4a32-9f9b-6a8bf5ee5b80">>}]}],
         [{seq_num,13}|
          {log_entry,"2024-07-03T19:22:06.325Z",
           <<"8bebbddf-1ab3-41c8-b414-71fc2d93cb4a">>,
           [{timestamp,<<"2024-07-03T19:22:06.325Z">>},
            {event_id,18},
            {component,ns_server},
            {severity,info},
            {uuid,<<"8bebbddf-1ab3-41c8-b414-71fc2d93cb4a">>}]}]],

    Logs = build_events_json_inner(Events, undefined, -1,
                                   [{component, ns_server}]),
    ?assertEqual(3, length(Logs)),
    Logs1 = build_events_json_inner(Events, undefined, -1,
                                    [{component, eventing}]),
    ?assertEqual(1, length(Logs1)),
    Logs2 = build_events_json_inner(Events, undefined, -1,
                                    [{component, ns_server},
                                     {event_id, 18}]),
    ?assertEqual(1, length(Logs2)),
    Logs3 = build_events_json_inner(Events, "2024-07-03T19:22:06Z", -1, []),
    ?assertEqual(2, length(Logs3)),
    Logs4 = build_events_json_inner(Events, "2024-07-03T19:22:06Z", 1, []),
    ?assertEqual(1, length(Logs4)).

-endif.
