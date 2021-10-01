%% @copyright 2021-Present Couchbase, Inc.
%%
%% Use of this software is governed by the Business Source License included
%% in the file licenses/BSL-Couchbase.txt.  As of the Change Date specified
%% in that file, in accordance with the Business Source License, use of this
%% software will be governed by the Apache License, Version 2.0, included in
%% the file licenses/APL2.txt.
%%
-module(event_log_server).

-behaviour(gossip_replicator).

-include("cut.hrl").

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

%% API
-export([start_link/0]).

-export([log/3, recent/0, delete_log/0, build_events_json/2,
         recent/1]).

%% exports for gossip_replicator.
-export([init/1,
         handle_add_log/4,
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

-record(event_log_state, {seq_num}).

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

handle_add_log(Log, State, Pending, ReplicateFun) ->
    %% Check if the log is already present in pending list and accordingly
    %% add the log.
    %% NOTE: It can happen the duplicate log is flushed from the pending list.
    %% Dedup against logs present in the gossip_replicator's unique_recent
    %% list will happen when merge_pending_list is called.

    Id = Log#log_entry.uuid,
    Filter = fun (L0) ->
               L = strip_seqnum(L0),
               case L#log_entry.uuid of
                   Id -> true;
                   _ -> false
               end
             end,

    case lists:any(Filter, Pending) of
        true ->
            ok;
        false ->
            ReplicateFun(Log)
    end,
    State.

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
merge_pending_list(Recent, Pending, MaxLen) ->
    lists:sublist(
      lists:umerge(fun order_entries/2,
                   Recent,
                   lists:sort(fun order_entries/2, Pending)),
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

handle_info(_Info, State, _ReplicatorFun) ->
    State.

%%--------------------------------------------------------------------
%%% Internal functions
%%--------------------------------------------------------------------
%%

order_entries([{?METADATA_SEQNUM, _} | A = #log_entry{}],
              [{?METADATA_SEQNUM, _} | B = #log_entry{}]) ->
    A#log_entry.timestamp >= B#log_entry.timestamp;
order_entries(A = #log_entry{}, B = #log_entry{}) ->
    A#log_entry.timestamp >= B#log_entry.timestamp.

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
    {MaxSeqNum, [{struct, get_event(strip_seqnum(L))} || L <- Logs]}.

build_events_json(MinTStamp, Limit) ->
    Logs0 = recent(),
    Logs = case {MinTStamp, Limit} of
               {_, 0} ->
                   [];
               {undefined, -1} ->
                   Logs0;
               {undefined, L} ->
                   misc:tail_of_length(Logs0, L);
               _ ->
                   misc:tail_of_length(
                     lists:filter(fun (Log0) ->
                                    Log = strip_seqnum(Log0),
                                    TStamp = Log#log_entry.timestamp,
                                    if
                                        TStamp >= MinTStamp ->
                                            true;
                                        true ->
                                            false
                                    end
                                  end, Logs0), Limit)
           end,
    %% Reverse the logs since they are stored in the descending order of time.
    Events = [{struct, get_event(strip_seqnum(Log))} ||
              Log <- lists:reverse(Logs)],
    {struct, [{events, Events}]}.

-ifdef(TEST).
order_entries_test() ->
    A = #log_entry{timestamp="2021-08-23T05:24:32.585Z"},
    B = #log_entry{timestamp="2021-08-23T05:24:09.625Z"},
    [A,B] = lists:sort(fun order_entries/2, [A,B]),
    [A,B] = lists:sort(fun order_entries/2, [B,A]).
-endif.
