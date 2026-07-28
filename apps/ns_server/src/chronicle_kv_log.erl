%% @author Couchbase <info@couchbase.com>
%% @copyright 2021-Present Couchbase, Inc.
%%
%% Use of this software is governed by the Business Source License included in
%% the file licenses/BSL-Couchbase.txt.  As of the Change Date specified in that
%% file, in accordance with the Business Source License, use of this software
%% will be governed by the Apache License, Version 2.0, included in the file
%% licenses/APL2.txt.
%%
-module(chronicle_kv_log).

-behaviour(gen_server2).

-export([sanitize/2]).
-export([sanitize_snapshot/2, sanitize_log/2, masked/0, sanitize_value/1]).

%% gen_server callbacks:
-export([start_link/0, init/1, handle_info/2]).

-include("ns_common.hrl").
-include("cb_cluster_secrets.hrl").
-include("jwt.hrl").

-ifdef(TEST).
-include_lib("eunit/include/eunit.hrl").
-endif.

%% Values above this many pending messages are dropped instead of logged.
%% Low because this counts messages, not bytes, and one value can be huge: a
%% 10k collection manifest is over 4MB (MB-72708).
-define(MAX_QUEUE_LEN, ?get_param(max_queue_len, 100)).

%% Marks messages counted by send_message/3, so inc and dec cannot drift.
-define(COUNTED(Msg), {'$counted', Msg}).

-record(state, {queue_len_counter :: counters:counters_ref(),
                %% the limit in force, which the setting may no longer match
                max_queue_len :: non_neg_integer(),
                values = #{} :: #{term() => term()}}).

start_link() ->
    gen_server:start_link({local, ?MODULE}, ?MODULE, [],
                          [{hibernate_after,
                            ?get_param(hibernate_after, 10000)}]).

init([]) ->
    process_flag(message_queue_data, off_heap),
    Self = self(),
    QueueLenCounter = counters:new(1, []),
    MaxQueueLen = ?MAX_QUEUE_LEN,
    ns_pubsub:subscribe_link(
      chronicle_compat_events:kv_event_manager(),
      fun ({{key, K}, R, {updated, V}}) ->
              Msg = case counters:get(QueueLenCounter, 1) > MaxQueueLen of
                        true ->
                            {{key, K}, R, value_not_logged};
                        false ->
                            {{key, K}, R, {updated, fun() -> V end}}
                    end,
              send_message(Self, QueueLenCounter, Msg);
          ({_, _, _} = Evt) ->
              send_message(Self, QueueLenCounter, Evt);
          (_) ->
              ok
      end),
    {ok, #state{queue_len_counter = QueueLenCounter,
                max_queue_len = MaxQueueLen}}.

%% Counted rather than measured: this runs in the event manager process, and
%% process_info/2 on us would be delivered as a signal and stall it.
send_message(Pid, QueueLenCounter, Msg) ->
    counters:add(QueueLenCounter, 1, 1),
    Pid ! ?COUNTED(Msg).

handle_info(?COUNTED(Msg),
            #state{queue_len_counter = QueueLenCounter} = State) ->
    counters:sub(QueueLenCounter, 1, 1),
    do_handle_info(Msg, State);
handle_info(Msg, State) ->
    do_handle_info(Msg, State).

do_handle_info({{key, K}, R, {updated, VFun}},
               #state{values = Values} = State) ->
    {noreply, State#state{values = log(K, VFun, R, Values)}};
do_handle_info({{key, K}, R, value_not_logged},
               #state{max_queue_len = MaxQueueLen, values = Values} = State) ->
    ?log_debug("update (key: ~p, rev: ~p), value not logged: more than ~p "
               "updates behind", [K, R, MaxQueueLen]),
    %% forget it: it is no longer the previous value to diff against
    {noreply, State#state{values = maps:remove(K, Values)}};
do_handle_info({{key, K}, R, deleted}, #state{values = Values} = State) ->
    ?log_debug("delete (key: ~p, rev: ~p)", [K, R]),
    {noreply, State#state{values = maps:remove(K, Values)}};
do_handle_info(Info, State) ->
    ?log_warning("Unexpected message(~p)", [Info]),
    {noreply, State}.

calculate_diff(K, V, Diff, Values) ->
    {case maps:find(K, Values) of
         {ok, Old} ->
             Diff(V, Old);
         error ->
             V
     end, maps:put(K, V, Values)}.

log(K, VFun, R, Values) ->
    {NewV, NewValues} = prepare_value(K, VFun, Values),
    VB = list_to_binary(io_lib:print(NewV, 0, 80, 100)),
    ?log_debug("update (key: ~p, rev: ~p)~n~s", [K, R, VB]),
    NewValues.


sanitize(root_cert_and_pkey, _V) ->
    masked();
sanitize(?CHRONICLE_SECRETS_KEY, V) ->
    cb_cluster_secrets:sanitize_chronicle_cfg(V);
sanitize(jwt_settings, V) ->
    menelaus_web_jwt:sanitize_chronicle_cfg(V);
sanitize(?JWT_SIGNING_KEYS_KEY, _V) ->
    masked();
sanitize({credentials, _}, V) ->
    menelaus_web_credentials:sanitize_chronicle_cfg(V);
sanitize({leaf, _}, {?METAKV2_SENSITIVE, _V}) ->
    masked();
sanitize(_, V) ->
    V.

%% Credentials like passwords, keys, shared secrets, etc. are masked.
masked() ->
    <<"********">>.

%% MB-65857: Personally identifiable information (PII), such as user and group
%% identifiers, is obfuscated using hashing.
%% TODO: Implement a unique, random salt for each log collection to hash and
%% obfuscate values. This ensures that the same value remains trackable within
%% a single log collection while preventing correlation across different log
%% collections.
sanitize_value(V) ->
    {sanitized, base64:encode(crypto:hash(sha256, term_to_binary(V)))}.

sanitize_snapshot(Mod, ModState) ->
    case Mod of
        chronicle_kv ->
            chronicle_kv:sanitize_state(fun sanitize/2, ModState);
        _ ->
            ModState
    end.

sanitize_log(Name, Command) ->
    case Name of
        kv ->
            chronicle_kv:sanitize_command(fun sanitize/2, Command);
        metakv ->
            chronicle_kv:sanitize_command(fun sanitize/2, Command);
        _ ->
            Command
    end.

prepare_value(K, VFun, Values) ->
    V = VFun(),
    case {ns_bucket:sub_key_match(K), K} of
        {{true, _Bucket, props}, _} ->
            calculate_diff(K, V, fun ns_config_log:compute_bucket_diff/2,
                           Values);
        {{true, _Bucket, collections}, _} ->
            calculate_diff(K, V, fun collections:diff_manifests/2, Values);
        {false, role_definitions} ->
            calculate_diff(K, V, fun menelaus_roles:diff_roles/2, Values);
        _ ->
            {sanitize(K, V), Values}
    end.

-ifdef(TEST).

%% The metakv2 sensitive tag has to be masked wherever a chronicle value can
%% reach a log or a dump. Both cbcollect_info chronicle tasks route through
%% sanitize_snapshot/2 and sanitize_log/2, which reach sanitize/2 below.
metakv2_sensitive_test() ->
    Key = {leaf, [<<"key">>, <<"bucket">>, <<"backup">>]},
    Secret = <<"an encryption key">>,

    ?assertEqual(masked(), sanitize(Key, {?METAKV2_SENSITIVE, Secret})),

    %% leaves that were not created sensitive keep logging their value, and
    %% directory entries are untouched
    ?assertEqual(Secret, sanitize(Key, Secret)),
    ?assertEqual([{leaf, <<"key">>}],
                 sanitize({dir, [<<"bucket">>, <<"backup">>]},
                          [{leaf, <<"key">>}])).

%% The metakv rsm is dumped by cbcollect_info alongside the kv one, so it has
%% to be routed through the sanitizer too. Metakv2 writes reach the log as a
%% transaction, which is the shape asserted here.
sanitize_log_covers_metakv_test() ->
    Key = {leaf, [<<"key">>, <<"bucket">>, <<"backup">>]},
    Secret = <<"an encryption key">>,
    Command = {transaction, [], [{set, Key, {?METAKV2_SENSITIVE, Secret}}]},
    Masked = {transaction, [], [{set, Key, masked()}]},

    ?assertEqual(Masked, sanitize_log(metakv, Command)),

    %% an rsm that is not dumped is left alone
    ?assertEqual(Command, sanitize_log(some_other_rsm, Command)).

%% The snapshot task reaches the same sanitizer by rsm module rather than by
%% name, and metakv is a chronicle_kv rsm.
sanitize_snapshot_covers_metakv_test() ->
    Key = {leaf, [<<"key">>, <<"bucket">>, <<"backup">>]},
    Secret = <<"an encryption key">>,
    Rev = {<<"history">>, 1},

    ?assertEqual(#{Key => {masked(), Rev}},
                 sanitize_snapshot(chronicle_kv,
                                   #{Key => {{?METAKV2_SENSITIVE, Secret},
                                             Rev}})).

-endif.
