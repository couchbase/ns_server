%% @author Couchbase <info@couchbase.com>
%% @copyright 2020 Couchbase, Inc.
%%
%% Licensed under the Apache License, Version 2.0 (the "License");
%% you may not use this file except in compliance with the License.
%% You may obtain a copy of the License at
%%
%%      http://www.apache.org/licenses/LICENSE-2.0
%%
%% Unless required by applicable law or agreed to in writing, software
%% distributed under the License is distributed on an "AS IS" BASIS,
%% WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
%% See the License for the specific language governing permissions and
%% limitations under the License.
%%
%% @doc helpers for backward compatible calls to chronicle/ns_config
%%

-module(chronicle_compat).

-include("ns_common.hrl").
-include("cut.hrl").

-export([backend/0,
         enabled/0,
         get/2,
         get/3,
         set/2,
         set_multiple/1,
         transaction/2,
         transaction/3,
         ro_txn/1,
         txn_get/2,
         txn_get_many/2,
         get_snapshot/1,
         get_snapshot/2,
         get_snapshot_with_revision/1,
         subscribe_to_key_change/1,
         subscribe_to_key_change/2,
         notify_if_key_changes/2,
         start_refresh_worker/2,
         pull/0,
         pull/1,
         config_sync/2,
         config_sync/3,
         node_keys/1,
         service_keys/1,
         upgrade/1]).

%% RPC from another nodes
-export([do_pull/1]).

-define(UPGRADE_PULL_TIMEOUT,
        ?get_timeout(upgrade_pull, 60000)).

backend() ->
    case enabled() of
        true ->
            chronicle;
        false ->
            ns_config
    end.

enabled() ->
    cluster_compat_mode:is_cluster_70().

get(Key, Opts) ->
    get(ns_config:latest(), Key, Opts).

get(direct, Key, Opts) ->
    get(ns_config:latest(), Key, Opts);
get(Config, Key, #{required := true}) ->
    {ok, Value} = get(Config, Key, #{}),
    Value;
get(Config, Key, #{default := Default}) ->
    case get(Config, Key, #{}) of
        {error, not_found} ->
            Default;
        {ok, Value} ->
            Value
    end;
get(Snapshot, Key, #{}) when is_map(Snapshot) ->
    case maps:find(Key, Snapshot) of
        {ok, {V, _R}} ->
            {ok, V};
        error ->
            {error, not_found}
    end;
get(Config, Key, #{}) ->
    case backend() of
        chronicle ->
            case ns_node_disco:couchdb_node() =:= node() of
                true ->
                    case ns_couchdb_chronicle_dup:lookup(Key) of
                        [{Key, {Value, _Rev}}] ->
                            {ok, Value};
                        [] ->
                            {error, not_found}
                    end;
                false ->
                    case chronicle_kv:get(kv, Key, #{}) of
                        {ok, {V, _R}} ->
                            {ok, V};
                        Error ->
                            Error
                    end
            end;
        ns_config ->
            case ns_config:search(Config, Key) of
                {value, Value} ->
                    {ok, Value};
                false ->
                    {error, not_found}
            end
    end.

set(Key, Value) ->
    case backend() of
        chronicle ->
            case chronicle_kv:set(kv, Key, Value) of
                {ok, _} ->
                    ok;
                Error ->
                    Error
            end;
        ns_config ->
            ns_config:set(Key, Value),
            ok
    end.

set_multiple(List) ->
    case backend() of
        chronicle ->
            Fun = fun (_) -> {commit, [{set, K, V} || {K, V} <- List]} end,
            case chronicle_kv:transaction(kv, [], Fun, #{}) of
                {ok, _} ->
                    ok;
                Error ->
                    Error
            end;
        ns_config ->
            ns_config:set(List)
    end.

transaction(Keys, Fun) ->
    transaction(backend(), Keys, Fun).

transaction(chronicle, Keys, Fun) ->
    chronicle_kv:transaction(kv, Keys, Fun, #{});

transaction(ns_config, Keys, Fun) ->
    TXNRV =
        ns_config:run_txn(
          fun (Cfg, SetFn) ->
                  Snapshot = txn_get_many(Keys, {ns_config, Cfg}),
                  BuildCommit =
                      lists:foldl(
                        fun ({set, K, V}, Acc) -> SetFn(K, V, Acc) end,
                        Cfg, _),
                  case Fun(Snapshot) of
                      {abort, _} = Abort ->
                          Abort;
                      {commit, Sets, Extra} ->
                          {commit, BuildCommit(Sets), Extra};
                      {commit, Sets} ->
                          {commit, BuildCommit(Sets)}
                  end
          end),
    case TXNRV of
        {commit, _} ->
            {ok, no_rev};
        {commit, _, Extra} ->
            {ok, no_rev, Extra};
        {abort, Error} ->
            Error;
        retry_needed ->
            erlang:error(exceeded_retries)
    end.

ro_txn(Body) ->
    ro_txn(Body, #{}).

ro_txn(Body, Opts) ->
    Type =
        case {backend(), ns_node_disco:couchdb_node() == node()} of
            {chronicle, true} ->
                couchdb;
            {Backend, _} ->
                Backend
        end,
    ro_txn(Type, Body, Opts).

ro_txn(chronicle, Body, Opts) ->
    chronicle_kv:ro_txn(kv, ?cut(Body({chronicle, _})), Opts);
ro_txn(ns_config, Body, _Opts) ->
    {ok, {Body({ns_config, ns_config:get()}), no_rev}};
ro_txn(couchdb, Body, #{}) ->
    {ok, {ns_couchdb_chronicle_dup:ro_txn(?cut(Body({couchdb, _}))), no_rev}}.

txn_get(K, {chronicle, Txn}) ->
    chronicle_kv:txn_get(K, Txn);
txn_get(K, {ns_config, Config}) ->
    case ns_config:search(Config, K) of
        {value, V} ->
            {ok, {V, no_rev}};
        false ->
            {error, not_found}
    end;
txn_get(K, {couchdb, TxnGet}) ->
    TxnGet(K).

txn_get_many(Keys, {chronicle, Txn}) ->
    chronicle_kv:txn_get_many(Keys, Txn);
txn_get_many(Keys, Txn) ->
    lists:foldl(
      fun (K, Acc) ->
              case txn_get(K, Txn) of
                  {ok, {V, R}} ->
                      maps:put(K, {V, R}, Acc);
                  {error, not_found} ->
                      Acc
              end
      end, #{}, Keys).

get_snapshot(Fetchers) ->
    get_snapshot(Fetchers, #{}).

get_snapshot(Fetchers, Opts) ->
    {Snapshot, _} = get_snapshot_with_revision(Fetchers, Opts),
    Snapshot.

get_snapshot_with_revision(Fetchers) ->
    get_snapshot_with_revision(Fetchers, #{}).

get_snapshot_with_revision(Fetchers, Opts) ->
    {ok, SnapshotWithRev} =
        ro_txn(
          fun (Txn) ->
                  lists:foldl(
                    fun (Fetcher, Acc) ->
                            maps:merge(Fetcher(Txn), Acc)
                    end, #{}, Fetchers)
          end, Opts),
    SnapshotWithRev.

subscribe_to_key_change(Handler) ->
    BuildHandler = fun (Type) ->
                           ?cut(Handler(extract_event_key(Type, _)))
                   end,
    ns_pubsub:subscribe_link(ns_config_events, BuildHandler(ns_config)),
    ns_pubsub:subscribe_link(chronicle_kv:event_manager(kv),
                             BuildHandler(chronicle)).

subscribe_to_key_change(Keys, Worker) when is_list(Keys) ->
    subscribe_to_key_change(lists:member(_, Keys), Worker);
subscribe_to_key_change(Filter, Worker) ->
    subscribe_to_key_change(fun (Key) ->
                                    case Filter(Key) of
                                        false ->
                                            ok;
                                        true ->
                                            Worker(Key)
                                    end
                            end).

notify_if_key_changes(Filter, Message) ->
    Self = self(),
    subscribe_to_key_change(Filter, fun (_) -> Self ! Message end).

start_refresh_worker(Filter, Refresh) ->
    RV = {ok, Pid} =
        work_queue:start_link(
          fun () ->
                  Self = self(),
                  subscribe_to_key_change(
                    Filter, fun (_) ->
                                    work_queue:submit_work(Self, Refresh)
                            end)
          end),
    work_queue:submit_sync_work(Pid, Refresh),
    RV.

extract_event_key(ns_config, {Key, _}) ->
    Key;
extract_event_key(chronicle, {{key, Key}, _, _}) ->
    Key;
extract_event_key(_, _) ->
    undefined.


pull() ->
    pull(ns_config_rep:get_timeout(pull)).

pull(Timeout) ->
    case backend() of
        ns_config ->
            ok;
        chronicle ->
            do_pull(Timeout)
    end.

do_pull(Timeout) ->
    ok = chronicle_rsm:sync(kv, quorum, Timeout).

remote_pull(Nodes, Timeout) ->
    {_, BadRPC, BadNodes} =
        misc:rpc_multicall_with_plist_result(Nodes, ?MODULE, do_pull, [Timeout],
                                             Timeout),
    case BadNodes =:= [] andalso BadRPC =:= [] of
        true ->
            ok;
        false ->
            Error = {remote_pull_failed, BadRPC ++
                         [{N, bad_node} || N <- BadNodes]},
            ?log_warning("Failed to push chronicle config ~p", [Error]),
            {error, Error}
    end.

config_sync(Type, Nodes) ->
    config_sync(Type, Nodes, ns_config_rep:get_timeout(Type)).

config_sync(pull, Nodes, Timeout) ->
    case backend() of
        ns_config ->
            ns_config_rep:pull_remotes(Nodes, Timeout);
        chronicle ->
            do_pull(Timeout)
    end;
config_sync(push, Nodes, Timeout) ->
    case backend() of
        ns_config ->
            ns_config_rep:ensure_config_seen_by_nodes(Nodes, Timeout);
        chronicle ->
            case remote_pull(Nodes, Timeout) of
                ok ->
                    ok;
                {error, {remote_pull_failed, BadResults}} ->
                    {error, BadResults}
            end
    end.

node_keys(Node) ->
    [{node, Node, membership},
     {node, Node, services},
     {node, Node, recovery_type},
     {node, Node, failover_vbuckets}].

service_keys(Service) ->
    [{service_map, Service},
     {service_failover_pending, Service}].

should_move(nodes_wanted) ->
    true;
should_move(server_groups) ->
    true;
should_move({node, _, membership}) ->
    true;
should_move({node, _, services}) ->
    true;
should_move({node, _, recovery_type}) ->
    true;
should_move({node, _, failover_vbuckets}) ->
    true;
should_move({service_map, _}) ->
    true;
should_move({service_failover_pending, _}) ->
    true;
should_move(auto_reprovision_cfg) ->
    true;
should_move(buckets_with_data) ->
    true;
should_move(_) ->
    false.

upgrade(Config) ->
    OtherNodes = ns_node_disco:nodes_wanted(Config) -- [node()],
    ok = chronicle_master:upgrade_cluster(OtherNodes),

    Pairs =
        ns_config:fold(
          fun (buckets, Buckets, Acc) ->
                  maps:merge(
                    Acc, maps:from_list(
                           ns_bucket:upgrade_to_chronicle(Buckets)));
              (Key, Value, Acc) ->
                  case should_move(Key) of
                      true ->
                          maps:put(Key, Value, Acc);
                      false ->
                          Acc
                  end
          end, #{}, Config),

    Sets = [{set, K, V} || {K, V} <- maps:to_list(Pairs)],

    {ok, Rev} = chronicle_kv:multi(kv, Sets),
    ?log_info("Keys are migrated to chronicle. Rev = ~p. Sets = ~p",
              [Rev, Sets]),

    remote_pull(OtherNodes, ?UPGRADE_PULL_TIMEOUT).
