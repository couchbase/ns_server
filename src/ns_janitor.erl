%% @author Couchbase <info@couchbase.com>
%% @copyright 2009-2019 Couchbase, Inc.
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
%% Monitor and maintain the vbucket layout of each bucket.
%%
-module(ns_janitor).

-include("cut.hrl").
-include("ns_common.hrl").

-ifdef(TEST).
-include_lib("eunit/include/eunit.hrl").
-endif.

-export([cleanup/2, reset_rebalance_status/1, cleanup_apply_config/5]).

-spec cleanup(Bucket::bucket_name(), Options::list()) ->
                     ok |
                     {error, wait_for_memcached_failed, [node()]} |
                     {error, marking_as_warmed_failed, [node()]} |
                     {error, unsafe_nodes, [node()]}.
cleanup(Bucket, Options) ->
    FullConfig = ns_config:get(),
    case ns_bucket:get_bucket(Bucket, FullConfig) of
        not_present ->
            ok;
        {ok, BucketConfig} ->
            case ns_bucket:bucket_type(BucketConfig) of
                membase ->
                    cleanup_membase_bucket(Bucket,
                                           Options, BucketConfig, FullConfig);
                _ -> ok
            end
    end.

cleanup_membase_bucket(Bucket, Options, BucketConfig, FullConfig) ->
    %% We always want to check for unsafe nodes, as we want to honor the
    %% auto-reprovisioning settings for ephemeral buckets. That is, we do not
    %% want to simply activate any bucket on a restarted node and lose the data
    %% instead of promoting the replicas.
    AllOptions = Options ++ auto_reprovision:get_cleanup_options(),
    {ok, RV} =
        leader_activities:run_activity(
          {ns_janitor, Bucket, cleanup}, majority,
          fun () ->
                  {ok, cleanup_with_membase_bucket_check_servers(Bucket,
                                                                 AllOptions,
                                                                 BucketConfig,
                                                                 FullConfig)}
          end,
          [quiet]),

    RV.

cleanup_with_membase_bucket_check_servers(Bucket, Options, BucketConfig, FullConfig) ->
    case compute_servers_list_cleanup(BucketConfig, FullConfig) of
        none ->
            cleanup_with_membase_bucket_check_map(Bucket, Options, BucketConfig);
        {update_servers, NewServers} ->
            update_servers(Bucket, NewServers),
            cleanup(Bucket, Options)
    end.

update_servers(Bucket, Servers) ->
    ?log_debug("janitor decided to update "
               "servers list for bucket ~p to ~p", [Bucket, Servers]),

    ns_bucket:set_servers(Bucket, Servers),
    ok = ns_config_rep:ensure_config_seen_by_nodes().

cleanup_with_membase_bucket_check_map(Bucket, Options, BucketConfig) ->
    case proplists:get_value(map, BucketConfig, []) of
        [] ->
            Servers = proplists:get_value(servers, BucketConfig, []),
            true = (Servers =/= []),

            ?log_info("janitor decided to generate initial vbucket map"),
            {NewMap, Opts} = ns_rebalancer:generate_initial_map(BucketConfig),
            set_initial_map(NewMap, Opts, Bucket, BucketConfig),

            cleanup(Bucket, Options);
        _ ->
            cleanup_with_membase_bucket_vbucket_map(Bucket, Options, BucketConfig)
    end.

set_initial_map(Map, Opts, Bucket, BucketConfig) ->
    case ns_rebalancer:unbalanced(Map, BucketConfig) of
        false ->
            ns_bucket:update_vbucket_map_history(Map, Opts);
        true ->
            ok
    end,

    ns_bucket:set_map(Bucket, Map),
    ns_bucket:set_map_opts(Bucket, Opts),

    ok = ns_config_rep:ensure_config_seen_by_nodes().

cleanup_with_membase_bucket_vbucket_map(Bucket, Options, BucketConfig) ->
    Servers = proplists:get_value(servers, BucketConfig, []),
    true = (Servers =/= []),
    Timeout = proplists:get_value(query_states_timeout, Options),
    Opts = [{timeout, Timeout} || Timeout =/= undefined],
    case janitor_agent:query_vbuckets(Bucket, Servers, [], Opts) of
        {States, []} ->
            cleanup_with_states(Bucket, Options, BucketConfig, Servers, States);
        {_States, Zombies} ->
            ?log_info("Bucket ~p not yet ready on ~p", [Bucket, Zombies]),
            {error, wait_for_memcached_failed, Zombies}
    end.

cleanup_with_states(Bucket, Options, BucketConfig, Servers, States) ->
    {NewBucketConfig, IgnoredVBuckets} = maybe_fixup_vbucket_map(Bucket,
                                                                 BucketConfig,
                                                                 States),

    %% Find all the unsafe nodes (nodes on which memcached restarted within
    %% the auto-failover timeout) using the vbucket states. If atleast one
    %% unsafe node is found then we won't bring the bucket online until we
    %% we reprovision it. Reprovisioning is initiated by the orchestrator at
    %% the end of every janitor run.
    UnsafeNodes = find_unsafe_nodes_with_vbucket_states(
                    NewBucketConfig, States,
                    should_check_for_unsafe_nodes(NewBucketConfig, Options)),

    case UnsafeNodes =/= [] of
        true ->
            {error, unsafe_nodes, UnsafeNodes};
        false ->
            cleanup_apply_config(Bucket, Servers,
                                 NewBucketConfig, IgnoredVBuckets, Options)
    end.

maybe_fixup_vbucket_map(Bucket, BucketConfig, States) ->
    {NewBucketConfig, IgnoredVBuckets} = compute_vbucket_map_fixup(Bucket,
                                                                   BucketConfig,
                                                                   States),

    case NewBucketConfig =:= BucketConfig of
        true ->
            ok;
        false ->
            fixup_vbucket_map(Bucket, BucketConfig, NewBucketConfig, States)
    end,

    {NewBucketConfig, IgnoredVBuckets}.

fixup_vbucket_map(Bucket, BucketConfig, NewBucketConfig, States) ->
    ?log_info("Janitor is going to change "
              "bucket config for bucket ~p", [Bucket]),
    ?log_info("VBucket states:~n~p", [dict:to_list(States)]),
    ?log_info("Old bucket config:~n~p", [BucketConfig]),

    ok = ns_bucket:set_bucket_config(Bucket, NewBucketConfig),
    ok = ns_config_rep:ensure_config_seen_by_nodes().

cleanup_apply_config(Bucket,
                     Servers, BucketConfig, IgnoredVBuckets, Options) ->
    {ok, Result} =
        leader_activities:run_activity(
          {ns_janitor, Bucket, apply_config}, {all, Servers},
          fun () ->
                  {ok, cleanup_apply_config_body(Bucket,
                                                 Servers, BucketConfig,
                                                 IgnoredVBuckets, Options)}
          end,
          [quiet]),

    Result.

cleanup_apply_config_body(Bucket, Servers,
                          BucketConfig, IgnoredVBuckets, Options) ->
    ApplyTimeout = proplists:get_value(apply_config_timeout,
                                       Options,
                                       undefined_timeout),
    ok = janitor_agent:apply_new_bucket_config_with_timeout(Bucket, undefined,
                                                            Servers,
                                                            BucketConfig,
                                                            IgnoredVBuckets,
                                                            ApplyTimeout),

    maybe_reset_rebalance_status(Options),

    case janitor_agent:mark_bucket_warmed(Bucket, Servers) of
        ok ->
            ok;
        {error, BadNodes, _BadReplies} ->
            {error, marking_as_warmed_failed, BadNodes}
    end.

should_check_for_unsafe_nodes(BCfg, Options) ->
    proplists:get_bool(check_for_unsafe_nodes, Options) andalso
        ns_bucket:storage_mode(BCfg) =:= ephemeral.

find_unsafe_nodes_with_vbucket_states(_BucketConfig, _States, false) ->
    [];
find_unsafe_nodes_with_vbucket_states(BucketConfig, States, true) ->
    Map = proplists:get_value(map, BucketConfig, []),
    true = (Map =/= []),
    EnumeratedChains = lists:zip(lists:seq(0, length(Map) - 1), Map),

    lists:foldl(
      fun ({VB, [Master | _ ] = Chain}, UnsafeNodesAcc) ->
              case lists:member(Master, UnsafeNodesAcc) of
                  true ->
                      UnsafeNodesAcc;
                  false ->
                      case data_loss_possible(VB, Chain, States) of
                          {true, Node} ->
                              [Node | UnsafeNodesAcc];
                          false ->
                              UnsafeNodesAcc
                      end
              end
      end, [], EnumeratedChains).

%% Condition that indicates possibility of data loss:
%% A vBucket is "missing" on a node where it is supposed to be active as per the
%% vBucket map, it is not active elsewhere in the cluster, and the vBucket is in
%% replica state on some other node[s]. If such a vBucket is brought online on
%% the node supposed to be its current master, then it will come up empty and
%% when the replication streams are establised the replicas will also lose their
%% data.
data_loss_possible(VBucket, Chain, States) ->
    NodeStates = janitor_agent:fetch_vbucket_states(VBucket, States),
    Master = hd(Chain),
    case janitor_agent:find_vbucket_state(Master, NodeStates) of
        missing ->
            case lists:keymember(active, 2, NodeStates) of
                false ->
                    %% If none of the nodes have the vBucket active check if
                    %% the other nodes have the vBucket in replica state.
                    case [N || {N, replica, _} <- NodeStates] of
                        [] ->
                            false;
                        Replicas ->
                            ?log_info("vBucket ~p missing on master ~p while "
                                      "replicas ~p are active. Can lead to "
                                      "dataloss.",
                                      [VBucket, Master, Replicas]),
                            {true, Master}
                    end;
                true ->
                    false
            end;
        _ ->
            false
    end.

reset_rebalance_status(Fn) ->
    Fun = fun ({rebalance_status, Value}) ->
                  case Value of
                      running ->
                          NewValue = Fn(),
                          {update, {rebalance_status, NewValue}};
                      _ ->
                          skip
                  end;
              ({rebalancer_pid, Pid}) when is_pid(Pid) ->
                  {update, {rebalancer_pid, undefined}};
              (_Other) ->
                  skip
          end,

    ok = ns_config:update(Fun).

maybe_reset_rebalance_status(Options) ->
    case proplists:get_bool(consider_resetting_rebalance_status, Options) of
        true ->
            maybe_reset_rebalance_status();
        false ->
            ok
    end.

maybe_reset_rebalance_status() ->
    Status = try ns_orchestrator:rebalance_progress_full()
             catch E:T ->
                     ?log_error("cannot reach orchestrator: ~p:~p", [E,T]),
                     error
             end,
    case Status of
        %% if rebalance is not actually running according to our
        %% orchestrator, we'll consider checking config and seeing if
        %% we should unmark is at not running
        not_running ->
            reset_rebalance_status(
              fun () ->
                      ale:info(?USER_LOGGER,
                               "Resetting rebalance status "
                               "since it's not really running"),
                      {none, <<"Rebalance stopped by janitor.">>}
              end);
        _ ->
            ok
    end.

%% !!! only purely functional code below (with notable exception of logging) !!!
%% lets try to keep as much as possible logic below this line

compute_servers_list_cleanup(BucketConfig, FullConfig) ->
    case proplists:get_value(servers, BucketConfig) of
        [] ->
            NewServers = ns_cluster_membership:service_active_nodes(FullConfig, kv),
            {update_servers, NewServers};
        Servers when is_list(Servers) ->
            none;
        Else ->
            ?log_error("Some garbage in servers field: ~p", [Else]),
            BucketConfig1 = [{servers, []} | lists:keydelete(servers, 1, BucketConfig)],
            compute_servers_list_cleanup(BucketConfig1, FullConfig)
    end.

compute_vbucket_map_fixup(Bucket, BucketConfig, States) ->
    Map = proplists:get_value(map, BucketConfig, []),
    true = ([] =/= Map),
    FFMap = proplists:get_value(fastForwardMap, BucketConfig),

    EnumeratedChains = mb_map:enumerate_chains(Map, FFMap),
    MapUpdates = [sanify_chain(Bucket, States, Chain, FutureChain, VBucket)
                  || {VBucket, Chain, FutureChain} <- EnumeratedChains],

    MapLen = length(Map),
    IgnoredVBuckets = [VBucket || {VBucket, ignore} <-
                                      lists:zip(lists:seq(0, MapLen - 1),
                                                MapUpdates)],
    NewMap = [case NewChain of
                  ignore -> OldChain;
                  _ -> NewChain
              end || {NewChain, OldChain} <- lists:zip(MapUpdates, Map)],
    NewAdjustedMap = case cluster_compat_mode:is_cluster_madhatter() of
                         true ->
                             %% Defer adjusting chain length to rebalance, at
                             %% the time of writing this code the logic is in,
                             %% ns_rebalancer:do_rebalance_membase_bucket.
                             NewMap;
                         false ->
                             NumReplicas = ns_bucket:num_replicas(BucketConfig),
                             mb_map:align_replicas(Map, NumReplicas)
                     end,
    NewBucketConfig = case NewAdjustedMap =:= Map of
                          true ->
                              BucketConfig;
                          false ->
                              ?log_debug("Janitor decided to update vbucket map"),
                              lists:keyreplace(map, 1, BucketConfig,
                                               {map, NewAdjustedMap})
                      end,
    {NewBucketConfig, IgnoredVBuckets}.

%% this will decide what vbucket map chain is right for this vbucket
sanify_chain(_Bucket, _States,
             [CurrentMaster | _] = CurrentChain,
             _FutureChain, _VBucket) when CurrentMaster =:= undefined ->
    %% We can get here on a hard-failover case.
    CurrentChain;
sanify_chain(Bucket, States,
             [CurrentMaster | _] = CurrentChain,
             FutureChain, VBucket) ->
    NodeStates = janitor_agent:fetch_vbucket_states(VBucket, States),
    Actives = [N || {N, active, _} <- NodeStates],

    case Actives of
        %% No Actives.
        [] ->
            CurrentMasterState =
                janitor_agent:find_vbucket_state(CurrentMaster, NodeStates),
            ?log_info("Setting vbucket ~p in ~p on ~p from ~p to active.",
                      [VBucket, Bucket, CurrentMaster, CurrentMasterState]),
            %% Let's activate according to vbucket map.
            CurrentChain;

        %% One Active.
        [ActiveNode] ->
            sanify_chain_one_active(Bucket, VBucket, ActiveNode,
                                    NodeStates, CurrentChain, FutureChain);

        %% Multiple Actives.
        _ ->
            ?log_error("Extra active nodes ~p for vbucket ~p in ~p. "
                       "This should never happen!", [Actives, Bucket, VBucket]),
            case lists:member(CurrentMaster, Actives) of
                false ->
                    ignore;
                true ->
                    %% Pick CurrentChain if CurrentMaster is active.
                    CurrentChain
            end
    end.

fill_missing_replicas(Chain, ExpectedLength) when ExpectedLength > length(Chain) ->
    Chain ++ lists:duplicate(ExpectedLength - length(Chain), undefined);
fill_missing_replicas(Chain, _) ->
    Chain.

derive_chain(Bucket, VBucket, ActiveNode, Chain) ->
    DerivedChain = case misc:position(ActiveNode, Chain) of
                       false ->
                           %% It's an extra node
                           ?log_error(
                              "Master for vbucket ~p in ~p is not "
                              "active, but ~p is, so making that the "
                              "master.",
                              [VBucket, Bucket, ActiveNode]),
                           [ActiveNode];
                       Pos ->
                           ?log_error(
                              "Master for vbucket ~p in ~p "
                              "is not active, but ~p is (one of "
                              "replicas). So making that master.",
                              [VBucket, Bucket, ActiveNode]),
                           [ActiveNode | lists:nthtail(Pos, Chain)]
                   end,
    %% Fill missing replicas, so we don't lose durability constraints.
    fill_missing_replicas(DerivedChain, length(Chain)).

sanify_chain_one_active(_Bucket, _VBucket, ActiveNode, _States,
                        [CurrentMaster | _CurrentReplicas] = CurrentChain,
                        _FutureChain)
  when ActiveNode =:= CurrentMaster ->
    CurrentChain;
sanify_chain_one_active(Bucket, VBucket, ActiveNode, States,
                        [CurrentMaster | _CurrentReplicas] = CurrentChain,
                        [FutureMaster | FutureReplicas] = FutureChain)
  when ActiveNode =:= FutureMaster ->
    %% we check expected replicas to be replicas. One other allowed
    %% possibility is if old master is replica in ff chain. In which
    %% case depending on where rebalance was stopped it may be dead (if
    %% stopped right after takeover) or replica (if stopped after
    %% post-move vbucket states are set).
    PickFutureChain = lists:all(
                        fun (undefined) ->
                                true;
                            (N) ->
                                case janitor_agent:find_vbucket_state(N,
                                                                      States) of
                                    replica ->
                                        true;
                                    dead when N =:= CurrentMaster ->
                                        %% old master might be dead or
                                        %% replica. Replica is tested
                                        %% above
                                        true;
                                    _ ->
                                        false
                                end
                        end, FutureReplicas),
    case PickFutureChain of
        true ->
            FutureChain;
        false ->
            derive_chain(Bucket, VBucket, ActiveNode, CurrentChain)
    end;
sanify_chain_one_active(Bucket, VBucket, ActiveNode, _States,
                        CurrentChain, FutureChain) ->
    ?log_error("Active node ~p for vbucket ~p in ~p, was not part of "
               "current topology ~p or future topology ~p. "
               "This should never happen!",
               [ActiveNode, Bucket, VBucket, CurrentChain, FutureChain]),
    %% One active node, but it's not the master and it's not fast-forward map
    %% master, so we'll just update vbucket map. Note behavior below with losing
    %% replicas makes little sense as of now. Especially with star replication.
    %% But we can adjust it later.
    derive_chain(Bucket, VBucket, ActiveNode, CurrentChain).

-ifdef(TEST).
sanify_chain_t(States, CurrentChain, FutureChain) ->
    sanify_chain("B",
                 dict:from_list(
                   [{0, [{N, S, []} || {N, S} <- States]}]),
                 CurrentChain, FutureChain, 0).

sanify_basic_test() ->
    %% normal case when everything matches vb map
    [a, b] = sanify_chain_t([{a, active}, {b, replica}], [a, b], []),

    %% yes, the code will keep both masters as long as expected master
    %% is there. Possibly something to fix in future
    [a, b] = sanify_chain_t([{a, active}, {b, active}], [a, b], []),

    %% main chain doesn't match but fast-forward chain does
    [b, c] = sanify_chain_t([{a, dead}, {b, active}, {c, replica}],
                            [a, b], [b, c]),

    %% main chain doesn't match but ff chain does. And old master is already
    %% deleted
    [b, c] = sanify_chain_t([{b, active}, {c, replica}], [a, b], [b, c]),

    %% lets make sure we touch all paths just in case
    %% this runs "there are >1 unexpected master" case
    ignore = sanify_chain_t([{a, active}, {b, active}], [c, a, b], []),

    %% this runs "master is one of replicas" case
    [b, undefined] = sanify_chain_t([{b, active}, {c, replica}], [a, b], []),

    %% and this runs "master is some non-chain member node" case
    [c, undefined] = sanify_chain_t([{c, active}], [a, b], []),

    %% lets also test rebalance stopped prior to complete takeover
    [a, b] = sanify_chain_t([{a, dead}, {b, replica}, {c, pending},
                             {d, replica}], [a, b], [c, d]),
    ok.

sanify_doesnt_lose_replicas_on_stopped_rebalance_test() ->
    %% simulates the following: We've completed move that switches
    %% replica and active but rebalance was stopped before we updated
    %% vbmap. We have code in sanify to detect this condition using
    %% fast-forward map and is supposed to recover perfectly from this
    %% condition.
    [a, b] = sanify_chain_t([{a, active}, {b, dead}], [b, a], [a, b]),

    %% rebalance can be stopped after updating vbucket states but
    %% before vbucket map update
    [a, b] = sanify_chain_t([{a, active}, {b, replica}], [b, a], [a, b]),
    %% same stuff but prior to takeover
    [a, b] = sanify_chain_t([{a, dead}, {b, pending}], [a, b], [b, a]),

    %% lets test more usual case too
    [c, d] = sanify_chain_t([{a, dead}, {b, replica}, {c, active},
                             {d, replica}], [a, b], [c, d]),

    %% but without FF map we're (too) conservative (should be fixable
    %% someday)
    [c, undefined] = sanify_chain_t([{a, dead}, {b, replica}, {c, active},
                                     {d, replica}], [a, b], []).

sanify_addition_of_replicas_test() ->
    [a, b] = sanify_chain_t([{a, active}, {b, replica}], [a, b], [a, b, c]),
    [a, b] = sanify_chain_t([{a, active}, {b, replica}, {c, replica}],
                            [a, b], [a, b, c]),

    %% replica addition with possible move.
    [a, b] = sanify_chain_t([{a, dead}, {b, replica}, {c, pending}],
                            [a, b], [c, a, b]),
    [c, d, a] = sanify_chain_t([{a, dead}, {b, replica}, {c, active},
                                {d, replica}], [a, b], [c, d, a]),
    [c, d, a] = sanify_chain_t([{a, replica}, {b, replica}, {c, active},
                                {d, replica}], [a, b], [c, d, a]).

-endif.
