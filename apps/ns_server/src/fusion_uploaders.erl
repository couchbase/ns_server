%% @author Couchbase <info@couchbase.com>
%% @copyright 2025-Present Couchbase, Inc.
%%
%% Use of this software is governed by the Business Source License included in
%% the file licenses/BSL-Couchbase.txt.  As of the Change Date specified in that
%% file, in accordance with the Business Source License, use of this software
%% will be governed by the Apache License, Version 2.0, included in the file
%% licenses/APL2.txt.
%%
%% Monitor and maintain the vbucket layout of each bucket.
%% There is one of these per bucket.
%%
%% @doc code for calculating fusion uploaders during the rebalance
%%

-module(fusion_uploaders).

-include("ns_common.hrl").
-include_lib("ns_common/include/cut.hrl").

-export([build_fast_forward_info/4,
         build_initial/1,
         get_moves/1,
         get_current/1,
         fail_nodes/2,
         get_config/0,
         get_status/0,
         get_state/0,
         get_state/1,
         get_log_store_uri/0,
         update_config/1,
         enable/0,
         maybe_grab_heartbeat_info/0,
         maybe_advance_state/0,
         config_key/0]).

%% incremented starting from 1 with each uploader change
%% The purpose of Term is to help
%% s3 to recognize rogue uploaders and ignore them.
-type inc_term() :: pos_integer().
-type uploader() :: {node() | undefined, inc_term()}.
%% fusion uploaders map, one item per vbucket
-type uploaders() :: [uploader()].
-type move() :: same | uploader().
-type moves() :: [move()].
-type fast_forward_info() :: {moves(), uploaders()}.
-type state() ::
        disabled | disabling | enabled | enabling | stopped | stopping.
-type bucket_state() ::
        disabled | disabling | enabled | stopped | stopping.
-type enable_error() :: not_initialized | {wrong_state, state(), [state()]} |
                        {failed_nodes, [node()]}.

-export_type([fast_forward_info/0, uploaders/0, enable_error/0,
              bucket_state/0]).

-spec build_fast_forward_info(ns_bucket:name(), ns_bucket:config(),
                              vbucket_map(), vbucket_map()) ->
          undefined | fast_forward_info().
build_fast_forward_info(Bucket, BucketConfig, Map, FastForwardMap) ->
    case ns_bucket:is_fusion(BucketConfig) of
        false ->
            undefined;
        true ->
            Current = ns_bucket:get_fusion_uploaders(Bucket),
            Moves = calculate_moves(Map, FastForwardMap, Current,
                                    allowance(Map, BucketConfig)),
            ?rebalance_info("Calculated fusion uploader moves. Moves:~n~p",
                            [Moves]),
            {Moves, Current}
    end.

allowance(Map, BucketConfig) ->
    length(Map) div length(ns_bucket:get_servers(BucketConfig)) + 1.

-spec build_initial(vbucket_map()) -> uploaders().
build_initial(VBucketMap) ->
    [{N, 1} || [N | _] <- VBucketMap].

-spec get_moves(fast_forward_info()) -> moves().
get_moves({Moves, _}) ->
    Moves.

-spec get_current(fast_forward_info()) -> uploaders().
get_current({_, Current}) ->
    Current.

%% uploader starts uploading from scratch if it is moved to a
%% node that was not filled from s3, so basically to any node that
%% is not a current uploader and is present in old chain
%%
%% we calculate uploader moves doing the best effort to minimize
%% the number of uploaders started from scratch and distribute
%% uploaders evenly between nodes
%%
%% parameter Allowance restricts how many uploaders can be
%% started from each node thus defining how much unbalance
%% we are ready to tolerate for the sake of not uploading from
%% scratch
calculate_moves(Map, FastForwardMap, CurrentUploaders, Allowance) ->
    Zipped = lists:zip3(Map, FastForwardMap, [N || {N, _} <- CurrentUploaders]),
    build_uploaders(Zipped, CurrentUploaders, Allowance, moves).

candidates({OldChain, NewChain, UploaderNode}) ->
    NotFromScratch = NewChain -- lists:delete(UploaderNode, OldChain),
    FromScratch = NewChain -- NotFromScratch,
    Choices = case NotFromScratch of
                  [] ->
                      length(FromScratch);
                  _ ->
                      length(NotFromScratch)
              end,
    {[NotFromScratch, FromScratch], Choices};
candidates({NodesWithUploadedData, Chain}) ->
    FromScratch = Chain -- [N || {N, _, _} <- NodesWithUploadedData],
    %% each node with data is a list of one here, because we want
    %% the term and seqno to prevail over usage during the uploader
    %% selection
    NotFromScratch =
        [[N] || {N, _, _} <- lists:sort(
                               fun ({_, TermA, SeqnoA}, {_, TermB, SeqnoB}) ->
                                       {TermA, SeqnoA} > {TermB, SeqnoB}
                               end, NodesWithUploadedData)],
    Choices = case NotFromScratch of
                  [] ->
                      length(FromScratch);
                  _ ->
                      length(NotFromScratch)
              end,
    {NotFromScratch ++ [FromScratch], Choices}.

%% this function assumes that Allowance is big enough so [] candidates
%% is never passed in
select_uploader([Candidates | Rest], Usage, Allowance) ->
    Allowed = lists:filter(?cut(maps:get(_, Usage, 0) =< Allowance),
                           Candidates),
    case Allowed of
        [] ->
            select_uploader(Rest, Usage, Allowance);
        _ ->
            {_, Winner} =
                lists:min([{maps:get(N, Usage, 0), N} || N <- Allowed]),
            Winner
    end.

build_uploaders(Infos, CurrentUploaders, Allowance, OutputFormat) ->
    CandidatesList = lists:map(fun candidates/1, Infos),

    %% zip together vbucket numbers, candidates and current uploaders
    %% so the info can be processed for each vbucket
    Zipped = misc:enumerate(lists:zip(CandidatesList, CurrentUploaders), 0),

    %% the algorithm processes the vbuckets with the least number
    %% of uploader candidates first in order to have more choice
    %% at the end when Usage approaches Allowance
    Sorted = lists:sort(
               fun ({_, {{_, ChoicesA}, _}}, {_, {{_, ChoicesB}, _}}) ->
                       ChoicesA > ChoicesB
               end, Zipped),
    {WithUploaders, _} =
        lists:mapfoldl(
          fun ({I, {{Candidates, _Choices}, {CurrentUploader, Term}}}, Usage) ->
                  Uploader = select_uploader(Candidates, Usage, Allowance),
                  NewUsage = maps:update_with(Uploader, _ + 1, 1, Usage),
                  UploaderOrMove =
                      case Uploader of
                          CurrentUploader ->
                              case OutputFormat of
                                  moves ->
                                      same;
                                  uploaders ->
                                      {CurrentUploader, Term}
                              end;
                          _ ->
                              {Uploader, Term + 1}
                      end,
                  {{I, UploaderOrMove}, NewUsage}
          end, #{}, Sorted),

    %% return calculated moves or uploaders in vbucket number order
    [Uploader || {_, Uploader} <- lists:sort(WithUploaders)].

-spec fail_nodes(uploaders(), [node()]) -> uploaders().
fail_nodes(Uploaders, FailedNodes) ->
    [case lists:member(N, FailedNodes) of
         true ->
             {undefined, C};
         false ->
             {N, C}
     end || {N, C} <- Uploaders].

config_key() ->
    fusion_config.

default_config() ->
    [{enable_sync_threshold_mb, 1024},
     {state, disabled},
     {log_store_uri_locked, false}].

-spec get_config() -> proplists:proplist() | not_found.
get_config() ->
    case chronicle_kv:get(kv, config_key()) of
        {ok, {Config, _}} ->
            Config;
        {error, not_found} ->
            not_found
    end.

get_config_with_default(Source) ->
    chronicle_compat:get(Source, config_key(), #{default => default_config()}).

-spec get_state() -> state().
get_state() ->
    get_state(get_config_with_default(direct)).

-spec get_state(proplists:proplist()) -> state().
get_state(Config) ->
    proplists:get_value(state, Config).

-spec get_status() -> [{state, state()}].
get_status() ->
    [{state, get_state()}].

-spec get_log_store_uri() -> string().
get_log_store_uri() ->
    proplists:get_value(log_store_uri, get_config()).

-spec update_config(proplists:proplist()) ->
          {ok, chronicle:revision()} | log_store_uri_locked.
update_config(Params) ->
    chronicle_kv:transaction(
      kv, [config_key()],
      fun (Snapshot) ->
              Config = get_config_with_default(Snapshot),
              URI = proplists:get_value(log_store_uri, Params),
              case proplists:get_bool(log_store_uri_locked, Config) andalso
                  URI =/= undefined andalso
                  URI =/= proplists:get_value(log_store_uri, Config) of
                  true ->
                      {abort, log_store_uri_locked};
                  false ->
                      {commit, [{set, config_key(),
                                 misc:update_proplist(Config, Params)}]}
              end
      end).

re_enable_uploaders(Bucket, BucketConfig, Map, Uploaders) ->
    case janitor_agent:get_fusion_sync_info(Bucket, Map) of
        {error, Error} ->
            {error, Error};
        {ok, NodesInfo} ->
            VBInfosArray =
                lists:foldl(
                  fun ({Node, VBSyncInfo}, Acc) ->
                          lists:foldl(
                            fun ({VB, Term, Seqno}, Acc1) ->
                                    array:set(VB, [{Node, Term, Seqno} |
                                                   array:get(VB, Acc1)], Acc1)
                            end, Acc, VBSyncInfo)
                  end, array:new(length(Map), {default, []}), NodesInfo),
            VBInfos = array:to_list(VBInfosArray),
            Allowance = allowance(Map, BucketConfig),
            ?log_debug("The following information was retrieved from bucket "
                       "~p~n~p~nCurrent uploaders: ~p~nAllowance: ~p",
                       [Bucket, VBInfos, Uploaders, Allowance]),
            {ok, build_uploaders(lists:zip(VBInfos, Map), Uploaders,
                                 allowance(Map, BucketConfig), uploaders)}
    end.

calculate_bucket_uploaders(Bucket, BucketConfig) ->
    case proplists:get_value(map, BucketConfig, []) of
        [] ->
            %% bucket map not yet properly initialized
            %% this case will be handled by janitor
            {ok, undefined};
        Map ->
            case ns_bucket:get_fusion_uploaders(Bucket) of
                not_found ->
                    %% this bucket was never enabled for fusion
                    {ok, build_initial(Map)};
                Uploaders ->
                    case ns_bucket:is_fusion(BucketConfig) of
                        false ->
                            %% fusion was disabled on this bucket which means
                            %% that data is erased. therefore  start from
                            %% scratch, but do not go lower or equal to
                            %% existing terms
                            Zipped = lists:zip(build_initial(Map), Uploaders),
                            {ok, lists:map(
                                   fun ({{Node, _}, {Node, Term}}) ->
                                           {Node, Term};
                                       ({{Node, _}, {_, Term}}) ->
                                           {Node, Term + 1}
                                   end, Zipped)};
                        true ->
                            %% fusion was stopped for this bucket
                            %% rebuild uploaders according to existing data
                            %% trying to minimize the initial upload
                            re_enable_uploaders(Bucket, BucketConfig, Map,
                                                Uploaders)
                    end
            end
    end.

calculate_uploaders([], Acc) ->
    {ok, lists:reverse(Acc)};
calculate_uploaders([{Bucket, BucketConfig} | Rest], Acc) ->
    case calculate_bucket_uploaders(Bucket, BucketConfig) of
        {error, _} = E ->
            E;
        {ok, Uploaders} ->
            calculate_uploaders(Rest, [{Bucket, Uploaders} | Acc])
    end.

-spec enable() -> ok | {error, enable_error()}.
enable() ->
    MagmaBuckets = ns_bucket:get_buckets_of_type(
                     {membase, magma}, ns_bucket:get_buckets()),
    case calculate_uploaders(MagmaBuckets, []) of
        {ok, BucketUploaders} ->
            [?log_debug("Setting uploaders for bucket ~p:~n~p", [BN, U]) ||
                {BN, U} <- BucketUploaders],
            case enable(BucketUploaders) of
                {ok, _} ->
                    post_enable(MagmaBuckets);
                Other ->
                    Other
            end;
        Error ->
            Error
    end.

enable_buckets(Snapshot, BucketUploaders) ->
    lists:flatmap(
      fun ({BucketName, Uploaders}) ->
              {ok, BucketConfig} = ns_bucket:get_bucket(BucketName, Snapshot),
              case Uploaders of
                  undefined ->
                      [];
                  _ ->
                      [{set, ns_bucket:fusion_uploaders_key(BucketName),
                        Uploaders}]
              end ++
                  case ns_bucket:get_fusion_state(BucketConfig) of
                      enabled ->
                          [];
                      _ ->
                          [{set, ns_bucket:sub_key(BucketName, props),
                            ns_bucket:set_fusion_state(enabled, BucketConfig)}]
                  end
      end, BucketUploaders).

post_enable(Buckets) ->
    Servers = lists:usort(lists:flatten(
                            [ns_bucket:get_servers(BC) || {_, BC} <- Buckets])),
    case chronicle_compat:push(Servers) of
        ok ->
            ok;
        {error, BadReplies} ->
            ?log_warning("Failed to "
                         "synchronize config to some nodes: ~p", [BadReplies]),
            %% returning error to the caller will be misleading, since the
            %% enabling procedure is already started
            ok
    end,
    %% proceed to start the uploaders
    [ns_orchestrator:request_janitor_run({bucket, BN}) ||
        {BN, _} <- Buckets],
    ok.

enable(BucketUploaders) ->
    chronicle_kv:transaction(
      kv, [config_key() |
           [ns_bucket:sub_key(BN, props) || {BN, _} <- BucketUploaders]],
      fun (Snapshot) ->
              try
                  Config = get_config_with_default(Snapshot),
                  proplists:get_value(log_store_uri,
                                      Config) =/= undefined orelse
                      throw(not_initialized),
                  State = proplists:get_value(state, Config),
                  (State == disabled) orelse (State == stopped) orelse
                      throw({wrong_state, State, [disabled, stopped]}),
                  BucketCommits = enable_buckets(Snapshot, BucketUploaders),
                  {commit, [{set, config_key(),
                             misc:update_proplist(
                               Config, [{state, enabling},
                                        {log_store_uri_locked, true}])} |
                            BucketCommits]}
              catch
                  throw:Error ->
                      {abort, {error, Error}}
              end
      end).

-spec maybe_grab_heartbeat_info() -> list().
maybe_grab_heartbeat_info() ->
    maybe
        false ?= get_state() =:= disabled,
        active ?= ns_cluster_membership:get_cluster_membership(node()),
        true ?= lists:member(kv, ns_cluster_membership:node_services(node())),
        [{fusion_stats,
          [{buckets,
            lists:filtermap(
              fun ({BucketName, BucketConfig}) ->
                      maybe_grab_heartbeat_info(
                        BucketName,
                        ns_bucket:get_fusion_state(BucketConfig))
              end, ns_bucket:get_buckets())}]}]
    else
        _ -> []
    end.

add_stat_value(Key, Value, Acc) ->
    maps:update_with(Key, fun(V) -> V + Value end, 0, Acc).

add_stat_value_from(Key, VBStats, Acc) ->
    Value = proplists:get_value(list_to_binary(atom_to_list(Key)), VBStats),
    add_stat_value(Key, Value, Acc).

process_vbucket_stats(Node, BucketName, VB, VBStats, ThisNodeUploaders, Acc) ->
    case proplists:get_value(<<"state">>, VBStats) of
        <<"enabled">> = E ->
            Term = proplists:get_value(<<"term">>, VBStats),
            Acc1 =
                case maps:find(VB, ThisNodeUploaders) of
                    {ok, Term} ->
                        Acc;
                    Other ->
                        Expected = case Other of
                                       {ok, OtherTerm} ->
                                           {E, OtherTerm};
                                       error ->
                                           <<"disabled">>
                                   end,
                        ?log_debug("Uploader ~p:~p state mismatch on ~p. Got: "
                                   "~p. Expected: ~p",
                                   [BucketName, VB, Node, {E, Term}, Expected]),
                        add_stat_value(uploaders_state_mismatch, 1, Acc)
                end,
            add_stat_value_from(snapshot_pending_bytes, VBStats, Acc1);
        Other ->
            case maps:find(VB, ThisNodeUploaders) of
                {ok, Term} ->
                    ?log_debug("Uploader ~p:~p state mismatch on ~p. Got: "
                               "~p, Expected: ~p",
                               [BucketName, VB, Other, {<<"enabled">>, Term}]),
                    add_stat_value(uploaders_state_mismatch, 1, Acc);
                error ->
                    Acc
            end
    end.

process_bucket_stats(Node, BucketName, VBucketsInfo, ThisNodeUploaders) ->
    lists:foldl(
      fun ({<<"vb_", N/binary>>, {VBStats}}, Acc) ->
              process_vbucket_stats(
                Node, BucketName, binary_to_integer(N),
                VBStats, ThisNodeUploaders, Acc)
      end, #{}, VBucketsInfo).

node_uploaders(ThisNode, State, Uploaders) ->
    case State of
        enabled ->
            maps:from_list(
              [{VB, Term} ||
                  {VB, {Node, Term}} <- misc:enumerate(Uploaders, 0),
                  Node =:= ThisNode]);
        _ ->
            #{}
    end.

%% this will be fed to lists:filtermap
maybe_grab_heartbeat_info(_BucketName, disabled) ->
    false;
maybe_grab_heartbeat_info(_BucketName, stopped) ->
    false;
maybe_grab_heartbeat_info(BucketName, State) ->
    Uploaders = ns_bucket:get_fusion_uploaders(BucketName),
    ThisNodeUploaders = node_uploaders(node(), State, Uploaders),
    case ns_memcached:get_fusion_uploaders_state(BucketName) of
        {ok, {VBucketsInfo}} ->
            case length(VBucketsInfo) =:= length(Uploaders) of
                false ->
                    ?log_debug(
                       "Vbucket number mismatch for ~p:~p (memcached) vs "
                       "~p (config)",
                       [BucketName, length(VBucketsInfo), length(Uploaders)]),
                    false;
                true ->
                    StatsMap = process_bucket_stats(
                                 node(), BucketName, VBucketsInfo,
                                 ThisNodeUploaders),
                    {true, {BucketName, maps:to_list(StatsMap)}}
            end;
        Error ->
            ?log_debug(
               "Failure to retrieve uploaders stats for bucket ~p, Error:~p",
               [BucketName, Error]),
            false
    end.

-spec maybe_advance_state() -> ok.
maybe_advance_state() ->
    maybe_advance_state(get_state()).

maybe_advance_state(enabling) ->
    FusionConfig = get_config_with_default(direct),
    Threshold = proplists:get_value(enable_sync_threshold_mb, FusionConfig)
        * 1024 * 1024,
    Buckets = ns_bucket:get_buckets(direct),
    FusionBuckets =
        ns_bucket:filter_buckets_by(Buckets, fun ns_bucket:is_fusion/1),

    case fetch_fusion_stats(FusionBuckets, #{}) of
        error ->
            ok;
        PerBucketPerNodeMap ->
            ToAdvance =
                analyze_fusion_stats(
                  FusionBuckets, PerBucketPerNodeMap,
                  fun (BucketInfo, Acc) ->
                          case {maps:find(snapshot_pending_bytes, BucketInfo),
                                maps:find(uploaders_state_mismatch,
                                          BucketInfo)} of
                              {{ok, Bytes}, error} ->
                                  case Acc + Bytes of
                                      NewAcc when NewAcc > Threshold ->
                                          false;
                                      NewAcc ->
                                          NewAcc
                                  end;
                              _ ->
                                  false
                          end
                  end, 0),

            case ToAdvance of
                {true, Bytes} ->
                    ?log_info("Changing fusion state to 'enabled', "
                              "~p bytes remains to be synced", [Bytes]),
                    {ok, _} = update_config([{state, enabled}]),
                    ok;
                false ->
                    ok
            end
    end;
maybe_advance_state(_) ->
    ok.

analyze_fusion_stats([], _, _, Acc) ->
    {true, Acc};
analyze_fusion_stats([{Bucket, BucketConfig} | Rest],
                     PerBucketPerNodeMap, Fun, Acc) ->
    Uploaders = ns_bucket:get_fusion_uploaders(Bucket),
    FusionState = ns_bucket:get_fusion_state(BucketConfig),
    Servers = ns_bucket:get_servers(BucketConfig),

    case analyze_fusion_stats_for_bucket(
           Bucket, Uploaders, FusionState, Servers,
           PerBucketPerNodeMap, Fun, Acc) of
        false ->
            false;
        NewAcc ->
            analyze_fusion_stats(Rest, PerBucketPerNodeMap, Fun, NewAcc)
    end.

analyze_fusion_stats_for_bucket(_, _, _, [], _, _, Acc) ->
    Acc;
analyze_fusion_stats_for_bucket(Bucket, Uploaders, FusionState, [Node | Rest],
                                PerBucketPerNodeMap, Fun, Acc) ->
    {ok, PerNodeMap} = maps:find(Bucket, PerBucketPerNodeMap),
    {ok, {VBucketsInfo}} = maps:find(Node, PerNodeMap),
    ThisNodeUploaders = node_uploaders(Node, FusionState, Uploaders),
    Aggregated = process_bucket_stats(
                   Node, Bucket, VBucketsInfo, ThisNodeUploaders),

    case Fun(Aggregated, Acc) of
        false ->
            false;
        NewAcc ->
            analyze_fusion_stats_for_bucket(
              Bucket, Uploaders, FusionState, Rest,
              PerBucketPerNodeMap, Fun, NewAcc)
    end.

fetch_fusion_stats([], Acc) ->
    Acc;
fetch_fusion_stats([{BucketName, BucketConfig} | Rest], Acc) ->
    case janitor_agent:get_fusion_uploaders_state(BucketName, BucketConfig) of
        {error, {failed_nodes, BadNodes}} ->
            ?log_warning("Unable to fetch uploaders state for bucket ~p from "
                         "nodes ~p", [BucketName, BadNodes]),
            error;
        {ok, PerNodeInfos} ->
            fetch_fusion_stats(
              Rest, Acc#{BucketName => maps:from_list(PerNodeInfos)})
    end.
