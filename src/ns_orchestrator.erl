%% @author Northscale <info@northscale.com>
%% @copyright 2010 NorthScale, Inc.
%% All rights reserved.

%% Monitor and maintain the vbucket layout of each bucket.
%% There is one of these per bucket.

-module(ns_orchestrator).

-behaviour(gen_server).

%% Constants and definitions

-record(state, {bucket, janitor, rebalancer, progress}).

%% API
-export([start_link/1]).

-export([failover/2,
         needs_rebalance/1,
         rebalance_progress/1,
         start_rebalance/3,
         stop_rebalance/1]).

%% gen_server callbacks
-export([init/1, handle_call/3, handle_cast/2,
         handle_info/2, terminate/2, code_change/3]).

%% API
start_link(Bucket) ->
    gen_server:start_link(server(Bucket), ?MODULE, Bucket, []).

failover(Bucket, Node) ->
    gen_server:call(server(Bucket), {failover, Node}).

needs_rebalance(Bucket) ->
    {_NumReplicas, _NumVBuckets, Map, Servers} = ns_bucket:config(Bucket),
    lists:any(fun (N) -> N == undefined end, lists:append(Map)) orelse
        unbalanced(histograms(Map, Servers)).

rebalance_progress(Bucket) ->
    gen_server:call(server(Bucket), rebalance_progress).

start_rebalance(Bucket, KeepNodes, EjectNodes) ->
    gen_server:call(server(Bucket), {start_rebalance, KeepNodes, EjectNodes}).

stop_rebalance(Bucket) ->
    gen_server:call(server(Bucket), stop_rebalance).

%% gen_server callbacks
init(Bucket) ->
    timer:send_interval(10000, janitor),
    {ok, #state{bucket=Bucket}}.

kill_vbuckets(_, _, []) ->
    ok;
kill_vbuckets(Node, Bucket, [V|Vs]) ->
    case ns_memcached:set_vbucket_state(Node, Bucket, V, dead) of
        {ok, _} ->
            kill_vbuckets(Node, Bucket, Vs);
        Error -> {error, Error}
    end.

handle_call({failover, Node}, _From, State = #state{bucket = Bucket}) ->
    {_, _, Map, Servers} = ns_bucket:config(Bucket),
    case lists:member(Node, Servers) of
        true ->
            case lists:member(Node, ns_node_disco:nodes_actual_proper()) of
                true ->
                    %% Make a last-ditch attempt to set vbuckets to dead
                    case ns_memcached:list_vbuckets(Node, Bucket) of
                        {ok, States} ->
                            ActiveVBuckets = [V || {V, active} <- States],
                            Result = kill_vbuckets(Node, Bucket, ActiveVBuckets),
                            error_logger:info_msg(
                              "~p:failover: got result ~p from attempt to kill vbuckets ~p on node ~p~n",
                              [?MODULE, Result, ActiveVBuckets, Node]),
                            ns_vbm_sup:set_replicas(Node, Bucket, []);
                        _ -> ok
                    end;
                false ->
                    ok
           end,
            ns_cluster:shun(Node),
            lists:foreach(fun (N) ->
                                  ns_vbm_sup:kill_dst_children(N, Bucket, Node)
                          end, lists:delete(Node, Servers)),
            %% Promote replicas of vbuckets on this node
            Map1 = promote_replicas(Bucket, Map, [Node]),
            ns_bucket:set_map(Map1),
            ns_bucket:set_servers(lists:delete(Node, Servers)),
            {reply, ok, State};
        false -> {reply, not_member, State}
    end;
handle_call(rebalance_progress, _From, State = #state{rebalancer = {_Pid, _Ref},
                                                      progress = Progress}) ->
    {reply, {running, Progress}, State};
handle_call(rebalance_progress, _From, State) ->
    {reply, not_running, State};
handle_call({start_rebalance, KeepNodes, EjectNodes}, _From,
            State = #state{bucket=Bucket, rebalancer=undefined}) ->
    {_NumReplicas, _NumVBuckets, Map, Servers} = ns_bucket:config(Bucket),
    Histograms = histograms(Map, Servers),
    case {lists:sort(Servers), lists:sort(KeepNodes), EjectNodes,
          unbalanced(Histograms)} of
        {S, S, [], false} ->
            error_logger:info_msg(
              "ns_orchestrator not rebalancing because already_balanced~n~p~n",
              [{Servers, KeepNodes, EjectNodes, Histograms}]),
            {reply, already_balanced, State};
        _ ->
            {ok, Pid, Ref} =
                misc:spawn_link_safe(
                  fun () ->
                          spawn_link(
                            fun() ->
                                    do_rebalance(Bucket, KeepNodes, EjectNodes, Map)
                            end)
                  end),
            {reply, ok, State#state{rebalancer={Pid, Ref}, progress=[]}}
    end;
handle_call({start_rebalance, _, _}, _From, State) ->
    error_logger:info_msg("ns_orchestrator not rebalancing because in_progress~n", []),
    {reply, in_progress, State};
handle_call(stop_rebalance, _From, State = #state{rebalancer={Pid, Ref}}) ->
    Pid ! stop,
    Reply = receive {Ref, Reason} -> Reason end,
    {reply, Reply, State#state{rebalancer=undefined}};
handle_call(stop_rebalance, _From, State) ->
    {reply, not_rebalancing, State};
handle_call(Request, From, State) ->
    error_logger:info_msg("~p:handle_call(~p, ~p, ~p)~n",
                          [?MODULE, Request, From, State]),
    {reply, {unhandled, ?MODULE, Request}, State}.

handle_cast({update_progress, Progress}, State) ->
    {noreply, State#state{progress=Progress}};
handle_cast(Msg, State) ->
    error_logger:info_msg("~p:handle_cast(~p, ~p)~n",
                          [?MODULE, Msg, State]),
    {noreply, State}.

handle_info(janitor, State = #state{bucket=Bucket, rebalancer=undefined}) ->
    misc:flush(janitor),
    {_, _, Map, Servers} = ns_bucket:config(Bucket),
    case Servers == undefined orelse Servers == [] of
        true ->
            error_logger:info_msg("Performing initial rebalance~n"),
            {ok, Pid, Ref} =
                misc:spawn_link_safe(
                  fun () ->
                          spawn_link(
                            fun() ->
                                    do_rebalance(Bucket, [node()], [], Map)
                            end)
                  end),
            {noreply, State#state{rebalancer={Pid, Ref}, progress=[]}};
        _ ->
            ns_janitor:cleanup(Bucket, Map, Servers),
            {noreply, State}
    end;
handle_info({Ref, Reason}, State = #state{rebalancer={_Pid, Ref}}) ->
    error_logger:info_msg("~p:handle_info(): rebalance finished with reason ~p~n",
                          [?MODULE, Reason]),
    {noreply, State#state{rebalancer=undefined}};
handle_info(Msg, State) ->
    error_logger:info_msg("~p:handle_info(~p, ~p)~n",
                          [?MODULE, Msg, State]),
    {noreply, State}.

terminate(_Reason, _State) ->
    ok.

code_change(_OldVsn, State, _Extra) ->
    {ok, State}.


%% Internal functions
apply_moves(_, [], Map) ->
    Map;
apply_moves(I, [{V, _, New}|Tail], Map) ->
    Chain = lists:nth(V+1, Map),
    NewChain = misc:nthreplace(I, New, Chain),
    apply_moves(I, Tail, misc:nthreplace(V+1, NewChain, Map)).

assign(Histogram, AvoidNodes) ->
    Histogram1 = lists:keysort(2, Histogram),
    case lists:splitwith(fun ({N, _}) -> lists:member(N, AvoidNodes) end,
                         Histogram1) of
        {Head, [{Node, N}|Rest]} ->
            {Node, Head ++ [{Node, N+1}|Rest]};
        {_, []} ->
            {undefined, Histogram1}
    end.

balance_nodes(Bucket, Map, Histograms, I) when is_integer(I) ->
    VNF = [{V, lists:nth(I, Chain), misc:nthdelete(I, Chain)} ||
              {V, Chain} <- misc:enumerate(Map, 0)],
    Hist = lists:nth(I, Histograms),
    balance_nodes(Bucket, VNF, Hist, []);
balance_nodes(Bucket, VNF, Hist, Moves) ->
    {MinNode, MinCount} = misc:keymin(2, Hist),
    {MaxNode, MaxCount} = misc:keymax(2, Hist),
    case MaxCount - MinCount > 1 of
        true ->
            %% Get the first vbucket that is on MaxNode and for which MinNode is not forbidden
            case lists:splitwith(
                   fun ({_, N, F}) ->
                           N /= MaxNode orelse
                               lists:member(MinNode, F)
                   end, VNF) of
                {Prefix, [{V, N, F}|Tail]} ->
                    N = MaxNode,
                    VNF1 = Prefix ++ [{V, MinNode, F}|Tail],
                    Hist1 = lists:keyreplace(MinNode, 1, Hist, {MinNode, MinCount + 1}),
                    Hist2 = lists:keyreplace(MaxNode, 1, Hist1, {MaxNode, MaxCount - 1}),
                    balance_nodes(Bucket, VNF1, Hist2, [{V, MaxNode, MinNode}|Moves]);
                X ->
                    error_logger:info_msg("~p:balance_nodes: No further moves (~p)~p",
                                          [?MODULE, VNF, Hist, Moves, X]),
                    Moves
            end;
        false ->
            Moves
    end.

do_rebalance(Bucket, KeepNodes, EjectNodes, Map) ->
    ns_bucket:set_servers(Bucket, KeepNodes ++ EjectNodes),
    AliveNodes = ns_node_disco:nodes_actual_proper(),
    RemapNodes = EjectNodes -- AliveNodes, % No active node, promote a replica
    lists:foreach(fun (N) -> ns_cluster:shun(N) end, RemapNodes),
    EvacuateNodes = EjectNodes -- RemapNodes, % Nodes we can move data off of
    Map1 = promote_replicas(Bucket, Map, RemapNodes),
    ns_bucket:set_map(Bucket, Map1),
    Histograms1 = histograms(Map1, KeepNodes),
    Moves1 = master_moves(Bucket, EvacuateNodes, Map1, Histograms1),
    Map2 = perform_moves(Bucket, Map1, Moves1),
    Histograms2 = histograms(Map2, KeepNodes),
    Moves2 = balance_nodes(Bucket, Map2, Histograms2, 1),
    Map3 = perform_moves(Bucket, Map2, Moves2),
    Histograms3 = histograms(Map3, KeepNodes),
    Map4 = new_replicas(Bucket, EjectNodes, Map3, Histograms3),
    ns_bucket:set_map(Bucket, Map4),
    Histograms4 = histograms(Map4, KeepNodes),
    ChainLength = length(lists:nth(1, Map4)),
    Map5 = lists:foldl(
             fun (I, M) ->
                     Moves = balance_nodes(Bucket, M, Histograms4, I),
                     apply_moves(I, Moves, M)
             end, Map4, lists:seq(2, ChainLength)),
    lists:foreach(fun (N) -> ns_cluster:shun(N) end, EvacuateNodes),
    ns_bucket:set_servers(Bucket, KeepNodes),
    ns_bucket:set_map(Bucket, Map5),
    ns_janitor:cleanup(Bucket, Map5, KeepNodes).

master_moves(Bucket, EvacuateNodes, Map, Histograms) ->
    master_moves(Bucket, EvacuateNodes, Map, Histograms, 0, []).

master_moves(_, _, [], _, _, Moves) ->
    Moves;
master_moves(Bucket, EvacuateNodes, [[OldMaster|_]|MapTail], Histograms, V,
                 Moves) ->
    [MHist|RHists] = Histograms,
    case (OldMaster == undefined) orelse lists:member(OldMaster, EvacuateNodes) of
        true ->
            {NewMaster, MHist1} = assign(MHist, []),
            master_moves(Bucket, EvacuateNodes, MapTail, [MHist1|RHists],
                             V+1, [{V, OldMaster, NewMaster}|Moves]);
        false ->
            master_moves(Bucket, EvacuateNodes, MapTail, Histograms, V+1,
                             Moves)
    end.

new_replicas(Bucket, EjectNodes, Map, Histograms) ->
    new_replicas(Bucket, EjectNodes, Map, Histograms, 0, []).

new_replicas(_, _, [], _, _, NewMapReversed) ->
    lists:reverse(NewMapReversed);
new_replicas(Bucket, EjectNodes, [Chain|MapTail], Histograms, V,
              NewMapReversed) ->
    %% Split off the masters - we don't want to move them!
    {[Master|Replicas], [MHist|RHists]} = {Chain, Histograms},
    ChainHist = lists:zip(Replicas, RHists),
    {Replicas1, RHists1} =
        lists:unzip(
          lists:map(fun ({undefined, Histogram}) ->
                            assign(Histogram, [Master|EjectNodes]);
                        (X = {OldNode, Histogram}) ->
                            case lists:member(OldNode, EjectNodes) of
                                true ->
                                    assign(Histogram, Chain ++ EjectNodes);
                                false ->
                                    X
                            end
                        end, ChainHist)),
    new_replicas(Bucket, EjectNodes, MapTail, [MHist|RHists1], V + 1,
                  [[Master|Replicas1]|NewMapReversed]).

perform_moves(Bucket, Map, []) ->
    ns_bucket:set_map(Bucket, Map),
    Map;
perform_moves(Bucket, Map, [{V, Old, New}|Moves]) ->
    [Old|Replicas] = lists:nth(V+1, Map),
    case {Old, New} of
        {X, X} ->
            perform_moves(Bucket, Map, Moves);
        {_, _} ->
            Map1 = misc:nthreplace(V+1, [New|lists:duplicate(length(Replicas),
                                                           undefined)], Map),
            error_logger:info_msg("Moving vbucket ~p for bucket ~p from ~p to ~p~n",
                                  [V, Bucket, Old, New]),
            case Old of
                undefined ->
                    ns_memcached:set_vbucket_state(New, Bucket, V, active);
                _ ->
                    ns_bucket:set_map(Bucket, Map1),
                    ns_vbm_sup:move(Bucket, V, Old, New)
            end,
            perform_moves(Bucket, Map1, Moves)
    end.

promote_replicas(Bucket, Map, RemapNodes) ->
    [promote_replica(Bucket, Chain, RemapNodes, V) ||
        {V, Chain} <- misc:enumerate(Map, 0)].

promote_replica(Bucket, Chain, RemapNodes, V) ->
    [OldMaster|_] = Chain,
    Bad = fun (Node) -> lists:member(Node, RemapNodes) end,
    NotBad = fun (Node) -> not lists:member(Node, RemapNodes) end,
    NewChain = lists:takewhile(NotBad, lists:dropwhile(Bad, Chain)), % TODO garbage collect orphaned pending buckets later
    NewChainExtended = NewChain ++ lists:duplicate(length(Chain) - length(NewChain), undefined),
    case NewChainExtended of
        [OldMaster|_] ->
            %% No need to promote
            NewChainExtended;
        [undefined|_] ->
            error_logger:error_msg("~p:promote_replicas(~p, ~p, ~p, ~p): No master~n", [?MODULE, Bucket, V, RemapNodes, Chain]),
            NewChainExtended;
        [NewMaster|_] ->
            error_logger:info_msg("~p:promote_replicas(~p, ~p, ~p, ~p): Setting node ~p active for vbucket ~p~n",
                                  [?MODULE, Bucket, V, RemapNodes, Chain, NewMaster, V]),
            ns_memcached:set_vbucket_state(NewMaster, V, active),
            NewChainExtended
    end.

histograms(Map, Servers) ->
    Histograms = [lists:keydelete(
                    undefined, 1,
                    misc:uniqc(
                      lists:sort(
                        [N || N<-L,
                              lists:member(N, Servers)]))) ||
                     L <- misc:rotate(Map)],
    lists:map(fun (H) ->
                      Missing = [{N, 0} || N <- Servers,
                                           not lists:keymember(N, 1, H)],
                      Missing ++ H
              end, Histograms).

server(Bucket) ->
    {global, list_to_atom(lists:flatten(io_lib:format("~s-~s", [?MODULE, Bucket])))}.

%% returns true iff the max vbucket count in any class on any server is >2 more than the min
unbalanced(Histograms) ->
    case [N || Histogram <- Histograms, {_, N} <- Histogram] of
        [] -> true;
        Counts -> lists:max(Counts) - lists:min(Counts) > 2
    end.

update_progress(Histograms) ->
    Groups = misc:keygroup(1, lists:keysort(1, lists:append(Histograms))),
    Counts = [{Node, Count}|| {Node, H} <- Groups,
                              Count <- lists:foldl(fun ((X), Y) -> X + Y end, H)].
