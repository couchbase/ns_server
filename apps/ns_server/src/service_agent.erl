%% @author Couchbase <info@couchbase.com>
%% @copyright 2016-Present Couchbase, Inc.
%%
%% Use of this software is governed by the Business Source License included in
%% the file licenses/BSL-Couchbase.txt.  As of the Change Date specified in that
%% file, in accordance with the Business Source License, use of this software
%% will be governed by the Apache License, Version 2.0, included in the file
%% licenses/APL2.txt.
%%
-module(service_agent).

-behaviour(gen_server).

-include_lib("ns_common/include/cut.hrl").
-include("ns_common.hrl").
-include("ns_config.hrl").
-include("service_api.hrl").

-export([start_link/1]).
-export([get_status/2]).
-export([wait_for_agents/3]).
-export([set_service_manager/3, unset_service_manager/3]).
-export([get_node_infos/3, prepare_rebalance/7, start_rebalance/7]).
-export([get_params/2]).
-export([prepare_pause_bucket/5, pause_bucket/5]).
-export([prepare_resume_bucket/6, resume_bucket/6]).
-export([spawn_connection_waiter/2]).
-export([init/1, handle_call/3, handle_cast/2,
         handle_info/2, terminate/2, code_change/3]).

-define(CONNECTION_TIMEOUT, ?get_timeout(wait_for_connection, 60000)).
-define(OUTER_TIMEOUT,      ?get_timeout(outer, 90000)).

-type revision() :: binary().
-type node_id() :: binary().

-record(topology, {
          nodes :: [node()],
          node_uuids :: [node_id()],
          is_balanced :: boolean(),
          messages :: [binary()]
         }).

-record(state, {
          service :: atom(),

          node_uuid_map :: dict:dict(),

          conn :: undefined | pid(),
          conn_mref :: undefined | reference(),

          service_manager :: undefined | pid(),
          service_manager_mref :: undefined | reference(),
          task_runner :: undefined | pid(),
          task_runner_queue :: undefined | queue:queue(),
          task_observer :: undefined | pid(),

          tasks :: undefined | {revision(), [any()]},
          topology :: undefined | {revision(), #topology{}},

          get_tasks_worker :: undefined | pid(),
          topology_worker :: undefined | pid(),

          type :: undefined | rebalance | failover | pause_bucket |
                  resume_bucket | dry_run_resume_bucket
         }).

start_link(Service) ->
    gen_server:start_link({local, server_name(Service)}, ?MODULE, Service, []).

get_status(Service, Timeout) ->
    gen_server:call(server_name(Service), get_status, Timeout).

wait_for_agents(Service, Nodes, Timeout) ->
    ?log_debug("Waiting for the service agents for "
               "service ~p to come up on nodes:~n~p", [Service, Nodes]),
    wait_for_agents_loop(Service, Nodes, [], Timeout).

-define(WAIT_FOR_AGENTS_SLEEP, 1000).

wait_for_agents_loop(Service, Nodes, _Acc, Timeout)
  when Timeout =< 0 ->
    process_bad_results(Service, get_agent, [{N, {error, timeout}} || N <- Nodes]);
wait_for_agents_loop(Service, Nodes, Acc, Timeout) ->
    {Elapsed, {Good, Bad}} =
        timer:tc(
          fun () ->
                  multi_call(Nodes, Service, get_agent, Timeout)
          end),

    case Bad of
        [] ->
            ?log_debug("All service agents are ready for ~p", [Service]),
            extract_ok_responses(Good ++ Acc);
        _ ->
            case lists:all(fun is_noproc/1, Bad) of
                true ->
                    NotReady = [N || {N, _} <- Bad],
                    ?log_debug("Service agent for ~s is not "
                               "ready on some nodes:~n~p", [Service, NotReady]),
                    timer:sleep(?WAIT_FOR_AGENTS_SLEEP),

                    ElapsedMs = Elapsed div 1000,
                    NewTimeout = Timeout - ElapsedMs - ?WAIT_FOR_AGENTS_SLEEP,
                    wait_for_agents_loop(Service, NotReady, Good ++ Acc, NewTimeout);
                false ->
                    process_bad_results(Service, get_agent, Bad)
            end
    end.

set_service_manager(Service, Nodes, Manager) ->
    Call = {Tag, _CallArgs} =
        case cluster_compat_mode:is_cluster_76() of
            true ->
                {set_service_manager, Manager};
            false ->
                {set_rebalancer, Manager}
        end,

    Result = multi_call(Nodes, Service, Call, ?OUTER_TIMEOUT),
    handle_multicall_result(Service, Tag, Result, fun just_ok/1).

unset_service_manager(Service, Nodes, Manager) ->
    Call = {_, _CallArgs, Tag} =
        case cluster_compat_mode:is_cluster_76() of
            true ->
                {if_service_manager, Manager, unset_service_manager};
            false ->
                {if_rebalance, Manager, unset_rebalancer}
        end,

    Result = multi_call(Nodes, Service, Call, ?OUTER_TIMEOUT),
    handle_multicall_result(Service, Tag, Result, fun just_ok/1).

get_node_infos(Service, Nodes, Manager) ->
    Tag = get_node_info,
    Call =
        case cluster_compat_mode:is_cluster_76() of
            true ->
                {if_service_manager, Manager, Tag};
            false ->
                {if_rebalance, Manager, Tag}
        end,

    Result = multi_call(Nodes, Service, Call, ?OUTER_TIMEOUT),
    handle_multicall_result(Service, Tag, Result).

get_params(Service, Leader) ->
    rpc:call(Leader, service_api, get_params, [Service], ?OUTER_TIMEOUT).

prepare_rebalance(Service, Nodes, Manager, RebalanceId, Type, KeepNodes,
                  EjectNodes) ->
    Tag = prepare_rebalance,
    Call =
        case cluster_compat_mode:is_cluster_76() of
            true ->
                {if_service_manager, Manager,
                 {Tag, RebalanceId, Type, KeepNodes, EjectNodes}};
            false ->
                {if_rebalance, Manager,
                 {Tag, RebalanceId, Type, KeepNodes, EjectNodes}}
        end,

    Result = multi_call(Nodes, Service, Call, ?OUTER_TIMEOUT),
    handle_multicall_result(Service, Tag, Result, fun just_ok/1).

start_rebalance(Service, Node, Manager, RebalanceId, Type, KeepNodes,
                EjectNodes) ->
    Observer = self(),
    Call =
        case cluster_compat_mode:is_cluster_76() of
            true ->
                {if_service_manager, Manager,
                 {start_rebalance, RebalanceId, Type, KeepNodes, EjectNodes,
                  Observer}};
            false ->
                {if_rebalance, Manager,
                 {start_rebalance, RebalanceId, Type, KeepNodes, EjectNodes,
                  Observer}}
        end,

    gen_server:call({server_name(Service), Node}, Call, ?OUTER_TIMEOUT).

prepare_pause_bucket(Service, Nodes, Id, Args, Manager) ->
    Result = multi_call(Nodes, Service,
                        {if_service_manager, Manager,
                         {prepare_pause_bucket, Id, Args}},
                        ?OUTER_TIMEOUT),
    handle_multicall_result(Service, prepare_pause_bucket, Result,
                            fun just_ok/1).

pause_bucket(Service, Node, Id, Args, Manager) ->
    Observer = self(),
    gen_server:call({server_name(Service), Node},
                    {if_service_manager, Manager,
                     {pause_bucket, Id, Args, Observer}},
                    ?OUTER_TIMEOUT).

prepare_resume_bucket(Service, Nodes, Id, Args, DryRun, Manager) ->
    Result = multi_call(Nodes, Service,
                        {if_service_manager, Manager,
                         {prepare_resume_bucket,
                          Id, Args, DryRun}},
                        ?OUTER_TIMEOUT),
    handle_multicall_result(Service, prepare_resume_bucket, Result,
                            fun just_ok/1).

resume_bucket(Service, Node, Id, Args, DryRun, Manager) ->
    Observer = self(),
    gen_server:call({server_name(Service), Node},
                    {if_service_manager, Manager,
                     {resume_bucket, Id, Args, DryRun, Observer}},
                    ?OUTER_TIMEOUT).

%% gen_server callbacks
init(Service)       ->
    process_flag(trap_exit, true),

    spawn_connection_waiter(self(), Service),

    ns_pubsub:subscribe_link(ns_config_events,
                             fun config_event_handler/2, self()),
    NodeUUIDMap = build_node_uuid_map(ns_config:get()),

    {ok, #state{service = Service,
                node_uuid_map = NodeUUIDMap}}.

handle_call(get_status, _From, #state{service = Service,
                                      topology = Topology} = State) ->
    Status =
        case Topology of
            undefined ->
                [{connected, false}];
            {_Rev, ActualTopology} ->
                [{connected, true},
                 {needs_rebalance, needs_rebalance(Service, ActualTopology)}]
        end,

    {reply, Status, State};
handle_call(get_agent, _From, State) ->
    {reply, {ok, self()}, State};

%% set_rebalancer is called when the cluster_compat_mode is less than 7.6.
handle_call({set_rebalancer, Pid}, From, State) ->
    handle_call({set_service_manager, Pid}, From, State);
handle_call({set_service_manager, Pid} = Call, From,
            #state{service_manager = Manager} = State0) ->
    State =
        case Manager of
            undefined ->
                State0;
            _ ->
                ?log_info("Got set_service_manager call ~p when "
                          "another service manager call is already running."
                          "Old service manager: ~p. "
                          "Going to abort the previous service manager call.",
                          [Call, Manager]),
                handle_unset_service_manager(State0)
        end,
    NewState = handle_set_service_manager(Pid, State),
    %% reply only when the revrpc connection is fully established
    run_on_task_runner(From, NewState, fun (_) -> ok end);

%% if_rebalance is called when the cluster_compat_mode is less than 7.6.
handle_call({if_rebalance, Pid, Call}, From, State) ->
    handle_call({if_service_manager, Pid, Call}, From, State);
handle_call({if_service_manager, Pid, Call} = FullCall, From,
            #state{service_manager = Manager} = State) ->
    case Pid =:= Manager of
        true ->
            do_handle_call(Call, From, State);
        false ->
            ?log_error("Got service-agent call ~p that "
                       "doesn't match service-manager pid ~p", [FullCall,
                                                                Manager]),
            {reply, nack, State}
    end;
handle_call(Call, From, State) ->
    ?log_warning("Unexpected call ~p from ~p when in state~n~p",
                 [Call, From, State]),
    {reply, nack, State}.

handle_cast({got_connection, Pid}, State) ->
    {noreply, handle_connection(Pid, State)};
handle_cast({config_event, Event}, #state{node_uuid_map = Map,
                                          topology = Topology} = State) ->
    {{node, Node, uuid}, Value} = Event,

    NewMap =
        case Value of
            ?DELETED_MARKER ->
                erase_node_uuid_mapping(Node, Map);
            _ ->
                add_node_uuid_mapping(Node, Value, Map)
        end,

    NewState0 = State#state{node_uuid_map = NewMap},
    NewState =
        case Topology of
            undefined ->
                NewState0;
            _ ->
                handle_new_topology(Topology, NewState0)
        end,

    {noreply, NewState};
handle_cast(Cast, State) ->
    ?log_warning("Unexpected cast ~p when in state~n~p",
                 [Cast, State]),
    {noreply, State}.

handle_info({task_call_reply, RV}, #state{task_runner_queue = Waiters}
            = State) ->
    {{value, From}, NewWaiters} = queue:out(Waiters),
    gen_server:reply(From, RV),
    {noreply, State#state{task_runner_queue = NewWaiters}};
handle_info({set_task_observer, Observer}, State) ->
    {noreply, handle_set_task_observer(Observer, State)};
handle_info({new_tasks, Tasks}, State) ->
    {noreply, handle_new_tasks(Tasks, State)};
handle_info({new_topology, Topology}, State) ->
    {noreply, handle_new_topology(Topology, State)};
handle_info({'EXIT', Pid, Reason}, State) ->
    ?log_error("Linked process ~p died with reason ~p. Terminating", [Pid, Reason]),
    {stop, {linked_process_died, Pid, {node(), Reason}}, State};
handle_info({'DOWN', MRef, _, _, Reason},
            #state{service_manager = Pid,
                   service_manager_mref = MRef} = State) ->
    ?log_error("Service Manager ~p died unexpectedly: ~p", [Pid, Reason]),
    {noreply, handle_unset_service_manager(State)};
handle_info({'DOWN', MRef, _, _, Reason}, #state{service = Service,
                                                 conn_mref = MRef} = State) ->
    ?log_error("Lost json rpc connection for service ~p, reason ~p. Terminating.",
               [Service, Reason]),
    {stop, {lost_connection, {node(), Reason}}, handle_lost_connection(State)};
handle_info(Msg, State) ->
    ?log_warning("Unexpected message ~p when in state~n~p",
                 [Msg, State]),
    {noreply, State}.

terminate(Reason, #state{service = Service,
                         conn = Conn,
                         get_tasks_worker = GetTasksWorker,
                         topology_worker = TopologyWorker,
                         task_runner = TaskRunner}) ->
    Pids = [P || P <- [GetTasksWorker, TopologyWorker, TaskRunner],
                 P =/= undefined],
    ok = misc:terminate_and_wait(Pids, Reason),

    if
        Reason =:= normal orelse Reason =:= shutdown ->
            ok;
        true ->
            ?log_error("Terminating abnormally"),
            case Conn of
                undefined ->
                    ok;
                _ when is_pid(Conn) ->
                    ?log_error("Terminating json rpc connection for ~p: ~p",
                               [Service, Conn]),
                    exit(Conn, {service_agent_died, Reason})
            end
    end.

code_change(_OldVsn, State, _Extra) ->
    {ok, State}.

%% internal
server_name(Service) when is_atom(Service) ->
    list_to_atom(?MODULE_STRING ++ "-" ++ atom_to_list(Service)).

spawn_connection_waiter(Agent, Service) ->
    proc_lib:spawn_link(
      fun () ->
              ns_pubsub:subscribe_link(json_rpc_events),
              json_rpc_connection_sup:reannounce(),

              Timeout = make_ref(),
              erlang:send_after(?CONNECTION_TIMEOUT, self(), Timeout),

              wait_for_connection_loop(
                Agent, service_api:get_label(Service), Timeout)
      end).

wait_for_connection_loop(Agent, WantedLabel, Timeout) ->
    receive
        {_, Label, _Params, Pid} when Label =:= WantedLabel ->
            gen_server:cast(Agent, {got_connection, Pid}),
            unlink(Agent);
        Timeout ->
            ?log_error("No connection with label ~p after ~pms. Exiting.",
                       [WantedLabel, ?CONNECTION_TIMEOUT]),
            exit({no_connection, WantedLabel});
        _Other ->
            wait_for_connection_loop(Agent, WantedLabel, Timeout)
    end.

handle_connection(Conn, State) ->
    try
        do_handle_connection(Conn, State)
    catch
        T:E:Stack ->
            %% We might get here because of misbehaving revrpc service, so try
            %% to drop the connection in the hope that it will help the
            %% service to recover. We do a similar thing in the terminate
            %% function, but that won't work for this case because there's no
            %% connection in the state yet.
            exit(Conn, {handle_connection_failed, {T, E}}),
            erlang:raise(T, E, Stack)
    end.

do_handle_connection(Conn, #state{service = Service,
                                  task_runner = TaskRunner} = State) ->
    ?log_debug("Observed new json rpc connection for ~p: ~p",
               [Service, Conn]),

    ConnMRef = erlang:monitor(process, Conn),
    State1 = State#state{conn = Conn,
                         conn_mref = ConnMRef},
    State2 = refresh_state(State1),
    State3 = cleanup_service(State2),

    State4 = start_long_poll_workers(State3),

    case TaskRunner of
        undefined ->
            ok;
        _ when is_pid(TaskRunner) ->
            pass_connection(TaskRunner, Conn)
    end,

    State4.

handle_lost_connection(State) ->
    State#state{conn = undefined,
                conn_mref = undefined}.

handle_set_service_manager(Pid, #state{conn = Conn} = State) ->
    MRef = erlang:monitor(process, Pid),
    TaskRunner = start_task_runner(),

    case Conn of
        undefined ->
            ok;
        _ when is_pid(Conn) ->
            pass_connection(TaskRunner, Conn)
    end,

    State#state{service_manager = Pid,
                service_manager_mref = MRef,
                task_runner = TaskRunner,
                task_runner_queue = queue:new(),
                task_observer = undefined}.

handle_unset_service_manager(#state{service_manager = Pid,
                                    service_manager_mref = MRef,
                                    task_runner = TaskRunner,
                                    task_runner_queue = Waiters} = State)
  when is_pid(Pid) ->
    erlang:demonitor(MRef, [flush]),

    misc:unlink_terminate_and_wait(TaskRunner,
                                   {shutdown, service_manager_terminated}),

    lists:foreach(
      fun (Waiter) ->
              gen_server:reply(Waiter, {error, service_manager_terminated})
      end, queue:to_list(Waiters)),

    drop_messages(),

    %% It's possible that we never saw the json-rpc connection. It might
    %% happen in the following scenario. A one node cluster is initialized
    %% with topology aware service, orchestrator will try to run initial
    %% rebalance (as part of service janitoring) for the service. That happens
    %% shortly after starting service_agent and the corresponding service
    %% itself. If while agent waits for the connection new node is added and
    %% rebalanced in, then orchestrator will terminate the janitor run to
    %% proceed with rebalance. That will result in unset_rebalance call when
    %% connection is still missing. In this case we don't have long poll
    %% workers yet, so we shouldn't attempt to terminate/restart them.
    State1 =
        when_have_connection(
            fun (S) ->
                    S1 = terminate_long_poll_workers(S),
                    drop_long_poll_messages(),

                    S2 = refresh_state(S1),
                    S3 = cleanup_service(S2),
                    start_long_poll_workers(S3)
            end, State),

    State1#state{service_manager = undefined,
                 service_manager_mref = undefined,
                 task_runner = undefined,
                 task_runner_queue = undefined,
                 task_observer = undefined}.

when_have_connection(Fun, #state{conn = Conn,
                                 get_tasks_worker = GetTasksWorker,
                                 topology_worker = TopologyWorker} = State) ->
    case Conn of
        undefined ->
            undefined = GetTasksWorker,
            undefined = TopologyWorker,

            State;
        _ when is_pid(Conn) ->
            Fun(State)
    end.

drop_messages() ->
    receive
        {task_call_reply, _} ->
            drop_messages();
        {set_task_observer, _} ->
            drop_messages()
    after
        0 -> ok
    end.

%% unset_rebalancer is called when the cluster_compat_mode is less than 7.6.
do_handle_call(unset_rebalancer, From, State) ->
    do_handle_call(unset_service_manager, From, State);
do_handle_call(unset_service_manager, _From, State) ->
    {reply, ok, handle_unset_service_manager(State)};
do_handle_call(get_node_info, From, State) ->
    run_on_task_runner(From, State, fun handle_get_node_info/1);
do_handle_call({prepare_rebalance, Id, Type, KeepNodes, EjectNodes}, From,
               State) ->
    run_on_task_runner(
      From, State,
      fun (Conn) ->
              handle_prepare_rebalance(Conn, Id, Type, KeepNodes, EjectNodes)
      end);
do_handle_call({start_rebalance, Id, Type, KeepNodes, EjectNodes, Observer},
               From, State) ->
    Self = self(),
    State1 = State#state{type = Type},

    run_on_task_runner(
      From, State1,
      fun (Conn) ->
              handle_start_rebalance(Conn, Id, Type, KeepNodes,
                                     EjectNodes, Self, Observer)
      end);
do_handle_call({prepare_pause_bucket, Id, Args},
               From, State) ->
    run_on_task_runner(
      From, State,
      fun (Conn) ->
              handle_prepare_pause_bucket(Conn, Id, Args)
      end);
do_handle_call({pause_bucket, Id, Args, Observer},
               From, State) ->
    Self = self(),
    State1 = State#state{type = pause_bucket},

    run_on_task_runner(
      From, State1,
      fun (Conn) ->
              handle_pause_bucket(Conn, Id, Args, Self, Observer)
      end);
do_handle_call({prepare_resume_bucket, Id, Args, DryRun},
               From, State) ->
    run_on_task_runner(
      From, State,
      fun (Conn) ->
              handle_prepare_resume_bucket(Conn, Id, Args, DryRun)
      end);
do_handle_call({resume_bucket, Id, Args, DryRun, Observer},
               From, State) ->
    Self = self(),
    State1 = case DryRun of
                 true ->
                     State#state{type = dry_run_resume_bucket};
                 false ->
                     State#state{type = resume_bucket}
             end,

    run_on_task_runner(
      From, State1,
      fun (Conn) ->
              handle_resume_bucket(Conn, Id, Args, DryRun, Self, Observer)
      end);
do_handle_call(Call, From, State) ->
    ?log_error("Unexpected call ~p from ~p when in state~n~p",
               [Call, From, State]),
    {reply, nack, State}.

must_get(Key, Props) when is_atom(Key) ->
    {_, Value} = lists:keyfind(atom_to_binary(Key, latin1), 1, Props),
    Value.

get_default(Key, Props, Default) when is_atom(Key) ->
    case lists:keyfind(atom_to_binary(Key, latin1), 1, Props) of
        {_, Value} ->
            Value;
        false ->
            Default
    end.

find_tasks_by_type(Type, Tasks) ->
    find_tasks_by_types([Type], Tasks).

find_tasks_by_types(Types, Tasks) ->
    lists:filter(
      fun (Task) ->
              lists:member(must_get(type, Task), Types)
      end, Tasks).

cancel_task(Conn, Task) ->
    Id = must_get(id, Task),
    case service_api:cancel_task(Conn, Id, undefined) of
        ok ->
            ok;
        {error, not_found} ->
            ok
    end.

cancel_tasks(Conn, Tasks) ->
    lists:foreach(
      fun (Task) ->
              ok = cancel_task(Conn, Task)
      end, Tasks).

find_stale_tasks(#state{tasks = {_Rev, Tasks}} = _State) ->
    %% Services expect the rebalance/pause/resume tasks to be cancelled before
    %% the prepare tasks. Reorder these tasks accordingly.
    NonPrepareTasks =
        find_tasks_by_types([?TASK_TYPE_REBALANCE,
                             ?TASK_TYPE_PAUSE_BUCKET,
                             ?TASK_TYPE_RESUME_BUCKET], Tasks),
    PrepareTasks =
        find_tasks_by_type(?TASK_TYPE_PREPARED, Tasks),

    NonPrepareTasks ++ PrepareTasks.

cleanup_service(#state{conn = Conn} = State) ->
    Stale = find_stale_tasks(State),
    case Stale of
        [] ->
            State;
        _ ->
            ?log_debug("Cleaning up stale tasks:~n~p", [Stale]),
            ok = cancel_tasks(Conn, Stale),
            NewState = refresh_state(State),
            case find_stale_tasks(NewState) of
                [] ->
                    NewState;
                StillStale ->
                    ?log_error("Failed to cleanup some stale tasks:~n~p",
                               [StillStale]),
                    exit({cleanup_service_failed, StillStale})
            end
    end.

refresh_state(#state{conn = Conn} = State) ->
    Tasks = grab_tasks(Conn),
    Topology = grab_topology(Conn),
    State1 = State#state{tasks = Tasks},
    handle_new_topology(Topology, State1).

grab_tasks(Conn) ->
    grab_tasks(Conn, undefined).

grab_tasks(Conn, Rev) ->
    {ok, Raw} = service_api:get_task_list(Conn, Rev),
    process_service_response(get_task_list, Raw, fun process_tasks/1).

process_tasks({Props}) ->
    Rev = must_get(rev, Props),
    Tasks0 = must_get(tasks, Props),
    Tasks = [begin
                 {TaskProps} = T,
                 TaskProps
             end || T <- Tasks0],
    {Rev, Tasks}.

grab_topology(Conn) ->
    grab_topology(Conn, undefined).

grab_topology(Conn, Rev) ->
    {ok, Raw} = service_api:get_current_topology(Conn, Rev),
    process_service_response(get_current_topology, Raw, fun process_topology/1).

process_topology({Props}) ->
    Rev = must_get(rev, Props),
    Nodes = must_get(nodes, Props),
    IsBalanced = must_get(isBalanced, Props),
    Messages = get_default(messages, Props, []),

    {Rev, #topology{nodes = [],
                    node_uuids = Nodes,
                    is_balanced = IsBalanced,
                    messages = Messages}}.

run_on_task_runner(From, #state{task_runner = TaskRunner,
                                task_runner_queue = Waiters} = State, Body) ->
    Parent = self(),
    NewWaiters = queue:in(From, Waiters),

    work_queue:submit_work(
      TaskRunner,
      fun () ->
              Conn = erlang:get(connection),
              true = is_pid(Conn),

              RV = Body(Conn),
              Parent ! {task_call_reply, RV}
      end),

    {noreply, State#state{task_runner_queue = NewWaiters}}.

start_task_runner() ->
    {ok, Pid} = work_queue:start_link(),
    work_queue:submit_work(Pid, fun task_runner_init/0),
    Pid.

task_runner_init() ->
    receive
        {connection, Conn} ->
            erlang:put(connection, Conn)
    end.

pass_connection(TaskRunner, Conn) ->
    TaskRunner ! {connection, Conn}.

start_long_poll_worker(Conn, Tag, Initial, GrabFun) ->
    true = is_pid(Conn),

    Initial1 =
        case Initial of
            {_, _} ->
                Initial;
            undefined ->
                {undefined, undefined}
        end,

    Agent = self(),
    Worker = proc_lib:spawn_link(
               fun () ->
                       long_poll_worker_loop(Agent, Conn, Tag, Initial1, GrabFun)
               end),

    Worker.

long_poll_worker_loop(Agent, Conn, Tag, {OldRev, OldValue}, GrabFun) ->
    {NewRev, NewValue} = New = GrabFun(Conn, OldRev),
    case NewRev =:= OldRev of
        true ->
            %% assert that values are the same to catch misbehaving services
            %% early
            {true, _, _} = {NewValue =:= OldValue, OldValue, NewValue},
            ok;
        false ->
            Agent ! {Tag, New}
    end,

    long_poll_worker_loop(Agent, Conn, Tag, New, GrabFun).

start_long_poll_workers(#state{tasks = Tasks,
                               topology = Topology} = State) ->
    %% since we resolve node ids into node names in the main process, we
    %% remove them from the initial value passed to the topology long poller;
    %% that way it can assert that whenever revision is the same, the values
    %% also match
    do_start_long_poll_workers(Tasks, cleanup_topology(Topology), State).

do_start_long_poll_workers(Tasks, Topology,
                           #state{conn = Conn,
                                  get_tasks_worker = undefined,
                                  topology_worker = undefined} = State) ->
    GetTasksWorker = start_long_poll_worker(Conn, new_tasks,
                                            Tasks, fun grab_tasks/2),
    TopologyWorker = start_long_poll_worker(Conn, new_topology,
                                            Topology, fun grab_topology/2),
    State#state{get_tasks_worker = GetTasksWorker,
                topology_worker = TopologyWorker}.

cleanup_topology({Rev, Topology}) ->
    {Rev, Topology#topology{nodes = []}}.

terminate_long_poll_workers(#state{get_tasks_worker = GetTasksWorker,
                                   topology_worker = TopologyWorker} = State) ->
    true = (GetTasksWorker =/= undefined),
    true = (TopologyWorker =/= undefined),

    Workers = [TopologyWorker, GetTasksWorker],
    lists:foreach(fun erlang:unlink/1, Workers),
    misc:terminate_and_wait(Workers, kill),

    State#state{get_tasks_worker = undefined,
                topology_worker = undefined}.

restart_long_poll_workers(State) ->
    State1 = terminate_long_poll_workers(State),
    drop_long_poll_messages(),

    %% this makes sure next time we get a message from any of the workers, it
    %% has the most up to date information; but we keep the old values in case
    %% anybody needs them
    do_start_long_poll_workers(undefined, undefined, State1).

drop_long_poll_messages() ->
    receive
        {new_tasks, _} ->
            drop_long_poll_messages();
        {new_topology, _} ->
            drop_long_poll_messages()
    after
        0 ->
            ok
    end.

handle_get_node_info(Conn) ->
    {ok, Raw} = service_api:get_node_info(Conn),
    {ok, process_service_response(get_node_info, Raw, fun process_get_node_info/1)}.

process_get_node_info({Props}) ->
    NodeId = must_get(nodeId, Props),
    Priority = must_get(priority, Props),
    Opaque = must_get(opaque, Props),
    [{node_id, NodeId},
     {priority, Priority},
     {opaque, Opaque}].

handle_prepare_rebalance(Conn, Id, Type, KeepNodes, EjectNodes) ->
    service_api:prepare_topology_change(Conn, Id, undefined, Type, KeepNodes, EjectNodes).

handle_start_rebalance(Conn, Id, Type, KeepNodes, EjectNodes, Agent, Observer) ->
    run_task_and_set_observer(
      ?cut(service_api:start_topology_change(Conn, Id, undefined, Type,
                                             KeepNodes, EjectNodes)),
      Agent, Observer).

handle_prepare_pause_bucket(Conn, Id, Args) ->
    service_api:prepare_pause_bucket(Conn, Id, Args).

handle_pause_bucket(Conn, Id, Args,
                    Agent, Observer) ->
    run_task_and_set_observer(
      ?cut(service_api:pause_bucket(Conn, Id, Args)), Agent, Observer).

handle_prepare_resume_bucket(Conn, Id, Args, DryRun) ->
    service_api:prepare_resume_bucket(Conn, Id, Args, DryRun).

handle_resume_bucket(Conn, Id, Args, DryRun, Agent, Observer) ->
    run_task_and_set_observer(
      ?cut(service_api:resume_bucket(Conn, Id, Args, DryRun)),
      Agent, Observer).

run_task_and_set_observer(Body, Agent, Observer) ->
    RV = Body(),

    case RV of
        ok ->
            Agent ! {set_task_observer, Observer};
        _ ->
            ok
    end,

    RV.

handle_set_task_observer(Observer, State) ->
    State1 = restart_long_poll_workers(State),
    State1#state{task_observer = Observer}.

handle_new_tasks(Tasks, State) ->
    State1 = State#state{tasks = Tasks},
    validate_new_tasks(State1),
    do_handle_new_tasks(State1).

validate_new_tasks(#state{service_manager = undefined} = State) ->
    [] = find_stale_tasks(State);
validate_new_tasks(_) ->
    ok.

get_task_type(Type) when Type =:= rebalance orelse Type =:= failover ->
    ?TASK_TYPE_REBALANCE;
get_task_type(pause_bucket) ->
    ?TASK_TYPE_PAUSE_BUCKET;
get_task_type(Type) when Type =:= dry_run_resume_bucket
                         orelse Type =:= resume_bucket ->
    ?TASK_TYPE_RESUME_BUCKET.

do_handle_new_tasks(#state{task_observer = undefined} = State) ->
    State;
do_handle_new_tasks(#state{task_observer = Observer,
                           type = Type,
                           tasks = {_Rev, Tasks}} = State)
  when is_pid(Observer) ->
    case find_tasks_by_type(get_task_type(Type), Tasks) of
        [] ->
            handle_task_done(Observer, State);
        [Task] ->
            case must_get(status, Task) of
                ?TASK_STATUS_RUNNING ->
                    handle_task_running(Observer, Task, State);
                ?TASK_STATUS_FAILED ->
                    handle_task_failed(Observer, Task, State);
                ?TASK_STATUS_CANNOT_RESUME ->
                    % TASK_STATUS_CANNOT_RESUME can only be received when the
                    % current running task is dry_run_resume_bucket.
                    dry_run_resume_bucket = Type,
                    handle_task_cannot_resume(Observer, State)
            end
    end.

handle_task_done(Observer, State) ->
    report_task_done(Observer),
    State#state{task_observer = undefined}.

report_task_done(Observer) ->
    Observer ! task_done.

handle_task_running(Observer, Task, State) ->
    Progress = must_get(progress, Task),
    report_task_progress(Observer, Progress),
    State.

report_task_progress(Observer, Progress) ->
    Observer ! {task_progress, Progress}.

handle_task_failed(Observer, Task, State) ->
    Error = get_default(errorMessage, Task, <<"unknown">>),
    report_task_failed(Observer, Error),
    handle_unset_service_manager(State).

handle_task_cannot_resume(Observer, State) ->
    report_task_failed(Observer, cannot_resume_bucket),
    handle_unset_service_manager(State).

report_task_failed(Observer, Error) ->
    Observer ! {task_failed, Error}.

handle_new_topology({Rev, Topology}, #state{node_uuid_map = Map} = State) ->
    #topology{node_uuids = UUIDs} = Topology,
    Nodes = lists:filtermap(
              fun (UUID) ->
                      case get_node_by_uuid(UUID, Map) of
                          {ok, Node} ->
                              {true, Node};
                          error ->
                              ?log_warning("Can't find matching node for uuid ~p",
                                           [UUID]),
                              false
                      end
              end, UUIDs),

    Topology1 = Topology#topology{nodes = lists:sort(Nodes)},
    report_new_topology(State, Nodes),

    State#state{topology = {Rev, Topology1}}.

report_new_topology(#state{type = rebalance, task_observer = Observer},
                    Nodes) when Observer =/= undefined ->
    Observer ! {new_topology, Nodes};
report_new_topology(_, _) ->
    ok.

process_service_response(Name, Raw, Fun) ->
    try
        Fun(Raw)
    catch
        T:E:S ->
            ?log_error("Error while processing response to ~p: ~p~n~p",
                       [Name, {T, E, S}, Raw])
    end.

handle_multicall_result(Service, Call, Result) ->
    handle_multicall_result(Service, Call, Result, fun extract_ok_responses/1).

handle_multicall_result(Service, Call, {Good, Bad}, OkFun) ->
    case Bad of
        [] ->
            OkFun(Good);
        _ ->
            process_bad_results(Service, Call, Bad)
    end.

is_good_result(ok) ->
    true;
is_good_result({ok, _}) ->
    true;
is_good_result(_) ->
    false.

just_ok(_) ->
    ok.

extract_ok_responses(Replies) ->
    ActualReplies =
        [begin
             {ok, ActualRV} = RV,
             {N, ActualRV}
         end || {N, RV} <- Replies],
    {ok, ActualReplies}.

process_bad_results(Service, Call, Bad) ->
    ?log_error("Service call ~p (service ~p) failed on some nodes:~n~p",
               [Call, Service, Bad]),
    {error, {bad_nodes, Service, Call, Bad}}.

config_event_handler({{node, _, uuid}, _} = Event, Agent) ->
    gen_server:cast(Agent, {config_event, Event}),
    Agent;
config_event_handler(_, Agent) ->
    Agent.

build_node_uuid_map(Config) ->
    ns_config:fold(
      fun (Key, Value, Acc) ->
              case Key of
                  {node, Node, uuid} ->
                      add_node_uuid_mapping(Node, Value, Acc);
                  _ ->
                      Acc
              end
      end, dict:new(), Config).

add_node_uuid_mapping(Node, UUID, Map) ->
    Map1 = erase_node_uuid_mapping(Node, Map),
    Map2 = dict:store({uuid, UUID}, Node, Map1),
    dict:store({node, Node}, UUID, Map2).

erase_node_uuid_mapping(Node, Map) ->
    Map1 = case get_uuid_by_node(Node, Map) of
               {ok, UUID} ->
                   dict:erase({uuid, UUID}, Map);
               error ->
                   Map
           end,
    dict:erase({node, Node}, Map1).

get_uuid_by_node(Node, Map) ->
    dict:find({node, Node}, Map).

get_node_by_uuid(UUID, Map) ->
    dict:find({uuid, UUID}, Map).

needs_rebalance(_Service, #topology{is_balanced = false}) ->
    true;
needs_rebalance(Service, #topology{nodes = Nodes}) ->
    ServiceNodes = ns_cluster_membership:service_active_nodes(Service),
    lists:sort(ServiceNodes) =/= Nodes.

is_noproc({_Node, {exit, {noproc, _}}}) ->
    true;
is_noproc(_) ->
    false.

multi_call(Nodes, Service, Request, Timeout) ->
    misc:multi_call(Nodes, server_name(Service),
                    Request, Timeout, fun is_good_result/1).
