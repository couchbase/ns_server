%% @author Couchbase <info@couchbase.com>
%% @copyright 2023-Present Couchbase, Inc.
%%
%% Use of this software is governed by the Business Source License included in
%% the file licenses/BSL-Couchbase.txt.  As of the Change Date specified in that
%% file, in accordance with the Business Source License, use of this software
%% will be governed by the Apache License, Version 2.0, included in the file
%% licenses/APL2.txt.
-module(global_tasks).

-behaviour(gen_server2).

-include("ns_common.hrl").
-include("cut.hrl").

-ifdef(TEST).
-include_lib("eunit/include/eunit.hrl").
-endif.

-export([start_link/0]).
-export([init/0, handle_info/2]).
-export([get_status_uri/1, get_tasks/1, get_default_tasks/0, update_task/4,
         update_task/5]).
-export([task_id/1, type/1, status/1, source_node/1, timestamp/1, bucket/1,
         bucket_uuid/1, extras/1]).

-define(SERVER, ?MODULE).

%% 60 seconds between cleanups
-define(CLEANUP_INTERVAL_MS, ?get_timeout(cleanup_interval_ms, 60000)).
%% 10 minutes before cleaning up a task without a defined expiry period
-define(DEFAULT_EXPIRY_PERIOD_S, ?get_timeout(default_expiry_period_s, 600)).

%% When adding a new task type, include it in both task_type() and ?TYPES, to
%% ensure that appropriate tests are ran
-type(task_type() :: loadingSampleBucket).
-define(TYPES, [loadingSampleBucket]).

%% When adding a new task status, include it in both status() and ?STATUSES, to
%% ensure that appropriate tests are ran
-type(status() :: queued | running | completed | failed).
-define(STATUSES, [queued, running, completed, failed]).

-type(task() :: [{atom(), atom() | binary() | integer() | extras()}]).
-type(extras() :: [{atom(), any()}]).

-type(task_json() :: [{task_id, binary()} |
                      {type, task_type()} |
                      {status, status()} |
                      {timestamp, integer()} |
                      {bucket, binary()} |
                      {bucket_uuid, binary()} |
                      {extras, extras()}
                     ]).

-export_type([task_type/0, status/0, task/0, extras/0]).

-record(state, {}).

-spec get_status_uri(binary()) -> binary().
get_status_uri(TaskId) ->
    list_to_binary("/pools/default/tasks?taskId=" ++ binary_to_list(TaskId)).

%% The default tasks list which will be retrieved when no filter is provided
%% As we add tasks from ns_heart, we will need to update this filter to keep
%% the /pools/default/tasks backwards compatible
-spec get_default_tasks() -> [task_json()].
get_default_tasks() ->
    get_tasks(
      fun (Task) ->
              status(Task) =:= running
      end).

%% Get the list of tasks, either filtering by task id or by an arbitrary filter
%% If chronicle can't find the tasks list, returns []
-spec get_tasks([binary()] | fun ((task()) -> boolean())) ->
          [task_json()] | {error, any()}.
get_tasks(TaskIds) when is_list(TaskIds) ->
    get_tasks(fun (Task) ->
                      lists:member(task_id(Task), TaskIds)
              end);
get_tasks(Filter) when is_function(Filter, 1) ->
    case cluster_compat_mode:is_cluster_elixir() of
        true ->
            case chronicle_compat:get(tasks, #{}) of
                {ok, Tasks} ->
                    lists:map(format_task(_), lists:filter(Filter, Tasks));
                {error, not_found} ->
                    ?log_warning("Missing tasks list. Assuming no tasks exist"),
                    [];
                {error, Reason} = Error ->
                    ?log_error("Failed to get tasks list. Error: ~p",
                               [Reason]),
                    Error
            end;
        false ->
            []
    end.


%% update_task replaces an existing task status for TaskId or creates a new one
%%
%% - TaskId should be a unique binary string to identify the task
%% - Type is the category that a task falls in. The Type should not change for
%%   statuses of a specific TaskId
%% - Status denotes the current state of the task
%% - Bucket is an optional property for associating a task with a bucket UUID
%% - Extras should be a list of {atom(), binary()}, in order to be consistently
%%   converted to json when returned by /pools/default/tasks?taskId={task_id}
%%   Extras should only be used when absolutely necessary, and when we know it
%%   will have a bounded size, as we do not want to have large tasks
-spec update_task(binary(), task_type(), status(), string() | undefined,
                  extras()) -> ok.
update_task(TaskId, Type, Status, Bucket, Extras) ->
    case cluster_compat_mode:is_cluster_elixir() of
        true ->
            Keys = [tasks] ++
                case Bucket of
                    undefined -> [];
                    _ -> [{bucket, Bucket, uuid}]
                end,
            Result =
                chronicle_compat:transaction(
                  Keys,
                  fun (Snapshot) ->
                          Tasks = chronicle_compat:get(Snapshot, tasks,
                                                       #{required => true}),
                          NewTasks = replace_task(
                                       Tasks,
                                       build_task(Snapshot, TaskId, Type,
                                                  Status, Bucket, Extras)),
                          {commit, [{set, tasks, NewTasks}]}
                  end),
            case Result of
                {ok, _} ->
                    ok;
                Error ->
                    ?log_error("Failed to update task ~p. Error: ~p",
                               [TaskId, Error]),
                    erlang:throw(Error)
            end;
        false ->
            ok
    end.

-spec update_task(binary(), task_type(), status(), extras()) -> any().
update_task(TaskId, Type, Status, Extras) ->
    update_task(TaskId, Type, Status, undefined, Extras).


%%%===================================================================
%%% Spawning and gen_server implementation
%%%===================================================================

start_link() ->
    proc_lib:start_link(?MODULE, init, []).

init() ->
    register(?SERVER, self()),
    proc_lib:init_ack({ok, self()}),
    initialise_tasks(),
    erlang:send_after(?CLEANUP_INTERVAL_MS, self(), cleanup),
    gen_server:enter_loop(?MODULE, [], #state{}).


handle_info(cleanup, State) ->
    cleanup_tasks(),
    erlang:send_after(?CLEANUP_INTERVAL_MS, self(), cleanup),
    {noreply, State};

handle_info(_Info, State = #state{}) ->
    {noreply, State}.

%%%===================================================================
%%% Internal functions
%%%===================================================================

initialise_tasks() ->
    Result = chronicle_compat:transaction(
               [tasks],
               fun (Snapshot) ->
                       case chronicle_compat:get(Snapshot, tasks, #{}) of
                           {ok, _} ->
                               %% Tasks list already exists
                               {commit, []};
                           {error, not_found} ->
                               %% Create an empty tasks list
                               {commit, [{set, tasks, []}]};
                           {error, _} = Error ->
                               {abort, Error}
                       end
               end),
    case Result of
        {ok, _} ->
            ok;
        Error ->
            ?log_error("Failed to initialise global tasks. Error: ~p", [Error]),
            exit(Error)
    end.

task_id(Task) ->
    proplists:get_value(task_id, Task).

type(Task) ->
    proplists:get_value(type, Task).

status(Task) ->
    proplists:get_value(status, Task).

source_node(Task) ->
    proplists:get_value(source_node, Task).

timestamp(Task) ->
    proplists:get_value(timestamp, Task).

bucket(Task) ->
    proplists:get_value(bucket, Task, undefined).

bucket_uuid(Task) ->
    proplists:get_value(bucket_uuid, Task).

extras(Task) ->
    proplists:get_value(extras, Task).

-spec format_task(task()) -> task_json().
format_task(Task) ->
    BaseProps = [task_id, type, status, extras],
    BucketProps =
        case bucket(Task) of
            undefined -> [];
            _Bucket -> [bucket, bucket_uuid]
        end,

    lists:map(
      fun (Property) ->
              Value = proplists:get_value(Property, Task),
              FormattedValue =
                  case Property of
                      bucket -> list_to_binary(Value);
                      extras -> {Value};
                      _ -> Value
                  end,
              {Property, FormattedValue}
      end, BaseProps ++ BucketProps).

-spec build_task(map(), binary(), task_type(), status(), string(), extras()) ->
          task().
build_task(Snapshot, TaskId, Type, Status, Bucket, Extras) ->
    [{task_id, TaskId},
     {type, Type},
     {status, Status},
     {source_node, node()},
     {timestamp, now_secs()}] ++
        case Bucket of
            undefined ->
                [];
            Bucket when is_list(Bucket) ->
                [{bucket, Bucket},
                 {bucket_uuid, ns_bucket:uuid(Bucket, Snapshot)}]
        end
        ++ [{extras, Extras}].

-spec replace_task([task()], task()) -> [task()].
replace_task(Tasks, NewTask) ->
    [NewTask | lists:filter(
                 fun (Task) ->
                         task_id(Task) =/= task_id(NewTask)
                 end, Tasks)].

%% Expiry period of a task status in seconds
-spec get_expiry_period(task()) -> integer().
get_expiry_period(Task) ->
    ConfigKey = {type(Task), status(Task)},
    ExpiryTime =
        case ConfigKey of
            {loadingSampleBucket, queued} ->
                %% 1 hour
                3600;
            {loadingSampleBucket, running} ->
                %% 1 hour
                3600;
            {loadingSampleBucket, completed} ->
                %% 10 minutes
                600;
            {loadingSampleBucket, failed} ->
                %% 10 minutes
                600;
            _ ->
                ?DEFAULT_EXPIRY_PERIOD_S
        end,
    %% All expiry periods should be configurable at run time, including those
    %% using the default expiry period
    ?get_timeout(ConfigKey, ExpiryTime).

cleanup_tasks() ->
    BucketUUIDKeys = lists:map(ns_bucket:sub_key(_, uuid),
                               ns_bucket:get_bucket_names()),
    %% We check and update in a transaction to avoid a status being updated
    %% after being added to a list of statuses to delete, but before the
    %% deletion has occurred, causing the deletion of the updated status
    Result = chronicle_compat:transaction([tasks | BucketUUIDKeys],
                                          do_cleanup(_)),
    case Result of
        {ok, _} ->
            ok;
        Error ->
            ?log_error("Failed to cleanup global tasks. Error: ~p", [Error])
    end.

-spec do_cleanup(map()) ->
          {commit, [{set, tasks, [task()]}]} | {abort, {error, any()}}.
do_cleanup(Snapshot) ->
    case chronicle_compat:get(Snapshot, tasks, #{}) of
        {ok, Tasks} ->
            NewTasks = lists:filter(should_keep_task(Snapshot, _), Tasks),
            case NewTasks =:= Tasks of
                true ->
                    {commit, []};
                false ->
                    {commit, [{set, tasks, NewTasks}]}
            end;
        {error, _} = Error ->
            {abort, Error}
    end.

-spec should_keep_task(map(), task()) -> boolean().
should_keep_task(Snapshot, Task) ->
    Checks = cleanup_checks() ++
        case bucket(Task) of
            undefined ->
                [];
            BucketName ->
                [bucket_missing(Snapshot, BucketName, _)]
        end,
    case functools:alternative(Task, Checks) of
        {ok, Reason} ->
            ?log_debug("Cleaning up task (~s):~n~p", [Reason, Task]),
            false;
        false ->
            true
    end.

%% Checks for cleaning up tasks that are no longer relevant
cleanup_checks() ->
    [task_expired(_),
     node_missing(_)].

-spec task_expired(task()) -> false | {ok, binary()}.
task_expired(Task) ->
    ExpiryTime = timestamp(Task) + get_expiry_period(Task),
    case now_secs() > ExpiryTime of
        true ->
            {ok, <<"expired">>};
        false ->
            false
    end.

-spec node_missing(task()) -> false | {ok, binary()}.
node_missing(Task) ->
    Node = source_node(Task),
    case lists:member(Node, ns_cluster_membership:nodes_wanted()) of
        true ->
            false;
        false ->
            {ok, <<"node missing">>}
    end.

%% If the bucket existed when the status was generated, a bucket_uuid would have
%% been stored. If the bucket no longer exists or no longer has this UUID, then
%% the bucket that the status is associated with is missing, so we can clean it
%% up.
%% The only concern is that a status may be missed if the bucket is deleted
%% immediately after the status was created.
-spec bucket_missing(map(), string(), task()) -> false | {ok, binary()}.
bucket_missing(Snapshot, BucketName, Task) ->
    OldUUID = bucket_uuid(Task),
    NewUUID = ns_bucket:uuid(BucketName, Snapshot),
    case {OldUUID, NewUUID} of
        {_, OldUUID} -> false;
        {not_present, _} -> false;
        _ -> {ok, <<"bucket missing">>}
    end.

-spec now_secs() -> integer().
now_secs() ->
    erlang:system_time(second).

-ifdef(TEST).
modules() ->
    [chronicle_compat, ns_cluster_membership, cluster_compat_mode, ns_config].

setup() ->
    meck:new(modules(), [passthrough]),
    meck:expect(cluster_compat_mode, is_cluster_elixir, fun () -> true end).

teardown(_) ->
    meck:unload(modules()).

-define(BUCKETS, [undefined, "default"]).
-define(EXTRAS, [[], [{test, <<"test">>}]]).
-define(SNAPSHOT, #{{bucket, "default", uuid} => {<<"test">>, 0}}).

%% Generate tasks of all possible type and status, and for each of those
%% configurations, also generate one with/without a bucket, and with/without a
%% key in the extras field.
%% Doesn't generate specific values for task_id, timestamp, or source_node,
%% which are determined as normal
-spec generate_tasks() -> [task()].
generate_tasks() ->
    lists:append(
      [lists:append(
         [lists:append(
            [[build_task(?SNAPSHOT, misc:uuid_v4(), Type, Status, Bucket,
                         Extras)
              || Type <- ?TYPES]
             || Status <- ?STATUSES])
          || Bucket <- ?BUCKETS])
       || Extras <- ?EXTRAS]).

%% Generate a cleanup candidate for each task, for each possible cleanup reason
-spec generate_all_expired_tasks([task()]) -> [task()].
generate_all_expired_tasks(Tasks) ->
    lists:append(lists:map(generate_expired_tasks(_), Tasks)).

%% Generate cleanup candidates for the task, for each possible cleanup reason
-spec generate_expired_tasks(task()) -> [task()].
generate_expired_tasks(Task) ->
    [%% time based expiry. Assumes that time won't jump 1 second back between
     %% now and the cleanup
     lists:keyreplace(timestamp, 1, Task,
                      {timestamp, now_secs() - get_expiry_period(Task) - 1000}),

     %% node missing
     lists:keyreplace(source_node, 1, Task, {source_node, other_node})
    ] ++
        %% bucket missing
        case bucket(Task) of
            undefined -> [];
            _ -> [lists:keyreplace(bucket_uuid, 1, Task,
                                   {bucket_uuid, <<"other uuid">>})]
        end.

%% Since lists would get truncated in the eunit output if we called ?assertEqual
%% opn the lists themselves, we instead have to assert that each pair of terms
%% in the lists are equal
-spec assert_lists_equal(list(), list()) -> ok.
assert_lists_equal(ExpectedList, ActualList) ->
    lists:foreach(fun ({Expected, Actual}) ->
                          ?assertEqual(Expected, Actual)
                  end,
                  lists:zip(lists:sort(ExpectedList), lists:sort(ActualList))).

cleanup_test__() ->
    meck:expect(chronicle_compat, get_snapshot,
                fun (_, _) ->
                        #{}
                end),
    meck:expect(ns_cluster_membership, nodes_wanted,
                fun () ->
                        [node()]
                end),
    meck:expect(ns_config, get_timeout,
                fun (_, Default) ->
                        Default
                end),
    TasksToKeep = generate_tasks(),
    TasksToRemove = generate_all_expired_tasks(TasksToKeep),
    Snapshot = ?SNAPSHOT#{tasks => {TasksToRemove ++ TasksToKeep, 0}},
    {commit, [{set, tasks, NewTasks}]} = do_cleanup(Snapshot),
    assert_lists_equal(TasksToKeep, NewTasks).

get_tasks_test__() ->
    Tasks = generate_tasks(),

    meck:expect(chronicle_compat, get,
                fun (_, _) ->
                        {ok, Tasks}
                end),

    %% Fetch all tasks, by task_id
    TaskIds = lists:map(task_id(_), Tasks),
    FetchedTasks = get_tasks(TaskIds),

    %% The fetched tasks should be formatted, for correct json encoding by ejson
    ExpectedTasks = lists:map(fun (Task) -> format_task(Task) end, Tasks),
    assert_lists_equal(ExpectedTasks, FetchedTasks),

    %% The list of tasks will be converted as follows in menelaus_web_misc, in
    %% order for ejson to encode the whole list together
    JSONTasks = [{Task} || Task <- FetchedTasks],

    %% Confirm that the final tasks list can be converted to json
    ejson:encode(JSONTasks),

    meck:expect(cluster_compat_mode, is_cluster_elixir, fun () -> false end),

    %% Confirm that get_tasks/1 returns [] for mixed version clusters
    ?assertEqual([], get_tasks(TaskIds)).

get_default_tasks_test__() ->
    Tasks = generate_tasks(),
    %% For now we only care about running tasks. As we move more tasks out from
    %% the heartbeat, we will need to update this test to match the previous
    %% behaviour
    DefaultTasks = lists:filter(
                     fun (Task) ->
                             status(Task) =:= running
                     end, Tasks),

    meck:expect(chronicle_compat, get,
                fun (_, _) ->
                        {ok, Tasks}
                end),

    %% Fetch the default list of tasks
    FetchedTasks = get_default_tasks(),

    %% The fetched tasks should be formatted, for correct json encoding by ejson
    ExpectedTasks = lists:map(fun (Task) -> format_task(Task) end, DefaultTasks),
    assert_lists_equal(ExpectedTasks, FetchedTasks),

    %% The list of tasks will be converted as follows in menelaus_web_misc, in
    %% order for ejson to encode the whole list together
    JSONTasks = [{Task} || Task <- FetchedTasks],

    %% Confirm that the final tasks list can be converted to json
    ejson:encode(JSONTasks),

    meck:expect(cluster_compat_mode, is_cluster_elixir, fun () -> false end),

    %% Confirm that get_default_tasks/0 returns [] for mixed version clusters
    ?assertEqual([], get_default_tasks()).

%% Generate a new task which is the same as Task, except for the status
-spec generate_task_update(task()) -> task().
generate_task_update(Task) ->
    OldStatus = status(Task),
    %% Generate a new, different status
    Status = hd(?STATUSES -- [OldStatus]),
    lists:keyreplace(status, 1, Task, {status, Status}).

%% Instead of somehow starting up chronicle in the unit test, we replace the
%% transaction call with one which checks that each new Task gets added to the
%% tasks list.
-spec assert_update_tasks(map(), [task()]) -> ok.
assert_update_tasks(Tasks, Transaction) ->
    meck:expect(chronicle_compat, transaction, Transaction),
    Return =
        lists:foreach(
          fun (Task) ->
                  update_task(task_id(Task), type(Task), status(Task),
                              bucket(Task), extras(Task))
          end, Tasks),
    ?assertEqual(ok, Return).

%% Pretend to be a chronicle transaction, and check that the modified task is
%% modified as expected
-spec fake_transaction(map(), [task()], _, fun((map()) -> {commit, list()})) ->
          {ok, any()}.
fake_transaction(Snapshot, ExpectedTasks, _, Fun) ->
    case Fun(Snapshot) of
        {commit, [{set, tasks, [NewTask | _]}]} ->
            TaskId = task_id(NewTask),
            [ExpectedTask] =
                lists:filter(
                  fun (Task1) ->
                          task_id(Task1) =:= TaskId
                  end, ExpectedTasks),

            %% Since we cannot predict what time the task was added, we have to
            %% ignore the timestamp when checking it was correctly updated
            ExpectedTaskWithoutTime = proplists:delete(timestamp, ExpectedTask),
            NewTaskWithoutTime = proplists:delete(timestamp, NewTask),

            ?assertEqual(ExpectedTaskWithoutTime, NewTaskWithoutTime),
            {ok, 0};
        Action ->
            ?assert(true, {unexpected_action, Action})
    end.

update_task_test__() ->
    Snapshot0 = ?SNAPSHOT#{tasks => {[], 0}},
    Tasks = generate_tasks(),

    %% Test that new tasks can be added
    Transaction0 = fake_transaction(Snapshot0, Tasks, _, _),
    assert_update_tasks(Tasks, Transaction0),

    %% Generate an updated task with a new status, for each existing task
    Snapshot1 = Snapshot0#{tasks => {Tasks, 0}},
    TaskUpdates = [generate_task_update(Task) || Task <- Tasks],

    %% Test that current tasks can be updated
    Transaction1 = fake_transaction(Snapshot1, TaskUpdates, _, _),
    assert_update_tasks(TaskUpdates, Transaction1),

    meck:expect(cluster_compat_mode, is_cluster_elixir, fun () -> false end),

    %% Confirm that update_task/5 returns ok for mixed version clusters
    Transaction2 = fun (_, _) -> error end,  %% The transaction shouldn't run
    assert_update_tasks(Tasks, Transaction2).

all_test_() ->
    {foreach, fun setup/0, fun teardown/1,
     [fun cleanup_test__/0,
      fun get_tasks_test__/0,
      fun get_default_tasks_test__/0,
      fun update_task_test__/0]}.
-endif.
