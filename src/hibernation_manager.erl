%% @author Couchbase <info@couchbase.com>
%% @copyright 2022-Present Couchbase, Inc.
%%
%% Use of this software is governed by the Business Source License included in
%% the file licenses/BSL-Couchbase.txt.  As of the Change Date specified in that
%% file, in accordance with the Business Source License, use of this software
%% will be governed by the Apache License, Version 2.0, included in the file
%% licenses/APL2.txt.

-module(hibernation_manager).

-include("ns_common.hrl").
-include("cut.hrl").

-ifdef(TEST).
-include_lib("eunit/include/eunit.hrl").
-endif.

%% TODO: These default timeouts are a function of the blobStorage
%% upload/download speeds and the size of the data - therefore needs
%% re-evaluation.

-define(PAUSE_BUCKET_TIMEOUT,
        ?get_timeout(pause_bucket, infinity)).

-define(RESUME_BUCKET_TIMEOUT,
        ?get_timeout(resume_bucket, infinity)).

-define(RESUME_BUCKET_DRY_RUN_TIMEOUT,
        ?get_timeout({dry_run, resume_bucket}, 5 * 60 * 1000)).

-export([pause_bucket/2,
         resume_bucket/2]).

-type supported_services() ::  index | fts.

-spec build_remote_path(
        For :: kv | supported_services(),
        RemotePath :: string()) -> string().
build_remote_path(For, RemotePath) ->
    filename:join(RemotePath, atom_to_list(For)).

-spec register_worker(For :: kv | supported_services()) -> true.
register_worker(For) ->
    WorkerName = list_to_atom(?MODULE_STRING ++ "-worker-" ++
                              atom_to_list(For)),
    erlang:register(WorkerName, self()).

supported_services() ->
    [index, fts].

build_service_workers_params(RemotePath) ->
    [{Service, ns_cluster_membership:service_active_nodes(Service),
      build_remote_path(Service, RemotePath)}
     || Service <- supported_services()].

build_kv_worker_params(Bucket, RemotePath) ->
    {kv, ns_bucket:live_bucket_nodes(Bucket),
     build_remote_path(kv, RemotePath)}.

build_workers_params(Bucket, RemotePath) ->
    [build_kv_worker_params(Bucket, RemotePath) |
     build_service_workers_params(RemotePath)].

pause_bucket(Bucket, RemotePath) ->
    spawn_link_hibernation_manager(
      pause_bucket, ?cut(do_pause_bucket(Bucket, RemotePath))).

resume_bucket(Bucket, RemotePath) ->
    spawn_link_hibernation_manager(
      resume_bucket, ?cut(do_resume_bucket(Bucket, RemotePath))).

spawn_link_hibernation_manager(Op, Body) ->
    proc_lib:spawn_link(
      fun () ->
              leader_activities:run_activity(
                Op, majority,
                fun () ->
                        leader_registry:register_name(?MODULE, self()),
                        Body()
                end)
      end).

do_pause_bucket(Bucket, RemotePath) ->
    WorkersParams = build_workers_params(Bucket, RemotePath),

    KVNodes = ns_bucket:live_bucket_nodes(Bucket),

    ok = kv_hibernation_agent:prepare_pause_bucket(Bucket, KVNodes, self()),

    ok = hibernation_utils:run_hibernation_op(
           fun ({For, Nodes, RP}) ->
                   register_worker(For),
                   pause_bucket_body(
                     For, Bucket, RP, Nodes)
           end, WorkersParams, ?PAUSE_BUCKET_TIMEOUT),

    kv_hibernation_agent:unprepare_pause_bucket(Bucket, KVNodes).

-spec pause_bucket_body(For, Bucket, RemotePath, Nodes) -> ok
    when For :: kv | supported_services(),
         Bucket :: bucket_name(),
         RemotePath :: string(),
         Nodes :: [node()].
pause_bucket_body(For, Bucket, RemotePath, Nodes) ->
    ProgressCallback = fun (_) -> ok end,

    service_manager:with_trap_exit_spawn_monitor_pause_bucket(
      For, Bucket, RemotePath, Nodes, ProgressCallback, #{}).

do_resume_bucket(Bucket, RemotePath) ->
    WorkersParams = build_workers_params(Bucket, RemotePath),

    %% Resume is performed in 2 stages.
    %%
    %% 1. dry_run phase: Services download
    %% bucket meta-data from the BlobStorage and evaluate if it is possible to
    %% resume the given bucket on the current cluster. If we get an ok from all
    %% the services we move on to the actual resume else the resume operation
    %% is aborted.
    %%
    %% 2. Actual resume: Services download bucket data (indexes etc) from the
    %% BlobStorage and send us ok - if any one of the Services fails, the
    %% entire Resume operation is aborted.

    ok = hibernation_utils:run_hibernation_op(
           fun ({For, Nodes, RP}) ->
                   register_worker(For),
                   resume_bucket_body(
                     For, Bucket, RP, true, Nodes)
           end, WorkersParams, ?RESUME_BUCKET_DRY_RUN_TIMEOUT),

    ok = hibernation_utils:run_hibernation_op(
           fun ({For, Nodes, RP}) ->
                   register_worker(For),
                   resume_bucket_body(
                     For, Bucket, RP, false, Nodes)
           end, WorkersParams, ?RESUME_BUCKET_TIMEOUT).

-spec resume_bucket_body(For, Bucket, RemotePath, DryRun, Nodes) -> ok
    when For :: kv | supported_services(),
         Bucket :: bucket_name(),
         RemotePath :: string(),
         DryRun :: true | false,
         Nodes :: [node()].
resume_bucket_body(For, Bucket, RemotePath, DryRun, Nodes) ->
    ProgressCallback = fun (_) -> ok end,

    service_manager:with_trap_exit_spawn_monitor_resume_bucket(
      For, Bucket, RemotePath, DryRun, Nodes, ProgressCallback, #{}).

-ifdef(TEST).

meck_base_modules() ->
    [ns_cluster_membership, ns_config, ns_bucket, kv_hibernation_agent,
     service_manager].

meck_expect_base() ->
    meck:new(meck_base_modules(), [passthrough]),

    meck:expect(ns_cluster_membership,
                service_active_nodes,
                fun (_) ->
                       [node_a, node_b]
                end),
    meck:expect(ns_config, get_timeout,
                fun (_, Default) ->
                        Default
                end),
    meck:expect(ns_bucket, live_bucket_nodes,
                fun (_) ->
                        [node_a, node_b]
                end),
    meck:expect(ns_bucket, update_bucket_props,
                fun (_, _) ->
                        ok
                end),
    meck:expect(kv_hibernation_agent, prepare_pause_bucket,
                fun (_, _, _) ->
                        ok
                end),
    meck:expect(kv_hibernation_agent, unprepare_pause_bucket,
                fun (_, _) ->
                        ok
                end).

hibernation_op_success() ->
    timer:sleep(100 + rand:uniform(100)),
    ok.

hibernation_op_fail(Service) ->
    case Service of
        kv ->
            timer:sleep(100 + rand:uniform(100)),
            exit(not_ok);
        indexer ->
            timer:sleep(500);
        fts ->
            timer:sleep(rand:uniform(200)),
            exit(not_ok)
    end.

run_test_and_assert(TestBody, SuccessTag, FailureTag) ->
    0 = ?flush(_),
    Parent = self(),

    erlang:spawn(
      fun () ->
              erlang:process_flag(trap_exit, true),
              Manager =
                  erlang:spawn_link(TestBody),

              receive
                  {'EXIT', Manager, Reason} ->
                      case Reason of
                          normal ->
                              Parent ! {test_result, exit_normal};
                          _ ->
                              Parent ! {test_result, exit_not_normal}
                      end
              end
      end),

    TestSuccess =
        receive
            {test_result, SuccessTag} ->
                true;
            {test_result, FailureTag} ->
                false
        after
            1500 ->
                ?flush({test_result, _}),
                false
        end,

    ?assertEqual(TestSuccess, true),
    0 = ?flush(_).

hibernation_manager_test() ->
    {foreach,
     fun meck_expect_base/0,
     fun () ->
             meck:unload(meck_base_modules())
     end,
     [{"Pause Bucket Success",
       fun () ->
               meck:expect(service_manager,
                           with_trap_exit_spawn_monitor_pause_bucket,
                           fun (_Service, _Bucket, _RemotePath, _Nodes,
                                _ProgressCallback, _Opts) ->
                                   hibernation_op_success()
                           end),

               run_test_and_assert(
                 ?cut(do_pause_bucket("foo", "foo-remote-path")),
                 exit_normal, exit_not_normal)
       end
       },
      {"Pause Bucket Failure",
       fun () ->
               meck:expect(service_manager,
                           with_trap_exit_spawn_monitor_pause_bucket,
                           fun (Service, _Bucket, _RemotePath, _Nodes,
                                _ProgressCallback, _Opts) ->
                                   hibernation_op_fail(Service)
                           end),

               run_test_and_assert(
                 ?cut(do_pause_bucket("foo", "foo-remote-path")),
                 exit_not_normal, exit_normal)
       end},
      {"Resume Bucket Success",
       fun () ->
              meck:expect(service_manager,
                          with_trap_exit_spawn_monitor_resume_bucket,
                          fun (_Service, _Bucket, _RemotePath, _DryRun, _Nodes,
                               _ProgressCallback, _Opts) ->
                                  hibernation_op_success()
                          end),

              run_test_and_assert(
                ?cut(do_resume_bucket("foo", "foo-remote-path")),
                exit_normal, exit_not_normal)
      end},
      {"Resume Bucket Failure",
       fun () ->
              meck:expect(service_manager,
                          with_trap_exit_spawn_monitor_resume_bucket,
                          fun (Service, _Bucket, _RemotePath, _DryRun, _Nodes,
                               _ProgressCallback, _Opts) ->
                                  hibernation_op_fail(Service)
                          end),

              run_test_and_assert(
                ?cut(do_resume_bucket("foo", "foo-remote-path")),
                exit_not_normal, exit_normal)
      end}]}.
-endif.
