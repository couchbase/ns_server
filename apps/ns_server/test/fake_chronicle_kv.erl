%% @author Couchbase, Inc <info@couchbase.com>
%% @copyright 2023-Present Couchbase, Inc.
%%
%% Use of this software is governed by the Business Source License included in
%% the file licenses/BSL-Couchbase.txt.  As of the Change Date specified in that
%% file, in accordance with the Business Source License, use of this software
%% will be governed by the Apache License, Version 2.0, included in the file
%% licenses/APL2.txt.
%%
%% @doc A module that pretends to be chronicle_kv via meck which allows us to
%% test code paths that need to interact with chronicle_kv without mocking
%% all of the functions in each test.
%%
%% Two approaches could have been taken to solve this problem:
%%     1) Mocking chronicle_kv
%%     2) Starting chronicle up properly
%% This module takes approach 1 as starting chronicle isn't necessarily
%% trivial due to the extra features that chronicle has (i.e. writing to
%% files and replicating config).
%%
%% Each chronicle_kv rsm (kv and metakv) has its own snapshot, stored as a map
%% in an ets table element, and its own event manager, as in chronicle. The name
%% passed to each chronicle_kv call picks the rsm.
%%
%% This helper is minimal, it was written to solve an issue for a specific
%% test, so the chronicle_kv interface that has been implemented may not be
%% complete. Hopefully the relative simplicity of the snapshot and functions
%% here allows future users to simply add the additional interface functions
%% required.
%%
%% The module supports concurrent writers via compare and swap
%% (ets:select_replace). All operations that modify the snapshot will be retried
%% til their modification is applied successfully.
%%
%% Use should be as follows:
%%     1) fake_chronicle_kv:setup(),
%%     2a) Merge a map into the kv snapshot
%%         fake_chronicle_kv:update_snapshot(#{}),
%%     2b) Upsert an individual key value pair to the kv snapshot
%%         fake_chronicle_kv:update_snapshot(auto_failover_cfg, []),
%%     3) Perform test
%%     4) fake_chronicle_kv:teardown(),
-module(fake_chronicle_kv).

-include("ns_test.hrl").

%% Needed for ets:fun2ms/1
-include_lib("stdlib/include/ms_transform.hrl").

%% API
-export([setup/0,
         teardown/0,
         update_snapshot/1,
         update_snapshot/2,
         get_ets_snapshot/0]).

%% Helper function API
-export([setup_cluster_compat_version/1]).

-define(TABLE_NAME, fake_chronicle_kv).
-define(FAKE_HISTORY_REV, <<"fake">>).
-define(RSMS, [kv, metakv]).

%% --------------------
%% API - Setup/Teardown
%% --------------------
setup() ->
    ets:new(?TABLE_NAME, [set, public, named_table]),
    lists:foreach(
      fun(Name) ->
              ets:insert(?TABLE_NAME, {{snapshot, Name}, #{seqno => 0}})
      end, ?RSMS),

    meck_setup(),

    fake_ns_config:setup_ns_config_events(),

    lists:foreach(
      fun(Name) ->
              {ok, _} =
                  gen_event:start_link(
                    {local, chronicle_kv:event_manager(Name)})
      end,
      ?RSMS),
    {ok, _} = chronicle_compat_events:start_link().

teardown() ->
    ets:delete(?TABLE_NAME),

    Pid = whereis(chronicle_compat_events),
    unlink(Pid),
    misc:terminate_and_wait(Pid, shutdown),

    lists:foreach(
      fun (Name) ->
              P = whereis(chronicle_kv:event_manager(Name)),
              unlink(P),
              misc:terminate_and_wait(P, shutdown)
      end, ?RSMS),

    fake_ns_config:teardown_ns_config_events(),

    ?meckUnload(ns_node_disco),
    ?meckUnload(chronicle_kv).

%% -------------------------
%% API - Snapshot Management
%% -------------------------
-spec update_snapshot(atom(), term()) -> true.
update_snapshot(Key, Value) ->
    update_snapshot(#{Key => Value}).

-spec update_snapshot(map()) -> true.
update_snapshot(Map) when is_map(Map) ->
    update_named_snapshot(kv, Map).

%% ----------------------
%% API - Helper Functions
%% ----------------------
-spec setup_cluster_compat_version(list()) -> true.
setup_cluster_compat_version(Version) ->
    update_snapshot(cluster_compat_version, Version).

%% ----------------------------------
%% Internal - chronicle_kv meck setup
%% ----------------------------------
meck_setup() ->
    %% chronicle_compat often tries to read from ns_couchdb_chronicle_dup
    %% if available, we will bypass that to hit chronicle_kv proper.
    meck:new(ns_node_disco, [passthrough]),
    meck:expect(ns_node_disco, couchdb_node, [], [not_this_node]),

    meck_setup_chronicle_kv().

meck_setup_chronicle_kv() ->
    %% No passthrough, causes headaches as local functions can't be
    %% intercepted by meck, so we must control all entry to these modules.
    meck:new(chronicle_kv),

    meck:expect(chronicle_kv, sync, 2, ok),

    meck_setup_chronicle_kv_getters(),
    meck_setup_chronicle_kv_setters().

meck_setup_chronicle_kv_getters() ->
    meck:expect(
      chronicle_kv, get_snapshot,
      fun (Name, _Fetchers) ->
              %% Don't care about fetchers, return the entire config. We
              %% should be using lookup functions to get specific keys
              %% anyways so this should just work, and we don't care about
              %% perf here.
              Snapshot = get_ets_snapshot(Name),
              maps:remove(seqno, Snapshot)
      end),


    meck:expect(chronicle_kv, ro_txn,
                fun(Name, Fun) ->
                        Snapshot = get_ets_snapshot(Name),
                        Seqno = get_snapshot_seqno(Snapshot),
                        SnapshotWithoutSeqno = maps:remove(seqno, Snapshot),
                        {ok,
                         {Fun(SnapshotWithoutSeqno),
                          make_rev(Seqno)}}
                end),
    meck:expect(chronicle_kv, ro_txn,
                fun(Name, Fun, _Opts) ->
                        Snapshot = get_ets_snapshot(Name),
                        Seqno = get_snapshot_seqno(Snapshot),
                        SnapshotWithoutSeqno = maps:remove(seqno, Snapshot),
                        {ok,
                         {Fun(SnapshotWithoutSeqno),
                          make_rev(Seqno)}}
                end),


    meck:expect(chronicle_kv, txn_get,
                fun(Key, Txn) ->
                        fetch_from_snapshot(Txn, Key, [])
                end),

    meck:expect(chronicle_kv, txn_get_many,
                fun(Keys, Txn) ->
                        get_keys_for_txn(Keys, Txn)
                end),


    meck:expect(chronicle_kv, get,
                fun(Name, Key) ->
                        fetch_from_latest_snapshot(Name, Key)
                end),
    meck:expect(chronicle_kv, get,
                fun(Name, Key, #{}) ->
                        fetch_from_latest_snapshot(Name, Key)
                end),

    meck:expect(chronicle_kv, get_full_snapshot,
                fun(Name) ->
                        Snapshot = get_ets_snapshot(Name),
                        Seqno = get_snapshot_seqno(Snapshot),
                        SnapshotWithoutSeqno = maps:remove(seqno, Snapshot),
                        {ok,
                         {SnapshotWithoutSeqno, make_rev(Seqno)}}
                end),

    meck:expect(chronicle_kv, get_revision,
                fun(Name) ->
                        make_rev(get_snapshot_seqno(get_ets_snapshot(Name)))
                end),

    meck:expect(chronicle_kv, event_manager,
                fun(Name) ->
                        list_to_atom(atom_to_list(Name) ++ "-events")
                end).

meck_setup_chronicle_kv_setters() ->
    meck:expect(chronicle_kv, transaction,
                fun(Name, Keys, Fun) ->
                        transaction(Name, Keys, Fun, #{})
                end),

    meck:expect(chronicle_kv, transaction,
                fun(Name, Keys, Fun, Opts) ->
                        transaction(Name, Keys, Fun, Opts)
                end),

    meck:expect(chronicle_kv, txn,
                fun(Name, Fun, Opts) ->
                        transaction(Name, all, Fun, Opts)
                end),

    meck:expect(chronicle_kv, txn,
                fun(Name, Fun) ->
                        transaction(Name, all, Fun, [])
                end),

    meck:expect(chronicle_kv, set,
                fun(Name, Key, Value) ->
                        transaction(Name, [Key],
                                    fun (_) ->
                                            {commit, [{set, Key, Value}]}
                                    end, #{})
                end).

%% ----------------------------------
%% Internal - getter/setter functions
%% ----------------------------------
get_ets_snapshot() ->
    get_ets_snapshot(kv).

get_ets_snapshot(Name) ->
    [{_, Snapshot}] = ets:lookup(?TABLE_NAME, {snapshot, Name}),
    Snapshot.

get_snapshot_seqno(Snapshot) ->
    maps:get(seqno, Snapshot).

update_named_snapshot(Name, Map) ->
    OldSnapshot = get_ets_snapshot(Name),
    %% Chronicle stores revs, we won't bother with the actual history rev here,
    %% but we do use the seqno in some places/tests.
    Seqno = get_snapshot_seqno(OldSnapshot) + 1,
    NewKVs = maps:map(fun(_Key, Value) -> add_rev_to_value(Value, Seqno) end,
                      Map),
    NewSnapshot = maps:merge(OldSnapshot, NewKVs),

    case store_ets_snapshot(Name, OldSnapshot, NewSnapshot, Seqno) of
        ok ->
            ok;
        retry ->
            update_named_snapshot(Name, Map)
    end.

store_ets_snapshot(Name, OldSnapshot, NewSnapshot, Seqno) ->
    compare_and_swap(Name, OldSnapshot, NewSnapshot#{seqno => Seqno}).

compare_and_swap(Name, OldSnapshot, NewSnapshot) ->
    %% There is only one value (the snapshot). select_replace (and fun2ms) lets
    %% us atomically replace the value (if it's the value that we expected, of
    %% course). This lets us avoid race conditions in which we made changes
    %% based on a now invalid snapshot - if we have concurrent writers. We will
    %% return up and the caller should repeat til we can successfully swap the
    %% value.
    MS = ets:fun2ms(
           fun({{snapshot, N}, Snapshot}) when N =:= Name,
                                              Snapshot =:= OldSnapshot ->
                   {{snapshot, N}, NewSnapshot}
           end),
    case ets:select_replace(?TABLE_NAME, MS) of
        1 ->
            notify_changes(Name, OldSnapshot, NewSnapshot),
            ok;
        0 ->
            retry
    end.

notify_changes(Name, OldSnapshot, NewSnapshot) ->
    Mgr = chronicle_kv:event_manager(Name),
    maps:foreach(
      fun (seqno, _) ->
              ok;
          (Key, NewValue) ->
              case maps:find(Key, OldSnapshot) of
                  {ok, NewValue} ->
                      ok;
                  _ ->
                      {Value, Rev} = NewValue,
                      gen_event:notify(Mgr,
                                       {{key, Key}, Rev, {updated, Value}})
              end
      end, NewSnapshot),
    DeleteRev = make_rev(get_snapshot_seqno(NewSnapshot)),
    maps:foreach(
      fun (seqno, _) ->
              ok;
          (Key, _) ->
              case maps:is_key(Key, NewSnapshot) of
                  true ->
                      ok;
                  false ->
                      gen_event:notify(Mgr, {{key, Key}, DeleteRev, deleted})
              end
      end, OldSnapshot).

add_rev_to_value(Value, Seqno) ->
    {Value, make_rev(Seqno)}.

make_rev(Seqno) ->
    {?FAKE_HISTORY_REV, Seqno}.

fetch_from_latest_snapshot(Name, Key) ->
    fetch_from_latest_snapshot(Name, Key, #{}).

fetch_from_latest_snapshot(Name, Key, Opts) ->
    fetch_from_snapshot(get_ets_snapshot(Name), Key, Opts).

fetch_from_snapshot(Snapshot, Key, _Opts) ->
    case maps:find(Key, Snapshot) of
        error -> {error, not_found};
        Other -> Other
    end.

get_keys_for_txn(Keys, Snapshot) ->
    maps:with(Keys, Snapshot).

apply_commit({set, Key, Value}, Seqno, Snapshot) ->
    Snapshot#{Key => add_rev_to_value(Value, Seqno)};
apply_commit({delete, Key}, _Seqno, Snapshot) ->
    maps:remove(Key, Snapshot).

do_commits(Name, TxnSnapshot, Commits) ->
    %% Chronicle gives every key in a transaction the same rev
    NewSeqno = get_snapshot_seqno(TxnSnapshot) + 1,
    NewMap = lists:foldl(
               fun (Commit, Snapshot) ->
                       apply_commit(Commit, NewSeqno, Snapshot)
               end, TxnSnapshot, Commits),

    case store_ets_snapshot(Name, TxnSnapshot, NewMap, NewSeqno) of
        ok ->
            {ok, make_rev(NewSeqno)};
        retry ->
            retry
    end.

transaction(Name, Keys, Fun, Opts) ->
    TxnSnapshot = get_ets_snapshot(Name),
    Snapshot = case Keys of
                   all -> TxnSnapshot;
                   _ -> get_keys_for_txn(Keys, TxnSnapshot)
               end,
    case Fun(Snapshot) of
        {commit, Commits} ->
            case do_commits(Name, TxnSnapshot, Commits) of
                {ok, Rev} -> {ok, Rev};
                retry -> transaction(Name, Keys, Fun, Opts)
            end;
        {commit, Commits, Results} ->
            case do_commits(Name, TxnSnapshot, Commits) of
                {ok, Rev} -> {ok, Rev, Results};
                retry -> transaction(Name, Keys, Fun, Opts)
            end;
        {abort, Error} ->
            Error
    end.
