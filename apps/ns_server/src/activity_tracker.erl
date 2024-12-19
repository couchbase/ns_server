%% @author Couchbase <info@couchbase.com>
%% @copyright 2024-Present Couchbase, Inc.
%%
%% Use of this software is governed by the Business Source License included in
%% the file licenses/BSL-Couchbase.txt.  As of the Change Date specified in that
%% file, in accordance with the Business Source License, use of this software
%% will be governed by the Apache License, Version 2.0, included in the file
%% licenses/APL2.txt.

-module(activity_tracker).

-behaviour(gen_server).

-include("ns_common.hrl").
-include("rbac.hrl").
-include_lib("ns_common/include/cut.hrl").

-ifdef(TEST).
-include_lib("eunit/include/eunit.hrl").
-endif.

-export([start_link/0,
         default/0,
         handle_get/1,
         handle_post/1,
         get_config/0,
         handle_activity/1,
         is_tracked/1,
         get_activity_from_node/1]).
-export([init/1, handle_call/3, handle_cast/2, handle_info/2, terminate/2,
         code_change/3]).

-define(SERVER, ?MODULE).
-define(TABLE, ?MODULE).
-define(CONFIG_KEY, user_activity).

%% 60s should be sufficient time that we don't timeout when a node is busy
-define(RPC_TIMEOUT, ?get_timeout(rpc_timeout, 60000)).

-define(DEFAULT_TRACKED_ROLES,
        [admin, ro_admin, security_admin, user_admin_local, user_admin_external,
         cluster_admin, eventing_admin, backup_admin, views_admin,
         replication_admin, fts_admin, analytics_admin]).

-record(state, {}).

%%%===================================================================
%%% External interface
%%%===================================================================

-spec default() -> [{atom(), any()}].
default() ->
    [{enabled, false},
     {tracked_roles, ?DEFAULT_TRACKED_ROLES},
     {tracked_groups, []}].

handle_get(Req) ->
    menelaus_util:assert_is_enterprise(),
    menelaus_util:assert_is_morpheus(),

    menelaus_web_settings2:handle_get([], params(), fun type_spec/1,
                                      get_config(), Req).

handle_post(Req) ->
    menelaus_util:assert_is_enterprise(),
    menelaus_util:assert_is_morpheus(),

    menelaus_web_settings2:handle_post(
      fun (Params, Req2) ->
              case Params of
                  [] -> ok;
                  _ ->
                      Props = lists:map(fun ({[K], V}) -> {K, V} end, Params),
                      set_config(Props)
              end,
              handle_get(Req2)
      end, [], params(), fun type_spec/1, get_config(), [], Req).

set_config(Changes) ->
    OldConfig = get_config(),

    NewConfig = misc:update_proplist(OldConfig, Changes),
    ns_config:set(?CONFIG_KEY, NewConfig).

params() ->
    [{"enabled",
      #{type => bool,
        cfg_key => enabled}},
     {"trackedRoles",
      #{type => tracked_roles, cfg_key => tracked_roles, default => false}},
     {"trackedGroups",
      #{type => tracked_groups, cfg_key => tracked_groups, default => false}}].

type_spec(tracked_roles) ->
    #{validators => [string,
        validator:validate(fun get_roles/1, _, _)]};
type_spec(tracked_groups) ->
    #{validators => [string,
        validator:validate(fun get_groups/1, _, _)]}.

parse_role(RoleStr, Definitions) ->
    try
        RoleName = menelaus_web_rbac:role_to_atom(RoleStr),
        case lists:keyfind(RoleName, 1, Definitions) of
            false ->
                {error, RoleStr};
            _ -> RoleName
        end
    catch
        error:badarg -> {error, RoleStr}
    end.

get_roles(RolesStr) ->
    Definitions = menelaus_roles:get_definitions(public),
    RolesRaw = string:tokens(RolesStr, ","),
    Roles = [parse_role(string:trim(RoleRaw), Definitions)
             || RoleRaw <- RolesRaw],

    %% Gather erroneous roles
    BadRoles = [BadRole || {error, BadRole} <- Roles],
    case BadRoles of
        [] -> {value, Roles};
        _ -> {error,
              io_lib:format("The following roles are invalid: ~s",
                            [string:join(BadRoles, ",")])}
    end.

get_groups(Str) ->
    Groups = string:lexemes(Str, ","),
    UnexpectedGroups = [Group || Group <- Groups,
                                 menelaus_users:group_exists(Group)],
    case UnexpectedGroups of
        [] -> {value, Groups};
        _ -> {error, io_lib:format("The following groups do not exist: ~s",
                                   string:join(UnexpectedGroups, ","))}
    end.

-spec get_config() -> proplists:proplist().
get_config() ->
    ns_config:read_key_fast(?CONFIG_KEY, []).

-spec handle_activity(#authn_res{}) -> ok.
handle_activity(#authn_res{identity = Identity}) ->
    case ns_node_disco:couchdb_node() =/= node() andalso is_tracked(Identity) of
        true ->
            Config = ns_config:read_key_fast(?CONFIG_KEY, []),
            case proplists:get_value(enabled, Config, false) of
                true ->
                    note_identity(Identity);
                false ->
                    ok
            end;
        false ->
            ok
    end.

-spec is_tracked(rbac_identity()) -> boolean().
is_tracked({_, local} = Identity) ->
    Config = get_config(),
    IsEnabled = proplists:get_value(enabled, Config, false),
    case IsEnabled of
        false ->
            false;
        true ->
            Props = menelaus_users:get_user_props(Identity, [groups, roles]),

            is_user_covered(Props, Config, tracked_roles, roles) orelse
                is_user_covered(Props, Config, tracked_groups, groups)

    end;
is_tracked(_Identity) ->
    %% Non-local users aren't tracked
    false.

%% Check if a user is covered by the list of groups/roles respectively
is_user_covered(UserProps, Config, TrackedCategory, Category) ->
    TrackedList = proplists:get_value(TrackedCategory, Config, []),
    List = proplists:get_value(Category, UserProps, []),
    TrackedSet = sets:from_list(TrackedList),
    Set = sets:from_list(List),
    not sets:is_disjoint(TrackedSet, Set).

-spec get_activity_from_node(node()) -> [{rbac_identity(), non_neg_integer()}].
get_activity_from_node(Node) ->
    %% This function will be called from remote nodes, so changing the message
    %% will require backwards compatibility handling
    gen_server:call({?SERVER, Node}, last_activity, ?RPC_TIMEOUT).


%%%===================================================================
%%% Spawning and gen_server implementation
%%%===================================================================

start_link() ->
    gen_server:start_link({local, ?SERVER}, ?MODULE, [], []).

init([]) ->
    ets:new(?TABLE, [named_table, set, public]),
    {ok, #state{}}.

%% This will be used by the activity_aggregator to fetch each node's latest
%% activity time for each user.
%% By going through a gen_server, we need to be careful that we don't risk a
%% backlog in the queue, from the potentially heavy calls to ets:tab2list/1
%% being serialised.
%% However, since the aggregator will only make one of these calls at a time
%% (every 15 mins when it fetches the latest information), this isn't really a
%% serious risk.
handle_call(last_activity, _From, State) ->
    Config = ns_config:read_key_fast(?CONFIG_KEY, []),
    case proplists:get_value(enabled, Config, false) of
        true ->
            {reply, ets:tab2list(?TABLE), State};
        false ->
            {reply, [], State}
    end;
handle_call(_Request, _From, State) ->
    {reply, ok, State}.

handle_cast(_Request, State) ->
    {noreply, State}.

handle_info(_Info, State) ->
    {noreply, State}.

terminate(_Reason, _State) ->
    ok.

code_change(_OldVsn, State, _Extra) ->
    {ok, State}.


%%%===================================================================
%%% Internal functions
%%%===================================================================

note_identity(Identity) ->
    Time = calendar:datetime_to_gregorian_seconds(
             calendar:universal_time()),
    ets:insert(?TABLE, {Identity, Time}).


%%%===================================================================
%%% Tests
%%%===================================================================


-ifdef(TEST).

-define(GROUP_A, a).
-define(GROUP_B, b).
-define(ROLE_X, x).
-define(ROLE_Y, y).

-define(local_user_in_a, {"user_in_a", local}).
-define(local_user_in_b, {"user_in_b", local}).
-define(local_user_with_x, {"user_with_x", local}).
-define(local_user_with_y, {"user_with_y", local}).
-define(external_user_in_a, {"user_in_a", external}).
-define(external_user_with_x, {"user_with_x", external}).


setup() ->
    fake_ns_config:setup(),

    meck:new(calendar, [unstick, passthrough]),

    %% couchdb node handling is covered by
    %% SampleBucketTestSet.post_with_couchdb_sample_test
    meck:expect(ns_node_disco, couchdb_node, fun () -> other_node end),

    meck:expect(menelaus_users, get_user_props,
                fun (?local_user_in_a, [groups, roles]) ->
                        [{groups, [?GROUP_A]},
                         {roles, []}];
                    (?local_user_with_x, [groups, roles]) ->
                        [{groups, []},
                         {roles, [?ROLE_X]}];
                    (?local_user_in_b, [groups, roles]) ->
                        [{groups, [?GROUP_B]},
                         {roles, []}];
                    (?local_user_with_y, [groups, roles]) ->
                        [{groups, []},
                         {roles, [?ROLE_Y]}];
                    (?external_user_in_a, [groups, roles]) ->
                        [{groups, [?GROUP_A]},
                         {roles, []}];
                    (?external_user_with_x, [groups, roles]) ->
                        [{groups, []},
                         {roles, [?ROLE_X]}]
                end),

    ns_config:set(?CONFIG_KEY, default()),
    start_link().

teardown(_) ->
    gen_server:stop(?SERVER),
    fake_ns_config:teardown(),
    meck:unload().

configure(Settings) ->
    ns_config:set(?CONFIG_KEY, Settings).

-define(auth(Identity), #authn_res{identity = Identity}).

get_last_activity(Identity) ->
    Activity = gen_server:call(?SERVER, last_activity),
    proplists:get_value(Identity, Activity).

track_covered_user_test__() ->
    CoveredGroups = [?GROUP_A],
    CoveredRoles = [?ROLE_X],
    configure([{enabled, true},
               {tracked_groups, CoveredGroups},
               {tracked_roles, CoveredRoles}]),
    meck:expect(calendar, universal_time, 0,
                meck:seq([{{2024,8,19},{14,12,I}} || I <- lists:seq(1, 6)])),
    lists:foreach(
      fun (Identity) ->
              ?assert(is_tracked(Identity)),

              %% Expect that auth is tracked for covered users
              Time0 = get_last_activity(Identity),
              ?assertEqual(undefined, Time0),
              handle_activity(?auth(Identity)),
              Time1 = get_last_activity(Identity),
              ?assertNotEqual(undefined, Time1),
              handle_activity(?auth(Identity)),
              Time2 = get_last_activity(Identity),
              ?assert(Time1 < Time2)
      end, [?local_user_with_x, ?local_user_in_a]).

dont_track_uncovered_user_test__() ->
    CoveredGroups = [?GROUP_A],
    CoveredRoles = [?ROLE_X],
    configure([{tracked_groups, CoveredGroups}, {tracked_roles, CoveredRoles}]),
    lists:foreach(
      fun (Identity) ->
              ?assertNot(is_tracked(Identity)),

              %% Expect that auth is not tracked for uncovered users
              Time0 = get_last_activity(Identity),
              ?assertEqual(undefined, Time0),
              handle_activity(?auth(Identity)),
              Time1 = get_last_activity(Identity),
              ?assertEqual(undefined, Time1)
      end, [?local_user_in_b,
            ?local_user_with_y,
            ?external_user_in_a,
            ?external_user_with_x]).

all_test_() ->
    {setup, fun setup/0, fun teardown/1,
     [fun track_covered_user_test__/0,
      fun dont_track_uncovered_user_test__/0]}.

-endif.
