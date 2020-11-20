%% @author Couchbase <info@couchbase.com>
%% @copyright 2016-2019 Couchbase, Inc.
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
%% @doc handling of memcached permissions file

-module(memcached_permissions).

-behaviour(memcached_cfg).

-ifdef(TEST).
-include_lib("eunit/include/eunit.hrl").
-endif.

-export([start_link/0, sync/0, jsonify_user_with_cache/2, spec_users/0]).

%% callbacks
-export([init/0, filter_event/1, handle_event/2, producer/1, refresh/0]).

-include("ns_common.hrl").
-include("pipes.hrl").
-include("cut.hrl").
-include("rbac.hrl").

-ifdef(TEST).
-include_lib("eunit/include/eunit.hrl").
-include("ns_test.hrl").
-endif.

-record(state, {buckets,
                users,
                cluster_admin,
                prometheus_user}).

collection_permissions_to_check([B, S, C]) ->
    [{{[{collection, [B, S, C]}, data, docs], read},      'Read'},
     {{[{collection, [B, S, C]}, data, docs], insert},    'Insert'},
     {{[{collection, [B, S, C]}, data, docs], delete},    'Delete'},
     {{[{collection, [B, S, C]}, data, docs], upsert},    'Upsert'},
     {{[{collection, [B, S, C]}, data, meta], read},      'MetaRead'},
     {{[{collection, [B, S, C]}, data, meta], write},     'MetaWrite'},
     {{[{collection, [B, S, C]}, data, xattr], read},     'XattrRead'},
     {{[{collection, [B, S, C]}, data, xattr], write},    'XattrWrite'},
     {{[{collection, [B, S, C]}, data, sxattr], read},    'SystemXattrRead'},
     {{[{collection, [B, S, C]}, data, sxattr], write},   'SystemXattrWrite'},
     {{[{collection, [B, S, C]}, data, dcpstream], read}, 'DcpStream'},
     {{[{collection, [B, S, C]}, stats], read},           'SimpleStats'}].

bucket_permissions_to_check(Bucket) ->
    [{{[admin, internal, stats], read},         'SimpleStats'},
     {{[{bucket, Bucket}, data, dcp], read},    'DcpProducer'},
     {{[{bucket, Bucket}, data, dcp], write},   'DcpConsumer'}].

global_permissions_to_check() ->
    [{{[stats, memcached], read},           'Stats'},
     {{[admin, internal, stats], read},     'Stats'},
     {{[buckets], create},                  'BucketManagement'},
     {{[admin, memcached, node], write},    'NodeManagement'},
     {{[admin, memcached, session], write}, 'SessionManagement'},
     {{[admin, memcached, idle], write},    'IdleConnection'},
     {{[admin, security, audit], write},    'AuditManagement'},
     {{[pools], read},                      'SystemSettings'}].

start_link() ->
    Path = ns_config:search_node_prop(ns_config:latest(), memcached, rbac_file),
    memcached_cfg:start_link(?MODULE, Path).

sync() ->
    memcached_cfg:sync(?MODULE).

init() ->
    Config = ns_config:get(),
    Self = self(),
    chronicle_compat:subscribe_to_key_change(
      fun (Key) ->
              case collections:key_match(Key) of
                  {true, _} ->
                      memcached_cfg:refresh(Self);
                  false ->
                      ok
              end
      end),

    AdminUser =
        case ns_config:search(Config, rest_creds) of
            {value, {U, _}} -> U;
            _ -> undefined
        end,
    PromUser =
        case ns_config:search_node(Config, prometheus_auth_info) of
            {value, {U2, _}} -> U2;
            _ -> undefined
        end,
    #state{buckets = buckets_uids(ns_bucket:get_buckets(Config)),
           users = spec_users(Config),
           cluster_admin = AdminUser,
           prometheus_user = PromUser}.

buckets_uids(Buckets) ->
    [{Name, ns_bucket:bucket_uuid(Props)} || {Name, Props} <- Buckets].

spec_users() -> spec_users(ns_config:get()).
spec_users(Config) ->
    [ns_config:search_node_prop(Config, memcached, admin_user) |
     ns_config:search_node_prop(Config, memcached, other_users, [])].

filter_event({buckets, _V}) ->
    true;
filter_event({cluster_compat_version, _V}) ->
    true;
filter_event({group_version, _V}) ->
    true;
filter_event({user_version, _V}) ->
    true;
filter_event({rest_creds, _V}) ->
    true;
filter_event({{node, Node, prometheus_auth_info}, _}) when Node =:= node() ->
    true;
filter_event(_) ->
    false.

handle_event({buckets, V}, #state{buckets = Buckets} = State) ->
    case buckets_uids(proplists:get_value(configs, V)) of
        Buckets ->
            unchanged;
        NewBuckets ->
            {changed, State#state{buckets = NewBuckets}}
    end;
handle_event({user_version, _V}, State) ->
    {changed, State};
handle_event({group_version, _V}, State) ->
    {changed, State};
handle_event({cluster_compat_version, _V}, State) ->
    {changed, State};
handle_event({rest_creds, {ClusterAdmin, _}},
             #state{cluster_admin = ClusterAdmin}) ->
    unchanged;
handle_event({rest_creds, {ClusterAdmin, _}}, State) ->
    {changed, State#state{cluster_admin = ClusterAdmin}};
handle_event({rest_creds, _}, #state{cluster_admin = undefined}) ->
    unchanged;
handle_event({rest_creds, _}, State) ->
    {changed, State#state{cluster_admin = undefined}};
handle_event({{node, Node, prometheus_auth_info}, {User, _}},
             #state{prometheus_user = User}) when Node =:= node() ->
    unchanged;
handle_event({{node, Node, prometheus_auth_info}, {User, _}},
             State) when Node =:= node() ->
    {changed, State#state{prometheus_user = User}};
handle_event({{node, Node, prometheus_auth_info}, _Info},
             State) when Node =:= node() ->
    {changed, State#state{prometheus_user = undefined}}.

refresh() ->
    memcached_refresh:refresh(rbac).

-record(priv_object, {privileges, children}).

priv_is_granted(_Privilege, [], _Map) ->
    false;
priv_is_granted(Privilege, [Object | Rest], Map) ->
    case maps:find(Object, Map) of
        {ok, #priv_object{privileges = Privileges, children = Children}} ->
            case maps:is_key(Privilege, Privileges) of
                true ->
                    true;
                false ->
                    priv_is_granted(Privilege, Rest, Children)
            end;
        error ->
            false
    end.

priv_set(Privilege, [Object], Map) ->
    maps:update_with(
      Object,
      fun (#priv_object{privileges = Privileges, children = Children}) ->
              #priv_object{privileges = Privileges#{Privilege => true},
                           children = priv_erase(Privilege, Children)}
      end,
      #priv_object{privileges = #{Privilege => true}, children = #{}},
      Map);
priv_set(Privilege, [Object | Rest], Map) ->
    Map#{Object =>
             case maps:find(Object, Map) of
                 {ok, #priv_object{privileges = Privileges,
                                   children = Children} = Old} ->
                     case maps:is_key(Privilege, Privileges) of
                         true ->
                             Old;
                         false ->
                             Old#priv_object{
                               children = priv_set(Privilege, Rest, Children)}
                     end;
                 error ->
                     #priv_object{privileges = #{},
                                  children = priv_set(Privilege, Rest, #{})}
             end}.

priv_erase(Privilege, Map) ->
    maps:fold(
      fun (Key, #priv_object{privileges = Privileges, children = Children},
           Acc) ->
              case #priv_object{privileges = maps:remove(Privilege, Privileges),
                                children = priv_erase(Privilege, Children)} of
                  #priv_object{privileges = P, children = C} when
                        map_size(P) =:= 0,
                        map_size(C) =:= 0 ->
                      Acc;
                  NotEmpty ->
                      Acc#{Key => NotEmpty}
              end
      end, #{}, Map).

bucket_permissions(BucketName, CompiledRoles, Acc) ->
    lists:foldl(
      fun ({Permission, MemcachedPrivilege}, Acc1) ->
              case menelaus_roles:is_allowed(Permission, CompiledRoles) of
                  true ->
                      priv_set(MemcachedPrivilege, [BucketName], Acc1);
                  false ->
                      Acc1
              end
      end, Acc, bucket_permissions_to_check(BucketName)).

get_priv_object_key([Bucket | Rest]) ->
    [case Bucket of
         {N, _} ->
             N;
         _ ->
             Bucket
     end | [Id || {_, Id} <- Rest]].

collection_permissions(Params, CompiledRoles, Acc) ->
    ToCheck = lists:map(
                fun (any) ->
                        all;
                    (X) ->
                        X
                end, menelaus_roles:strip_ids(?RBAC_COLLECTION_PARAMS, Params)),
    ToStore = get_priv_object_key(Params),
    lists:foldl(
      fun ({Permission, MemcachedPrivilege}, Acc1) ->
              case priv_is_granted(MemcachedPrivilege, ToStore, Acc1) of
                  true ->
                      Acc1;
                  false ->
                      case menelaus_roles:is_allowed(Permission,
                                                     CompiledRoles) of
                          true ->
                              priv_set(MemcachedPrivilege, ToStore, Acc1);
                          false ->
                              Acc1
                      end
              end
      end, Acc, collection_permissions_to_check(ToCheck)).

global_permissions(CompiledRoles) ->
    lists:usort(
      [MemcachedPermission ||
          {Permission, MemcachedPermission} <- global_permissions_to_check(),
          menelaus_roles:is_allowed(Permission, CompiledRoles)]).

check_permissions(BucketNames, Roles, CompiledRoles, RoleDefinitions) ->
    CollectionParams =
        [[N, any, any] || N <- BucketNames] ++
        [Params || {RoleName, Params} <- Roles, Params =/= [any, any, any],
                   menelaus_roles:get_param_defs(RoleName, RoleDefinitions) =:=
                       ?RBAC_COLLECTION_PARAMS],
    BucketPrivileges =
        lists:foldl(bucket_permissions(_, CompiledRoles, _), #{},
                    BucketNames),
    {global_permissions(CompiledRoles),
     lists:foldl(collection_permissions(_, CompiledRoles, _),
                 BucketPrivileges, CollectionParams)}.

permissions_for_user(Roles, Snapshot, RoleDefinitions) ->
    CompiledRoles = menelaus_roles:compile_roles(Roles, RoleDefinitions,
                                                 Snapshot),
    check_permissions(ns_bucket:get_bucket_names(Snapshot), Roles,
                      CompiledRoles, RoleDefinitions).

jsonify_user_with_cache(Identity, BucketNames) ->
    %% TODO: consider caching collection parameters too so get_roles call
    %% doesn't have to be made here
    jsonify_user(Identity,
                 check_permissions(BucketNames,
                                   menelaus_roles:get_roles(Identity),
                                   menelaus_roles:get_compiled_roles(Identity),
                                   menelaus_roles:get_definitions(all))).

jsonify_key(String) when is_list(String) ->
    list_to_binary(String);
jsonify_key(Num) when is_number(Num) ->
    collections:convert_uid_to_memcached(Num).

jsonify_privs([SectionKey | Rest], Map) ->
    {SectionKey,
     {maps:fold(
        fun (Key, #priv_object{privileges = Privileges, children = Children},
             Acc) ->
                [{jsonify_key(Key),
                  {[{privileges, maps:keys(Privileges)} ||
                       map_size(Privileges) =/= 0] ++
                       [jsonify_privs(Rest, Children) ||
                           map_size(Children) =/= 0]}} | Acc]
        end, [], Map)}}.

jsonify_user({UserName, Domain}, {GlobalPermissions, BucketPermissions}) ->
    Buckets =
        case BucketPermissions of
            all ->
                {buckets, {[{<<"*">>, [all]}]}};
            _ ->
                jsonify_privs([buckets, scopes, collections], BucketPermissions)
        end,
    Global = {privileges, GlobalPermissions},
    {list_to_binary(UserName), {[Buckets, Global, {domain, Domain}]}}.

memcached_admin_json(AU) ->
    jsonify_user({AU, local}, {[all], all}).

jsonify_users(Users, RoleDefinitions, ClusterAdmin, PromUser) ->
    Snapshot = ns_bucket:get_snapshot(),
    ?make_transducer(
       begin
           ?yield(object_start),
           lists:foreach(fun (U) ->
                                 ?yield({kv, memcached_admin_json(U)})
                         end, Users),

           EmitUser =
               fun (Identity, Roles) ->
                       Permissions =
                           permissions_for_user(Roles, Snapshot,
                                                RoleDefinitions),
                       ?yield({kv, jsonify_user(Identity, Permissions)})
               end,

           EmitLocalUser =
               fun (undefined, _) ->
                       ok;
                   (Name, Identity) ->
                       EmitUser({Name, local},
                                menelaus_roles:get_roles(Identity))
               end,

           EmitLocalUser(ClusterAdmin, {ClusterAdmin, admin}),
           EmitLocalUser(PromUser, {PromUser, stats_reader}),

           lists:foreach(?cut(EmitLocalUser(_1 ++ ";legacy", {_1, bucket})),
                         ns_bucket:get_bucket_names(Snapshot)),

           pipes:foreach(
             ?producer(),
             fun ({{user, {UserName, _} = Identity}, Props}) ->
                     case UserName of
                         ClusterAdmin ->
                             TagCA = ns_config_log:tag_user_name(ClusterAdmin),
                             ?log_warning("Encountered user ~p with the same
                                          name as cluster administrator",
                                          [TagCA]);
                         _ ->
                             EmitUser(Identity,
                                      proplists:get_value(roles, Props, []))
                     end
             end),
           ?yield(object_end)
       end).

producer(#state{users = Users,
                cluster_admin = ClusterAdmin,
                prometheus_user = PromUser}) ->
    Config = ns_config:get(),
    case menelaus_users:upgrade_in_progress(Config) of
        true ->
            ?log_debug("Skipping update during users upgrade"),
            undefined;
        false ->
            RoleDefinitions = menelaus_roles:get_definitions(Config, all),
            pipes:compose([menelaus_users:select_users({'_', local}, [roles]),
                           jsonify_users(Users, RoleDefinitions, ClusterAdmin,
                                         PromUser),
                           sjson:encode_extended_json([{compact, false},
                                                       {strict, false}])])
    end.

-ifdef(TEST).
flatten_priv_object(Map) ->
    flatten_priv_object([], [], Map).

flatten_priv_object(Prefix, Acc, Map) ->
    maps:fold(
      fun (Key, #priv_object{
                   privileges = Privileges,
                   children = Children}, Acc1) when map_size(Privileges) =:= 0,
                                                    map_size(Children) =:= 0 ->
              [{lists:reverse([Key | Prefix]), empty} | Acc1];
          (Key, #priv_object{privileges = Privileges,
                             children = Children}, Acc1) ->
              NewPrefix = [Key | Prefix],
              NewPrefixReversed = lists:reverse(NewPrefix),
              flatten_priv_object(
                NewPrefix,
                Acc1 ++ [{NewPrefixReversed, K} || K <- maps:keys(Privileges)],
                Children)
      end, Acc, Map).

priv_object_test() ->
    PrivObject =
        functools:chain(
          #{},
          [priv_set(p1, [b1, s1, c1], _),
           priv_set(p1, [b2], _),
           priv_set(p2, [b1, s1, c1], _),
           priv_set(p2, [b1, s1, c2], _),
           priv_set(p2, [b1, s2, c3], _),
           priv_set(p2, [b1, s2], _),
           priv_set(p3, [b1, s1, c1], _),
           priv_set(p3, [b1], _)]),
    ?assert(priv_is_granted(p1, [b1, s1, c1], PrivObject)),
    ?assertNot(priv_is_granted(p1, [b1, s1], PrivObject)),
    ?assertNot(priv_is_granted(p1, [b1], PrivObject)),
    ?assert(priv_is_granted(p1, [b2, any, any], PrivObject)),
    ?assert(priv_is_granted(p1, [b2, any], PrivObject)),
    ?assert(priv_is_granted(p1, [b2], PrivObject)),
    ?assertNot(priv_is_granted(wrong, [b2], PrivObject)),
    ?assertNot(priv_is_granted(p1, [wrong], PrivObject)),
    ?assertListsEqual([{[b1, s1, c1], p1},
                       {[b2], p1},
                       {[b1, s1, c1], p2},
                       {[b1, s1, c2], p2},
                       {[b1, s2], p2},
                       {[b1], p3}], flatten_priv_object(PrivObject)).

permissions_for_user_test_() ->
    Manifest =
        [{uid, 2},
         {scopes, [{"s",  [{uid, 1}, {collections, [{"c",  [{uid, 1}]},
                                                    {"c1", [{uid, 2}]}]}]},
                   {"s1", [{uid, 2}, {collections, [{"c",  [{uid, 3}]}]}]}]}],
    Snapshot =
        ns_bucket:toy_buckets(
          [{"test", [{props, [{uuid, <<"test_id">>}]}]},
           {"default", [{props, [{uuid, <<"default_id">>}]},
                        {collections, Manifest}]}]),

    All = fun (L) -> lists:usort([P || {_, P} <- L]) end,
    Read = fun (L) -> lists:usort([P || {{_, read}, P} <- L]) end,
    DataRead = fun (L) ->
                       lists:usort([P || {{[_, data | _], read}, P} <- L])
               end,

    BucketsPlusCollections = bucket_permissions_to_check(undefined) ++
        collection_permissions_to_check([x, x, x]),
    JustCollections = collection_permissions_to_check([x, x, x]),

    AllBucketPermissions = All(BucketsPlusCollections),

    Test =
        fun (Roles, ExpectedGlobal, ExpectedBuckets) ->
                {lists:flatten(io_lib:format("~p", [Roles])),
                 fun () ->
                         {GlobalRes, BucketsRes} =
                             permissions_for_user(
                               Roles, Snapshot,
                               menelaus_roles:get_definitions(all)),
                         ?assertListsEqual(ExpectedGlobal, GlobalRes),
                         FlatExpected =
                             lists:flatmap(
                               fun ({Key, List}) ->
                                       [{Key, El} || El <- List]
                               end, ExpectedBuckets),
                         ?assertListsEqual(FlatExpected,
                                           flatten_priv_object(BucketsRes))
                 end}
        end,
    {foreach,
     fun() ->
             meck:new(cluster_compat_mode, [passthrough]),
             meck:expect(cluster_compat_mode, is_enterprise,
                         fun () -> true end),
             meck:expect(cluster_compat_mode, get_compat_version,
                         fun (_) -> ?VERSION_CHESHIRECAT end)
     end,
     fun (_) ->
             meck:unload(cluster_compat_mode)
     end,
     [Test([admin],
           All(global_permissions_to_check()),
           [{["default"], AllBucketPermissions},
            {["test"], AllBucketPermissions}]),
      Test([ro_admin],
           ['Stats','SystemSettings'],
           [{["default"], ['SimpleStats']},
            {["test"], ['SimpleStats']}]),
      Test([{bucket_admin, [{"test", <<"test_id">>}]}],
           ['Stats','SystemSettings'],
           [{["test"], ['SimpleStats']}]),
      Test([{bucket_full_access, ["test"]}],
           ['SystemSettings'],
           [{["test"], AllBucketPermissions}]),
      Test([{views_admin, [{"test", <<"test_id">>}]},
            {views_reader, [{"default", <<"default_id">>}]}],
           ['Stats', 'SystemSettings'],
           [{["default"], ['Read']},
            {["test"], Read(BucketsPlusCollections)}]),
      Test([{data_reader, [{"test", <<"test_id">>}, any, any]}],
           ['SystemSettings'],
           [{["test"], ['MetaRead', 'Read', 'XattrRead']}]),
      Test([{data_reader, [{"default", <<"default_id">>}, {"s", 1}, any]}],
           ['SystemSettings'],
           [{["default", 1], ['MetaRead', 'Read', 'XattrRead']}]),
      Test([{data_reader, [{"default", <<"default_id">>}, {"s", 1}, {"c", 1}]}],
           ['SystemSettings'],
           [{["default", 1, 1], ['MetaRead', 'Read', 'XattrRead']}]),
      Test([{data_dcp_reader, [{"test", <<"test_id">>}, any, any]}],
           ['IdleConnection','SystemSettings'],
           [{["test"], DataRead(BucketsPlusCollections)}]),
      Test([{data_dcp_reader,
             [{"default", <<"default_id">>}, {"s", 1}, {"c", 1}]}],
           ['IdleConnection','SystemSettings'],
           [{["default"], ['DcpProducer']},
            {["default", 1, 1], DataRead(JustCollections)}]),
      Test([{data_monitoring,
             [{"default", <<"default_id">>}, {"s", 1}, {"c", 1}]}],
           ['SystemSettings'],
           [{["default", 1, 1], ['SimpleStats']}]),
      Test([{data_backup, [{"test", <<"test_id">>}]},
            {data_monitoring, [{"default", <<"default_id">>}, any, any]}],
           ['SystemSettings'],
           [{["default"], ['SimpleStats']},
            {["test"], AllBucketPermissions}]),
      Test([{data_writer, [{"test", <<"test_id">>}, any, any]}],
           ['SystemSettings'],
           [{["test"], ['Delete', 'Insert', 'Upsert', 'XattrWrite']}]),
      Test([{data_writer, [{"test", <<"test_id">>}, any, any]},
            {data_writer, [{"default", <<"default_id">>}, {"s", 1}, {"c", 1}]},
            {data_writer, [{"default", <<"default_id">>}, {"s", 1}, any]},
            {data_reader, [{"default", <<"default_id">>}, {"s1", 2}, any]}],
           ['SystemSettings'],
           [{["test"], ['Delete', 'Insert', 'Upsert', 'XattrWrite']},
            {["default", 1], ['Delete', 'Insert', 'Upsert', 'XattrWrite']},
            {["default", 2], ['MetaRead', 'Read', 'XattrRead']}])]}.
-endif.
