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
%% 1. Permission is defined as a pair {object, operation}
%% 2. Objects are organized in the tree structure with common root []
%% 3. One vertex of this tree can be parametrized: {bucket, bucket_name},
%%    wildcard all can be used in place of bucket_name
%% 4. Permission pattern is a pair {Object pattern, Allowed operations}
%% 5. Allowed operations can be list of operations, all or none
%% 6. Object pattern is a list of vertices that define a certain subtree of the
%%    objects tree
%% 7. Object pattern vertex {bucket, bucket_name} always matches object vertex
%%    {bucket, any}, object pattern vertex {bucket, any} matches
%%    {bucket, bucket_name} with any bucket_name
%%    otherwise vertices match if they are equal
%% 8. Object matches the object pattern if all the vertices of object pattern
%%    match corresponding vertices of the object.
%% 9. Each role is defined as a list of permission patterns.
%% 10.To find which operations are allowed for certain object in certain role
%%    we look for the first permission pattern with matching object pattern in
%%    the permission pattern list of the role.
%% 11.The permission is allowed by the role if its operation is among the
%%    allowed operations for its object.
%% 12.Each user can have multiple roles assigned
%% 13.Certain permission is allowed to the user if it is allowed at least by
%%    one of the roles assigned to user.

%% @doc roles and permissions implementation

-module(menelaus_roles).

-include("ns_common.hrl").
-include("ns_config.hrl").
-include("rbac.hrl").
-include("pipes.hrl").
-include("cut.hrl").

-ifdef(TEST).
-include_lib("eunit/include/eunit.hrl").
-include("ns_test.hrl").
-endif.

-define(DEFAULT_EXTERNAL_ROLES_POLLING_INTERVAL, 10*60*1000).

-export([get_definitions/1,
         get_definitions/2,
         is_allowed/2,
         get_roles/1,
         get_compiled_roles/1,
         compile_roles/3,
         validate_roles/2,
         params_version/1,
         filter_out_invalid_roles/3,
         produce_roles_by_permission/2,
         get_security_roles/1,
         external_auth_polling_interval/0,
         get_param_defs/2,
         strip_ids/2]).

-export([start_compiled_roles_cache/0]).

%% for RPC from ns_couchdb node
-export([build_compiled_roles/1]).

-spec roles() -> [rbac_role_def(), ...].
roles() ->
    [{admin, [],
      [{name, <<"Full Admin">>},
       {desc, <<"Can manage all cluster features (including security). "
                "This user can access the web console. This user can read and "
                "write all data.">>},
       {ce, true}],
      [{[], all}]},
     {ro_admin, [],
      [{name, <<"Read-Only Admin">>},
       {desc, <<"Can view all cluster statistics. This user can access the "
                "web console. This user can read some data.">>},
       {ce, true}],
      [{[{bucket, any}, password], none},
       {[{bucket, any}, data], none},
       {[{bucket, any}, fts], none},
       {[admin, security], [read]},
       {[admin], none},
       {[eventing], none},
       {[], [read, list]}]},
     {security_admin, [],
      [{name, <<"Security Admin">>},
       {desc, <<"Can view all cluster statistics and manage user roles, but "
                "not grant Full Admin or Security Admin roles to other users "
                "or alter their own role. This user can access the web "
                "console. This user cannot read data.">>}],
      [{[admin, security, admin], none},
       {[admin, security], all},
       {[admin, logs], none},
       {[{bucket, any}, data], none},
       {[{bucket, any}, views], none},
       {[{bucket, any}, n1ql], none},
       {[{bucket, any}, fts], none},
       {[{bucket, any}, password], none},
       {[{bucket, any}], [read]},
       {[], [read, list]}]},
     {cluster_admin, [],
      [{name, <<"Cluster Admin">>},
       {desc, <<"Can manage all cluster features except security. This user "
                "can access the web console. This user cannot read data.">>}],
      [{[admin, internal], none},
       {[admin, security], none},
       {[admin, diag], read},
       {[{bucket, any}, data], none},
       {[{bucket, any}, views], none},
       {[{bucket, any}, n1ql], none},
       {[{bucket, any}, fts], none},
       {[{bucket, any}, password], none},
       {[n1ql, curl], none},
       {[eventing], none},
       {[], all}]},
     {bucket_admin, [bucket_name],
      [{name, <<"Bucket Admin">>},
       {desc, <<"Can manage ALL bucket features for a given bucket (including "
                "start/stop XDCR). This user can access the web console. This "
                "user cannot read data.">>}],
      [{[{bucket, bucket_name}, xdcr], [read, execute]},
       {[{bucket, bucket_name}, data], none},
       {[{bucket, bucket_name}, views], none},
       {[{bucket, bucket_name}, n1ql], none},
       {[{bucket, bucket_name}, password], none},
       {[{bucket, bucket_name}, fts], none},
       {[{bucket, bucket_name}], all},
       {[{bucket, any}, settings], [read]},
       {[{bucket, any}], none},
       {[xdcr], none},
       {[admin], none},
       {[eventing], none},
       {[], [read]}]},
     {bucket_full_access, [bucket_name],
      [{name, <<"Application Access">>},
       {desc, <<"Full access to bucket data. This user cannot access the web "
                "console and is intended only for application access. This "
                "user can read and write data.">>},
       {ce, true}],
      [{[{bucket, bucket_name}, data], all},
       {[{bucket, bucket_name}, views], all},
       {[{bucket, bucket_name}, n1ql, index], all},
       {[{bucket, bucket_name}, n1ql], [execute]},
       {[{bucket, bucket_name}], [read, flush]},
       {[{bucket, bucket_name}, settings], [read]},
       {[pools], [read]}]},
     {views_admin, [bucket_name],
      [{name, <<"Views Admin">>},
       {desc, <<"Can create and manage views of a given bucket. This user can "
                "access the web console. This user can read some data.">>}],
      [{[{bucket, bucket_name}, views], all},
       {[{bucket, bucket_name}, data], [read]},
       {[{bucket, bucket_name}, stats], [read]},
       {[{bucket, any}, settings], [read]},
       {[{bucket, any}], none},
       {[{bucket, bucket_name}, n1ql], [execute]},
       {[xdcr], none},
       {[admin], none},
       {[eventing], none},
       {[], [read]}]},
     {views_reader, [bucket_name],
      [{name, <<"Views Reader">>},
       {desc, <<"Can read data from the views of a given bucket. This user "
                "cannot access the web console and is intended only for "
                "application access. This user can read some data.">>}],
      [{[{bucket, bucket_name}, views], [read]},
       {[{bucket, bucket_name}, data, docs], [read]},
       {[pools], [read]}]},
     {replication_admin, [],
      [{name, <<"XDCR Admin">>},
       {desc, <<"Can administer XDCR features to create cluster references and "
                "replication streams out of this cluster. This user can "
                "access the web console. This user can read some data.">>}],
      [{[{bucket, any}, xdcr], all},
       {[{bucket, any}, data], [read]},
       {[{bucket, any}, settings], [read]},
       {[{bucket, any}, stats], [read]},
       {[{bucket, any}], none},
       {[xdcr], all},
       {[admin], none},
       {[eventing], none},
       {[], [read]}]},
     {data_reader, ?RBAC_COLLECTION_PARAMS,
      [{name, <<"Data Reader">>},
       {desc, <<"Can read data from a given bucket, scope or collection. "
                "This user cannot access the web console and is intended only "
                "for application access. This user can read data, but cannot "
                "write it.">>}],
      [{[{collection, ?RBAC_COLLECTION_PARAMS}, data, docs], [read]},
       {[{collection, ?RBAC_COLLECTION_PARAMS}, data, meta], [read]},
       {[{collection, ?RBAC_COLLECTION_PARAMS}, data, xattr], [read]},
       {[{bucket, bucket_name}, settings], [read]},
       {[pools], [read]}]},
     {data_writer, ?RBAC_COLLECTION_PARAMS,
      [{name, <<"Data Writer">>},
       {desc, <<"Can write data to a given bucket, scope or collection. "
                "This user cannot access the web console and is intended only "
                "for application access. This user can write data, but cannot "
                "read it.">>}],
      [{[{collection, ?RBAC_COLLECTION_PARAMS}, data, docs],
        [insert, upsert, delete]},
       {[{collection, ?RBAC_COLLECTION_PARAMS}, data, xattr], [write]},
       {[{bucket, bucket_name}, settings], [read]},
       {[pools], [read]}]},
     {data_dcp_reader, ?RBAC_COLLECTION_PARAMS,
      [{name, <<"Data DCP Reader">>},
       {desc, <<"Can initiate DCP streams for a given bucket, scope or "
                "collection. This user cannot access the web console and is "
                "intended only for application access. "
                "This user can read data.">>}],
      [{[{collection, ?RBAC_COLLECTION_PARAMS}, data, docs], [read]},
       {[{collection, ?RBAC_COLLECTION_PARAMS}, data, meta], [read]},
       {[{collection, ?RBAC_COLLECTION_PARAMS}, data, dcpstream], [read]},
       {[{collection, ?RBAC_COLLECTION_PARAMS}, data, sxattr], [read]},
       {[{collection, ?RBAC_COLLECTION_PARAMS}, data, xattr], [read]},
       {[{bucket, bucket_name}, data, dcp], [read]},
       {[{bucket, bucket_name}, settings], [read]},
       {[admin, memcached, idle], [write]},
       {[pools], [read]}]},
     {data_backup, [bucket_name],
      [{name, <<"Data Backup & Restore">>},
       {desc, <<"Can backup and restore a given bucket’s data. This user "
                "cannot access the web console and is intended only for "
                "application access. This user can read data.">>}],
      [{[{bucket, bucket_name}, data], all},
       {[{bucket, bucket_name}, views], [read, write]},
       {[{bucket, bucket_name}, fts], [read, write, manage]},
       {[{bucket, bucket_name}, stats], [read]},
       {[{bucket, bucket_name}, settings], [read]},
       {[{bucket, bucket_name}, n1ql, index], [create, list, build]},
       {[{bucket, bucket_name}, analytics], [manage, select]},
       {[analytics], [select, backup]},
       {[pools], [read]}]},
     {data_monitoring, ?RBAC_COLLECTION_PARAMS,
      [{name, <<"Data Monitor">>},
       {desc, <<"Can read statistics for a given bucket, scope or collection. "
                "This user cannot access the web console and is intended only "
                "for application access. This user cannot read data.">>}],
      [{[{collection, ?RBAC_COLLECTION_PARAMS}, stats], [read]},
       {[{bucket, bucket_name}, settings], [read]},
       {[tasks], [read]},
       {[pools], [read]}]},
     {fts_admin, [bucket_name],
      [{name, <<"Search Admin">>},
       {desc, <<"Can administer all Full Text Search features. This user can "
                "access the web console. This user can read some data.">>}],
      [{[{bucket, bucket_name}, fts], [read, write, manage]},
       {[settings, fts], [read, write, manage]},
       {[ui], [read]},
       {[pools], [read]},
       {[{bucket, bucket_name}, settings], [read]}]},
     {fts_searcher, ?RBAC_COLLECTION_PARAMS,
      [{name, <<"Search Reader">>},
       {desc, <<"Can query Full Text Search indexes for a given bucket, scope "
                "or collection. This user can access the web console. This "
                "user can read some data.">>}],
      [{[{collection, ?RBAC_COLLECTION_PARAMS}, fts], [read]},
       {[settings, fts], [read]},
       {[ui], [read]},
       {[pools], [read]},
       {[{bucket, bucket_name}, settings], [read]}]},
     {query_select, ?RBAC_COLLECTION_PARAMS,
      [{name, <<"Query Select">>},
       {desc, <<"Can execute a SELECT statement on a given bucket, scope or "
                "collection to retrieve data. This user can access the web "
                "console and can read data, but not write it.">>}],
      [{[{collection, ?RBAC_COLLECTION_PARAMS}, n1ql, select], [execute]},
       {[{collection, ?RBAC_COLLECTION_PARAMS}, data, docs], [read]},
       {[{bucket, bucket_name}, settings], [read]},
       {[ui], [read]},
       {[pools], [read]}]},
     {query_update, ?RBAC_COLLECTION_PARAMS,
      [{name, <<"Query Update">>},
       {desc, <<"Can execute an UPDATE statement on a given bucket, scope or "
                "collection to update data. This user can access the web "
                "console and write data, but cannot read it.">>}],
      [{[{collection, ?RBAC_COLLECTION_PARAMS}, n1ql, update], [execute]},
       {[{collection, ?RBAC_COLLECTION_PARAMS}, data, docs], [upsert]},
       {[{bucket, bucket_name}, settings], [read]},
       {[ui], [read]},
       {[pools], [read]}]},
     {query_insert, ?RBAC_COLLECTION_PARAMS,
      [{name, <<"Query Insert">>},
       {desc, <<"Can execute an INSERT statement on a given bucket, scope or "
                "collection to add data. This user can access the web console "
                "and insert data, but cannot read it.">>}],
      [{[{collection, ?RBAC_COLLECTION_PARAMS}, n1ql, insert], [execute]},
       {[{collection, ?RBAC_COLLECTION_PARAMS}, data, docs], [insert]},
       {[{bucket, bucket_name}, settings], [read]},
       {[ui], [read]},
       {[pools], [read]}]},
     {query_delete, ?RBAC_COLLECTION_PARAMS,
      [{name, <<"Query Delete">>},
       {desc, <<"Can execute a DELETE statement on a given bucket, scope or "
                "collection to delete data. This user can access the web "
                "console, but cannot read data. This user can delete data.">>}],
      [{[{collection, ?RBAC_COLLECTION_PARAMS}, n1ql, delete], [execute]},
       {[{collection, ?RBAC_COLLECTION_PARAMS}, data, docs], [delete]},
       {[{bucket, bucket_name}, settings], [read]},
       {[ui], [read]},
       {[pools], [read]}]},
     {query_manage_index, ?RBAC_COLLECTION_PARAMS,
      [{name, <<"Query Manage Index">>},
       {desc, <<"Can manage indexes for a given bucket, scope or collection. "
                "This user can access the web console, but cannot read data.">>
       }],
      [{[{collection, ?RBAC_COLLECTION_PARAMS}, n1ql, index], all},
       {[{bucket, bucket_name}, settings], [read]},
       {[ui], [read]},
       {[pools], [read]}]},
     {query_system_catalog, [],
      [{name, <<"Query System Catalog">>},
       {desc, <<"Can look up system catalog information via N1QL. This user "
                "can access the web console, but cannot read user data.">>}],
      [{[{bucket, any}, n1ql, index], [list]},
       {[{bucket, any}, settings], [read]},
       {[n1ql, meta], [read]},
       {[ui], [read]},
       {[pools], [read]}]},
     {query_external_access, [],
      [{name, <<"Query CURL Access">>},
       {desc, <<"Can execute the CURL statement from within N1QL. This user "
                "can access the web console, but cannot read data (within "
                "Couchbase).">>}],
      [{[n1ql, curl], [execute]},
       {[{bucket, any}, settings], [read]},
       {[ui], [read]},
       {[pools], [read]}]},
     {replication_target, [bucket_name],
      [{name, <<"XDCR Inbound">>},
       {desc, <<"Can create XDCR streams into a given bucket. This user cannot "
                "access the web console or read any data.">>}],
      [{[{bucket, bucket_name}, settings], [read]},
       {[{bucket, bucket_name}, data, meta], [read, write]},
       {[{bucket, bucket_name}, stats], [read]},
       {[pools], [read]}]},
     {analytics_manager, [bucket_name],
      [{name, <<"Analytics Manager">>},
       {desc, <<"Can manage Analytics local links. Can manage datasets on a "
                "given bucket. Can query datasets created on this bucket. "
                "This user can access the web console and read some data.">>}],
      [{[{bucket, bucket_name}, analytics], [manage, select]},
       {[ui], [read]},
       {[pools], [read]}]},
     {analytics_reader, [],
      [{name, <<"Analytics Reader">>},
       {desc, <<"Can query datasets. This is a global role as datasets may "
                "be created on different buckets. This user can access the "
                "web console and read some data.">>}],
      [{[analytics], [select]},
       {[{bucket, any}, analytics], [select]},
       {[ui], [read]},
       {[pools], [read]}]},
     {analytics_select, [bucket_name],
      [{name, <<"Analytics Select">>},
       {desc, <<"Can query datasets created on this bucket. This user can "
                "access the web console and read some data.">>}],
      [{[{bucket, bucket_name}, analytics], [select]},
       {[ui], [read]},
       {[pools], [read]}]},
     {analytics_admin, [],
      [{name, <<"Analytics Admin">>},
       {desc, <<"Can manage dataverses. Can manage all Analytics links. "
                "Can manage all datasets. This user can access the web "
                "console but cannot read data.">>}],
      [{[analytics], [manage]},
       {[{bucket, any}, analytics], [manage]},
       {[ui], [read]},
       {[pools], [read]}]},
     {mobile_sync_gateway, [bucket_name],
      [{name, <<"Sync Gateway">>},
       {desc, <<"Full access to bucket data as required by Sync Gateway. "
                "This user cannot access the web console and is intended "
                "only for use by Sync Gateway. This user can read and "
                "write data, manage indexes and views, and read some "
                "cluster information.">>}],
      [{[{bucket, bucket_name}, data], all},
       {[{bucket, bucket_name}, views], all},
       {[{bucket, bucket_name}, n1ql, index], all},
       {[{bucket, bucket_name}, n1ql], [execute]},
       {[{bucket, bucket_name}], [read, flush]},
       {[{bucket, bucket_name}, settings], [read]},
       {[admin, memcached, idle], [write]},
       {[settings, autocompaction], [read]},
       {[pools], [read]}]}].

internal_roles() ->
    [{stats_reader, [], [],
      [{[admin, internal, stats], [read]}]}].

-spec get_definitions(all | public) -> [rbac_role_def(), ...].
get_definitions(Type) ->
    get_definitions(ns_config:latest(), Type).

-spec get_definitions(ns_config(), all | public) -> [rbac_role_def(), ...].
get_definitions(Config, all) ->
    get_definitions(Config, public) ++ internal_roles();
get_definitions(Config, public) ->
    case cluster_compat_mode:is_cluster_cheshirecat(Config) of
        true ->
            roles();
        false ->
            case cluster_compat_mode:is_cluster_66(Config) of
                true ->
                    menelaus_old_roles:roles_pre_cheshirecat();
                false ->
                    case cluster_compat_mode:is_cluster_55(Config) of
                        true ->
                            menelaus_old_roles:roles_pre_66();
                        false ->
                            menelaus_old_roles:roles_pre_55()
                    end
            end
    end.

-spec object_match(
        rbac_permission_object(), rbac_permission_pattern_object()) ->
                          boolean().
object_match(_, []) ->
    true;
object_match([], [_|_]) ->
    false;
object_match([Vertex | RestOfObject],
             [FilterVertex | RestOfObjectPattern]) ->
    case vertex_match(Vertex, FilterVertex) of
        true ->
            object_match(RestOfObject, RestOfObjectPattern);
        false ->
            false
    end;
object_match(_, _) ->
    false.

vertex_params_match(Params, FilterParams) ->
    lists:all(fun vertex_param_match/1, lists:zip(Params, FilterParams)).

vertex_param_match({any, _}) ->
    true;
vertex_param_match({all, any}) ->
    true;
vertex_param_match({_, any}) ->
    true;
vertex_param_match({A, B}) ->
    A =:= B.

vertex_match({collection, Params}, {bucket, B}) ->
    vertex_params_match(Params, [B, any, any]);
vertex_match({bucket, B}, {collection, Params}) ->
    vertex_params_match([B, all, all], Params);
vertex_match({scope, [B, S]}, Filter) ->
    vertex_match({collection, [B, S, all]}, Filter);
vertex_match({collection, Params}, {collection, FilterParams}) ->
    vertex_params_match(Params, FilterParams);
vertex_match({_Same, Param}, {_Same, FilterParam}) ->
    vertex_param_match({Param, FilterParam});
vertex_match(_Same, _Same) ->
    true;
vertex_match(_, _) ->
    false.

-spec get_allowed_operations(
        rbac_permission_object(), [rbac_permission_pattern()]) ->
                                    rbac_permission_pattern_operations().
get_allowed_operations(_Object, []) ->
    none;
get_allowed_operations(Object, [{ObjectPattern, AllowedOperations} | Rest]) ->
    case object_match(Object, ObjectPattern) of
        true ->
            AllowedOperations;
        false ->
            get_allowed_operations(Object, Rest)
    end.

-spec operation_allowed(rbac_operation(),
                        rbac_permission_pattern_operations()) ->
                               boolean().
operation_allowed(_, all) ->
    true;
operation_allowed(_, none) ->
    false;
operation_allowed(any, _) ->
    true;
operation_allowed(Operation, AllowedOperations) ->
    lists:member(Operation, AllowedOperations).

-spec is_allowed(rbac_permission(),
                 rbac_identity() | [rbac_compiled_role()]) -> boolean().
is_allowed(Permission, {_, _} = Identity) ->
    Roles = get_compiled_roles(Identity),
    is_allowed(Permission, Roles);
is_allowed({Object, Operation}, Roles) ->
    lists:any(fun (Role) ->
                      Operations = get_allowed_operations(Object, Role),
                      operation_allowed(Operation, Operations)
              end, Roles).

-spec substitute_params([string()],
                        [atom()], [rbac_permission_pattern_raw()]) ->
                               [rbac_permission_pattern()].
substitute_params([], [], Permissions) ->
    Permissions;
substitute_params(Params, ParamDefinitions, Permissions) ->
    ParamPairs = lists:zip(ParamDefinitions, Params),
    lists:map(
      fun ({ObjectPattern, AllowedOperations}) ->
              {lists:map(
                 fun ({Name, any}) ->
                         {Name, any};
                     ({Name, List}) when is_list(List) ->
                         {Name, [substitute_param(Param, ParamPairs) ||
                                    Param <- List]};
                     ({Name, Param}) ->
                         {Name, substitute_param(Param, ParamPairs)};
                     (Vertex) ->
                         Vertex
                 end, ObjectPattern), AllowedOperations}
      end, Permissions).

substitute_param(Param, ParamPairs) ->
    {Param, Subst} = lists:keyfind(Param, 1, ParamPairs),
    Subst.

find_bucket(Name, Buckets) ->
    find_object(Name, Buckets,
                fun (N, B) ->
                        case ns_bucket:get_bucket_from_configs(N, B) of
                            {ok, Props} ->
                                Props;
                            not_present ->
                                undefined
                        end
                end,
                fun ns_bucket:bucket_uuid/1).

find_scope(Name, BucketCfg) ->
    find_object(Name, BucketCfg,
                ?cut(collections:get_scope(_1, collections:get_manifest(_2))),
                fun collections:get_uid/1).

find_collection(Name, Scope) ->
    find_object(Name, Scope, fun collections:get_collection/2,
                fun collections:get_uid/1).

find_object(any, _List, _Find, _GetId) ->
    {any, any};
find_object({Name, Id}, List, Find, GetId) ->
    case find_object(Name, List, Find, GetId) of
        RV = {{Name, Id}, _} ->
            RV;
        _ ->
            undefined
    end;
find_object(Name, List, Find, GetId) when is_list(Name) ->
    case Find(Name, List) of
        undefined ->
            undefined;
        Props ->
            {{Name, GetId(Props)}, Props}
    end.

-spec params_version(list()) -> term().
params_version(Buckets) ->
    [{Name, ns_bucket:bucket_uuid(Props),
      collections:get_uid(collections:get_manifest(Props))} ||
        {Name, Props} <- Buckets].

compile_params([], [], _Buckets) ->
    [];
compile_params([bucket_name], [B], Buckets) ->
    case find_bucket(B, Buckets) of
        {Bucket, _} ->
            [Bucket];
        undefined ->
            false
    end;
compile_params(?RBAC_COLLECTION_PARAMS, [B, S, C], Buckets) ->
    case find_bucket(B, Buckets) of
        {Bucket, Props} ->
            case find_scope(S, Props) of
                {Scope, ScopeProps} ->
                    case find_collection(C, ScopeProps) of
                        {Coll, _} ->
                            [Bucket, Scope, Coll];
                        undefined ->
                            false
                    end;
                undefined ->
                    false
            end;
        undefined ->
            false
    end.

compile_role({Name, Params}, CompileRole, Definitions, Buckets) ->
    case lists:keyfind(Name, 1, Definitions) of
        {Name, ParamDefs, _Props, Permissions} ->
            case compile_params(ParamDefs, Params, Buckets) of
                false ->
                    false;
                NewParams ->
                    {true, CompileRole(Name, NewParams, ParamDefs, Permissions)}
            end;
        false ->
            false
    end;
compile_role(Name, CompileRole, Definitions, Buckets) when is_atom(Name) ->
    compile_role({Name, []}, CompileRole, Definitions, Buckets).

compile_roles(CompileRole, Roles, Definitions, Buckets) ->
    lists:filtermap(compile_role(_, CompileRole, Definitions, Buckets), Roles).

-spec compile_roles([rbac_role()], [rbac_role_def()] | undefined, list()) ->
                           [rbac_compiled_role()].
compile_roles(_Roles, undefined, _Buckets) ->
    %% can happen briefly after node joins the cluster on pre 5.0 clusters
    [];
compile_roles(Roles, Definitions, Buckets) ->
    compile_roles(
      fun (_Name, Params, ParamDefs, Permissions) ->
              substitute_params(strip_ids(ParamDefs, Params),
                                ParamDefs, Permissions)
      end, Roles, Definitions, Buckets).

-spec get_roles(rbac_identity()) -> [rbac_role()].
get_roles({"", wrong_token}) ->
    case ns_config_auth:is_system_provisioned() of
        false ->
            [admin];
        true ->
            []
    end;
get_roles({"", anonymous}) ->
    case ns_config_auth:is_system_provisioned() of
        false ->
            [admin];
        true ->
            [{bucket_full_access, [BucketName]} ||
                BucketName <- ns_config_auth:get_no_auth_buckets(
                                ns_config:latest())]
    end;
get_roles({_, admin}) ->
    [admin];
get_roles({_, stats_reader}) ->
    [stats_reader];
get_roles({BucketName, bucket}) ->
    [{bucket_full_access, [BucketName]}];
get_roles({_User, external} = Identity) ->
    menelaus_users:get_roles(Identity);
get_roles({_User, local} = Identity) ->
    menelaus_users:get_roles(Identity).

compiled_roles_cache_name() ->
    compiled_roles_cache.

start_compiled_roles_cache() ->
    UsersFilter =
        fun ({user_version, _V}) ->
                true;
            ({group_version, _V}) ->
                true;
            (_) ->
                false
        end,
    ConfigFilter =
        fun ({buckets, _}) ->
                true;
            ({cluster_compat_version, _}) ->
                true;
            ({rest_creds, _}) ->
                true;
            (_) ->
                false
        end,
    GetVersion =
        fun () ->
                {cluster_compat_mode:get_compat_version(ns_config:latest()),
                 menelaus_users:get_users_version(),
                 menelaus_users:get_groups_version(),
                 ns_config_auth:is_system_provisioned(),
                 [{Name, ns_bucket:bucket_uuid(BucketConfig)} ||
                     {Name, BucketConfig} <- ns_bucket:get_buckets(
                                               ns_config:latest())]}
        end,
    GetEvents =
        case ns_node_disco:couchdb_node() == node() of
            true ->
                fun () ->
                        dist_manager:wait_for_node(
                          fun ns_node_disco:ns_server_node/0),
                        [{{user_storage_events, ns_node_disco:ns_server_node()},
                          UsersFilter},
                         {ns_config_events, ConfigFilter}]
                end;
            false ->
                fun () ->
                        [{user_storage_events, UsersFilter},
                         {ns_config_events, ConfigFilter}]
                end
        end,

    versioned_cache:start_link(
      compiled_roles_cache_name(), 200, fun build_compiled_roles/1,
      GetEvents, GetVersion).

-spec get_compiled_roles(rbac_identity()) -> [rbac_compiled_role()].
get_compiled_roles({_, external} = Identity) ->
    roles_cache:build_compiled_roles(Identity);
get_compiled_roles(Identity) ->
    versioned_cache:get(compiled_roles_cache_name(), Identity).

build_compiled_roles(Identity) ->
    case ns_node_disco:couchdb_node() == node() of
        false ->
            ?log_debug("Compile roles for user ~p",
                       [ns_config_log:tag_user_data(Identity)]),
            Definitions = get_definitions(all),
            compile_roles(get_roles(Identity), Definitions,
                          ns_bucket:get_buckets());
        true ->
            ?log_debug("Retrieve compiled roles for user ~p from ns_server "
                       "node", [ns_config_log:tag_user_data(Identity)]),
            rpc:call(ns_node_disco:ns_server_node(),
                     ?MODULE, build_compiled_roles, [Identity])
    end.

filter_out_invalid_roles(Roles, Definitions, Buckets) ->
    compile_roles(fun (Name, [], _, _) ->
                          Name;
                      (Name, Params, _, _) ->
                          {Name, Params}
                  end, Roles, Definitions, Buckets).

get_applicable_buckets(Buckets, {[{bucket, Bucket} | _], _})
  when Bucket =/= any ->
    case ns_bucket:get_bucket_from_configs(Bucket, Buckets) of
        {ok, Props} ->
            [{Bucket, Props}];
        not_present ->
            []
    end;
get_applicable_buckets(Buckets, _) ->
    Buckets.

calculate_possible_param_values(_Buckets, [], _) ->
    [[]];
calculate_possible_param_values(Buckets, [bucket_name], Permission) ->
    [[any] | [[{Name, ns_bucket:bucket_uuid(Props)}] ||
                 {Name, Props} <- get_applicable_buckets(Buckets, Permission)]];
calculate_possible_param_values(Buckets, ?RBAC_COLLECTION_PARAMS, Permission) ->
    [[any, any, any] |
     [[{Name, ns_bucket:bucket_uuid(Props)}, any, any] ||
         {Name, Props} <- get_applicable_buckets(Buckets, Permission)]].

all_params_combinations() ->
    [[], [bucket_name], ?RBAC_COLLECTION_PARAMS].

-spec calculate_possible_param_values(list(), undefined | rbac_permission()) ->
                                             rbac_all_param_values().
calculate_possible_param_values(Buckets, Permission) ->
    [{Combination,
      calculate_possible_param_values(Buckets, Combination, Permission)} ||
        Combination <- all_params_combinations()].

-spec get_possible_param_values([atom()], rbac_all_param_values()) ->
                                       [[rbac_role_param()]].
get_possible_param_values(ParamDefs, AllValues) ->
    {ParamDefs, Values} = lists:keyfind(ParamDefs, 1, AllValues),
    Values.

visible_roles_filter() ->
    case cluster_compat_mode:is_enterprise() of
        true ->
            pipes:filter(fun ({_, _, Props, _}) -> Props =/= [] end);
        false ->
            pipes:filter(fun ({_, _, Props, _}) ->
                                 proplists:get_value(ce, Props, false)
                         end)
    end.

expand_params(AllPossibleValues) ->
    ?make_transducer(
       pipes:foreach(
         ?producer(),
         fun ({Role, [], Props, _}) ->
                 ?yield({Role, Props});
             ({Role, ParamDefs, Props, _}) ->
                 lists:foreach(
                   fun (Values) ->
                           ?yield({{Role, Values}, Props})
                   end, get_possible_param_values(ParamDefs, AllPossibleValues))
         end)).

filter_by_permission(undefined, _Buckets, _Definitions) ->
    pipes:filter(fun (_) -> true end);
filter_by_permission(Permission, Buckets, Definitions) ->
    pipes:filter(
      fun ({Role, _}) ->
              is_allowed(Permission,
                         compile_roles([Role], Definitions, Buckets))
      end).

-spec produce_roles_by_permission(rbac_permission(), ns_config()) ->
                                         pipes:producer(rbac_role()).
produce_roles_by_permission(Permission, Config) ->
    Buckets = ns_bucket:get_buckets(Config),
    AllValues = calculate_possible_param_values(Buckets, Permission),
    Definitions = get_definitions(Config, public),
    pipes:compose(
      [pipes:stream_list(Definitions),
       visible_roles_filter(),
       expand_params(AllValues),
       filter_by_permission(Permission, Buckets, Definitions)]).

strip_id(_, any) ->
    any;
strip_id(_, {P, _Id}) ->
    P;
strip_id(bucket_name, P) ->
    %% to be removed as part of MB-38411
    P.

-spec strip_ids([rbac_role_def_param()], [rbac_role_param()]) ->
                       [rbac_role_param()].
strip_ids(ParamDefs, Params) ->
    [strip_id(ParamDef, Param) || {ParamDef, Param} <-
                                      lists:zip(ParamDefs, Params)].

-spec get_param_defs(rbac_role_name(), [rbac_role_def()]) ->
                            not_found | [rbac_role_def_param()].
get_param_defs(RoleName, Definitions) ->
    case lists:keyfind(RoleName, 1, Definitions) of
        {RoleName, ParamsDef, _, _} ->
            ParamsDef;
        _ ->
            not_found
    end.

-spec validate_role(rbac_role(), [rbac_role_def()], list()) ->
                           false | {ok, rbac_role()}.
validate_role(Role, Definitions, Buckets) when is_atom(Role) ->
    validate_role(Role, [], Definitions, Buckets);
validate_role({Role, Params}, Definitions, Buckets) ->
    validate_role(Role, Params, Definitions, Buckets).

validate_role(Role, Params, Definitions, Buckets) ->
    case lists:keyfind(Role, 1, Definitions) of
        {Role, ParamsDef, _, _} when length(Params) =:= length(ParamsDef) ->
            case compile_params(ParamsDef, Params, Buckets) of
                false ->
                    false;
                [] ->
                    {ok, Role};
                Expanded ->
                    {ok, {Role, Expanded}}
            end;
        _ ->
            false
    end.

-spec validate_roles([rbac_role()], ns_config()) ->
                            {GoodRoles :: [rbac_role()],
                             BadRoles :: [rbac_role()]}.
validate_roles(Roles, Config) ->
    Definitions = pipes:run(pipes:stream_list(get_definitions(Config, public)),
                            visible_roles_filter(),
                            pipes:collect()),
    Buckets = ns_bucket:get_buckets(Config),
    lists:foldl(fun (Role, {Validated, Unknown}) ->
                        case validate_role(Role, Definitions, Buckets) of
                            false ->
                                {Validated, [Role | Unknown]};
                            {ok, R} ->
                                {[R | Validated], Unknown}
                        end
                end, {[], []}, Roles).

-spec get_security_roles(ns_config()) -> [rbac_role()].
get_security_roles(Config) ->
    pipes:run(produce_roles_by_permission({[admin, security], any}, Config),
              pipes:collect()).

external_auth_polling_interval() ->
    ns_config:read_key_fast(external_auth_polling_interval,
                            ?DEFAULT_EXTERNAL_ROLES_POLLING_INTERVAL).


-ifdef(TEST).
filter_out_invalid_roles_test() ->
    Roles = [{role1, [{"bucket1", <<"id1">>}]},
             {role2, [{"bucket2", <<"id2">>}]}],
    Definitions = [{role1, [bucket_name],
                    [{name,<<"">>},{desc, <<"">>}],
                    [{[{bucket,bucket_name},settings],[read]}]},
                   {role2, [bucket_name],
                    [{name,<<"">>},{desc, <<"">>}],
                    [{[{bucket,bucket_name},n1ql,update],[execute]}]}],
    Buckets = [{"bucket1", [{uuid, <<"id1">>}]}],
    ?assertEqual([{role1, [{"bucket1", <<"id1">>}]}],
                 filter_out_invalid_roles(Roles, Definitions, Buckets)).

%% assertEqual is used instead of assert and assertNot to avoid
%% dialyzer warnings
object_match_test() ->
    ?assertEqual(true, object_match([], [])),
    ?assertEqual(false, object_match([], [o1, o2])),
    ?assertEqual(true, object_match([o3], [])),
    ?assertEqual(true, object_match([o1, o2], [o1, o2])),
    ?assertEqual(false, object_match([o1], [o1, o2])),
    ?assertEqual(true, object_match([o1, o2], [o1])),
    ?assertEqual(true, object_match([{b, "a"}], [{b, "a"}])),
    ?assertEqual(false, object_match([{b, "a"}], [{b, "b"}])),
    ?assertEqual(true, object_match([{b, any}], [{b, "b"}])),
    ?assertEqual(true, object_match([{b, "a"}], [{b, any}])),
    ?assertEqual(true, object_match([{b, any}], [{b, any}])),
    ?assertEqual(true, object_match([{b, all}], [{b, any}])),
    ?assertEqual(false, object_match([{b, all}], [{b, "a"}])).

object_match_with_collections_test() ->
    ?assertEqual(true, object_match([{collection, ["b", "s", "c"]}],
                                    [{bucket, "b"}])),
    ?assertEqual(true, object_match([{collection, ["b", "s", all]}],
                                    [{bucket, "b"}])),
    ?assertEqual(true, object_match([{collection, ["b", all, all]}],
                                    [{bucket, "b"}])),
    ?assertEqual(true, object_match([{scope, ["b", "s"]}], [{bucket, "b"}])),
    ?assertEqual(true, object_match([{scope, ["b", all]}], [{bucket, "b"}])),
    ?assertEqual(true, object_match([{collection, ["b", "s", "c"]}],
                                    [{collection, ["b", "s", "c"]}])),
    ?assertEqual(false, object_match([{collection, ["b", "s", "c1"]}],
                                     [{collection, ["b", "s", "c"]}])),
    ?assertEqual(false, object_match([{collection, ["b", "s", all]}],
                                     [{collection, ["b", "s", "c"]}])),
    ?assertEqual(true, object_match([{collection, ["b", "s", any]}],
                                    [{collection, ["b", "s", "c"]}])),
    ?assertEqual(false, object_match([{scope, ["b", "s"]}],
                                     [{collection, ["b", "s", "c"]}])),
    ?assertEqual(true, object_match([{scope, ["b", "s"]}],
                                    [{collection, ["b", "s", any]}])),
    ?assertEqual(false, object_match([{bucket, "b"}],
                                     [{collection, ["b", "s", "c"]}])),
    ?assertEqual(false, object_match([{bucket, "b"}],
                                     [{collection, ["b", "s", any]}])),
    ?assertEqual(true, object_match([{bucket, "b"}],
                                    [{collection, ["b", any, any]}])),
    ?assertEqual(false, object_match([{bucket, "b"}],
                                     [{collection, ["b1", any, any]}])).

toy_buckets() ->
    [{"test", [{uuid, <<"test_id">>}]},
     {"default", [{uuid, <<"default_id">>},
                  {collections_manifest, toy_manifest()}]}].

toy_manifest() ->
    [{uid, 2},
     {scopes, [{"s",  [{uid, 1}, {collections, [{"c",  [{uid, 1}]},
                                                {"c1", [{uid, 2}]}]}]},
               {"s1", [{uid, 2}, {collections, [{"c",  [{uid, 3}]}]}]}]}].

compile_roles(Roles, Definitions) ->
    compile_roles(Roles, Definitions, toy_buckets()).

compile_roles_test() ->
    Definitions = [{simple_role, [], [],
                    [{[admin], all}]},
                   {test_role, [bucket_name], [],
                    [{[{bucket, bucket_name}], none}]},
                   {test_role1, ?RBAC_COLLECTION_PARAMS, [],
                    [{[{bucket, bucket_name}], oper1},
                     {[{bucket, any}, docs], oper2},
                     {[v1, v2], oper3},
                     {[{collection, ?RBAC_COLLECTION_PARAMS}], oper4}]}],
    ?assertEqual([[{[admin], all}]],
                 compile_roles([simple_role, wrong_role], Definitions)),
    ?assertEqual([[{[{bucket, "test"}], none}]],
                 compile_roles([{test_role, ["test"]}], Definitions)),
    ?assertEqual([[{[{bucket, "test"}], none}]],
                 compile_roles([{test_role, [{"test", <<"test_id">>}]}],
                               Definitions)),
    ?assertEqual([], compile_roles([{test_role, [{"test", <<"wrong_id">>}]}],
                                   Definitions)),

    ExpectedTestRole1 = [[{[{bucket, "default"}], oper1},
                          {[{bucket, any}, docs], oper2},
                          {[v1, v2], oper3},
                          {[{collection, ["default", "s", "c"]}], oper4}]],
    ?assertEqual(ExpectedTestRole1,
                 compile_roles(
                   [{test_role1, ["default", "s", "c"]}], Definitions)),
    ?assertEqual(ExpectedTestRole1,
                 compile_roles(
                   [{test_role1, [{"default", <<"default_id">>},
                                  {"s", 1}, {"c", 1}]}], Definitions)),
    ?assertEqual([],
                 compile_roles(
                   [{test_role1, [{"default", <<"wrong_id">>},
                                  {"s", 1}, {"c", 1}]}], Definitions)),
    ?assertEqual([],
                 compile_roles(
                   [{test_role1, [{"default", <<"default_id">>},
                                  {"s", 1}, {"c", 2}]}], Definitions)).

admin_test() ->
    Roles = compile_roles([admin], roles()),
    ?assertEqual(true, is_allowed({[buckets], create}, Roles)),
    ?assertEqual(true, is_allowed({[something, something], anything}, Roles)).

ro_admin_test() ->
    Roles = compile_roles([ro_admin], roles()),
    ?assertEqual(false,
                 is_allowed({[{bucket, "test"}, password], read}, Roles)),
    ?assertEqual(false, is_allowed({[{bucket, "test"}, data], read}, Roles)),
    ?assertEqual(true,
                 is_allowed({[{bucket, "test"}, something], read}, Roles)),
    ?assertEqual(false,
                 is_allowed({[{bucket, "test"}, something], write}, Roles)),
    ?assertEqual(false, is_allowed({[admin, security], write}, Roles)),
    ?assertEqual(true, is_allowed({[admin, security], read}, Roles)),
    ?assertEqual(false, is_allowed({[admin, other], write}, Roles)),
    ?assertEqual(true, is_allowed({[anything], read}, Roles)),
    ?assertEqual(false, is_allowed({[anything], write}, Roles)).

bucket_views_admin_check_global(Roles) ->
    ?assertEqual(false, is_allowed({[xdcr], read}, Roles)),
    ?assertEqual(false, is_allowed({[admin], read}, Roles)),
    ?assertEqual(true, is_allowed({[something], read}, Roles)),
    ?assertEqual(false, is_allowed({[something], write}, Roles)),
    ?assertEqual(false, is_allowed({[buckets], create}, Roles)).

bucket_views_admin_check_another(Roles) ->
    ?assertEqual(false, is_allowed({[{bucket, "another"}, xdcr], read}, Roles)),
    ?assertEqual(false,
                 is_allowed({[{bucket, "another"}, views], read}, Roles)),
    ?assertEqual(false, is_allowed({[{bucket, "another"}, data], read}, Roles)),
    ?assertEqual(true,
                 is_allowed({[{bucket, "another"}, settings], read}, Roles)),
    ?assertEqual(false,
                 is_allowed({[{bucket, "another"}, settings], write}, Roles)),
    ?assertEqual(false, is_allowed({[{bucket, "another"}], read}, Roles)),
    ?assertEqual(false, is_allowed({[buckets], create}, Roles)).

bucket_admin_check_default(Roles) ->
    ?assertEqual(true, is_allowed({[{bucket, "default"}, xdcr], read}, Roles)),
    ?assertEqual(true,
                 is_allowed({[{bucket, "default"}, xdcr], execute}, Roles)),
    ?assertEqual(
       true, is_allowed({[{bucket, "default"}, anything], anything}, Roles)),
    ?assertEqual(
       true, is_allowed({[{bucket, "default"}, anything], anything}, Roles)).

bucket_admin_test() ->
    Roles = compile_roles([{bucket_admin, ["default"]}], roles()),
    bucket_admin_check_default(Roles),
    bucket_views_admin_check_another(Roles),
    bucket_views_admin_check_global(Roles).

bucket_admin_wildcard_test() ->
    Roles = compile_roles([{bucket_admin, [any]}], roles()),
    bucket_admin_check_default(Roles),
    bucket_views_admin_check_global(Roles).

views_admin_check_default(Roles) ->
    ?assertEqual(true,
                 is_allowed({[{bucket, "default"}, views], anything}, Roles)),
    ?assertEqual(true,
                 is_allowed({[{bucket, "default"}, data], read}, Roles)),
    ?assertEqual(false,
                 is_allowed({[{bucket, "default"}, data], write}, Roles)),
    ?assertEqual(true,
                 is_allowed({[{bucket, "default"}, settings], read}, Roles)),
    ?assertEqual(false,
                 is_allowed({[{bucket, "default"}, settings], write}, Roles)),
    ?assertEqual(false, is_allowed({[{bucket, "default"}], read}, Roles)).

views_admin_test() ->
    Roles = compile_roles([{views_admin, ["default"]}], roles()),
    views_admin_check_default(Roles),
    bucket_views_admin_check_another(Roles),
    bucket_views_admin_check_global(Roles).

views_admin_wildcard_test() ->
    Roles = compile_roles([{views_admin, [any]}], roles()),
    views_admin_check_default(Roles),
    bucket_views_admin_check_global(Roles).

bucket_full_access_check(Roles, Bucket, Allowed) ->
    ?assertEqual(Allowed,
                 is_allowed({[{bucket, Bucket}, data], anything}, Roles)),
    ?assertEqual(Allowed, is_allowed({[{bucket, Bucket}], flush}, Roles)),
    ?assertEqual(Allowed, is_allowed({[{bucket, Bucket}], flush}, Roles)),
    ?assertEqual(false, is_allowed({[{bucket, Bucket}], write}, Roles)).

bucket_full_access_test() ->
    Roles = compile_roles([{bucket_full_access, ["default"]}], roles()),
    bucket_full_access_check(Roles, "default", true),
    bucket_full_access_check(Roles, "another", false),
    ?assertEqual(true, is_allowed({[pools], read}, Roles)),
    ?assertEqual(false, is_allowed({[another], read}, Roles)).

replication_admin_test() ->
    Roles = compile_roles([replication_admin], roles()),
    ?assertEqual(true,
                 is_allowed({[{bucket, "default"}, xdcr], anything}, Roles)),
    ?assertEqual(false,
                 is_allowed({[{bucket, "default"}, password], read}, Roles)),
    ?assertEqual(false,
                 is_allowed({[{bucket, "default"}, views], read}, Roles)),
    ?assertEqual(true,
                 is_allowed({[{bucket, "default"}, settings], read}, Roles)),
    ?assertEqual(false,
                 is_allowed({[{bucket, "default"}, settings], write}, Roles)),
    ?assertEqual(true,
                 is_allowed({[{bucket, "default"}, data], read}, Roles)),
    ?assertEqual(false,
                 is_allowed({[{bucket, "default"}, data], write}, Roles)),
    ?assertEqual(true, is_allowed({[xdcr], anything}, Roles)),
    ?assertEqual(false, is_allowed({[admin], read}, Roles)),
    ?assertEqual(true, is_allowed({[other], read}, Roles)).

data_reader_collection_test_() ->
    Permissions =
        [{[{collection, ["default", "s", "c"]}, data, docs], read},
         {[{collection, ["default", "s", "c1"]}, data, docs], read},
         {[{collection, ["default", "s", "c2"]}, data, docs], read},
         {[{scope, ["default", "s"]}, data, docs], read},
         {[{scope, ["default", "s1"]}, data, docs], read},
         {[{scope, ["default", "s2"]}, data, docs], read},
         {[{bucket, "default"}, data, docs], read},
         {[{bucket, "default"}, settings], read}],
    Test =
        fun (Params, Results) ->
                fun () ->
                        Roles = compile_roles([{data_reader, Params}], roles()),
                        ?assertEqual(Results, lists:map(is_allowed(_, Roles),
                                                        Permissions))
                end
        end,
    {foreach, fun () -> ok end,
     [{"existing collection with id's",
       Test([{"default", <<"default_id">>}, {"s", 1}, {"c", 1}],
            [true, false, false, false, false, false, false, true])},
      {"wrong collection id",
       Test([{"default", <<"default_id">>}, {"s", 1}, {"c", 2}],
            [false, false, false, false, false, false, false, false])},
      {"existing collection without id's",
       Test(["default", "s", "c"],
            [true, false, false, false, false, false, false, true])},
      {"scope",
       Test(["default", "s", any],
            [true, true, true, true, false, false, false, true])},
      {"whole bucket",
       Test(["default", any, any],
            [true, true, true, true, true, true, true, true])},
      {"another bucket",
       Test(["test", any, any],
            [false, false, false, false, false, false, false, false])}
     ]}.

validate_role_test() ->
    ValidateRole = validate_role(_, roles(), toy_buckets()),
    ?assertEqual({ok, admin}, ValidateRole(admin)),
    ?assertEqual({ok, {bucket_admin, [{"test", <<"test_id">>}]}},
                 ValidateRole({bucket_admin, ["test"]})),
    ?assertEqual({ok, {views_admin, [any]}},
                 ValidateRole({views_admin, [any]})),
    ?assertEqual(false, ValidateRole(something)),
    ?assertEqual(false, ValidateRole({bucket_admin, ["something"]})),
    ?assertEqual(false, ValidateRole({something, ["test"]})),
    ?assertEqual(false, ValidateRole({admin, ["test"]})),
    ?assertEqual(false, ValidateRole(bucket_admin)),
    ?assertEqual(false, ValidateRole({bucket_admin, ["test", "test"]})),
    ?assertEqual(false, ValidateRole({data_reader, ["default"]})),
    ?assertEqual(false, ValidateRole({data_reader, ["default", "s"]})),
    DataReader =
        {data_reader, [{"default", <<"default_id">>}, {"s", 1}, {"c", 1}]},
    ?assertEqual({ok, DataReader},
                 ValidateRole({data_reader, ["default", "s", "c"]})),
    ?assertEqual(false, ValidateRole({data_reader, ["default", "s", "d"]})),
    ?assertEqual({ok, DataReader}, ValidateRole(DataReader)),
    ?assertEqual(false, ValidateRole(
                          {data_reader,
                           [{"default", <<"test_id">>}, {"s", 1}, {"c", 2}]})).

enum_roles(Roles, Buckets) ->
    Definitions = roles(),
    lists:flatmap(
      fun (BucketName) ->
              BucketWithId =
                  case BucketName of
                      any ->
                          any;
                      _ ->
                          {ok, Props} = ns_bucket:get_bucket_from_configs(
                                          BucketName, toy_buckets()),
                          {BucketName, ns_bucket:bucket_uuid(Props)}
                  end,
              lists:map(
                fun (Role) ->
                        Length = length(get_param_defs(Role, Definitions)),
                        {Role, misc:align_list([BucketWithId], Length, any)}
                end, Roles)
      end, Buckets).

produce_roles_by_permission_test_() ->
    Config = [[{buckets, [{configs, toy_buckets()}]}]],
    GetRoles =
        fun (Permission) ->
                proplists:get_keys(
                  pipes:run(produce_roles_by_permission(Permission, Config),
                            pipes:collect()))
        end,
    Test =
        fun (Roles, Permission) ->
                fun () ->
                        ?assertListsEqual(Roles, GetRoles(Permission))
                end
        end,
    {foreach,
     fun() ->
             meck:new(cluster_compat_mode, [passthrough]),
             meck:expect(cluster_compat_mode, is_enterprise,
                         fun () -> true end),
             meck:expect(cluster_compat_mode, is_cluster_cheshirecat,
                         fun (_) -> true end)
     end,
     fun (_) ->
             meck:unload(cluster_compat_mode)
     end,
     [{"security permission",
       Test([admin, ro_admin, security_admin], {[admin, security], any})},
      {"pools read",
       fun () ->
               Roles = GetRoles({[pools], read}),
               ?assertListsEqual(
                  [],
                  [admin, analytics_reader,
                   {data_reader, [any, any, any]},
                   {data_reader, [{"test",<<"test_id">>}, any, any]}] -- Roles)
       end},
      {"bucket settings read",
       Test([admin, cluster_admin, query_external_access, query_system_catalog,
             replication_admin, ro_admin, security_admin] ++
                enum_roles([bucket_full_access, bucket_admin, views_admin,
                            data_backup, data_dcp_reader,
                            data_monitoring, data_writer, data_reader,
                            fts_admin, fts_searcher, query_delete,
                            query_insert, query_manage_index, query_select,
                            query_update, replication_target,
                            mobile_sync_gateway],
                           [any, "test"]),
            {[{bucket, "test"}, settings], read})},
      {"xattr write",
       Test([admin] ++
                enum_roles([bucket_full_access, data_backup, data_writer,
                            mobile_sync_gateway],
                           [any, "test"]),
            {[{bucket, "test"}, data, xattr], write})},
      {"any bucket",
       Test([admin] ++
                enum_roles([bucket_full_access, data_backup, data_writer,
                            mobile_sync_gateway],
                           [any, "test", "default"]),
            {[{bucket, any}, data, xattr], write})},
      {"wrong bucket",
       Test([admin] ++
                enum_roles([bucket_full_access, data_backup, data_writer,
                            mobile_sync_gateway],
                           [any]),
            {[{bucket, "wrong"}, data, xattr], write})}]}.

params_version_test() ->
    Version1 = params_version(toy_buckets()),
    Version2 = params_version(lists:keydelete("test", 1, toy_buckets())),
    Version3 = params_version(lists:keyreplace(
                                "test", 1, toy_buckets(),
                                {"test", [{uuid, <<"test_id1">>}]})),
    Version4 = params_version(
                 lists:keyreplace(
                   "test", 1, toy_buckets(),
                   {"test", [{uuid, <<"test_id">>},
                             {collections_manifest, toy_manifest()}]})),
    ?assertNotEqual(Version1, Version2),
    ?assertNotEqual(Version1, Version3),
    ?assertNotEqual(Version1, Version4).

-endif.
