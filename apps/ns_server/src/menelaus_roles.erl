%% @author Couchbase <info@couchbase.com>
%% @copyright 2016-Present Couchbase, Inc.
%%
%% Use of this software is governed by the Business Source License included in
%% the file licenses/BSL-Couchbase.txt.  As of the Change Date specified in that
%% file, in accordance with the Business Source License, use of this software
%% will be governed by the Apache License, Version 2.0, included in the file
%% licenses/APL2.txt.
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
-include_lib("ns_common/include/cut.hrl").

-ifdef(TEST).
-include_lib("eunit/include/eunit.hrl").
-include("ns_test.hrl").
-endif.

-define(DEFAULT_EXTERNAL_ROLES_POLLING_INTERVAL, 10*60*1000).

-export([get_definitions/1,
         get_public_definitions/1,
         is_allowed/2,
         get_roles/1,
         get_compiled_roles/1,
         get_params_from_permissions/1,
         compile_params/3,
         compile_roles/3,
         validate_roles/1,
         validate_roles/2,
         validate_roles/3,
         params_version/1,
         filter_out_invalid_roles/3,
         produce_roles_by_permission/2,
         get_security_roles/1,
         get_user_admin_roles/1,
         external_auth_polling_interval/0,
         get_param_defs/2,
         ui_folders/0,
         get_visible_role_definitions/0,
         strip_ids/2]).

-export([start_compiled_roles_cache/0]).

%% for RPC from ns_couchdb node
-export([build_compiled_roles/1]).

-spec roles() -> [rbac_role_def(), ...].
roles() ->
    [{admin, [],
      [{name, <<"Full Admin">>},
       {folder, admin},
       {desc, <<"Can manage all cluster features (including security). "
                "This user can access the web console. This user can read and "
                "write all data.">>},
       {ce, true}],
      [{[], all}]},
     {ro_admin, [],
      [{name, <<"Read-Only Admin">>},
       {folder, admin},
       {desc, <<"Can view all cluster statistics. This user can access the "
                "web console.">>},
       {ce, true}],
      [{[{bucket, any}, data], none},
       {[{bucket, any}, fts], none},
       {[{bucket, any}, analytics], none},
       {[admin, security], [read]},
       {[admin, security_info], [read]},
       {[admin, stats_export], [read]},
       {[admin, users], [read]},
       {[admin], none},
       {[eventing], none},
       {[analytics], none},
       {[backup], [read]},
       {[], [read, list]}]},
     {security_admin, [],
      [{name, <<"Security Admin">>},
       {folder, admin},
       {desc, <<"Can view all cluster statistics, manage certificates, and "
                "manage security related settings. This user can access the "
                "web console. This user cannot read data.">>}],
      [{[admin, security, admin], none},
       {[admin, security], all},
       {[admin, security_info], all},
       {[admin, users], [read]},
       {[admin, logs], none},
       {[admin, event], none},
       {[admin, metakv], none},
       {[admin, settings, metrics], none},
       {[{bucket, any}, data], none},
       {[{bucket, any}, views], none},
       {[{bucket, any}, n1ql], none},
       {[{bucket, any}, fts], none},
       {[{bucket, any}, analytics], none},
       {[{bucket, any}], [read]},
       {[analytics], none},
       {[backup], none},
       {[eventing], none},
       {[xdcr], none},
       {[settings, fts], none},
       {[settings, metrics], none},
       {[], [read, list]}]},
     {user_admin_local, [],
      [{name, <<"Local User Admin">>},
       {folder, admin},
       {desc, <<"Can view all cluster statistics and manage local user "
                "roles, but not grant Full Admin or Security Admin roles to "
                "other users or itself. This user can access the web console. "
                "This user cannot read data.">>}],
      [{[admin, security, admin], none},
       {[admin, security], none},
       {[admin, security_info], [read, write]},
       {[admin, users, admin], none},
       {[admin, users, external], none},
       {[admin, users], all},
       {[admin, logs], none},
       {[admin, event], none},
       {[admin, metakv], none},
       {[admin, settings, metrics], none},
       {[{bucket, any}, data], none},
       {[{bucket, any}, views], none},
       {[{bucket, any}, n1ql], none},
       {[{bucket, any}, fts], none},
       {[{bucket, any}, analytics], none},
       {[{bucket, any}], [read]},
       {[analytics], none},
       {[backup], none},
       {[eventing], none},
       {[xdcr], none},
       {[settings, fts], none},
       {[settings, metrics], none},
       {[], [read, list]}]},
     {user_admin_external, [],
      [{name, <<"External User Admin">>},
       {folder, admin},
       {desc, <<"Can view all cluster statistics and manage external user "
                "roles, but not grant Full Admin or Security Admin roles to "
                "other users or itself. This user can access the web console. "
                "This user cannot read data.">>}],
      [{[admin, security, admin], none},
       {[admin, security], none},
       {[admin, security_info], [read, write]},
       {[admin, users, admin], none},
       {[admin, users, local], none},
       {[admin, users], all},
       {[admin, logs], none},
       {[admin, event], none},
       {[admin, metakv], none},
       {[admin, settings], none},
       {[{bucket, any}, data], none},
       {[{bucket, any}, views], none},
       {[{bucket, any}, n1ql], none},
       {[{bucket, any}, fts], none},
       {[{bucket, any}, analytics], none},
       {[{bucket, any}], [read]},
       {[analytics], none},
       {[backup], none},
       {[eventing], none},
       {[xdcr], none},
       {[settings, fts], none},
       {[settings, metrics], none},
       {[], [read, list]}]},
     {cluster_admin, [],
      [{name, <<"Cluster Admin">>},
       {folder, admin},
       {desc, <<"Can manage all cluster features except security and users. "
                "This user can access the web console. This user cannot read "
                "data.">>}],
      [{[admin, internal], none},
       {[admin, security], none},
       {[admin, security_info], none},
       {[admin, users], none},
       {[admin, diag], [read]},
       {[admin, event], none},
       {[admin, metakv], none},
       {[admin, settings, metrics], none},
       {[{bucket, any}, data], none},
       {[{bucket, any}, views], none},
       {[{bucket, any}, n1ql], none},
       {[{bucket, any}, fts], none},
       {[{bucket, any}, analytics], none},
       {[n1ql, curl], none},
       {[eventing], none},
       {[analytics], none},
       {[backup], none},
       {[], all}]},
     {eventing_admin, [],
      [{name, <<"Eventing Full Admin">>},
       {folder, admin},
       {desc, <<"Can create/manage eventing functions. This user can access "
                "the web console">>}],
      [{[admin], none},
       {[xdcr], none},
       {[{bucket, any}, xdcr], none},
       %% This role is intentionally given this powerful permission
       %% (see MB-42835).
       {[{bucket, any}], all},
       {[n1ql], all},
       {[eventing], all},
       {[analytics], all},
       {[buckets], all},
       {[settings, metrics], none},
       {[], [read]}]},
     {backup_admin, [],
      [{name, <<"Backup Full Admin">>},
       {folder, admin},
       {desc, <<"Can perform backup related tasks. This user can access "
                "the web console">>}],
      [{[admin], none},
       {[settings, metrics], none},
       {[], all}]},
     {bucket_admin, [bucket_name],
      [{name, <<"Bucket Admin">>},
       {folder, bucket},
       {desc, <<"Can manage ALL bucket features for a given bucket (including "
                "start/stop XDCR). This user can access the web console. This "
                "user cannot read data.">>}],
      [{[{bucket, bucket_name}, xdcr], [read, execute]},
       {[{bucket, bucket_name}, data], none},
       {[{bucket, bucket_name}, views], none},
       {[{bucket, bucket_name}, n1ql], none},
       {[{bucket, bucket_name}, fts], none},
       {[{bucket, any}, analytics], none},
       {[{bucket, bucket_name}], all},
       {[{bucket, any}, settings], [read]},
       {[{bucket, any}], none},
       {[xdcr], none},
       {[admin], none},
       {[eventing], none},
       {[analytics], none},
       {[backup], none},
       {[settings, metrics], none},
       {[n1ql, meta], [none]},
       {[], [read]}]},
     {scope_admin, ?RBAC_SCOPE_PARAMS,
      [{name, <<"Manage Scopes">>},
       {folder, bucket},
       {desc, <<"Can create/delete scopes and collections within a given "
                "bucket. This user cannot access the web console.">>}],
      [{[{collection, [bucket_name, scope_name, any]}, collections], all}]},
     {bucket_full_access, [bucket_name],
      [{name, <<"Application Access">>},
       {folder, bucket},
       {desc, <<"Full access to bucket data. This user cannot access the web "
                "console and is intended only for application access. This "
                "user can read and write data except for the _system scope "
                "which can only be read.">>},
       {ce, true}],
      [{[{bucket, bucket_name}, data, docs], [read, insert, delete, upsert,
                                              range_scan, sread]},
       {[{bucket, bucket_name}, data], all},
       {[{bucket, bucket_name}, views], all},
       {[{bucket, bucket_name}, n1ql, index], all},
       {[{bucket, bucket_name}, n1ql], [execute]},
       {[{bucket, bucket_name}], [read, flush]},
       {[{bucket, bucket_name}, settings], [read]},
       {[pools], [read]},
       {[app_telemetry], [write]}]},
     {views_admin, [bucket_name],
      [{name, <<"Views Admin">>},
       {folder, admin},
       {desc, <<"Can create and manage views of a given bucket. This user can "
                "access the web console. This user can read some data.">>}],
      [{[{bucket, bucket_name}, views], all},
       {[{bucket, bucket_name}, data, docs], [read, sread]},
       {[{bucket, bucket_name}, data], [read]},
       {[{bucket, bucket_name}, stats], [read]},
       {[{bucket, any}, settings], [read]},
       {[{bucket, any}], none},
       {[{bucket, bucket_name}, n1ql], [execute]},
       {[xdcr], none},
       {[admin], none},
       {[eventing], none},
       {[analytics], none},
       {[backup], none},
       {[settings, metrics], none},
       {[], [read]}]},
     {views_reader, [bucket_name],
      [{name, <<"Views Reader">>},
       {folder, views},
       {desc, <<"Can read data from the views of a given bucket. This user "
                "cannot access the web console and is intended only for "
                "application access. This user can read some data.">>}],
      [{[{bucket, bucket_name}, views], [read]},
       {[{bucket, bucket_name}, data, docs], [read, sread]},
       {[pools], [read]},
       {[app_telemetry], [write]}]},
     {replication_admin, [],
      [{name, <<"XDCR Admin">>},
       {folder, xdcr},
       {desc, <<"Can administer XDCR features to create cluster references and "
                "replication streams out of this cluster. This user can "
                "access the web console. This user can read some data.">>}],
      [{[{bucket, any}, xdcr], all},
       {[{bucket, any}, data, docs], [read, sread]},
       {[{bucket, any}, data], [read]},
       {[{bucket, any}, settings], [read]},
       {[{bucket, any}, stats], [read]},
       {[{bucket, any}, collections], [read]},
       {[{bucket, any}], none},
       {[xdcr, developer], [read]},
       {[xdcr], all},
       {[admin], none},
       {[eventing], none},
       {[analytics], none},
       {[backup], none},
       {[settings, metrics], none},
       {[], [read]}]},
     {data_reader, ?RBAC_COLLECTION_PARAMS,
      [{name, <<"Data Reader">>},
       {folder, data},
       {desc, <<"Can read data from a given bucket, scope or collection. "
                "This user cannot access the web console and is intended only "
                "for application access. This user can read data, but cannot "
                "write it.">>}],
      [{[{collection, ?RBAC_COLLECTION_PARAMS}, data, docs],
        [read, range_scan, sread]},
       {[{bucket, bucket_name}, settings], [read]},
       {[pools], [read]},
       {[app_telemetry], [write]}]},
     {data_writer, ?RBAC_COLLECTION_PARAMS,
      [{name, <<"Data Writer">>},
       {folder, data},
       {desc, <<"Can write data to a given bucket, scope or collection. "
                "This user cannot access the web console and is intended only "
                "for application access. This user can write data, but cannot "
                "read it.">>}],
      [{[{collection, ?RBAC_COLLECTION_PARAMS}, data, docs],
        [insert, upsert, delete]},
       {[{bucket, bucket_name}, settings], [read]},
       {[pools], [read]},
       {[app_telemetry], [write]}]},
     {data_dcp_reader, ?RBAC_COLLECTION_PARAMS,
      [{name, <<"Data DCP Reader">>},
       {folder, data},
       {desc, <<"Can initiate DCP streams for a given bucket, scope or "
                "collection. This user cannot access the web console and is "
                "intended only for application access. "
                "This user can read data.">>}],
      [{[{collection, ?RBAC_COLLECTION_PARAMS}, data, docs], [read, sread]},
       {[{collection, ?RBAC_COLLECTION_PARAMS}, data, dcpstream], [read]},
       {[{collection, ?RBAC_COLLECTION_PARAMS}, data, sxattr], [read]},
       {[{collection, ?RBAC_COLLECTION_PARAMS}, collections], [read]},
       {[{bucket, bucket_name}, data, dcp], [read]},
       {[{bucket, bucket_name}, data, docs], [sread]},
       {[{bucket, bucket_name}, settings], [read]},
       {[admin, memcached, idle], [write]},
       {[pools], [read]},
       {[app_telemetry], [write]}]},
     {data_backup, [bucket_name],
      [{name, <<"Data Backup & Restore">>},
       {folder, backup},
       {desc, <<"Can backup and restore a given bucket’s data. This user "
                "cannot access the web console and is intended only for "
                "application access. This user can read data.">>}],
      [{[{collection, [bucket_name, any, any]}, collections], all},
       {[{bucket, bucket_name}, data], all},
       {[{bucket, bucket_name}, views], [read, write]},
       {[{bucket, bucket_name}, fts], [read, write, manage]},
       {[{bucket, bucket_name}, stats], [read]},
       {[{bucket, bucket_name}, settings], [read]},
       {[{bucket, bucket_name}, n1ql, index], [create, list, build]},
       {[{bucket, bucket_name}, n1ql, meta], [backup]},
       {[{bucket, bucket_name}, analytics], [manage, select]},
       {[analytics], [select, backup]},
       {[pools], [read]},
       {[app_telemetry], [write]}]},
     {data_monitoring, ?RBAC_COLLECTION_PARAMS,
      [{name, <<"Data Monitor">>},
       {folder, data},
       {desc, <<"Can read statistics for a given bucket, scope or collection. "
                "This user cannot access the web console and is intended only "
                "for application access. This user cannot read data.">>}],
      [{[{collection, ?RBAC_COLLECTION_PARAMS}, stats], [read]},
       {[{collection, ?RBAC_COLLECTION_PARAMS}, collections], [read]},
       {[{bucket, bucket_name}, settings], [read]},
       {[tasks], [read]},
       {[pools], [read]}]},
     {fts_admin, [bucket_name],
      [{name, <<"Search Admin">>},
       {folder, search},
       {desc, <<"Can administer all Full Text Search features. This user can "
                "access the web console. This user can read some data.">>}],
      [{[{bucket, bucket_name}, fts], [read, write, manage]},
       {[{bucket, bucket_name}, collections], [read]},
       {[{bucket, bucket_name}, data, docs], [read, sread]},
       {[settings, fts], [read, write, manage]},
       {[ui], [read]},
       {[pools], [read]},
       {[{bucket, bucket_name}, settings], [read]}]},
     {fts_searcher, ?RBAC_COLLECTION_PARAMS,
      [{name, <<"Search Reader">>},
       {folder, search},
       {desc, <<"Can query Full Text Search indexes for a given bucket, scope "
                "or collection. This user can access the web console. This "
                "user can read some data.">>}],
      [{[{collection, ?RBAC_COLLECTION_PARAMS}, fts], [read]},
       {[settings, fts], [read]},
       {[ui], [read]},
       {[pools], [read]},
       {[{bucket, bucket_name}, settings], [read]},
       {[app_telemetry], [write]}]},
     {query_select, ?RBAC_COLLECTION_PARAMS,
      [{name, <<"Query Select">>},
       {folder, 'query'},
       {desc, <<"Can execute a SELECT statement on a given bucket, scope or "
                "collection to retrieve data. This user can access the web "
                "console and can read data, but not write it.">>}],
      [{[{collection, ?RBAC_COLLECTION_PARAMS}, n1ql, select], [execute]},
       {[{collection, ?RBAC_COLLECTION_PARAMS}, data, docs], [read, sread]},
       {[{bucket, bucket_name}, settings], [read]},
       {[ui], [read]},
       {[pools], [read]},
       {[app_telemetry], [write]}]},
     {query_update, ?RBAC_COLLECTION_PARAMS,
      [{name, <<"Query Update">>},
       {folder, 'query'},
       {desc, <<"Can execute an UPDATE statement on a given bucket, scope or "
                "collection to update data. This user can access the web "
                "console and write data, but cannot read it.">>}],
      [{[{collection, ?RBAC_COLLECTION_PARAMS}, n1ql, update], [execute]},
       {[{collection, ?RBAC_COLLECTION_PARAMS}, data, docs],
        [upsert, range_scan]},
       {[{bucket, bucket_name}, settings], [read]},
       {[ui], [read]},
       {[pools], [read]},
       {[app_telemetry], [write]}]},
     {query_insert, ?RBAC_COLLECTION_PARAMS,
      [{name, <<"Query Insert">>},
       {folder, 'query'},
       {desc, <<"Can execute an INSERT statement on a given bucket, scope or "
                "collection to add data. This user can access the web console "
                "and insert data, but cannot read it.">>}],
      [{[{collection, ?RBAC_COLLECTION_PARAMS}, n1ql, insert], [execute]},
       {[{collection, ?RBAC_COLLECTION_PARAMS}, data, docs], [insert]},
       {[{bucket, bucket_name}, settings], [read]},
       {[ui], [read]},
       {[pools], [read]},
       {[app_telemetry], [write]}]},
     {query_delete, ?RBAC_COLLECTION_PARAMS,
      [{name, <<"Query Delete">>},
       {folder, 'query'},
       {desc, <<"Can execute a DELETE statement on a given bucket, scope or "
                "collection to delete data. This user can access the web "
                "console, but cannot read data. This user can delete data.">>}],
      [{[{collection, ?RBAC_COLLECTION_PARAMS}, n1ql, delete], [execute]},
       {[{collection, ?RBAC_COLLECTION_PARAMS}, data, docs],
        [delete, range_scan]},
       {[{bucket, bucket_name}, settings], [read]},
       {[ui], [read]},
       {[pools], [read]},
       {[app_telemetry], [write]}]},
     {query_manage_index, ?RBAC_COLLECTION_PARAMS,
      [{name, <<"Query Manage Index">>},
       {folder, 'query'},
       {desc, <<"Can manage indexes for a given bucket, scope or collection. "
                "This user can access the web console, can read statistics "
                "for a given bucket, scope or collection. This user cannot "
                "read data.">>
       }],
      [{[{collection, ?RBAC_COLLECTION_PARAMS}, n1ql, index], all},
       {[{collection, ?RBAC_COLLECTION_PARAMS}, collections], [read]},
       {[{bucket, bucket_name}, settings], [read]},
       {[{bucket, bucket_name}, stats], [read]},
       {[settings, indexes], [read]},
       {[ui], [read]},
       {[pools], [read]}]},
     {query_list_index, ?RBAC_COLLECTION_PARAMS,
      [{name, <<"Query List Index">>},
       {folder, 'query'},
       {desc, <<"Can list indexes for a given bucket, scope or collection. "
                "This user can access the web console, can read statistics "
                "for a given bucket, scope or collection. This user cannot "
                "read data.">>
       }],
      [{[{collection, ?RBAC_COLLECTION_PARAMS}, n1ql, index], [list]},
       {[{collection, ?RBAC_COLLECTION_PARAMS}, collections], [read]},
       {[{bucket, bucket_name}, settings], [read]},
       {[{bucket, bucket_name}, stats], [read]},
       {[settings, indexes], [read]},
       {[ui], [read]},
       {[pools], [read]}]},
     {query_system_catalog, [],
      [{name, <<"Query System Catalog">>},
       {folder, 'query'},
       {desc, <<"Can look up system catalog information via N1QL. This user "
                "can access the web console, but cannot read user data.">>}],
      [{[{bucket, any}, n1ql, index], [list]},
       {[{bucket, any}, settings], [read]},
       {[n1ql, meta], [read]},
       {[settings, indexes], [read]},
       {[ui], [read]},
       {[pools], [read]}]},
     {query_external_access, [],
      [{name, <<"Query CURL Access">>},
       {folder, 'query'},
       {desc, <<"Can execute the CURL statement from within N1QL. This user "
                "can access the web console, but cannot read data (within "
                "Couchbase).">>}],
      [{[n1ql, curl], [execute]},
       {[{bucket, any}, settings], [read]},
       {[ui], [read]},
       {[pools], [read]},
       {[app_telemetry], [write]}]},
     {query_manage_global_functions, [],
      [{name, <<"Manage Global Functions">>},
       {folder, 'query'},
       {desc, <<"Can manage global n1ql functions">>}],
      [{[n1ql, udf], [manage]},
       {[ui], [read]},
       {[pools], [read]}]},
     {query_execute_global_functions, [],
      [{name, <<"Execute Global Functions">>},
       {folder, 'query'},
       {desc, <<"Can execute global n1ql functions">>}],
      [{[n1ql, udf], [execute]},
       {[ui], [read]},
       {[pools], [read]},
       {[app_telemetry], [write]}]},
     {query_manage_functions, ?RBAC_SCOPE_PARAMS,
      [{name, <<"Manage Scope Functions">>},
       {folder, 'query'},
       {desc, <<"Can manage n1ql functions for a given scope">>}],
      [{[{collection, [bucket_name, scope_name, any]}, n1ql, udf], [manage]},
       {[{collection, [bucket_name, scope_name, any]}, collections], [read]},
       {[ui], [read]},
       {[pools], [read]}]},
     {query_execute_functions, ?RBAC_SCOPE_PARAMS,
      [{name, <<"Execute Scope Functions">>},
       {folder, 'query'},
       {desc, <<"Can execute n1ql functions for a given scope">>}],
      [{[{collection, [bucket_name, scope_name, any]}, n1ql, udf], [execute]},
       {[ui], [read]},
       {[pools], [read]},
       {[app_telemetry], [write]}]},
     {query_manage_global_external_functions, [],
      [{name, <<"Manage Global External Functions">>},
       {folder, 'query'},
       {desc, <<"Can manage global external language functions">>}],
      [{[n1ql, udf_external], [manage]},
       {[ui], [read]},
       {[pools], [read]}]},
     {query_execute_global_external_functions, [],
      [{name, <<"Execute Global External Functions">>},
       {folder, 'query'},
       {desc, <<"Can execute global external language functions">>}],
      [{[n1ql, udf_external], [execute]},
       {[ui], [read]},
       {[pools], [read]},
       {[app_telemetry], [write]}]},
     {query_manage_external_functions, ?RBAC_SCOPE_PARAMS,
      [{name, <<"Manage Scope External Functions">>},
       {folder, 'query'},
       {desc, <<"Can manage external language functions for a given scope">>}],
      [{[{collection, [bucket_name, scope_name, any]}, n1ql,
         udf_external], [manage]},
       {[{collection, [bucket_name, scope_name, any]}, collections], [read]},
       {[ui], [read]},
       {[pools], [read]}]},
     {query_execute_external_functions, ?RBAC_SCOPE_PARAMS,
      [{name, <<"Execute Scope External Functions">>},
       {folder, 'query'},
       {desc, <<"Can execute external language functions for a given scope">>}],
      [{[{collection, [bucket_name, scope_name, any]}, n1ql,
         udf_external], [execute]},
       {[ui], [read]},
       {[pools], [read]},
       {[app_telemetry], [write]}]},
     {query_manage_sequences, ?RBAC_SCOPE_PARAMS,
      [{name, <<"Manage Sequences">>},
       {folder, 'query'},
       {desc, <<"Can manage sequences for a given scope">>}],
      [{[{collection, [bucket_name, scope_name, any]}, n1ql, sequences],
        [manage]},
       {[{collection, [bucket_name, scope_name, any]}, collections], [read]},
       {[ui], [read]},
       {[pools], [read]}]},
     {query_use_sequences, ?RBAC_SCOPE_PARAMS,
      [{name, <<"Use Sequences">>},
       {folder, 'query'},
       {desc, <<"Can use sequences for a given scope">>}],
      [{[{collection, [bucket_name, scope_name, any]}, n1ql, sequences],
        [execute]},
       {[{collection, [bucket_name, scope_name, any]}, collections], [read]},
       {[ui], [read]},
       {[pools], [read]},
       {[app_telemetry], [write]}]},
     {query_use_sequential_scans, ?RBAC_COLLECTION_PARAMS,
      [{name, <<"Query Use Sequential Scans">>},
       {folder, 'query'},
       {desc, <<"Can use sequential scans for access to a given bucket, scope "
                "or collection.">>}],
      [{[{collection, ?RBAC_COLLECTION_PARAMS}, n1ql, sequential_scan],
        [execute]},
       {[{collection, ?RBAC_COLLECTION_PARAMS}, data, docs], [range_scan]},
       {[app_telemetry], [write]}]},
     {query_manage_system_catalog, [],
      [{name, <<"Query Manage System Catalog">>},
       {folder, query},
       {desc, <<"Can manage Query system catalogs via SQL++. "
                "This user can access the web console. This user cannot "
                "read data.">>}],
      [{[n1ql, meta], [manage]},
       {[ui], [read]},
       {[pools], [read]}]},
     {replication_target, [bucket_name],
      [{name, <<"XDCR Inbound">>},
       {folder, xdcr},
       {desc, <<"Can create XDCR streams into a given bucket. This user cannot "
                "access the web console.">>}],
      [{[{bucket, bucket_name}, settings], [read]},
       {[{bucket, bucket_name}, data, docs], [read, sread, upsert]},
       {[{bucket, bucket_name}, data, meta], [write]},
       {[{bucket, bucket_name}, data, sxattr], [read, write]},
       {[{bucket, bucket_name}, stats], [read]},
       {[{bucket, bucket_name}, collections], [read]},
       {[xdcr, c2c_communications], all},
       {[pools], [read]},
       {[app_telemetry], [write]}]},
     {analytics_manager, [bucket_name],
      [{name, <<"Analytics Manager">>},
       {folder, analytics},
       {desc, <<"Can manage Analytics local links. Can manage datasets on a "
                "given bucket. Can query datasets created on this bucket. "
                "This user can access the web console and read some data.">>}],
      [{[{bucket, bucket_name}, analytics], [manage, select]},
       {[ui], [read]},
       {[pools], [read]}]},
     {analytics_reader, [],
      [{name, <<"Analytics Reader">>},
       {folder, analytics},
       {desc, <<"Can query datasets. This is a global role as datasets may "
                "be created on different buckets. This user can access the "
                "web console and read some data.">>}],
      [{[analytics], [select]},
       {[{bucket, any}, analytics], [select]},
       {[ui], [read]},
       {[pools], [read]},
       {[app_telemetry], [write]}]},
     {analytics_select, ?RBAC_COLLECTION_PARAMS,
      [{name, <<"Analytics Select">>},
       {folder, analytics},
       {desc, <<"Can query datasets on a given bucket, scope or "
                "collection. This user can access the web console and read "
                "some data.">>}],
      [{[{collection, ?RBAC_COLLECTION_PARAMS}, analytics], [select]},
       {[ui], [read]},
       {[pools], [read]},
       {[app_telemetry], [write]}]},
     {analytics_admin, [],
      [{name, <<"Analytics Admin">>},
       {folder, analytics},
       {desc, <<"Can manage dataverses. Can manage all Analytics links. "
                "Can manage all datasets. This user can access the web "
                "console but cannot read data.">>}],
      [{[analytics], [manage]},
       {[{bucket, any}, analytics], [manage]},
       {[ui], [read]},
       {[pools], [read]}]},
     {mobile_sync_gateway, [bucket_name],
      [{name, <<"Sync Gateway">>},
       {folder, mobile},
       {desc, <<"Full access to bucket data as required by Sync Gateway. "
                "This user cannot access the web console and is intended "
                "only for use by Sync Gateway. This user can read and "
                "write data, manage indexes and views, and read some "
                "cluster information.">>}],
      [{[{collection, [bucket_name, ?SYSTEM_SCOPE_NAME, "_mobile"]}, data],
        all},
       {[{bucket, bucket_name}, data, docs], [read, insert, delete, upsert,
                                              range_scan, sread]},
       {[{bucket, bucket_name}, data], all},
       {[{bucket, bucket_name}, views], all},
       {[{bucket, bucket_name}, n1ql, index], all},
       {[{bucket, bucket_name}, n1ql], [execute]},
       {[{bucket, bucket_name}], [read, flush]},
       {[{bucket, bucket_name}, settings], [read]},
       {[admin, memcached, idle], [write]},
       {[settings, autocompaction], [read]},
       {[pools], [read]}]},
     {sync_gateway_configurator, ?RBAC_COLLECTION_PARAMS,
      [{name, <<"Sync Gateway Architect">>},
       {folder, mobile},
       {desc, <<"Can manage Sync Gateway databases and users, "
                "and access Sync Gateway's /metrics endpoint. "
                "This user cannot read application data.">>}],
      [{[{collection, [any, any, any]}, sgw, appdata], none},
       {[{collection, [any, any, any]}, sgw, principal_appdata], none},
       {[{collection, [any, any, any]}, sgw, replications], none},
       {[{collection, ?RBAC_COLLECTION_PARAMS}, sgw], all},
       {[admin, stats_export], [read]}]},
     {sync_gateway_app, ?RBAC_COLLECTION_PARAMS,
      [{name, <<"Sync Gateway Application">>},
       {folder, mobile},
       {desc, <<"Can manage Sync Gateway users and roles, and "
                "read and write application data through Sync "
                "Gateway.">>}],
      [{[{collection, ?RBAC_COLLECTION_PARAMS}, sgw, auth], [configure]},
       {[{collection, ?RBAC_COLLECTION_PARAMS}, sgw, principal], [read, write]},
       {[{collection, ?RBAC_COLLECTION_PARAMS}, sgw, appdata], [read, write]},
       {[{collection, ?RBAC_COLLECTION_PARAMS}, sgw, principal_appdata],
        [read]}]},
     {sync_gateway_app_ro, ?RBAC_COLLECTION_PARAMS,
      [{name, <<"Sync Gateway Application Read Only">>},
       {folder, mobile},
       {desc, <<"Can read Sync Gateway users and roles, and "
                "read application data through Sync Gateway.">>}],
      [{[{collection, ?RBAC_COLLECTION_PARAMS}, sgw, appdata], [read]},
       {[{collection, ?RBAC_COLLECTION_PARAMS}, sgw, principal], [read]},
       {[{collection, ?RBAC_COLLECTION_PARAMS}, sgw, principal_appdata],
        [read]}]},
     {sync_gateway_replicator, ?RBAC_COLLECTION_PARAMS,
      [{name, <<"Sync Gateway Replicator">>},
       {folder, mobile},
       {desc, <<"Can manage Inter-Sync Gateway Replications. "
                "This user cannot read application data.">>}],
      [{[{collection, ?RBAC_COLLECTION_PARAMS}, sgw, replications], all}]},
     {sync_gateway_dev_ops, [],
      [{name, <<"Sync Gateway Dev Ops">>},
       {folder, mobile},
       {desc, <<"Can manage Sync Gateway node-level configuration, "
                "and access Sync Gateway's /metrics endpoint "
                "for Prometheus integration.">>}],
      [{[sgw, dev_ops], all},
       {[admin, stats_export], [read]}]},
     {external_stats_reader, [],
      [{name, <<"External Stats Reader">>},
       {folder, admin},
       {desc, <<"Access to /metrics endpoint for Prometheus integration. "
                "Can read all stats for all services. This user cannot "
                "access the web console">>}],
      [{[admin, stats_export], [read]}]},
     {application_telemetry_writer, [],
      [{name, <<"Application Telemetry Writer">>},
       {folder, admin},
       {desc, <<"Can report application telemetry through the SDK. "
                "This user cannot access the web console">>}],
      [{[app_telemetry], [write]}]},
     {eventing_manage_functions, ?RBAC_SCOPE_PARAMS,
      [{name, <<"Manage Scope Functions">>},
       {folder, eventing},
       {desc, <<"Can manage eventing functions for a given scope">>}],
      [{[{collection, [bucket_name, scope_name, any]}, eventing, function],
        [manage]},
       {[{collection, [bucket_name, scope_name, any]}, collections], [read]},
       {[{bucket, bucket_name}, stats], [read]},
       {[ui], [read]},
       {[pools], [read]}]}
    ].

ui_folders() ->
    [{admin, "Administrative"},
     {bucket, "Bucket"},
     {data, "Data"},
     {views, "Views"},
     {'query', "Query & Index"},
     {search, "Search"},
     {analytics, "Analytics"},
     {eventing, "Eventing"},
     {xdcr, "XDCR"},
     {backup, "Backup"},
     {mobile, "Mobile"}].

internal_roles() ->
    [{stats_reader, [], [], [{[admin, internal, stats], [read]}]},
     {metakv2_access, [], [], [{[admin, internal, metakv2], all}]}].

maybe_add_developer_preview_roles() ->
    DP = cluster_compat_mode:is_developer_preview(),
    add_replication_developer_roles(DP).

add_replication_developer_roles(true) ->
    [{replication_developer, [],
      [{name, <<"XDCR Developer">>},
       {folder, xdcr},
       {desc, <<"Can read and write Custom Conflict Resolution merge "
                "functions. This user cannot access the web console.">>}],
      [{[xdcr, developer], all}]}];
add_replication_developer_roles(false) ->
    [].

maybe_add_serverless_roles() ->
    add_serverless_roles(config_profile:is_serverless()).

add_serverless_roles(true) ->
    [{regulator_access, [],
      [{name, <<"Regulator Access">>},
       {folder, admin},
       {desc, <<"Can access a limited number of REST endpoints.">>}],
      [{[pools], [read]},
       {[{bucket, any}, settings], [read]},
       {[admin, event], all},
       {[admin, metakv], all},
       %% Needed for /internalSettings
       {[admin, settings], [read]}]},
     %% The query_manage_index_regular role is the same as the
     %% query_manage_index role with the exception that it cannot manage
     %% parameterized indexes and cannot alter normal indexes.
     {query_manage_index_regular, ?RBAC_COLLECTION_PARAMS,
      [{name, <<"Query Manage Index (Regular)">>},
       {folder, 'query'},
       {desc, <<"Can manage (except for altering) indexes for a given bucket, "
                "scope or collection. Cannot manage parameterized indexes."
                "This user can access the web console, can read statistics "
                "for a given bucket, scope or collection. This user cannot "
                "read data.">>
       }],
      [{[{collection, ?RBAC_COLLECTION_PARAMS}, n1ql, index, parameterized],
        none},
       {[{collection, ?RBAC_COLLECTION_PARAMS}, n1ql, index],
        [create, drop, list, build]},
       {[{collection, ?RBAC_COLLECTION_PARAMS}, collections], [read]},
       {[{bucket, bucket_name}, settings], [read]},
       {[{bucket, bucket_name}, stats], [read]},
       {[settings, indexes], [read]},
       {[ui], [read]},
       {[pools], [read]}]}];
add_serverless_roles(false) ->
    [].

-spec get_definitions(all | public) -> [rbac_role_def(), ...].
get_definitions(all) ->
    get_definitions(public) ++ internal_roles();
get_definitions(public) ->
    get_public_definitions(cluster_compat_mode:get_compat_version()).

-spec get_public_definitions(list()) -> [rbac_role_def(), ...].
get_public_definitions(Version) ->
    [{_, Fun} | _] = public_definitions(Version),
    Fun().

public_definitions(Version) ->
    lists:dropwhile(fun ({undefined, _}) ->
                            false;
                        ({V, _}) ->
                            Version >= V
                    end, public_definitions()).

public_definitions() ->
    [{?VERSION_76, fun menelaus_old_roles:roles_pre_76/0},
     {?VERSION_MORPHEUS, fun menelaus_old_roles:roles_pre_morpheus/0},
     {undefined, ?cut(roles() ++ maybe_add_developer_preview_roles()
                      ++ maybe_add_serverless_roles())}].

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
vertex_param_match({_, any}) ->
    true;
vertex_param_match({A, B}) ->
    A =:= B.

is_data_vertex({bucket, _}) ->
    true;
is_data_vertex({scope, _}) ->
    true;
is_data_vertex({collection, _}) ->
    true;
is_data_vertex(_) ->
    false.

get_vertex_param_list({bucket, B}) ->
    [B];
get_vertex_param_list({_, Params}) ->
    Params;
get_vertex_param_list(_) ->
    [].

expand_vertex(Vertex, Pad) ->
    case is_data_vertex(Vertex) of
        true ->
            {collection,
             misc:align_list(get_vertex_param_list(Vertex), 3, Pad)};
        false ->
            Vertex
    end.

vertex_match(PermissionVertex, FilterVertex) ->
    expanded_vertex_match(expand_vertex(PermissionVertex, all),
                          expand_vertex(FilterVertex, any)).

expanded_vertex_match({Same, Params}, {Same, FilterParams}) ->
    vertex_params_match(Params, FilterParams);
expanded_vertex_match(Same, Same) ->
    true;
expanded_vertex_match(_, _) ->
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
                 #authn_res{} | [rbac_compiled_role()]) -> boolean().
is_allowed(_Permission, #authn_res{password_expired = true}) ->
    false;
is_allowed(Permission, #authn_res{} = AuthnRes) ->
    case menelaus_auth:check_expiration(AuthnRes) of
        {error, expired} -> false;
        ok ->
            Roles = get_compiled_roles(AuthnRes),
            is_allowed(Permission, Roles)
    end;
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
                 fun ({Name, List}) when is_list(List) ->
                         {Name, [substitute_param(Param, ParamPairs) ||
                                    Param <- List]};
                     ({Name, Param}) ->
                         {Name, substitute_param(Param, ParamPairs)};
                     (Vertex) ->
                         Vertex
                 end, ObjectPattern), AllowedOperations}
      end, Permissions).

substitute_param(any, _ParamPairs) ->
    any;
substitute_param(Param, ParamPairs) ->
    case lists:keyfind(Param, 1, ParamPairs) of
        {Param, Subst} ->
            Subst;
        false ->
            Param
    end.

compile_param(bucket_name, Name, Snapshot) ->
    find_object(Name,
                fun (BucketName) ->
                        case ns_bucket:uuid(BucketName, Snapshot) of
                            not_present ->
                                undefined;
                            UUID ->
                                {UUID,
                                 collections:get_manifest(BucketName, Snapshot)}
                        end
                end);
compile_param(scope_name, Name, Manifest) ->
    find_object(Name,
                fun (ScopeName) ->
                        case Manifest of
                            undefined ->
                                undefined;
                            _ ->
                                maybe_add_id(collections:get_scope(ScopeName,
                                                                   Manifest))
                        end
                end);
compile_param(collection_name, Name, Scope) ->
    find_object(Name, ?cut(maybe_add_id(collections:get_collection(_, Scope)))).

maybe_add_id(undefined) ->
    undefined;
maybe_add_id(Props) ->
    {collections:get_uid(Props), Props}.

find_object(any, _Find) ->
    {any, any};
find_object({Name, Id}, Find) ->
    case find_object(Name, Find) of
        RV = {{Name, Id}, _} ->
            RV;
        _ ->
            undefined
    end;
find_object(Name, Find) when is_list(Name) ->
    case Find(Name) of
        undefined ->
            undefined;
        {UUID, Props} ->
            {{Name, UUID}, Props}
    end.

params_version() ->
    params_version(ns_bucket:get_snapshot(all, [collections, props, uuid])).

-spec params_version(map()) -> term().
params_version(Snapshot) ->
    lists:map(
      fun (Name) ->
              UUID = ns_bucket:uuid(Name, Snapshot),
              {ok, BucketConfig} = ns_bucket:get_bucket(Name, Snapshot),
              DefaultManifest = collections:default_manifest(BucketConfig),
              Manifest = collections:get_manifest(Name, Snapshot,
                                                  DefaultManifest),
              ManifestUid = collections:get_uid(Manifest),
              {Name, UUID, ManifestUid}
      end,
      ns_bucket:get_bucket_names(Snapshot)).

compile_params([], [], Acc, _) ->
    lists:reverse(Acc);
compile_params([ParamDef | RestParamDefs], [Param | RestParams], Acc, Ctx) ->
    case compile_param(ParamDef, Param, Ctx) of
        undefined ->
            false;
        {Compiled, NewCtx} ->
            compile_params(RestParamDefs, RestParams, [Compiled | Acc], NewCtx)
    end.

compile_params(ParamDefs, Params, Buckets) ->
    compile_params(ParamDefs, Params, [], Buckets).

compile_role({Name, Params}, CompileRole, Definitions, Snapshot) ->
    case lists:keyfind(Name, 1, Definitions) of
        {Name, ParamDefs, _Props, Permissions} ->
            case compile_params(ParamDefs, Params, Snapshot) of
                false ->
                    false;
                NewParams ->
                    {true, CompileRole(Name, NewParams, ParamDefs, Permissions)}
            end;
        false ->
            false
    end;
compile_role(Name, CompileRole, Definitions, Snapshot) when is_atom(Name) ->
    compile_role({Name, []}, CompileRole, Definitions, Snapshot).

compile_roles(CompileRole, Roles, Definitions, Snapshot) ->
    case do_compile_roles(CompileRole, Roles, Definitions, Snapshot) of
        try_another_version ->
            [_ | OtherDefinitions] =
                public_definitions(cluster_compat_mode:get_compat_version()),
            compile_roles_with_other_definitions(
              CompileRole, Roles, OtherDefinitions, Snapshot);
        Other ->
            Other
    end.

compile_roles_with_other_definitions(_CompileRole, _Roles, [], _Snapshot) ->
    exit(roles_impossible_to_compile);
compile_roles_with_other_definitions(
  CompileRole, Roles, [{Ver, GetDefinitions} | Rest], Snapshot) ->
    case Ver of
        undefined ->
            ?log_debug("Compile roles with latest definitions");
        _ ->
            ?log_debug(
               "Compile roles with definitions for version greater than  ~p",
               [Ver])
    end,
    case do_compile_roles(CompileRole, Roles,
                          GetDefinitions() ++ internal_roles(), Snapshot) of
        try_another_version ->
            compile_roles_with_other_definitions(
              CompileRole, Roles, Rest, Snapshot);
        Other ->
            Other
    end.

do_compile_roles(CompileRole, Roles, Definitions, Snapshot) ->
    try
        lists:filtermap(compile_role(_, CompileRole, Definitions, Snapshot),
                        Roles)
    catch
        T:E:S ->
            ?log_debug("Error compiling roles~n~p", [{T, E, S}]),
            case menelaus_users:upgrade_in_progress() of
                true ->
                    %% compilation crashed during unfinished upgrade
                    %% it could happen that the users database is already
                    %% upgraded, but we are still using old definitions
                    %% because cluster compat version is not yet updated
                    %% let's try to compile with newer definitions
                    try_another_version;
                false ->
                    error(E)
            end
    end.


-spec compile_roles([rbac_role()], [rbac_role_def()] | undefined, map()) ->
                           [rbac_compiled_role()].
compile_roles(_Roles, undefined, _Snapshot) ->
    %% can happen briefly after node joins the cluster on pre 5.0 clusters
    [];
compile_roles(Roles, Definitions, Snapshot) ->
    compile_roles(
      fun (_Name, Params, ParamDefs, Permissions) ->
              substitute_params(strip_ids(ParamDefs, Params),
                                ParamDefs, Permissions)
      end, Roles, Definitions, Snapshot).

get_roles(#authn_res{identity = Id,
                     extra_groups = Groups,
                     extra_roles = Roles}) ->
    ExtraRoles =
        lists:append([menelaus_users:get_group_roles(G) || G <- Groups]) ++
        Roles,
    IdentityRoles = get_roles_for_identity(Id),
    %% This check is done for optimization purposes.
    %% Most of the times ExtraRoles is empty, so there is no need in
    %% uniq(IdentityRoles) call which is not free.
    case ExtraRoles of
        [] -> IdentityRoles;
        _ -> lists:uniq(ExtraRoles ++ IdentityRoles)
    end;
get_roles({_, _} = Id) ->
    get_roles_for_identity(Id).

-spec get_roles_for_identity(rbac_identity()) -> [rbac_role()].
get_roles_for_identity({"", wrong_token}) ->
    case ns_config_auth:is_system_provisioned() of
        false ->
            [admin];
        true ->
            []
    end;
get_roles_for_identity(?ANONYMOUS_IDENTITY) ->
    case ns_config_auth:is_system_provisioned() of
        false ->
            [admin];
        true ->
            []
    end;
get_roles_for_identity({_, admin}) ->
    [admin];
get_roles_for_identity({_, local_token}) ->
    [admin];
get_roles_for_identity({_, stats_reader}) ->
    [stats_reader];
get_roles_for_identity({BucketName, bucket}) ->
    [{bucket_full_access, [BucketName]}];
get_roles_for_identity({_User, external} = Identity) ->
    menelaus_users:get_roles(Identity);
get_roles_for_identity({_User, local} = Identity) ->
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
        fun (cluster_compat_version) ->
                true;
            (rest_creds) ->
                true;
            (Key) ->
                collections:key_match(Key) =/= false orelse
                    ns_bucket:buckets_change(Key)
        end,
    GetVersion =
        fun () ->
                {cluster_compat_mode:get_compat_version(),
                 menelaus_users:get_users_version(),
                 menelaus_users:get_groups_version(),
                 ns_config_auth:is_system_provisioned(),
                 params_version()}
        end,
    GetEvents =
        case ns_node_disco:couchdb_node() == node() of
            true ->
                fun () ->
                        dist_manager:wait_for_node(
                          fun ns_node_disco:ns_server_node/0),
                        [{{user_storage_events, ns_node_disco:ns_server_node()},
                          UsersFilter},
                         {config_events, ConfigFilter}]
                end;
            false ->
                fun () ->
                        [{user_storage_events, UsersFilter},
                         {config_events, ConfigFilter}]
                end
        end,

    versioned_cache:start_link(
      compiled_roles_cache_name(), 200, fun build_compiled_roles/1,
      GetEvents, GetVersion).

get_compiled_roles(#authn_res{identity = {_, external}} = AuthnRes) ->
    roles_cache:build_compiled_roles(AuthnRes);
get_compiled_roles(#authn_res{identity = Identity,
                              extra_roles = ExtraRoles,
                              extra_groups = ExtraGroups}) ->
    %% Dropping everything but what we need for roles calculation here.
    %% Reason: We don't want things like session_id to be part of the cache
    %% key. In other words, if some user relogins, cache key should not
    %% change
    AuthnRes = #authn_res{identity = Identity,
                          extra_roles = ExtraRoles,
                          extra_groups = ExtraGroups},
    versioned_cache:get(compiled_roles_cache_name(), AuthnRes);
get_compiled_roles({_, _} = Identity) ->
    get_compiled_roles(#authn_res{identity = Identity}).

-spec get_params_from_permission(rbac_permission_pattern()) ->
          false | {true, [rbac_permission_pattern_vertex_param(),...]}.
get_params_from_permission({ObjectPattern, _}) ->
    case ObjectPattern of
        [{collection, [B, S, C]}|_] ->
            {true, [B, S, C]};
        [{scope, [B, S]}|_]  ->
            {true, [B, S, any]};
        [{bucket, B}|_] ->
            {true, [B, any, any]};
        [] ->
            {true, [any, any, any]};
        _ ->
            false
    end.

%% Extract the set of bucket, scope and collection params from the list of roles
%% in compiled roles. These are iterated over to set memcached privileges.
-spec get_params_from_permissions([rbac_compiled_role()]) ->
          [[rbac_permission_pattern_vertex_param(),...]].
get_params_from_permissions(CompiledRoles) ->
    lists:usort(
      lists:flatmap(
        fun(Perms) ->
                lists:filtermap(get_params_from_permission(_), Perms)
        end, CompiledRoles)).

build_compiled_roles(#authn_res{identity = Identity} = AuthnRes) ->
    case ns_node_disco:couchdb_node() == node() of
        false ->
            ?log_debug("Compile roles for user ~p",
                       [ns_config_log:tag_user_data(Identity)]),
            Definitions = get_definitions(all),
            compile_roles(get_roles(AuthnRes), Definitions,
                          ns_bucket:get_snapshot(all, [collections, uuid]));
        true ->
            ?log_debug("Retrieve compiled roles for user ~p from ns_server "
                       "node", [ns_config_log:tag_user_data(Identity)]),
            rpc:call(ns_node_disco:ns_server_node(),
                     ?MODULE, build_compiled_roles, [AuthnRes])
    end.

filter_out_invalid_roles(Roles, Definitions, Snapshot) ->
    compile_roles(fun (Name, [], _, _) ->
                          Name;
                      (Name, Params, _, _) ->
                          {Name, Params}
                  end, Roles, Definitions, Snapshot).

get_permission_params({[V | _], _}) ->
    case is_data_vertex(V) of
        true ->
            get_vertex_param_list(V);
        _ ->
            []
    end;
get_permission_params(_) ->
    [].

calculate_possible_param_values(Snapshot, Combination, Permission) ->
    Len = length(Combination),
    PermissionParams = get_permission_params(Permission),
    RawParams =
        lists:usort(
          lists:map(
            fun (I) ->
                    misc:align_list(PermissionParams, I, any) ++
                        lists:duplicate(Len - I, any)
            end, lists:seq(0, length(Combination)))),
    lists:filtermap(
      fun (Params) ->
              case compile_params(Combination, Params, Snapshot) of
                  false ->
                      false;
                  Compiled ->
                      {true, Compiled}
              end
      end, RawParams).

all_params_combinations() ->
    [[], [bucket_name], ?RBAC_SCOPE_PARAMS, ?RBAC_COLLECTION_PARAMS].

-spec calculate_possible_param_values(map(), undefined | rbac_permission()) ->
                                             rbac_all_param_values().
calculate_possible_param_values(Snapshot, Permission) ->
    [{Combination,
      calculate_possible_param_values(Snapshot, Combination, Permission)} ||
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

filter_by_permission(undefined, _Snapshot, _Definitions) ->
    pipes:filter(fun (_) -> true end);
filter_by_permission(Permission, Snapshot, Definitions) ->
    pipes:filter(
      fun ({Role, _}) ->
              is_allowed(Permission,
                         compile_roles([Role], Definitions, Snapshot))
      end).

-spec produce_roles_by_permission(rbac_permission(), map()) ->
                                         pipes:producer(rbac_role()).
produce_roles_by_permission(Permission, Snapshot) ->
    AllValues = calculate_possible_param_values(Snapshot, Permission),
    Definitions = get_definitions(public),
    pipes:compose(
      [pipes:stream_list(Definitions),
       visible_roles_filter(),
       expand_params(AllValues),
       filter_by_permission(Permission, Snapshot, Definitions)]).

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

-spec validate_role(rbac_role(), [rbac_role_def()], map()) ->
                           false | {ok, rbac_role()}.
validate_role(Role, Definitions, Snapshot) when is_atom(Role) ->
    validate_role(Role, [], Definitions, Snapshot);
validate_role({Role, Params}, Definitions, Snapshot) ->
    validate_role(Role, Params, Definitions, Snapshot).

validate_role(Role, Params, Definitions, Snapshot) ->
    case lists:keyfind(Role, 1, Definitions) of
        {Role, ParamsDef, _, _} when length(Params) =:= length(ParamsDef) ->
            case compile_params(ParamsDef, Params, Snapshot) of
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

get_visible_role_definitions() ->
    pipes:run(pipes:stream_list(get_definitions(public)),
              visible_roles_filter(),
              pipes:collect()).

-spec validate_roles([rbac_role()]) ->
          {GoodRoles :: [rbac_role()], BadRoles :: [rbac_role()]}.
validate_roles(Roles) ->
    validate_roles(Roles, public).

-spec validate_roles([rbac_role()], public | all) ->
          {GoodRoles :: [rbac_role()], BadRoles :: [rbac_role()]}.
validate_roles(Roles, Scope) ->
    validate_roles(Roles, Scope,
                   ns_bucket:get_snapshot(all, [collections, uuid])).

-spec validate_roles([rbac_role()], public | all, map()) ->
          {GoodRoles :: [rbac_role()], BadRoles :: [rbac_role()]}.
validate_roles(Roles, Scope, Snapshot) ->
    Definitions =
        case Scope of
            public ->
                get_visible_role_definitions();
            all ->
                get_definitions(all)
        end,
    lists:foldl(fun (Role, {Validated, Unknown}) ->
                        case validate_role(Role, Definitions, Snapshot) of
                            false ->
                                {Validated, [Role | Unknown]};
                            {ok, R} ->
                                {[R | Validated], Unknown}
                        end
                end, {[], []}, Roles).

-spec get_security_roles(map()) -> [rbac_role()].
get_security_roles(Snapshot) ->
    pipes:run(produce_roles_by_permission({[admin, security], any}, Snapshot),
              pipes:collect()).

-spec get_user_admin_roles(map()) -> [rbac_role()].
get_user_admin_roles(Snapshot) ->
    pipes:run(produce_roles_by_permission({[admin, users], any}, Snapshot),
              pipes:collect()).

external_auth_polling_interval() ->
    ns_config:read_key_fast(external_auth_polling_interval,
                            ?DEFAULT_EXTERNAL_ROLES_POLLING_INTERVAL).


-ifdef(TEST).
setup_meck() ->
    meck:new(cluster_compat_mode, [passthrough]),
    meck:expect(cluster_compat_mode, is_cluster_76,
                fun () -> true end),
    meck:expect(cluster_compat_mode, is_cluster_72,
        fun () -> true end),
    meck:expect(cluster_compat_mode, is_cluster_morpheus,
        fun () -> true end),
    meck:expect(cluster_compat_mode, is_enterprise,
        fun () -> true end),
    meck:new(ns_config, [passthrough]),
    meck:expect(ns_config, search_node_with_default,
                fun (_, Default) -> Default end).

teardown_meck() ->
    meck:unload(cluster_compat_mode),
    meck:unload(ns_config).

filter_out_invalid_roles_test() ->
    Roles = [{role1, [{"bucket1", <<"id1">>}]},
             {role2, [{"bucket2", <<"id2">>}]}],
    Definitions = [{role1, [bucket_name],
                    [{name,<<"">>},{desc, <<"">>}],
                    [{[{bucket,bucket_name},settings],[read]}]},
                   {role2, [bucket_name],
                    [{name,<<"">>},{desc, <<"">>}],
                    [{[{bucket,bucket_name},n1ql,update],[execute]}]}],
    Snapshot = ns_bucket:toy_buckets([{"bucket1", [{uuid, <<"id1">>}]}]),
    ?assertEqual([{role1, [{"bucket1", <<"id1">>}]}],
                 filter_out_invalid_roles(Roles, Definitions, Snapshot)).

%% assertEqual is used instead of assert and assertNot to avoid
%% dialyzer warnings
object_match_test() ->
    ?assertEqual(true, object_match([], [])),
    ?assertEqual(false, object_match([], [o1, o2])),
    ?assertEqual(true, object_match([o3], [])),
    ?assertEqual(true, object_match([o1, o2], [o1, o2])),
    ?assertEqual(false, object_match([o1], [o1, o2])),
    ?assertEqual(true, object_match([o1, o2], [o1])),
    ?assertEqual(true, object_match([{bucket, "a"}], [{bucket, "a"}])),
    ?assertEqual(false, object_match([{bucket, "a"}], [{bucket, "b"}])),
    ?assertEqual(true, object_match([{bucket, any}], [{bucket, "b"}])),
    ?assertEqual(true, object_match([{bucket, "a"}], [{bucket, any}])),
    ?assertEqual(true, object_match([{bucket, any}], [{bucket, any}])),
    ?assertEqual(true, object_match([{bucket, all}], [{bucket, any}])),
    ?assertEqual(false, object_match([{bucket, all}], [{bucket, "a"}])).

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

toy_buckets_props() ->
    [{"test", [{uuid, <<"test_id">>}, {props, toy_props()}]},
     {"default", [{uuid, <<"default_id">>}, {collections, toy_manifest()},
                  {props, toy_props()}]}].

toy_buckets() ->
    ns_bucket:toy_buckets(toy_buckets_props()).

toy_manifest() ->
    [{uid, 2},
     {scopes, [{"s",  [{uid, 1}, {collections, [{"c",  [{uid, 1}]},
                                                {"c1", [{uid, 2}]}]}]},
               {"s1", [{uid, 2}, {collections, [{"c",  [{uid, 3}]}]}]}]}].

toy_props() ->
    [{storage_mode, magma}, {type, membase}].

compile_roles(Roles, Definitions) ->
    compile_roles(Roles, Definitions, toy_buckets()).

compile_roles_test() ->
    StripId = fun ({N, _Id}) -> N; (N) -> N end,
    PermissionFilters =
        fun([B, S, C]) ->
                [{[{bucket, StripId(B)}], oper1},
                 {[{bucket, any}, docs], oper2},
                 {[v1, v2], oper3},
                 {[{collection, [StripId(B), StripId(S), StripId(C)]}],
                  oper4}]
        end,

    Definitions = [{simple_role, [], [],
                    [{[admin], all}]},
                   {test_role, [bucket_name], [],
                    [{[{bucket, bucket_name}], none}]},
                   {test_role1, ?RBAC_COLLECTION_PARAMS, [],
                    PermissionFilters(?RBAC_COLLECTION_PARAMS)},
                   {test_role2, ?RBAC_SCOPE_PARAMS, [],
                    PermissionFilters(?RBAC_SCOPE_PARAMS ++ [any])}],

    ?assertEqual([[{[admin], all}]],
                 compile_roles([simple_role, wrong_role], Definitions)),
    ?assertEqual([[{[{bucket, "test"}], none}]],
                 compile_roles([{test_role, ["test"]}], Definitions)),
    ?assertEqual([[{[{bucket, "test"}], none}]],
                 compile_roles([{test_role, [{"test", <<"test_id">>}]}],
                               Definitions)),
    ?assertEqual([], compile_roles([{test_role, [{"test", <<"wrong_id">>}]}],
                                   Definitions)),

    TestRole =
        fun (Success, Role, RoleParams, ParamsForExpected) ->
                Expected = [PermissionFilters(ParamsForExpected) || Success],
                ?assertEqual(Expected,
                             compile_roles([{Role, RoleParams}],
                                           Definitions))
        end,

    TestRole1 = ?cut(TestRole(_1, test_role1, _2, _2)),
    TestRole1(true, ["default", "s", "c"]),
    TestRole1(true, [{"default", <<"default_id">>}, {"s", 1}, {"c", 1}]),
    TestRole1(true, [{"default", <<"default_id">>}, {"s", 1}, any]),
    TestRole1(true, [{"default", <<"default_id">>}, any, any]),
    TestRole1(true, [any, any, any]),
    TestRole1(false, [{"default", <<"wrong_id">>}, {"s", 1}, {"c", 1}]),
    TestRole1(false, [{"default", <<"default_id">>}, {"s", 1}, {"c", 2}]),

    TestRole2 = ?cut(TestRole(_1, test_role2, _2, _2 ++ [any])),
    TestRole2(true, ["default", "s"]),
    TestRole2(true, [{"default", <<"default_id">>}, {"s", 1}]),
    TestRole2(true, [{"default", <<"default_id">>}, any]),
    TestRole2(true, [any, any]),
    TestRole1(false, [{"default", <<"wrong_id">>}, {"s", 1}]),
    TestRole1(false, [{"default", <<"default_id">>}, {"s", 2}]).

admin_test() ->
    Roles = compile_roles([admin], roles()),
    ?assertEqual(true, is_allowed({[buckets], create}, Roles)),
    ?assertEqual(true, is_allowed({[something, something], anything}, Roles)).

cluster_admin_test() ->
    Roles = compile_roles([cluster_admin], roles()),
    ?assertEqual(true, is_allowed({[settings, metrics], any}, Roles)),
    ?assertEqual(false, is_allowed({[admin, settings, metrics], any}, Roles)).

eventing_admin_test() ->
    Roles = compile_roles([eventing_admin], roles()),
    ?assertEqual(false, is_allowed({[admin], any}, Roles)),
    ?assertEqual(false, is_allowed({[xdcr], any}, Roles)),
    ?assertEqual(false, is_allowed({[{bucket, "test"}, xdcr], any}, Roles)),
    ?assertEqual(true, is_allowed({[buckets], create}, Roles)),
    ?assertEqual(true, is_allowed({[n1ql], all}, Roles)),
    ?assertEqual(true, is_allowed({[analytics], all}, Roles)),
    ?assertEqual(true, is_allowed({[eventing], all}, Roles)),
    ?assertEqual(true, is_allowed({[anything], read}, Roles)),
    ?assertEqual(false, is_allowed({[anything], write}, Roles)).

backup_admin_test() ->
    Roles = compile_roles([backup_admin], roles()),
    ?assertEqual(false, is_allowed({[admin, users], read}, Roles)),
    ?assertEqual(false, is_allowed({[admin, users], write}, Roles)),
    ?assertEqual(false, is_allowed({[admin], any}, Roles)),
    ?assertEqual(true, is_allowed({[buckets], create}, Roles)),
    ?assertEqual(true, is_allowed({[backup], all}, Roles)),
    ?assertEqual(true, is_allowed({[anything], all}, Roles)).

ro_admin_test() ->
    Roles = compile_roles([ro_admin], roles()),
    ?assertEqual(false, is_allowed({[{bucket, "test"}, data], read}, Roles)),
    ?assertEqual(true,
                 is_allowed({[{bucket, "test"}, something], read}, Roles)),
    ?assertEqual(false,
                 is_allowed({[{bucket, "test"}, something], write}, Roles)),
    ?assertEqual(false, is_allowed({[admin, security], write}, Roles)),
    ?assertEqual(true, is_allowed({[admin, security], read}, Roles)),
    ?assertEqual(true, is_allowed({[admin, security_info], read}, Roles)),
    ?assertEqual(true, is_allowed({[admin, users], read}, Roles)),
    ?assertEqual(false, is_allowed({[admin, users], write}, Roles)),
    ?assertEqual(false, is_allowed({[admin, event], write}, Roles)),
    ?assertEqual(false, is_allowed({[admin, event], read}, Roles)),
    ?assertEqual(false, is_allowed({[admin, metakv], write}, Roles)),
    ?assertEqual(false, is_allowed({[admin, other], write}, Roles)),
    ?assertEqual(false, is_allowed({[admin, settings, metrics], write}, Roles)),
    ?assertEqual(false, is_allowed({[admin, settings, metrics], read}, Roles)),
    ?assertEqual(false, is_allowed({[settings, metrics], write}, Roles)),
    ?assertEqual(true, is_allowed({[settings, metrics], read}, Roles)),
    ?assertEqual(true, is_allowed({[anything], read}, Roles)),
    ?assertEqual(true, is_allowed({[backup], read}, Roles)),
    ?assertEqual(false, is_allowed({[anything], write}, Roles)).

security_admin_test() ->
    Roles = compile_roles([security_admin], roles()),
    ?assertEqual(false, is_allowed({[{bucket, "test"}, data], read}, Roles)),
    ?assertEqual(true,
                 is_allowed({[{bucket, "test"}, something], read}, Roles)),
    ?assertEqual(false,
                 is_allowed({[{bucket, "test"}, something], write}, Roles)),
    ?assertEqual(true, is_allowed({[admin, security], write}, Roles)),
    ?assertEqual(true, is_allowed({[admin, security], read}, Roles)),
    ?assertEqual(true, is_allowed({[admin, security_info], read}, Roles)),
    ?assertEqual(true, is_allowed({[admin, users], read}, Roles)),
    ?assertEqual(false, is_allowed({[admin, users], write}, Roles)),
    ?assertEqual(false, is_allowed({[admin, event], write}, Roles)),
    ?assertEqual(false, is_allowed({[admin, event], read}, Roles)),
    ?assertEqual(false, is_allowed({[admin, metakv], write}, Roles)),
    ?assertEqual(false, is_allowed({[admin, other], write}, Roles)),
    ?assertEqual(false, is_allowed({[admin, settings, metrics], write}, Roles)),
    ?assertEqual(false, is_allowed({[admin, settings, metrics], read}, Roles)),
    ?assertEqual(false, is_allowed({[settings, metrics], write}, Roles)),
    ?assertEqual(false, is_allowed({[settings, metrics], read}, Roles)),
    ?assertEqual(true, is_allowed({[anything], read}, Roles)),
    ?assertEqual(false, is_allowed({[backup], read}, Roles)),
    ?assertEqual(false, is_allowed({[anything], write}, Roles)).

user_admin_local_test() ->
    Roles = compile_roles([user_admin_local], roles()),
    ?assertEqual(false, is_allowed({[{bucket, "test"}, data], read}, Roles)),
    ?assertEqual(true,
                 is_allowed({[{bucket, "test"}, something], read}, Roles)),
    ?assertEqual(false,
                 is_allowed({[{bucket, "test"}, something], write}, Roles)),
    ?assertEqual(false, is_allowed({[admin, security], write}, Roles)),
    ?assertEqual(false, is_allowed({[admin, security], read}, Roles)),
    ?assertEqual(true, is_allowed({[admin, security_info], read}, Roles)),
    ?assertEqual(true, is_allowed({[admin, users], read}, Roles)),
    ?assertEqual(true, is_allowed({[admin, users], write}, Roles)),
    ?assertEqual(true, is_allowed({[admin, users, local], read}, Roles)),
    ?assertEqual(true, is_allowed({[admin, users, local], write}, Roles)),
    ?assertEqual(false, is_allowed({[admin, users, external], read}, Roles)),
    ?assertEqual(false, is_allowed({[admin, users, external], write}, Roles)),
    ?assertEqual(false, is_allowed({[admin, event], write}, Roles)),
    ?assertEqual(false, is_allowed({[admin, event], read}, Roles)),
    ?assertEqual(false, is_allowed({[admin, metakv], write}, Roles)),
    ?assertEqual(false, is_allowed({[admin, other], write}, Roles)),
    ?assertEqual(false, is_allowed({[admin, settings, metrics], write}, Roles)),
    ?assertEqual(false, is_allowed({[admin, settings, metrics], read}, Roles)),
    ?assertEqual(false, is_allowed({[settings, metrics], write}, Roles)),
    ?assertEqual(false, is_allowed({[settings, metrics], read}, Roles)),
    ?assertEqual(true, is_allowed({[anything], read}, Roles)),
    ?assertEqual(false, is_allowed({[backup], read}, Roles)),
    ?assertEqual(false, is_allowed({[anything], write}, Roles)).

user_admin_external_test() ->
    Roles = compile_roles([user_admin_external], roles()),
    ?assertEqual(false, is_allowed({[{bucket, "test"}, data], read}, Roles)),
    ?assertEqual(true,
                 is_allowed({[{bucket, "test"}, something], read}, Roles)),
    ?assertEqual(false,
                 is_allowed({[{bucket, "test"}, something], write}, Roles)),
    ?assertEqual(false, is_allowed({[admin, security], write}, Roles)),
    ?assertEqual(false, is_allowed({[admin, security], read}, Roles)),
    ?assertEqual(true, is_allowed({[admin, security_info], read}, Roles)),
    ?assertEqual(true, is_allowed({[admin, users], read}, Roles)),
    ?assertEqual(true, is_allowed({[admin, users], write}, Roles)),
    ?assertEqual(false, is_allowed({[admin, users, local], read}, Roles)),
    ?assertEqual(false, is_allowed({[admin, users, local], write}, Roles)),
    ?assertEqual(true, is_allowed({[admin, users, external], read}, Roles)),
    ?assertEqual(true, is_allowed({[admin, users, external], write}, Roles)),
    ?assertEqual(false, is_allowed({[admin, event], write}, Roles)),
    ?assertEqual(false, is_allowed({[admin, event], read}, Roles)),
    ?assertEqual(false, is_allowed({[admin, metakv], write}, Roles)),
    ?assertEqual(false, is_allowed({[admin, other], write}, Roles)),
    ?assertEqual(false, is_allowed({[admin, settings, metrics], write}, Roles)),
    ?assertEqual(false, is_allowed({[admin, settings, metrics], read}, Roles)),
    ?assertEqual(false, is_allowed({[settings, metrics], write}, Roles)),
    ?assertEqual(false, is_allowed({[settings, metrics], read}, Roles)),
    ?assertEqual(true, is_allowed({[anything], read}, Roles)),
    ?assertEqual(false, is_allowed({[backup], read}, Roles)),
    ?assertEqual(false, is_allowed({[anything], write}, Roles)).

regulator_access_test() ->
    Roles = compile_roles([regulator_access],
                          roles() ++ add_serverless_roles(true)),
    ?assertEqual(false, is_allowed({[{bucket, "test"}, data], read}, Roles)),
    ?assertEqual(false,
                 is_allowed({[{bucket, "test"}, something], read}, Roles)),
    ?assertEqual(false,
                 is_allowed({[{bucket, "test"}, something], write}, Roles)),
    ?assertEqual(false, is_allowed({[admin, security], write}, Roles)),
    ?assertEqual(false, is_allowed({[admin, security], read}, Roles)),
    ?assertEqual(false, is_allowed({[admin, security_info], read}, Roles)),
    ?assertEqual(true, is_allowed({[admin, event], write}, Roles)),
    ?assertEqual(true, is_allowed({[admin, event], read}, Roles)),
    ?assertEqual(true, is_allowed({[admin, metakv], write}, Roles)),
    ?assertEqual(false, is_allowed({[admin, other], write}, Roles)),
    ?assertEqual(false, is_allowed({[admin, settings, metrics], write}, Roles)),
    ?assertEqual(true, is_allowed({[admin, settings, metrics], read}, Roles)),
    ?assertEqual(false, is_allowed({[settings, metrics], write}, Roles)),
    ?assertEqual(false, is_allowed({[settings, metrics], read}, Roles)),
    ?assertEqual(false, is_allowed({[anything], read}, Roles)),
    ?assertEqual(false, is_allowed({[anything], write}, Roles)).

%% Extracts all the role names and bucket argument (if applicable).
extract_all_names(Roles) ->
    lists:foldl(
      fun ({Name, [], _Description, _Filters}, AccIn) ->
              [{Name, []} | AccIn];
          ({Name, [bucket_name], _Description, _Filters}, AccIn) ->
              [{Name, ["default"]} | AccIn];
          ({Name, ?RBAC_SCOPE_PARAMS, _Description, _Filters}, AccIn) ->
              [{Name, ["default", "s"]} | AccIn];
          ({Name, ?RBAC_COLLECTION_PARAMS, _Description, _Filters},
           AccIn) ->
              [{Name, ["default", "s", "c"]} | AccIn]
      end, [], Roles).

remove_exempted_names(AllNames, ExemptedNames) ->
    lists:filter(
      fun ({Name, _}) ->
              not lists:member(Name, ExemptedNames)
      end, AllNames).

roles_with_admin_event_metakv_permissions() ->
    [regulator_access, admin].

%% Ensure none of the roles, except those who are granted permission,
%% have access to the admin event/metakv permission.
admin_event_metakv_permissions_test() ->
    AllRoles = roles() ++ add_serverless_roles(true),
    AllNames0 = extract_all_names(AllRoles),
    AllNames =
        remove_exempted_names(AllNames0,
                              roles_with_admin_event_metakv_permissions()),
    Roles = compile_roles(AllNames, AllRoles),

    ?assertEqual(false, is_allowed({[admin, event], write}, Roles)),
    ?assertEqual(false, is_allowed({[admin, event], read}, Roles)),
    ?assertEqual(false, is_allowed({[admin, metakv], write}, Roles)).

roles_bucket_sys_write_permissions() ->
    [admin, eventing_admin, backup_admin, data_backup].

system_collections_write_permissions_test() ->
    AllRoles = roles() ++ add_serverless_roles(true),
    AllNames = extract_all_names(AllRoles),

    {SysWrite, NoSysWrite} =
        lists:partition(
          fun ({Name, _}) ->
                  lists:member(Name, roles_bucket_sys_write_permissions())
          end, AllNames),

    %% Ensure that all roles in SysWrite can write to all system collections.
    lists:foreach(
      fun(Name) ->
              Roles = compile_roles([Name], AllRoles),
              ?assertEqual(true, is_allowed({[{bucket, "default"},
                                              data, docs], swrite}, Roles)),
              ?assertEqual(true, is_allowed({[{collection,
                                               ["default", "s", "c"]},
                                              data, docs], swrite}, Roles))
      end, SysWrite),

    %% Ensure none of the roles in NoSysWrite can write to system collections.
    Roles0 = compile_roles(NoSysWrite, AllRoles),
    ?assertEqual(false, is_allowed({[{bucket, "default"}, data, docs], swrite},
                                   Roles0)),
    ?assertEqual(false, is_allowed({[{collection, ["default", "s", "c"]},
                                     data, docs], swrite}, Roles0)),

    %% Ensure that mobile_sync_gateway can write only to _mobile and not to
    %% other system collections.
    Roles1 = compile_roles([{mobile_sync_gateway, ["default"]}], AllRoles),
    ?assertEqual(true, is_allowed({[{collection, ["default",
                                                  ?SYSTEM_SCOPE_NAME,
                                                  "_mobile"]},
                                    data, docs], swrite}, Roles1)),

    ?assertEqual(false, is_allowed({[{collection, ["default",
                                                   ?SYSTEM_SCOPE_NAME,
                                                   "_query"]},
                                     data, docs], swrite}, Roles1)).

system_collections_read_permissions_test() ->
    AllRoles = roles() ++ add_serverless_roles(true),
    AllNames = extract_all_names(AllRoles),

    %% For now, we're retaining the ability to read from system collections -
    %% avoid filtering out system collections in DCP streams (when DCPProducer
    %% is set at the bucket level or DCPStream at the collection level). If
    %% docs can be read in non-system collections, allow reads from system
    %% collections too.
    lists:foreach(
      fun(Name)->
              Roles = compile_roles([Name], AllRoles),
              Perms0 = [{[{bucket, "default"}, data], read},
                        {[{bucket, "default"}, data, docs], read},
                        {[{bucket, "default"}, data, dcp], read}],
              Allowed0 = lists:any(is_allowed(_, Roles), Perms0),
              ?assertEqual(Allowed0,
                           is_allowed({[{bucket, "default"},
                                        data, docs], sread}, Roles)),
              Perms1 = [{[{collection, ["default", "s", "c"]},
                          data], read},
                        {[{collection, ["default", "s", "c"]},
                          data, docs], read},
                        {[{collection, ["default", "s", "c"]},
                          data, dcpstream], read}],
              Allowed1 = lists:any(is_allowed(_, Roles), Perms1),
              ?assertEqual(Allowed1,
                           is_allowed({[{collection,
                                         ["default", "s", "c"]},
                                        data, docs], sread}, Roles))
      end, AllNames),

    %% mobile_sync_gateway can read from all system collections.
    Roles = compile_roles([{mobile_sync_gateway,["test"]}], AllRoles),
    ?assertEqual(true, is_allowed({[{collection,
                                     ["test", ?SYSTEM_SCOPE_NAME, "_mobile"]},
                                    data, docs], sread}, Roles)),
    ?assertEqual(true, is_allowed({[{collection,
                                      ["test", ?SYSTEM_SCOPE_NAME, "_query"]},
                                     data, docs], sread}, Roles)).

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
                 is_allowed({[{bucket, "default"}, views], read}, Roles)),
    ?assertEqual(true,
                 is_allowed({[{bucket, "default"}, settings], read}, Roles)),
    ?assertEqual(false,
                 is_allowed({[{bucket, "default"}, settings], write}, Roles)),
    ?assertEqual(true,
                 is_allowed({[{bucket, "default"}, data], read}, Roles)),
    ?assertEqual(false,
                 is_allowed({[{bucket, "default"}, data], write}, Roles)),
    ?assertEqual(true, is_allowed({[xdcr, developer], read}, Roles)),
    ?assertEqual(false, is_allowed({[xdcr, developer], write}, Roles)),
    ?assertEqual(true, is_allowed({[xdcr], anything}, Roles)),
    ?assertEqual(false, is_allowed({[admin], read}, Roles)),
    ?assertEqual(true, is_allowed({[other], read}, Roles)).

compile_and_assert(Role, Permissions, Params, Results) ->
    Roles = compile_roles([{Role, Params}], roles()),
    ?assertEqual(Results, lists:map(
        fun (Permission) ->
            {Object, Operations} = Permission,
            case is_list(Operations) of
                true ->
                    lists:all(fun(Operation) ->
                                is_allowed({Object, Operation}, Roles)
                              end, Operations);
                false ->
                    is_allowed(Permission, Roles)
            end
        end, Permissions)).

collection_roles_test_() ->
    Roles = [{data_reader, [read, range_scan]},
             {query_select, [read]},
             {query_delete, [delete, range_scan]},
             {query_update, [upsert, range_scan]},
             {query_use_sequential_scans, [range_scan]}],

    Permissions =
        fun (Role, Ops) ->
                [{P, Ops} ||
                    P <- [[{collection, ["default", "s", "c"]}, data, docs],
                          [{collection, ["default", "s", "c1"]}, data, docs],
                          [{collection, ["default", "s", "c2"]}, data, docs],
                          [{scope, ["default", "s"]}, data, docs],
                          [{scope, ["default", "s1"]}, data, docs],
                          [{scope, ["default", "s2"]}, data, docs],
                          [{bucket, "default"}, data, docs]]] ++
                    [{[{bucket, "default"}, settings], read} ||
                        Role =/= query_use_sequential_scans]
        end,

    RolesWithPermissions = [{R, Permissions(R, Ops)} || {R, Ops} <- Roles],

    TestTemplates =
        [{"existing collection with id's",
          [{"default", <<"default_id">>}, {"s", 1}, {"c", 1}],
          [true, false, false, false, false, false, false, true]},
         {"wrong collection id",
          [{"default", <<"default_id">>}, {"s", 1}, {"c", 2}],
          [false, false, false, false, false, false, false, false]},
         {"existing collection without id's",
          ["default", "s", "c"],
          [true, false, false, false, false, false, false, true]},
         {"scope",
          ["default", "s", any],
          [true, true, true, true, false, false, false, true]},
         {"whole bucket",
          ["default", any, any],
          [true, true, true, true, true, true, true, true]},
         {"another bucket",
          ["test", any, any],
          [false, false, false, false, false, false, false, false]}
        ],

    {foreach, fun () -> ok end,
     [{Title ++ ", role = " ++ atom_to_list(Role),
       fun () ->
               compile_and_assert(Role, Perm, Params,
                                  lists:sublist(Expected, length(Perm)))
       end} ||
         {Title, Params, Expected} <- TestTemplates,
         {Role, Perm} <- RolesWithPermissions]}.

query_functions_test_() ->
    Roles = [{query_manage_functions, [n1ql, udf], manage},
             {query_execute_functions, [n1ql, udf], execute},
             {query_manage_external_functions, [n1ql, udf_external], manage},
             {query_execute_external_functions, [n1ql, udf_external], execute},
             {query_manage_sequences, [n1ql, sequences], manage},
             {query_use_sequences, [n1ql, sequences], execute}],

    Sources = [{scope, ["default", "s"]},
               {scope, ["default", "s1"]},
               {scope, ["default", "s2"]},
               {bucket, "default"}],

    Tests =
        lists:flatmap(
          fun ({Role, Object, Oper}) ->
                  RoleStr = atom_to_list(Role),
                  Permissions = [{[S | Object], Oper} || S <- Sources],
                  Test =
                      ?cut(fun () ->
                                   compile_and_assert(Role, Permissions, _, _)
                           end),

                  [{"existing scope with id's : " ++ RoleStr,
                    Test([{"default", <<"default_id">>}, {"s", 1}],
                         [true, false, false, false])},
                   {"wrong scope id : " ++ RoleStr,
                    Test([{"default", <<"default_id">>}, {"s", 2}],
                         [false, false, false, false])},
                   {"existing scope without id's : " ++ RoleStr,
                    Test(["default", "s"],
                         [true, false, false, false])},
                   {"whole bucket",
                    Test(["default", any],
                         [true, true, true, true])},
                   {"another bucket",
                    Test(["test", any],
                         [false, false, false, false])}]
          end, Roles),

    {foreach, fun () -> ok end, Tests}.

eventing_functions_test_() ->
    Roles = [{eventing_manage_functions, [eventing, function], manage}],

    Sources = [{scope, ["default", "s"]},
               {scope, ["default", "s1"]},
               {bucket, "default"}],

    Tests =
        lists:flatmap(
          fun ({Role, Object, Oper}) ->
                  RoleStr = atom_to_list(Role),
                  Permissions = [{[S | Object], Oper} || S <- Sources],
                  Test =
                    ?cut(fun () ->
                                 compile_and_assert(Role, Permissions, _, _)
                         end),

                    [{"existing scope with id's : " ++ RoleStr,
                      Test([{"default", <<"default_id">>}, {"s", 1}],
                           [true, false, false])},
                     {"whole bucket",
                      Test(["default", any],
                           [true, true, true])},
                     {"another bucket",
                      Test(["test", any],
                           [false, false, false])}]
          end, Roles),

        {foreach, fun () -> ok end, Tests}.

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
                           [{"default", <<"test_id">>}, {"s", 1}, {"c", 2}]})),
    QMF = {query_manage_functions, [{"default", <<"default_id">>}, {"s", 1}]},
    ?assertEqual({ok, QMF}, ValidateRole(QMF)),
    ?assertEqual({ok, QMF}, ValidateRole({query_manage_functions,
                                          ["default", "s"]})),
    ?assertEqual(false, ValidateRole({query_manage_functions,
                                      [{"default", <<"test_id">>}, {"s", 1}]})),
    ?assertEqual(false, ValidateRole({query_manage_functions,
                                      [{"default", <<"default_id">>},
                                       {"s", 2}]})).

enum_roles(Roles, ParamsList) ->
    Definitions = roles(),
    lists:flatmap(
      fun (Params) ->
              lists:map(
                fun (Role) ->
                        Length = length(get_param_defs(Role, Definitions)),
                        {Role, misc:align_list(Params, Length, any)}
                end, Roles)
      end, ParamsList).

produce_roles_by_permission_test_() ->
    GetRoles =
        fun (Permission) ->
                proplists:get_keys(
                  pipes:run(produce_roles_by_permission(Permission,
                                                        toy_buckets()),
                            pipes:collect()))
        end,
    Test =
        fun (Roles, Permission) ->
                fun () ->
                        ?assertListsEqual(Roles, GetRoles(Permission))
                end
        end,
    TestBucket = {"test", <<"test_id">>},
    DefaultBucket = {"default", <<"default_id">>},
    {foreach,
     fun() ->
             meck:new(cluster_compat_mode, [passthrough]),
             meck:expect(cluster_compat_mode, is_enterprise,
                         fun () -> true end),
             meck:expect(cluster_compat_mode, get_compat_version,
                         fun () -> ?LATEST_VERSION_NUM end),
             meck:expect(cluster_compat_mode, is_developer_preview,
                         fun () -> false end)
     end,
     fun (_) ->
             meck:unload(cluster_compat_mode)
     end,
     [{"security permission",
       Test([admin, ro_admin, security_admin],
            {[admin, security], any})},
      {"admin security permission (read)",
       Test([admin, ro_admin],
            {[admin, security, admin], read})},
      {"admin security permission (write)",
       Test([admin],
            {[admin, security, admin], write})},
      {"users permission",
       Test([admin, user_admin_local, user_admin_external,
             ro_admin, security_admin],
            {[admin, users], any})},
      {"security_info permission",
       Test([user_admin_local, user_admin_external, admin, ro_admin,
             security_admin],
            {[admin, security_info], read})},
      {"pools read",
       fun () ->
               Roles = GetRoles({[pools], read}),
               ?assertListsEqual(
                  [],
                  [admin, analytics_reader,
                   {data_reader, [any, any, any]}] -- Roles)
       end},
      {"bucket settings read",
       Test([admin, cluster_admin, query_external_access, query_system_catalog,
             replication_admin, ro_admin, security_admin, user_admin_local,
             user_admin_external, eventing_admin, backup_admin] ++
                enum_roles([bucket_full_access, bucket_admin, views_admin,
                            data_backup, data_dcp_reader,
                            data_monitoring, data_writer, data_reader,
                            fts_admin, fts_searcher, query_delete,
                            query_insert, query_manage_index,
                            query_list_index, query_select,
                            query_update, replication_target,
                            mobile_sync_gateway],
                           [[any], [TestBucket]]),
            {[{bucket, "test"}, settings], read})},
      {"docs insert for bucket",
       Test([admin, eventing_admin, backup_admin] ++
                enum_roles([bucket_full_access, data_backup, data_writer,
                            mobile_sync_gateway, query_insert],
                           [[any], [TestBucket]]),
            {[{bucket, "test"}, data, docs], insert})},
      {"docs insert for wrong bucket",
       Test([admin, eventing_admin, backup_admin] ++
                enum_roles([bucket_full_access, data_backup, data_writer,
                            mobile_sync_gateway, query_insert],
                           [[any]]),
            {[{bucket, "wrong"}, data, docs], insert})},
      {"docs insert for collection",
       Test([admin, eventing_admin, backup_admin] ++
                enum_roles([bucket_full_access, data_backup, data_writer,
                            mobile_sync_gateway, query_insert],
                           [[any], [DefaultBucket]]) ++
                enum_roles([data_writer, query_insert],
                           [[DefaultBucket, {"s", 1}]]) ++
                enum_roles([data_writer, query_insert],
                           [[DefaultBucket, {"s", 1}, {"c", 1}]]),
            {[{collection, ["default", "s", "c"]}, data, docs], insert})},
      {"docs insert for wrong collection",
       Test([admin, eventing_admin, backup_admin] ++
                enum_roles([bucket_full_access, data_backup, data_writer,
                            mobile_sync_gateway, query_insert],
                           [[any], [DefaultBucket]]) ++
                enum_roles([data_writer, query_insert],
                           [[DefaultBucket, {"s", 1}]]),
            {[{collection, ["default", "s", "w"]}, data, docs], insert})},
      {"docs insert for scope",
       Test([admin, eventing_admin, backup_admin] ++
                enum_roles([bucket_full_access, data_backup, data_writer,
                            mobile_sync_gateway, query_insert],
                           [[any], [DefaultBucket]]) ++
                enum_roles([data_writer, query_insert],
                           [[DefaultBucket, {"s", 1}]]),
            {[{scope, ["default", "s"]}, data, docs], insert})},
      {"docs insert for wrong scope",
       Test([admin, eventing_admin, backup_admin] ++
                enum_roles([bucket_full_access, data_backup, data_writer,
                            mobile_sync_gateway, query_insert],
                           [[any], [DefaultBucket]]),
            {[{scope, ["default", "w"]}, data, docs], insert})},
      {"any bucket",
       Test([admin, eventing_admin, backup_admin] ++
                enum_roles([bucket_full_access, data_backup, data_writer,
                            mobile_sync_gateway, query_insert],
                           [[any]]),
            {[{bucket, any}, data, docs], insert})},
      {"wrong bucket",
       Test([admin, eventing_admin, backup_admin] ++
                enum_roles([bucket_full_access, data_backup, data_writer,
                            mobile_sync_gateway, query_insert],
                           [[any]]),
            {[{bucket, "wrong"}, data, docs], insert})}]}.


params_version_get_snapshot(TestProps, _, SubKeys) ->
    PrunedProps = lists:flatmap(
                    fun({Bucket, Props}) ->
                            [{Bucket,
                              lists:filtermap(
                                fun({SubKey, _}) ->
                                        lists:member(SubKey, SubKeys)
                                end, Props)}]
                    end, TestProps),
    ns_bucket:toy_buckets(PrunedProps).

params_version_case(TestProps) ->
    meck:expect(ns_bucket, get_snapshot,
                params_version_get_snapshot(TestProps, _, _)),
    Snapshot = ns_bucket:toy_buckets(TestProps),
    Version = params_version(Snapshot),
    ?assertEqual(params_version(), Version),
    Version.

params_version_test() ->
    setup_meck(),
    meck:new(ns_bucket, [passthrough]),

    try
        Update = ?cut(lists:keyreplace("test", 1, toy_buckets_props(),
                                       {"test", _})),
        BaseVersion = params_version_case(toy_buckets_props()),
        lists:foreach(
          fun(X) -> ?assertNotEqual(params_version_case(X), BaseVersion) end,
          [lists:keydelete("test", 1, toy_buckets_props()),
           Update([{uuid, <<"test_id1">>}, {props, toy_props()}]),
           Update([{uuid, <<"test_id">>}, {collections, toy_manifest()},
                   {props, toy_props()}])])
    after
        meck:unload(ns_bucket),
        teardown_meck()
    end.

validate_test_roles(Roles) ->
    lists:all(
      fun ({Name, Params, Desc, Permissions}) when is_atom(Name),
                                                   is_list(Params),
                                                   is_list(Desc),
                                                   is_list(Permissions) ->
          ?assert(lists:member(Params, all_params_combinations())),
          ?assert(lists:all(fun ({_, _}) -> true; (_) -> false end, Desc)),
          ValidateObject =
              fun (Obj) ->
                  ?assert(lists:all(
                            fun (A) when is_atom(A) -> true;
                                ({A, _}) when is_atom(A) -> true;
                                (_) -> false
                            end, Obj)),
                  true
              end,
          ?assert(lists:all(
                    fun ({Object, all}) -> ValidateObject(Object);
                        ({Object, none}) -> ValidateObject(Object);
                        ({Object, Ops}) when is_list(Ops) ->
                            ?assert(lists:all(fun (A) -> is_atom(A) end, Ops)),
                            ValidateObject(Object)
                    end, Permissions)),
          true
      end, Roles).

roles_format_test() ->
    setup_meck(),

    ?assert(validate_test_roles(roles())),
    ?assert(validate_test_roles(menelaus_old_roles:roles_pre_76())),
    ?assert(validate_test_roles(menelaus_old_roles:roles_pre_morpheus())),

    teardown_meck().

params_from_permissions_test() ->
    CompiledRoles =
        [[{[{collection,["ab","_default","_default"]},data,docs],
           [read,range_scan,sread]},
          {[{bucket,"ab"},settings],[read]},
          {[pools],[read]}],
         [{[{collection,["bc","_system","_mobile"]},data],all},
          {[{bucket,"bc"},data,docs],
           [read,insert,delete,upsert,range_scan,sread]},
          {[{bucket,"bc"},data],all},
          {[{bucket,"bc"},views],all},
          {[{bucket,"bc"},n1ql,index],all},
          {[{bucket,"bc"},n1ql],[execute]},
          {[{bucket,"bc"}],[read,flush]},
          {[{bucket,"bc"},settings],[read]},
          {[admin,memcached,idle],[write]},
          {[settings,autocompaction],[read]},
          {[pools],[read]}],
         [{[{scope,["ab","_system"]},collections],all}]],
    Expected =
        [["ab", any, any],
         ["ab","_default","_default"],
         ["ab","_system", any],
         ["bc", any, any],
         ["bc","_system","_mobile"]],

    ?assertEqual(Expected, get_params_from_permissions(CompiledRoles)).

-endif.
