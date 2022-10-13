-module(cb_creds_rotation).

-include("ns_common.hrl").

%% API
-export([rotate_password/0]).

rotate_password() ->
    StartTS = erlang:system_time(millisecond),
    Node = dist_manager:this_node(),
    NewPass = ns_config_default:generate_internal_pass(),
    [OldPass | _] = ns_config_auth:get_special_passwords(Node,
                                                         ns_config:latest()),

    ServerPasswordSync =
        fun () ->
            ns_config:sync_announcements(),
            chronicle_compat_events:sync(),
            memcached_passwords:sync(),
            menelaus_cbauth:sync()
        end,

    ClientPasswordSync =
        fun () ->
            ns_config:sync_announcements(),
            chronicle_compat_events:sync(),
            ns_config_rep:ensure_config_seen_by_nodes(
              ns_node_disco:nodes_actual_other(), infinity),
            [menelaus_cbauth:sync(N) || N <- ns_node_disco:nodes_actual()]
        end,

    ?log_info("Start password rotation phase 0"),
    %% Phase0: Before removing anything we make sure that current passwords are
    %% propagated properly. If previous rotation finished unsuccessfully for
    %% any reason, it might be the case that previous sync has not finished.
    ClientPasswordSync(),

    ?log_info("Start password rotation phase 1"),
    %% Phase1: Add NewPass to all internal "servers", so all servers can now
    %% accept NewPass as a valid password. OldPass should still work as well.
    %% This change affects only "servers". At the same time we know that
    %% "servers" only use local node's admin passwords from ns_config.
    %% Which means this change doesn't actually affect remote nodes.
    update_admin_pass(Node, [OldPass, NewPass]),
    ServerPasswordSync(),

    ?log_info("Start password rotation phase 2"),
    %% Phase2: Switch internal "clients" to use NewPass when authenticating.
    %% This change affects "clients" only. "Clients" can hypothetically use
    %% passwords for all the nodes in the cluster, so this change actually
    %% affects all the nodes in the cluster.
    update_admin_pass(Node, [NewPass, OldPass]),
    ClientPasswordSync(),

    ?log_info("Start password rotation phase 3"),
    %% Phase3: Since all internal "clients" and all "servers" use
    %% NewPass now, it is safe to remove OldPass complitely.
    %% This change affects "servers" only, it means it affects local
    %% node only (see the comments above).
    update_admin_pass(Node, [NewPass]),
    ServerPasswordSync(),

    ?log_info("Password rotation finished (total time: ~pms)",
               [erlang:system_time(millisecond) - StartTS]),
    ok.

update_admin_pass(Node, NewPasswords) ->
    ns_config:update_key(
      {node, Node, memcached},
      fun (List) ->
          Res = misc:key_update(
                  admin_pass,
                  List,
                  fun (_) -> {v2, NewPasswords} end),
          case Res of
              false -> List;
              NewList when is_list(NewList) -> NewList
          end
      end).
