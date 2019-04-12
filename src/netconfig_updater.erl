-module(netconfig_updater).

-behaviour(gen_server).

%% API
-export([start_link/0, apply_net_config/2, apply_ext_dist_protocols/1]).

%% gen_server callbacks
-export([init/1, handle_call/3, handle_cast/2, handle_info/2,
         terminate/2, code_change/3]).

-record(s, {}).

-include_lib("kernel/include/net_address.hrl").
-include("ns_common.hrl").

%%%===================================================================
%%% API
%%%===================================================================

start_link() ->
    proc_lib:start_link(?MODULE, init, [[]]).

apply_net_config(AFamily, CEncrypt) ->
    gen_server:call(?MODULE, {apply_net_config, AFamily, CEncrypt}, infinity).

apply_ext_dist_protocols(Protos) ->
    gen_server:call(?MODULE, {apply_ext_dist_protocols, Protos}, infinity).

%%%===================================================================
%%% gen_server callbacks
%%%===================================================================

init([]) ->
    ServerName = ?MODULE,
    register(ServerName, self()),
    proc_lib:init_ack({ok, self()}),
    case misc:consult_marker(update_marker_path()) of
        {ok, [Cmd]} ->
            ?log_info("Found update netconfig marker: ~p", [Cmd]),
            case apply_and_delete_marker(Cmd) of
                ok -> ok;
                {error, Error} -> erlang:error(Error)
            end;
        false -> ok
    end,
    gen_server:enter_loop(?MODULE, [], #s{}, {local, ServerName}, hibernate).

handle_call({apply_net_config, _, _} = Cmd, _From, State) ->
    CurAFamily = cb_dist:address_family(),
    CurCEncrypt = cb_dist:external_encryption(),
    handle_with_marker(Cmd, {apply_net_config, CurAFamily, CurCEncrypt}, State);

handle_call({apply_ext_dist_protocols, _} = Cmd, _From, State) ->
    CurProtos = cb_dist:external_listeners(),
    handle_with_marker(Cmd, {apply_ext_dist_protocols, CurProtos}, State);

handle_call(Request, _From, State) ->
    ?log_error("Unhandled call: ~p", [Request]),
    {noreply, State, hibernate}.

handle_cast(Msg, State) ->
    ?log_error("Unhandled cast: ~p", [Msg]),
    {noreply, State, hibernate}.

handle_info(Info, State) ->
    ?log_error("Unhandled info: ~p", [Info]),
    {noreply, State, hibernate}.

terminate(_Reason, _State) ->
    ok.

code_change(_OldVsn, State, _Extra) ->
    {ok, State}.

%%%===================================================================
%%% Internal functions
%%%===================================================================

handle_with_marker(Command, Marker, State) ->
    case misc:marker_exists(update_marker_path()) of
        false ->
            MarkerStr = io_lib:format("~p.", [Marker]),
            misc:create_marker(update_marker_path(), MarkerStr),
            case apply_and_delete_marker(Command) of
                ok -> {reply, ok, State, hibernate};
                {error, _} = Error -> {stop, Error, Error, State}
            end;
        true ->
            {stop, marker_exists, State}
    end.

apply_and_delete_marker(Cmd) ->
    Res = case Cmd of
              {apply_net_config, AFamily, CEncrypt} ->
                  apply_net_config_unprotected(AFamily, CEncrypt);
              {apply_ext_dist_protocols, Protos} ->
                  apply_ext_dist_protocols_unprotected(Protos)
          end,
    (Res =:= ok) andalso misc:remove_marker(update_marker_path()),
    Res.

apply_net_config_unprotected(AFamily, CEncrypt) ->
    ?log_info("Node is going to apply the following net settings: afamily ~p, "
              "encryptiion ~p", [AFamily, CEncrypt]),
    case update_type(AFamily, CEncrypt) of
        empty -> ok;
        Type ->
            try
                update_proto_in_dist_config(AFamily, CEncrypt),
                case Type of
                    external_only -> ok;
                    _ -> change_local_dist_proto(AFamily, false)
                end,
                change_ext_dist_proto(AFamily, CEncrypt),
                ns_config:set({node, node(), address_family},
                              AFamily),
                ns_config:set({node, node(), cluster_encryption},
                              CEncrypt),
                ?log_info("Node network settings (afamily: ~p, encryptiion: ~p)"
                          " successfully applied", [AFamily, CEncrypt]),
                ok
            catch
                error:Error ->
                    Msg = iolist_to_binary(format_error(Error)),
                    ?log_error("~s", [Msg]),
                    {error, Msg}
            end
    end.

update_type(AFamily, CEncrypt) ->
    CurAFamily = cb_dist:address_family(),
    CurCEncrypt = cb_dist:external_encryption(),
    case {CurAFamily =/= AFamily, CurCEncrypt =/= CEncrypt} of
        {true, _} -> all;
        {false, true} -> external_only;
        {false, false} -> empty
    end.

update_proto_in_dist_config(AFamily, CEncryption) ->
    case cb_dist:update_net_settings_in_config(AFamily, CEncryption) of
        {ok, _} -> ok;
        {error, Error} ->
            erlang:error({update_cb_dist_config_error,
                          cb_dist:format_error(Error)})
    end.


change_local_dist_proto(ExpectedFamily, ExpectedEncryption) ->
    ?log_info("Reconnecting to babysitter and restarting couchdb since local "
              "dist protocol settings changed, expected afamily is ~p, "
              "expected encryption is ~p",
              [ExpectedFamily, ExpectedEncryption]),
    Babysitter = ns_server:get_babysitter_node(),
    case cb_dist:reload_config(Babysitter) of
        {ok, _} -> ok;
        {error, Error} ->
            erlang:error({reload_cb_dist_config_error, Babysitter,
                          cb_dist:format_error(Error)})
    end,
    ensure_connection_proto(Babysitter,
                            ExpectedFamily, ExpectedEncryption, 10),
    %% Curently couchdb doesn't support gracefull change of afamily
    %% so we have to restart it. Unfortunatelly we can't do it without
    %% restarting ns_server.
    case ns_server_cluster_sup:restart_ns_server() of
        {ok, _} ->
            check_connection_proto(ns_node_disco:couchdb_node(),
                                   ExpectedFamily, ExpectedEncryption);
        {error, not_running} -> ok;
        Error2 -> erlang:error({ns_server_restart_error, Error2})
    end.

change_ext_dist_proto(ExpectedFamily, ExpectedEncryption) ->
    Nodes = ns_node_disco:nodes_wanted() -- [node()],
    ?log_info("Reconnecting to all known erl nodes since dist protocol "
              "settings changed, expected afamily is ~p, expected encryption "
              "is ~p, nodes: ~p", [ExpectedFamily, ExpectedEncryption, Nodes]),
    [ensure_connection_proto(N, ExpectedFamily, ExpectedEncryption, 10)
        || N <- Nodes],
    ok.

ensure_connection_proto(Node, _Family, _Encr, Retries) when Retries =< 0 ->
    erlang:error({exceeded_retries, Node});
ensure_connection_proto(Node, Family, Encryption, Retries) ->
    erlang:disconnect_node(Node),
    case net_kernel:connect(Node) of
        true ->
            ?log_debug("Reconnected to ~p, checking connection type...",
                       [Node]),
            try check_connection_proto(Node, Family, Encryption) of
                ok -> ok
            catch
                error:Reason ->
                    ?log_error("Checking node ~p connection type failed with "
                               "reason: ~p, retries left: ~p",
                               [Node, Reason, Retries - 1]),
                    timer:sleep(rand:uniform(30)),
                    ensure_connection_proto(Node, Family, Encryption,
                                            Retries - 1)
            end;
        false ->
            ?log_error("Failed to connect to node ~p, retries left: ~p",
                       [Node, Retries - 1]),
            timer:sleep(100),
            ensure_connection_proto(Node, Family, Encryption, Retries - 1)
    end.

check_connection_proto(Node, Family, Encryption) ->
    Proto = case Encryption of
                true -> proxy;
                false -> tcp
            end,
    case net_kernel:node_info(Node) of
        {ok, Info} ->
            case proplists:get_value(address, Info) of
                %% Workaround for a bug in inet_tls_dist.erl
                %% address family is always set to inet, even when the socket
                %% is actually an inet6 socket
                #net_address{address = {{_, _, _, _, _, _, _, _}, _},
                             protocol = proxy,
                             family = inet} when Proto == proxy,
                                                 Family == inet6 -> ok;
                #net_address{protocol = Proto, family = Family} -> ok;
                A -> erlang:error({wrong_proto, Node, A})
            end;
        {error, Error} ->
            erlang:error({node_info, Node, Error})
    end.

format_error({update_cb_dist_config_error, Msg}) ->
    io_lib:format("Failed to update cb_dist configuration file: ~s", [Msg]);
format_error({reload_cb_dist_config_error, Node, Msg}) ->
    io_lib:format("Failed to reload cb_dist configuration file on node ~p: ~s",
                  [Node, Msg]);
format_error({ns_server_restart_error, Error}) ->
    io_lib:format("Restart error: ~p", [Error]);
format_error({node_info, Node, Error}) ->
    io_lib:format("Failed to get connection info to node ~p: ~p",
                  [Node, Error]);
format_error({wrong_proto, Node, _}) ->
    io_lib:format("Couldn't establish connection of desired type to node ~p",
                  [Node]);
format_error({exceeded_retries, Node}) ->
    io_lib:format("Reconnect to ~p retries exceeded", [Node]);
format_error({host_ip_not_allowed, Addr}) ->
    io_lib:format("Can't change address family when node is using raw IP "
                  "addr: ~p", [Addr]);
format_error({rename_failed, Addr, Reason}) ->
    io_lib:format("Address change (~p) failed with reason: ~p", [Addr, Reason]);
format_error(R) ->
    io_lib:format("~p", [R]).

apply_ext_dist_protocols_unprotected(Protos) ->
    ?log_info("Node is going to change dist protocols to ~p", [Protos]),
    case cb_dist:update_listeners_in_config(Protos) of
        {ok, Listeners} ->
            NotStarted = case Protos of
                             undefined -> [];
                             _ -> Protos -- Listeners
                         end,
            case NotStarted of
                [] ->
                    ns_config:set({node, node(), erl_external_dist_protocols},
                                  Protos),
                    ok;
                L ->
                    ProtoStrs = [cb_dist:proto2str(P) || P <- L],
                    Msg = io_lib:format("Failed to start listeners: ~s",
                                        [string:join(ProtoStrs, ", ")]),
                    {error, iolist_to_binary(Msg)}
            end;
        {error, Error} ->
            Msg = io_lib:format("Failed to update cb_dist config: ~s",
                                [cb_dist:format_error(Error)]),
            {error, iolist_to_binary(Msg)}
    end.

update_marker_path() ->
    path_config:component_path(data, "netconfig_marker").
