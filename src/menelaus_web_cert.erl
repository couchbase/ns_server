%% @author Couchbase <info@couchbase.com>
%% @copyright 2015-Present Couchbase, Inc.
%%
%% Use of this software is governed by the Business Source License included
%% in the file licenses/BSL-Couchbase.txt.  As of the Change Date specified
%% in that file, in accordance with the Business Source License, use of this
%% software will be governed by the Apache License, Version 2.0, included in
%% the file licenses/APL2.txt.
%%
%% @doc REST api's for handling ssl certificates

-module(menelaus_web_cert).

-include("ns_common.hrl").

-export([handle_get_trustedCAs/1,
         handle_cluster_certificate/1,
         handle_regenerate_certificate/1,
         handle_load_ca_certs/1,
         handle_upload_cluster_ca/1, %% deprecated
         handle_reload_node_certificate/1,
         handle_get_node_certificate/2,
         handle_client_cert_auth_settings/1,
         handle_client_cert_auth_settings_post/1]).

-define(MAX_CLIENT_CERT_PREFIXES, ?get_param(max_prefixes, 10)).

handle_get_trustedCAs(Req) ->
    menelaus_util:assert_is_enterprise(),
    Warnings = ns_server_cert:get_warnings(),
    Json = lists:map(
             fun (Props) ->
                 CAId = proplists:get_value(id, Props),
                 CAWarnings = [{warning_props(W)} || {{ca, Id}, W} <- Warnings,
                                                     Id =:= CAId],
                 {JSONObjProps} = jsonify_cert_props(Props),
                 {JSONObjProps ++ [{warnings, CAWarnings}]}
             end, ns_server_cert:trusted_CAs(props)),
    menelaus_util:reply_json(Req, Json).

handle_cluster_certificate(Req) ->
    menelaus_util:assert_is_enterprise(),
    %% This API doesn't make sense anymore because it is now possible that
    %% different nodes in the cluster might have different CAs (not that it's
    %% good idea in general but it is definitely the case during CA rotation)
    %% So, the idea is to keep this endpoint working for backward compat reasons
    %% until at least one CA is loaded. When the CA is added  this endpoint is
    %% not correct anymore and should start returning error
    assert_old_CAs(),

    case proplists:get_value("extended", mochiweb_request:parse_qs(Req)) of
        "true" ->
            handle_cluster_certificate_extended(Req);
        _ ->
            handle_cluster_certificate_simple(Req)
    end.

assert_old_CAs() ->
    NoNewCAsUploaded =
        lists:all(
          fun (P) -> upgrade == proplists:get_value(origin, P) end,
          ns_server_cert:trusted_CAs(props)),
    case NoNewCAsUploaded of
        true -> ok;
        false ->
            Err = <<"deprecated, please use /pools/default/trustedCAs">>,
            menelaus_util:web_exception(400, Err)
    end.

handle_cluster_certificate_simple(Req) ->
    Cert = lists:last(ns_server_cert:trusted_CAs(pem)),
    menelaus_util:reply_ok(Req, "text/plain", Cert).

format_time(UTCSeconds) ->
    LocalTime = calendar:universal_time_to_local_time(
                  calendar:gregorian_seconds_to_datetime(UTCSeconds)),
    menelaus_util:format_server_time(LocalTime, 0).

warning_props({expires_soon, UTCSeconds}) ->
    [{message, ns_error_messages:node_certificate_warning(expires_soon)},
     {expires, format_time(UTCSeconds)}];
warning_props(Warning) ->
    [{message, ns_error_messages:node_certificate_warning(Warning)}].

translate_warning({{node, Node}, Warning}) ->
    [{node, Node} | warning_props(Warning)];
translate_warning({{ca, Id}, Warning}) ->
    [{ca, Id} | warning_props(Warning)].

jsonify_cert_props(Props) ->
    {lists:filtermap(
       fun ({expires, UTCSeconds}) ->
               {true, {expires, format_time(UTCSeconds)}};
           ({not_after, UTCSeconds}) ->
               {true, {notAfter, format_time(UTCSeconds)}};
           ({not_before, UTCSeconds}) ->
               {true, {notBefore, format_time(UTCSeconds)}};
           ({load_timestamp, UTCSeconds}) ->
               {true, {loadTimestamp, format_time(UTCSeconds)}};
           ({load_host, H}) ->
               {true, {loadHost, H}};
           ({load_file, F}) ->
               {true, {loadFile, F}};
           ({K, _}) when K =:= subject;
                         K =:= pem;
                         K =:= id;
                         K =:= type ->
               true;
           ({_, _}) ->
               false
       end, Props)}.

handle_cluster_certificate_extended(Req) ->
    CertProps =
        lists:filtermap( %% to be compatible with pre-NEO
          fun ({not_after, V}) -> {true, {expires, V}};
              ({not_before, _}) -> false;
              ({id, _}) -> false;
              ({K, V}) -> {true, {K, V}}
          end, lists:last(ns_server_cert:trusted_CAs(props))),
    CertJson = jsonify_cert_props(CertProps),
    Warnings = [{translate_warning(W)} || W <- ns_server_cert:get_warnings()],
    menelaus_util:reply_json(Req, {[{cert, CertJson}, {warnings, Warnings}]}).

handle_regenerate_certificate(Req) ->
    menelaus_util:assert_is_enterprise(),
    assert_n2n_encryption_is_disabled(),

    ns_server_cert:generate_and_set_cert_and_pkey(),
    ns_ssl_services_setup:sync(),
    ?log_info("Completed certificate regeneration"),
    ns_audit:regenerate_certificate(Req),
    handle_cluster_certificate_simple(Req).

reply_error(Req, Error) ->
    menelaus_util:reply_json(
      Req, {[{error, ns_error_messages:cert_validation_error_message(Error)}]}, 400).

handle_load_ca_certs(Req) ->
    menelaus_util:assert_is_enterprise(),
    menelaus_util:assert_is_NEO(),
    Nodes = nodes(),
    case ns_server_cert:load_CAs_from_inbox() of
        {ok, NewCertsProps} ->
            lists:foreach(
              fun (Props) ->
                  Subject = proplists:get_value(subject, Props),
                  Expire = proplists:get_value(not_after, Props),
                  ns_audit:upload_cluster_ca(Req, Subject, Expire)
              end, NewCertsProps),
            ns_ssl_services_setup:sync(),
            case netconfig_updater:ensure_tls_dist_started(Nodes) of
                ok ->
                    CertsJson = [jsonify_cert_props(C) || C <- NewCertsProps],
                    menelaus_util:reply_json(Req, CertsJson, 200);
                {error, ErrorMsg} ->
                    menelaus_util:reply_json(Req, ErrorMsg, 400)
            end;
        {error, Error} ->
            ?log_error("Error loading CA certificates: ~p", [Error]),
            menelaus_util:reply_json(
              Req, ns_error_messages:load_CAs_from_inbox_error(Error), 400)
    end.

handle_upload_cluster_ca(Req) ->
    case (not cluster_compat_mode:is_cluster_NEO()) orelse
         ns_config:read_key_fast(allow_non_local_ca_upload, false) of
        true -> ok;
        false -> menelaus_util:ensure_local(Req)
    end,
    menelaus_util:assert_is_enterprise(),

    case mochiweb_request:recv_body(Req) of
        undefined ->
            reply_error(Req, empty_cert);
        PemEncodedCA ->
            case cluster_compat_mode:is_cluster_NEO() of
                true ->
                    case ns_server_cert:add_CAs(uploaded, PemEncodedCA,
                                                [{single_cert, true}]) of
                        {ok, []} ->
                            reply_error(Req, already_in_use);
                        {ok, [Props]} ->
                            ns_audit:upload_cluster_ca(
                              Req,
                              proplists:get_value(subject, Props),
                              proplists:get_value(not_after, Props)),
                            handle_cluster_certificate_extended(Req);
                        {error, Error} ->
                            reply_error(Req, Error)
                    end;
                false ->
                    assert_n2n_encryption_is_disabled(),
                    case ns_server_cert:set_cluster_ca(PemEncodedCA) of
                        {ok, Props} ->
                            ns_audit:upload_cluster_ca(
                              Req,
                              proplists:get_value(subject, Props),
                              proplists:get_value(expires, Props)),
                            handle_cluster_certificate_extended(Req);
                        {error, Error} ->
                            reply_error(Req, Error)
                    end
            end
    end.

assert_n2n_encryption_is_disabled() ->
    case misc:is_cluster_encryption_fully_disabled() of
        true -> ok;
        false ->
            menelaus_util:web_exception(
              400, "Operation requires node-to-node encryption to be disabled")
    end.

handle_reload_node_certificate(Req) ->
    menelaus_util:assert_is_enterprise(),
    Nodes = nodes(),
    {PassphraseSettings} =
        case mochiweb_request:recv_body(Req) of
            undefined -> {[]};
            <<>> -> {[]};
            Bin when is_binary(Bin) -> ejson:decode(Bin)
        end,
    case ns_server_cert:load_node_certs_from_inbox(PassphraseSettings) of
        {ok, Props} ->
            ns_audit:reload_node_certificate(Req,
                                             proplists:get_value(subject, Props),
                                             proplists:get_value(not_after, Props)),
            ns_ssl_services_setup:sync(),
            case netconfig_updater:ensure_tls_dist_started(Nodes) of
                ok ->
                    menelaus_util:reply(Req, 200);
                {error, ErrorMsg} ->
                    menelaus_util:reply_json(Req, ErrorMsg, 400)
            end;
        {error, Error} ->
            ?log_error("Error reloading node certificate: ~p", [Error]),
            menelaus_util:reply_json(
              Req, ns_error_messages:reload_node_certificate_error(Error), 400)
    end.

handle_get_node_certificate(NodeId, Req) ->
    menelaus_util:assert_is_enterprise(),

    case menelaus_web_node:find_node_hostname(NodeId, Req) of
        {ok, Node} ->
            case ns_server_cert:get_node_cert_info(Node) of
                [] ->
                    menelaus_util:reply_text(Req, <<"Certificate is not set up on this node">>, 404);
                Props ->
                    Filtered =
                        lists:filtermap(
                            fun ({subject, _}) -> true;
                                %% Backward compat:
                                ({not_after, V}) -> {true, {expires, V}};
                                ({pem, _}) -> true;
                                ({type, _}) -> true;
                                (_) -> false
                            end, Props),
                    CertJson = jsonify_cert_props(Filtered),
                    menelaus_util:reply_json(Req, CertJson)
            end;
        {error, {invalid_node, Reason}} ->
            menelaus_util:reply_text(Req, Reason, 400);
        {error, not_found} ->
            menelaus_util:reply_text(
              Req,
              <<"Node is not found, make sure the ip address/hostname matches the ip address/hostname used by Couchbase">>,
              404)
    end.

allowed_values(Key) ->
    Values = [{"state", ["enable", "disable", "mandatory"]},
              {"path", ["subject.cn", "san.uri", "san.dnsname", "san.email"]},
              {"prefix", any},
              {"delimiter", any}],
    proplists:get_value(Key, Values, none).

handle_client_cert_auth_settings(Req) ->
    Cca = ns_ssl_services_setup:client_cert_auth(),
    State = list_to_binary(proplists:get_value(state, Cca)),
    Prefixes = [begin
                    {struct, [{list_to_binary(atom_to_list(K)), list_to_binary(V)}
                              || {K, V} <- Triple]}
                end || Triple <- proplists:get_value(prefixes, Cca, [])],

    Out = {struct, [{<<"state">>, State}, {<<"prefixes">>, Prefixes}]},
    menelaus_util:reply_json(Req, Out).

validate_client_cert_auth_param(Key, Val) ->
    Values = allowed_values(Key),
    case Values == any orelse lists:member(Val, Values) of
        true ->
            {ok, {list_to_atom(Key), Val}};
        false ->
            {error, io_lib:format("Invalid value '~s' for key '~s'", [Val, Key])}
    end.

validate_client_cert_auth_state(StateVal, Prefixes, Cfg, Errors) ->
    case validate_client_cert_auth_param("state", StateVal) of
        {ok, CfgPair} ->
            case StateVal =/= "disable" andalso Prefixes =:= [] of
                true ->
                    E = {error, io_lib:format("'prefixes' cannot be empty when the "
                                              "'state' is '~s'", [StateVal])},
                    {Cfg, [E | Errors]};
                false ->
                    case StateVal =:= "mandatory" andalso
                        misc:should_cluster_data_be_encrypted() of
                        false -> {[CfgPair | Cfg], Errors};
                        true ->
                            M = "Cannot set 'state' to 'mandatory' when "
                                "cluster encryption level has been set to "
                                "'all'",
                            E = {error, M},
                            {Cfg, [E | Errors]}
                    end
            end;
        Err ->
            {Cfg, [Err | Errors]}
    end.

validate_triple(Triple) ->
    Triple1 = lists:sort(Triple),
    case [K || {K, _V} <- Triple1] =:= ["delimiter", "path", "prefix"] of
        true ->
            case validate_client_cert_auth_param("path", proplists:get_value("path", Triple1)) of
                {ok, _} ->
                    {[{list_to_atom(K), V} || {K, V} <- Triple1], []};
                E ->
                    {[], [E]}
            end;
        false ->
            E = {error, io_lib:format("Invalid prefixes entry (~p). Must contain "
                                      "'path', 'prefix' & 'delimiter' fields.",
                                      [Triple1])},
            {[], [E]}
    end.

check_for_duplicate_prefixes(_PrefixCfg, Errors) when Errors =/= [] ->
    Errors;
check_for_duplicate_prefixes(PrefixCfg, Errors) ->
    {_, NewErrors} =
        lists:foldl(
          fun(Triple, {Set, EAcc}) ->
                  Path = proplists:get_value(path, Triple),
                  Prefix = proplists:get_value(prefix, Triple),

                  case sets:is_element({Path, Prefix}, Set) of
                      true ->
                          E = {error,
                               io_lib:format("Multiple entries with same path & prefix "
                                             "(~p) are not allowed", [{Path, Prefix}])},
                          {Set, [E | EAcc]};
                      false ->
                          {sets:add_element({Path, Prefix}, Set), EAcc}
                  end
          end, {sets:new(), Errors}, PrefixCfg),

    NewErrors.

validate_client_cert_auth_prefixes(Prefixes, Cfg, Errors) ->
    %% Prefixes are represented as a list of lists. Each list contains
    %% tuples representing the path, prefix and delimiter.
    {PCfg, PErrs0} = lists:foldr(
                      fun({C, E}, {CAcc, EAcc}) ->
                              {[C | CAcc], E ++ EAcc}
                      end, {[], []}, [validate_triple(Triple) || Triple <- Prefixes]),

    PErrs = check_for_duplicate_prefixes(PCfg, PErrs0),
    {Cfg ++ [{prefixes, PCfg}], PErrs ++ Errors}.

handle_client_cert_auth_settings_post(Req) ->
    menelaus_util:assert_is_enterprise(),

    try
        JSON = menelaus_util:parse_json(Req),
        do_handle_client_cert_auth_settings_post(Req, JSON)
    catch
        throw:{error, Msg} ->
            menelaus_util:reply_json(Req, Msg, 400);
        _:_ ->
            menelaus_util:reply_json(Req, <<"Invalid JSON">>, 400)
    end.

%% The client_cert_auth settings will be a JSON payload and it'll look like
%% the following:
%%
%% {
%%     "state": "enable",
%%     "prefixes": [
%%       {
%%         "path": "san.uri",
%%         "prefix": "www.cb-",
%%         "delimiter": ".,;"
%%       },
%%       {
%%         "path": "san.email",
%%         "prefix": "a",
%%         "delimiter": "@"
%%       }
%%     ]
%% }
do_handle_client_cert_auth_settings_post(Req, JSON) ->
    {struct, Data} = JSON,
    StateRaw = proplists:get_value(<<"state">>, Data),
    PrefixesRaw = proplists:get_value(<<"prefixes">>, Data),

    case StateRaw =:= undefined orelse PrefixesRaw =:= undefined of
        true ->
            throw({error,
                   <<"Unsupported format: Must contain 'state' and 'prefixes' "
                     "fields">>});
        false ->
            case length(proplists:get_keys(Data)) > 2 of
                true ->
                    throw({error, <<"Unsupported fields: Must contain 'state' "
                                    "and 'prefixes' fields only">>});
                false -> ok
            end
    end,

    State = binary_to_list(StateRaw),
    case length(PrefixesRaw) > ?MAX_CLIENT_CERT_PREFIXES of
        true ->
            Err = io_lib:format("Maximum number of prefixes supported is ~p",
                                [?MAX_CLIENT_CERT_PREFIXES]),
            menelaus_util:reply_json(Req, list_to_binary(Err), 400);
        false ->
            Prefixes = [[{binary_to_list(K), binary_to_list(V)} || {K, V} <- Triple]
                        || {struct, Triple} <- PrefixesRaw],

            {Cfg0, Errors0} = validate_client_cert_auth_state(State, Prefixes, [], []),
            {Cfg, Errors} = validate_client_cert_auth_prefixes(Prefixes, Cfg0, Errors0),

            case Errors of
                [] ->
                    case ns_ssl_services_setup:client_cert_auth() of
                        Cfg ->
                            menelaus_util:reply(Req, 200);
                        _ ->
                            ns_config:set(client_cert_auth, Cfg),
                            ns_audit:client_cert_auth(Req, Cfg),
                            menelaus_util:reply(Req, 202)
                    end;
                _ ->
                    Out = [list_to_binary(Msg) || {error, Msg} <- Errors],
                    menelaus_util:reply_json(Req, Out, 400)
            end
    end.
