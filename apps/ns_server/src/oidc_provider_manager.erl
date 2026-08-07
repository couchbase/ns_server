%% @author Couchbase <info@couchbase.com>
%% @copyright 2025-Present Couchbase, Inc.
%%
%% Use of this software is governed by the Business Source License included in
%% the file licenses/BSL-Couchbase.txt.  As of the Change Date specified in that
%% file, in accordance with the Business Source License, use of this software
%% will be governed by the Apache License, Version 2.0, included in the file
%% licenses/APL2.txt.
%%
%% @doc Manages OIDC provider configuration workers (oidcc) per issuer with
%% discovery URI.

-module(oidc_provider_manager).

-behavior(gen_server).

-include("ns_common.hrl").

-ifdef(TEST).
-include_lib("eunit/include/eunit.hrl").
-endif.

-export([start_link/0,
         restart_workers/0,
         connect_options/2,
         get_httpc_profile/2]).

-export([init/1, handle_call/3, handle_cast/2, handle_info/2,
         terminate/2, code_change/3]).

%% Identifies the connect options of an issuer.
-type profile_key() :: {URL :: string(),
                        AddressFamily :: undefined | inet | inet6,
                        VerifyPeer :: boolean(),
                        CACerts :: [binary()],
                        SNI :: string(),
                        TrustedCAs :: chronicle:revision() | not_found |
                                      undefined}.

-record(state, {
                name_to_pid = #{} :: map(),
                %% IssuerName => {ProfileName, ConnectOptionsKey}. Each issuer
                %% gets its own httpc profile so that TLS settings are never
                %% inherited from a connection opened with different ones.
                profiles = #{} :: #{string() => {atom(), profile_key()}},
                retry_timer_ref :: undefined | reference()
               }).

-define(RETRY_INTERVAL_MS, 30000). %% 30 seconds

start_link() ->
    gen_server:start_link({local, ?MODULE}, ?MODULE, [], []).

restart_workers() ->
    gen_server:cast(?MODULE, restart).

%% Returns the httpc profile to be used for all requests to this issuer.
%% httpc picks a pooled connection by {host, port, scheme} alone and ignores
%% the TLS options of the request being sent, so a connection opened with
%% relaxed options would be reused for one that asks for peer verification.
%% Requests are therefore isolated by issuer, and the profile is restarted
%% whenever the connect options of the issuer change.
-spec get_httpc_profile(IssuerName :: string(), Key :: profile_key()) ->
          {ok, atom()} | {error, term()}.
get_httpc_profile(IssuerName, Key) ->
    gen_server:call(?MODULE, {get_httpc_profile, IssuerName, Key}).

%% Returns the ssl options for URL along with a key that identifies them. The
%% key is derived from the settings rather than from the options themselves
%% because the latter hold a closure, which is not comparable across modules.
-spec connect_options(URL :: string(), OidcSettings :: map()) ->
          {list(), profile_key()}.
connect_options(URL, OidcSettings) ->
    AddressFamily = maps:get(address_family, OidcSettings, undefined),
    VerifyPeer = maps:get(tls_verify_peer, OidcSettings, true),
    {_, Certs} = maps:get(tls_ca, OidcSettings, {<<>>, []}),
    SNI = maps:get(tls_sni, OidcSettings, ""),
    Opts = misc:tls_connect_options(URL, AddressFamily, VerifyPeer, Certs, SNI,
                                    []),
    {Opts, {URL, AddressFamily, VerifyPeer, Certs, SNI,
            trusted_CAs_marker(URL, VerifyPeer)}}.

%% tls_connect_options/6 appends the trusted CAs of the node to the CA list, so
%% the options change when those do (when peer verification is in use). The
%% chronicle revision is used rather than the certs themselves. Only an https
%% URL with peer verification stores the rev, otherwise it stays undefined - so
%% that unaffected issuers don't recreate their connections unnecessarily.
trusted_CAs_marker("https://" ++ _, true) ->
    case chronicle_kv:get(kv, ca_certificates) of
        {ok, {_Certs, Rev}} -> Rev;
        {error, not_found} -> not_found
    end;
trusted_CAs_marker(_URL, _VerifyPeer) ->
    undefined.

init([]) ->
    process_flag(trap_exit, true),
    Self = self(),
    %% The workers hold the ssl options they were started with, so a change in
    %% the trusted CAs of the node has to restart them as well as the profiles.
    chronicle_compat_events:subscribe(
      fun (jwt_settings) -> Self ! restart;
          (ca_certificates) -> Self ! restart;
          (_) -> ok
      end),

    {ok, start_all_workers(#state{})}.

handle_call({get_httpc_profile, IssuerName, Key}, _From, State0) ->
    case ensure_profile(IssuerName, Key, State0) of
        {ok, Profile, State} ->
            {reply, {ok, Profile}, State};
        {error, Reason, State} ->
            {reply, {error, Reason}, State}
    end;
handle_call(_Req, _From, State) ->
    {reply, ok, State}.

restart_body(State) ->
    cancel_retry_timer(State),
    stop_all_workers(State),
    case menelaus_web_jwt:is_enabled() of
        true ->
            {noreply, start_all_workers(#state{})};
        false ->
            {noreply, #state{}}
    end.

handle_cast(restart, State0) ->
    restart_body(State0);
handle_cast(_Msg, State) ->
    {noreply, State}.

handle_info(restart, State0) ->
    restart_body(State0);
handle_info({'EXIT', Pid, Reason},
            #state{name_to_pid = Map0} = State0) ->
    case maps:fold(fun(K, V, Acc) ->
                           case V =:= Pid of
                               true -> K;
                               false -> Acc
                           end
                   end, undefined, Map0) of
        undefined ->
            ?log_warning("OIDC provider worker ~p exited (not in map): ~p",
                         [Pid, Reason]),
            {noreply, State0};
        IssuerName ->
            ?log_warning("OIDC provider worker for ~p (~p) exited: ~p",
                         [IssuerName, Pid, Reason]),
            Map = maps:remove(IssuerName, Map0),
            {noreply, maybe_schedule_retry(State0#state{name_to_pid = Map})}
    end;
handle_info(retry_workers, #state{} = State0) ->
    %% Cancel any scheduled retry and re-run the worker start routine which
    %% will preserve already-started workers.
    State1 = cancel_retry_timer(State0),
    State2 = start_all_workers(State1),
    {noreply, State2};
handle_info(_Info, State) ->
    {noreply, State}.

terminate(_Reason, State) ->
    cancel_retry_timer(State),
    stop_all_workers(State),
    ok.

code_change(_OldVsn, State, _Extra) ->
    {ok, State}.

%% Internal
start_all_workers(#state{name_to_pid = Map0} = State0) ->
    Issuers = get_oidc_issuers_with_discovery(),
    %% Only attempt to start issuers that are not already present in our map.
    MissingIssuers = [I || #{name := N} = I <- Issuers,
                           not maps:is_key(N, Map0)],
    State1 = lists:foldl(fun start_worker_fold/2, State0, MissingIssuers),
    %% If any of the missing issuers failed to start (i.e. the map size
    %% didn't increase by the number of missing issuers), schedule a retry.
    ExpectedSize = maps:size(Map0) + length(MissingIssuers),
    case maps:size(State1#state.name_to_pid) < ExpectedSize of
        true -> maybe_schedule_retry(State1);
        false -> State1
    end.

stop_all_workers(#state{name_to_pid = Map, profiles = Profiles}) ->
    misc:terminate_and_wait([Pid || {_, Pid} <- maps:to_list(Map)], shutdown),
    %% Dropping the profiles closes the pooled connections, so none of them
    %% can outlive the settings they were opened with.
    [stop_profile(Profile) || {Profile, _Key} <- maps:values(Profiles)],
    ok.

maybe_schedule_retry(#state{retry_timer_ref = undefined} = State) ->
    Ref = erlang:send_after(?RETRY_INTERVAL_MS, self(), retry_workers),
    ?log_debug("Scheduled OIDC provider worker retry in ~p ms",
               [?RETRY_INTERVAL_MS]),
    State#state{retry_timer_ref = Ref};
maybe_schedule_retry(State) ->
    State.

cancel_retry_timer(#state{retry_timer_ref = undefined} = State) ->
    State;
cancel_retry_timer(#state{retry_timer_ref = Ref} = State) ->
    erlang:cancel_timer(Ref),
    misc:flush(retry_workers),
    State.

start_worker_fold(#{name := IssuerName, profile_key := Key} = IssuerMap,
                  #state{name_to_pid = Map} = State0) ->
    WorkerName = {local, list_to_atom(IssuerName)},
    case ensure_profile(IssuerName, Key, State0) of
        {ok, Profile, State} ->
            case start_provider_worker(WorkerName, IssuerMap, Profile) of
                {ok, Pid} ->
                    State#state{name_to_pid = Map#{IssuerName => Pid}};
                {error, Reason} ->
                    ?log_warning("Failed to start OIDC provider worker for "
                                 "~p: ~p", [IssuerName, Reason]),
                    State
            end;
        {error, Reason, State} ->
            ?log_warning("Failed to start OIDC httpc profile for ~p: ~p",
                         [IssuerName, Reason]),
            State
    end.

-spec ensure_profile(IssuerName :: string(), Key :: profile_key(),
                     State :: #state{}) ->
          {ok, atom(), #state{}} | {error, term(), #state{}}.
ensure_profile(IssuerName, Key, #state{profiles = Profiles} = State) ->
    Profile = profile_name(IssuerName),
    case maps:find(IssuerName, Profiles) of
        {ok, {Profile, Key}} ->
            {ok, Profile, State};
        Other ->
            %% Either there is no profile yet or the connect options changed,
            %% in which case the pooled connections must not be reused.
            case Other of
                {ok, {Profile, _StaleKey}} -> stop_profile(Profile);
                error -> ok
            end,
            case start_profile(Profile) of
                ok ->
                    {ok, Profile,
                     State#state{profiles =
                                     Profiles#{IssuerName => {Profile, Key}}}};
                {error, Reason} ->
                    {error, Reason,
                     State#state{profiles = maps:remove(IssuerName, Profiles)}}
            end
    end.

profile_name(IssuerName) ->
    list_to_atom("oidc_httpc-" ++ IssuerName).

start_profile(Profile) ->
    case inets:start(httpc, [{profile, Profile}]) of
        {ok, _Pid} -> ok;
        {error, {already_started, _}} ->
            %% Left over from a previous incarnation of this process. Restart
            %% it so that it starts with no pooled connections.
            stop_profile(Profile),
            case inets:start(httpc, [{profile, Profile}]) of
                {ok, _} -> ok;
                {error, _} = Error -> Error
            end;
        {error, _} = Error -> Error
    end.

stop_profile(Profile) ->
    case inets:stop(httpc, Profile) of
        ok -> ok;
        Error ->
            ?log_warning("Failed to stop OIDC httpc profile ~p: ~p",
                         [Profile, Error]),
            ok
    end.

-spec start_provider_worker(WorkerName :: {local, atom()},
                            IssuerMap :: map(),
                            Profile :: atom()) ->
          {ok, pid()} | {error, term()}.
start_provider_worker(WorkerName, IssuerMap, Profile) ->
    DiscoveryUri = maps:get(discovery_uri, IssuerMap),
    case derive_issuer_from_discovery(DiscoveryUri) of
        undefined ->
            {error, invalid_discovery_uri};
        IssuerUri when is_binary(IssuerUri) ->
            %% Allow unsafe HTTP only for localhost development
            ParsedIssuer = uri_string:parse(IssuerUri),
            Scheme = maps:get(scheme, ParsedIssuer, <<>>),
            Host = maps:get(host, ParsedIssuer, <<>>),
            AllowUnsafe = (Scheme =:= <<"http">>) andalso
                lists:member(Host, [<<"localhost">>, <<"127.0.0.1">>]),
            Quirks0 =
                case AllowUnsafe of
                    true -> #{allow_unsafe_http => true};
                    false -> #{}
                end,
            DisablePAR = maps:get(disable_par, IssuerMap, false),
            Quirks =
                case DisablePAR of
                    true ->
                        %% This is to bypass Keycloak Bug #43034.
                        %% https://github.com/keycloak/keycloak/issues/43034
                        DocOverrides =
                            #{
                              %% Force-disable PAR regardless of discovery doc
                              <<"require_pushed_authorization_requests">> =>
                                  false,
                              <<"pushed_authorization_request_endpoint">> =>
                                  undefined
                             },
                        maps:put(document_overrides, DocOverrides, Quirks0);
                    false ->
                        Quirks0
                end,
            HttpTimeoutMs = maps:get(http_timeout_ms, IssuerMap),
            SslOpts = maps:get(ssl_opts, IssuerMap, []),
            RequestOpts = #{timeout => HttpTimeoutMs, ssl => SslOpts,
                            httpc_profile => Profile},
            ProviderOpts = #{quirks => Quirks, request_opts => RequestOpts},
            try oidcc_provider_configuration_worker:start_link(
                  #{issuer => IssuerUri,
                    name => WorkerName,
                    provider_configuration_opts => ProviderOpts}) of
                {ok, Pid} -> {ok, Pid};
                {error, Reason} -> {error, Reason}
            catch T:E ->
                    {error, {T, E}}
            end
    end.
-spec derive_issuer_from_discovery(DiscoveryUri :: list()) -> binary() |
          undefined.
derive_issuer_from_discovery(DiscoveryUri) when is_list(DiscoveryUri) ->
    DiscoveryUriBin = list_to_binary(DiscoveryUri),
    case uri_string:parse(DiscoveryUriBin) of
        {error, Reason, Info} ->
            ?log_warning("Failed to parse discovery URI ~p: ~p ~p",
                         [DiscoveryUri, Reason, Info]),
            undefined;
        URI ->
            Path = maps:get(path, URI, <<>>),
            case binary:split(Path, <<"/.well-known/openid-configuration">>) of
                [Prefix, <<>>] ->
                    NewURI = URI#{path => Prefix},
                    uri_string:recompose(NewURI);
                _ ->
                    ?log_warning("Discovery URI ~p does not have the expected "
                                 "path", [DiscoveryUri]),
                    undefined
            end
    end.

get_oidc_issuers_with_discovery() ->
    case chronicle_kv:get(kv, jwt_settings) of
        {ok, {Settings, _Rev}} ->
            IssuersMap = maps:get(issuers, Settings, #{}),
            lists:foldl(
              fun({Name, Props}, Acc) ->
                      case maps:get(oidc_settings, Props, undefined) of
                          undefined -> Acc;
                          OIDC ->
                              case build_discovery_issuer(Name, OIDC) of
                                  ignore -> Acc;
                                  Map -> [Map | Acc]
                              end
                      end
              end, [], maps:to_list(IssuersMap));
        _ -> []
    end.

-spec build_discovery_issuer(Name :: string(), OIDC :: map()) ->
          map() | ignore.
build_discovery_issuer(Name, OIDC) ->
    case maps:get(oidc_discovery_uri, OIDC, undefined) of
        undefined ->
            ignore;
        Disc ->
            HttpTimeoutMs = maps:get(http_timeout_ms, OIDC),
            {SslOpts, Key} = connect_options(Disc, OIDC),
            DisablePAR =
                maps:get(disable_pushed_authorization_requests, OIDC, false),
            #{name => Name,
              discovery_uri => Disc,
              http_timeout_ms => HttpTimeoutMs,
              ssl_opts => SslOpts,
              profile_key => Key,
              disable_par => DisablePAR}
    end.

-ifdef(TEST).

-define(HTTP_URL, "http://localhost:8080/.well-known/openid-configuration").
-define(HTTPS_URL, "https://localhost:8443/.well-known/openid-configuration").

%% The key tracks every setting, including ones the current scheme ignores, so
%% that it can never miss a change in the options. http shows that plainly: the
%% TLS settings are inert there, yet each one still gives a different key.
connect_options_key_tracks_settings_test() ->
    Settings = #{tls_verify_peer => false},
    {Opts, Key} = connect_options(?HTTP_URL, Settings),
    ?assertEqual({Opts, Key}, connect_options(?HTTP_URL, Settings)),

    SameOpts = [Settings#{tls_verify_peer => true},
                Settings#{tls_ca => {<<"ca">>, [<<"cert">>]}},
                Settings#{tls_sni => "idp.example.com"}],
    lists:foreach(
      fun(S) ->
              {VariedOpts, VariedKey} = connect_options(?HTTP_URL, S),
              ?assertEqual(Opts, VariedOpts),
              ?assertNotEqual(Key, VariedKey)
      end, SameOpts),

    %% The address family is the one setting that reaches the options of an
    %% http URL, so here they differ as well.
    {InetOpts, InetKey} = connect_options(?HTTP_URL,
                                          Settings#{address_family => inet6}),
    ?assertNotEqual(Opts, InetOpts),
    ?assertNotEqual(Key, InetKey),

    ?assertNotEqual(Key, element(2, connect_options("http://other:8080/",
                                                    Settings))).

%% Over https with peer verification the node's trusted CAs are part of the
%% options, so the key has to follow them. It carries the chronicle revision
%% rather than the certificates, and reads it only in this one case.
connect_options_key_over_https_test_() ->
    {setup,
     fun() ->
             meck:new(ns_server_cert, [passthrough]),
             meck:expect(ns_server_cert, trusted_CAs,
                         fun(der) -> [<<"node">>] end),
             meck:new(chronicle_kv, [passthrough]),
             set_ca_revision({'ca-rev', 1})
     end,
     fun(_) ->
             meck:unload(chronicle_kv),
             meck:unload(ns_server_cert)
     end,
     [{"a CA change gives a new key when verification is on",
       fun() ->
               Settings = #{tls_verify_peer => true},
               {_, Key} = connect_options(?HTTPS_URL, Settings),
               ?assertEqual(Key, element(2, connect_options(?HTTPS_URL,
                                                            Settings))),
               set_ca_revision({'ca-rev', 2}),
               ?assertNotEqual(Key, element(2, connect_options(?HTTPS_URL,
                                                               Settings)))
       end},

      {"CAs that cannot be read are still distinct from any revision",
       fun() ->
               Settings = #{tls_verify_peer => true},
               set_ca_revision({'ca-rev', 3}),
               {_, Key} = connect_options(?HTTPS_URL, Settings),
               meck:expect(chronicle_kv, get,
                           fun(kv, ca_certificates) -> {error, not_found} end),
               {_, NotFoundKey} = connect_options(?HTTPS_URL, Settings),
               ?assertNotEqual(Key, NotFoundKey),
               ?assertEqual(NotFoundKey, element(2,
                                                 connect_options(?HTTPS_URL,
                                                                 Settings)))
       end},

      {"without verification a CA change keeps the connections",
       fun() ->
               Settings = #{tls_verify_peer => false},
               set_ca_revision({'ca-rev', 4}),
               {Opts, Key} = connect_options(?HTTPS_URL, Settings),
               meck:reset(chronicle_kv),
               set_ca_revision({'ca-rev', 5}),
               ?assertEqual({Opts, Key}, connect_options(?HTTPS_URL, Settings)),
               ?assertEqual(0, meck:num_calls(chronicle_kv, get,
                                              [kv, ca_certificates]))
       end}]}.

set_ca_revision(Rev) ->
    meck:expect(chronicle_kv, get,
                fun(kv, ca_certificates) -> {ok, {[], Rev}} end).

%% The trusted CAs of the node take part in the options only over https with
%% peer verification, so the marker stays undefined in every other case and a
%% CA change does not restart profiles it cannot affect.
trusted_CAs_marker_test() ->
    ?assertEqual(undefined, trusted_CAs_marker("http://localhost:8080/", true)),
    ?assertEqual(undefined, trusted_CAs_marker("http://localhost:8080/",
                                               false)),
    ?assertEqual(undefined, trusted_CAs_marker("https://localhost:8443/",
                                               false)).

%% A change in connect options must not leave the issuer with a profile that
%% still holds connections established with the previous ones.
profile_lifecycle_test() ->
    {ok, _} = application:ensure_all_started(inets),
    IssuerName = "test-oidc-issuer",
    Settings = #{tls_verify_peer => false},
    {_, Key1} = connect_options("http://localhost:8080/", Settings),
    {_, Key2} = connect_options("http://localhost:8081/", Settings),
    {ok, Profile, State1} = ensure_profile(IssuerName, Key1, #state{}),
    Pid1 = whereis(httpc:profile_name(Profile)),
    ?assert(is_pid(Pid1)),

    %% Unchanged options keep the same profile.
    ?assertEqual({ok, Profile, State1},
                 ensure_profile(IssuerName, Key1, State1)),
    ?assertEqual(Pid1, whereis(httpc:profile_name(Profile))),

    %% Changed options restart it.
    {ok, Profile, State2} = ensure_profile(IssuerName, Key2, State1),
    Pid2 = whereis(httpc:profile_name(Profile)),
    ?assert(is_pid(Pid2)),
    ?assertNotEqual(Pid1, Pid2),

    stop_all_workers(State2),
    ?assertEqual(undefined, whereis(httpc:profile_name(Profile))).

-endif.
