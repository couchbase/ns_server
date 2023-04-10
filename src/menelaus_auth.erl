%% @author Couchbase <info@couchbase.com>
%% @copyright 2009-Present Couchbase, Inc.
%%
%% Use of this software is governed by the Business Source License included in
%% the file licenses/BSL-Couchbase.txt.  As of the Change Date specified in that
%% file, in accordance with the Business Source License, use of this software
%% will be governed by the Apache License, Version 2.0, included in the file
%% licenses/APL2.txt.
%%
%% @doc Web server for menelaus.

-module(menelaus_auth).
-author('Northscale <info@northscale.com>').

-include("ns_common.hrl").
-include("rbac.hrl").
-include("cut.hrl").

-export([has_permission/2,
         is_internal/1,
         filter_accessible_buckets/3,
         extract_auth/1,
         extract_identity_from_cert/1,
         extract_ui_auth_token/1,
         uilogin/2,
         uilogin_phase2/5,
         can_use_cert_for_auth/1,
         complete_uilogout/1,
         maybe_refresh_token/1,
         get_authn_res/1,
         get_identity/1,
         get_user_id/1,
         get_session_id/1,
         is_UI_req/1,
         verify_rest_auth/2,
         new_session_id/0,
         get_resp_headers/1]).

%% rpc from ns_couchdb node
-export([authenticate/1,
         authenticate_external/2]).

%% External API

new_session_id() ->
    base64:encode(crypto:strong_rand_bytes(16)).

filter_accessible_buckets(Fun, Buckets, Req) ->
    AuthnRes = get_authn_res(Req),
    Roles = menelaus_roles:get_compiled_roles(AuthnRes),
    lists:filter(?cut(menelaus_roles:is_allowed(Fun(_), Roles)), Buckets).

-spec get_cookies(mochiweb_request()) -> [{string(), string()}].
get_cookies(Req) ->
    case mochiweb_request:get_header_value("Cookie", Req) of
        undefined -> [];
        RawCookies ->
            RV = mochiweb_cookies:parse_cookie(RawCookies),
            RV
    end.

-spec lookup_cookie(mochiweb_request(), string()) -> string() | undefined.
lookup_cookie(Req, Cookie) ->
    proplists:get_value(Cookie, get_cookies(Req)).

-spec ui_auth_cookie_name(mochiweb_request()) -> string().
ui_auth_cookie_name(Req) ->
    %% NOTE: cookies are _not_ per-port and in general quite
    %% unexpectedly a stupid piece of mess. In order to have working
    %% dev mode clusters where different nodes are at different ports
    %% we use different cookie names for different host:port
    %% combination.
    case mochiweb_request:get_header_value("host", Req) of
        undefined ->
            "ui-auth";
        Host ->
            "ui-auth-" ++ mochiweb_util:quote_plus(Host)
    end.

-spec extract_ui_auth_token(mochiweb_request()) ->
                                    {token, auth_token() | undefined} | not_ui.
extract_ui_auth_token(Req) ->
    case mochiweb_request:get_header_value("ns-server-ui", Req) of
        "yes" ->
            Token =
                case mochiweb_request:get_header_value("ns-server-auth-token",
                                                       Req) of
                    undefined ->
                        lookup_cookie(Req, ui_auth_cookie_name(Req));
                    T ->
                        T
                end,
            {token, Token};
        _ ->
            not_ui
    end.

-spec generate_auth_cookie(mochiweb_request(), auth_token()) -> {string(), string()}.
generate_auth_cookie(Req, Token) ->
    Options = [{path, "/"}, {http_only, true}],
    SslOptions = case mochiweb_request:get(socket, Req) of
                     {ssl, _} -> [{secure, true}];
                     _ -> ""
                 end,
    mochiweb_cookies:cookie(ui_auth_cookie_name(Req), Token, Options ++ SslOptions).

-spec kill_auth_cookie(mochiweb_request()) -> {string(), string()}.
kill_auth_cookie(Req) ->
    {Name, Content} = generate_auth_cookie(Req, ""),
    {Name, Content ++ "; expires=Thu, 01 Jan 1970 00:00:00 GMT"}.

-spec complete_uilogout(mochiweb_request()) ->
                {Session :: #uisession{} | undefined, [{string(), string()}]}.
complete_uilogout(Req) ->
    case get_authn_res(Req) of
        #authn_res{type = ui, session_id = SessionId} ->
            UISession = menelaus_ui_auth:logout(SessionId),
            ns_audit:logout(Req),
            {UISession, [kill_auth_cookie(Req)]};
        _ ->
            {undefined, []}
    end.

-spec maybe_refresh_token(mochiweb_request()) -> [{string(), string()}].
maybe_refresh_token(Req) ->
    case extract_ui_auth_token(Req) of
        not_ui -> [];
        {token, undefined} -> [];
        {token, Token} ->
            case menelaus_ui_auth:maybe_refresh(Token) of
                nothing ->
                    [];
                {new_token, NewToken} ->
                    [generate_auth_cookie(Req, NewToken)]
            end
    end.

maybe_store_rejected_user(undefined, Req) ->
    Req;
maybe_store_rejected_user(User, Req) ->
    store_authn_res(#authn_res{identity = {User, rejected}}, Req).

store_authn_res(#authn_res{} = AuthnRes, Req) ->
    mochiweb_request:set_meta(authn_res, AuthnRes, Req).

append_resp_headers(Headers, Req) ->
    CurHeaders = mochiweb_request:get_meta(resp_headers, [], Req),
    mochiweb_request:set_meta(resp_headers, CurHeaders ++ Headers, Req).

get_resp_headers(Req) ->
    mochiweb_request:get_meta(resp_headers, [], Req).

-spec get_authn_res(mochiweb_request()) -> #authn_res{} | undefined.
get_authn_res(Req) ->
    mochiweb_request:get_meta(authn_res, undefined, Req).

-spec get_identity(mochiweb_request()) -> rbac_identity() | undefined.
get_identity(Req) ->
    case get_authn_res(Req) of
        undefined -> undefined;
        #authn_res{identity = Id} -> Id
    end.

-spec get_session_id(mochiweb_request()) -> binary() | undefined.
get_session_id(Req) ->
    case get_authn_res(Req) of
        undefined -> undefined;
        #authn_res{session_id = SessionId} -> SessionId
    end.

-spec get_user_id(mochiweb_request()) -> rbac_user_id() | undefined.
get_user_id(Req) ->
    case mochiweb_request:get_meta(authn_res, undefined, Req) of
        #authn_res{identity = {Name, _}} -> Name;
        undefined -> undefined
    end.

is_UI_req(Req) ->
    case get_authn_res(Req) of
        undefined -> false;
        #authn_res{type = ui} -> true;
        #authn_res{} -> false
    end.

-spec extract_auth(mochiweb_request()) -> {User :: string(), Passwd :: string()}
                                              | {scram_sha, string()}
                                              | {token, string() | undefined}
                                              | {client_cert_auth, string()}
                                              | undefined.
extract_auth(Req) ->
    case extract_ui_auth_token(Req) of
        {token, Token} ->
            {token, Token};
        not_ui ->
            Sock = mochiweb_request:get(socket, Req),
            case ns_ssl_services_setup:get_user_name_from_client_cert(Sock) of
                undefined ->
                    case mochiweb_request:get_header_value("authorization", Req) of
                        "Basic " ++ Value ->
                            parse_basic_auth_header(Value);
                        "SCRAM-" ++ Value ->
                            {scram_sha, Value};
                        undefined ->
                            undefined;
                        _ ->
                            error
                    end;
                failed ->
                    error;
                UName ->
                    {client_cert_auth, UName}
            end
    end.

get_rejected_user(Auth) ->
    case Auth of
        {client_cert_auth, User} ->
            User;
        {User, _} when is_list(User) ->
            User;
        _ ->
            undefined
    end.

parse_basic_auth_header(Value) ->
    case (catch base64:decode_to_string(Value)) of
        UserPasswordStr when is_list(UserPasswordStr) ->
            case string:chr(UserPasswordStr, $:) of
                0 ->
                    case UserPasswordStr of
                        "" ->
                            undefined;
                        _ ->
                            {UserPasswordStr, ""}
                    end;
                I ->
                    {string:substr(UserPasswordStr, 1, I - 1),
                     string:substr(UserPasswordStr, I + 1)}
            end;
        _ ->
            error
    end.

-spec has_permission(rbac_permission(), mochiweb_request()) -> boolean().
has_permission(Permission, Req) ->
    menelaus_roles:is_allowed(Permission, get_authn_res(Req)).

-spec is_internal(mochiweb_request()) -> boolean().
is_internal(Req) ->
    case get_identity(Req) of
        {"@" ++ _, admin} ->
            true;
        _ ->
            false
    end.

-spec authenticate(error | undefined |
                   {token, auth_token()} |
                   {scram_sha, string()} |
                   {client_cert_auth, string()} |
                   {rbac_user_id(), rbac_password()}) ->
          {ok, #authn_res{}, [RespHeader]} |
          {error, auth_failure | temporary_failure} |
          {unfinished, RespHeaders :: [RespHeader]}
                                        when RespHeader :: {string(), string()}.
authenticate(error) ->
    {error, auth_failure};
authenticate(undefined) ->
    {ok, #authn_res{identity = {"", anonymous}}, []};
authenticate({token, Token} = Param) ->
    case ns_node_disco:couchdb_node() == node() of
        false ->
            case menelaus_ui_auth:check(Token) of
                false ->
                    %% this is needed so UI can get /pools on unprovisioned
                    %% system with leftover cookie
                    case ns_config_auth:is_system_provisioned() of
                        false ->
                            {ok, #authn_res{identity = {"", wrong_token}}, []};
                        true ->
                            {error, auth_failure}
                    end;
                {ok, #authn_res{} = AuthnRes} ->
                    {ok, AuthnRes, []}
            end;
        true ->
            rpc:call(ns_node_disco:ns_server_node(), ?MODULE, authenticate, [Param])
    end;
authenticate({client_cert_auth, "@" ++ _ = Username}) ->
    {ok, #authn_res{identity = {Username, admin}}, []};
authenticate({client_cert_auth, Username} = Param) ->
    %% Just returning the username as the request is already authenticated based
    %% on the client certificate.
    case ns_node_disco:couchdb_node() == node() of
        false ->
            case ns_config_auth:get_user(admin) of
                Username ->
                    {ok, #authn_res{identity = {Username, admin}}, []};
                _ ->
                    Identity = {Username, local},
                    case menelaus_users:user_exists(Identity) of
                        true ->
                            {ok, #authn_res{identity = Identity}, []};
                        false ->
                            {error, auth_failure}
                    end
            end;
        true ->
            rpc:call(ns_node_disco:ns_server_node(), ?MODULE, authenticate,
                     [Param])
    end;
authenticate({scram_sha, AuthHeader}) ->
    case scram_sha:authenticate(AuthHeader) of
        {ok, Identity, RespHeaders} ->
            {ok, #authn_res{identity = Identity}, RespHeaders};
        {first_step, RespHeaders} ->
            {unfinished, RespHeaders};
        auth_failure ->
            {error, auth_failure}
    end;
authenticate({Username, Password}) ->
    case ns_config_auth:authenticate(Username, Password) of
        {ok, Id} ->
            {ok, #authn_res{identity = Id}, []};
        {error, auth_failure}->
            authenticate_external(Username, Password);
        {error, Reason} ->
            {error, Reason}
    end.

-spec authenticate_external(rbac_user_id(), rbac_password()) ->
          {error, auth_failure} | {ok, #authn_res{}}.
authenticate_external(Username, Password) ->
    case ns_node_disco:couchdb_node() == node() of
        false ->
            case is_external_auth_allowed(Username) andalso
                 (saslauthd_auth:authenticate(Username, Password) orelse
                  ldap_auth_cache:authenticate(Username, Password)) of
                true ->
                    {ok, #authn_res{identity = {Username, external}}, []};
                false ->
                    {error, auth_failure}
            end;
        true ->
            rpc:call(ns_node_disco:ns_server_node(), ?MODULE,
                     authenticate_external, [Username, Password])
    end.

is_external_auth_allowed("@" ++ _) -> false;
is_external_auth_allowed(Username) ->
    ns_config_auth:get_user(admin) /= Username.

-spec uilogin(mochiweb_request(), list()) -> mochiweb_response().
uilogin(Req, Params) ->
    CertAuth = proplists:get_value("use_cert_for_auth",
                                   mochiweb_request:parse_qs(Req)) =:= "1",
    {User, AuthnStatus} =
        case CertAuth of
            true ->
                S = mochiweb_request:get(socket, Req),
                case ns_ssl_services_setup:get_user_name_from_client_cert(S) of
                    X when X =:= undefined; X =:= failed ->
                        {invalid_client_cert, {error, auth_failure}};
                    UName ->
                        {UName, authenticate({client_cert_auth, UName})}
                end;
            false ->
                Usr = proplists:get_value("user", Params),
                Password = proplists:get_value("password", Params),
                {Usr, authenticate({Usr, Password})}
        end,

    case AuthnStatus of
        {ok, #authn_res{type = tmp, identity = Identity} = AuthnRes,
         RespHeaders} ->
            AuthnRes2 = AuthnRes#authn_res{type = ui,
                                           session_id = new_session_id(),
                                           identity = Identity},
            RandomName = base64:encode(rand:bytes(6)),
            SessionName = <<"UI - ", RandomName/binary>>,
            Req2 = append_resp_headers(RespHeaders, Req),
            uilogin_phase2(Req2, simple, SessionName, AuthnRes2,
                           ?cut(menelaus_util:reply(_1, 200, _2)));
        {error, auth_failure} ->
            ns_audit:login_failure(
              maybe_store_rejected_user(User, Req)),
            menelaus_util:reply(Req, 400);
        {error, temporary_failure} ->
            ns_audit:login_failure(
              maybe_store_rejected_user(User, Req)),
            Msg = <<"Temporary error occurred. Please try again later.">>,
            menelaus_util:reply_json(Req, Msg, 503)
    end.

uilogin_phase2(Req, UISessionType, UISessionName, #authn_res{} = AuthnRes,
               Continuation) ->
    UIPermission = {[ui], read},
    case check_permission(AuthnRes, UIPermission) of
        allowed ->
            Token = menelaus_ui_auth:start_ui_session(UISessionType,
                                                      UISessionName,
                                                      AuthnRes),
            CookieHeader = generate_auth_cookie(Req, Token),
            ns_audit:login_success(store_authn_res(AuthnRes, Req)),
            Continuation(Req, [CookieHeader]);
        AuthzRes when AuthzRes == forbidden; AuthzRes == auth_failure ->
            ns_audit:login_failure(store_authn_res(AuthnRes, Req)),
            menelaus_util:reply_json(
              Req,
              menelaus_web_rbac:forbidden_response([UIPermission]),
              403)
    end.

-spec can_use_cert_for_auth(mochiweb_request()) ->
                                   can_use | cannot_use | must_use.
can_use_cert_for_auth(Req) ->
    case mochiweb_request:get(socket, Req) of
        {ssl, SSLSock} ->
            CCAState = ns_ssl_services_setup:client_cert_auth_state(),
            case {ssl:peercert(SSLSock), CCAState} of
                {_, "mandatory"} ->
                    must_use;
                {{ok, _Cert}, "enable"} ->
                    can_use;
                _ ->
                    cannot_use
            end;
        _ ->
            cannot_use
    end.

-spec verify_rest_auth(mochiweb_request(),
                       rbac_permission() | no_check | local) ->
                              {auth_failure | forbidden | allowed
                              | temporary_failure, mochiweb_request()}.
verify_rest_auth(Req, Permission) ->
    Auth = extract_auth(Req),
    case authenticate(Auth) of
        {ok, #authn_res{identity = Identity} = AuthnRes,
         RespHeaders} ->
            Req2 = append_resp_headers(RespHeaders, Req),
            case extract_effective_identity(Identity, Req2) of
                error ->
                    Req3 = maybe_store_rejected_user(
                             get_rejected_user(Auth), Req2),
                    {auth_failure, Req3};
                EffectiveIdentity ->
                    AuthnRes2 = AuthnRes#authn_res{
                                    identity = EffectiveIdentity
                                },
                    {check_permission(AuthnRes2, Permission),
                     store_authn_res(AuthnRes2, Req2)}
            end;
        {error, auth_failure} ->
            Req2 = maybe_store_rejected_user(get_rejected_user(Auth), Req),
            {auth_failure, Req2};
        {error, temporary_failure} ->
            {temporary_failure, Req};
        {unfinished, RespHeaders} ->
            %% When mochiweb decides if it needs to close the connection
            %% it checks if body is "received" (and many other things)
            %% If body is not received it will close the connection
            %% but we don't want it to happen in this case
            %% because it is kind of "graceful" 401
            mochiweb_request:recv_body(Req),
            Req2 = append_resp_headers(RespHeaders, Req),
            {auth_failure, Req2}
    end.

%% When we say identity, we could be referring to one of the following
%% three identities.
%%
%% 1) real identity: The user that is authenticated.
%% 2) on-behalf-of identity: The user on whose behalf the action is
%%    being taken, if a valid cb-on-behalf-of Header is present.
%%    This may also be referred to as the "authorization user".
%% 3) effective identity: on-behalf-of identity if present, else the real
%%    identity.

-spec extract_effective_identity(rbac_identity(), mochiweb_request()) ->
                                                    error | rbac_identity().
extract_effective_identity({[$@ | _], admin} = Identity, Req) ->
     case extract_on_behalf_of_identity(Req) of
         error ->
             error;
         undefined ->
             Identity;
         {ok, RealIdentity} ->
            RealIdentity
     end;
extract_effective_identity(Identity, _Req) ->
    Identity.

-spec extract_on_behalf_of_identity(mochiweb_request()) ->
                                                error | undefined
                                                | {ok, rbac_identity()}.
extract_on_behalf_of_identity(Req) ->
    case mochiweb_request:get_header_value("cb-on-behalf-of", Req) of
        Header when is_list(Header) ->
            case parse_on_behalf_of_header(Header) of
                {User, Domain} ->
                    {ok, {User, list_to_existing_atom(Domain)}};
                _ ->
                    ?log_debug("Invalid format of cb-on-behalf-of: ~s",
                               [ns_config_log:tag_user_name(Header)]),
                    error
            end;
        undefined ->
            undefined
    end.

parse_on_behalf_of_header(Header) ->
    case (catch base64:decode_to_string(Header)) of
        UserDomainStr when is_list(UserDomainStr) ->
            case string:chr(UserDomainStr, $:) of
                0 ->
                    error;
                I ->
                    {string:substr(UserDomainStr, 1, I - 1),
                     string:substr(UserDomainStr, I + 1)}
            end;
        _ ->
            error
    end.

-spec extract_identity_from_cert(binary()) ->
          tuple() | auth_failure | temporary_failure.
extract_identity_from_cert(CertDer) ->
    case ns_ssl_services_setup:get_user_name_from_client_cert(CertDer) of
        undefined ->
            auth_failure;
        failed ->
            auth_failure;
        UName ->
            case authenticate({client_cert_auth, UName}) of
                {ok, #authn_res{identity = Identity}, _} ->
                    Identity;
                {error, Type} ->
                    Type
            end
    end.

-spec check_permission(#authn_res{}, rbac_permission() | no_check | local) ->
                              auth_failure | forbidden | allowed.
check_permission(_AuthnRes, no_check) ->
    allowed;
check_permission(#authn_res{identity = {"@" ++ _, local_token}}, local) ->
    allowed;
check_permission(_, local) ->
    forbidden;
check_permission(#authn_res{identity = Identity},
                 no_check_disallow_anonymous) ->
    case Identity of
        {"", anonymous} ->
            auth_failure;
        _ ->
            allowed
    end;
check_permission(#authn_res{identity = Identity} = AuthnRes, Permission) ->
    Roles = menelaus_roles:get_compiled_roles(AuthnRes),
    case Roles of
        [] ->
            %% this can happen in case of expired token, or if LDAP
            %% server authenticates the user that has no roles assigned
            auth_failure;
        _ ->
            case menelaus_roles:is_allowed(Permission, Roles) of
                true ->
                    allowed;
                false ->
                    ?log_debug("Access denied.~nIdentity: ~p~nRoles: ~p~n"
                               "Permission: ~p~n",
                               [ns_config_log:tag_user_data(Identity),
                               Roles, Permission]),
                    case Identity of
                        {"", anonymous} ->
                            %% we do allow some api's for anonymous
                            %% under some circumstances, but we want to return 401 in case
                            %% if autorization for requests with no auth fails
                            auth_failure;
                        _ ->
                            forbidden
                    end
            end
    end.
