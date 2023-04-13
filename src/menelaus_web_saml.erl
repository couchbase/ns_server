%% @author Couchbase <info@couchbase.com>
%% @copyright 2022-Present Couchbase, Inc.
%%
%% Use of this software is governed by the Business Source License included in
%% the file licenses/BSL-Couchbase.txt.  As of the Change Date specified in that
%% file, in accordance with the Business Source License, use of this software
%% will be governed by the Apache License, Version 2.0, included in the file
%% licenses/APL2.txt.
%%
%% @doc Support for SSO

-module(menelaus_web_saml).

-export([handle_auth/1,
         handle_deauth/1,
         handle_saml_metadata/1,
         handle_get_saml_consume/1,
         handle_post_saml_consume/1,
         handle_get_saml_logout/1,
         handle_post_saml_logout/1]).

-include("ns_common.hrl").
-include("rbac.hrl").
-include("cut.hrl").
-include_lib("esaml/include/esaml.hrl").

-define(DEFAULT_NAMEID_FORMAT,
        "urn:oasis:names:tc:SAML:2.0:nameid-format:persistent").

%%%===================================================================
%%% API
%%%===================================================================

handle_auth(Req) ->
    SSOOpts = extract_saml_settings_if_enabled(),
    ?log_debug("Starting saml authentication "),
    IDPMetadata = try_get_idp_metadata(SSOOpts),
    SPMetadata = build_sp_metadata(SSOOpts, Req),
    Binding = proplists:get_value(authn_binding, SSOOpts, post),
    RelayState = <<"">>,
    %% Using "persistent" by default because this seems to be the only option
    %% that single logout works with
    NameIDFormat = proplists:get_value(authn_nameID_Format, SSOOpts,
                                       ?DEFAULT_NAMEID_FORMAT),
    SignedXml = esaml_sp:generate_authn_request(_, SPMetadata, NameIDFormat),
    case Binding of
        redirect ->
            IDPURL = IDPMetadata#esaml_idp_metadata.login_redirect_location,
            reply_via_redirect(IDPURL, SignedXml(IDPURL), RelayState, [], Req);
        post ->
            IDPURL = IDPMetadata#esaml_idp_metadata.login_post_location,
            reply_via_post(IDPURL, SignedXml(IDPURL), RelayState, [], Req)
    end.

handle_deauth(Req) ->
    SSOOpts = extract_saml_settings_if_enabled(),
    ?log_debug("Starting saml single logout"),
    case proplists:get_value(single_logout, SSOOpts, true) of
        true -> ok;
        false ->
            ?log_debug("Single logout is turned off"),
            menelaus_util:web_exception(404, "not found")
    end,

    {Session, Headers} = menelaus_auth:complete_uilogout(Req),

    case Session of
        #uisession{type = saml, session_name = NameID} ->
            handle_single_logout(SSOOpts, NameID, Headers, Req);
        #uisession{type = simple} ->
            ?log_debug("User is not a saml user, ignoring single logout"),
            menelaus_util:reply_text(Req, <<"Redirecting...">>, 302,
                                     [{"Location", "/"} | Headers]);
        undefined ->
            ?log_debug("User not authenticated"),
            menelaus_util:reply_text(Req, <<"Redirecting...">>, 302,
                                     [{"Location", "/"} | Headers])
    end.

handle_single_logout(SSOOpts, NameID, ExtraHeaders, Req) ->
    IDPMetadata = try_get_idp_metadata(SSOOpts),
    SPMetadata = build_sp_metadata(SSOOpts, Req),
    NameIDFormat = proplists:get_value(authn_nameID_format, SSOOpts,
                                       ?DEFAULT_NAMEID_FORMAT),
    Subject = #esaml_subject{name = binary_to_list(NameID),
                             name_format = NameIDFormat},
    SignedXml = esaml_sp:generate_logout_request(_, "", Subject, SPMetadata),
    case proplists:get_value(logout_resp_binding, SSOOpts, post) of
        redirect ->
            URL = IDPMetadata#esaml_idp_metadata.logout_redirect_location,
            reply_via_redirect(URL, SignedXml(URL), <<>>, ExtraHeaders, Req);
        post ->
            URL = IDPMetadata#esaml_idp_metadata.logout_post_location,
            reply_via_post(URL, SignedXml(URL), <<>>, ExtraHeaders, Req)
    end.

handle_saml_metadata(Req) ->
    SSOOpts = extract_saml_settings_if_enabled(),
    SPMetadata = build_sp_metadata(SSOOpts, Req),
    SignedXml = esaml_sp:generate_metadata(SPMetadata),
    Metadata = xmerl:export([SignedXml], xmerl_xml),
    menelaus_util:reply_text(Req, Metadata, 200,
                             [{"Content-Type", "text/xml"}]).

handle_get_saml_consume(Req) ->
    handle_saml_consume(Req, mochiweb_request:parse_qs(Req)).

handle_post_saml_consume(Req) ->
    handle_saml_consume(Req, mochiweb_request:parse_post(Req)).

handle_saml_consume(Req, UnvalidatedParams) ->
    SSOOpts = extract_saml_settings_if_enabled(),
    ?log_debug("Starting saml consume"),
    %% Making sure metadata is up to date. By doing that we also update
    %% certificates that will be used for assertion verification
    _IDPMetadata = try_get_idp_metadata(SSOOpts),
    SPMetadata = build_sp_metadata(SSOOpts, Req),
    validator:handle(
      fun (Params) ->
          Assertion = proplists:get_value('SAMLResponse', Params),
          ?log_debug("Decoded assertion: ~p", [Assertion]),
          Subject = Assertion#esaml_assertion.subject,
          NameID = Subject#esaml_subject.name,
          Username =
              case proplists:get_value(username, SSOOpts, 'NameID') of
                  'NameID' ->
                      case Subject#esaml_subject.name_format of
                          "urn:oasis:names:tc:SAML:2.0:"
                          "nameid-format:transient" ->
                              ?log_warning(
                                "Using transient name as an identity: ~p",
                                [ns_config_log:tag_user_name(NameID)]);
                          _ ->
                              ok
                      end,
                      NameID;
                  'Attribute' ->
                      AttrName = proplists:get_value(username_attr_name,
                                                     SSOOpts,
                                                     "mail"),
                      AttrNameMapped = esaml:common_attrib_map(AttrName),
                      Attrs = Assertion#esaml_assertion.attributes,
                      proplists:get_value(AttrNameMapped, Attrs)
              end,
          case is_list(Username) andalso length(Username) > 0 of
              true when NameID =/= undefined, length(NameID) > 0 ->
                  ?log_debug("Successful saml login: ~s",
                             [ns_config_log:tag_user_name(Username)]),
                  AuthnRes =
                      #authn_res{type = ui,
                                 session_id = menelaus_auth:new_session_id(),
                                 identity = {Username, external}},
                  SessionName = iolist_to_binary(NameID),
                  menelaus_auth:uilogin_phase2(
                    Req,
                    saml,
                    SessionName,
                    AuthnRes,
                    ?cut(menelaus_util:reply_text(_1, <<"Redirecting...">>, 302,
                                                  [{"Location", "/"} | _2])));
              true ->
                  ?log_debug("NameID is not defined: ~p", [NameID]),
                  Msg = "Missing NameID",
                  menelaus_util:reply_text(Req, iolist_to_binary(Msg), 403);
              false ->
                  ?log_debug("Could not extract identity from assertion"),
                  Msg = "Unable to extract username from assertion",
                  menelaus_util:reply_text(Req, iolist_to_binary(Msg), 403)
          end
      end, Req, UnvalidatedParams,
      [validator:string('SAMLEncoding', _),
       validator:default('SAMLEncoding', "", _),
       validate_authn_response('SAMLResponse', 'SAMLEncoding', SPMetadata, _),
       validator:required('SAMLResponse', _),
       validator:string('RelayState', _)]).

handle_get_saml_logout(Req) ->
    handle_saml_logout(Req, mochiweb_request:parse_qs(Req)).

handle_post_saml_logout(Req) ->
    handle_saml_logout(Req, mochiweb_request:parse_post(Req)).

handle_saml_logout(Req, UnvalidatedParams) ->
    SSOOpts = extract_saml_settings_if_enabled(),
    ?log_debug("Starting saml logout"),
    IDPMetadata = try_get_idp_metadata(SSOOpts),
    SPMetadata = build_sp_metadata(SSOOpts, Req),
    validator:handle(
      fun (Params) ->
          LogoutReq = proplists:get_value('SAMLRequest', Params),
          LogoutResp = proplists:get_value('SAMLResponse', Params),
          case {LogoutReq, LogoutResp} of
              {undefined, undefined} ->
                  ?log_debug("Empty saml message"),
                  menelaus_util:reply_text(Req, "Missing SAML message", 400);
              {#esaml_logoutreq{name = NameID}, _} ->
                  SessionName = iolist_to_binary(NameID),
                  menelaus_ui_auth:logout_by_session_name(saml,
                                                          SessionName),
                  SignedXml = esaml_sp:generate_logout_response(_, success,
                                                                SPMetadata),
                  BindingToUse = proplists:get_value(logout_resp_binding,
                                                     SSOOpts, post),
                  case BindingToUse of
                      redirect ->
                          URL = IDPMetadata#esaml_idp_metadata.logout_redirect_location,
                          reply_via_redirect(URL, SignedXml(URL), <<>>, [],
                                             Req);
                      post ->
                          URL = IDPMetadata#esaml_idp_metadata.logout_post_location,
                          reply_via_post(URL, SignedXml(URL), <<>>, [],
                                         Req)
                  end;
              {_, #esaml_logoutresp{}} ->
                  ?log_debug("Successful logout response"),
                  menelaus_util:reply(Req, 200)
          end
      end, Req, UnvalidatedParams,
      [validator:string('SAMLEncoding', _),
       validator:default('SAMLEncoding', "", _),
       validate_logout_response('SAMLResponse', 'SAMLEncoding', SPMetadata, _),
       validate_logout_request('SAMLRequest', 'SAMLEncoding', SPMetadata, _)]).

%%%===================================================================
%%% Internal functions
%%%===================================================================

extract_saml_settings() ->
    ns_config:read_key_fast(sso_options, []).

extract_saml_settings_if_enabled() ->
    Opts = extract_saml_settings(),
    assert_saml_enabled(Opts),
    Opts.

assert_saml_enabled(Opts) ->
    %% Pretend that we don't have this endpoint when saml is disabled
    case proplists:get_value(enabled, Opts) of
        true -> ok;
        false -> menelaus_util:web_exception(404, "not found")
    end.

reply_via_redirect("", _, _, _, _) ->
    menelaus_util:web_exception(500,
                                <<"IDP doesn't support Redirect binding">>);
reply_via_redirect(IDPURL, SignedXml, RelayState, ExtraHeaders, Req)
                                     when is_list(IDPURL), length(IDPURL) > 0 ->
    Location = esaml_binding:encode_http_redirect(
                 IDPURL,
                 SignedXml,
                 _Username = undefined,
                 RelayState),
    LocationStr = binary_to_list(Location),
    ?log_debug("Redirecting user to ~s using HTTP code 302, full url: ~s",
               [IDPURL, LocationStr]),
    menelaus_util:reply_text(Req, <<"Redirecting...">>, 302,
                             [{allow_cache, false},
                              {"Location", LocationStr} | ExtraHeaders]).

reply_via_post("", _, _, _, _) ->
    menelaus_util:web_exception(500, <<"IDP doesn't support POST binding">>);
reply_via_post(IDPURL, SignedXml, RelayState, ExtraHeaders, Req)
                                     when is_list(IDPURL), length(IDPURL) > 0 ->
    HTMLBin = esaml_binding:encode_http_post(IDPURL, SignedXml, RelayState),
    ?log_debug("Redirecting user to ~s using POST:~n~s", [IDPURL, HTMLBin]),
    menelaus_util:reply(Req, HTMLBin, 200,
                        [{allow_cache, false},
                         {"Content-Type", "text/html"} | ExtraHeaders]).

build_sp_metadata(Opts, Req) ->
    DefaultScheme = case cluster_compat_mode:is_enterprise() of
                        true -> https;
                        false -> http
                    end,
    BaseURL = build_base_url(
                proplists:get_value(base_url, Opts, alternate),
                proplists:get_value(custom_base_url, Opts),
                proplists:get_value(scheme, Opts, DefaultScheme),
                Req) ++ "/saml/",

    OrgName = proplists:get_value(org_name, Opts, ""),
    OrgDispName = proplists:get_value(org_display_name, Opts, ""),
    OrgUrl = proplists:get_value(org_url, Opts, ""),

    ContactName = proplists:get_value(contact_name, Opts, ""),
    ContactEmail = proplists:get_value(contact_email, Opts, ""),

    IdpSignsAssertions = proplists:get_value(idp_signs_assertions, Opts, true),
    IdpSignsEnvelopes = proplists:get_value(idp_signs_envelopes, Opts, true),
    Recipient = case proplists:get_value(check_recipient, Opts, consumeURL) of
                    any -> any;
                    consumeURL -> undefined;
                    custom -> proplists:get_value(recipient_value, Opts, "")
                end,

    SP = #esaml_sp{
           idp_signs_assertions = IdpSignsAssertions,
           idp_signs_envelopes = IdpSignsEnvelopes,
           consume_uri = BaseURL ++ "/"?SAML_CONSUME_ENDPOINT_PATH,
           metadata_uri = BaseURL ++ "/"?SAML_METADATA_ENDPOINT_PATH,
           logout_uri = BaseURL ++ "/"?SAML_LOGOUT_ENDPOINT_PATH,
           assertion_recipient = Recipient,
           org = #esaml_org{
                   name = [{en, OrgName}],
                   displayname = OrgDispName,
                   url = OrgUrl
                 },
           tech = #esaml_contact{
                    name = ContactName,
                    email = ContactEmail
                  }
         },

    ClientCert = proplists:get_value(cert, Opts),
    ClientKey = proplists:get_value(key, Opts),
    CertChain = proplists:get_value(chain, Opts, []),

    SignRequests = proplists:get_value(sign_requests, Opts, true),
    SignMetadata = proplists:get_value(sign_metadata, Opts, true),

    SP2 = case (ClientKey =/= undefined) andalso (ClientCert =/= undefined) of
              true ->
                  SP#esaml_sp{key = ClientKey,
                              certificate = ClientCert,
                              cert_chain = CertChain,
                              sp_sign_requests = SignRequests,
                              sp_sign_metadata = SignMetadata};
              false ->
                  SP
          end,

    FPsUsage = proplists:get_value(fingerprints_usage, Opts, metadata_initial),

    FPs = case FPsUsage of
              everything -> proplists:get_value(trusted_fingerprints, Opts, []);
              U when U =:= metadata_initial; U =:= metadata ->
                  case trusted_fingerprints_from_metadata() of
                      {ok, L} -> L;
                      %% It may happen that it is expired or not set
                      %% when we are building reply for /sso/<nam>/samlMetadata
                      %% In this case esaml doesn't need trusted fingerprints
                      %% because it is not verifying anything
                      {error, not_set} -> [];
                      {error, expired} -> []
                  end
          end,

    SP2#esaml_sp{entity_id = proplists:get_value(entity_id, Opts),
                 trusted_fingerprints = FPs}.

try_get_idp_metadata(Opts) ->
    URL = proplists:get_value(idp_metadata_url, Opts),
    case get_idp_metadata(URL, Opts) of
        {ok, Meta} -> Meta;
        {error, Reason} ->
            Msg = io_lib:format("Failed to get IDP metadata from ~s. "
                                "Reason: ~p", [URL, Reason]),
            menelaus_util:web_exception(500, iolist_to_binary(Msg))
    end.

get_idp_metadata(URL, Opts) ->
    case ets:lookup(esaml_idp_meta_cache, URL) of
        [{URL, Meta}] ->
            case metadata_expired(Meta) of
                false ->
                    ?log_debug("Loading IDP metadata for ~s from cache", [URL]),
                    {ok, Meta};
                true ->
                    ?log_debug("IDP metadata for ~s has expired", [URL]),
                    load_idp_metadata(URL, Opts)
            end;
        _ ->
            ?log_debug("IDP metadata for ~s not found in cached", [URL]),
            load_idp_metadata(URL, Opts)
    end.

metadata_expired(#esaml_idp_metadata{valid_until = undefined}) ->
    false;
metadata_expired(#esaml_idp_metadata{valid_until = Datetime}) ->
    calendar:universal_time() > Datetime.

extract_connect_options(URL, SSOOpts) ->
    AddrSettings = case proplists:get_value(address_family, SSOOpts) of
                       undefined -> [];
                       AF -> [AF]
                   end,

    Opts =
        case URL of
            "https://" ++ _ ->
                case proplists:get_value(tls_verify_peer, SSOOpts, true) of
                    true ->
                        CACerts = proplists:get_value(tls_ca, SSOOpts, []) ++
                                  ns_server_cert:trusted_CAs(der),
                        [{verify, verify_peer}, {cacerts, CACerts},
                         {depth, ?ALLOWED_CERT_CHAIN_LENGTH}] ++
                        case proplists:get_value(tls_sni, SSOOpts, "") of
                            "" -> [];
                            SNI -> [{server_name_indication, SNI}]
                        end;
                    false ->
                        [{verify, verify_none}]
                end;
            "http://" ++ _ ->
                []
        end ++ AddrSettings,

    ExtraOpts = proplists:get_value(tls_extra_opts, SSOOpts, []),
    misc:update_proplist_relaxed(Opts, ExtraOpts).

load_idp_metadata(URL, Opts) ->
    try
        Timeout = proplists:get_value(metadata_http_timeout, Opts, 5000),
        ConnectOptions = extract_connect_options(URL, Opts),

        Body = case rest_utils:request(<<"saml_metadata">>, URL, "GET", [],
                                       <<>>, Timeout,
                                       [{connect_options, ConnectOptions}]) of
                   {ok, {{200, _}, _RespHeaders, Bin}} -> binary_to_list(Bin);
                   {ok, {{Status, _Reason}, _RespHeaders, _RespBody}} ->
                       error({error, {rest_failed, URL, {status, Status}}});
                   {error, Reason} ->
                       error({error, {rest_failed, URL, {error, Reason}}})
               end,

        ?log_debug("Received IDP metadata from ~s:~n~s",
                   [URL, Body]),

        Xml = try xmerl_scan:string(Body, [{namespace_conformant, true}]) of
                  {X, _} -> X
              catch
                  _:_ -> error({error, {invalid_xml, Body}})
              end,

        case proplists:get_value(idp_signs_metadata, Opts, true) of
            true ->
                FPs = trusted_fingerprints_for_metadata(Opts),
                try xmerl_dsig:verify(Xml, FPs) of
                    ok -> ok;
                    {error, Reason2} ->
                        error({error, {signature_verification_failed, Reason2}})
                catch
                    _:Reason2:ST2 ->
                        ?log_error("xmerl_dsig:verify crashed with reason:~n~p"
                                   "~nfor metadata:~n~p with FPs:~n~p~n~p",
                                   [Reason2, Xml, FPs, ST2]),
                        error({error, {signature_verification_failed, unknown}})
                end;
            false ->
                ok
        end,

        try esaml:decode_idp_metadata(Xml) of
            {ok, Meta} -> {ok, cache_idp_metadata(Meta, URL)};
            {error, Reason3} -> error({error, {bad_metadata, Reason3}})
        catch
            _:Reason3:ST3 ->
                ?log_error("metadata decode crashed with reason:~n~p~n"
                           "for metadata:~n~p:~n~p",
                           [Reason3, Xml, ST3]),
                error({error, {bad_metadata, unknown}})
        end
    catch
        error:{error, Error} ->
            ?log_error("Failed to get metadata from ~p.~nReason: ~p",
                       [URL, Error]),
            {error, Error}
    end.

cache_idp_metadata(#esaml_idp_metadata{valid_until = ValidUntilExpiration,
                                       cache_duration = CacheDurationDur,
                                       certificates = TrustedCerts} = Meta,
                   URL) ->
    CacheDurationExpiration =
        case CacheDurationDur of
            undefined -> undefined;
            DurProps when is_list(DurProps) ->
                NowDT = calendar:universal_time(),
                datetime_add_interval(NowDT, DurProps)
        end,
    MetaExpirationDateTime = min_if_defined([ValidUntilExpiration,
                                             CacheDurationExpiration]),
    FPsFromIdp = lists:map(fun (DerBin) ->
                               {sha256, crypto:hash(sha256, DerBin)}
                           end, TrustedCerts),
    ns_config:set(saml_sign_fingerprints,
                  {FPsFromIdp, MetaExpirationDateTime}),
    MetaWithExpirationSet = Meta#esaml_idp_metadata{
                              valid_until = MetaExpirationDateTime,
                              cache_duration = undefined
                            },
    ets:insert(esaml_idp_meta_cache, {URL, MetaWithExpirationSet}),
    MetaWithExpirationSet.

min_if_defined(List) ->
    NoUndefined = lists:filter(fun (E) -> E =/= undefined end, List),
    case NoUndefined of
        [] -> undefined;
        _ -> lists:min(NoUndefined)
    end.

datetime_add_interval(Datetime, IntProps) ->
    #{years := Y, months := M, days := D,
      hours := HH, minutes := MM, seconds := SS} = maps:from_list(IntProps),
    functools:chain(Datetime, [iso8601:add_time(_, HH, MM, SS),
                               iso8601:add_years(_, Y),
                               iso8601:add_months(_, M),
                               iso8601:add_days(_, D)]).

trusted_fingerprints_from_metadata() ->
    case ns_config:read_key_fast(saml_sign_fingerprints, undefined) of
        undefined ->
            {error, not_set};
        {FPList, undefined} when is_list(FPList) ->
            {ok, FPList};
        {FPList, ValidUntilDateTime = {_, _}} when is_list(FPList) ->
            case calendar:universal_time() > ValidUntilDateTime of
                true -> {error, expired};
                false -> {ok, FPList}
            end
    end.

trusted_fingerprints_for_metadata(Opts) ->
    ExtraFPs = proplists:get_value(trusted_fingerprints, Opts, []),
    ExtraFPsUsage = proplists:get_value(fingerprints_usage, Opts,
                                        metadata_initial),
    case ExtraFPsUsage of
        everything ->
            ExtraFPs;
        metadata ->
            ExtraFPs;
        metadata_initial ->
            case trusted_fingerprints_from_metadata() of
                {ok, L} -> L;
                {error, not_set} -> ExtraFPs;
                %% Configuration endpoint is supposed to remove
                %% expired FPs if it sets metadata fingerprints
                %% so we will not get 'expired' if FPs just
                %% have been set
                {error, expired} -> []
            end
    end.

validate_authn_response(NameResp, NameEnc, SPMetadata, State) ->
    validator:validate_relative(
      fun (Resp, Enc) ->
          SAMLEncoding = list_to_binary(Enc),
          SAMLResponse = list_to_binary(Resp),
          ?log_debug("Received saml authn response: ~s~nEncoding: ~s",
                     [SAMLResponse, SAMLEncoding]),
          try esaml_binding:decode_response(SAMLEncoding, SAMLResponse) of
              Xml ->
                  %% We can't use fun esaml_util:check_dupe_ets/2 because
                  %% it makes rpc:call to all nodes with a fun which is dangerous
                  DupeCheckFun = fun (_Assertion, _Digest) -> ok end,
                  case esaml_sp:validate_assertion(Xml, DupeCheckFun,
                                                   SPMetadata) of
                      {ok, Assertion} ->
                          ?log_debug("Assertion validated successfully"),
                          {value, Assertion};
                      {error, E} ->
                          ?log_debug("Assertion validation failed: ~p", [E]),
                          Msg = io_lib:format("Assertion validation failed:"
                                              " ~p", [E]),
                          {error, Msg}
                  end
          catch
              _:Reason ->
                  ?log_debug("Failed to decode authn response:~n~p", [Reason]),
                  Msg = io_lib:format("Assertion decode failed: ~p", [Reason]),
                  {error, Msg}
          end
      end, NameResp, NameEnc, State).

validate_logout_request(NameReq, NameEnc, SPMetadata, State) ->
    validator:validate_relative(
      fun (LOReq, Enc) ->
          SAMLEncoding = list_to_binary(Enc),
          SAMLRequest = list_to_binary(LOReq),
          ?log_debug("Received saml logout request: ~s~nEncoding: ~s",
                     [SAMLRequest, SAMLEncoding]),
          %% Seems like decode_response can actually decode requests as well
          try esaml_binding:decode_response(SAMLEncoding, SAMLRequest) of
              Xml ->
                  case esaml_sp:validate_logout_request(Xml, SPMetadata) of
                      {ok, LogoutReq} ->
                          {value, LogoutReq};
                      {error, E} ->
                          ?log_debug("Logout req validation failed: ~p", [E]),
                          Msg = io_lib:format("Logout req validation failed:"
                                              " ~p", [E]),
                          {error, Msg}
                  end
          catch
              _:Reason ->
                  ?log_debug("Failed to decode logout request:~n~p", [Reason]),
                  Msg = io_lib:format("Logout request decode failed: ~p",
                                      [Reason]),
                  {error, Msg}
          end
      end, NameReq, NameEnc, State).

validate_logout_response(NameResp, NameEnc, SPMetadata, State) ->
    validator:validate_relative(
      fun (LOResp, Enc) ->
          SAMLEncoding = list_to_binary(Enc),
          SAMLResponse = list_to_binary(LOResp),
          ?log_debug("Received saml logout response: ~s~nEncoding: ~s",
                     [SAMLResponse, SAMLEncoding]),
          %% Seems like decode_response can actually decode requests as well
          try esaml_binding:decode_response(SAMLEncoding, SAMLResponse) of
              Xml ->
                  case esaml_sp:validate_logout_response(Xml, SPMetadata) of
                      {ok, LogoutResp} ->
                          {value, LogoutResp};
                      {error, {status, Status, SecondLevelStatus}} ->
                          Msg = io_lib:format("SAML IDP returned status: ~p "
                                              "(second level status: ~p) in "
                                              "logout response",
                                              [Status, SecondLevelStatus]),
                          {error, Msg};
                      {error, E} ->
                          ?log_debug("Logout resp validation failed: ~p", [E]),
                          Msg = io_lib:format("Logout resp validation failed:"
                                              " ~p", [E]),
                          {error, Msg}
                  end
          catch
              _:Reason ->
                  ?log_debug("Failed to decode logout response:~n~p", [Reason]),
                  Msg = io_lib:format("Logout response decode failed: ~p",
                                      [Reason]),
                  {error, Msg}
          end
      end, NameResp, NameEnc, State).

build_base_url(node, _, Scheme, Req) ->
    build_node_url(Scheme, undefined, undefined, Req);
build_base_url(alternate, _, Scheme, Req) ->
    Node = node(),
    {AltHostName, AltPorts} =
        service_ports:get_raw_external_host_and_ports(
          Node, ns_config:latest()),
    PortName = case Scheme of
                   http -> rest_port;
                   https -> ssl_rest_port
               end,
    AltPort = proplists:get_value(PortName, AltPorts),
    build_node_url(Scheme, AltHostName, AltPort, Req);
build_base_url(custom, URLBin, _Scheme, _Req) when is_binary(URLBin) ->
    binary_to_list(URLBin).

build_node_url(Scheme, Host, undefined, Req) ->
    PortName = case Scheme of
                   http -> rest_port;
                   https -> ssl_rest_port
               end,
    Port = service_ports:get_port(PortName),
    true = is_integer(Port),
    build_node_url(Scheme, Host, Port, Req);
build_node_url(Scheme, undefined, Port, Req) ->
    H = misc:extract_node_address(node()),
    Host = case misc:is_localhost(H) of
               true  -> menelaus_util:local_addr(Req);
               false -> H
           end,
    build_node_url(Scheme, Host, Port, Req);
build_node_url(Scheme, Host, Port, _Req) ->
    URL = io_lib:format("~p://~s:~b",
                        [Scheme, misc:maybe_add_brackets(Host), Port]),
    lists:flatten(URL).
