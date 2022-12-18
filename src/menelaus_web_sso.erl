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

-module(menelaus_web_sso).

-export([handle_auth/2,
         handle_deauth/2,
         handle_saml_metadata/2,
         handle_get_saml_consume/2,
         handle_post_saml_consume/2,
         handle_get_saml_logout/2,
         handle_post_saml_logout/2]).

-include("ns_common.hrl").
-include("cut.hrl").
-include_lib("esaml/include/esaml.hrl").

-define(DEFAULT_NAMEID_FORMAT,
        "urn:oasis:names:tc:SAML:2.0:nameid-format:persistent").

%%%===================================================================
%%% API
%%%===================================================================

handle_auth(SSOName, Req) ->
    SSOOpts = extract_saml_settings(SSOName),
    ?log_debug("Starting saml(~s) authentication ", [SSOName]),
    SPMetadata = build_sp_metadata(SSOName, SSOOpts, Req),
    IDPMetadata = get_idp_metadata(SSOOpts),
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

handle_deauth(SSOName, Req) ->
    SSOOpts = extract_saml_settings(SSOName),
    ?log_debug("Starting saml(~s) single logout", [SSOName]),
    case proplists:get_value(single_logout, SSOOpts, true) of
        true -> ok;
        false ->
            ?log_debug("Single logout is turned off"),
            menelaus_util:web_exception(404, "not found")
    end,

    Token = menelaus_auth:get_token(Req),
    false = (Token =:= undefined),
    {Session, Headers} = menelaus_auth:complete_uilogout(Token, Req),

    case Session of
        #uisession{type = {sso, SSOName}, session_name = NameID} ->
            handle_single_logout(SSOName, SSOOpts, NameID, Headers, Req);
        #uisession{type = {sso, RealSSOName}} ->
            ?log_error("Called deauth for wrong SSO: ~p, while real SSO is ~p",
                       [SSOName, RealSSOName]),
            menelaus_util:reply(Req, "Wrong sso", 400, Headers);
        #uisession{type = simple} ->
            ?log_debug("User is not a saml user, ignoring single logout"),
            menelaus_util:reply_text(Req, <<"Redirecting...">>, 302,
                                     [{"Location", "/"} | Headers]);
        undefined ->
            ?log_debug("User not authenticated"),
            menelaus_util:reply_text(Req, <<"Redirecting...">>, 302,
                                     [{"Location", "/"} | Headers])
    end.

handle_single_logout(SSOName, SSOOpts, NameID, ExtraHeaders, Req) ->
    SPMetadata = build_sp_metadata(SSOName, SSOOpts, Req),
    IDPMetadata = get_idp_metadata(SSOOpts),
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

handle_saml_metadata(SSOName, Req) ->
    SSOOpts = extract_saml_settings(SSOName),
    SPMetadata = build_sp_metadata(SSOName, SSOOpts, Req),
    SignedXml = esaml_sp:generate_metadata(SPMetadata),
    Metadata = xmerl:export([SignedXml], xmerl_xml),
    menelaus_util:reply_text(Req, Metadata, 200,
                             [{"Content-Type", "text/xml"}]).

handle_get_saml_consume(SSOName, Req) ->
    handle_saml_consume(SSOName, Req, mochiweb_request:parse_qs(Req)).

handle_post_saml_consume(SSOName, Req) ->
    handle_saml_consume(SSOName, Req, mochiweb_request:parse_post(Req)).

handle_saml_consume(SSOName, Req, UnvalidatedParams) ->
    SSOOpts = extract_saml_settings(SSOName),
    ?log_debug("Starting saml(~s) consume", [SSOName]),
    SPMetadata = build_sp_metadata(SSOName, SSOOpts, Req),
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
                  ?log_debug("Successful saml(~s) login: ~s",
                             [SSOName, ns_config_log:tag_user_name(Username)]),
                  menelaus_auth:uilogin_phase2(Req,
                                               {sso, SSOName},
                                               iolist_to_binary(NameID),
                                               {Username, external});
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

handle_get_saml_logout(SSOName, Req) ->
    handle_saml_logout(SSOName, Req, mochiweb_request:parse_qs(Req)).

handle_post_saml_logout(SSOName, Req) ->
    handle_saml_logout(SSOName, Req, mochiweb_request:parse_post(Req)).

handle_saml_logout(SSOName, Req, UnvalidatedParams) ->
    SSOOpts = extract_saml_settings(SSOName),
    ?log_debug("Starting saml(~s) logout", [SSOName]),
    SPMetadata = build_sp_metadata(SSOName, SSOOpts, Req),
    validator:handle(
      fun (Params) ->
          IDPMetadata = get_idp_metadata(SSOOpts),
          LogoutReq = proplists:get_value('SAMLRequest', Params),
          LogoutResp = proplists:get_value('SAMLResponse', Params),
          case {LogoutReq, LogoutResp} of
              {undefined, undefined} ->
                  ?log_debug("Empty saml message"),
                  menelaus_util:reply_text(Req, "Missing SAML message", 400);
              {#esaml_logoutreq{name = NameID}, _} ->
                  SessionName = iolist_to_binary(NameID),
                  menelaus_ui_auth:logout_by_session_name(SessionName),
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

extract_sso_settings(SSOName) ->
    Opts = ns_config:read_key_fast(sso_options, []),
    proplists:get_value(SSOName, Opts, []).

extract_saml_settings(SSOName) ->
    Opts = extract_sso_settings(SSOName),
    assert_saml_sso(Opts),
    Opts.

assert_saml_sso(Opts) ->
    %% Pretend that we don't have this endpoint for non saml SSO
    case proplists:get_value(type, Opts) of
        saml -> ok;
        _ -> menelaus_util:web_exception(404, "not found")
    end.

reply_via_redirect(IDPURL, SignedXml, RelayState, ExtraHeaders, Req) ->
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

reply_via_post(IDPURL, SignedXml, RelayState, ExtraHeaders, Req) ->
    HTMLBin = esaml_binding:encode_http_post(IDPURL, SignedXml, RelayState),
    ?log_debug("Redirecting user to ~s using POST:~n~s", [IDPURL, HTMLBin]),
    menelaus_util:reply(Req, HTMLBin, 200,
                        [{allow_cache, false},
                         {"Content-Type", "text/html"} | ExtraHeaders]).

build_sp_metadata(Name, Opts, Req) ->
    DefaultScheme = case cluster_compat_mode:is_enterprise() of
                        true -> https;
                        false -> http
                    end,
    BaseURL = build_base_url(
                proplists:get_value(base_url, Opts, alternate),
                proplists:get_value(custom_base_url, Opts),
                proplists:get_value(scheme, Opts, DefaultScheme),
                Req) ++ "/sso/" ++ Name,

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

    SP3 = case proplists:get_value(trusted_fingerprints, Opts) of
              undefined -> SP2#esaml_sp{trusted_fingerprints = []};
              [] -> SP2#esaml_sp{trusted_fingerprints = []};
              FPs -> SP2#esaml_sp{trusted_fingerprints = FPs}
          end,

    SP3#esaml_sp{entity_id = proplists:get_value(entity_id, Opts)}.

get_idp_metadata(Opts) ->
    URL = proplists:get_value(idp_metadata_url, Opts),
    case proplists:get_value(trusted_fingerprints, Opts) of
        undefined -> esaml_util:load_metadata(URL);
        FPs -> esaml_util:load_metadata(URL, FPs)
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
