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
         handle_saml_metadata/2,
         handle_get_saml_consume/2,
         handle_post_saml_consume/2]).

-include("ns_common.hrl").
-include("cut.hrl").
-include_lib("esaml/include/esaml.hrl").

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
    SignedXml = esaml_sp:generate_authn_request(_, SPMetadata),
    case Binding of
        redirect ->
            IDPURL = IDPMetadata#esaml_idp_metadata.login_redirect_location,
            Location = esaml_binding:encode_http_redirect(
                         IDPURL,
                         SignedXml(IDPURL),
                         _Username = undefined,
                         RelayState),
            LocationStr = binary_to_list(Location),
            menelaus_util:reply_text(Req, <<"Redirecting...">>, 302,
                                     [{allow_cache, false},
                                      {"Location", LocationStr}]);
        post ->
            IDPURL = IDPMetadata#esaml_idp_metadata.login_post_location,
            HTMLBin = esaml_binding:encode_http_post(IDPURL,
                                                     SignedXml(IDPURL),
                                                     RelayState),
            menelaus_util:reply(Req, HTMLBin, 200,
                                [{allow_cache, false},
                                 {"Content-Type", "text/html"}])
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
                  menelaus_auth:uilogin_phase2(Req, {Username, external});
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
