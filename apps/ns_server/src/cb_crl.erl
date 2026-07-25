%% @author Couchbase <info@couchbase.com>
%% @copyright 2026-Present Couchbase, Inc.
%%
%% Use of this software is governed by the Business Source License included in
%% the file licenses/BSL-Couchbase.txt.  As of the Change Date specified in that
%% file, in accordance with the Business Source License, use of this software
%% is governed by the Apache License, Version 2.0, included in
%% the file licenses/APL2.txt.

-module(cb_crl).

-include("ns_common.hrl").
-include_lib("public_key/include/public_key.hrl").

-export([verify_fun/1, verify/4, verify_chain/2, crl_check_safe/2,
         crl_check/1]).

-type pkix_crls_validate_verdict() :: valid | {bad_cert, Reason :: term()}.
-type verdict_expiration_datetime() :: calendar:datetime() | undefined.

%% Note that the verify_fun_verdict type does not include
%% {fail, cert_decode_error} because verify_fun is always called with
%% already decoded certs
-type verify_fun_verdict(State) :: {valid, State} |
                                   {fail, {bad_cert, term()} | internal_error |
                                          crl_unavailable} |
                                   {unknown, State}.

-record(verify_state, {certs = [] :: [#'OTPCertificate'{}]}).

-export_type([pkix_crls_validate_verdict/0]).

-spec verify_fun(CRLScope :: crl_scope()) ->
          fun((#'OTPCertificate'{}, term(), State) ->
              verify_fun_verdict(State)) when State :: term().
verify_fun(CRLScope) ->
    fun (Cert, Event, State) ->
        verify(Cert, Event, CRLScope, State)
    end.

%% verify_fun implementation.  Called by the SSL layer for every certificate
%% event during the TLS handshake.
%%
%% The SSL layer validates the chain root -> leaf, so the certs are collected in
%% the verify_fun state and the whole chain is checked at the valid_peer event,
%% where the scope it belongs to is known.  Failing every bad_cert event is what
%% makes that safe: the routes that skip valid_peer (unknown_ca, invalid_issuer,
%% selfsigned_peer, max_path_length_reached) all arrive as bad_cert first.
-spec verify(OtpCert  :: #'OTPCertificate'{},
             Event    :: term(),
             CRLScope :: crl_scope(),
             State) -> verify_fun_verdict(State) when State :: #verify_state{} |
                                                               undefined.
verify(OtpCert, valid, _CRLScope, State) ->
    {valid, add_cert(OtpCert, State)};
verify(OtpCert, valid_peer, CRLScope, State0) ->
    #verify_state{certs = ChainReversed} = add_cert(OtpCert, State0),
    %% Chain: Leaf cert is the last element
    Chain = lists:reverse(ChainReversed),
    Results = verify_chain_on_ns_server(Chain, CRLScope),
    case [R || {R, _Expiry} <- Results, R =/= valid] of
        [] -> {valid, undefined};
        [Reason | _] -> {fail, Reason}
    end;
verify(_OtpCert, {bad_cert, _} = Reason, _CRLScope, _State) ->
    %% Non-CRL cert failure (expired, bad signature, etc.):
    %% respect the SSL layer's verdict.
    {fail, Reason};
verify(_OtpCert, {extension, _}, _CRLScope, State) ->
    {unknown, State}.

%% The cb_crl_cache ETS table and ns_server_cert state live only on the
%% ns_server node, but this callback runs on whichever node terminates the TLS
%% connection — including the ns_couchdb node (capi SSL service).  So when
%% invoked there, check the chain on ns_server via RPC; verify_chain/2
%% (and below) can then assume it is running on the ns_server node.
verify_chain_on_ns_server(Chain, CRLScope) ->
    case ns_node_disco:couchdb_node() == node() of
        true ->
            case rpc:call(ns_node_disco:ns_server_node(), ?MODULE, verify_chain,
                          [Chain, CRLScope]) of
                {badrpc, _} -> %% fail closed
                    [{crl_unavailable, undefined} || _ <- Chain];
                Results ->
                    Results
            end;
        false ->
            verify_chain(Chain, CRLScope)
    end.

%% Check a certificate chain, which must be ordered root -> leaf, under the CRL
%% policy of the scope the chain belongs to.
%% Returns one result per certificate, in the same order; each is the verdict
%% plus the expiry of the computed status, telling the caller how long it may
%% be cached.
-spec verify_chain([#'OTPCertificate'{} | binary(), ...], crl_scope()) ->
          [{pkix_crls_validate_verdict() | internal_error | crl_unavailable |
            cert_decode_error,
            verdict_expiration_datetime()}].
verify_chain(Chain, CRLScope) ->
    %% Change scope to node_to_node if this is an internal cert:
    EffectiveScope = effective_scope(Chain, CRLScope),
    case wait_for_crl_policy(EffectiveScope, 5000) of
        {ok, disabled} ->
            [{valid, undefined} || _ <- Chain];
        {ok, Policy} ->
            case wait_for_check_intermediate_certs(Chain, 5000) of
                {ok, CheckCACerts} ->
                    check_chain(Chain, Policy, CheckCACerts, []);
                timeout ->
                    ?log_debug("Rejecting: check_intermediate_certs flag not "
                               "yet available; expected only during startup."),
                    [{crl_unavailable, undefined} || _ <- Chain]
            end;
        timeout ->
            %% This can happen during startup when cb_crl_manager has
            %% not yet written the node_to_node policy to cb_crl_cache.
            %% Fail closed; the peer will retry once policy is available.
            ?log_debug("Rejecting the distribution connection as the CRL "
                       "policy is not available yet; the peer should retry "
                       "shortly. This is expected only during startup. "),
            [{crl_unavailable, undefined} || _ <- Chain]
    end.

%% The scope a cert is really governed by. Internal client certs (SAN rfc822Name
%% <name>@internal.couchbase.com, see ns_server_cert:generate_certs/3) carry the
%% cluster's own node-to-node traffic, yet they are presented to listeners that
%% verify under the client_auth scope, so the nodeToNode policy is the one that
%% must govern them.
-spec effective_scope([#'OTPCertificate'{} | binary()], crl_scope()) ->
          crl_scope().
effective_scope(Chain, client_auth) ->
    Leaf = lists:last(Chain),
    try ns_server_cert:extract_internal_client_cert_user(Leaf) of
        {ok, _User} -> node_to_node;
        {error, not_found} -> client_auth
    catch _:_ ->
            %% Undecodable leaf; check_chain reports it as cert_decode_error.
            client_auth
    end;
effective_scope(_Chain, node_to_node) ->
    node_to_node.

check_chain([LeafCert], Policy, _CheckIntCerts, Acc) ->
    Res = crl_check_safe(LeafCert, Policy),
    lists:reverse([Res | Acc]);
check_chain([_IntCert | Rest], Policy, false = CheckIntCerts, Acc) ->
    check_chain(Rest, Policy, CheckIntCerts, [{valid, undefined} | Acc]);
check_chain([IntCert | Rest], Policy, true = CheckIntCerts, Acc) ->
    Res = try public_key:pkix_is_self_signed(IntCert) of
              true -> {valid, undefined};
              false -> crl_check_safe(IntCert, Policy)
          catch
              _:_ -> {cert_decode_error, undefined}
          end,
    check_chain(Rest, Policy, CheckIntCerts, [Res | Acc]).

add_cert(OtpCert, #verify_state{certs = Certs} = State) ->
    State#verify_state{certs = [OtpCert | Certs]};
add_cert(OtpCert, _UserState) ->
    #verify_state{certs = [OtpCert]}.

wait_for_crl_policy(Scope, Remaining) ->
    wait_for_value(fun () -> cb_crl_cache:get_policy(Scope) end, Remaining).

%% A chain without CA certs doesn't care about the flag.
wait_for_check_intermediate_certs([_Leaf], _Timeout) ->
    {ok, false};
wait_for_check_intermediate_certs(_Chain, Timeout) ->
    wait_for_value(fun cb_crl_cache:get_check_intermediate_certs/0, Timeout).

%% Poll GetFun/0 every 100 ms until it returns a value other than 'unknown',
%% or until Remaining milliseconds have elapsed.
wait_for_value(GetFun, Remaining) ->
    case GetFun() of
        unknown when Remaining > 0 ->
            timer:sleep(100),
            wait_for_value(GetFun, max(0, Remaining - 100));
        unknown ->
            timeout;
        Value ->
            {ok, Value}
    end.

%% Determine the revocation status of a certificate under the active policy.
%% The policy-independent verdict (from public_key:pkix_crls_validate/3) is
%% cached by cb_crl_status_cache keyed on the certificate, so repeated
%% handshakes for the same cert do not re-run the validation; the per-scope
%% policy is then applied to the cached verdict (apply_policy/3), so the same
%% cached verdict serves all scopes.  Returns the verify_fun result together
%% with the source nextUpdate (used for the diagnostic `expiration` field and
%% cache freshness).
-spec crl_check_safe(#'OTPCertificate'{} | binary(), permissive | require) ->
          {pkix_crls_validate_verdict() | internal_error | cert_decode_error,
           verdict_expiration_datetime()}.
crl_check_safe(Cert, Policy) when Policy == permissive; Policy == require ->
    try
        crl_check(Cert, Policy)
    catch
        C:E:ST ->
            ?log_error("CRL check exception ~p:~p~n~p", [C, E, ST]),
            {internal_error, undefined}
    end.

-spec crl_check(#'OTPCertificate'{} | binary(), permissive | require) ->
          {pkix_crls_validate_verdict() | cert_decode_error,
           verdict_expiration_datetime()}.
crl_check(DerCert, Policy) when is_binary(DerCert) ->
    try public_key:pkix_decode_cert(DerCert, otp) of
        OtpCert -> crl_check(OtpCert, Policy)
    catch
        C:E:ST ->
            ?log_error("(CRL) cert decode failed: ~p:~p~nStacktrace: ~p",
                       [C, E, ST]),
            {cert_decode_error, undefined}
    end;
crl_check(OtpCert, Policy) when Policy == permissive; Policy == require ->
    try
        {CacheStatus, {RawVerdict, NextUpdate}} =
            cb_crl_status_cache:crl_check(OtpCert),
        Res = {apply_policy(RawVerdict, Policy, OtpCert), NextUpdate},
        notify_verdict(verdict_label(RawVerdict), CacheStatus),
        Res
    catch
        C:E:ST ->
            notify_verdict(internal_error, miss),
            erlang:raise(C, E, ST)
    end.

%% Report one crl_status_checks tick, labelled with the check's verdict.
-spec notify_verdict(valid | revoked | undetermined | internal_error,
                     hit | miss) -> ok.
notify_verdict(Verdict, CacheStatus) ->
    ns_server_stats:notify_counter(
      {<<"crl_status_checks">>, [{verdict, Verdict}, {cache, CacheStatus}]}).

%% Verdict label for the metric: the revocation determination this check
%% produced, independent of policy (an 'undetermined' cert is reported as
%% undetermined even when a permissive policy lets it through as valid).
-spec verdict_label(pkix_crls_validate_verdict()) ->
          valid | revoked | undetermined | internal_error.
verdict_label(valid) -> valid;
verdict_label({bad_cert, {revoked, _}}) -> revoked;
verdict_label({bad_cert, {revocation_status_undetermined, _}}) -> undetermined;
verdict_label({bad_cert, _}) -> internal_error.

%% Run the actual CRL validation for a certificate and return the raw
%% public_key:pkix_crls_validate/3 result verbatim (valid | {bad_cert, Reason}),
%% together with the source nextUpdate.  This is the (potentially expensive)
%% computation that cb_crl_status_cache memoizes; interpretation per the active
%% policy happens later, in apply_policy/3.
-spec crl_check(#'OTPCertificate'{}) ->
          {pkix_crls_validate_verdict(), calendar:datetime() | undefined}.
crl_check(OtpCert) ->
    DPsAndCRLs = build_dps_and_crls(OtpCert),
    NextUpdate = compute_expiry(DPsAndCRLs),
    TrustedDerCAs = ns_server_cert:trusted_CAs(der),
    IssuerFun = make_issuer_fun(TrustedDerCAs),
    Opts = [{issuer_fun, {IssuerFun, undefined}},
            {undetermined_details, true}],
    {public_key:pkix_crls_validate(OtpCert, DPsAndCRLs, Opts), NextUpdate}.

%% Apply policy to a pkix_crls_validate/3 verdict to a verify_fun result.
%% The revocation_status_undetermined disposition is the
%% fail-open (permissive) / fail-closed (require) knob; a revoked cert always
%% fails; valid always passes; any other bad_cert reason fails.
-spec apply_policy(pkix_crls_validate_verdict(), permissive | require,
                   #'OTPCertificate'{}) -> pkix_crls_validate_verdict().
apply_policy(valid, _Policy, _OtpCert) ->
    valid;
apply_policy({bad_cert, {revoked, Reason}}, Policy, OtpCert) ->
    SubjectStr = ns_server_cert:get_subject(OtpCert),
    ?log_debug("(CRL) Certificate revoked \"~s\" (policy=~p): ~p",
               [ns_config_log:tag_user_name(SubjectStr), Policy, Reason]),
    %% Based on this reason path_validation_alert will send CERTIFICATE_REVOKED
    %% alert
    {bad_cert, {revoked, Reason}};
apply_policy({bad_cert, {revocation_status_undetermined, Details}},
             permissive = Policy, OtpCert) ->
    SubjectStr = ns_server_cert:get_subject(OtpCert),
    ?log_debug("(CRL) Certificate status undetermined \"~s\" "
               "(policy=~p, treat as valid): ~p",
               [ns_config_log:tag_user_name(SubjectStr), Policy, Details]),
    valid;
apply_policy({bad_cert, {revocation_status_undetermined, Details}},
             Policy, OtpCert) ->
    SubjectStr = ns_server_cert:get_subject(OtpCert),
    ?log_debug("(CRL) Certificate status undetermined \"~s\" "
               "(policy=~p, will fail): ~p",
               [ns_config_log:tag_user_name(SubjectStr), Policy, Details]),
    %% Based on this reason path_validation_alert will send BAD_CERTIFICATE
    %% alert
    {bad_cert, {revocation_status_undetermined, Details}};
apply_policy({bad_cert, Reason}, Policy, OtpCert) ->
    SubjectStr = ns_server_cert:get_subject(OtpCert),
    ?log_error("(CRL) Unexpected CRL validation status for certificate \"~s\" "
               "(policy=~p, will fail): ~p",
               [ns_config_log:tag_user_name(SubjectStr), Policy, Reason]),
    {bad_cert, Reason}.

%% Compute when the CRL-based status expires: the earliest nextUpdate among
%% all CRLs that have not already expired.  Returns undefined when there are
%% no CRLs, all CRLs have already expired, or no CRL carries a nextUpdate.
-spec compute_expiry([{#'DistributionPoint'{},
                       {public_key:der_encoded(), #'CertificateList'{}}}]) ->
          calendar:datetime() | undefined.
compute_expiry(DPsAndCRLs) ->
    NowSecs = calendar:datetime_to_gregorian_seconds(calendar:universal_time()),
    NextUpdateSecs =
        lists:filtermap(
          fun ({_, {_, #'CertificateList'{tbsCertList = TBS}}}) ->
                  case TBS#'TBSCertList'.nextUpdate of
                      asn1_NOVALUE ->
                          false;
                      Raw ->
                          case pubkey_cert:time_str_2_gregorian_sec(Raw) of
                              Secs when Secs > NowSecs -> {true, Secs};
                              _                        -> false
                          end
                  end
          end, DPsAndCRLs),
    case NextUpdateSecs of
        [] -> undefined;
        _  -> calendar:gregorian_seconds_to_datetime(lists:min(NextUpdateSecs))
    end.

%% Build the [{DistributionPoint, {DerCRL, OtpCRL}}] list required by
%% public_key:pkix_crls_validate/3.
-spec build_dps_and_crls(#'OTPCertificate'{}) ->
          [{#'DistributionPoint'{},
            {public_key:der_encoded(), #'CertificateList'{}}}].
build_dps_and_crls(OtpCert) ->
    Pairs = get_crls_for_cert_dps(OtpCert) ++ get_crls_for_cert_issuer(OtpCert),
    Decoded =
        lists:filtermap(
          fun ({DP, Der}) ->
                  try public_key:der_decode('CertificateList', Der) of
                      OtpCRL -> {true, {DP, {Der, OtpCRL}}}
                  catch _:_ ->
                      ?log_error("Failed to decode CRL for DP ~p: ~p",
                                 [DP, Der]),
                      false
                  end
          end, lists:uniq(Pairs)),
    %% Sort newest-first so that pkix_crls_validate/3 sees the most
    %% recent CRL first and avoids false "not revoked" results when
    %% an outdated CRL is checked before a newer one.
    lists:sort(
        fun ({_, {_, CRL1}}, {_, {_, CRL2}}) ->
                crl_this_update_secs(CRL1) >= crl_this_update_secs(CRL2)
        end, Decoded).

-spec crl_this_update_secs(#'CertificateList'{}) -> non_neg_integer().
crl_this_update_secs(#'CertificateList'{tbsCertList = TBS}) ->
    try pubkey_cert:time_str_2_gregorian_sec(TBS#'TBSCertList'.thisUpdate)
    catch _:_ -> 0
    end.

get_crls_for_cert_dps(OtpCert) ->
    %% Extract the cert's CDP DPs and retrieve matching CRLs from the cache.
    DPs = public_key:pkix_dist_points(OtpCert),
    Issuer  = (OtpCert#'OTPCertificate'.tbsCertificate)
                  #'OTPTBSCertificate'.issuer,
    lists:flatmap(
        fun (DP) ->
                case cb_crl_cache:lookup(
                        DP, Issuer, undefined) of
                    not_available -> [];
                    DerCRLs -> [{DP, D} || D <- DerCRLs]
                end
        end, DPs).

get_crls_for_cert_issuer(OtpCert) ->
    %% This is a synthetic DP that contains the cert issuer and names for
    %% certificate's id-ce-issuerAltName extension (if present)
    SynDP = public_key:pkix_dist_point(OtpCert),
    #'DistributionPoint'{distributionPoint = {fullName, GenNames}} = SynDP,
    DerCRLs = lists:flatmap(
                fun (GenName) ->
                        case GenName of
                            {directoryName, Name} ->
                                cb_crl_cache:select(Name, undefined);
                            _ -> []
                        end
                end, GenNames),
    [{SynDP, Der} || Der <- lists:uniq(DerCRLs)].

%% Build the issuer_fun for public_key:pkix_crls_validate/3.
%%
%% Required signature (from OTP public_key docs):
%%   fun(DP, CRL, Issuer, UserState) ->
%%       {ok, TrustedOtpCert, CertPath} | {error, Reason}
%%
%% pubkey_crl calls pkix_path_validation(TrustedOtpCert, CertPath)
%% and uses the resulting public key to verify the CRL signature.
%% When CertPath is empty, pkix_path_validation returns the public
%% key of TrustedOtpCert itself — meaning the trust anchor directly
%% signed the CRL.
%%
%% Uses public_key:pkix_is_issuer/2 to locate the trusted CA whose
%% subject matches the CRL's issuer, then returns it as the trust
%% anchor with CertPath = [].  When multiple CAs share the same
%% subject name (e.g. during a key rollover), the AKI keyIdentifier
%% in the CRL is matched against each candidate's SKI to pick the
%% correct one.
%%
%% Limitation: this does not support dedicated CRL signing
%% certificates (a leaf cert, not a CA, issued specifically for CRL
%% signing).  In that case CertPath would need to contain the signing
%% cert and TrustedOtpCert would be its issuing CA.  Standard PKI
%% deployments (CA signs its own CRLs) are handled correctly.
-spec make_issuer_fun([public_key:der_encoded()]) ->
          fun((#'DistributionPoint'{}, #'CertificateList'{},
               term(), term()) ->
               {ok, #'OTPCertificate'{},
                    [public_key:der_encoded()]} |
               {error, term()}).
make_issuer_fun(TrustedDerCAs) ->
    fun (_DP, CRL, _Issuer, _UserState) ->
            Matching =
                lists:filter(
                  fun (DerCA) ->
                          try public_key:pkix_is_issuer(CRL, DerCA)
                          catch _:_ -> false
                          end
                  end, TrustedDerCAs),
            case Matching of
                [] ->
                    ?log_warning("CRL issuer not found for CRL with issuer ~p",
                                 [ns_server_cert:format_name(
                                    public_key:pkix_crl_issuer(CRL))]),
                    {error, issuer_not_found};
                [DerCA] ->
                    OtpCA = public_key:pkix_decode_cert(DerCA, otp),
                    {ok, OtpCA, []};
                [_ | _] ->
                    ?log_debug("Multiple CAs share subject of CRL issuer ~p; "
                               "using AKI/SKI to disambiguate",
                               [ns_server_cert:format_name(
                                  public_key:pkix_crl_issuer(CRL))]),
                    AKI = crl_aki_key_id(CRL),
                    case search_by_aki(AKI, Matching) of
                        {ok, OtpCA} -> {ok, OtpCA, []};
                        error ->
                            %% Failed to find the CA by AKI, so just take
                            %% the latest one (first one in the list)
                            DerCA = hd(Matching),
                            OtpCA = public_key:pkix_decode_cert(DerCA, otp),
                            {ok, OtpCA, []}
                    end
            end
    end.

-spec search_by_aki(binary() | undefined, [binary()]) ->
          {ok, #'OTPCertificate'{}} | error.
search_by_aki(undefined, _CandidatesDer) -> error; %% There is no AKI in CRL
search_by_aki(_AKIKeyId, []) -> error;
search_by_aki(AKIKeyId, [CADer | RestCAs]) ->
    try public_key:pkix_decode_cert(CADer, otp) of
        OtpCACert ->
            case cert_ski(OtpCACert) == AKIKeyId of
                true -> {ok, OtpCACert};
                false -> search_by_aki(AKIKeyId, RestCAs)
            end
    catch
        _:_ ->
            ?log_warning("Failed to decode cert:~n~p", [CADer]),
            search_by_aki(AKIKeyId, RestCAs)
    end.

%% Extract the keyIdentifier field from a CRL's AKI extension.
%% Returns undefined when the extension is absent or carries no keyIdentifier.
-spec crl_aki_key_id(#'CertificateList'{}) -> binary() | undefined.
crl_aki_key_id(CRL) ->
    Exts = (CRL#'CertificateList'.tbsCertList)#'TBSCertList'.crlExtensions,
    case Exts of
        asn1_NOVALUE -> undefined;
        _ ->
            case lists:keyfind(?'id-ce-authorityKeyIdentifier',
                               #'Extension'.extnID, Exts) of
                false -> undefined;
                #'Extension'{extnValue = Val} ->
                    try public_key:der_decode('AuthorityKeyIdentifier', Val) of
                        #'AuthorityKeyIdentifier'{keyIdentifier = KeyId} ->
                            case KeyId of
                                asn1_NOVALUE -> undefined;
                                _ -> KeyId
                            end
                    catch _:_ ->
                        undefined
                    end
            end
    end.

%% Extract the keyIdentifier from a decoded CA cert's SKI extension.
%% Returns undefined when the extension is absent.
-spec cert_ski(#'OTPCertificate'{}) -> binary() | undefined.
cert_ski(OtpCA) ->
    TBS = OtpCA#'OTPCertificate'.tbsCertificate,
    Exts = TBS#'OTPTBSCertificate'.extensions,
    case Exts of
        asn1_NOVALUE -> undefined;
        _ ->
            case lists:keyfind(?'id-ce-subjectKeyIdentifier',
                               #'Extension'.extnID, Exts) of
                false -> undefined;
                #'Extension'{extnValue = Id} -> Id
            end
    end.