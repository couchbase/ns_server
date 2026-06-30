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

-export([verify_fun/1, verify/4, verify_local_with_expiry/4, crl_check/2]).

-spec verify_fun(CRLScope :: crl_scope()) ->
          fun((#'OTPCertificate'{}, term(), term()) ->
              {valid, term()} | {fail, term()} | {unknown, term()}).
verify_fun(CRLScope) ->
    fun (Cert, Event, State) ->
        verify(Cert, Event, CRLScope, State)
    end.

%% verify_fun entry point.  Called by the SSL layer for every certificate event
%% during the TLS handshake.
%%
%% The cb_crl_cache ETS table and ns_server_cert state live only on the
%% ns_server node, but this callback runs on whichever node terminates the TLS
%% connection — including the ns_couchdb node (capi SSL service).  So when
%% invoked on the couchdb node, run the whole check on ns_server via RPC;
%% everything in verify_local/4 (and below) can then assume it is running on the
%% ns_server node.
-spec verify(OtpCert  :: #'OTPCertificate'{},
                 Event    :: term(),
                 CRLScope :: crl_scope(),
                 State    :: term()) ->
          {valid, term()} | {fail, term()} | {unknown, term()}.
verify(OtpCert, Event, CRLScope, State) ->
    case ns_node_disco:couchdb_node() == node() of
        true ->
            case rpc:call(ns_node_disco:ns_server_node(), ?MODULE, verify,
                          [OtpCert, Event, CRLScope, State]) of
                {badrpc, _} -> {fail, crl_policy_unavailable}; %% fail closed
                Result      -> Result
            end;
        false ->
            verify_local(OtpCert, Event, CRLScope, State)
    end.

%% verify_fun implementation.  Runs on the ns_server node (directly, or via the
%% RPC in verify/4).
%%
%% CRL checking is performed for valid_peer (the leaf cert) and,
%% when check_intermediate_certs is enabled in the CRL config, also
%% for valid events (intermediate CA certs).  The same per-scope
%% policy applies to both.
-spec verify_local(OtpCert  :: #'OTPCertificate'{},
                   Event    :: term(),
                   CRLScope :: crl_scope(),
                   State    :: term()) ->
          {valid, term()} | {fail, term()} | {unknown, term()}.
verify_local(OtpCert, Event, CRLScope, State) ->
    {Result, _Expiry} = verify_local_with_expiry(OtpCert, Event, CRLScope,
                                                 State),
    Result.

%% Like verify_local/4 but also returns the expiry of the computed status.
%% Used by the /_cbauth/crlsValidate diagnostic endpoint so callers
%% know how long to cache the result.
-spec verify_local_with_expiry(OtpCert  :: #'OTPCertificate'{},
                               Event    :: term(),
                               CRLScope :: crl_scope(),
                               State    :: term()) ->
          {{valid, term()} | {fail, term()} | {unknown, term()},
           calendar:datetime() | undefined}.
verify_local_with_expiry(OtpCert, valid_peer, CRLScope, State) ->
    case wait_for_crl_policy(CRLScope, 5000) of
        {ok, disabled} ->
            {{valid, State}, undefined};
        {ok, Policy} ->
            %% OOTB (cluster-generated) certs are checked the same way as any
            %% other cert: the cluster publishes an empty CRL issued by the OOTB
            %% CA (see ns_server_cert / cb_crl_manager generated CRLs), so their
            %% serial is simply not on a revocation list -> good.
            case crl_check(OtpCert, Policy) of
                {valid, Expiry} -> {{valid, State}, Expiry};
                {{fail, Reason}, Expiry} -> {{fail, Reason}, Expiry}
            end;
        timeout ->
            %% This can happen during startup when cb_crl_manager has
            %% not yet written the node_to_node policy to cb_crl_cache.
            %% Fail closed; the peer will retry once policy is available.
            ?log_debug("Rejecting the distribution connection as the CRL "
                       "policy is not available yet; the peer should retry "
                       "shortly. This is expected only during startup. "),
            {{fail, {bad_cert, crl_policy_not_available_yet}}, undefined}
    end;
verify_local_with_expiry(_OtpCert, {bad_cert, _} = Reason, _CRLScope, _State) ->
    %% Non-CRL cert failure (expired, bad signature, etc.):
    %% respect the SSL layer's verdict.
    {{fail, Reason}, undefined};
verify_local_with_expiry(_OtpCert, {extension, _}, _CRLScope, State) ->
    {{unknown, State}, undefined};
verify_local_with_expiry(OtpCert, valid, CRLScope, State) ->
    case wait_for_check_intermediate_certs(5000) of
        {ok, false} ->
            {{valid, State}, undefined};
        {ok, true} ->
            case public_key:pkix_is_self_signed(OtpCert) of
                true ->
                    %% Root certs can't be revoked by definition
                    {{valid, State}, undefined};
                false ->
                    %% The CRL check is pretty much the same as for the leaf
                    %% cert, so just call verify/4 recursively with valid_peer
                    verify_local_with_expiry(OtpCert, valid_peer, CRLScope,
                                             State)
            end;
        timeout ->
            ?log_debug("Rejecting: check_intermediate_certs flag not yet "
                       "available; expected only during startup."),
            {{fail, {bad_cert, crl_policy_not_available_yet}}, undefined}
    end.

wait_for_crl_policy(Scope, Remaining) ->
    wait_for_value(fun () -> cb_crl_cache:get_policy(Scope) end, Remaining).

wait_for_check_intermediate_certs(Remaining) ->
    wait_for_value(fun cb_crl_cache:get_check_intermediate_certs/0, Remaining).

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

%% Perform the actual CRL revocation check and map the result to a
%% verify_fun return value according to the active policy.
-spec crl_check(#'OTPCertificate'{}, permissive | require) ->
          {valid | {fail, term()}, calendar:datetime() | undefined}.
crl_check(OtpCert, Policy) when Policy == permissive; Policy == require ->
    try
        DPsAndCRLs = build_dps_and_crls(OtpCert),
        Expiry = compute_expiry(DPsAndCRLs),
        TrustedDerCAs = ns_server_cert:trusted_CAs(der),
        IssuerFun = make_issuer_fun(TrustedDerCAs),
        Opts = [{issuer_fun, {IssuerFun, undefined}},
                {undetermined_details, true}],
        Result =
            case public_key:pkix_crls_validate(OtpCert, DPsAndCRLs, Opts) of
                valid ->
                    valid;
                {bad_cert, Reason} ->
                    SubjectStr = ns_server_cert:get_subject(OtpCert),
                    handle_bad_cert_crl_reason(Reason, Policy, SubjectStr)
            end,
        {Result, Expiry}
    catch
        C:E:ST ->
            ?log_error("CRL check exception ~p:~p~n~p", [C, E, ST]),
            {{fail, internal_error}, undefined}
    end.

handle_bad_cert_crl_reason({revoked, Reason}, Policy, SubjectStr) ->
    ?log_debug("(CRL) Certificate revoked \"~s\" (policy=~p): ~p",
               [ns_config_log:tag_user_name(SubjectStr), Policy, Reason]),
    %% Based on this reason path_validation_alert will send CERTIFICATE_REVOKED
    %% alert
    {fail, {bad_cert, {revoked, Reason}}};
handle_bad_cert_crl_reason({revocation_status_undetermined, Reason},
                           permissive = Policy, SubjectStr) ->
    ?log_debug("(CRL) Certificate status undetermined \"~s\" "
               "(policy=~p, treat as valid): ~p",
               [ns_config_log:tag_user_name(SubjectStr), Policy, Reason]),
    valid;
handle_bad_cert_crl_reason({revocation_status_undetermined, Details},
                           Policy, SubjectStr) ->
    ?log_debug("(CRL) Certificate status undetermined \"~s\" "
               "(policy=~p, will fail): ~p",
               [ns_config_log:tag_user_name(SubjectStr), Policy, Details]),
    %% Based on this reason path_validation_alert will send BAD_CERTIFICATE
    %% alert
    {fail, {bad_cert, {revocation_status_undetermined, Details}}};
handle_bad_cert_crl_reason(Reason, Policy, SubjectStr) ->
    ?log_error("(CRL) Unexpected CRL validation status for certificate \"~s\" "
               "(policy=~p, will fail): ~p",
               [ns_config_log:tag_user_name(SubjectStr), Policy, Reason]),
    {fail, {bad_cert, Reason}}.

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