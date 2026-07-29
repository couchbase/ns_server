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

-ifdef(TEST).
-include_lib("eunit/include/eunit.hrl").
-endif.

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

%% How a CRL is named in the verdict: issuer and CRL number identify it, which
%% is all an operator needs to find the file again.  Never the CRL itself, and
%% the number is absent from a CRL that carries no cRLNumber extension.
-type crl_desc() :: {Issuer :: binary(),
                     CRLNumber :: non_neg_integer() | undefined} |
                    unknown_crl.

-record(verify_state, {certs = [] :: [#'OTPCertificate'{}]}).

%% The descriptions end up in a TLS alert string and in REST responses, so keep
%% each list bounded even if a cert somehow matches very many CRLs.
-define(MAX_REPORTED_CRLS, 20).

%% The update_crl callback takes no user state (unlike issuer_fun), so what it
%% observes has to leave through a side channel.  The process dictionary is
%% enough: the pkix_crls_validate/3 call is synchronous and confined to one
%% process (the TLS handshake process, or the cb_crl_status_cache worker), so
%% no two CRL checks ever share the accumulator.
-define(STALE_CRLS_KEY, {?MODULE, stale_crls}).

%% Evaluate Body with the stale-CRL accumulator armed, and always disarm it
%% afterwards.  Deliberately not asserting that the key was unset: crl_check/1
%% does not nest, but if it ever did, losing a few descriptions is the right
%% failure mode for a diagnostic - refusing the connection is not.
-define(WITH_STALE_CRL_TRACKING(Body),
        begin
            erlang:put(?STALE_CRLS_KEY, sets:new()),
            try Body
            after
                erlang:erase(?STALE_CRLS_KEY)
            end
        end).

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

%% Run the actual CRL validation for a certificate and return the
%% public_key:pkix_crls_validate/3 result (valid | {bad_cert, Reason}), together
%% with the source nextUpdate.  This is the (potentially expensive) computation
%% that cb_crl_status_cache memoizes; interpretation per the active policy
%% happens later, in apply_policy/3.
%%
%% The only departure from the raw pkix result is refine_undetermined/3, which
%% annotates an undetermined verdict with the CRLs the check was made from and
%% the ones OTP discarded as expired.
-spec crl_check(#'OTPCertificate'{}) ->
          {pkix_crls_validate_verdict(), calendar:datetime() | undefined}.
crl_check(OtpCert) ->
    DPsAndCRLs = build_dps_and_crls(OtpCert),
    NextUpdate = compute_expiry(DPsAndCRLs),
    TrustedDerCAs = ns_server_cert:trusted_CAs(der),
    IssuerFun = make_issuer_fun(TrustedDerCAs),
    %% update_crl exists so that a stale CRL can be re-fetched; we do not
    %% re-fetch (the callback returns the CRL unchanged, which is what makes
    %% pubkey_crl:fresh_crl/3 discard it, exactly as the default callback
    %% would), but OTP calls it only for a CRL it has already judged stale, so
    %% it doubles as the notification of that discard.
    Opts = [{issuer_fun, {IssuerFun, undefined}},
            {undetermined_details, true},
            {update_crl, fun (_DP, CRL) ->
                                 record_stale_crl(CRL),
                                 CRL
                         end}],
    {Verdict, StaleCRLs} =
        ?WITH_STALE_CRL_TRACKING(
           begin
               V = public_key:pkix_crls_validate(OtpCert, DPsAndCRLs, Opts),
               {V, get_stale_crls()}
           end),
    {refine_undetermined(Verdict, StaleCRLs, describe_crls(DPsAndCRLs)),
     NextUpdate}.

%% OTP reports "revocation status undetermined" with the details of every CRL
%% it rejected, but a CRL discarded for being stale contributes no details (see
%% pubkey_crl:fresh_crl/3 and the no_fresh_crl clause of
%% public_key:pkix_crls_validate/5), so nothing in the verdict says a CRL
%% expired.  Attach what was discarded, since re-issuing an expired CRL is a
%% completely different remediation from providing one.
%%
%% Attached to every undetermined verdict, whatever OTP's own reason, and
%% attached unconditionally - the empty list included:
%%
%%   * OTP's reason being something other than no_relevant_crls does NOT mean
%%     nothing expired.  A cert covered by two CRLs, one of them expired, is
%%     reported with whatever the surviving CRL made OTP say - a rejected-CRL
%%     list, or nothing at all for an incomplete reasons mask - and the expiry
%%     would go unmentioned.  Keying the annotation off no_relevant_crls hid
%%     exactly the cases where a CRL set is partially stale.
%%
%%   * The expired CRLs are evidence, not the cause.  no_relevant_crls only
%%     means the work list ran out with nothing to report, and a fresh CRL can
%%     end up there too (pubkey_crl:crl_status/2 leaves the details alone both
%%     for an unhandled critical extension and for an incomplete reasons mask,
%%     i.e. CRLs partitioned by revocation reason).  So the expired CRLs may be
%%     the reason there is no verdict, or merely be present alongside it - which
%%     is why they are reported next to OTP's reason rather than as it.
%%
%%   * Always attaching means one shape for consumers to read, and an explicit
%%     {expired_crls, []} answers "did anything expire?" with no, instead of
%%     leaving it unasked.
%%
%% OTP's reason is carried through opaquely, never inspected: the inside of it is
%% undocumented (today a {bad_crls, _} pair, but nothing promises that), so it is
%% paired with our annotation rather than reached into.  Only
%% format_undetermined_details/1 looks inside, where a shape change costs a
%% prettier message and nothing more.
%%
%% Note this pairs with {undetermined_details, true} in crl_check/1: without that
%% option OTP reports the bare revocation_status_undetermined atom, which has no
%% reason to pair with and is left alone by the passthrough clause.
%% The CRLs the check was made from are named too (crls_considered).  OTP's
%% reason describes at most the CRLs it rejected, and for the causes it does not
%% explain at all it describes nothing, so without this an operator has no way of
%% telling which CRLs were even in play - which file to go and look at.  It is
%% the full input set, expired and rejected entries included, so that it stays a
%% faithful answer to "what did the node decide from"; the other lists then say
%% which of those were unusable and why.
-spec refine_undetermined(pkix_crls_validate_verdict(),
                          sets:set(crl_desc()), [crl_desc()]) ->
          pkix_crls_validate_verdict().
refine_undetermined({bad_cert, {revocation_status_undetermined, Reason}},
                    StaleCRLs, Considered) ->
    {bad_cert, {revocation_status_undetermined,
                {Reason,
                 {expired_crls, report_crls(StaleCRLs)},
                 {crls_considered, Considered}}}};
refine_undetermined(Verdict, _StaleCRLs, _Considered) ->
    Verdict.

%%%===================================================================
%%% Stale CRL tracking
%%%===================================================================

%% A set, because the same CRL reaches the callback once per distribution point
%% it is attached to.  A CRL we cannot describe is still recorded, as
%% unknown_crl: that an expired CRL was discarded is worth reporting even
%% unnamed.
-spec record_stale_crl(term()) -> ok.
record_stale_crl(CRL) ->
    erlang:put(?STALE_CRLS_KEY,
               sets:add_element(describe_crl(CRL), get_stale_crls())),
    ok.

-spec get_stale_crls() -> sets:set(crl_desc()).
get_stale_crls() ->
    case erlang:get(?STALE_CRLS_KEY) of
        undefined -> sets:new();
        Descs -> Descs
    end.

%% Identify a CRL for the log/diagnostic message.  OTP documents the update_crl
%% callback as taking a #'CertificateList'{} but actually hands it the
%% {DerCRL, #'CertificateList'{}} pair, so accept either.  This is purely
%% diagnostic and runs on a path that is already failing, so anything
%% unexpected degrades to 'unknown_crl' rather than failing the check.
-spec describe_crl(term()) -> crl_desc().
describe_crl({_Der, CRL}) ->
    describe_crl(CRL);
describe_crl(#'CertificateList'{} = CRL) ->
    {crl_issuer_bin_for_debug(CRL), crl_number(CRL)};
describe_crl(_Other) ->
    unknown_crl.

%% Describe every CRL that was handed to pkix_crls_validate/3, so that an
%% undetermined verdict says what the decision was made from.  Deduplicated: the
%% same CRL appears in the list once per distribution point it matched.
-spec describe_crls([{#'DistributionPoint'{},
                      {public_key:der_encoded(), #'CertificateList'{}}}]) ->
          [crl_desc()].
describe_crls(DPsAndCRLs) ->
    report_crls(
      sets:from_list([describe_crl(CRL) || {_DP, {_Der, CRL}} <- DPsAndCRLs])).

%% sets:to_list/1 order is unspecified; sort so that the log line, the audit
%% reason and the REST details do not reorder run to run.
-spec report_crls(sets:set(crl_desc())) -> [crl_desc()].
report_crls(Descs) ->
    lists:sublist(lists:sort(sets:to_list(Descs)), ?MAX_REPORTED_CRLS).

%% Diagnostic only, like the rest of the description: an undecodable CRL number
%% is simply not reported.
-spec crl_number(#'CertificateList'{}) -> non_neg_integer() | undefined.
crl_number(CRL) ->
    try cb_crl_manager:get_crl_number(CRL)
    catch _:_ -> undefined
    end.

%% A CRL's issuer name for a log or diagnostic message.  Never fails and never
%% returns something unprintable, so callers can drop it straight into a
%% message; do not use it where the name has to be exact.
%%
%% Not iolist_to_binary/1: an issuer name can hold codepoints above 255 (a
%% utf8String attribute value).
-spec crl_issuer_bin_for_debug(#'CertificateList'{}) -> binary().
crl_issuer_bin_for_debug(CRL) ->
    try ns_server_cert:format_name(public_key:pkix_crl_issuer(CRL)) of
        Name ->
            case unicode:characters_to_binary(Name) of
                Bin when is_binary(Bin) -> Bin;
                _ -> misc:format_bin("~p", [Name])
            end
    catch
        _:_ -> <<"unknown issuer">>
    end.

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
    ?log_warning("(CRL) Certificate status undetermined \"~s\" "
                 "(policy=~p, treat as valid): ~s",
                 [ns_config_log:tag_user_name(SubjectStr), Policy,
                  format_undetermined_details(Details)]),
    valid;
apply_policy({bad_cert, {revocation_status_undetermined, Details}},
             Policy, OtpCert) ->
    SubjectStr = ns_server_cert:get_subject(OtpCert),
    ?log_debug("(CRL) Certificate status undetermined \"~s\" "
               "(policy=~p, will fail): ~s",
               [ns_config_log:tag_user_name(SubjectStr), Policy,
                format_undetermined_details(Details)]),
    %% Based on this reason path_validation_alert will send BAD_CERTIFICATE
    %% alert
    {bad_cert, {revocation_status_undetermined, Details}};
apply_policy({bad_cert, Reason}, Policy, OtpCert) ->
    SubjectStr = ns_server_cert:get_subject(OtpCert),
    ?log_error("(CRL) Unexpected CRL validation status for certificate \"~s\" "
               "(policy=~p, will fail): ~p",
               [ns_config_log:tag_user_name(SubjectStr), Policy, Reason]),
    {bad_cert, Reason}.

%% ~p of the raw term is unreadable for the cases operators hit most often (it
%% wraps the CRL descriptions across several lines), so spell those out.
-spec format_undetermined_details(term()) -> iolist().
format_undetermined_details({PkixReason,
                             {expired_crls, Expired},
                             {crls_considered, Considered}}) ->
    [format_pkix_reason(PkixReason),
     format_crl_list("expired CRLs", Expired),
     format_crl_list("CRLs considered", Considered)];
format_undetermined_details(Details) ->
    io_lib:format("~p", [Details]).

%% OTP's own reason for the undetermined status.  This is the one place that
%% looks inside that term - refine_undetermined/3 deliberately does not - so
%% every clause here is a best-effort prettification of what OTP happens to
%% produce today, and an unrecognised shape simply keeps the raw term.
%%
%% OTP has two ways of saying "no CRL answered and none was rejected", picked by
%% which exit path it took: the no_relevant_crls atom when the
%% distribution-point work list ran out, and a bare empty list when the last
%% distribution point left the status undetermined (compare
%% public_key:pkix_crls_validate/5, which runs its details through
%% format_details/1, with do_pkix_crls_validate/5, which does not).
%%
%% The empty list is the one OTP names no cause for at all.  Only two things
%% produce it (pubkey_crl:crl_status/2: an incomplete revocation-reason mask, or
%% a critical extension OTP does not handle - on the CRL or on one of its
%% revocation entries) and neither is visible in the verdict, so say which two to
%% check and leave the detail to the documentation.
-spec format_pkix_reason(term()) -> iolist().
format_pkix_reason({bad_crls, no_relevant_crls}) ->
    "no usable CRL for this certificate";
format_pkix_reason({bad_crls, []}) ->
    "no CRL established this certificate's status; check CRLs for "
    "incomplete onlySomeReasons coverage or an unhandled critical extension";
format_pkix_reason({bad_crls, Rejected}) when is_list(Rejected) ->
    format_rejected_crls(Rejected);
format_pkix_reason(Reason) ->
    io_lib:format("~p", [Reason]).

%% Anything else in a {bad_crls, _} is OTP's list of the CRLs it rejected, one
%% {{bad_crl, Why}, CRL} per rejection.  ~p of that dumps every decoded CRL
%% record in full - pages of it - so name each CRL the way the other lists do and
%% keep only the reason.  Deduplicated and bounded for the same reasons they are:
%% a CRL is rejected once per distribution point it matched, and this ends up in
%% a TLS alert string.
-spec format_rejected_crls([term()]) -> iolist().
format_rejected_crls(Rejected) ->
    Descs = lists:usort([describe_rejection(R) || R <- Rejected]),
    ["rejected CRLs: ",
     lists:join(", ", [format_rejection(D)
                       || D <- lists:sublist(Descs, ?MAX_REPORTED_CRLS)])].

-spec describe_rejection(term()) -> {crl_desc() | term(), term()}.
describe_rejection({{bad_crl, Why}, CRL}) ->
    {describe_crl(CRL), Why};
describe_rejection(Other) ->
    {unknown_crl, Other}.

-spec format_rejection({crl_desc() | term(), term()}) -> iolist().
format_rejection({Desc, Why}) ->
    [format_crl_desc(Desc), io_lib:format(" (~p)", [Why])].

-spec format_crl_list(string(), [crl_desc()]) -> iolist().
format_crl_list(_Label, []) ->
    [];
format_crl_list(Label, Descs) ->
    ["; ", Label, ": ", lists:join(", ", [format_crl_desc(D) || D <- Descs])].

%% Quoted because an issuer name contains commas, which are also what separates
%% one description from the next.
-spec format_crl_desc(crl_desc()) -> iolist().
format_crl_desc(unknown_crl) ->
    "unidentified CRL";
format_crl_desc({Issuer, undefined}) ->
    ["\"", Issuer, "\""];
format_crl_desc({Issuer, CRLNumber}) ->
    ["\"", Issuer, "\" #", integer_to_list(CRLNumber)].

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
                    ?log_warning("CRL issuer not found for CRL with issuer ~s",
                                 [crl_issuer_bin_for_debug(CRL)]),
                    {error, issuer_not_found};
                [DerCA] ->
                    OtpCA = public_key:pkix_decode_cert(DerCA, otp),
                    {ok, OtpCA, []};
                [_ | _] ->
                    ?log_debug("Multiple CAs share subject of CRL issuer ~s; "
                               "using AKI/SKI to disambiguate",
                               [crl_issuer_bin_for_debug(CRL)]),
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

%%%===================================================================
%%% Tests
%%%===================================================================
-ifdef(TEST).

undetermined(Details) ->
    {bad_cert, {revocation_status_undetermined, Details}}.

%% CRLNumber may be an integer, asn1_NOVALUE for a CRL with no cRLNumber
%% extension, or a raw binary to stand in for an undecodable one.
fake_crl(CN, CRLNumber) ->
    CNAttr = #'AttributeTypeAndValue'{type = ?'id-at-commonName',
                                      value = {printableString, CN}},
    Exts = case CRLNumber of
               asn1_NOVALUE ->
                   asn1_NOVALUE;
               Raw when is_binary(Raw) ->
                   [#'Extension'{extnID = ?'id-ce-cRLNumber',
                                 critical = false,
                                 extnValue = Raw}];
               N ->
                   [#'Extension'{extnID = ?'id-ce-cRLNumber',
                                 critical = false,
                                 extnValue =
                                     public_key:der_encode('CRLNumber', N)}]
           end,
    TBS = #'TBSCertList'{issuer = {rdnSequence, [[CNAttr]]},
                         crlExtensions = Exts},
    #'CertificateList'{tbsCertList = TBS}.

%% A {DP, {Der, CRL}} entry as build_dps_and_crls/1 produces them.
fake_dp_and_crl(CRL) ->
    {#'DistributionPoint'{}, {<<"der">>, CRL}}.

%% Anything that is not an undetermined verdict passes through untouched, even
%% when CRLs were discarded as stale.
refine_undetermined_passthrough_test() ->
    Stale = sets:from_list([{<<"CN=ca">>, 1}]),
    Refine = fun (Verdict) -> refine_undetermined(Verdict, Stale, []) end,
    ?assertEqual(valid, Refine(valid)),
    Revoked = {bad_cert, {revoked, keyCompromise}},
    ?assertEqual(Revoked, Refine(Revoked)),
    Failed = {bad_cert, unknown_ca},
    ?assertEqual(Failed, Refine(Failed)),
    %% Without {undetermined_details, true} OTP reports a bare atom, which has
    %% no reason to annotate.
    Bare = {bad_cert, revocation_status_undetermined},
    ?assertEqual(Bare, Refine(Bare)).

%% Every undetermined verdict is annotated, whatever OTP's own reason - which is
%% carried through opaquely - and both lists are present even when empty.
refine_undetermined_expired_crls_test() ->
    Descs = [{<<"CN=ca">>, 7}],
    Annotate = fun (Reason, Stale) ->
                       refine_undetermined(undetermined(Reason), Stale, Descs)
               end,
    Expect = fun (Reason, Expired) ->
                     undetermined({Reason,
                                   {expired_crls, Expired},
                                   {crls_considered, Descs}})
             end,
    ?assertEqual(Expect({bad_crls, no_relevant_crls}, Descs),
                 Annotate({bad_crls, no_relevant_crls},
                          sets:from_list(Descs))),
    %% Nothing stale: the tuple is attached anyway, empty.
    ?assertEqual(Expect({bad_crls, no_relevant_crls}, []),
                 Annotate({bad_crls, no_relevant_crls}, sets:new())),
    %% A reason other than no_relevant_crls is annotated too - this is what
    %% used to hide a partially stale CRL set.
    Rejected = {bad_crls, [{{bad_crl, invalid_signature}, crl}]},
    ?assertEqual(Expect(Rejected, Descs),
                 Annotate(Rejected, sets:from_list(Descs))),
    %% Including the empty list OTP produces for an incomplete reasons mask.
    ?assertEqual(Expect({bad_crls, []}, Descs),
                 Annotate({bad_crls, []}, sets:from_list(Descs))),
    %% The reason is never inspected, so a shape OTP does not produce today is
    %% carried through just the same.
    ?assertEqual(Expect(whatever_otp_invents, Descs),
                 Annotate(whatever_otp_invents, sets:from_list(Descs))),
    Many = [{list_to_binary("CN=ca" ++ integer_to_list(N)), N}
            || N <- lists:seq(1, ?MAX_REPORTED_CRLS + 3)],
    {bad_cert, {revocation_status_undetermined,
                {_, {expired_crls, Reported}, _}}} =
        Annotate({bad_crls, no_relevant_crls}, sets:from_list(Many)),
    %% Capped, and reported in a stable order regardless of set iteration.
    ?assertEqual(lists:sublist(lists:sort(Many), ?MAX_REPORTED_CRLS),
                 Reported).

%% The CRLs the check was made from are named once each, however many
%% distribution points they matched, and are capped like the expired list.
describe_crls_test() ->
    CRL1 = fake_crl("ca1", 3),
    CRL2 = fake_crl("ca2", 4),
    ?assertEqual([{<<"CN=ca1">>, 3}, {<<"CN=ca2">>, 4}],
                 describe_crls([fake_dp_and_crl(C)
                                || C <- [CRL1, CRL2, CRL1]])),
    %% Two CRLs from one issuer are distinct entries: the number tells them
    %% apart, which is the point of reporting it.
    ?assertEqual([{<<"CN=ca1">>, 3}, {<<"CN=ca1">>, 5}],
                 describe_crls([fake_dp_and_crl(C)
                                || C <- [CRL1, fake_crl("ca1", 5)]])),
    ?assertEqual([], describe_crls([])),
    Many = [fake_dp_and_crl(fake_crl("ca" ++ integer_to_list(N), N))
            || N <- lists:seq(1, ?MAX_REPORTED_CRLS + 3)],
    ?assertEqual(?MAX_REPORTED_CRLS, length(describe_crls(Many))).

%% The accumulator is per-call: it starts empty, collapses repeats, and is
%% cleaned up even when the wrapped computation throws.
stale_crl_tracking_test() ->
    Recorded = fun (Fun) -> lists:sort(sets:to_list(Fun())) end,
    ?assertEqual([], sets:to_list(get_stale_crls())),
    CRL1 = fake_crl("ca1", 1),
    CRL2 = fake_crl("ca2", 2),
    ?assertEqual([{<<"CN=ca1">>, 1}, {<<"CN=ca2">>, 2}],
                 Recorded(
                   fun () ->
                       ?WITH_STALE_CRL_TRACKING(
                          begin
                              record_stale_crl(CRL1),
                              record_stale_crl(CRL2),
                              %% The same CRL arrives once per distribution
                              %% point.
                              record_stale_crl(CRL1),
                              get_stale_crls()
                          end)
                   end)),
    %% An undescribable CRL is still reported, once.
    ?assertEqual([unknown_crl],
                 Recorded(
                   fun () ->
                       ?WITH_STALE_CRL_TRACKING(
                          begin
                              record_stale_crl(garbage),
                              record_stale_crl(garbage),
                              get_stale_crls()
                          end)
                   end)),
    ?assertEqual([], sets:to_list(get_stale_crls())),
    ?assertError(oops, ?WITH_STALE_CRL_TRACKING(error(oops))),
    ?assertEqual([], sets:to_list(get_stale_crls())).

format_undetermined_details_test() ->
    Fmt = fun (Reason, Expired, Considered) ->
                  iolist_to_binary(
                    format_undetermined_details({Reason,
                                                 {expired_crls, Expired},
                                                 {crls_considered, Considered}}))
          end,
    Ca1 = {<<"CN=ca1">>, 7},
    Ca2 = {<<"CN=ca2">>, undefined},
    %% Nothing expired, nothing considered: no lists at all.
    ?assertEqual(<<"no usable CRL for this certificate">>,
                 Fmt({bad_crls, no_relevant_crls}, [], [])),
    %% Expired first, then the full input set it is a subset of: a numbered CRL,
    %% an unnumbered one and an unidentified one.
    ?assertEqual(<<"no usable CRL for this certificate"
                   "; expired CRLs: \"CN=ca1\" #7"
                   "; CRLs considered: "
                   "\"CN=ca1\" #7, \"CN=ca2\", unidentified CRL">>,
                 Fmt({bad_crls, no_relevant_crls},
                     [Ca1], [Ca1, Ca2, unknown_crl])),
    %% A details shape without our annotation keeps the raw term.
    ?assertEqual(<<"{bad_crls,no_relevant_crls}">>,
                 iolist_to_binary(
                   format_undetermined_details({bad_crls,
                                                no_relevant_crls}))).

%% OTP's rejected-CRL list: each CRL named as everywhere else, carrying only its
%% rejection reason - never the decoded record ~p would print.
format_rejected_crls_test() ->
    Fmt = fun (Rejected) ->
                  iolist_to_binary(
                    format_undetermined_details(
                      {{bad_crls, Rejected},
                       {expired_crls, []},
                       {crls_considered, [{<<"CN=ca1">>, 7}]}}))
          end,
    CRL1 = fake_crl("ca1", 7),
    CRL2 = fake_crl("ca2", asn1_NOVALUE),
    ?assertEqual(<<"rejected CRLs: \"CN=ca1\" #7 (invalid_signature)"
                   "; CRLs considered: \"CN=ca1\" #7">>,
                 Fmt([{{bad_crl, invalid_signature}, CRL1}])),
    %% One entry per rejection, deduplicated: the same CRL is rejected once per
    %% distribution point it matched.
    ?assertEqual(<<"rejected CRLs: \"CN=ca1\" #7 (mask_error), "
                   "\"CN=ca2\" (scope_error)"
                   "; CRLs considered: \"CN=ca1\" #7">>,
                 Fmt([{{bad_crl, mask_error}, CRL1},
                      {{bad_crl, scope_error}, CRL2},
                      {{bad_crl, mask_error}, CRL1}])),
    %% Bounded, like every other list.
    Many = [{{bad_crl, mask_error}, fake_crl("ca" ++ integer_to_list(N), N)}
            || N <- lists:seq(1, ?MAX_REPORTED_CRLS + 3)],
    ?assertEqual(?MAX_REPORTED_CRLS,
                 length(binary:matches(Fmt(Many), <<"(mask_error)">>))),
    %% An entry shaped in a way OTP does not produce today still renders.
    ?assertEqual(<<"rejected CRLs: unidentified CRL (surprise)"
                   "; CRLs considered: \"CN=ca1\" #7">>,
                 Fmt([surprise])).

%% The cause OTP declines to explain: say so, name the two things to check, and
%% let the CRLs listed after it carry the specifics.
format_no_reason_details_test() ->
    Msg = iolist_to_binary(
            format_undetermined_details(
              {{bad_crls, []},
               {expired_crls, [{<<"CN=ca">>, 7}]},
               {crls_considered, [{<<"CN=ca">>, 7}, {<<"CN=ca">>, 8}]}})),
    ?assertEqual(
       <<"no CRL established this certificate's status; check CRLs for "
         "incomplete onlySomeReasons coverage or an unhandled critical "
         "extension"
         "; expired CRLs: \"CN=ca\" #7"
         "; CRLs considered: \"CN=ca\" #7, \"CN=ca\" #8">>,
       Msg).

%% OTP hands the callback the {DerCRL, CertificateList} pair, not the bare
%% record the docs describe; both must work, and anything else must degrade
%% rather than fail the check.
describe_crl_test() ->
    CRL = fake_crl("ca", 7),
    ?assertEqual({<<"CN=ca">>, 7}, describe_crl(CRL)),
    ?assertEqual({<<"CN=ca">>, 7}, describe_crl({<<"der">>, CRL})),
    %% A CRL with no cRLNumber extension, and one whose number will not decode:
    %% neither is worth failing a handshake over.
    ?assertEqual({<<"CN=ca">>, undefined},
                 describe_crl(fake_crl("ca", asn1_NOVALUE))),
    ?assertEqual({<<"CN=ca">>, undefined},
                 describe_crl(fake_crl("ca", <<"not a CRL number">>))),
    ?assertEqual({<<"unknown issuer">>, undefined},
                 describe_crl(#'CertificateList'{tbsCertList = garbage})),
    ?assertEqual(unknown_crl, describe_crl(garbage)),
    ?assertEqual(unknown_crl, describe_crl({<<"der">>, garbage})).

-endif.