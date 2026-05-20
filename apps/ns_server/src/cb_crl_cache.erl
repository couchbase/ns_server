%% @author Couchbase <info@couchbase.com>
%% @copyright 2026-Present Couchbase, Inc.
%%
%% Use of this software is governed by the Business Source License included in
%% the file licenses/BSL-Couchbase.txt.  As of the Change Date specified in that
%% file, in accordance with the Business Source License, use of this software
%% will be governed by the Apache License, Version 2.0, included in the file
%% licenses/APL2.txt.
%%
-module(cb_crl_cache).

-behaviour(gen_server).
-behaviour(ssl_crl_cache_api).

-include("ns_common.hrl").
-include_lib("ns_common/include/cut.hrl").
-include_lib("public_key/include/public_key.hrl").

%% ssl_crl_cache_api behaviour
-export([lookup/3, select/2, fresh_crl/2]).

%% public API
-export([start_link/0]).

%% gen_server callbacks
-export([init/1, handle_call/3, handle_cast/2, handle_info/2,
         terminate/2, code_change/3]).

-define(SERVER, ?MODULE).
-define(ETS, cb_crl_cache).

-type crl_cache_ref() :: undefined.
-type der_crl() :: public_key:der_encoded().

-record(state, {}).

%%%===================================================================
%%% Public API
%%%===================================================================

start_link() ->
    gen_server:start_link({local, ?SERVER}, ?MODULE, [], []).

%%%===================================================================
%%% ssl_crl_cache_api callbacks
%%%===================================================================
%% This module is plugged into TLS options as
%%     {crl_cache, {cb_crl_cache, undefined}}
%% and so receives lookup/3, select/2 and fresh_crl/2 invocations from
%% the SSL handshake.
%%
%% De-facto the lookup callback is called when the certificate contains the CRL
%% Distribution Point extension.
%% The DP arg is the Distribution Point from the-certificate-to-be-validated.
%% CertIssuer is the issuer of the-certificate-to-be-validated.
%% DP may contain cRLIssuer, in this case we should return CRLs issued
%% by it, otherwise we should return CRLs issued by CertIssuer
%% According to rfc5280:
%% cRLIssuer ::= GeneralNames -- a list!!!
%% and CertIssuer is a Name where
%% Name ::= CHOICE { rdnSequence  RDNSequence }
-spec lookup(Distpoint :: #'DistributionPoint'{},
             Issuer :: public_key:issuer_name(),
             CacheRef :: crl_cache_ref()) -> not_available | [der_crl()].
lookup(#'DistributionPoint'{cRLIssuer = asn1_NOVALUE} = DP, CertIssuer,
       DbHandle) ->
    CRLs = select(CertIssuer, DbHandle),
    case lists:filter(public_key:pkix_match_dist_point(_, DP), CRLs) of
        [] -> not_available; %% Let it check other DPs
        Matched -> Matched
    end;
lookup(#'DistributionPoint'{cRLIssuer = CRLIssuer}, _CertIssuer, DbHandle) ->
    select(CRLIssuer, DbHandle).

%% De-facto the select callback is called when the certificate does not contain
%% the CRL DP extension.
%% The issuer is the issuer of the certificate-to-be-validated.
%% Issuer can also be taken from id-ce-issuerAltName extension of
%% the certificate-to-be-validated.
%% At the same time, according to the erlang doc the first arg can also be a
%% list names originating from #'DistributionPoint'.cRLissuer.
%% According to rfc5280:
%% Issuer is a Name while
%% id-ce-issuerAltName ::= GeneralNames -- a list!!!
%% and cRLIssuer ::= GeneralNames -- a list!!!

%% GeneralNames ::= SEQUENCE SIZE (1..MAX) OF GeneralName
%% GeneralName ::= CHOICE {
%%        otherName                       [0]     OtherName,
%%        rfc822Name                      [1]     IA5String,
%%        dNSName                         [2]     IA5String,
%%        x400Address                     [3]     ORAddress,
%%        directoryName                   [4]     Name,
%%        ediPartyName                    [5]     EDIPartyName,
%%        uniformResourceIdentifier       [6]     IA5String,
%%        iPAddress                       [7]     OCTET STRING,
%%        registeredID                    [8]     OBJECT IDENTIFIER }

-spec select(IssuerOrDPLocations, CacheRef) -> [der_crl()]
            when IssuerOrDPLocations :: public_key:issuer_name() | list(),
                 CacheRef :: crl_cache_ref().
select({rdnSequence, _} = Issuer, DbHandle) ->
    select([{directoryName, Issuer}], DbHandle);
select(DPLocations, _DbHandle) when is_list(DPLocations) ->
    issuer_crls(DPLocations);
select(_Other, _DbHandle) ->
    [].

%% Called by SSL when nextUpdate has passed; we return the CRL we have
%% (the gen_server is responsible for refreshing it asynchronously).
fresh_crl(_DP, CRL) ->
    CRL.

%% The arg can be any name:
%% GeneralNames ::= SEQUENCE SIZE (1..MAX) OF GeneralName
%% but de-facto ssl_crl_cache and ssl_crl_hash_dir handle only directoryName
%% so we also handle only directoryName here
-spec issuer_crls([{directoryName, public_key:issuer_name()} | any()]) ->
          [der_crl()].
issuer_crls(Names) ->
    lists:flatmap(
      fun ({directoryName, IssuerName}) ->
              NormIssuer = public_key:pkix_normalize_name(IssuerName),
              try ets:lookup(?ETS, {issuer, NormIssuer}) of
                  [] ->
                      [];
                  [{{issuer, _}, FileKeys}] ->
                      lists:flatmap(
                        fun (FileKey) ->
                                case ets:lookup(?ETS, FileKey) of
                                    [{_, CRLPairs}] ->
                                        %% Return only CRLs whose issuer
                                        %% matches the one being looked up
                                        [Der || {NI, Der} <- CRLPairs,
                                                NI =:= NormIssuer];
                                    [] ->
                                        []
                                end
                        end, FileKeys)
              catch
                  error:badarg -> []
              end;
          (_) -> []
      end, Names).

%%%===================================================================
%%% gen_server callbacks
%%%===================================================================

init([]) ->
    %% ETS layout (set):
    %%   {crl_file, Path}              => CRLBinary
    %%   {issuer,   NormalizedIssuer}  => [{crl_file, Path}]
    ets:new(?ETS, [named_table, protected, set]),
    {ok, #state{}}.

handle_call(Req, _From, State) ->
    ?log_error("Received unknown call: ~p", [Req]),
    {reply, {error, unknown_request}, State}.

handle_cast(Msg, State) ->
    ?log_error("Received unknown cast: ~p", [Msg]),
    {noreply, State}.

handle_info(Msg, State) ->
    ?log_error("Received unknown info: ~p", [Msg]),
    {noreply, State}.

terminate(_Reason, _State) -> ok.

code_change(_, State, _) -> {ok, State}.

