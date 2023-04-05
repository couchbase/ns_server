-module(cb_saml).

-export([get_idp_metadata/2,
         trusted_fingerprints_from_metadata/0]).

-include("ns_common.hrl").
-include("cut.hrl").

-include_lib("esaml/include/esaml.hrl").

get_idp_metadata(URL, Opts) ->
    SettingsUuid = proplists:get_value(uuid, Opts),
    case ets:lookup(esaml_idp_meta_cache, metadata) of
        [{metadata, {MetaUuid, Meta}}] ->
            %% If Uuid in cache doesn't match the Uuid of current settings,
            %% it means settings have changed and we need to refresh the cache
            case (MetaUuid =/= SettingsUuid) orelse metadata_expired(Meta) of
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

cache_idp_metadata(#esaml_idp_metadata{valid_until = ValidUntilExpiration,
                                       cache_duration = CacheDurationDur,
                                       certificates = TrustedCerts} = Meta,
                   Opts) ->
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
    Uuid = proplists:get_value(uuid, Opts),
    ets:insert(esaml_idp_meta_cache, {metadata, {Uuid, MetaWithExpirationSet}}),
    MetaWithExpirationSet.

load_idp_metadata(URL, Opts) ->
    try
        Timeout = proplists:get_value(md_http_timeout, Opts),
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

        case proplists:get_value(idp_signs_metadata, Opts) of
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
            {ok, Meta} -> {ok, cache_idp_metadata(Meta, Opts)};
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

metadata_expired(#esaml_idp_metadata{valid_until = undefined}) ->
    false;
metadata_expired(#esaml_idp_metadata{valid_until = Datetime}) ->
    calendar:universal_time() > Datetime.

extract_connect_options(URL, SSOOpts) ->
    AddrSettings = case proplists:get_value(md_address_family, SSOOpts) of
                       undefined -> [];
                       AF -> [AF]
                   end,

    Opts =
        case URL of
            "https://" ++ _ ->
                case proplists:get_value(md_tls_verify_peer, SSOOpts) of
                    true ->
                        {_, Certs} = proplists:get_value(md_tls_ca, SSOOpts),
                        CACerts = Certs ++ ns_server_cert:trusted_CAs(der),
                        [{verify, verify_peer}, {cacerts, CACerts},
                         {depth, ?ALLOWED_CERT_CHAIN_LENGTH}] ++
                        case proplists:get_value(md_tls_sni, SSOOpts) of
                            "" -> [];
                            SNI -> [{server_name_indication, SNI}]
                        end;
                    false ->
                        [{verify, verify_none}]
                end;
            "http://" ++ _ ->
                []
        end ++ AddrSettings,

    ExtraOpts = proplists:get_value(md_tls_extra_opts, SSOOpts),
    misc:update_proplist_relaxed(Opts, ExtraOpts).

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
    {_, ExtraFPs} = proplists:get_value(trusted_fingerprints, Opts),
    ExtraFPsUsage = proplists:get_value(fingerprints_usage, Opts),
    case ExtraFPsUsage of
        everything ->
            ExtraFPs;
        metadataOnly ->
            ExtraFPs;
        metadataInitialOnly ->
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
