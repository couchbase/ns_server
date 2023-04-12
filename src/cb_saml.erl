-module(cb_saml).

-behaviour(gen_server).

%% API
-export([start_link/0,
         load_idp_metadata/3,
         try_parse_idp_metadata/2,
         extract_fingerprints/2,
         trusted_fingerprints_from_metadata/0,
         get_idp_metadata/1,
         format_error/1,
         cleanup_metadata/0,
         cache_idp_metadata/2,
         check_dupe/2,
         check_dupe_global/2]).

%% gen_server callbacks
-export([init/1, handle_call/3, handle_cast/2, handle_info/2,
         terminate/2, code_change/3]).

-include("ns_common.hrl").
-include("cut.hrl").

-include_lib("esaml/include/esaml.hrl").

-record(s, {refresh_timer_ref, dupe_cleanup_timer_ref}).

-define(MIN_REFRESH_INTERVAL, ?get_timeout(min_refresh_interval, 60000)).
-define(DUPE_CLEANUP_INTERVAL, ?get_timeout(dupe_cleanup_interval, 60000)).
-define(DUPE_ETS, saml_dupe_assertion).

%%%===================================================================
%%% API
%%%===================================================================

start_link() ->
    gen_server:start_link({local, ?MODULE}, ?MODULE, [], []).

get_idp_metadata(Opts) ->
    SettingsUuid = proplists:get_value(uuid, Opts),
    case ets:lookup(?MODULE, metadata) of
        [{metadata, {MetaUuid, _RefreshDT, MetaExpirationDateTime, Meta}}] ->
            %% If Uuid in cache doesn't match the Uuid of current settings,
            %% it means settings have changed and we need to refresh the cache
            CanReload = can_reload_metadata(Opts),
            case (MetaUuid =/= SettingsUuid) orelse
                 (CanReload andalso metadata_expired(MetaExpirationDateTime)) of
                false ->
                    ?log_debug("Loading IDP metadata from cache"),
                    {ok, Meta};
                true ->
                    URL = proplists:get_value(idp_metadata_url, Opts),
                    ?log_debug("IDP metadata has expired (will reload "
                               "from ~s)", [URL]),
                    case load_and_cache_idp_metadata(URL, Opts) of
                        {ok, {_NewRefreshDT, NewMeta}} -> {ok, NewMeta};
                        {error, _} = Error -> Error
                    end
            end;
        [] ->
            case can_reload_metadata(Opts) of
                true ->
                    URL = proplists:get_value(idp_metadata_url, Opts),
                    ?log_debug("IDP metadata not found in cache (will "
                               "reload from ~s)", [URL]),
                    case load_and_cache_idp_metadata(URL, Opts) of
                        {ok, {_NewRefreshDT, NewMeta}} -> {ok, NewMeta};
                        {error, _} = Error -> Error
                    end;
                false ->
                    ?log_debug("IDP metadata not found in cache (will "
                               "load from configuration)"),
                    {zip, MetaZipped} = proplists:get_value(idp_metadata, Opts),
                    Meta = zlib:unzip(MetaZipped),
                    ParsedMetadata = try_parse_idp_metadata(Meta, false),
                    save_fingerprints_from_metadata(Opts,
                                                    ParsedMetadata),
                    cache_idp_metadata(ParsedMetadata, Opts),
                    {ok, ParsedMetadata}
            end
    end.

format_error({rest_failed, URL, {status, Status}}) ->
    io_lib:format("HTTP request ~s returned ~p", [URL, Status]);
format_error({rest_failed, URL, {error, Reason}}) ->
    case misc:parse_url(URL) of
        {ok, #{host := Host, port := Port}} ->
            case ns_error_messages:connection_error_message(Reason, Host, Port) of
                undefined ->
                    io_lib:format("HTTP request ~s failed: ~p", [URL, Reason]);
                Msg ->
                    io_lib:format("HTTP request ~s failed: ~s", [URL, Msg])
            end;
        {error, _} ->
            io_lib:format("HTTP request ~s failed: ~p", [URL, Reason])
    end;
format_error({invalid_xml, _}) ->
    "invalid xml";
format_error({md_signature_verification_failed, Error}) ->
    io_lib:format("metadata signature verification failed: ~p", [Error]);
format_error({bad_metadata, Reason}) ->
    io_lib:format("invalid metadata, reason: ~p", [Reason]);
format_error(Unknown) ->
    io_lib:format("unexpected error: ~p", [Unknown]).

cleanup_metadata() ->
    ns_config:delete(saml_sign_fingerprints),
    ets:delete(?MODULE, metadata).

extract_fingerprints(#esaml_idp_metadata{certificates = TrustedCerts} = Meta,
                     Props) ->
    FPsExpirationDateTime = metadata_expiration(Meta, Props),
    FPsFromIdp = lists:map(fun (DerBin) ->
                              {sha512, crypto:hash(sha512, DerBin)}
                           end, TrustedCerts),
    {FPsFromIdp, FPsExpirationDateTime}.

cache_idp_metadata(#esaml_idp_metadata{} = Meta, Opts) ->
    MetaExpirationDateTime = metadata_expiration(Meta, Opts),
    RefreshDT =
        case can_reload_metadata(Opts) of
            true ->
                case proplists:get_value(idp_metadata_refresh_interval, Opts) of
                    I when is_number(I), I > 0 ->
                        NowDT = calendar:universal_time(),
                        iso8601:add_time(NowDT, 0, 0, I);
                    _ ->
                        undefined
                end;
            false ->
                undefined
        end,
    %% We need Uuid to make sure that record in cache is taken for these
    %% settings exactly. If settings change, uuid change, cache becomes invalid.
    Uuid = proplists:get_value(uuid, Opts),
    false = (Uuid == undefined),
    ets:insert(?MODULE,
               {metadata, {Uuid, RefreshDT, MetaExpirationDateTime, Meta}}),
    RefreshDT.

load_idp_metadata(URL, Opts, FPs) ->
    try
        Timeout = proplists:get_value(md_http_timeout, Opts),
        ConnectOptions = extract_connect_options(URL, Opts),

        Body = case rest_utils:request(<<"saml_metadata">>, URL, "GET", [],
                                       <<>>, Timeout,
                                       [{connect_options, ConnectOptions}]) of
                   {ok, {{200, _}, _RespHeaders, Bin}} -> Bin;
                   {ok, {{Status, _Reason}, _RespHeaders, _RespBody}} ->
                       throw({rest_failed, URL, {status, Status}});
                   {error, Reason} ->
                       throw({rest_failed, URL, {error, Reason}})
               end,

        ?log_debug("Received IDP metadata from ~s:~n~s", [URL, Body]),
        Verify = case proplists:get_value(idp_signs_metadata, Opts) of
                     true -> {verify, FPs};
                     false -> false
                 end,
        {ok, {Body, parse_metadata(Body, Verify)}}
    catch
        throw:Error ->
            ?log_error("Failed to get metadata from ~p.~nReason: ~p",
                       [URL, Error]),
            {error, Error}
    end.

try_parse_idp_metadata(XmlBin, Verify) ->
    try
        parse_metadata(XmlBin, Verify)
    catch
        throw:Error -> error(Error)
    end.

check_dupe_global(Assertion, Digest) ->
    {Res, BadNodes} =
        rpc:multicall(?MODULE, check_dupe, [Assertion, Digest], 5000),
    case BadNodes of
        [] ->
            case lists:usort(Res) of
                [ok] -> ok;
                [_ | _] -> {error, duplicate_assertion}
            end;
        _ ->
            ?log_warning("Dupe assertion check failed on nodes: ~p",
                         [BadNodes]),
            {error, {bad_nodes, BadNodes}}
    end.

check_dupe(Assertion, Digest) ->
    ExpirationTimestamp = esaml:stale_time(Assertion), %% in gregorian seconds
    %% We assume that security is more important than RAM, so we are
    %% not setting any limit for the size of this table here.
    %% Note that in order to get to this table the assertion has to be valid,
    %% so it should be impossible to infate the size of the table by an
    %% unauthentication user. The only problematic scenario that I see is
    %% the one when IDP sets NotOnOrAfter to some date that is too far in
    %% the future. In this case we will basically never clean that table,
    %% we consider it a security problem then and don't let user log in
    %% (because we can't hold cache for used assertions that long).
    Now = calendar:datetime_to_gregorian_seconds(calendar:universal_time()),
    case ExpirationTimestamp < Now + ?SECS_IN_DAY of
        true ->
            case ets:insert_new(?DUPE_ETS, {Digest, ExpirationTimestamp}) of
                true -> ok;
                false -> {error, duplicate_assertion}
            end;
        false ->
            {error, bad_not_on_or_after}
    end.

%%%===================================================================
%%% gen_server callbacks
%%%===================================================================

init([]) ->
    ets:new(?MODULE, [public, named_table, set]),
    ets:new(?DUPE_ETS, [public, named_table, set]),
    Self = self(),
    ns_pubsub:subscribe_link(
      ns_config_events,
      fun ({sso_settings, _}) -> Self ! settings_update;
          (_) -> ok
      end),
    self() ! settings_update,
    {ok, restart_dupe_cleanup_timer(#s{})}.

handle_call(Request, _From, State) ->
    ?log_warning("Unhandled call: ~p", [Request]),
    {noreply, State}.

handle_cast(Msg, State) ->
    ?log_warning("Unhandled cast: ~p", [Msg]),
    {noreply, State}.

handle_info(settings_update, State) ->
    ?log_debug("Settings have changed or this is the first start"),
    misc:flush(settings_update),
    %% We don't want to call refresh immediately because it will trigger
    %% metadata request on all the nodes simultaneously, which is not great
    Delay = rand:uniform(?MIN_REFRESH_INTERVAL),
    {noreply, restart_refresh_timer(Delay, State)};

handle_info(refresh, State) ->
    misc:flush(refresh),
    NextUpdateDT = refresh_metadata(),
    Time =
        case NextUpdateDT of
            undefined -> undefined;
            {_, _} ->
                CurrentDT = calendar:universal_time(),
                TimeS = calendar:datetime_to_gregorian_seconds(NextUpdateDT) -
                        calendar:datetime_to_gregorian_seconds(CurrentDT) +
                        1, %% Adding 1 second here to make sure medatadata has
                           %% already expired by the time when the timer fires

                %% We don't want to do 'refresh' too often
                max(TimeS * 1000, ?MIN_REFRESH_INTERVAL)
        end,
    {noreply, restart_refresh_timer(Time, State)};

handle_info(dupe_cleanup, State) ->
    misc:flush(dupe_cleanup),
    remove_expired_assertions(),
    {noreply, restart_dupe_cleanup_timer(State)};

handle_info(Info, State) ->
    ?log_warning("Unhandled info: ~p", [Info]),
    {noreply, State}.

terminate(_Reason, _State) ->
    ok.

code_change(_OldVsn, State, _Extra) ->
    {ok, State}.

%%%===================================================================
%%% Internal functions
%%%===================================================================

metadata_expired(undefined) ->
    false;
metadata_expired(Datetime) ->
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

load_and_cache_idp_metadata(URL, Opts) ->
    {_, ExtraFPs} = proplists:get_value(trusted_fingerprints, Opts),
    ExtraFPsUsage = proplists:get_value(fingerprints_usage, Opts),
    FPs = case ExtraFPsUsage of
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
          end,
    case load_idp_metadata(URL, Opts, FPs) of
        {ok, {_, ParsedMeta}} ->
            save_fingerprints_from_metadata(Opts, ParsedMeta),
            RefreshDT = cache_idp_metadata(ParsedMeta, Opts),
            {ok, {RefreshDT, ParsedMeta}};
        {error, _} = Error ->
            Error
    end.

parse_metadata(XmlBin, Verify) when is_binary(XmlBin) ->
    XmlStr = binary_to_list(XmlBin),
    Xml = try xmerl_scan:string(XmlStr, [{namespace_conformant, true}]) of
              {X, _} -> X
          catch
              _:_ -> throw({invalid_xml, XmlStr})
          end,

    case Verify of
        {verify, FPs} ->
            try xmerl_dsig:verify(Xml, FPs) of
                ok -> ok;
                {error, Reason2} ->
                    throw({md_signature_verification_failed, Reason2})
            catch
                _:Reason2:ST2 ->
                    ?log_error("xmerl_dsig:verify crashed with reason:~n~p"
                               "~nfor metadata:~n~p with FPs:~n~p~n~p",
                               [Reason2, Xml, FPs, ST2]),
                    throw({md_signature_verification_failed, unknown})
            end;
        false -> ok
    end,

    try esaml:decode_idp_metadata(Xml) of
        {ok, Meta} -> Meta;
        {error, Reason3} -> throw({bad_metadata, Reason3})
    catch
        _:Reason3:ST3 ->
            ?log_error("metadata decode crashed with reason:~n~p~n"
                       "for metadata:~n~p:~n~p",
                       [Reason3, Xml, ST3]),
            throw({bad_metadata, unknown})
    end.

metadata_expiration(#esaml_idp_metadata{valid_until = ValidUntilExpiration,
                                        cache_duration = CacheDurationDur},
                    Opts) ->
    %% We only set expiration if we can update metadata, otherwise it doesn't
    %% make much sense
    case can_reload_metadata(Opts) of
        true ->
            CacheDurationExpiration =
                case CacheDurationDur of
                    undefined -> undefined;
                    DurProps when is_list(DurProps) ->
                        NowDT = calendar:universal_time(),
                        datetime_add_interval(NowDT, DurProps)
                end,
            min_if_defined([ValidUntilExpiration, CacheDurationExpiration]);
        false ->
            undefined
    end.

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

should_refresh_metadata(CurrentDT, Props) ->
    case can_refresh_metadata(Props) of
        true ->
            Uuid = proplists:get_value(uuid, Props),
            case ets:lookup(?MODULE, metadata) of
                [{metadata, {Uuid, RefreshDT, _Exp, _Meta}}]
                                                when RefreshDT /= undefined,
                                                     CurrentDT >= RefreshDT ->
                    now;
                [{metadata, {Uuid, RefreshDT, _Exp, _Meta}}]
                                                when RefreshDT /= undefined ->
                    {at, RefreshDT};
                [{metadata, {_OtherUuid, _RefreshDT, _Exp, _Meta}}] ->
                    {at, undefined};
                [] ->
                    now
            end;
        false ->
            {at, undefined}
    end.

refresh_metadata() ->
    ?log_debug("Refreshing metadata"),
    CurrentDT = calendar:universal_time(),
    Props = ns_config:read_key_fast(sso_settings, []),
    case proplists:get_bool(enabled, Props) of
        true ->
            Props2 = misc:update_proplist(menelaus_web_saml:defaults(), Props),
            case should_refresh_metadata(CurrentDT, Props2) of
                now ->
                    ?log_debug("Refreshing saml metadata"),
                    URL = proplists:get_value(idp_metadata_url, Props2),
                    case load_and_cache_idp_metadata(URL, Props2) of
                        {ok, {RefreshDT, _Meta}} ->
                            RefreshDT;
                        {error, _} ->
                            CurrentDT
                    end;
                {at, RefreshDT} ->
                    RefreshDT
            end;
        false ->
            undefined
    end.

can_reload_metadata(Opts) ->
    http == proplists:get_value(idp_metadata_origin, Opts).

can_refresh_metadata(Opts) ->
    case can_reload_metadata(Opts) of
        true ->
            I = proplists:get_value(idp_metadata_refresh_interval, Opts),
            is_number(I) andalso (I > 0);
        false ->
            false
    end.

save_fingerprints_from_metadata(Opts, Meta) ->
    Fingerprints = extract_fingerprints(Meta, Opts),
    %% Most of the time fingerprints will stay the same. We don't want
    %% save it in this case in order to avoid ns_config_events updates,
    %% and unnecessary replications.
    ns_config:run_txn(
      fun (OldCfg, SetFun) ->
          Cur = ns_config:search(OldCfg, saml_sign_fingerprints,
                                 undefined),
          case Cur == Fingerprints of
              true ->
                  {abort, same};
              false ->
                  {commit, SetFun(saml_sign_fingerprints,
                                  Fingerprints, OldCfg)}
          end
      end).

restart_refresh_timer(Time, #s{refresh_timer_ref = TimerRef} = State) ->
    catch erlang:cancel_timer(TimerRef),
    NewRef = case Time of
                 undefined ->
                    ?log_debug("Disabling refresh timer"),
                    undefined;
                 _ ->
                    ?log_debug("Restarting refresh timer: ~p ms", [Time]),
                    erlang:send_after(Time, self(), refresh)
             end,
    State#s{refresh_timer_ref = NewRef}.

restart_dupe_cleanup_timer(#s{dupe_cleanup_timer_ref = TimerRef} = State) ->
    catch erlang:cancel_timer(TimerRef),
    NewRef = erlang:send_after(?DUPE_CLEANUP_INTERVAL, self(), dupe_cleanup),
    State#s{dupe_cleanup_timer_ref = NewRef}.

%% We don't expect the number of successfull authentications via saml to be
%% huge (as it is meant to be used for UI only and by humans only), so we
%% simply check every record here.
remove_expired_assertions() ->
    Now = calendar:datetime_to_gregorian_seconds(calendar:universal_time()),
    N = ets:select_delete(?DUPE_ETS, [{{'_', '$1'},
                                      [{'<', '$1', Now}],
                                      [true]}]),
    case N > 0 of
        true -> ?log_debug("Removed ~p records from saml dupe table", [N]);
        false -> ok
    end.
