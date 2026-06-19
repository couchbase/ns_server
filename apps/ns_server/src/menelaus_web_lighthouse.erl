%% @author Couchbase <info@couchbase.com>
%% @copyright 2026-Present Couchbase, Inc.
%%
%% Use of this software is governed by the Business Source License included in
%% the file licenses/BSL-Couchbase.txt.  As of the Change Date specified in that
%% file, in accordance with the Business Source License, use of this software
%% will be governed by the Apache License, Version 2.0, included in the file
%% licenses/APL2.txt.

%% @doc Internal REST API for configuring lighthouse reporting

-module(menelaus_web_lighthouse).

-include_lib("ns_common/include/cut.hrl").


%% API
-export([handle_get_settings/2,
         handle_post_settings/2,
         handle_ingest/1]).

%%%===================================================================
%%% API
%%%===================================================================

params_internal() ->
    [{"enabled",
      #{cfg_key => reporting_enabled, type => bool}},
     {"endpoint",
      #{cfg_key => reporting_endpoint, type => endpoint}},
     {"reportIntervalHours",
      #{cfg_key => reporting_interval_hours, type => pos_int}},
     {"reportTimeoutSeconds",
      #{cfg_key => reporting_timeout_seconds, type => pos_int}},
     {"externalNodesMaxPayloadBytes",
      #{cfg_key => external_nodes_max_payload_bytes, type => int}},
     {"externalNodesMaxCount",
      #{cfg_key => external_nodes_max_count, type => int}}].

type_spec(endpoint) ->
    #{validators => [string, validate_endpoint()]}.

validate_endpoint() ->
    validator:validate(
      fun (Endpoint) ->
              case misc:is_valid_hostname(Endpoint) of
                  true -> {value, list_to_binary(Endpoint)};
                  false -> {error, "invalid hostname"}
              end
      end, _, _).

handle_get_settings(Path, Req) ->
    Settings = maps:to_list(lighthouse_reporter:build_settings()),
    menelaus_web_settings2:handle_get(Path, params_internal(), fun type_spec/1,
                                      Settings, Req).

handle_post_settings(Path, Req) ->
    menelaus_web_settings2:handle_post(
      apply_props(Path, _, _), Path, params_internal(), fun type_spec/1, Req).

apply_props(Path, NewProps, Req) ->
    OldProps = maps:to_list(lighthouse_reporter:build_settings()),
    MergedProps = menelaus_web_settings2:apply_changes(OldProps, NewProps),
    ns_config:set(lighthouse_reporter:config_key(),
                  maps:from_list(MergedProps)),
    handle_get_settings(Path, Req).

handle_ingest(Req) ->
    validator:handle(
      fun (Params) ->
              Opts = maps:from_list(Params),
              validator:handle(
                fun (Payload) ->
                        PayloadEncoded = ejson:encode({Payload}),
                        case lighthouse_reporter:ingest(Opts, PayloadEncoded) of
                            ok ->
                                %% Respond with 204 (No Content), consistent
                                %% with the lighthouse portal itself
                                menelaus_util:reply(Req, 204);
                            {error, too_many_payloads} ->
                                menelaus_util:reply(Req, 507)
                        end
                end, Req, json, [],
                lighthouse_reporter:max_external_payload_size())
      end, Req, qs, ingest_validators()).

ingest_validators() ->
    [validator:required(product_name, _),
     validator:string(product_name, _),
     validator:required(instance_id, _),
     validator:string(instance_id, _)].
