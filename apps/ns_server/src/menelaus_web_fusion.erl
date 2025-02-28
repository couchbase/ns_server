%% @author Couchbase <info@couchbase.com>
%% @copyright 2025-Present Couchbase, Inc.
%%
%% Use of this software is governed by the Business Source License included in
%% the file licenses/BSL-Couchbase.txt.  As of the Change Date specified in that
%% file, in accordance with the Business Source License, use of this software
%% will be governed by the Apache License, Version 2.0, included in the file
%% licenses/APL2.txt.
%%

%% @doc implementation of fusion REST API's

-module(menelaus_web_fusion).

-include_lib("ns_common/include/cut.hrl").

-export([handle_prepare_rebalance/1]).

handle_prepare_rebalance(Req) ->
    menelaus_util:assert_is_enterprise(),
    menelaus_util:assert_is_morpheus(),
    NodeValidator =
        fun (String) ->
                try {value, list_to_existing_atom(String)}
                catch error:badarg -> {error, "Unknown node"} end
        end,
    validator:handle(
      fun (Params) ->
              KeepNodes = proplists:get_value(keepNodes, Params),
              Options = [{local_addr, menelaus_util:local_addr(Req)}],
              case ns_orchestrator:prepare_fusion_rebalance(
                     KeepNodes, Options) of
                  {ok, AccelerationPlan} ->
                      menelaus_util:reply_json(Req, AccelerationPlan, 200);
                  {unknown_nodes, Nodes} ->
                      validator:report_errors_for_one(
                        Req,
                        [{keepNodes,
                          io_lib:format("Unknown nodes ~p", [Nodes])}], 400);
                  Other ->
                      menelaus_util:reply_text(
                        Req, io_lib:format("Unknown error ~p", [Other]), 500)
              end
      end, Req, form,
      [validator:required(keepNodes, _),
       validator:token_list(keepNodes, ",", NodeValidator, _),
       validator:unsupported(_)]).
