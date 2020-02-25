%% @author Couchbase <info@couchbase.com>
%% @copyright 2010-2020 Couchbase, Inc.
%%
%% Licensed under the Apache License, Version 2.0 (the "License");
%% you may not use this file except in compliance with the License.
%% You may obtain a copy of the License at
%%
%%      http://www.apache.org/licenses/LICENSE-2.0
%%
%% Unless required by applicable law or agreed to in writing, software
%% distributed under the License is distributed on an "AS IS" BASIS,
%% WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
%% See the License for the specific language governing permissions and
%% limitations under the License.

-define(assertListsEqual(Expect, Expr),
        (fun () ->
                 __X = lists:sort(Expect),
                 case lists:sort(Expr) of
                     __X -> ok;
                     __V -> erlang:error({assertListsEqual,
                                          [{module, ?MODULE},
                                           {line, ?LINE},
                                           {expression, (??Expr)},
                                           {missing, __X -- __V},
                                           {extra, __V -- __X}]})
                 end
         end)()).

-define(_assertListsEqual(Expect, Expr),
        ?_test(?assertListsEqual(Expect, Expr))).
