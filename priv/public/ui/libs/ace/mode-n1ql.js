(function() {

  //
  // some globals used by both the highlighter and the autocompleter
  //

  var keywords = (
      "ADVISE|ALL|ALTER|ANALYZE|AND|ANY|ARRAY|AS|ASC|BEGIN|BETWEEN|BINARY|BOOLEAN|BREAK|BUCKET|BUILD|BY|CALL|CASE|CAST|CLUSTER|COLLATE|COLLECTION|COMMIT|CONNECT|CONTINUE|CORRELATED|CORRELATE|COVER|CREATE|CURRENT|DATABASE|DATASET|DATASTORE|DECLARE|DECREMENT|DELETE|DERIVED|DESC|DESCRIBE|DISTINCT|DO|DROP|EACH|ELEMENT|ELSE|END|EVERY|EXCEPT|EXCLUDE|EXECUTE|EXISTS|EXPLAIN|FETCH|FIRST|FLATTEN|FOLLOWING|FOR|FORCE|FROM|FTS|FUNCTION|GOLANG|GRANT|GROUP|GROUPS|GSI|HASH|HAVING|IF|IGNORE|ILIKE|IN|INCLUDE|INCREMENT|INDEX|INFER|INLINE|INNER|INSERT|INTERSECT|INTO|IS|JAVASCRIPT|JOIN|KEY|KEYS|KEYSPACE|KNOWN|LANGUAGE|LAST|LEFT|LET|LETTING|LIKE|LIMIT|LSM|MAP|MAPPING|MATCHED|MATERIALIZED|MERGE|MINUS|MISSING|NAMESPACE|NAMESPACE_ID|NEST|NL|NO|NOT|NOT_A_TOKEN|NTH_VALUE|NULL|NULLS|NUMBER|OBJECT|OFFSET|ON|OPTION|OR|ORDER|OTHERS|OUTER|OVER|PARSE|PARTITION|PASSWORD|PATH|POOL|PRECEDING|PREPARE|PRIMARY|PRIVATE|PRIVILEGE|PROBE|PROCEDURE|PUBLIC|RANGE|RAW|REALM|REDUCE|RENAME|RESPECT|RETURN|RETURNING|REVOKE|RIGHT|ROLE|ROLLBACK|ROW|ROWS|SATISFIES|SCHEMA|SELECT|SELF|SEMI|SET|SHOW|SOME|START|STATISTICS|STRING|SYSTEM|THEN|TIES|TO|TRANSACTION|TRIGGER|TRUNCATE|UNBOUNDED|UNDER|UNION|UNIQUE|UNKNOWN|UNNEST|UNSET|UPDATE|UPSERT|USE|USER|USING|VALIDATE|VALUE|VALUED|VALUES|VIA|VIEW|WHEN|WHERE|WHILE|WITH|WITHIN|WORK|XOR"
  );
  var keywords_array = keywords.split('|');

  var sysCatalogs = (
      "system:active_requests|system:applicable_roles|system:completed_requests|system:datastores|system:dual|system:functions|system:functions_cache|system:indexes|system:keyspaces|system:my_user_info|system:namespaces|system:nodes|system:prepareds|system:user_info"
  );
  var sysCatalogs_array = sysCatalogs.split('|');

  var roles = (
      "ADMIN|RO_ADMIN|CLUSTER_ADMIN|BUCKET_ADMIN|BUCKET_ADMIN|BUCKET_ADMIN|BUCKET_ADMIN|BUCKET_ADMIN|BUCKET_SASL|BUCKET_SASL|BUCKET_SASL|BUCKET_SASL|BUCKET_SASL|VIEWS_ADMIN|VIEWS_ADMIN|VIEWS_ADMIN|VIEWS_ADMIN|VIEWS_ADMIN|REPLICATION_ADMIN|DATA_READER|DATA_READER|DATA_READER|DATA_READER|DATA_READER|DATA_READER_WRITER|DATA_READER_WRITER|DATA_READER_WRITER|DATA_READER_WRITER|DATA_READER_WRITER|DATA_DCP_READER|DATA_DCP_READER|DATA_DCP_READER|DATA_DCP_READER|DATA_DCP_READER|DATA_BACKUP|DATA_BACKUP|DATA_BACKUP|DATA_BACKUP|DATA_BACKUP|DATA_MONITORING|DATA_MONITORING|DATA_MONITORING|DATA_MONITORING|DATA_MONITORING|FTS_ADMIN|FTS_ADMIN|FTS_ADMIN|FTS_ADMIN|FTS_ADMIN|FTS_SEARCHER|FTS_SEARCHER|FTS_SEARCHER|FTS_SEARCHER|FTS_SEARCHER|QUERY_SELECT|QUERY_SELECT|QUERY_SELECT|QUERY_SELECT|QUERY_SELECT|QUERY_UPDATE|QUERY_UPDATE|QUERY_UPDATE|QUERY_UPDATE|QUERY_UPDATE|QUERY_INSERT|QUERY_INSERT|QUERY_INSERT|QUERY_INSERT|QUERY_INSERT|QUERY_DELETE|QUERY_DELETE|QUERY_DELETE|QUERY_DELETE|QUERY_DELETE|QUERY_MANAGE_INDEX|QUERY_MANAGE_INDEX|QUERY_MANAGE_INDEX|QUERY_MANAGE_INDEX|QUERY_MANAGE_INDEX|QUERY_SYSTEM_CATALOG|QUERY_EXTERNAL_ACCESS"
  );
  var roles_array = roles.split('|');

  var builtinConstants = (
      "TRUE|FALSE|INDEXES|KEYSPACES"
  );
  var builtinConstants_array = builtinConstants.split('|');

  // this list of functions should be updated w.r.t. https://github.com/couchbase/query/blob/master/expression/func_registry.go
  var builtinFunctions = (
      "ABS|ACOS|ARRAY_AGG|ARRAY_APPEND|ARRAY_AVG|ARRAY_CONCAT|ARRAY_CONTAINS|ARRAY_COUNT|ARRAY_DISTINCT|ARRAY_IFNULL|ARRAY_LENGTH|ARRAY_MAX|ARRAY_MIN|ARRAY_POSITION|ARRAY_PREPEND|ARRAY_PUT|ARRAY_RANGE|ARRAY_REMOVE|ARRAY_REPEAT|ARRAY_REPLACE|ARRAY_REVERSE|ARRAY_SORT|ARRAY_SUM|ASIN|ATAN|ATAN2|AVG|BASE64|CEIL|CLOCK_MILLIS|CLOCK_STR|CONTAINS|COS|COUNT|DATE_ADD_MILLIS|DATE_ADD_STR|DATE_DIFF_MILLIS|DATE_DIFF_STR|DATE_PART_MILLIS|DATE_PART_STR|DATE_TRUNC_MILLIS|DATE_TRUNC_STR|DECODE_JSON|DEGREES|ENCODE_JSON|ENCODED_SIZE|EXP|FLOOR|GREATEST|IFINF|IFMISSING|IFMISSINGORNULL|IFNAN|IFNANORINF|IFNULL|INITCAP|IS_ARRAY|IS_ATOM|IS_BOOLEAN|IS_NUMBER|IS_OBJECT|IS_STRING|LEAST|LENGTH|LN|LOG|LOWER|LTRIM|MAX|META|MILLIS|MILLIS_TO_STR|MILLIS_TO_UTC|MILLIS_TO_ZONE_NAME|MIN|MISSINGIF|NANIF|NEGINFIF|NOW_MILLIS|NOW_STR|NULLIF|OBJECT_LENGTH|OBJECT_NAMES|OBJECT_PAIRS|OBJECT_REMOVE|OBJECT_VALUES|PI|POLY_LENGTH|POSINFIF|POSITION|POWER|RADIANS|RANDOM|REGEXP_CONTAINS|REGEXP_LIKE|REGEXP_POSITION|REGEXP_REPLACE|REPEAT|REPLACE|ROUND|RTRIM|SIGN|SIN|SPLIT|SQRT|STR_TO_MILLIS|STR_TO_UTC|STR_TO_ZONE_NAME|SUBSTR|SUM|TAN|TITLE|TO_ARRAY|TO_ATOM|TO_BOOLEAN|TO_NUMBER|TO_OBJECT|TO_STRING|TRIM|TRUNC|TYPE|UPPER|UUID"
  );
  var builtinFunctions_array = builtinFunctions.split('|');

  //
  // put all categories of keywords in one data structure we can traverse
  //

  var terms = [
    {name:"keyword", tokens: keywords_array},
    {name:"built-in", tokens: builtinConstants_array},
    {name:"function", tokens: builtinFunctions_array},
    {name:"role", tokens: roles_array},
    {name:"system-catalog", tokens: sysCatalogs_array}
    ];

  //
  // language tokens
  //

  define("ace/mode/n1ql_highlight_rules",["require","exports","module","ace/lib/oop","ace/mode/text_highlight_rules"],
      function(require, exports, module) {
    "use strict";

    var oop = require("../lib/oop");
    var TextHighlightRules = require("./text_highlight_rules").TextHighlightRules;

    var N1qlHighlightRules = function() {

      var keywordMapper = this.createKeywordMapper({
        "support.function": builtinFunctions,
        "keyword": keywords,
        "constant.language": builtinConstants,
        "storage.type": roles
      }, "identifier", true);

      this.$rules = {
          "start" : [ {
            token : "comment",
            start : "/\\*",
            end : "\\*/"
          }, {
            token : "constant.numeric",   // " string, make blue like numbers
            regex : '".*?"'
          }, {
            token : "constant.numeric",   // ' string, make blue like numbers
            regex : "'.*?'"
          }, {
            token : "identifier",         // ` quoted identifier, make like identifiers
            regex : "[`](([`][`])|[^`])+[`]"
          }, {
            token : "constant.numeric",   // float
            regex : "[+-]?\\d+(?:(?:\\.\\d*)?(?:[eE][+-]?\\d+)?)?\\b"
          }, {
            token : keywordMapper,
            regex : "[a-zA-Z_$][a-zA-Z0-9_$]*\\b"
          }, {
            token : "keyword.operator",
            regex : "\\+|\\-|\\/|\\/\\/|%|<@>|@>|<@|&|\\^|~|<|>|<=|=>|==|!=|<>|="
          }, {
            token : "paren.lparen",
            regex : "[\\(]"
          }, {
            token : "paren.rparen",
            regex : "[\\)]"
          }, {
            token : "text",
            regex : "\\s+"
          } ]
      };
      this.normalizeRules();
    };

    oop.inherits(N1qlHighlightRules, TextHighlightRules);

    exports.N1qlHighlightRules = N1qlHighlightRules;
  });


  /*
   * Define the N1QL mode
   */

  define("ace/mode/n1ql_completions",["require","exports","module","ace/token_iterator"], function(require, exports, module) {
    "use strict";

    var TokenIterator = require("../token_iterator").TokenIterator;


    function is(token, type) {
      return token.type.lastIndexOf(type + ".xml") > -1;
    }

    function findTagName(session, pos) {
      var iterator = new TokenIterator(session, pos.row, pos.column);
      var token = iterator.getCurrentToken();
      while (token && !is(token, "tag-name")){
        token = iterator.stepBackward();
      }
      if (token)
        return token.value;
    }

    var N1qlCompletions = function() {
    };

    (function() {

      this.getCompletions = function(state, session, pos, prefix) {
        var token = session.getTokenAt(pos.row, pos.column);

        // return anything matching from the terms structure

        var results = [];
        var prefix_upper = prefix.toLocaleUpperCase();

        for (var i=0; i<terms.length; i++)
          for (var t=0; t<terms[i].tokens.length; t++)
            if (_.startsWith(terms[i].tokens[t].toLocaleUpperCase(),prefix_upper))
              results.push({value: terms[i].tokens[t], meta: terms[i].name, score: 1});

        return results;
      };


    }).call(N1qlCompletions.prototype);

    exports.N1qlCompletions = N1qlCompletions;
  });

  define("ace/mode/n1ql",["require","exports","module","ace/lib/oop","ace/mode/text","ace/mode/n1ql_highlight_rules",
    "ace/mode/query-formatter"],
      function(require, exports, module) {
    "use strict";

    var oop = require("../lib/oop");
    var TextMode = require("./text").Mode;
    var N1qlHighlightRules = require("./n1ql_highlight_rules").N1qlHighlightRules;
    var N1qlCompletions = require("./n1ql_completions").N1qlCompletions;

    //////////////////////////////////////////////////////////////////////////////////////
    // build a N1QL formatter from the more generic formatter package
    //
    // it needs to know keywords or function names (to be upper cased)
    //////////////////////////////////////////////////////////////////////////////////////

    // certain keywords will get formatted onto their own line, some with indenting
    var kw_regex_str = '\\b(?:' + sysCatalogs + ')|\\b(' + keywords + '|' + roles + '|' + builtinConstants + ')\\b';
    var function_regex_str = '\\b(' + builtinFunctions + ')\\s*\\(';

    var formatter = require("ace/mode/query-formatter").create(kw_regex_str,function_regex_str);

    /////////////////////////////////////////////////////////////////////////

    var Mode = function() {
      this.HighlightRules = N1qlHighlightRules;
      this.$completer = new N1qlCompletions();
      this.format = formatter;
    };
    oop.inherits(Mode, TextMode);

    (function() {

      this.getCompletions = function(state, session, pos, prefix) {
        return this.$completer.getCompletions(state, session, pos, prefix);
      };

      this.$id = "ace/mode/n1ql";
    }).call(Mode.prototype);

    exports.Mode = Mode;
    exports.Instance = new Mode();

  });

})();
