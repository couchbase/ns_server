(function() {

  //
  // some globals used by both the highlighter and the autocompleter
  //

  var keywords = (
      "ALL|ALTER|ANALYZE|AND|ANY|ARRAY|AS|ASC|BEGIN|BETWEEN|BINARY|BOOLEAN|BREAK|BUCKET|BUILD|BY|CALL|CASE|CAST|CLUSTER|COLLATE|COLLECTION|COMMIT|CONNECT|CONTINUE|CORRELATE|CREATE|DATABASE|DATASET|DATASTORE|DECLARE|DECREMENT|DELETE|DERIVED|DESC|DESCRIBE|DISTINCT|DO|DROP|EACH|ELEMENT|ELSE|END|EVERY|EXCEPT|EXCLUDE|EXECUTE|EXISTS|EXPLAIN|FIRST|FLATTEN|FOR|FORCE|FROM|FUNCTION|GRANT|GROUP|GSI|HASH|HAVING|IF|IGNORE|ILIKE|IN|INCLUDE|INCREMENT|INDEX|INFER|INLINE|INNER|INSERT|INTERSECT|INTO|IS|JOIN|KEY|KEYS|KEYSPACE|LAST|LEFT|LET|LETTING|LIKE|LIMIT|LSM|MAP|MAPPING|MATCHED|MATERIALIZED|MERGE|MINUS|MISSING|NAMESPACE|NEST|NOT|NULL|NUMBER|OBJECT|OFFSET|ON|OPTION|OR|ORDER|OUTER|OVER|PARSE|PARTITION|PASSWORD|PATH|POOL|PREPARE|PRIMARY|PRIVATE|PRIVILEGE|PROCEDURE|PUBLIC|RAW|REALM|REDUCE|RENAME|RETURN|RETURNING|REVOKE|RIGHT|ROLE|ROLLBACK|SATISFIES|SCHEMA|SELECT|SELF|SEMI|SET|SHOW|SOME|START|STATISTICS|STRING|THEN|TO|TRANSACTION|TRIGGER|TRUNCATE|UNDER|UNION|UNIQUE|UNNEST|UNSET|UPDATE|UPSERT|USE|USER|USING|VALIDATE|VALUE|VALUED|VALUES|VIA|VIEW|WHEN|WHERE|WHILE|WITH|WITHIN|WORK|XOR"
  );
  var keywords_array = keywords.split('|');

  var sysCatalogs = (
      "system:datastores|system:namespaces|system:keyspaces|system:indexes|system:dual|system:user_info|system:my_user_info|system:nodes|system:applicable_roles|system:prepareds|system:completed_requests|system:active_requests"
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

  define("ace/mode/n1ql",["require","exports","module","ace/lib/oop","ace/mode/text","ace/mode/n1ql_highlight_rules","ace/range"],
      function(require, exports, module) {
    "use strict";

    var oop = require("../lib/oop");
    var TextMode = require("./text").Mode;
    var N1qlHighlightRules = require("./n1ql_highlight_rules").N1qlHighlightRules;
    var N1qlCompletions = require("./n1ql_completions").N1qlCompletions;
    var Range = require("../range").Range;

    //////////////////////////////////////////////////////////////////////////////////////
    // format N1QL queries. Code borrowed and extended from vkbeautify
    //////////////////////////////////////////////////////////////////////////////////////

    // certain keywords will get formatted onto their own line, some with indenting
    var newline_before = "SELECT|FROM|WHERE|GROUP BY|HAVING|ORDER|LIMIT";
    var newline_before_and_after = "UNION";
    var newline_before_plus_indent = "AND|OR|JOIN|SET|LET";
    var newline_before_plus_2_indent = "THEN|WHEN|ELSE";

    var newline_keywords = newline_before + '|' + newline_before_and_after + '|' + newline_before_plus_indent
    + '|' + newline_before_plus_2_indent;

    // regexes must ignore keywords inside strings or comments, make a prefix to match strings or comments
    var prefix = "\"(?:[^\"\\\\]|\\\\.)*\"|'(?:[^'\\\\]|\\\\.)*'|(?:\\/\\*[\\s\\S]*?\\*\\/)|`(?:[^`])*`"

      // we want to detect all keywords above, so make a regex that matches them
      var match_string = new RegExp(prefix,'ig');
    var newline_before_regex = new RegExp(prefix + '|\\b(' + newline_before + ')\\b','ig');
    var newline_before_and_after_regex = new RegExp(prefix + '|\\b(' + newline_before_and_after + ')\\b','ig');
    var newline_before_plus_indent_regex = new RegExp(prefix + '|\\b(' + newline_before_plus_indent + '|\\s{0,}\\(\\s{0,}SELECT\\s{0,})\\b','ig');
    var newline_before_plus_2_indent_regex = new RegExp(prefix + '|\\b(' + newline_before_plus_2_indent + ')\\b','ig');

    var kw_regex_str = prefix + '|\\b(?:' + sysCatalogs + ')|\\b(' + keywords + '|' + roles + '|' + builtinConstants + '|' + builtinFunctions + ')\\b';
    var kw_regex = new RegExp(kw_regex_str,'ig');

    var comma_not_in_parens_regex = /(?:\([^\)]*\))|(\,)/ig;

    //
    //
    //

    function createShiftArr(step) {

      var space = '    ';

      if ( isNaN(parseInt(step)) ) {  // argument is string
        space = step;
      } else { // argument is integer
        switch(step) {
        case 1: space = ' '; break;
        case 2: space = '  '; break;
        case 3: space = '   '; break;
        case 4: space = '    '; break;
        case 5: space = '     '; break;
        case 6: space = '      '; break;
        case 7: space = '       '; break;
        case 8: space = '        '; break;
        case 9: space = '         '; break;
        case 10: space = '          '; break;
        case 11: space = '           '; break;
        case 12: space = '            '; break;
        }
      }

      var shift = ['\n']; // array of shifts
      for(var ix=0;ix<100;ix++){
        shift.push(shift[ix]+space);
      }
      return shift;
    }

    function isSubquery(str, parenthesisLevel) {
      return  parenthesisLevel - (str.replace(/\(/g,'').length - str.replace(/\)/g,'').length )
    }

    //
    // if we have commas delimiting projection lists, let statements, etc, we want a newline
    // and indentation after each comma. But we don't want newlines for comma-delimited items in function
    // calls, e.g. max(a,b,c)
    //

    function replace_top_level_commas(text,tab,parenDepth) {
      var items = [];
      var start = 0;

      for (var i=0; i < text.length; i++) {
        switch (text.charAt(i)) {
        case '(': parenDepth.depth++; break;
        case ')': parenDepth.depth--; break;
        case ',':
          if (parenDepth.depth <= 0) {
            items.push((items.length ? tab : '') + text.substring(start,i+1));
            while (i++ < text.length && /\s/.exec(text.charAt(i))); // skip any whitespace after the comma
            start = i;
            i--; // don't overshoot
          }
          break;
        }
      }

      // get the last one
      items.push((items.length ? tab : '') + text.substring(start,text.length));
      return(items);
    }

    // split query into an array of lines, with strings separate entries so we won't try to
    // parse their contents
    function split_n1ql(str, tab) {

      var str2 = str.replace(/\s{1,}/g," "); // simplify whitespace to single spaces
      str2 = str2.replace(match_string, function(match) {return "~::~" + match + "~::~"});
      str2 = str2.replace(kw_regex, function(match,p1) {if (p1) return p1.toUpperCase(); else return match}); // upper case all keywords
      str2 = str2.replace(newline_before_regex, function(match,p1) {if (p1) return "~::~" + p1; else return match});
      str2 = str2.replace(newline_before_and_after_regex, function(match,p1) {if (p1) return "~::~" + p1 + "~::~"; else return match});
      str2 = str2.replace(newline_before_plus_indent_regex, function(match,p1) {if (p1) return "~::~" + tab + p1; else return match});
      str2 = str2.replace(newline_before_plus_2_indent_regex, function(match,p1) {if (p1) return "~::~" + tab + tab + p1; else return match});
      str2 = str2.replace(/~::~w{1,}/g,"~::~"); // remove blank lines
      str2 = str2.replace(/~::~ /ig,'~::~');

      // get an array of lines, based on the above breaks, then make a new array where we also split on comma-delimited lists
      var arr =  str2.split('~::~');
      var arr2 = [];

      var lastWasSpecial = false;
      var parenDepth = {depth:0};
      arr.forEach(function (s) {
        if (isSpecialString(s)) { // special strings don't get new lines
          arr2.push(s);
          lastWasSpecial = true;
        }
        else {
          if (!lastWasSpecial)
            parenDepth.depth = 0; // reset paren depth for a new line
          arr2 = arr2.concat(replace_top_level_commas(s,tab,parenDepth));
          lastWasSpecial = false;
        }
      });

      return(arr2);
    }

    // some text is special: comments, quoted strings, and we don't want to look inside them for formatting
    function isSpecialString(str) {
      return((str.startsWith('"') || str.startsWith("'") ||
            (str.startsWith('/*') && str.endsWith('*/')) ||
            (str.startsWith('`') && str.endsWith('`'))));
    }

    //
    // format a N1QL string
    //

    function n1ql(text,step) {

      var tab = this.step,
      ar = split_n1ql(text,tab),
      deep = 0,
      parenthesisLevel = 0,
      str = '',
      ix = 0,
      shift = step ? createShiftArr(step) : this.shift;

      // loop through the array of query elements.
      // Some will be strings, so we will just add those to the query string
      // Others need to be checked for nesting level
      var len = ar.length;
      var prev_was_string = false;

      for(ix=0;ix<len;ix++) {
        // remove blank lines
        if (ar[ix].trim().length == 0)
          continue;

        // handle strings and comments and literal identifiers
        if (isSpecialString(ar[ix])) {
          str += ar[ix];
          prev_was_string = true;
          continue;
        }

        // strings got put into separate array elements, so we could avoid parsing them
        // usually that means no newline after strings, unless the string matches a keyword that requires one
        var force_newline = newline_before_regex.exec(ar[ix]) || newline_before_and_after_regex.exec(ar[ix]) ||
          newline_before_plus_indent_regex.exec(ar[ix]) || newline_before_plus_indent_regex.exec(ar[ix]);
        //console.log("Got line: " + ar[ix] + ', prev: ' + prev_was_string + ", force: " + JSON.stringify(force_newline));
        if (prev_was_string && !force_newline)
          str += (ar[ix].startsWith(',') ? '':' ') + ar[ix];
        else
          str += shift[parenthesisLevel]+ar[ix];

        // see if nesting is going up or down.
        parenthesisLevel = isSubquery(ar[ix], parenthesisLevel);

        prev_was_string = false;
      }

      str = str.replace(/^\n{1,}/,'').replace(/\n{1,}/g,"\n");
      return str;
    }

    //////////////////////////////////////////////////////////////////////////////////////

    var Mode = function() {
      this.HighlightRules = N1qlHighlightRules;
      this.$completer = new N1qlCompletions();
      this.step = '  '; // 2 spaces
      this.shift = createShiftArr(this.step);
      this.format = n1ql;
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
