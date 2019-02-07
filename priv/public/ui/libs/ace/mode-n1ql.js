(function() {

  //
  // some globals used by both the highlighter and the autocompleter
  //

  var keywords = (
      "ALL|ALTER|ANALYZE|AND|ANY|ARRAY|AS|ASC|BEGIN|BETWEEN|BINARY|BOOLEAN|BREAK|BUCKET|BUILD|BY|CALL|CASE|CAST|CLUSTER|COLLATE|COLLECTION|COMMIT|CONNECT|CONTINUE|CORRELATE|CREATE|CURRENT|DATABASE|DATASET|DATASTORE|DECLARE|DECREMENT|DELETE|DERIVED|DESC|DESCRIBE|DISTINCT|DO|DROP|EACH|ELEMENT|ELSE|END|EVERY|EXCEPT|EXCLUDE|EXECUTE|EXISTS|EXPLAIN|FIRST|FLATTEN|FOLLOWING|FOR|FORCE|FROM|FUNCTION|GRANT|GROUP|GROUPS|GSI|HASH|HAVING|IF|IGNORE|ILIKE|IN|INCLUDE|INCREMENT|INDEX|INFER|INLINE|INNER|INSERT|INTERSECT|INTO|IS|JOIN|KEY|KEYS|KEYSPACE|LAST|LEFT|LET|LETTING|LIKE|LIMIT|LSM|MAP|MAPPING|MATCHED|MATERIALIZED|MERGE|MINUS|MISSING|NAMESPACE|NEST|NO|NOT|NTH_VALUE|NULL|NULLS|NUMBER|OBJECT|OFFSET|ON|OPTION|OR|ORDER|OTHERS|OUTER|OVER|PARSE|PARTITION|PASSWORD|PATH|POOL|PRECEDING|PREPARE|PRIMARY|PRIVATE|PRIVILEGE|PROCEDURE|PUBLIC|RANGE|RAW|REALM|REDUCE|RENAME|RESPECT|RETURN|RETURNING|REVOKE|RIGHT|ROLE|ROLLBACK|ROW|ROWS|SATISFIES|SCHEMA|SELECT|SELF|SEMI|SET|SHOW|SOME|START|STATISTICS|STRING|THEN|TIES|TO|TRANSACTION|TRIGGER|TRUNCATE|UNBOUNDED|UNDER|UNION|UNIQUE|UNNEST|UNSET|UPDATE|UPSERT|USE|USER|USING|VALIDATE|VALUE|VALUED|VALUES|VIA|VIEW|WHEN|WHERE|WHILE|WITH|WITHIN|WORK|XOR"
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
    //
    // Step 1: strip out newlines and extra spaces
    // Step 2: add back newlines before or after certain keywords (e.g. SELECT, WHERE...),
    //         this ensures that any nested subqueries are not on the line as their parent
    // Step 3: add further newlines in any top-level comma-delimited lists, e.g.
    //           select a, b, c from ...
    //         but *not*:
    //           select max(a,b)
    // Step 4: figure out indentation for each line. We will have a stack of indentations
    //           so that the indents will accumulate
    //         if a line increases the count of parentheses, we increase the indentation
    //         if a line ends in a comma, align subsequent lines with the first space on
    //          the first line with the comma
    //         if a line starts with a keyword needing extra indentation, indent that
    //          one line only
    //////////////////////////////////////////////////////////////////////////////////////

    // certain keywords will get formatted onto their own line, some with indenting
    var newline_before = "FROM|WHERE|GROUP BY|HAVING|OUTER JOIN|INNER JOIN|JOIN|LIMIT|ORDER BY|OFFSET|OUTER JOIN|ROWS|" +
    		"RANGE|GROUPS|EXCLUDE|UNNEST|SET|LET";
    var newline_before_and_after = "UNION";
    var newline_before_plus_indent = "AND|OR|JOIN";

    var newline_keywords = newline_before + '|' + newline_before_and_after + '|' + newline_before_plus_indent;

    // regexes must ignore keywords inside strings or comments, make a prefix to match strings or comments
    var prefix = "\"(?:[^\"\\\\]|\\\\.)*\"|'(?:[^'\\\\]|\\\\.)*'|(?:\\/\\*[\\s\\S]*?\\*\\/)|`(?:[^`])*`";

    // we want to detect all keywords above, so make a regex that matches them
    var match_string = new RegExp(prefix,'ig');
    var newline_before_regex =
      new RegExp(prefix +                       // ignore strings, comments, literal field names, etc.
          '|(?:\\bBETWEEN\\b.+?\\bAND\\b)' +    // don't want newline before AND in "BETWEEN ... AND"
          '|\\b(' + newline_before + '|' + newline_before_plus_indent + ')\\b','ig');
    var newline_before_and_after_regex = new RegExp(prefix + '|\\b(' + newline_before_and_after + ')\\b','ig');
    var newline_after_regex = /\bOVER[\s]*\(/ig;
    var newline_select_split_regex = /\([\s]*SELECT\b/ig;
    // we need an indent if the line starts with one of these
    var needs_indent_regex = new RegExp('^(' + newline_before_plus_indent + ')\\b','ig');

    var kw_regex_str = prefix + '|\\b(?:' + sysCatalogs + ')|\\b(' + keywords + '|' + roles + '|' + builtinConstants + ')\\b';
    var kw_regex = new RegExp(kw_regex_str,'ig');

    var function_regex_str = prefix + '|\\b(' + builtinFunctions + ')\\s*\\(';
    var function_regex = new RegExp(function_regex_str,'ig');

    var comma_not_in_parens_regex = /(?:\([^\)]*\))|(\,)/ig;

    //
    //
    //

    function isSubquery(str, parenthesisLevel) {
      return  parenthesisLevel - (str.replace(/\(/g,'').length - str.replace(/\)/g,'').length )
    }

    // some text is special: comments, quoted strings, and we don't want to look inside them for formatting
    function isSpecialString(str) {
      return((str.startsWith('"') || str.startsWith("'") ||
            (str.startsWith('/*') && str.endsWith('*/')) ||
            (str.startsWith('`') && str.endsWith('`'))));
    }

    //
    // if we have commas delimiting projection lists, let statements, etc, we want a newline
    // and indentation after each comma. But we don't want newlines for comma-delimited items in function
    // calls, e.g. max(a,b,c)
    //

    function replace_top_level_commas(text,tab,parenDepth) {
      var items = [];
      var start = 0;
      var indent = tab;

      for (var i=0; i < text.length; i++) {
        switch (text.charAt(i)) {
        case '(': parenDepth.depth++; break;
        case ')': parenDepth.depth--; break;
        case ',':
          if (parenDepth.depth <= 0) {
            items.push(text.substring(start,i+1));
            while (i++ < text.length && /\s/.exec(text.charAt(i))); // skip any whitespace after the comma
            start = i;
            i--; // don't overshoot
          }
          break;
        }
      }

      // get the last one
      items.push((items.length ? indent : '') + text.substring(start,text.length));
      return(items);
    }

    // split query into an array of lines, with strings separate entries so we won't try to
    // parse their contents
    function split_n1ql(str, tab, specials) {

      var str2 = str.replace(/\s{1,}/g," ");                                                  // simplify whitespace to single spaces
      str2 = str2.replace(match_string, function(match) {specials.push(match); return "^&&^"});
      str2 = str2.replace(kw_regex, function(match,p1) {if (p1) return p1.toUpperCase(); else return match}); // upper case all keywords
      str2 = str2.replace(function_regex, function(match,p1) {if (p1) return p1.toUpperCase() + '('; else return match}); // upper case all keywords
      str2 = str2.replace(newline_before_regex, function(match,p1) {if (p1) return "~::~" + p1; else return match});
      str2 = str2.replace(newline_before_and_after_regex, function(match,p1) {if (p1) return "~::~" + p1 + "~::~"; else return match});
      str2 = str2.replace(/\bOVER[\s]*\(/ig, function(match) {return 'OVER (~::~';});         // put a newline after ( in "OVER ("
      str2 = str2.replace(newline_select_split_regex, function(match) {return '(~::~SELECT'});// put a newline after ( in "( SELECT"
      str2 = str2.replace(/\)[\s]*,/ig,function(match) {return '),'});                        // remove any whitespace between ) and ,
      str2 = str2.replace(/~::~w{1,}/g,"~::~");                                               // remove blank lines
      str2 = str2.replace(/~::~ /ig,'~::~');

      // get an array of lines, based on the above breaks, then make a new array where we also split on comma-delimited lists
      var arr =  str2.split('~::~');
      var arr2 = [];

      arr.forEach(function (s) {
        var parenDepth = {depth:0};
        arr2 = arr2.concat(replace_top_level_commas(s,tab,parenDepth));
          });

      return(arr2);
    }

    //
    // format a N1QL string
    //

    function n1ql(text,step) {

      var tab = this.step,
      ar,
      deep = 0,
      paren_level = 0,
      str = '',
      ix = 0,
      specials = [],
      indents = [''],  // stack of indentation strings
      parens_in_lists = []; // are nested queries part of comma-delimited lists

      ar = split_n1ql(text,tab,specials);

      // now we have an array of either:
      // - things that should start on a newline, as indicated by starting with a special keyword
      // - things that should start on a newline, as indicated by the previous element ending with a comma
      // - strings or comments, which we can't look inside
      //
      // loop through the array of query elements.
      // we need to add appropriate indentation for each, based on this element and the previous
      // non-special element

      var comma_prev = false;
      var paren_prev = false;
      var prev_paren_level = 0;
      var inside_case = false; // are we part of a multi-line CASE statement?

      // Some will be specials, so we will just add those to the query string
      // Others need to be checked for nesting level
      var len = ar.length;

      for(ix=0;ix<len;ix++) {
        ar[ix] = ar[ix].trim();

        // remove blank lines
        if (ar[ix].length == 0)
          continue;

        // check for changes in the nesting level
        prev_paren_level = paren_level;
        paren_level = isSubquery(ar[ix], paren_level);

        // is this a string that should start or end with a new line?
        // - did the previous string end with a comma?
        // - does this string match a keyword that needs a newline?

        needs_indent_regex.lastIndex = 0;
        newline_before_and_after_regex.lastIndex = 0;
        newline_after_regex.lastIndex = 0;

        var needs_indent = !!needs_indent_regex.exec(ar[ix]);
        var after = !!newline_before_and_after_regex.exec(ar[ix]) || !!newline_after_regex.exec(ar[ix]);
        var ends_with_comma = ar[ix].endsWith(',');
        var ends_with_paren_comma = ar[ix].endsWith('),');
        var ends_with_paren = ar[ix].endsWith('(');

//        console.log("Got string: " + ar[ix]);
//        console.log("bfore indents len: " + indents.length + " paren_level " + paren_level +
//            " prev_paren_level " + prev_paren_level +
//            " ends_with_comma " + ends_with_comma +
//            " comma_prev " + comma_prev +
//            " parens_in_lists " + JSON.stringify(parens_in_lists)
//            );

        // each array element should start a new line, add appropriate indent
         str += '\n' + indents[indents.length - 1];

        // do we need a special indent for just this line?
        if (needs_indent)
          str += tab;

        // add the string
        str += ar[ix];

        // should there be a newline after?
        if (after)
          str += '\n';

        // if this is the first in a comma-delimited list, we need an appropriate indent.
        // if the line starts "SELECT" then we want 8 spaces indent
        // if the list starts "ORDER BY" or "GROUP BY" then we want 9 spaces indent
        // otherwise find the *last* space in the line for subsequent alignment
        if (ends_with_comma && !comma_prev && (paren_level == prev_paren_level)) {
          var fs;
          if (ar[ix].startsWith("SELECT "))
            fs = 7;
          else if (ar[ix].startsWith("GROUP BY") || ar[ix].startsWith("ORDER BY"))
            fs = 9;
          else if (ar[ix].startsWith("PARTITION BY"))
            fs = 13;
          else if (ar[ix].startsWith("LET"))
            fs = 4;
          else for (fs = ar[ix].length - 1; fs >= 0; fs--)
            if (ar[ix].charAt(fs) == ' ') {
              fs++;
              break;
            }
          // subsequent lines should be indented by this much
          indents.push(indents[indents.length - 1] + ' '.repeat(fs));
        }

        // if the nesting level goes up, add elements to the indent array,
        // if it goes down, pop them
        if (paren_level > prev_paren_level) {
          indents.push(indents[indents.length-1] + tab);
          parens_in_lists.push(comma_prev); // is the paren scope part of a comma list?
        }
        else if (paren_level < prev_paren_level) {
          // get rid of indentation for the parens
          indents.pop();

          // if our paren scope had a comma list, pop that indent
          if (comma_prev)
            indents.pop();

          // go back to comma status from outside paren scope
          comma_prev = parens_in_lists.pop();
          if (comma_prev && !ends_with_comma)
            indents.pop();
        }
        // if the previous item had a comma, but this doesn't, pop the comma indent
        else if (comma_prev && !ends_with_comma)
          indents.pop();

        comma_prev = ends_with_comma; // remember comma status
        paren_prev = ends_with_paren;
      }

      // insert the special strings back into the string
      while (/\^\&\&\^/ig.exec(str)) {
        if (!specials.length)
          break;
        str = str.replace(/\^\&\&\^/ig, function(match) {return(specials.shift());});
      }

      str = str.replace(/^\n{1,}/,'').replace(/\n{1,}/g,"\n");
      return str;
    }

    //////////////////////////////////////////////////////////////////////////////////////

    var Mode = function() {
      this.HighlightRules = N1qlHighlightRules;
      this.$completer = new N1qlCompletions();
      this.step = '  '; // 2 spaces
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
