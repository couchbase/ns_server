import { u as utcFormat, a as utcParse } from './common/defaultLocale-8471ceb2.js';
export { t as timeFormat, d as timeFormatDefaultLocale, f as timeFormatLocale, b as timeParse, u as utcFormat, a as utcParse } from './common/defaultLocale-8471ceb2.js';
import './common/utcYear-1e11091a.js';

var isoSpecifier = "%Y-%m-%dT%H:%M:%S.%LZ";

function formatIsoNative(date) {
  return date.toISOString();
}

var formatIso = Date.prototype.toISOString
    ? formatIsoNative
    : utcFormat(isoSpecifier);

var formatIso$1 = formatIso;

function parseIsoNative(string) {
  var date = new Date(string);
  return isNaN(date) ? null : date;
}

var parseIso = +new Date("2000-01-01T00:00:00.000Z")
    ? parseIsoNative
    : utcParse(isoSpecifier);

var parseIso$1 = parseIso;

export { formatIso$1 as isoFormat, parseIso$1 as isoParse };
