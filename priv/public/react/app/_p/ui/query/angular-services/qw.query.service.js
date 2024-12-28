/*
Copyright 2020-Present Couchbase, Inc.

Use of this software is governed by the Business Source License included in
the file licenses/BSL-Couchbase.txt.  As of the Change Date specified in that
file, in accordance with the Business Source License, use of this software will
be governed by the Apache License, Version 2.0, included in the file
licenses/APL2.txt.
*/

import { HttpHeaders } from '@angular/common/http';
import { HttpClient } from '../../../../mn.http.client.js';
class QwQueryServiceClass {

  constructor(http) {
    this.http = http;

    /**
     * Fast UUID generator, RFC4122 version 4 compliant.
     * @author Jeff Ward (jcward.com).
     * @license MIT license
     * @link http://stackoverflow.com/questions/105034/how-to-create-a-guid-uuid-in-javascript/21963136#21963136
     **/
    this.UUID = (function () {
      var self = {};
      var lut = [];
      for (var i = 0; i < 256; i++) {
        lut[i] = (i < 16 ? '0' : '') + (i).toString(16);
      }
      self.generate = function () {
        var d0 = Math.random() * 0xffffffff | 0;
        var d1 = Math.random() * 0xffffffff | 0;
        var d2 = Math.random() * 0xffffffff | 0;
        var d3 = Math.random() * 0xffffffff | 0;
        return lut[d0 & 0xff] + lut[d0 >> 8 & 0xff] + lut[d0 >> 16 & 0xff] + lut[d0 >> 24 & 0xff] + '-' +
            lut[d1 & 0xff] + lut[d1 >> 8 & 0xff] + '-' + lut[d1 >> 16 & 0x0f | 0x40] + lut[d1 >> 24 & 0xff] + '-' +
            lut[d2 & 0x3f | 0x80] + lut[d2 >> 8 & 0xff] + '-' + lut[d2 >> 16 & 0xff] + lut[d2 >> 24 & 0xff] +
            lut[d3 & 0xff] + lut[d3 >> 8 & 0xff] + lut[d3 >> 16 & 0xff] + lut[d3 >> 24 & 0xff];
      }
      return self;
    })();
  }

  // create a query request object for internal queries (no user options)
  // timeout should be an integer number of seconds
  buildQueryRequest(queryText, timeout, is_user_query) {

    var queryRequest = {
      url: '/_p/query/query/service',
      method: "POST",
      headers: {
        'Content-Type': 'application/json',
        'ignore-401': 'true',
        'CB-User-Agent': 'Couchbase Query Workbench',
        'isNotForm': 'true'
      },
      data: {
        statement: queryText,
        pretty: false,
        timeout: (timeout || 0) + 's',
        client_context_id: "INTERNAL-" + this.UUID.generate(),
      },
      mnHttp: {
        isNotForm: true,
        group: "global"
      },
      reportProgress: is_user_query,
    };

    // our queries run through a ns_server proxy, so it needs a timeout at least
    // as long as that for the query service.
    if (timeout)
      queryRequest.headers['ns-server-proxy-timeout'] = (timeout + 1) * 1000;

    return(queryRequest);
  }

  //
  // run an internal UI query against the query service. For user queries, use
  // the QwQueryWorkbenchService, which includes user options and puts the result
  // in the query history.
  //
  // we run queries many places, some of them are still written to expect a Promise
  // (as was returned by the old $http). This function builds the query request, uses
  // the new HttpClient, and converts the response from an Observable to a Promise.
  //

  executeQueryUtil(queryText) {
    return(this.executeQueryUtilNew(queryText))
        .toPromise().then(this.handleSuccess,this.handleFailure);
   }

  //
  // query utility for new HttpClient with observables
  //

  executeQueryUtilNew(queryText) {
    var request = this.buildQueryRequest(queryText);
    return this.http.post(request.url,request.data,this.configToOptions(request));
  }

  // convenience functions for interacting with HttpClient

  // convert the $http config to an HttpClient options object

  configToOptions(config) {
    var options = {observe: 'response'};
    if (config.headers) {
      // can't pass options to HttpHeaders constructor, because it can't
      // handle headers with numeric values
      options.headers = new HttpHeaders();
      Object.keys(config.headers).forEach(key =>
          options.headers = options.headers.set(key,config.headers[key]));
    }

    if (config.params)
      options.params = config.params;
    return(options);
  }

  handleSuccess(resp) {
    if (resp && resp.status == 200 && resp.body) {
      if (typeof resp.body == 'string') try {
        resp.data = JSON.parse(resp.body);
      } catch (e) {}
      else
        resp.data = resp.body;
    }
    return(resp);
  }

  handleFailure(resp) {
    if (typeof resp.error == 'string') try {
      resp.data = JSON.parse(resp.error);
    } catch (e) {}

    return(Promise.reject(resp));
  }
}

const QwQueryService = new QwQueryServiceClass(HttpClient);
export { QwQueryService };
