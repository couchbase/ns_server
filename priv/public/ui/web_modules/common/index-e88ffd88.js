var t="http://www.w3.org/1999/xhtml",n={svg:"http://www.w3.org/2000/svg",xhtml:t,xlink:"http://www.w3.org/1999/xlink",xml:"http://www.w3.org/XML/1998/namespace",xmlns:"http://www.w3.org/2000/xmlns/"};function e(t){var e=t+="",r=e.indexOf(":");return r>=0&&"xmlns"!==(e=t.slice(0,r))&&(t=t.slice(r+1)),n.hasOwnProperty(e)?{space:n[e],local:t}:t}function r(n){return function(){var e=this.ownerDocument,r=this.namespaceURI;return r===t&&e.documentElement.namespaceURI===t?e.createElement(n):e.createElementNS(r,n)}}function i(t){return function(){return this.ownerDocument.createElementNS(t.space,t.local)}}function o(t){var n=e(t);return(n.local?i:r)(n)}function u(){}function s(t){return null==t?u:function(){return this.querySelector(t)}}function a(){return[]}function c(t){return null==t?a:function(){return this.querySelectorAll(t)}}function l(t){return function(){return this.matches(t)}}function h(t){return new Array(t.length)}function f(t,n){this.ownerDocument=t.ownerDocument,this.namespaceURI=t.namespaceURI,this._next=null,this._parent=t,this.__data__=n}f.prototype={constructor:f,appendChild:function(t){return this._parent.insertBefore(t,this._next)},insertBefore:function(t,n){return this._parent.insertBefore(t,n)},querySelector:function(t){return this._parent.querySelector(t)},querySelectorAll:function(t){return this._parent.querySelectorAll(t)}};function p(t,n,e,r,i,o){for(var u,s=0,a=n.length,c=o.length;s<c;++s)(u=n[s])?(u.__data__=o[s],r[s]=u):e[s]=new f(t,o[s]);for(;s<a;++s)(u=n[s])&&(i[s]=u)}function _(t,n,e,r,i,o,u){var s,a,c,l={},h=n.length,p=o.length,_=new Array(h);for(s=0;s<h;++s)(a=n[s])&&(_[s]=c="$"+u.call(a,a.__data__,s,n),c in l?i[s]=a:l[c]=a);for(s=0;s<p;++s)(a=l[c="$"+u.call(t,o[s],s,o)])?(r[s]=a,a.__data__=o[s],l[c]=null):e[s]=new f(t,o[s]);for(s=0;s<h;++s)(a=n[s])&&l[_[s]]===a&&(i[s]=a)}function v(t,n){return t<n?-1:t>n?1:t>=n?0:NaN}function y(t){return function(){this.removeAttribute(t)}}function d(t){return function(){this.removeAttributeNS(t.space,t.local)}}function m(t,n){return function(){this.setAttribute(t,n)}}function g(t,n){return function(){this.setAttributeNS(t.space,t.local,n)}}function w(t,n){return function(){var e=n.apply(this,arguments);null==e?this.removeAttribute(t):this.setAttribute(t,e)}}function A(t,n){return function(){var e=n.apply(this,arguments);null==e?this.removeAttributeNS(t.space,t.local):this.setAttributeNS(t.space,t.local,e)}}function x(t){return t.ownerDocument&&t.ownerDocument.defaultView||t.document&&t||t.defaultView}function b(t){return function(){this.style.removeProperty(t)}}function S(t,n,e){return function(){this.style.setProperty(t,n,e)}}function N(t,n,e){return function(){var r=n.apply(this,arguments);null==r?this.style.removeProperty(t):this.style.setProperty(t,r,e)}}function E(t,n){return t.style.getPropertyValue(n)||x(t).getComputedStyle(t,null).getPropertyValue(n)}function C(t){return function(){delete this[t]}}function L(t,n){return function(){this[t]=n}}function P(t,n){return function(){var e=n.apply(this,arguments);null==e?delete this[t]:this[t]=e}}function B(t){return t.trim().split(/^|\s+/)}function D(t){return t.classList||new O(t)}function O(t){this._node=t,this._names=B(t.getAttribute("class")||"")}function q(t,n){for(var e=D(t),r=-1,i=n.length;++r<i;)e.add(n[r])}function M(t,n){for(var e=D(t),r=-1,i=n.length;++r<i;)e.remove(n[r])}function T(t){return function(){q(this,t)}}function H(t){return function(){M(this,t)}}function I(t,n){return function(){(n.apply(this,arguments)?q:M)(this,t)}}function R(){this.textContent=""}function U(t){return function(){this.textContent=t}}function V(t){return function(){var n=t.apply(this,arguments);this.textContent=null==n?"":n}}function j(){this.innerHTML=""}function z(t){return function(){this.innerHTML=t}}function k(t){return function(){var n=t.apply(this,arguments);this.innerHTML=null==n?"":n}}function $(){this.nextSibling&&this.parentNode.appendChild(this)}function X(){this.previousSibling&&this.parentNode.insertBefore(this,this.parentNode.firstChild)}function F(){return null}function G(){var t=this.parentNode;t&&t.removeChild(this)}function J(){var t=this.cloneNode(!1),n=this.parentNode;return n?n.insertBefore(t,this.nextSibling):t}function K(){var t=this.cloneNode(!0),n=this.parentNode;return n?n.insertBefore(t,this.nextSibling):t}O.prototype={add:function(t){this._names.indexOf(t)<0&&(this._names.push(t),this._node.setAttribute("class",this._names.join(" ")))},remove:function(t){var n=this._names.indexOf(t);n>=0&&(this._names.splice(n,1),this._node.setAttribute("class",this._names.join(" ")))},contains:function(t){return this._names.indexOf(t)>=0}};var Q={},W=null;"undefined"!=typeof document&&("onmouseenter"in document.documentElement||(Q={mouseenter:"mouseover",mouseleave:"mouseout"}));function Y(t,n,e){return t=Z(t,n,e),function(n){var e=n.relatedTarget;e&&(e===this||8&e.compareDocumentPosition(this))||t.call(this,n)}}function Z(t,n,e){return function(r){var i=W;W=r;try{t.call(this,this.__data__,n,e)}finally{W=i}}}function tt(t){return t.trim().split(/^|\s+/).map((function(t){var n="",e=t.indexOf(".");return e>=0&&(n=t.slice(e+1),t=t.slice(0,e)),{type:t,name:n}}))}function nt(t){return function(){var n=this.__on;if(n){for(var e,r=0,i=-1,o=n.length;r<o;++r)e=n[r],t.type&&e.type!==t.type||e.name!==t.name?n[++i]=e:this.removeEventListener(e.type,e.listener,e.capture);++i?n.length=i:delete this.__on}}}function et(t,n,e){var r=Q.hasOwnProperty(t.type)?Y:Z;return function(i,o,u){var s,a=this.__on,c=r(n,o,u);if(a)for(var l=0,h=a.length;l<h;++l)if((s=a[l]).type===t.type&&s.name===t.name)return this.removeEventListener(s.type,s.listener,s.capture),this.addEventListener(s.type,s.listener=c,s.capture=e),void(s.value=n);this.addEventListener(t.type,c,e),s={type:t.type,name:t.name,value:n,listener:c,capture:e},a?a.push(s):this.__on=[s]}}function rt(t,n,e,r){var i=W;t.sourceEvent=W,W=t;try{return n.apply(e,r)}finally{W=i}}function it(t,n,e){var r=x(t),i=r.CustomEvent;"function"==typeof i?i=new i(n,e):(i=r.document.createEvent("Event"),e?(i.initEvent(n,e.bubbles,e.cancelable),i.detail=e.detail):i.initEvent(n,!1,!1)),t.dispatchEvent(i)}function ot(t,n){return function(){return it(this,t,n)}}function ut(t,n){return function(){return it(this,t,n.apply(this,arguments))}}var st=[null];function at(t,n){this._groups=t,this._parents=n}function ct(){return new at([[document.documentElement]],st)}at.prototype=ct.prototype={constructor:at,select:function(t){"function"!=typeof t&&(t=s(t));for(var n=this._groups,e=n.length,r=new Array(e),i=0;i<e;++i)for(var o,u,a=n[i],c=a.length,l=r[i]=new Array(c),h=0;h<c;++h)(o=a[h])&&(u=t.call(o,o.__data__,h,a))&&("__data__"in o&&(u.__data__=o.__data__),l[h]=u);return new at(r,this._parents)},selectAll:function(t){"function"!=typeof t&&(t=c(t));for(var n=this._groups,e=n.length,r=[],i=[],o=0;o<e;++o)for(var u,s=n[o],a=s.length,l=0;l<a;++l)(u=s[l])&&(r.push(t.call(u,u.__data__,l,s)),i.push(u));return new at(r,i)},filter:function(t){"function"!=typeof t&&(t=l(t));for(var n=this._groups,e=n.length,r=new Array(e),i=0;i<e;++i)for(var o,u=n[i],s=u.length,a=r[i]=[],c=0;c<s;++c)(o=u[c])&&t.call(o,o.__data__,c,u)&&a.push(o);return new at(r,this._parents)},data:function(t,n){if(!t)return y=new Array(this.size()),l=-1,this.each((function(t){y[++l]=t})),y;var e,r=n?_:p,i=this._parents,o=this._groups;"function"!=typeof t&&(e=t,t=function(){return e});for(var u=o.length,s=new Array(u),a=new Array(u),c=new Array(u),l=0;l<u;++l){var h=i[l],f=o[l],v=f.length,y=t.call(h,h&&h.__data__,l,i),d=y.length,m=a[l]=new Array(d),g=s[l]=new Array(d);r(h,f,m,g,c[l]=new Array(v),y,n);for(var w,A,x=0,b=0;x<d;++x)if(w=m[x]){for(x>=b&&(b=x+1);!(A=g[b])&&++b<d;);w._next=A||null}}return(s=new at(s,i))._enter=a,s._exit=c,s},enter:function(){return new at(this._enter||this._groups.map(h),this._parents)},exit:function(){return new at(this._exit||this._groups.map(h),this._parents)},join:function(t,n,e){var r=this.enter(),i=this,o=this.exit();return r="function"==typeof t?t(r):r.append(t+""),null!=n&&(i=n(i)),null==e?o.remove():e(o),r&&i?r.merge(i).order():i},merge:function(t){for(var n=this._groups,e=t._groups,r=n.length,i=e.length,o=Math.min(r,i),u=new Array(r),s=0;s<o;++s)for(var a,c=n[s],l=e[s],h=c.length,f=u[s]=new Array(h),p=0;p<h;++p)(a=c[p]||l[p])&&(f[p]=a);for(;s<r;++s)u[s]=n[s];return new at(u,this._parents)},order:function(){for(var t=this._groups,n=-1,e=t.length;++n<e;)for(var r,i=t[n],o=i.length-1,u=i[o];--o>=0;)(r=i[o])&&(u&&4^r.compareDocumentPosition(u)&&u.parentNode.insertBefore(r,u),u=r);return this},sort:function(t){function n(n,e){return n&&e?t(n.__data__,e.__data__):!n-!e}t||(t=v);for(var e=this._groups,r=e.length,i=new Array(r),o=0;o<r;++o){for(var u,s=e[o],a=s.length,c=i[o]=new Array(a),l=0;l<a;++l)(u=s[l])&&(c[l]=u);c.sort(n)}return new at(i,this._parents).order()},call:function(){var t=arguments[0];return arguments[0]=this,t.apply(null,arguments),this},nodes:function(){var t=new Array(this.size()),n=-1;return this.each((function(){t[++n]=this})),t},node:function(){for(var t=this._groups,n=0,e=t.length;n<e;++n)for(var r=t[n],i=0,o=r.length;i<o;++i){var u=r[i];if(u)return u}return null},size:function(){var t=0;return this.each((function(){++t})),t},empty:function(){return!this.node()},each:function(t){for(var n=this._groups,e=0,r=n.length;e<r;++e)for(var i,o=n[e],u=0,s=o.length;u<s;++u)(i=o[u])&&t.call(i,i.__data__,u,o);return this},attr:function(t,n){var r=e(t);if(arguments.length<2){var i=this.node();return r.local?i.getAttributeNS(r.space,r.local):i.getAttribute(r)}return this.each((null==n?r.local?d:y:"function"==typeof n?r.local?A:w:r.local?g:m)(r,n))},style:function(t,n,e){return arguments.length>1?this.each((null==n?b:"function"==typeof n?N:S)(t,n,null==e?"":e)):E(this.node(),t)},property:function(t,n){return arguments.length>1?this.each((null==n?C:"function"==typeof n?P:L)(t,n)):this.node()[t]},classed:function(t,n){var e=B(t+"");if(arguments.length<2){for(var r=D(this.node()),i=-1,o=e.length;++i<o;)if(!r.contains(e[i]))return!1;return!0}return this.each(("function"==typeof n?I:n?T:H)(e,n))},text:function(t){return arguments.length?this.each(null==t?R:("function"==typeof t?V:U)(t)):this.node().textContent},html:function(t){return arguments.length?this.each(null==t?j:("function"==typeof t?k:z)(t)):this.node().innerHTML},raise:function(){return this.each($)},lower:function(){return this.each(X)},append:function(t){var n="function"==typeof t?t:o(t);return this.select((function(){return this.appendChild(n.apply(this,arguments))}))},insert:function(t,n){var e="function"==typeof t?t:o(t),r=null==n?F:"function"==typeof n?n:s(n);return this.select((function(){return this.insertBefore(e.apply(this,arguments),r.apply(this,arguments)||null)}))},remove:function(){return this.each(G)},clone:function(t){return this.select(t?K:J)},datum:function(t){return arguments.length?this.property("__data__",t):this.node().__data__},on:function(t,n,e){var r,i,o=tt(t+""),u=o.length;if(!(arguments.length<2)){for(s=n?et:nt,null==e&&(e=!1),r=0;r<u;++r)this.each(s(o[r],n,e));return this}var s=this.node().__on;if(s)for(var a,c=0,l=s.length;c<l;++c)for(r=0,a=s[c];r<u;++r)if((i=o[r]).type===a.type&&i.name===a.name)return a.value},dispatch:function(t,n){return this.each(("function"==typeof n?ut:ot)(t,n))}};export{at as S,c as a,ct as b,rt as c,E as d,W as e,o as f,n as g,x as h,l as m,e as n,st as r,s};
//# sourceMappingURL=index-e88ffd88.js.map