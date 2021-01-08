import{R as t,r,d as e,e as s,C as u,h as l,b as h,n as b}from"./common/rgb-50db7803.js";export{f as interpolateBasis,g as interpolateBasisClosed,i as interpolateRgb,j as interpolateRgbBasis,k as interpolateRgbBasisClosed}from"./common/rgb-50db7803.js";import{r as m,d as y}from"./common/cubehelix-b37f4760.js";export{c as interpolateCubehelix,a as interpolateCubehelixLong}from"./common/cubehelix-b37f4760.js";export{i as interpolate,a as interpolateArray,d as interpolateDate,n as interpolateNumberArray,o as interpolateObject}from"./common/value-2cd045dd.js";export{i as interpolateNumber,a as interpolateString}from"./common/string-cfd0b55d.js";export{i as interpolateRound,p as piecewise}from"./common/piecewise-ef887050.js";export{a as interpolateTransformCss,i as interpolateTransformSvg}from"./common/index-f3df269c.js";export{i as interpolateZoom}from"./common/zoom-74300348.js";var w=6/29,v=3*w*w;function x(n){if(n instanceof M)return new M(n.l,n.a,n.b,n.opacity);if(n instanceof D)return S(n);n instanceof t||(n=r(n));var a,i,e=B(n.r),o=B(n.g),s=B(n.b),c=C((.2225045*e+.7168786*o+.0606169*s)/1);return e===o&&o===s?a=i=c:(a=C((.4360747*e+.3850649*o+.1430804*s)/.96422),i=C((.0139322*e+.0971045*o+.7141733*s)/.82521)),new M(116*c-16,500*(a-c),200*(c-i),n.opacity)}function N(t,n,r,a){return 1===arguments.length?x(t):new M(t,n,r,null==a?1:a)}function M(t,n,r,a){this.l=+t,this.a=+n,this.b=+r,this.opacity=+a}function C(t){return t>.008856451679035631?Math.pow(t,1/3):t/v+4/29}function H(t){return t>w?t*t*t:v*(t-4/29)}function R(t){return 255*(t<=.0031308?12.92*t:1.055*Math.pow(t,1/2.4)-.055)}function B(t){return(t/=255)<=.04045?t/12.92:Math.pow((t+.055)/1.055,2.4)}function L(t){if(t instanceof D)return new D(t.h,t.c,t.l,t.opacity);if(t instanceof M||(t=x(t)),0===t.a&&0===t.b)return new D(NaN,0<t.l&&t.l<100?0:NaN,t.l,t.opacity);var n=Math.atan2(t.b,t.a)*m;return new D(n<0?n+360:n,Math.sqrt(t.a*t.a+t.b*t.b),t.l,t.opacity)}function A(t,n,r,a){return 1===arguments.length?L(t):new D(t,n,r,null==a?1:a)}function D(t,n,r,a){this.h=+t,this.c=+n,this.l=+r,this.opacity=+a}function S(t){if(isNaN(t.h))return new M(t.l,0,0,t.opacity);var n=t.h*y;return new M(t.l,Math.cos(n)*t.c,Math.sin(n)*t.c,t.opacity)}function T(t){var n=t.length;return function(r){return t[Math.max(0,Math.min(n-1,Math.floor(r*n)))]}}function q(t,n){var r=l(+t,+n);return function(t){var n=r(t);return n-360*Math.floor(n/360)}}function z(t){return function(n,r){var a=t((n=h(n)).h,(r=h(r)).h),i=b(n.s,r.s),e=b(n.l,r.l),o=b(n.opacity,r.opacity);return function(t){return n.h=a(t),n.s=i(t),n.l=e(t),n.opacity=o(t),n+""}}}e(M,N,s(u,{brighter:function(t){return new M(this.l+18*(null==t?1:t),this.a,this.b,this.opacity)},darker:function(t){return new M(this.l-18*(null==t?1:t),this.a,this.b,this.opacity)},rgb:function(){var n=(this.l+16)/116,r=isNaN(this.a)?n:n+this.a/500,a=isNaN(this.b)?n:n-this.b/200;return r=.96422*H(r),n=1*H(n),a=.82521*H(a),new t(R(3.1338561*r-1.6168667*n-.4906146*a),R(-.9787684*r+1.9161415*n+.033454*a),R(.0719453*r-.2289914*n+1.4052427*a),this.opacity)}})),e(D,A,s(u,{brighter:function(t){return new D(this.h,this.c,this.l+18*(null==t?1:t),this.opacity)},darker:function(t){return new D(this.h,this.c,this.l-18*(null==t?1:t),this.opacity)},rgb:function(){return S(this).rgb()}}));var O=z(l),Z=z(b);function E(t,n){var r=b((t=N(t)).l,(n=N(n)).l),a=b(t.a,n.a),i=b(t.b,n.b),e=b(t.opacity,n.opacity);return function(n){return t.l=r(n),t.a=a(n),t.b=i(n),t.opacity=e(n),t+""}}function F(t){return function(n,r){var a=t((n=A(n)).h,(r=A(r)).h),i=b(n.c,r.c),e=b(n.l,r.l),o=b(n.opacity,r.opacity);return function(t){return n.h=a(t),n.c=i(t),n.l=e(t),n.opacity=o(t),n+""}}}var G=F(l),I=F(b);function J(t,n){for(var r=new Array(n),a=0;a<n;++a)r[a]=t(a/(n-1));return r}export{T as interpolateDiscrete,G as interpolateHcl,I as interpolateHclLong,O as interpolateHsl,Z as interpolateHslLong,q as interpolateHue,E as interpolateLab,J as quantize};
//# sourceMappingURL=d3-interpolate.js.map