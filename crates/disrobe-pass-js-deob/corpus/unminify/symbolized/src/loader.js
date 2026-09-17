export function createLoader(baseUrl, transport) {
  var cache = {};

  function buildUrl(resource, params) {
    var query = [];
    for (var key in params) {
      if (Object.prototype.hasOwnProperty.call(params, key)) {
        query.push(encodeURIComponent(key) + '=' + encodeURIComponent(params[key]));
      }
    }
    return baseUrl + '/' + resource + (query.length ? '?' + query.join('&') : '');
  }

  function load(resource, params) {
    var url = buildUrl(resource, params);
    if (cache[url]) {
      return cache[url];
    }
    var promise = transport(url)
      .then(function (response) {
        if (!response.ok) {
          throw new Error('request failed for ' + resource);
        }
        return response.json();
      })
      .catch(function (error) {
        delete cache[url];
        throw error;
      });
    cache[url] = promise;
    return promise;
  }

  function invalidate(resource) {
    var prefix = baseUrl + '/' + resource;
    var removed = 0;
    for (var url in cache) {
      if (url.indexOf(prefix) === 0) {
        delete cache[url];
        removed = removed + 1;
      }
    }
    return removed;
  }

  return { load: load, invalidate: invalidate };
}
