import urljoin from 'url-join';
import qs from 'qs';
import request from 'request';

export function create_url(base_url, query_obj) {
    return urljoin(base_url, serialize_params(query_obj));
}

export function serialize_params(obj) {
    return "?" + qs.stringify(obj)
}

export function fetch_jwks(options, callback) {
    request(options, function(error, response, body) {
        console.log('error:', error); // eslint-disable-line no-console
        console.log('statusCode:', response && response.statusCode); // eslint-disable-line no-console
        console.log('body:', body); // eslint-disable-line no-console
        callback(body.keys)
    });
}

export async function fetch_jwkset(options) {
    return new Promise((resolve, reject) => {
        request(options, function(err, res, body) {
            if (err) reject(err);
            else resolve(body.keys);
        });
    });
}