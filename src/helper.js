import 'core-js/features/promise';
import "regenerator-runtime/runtime";
import urljoin from 'url-join';
import qs from 'qs';
import Base64 from 'crypto-js/enc-base64';

export function create_url(base_url, query_obj) {
    return urljoin(base_url, serialize_params(query_obj));
}

export function serialize_params(obj) {
    return "?" + qs.stringify(obj)
}

export function base64URL(string) {
    return string.toString(Base64).replace(/=/g, '').replace(/\+/g, '-').replace(/\//g, '_')
}