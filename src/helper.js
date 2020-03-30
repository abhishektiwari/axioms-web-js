import 'core-js/features/promise';
import "regenerator-runtime/runtime";
import urljoin from 'url-join';
import qs from 'qs';

export function create_url(base_url, query_obj) {
    return urljoin(base_url, serialize_params(query_obj));
}

export function serialize_params(obj) {
    return "?" + qs.stringify(obj)
}