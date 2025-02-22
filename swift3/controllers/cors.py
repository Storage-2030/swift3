# Copyright (c) 2018 OpenStack Foundation.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
# implied.
# See the License for the specific language governing permissions and
# limitations under the License.

import re

from swift.common.utils import public

from swift3.controllers.base import Controller, bucket_operation, \
    check_container_existence
from swift3.etree import fromstring, DocumentInvalid, XMLSyntaxError
from swift3.iam import check_iam_access
from swift3.response import HTTPOk, HTTPNoContent, MalformedXML, \
    NoSuchCORSConfiguration, CORSInvalidRequest

from swift3.utils import LOGGER, sysmeta_header, log_s3api_command, \
    convert_response

MAX_CORS_BODY_SIZE = 10240

BUCKET_CORS_HEADER = sysmeta_header('bucket', 'cors')

CORS_ALLOWED_HTTP_METHOD = ('GET', 'POST', 'PUT', 'HEAD', 'DELETE')


def match(pattern, value):
    '''helper function for wildcard'''
    if '*' not in pattern:
        return pattern == value
    # protect dot as we keep them as is
    pattern = pattern.replace('.', '\\.')
    pattern = '^' + pattern.replace('*', '.*') + '$'
    return re.match(pattern, value) is not None


def get_cors(app, req, method, origin):
    sysmeta = req.get_container_info(app).get('sysmeta', {})
    body = sysmeta.get('swift3-cors')
    if not body:
        return None
    data = fromstring(body, "CorsConfiguration")

    # we have to iterate over each to find matching origin
    # whe have to manage wildcard in domain
    rules = data.findall('CORSRule')
    for rule in rules:
        item = rule.find('AllowedOrigin')
        if match(item.text, origin) or item.text == '*':
            # check AllowedMethod
            methods = rule.findall('AllowedMethod')
            for m in methods:
                if m.text == method:
                    hdrs = req.headers.get('Access-Control-Request-Headers')
                    if hdrs:
                        allowed = [x.text.lower()
                                   for x in rule.findall('AllowedHeader')]

                        # manage * as well for headers
                        hdrs = [x.lower().strip() for x in hdrs.split(',')]
                        if '*' not in allowed \
                                and not all([hdr in allowed for hdr in hdrs]):
                            # some requested headers are not found
                            continue
                    return rule
    return None


def cors_fill_headers(req, resp, rule):
    def set_header_if_item(hdr, tag):
        val = rule.find(tag)
        if val is not None:
            resp.headers[hdr] = val.text

    def set_header_if_items(hdr, tag):
        vals = [m.text for m in rule.findall(tag)]
        if vals:
            resp.headers[hdr] = ', '.join(vals)

    # use from request as rule may contains wildcard
    # NOTE: if * AND request is anonymous, we can reply '*'
    # https://developer.mozilla.org/en-US/docs/Web/HTTP/CORS#Access-Control-Allow-Origin
    if req._is_anonymous and rule.find('AllowedOrigin').text == '*':
        resp.headers['Access-Control-Allow-Origin'] = '*'
    else:
        resp.headers['Access-Control-Allow-Origin'] = req.headers.get('Origin')
    set_header_if_items('Access-Control-Allow-Headers', 'AllowedHeader')
    set_header_if_items('Access-Control-Allow-Methods', 'AllowedMethod')
    set_header_if_items('Access-Control-Expose-Headers', 'ExposeHeader')
    set_header_if_item('Access-Control-Max-Age', 'MaxAgeSeconds')
    resp.headers['Access-Control-Allow-Credentials'] = 'true'

    return resp


def check_cors_rule(data):
    '''Check at minima CORS rules'''
    rules = data.findall('CORSRule')
    for rule in rules:
        origin = rule.find('AllowedOrigin')
        if origin.text.count('*') > 1:
            raise CORSInvalidRequest(
                'AllowedOrigin "%s" can not have more than one wildcard'
                % origin.text)

        for method in rule.findall('AllowedMethod'):
            if method.text not in CORS_ALLOWED_HTTP_METHOD:
                raise CORSInvalidRequest(
                    "Found unsupported HTTP method in CORS config. "
                    "Unsupported method is %s" % method.text)
        for exposed in rule.findall('ExposeHeader'):
            if '*' in exposed.text:
                raise CORSInvalidRequest(
                    'ExposeHeader "%s" contains wildcard. We currently do '
                    'not support wildcard for ExposeHeader.' % exposed.text)
        for allowed in rule.findall('AllowedHeader'):
            if allowed.text.count('*') > 1:
                raise CORSInvalidRequest(
                    'AllowedHeader "%s" can not have more than one wildcard.'
                    % allowed.text)


class CorsController(Controller):
    """
    Handles the following APIs:

     - GET Bucket CORS
     - PUT Bucket CORS
     - DELETE Bucket CORS

    """

    @public
    @bucket_operation
    @check_container_existence
    @check_iam_access('s3:GetBucketCORS')
    def GET(self, req):  # pylint: disable=invalid-name
        """
        Handles GET Bucket CORS.
        """
        log_s3api_command(req, 'get-bucket-cors')
        resp = req.get_response(self.app, method='HEAD')
        body = resp.sysmeta_headers.get(BUCKET_CORS_HEADER)
        if not body:
            raise NoSuchCORSConfiguration
        return HTTPOk(body=body, content_type='application/xml')

    @public
    @bucket_operation
    @check_container_existence
    @check_iam_access('s3:PutBucketCORS')
    def PUT(self, req):  # pylint: disable=invalid-name
        """
        Handles PUT Bucket CORS.
        """
        log_s3api_command(req, 'put-bucket-cors')
        xml = req.xml(MAX_CORS_BODY_SIZE)
        try:
            data = fromstring(xml, "CorsConfiguration")
        except (XMLSyntaxError, DocumentInvalid):
            raise MalformedXML()
        except Exception as exc:
            LOGGER.error(exc)
            raise

        # forbid wildcard for ExposeHeader
        check_cors_rule(data)

        req.headers[BUCKET_CORS_HEADER] = xml
        resp = req.get_response(self.app, 'POST')
        return convert_response(req, resp, 204, HTTPOk)

    @public
    @bucket_operation
    @check_container_existence
    @check_iam_access('s3:PutBucketCORS')  # No specific permission for DELETE
    def DELETE(self, req):  # pylint: disable=invalid-name
        """
        Handles DELETE Bucket CORS.
        """
        log_s3api_command(req, 'delete-bucket-cors')
        req.headers[BUCKET_CORS_HEADER] = ''
        resp = req.get_response(self.app, 'POST')
        return convert_response(req, resp, 202, HTTPNoContent)
