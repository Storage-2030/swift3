# Copyright (c) 2014,2017-2018 OpenStack Foundation.
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

import base64
from collections import defaultdict
from email.header import Header
from hashlib import sha1, sha256, md5
import hmac
import re
import six
import string
from six.moves.urllib.parse import parse_qsl, quote, unquote, urlparse

from swift.common.utils import split_path
from swift.common import swob
from swift.common.http import HTTP_OK, HTTP_CREATED, HTTP_ACCEPTED, \
    HTTP_NO_CONTENT, HTTP_UNAUTHORIZED, HTTP_FORBIDDEN, HTTP_NOT_FOUND, \
    HTTP_CONFLICT, HTTP_UNPROCESSABLE_ENTITY, HTTP_REQUEST_ENTITY_TOO_LARGE, \
    HTTP_PARTIAL_CONTENT, HTTP_NOT_MODIFIED, HTTP_PRECONDITION_FAILED, \
    HTTP_REQUESTED_RANGE_NOT_SATISFIABLE, HTTP_LENGTH_REQUIRED, \
    HTTP_BAD_REQUEST, HTTP_REQUEST_TIMEOUT, HTTP_SERVICE_UNAVAILABLE, \
    HTTP_CLIENT_CLOSED_REQUEST, HTTP_METHOD_NOT_ALLOWED, is_success

from swift.common.constraints import check_utf8, valid_api_version
from swift.proxy.controllers.base import get_container_info, \
    headers_to_container_info, get_object_info

from swift3.controllers import ServiceController, BucketController, \
    ObjectController, AclController, MultiObjectDeleteController, \
    LocationController, LoggingStatusController, PartController, \
    TaggingController, \
    UploadController, UploadsController, VersioningController, \
    UnsupportedController, S3AclController, LifecycleController, \
    CorsController, UniqueBucketController
from swift3.response import AccessDenied, InvalidArgument, InvalidDigest, \
    RequestTimeTooSkewed, Response, SignatureDoesNotMatch, \
    BucketAlreadyExists, BucketNotEmpty, EntityTooLarge, OperationAborted, \
    InternalError, NoSuchBucket, NoSuchKey, PreconditionFailed, InvalidRange, \
    MissingContentLength, InvalidStorageClass, S3NotImplemented, InvalidURI, \
    MalformedXML, InvalidRequest, RequestTimeout, InvalidBucketName, \
    BadDigest, AuthorizationHeaderMalformed, \
    AuthorizationQueryParametersError, ServiceUnavailable, \
    BadRequest, MethodNotAllowed
from swift3.exception import NotS3Request
from swift3.utils import utf8encode, LOGGER, check_path_header, S3Timestamp, \
    mktime, MULTIUPLOAD_SUFFIX, versioned_object_name, VERSIONING_SUFFIX
from swift3.cfg import CONF
from swift3.subresource import decode_acl, encode_acl
from swift3.utils import sysmeta_header, validate_bucket_name
from swift3.acl_utils import handle_acl_header
from swift3.acl_handlers import get_acl_handler


# List of sub-resources that must be maintained as part of the HMAC
# signature string.
ALLOWED_SUB_RESOURCES = sorted([
    'acl', 'delete', 'lifecycle', 'location', 'logging', 'notification',
    'partNumber', 'policy', 'requestPayment', 'torrent', 'uploads', 'uploadId',
    'versionId', 'versioning', 'versions', 'website',
    'response-cache-control', 'response-content-disposition',
    'response-content-encoding', 'response-content-language',
    'response-content-type', 'response-expires', 'cors', 'tagging', 'restore'
])


MAX_32BIT_INT = 2147483647
SIGV2_TIMESTAMP_FORMAT = '%Y-%m-%dT%H:%M:%S'
SIGV4_X_AMZ_DATE_FORMAT = '%Y%m%dT%H%M%SZ'
SERVICE = 's3'  # useful for mocking out in tests


def _header_strip(value):
    # S3 seems to strip *all* control characters
    if value is None:
        return None
    stripped = _header_strip.re.sub('', value)
    if value and not stripped:
        # If there's nothing left after stripping,
        # behave as though it wasn't provided
        return None
    return stripped


_header_strip.re = re.compile('^[\x00-\x20]*|[\x00-\x20]*$')


def _header_acl_property(resource):
    """
    Set and retrieve the acl in self.headers
    """
    def getter(self):
        return getattr(self, '_%s' % resource)

    def setter(self, value):
        self.headers.update(encode_acl(resource, value))
        setattr(self, '_%s' % resource, value)

    def deleter(self):
        self.headers[sysmeta_header(resource, 'acl')] = ''

    return property(getter, setter, deleter,
                    doc='Get and set the %s acl property' % resource)


class SigV4Mixin(object):
    """
    A request class mixin to provide S3 signature v4 functionality
    """

    def check_signature(self, secret):
        user_signature = self.signature
        derived_secret = 'AWS4' + secret
        for scope_piece in self.scope:
            derived_secret = hmac.new(
                derived_secret, scope_piece, sha256).digest()
        valid_signature = hmac.new(
            derived_secret, self.string_to_sign, sha256).hexdigest()
        return user_signature == valid_signature

    @property
    def _is_query_auth(self):
        return 'X-Amz-Credential' in self.params

    @property
    def timestamp(self):
        """
        Return timestamp string according to the auth type
        The difference from v2 is v4 have to see 'X-Amz-Date' even though
        it's query auth type.
        """
        if not self._timestamp:
            try:
                if self._is_query_auth and 'X-Amz-Date' in self.params:
                    # NOTE(andrey-mp): Date in Signature V4 has different
                    # format
                    timestamp = mktime(
                        self.params['X-Amz-Date'], SIGV4_X_AMZ_DATE_FORMAT)
                else:
                    if self.headers.get('X-Amz-Date'):
                        timestamp = mktime(
                            self.headers.get('X-Amz-Date'),
                            SIGV4_X_AMZ_DATE_FORMAT)
                    else:
                        timestamp = mktime(self.headers.get('Date'))
            except (ValueError, TypeError):
                raise AccessDenied('AWS authentication requires a valid Date '
                                   'or x-amz-date header')

            if timestamp < 0:
                raise AccessDenied('AWS authentication requires a valid Date '
                                   'or x-amz-date header')

            try:
                self._timestamp = S3Timestamp(timestamp)
            except ValueError:
                # Must be far-future; blame clock skew
                raise RequestTimeTooSkewed()

        return self._timestamp

    def _validate_expire_param(self):
        """
        Validate X-Amz-Expires in query parameter
        :raises: AccessDenied
        :raises: AuthorizationQueryParametersError
        :raises: AccessDenined
        """
        err = None
        try:
            expires = int(self.params['X-Amz-Expires'])
        except ValueError:
            err = 'X-Amz-Expires should be a number'
        else:
            if expires < 0:
                err = 'X-Amz-Expires must be non-negative'
            elif expires >= 2 ** 63:
                err = 'X-Amz-Expires should be a number'
            elif expires > 604800:
                err = ('X-Amz-Expires must be less than a week (in seconds); '
                       'that is, the given X-Amz-Expires must be less than '
                       '604800 seconds')
        if err:
            raise AuthorizationQueryParametersError(err)

        if int(self.timestamp) + expires < S3Timestamp.now():
            raise AccessDenied('Request has expired')

    def _parse_query_authentication(self):
        """
        Parse v4 query authentication
        - version 4:
            'X-Amz-Credential' and 'X-Amz-Signature' should be in param
        :raises: AccessDenied
        :raises: AuthorizationHeaderMalformed
        """
        if self.params.get('X-Amz-Algorithm') != 'AWS4-HMAC-SHA256':
            raise InvalidArgument('X-Amz-Algorithm',
                                  self.params.get('X-Amz-Algorithm'))
        try:
            cred_param = self.params['X-Amz-Credential'].split("/")
            access = cred_param[0]
            sig = self.params['X-Amz-Signature']
            expires = self.params['X-Amz-Expires']
        except KeyError:
            raise AccessDenied()

        try:
            signed_headers = self.params['X-Amz-SignedHeaders']
        except KeyError:
            # TODO: make sure if is it malformed request?
            raise AuthorizationHeaderMalformed()

        self._signed_headers = set(signed_headers.split(';'))

        # credential must be in following format:
        # <access-key-id>/<date>/<AWS-region>/<AWS-service>/aws4_request
        if not all([access, sig, len(cred_param) == 5, expires]):
            raise AccessDenied()

        return access, sig

    def _parse_header_authentication(self):
        """
        Parse v4 header authentication
        - version 4:
            'X-Amz-Credential' and 'X-Amz-Signature' should be in param
        :raises: AccessDenied
        :raises: AuthorizationHeaderMalformed
        """

        auth_str = self.headers['Authorization']
        cred_param = auth_str.partition(
            "Credential=")[2].split(',')[0].split("/")
        access = cred_param[0]
        sig = auth_str.partition("Signature=")[2].split(',')[0]
        signed_headers = auth_str.partition(
            "SignedHeaders=")[2].split(',', 1)[0]
        # credential must be in following format:
        # <access-key-id>/<date>/<AWS-region>/<AWS-service>/aws4_request
        if not all([access, sig, len(cred_param) == 5]):
            raise AccessDenied()
        if not signed_headers:
            # TODO: make sure if is it Malformed?
            raise AuthorizationHeaderMalformed()

        self._signed_headers = set(signed_headers.split(';'))

        return access, sig

    def _canonical_query_string(self):
        return '&'.join(
            '%s=%s' % (quote(key, safe='-_.~'),
                       quote(value, safe='-_.~'))
            for key, value in sorted(self.params.items())
            if key not in ('Signature', 'X-Amz-Signature'))

    def _headers_to_sign(self):
        """
        Select the headers from the request that need to be included
        in the StringToSign.

        :return : dict of headers to sign, the keys are all lower case
        """
        if 'headers_raw' in self.environ:  # eventlet >= 0.19.0
            # See https://github.com/eventlet/eventlet/commit/67ec999
            headers_lower_dict = defaultdict(list)
            for key, value in self.environ['headers_raw']:
                headers_lower_dict[key.lower().strip()].append(
                    ' '.join(_header_strip(value or '').split()))
            headers_lower_dict = {k: ','.join(v)
                                  for k, v in headers_lower_dict.items()}
        else:  # mostly-functional fallback
            headers_lower_dict = dict(
                (k.lower().strip(), ' '.join(_header_strip(v or '').split()))
                for (k, v) in six.iteritems(self.headers))

        if 'host' in headers_lower_dict and re.match(
                'Boto/2.[0-9].[0-2]',
                headers_lower_dict.get('user-agent', '')):
            # Boto versions < 2.9.3 strip the port component of the host:port
            # header, so detect the user-agent via the header and strip the
            # port if we detect an old boto version.
            headers_lower_dict['host'] = \
                headers_lower_dict['host'].split(':')[0]

        headers_to_sign = [
            (key, value) for key, value in sorted(headers_lower_dict.items())
            if key in self._signed_headers]

        if len(headers_to_sign) != len(self._signed_headers):
            # NOTE: if we are missing the header suggested via
            # signed_header in actual header, it results in
            # SignatureDoesNotMatch in actual S3 so we can raise
            # the error immediately here to save redundant check
            # process.
            raise SignatureDoesNotMatch()

        return headers_to_sign

    def _canonical_uri(self):
        """
        It won't require bucket name in canonical_uri for v4.
        """
        return self.environ.get('RAW_PATH_INFO', self.path)

    def _canonical_request(self):
        # prepare 'canonical_request'
        # Example requests are like following:
        #
        # GET
        # /
        # Action=ListUsers&Version=2010-05-08
        # content-type:application/x-www-form-urlencoded; charset=utf-8
        # host:iam.amazonaws.com
        # x-amz-date:20150830T123600Z
        #
        # content-type;host;x-amz-date
        # e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
        #

        # 1. Add verb like: GET
        cr = [self.method.upper()]

        # 2. Add path like: /
        path = self._canonical_uri()
        cr.append(path)

        # 3. Add query like: Action=ListUsers&Version=2010-05-08
        cr.append(self._canonical_query_string())

        # 4. Add headers like:
        # content-type:application/x-www-form-urlencoded; charset=utf-8
        # host:iam.amazonaws.com
        # x-amz-date:20150830T123600Z
        headers_to_sign = self._headers_to_sign()
        cr.append(''.join('%s:%s\n' % (key, value)
                          for key, value in headers_to_sign))

        # 5. Add signed headers into canonical request like
        # content-type;host;x-amz-date
        cr.append(';'.join(k for k, v in headers_to_sign))

        # 6. Add payload string at the tail
        if 'X-Amz-Credential' in self.params:
            # V4 with query parameters only
            hashed_payload = 'UNSIGNED-PAYLOAD'
        elif 'X-Amz-Content-SHA256' not in self.headers:
            msg = 'Missing required header for this request: ' \
                  'x-amz-content-sha256'
            raise InvalidRequest(msg)
        else:
            hashed_payload = self.headers['X-Amz-Content-SHA256']
        cr.append(hashed_payload)
        return '\n'.join(cr).encode('utf-8')

    @property
    def scope(self):
        return [self.timestamp.amz_date_format.split('T')[0],
                CONF.location, SERVICE, 'aws4_request']

    def _string_to_sign(self):
        """
        Create 'StringToSign' value in Amazon terminology for v4.
        """
        return '\n'.join(['AWS4-HMAC-SHA256',
                          self.timestamp.amz_date_format,
                          '/'.join(self.scope),
                          sha256(self._canonical_request()).hexdigest()])

    def to_swift_req(self, method, container, obj, query=None,
                     body=None, headers=None):
        # SigV4 PUT requests may have a chunked body without the
        # 'Transfer-Encoding' header.
        # The presence of HTTP_X_AMZ_DECODED_CONTENT_LENGTH header
        # is a sign we are in such case.
        if (method == 'PUT' and
                'HTTP_X_AMZ_DECODED_CONTENT_LENGTH' in self.environ):
            try:
                self.environ['HTTP_TRANSFER_ENCODING'] = "chunked"
                self.environ.pop('CONTENT_LENGTH', None)
                self.environ['eventlet.input'].chunked_input = True
            except KeyError:
                LOGGER.warning('SigV4 PUT request ' +
                               'but failed to set chunked transfer-encoding')
        return super(SigV4Mixin, self).to_swift_req(
            method, container, obj, query=query, body=body, headers=headers)


def get_request_class(env):
    """
    Helper function to find a request class to use from Map
    """
    if CONF.s3_acl:
        request_classes = (S3AclRequest, SigV4S3AclRequest)
    else:
        request_classes = (Request, SigV4Request)

    req = swob.Request(env)
    if 'X-Amz-Credential' in req.params or \
            req.headers.get('Authorization', '').startswith(
                'AWS4-HMAC-SHA256 '):
        # This is an Amazon SigV4 request
        return request_classes[1]
    else:
        # The others using Amazon SigV2 class
        return request_classes[0]


class Request(swob.Request):
    """
    S3 request object.
    """

    bucket_acl = _header_acl_property('container')
    object_acl = _header_acl_property('object')

    def __init__(self, env, app=None, slo_enabled=True):
        # NOTE: app is not used by this class, need for compatibility of S3acl
        swob.Request.__init__(self, env)

        # Allow to accept HTTP requests with an absoluteURI
        path_info = self.environ.get('PATH_INFO')
        if path_info:
            self.environ['PATH_INFO'] = urlparse(path_info).path
        raw_path_info = self.environ.get('RAW_PATH_INFO')
        if raw_path_info:
            self.environ['RAW_PATH_INFO'] = urlparse(raw_path_info).path

        self._timestamp = None
        self.access_key, self.signature = self._parse_auth_info()
        self.bucket_in_host = self._parse_host()
        self.container_name, self.object_name = self._parse_uri()
        self._validate_headers()
        if not self._is_anonymous:
            # Lock in string-to-sign now, before we start messing
            # with query params
            self.string_to_sign = self._string_to_sign()
            self.environ['swift3.auth_details'] = {
                'access_key': self.access_key,
                'signature': self.signature,
                'string_to_sign': self.string_to_sign,
                'check_signature': self.check_signature,
            }
        else:
            self.string_to_sign = None
        self._cleanup_invalid_range_format()
        self.token = None
        self.account = None
        self.user_id = None
        self.slo_enabled = slo_enabled

        # NOTE(andrey-mp): substitute authorization header for next modules
        # in pipeline (s3token). it uses this and X-Auth-Token in specific
        # format.
        # (kota_): yeah, the reason we need this is s3token only supports
        # v2 like header consists of AWS access:signature. Since the commit
        # b626a3ca86e467fc7564eac236b9ee2efd49bdcc, the s3token is in swift3
        # repo so probably we need to change s3token to support v4 format.
        if self.access_key:
            self.headers['Authorization'] = 'AWS %s:%s' % (
                self.access_key, self.signature)
        # Avoids that swift.swob.Response replaces Location header value
        # by full URL when absolute path given. See swift.swob for more detail.
        self.environ['swift.leave_relative_location'] = True

    def check_signature(self, secret):
        user_signature = self.signature
        valid_signature = base64.b64encode(hmac.new(
            secret, self.string_to_sign, sha1).digest()).strip()
        return user_signature == valid_signature

    @property
    def timestamp(self):
        """
        S3Timestamp from Date header. If X-Amz-Date header specified, it
        will be prior to Date header.

        :return : S3Timestamp instance
        """
        if not self._timestamp:
            try:
                if self._is_query_auth and 'Timestamp' in self.params:
                    # If Timestamp specified in query, it should be prior
                    # to any Date header (is this right?)
                    timestamp = mktime(
                        self.params['Timestamp'], SIGV2_TIMESTAMP_FORMAT)
                else:
                    timestamp = mktime(
                        self.headers.get('X-Amz-Date',
                                         self.headers.get('Date')))
            except ValueError:
                raise AccessDenied('AWS authentication requires a valid Date '
                                   'or x-amz-date header')

            if timestamp < 0:
                raise AccessDenied('AWS authentication requires a valid Date '
                                   'or x-amz-date header')
            try:
                self._timestamp = S3Timestamp(timestamp)
            except ValueError:
                # Must be far-future; blame clock skew
                raise RequestTimeTooSkewed()

        return self._timestamp

    @property
    def _is_header_auth(self):
        return 'Authorization' in self.headers

    @property
    def _is_query_auth(self):
        return ('AWSAccessKeyId' in self.params or
                'X-Amz-Credential' in self.params)

    @property
    def _is_anonymous(self):
        return (not self._is_header_auth and
                'Signature' not in self.params and
                'Expires' not in self.params and
                'X-Amz-Credential' not in self.params)

    def _cleanup_invalid_range_format(self):
        range_ = self.headers.get('Range', None)
        if range_ is not None:
            try:
                swob.Range(range_)
            except ValueError:
                del self.headers['Range']

    def _parse_host(self):
        storage_domain = CONF.storage_domain
        if not storage_domain:
            return None

        if not storage_domain.startswith('.'):
            storage_domain = '.' + storage_domain

        if 'HTTP_HOST' in self.environ:
            given_domain = self.environ['HTTP_HOST']
        elif 'SERVER_NAME' in self.environ:
            given_domain = self.environ['SERVER_NAME']
        else:
            return None

        port = ''
        if ':' in given_domain:
            given_domain, port = given_domain.rsplit(':', 1)
        if given_domain.endswith(storage_domain):
            return given_domain[:-len(storage_domain)]

        return None

    def _parse_uri(self):
        if not check_utf8(self.environ['PATH_INFO']):
            raise InvalidURI(self.path)

        if self.bucket_in_host:
            obj = self.environ['PATH_INFO'][1:] or None
            return self.bucket_in_host, obj

        try:
            bucket, obj = self.split_path(0, 2, True)
        except ValueError:
            raise InvalidURI(self.path)

        if bucket and not validate_bucket_name(bucket):
            # Ignore GET service case
            raise InvalidBucketName(bucket)
        return (bucket, obj)

    def _parse_query_authentication(self):
        """
        Parse v2 authentication query args
        TODO: make sure if 0, 1, 3 is supported?
        - version 0, 1, 2, 3:
            'AWSAccessKeyId' and 'Signature' should be in param

        :return: a tuple of access_key and signature
        :raises: AccessDenied
        """
        try:
            access = self.params['AWSAccessKeyId']
            expires = self.params['Expires']
            sig = self.params['Signature']
        except KeyError:
            raise AccessDenied()

        if not all([access, sig, expires]):
            raise AccessDenied()

        return access, sig

    def _parse_header_authentication(self):
        """
        Parse v2 header authentication info

        :returns: a tuple of access_key and signature
        :raises: AccessDenied
        """
        auth_str = self.headers['Authorization']
        if not auth_str.startswith('AWS ') or ':' not in auth_str:
            raise AccessDenied()
        # This means signature format V2
        access, sig = auth_str.split(' ', 1)[1].rsplit(':', 1)
        return access, sig

    def _is_allowed_anonymous_request(self):
        """
        Tell if the current request represents an allowed anonymous request.

        Will return False if anonymous requests are disabled by configuration.
        """
        if not self._is_anonymous:
            return False

        if self._parse_host():
            # Virtual-hosted style anonymous request
            return True

        src = self.environ['PATH_INFO'].lstrip('/').split('/', 2)[0]
        if not src:
            # Maybe a virtual-hosted style CORS request
            return self.method == 'OPTIONS'
        elif valid_api_version(src) or src in ('auth', 'info'):
            # Not an S3 request
            return False
        # Path-style anonymous request
        return CONF.allow_anymous_path_request

    def _parse_auth_info(self):
        """Extract the access key identifier and signature.

        :returns: a tuple of access_key and signature
        :raises: NotS3Request
        """
        if self._is_query_auth:
            return self._parse_query_authentication()
        elif self._is_header_auth:
            return self._parse_header_authentication()
        # TODO(mb): check src against auth_prefix's tempauth
        elif self.bucket_db and self._is_allowed_anonymous_request():
            # This is an anonymous request, we will have to resolve the
            # account name from the bucket name thanks to the bucket DB.
            return None, None
        else:
            # if this request is neither query auth nor header auth
            # swift3 regard this as not s3 request
            raise NotS3Request()

    def _validate_expire_param(self):
        """
        Validate Expires in query parameters
        :raises: AccessDenied
        """
        # Expires header is a float since epoch
        try:
            ex = S3Timestamp(float(self.params['Expires']))
        except ValueError:
            raise AccessDenied()

        if S3Timestamp.now() > ex:
            raise AccessDenied('Request has expired')

        if ex >= 2 ** 31:
            raise AccessDenied(
                'Invalid date (should be seconds since epoch): %s' %
                self.params['Expires'])

    def _validate_dates(self):
        """
        Validate Date/X-Amz-Date headers for signature v2
        :raises: AccessDenied
        :raises: RequestTimeTooSkewed
        """
        if self._is_anonymous:
            return

        if self._is_query_auth:
            self._validate_expire_param()
            # TODO: make sure the case if timestamp param in query
            return

        date_header = self.headers.get('Date')
        amz_date_header = self.headers.get('X-Amz-Date')
        if not date_header and not amz_date_header:
            raise AccessDenied('AWS authentication requires a valid Date '
                               'or x-amz-date header')

        # Anyways, request timestamp should be validated
        epoch = S3Timestamp(0)
        if self.timestamp < epoch:
            raise AccessDenied()

        # If the standard date is too far ahead or behind, it is an
        # error
        delta = 60 * 5
        if abs(int(self.timestamp) - int(S3Timestamp.now())) > delta:
            raise RequestTimeTooSkewed()

    def _validate_headers(self):
        if 'CONTENT_LENGTH' in self.environ:
            try:
                if self.content_length < 0:
                    raise InvalidArgument('Content-Length',
                                          self.content_length)
            except (ValueError, TypeError):
                raise InvalidArgument('Content-Length',
                                      self.environ['CONTENT_LENGTH'])

        self._validate_dates()

        value = _header_strip(self.headers.get('Content-MD5'))
        if value is not None:
            if not re.match('^[A-Za-z0-9+/]+={0,2}$', value):
                # Non-base64-alphabet characters in value.
                raise InvalidDigest(content_md5=value)
            try:
                self.headers['ETag'] = value.decode('base64').encode('hex')
            except Exception:
                raise InvalidDigest(content_md5=value)

            if len(self.headers['ETag']) != 32:
                raise InvalidDigest(content_md5=value)

        if self.method == 'PUT' and any(h in self.headers for h in (
                'If-Match', 'If-None-Match',
                'If-Modified-Since', 'If-Unmodified-Since')):
            raise S3NotImplemented(
                'Conditional object PUTs are not supported.')

        if 'X-Amz-Copy-Source' in self.headers:
            try:
                check_path_header(self, 'X-Amz-Copy-Source', 2, '')
            except swob.HTTPException:
                msg = 'Copy Source must mention the source bucket and key: ' \
                      'sourcebucket/sourcekey'
                raise InvalidArgument('x-amz-copy-source',
                                      self.headers['X-Amz-Copy-Source'],
                                      msg)

        if 'x-amz-metadata-directive' in self.headers:
            value = self.headers['x-amz-metadata-directive']
            if value not in ('COPY', 'REPLACE'):
                err_msg = 'Unknown metadata directive.'
                raise InvalidArgument('x-amz-metadata-directive', value,
                                      err_msg)

        if 'x-amz-storage-class' in self.headers:
            # Only STANDARD is supported now.
            if self.headers['x-amz-storage-class'] != 'STANDARD':
                raise InvalidStorageClass()

        if 'x-amz-mfa' in self.headers:
            raise S3NotImplemented('MFA Delete is not supported.')

        if 'x-amz-server-side-encryption' in self.headers:
            raise S3NotImplemented('Server-side encryption is not supported.')

        if 'x-amz-website-redirect-location' in self.headers:
            raise S3NotImplemented('Website redirection is not supported.')

    @property
    def body(self):
        """
        swob.Request.body is not secure against malicious input.  It consumes
        too much memory without any check when the request body is excessively
        large.  Use xml() instead.
        """
        raise AttributeError("No attribute 'body'")

    def xml(self, max_length):
        """
        Similar to swob.Request.body, but it checks the content length before
        creating a body string.
        """
        te = self.headers.get('transfer-encoding', '')
        te = [x.strip() for x in te.split(',') if x.strip()]
        if te and (len(te) > 1 or te[-1] != 'chunked'):
            raise S3NotImplemented('A header you provided implies '
                                   'functionality that is not implemented',
                                   header='Transfer-Encoding')

        if self.message_length() > max_length:
            raise MalformedXML()

        if te or self.message_length():
            # Limit the read similar to how SLO handles manifests
            body = self.body_file.read(max_length)
        else:
            # No (or zero) Content-Length provided, and not chunked transfer;
            # no body. Assume zero-length, and enforce a required body below.
            return None

        return body

    def check_md5(self, body):
        if 'HTTP_CONTENT_MD5' not in self.environ:
            raise InvalidRequest('Missing required header for this request: '
                                 'Content-MD5')

        digest = md5(body).digest().encode('base64').strip()
        if self.environ['HTTP_CONTENT_MD5'] != digest:
            raise BadDigest(content_md5=self.environ['HTTP_CONTENT_MD5'])

    def _copy_source_headers(self):
        env = {}
        for key, value in self.environ.items():
            if key.startswith('HTTP_X_AMZ_COPY_SOURCE_'):
                env[key.replace('X_AMZ_COPY_SOURCE_', '')] = value

        return swob.HeaderEnvironProxy(env)

    def _split_path_query(self, src_path, minsegs=1, maxsegs=None,
                          rest_with_last=False):
        """
        Split path, and extract a query string from the last part.
        """
        split = split_path(src_path, minsegs, maxsegs, rest_with_last)
        if rest_with_last and '?' in split[-1]:
            last, query = split[-1].rsplit('?', 1)
            query = dict(parse_qsl(query, True))
            return split[:-1] + [last, query]
        else:
            return split + [None]

    def check_copy_source(self, app):
        """
        check_copy_source checks the copy source existence and if copying an
        object to itself, for illegal request parameters

        :returns: the source HEAD response
        """
        if 'X-Amz-Copy-Source' not in self.headers:
            return None

        src_path = unquote(self.headers['X-Amz-Copy-Source'])
        src_path = src_path if src_path.startswith('/') else \
            ('/' + src_path)
        src_bucket, src_obj, query = self._split_path_query(
            src_path, 0, 2, True)
        headers = swob.HeaderKeyDict()
        headers.update(self._copy_source_headers())

        src_resp = self.get_versioned_response(app, 'HEAD', src_bucket,
                                               src_obj,
                                               headers=headers, query=query)
        if src_resp.status_int == 304:  # pylint: disable-msg=E1101
            raise PreconditionFailed()

        self.headers['X-Amz-Copy-Source'] = \
            '/' + self.headers['X-Amz-Copy-Source'].lstrip('/')
        source_container, source_obj = \
            split_path(self.headers['X-Amz-Copy-Source'], 1, 2, True)

        if (self.container_name == source_container and
                self.object_name == source_obj):
            if self.headers.get('x-amz-metadata-directive', 'COPY') == 'COPY':
                raise InvalidRequest("This copy request is illegal "
                                     "because it is trying to copy an "
                                     "object to itself without "
                                     "changing the object's metadata, "
                                     "storage class, website redirect "
                                     "location or encryption "
                                     "attributes.")
            else:
                self.environ['swift3.copy_to_itself'] = True

        return src_resp

    def _canonical_uri(self):
        """
        Require bucket name in canonical_uri for v2 in virtual hosted-style.
        """
        raw_path_info = self.environ.get('RAW_PATH_INFO', self.path)
        if self.bucket_in_host:
            raw_path_info = '/' + self.bucket_in_host + raw_path_info
        return raw_path_info

    def _string_to_sign(self):
        """
        Create 'StringToSign' value in Amazon terminology for v2.
        """
        amz_headers = {}

        buf = [self.method,
               _header_strip(self.headers.get('Content-MD5')) or '',
               _header_strip(self.headers.get('Content-Type')) or '']

        if 'headers_raw' in self.environ:  # eventlet >= 0.19.0
            # See https://github.com/eventlet/eventlet/commit/67ec999
            amz_headers = defaultdict(list)
            for key, value in self.environ['headers_raw']:
                key = key.lower()
                if not key.startswith('x-amz-'):
                    continue
                amz_headers[key.strip()].append(value.strip())
            amz_headers = dict((key, ','.join(value))
                               for key, value in amz_headers.items())
        else:  # mostly-functional fallback
            amz_headers = dict((key.lower(), value)
                               for key, value in self.headers.items()
                               if key.lower().startswith('x-amz-'))

        if self._is_header_auth:
            if 'x-amz-date' in amz_headers:
                buf.append('')
            elif 'Date' in self.headers:
                buf.append(self.headers['Date'])
        elif self._is_query_auth:
            buf.append(self.params['Expires'])
        else:
            # Should have already raised NotS3Request in _parse_auth_info,
            # but as a sanity check...
            raise AccessDenied()

        for key, value in sorted(amz_headers.items()):
            buf.append("%s:%s" % (key, value))

        path = self._canonical_uri()
        if self.query_string:
            path += '?' + self.query_string
        params = []
        if '?' in path:
            path, args = path.split('?', 1)
            for key, value in sorted(self.params.items()):
                if key in ALLOWED_SUB_RESOURCES:
                    params.append('%s=%s' % (key, value) if value else key)
        if params:
            buf.append('%s?%s' % (path, '&'.join(params)))
        else:
            buf.append(path)
        return '\n'.join(buf)

    @property
    def controller_name(self):
        return self.controller.__name__[:-len('Controller')]

    @property
    def controller(self):
        if self.is_service_request:
            return ServiceController

        if not self.slo_enabled:
            multi_part = ['partNumber', 'uploadId', 'uploads']
            if len([p for p in multi_part if p in self.params]):
                LOGGER.warning('multipart: No SLO middleware in pipeline')
                raise S3NotImplemented("Multi-part feature isn't support")

        if 'acl' in self.params:
            return AclController
        if 'delete' in self.params:
            return MultiObjectDeleteController
        if 'lifecycle' in self.params:
            return LifecycleController
        if 'location' in self.params:
            return LocationController
        if 'logging' in self.params:
            return LoggingStatusController
        if 'partNumber' in self.params:
            return PartController
        if 'tagging' in self.params:
            return TaggingController
        if 'uploadId' in self.params:
            return UploadController
        if 'uploads' in self.params:
            return UploadsController
        if 'versioning' in self.params:
            return VersioningController
        if 'cors' in self.params:
            return CorsController

        unsupported = ('notification', 'policy', 'requestPayment', 'torrent',
                       'website', 'restore')
        if set(unsupported) & set(self.params):
            return UnsupportedController

        if self.is_object_request:
            return ObjectController
        if self.bucket_db:
            return UniqueBucketController
        return BucketController

    @property
    def is_service_request(self):
        return not self.container_name

    @property
    def is_bucket_request(self):
        return self.container_name and not self.object_name

    @property
    def is_object_request(self):
        return self.container_name and self.object_name

    @property
    def is_authenticated(self):
        return self.account is not None

    @property
    def bucket_db(self):
        return self.environ.get('swift3.bucket_db')

    def to_swift_req(self, method, container, obj, query=None,
                     body=None, headers=None):
        """
        Create a Swift request based on this request's environment.
        """
        env = self.environ.copy()

        if container and self.bucket_db:
            ct_owner = self.bucket_db.get_owner(container)
            account = ct_owner if ct_owner else None
        else:
            account = None

        if account is None:
            if self.account is None:
                account = self.access_key
            else:
                account = self.account

        drop_metadata = False
        if ('HTTP_X_AMZ_METADATA_DIRECTIVE' in env or
                'HTTP_X_AMZ_COPY_SOURCE' in env):
            drop_metadata = \
                env.get('HTTP_X_AMZ_METADATA_DIRECTIVE', 'COPY') == 'COPY'
            env['HTTP_X_FRESH_METADATA'] = str(not drop_metadata)
            env.pop('HTTP_X_AMZ_METADATA_DIRECTIVE', None)

        def sanitize(value):
            if set(value).issubset(string.printable):
                return value

            value = Header(value, 'UTF-8').encode()
            if value.startswith('=?utf-8?q?'):
                return '=?UTF-8?Q?' + value[10:]
            elif value.startswith('=?utf-8?b?'):
                return '=?UTF-8?B?' + value[10:]
            else:
                return value

        if 'headers_raw' in env:  # eventlet >= 0.19.0
            # See https://github.com/eventlet/eventlet/commit/67ec999
            for key, value in env['headers_raw']:
                if not key.lower().startswith('x-amz-meta-'):
                    continue
                # AWS ignores user-defined headers with these characters
                if any(c in key for c in ' "),/;<=>?@[\\]{}'):
                    # NB: apparently, '(' *is* allowed
                    continue
                # Note that this may have already been deleted, e.g. if the
                # client sent multiple headers with the same name, or both
                # x-amz-meta-foo-bar and x-amz-meta-foo_bar
                env.pop('HTTP_' + key.replace('-', '_').upper(), None)
                if drop_metadata:
                    continue
                # Need to preserve underscores. Since we know '=' can't be
                # present, quoted-printable seems appropriate.
                key = key.replace('_', '=5F').replace('-', '_').upper()
                key = 'HTTP_X_OBJECT_META_' + key[11:]
                if key in env:
                    env[key] += ',' + sanitize(value)
                else:
                    env[key] = sanitize(value)
        else:  # mostly-functional fallback
            for key in self.environ:
                if not key.startswith('HTTP_X_AMZ_META_'):
                    continue
                # AWS ignores user-defined headers with these characters
                if any(c in key for c in ' "),/;<=>?@[\\]{}'):
                    # NB: apparently, '(' *is* allowed
                    continue
                value = env.pop(key)
                if drop_metadata:
                    continue
                env['HTTP_X_OBJECT_META_' + key[16:]] = sanitize(value)

        if 'HTTP_X_AMZ_COPY_SOURCE' in env:
            raw_copy_source = env['HTTP_X_AMZ_COPY_SOURCE']
            if not raw_copy_source.startswith('/'):
                raw_copy_source = '/' + raw_copy_source
            # Check for a query string with versionId
            if '?' in raw_copy_source:
                src_ct, src_obj, src_qs = self._split_path_query(
                    raw_copy_source, 2, 2, True)
                if src_qs and 'versionId' in src_qs:
                    version_id = src_qs['versionId']
                    src_ct = src_ct + VERSIONING_SUFFIX
                    src_obj = versioned_object_name(src_obj, version_id)
                env['HTTP_X_COPY_FROM'] = '%s/%s' % (src_ct, src_obj)
            else:
                env['HTTP_X_COPY_FROM'] = raw_copy_source
            del env['HTTP_X_AMZ_COPY_SOURCE']
            env['CONTENT_LENGTH'] = '0'
            # Mitigate a bug where overwriting a SLO did not remove parts.
            if env.get('swift3.copy_to_itself', False):
                if query is None:
                    query = dict()
                query['multipart-manifest'] = 'get'

        if CONF.force_swift_request_proxy_log:
            env['swift.proxy_access_log_made'] = False
        env['swift.source'] = 'S3'
        if method is not None:
            env['REQUEST_METHOD'] = method

        env['HTTP_X_AUTH_TOKEN'] = self.token

        if obj:
            path = '/v1/%s/%s/%s' % (account, container, obj)
        elif container:
            path = '/v1/%s/%s' % (account, container)
        else:
            path = '/v1/%s' % (account)
        env['PATH_INFO'] = path

        query_string = ''
        if query is not None:
            params = []
            for key, value in sorted(query.items()):
                if value is not None:
                    params.append('%s=%s' % (key, quote(str(value))))
                else:
                    params.append(key)
            query_string = '&'.join(params)
        env['QUERY_STRING'] = query_string

        return swob.Request.blank(quote(path), environ=env, body=body,
                                  headers=headers)

    def _swift_success_codes(self, method, container, obj):
        """
        Returns a list of expected success codes from Swift.
        """
        if not container:
            # Swift account access.
            code_map = {
                'GET': [
                    HTTP_OK,
                ],
            }
        elif not obj:
            # Swift container access.
            code_map = {
                'HEAD': [
                    HTTP_NO_CONTENT,
                ],
                'GET': [
                    HTTP_OK,
                    HTTP_NO_CONTENT,
                ],
                'PUT': [
                    HTTP_CREATED,
                ],
                'POST': [
                    HTTP_NO_CONTENT,
                ],
                'DELETE': [
                    HTTP_NO_CONTENT,
                ],
            }
            # If bucket creation succeeds after a timeout,
            # we have to accept that the container already exists.
            # We rely on the bucket_db to know if the bucket already
            # exists or not.
            if self.bucket_db:
                code_map['PUT'].append(HTTP_NO_CONTENT)
        else:
            # Swift object access.
            code_map = {
                'HEAD': [
                    HTTP_OK,
                    HTTP_PARTIAL_CONTENT,
                    HTTP_NOT_MODIFIED,
                ],
                'GET': [
                    HTTP_OK,
                    HTTP_PARTIAL_CONTENT,
                    HTTP_NOT_MODIFIED,
                ],
                'PUT': [
                    HTTP_CREATED,
                ],
                'POST': [
                    HTTP_ACCEPTED,
                ],
                'DELETE': [
                    HTTP_OK,
                    HTTP_NO_CONTENT,
                ],
            }

        return code_map[method]

    def _swift_error_codes(self, method, container, obj, env, app):
        """
        Returns a dict from expected Swift error codes to the corresponding S3
        error responses.
        """
        if not container:
            # Swift account access.
            code_map = {
                'GET': {
                },
            }
        elif not obj:
            # Swift container access.
            code_map = {
                'HEAD': {
                    HTTP_NOT_FOUND: (NoSuchBucket, container),
                },
                'GET': {
                    HTTP_NOT_FOUND: (NoSuchBucket, container),
                },
                'PUT': {
                    HTTP_NO_CONTENT: (BucketAlreadyExists, container),
                    HTTP_ACCEPTED: (BucketAlreadyExists, container),
                },
                'POST': {
                    HTTP_NOT_FOUND: (NoSuchBucket, container),
                },
                'DELETE': {
                    HTTP_NOT_FOUND: (NoSuchBucket, container),
                    HTTP_CONFLICT: BucketNotEmpty,
                },
            }
        else:
            # Swift object access.

            # 404s differ depending upon whether the bucket exists
            # Note that base-container-existence checks happen elsewhere for
            # multi-part uploads, and get_container_info should be pulling
            # from the env cache
            def not_found_handler():
                if container.endswith(MULTIUPLOAD_SUFFIX) or \
                        is_success(get_container_info(
                            env, app, swift_source='S3').get('status')):
                    return NoSuchKey(obj)
                return NoSuchBucket(container)

            code_map = {
                'HEAD': {
                    HTTP_NOT_FOUND: not_found_handler,
                    HTTP_PRECONDITION_FAILED: PreconditionFailed,
                },
                'GET': {
                    HTTP_NOT_FOUND: not_found_handler,
                    HTTP_PRECONDITION_FAILED: PreconditionFailed,
                    HTTP_REQUESTED_RANGE_NOT_SATISFIABLE: InvalidRange,
                },
                'PUT': {
                    HTTP_NOT_FOUND: (NoSuchBucket, container),
                    HTTP_UNPROCESSABLE_ENTITY: BadDigest,
                    HTTP_REQUEST_ENTITY_TOO_LARGE: EntityTooLarge,
                    HTTP_LENGTH_REQUIRED: MissingContentLength,
                    HTTP_REQUEST_TIMEOUT: RequestTimeout,
                    HTTP_CONFLICT: OperationAborted,
                },
                'POST': {
                    HTTP_NOT_FOUND: not_found_handler,
                    HTTP_PRECONDITION_FAILED: PreconditionFailed,
                },
                'DELETE': {
                    HTTP_NOT_FOUND: (NoSuchBucket, container),
                    HTTP_METHOD_NOT_ALLOWED: (MethodNotAllowed,
                                              method, 'object'),
                },
            }

        return code_map[method]

    def _get_response(self, app, method, container, obj,
                      headers=None, body=None, query=None):
        """
        Calls the application with this request's environment.  Returns a
        Response object that wraps up the application's result.
        """

        method = method or self.environ['REQUEST_METHOD']

        if container is None:
            container = self.container_name
        if obj is None:
            obj = self.object_name

        sw_req = self.to_swift_req(method, container, obj, headers=headers,
                                   body=body, query=query)

        if self.bucket_db:
            if self._is_anonymous and method == 'HEAD':
                # Allow anonymous HEAD requests to read object ACLs
                sw_req.environ['swift.authorize_override'] = True

        sw_resp = sw_req.get_response(app)

        # reuse account and tokens
        _, self.account, _ = split_path(sw_resp.environ['PATH_INFO'],
                                        2, 3, True)
        self.account = utf8encode(self.account)

        resp = Response.from_swift_resp(sw_resp)
        status = resp.status_int  # pylint: disable-msg=E1101

        if not self.user_id:
            if 'HTTP_X_USER_NAME' in sw_resp.environ:
                # keystone
                self.user_id = \
                    utf8encode("%s:%s" %
                               (sw_resp.environ['HTTP_X_TENANT_NAME'],
                                sw_resp.environ['HTTP_X_USER_NAME']))
            else:
                # tempauth
                self.user_id = self.access_key

        success_codes = self._swift_success_codes(method, container, obj)
        error_codes = self._swift_error_codes(method, container, obj,
                                              sw_req.environ, app)

        if status in success_codes:
            return resp

        err_msg = resp.body

        if status in error_codes:
            err_resp = \
                error_codes[sw_resp.status_int]  # pylint: disable-msg=E1101
            if isinstance(err_resp, tuple):
                raise err_resp[0](*err_resp[1:])
            else:
                raise err_resp()

        if status == HTTP_BAD_REQUEST:
            raise BadRequest(err_msg)
        if status == HTTP_UNAUTHORIZED:
            raise SignatureDoesNotMatch()
        if status == HTTP_FORBIDDEN:
            raise AccessDenied()
        if status == HTTP_SERVICE_UNAVAILABLE:
            raise ServiceUnavailable()
        if status == HTTP_CLIENT_CLOSED_REQUEST:
            raise RequestTimeout()

        raise InternalError('unexpected status code %d' % status)

    def get_response(self, app, method=None, container=None, obj=None,
                     headers=None, body=None, query=None):
        """
        get_response is an entry point to be extended for child classes.
        If additional tasks needed at that time of getting swift response,
        we can override this method. swift3.request.Request need to just call
        _get_response to get pure swift response.
        """

        if 'HTTP_X_AMZ_ACL' in self.environ:
            handle_acl_header(self)

        return self._get_response(app, method, container, obj,
                                  headers, body, query)

    def _build_version(self, container=None, obj=None, query=None):
        """
        Get modified copies of container and object names by taking
        the optional 'versionId' from query or self.params into account.
        """
        if query and 'versionId' in query:
            version_id = query['versionId']
        elif 'versionId' in self.params:
            version_id = self.params['versionId']
        else:
            version_id = None
        if version_id:
            container = (container or self.container_name) + VERSIONING_SUFFIX
            obj = versioned_object_name(obj or self.object_name, version_id)
        return container, obj

    def get_versioned_response(self, app, method=None, container=None,
                               obj=None, headers=None, body=None, query=None):
        """
        Same as get_response(), but take the optional 'versionId'
        from self.params into account.
        """
        container, obj = self._build_version(container, obj, query)
        return self.get_response(app, method, container, obj,
                                 headers, body, query)

    def _get_versioned_response(self, app, method=None, container=None,
                                obj=None, headers=None, body=None, query=None):
        """
        Same as _get_reponse(), but take the optional 'versionId'
        from self.params into account.
        """
        container, obj = self._build_version(container, obj, query)
        return self._get_response(app, method, container, obj,
                                  headers, body, query)

    def get_validated_param(self, param, default, limit=MAX_32BIT_INT):
        value = default
        if param in self.params:
            try:
                value = int(self.params[param])
                if value < 0:
                    err_msg = 'Argument %s must be an integer between 0 and' \
                              ' %d' % (param, MAX_32BIT_INT)
                    raise InvalidArgument(param, self.params[param], err_msg)

                if value > MAX_32BIT_INT:
                    # check the value because int() could build either a long
                    # instance or a 64bit integer.
                    raise ValueError()

                if limit < value:
                    value = limit

            except ValueError:
                err_msg = 'Provided %s not an integer or within ' \
                          'integer range' % param
                raise InvalidArgument(param, self.params[param], err_msg)

        return value

    def get_container_info(self, app):
        """
        get_container_info will return a result dict of get_container_info
        from the backend Swift.

        :returns: a dictionary of container info from
                  swift.controllers.base.get_container_info
        :raises: NoSuchBucket when the container doesn't exist
        :raises: InternalError when the request failed without 404
        """
        if self.is_authenticated or \
                self.bucket_db and self._is_allowed_anonymous_request():
            # if we have already authenticated, yes we can use the account
            # name like as AUTH_xxx for performance efficiency
            sw_req = self.to_swift_req(app, self.container_name, None)
            info = get_container_info(sw_req.environ, app)
            if is_success(info['status']):
                return info
            elif info['status'] == 404:
                raise NoSuchBucket(self.container_name)
            else:
                raise InternalError(
                    'unexpected status code %d' % info['status'])
        else:
            # otherwise we do naive HEAD request with the authentication
            resp = self.get_response(app, 'HEAD', self.container_name, '')
            all_headers = dict(resp.sw_headers)
            all_headers.update(resp.sysmeta_headers)
            return headers_to_container_info(
                all_headers, resp.status_int)  # pylint: disable-msg=E1101

    def get_object_info(self, app, container_name=None, object_name=None):
        if container_name is None:
            container_name = self.container_name
        if object_name is None:
            object_name = self.object_name
        sw_req = self.to_swift_req('HEAD', container_name, object_name)
        return get_object_info(sw_req.environ, app)

    def gen_multipart_manifest_delete_query(self, app):
        if not CONF.allow_multipart_uploads:
            return None
        query = {'multipart-manifest': 'delete'}
        try:
            resp = self.get_versioned_response(app, 'HEAD')
        except NoSuchKey:
            return None
        return query if resp.is_slo else None


class S3AclRequest(Request):
    """
    S3Acl request object.
    """
    def __init__(self, env, app, slo_enabled=True):
        super(S3AclRequest, self).__init__(env, slo_enabled)
        if not self._is_anonymous:
            self.authenticate(app)

    @property
    def controller(self):
        if 'acl' in self.params and not self.is_service_request:
            return S3AclController
        return super(S3AclRequest, self).controller

    def authenticate(self, app):
        """
        authenticate method will run pre-authenticate request and retrieve
        account information.
        Note that it currently supports only keystone and tempauth.
        (no support for the third party authentication middleware)
        """
        sw_req = self.to_swift_req('TEST', None, None, body='')
        # don't show log message of this request
        sw_req.environ['swift.proxy_access_log_made'] = True

        sw_resp = sw_req.get_response(app)

        if not sw_req.remote_user:
            raise SignatureDoesNotMatch()

        _, self.account, _ = split_path(sw_resp.environ['PATH_INFO'],
                                        2, 3, True)
        self.account = utf8encode(self.account)

        if 'HTTP_X_USER_NAME' in sw_resp.environ:
            # keystone
            self.user_id = "%s:%s" % (sw_resp.environ['HTTP_X_TENANT_NAME'],
                                      sw_resp.environ['HTTP_X_USER_NAME'])
            self.user_id = utf8encode(self.user_id)
            self.token = sw_resp.environ.get('HTTP_X_AUTH_TOKEN')
        else:
            # tempauth
            self.user_id = self.access_key

        # Need to skip S3 authorization on subsequent requests to prevent
        # overwriting the account in PATH_INFO
        del self.headers['Authorization']
        del self.environ['swift3.auth_details']

    def to_swift_req(self, method, container, obj, query=None,
                     body=None, headers=None):
        sw_req = super(S3AclRequest, self).to_swift_req(
            method, container, obj, query, body, headers)
        if self.account:
            sw_req.environ['swift_owner'] = True  # needed to set ACL
            sw_req.environ['swift.authorize_override'] = True
            sw_req.environ['swift.authorize'] = lambda req: None
        return sw_req

    def get_acl_response(self, app, method=None, container=None, obj=None,
                         headers=None, body=None, query=None):
        """
        Wrapper method of _get_response to add s3 acl information
        from response sysmeta headers.
        """

        resp = self._get_response(
            app, method, container, obj, headers, body, query)

        resp.bucket_acl = decode_acl('container', resp.sysmeta_headers)
        resp.object_acl = decode_acl('object', resp.sysmeta_headers)
        return resp

    def get_response(self, app, method=None, container=None, obj=None,
                     headers=None, body=None, query=None):
        """
        Wrap up get_response call to hook with acl handling method.
        """
        acl_handler = get_acl_handler(self.controller_name)(
            self, container, obj, headers)
        resp = acl_handler.handle_acl(app, method)

        # possible to skip recalling get_response_acl if resp is not
        # None (e.g. HEAD)
        if resp:
            return resp
        return self.get_acl_response(app, method, container, obj,
                                     headers, body, query)


class SigV4Request(SigV4Mixin, Request):
    pass


class SigV4S3AclRequest(SigV4Mixin, S3AclRequest):
    pass
