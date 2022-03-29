# Copyright (c) 2017 OpenStack Foundation.
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

from swift.common.utils import public

from swift3.controllers.base import Controller, bucket_operation
from swift3.etree import fromstring, DocumentInvalid, XMLSyntaxError
from swift3.iam import check_iam_access
from swift3.response import HTTPNoContent, HTTPOk, \
    NoSuchLifecycleConfiguration, MalformedXML
from swift3.utils import convert_response, sysmeta_header


LIFECYCLE_HEADER = sysmeta_header('container', 'lifecycle')
MAX_LIFECYCLE_BODY_SIZE = 64 * 1024  # Arbitrary


class LifecycleController(Controller):
    """
    Handles the following APIs:

     - GET Bucket lifecycle
     - PUT Bucket lifecycle
     - DELETE Bucket lifecycle

    """

    @public
    @bucket_operation(err_resp=NoSuchLifecycleConfiguration)
    @check_iam_access('s3:GetLifecycleConfiguration')
    def GET(self, req):
        """
        Handles GET Bucket lifecycle.
        """
        resp = req.get_response(self.app, method='HEAD')
        body = resp.sysmeta_headers.get(LIFECYCLE_HEADER)
        if not body:
            raise NoSuchLifecycleConfiguration()

        return HTTPOk(body=body, content_type='application/xml')

    @public
    @bucket_operation()
    @check_iam_access('s3:PutLifecycleConfiguration')
    def PUT(self, req):
        """
        Handles PUT Bucket lifecycle.
        """
        body = req.xml(MAX_LIFECYCLE_BODY_SIZE)
        try:
            # Just validate the body
            fromstring(body, 'LifecycleConfiguration')
        except (DocumentInvalid, XMLSyntaxError) as exc:
            raise MalformedXML(str(exc))

        req.headers[LIFECYCLE_HEADER] = body
        resp = req.get_response(self.app, method='POST')
        return convert_response(req, resp, 204, HTTPOk)

    @public
    @bucket_operation()
    # No specific permission for DELETE
    @check_iam_access('s3:PutLifecycleConfiguration')
    def DELETE(self, req):
        """
        Handles DELETE Bucket lifecycle.
        """
        req.headers[LIFECYCLE_HEADER] = ""
        resp = req.get_response(self.app, method='POST')
        return convert_response(req, resp, 202, HTTPNoContent)
